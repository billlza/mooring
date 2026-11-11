// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's F7 retention: detail for 7 days, hours for 35 days, day and
//! month buckets for 13 calendar months after their end. Expired months
//! fold into lifetime counters before deletion. Revocation uses the last
//! known non-revoked instant, so observing it late cannot extend retention.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{Principal, StatsEmail, UsageMonth};
use mooring_model::{CalendarDate, Deployment, UnixTime, UserId, UserStatus};

use super::{CollectedUsage, Counters, add_counters, corrupt};
use crate::error::UsageError;
use crate::wire::accounting_user;

fn after_thirteen_months(at: UnixTime) -> Result<UnixTime, UsageError> {
    let date = CalendarDate::utc_of(at)?;
    let ordinal = u32::from(date.year()) * 12 + u32::from(date.month() - 1) + 13;
    let year = u16::try_from(ordinal / 12).map_err(|_| corrupt("retention date overflows"))?;
    let month = (ordinal % 12 + 1) as u8;
    let day = date
        .day()
        .min(mooring_model::date::days_in_month(year, month));
    let boundary = CalendarDate::new(year, month, day)?.utc_start().as_secs();
    Ok(UnixTime::from_secs(boundary + at.as_secs() % 86_400))
}

fn revoked(status: UserStatus) -> bool {
    matches!(
        status,
        UserStatus::Revoked { .. } | UserStatus::RevokePending
    )
}

/// When a user's retained usage goes, as the prune decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Deletion {
    /// The user is not revoked: each bin and month expires on its own.
    Tiered,
    /// The user is revoked: all of it goes at this instant, 13 months after
    /// the last time it was seen not revoked, if the tiers have not taken
    /// it first.
    At(UnixTime),
    /// It is gone: the user's deadline has passed, it was never seen not
    /// revoked, or the deployment does not hold it.
    Done,
}

impl CollectedUsage {
    /// When `user`'s retained usage goes, judged at `now`.
    pub(super) fn deletion(
        &self,
        deployment: &Deployment,
        user: &UserId,
        now: UnixTime,
    ) -> Result<Deletion, UsageError> {
        let Some(row) = deployment.users().get(user) else {
            return Ok(Deletion::Done);
        };
        if !revoked(row.status) {
            return Ok(Deletion::Tiered);
        }
        let Some(at) = self.last_nonrevoked.get(user) else {
            return Ok(Deletion::Done);
        };
        let end = after_thirteen_months(*at)?;
        Ok(if now >= end {
            Deletion::Done
        } else {
            Deletion::At(end)
        })
    }

    /// Removes counters whose retention has ended before comparing an
    /// incoming snapshot with the pruned one. Unknown principals still fail.
    pub fn retain_counter_users(
        &self,
        node: &mooring_model::NodeId,
        counters: &mut BTreeMap<StatsEmail, mooring_agent_proto::Traffic>,
        deployment: &Deployment,
        now: UnixTime,
    ) -> Result<(), UsageError> {
        let mut remove = Vec::new();
        for email in counters.keys() {
            if let crate::usage::Owner::User(user) =
                crate::usage::resolve(node, email, deployment.users())?
                && self.erased(deployment, &user, now)?
            {
                remove.push(email.clone());
            }
        }
        for email in remove {
            counters.remove(&email);
        }
        Ok(())
    }

    /// Whether a row's retained usage was deleted, not a zero lifetime.
    pub(crate) fn erased(
        &self,
        deployment: &Deployment,
        user: &UserId,
        now: UnixTime,
    ) -> Result<bool, UsageError> {
        Ok(self.deletion(deployment, user, now)? == Deletion::Done)
    }

    /// Applies deletion to every retained representation before publication
    /// and writing. Forgotten or expired users cannot reappear from a replay.
    pub fn prune(&mut self, deployment: &Deployment, now: UnixTime) -> Result<(), UsageError> {
        *self = self.pruned(deployment, now)?;
        Ok(())
    }

    /// A copy of this history pruned at `now`; this one is left as it is.
    pub(super) fn pruned(
        &self,
        deployment: &Deployment,
        now: UnixTime,
    ) -> Result<Self, UsageError> {
        let mut candidate = self.clone();
        candidate.prune_inner(deployment, now)?;
        Ok(candidate)
    }

    fn prune_inner(&mut self, deployment: &Deployment, now: UnixTime) -> Result<(), UsageError> {
        for (id, user) in deployment.users() {
            if !revoked(user.status) {
                self.last_nonrevoked.insert(id.clone(), now);
            }
        }
        let keep: BTreeSet<_> = deployment
            .users()
            .keys()
            .map(|id| {
                self.erased(deployment, id, now)
                    .map(|erased| (!erased).then_some(id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        self.last_nonrevoked.retain(|id, _| keep.contains(id));
        for history in self.nodes.values_mut() {
            history
                .five_min
                .retain(|at, _| at.saturating_add(300 + 7 * 86_400) > now.as_secs());
            history
                .hour
                .retain(|at, _| at.saturating_add(3600 + 35 * 86_400) > now.as_secs());
            let expired_days = history
                .day
                .keys()
                .copied()
                .map(|at| {
                    after_thirteen_months(UnixTime::from_secs(at + 86_400))
                        .map(|end| (at, end <= now))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (at, expired) in expired_days {
                if expired {
                    history.day.remove(&at);
                }
            }
            let expired_months = history
                .months
                .keys()
                .copied()
                .map(|month| {
                    let end = month
                        .next()
                        .ok_or_else(|| corrupt("month has no successor"))?
                        .start();
                    after_thirteen_months(UnixTime::from_secs(end.as_secs()))
                        .map(|end| (month, end <= now))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (month, expired) in expired_months {
                if !expired {
                    continue;
                }
                let expected = history.folded_before.or_else(|| {
                    history.origin.and_then(|at| {
                        UsageMonth::containing(mooring_agent_proto::UnixTime::from_secs(
                            at.as_secs(),
                        ))
                        .ok()
                    })
                });
                if expected != Some(month) {
                    history.lifetime_complete = false;
                }
                let Some(sample) = history.months.remove(&month) else {
                    return Err(corrupt("retention month disappeared"));
                };
                if !sample.is_final() {
                    history.lifetime_complete = false;
                }
                add_counters(&mut history.folded, &sample.sample.traffic)?;
                history.folded_before = month.next();
            }
            let clean = |counters: &mut Counters| {
                counters.retain(|email: &StatsEmail, _| match &email.principal {
                    Principal::Probe => true,
                    Principal::User(opaque) => {
                        accounting_user(opaque).is_ok_and(|id| keep.contains(&id))
                    }
                })
            };
            clean(&mut history.folded);
            for bins in [&mut history.five_min, &mut history.hour, &mut history.day] {
                for counters in bins.values_mut() {
                    clean(counters);
                }
            }
            for month in history.months.values_mut() {
                clean(&mut month.sample.traffic);
            }
        }
        self.nodes
            .retain(|node, _| deployment.nodes().contains_key(node));
        Ok(())
    }
}
