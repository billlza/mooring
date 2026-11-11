// SPDX-License-Identifier: GPL-3.0-or-later

//! Reconcile monthly totals with closed detail. A period uses complete
//! detail when available, otherwise monthly totals minus a proven prefix.
//! An unknown prefix with positive traffic makes that user's figure null;
//! a verified zero monthly total remains a real zero. No bytes are spread
//! arbitrarily across a lost day or billing boundary.

use std::collections::BTreeMap;

use mooring_agent_proto::{Inbound, Principal, StatsEmail, Traffic, UsageMonth};
use mooring_model::{Deployment, NodeId, UnixTime};

use super::{CollectedUsage, Counters, NodeUsageHistory, add_counters, corrupt, principal_of};
use crate::error::UsageError;
use crate::period::UsagePeriods;
use crate::usage::{
    Counted, MissingPeriods, ProtocolTraffic, UsageReport, UserUsage, add, resolve,
};

/// The latest accounting sample may trail publication by at most three
/// minutes (one-minute pulls and node polls, with a bounded probe-slot wait).
const FRESH_SECS: u64 = 180;

/// A period's counters: its total, less a proven prefix, unknown for the
/// emails whose `uncertain` share is not zero.
pub(super) struct Metric {
    total: Counters,
    prefix: Counters,
    uncertain: Counters,
}

fn subtract(node: &NodeId, total: Traffic, old: Traffic) -> Result<Traffic, UsageError> {
    let difference = |value: u64, old: u64| {
        value
            .checked_sub(old)
            .ok_or_else(|| UsageError::MonthlyInconsistent { node: node.clone() })
    };
    Ok(Traffic {
        uplink: difference(total.uplink, old.uplink)?,
        downlink: difference(total.downlink, old.downlink)?,
    })
}

impl Metric {
    /// `email`'s bytes in the period: `None` when they cannot be told.
    pub(super) fn value(
        &self,
        node: &NodeId,
        email: &StatsEmail,
    ) -> Result<Option<Traffic>, UsageError> {
        if self
            .uncertain
            .get(email)
            .is_some_and(|bytes| *bytes != Traffic::default())
        {
            return Ok(None);
        }
        subtract(
            node,
            self.total.get(email).copied().unwrap_or_default(),
            self.prefix.get(email).copied().unwrap_or_default(),
        )
        .map(Some)
    }
}

impl NodeUsageHistory {
    fn months_between(
        &self,
        mut first: UsageMonth,
        last: UsageMonth,
    ) -> Result<Option<Counters>, UsageError> {
        let mut total = Counters::new();
        // Retention bounds the monthly history; an older missing month is
        // unknown, never an unbounded walk backwards through the calendar.
        for _ in 0..=14 {
            if first > last {
                return Ok(Some(total));
            }
            let Some(sample) = self.months.get(&first) else {
                return Ok(None);
            };
            if first < last && !sample.is_final() {
                return Ok(None);
            }
            add_counters(&mut total, &sample.sample.traffic)?;
            first = first
                .next()
                .ok_or_else(|| corrupt("month has no successor"))?;
        }
        Ok(None)
    }

    fn period(
        &self,
        node: &NodeId,
        start: u64,
        detail_end: u64,
        current: UsageMonth,
        prefer_month: bool,
    ) -> Result<Option<Metric>, UsageError> {
        if !prefer_month && let Some(total) = self.detailed(start, detail_end)? {
            return Ok(Some(Metric {
                total,
                prefix: Counters::new(),
                uncertain: Counters::new(),
            }));
        }
        let first = UsageMonth::containing(mooring_agent_proto::UnixTime::from_secs(start))
            .map_err(|_| corrupt("period outside calendar"))?;
        let Some(total) = self.months_between(first, current)? else {
            return Ok(None);
        };
        let first_record = self
            .months
            .get(&first)
            .ok_or_else(|| corrupt("first month disappeared"))?;
        let end = if first < current {
            first
                .next()
                .ok_or_else(|| corrupt("month has no successor"))?
                .start()
                .as_secs()
        } else {
            first_record.sample.updated_at.as_secs()
        };
        let mut uncertain = Counters::new();
        let prefix = if start == first.start().as_secs()
            || self.origin.is_some_and(|at| at.as_secs() >= start)
        {
            Counters::new()
        } else if let Some(prefix) = self.detailed(first.start().as_secs(), start)? {
            prefix
        } else if let Some(suffix) = self.detailed(start, end)? {
            let mut prefix = Counters::new();
            for (email, bytes) in &first_record.sample.traffic {
                prefix.insert(
                    email.clone(),
                    subtract(node, *bytes, suffix.get(email).copied().unwrap_or_default())?,
                );
            }
            prefix
        } else {
            let prefix = self.known(first.start().as_secs(), start)?;
            let suffix = self.known(start, end)?;
            for (email, bytes) in &first_record.sample.traffic {
                let left = subtract(node, *bytes, prefix.get(email).copied().unwrap_or_default())?;
                let residual =
                    subtract(node, left, suffix.get(email).copied().unwrap_or_default())?;
                if residual != Traffic::default() {
                    uncertain.insert(email.clone(), residual);
                }
            }
            prefix
        };
        Ok(Some(Metric {
            total,
            prefix,
            uncertain,
        }))
    }

    /// Everything the node counted from its origin through `current`:
    /// `None` unless its lifetime is complete (a recorded origin, and every
    /// month folded since final when it was folded), no month is held from
    /// before it, and every month from the first one kept through `current`
    /// is held, each but `current` final.
    pub(super) fn lifetime(&self, current: UsageMonth) -> Result<Option<Metric>, UsageError> {
        if !self.lifetime_complete {
            return Ok(None);
        }
        let Some(origin) = self.origin else {
            return Err(corrupt("lifetime has no origin"));
        };
        let first = self.folded_before.unwrap_or(
            UsageMonth::containing(mooring_agent_proto::UnixTime::from_secs(origin.as_secs()))
                .map_err(|_| corrupt("origin outside calendar"))?,
        );
        // A month from before the recorded origin was counted before it (a
        // VPS adopted again with its old files, before adoption refused
        // one, a clock that ran ahead when the origin was recorded, or a
        // first apply whose first poll came before a month's end and the
        // last unserved sighting after it): a sum from the origin would
        // leave it out.
        if self
            .months
            .keys()
            .next()
            .is_some_and(|month| *month < first)
        {
            return Ok(None);
        }
        let Some(mut total) = self.months_between(first, current)? else {
            return Ok(None);
        };
        add_counters(&mut total, &self.folded)?;
        Ok(Some(Metric {
            total,
            prefix: Counters::new(),
            uncertain: Counters::new(),
        }))
    }

    /// Validates all stored principals against the current deployment before
    /// a collected batch is admitted. Unknown emails never become zero users.
    pub fn validate_users(&self, node: &NodeId, deployment: &Deployment) -> Result<(), UsageError> {
        for counters in self
            .months
            .values()
            .map(|month| &month.sample.traffic)
            .chain(std::iter::once(&self.folded))
            .chain(self.five_min.values())
            .chain(self.hour.values())
            .chain(self.day.values())
        {
            for email in counters.keys() {
                resolve(node, email, deployment.users())?;
            }
        }
        self.check_monthly_detail(node)
    }

    fn known(&self, from: u64, through: u64) -> Result<Counters, UsageError> {
        if from >= through {
            return Ok(Counters::new());
        }
        let mut bins = Vec::new();
        for (source, width) in [
            (&self.day, 86_400),
            (&self.hour, 3600),
            (&self.five_min, 300),
        ] {
            bins.extend(
                source
                    .range(from..through)
                    .filter(|(at, _)| **at + width <= through)
                    .map(|(at, bytes)| (*at, width, bytes)),
            );
        }
        bins.sort_by_key(|(at, width, _)| (*at, std::cmp::Reverse(*width)));
        let mut cursor = from;
        let mut known = Counters::new();
        for (at, width, bytes) in bins {
            if at < cursor {
                continue;
            }
            add_counters(&mut known, bytes)?;
            cursor = at + width;
        }
        Ok(known)
    }

    fn check_monthly_detail(&self, node: &NodeId) -> Result<(), UsageError> {
        for record in self.months.values() {
            let sample = &record.sample;
            let through = sample.updated_at.as_secs() / 300 * 300;
            for (email, bytes) in self.known(sample.month.start().as_secs(), through)? {
                subtract(
                    node,
                    sample.traffic.get(&email).copied().unwrap_or_default(),
                    bytes,
                )?;
            }
        }
        Ok(())
    }
}

impl CollectedUsage {
    /// Figures from each node's latest sample. `periods.through` bounds the
    /// report's calendar; `sampled_at` names the actual source times. Detail
    /// ends at a closed five-minute boundary; monthly recovery can be newer.
    pub fn aggregate(
        &self,
        deployment: &Deployment,
        now: UnixTime,
    ) -> Result<UsageReport, UsageError> {
        let periods = UsagePeriods::ending(deployment.exit().sim.cycle(), now)?;
        let current =
            UsageMonth::containing(mooring_agent_proto::UnixTime::from_secs(now.as_secs()))
                .map_err(|_| corrupt("current month outside calendar"))?;
        let mut rows: BTreeMap<_, _> = deployment
            .users()
            .keys()
            .map(|id| (id.clone(), Counted::default()))
            .collect();
        let mut sampled_at = BTreeMap::new();
        let mut probe_cycle = BTreeMap::<NodeId, Option<ProtocolTraffic>>::new();
        for (node, config) in deployment.nodes() {
            if config.lifecycle.stage() == mooring_model::node::LifecycleStage::Planned {
                continue;
            }
            let history = self
                .nodes
                .get(node)
                .ok_or_else(|| UsageError::MissingLedger { node: node.clone() })?;
            history.validate_users(node, deployment)?;

            let sample = history
                .months
                .get(&current)
                .ok_or_else(|| UsageError::MissingLedger { node: node.clone() })?;
            let at = UnixTime::from_secs(sample.sample.updated_at.as_secs());
            if at > now {
                return Err(corrupt("node accounting sample is in the future"));
            }
            if now.as_secs() - at.as_secs() > FRESH_SECS {
                return Err(UsageError::NotCoveredThrough {
                    node: node.clone(),
                    covered_to: at,
                    through: now,
                });
            }
            let detail_through = history
                .detail_through()
                .map(|end| end.min(at.as_secs() / 300 * 300));
            let detail_end = at.as_secs() / 300 * 300;
            sampled_at.insert(
                node.clone(),
                super::super::UsageSampleTimes {
                    monthly_at: at,
                    detail_through: detail_through.map(UnixTime::from_secs),
                },
            );
            let today = history.period(
                node,
                periods.utc_day.utc_start().as_secs(),
                detail_end,
                current,
                false,
            )?;
            let cycle = history.period(
                node,
                periods.cycle.starts_at().as_secs(),
                detail_end,
                current,
                false,
            )?;
            let month = history.period(
                node,
                periods.utc_month_start.utc_start().as_secs(),
                detail_end,
                current,
                true,
            )?;
            let lifetime = history.lifetime(current)?;
            for (id, row) in &mut rows {
                if self.erased(deployment, id, now)? {
                    row.missing = MissingPeriods {
                        today: true,
                        cycle: true,
                        month: true,
                        lifetime: true,
                    };
                    continue;
                }
                let principal = principal_of(id)?;
                for &inbound in Inbound::ALL {
                    let email = StatsEmail {
                        principal: principal.clone(),
                        inbound,
                    };
                    for (metric, total, missing) in [
                        (&today, &mut row.today, &mut row.missing.today),
                        (&month, &mut row.month, &mut row.missing.month),
                        (&lifetime, &mut row.lifetime, &mut row.missing.lifetime),
                    ] {
                        match metric
                            .as_ref()
                            .map(|m| m.value(node, &email))
                            .transpose()?
                            .flatten()
                        {
                            Some(bytes) => add(total, bytes)?,
                            None => *missing = true,
                        }
                    }
                    match cycle
                        .as_ref()
                        .map(|m| m.value(node, &email))
                        .transpose()?
                        .flatten()
                    {
                        Some(bytes) => {
                            add(&mut row.cycle, bytes)?;
                            if bytes != Traffic::default() {
                                add(row.cycle_by_node.entry(node.clone()).or_default(), bytes)?;
                            }
                            row.cycle_by_protocol.add(inbound, bytes)?;
                        }
                        None => row.missing.cycle = true,
                    }
                }
            }
            let mut counted_probe = ProtocolTraffic::default();
            let mut complete_probe = true;
            for &inbound in Inbound::ALL {
                let email = StatsEmail {
                    principal: Principal::Probe,
                    inbound,
                };
                match cycle
                    .as_ref()
                    .map(|m| m.value(node, &email))
                    .transpose()?
                    .flatten()
                {
                    Some(bytes) => counted_probe.add(inbound, bytes)?,
                    None => complete_probe = false,
                }
            }
            probe_cycle.insert(node.clone(), complete_probe.then_some(counted_probe));
        }
        Ok(UsageReport {
            periods,
            sampled_at,
            probe_cycle,
            users: rows
                .into_iter()
                .map(|(id, counted)| Ok((id, UserUsage::derive(counted)?)))
                .collect::<Result<_, UsageError>>()?,
        })
    }
}
