// SPDX-License-Identifier: GPL-3.0-or-later

//! One user's retained usage (design §15.3, `mooringctl user usage`): for
//! each node that may have counted the user's traffic, the hourly and
//! daily bins its history holds and the monthly, folded and lifetime
//! totals, as the daemon would keep them at `now`. A node the daemon has
//! not collected from yet holds none of them.
//!
//! # Retention
//!
//! The history is read from a copy pruned at `now` ([`CollectedUsage::prune`]),
//! so a read applies the retention the daemon's own prune applies (F7):
//! what a stopped daemon has not pruned yet is not shown, and the stored
//! document is left as it is. A revoked user's history is shown until its
//! deadline, and once it has passed, nothing of it is.
//!
//! # Nothing is invented
//!
//! A bin held in which the user had no bytes is left out of `bins`, as a
//! verified zero; outside a tier's `held` ranges nothing is known; a total
//! that cannot be told is `None`, never 0. The five-minute bins, kept 7
//! days, are left out: an hour holds the sum of its five-minute bins once
//! all twelve are held.

mod document;

use std::collections::BTreeMap;

use mooring_agent_proto::{Inbound, StatsEmail, UsageMonth};
use mooring_model::{Deployment, NodeId, UnixTime, UserId};

pub use self::document::{
    Bin, Folded, HeldRange, MonthTotal, NodeHistory, NodeStage, Retention, SuspendedFor, Tier,
    Totals, UsageScope, UserState, UserUsageHistory,
};

use super::aggregate::Metric;
use super::retention::Deletion;
use super::{Bins, CollectedUsage, Counters, NodeUsageHistory, corrupt, principal_of};
use crate::error::UsageError;
use crate::usage::ProtocolTraffic;
use crate::wire::{mac_time, wire_time};

impl CollectedUsage {
    /// What this history holds about `user` at `now`, its parts as `scope`
    /// says, once pruned at `now` as the daemon prunes it. Every node past
    /// `Planned` is listed. One the daemon has not collected from yet holds
    /// nothing on this Mac, so its tiers are held nowhere and its totals
    /// are unknown. It is not refused as the aggregate refuses it: the
    /// aggregate needs every node's figures, and this only shows what is
    /// held.
    ///
    /// Refused, in this order:
    /// - a user the deployment does not hold ([`UsageError::Model`]);
    /// - a `now` past the year 9999;
    /// - anything dated after `now`: a month received, a bin that ends, an
    ///   origin recorded or a user last seen not revoked after it. Only a
    ///   clock that went back or a corrupt document leaves one
    ///   (`LedgerCorrupt`).
    /// - node by node, in id order, a history that names an accounting
    ///   email no user of the deployment has, or that holds a month total
    ///   below the detail it covers. The aggregate refuses these too
    ///   (`UnknownUser`, `PrincipalNotAUser`, `MonthlyInconsistent`).
    /// - a total that overflows while the copy is pruned or a lifetime is
    ///   summed (`CounterOverflow`).
    pub fn user_history(
        &self,
        deployment: &Deployment,
        user: &UserId,
        now: UnixTime,
        scope: UsageScope,
    ) -> Result<UserUsageHistory, UsageError> {
        let row = deployment.user(user)?;
        let current = UsageMonth::containing(wire_time(now))
            .map_err(|_| corrupt("current month outside calendar"))?;
        for (node, history) in &self.nodes {
            if history.dated_after(now) {
                return Err(corrupt(format!(
                    "{node} holds usage dated after now (the Mac's clock went back, or the document is corrupt)"
                )));
            }
        }
        // A sighting after now would push a revoked user's deadline out.
        if self.last_nonrevoked.values().any(|seen| *seen > now) {
            return Err(corrupt(
                "a user was last seen not revoked after now (the Mac's clock went back, or the document is corrupt)",
            ));
        }
        let served = served(deployment);
        // The stored document is checked as the aggregate checks it. The
        // prune drops the counters of ids the deployment does not hold, so
        // after the prune another deployment's document would read as no
        // traffic. The prune keeps what this checks.
        for (node, history) in &self.nodes {
            if served.contains_key(node) {
                history.validate_users(node, deployment)?;
            }
        }
        let kept = self.pruned(deployment, now)?;
        let deletion = kept.deletion(deployment, user, now)?;
        let emails = UserEmails::of(user)?;
        // A node with no history, which the daemon has not collected from
        // yet, holds what an empty history holds: no held range, no month
        // and no lifetime, which are nothing known, never zeros.
        let uncollected = NodeUsageHistory::default();
        let nodes = if deletion == Deletion::Done {
            Vec::new()
        } else {
            served
                .iter()
                .map(|(&node, &stage)| {
                    let history = kept.nodes.get(node).unwrap_or(&uncollected);
                    emails.node(node, stage, history, current, scope)
                })
                .collect::<Result<_, _>>()?
        };
        Ok(UserUsageHistory::new(
            scope,
            now,
            row,
            Retention::of(deletion),
            nodes,
        ))
    }
}

/// The deployment's nodes that may have counted traffic, every one past
/// `Planned`, with their stages.
fn served(deployment: &Deployment) -> BTreeMap<&NodeId, NodeStage> {
    deployment
        .nodes()
        .iter()
        .filter_map(|(id, node)| Some((id, NodeStage::of(node.lifecycle.stage())?)))
        .collect()
}

impl NodeUsageHistory {
    /// Whether any of it is dated after `now`: a month received after it
    /// (its sample, never received before it was taken, then is too), a
    /// bin of any tier that ends after it, or an origin after it.
    fn dated_after(&self, now: UnixTime) -> bool {
        let now = now.as_secs();
        self.origin.is_some_and(|origin| origin.as_secs() > now)
            || self
                .months
                .values()
                .any(|record| record.received_at.as_secs() > now)
            || [
                (&self.five_min, 300),
                (&self.hour, 3600),
                (&self.day, 86_400),
            ]
            .into_iter()
            .any(|(bins, width)| {
                bins.last_key_value()
                    .is_some_and(|(start, _)| start + width > now)
            })
    }
}

/// The user's two accounting emails, as the renderer names them.
struct UserEmails {
    reality: StatsEmail,
    hy2: StatsEmail,
}

impl UserEmails {
    fn of(user: &UserId) -> Result<Self, UsageError> {
        let principal = principal_of(user)?;
        Ok(Self {
            reality: StatsEmail {
                principal: principal.clone(),
                inbound: Inbound::Reality,
            },
            hy2: StatsEmail {
                principal,
                inbound: Inbound::Hy2,
            },
        })
    }

    /// The user's bytes in `counters`, a held bin or a month's total: an
    /// email they do not name had no traffic there (an empty map is a
    /// verified zero, design §11.5).
    fn bytes(&self, counters: &Counters) -> ProtocolTraffic {
        let of = |email| counters.get(email).copied().unwrap_or_default();
        ProtocolTraffic {
            reality: of(&self.reality),
            hy2: of(&self.hy2),
        }
    }

    /// The user's bytes in `metric`; `None` when either protocol's cannot
    /// be told.
    fn metric(
        &self,
        node: &NodeId,
        metric: &Metric,
    ) -> Result<Option<ProtocolTraffic>, UsageError> {
        let reality = metric.value(node, &self.reality)?;
        let hy2 = metric.value(node, &self.hy2)?;
        Ok(reality
            .zip(hy2)
            .map(|(reality, hy2)| ProtocolTraffic { reality, hy2 }))
    }

    /// One node's part.
    fn node(
        &self,
        node: &NodeId,
        stage: NodeStage,
        history: &NodeUsageHistory,
        current: UsageMonth,
        scope: UsageScope,
    ) -> Result<NodeHistory, UsageError> {
        Ok(NodeHistory {
            node: node.clone(),
            stage,
            hourly: self.tier(&history.hour, 3600),
            daily: self.tier(&history.day, 86_400),
            totals: match scope {
                UsageScope::All => Some(self.totals(node, history, current)?),
                UsageScope::BinsOnly => None,
            },
        })
    }

    /// The tier of `bins`, each `width` seconds: the stretches held without
    /// a gap, and the bins with any of the user's bytes. A bin's start is
    /// aligned to its width and its end fits 64 bits (a decoded document is
    /// checked so, and the collector folds only whole bins).
    fn tier(&self, bins: &Bins, width: u64) -> Tier {
        let mut held: Vec<HeldRange> = Vec::new();
        let mut listed = Vec::new();
        for (&at, counters) in bins {
            let start = UnixTime::from_secs(at);
            let end = UnixTime::from_secs(at + width);
            match held.last_mut() {
                Some(range) if range.to == start => range.to = end,
                _ => held.push(HeldRange {
                    from: start,
                    to: end,
                }),
            }
            let bytes = self.bytes(counters);
            if bytes != ProtocolTraffic::default() {
                listed.push(Bin { start, bytes });
            }
        }
        Tier { held, bins: listed }
    }

    /// The node's totals: each month held, the months folded, and the
    /// lifetime through `current`.
    fn totals(
        &self,
        node: &NodeId,
        history: &NodeUsageHistory,
        current: UsageMonth,
    ) -> Result<Totals, UsageError> {
        let lifetime = match history.lifetime(current)? {
            Some(metric) => self.metric(node, &metric)?,
            None => None,
        };
        Ok(Totals {
            months: history
                .months
                .iter()
                .map(|(&month, record)| MonthTotal {
                    month,
                    counted_through: mac_time(record.sample.updated_at),
                    is_final: record.is_final(),
                    bytes: self.bytes(&record.sample.traffic),
                })
                .collect(),
            folded: history.folded_before.map(|before| Folded {
                before,
                complete: history.lifetime_complete,
                bytes: self.bytes(&history.folded),
            }),
            lifetime,
        })
    }
}
