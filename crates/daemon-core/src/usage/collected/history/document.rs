// SPDX-License-Identifier: GPL-3.0-or-later

//! The document of one user's usage history, `mooring-user-usage` version
//! 1, exactly as `mooringctl user usage` prints and writes it (design
//! §15.3): every key always present, `null` for what is absent or unknown
//! (never 0), and no other key. These types are that shape and are only
//! serialised. The status, the suspension's reason, the retention and the
//! node's stage are mapped from the model's enums below, by matches that
//! name every variant: a new variant needs a decision here, and the
//! model's own serde form of those enums never reaches the document.
//! Times, ids, the alias, months and byte counts serialise as
//! `mooring-model` and `mooring-agent-proto` spell them, which
//! `contract/usage-fixtures/` pins.
//!
//! The document names the user by id and alias. It has no field for a
//! label, a credential, a short id or an address.
//!
//! Its parts' fields are public to read; `#[non_exhaustive]` keeps any other
//! crate from building one, so only [`CollectedUsage::user_history`]
//! makes a document.
//!
//! [`CollectedUsage::user_history`]: crate::usage::CollectedUsage::user_history

use mooring_agent_proto::UsageMonth;
use mooring_model::node::LifecycleStage;
use mooring_model::{NodeId, PublicAlias, SuspendReason, UnixTime, User, UserId, UserStatus};
use serde::Serialize;

use super::super::retention::Deletion;
use crate::usage::ProtocolTraffic;

/// What the document is, so that no other JSON is taken for it.
const FORMAT: &str = "mooring-user-usage";

/// The document's version.
const VERSION: u32 = 1;

/// Which parts of a user's history the document carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageScope {
    /// The hourly and daily bins and the totals.
    All,
    /// The hourly and daily bins alone: every node's `totals` is `null`.
    BinsOnly,
}

/// One user's usage as this Mac holds it at `generated_at`: what the
/// daemon's prune keeps at that instant, per node that may have counted
/// the user's traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserUsageHistory {
    format: &'static str,
    version: u32,
    scope: UsageScope,
    generated_at: UnixTime,
    user: UserId,
    alias: Option<PublicAlias>,
    status: UserState,
    retention: Retention,
    nodes: Vec<NodeHistory>,
}

impl UserUsageHistory {
    /// The document of `user` (its id, alias and status) at `generated_at`.
    pub(super) fn new(
        scope: UsageScope,
        generated_at: UnixTime,
        user: &User,
        retention: Retention,
        nodes: Vec<NodeHistory>,
    ) -> Self {
        Self {
            format: FORMAT,
            version: VERSION,
            scope,
            generated_at,
            user: user.id.clone(),
            alias: user.alias.clone(),
            status: UserState::of(user.status),
            retention,
            nodes,
        }
    }

    /// Which parts it carries.
    #[must_use]
    pub const fn scope(&self) -> UsageScope {
        self.scope
    }

    /// The instant it was made, the one its retention was judged at.
    #[must_use]
    pub const fn generated_at(&self) -> UnixTime {
        self.generated_at
    }

    /// The user.
    #[must_use]
    pub const fn user(&self) -> &UserId {
        &self.user
    }

    /// The user's public alias, if it has one.
    #[must_use]
    pub const fn alias(&self) -> Option<&PublicAlias> {
        self.alias.as_ref()
    }

    /// The user's status.
    #[must_use]
    pub const fn status(&self) -> UserState {
        self.status
    }

    /// How long the history is kept.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.retention
    }

    /// Every node past `Planned`, in id order; none once the history is
    /// erased.
    #[must_use]
    pub fn nodes(&self) -> &[NodeHistory] {
        &self.nodes
    }

    /// The document pretty-printed and ending with a newline: the file
    /// `mooringctl user usage --out` writes, as `contract/usage-fixtures/`
    /// pins it. Encoding these types cannot fail; the error is serde's.
    pub fn pretty(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// `"active"`, `{"suspended": {"reason": …, "since": …}}`,
/// `"revoke_pending"` or `"revoked"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    /// Served.
    Active,
    /// Served nowhere, its credentials kept.
    Suspended {
        /// Why.
        reason: SuspendedFor,
        /// Since when.
        since: UnixTime,
    },
    /// Being revoked: served nowhere, its removal not yet committed on
    /// every node.
    RevokePending,
    /// Revoked on every node.
    Revoked,
}

impl UserState {
    const fn of(status: UserStatus) -> Self {
        match status {
            UserStatus::Active => Self::Active,
            UserStatus::Suspended { reason, since } => Self::Suspended {
                reason: SuspendedFor::of(reason),
                since,
            },
            UserStatus::RevokePending => Self::RevokePending,
            UserStatus::Revoked { .. } => Self::Revoked,
        }
    }
}

/// Why a user is suspended. A suspension for quota leaves out the cycle it
/// names, as the portal's snapshot does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendedFor {
    /// By the operator.
    Operator,
    /// Over its quota.
    QuotaExceeded,
    /// Past its expiry.
    Expired,
    /// For an abuse review.
    AbuseReview,
}

impl SuspendedFor {
    const fn of(reason: SuspendReason) -> Self {
        match reason {
            SuspendReason::Operator => Self::Operator,
            SuspendReason::QuotaExceeded { .. } => Self::QuotaExceeded,
            SuspendReason::Expired => Self::Expired,
            SuspendReason::AbuseReview => Self::AbuseReview,
        }
    }
}

/// `"tiered"`, `{"until": …}` or `"erased"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    /// The user is not revoked: each bin and month is kept as long as F7
    /// keeps its tier (design §11.5, §15.7).
    Tiered,
    /// The user is revoked: everything held goes by this instant at the
    /// latest, 13 months after the last time the daemon saw it not
    /// revoked. That sighting came before the revocation, so the instant
    /// is never later than 13 months after it.
    Until(UnixTime),
    /// The user is revoked and its retention has ended: its deadline has
    /// passed, or the daemon never saw it not revoked. Nothing of its
    /// history is shown, and the daemon's next prune deletes what
    /// `usage/users.json` may still hold.
    Erased,
}

impl Retention {
    pub(super) const fn of(deletion: Deletion) -> Self {
        match deletion {
            Deletion::Tiered => Self::Tiered,
            Deletion::At(until) => Self::Until(until),
            Deletion::Done => Self::Erased,
        }
    }
}

/// A node's stage past `Planned`, the only nodes whose agents may hold
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStage {
    /// Adopted.
    Adopted,
    /// A generation is committed and confirmed.
    Applied,
    /// Being shut down.
    Retiring,
    /// Shut down; its VM is still to be deleted.
    RetiredPendingProviderDeletion,
    /// Retired.
    Retired,
}

impl NodeStage {
    /// The stage of a node whose agent may hold records; `None` for a
    /// planned one, not adopted yet.
    pub(super) const fn of(stage: LifecycleStage) -> Option<Self> {
        match stage {
            LifecycleStage::Planned => None,
            LifecycleStage::Adopted => Some(Self::Adopted),
            LifecycleStage::Applied => Some(Self::Applied),
            LifecycleStage::Retiring => Some(Self::Retiring),
            LifecycleStage::RetiredPendingProviderDeletion => {
                Some(Self::RetiredPendingProviderDeletion)
            }
            LifecycleStage::Retired => Some(Self::Retired),
        }
    }
}

/// What one node's history holds for the user: nothing, for a node the
/// daemon has not collected from yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NodeHistory {
    /// The node.
    pub node: NodeId,
    /// Its stage.
    pub stage: NodeStage,
    /// Its hourly bins.
    pub hourly: Tier,
    /// Its daily bins.
    pub daily: Tier,
    /// Its totals; `None` in a document of the bins alone.
    pub totals: Option<Totals>,
}

/// One tier of bins: where the node holds it, and the bins in which the
/// user had traffic. A bin held but not listed is a verified zero; outside
/// `held`, nothing is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Tier {
    /// The stretches the tier holds without a gap, in time order.
    pub held: Vec<HeldRange>,
    /// The bins with any of the user's bytes, in time order.
    pub bins: Vec<Bin>,
}

/// `[from, to)`: whole bins held without a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct HeldRange {
    /// The first bin's start.
    pub from: UnixTime,
    /// The last bin's end.
    pub to: UnixTime,
}

/// The user's bytes in one bin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Bin {
    /// The bin's start.
    pub start: UnixTime,
    /// The user's bytes in it; never both protocols zero.
    pub bytes: ProtocolTraffic,
}

/// The node's totals for the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Totals {
    /// Each month the node's history holds, in order.
    pub months: Vec<MonthTotal>,
    /// The months that outlived their retention, folded into one total;
    /// `None` when none has.
    pub folded: Option<Folded>,
    /// Everything the node counted for the user since it was first served;
    /// `None` when that cannot be told (no recorded origin, a month missing
    /// or not final, or a month held from before the origin).
    pub lifetime: Option<ProtocolTraffic>,
}

/// The user's bytes in one month's total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MonthTotal {
    /// The month.
    pub month: UsageMonth,
    /// The node's accounting poll the total is as of.
    pub counted_through: UnixTime,
    /// Whether the total was received once the month had ended by the
    /// Mac's clock. A node whose clock runs behind the Mac's can still add
    /// to it, and the daemon pulls a month again for 7 days after it ends.
    #[serde(rename = "final")]
    pub is_final: bool,
    /// The user's bytes.
    pub bytes: ProtocolTraffic,
}

/// The user's bytes in the months the node's history held, and folded
/// into one total once their retention ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Folded {
    /// The months folded are some or all of those before this one.
    pub before: UsageMonth,
    /// Whether they are every month the node counted in before `before`,
    /// each final when it was folded (the node's origin is recorded, and no
    /// month was missing); otherwise `bytes` is a lower bound.
    pub complete: bool,
    /// The user's bytes in them.
    pub bytes: ProtocolTraffic,
}

#[cfg(test)]
mod tests {
    use mooring_model::node::LifecycleStage;
    use mooring_model::{CalendarDate, SuspendReason, UnixTime, UserStatus};
    use serde_json::{Value, json};

    use super::{Deletion, NodeStage, Retention, SuspendedFor, UserState};

    fn spelled<T: serde::Serialize>(value: T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    /// Every stage past `Planned` has its own name, and a planned node has
    /// none: it never served, so it is never listed.
    #[test]
    fn every_stage_past_planned_has_its_own_name() {
        let names = [
            (LifecycleStage::Planned, None),
            (LifecycleStage::Adopted, Some("adopted")),
            (LifecycleStage::Applied, Some("applied")),
            (LifecycleStage::Retiring, Some("retiring")),
            (
                LifecycleStage::RetiredPendingProviderDeletion,
                Some("retired_pending_provider_deletion"),
            ),
            (LifecycleStage::Retired, Some("retired")),
        ];
        assert_eq!(names.len(), LifecycleStage::ALL.len());
        for (stage, name) in names {
            assert_eq!(
                NodeStage::of(stage).map(spelled),
                name.map(Value::from),
                "{stage:?}"
            );
        }
    }

    /// Every status and every reason has its own spelling; a suspension
    /// for quota leaves its cycle out.
    #[test]
    fn every_status_and_reason_has_its_own_spelling() {
        let since = UnixTime::from_secs(1_793_000_000);
        let suspended = |reason| UserStatus::Suspended { reason, since };
        let cases = [
            (UserStatus::Active, json!("active")),
            (UserStatus::RevokePending, json!("revoke_pending")),
            (
                UserStatus::Revoked {
                    since: UnixTime::from_secs(1_791_417_600),
                },
                json!("revoked"),
            ),
            (
                suspended(SuspendReason::Operator),
                json!({"suspended": {"reason": "operator", "since": 1_793_000_000}}),
            ),
            (
                suspended(SuspendReason::QuotaExceeded {
                    cycle_start: CalendarDate::parse("2026-10-23").unwrap(),
                }),
                json!({"suspended": {"reason": "quota_exceeded", "since": 1_793_000_000}}),
            ),
            (
                suspended(SuspendReason::Expired),
                json!({"suspended": {"reason": "expired", "since": 1_793_000_000}}),
            ),
            (
                suspended(SuspendReason::AbuseReview),
                json!({"suspended": {"reason": "abuse_review", "since": 1_793_000_000}}),
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(spelled(UserState::of(status)), expected, "{status:?}");
        }
        assert_eq!(
            UserState::of(suspended(SuspendReason::Expired)),
            UserState::Suspended {
                reason: SuspendedFor::Expired,
                since
            }
        );
    }

    /// The prune's three outcomes are the document's three retentions.
    #[test]
    fn each_deletion_is_its_retention() {
        let at = UnixTime::from_secs(1_830_000_000);
        assert_eq!(spelled(Retention::of(Deletion::Tiered)), json!("tiered"));
        assert_eq!(
            spelled(Retention::of(Deletion::At(at))),
            json!({"until": 1_830_000_000})
        );
        assert_eq!(spelled(Retention::of(Deletion::Done)), json!("erased"));
    }
}
