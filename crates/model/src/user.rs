// SPDX-License-Identifier: GPL-3.0-or-later

//! Users, their CFM client profiles and their lifecycle (design §7, §9.1,
//! §13.5).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::{NonZeroU16, NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::date::CalendarDate;
use crate::error::ModelError;
use crate::ids::{LocalLabel, NodeId, PublicAlias, ShortId, UserId};
use crate::time::UnixTime;

/// The CFM release line a user's client belongs to; it selects the export shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientLine {
    /// CFM 0.4 (sing-box 1.14.1).
    Cfm04,
    /// CFM 0.5 (sing-box 1.14.2).
    Cfm05,
}

/// An optional client capability that changes the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Emit `support_x25519mlkem768` (sing-box) or `support-x25519mlkem768`
    /// (Clash); requires a CFM build whose importer accepts it.
    RealityMlkemOptIn,
}

impl ClientLine {
    /// Whether this line's importer accepts `capability`. `mooring-export`
    /// refuses an unsupported pair with `CapabilityUnsupported`.
    #[must_use]
    pub const fn accepts(self, capability: Capability) -> bool {
        match (self, capability) {
            (Self::Cfm04, Capability::RealityMlkemOptIn) => false,
            (Self::Cfm05, Capability::RealityMlkemOptIn) => true,
        }
    }
}

/// A user's client: its CFM line and opted-in capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    /// The CFM line.
    pub line: ClientLine,
    /// The capabilities the user's build supports.
    pub capabilities: BTreeSet<Capability>,
}

/// Why a user is suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SuspendReason {
    /// The operator suspended the user.
    Operator,
    /// The user's served bytes passed their quota in the SIM billing cycle
    /// that started on `cycle_start`. It records the cycle as it was when
    /// the user was suspended: a later change to the quota or the bill day
    /// neither alters it nor resumes the user.
    QuotaExceeded {
        /// The first day of the billing cycle whose quota was exceeded.
        cycle_start: CalendarDate,
    },
    /// The user's access expired (`UserPolicy::expires_at`).
    Expired,
    /// The user is suspended while an abuse complaint is reviewed.
    AbuseReview,
}

/// A user's lifecycle state (design §13.5).
///
/// Transitions ([`User::suspend`], [`User::resume`], [`User::revoke`]):
/// an active user may be suspended and a suspended one resumed; an active
/// or suspended user may be revoked; revocation then proceeds node by node
/// through `Bookkeeping::RevocationCommitted`, or a record that drops a
/// node (`RetirementShutDown`, `PlanCancelled`), and never goes back.
/// Suspending and resuming change which users the nodes serve, so they are
/// configuration changes that bump `config_generation`, never bookkeeping.
/// A revoked user leaves the deployment only by the bookkeeping record
/// `RevokedUserRemoved` (design §15.7): 13 months after its revocation, or
/// at once on its request (`user forget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UserStatus {
    /// The user is served.
    Active,
    /// Served nowhere and exported nowhere, but still holding its per-node
    /// credentials (their secrets stay referenced), so resuming restores
    /// service without delivering a new file into China.
    Suspended {
        /// Why.
        reason: SuspendReason,
        /// When the user was suspended.
        since: UnixTime,
    },
    /// Being revoked: served nowhere, and `per_node` lists exactly the nodes
    /// that have not yet committed the removal (at least one). A node's
    /// entry and its credentials are removed once it commits; with none
    /// left the user is `Revoked`. The remaining set is never stored apart
    /// from `per_node`, so the two cannot disagree.
    RevokePending,
    /// Revoked on every node; the user holds no credentials. The Mac keeps
    /// the user's records until 13 months after `since`, when the apply job
    /// removes them, or until the user asks for them to go
    /// (`RevokedUserRemoved`, design §15.7).
    Revoked {
        /// When the user became revoked: the last node committed the
        /// revocation, or the user held credentials on none. A state of
        /// version 2, which kept no time, lifts with the lift's time, which
        /// can only delay the removal.
        since: UnixTime,
    },
}

impl UserStatus {
    /// Whether a configuration change may move a user from this status to
    /// `next`: the status unchanged, or one step the user transitions
    /// take. `Active` and `Suspended` swap ([`User::suspend`],
    /// [`User::resume`]); either starts a revocation ([`User::revoke`]),
    /// becoming `RevokePending` or, holding no credentials, `Revoked`.
    /// Nothing else: a suspension is not re-labelled in place, and a
    /// revocation settles only through bookkeeping
    /// (`Bookkeeping::RevocationCommitted`, or a record that drops the
    /// last node it waits on) and never goes back, and a revocation's time
    /// is never edited. The store refuses any other change
    /// (`UserStatusEdited`), and every removal: a user leaves only by the
    /// record `RevokedUserRemoved`.
    #[must_use]
    pub fn may_change_to(self, next: Self) -> bool {
        match (self, next) {
            (from, to) if from == to => true,
            (Self::Active, Self::Suspended { .. })
            | (Self::Suspended { .. }, Self::Active)
            | (Self::Active | Self::Suspended { .. }, Self::RevokePending | Self::Revoked { .. }) => {
                true
            }
            _ => false,
        }
    }

    /// Whether the user is revoked, at any time.
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

/// A user's public data on one node; the credentials are secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserNodePublic {
    /// The user's REALITY short id on the node.
    pub short_id: ShortId,
}

/// The share of a quota at which the operator is warned, 1..=99 percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct WarnPercent(u8);

impl WarnPercent {
    /// Accepts 1..=99.
    pub fn new(percent: u8) -> Result<Self, ModelError> {
        Self::checked(percent).ok_or(ModelError::InvalidWarnPercent { percent })
    }

    /// The share `percent` if it is 1..=99; usable in constants.
    pub(crate) const fn checked(percent: u8) -> Option<Self> {
        if matches!(percent, 1..=99) {
            Some(Self(percent))
        } else {
            None
        }
    }

    /// The percentage.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for WarnPercent {
    type Error = ModelError;

    fn try_from(percent: u8) -> Result<Self, Self::Error> {
        Self::new(percent)
    }
}

impl From<WarnPercent> for u8 {
    fn from(percent: WarnPercent) -> Self {
        percent.0
    }
}

/// What reaching a quota does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaAction {
    /// Only the operator is told.
    Warn,
    /// The user is suspended (`SuspendReason::QuotaExceeded`) by an explicit
    /// enforcement run, never by the export or the renderers.
    Suspend,
}

/// A per-user quota on the bytes served to the user in one SIM billing
/// cycle (proxied payload, both directions, every node).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserQuota {
    /// The quota per billing cycle, in served bytes.
    pub cycle_served_bytes: NonZeroU64,
    /// The share of the quota at which the operator is warned.
    pub warn_percent: WarnPercent,
    /// What reaching the quota does.
    pub action: QuotaAction,
}

/// A user's access policy. Every part is optional and off unless the
/// operator sets it, so [`UserPolicy::NONE`] is the only implicit value.
/// The expiry default is a pending operator decision; a quota set here
/// overrides the deployment's automatic quota
/// ([`crate::quota::AutoQuotaPolicy`], decision F4).
///
/// The policy is a record, not an enforcement point: exports and renders
/// look only at [`UserStatus`]. Moving an expired or over-quota user to
/// `Suspended` is an explicit operator or daemon action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPolicy {
    /// When the user's access expires, if it does. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub expires_at: Option<UnixTime>,
    /// This user's own quota, which overrides the automatic one; `None`:
    /// the automatic quota applies when automatic quotas are on and enough
    /// users are active, and otherwise there is no quota. The key is
    /// required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub quota: Option<UserQuota>,
}

impl UserPolicy {
    /// No expiry and no quota.
    pub const NONE: Self = Self {
        expires_at: None,
        quota: None,
    };
}

/// The revision of the user agreement a user accepted; revisions count
/// from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgreementVersion(NonZeroU16);

impl AgreementVersion {
    /// The revision of the user agreement (`docs/runbooks/user-agreement.md`)
    /// this build requires: `user export` refuses a user whose record is of
    /// another revision, or who has none (decision F9). A new revision of the
    /// text changes this constant in the same commit; the export crate's
    /// `agreement_text` test pins the text of this revision by its SHA-256,
    /// so an edit made without a new revision fails it.
    pub const CURRENT: Self = Self(NonZeroU16::MIN);

    /// The agreement revision `revision`.
    #[must_use]
    pub const fn new(revision: NonZeroU16) -> Self {
        Self(revision)
    }

    /// The revision number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for AgreementVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The acceptance a refusal names, when a user has none of the revision
/// required: none at all, or one of another revision. Every refusal for the
/// agreement (a user export's, the portal's) words it this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordedAgreement(pub Option<AgreementVersion>);

impl fmt::Display for RecordedAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("no acceptance is recorded"),
            Some(version) => write!(f, "the recorded acceptance is of revision {version}"),
        }
    }
}

/// That a user accepted a revision of the user agreement, and on which day
/// (a calendar day, never compared with a clock). Since decision F9
/// (2026-10-15) `user export` requires a record of
/// [`AgreementVersion::CURRENT`]. Mac-only, like the label: never rendered,
/// sent or exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreementRecord {
    /// The accepted revision.
    pub version: AgreementVersion,
    /// The day it was accepted.
    pub accepted_on: CalendarDate,
}

/// One user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// The opaque id; the only user identifier sent to a VPS.
    pub id: UserId,
    /// The Mac-only label; never exported or sent.
    pub label: LocalLabel,
    /// The user's client.
    pub client: ClientProfile,
    /// Lifecycle state.
    pub status: UserStatus,
    /// The nodes the user holds credentials on.
    pub per_node: BTreeMap<NodeId, UserNodePublic>,
    /// Expiry and quota.
    pub policy: UserPolicy,
    /// The randomly generated alias the user and the operator may quote
    /// instead of a name; unique among users. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub alias: Option<PublicAlias>,
    /// The agreement revision the user accepted, if recorded. The key is
    /// required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub agreement: Option<AgreementRecord>,
}

impl User {
    /// Whether the user is served on `node`: active and holding credentials there.
    #[must_use]
    pub fn is_served_on(&self, node: &NodeId) -> bool {
        self.status == UserStatus::Active && self.per_node.contains_key(node)
    }

    /// Whether the user accepted agreement revision `required`: a record of
    /// exactly that revision (decision F9). `Err` gives what is recorded
    /// instead, for the refusal to name. A user export, the portal snapshot
    /// and the portal bundle all check an acceptance with this one rule.
    pub fn accepted(&self, required: AgreementVersion) -> Result<(), RecordedAgreement> {
        match self.agreement {
            Some(record) if record.version == required => Ok(()),
            recorded => Err(RecordedAgreement(recorded.map(|record| record.version))),
        }
    }

    /// The nodes that still have to commit this user's revocation, in id
    /// order: every node holding credentials while `RevokePending`, and none
    /// otherwise.
    pub fn revocation_remaining(&self) -> impl Iterator<Item = &NodeId> {
        let pending = self.status == UserStatus::RevokePending;
        self.per_node.keys().filter(move |_| pending)
    }

    /// Suspends an active user (`UserNotActive` otherwise), keeping its
    /// credentials and their secrets.
    pub fn suspend(&mut self, reason: SuspendReason, since: UnixTime) -> Result<(), ModelError> {
        if self.status != UserStatus::Active {
            return Err(ModelError::UserNotActive {
                user: self.id.clone(),
            });
        }
        self.status = UserStatus::Suspended { reason, since };
        Ok(())
    }

    /// Resumes a suspended user (`UserNotSuspended` otherwise).
    pub fn resume(&mut self) -> Result<(), ModelError> {
        if !matches!(self.status, UserStatus::Suspended { .. }) {
            return Err(ModelError::UserNotSuspended {
                user: self.id.clone(),
            });
        }
        self.status = UserStatus::Active;
        Ok(())
    }

    /// Starts revoking an active or suspended user at `at`
    /// (`RevocationAlreadyStarted` otherwise): `RevokePending` on the nodes
    /// holding its credentials, or `Revoked` since `at` when none does.
    pub fn revoke(&mut self, at: UnixTime) -> Result<(), ModelError> {
        match self.status {
            UserStatus::Active | UserStatus::Suspended { .. } => {}
            UserStatus::RevokePending | UserStatus::Revoked { .. } => {
                return Err(ModelError::RevocationAlreadyStarted {
                    user: self.id.clone(),
                });
            }
        }
        self.status = if self.per_node.is_empty() {
            UserStatus::Revoked { since: at }
        } else {
            UserStatus::RevokePending
        };
        Ok(())
    }

    /// A user pending revocation with no node left to commit it becomes
    /// revoked at `at`; any other user is left as it is.
    pub(crate) fn settle_revocation(&mut self, at: UnixTime) {
        if self.status == UserStatus::RevokePending && self.per_node.is_empty() {
            self.status = UserStatus::Revoked { since: at };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        let short_id = UserNodePublic {
            short_id: ShortId::parse("5f1e000100000001").unwrap(),
        };
        User {
            id: UserId::parse("abcdefghij").unwrap(),
            label: LocalLabel::parse("User").unwrap(),
            client: ClientProfile {
                line: ClientLine::Cfm05,
                capabilities: BTreeSet::new(),
            },
            status: UserStatus::Active,
            per_node: ["lon1", "ams1"]
                .into_iter()
                .map(|node| (NodeId::parse(node).unwrap(), short_id))
                .collect(),
            policy: UserPolicy::NONE,
            alias: None,
            agreement: None,
        }
    }

    fn date(text: &str) -> CalendarDate {
        CalendarDate::parse(text).unwrap()
    }

    #[test]
    fn the_current_agreement_revision_is_the_first() {
        assert_eq!(AgreementVersion::CURRENT.get(), 1);
        assert_eq!(AgreementVersion::CURRENT.to_string(), "1");
        assert_eq!(
            AgreementVersion::new(NonZeroU16::new(12).unwrap()).to_string(),
            "12"
        );
    }

    /// An acceptance counts for exactly its revision; the refusal names
    /// what is recorded instead.
    #[test]
    fn an_acceptance_counts_for_exactly_its_revision() {
        let first = AgreementVersion::CURRENT;
        let second = AgreementVersion::new(NonZeroU16::new(first.get() + 1).unwrap());
        let mut user = user();
        assert_eq!(user.accepted(first), Err(RecordedAgreement(None)));
        user.agreement = Some(AgreementRecord {
            version: first,
            accepted_on: date("2026-10-20"),
        });
        assert_eq!(user.accepted(first), Ok(()));
        assert_eq!(user.accepted(second), Err(RecordedAgreement(Some(first))));
        assert_eq!(
            RecordedAgreement(None).to_string(),
            "no acceptance is recorded"
        );
        assert_eq!(
            RecordedAgreement(Some(first)).to_string(),
            format!("the recorded acceptance is of revision {first}")
        );
    }

    #[test]
    fn capability_support_by_line() {
        assert!(!ClientLine::Cfm04.accepts(Capability::RealityMlkemOptIn));
        assert!(ClientLine::Cfm05.accepts(Capability::RealityMlkemOptIn));
    }

    #[test]
    fn status_serde_is_closed() {
        let since = UnixTime::from_secs(1_791_417_600);
        for (status, json) in [
            (UserStatus::Active, "\"active\"".to_owned()),
            (UserStatus::RevokePending, "\"revoke_pending\"".to_owned()),
            (
                UserStatus::Revoked { since },
                r#"{"revoked":{"since":1791417600}}"#.to_owned(),
            ),
            (
                UserStatus::Suspended {
                    reason: SuspendReason::Operator,
                    since,
                },
                r#"{"suspended":{"reason":"operator","since":1791417600}}"#.to_owned(),
            ),
            (
                UserStatus::Suspended {
                    reason: SuspendReason::QuotaExceeded {
                        cycle_start: date("2026-10-01"),
                    },
                    since,
                },
                r#"{"suspended":{"reason":{"quota_exceeded":{"cycle_start":"2026-10-01"}},"since":1791417600}}"#.to_owned(),
            ),
            (
                UserStatus::Suspended {
                    reason: SuspendReason::Expired,
                    since,
                },
                r#"{"suspended":{"reason":"expired","since":1791417600}}"#.to_owned(),
            ),
            (
                UserStatus::Suspended {
                    reason: SuspendReason::AbuseReview,
                    since,
                },
                r#"{"suspended":{"reason":"abuse_review","since":1791417600}}"#.to_owned(),
            ),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<UserStatus>(&json).unwrap(), status);
        }
        // The pre-structural form carried a separate `remaining` list.
        assert!(
            serde_json::from_str::<UserStatus>(r#"{"revoke_pending":{"remaining":["lon1"]}}"#)
                .is_err()
        );
        for bad in [
            "\"suspended\"",
            r#"{"suspended":{"reason":"operator"}}"#,
            r#"{"suspended":{"since":1}}"#,
            r#"{"suspended":{"reason":"operator","since":1,"by":"me"}}"#,
            r#"{"suspended":{"reason":"quota_exceeded","since":1}}"#,
            r#"{"suspended":{"reason":{"quota_exceeded":{"cycle_start":"2026-10-01","bytes":1}},"since":1}}"#,
            r#"{"suspended":{"reason":"holiday","since":1}}"#,
            // Version 2's form, which kept no time, is a decode error: a
            // version-2 document lifts through its own types.
            "\"revoked\"",
            r#"{"revoked":{}}"#,
            r#"{"revoked":{"since":1,"by":"me"}}"#,
        ] {
            assert!(serde_json::from_str::<UserStatus>(bad).is_err(), "{bad}");
        }
        assert!(
            serde_json::from_str::<ClientProfile>(r#"{"line":"cfm06","capabilities":[]}"#).is_err()
        );
    }

    #[test]
    fn the_remaining_revocations_are_the_nodes_holding_credentials() {
        let mut user = user();
        assert_eq!(user.revocation_remaining().count(), 0);
        assert!(user.is_served_on(&NodeId::parse("lon1").unwrap()));
        user.status = UserStatus::RevokePending;
        let remaining: Vec<&str> = user.revocation_remaining().map(NodeId::as_str).collect();
        assert_eq!(remaining, ["ams1", "lon1"]);
        assert!(!user.is_served_on(&NodeId::parse("lon1").unwrap()));
    }

    /// The transition table the store enforces on configuration changes:
    /// every pair of statuses, against the steps `suspend`, `resume` and
    /// `revoke` take; and every step those methods take is in the table.
    #[test]
    fn a_status_changes_only_along_the_transitions() {
        let since = UnixTime::from_secs(1_791_417_600);
        let operator = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since,
        };
        let expired = UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since,
        };
        let later = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since: UnixTime::from_secs(since.as_secs() + 1),
        };
        let revoked = UserStatus::Revoked { since };
        let revoked_later = UserStatus::Revoked {
            since: UnixTime::from_secs(since.as_secs() + 1),
        };
        let all = [
            UserStatus::Active,
            operator,
            expired,
            later,
            UserStatus::RevokePending,
            revoked,
            revoked_later,
        ];
        let suspended = |status: UserStatus| matches!(status, UserStatus::Suspended { .. });
        for from in all {
            for to in all {
                let expected = from == to
                    || (from == UserStatus::Active && suspended(to))
                    || (suspended(from) && to == UserStatus::Active)
                    || ((from == UserStatus::Active || suspended(from))
                        && matches!(to, UserStatus::RevokePending | UserStatus::Revoked { .. }));
                assert_eq!(from.may_change_to(to), expected, "{from:?} -> {to:?}");
            }
            assert_eq!(
                from.is_revoked(),
                matches!(from, UserStatus::Revoked { .. }),
                "{from:?}"
            );
        }
        // A revocation's time is never edited.
        assert!(!revoked.may_change_to(revoked_later));
        // Every step the methods take is allowed.
        let mut held = user();
        let mut none = user();
        none.per_node.clear();
        for user in [&mut held, &mut none] {
            let start = user.status;
            user.suspend(SuspendReason::Expired, since).unwrap();
            assert!(start.may_change_to(user.status));
            let suspended = user.status;
            user.resume().unwrap();
            assert!(suspended.may_change_to(user.status));
            user.suspend(SuspendReason::AbuseReview, since).unwrap();
            let suspended = user.status;
            user.revoke(since).unwrap();
            assert!(suspended.may_change_to(user.status));
        }
        assert_eq!(held.status, UserStatus::RevokePending);
        assert_eq!(none.status, UserStatus::Revoked { since });
        let mut active = user();
        active.revoke(since).unwrap();
        assert!(UserStatus::Active.may_change_to(active.status));
    }

    /// Suspension keeps the credentials but serves the user nowhere; only a
    /// suspended user resumes; active and suspended users can be revoked.
    #[test]
    fn suspension_resumption_and_revocation_follow_the_transitions() {
        let since = UnixTime::from_secs(1_791_417_600);
        let lon1 = NodeId::parse("lon1").unwrap();
        let mut user = user();
        let held = user.per_node.clone();
        user.suspend(SuspendReason::AbuseReview, since).unwrap();
        assert_eq!(
            user.status,
            UserStatus::Suspended {
                reason: SuspendReason::AbuseReview,
                since
            }
        );
        assert_eq!(user.per_node, held, "suspension keeps the credentials");
        assert!(!user.is_served_on(&lon1));
        assert_eq!(user.revocation_remaining().count(), 0);
        assert_eq!(
            user.suspend(SuspendReason::Operator, since),
            Err(ModelError::UserNotActive {
                user: user.id.clone()
            })
        );
        user.resume().unwrap();
        assert_eq!(user.status, UserStatus::Active);
        assert!(user.is_served_on(&lon1));
        assert_eq!(
            user.resume(),
            Err(ModelError::UserNotSuspended {
                user: user.id.clone()
            })
        );

        // A suspended user can be revoked; revocation never goes back.
        user.suspend(SuspendReason::Expired, since).unwrap();
        user.revoke(since).unwrap();
        assert_eq!(user.status, UserStatus::RevokePending);
        assert_eq!(user.per_node, held);
        assert_eq!(
            user.clone().revoke(since),
            Err(ModelError::RevocationAlreadyStarted {
                user: user.id.clone()
            })
        );
        assert_eq!(
            user.clone().resume(),
            Err(ModelError::UserNotSuspended {
                user: user.id.clone()
            })
        );
        assert_eq!(
            user.clone().suspend(SuspendReason::Operator, since),
            Err(ModelError::UserNotActive {
                user: user.id.clone()
            })
        );
        // The last node's commit settles the revocation at its time.
        let settled = UnixTime::from_secs(since.as_secs() + 600);
        user.settle_revocation(settled);
        assert_eq!(user.status, UserStatus::RevokePending, "nodes are left");
        user.per_node.clear();
        user.settle_revocation(settled);
        assert_eq!(user.status, UserStatus::Revoked { since: settled });
        user.settle_revocation(UnixTime::from_secs(settled.as_secs() + 1));
        assert_eq!(
            user.status,
            UserStatus::Revoked { since: settled },
            "a revoked user keeps the time it was revoked"
        );
        assert_eq!(
            user.clone().revoke(since),
            Err(ModelError::RevocationAlreadyStarted {
                user: user.id.clone()
            })
        );

        // An active user holding no credentials is revoked at once.
        let mut bare = self::user();
        bare.per_node.clear();
        bare.revoke(settled).unwrap();
        assert_eq!(bare.status, UserStatus::Revoked { since: settled });
        // An active user is never settled.
        let mut active = self::user();
        active.per_node.clear();
        active.settle_revocation(settled);
        assert_eq!(active.status, UserStatus::Active);
    }

    #[test]
    fn policy_alias_and_agreement_keys_are_required() {
        let mut full = user();
        full.policy = UserPolicy {
            expires_at: Some(UnixTime::from_secs(1_800_000_000)),
            quota: Some(UserQuota {
                cycle_served_bytes: NonZeroU64::new(40_000_000_000).unwrap(),
                warn_percent: WarnPercent::new(80).unwrap(),
                action: QuotaAction::Suspend,
            }),
        };
        full.alias = Some(PublicAlias::parse("k7qd-m2xa").unwrap());
        full.agreement = Some(AgreementRecord {
            version: AgreementVersion::new(NonZeroU16::new(1).unwrap()),
            accepted_on: date("2026-10-08"),
        });
        let json = serde_json::to_string(&full).unwrap();
        assert!(json.ends_with(
            r#""policy":{"expires_at":1800000000,"quota":{"cycle_served_bytes":40000000000,"warn_percent":80,"action":"suspend"}},"alias":"k7qd-m2xa","agreement":{"version":1,"accepted_on":"2026-10-08"}}"#
        ), "{json}");
        assert_eq!(serde_json::from_str::<User>(&json).unwrap(), full);
        let bare = serde_json::to_string(&user()).unwrap();
        assert!(bare.ends_with(
            r#""policy":{"expires_at":null,"quota":null},"alias":null,"agreement":null}"#
        ));
        assert_eq!(serde_json::from_str::<User>(&bare).unwrap(), user());
        for missing in [
            bare.replace(r#","alias":null"#, ""),
            bare.replace(r#","agreement":null"#, ""),
            bare.replace(r#""expires_at":null,"#, ""),
            bare.replace(r#","quota":null"#, ""),
            bare.replace(r#","policy":{"expires_at":null,"quota":null}"#, ""),
        ] {
            assert!(serde_json::from_str::<User>(&missing).is_err(), "{missing}");
        }
        for bad in [
            json.replace(r#""warn_percent":80"#, r#""warn_percent":0"#),
            json.replace(r#""warn_percent":80"#, r#""warn_percent":100"#),
            json.replace(
                r#""cycle_served_bytes":40000000000"#,
                r#""cycle_served_bytes":0"#,
            ),
            json.replace(r#""action":"suspend""#, r#""action":"revoke""#),
            json.replace(r#""version":1"#, r#""version":0"#),
            json.replace(
                r#""accepted_on":"2026-10-08""#,
                r#""accepted_on":1791417600"#,
            ),
            json.replace(r#""alias":"k7qd-m2xa""#, r#""alias":"Alice""#),
            json.replace(r#""quota":{"#, r#""quota":{"extra":1,"#),
        ] {
            assert!(serde_json::from_str::<User>(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn warn_percent_bounds() {
        for bad in [0, 100, 255] {
            assert_eq!(
                WarnPercent::new(bad),
                Err(ModelError::InvalidWarnPercent { percent: bad })
            );
        }
        assert_eq!(WarnPercent::new(1).unwrap().get(), 1);
        assert_eq!(WarnPercent::new(99).unwrap().get(), 99);
        assert_eq!(AgreementVersion::new(NonZeroU16::new(3).unwrap()).get(), 3);
        assert_eq!(QuotaAction::Warn, serde_json::from_str("\"warn\"").unwrap());
    }
}
