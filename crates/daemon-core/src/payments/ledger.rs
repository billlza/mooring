// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment ledger (design §9.6): `payments/ledger.json`, the daemon's
//! record of what the portal listed and what Mooring did about it.
//!
//! It holds the cursor and every order the portal named, with the grant,
//! refunds and dispute that named it, so that one write keeps the cursor
//! and everything a page did together (contract §5.1).
//! [`PaymentLedger::apply`] applies a page to a copy, which the daemon
//! writes and only then keeps.
//!
//! # Rules
//!
//! - **Once per order** (contract §5.2). A grant of an order granted
//!   already is skipped, whatever its number; a refund again with the same
//!   cumulative amount and in-full flag, and a dispute again with the same
//!   amount, too. An entry that gives a recorded order other terms or the
//!   other Stripe mode, a dispute of another amount, or a grant of an order
//!   known only from a refund or dispute contradicts the portal's
//!   guarantees: the whole page is refused ([`ApplyRefusal::Contradicted`]).
//! - **Grants** are computed once, at `now`, and recorded: a service period
//!   from the later of `now` and the user's paid expiry before it, or a
//!   traffic pack at `now` (design §9.6). A grant for a user the deployment
//!   does not hold, or one being revoked, is held, not granted, and the
//!   cursor moves past it.
//! - **Refunds and disputes** are recorded. The first refund in full of a
//!   granted order takes back what the order gave that the user had not
//!   used yet ([`super::refund`]; the operator's decision of 2026-11-12).
//!   The time taken back follows from the grants and refunds
//!   ([`PaymentLedger::take_backs`]). A pack's refund waits for the usage
//!   ([`PackUse::Awaiting`]) until [`PaymentLedger::settle`] records the
//!   user's use at its time, or that the pack's cycle ended first. Nothing
//!   else of either changes anything.
//! - **Test mode** (contract §5.3): a page of Stripe's test mode is applied
//!   only while the operator rehearses ([`ApplyRefusal::TestMode`]), and its
//!   grants count only while the rehearsal lasts ([`Entitlements`]).

use std::collections::{BTreeMap, BTreeSet};

use mooring_model::date::SECS_PER_DAY;
use mooring_model::user::SuspendReason;
use mooring_model::{CalendarDate, Deployment, UnixTime, User, UserId, UserStatus};
use serde::{Deserialize, Serialize};

use super::entitlement::{Entitlements, PackRefund, PaidPack, PaidPeriod};
use super::error::{ApplyRefusal, Contradiction, LedgerError};
use super::feed::{EntryEvent, FeedEntry, FeedPage, OrderTerms};
use super::ids::OrderId;
use super::refund::{PackUse, RefundEffect, TakeBacks, pack_taken_back};
use crate::period::BillingCycle;

mod v1;
mod v2;

/// The ledger's version: 3 since a refunded pack waits for the usage
/// (2026-11-12): a pack's use carries when Mooring learned it, and one not
/// learned yet is recorded as waited for. Versions 1 and 2 are read and
/// lifted.
pub const LEDGER_VERSION: u32 = 3;

/// The largest ledger written or read, in bytes. An order takes about
/// 700 bytes, so this holds thousands of orders.
pub const MAX_LEDGER_BYTES: usize = 4 << 20;

/// Why the pull stopped until the operator changes its settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// 409: the cursor is past the portal's journal, which is then not the
    /// one pulled before.
    Conflict,
    /// 401: the token is wrong, or unset at the portal.
    Unauthorized,
    /// 400: the portal says Mooring's request is malformed.
    BadRequest,
    /// An entry contradicted the ledger ([`ApplyRefusal::Contradicted`]).
    Inconsistent,
}

impl StopReason {
    /// The reason as the ledger writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::BadRequest => "bad_request",
            Self::Inconsistent => "inconsistent",
        }
    }
}

/// A stop in force: until the pull's settings change from the revision it
/// was made under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    /// Why.
    pub reason: StopReason,
    /// When.
    pub at: UnixTime,
    /// The revision of the settings in force then.
    pub settings_revision: u64,
}

/// Why a grant was held rather than granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldReason {
    /// The deployment holds no user of the order's user id.
    UnknownUser,
    /// The user is being revoked or is revoked.
    UserRevoked,
    /// The service period would end after 9999-12-31.
    BeyondCalendar,
}

impl HeldReason {
    /// The reason as the ledger writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownUser => "unknown_user",
            Self::UserRevoked => "user_revoked",
            Self::BeyondCalendar => "beyond_calendar",
        }
    }
}

/// What a grant gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantOutcome {
    /// Service from `from` until `until` (`month`, `month_auto`).
    Period {
        /// The period's first instant.
        from: UnixTime,
        /// The instant after its last.
        until: UnixTime,
    },
    /// A traffic pack, granted at the grant's `applied_at` (`traffic`).
    Pack,
    /// Nothing: the grant was held.
    Held {
        /// Why.
        reason: HeldReason,
    },
}

/// A grant entry and what Mooring did about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    /// The entry's number.
    pub seq: u64,
    /// When the portal wrote the entry.
    pub recorded_at: UnixTime,
    /// When Mooring applied it.
    pub applied_at: UnixTime,
    /// What it gave.
    pub outcome: GrantOutcome,
}

/// A refund entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundRecord {
    /// The entry's number.
    pub seq: u64,
    /// Everything refunded so far, in the currency's hundredths.
    pub amount_refunded: u64,
    /// Whether Stripe says that is all of the payment.
    pub refunded_in_full: bool,
    /// When the portal wrote the entry.
    pub recorded_at: UnixTime,
    /// When Mooring recorded it.
    pub applied_at: UnixTime,
    /// On the refund that takes a granted traffic pack back (the order's
    /// first in full), what Mooring knows of the user's use at its time;
    /// `None` on every other refund. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pack_use: Option<PackUse>,
}

/// A dispute entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeRecord {
    /// The entry's number.
    pub seq: u64,
    /// The amount disputed.
    pub amount_disputed: u64,
    /// When the portal wrote the entry.
    pub recorded_at: UnixTime,
    /// When Mooring recorded it.
    pub applied_at: UnixTime,
}

/// One order the portal named, and every entry that named it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderRecord {
    /// The order.
    pub order: OrderId,
    /// Its terms.
    pub terms: OrderTerms,
    /// Whether it was paid in Stripe's live mode.
    pub livemode: bool,
    /// Its grant; `None` for an order known only from a refund or dispute.
    /// The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub grant: Option<GrantRecord>,
    /// Its refunds, each cumulative amount and flag once, in their order.
    pub refunds: Vec<RefundRecord>,
    /// Its dispute. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub dispute: Option<DisputeRecord>,
}

impl OrderRecord {
    fn new(order: OrderId, terms: OrderTerms, livemode: bool) -> Self {
        Self {
            order,
            terms,
            livemode,
            grant: None,
            refunds: Vec::new(),
            dispute: None,
        }
    }

    /// Whether Mooring granted the order: its grant gave a period or a
    /// pack. A grant held, or none known, is not.
    #[must_use]
    pub fn granted(&self) -> bool {
        matches!(
            self.grant.map(|grant| grant.outcome),
            Some(GrantOutcome::Period { .. } | GrantOutcome::Pack)
        )
    }

    /// The order's first refund in full, the one that takes back what the
    /// order gave, if any.
    #[must_use]
    pub fn first_refund_in_full(&self) -> Option<&RefundRecord> {
        self.refunds.iter().find(|refund| refund.refunded_in_full)
    }

    /// Whether the order counts: always when paid in live mode, and while
    /// the operator rehearses when paid in test mode.
    const fn counts(&self, rehearsal: bool) -> bool {
        self.livemode || rehearsal
    }
}

/// The version of a document on disk, read first to choose its shape.
#[derive(Debug, Deserialize)]
struct Version {
    version: u32,
}

/// The document on disk, as read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    /// [`LEDGER_VERSION`], read first ([`Version`]).
    #[serde(rename = "version")]
    _version: u32,
    cursor: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pulled_at: Option<UnixTime>,
    #[serde(deserialize_with = "Option::deserialize")]
    stopped: Option<Stop>,
    orders: Vec<OrderRecord>,
}

/// The document on disk, as written: [`LedgerFile`]'s keys in its order.
#[derive(Debug, Serialize)]
struct LedgerFileRef<'a> {
    version: u32,
    cursor: u64,
    pulled_at: Option<UnixTime>,
    stopped: Option<Stop>,
    orders: Vec<&'a OrderRecord>,
}

/// The ledger as its file holds it.
impl Serialize for PaymentLedger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        LedgerFileRef {
            version: LEDGER_VERSION,
            cursor: self.cursor,
            pulled_at: self.pulled_at,
            stopped: self.stopped,
            orders: self.orders.values().collect(),
        }
        .serialize(serializer)
    }
}

/// What one entry of an applied page did, for the daemon's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerEvent {
    /// An order was granted.
    Granted {
        /// The order.
        order: OrderId,
        /// The user.
        user: UserId,
        /// The period or the pack.
        outcome: GrantOutcome,
        /// Whether it was paid in Stripe's live mode.
        livemode: bool,
        /// Why the user is suspended, if they are: the apply job resumes a
        /// suspension at expiry once the user's paid time runs past its
        /// run, and one for quota once the user's quota covers what they
        /// used this cycle, or in the next billing cycle; only the operator
        /// lifts the others (design §13.6).
        suspended: Option<SuspendReason>,
    },
    /// A grant was held.
    Held {
        /// The order.
        order: OrderId,
        /// The user id it names.
        user: UserId,
        /// Why.
        reason: HeldReason,
    },
    /// A refund was recorded. The daemon's log names the order only: a
    /// line can outlive the 13 months the agreement keeps a user's records.
    Refunded {
        /// The order.
        order: OrderId,
        /// Everything refunded so far.
        amount_refunded: u64,
        /// Whether that is all of the payment.
        in_full: bool,
        /// Whether Mooring granted the order ([`OrderRecord::granted`]).
        granted: bool,
        /// What it took back.
        effect: RefundEffect,
    },
    /// A dispute was recorded; it changes nothing.
    Disputed {
        /// The order.
        order: OrderId,
        /// The user.
        user: UserId,
        /// The amount disputed.
        amount_disputed: u64,
        /// Whether Mooring granted the order ([`OrderRecord::granted`]).
        granted: bool,
    },
    /// An entry the ledger holds already was skipped.
    Repeated {
        /// The entry's number.
        seq: u64,
        /// The order.
        order: OrderId,
    },
    /// A refund in full that waited for the usage waits no more
    /// ([`PaymentLedger::settle`]). As a refund's, its line names the
    /// order only.
    Settled {
        /// The order.
        order: OrderId,
        /// What was learned: the user's use at the refund's time, or that
        /// the pack's billing cycle ended first.
        used: PackUse,
    },
}

/// A page applied to a copy of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The ledger to write, with the page's cursor.
    pub ledger: PaymentLedger,
    /// What each entry did, in order.
    pub events: Vec<LedgerEvent>,
}

/// What [`PaymentLedger::settle`] recorded on a copy of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The ledger to write.
    pub ledger: PaymentLedger,
    /// What was learned of each refund that waited, in the order of their
    /// orders' ids.
    pub events: Vec<LedgerEvent>,
}

/// What [`PaymentLedger::without_removed_users`] took out, by count: the
/// daemon's log names no removed user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pruned {
    /// The removed users whose orders went.
    pub users: usize,
    /// The orders that went.
    pub orders: usize,
}

/// The payment ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaymentLedger {
    cursor: u64,
    pulled_at: Option<UnixTime>,
    stopped: Option<Stop>,
    orders: BTreeMap<OrderId, OrderRecord>,
}

impl PaymentLedger {
    /// The ledger before the first pull: cursor 0, no order.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a ledger the daemon wrote, of this version or an earlier one,
    /// which is lifted: a refund that takes a pack back and whose use was
    /// not recorded (version 1) or not known (version 2) waits for the
    /// usage ([`PackUse::Awaiting`]), and a use version 2 recorded was
    /// learned when its refund was applied. Besides its shape and version,
    /// orders are in id order and each once, every recorded entry is at or
    /// below the cursor, a grant's number is below its refunds' and
    /// dispute's, a period ends after it starts and within the calendar, a
    /// period or pack is of an order of its kind, each refund's amount and
    /// flag are recorded once, a pack's use is recorded on the refund that
    /// takes a granted pack back and on no other, and it was learned no
    /// earlier than that refund was applied.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(LedgerError::TooLarge);
        }
        let Version { version } = serde_json::from_slice(bytes).map_err(LedgerError::Decode)?;
        let file = match version {
            LEDGER_VERSION => {
                serde_json::from_slice::<LedgerFile>(bytes).map_err(LedgerError::Decode)?
            }
            v2::VERSION => serde_json::from_slice::<v2::LedgerFile>(bytes)
                .map_err(LedgerError::Decode)?
                .lift(),
            v1::VERSION => serde_json::from_slice::<v1::LedgerFile>(bytes)
                .map_err(LedgerError::Decode)?
                .lift()
                .lift(),
            found => return Err(LedgerError::UnknownVersion { found }),
        };
        let mut orders = BTreeMap::new();
        for record in file.orders {
            if orders
                .last_key_value()
                .is_some_and(|(last, _): (&OrderId, _)| *last >= record.order)
            {
                return Err(inconsistent("orders are not in id order, each once"));
            }
            check_record(&record, file.cursor)?;
            orders.insert(record.order.clone(), record);
        }
        Ok(Self {
            cursor: file.cursor,
            pulled_at: file.pulled_at,
            stopped: file.stopped,
            orders,
        })
    }

    /// The document to write: pretty-printed JSON with a trailing newline,
    /// orders in id order. `TooLarge` past [`MAX_LEDGER_BYTES`], which this
    /// build would refuse to read back.
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(LedgerError::Encode)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(LedgerError::TooLarge);
        }
        Ok(bytes)
    }

    /// The number of the last entry acted on.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// When the last page was applied.
    #[must_use]
    pub const fn pulled_at(&self) -> Option<UnixTime> {
        self.pulled_at
    }

    /// The stop in force, if any.
    #[must_use]
    pub const fn stopped(&self) -> Option<Stop> {
        self.stopped
    }

    /// Every order, in id order.
    #[must_use]
    pub const fn orders(&self) -> &BTreeMap<OrderId, OrderRecord> {
        &self.orders
    }

    /// A copy without the orders of users removed from `deployment`, or
    /// `None` when it has none (design §9.6; the agreement's clause 4: a
    /// user's payment records go 13 months after the revocation, or at once
    /// on the user's request). An order goes when the deployment no longer
    /// holds its user and either keeps the user's bare id (a removal at the
    /// user's request) or the ledger granted the order, or held it while
    /// the user was being revoked or beyond the calendar: the user was the
    /// deployment's then, so it has been removed since. An order held for
    /// an id the deployment never held (`unknown_user`), or known only from
    /// a refund or dispute, stays unless the id is kept: nothing tells it
    /// apart from an order the portal sent for a user Mooring never had,
    /// which the operator settles at Stripe. The cursor, the last pull and
    /// the stop stay. Dropping an order forgets that it was granted, which
    /// matters only if the portal sent it again, which it does only after
    /// its journal was rewound (contract §5.1).
    #[must_use]
    pub fn without_removed_users(&self, deployment: &Deployment) -> Option<(Self, Pruned)> {
        let removed = |record: &OrderRecord| {
            let user = &record.terms.user;
            !deployment.users().contains_key(user)
                && (deployment.forgotten().contains_key(user)
                    || record.grant.is_some_and(|grant| {
                        grant.outcome
                            != (GrantOutcome::Held {
                                reason: HeldReason::UnknownUser,
                            })
                    }))
        };
        let gone: Vec<&OrderRecord> = self
            .orders
            .values()
            .filter(|record| removed(record))
            .collect();
        if gone.is_empty() {
            return None;
        }
        let users: BTreeSet<&UserId> = gone.iter().map(|record| &record.terms.user).collect();
        let pruned = Pruned {
            users: users.len(),
            orders: gone.len(),
        };
        let mut next = self.clone();
        next.orders.retain(|_, record| !removed(record));
        Some((next, pruned))
    }

    /// A copy with `stop` in force (or none), and nothing else changed.
    #[must_use]
    pub fn with_stop(&self, stop: Option<Stop>) -> Self {
        Self {
            stopped: stop,
            ..self.clone()
        }
    }

    /// Applies `page`, which follows the ledger's cursor, to a copy at
    /// `now`, for the deployment's `users`; `rehearsal` when the operator
    /// rehearses. A refund in full of a pack is recorded as waiting for the
    /// usage ([`PackUse::Awaiting`]), which [`Self::settle`] ends. The copy
    /// has the page's cursor, `now` as its last pull and no stop.
    pub fn apply(
        &self,
        page: &FeedPage,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
        rehearsal: bool,
    ) -> Result<Applied, ApplyRefusal> {
        if !page.livemode() && !rehearsal {
            return Err(ApplyRefusal::TestMode);
        }
        if page.after() != self.cursor {
            return Err(ApplyRefusal::CursorMoved {
                after: page.after(),
                cursor: self.cursor,
            });
        }
        let mut next = self.clone();
        let mut events = Vec::with_capacity(page.entries().len());
        for entry in page.entries() {
            let event = next
                .apply_entry(entry, page.livemode(), users, now)
                .map_err(|contradiction| ApplyRefusal::Contradicted {
                    seq: entry.seq,
                    order: entry.order.clone(),
                    contradiction,
                })?;
            events.push(event);
        }
        next.cursor = page.next();
        next.pulled_at = Some(now);
        next.stopped = None;
        Ok(Applied {
            ledger: next,
            events,
        })
    }

    /// What the orders that count give each user: every order paid in live
    /// mode, and while the operator rehearses (`rehearsal`) those paid in
    /// test mode too. A period counts as the refunds in full leave it
    /// ([`Self::take_backs`]), and a pack refunded in full carries its
    /// refund.
    #[must_use]
    pub fn entitlements(&self, rehearsal: bool) -> Entitlements {
        let take_backs = self.take_backs();
        let mut entitlements = Entitlements::default();
        for record in self.orders.values() {
            if !record.counts(rehearsal) {
                continue;
            }
            let Some(grant) = record.grant else {
                continue;
            };
            let user = record.terms.user.clone();
            match grant.outcome {
                GrantOutcome::Period { .. } => {
                    if let Some((from, until)) = take_backs.period(record) {
                        entitlements.add_period(
                            user,
                            PaidPeriod {
                                order: record.order.clone(),
                                from,
                                until,
                                quota_bytes: record.terms.traffic_bytes,
                                livemode: record.livemode,
                            },
                        );
                    }
                }
                GrantOutcome::Pack => entitlements.add_pack(
                    user,
                    PaidPack {
                        order: record.order.clone(),
                        granted_at: grant.applied_at,
                        bytes: record.terms.traffic_bytes,
                        livemode: record.livemode,
                        refund: record.first_refund_in_full().and_then(|refund| {
                            pack_taken_back(record).map(|used| PackRefund {
                                at: refund.recorded_at,
                                used,
                            })
                        }),
                    },
                ),
                GrantOutcome::Held { .. } => {}
            }
        }
        entitlements
    }

    /// The orders whose refund in full waits for the usage
    /// ([`PackUse::Awaiting`]), in id order.
    pub fn awaiting_usage(&self) -> impl Iterator<Item = &OrderRecord> {
        self.orders
            .values()
            .filter(|record| pack_taken_back(record) == Some(PackUse::Awaiting))
    }

    /// Records on a copy what can be told at `now` of the packs whose
    /// refund in full waits for the usage (design §9.6); `None` when
    /// nothing can. `cycle` is the billing cycle `now` is in, and
    /// `served_before` tells the bytes the nodes had counted for a user
    /// in it before an instant, at most (never fewer than they had
    /// counted), or `None` while the usage cannot tell: it is behind, it
    /// does not reach the instant, or it has no figure for the user.
    ///
    /// - A pack of `cycle` whose user's use at the refund's time
    ///   `served_before` tells: the use is recorded as learned at `now`
    ///   (or when the refund was applied, were that later: a clock that
    ///   stepped back), and from then on the pack counts only what the
    ///   user had used of it ([`PackUse::Served`]).
    /// - A pack of an earlier cycle: its cycle has ended, and nothing of
    ///   it is taken back ([`PackUse::CycleEnded`]). The usage is not
    ///   asked.
    /// - Every other one waits on, and its pack counts in full.
    #[must_use]
    pub fn settle(
        &self,
        now: UnixTime,
        cycle: BillingCycle,
        served_before: &dyn Fn(&UserId, UnixTime) -> Option<u64>,
    ) -> Option<Settlement> {
        let mut next = self.clone();
        let mut events = Vec::new();
        for record in next.orders.values_mut() {
            let Some(grant) = record
                .grant
                .filter(|grant| grant.outcome == GrantOutcome::Pack)
            else {
                continue;
            };
            let Some(refund) = record
                .refunds
                .iter_mut()
                .find(|refund| refund.refunded_in_full)
                .filter(|refund| refund.pack_use == Some(PackUse::Awaiting))
            else {
                continue;
            };
            let used = if grant.applied_at < cycle.starts_at() {
                PackUse::CycleEnded
            } else if cycle.contains(grant.applied_at) {
                match served_before(&record.terms.user, refund.recorded_at) {
                    Some(bytes) => PackUse::Served {
                        bytes,
                        learned_at: now.max(refund.applied_at),
                    },
                    None => continue,
                }
            } else {
                continue;
            };
            refund.pack_use = Some(used);
            events.push(LedgerEvent::Settled {
                order: record.order.clone(),
                used,
            });
        }
        (!events.is_empty()).then_some(Settlement {
            ledger: next,
            events,
        })
    }

    /// What the refunds in full took back: each period as it counts, and
    /// what each refund did (design §9.6).
    #[must_use]
    pub fn take_backs(&self) -> TakeBacks {
        TakeBacks::of(self.orders.values())
    }

    /// [`Self::take_backs`] for `user`'s orders alone, which is all a
    /// refund of theirs reaches: a period follows only its own user's.
    fn take_backs_of(&self, user: &UserId) -> TakeBacks {
        TakeBacks::of(
            self.orders
                .values()
                .filter(|record| record.terms.user == *user),
        )
    }

    fn apply_entry(
        &mut self,
        entry: &FeedEntry,
        livemode: bool,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
    ) -> Result<LedgerEvent, Contradiction> {
        if let Some(record) = self.orders.get(&entry.order) {
            if record.terms != entry.terms {
                return Err(Contradiction::TermsDiffer);
            }
            if record.livemode != livemode {
                return Err(Contradiction::ModeDiffers);
            }
        }
        match entry.event {
            EntryEvent::Grant => self.grant(entry, livemode, users, now),
            EntryEvent::Refund {
                amount_refunded,
                in_full,
            } => {
                let record = self.record_of(entry, livemode);
                let granted = record.granted();
                let order = record.order.clone();
                let user = record.terms.user.clone();
                let repeated = record.refunds.iter().any(|refund| {
                    refund.amount_refunded == amount_refunded && refund.refunded_in_full == in_full
                });
                if repeated {
                    return Ok(LedgerEvent::Repeated {
                        seq: entry.seq,
                        order,
                    });
                }
                let takes_back = in_full && record.first_refund_in_full().is_none();
                let takes_pack_back = takes_back
                    && record
                        .grant
                        .is_some_and(|grant| grant.outcome == GrantOutcome::Pack);
                let pack_use = takes_pack_back.then_some(PackUse::Awaiting);
                record.refunds.push(RefundRecord {
                    seq: entry.seq,
                    amount_refunded,
                    refunded_in_full: in_full,
                    recorded_at: entry.recorded_at,
                    applied_at: now,
                    pack_use,
                });
                Ok(LedgerEvent::Refunded {
                    order,
                    amount_refunded,
                    in_full,
                    granted,
                    effect: self.take_backs_of(&user).effect(entry.seq),
                })
            }
            EntryEvent::Dispute { amount_disputed } => {
                let record = self.record_of(entry, livemode);
                let granted = record.granted();
                let user = record.terms.user.clone();
                let order = record.order.clone();
                match record.dispute {
                    Some(dispute) if dispute.amount_disputed == amount_disputed => {
                        Ok(LedgerEvent::Repeated {
                            seq: entry.seq,
                            order,
                        })
                    }
                    Some(_) => Err(Contradiction::SecondDispute),
                    None => {
                        record.dispute = Some(DisputeRecord {
                            seq: entry.seq,
                            amount_disputed,
                            recorded_at: entry.recorded_at,
                            applied_at: now,
                        });
                        Ok(LedgerEvent::Disputed {
                            order,
                            user,
                            amount_disputed,
                            granted,
                        })
                    }
                }
            }
        }
    }

    /// The record of a refund's or dispute's order, made from the entry
    /// when the ledger holds none. A recorded grant is never numbered after
    /// the entry: the entry follows the cursor, and the cursor every entry
    /// recorded.
    fn record_of(&mut self, entry: &FeedEntry, livemode: bool) -> &mut OrderRecord {
        self.orders
            .entry(entry.order.clone())
            .or_insert_with(|| OrderRecord::new(entry.order.clone(), entry.terms.clone(), livemode))
    }

    fn grant(
        &mut self,
        entry: &FeedEntry,
        livemode: bool,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
    ) -> Result<LedgerEvent, Contradiction> {
        if let Some(record) = self.orders.get(&entry.order) {
            return match record.grant {
                Some(_) => Ok(LedgerEvent::Repeated {
                    seq: entry.seq,
                    order: entry.order.clone(),
                }),
                None => Err(Contradiction::GrantAfterOtherEntries),
            };
        }
        let terms = &entry.terms;
        let (outcome, suspended) = match users.get(&terms.user) {
            None => (
                GrantOutcome::Held {
                    reason: HeldReason::UnknownUser,
                },
                None,
            ),
            Some(user) => match user.status {
                UserStatus::RevokePending | UserStatus::Revoked { .. } => (
                    GrantOutcome::Held {
                        reason: HeldReason::UserRevoked,
                    },
                    None,
                ),
                UserStatus::Active => (self.outcome_for(user, terms, livemode, now), None),
                UserStatus::Suspended { reason, .. } => {
                    (self.outcome_for(user, terms, livemode, now), Some(reason))
                }
            },
        };
        let mut record = OrderRecord::new(entry.order.clone(), terms.clone(), livemode);
        record.grant = Some(GrantRecord {
            seq: entry.seq,
            recorded_at: entry.recorded_at,
            applied_at: now,
            outcome,
        });
        self.orders.insert(entry.order.clone(), record);
        Ok(match outcome {
            GrantOutcome::Held { reason } => LedgerEvent::Held {
                order: entry.order.clone(),
                user: terms.user.clone(),
                reason,
            },
            GrantOutcome::Period { .. } | GrantOutcome::Pack => LedgerEvent::Granted {
                order: entry.order.clone(),
                user: terms.user.clone(),
                outcome,
                livemode,
                suspended,
            },
        })
    }

    /// What a grant of `terms` gives `user` at `now`: a traffic pack, or a
    /// service period from the later of `now` and the user's paid expiry
    /// before it ([`Self::paid_expiry`]), held when it would end after
    /// 9999-12-31.
    fn outcome_for(
        &self,
        user: &User,
        terms: &OrderTerms,
        livemode: bool,
        now: UnixTime,
    ) -> GrantOutcome {
        if !terms.plan_kind.buys_service() {
            return GrantOutcome::Pack;
        }
        let from = self
            .paid_expiry(user, livemode)
            .map_or(now, |expiry| expiry.max(now));
        let until = u64::from(terms.days.get())
            .checked_mul(SECS_PER_DAY)
            .and_then(|length| from.checked_add_secs(length))
            .filter(|until| CalendarDate::utc_of(*until).is_ok());
        match until {
            Some(until) => GrantOutcome::Period { from, until },
            None => GrantOutcome::Held {
                reason: HeldReason::BeyondCalendar,
            },
        }
    }

    /// The expiry a new period of `user` follows: without a period that a
    /// grant of this mode builds on, the user's own record
    /// (`UserPolicy::expires_at`); with one, the later of its end, as the
    /// refunds in full leave it, and the record. A live grant builds on
    /// live periods only, so a rehearsal never moves real time; a test-mode
    /// grant builds on every period.
    fn paid_expiry(&self, user: &User, livemode: bool) -> Option<UnixTime> {
        let take_backs = self.take_backs_of(&user.id);
        let last_end = self
            .orders
            .values()
            .filter(|record| record.terms.user == user.id && (record.livemode || !livemode))
            .filter_map(|record| take_backs.period(record))
            .map(|(_, until)| until)
            .max();
        match (last_end, user.policy.expires_at) {
            (None, record) => record,
            (Some(end), Some(record)) => Some(end.max(record)),
            (Some(end), None) => Some(end),
        }
    }
}

fn inconsistent(what: &'static str) -> LedgerError {
    LedgerError::Inconsistent { what }
}

/// The rules one recorded order keeps (see [`PaymentLedger::decode`]).
fn check_record(record: &OrderRecord, cursor: u64) -> Result<(), LedgerError> {
    let grant_seq = record.grant.map(|grant| grant.seq);
    let mut seqs: Vec<u64> = grant_seq.into_iter().collect();
    seqs.extend(record.refunds.iter().map(|refund| refund.seq));
    seqs.extend(record.dispute.iter().map(|dispute| dispute.seq));
    if seqs.iter().any(|&seq| seq == 0 || seq > cursor) {
        return Err(inconsistent("an entry is numbered 0 or after the cursor"));
    }
    if let Some(granted) = grant_seq
        && seqs.iter().skip(1).any(|&seq| seq <= granted)
    {
        return Err(inconsistent("a refund or dispute comes before its grant"));
    }
    if let Some(grant) = record.grant {
        let kind = record.terms.plan_kind;
        match grant.outcome {
            GrantOutcome::Period { from, until } => {
                if !kind.buys_service() {
                    return Err(inconsistent("a period is recorded for a traffic order"));
                }
                if from >= until || CalendarDate::utc_of(until).is_err() {
                    return Err(inconsistent("a period does not end after it starts"));
                }
            }
            GrantOutcome::Pack if kind.buys_service() => {
                return Err(inconsistent("a pack is recorded for a service order"));
            }
            GrantOutcome::Pack | GrantOutcome::Held { .. } => {}
        }
    }
    let first_in_full = record
        .refunds
        .iter()
        .position(|refund| refund.refunded_in_full);
    let pack = record
        .grant
        .is_some_and(|grant| grant.outcome == GrantOutcome::Pack);
    for (index, refund) in record.refunds.iter().enumerate() {
        let again = record.refunds[..index].iter().any(|earlier| {
            earlier.amount_refunded == refund.amount_refunded
                && earlier.refunded_in_full == refund.refunded_in_full
        });
        if again {
            return Err(inconsistent("a refund is recorded twice"));
        }
        let takes_pack_back = pack && first_in_full == Some(index);
        if refund.pack_use.is_some() != takes_pack_back {
            return Err(inconsistent(if takes_pack_back {
                "the refund that takes a pack back records no use"
            } else {
                "a use is recorded on a refund that takes no pack back"
            }));
        }
        if let Some(PackUse::Served { learned_at, .. }) = refund.pack_use
            && learned_at < refund.applied_at
        {
            return Err(inconsistent(
                "a pack's use was learned before its refund was applied",
            ));
        }
    }
    Ok(())
}
