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
//! - **Refunds and disputes** are recorded and change nothing.
//! - **Test mode** (contract §5.3): a page of Stripe's test mode is applied
//!   only while the operator rehearses ([`ApplyRefusal::TestMode`]), and its
//!   grants count only while the rehearsal lasts ([`Entitlements`]).

use std::collections::BTreeMap;

use mooring_model::date::SECS_PER_DAY;
use mooring_model::{CalendarDate, UnixTime, User, UserId, UserStatus};
use serde::{Deserialize, Serialize};

use super::entitlement::{Entitlements, PaidPack, PaidPeriod};
use super::error::{ApplyRefusal, Contradiction, LedgerError};
use super::feed::{EntryEvent, FeedEntry, FeedPage, OrderTerms};
use super::ids::OrderId;

/// The ledger's version.
pub const LEDGER_VERSION: u32 = 1;

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

    /// The order's period, if its grant gave one.
    fn period(&self) -> Option<(UnixTime, UnixTime)> {
        match self.grant?.outcome {
            GrantOutcome::Period { from, until } => Some((from, until)),
            GrantOutcome::Pack | GrantOutcome::Held { .. } => None,
        }
    }

    /// Whether the order counts: always when paid in live mode, and while
    /// the operator rehearses when paid in test mode.
    const fn counts(&self, rehearsal: bool) -> bool {
        self.livemode || rehearsal
    }
}

/// The document on disk, as read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    version: u32,
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
        /// Whether the user is suspended, which only the operator lifts.
        suspended: bool,
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
    /// A refund was recorded; it changes nothing.
    Refunded {
        /// The order.
        order: OrderId,
        /// The user.
        user: UserId,
        /// Everything refunded so far.
        amount_refunded: u64,
        /// Whether that is all of the payment.
        in_full: bool,
        /// Whether Mooring granted the order ([`OrderRecord::granted`]).
        granted: bool,
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
}

/// A page applied to a copy of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The ledger to write, with the page's cursor.
    pub ledger: PaymentLedger,
    /// What each entry did, in order.
    pub events: Vec<LedgerEvent>,
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

    /// Reads a ledger the daemon wrote. Besides its shape and version,
    /// orders are in id order and each once, every recorded entry is at or
    /// below the cursor, a grant's number is below its refunds' and
    /// dispute's, a period ends after it starts and within the calendar, a
    /// period or pack is of an order of its kind, and each refund's amount
    /// and flag are recorded once.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(LedgerError::TooLarge);
        }
        let file: LedgerFile = serde_json::from_slice(bytes).map_err(LedgerError::Decode)?;
        if file.version != LEDGER_VERSION {
            return Err(LedgerError::UnknownVersion {
                found: file.version,
            });
        }
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
    /// rehearses. The copy has the page's cursor, `now` as its last pull
    /// and no stop.
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
    /// test mode too.
    #[must_use]
    pub fn entitlements(&self, rehearsal: bool) -> Entitlements {
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
                GrantOutcome::Period { from, until } => entitlements.add_period(
                    user,
                    PaidPeriod {
                        order: record.order.clone(),
                        from,
                        until,
                        quota_bytes: record.terms.traffic_bytes,
                        livemode: record.livemode,
                    },
                ),
                GrantOutcome::Pack => entitlements.add_pack(
                    user,
                    PaidPack {
                        order: record.order.clone(),
                        granted_at: grant.applied_at,
                        bytes: record.terms.traffic_bytes,
                        livemode: record.livemode,
                    },
                ),
                GrantOutcome::Held { .. } => {}
            }
        }
        entitlements
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
                let user = record.terms.user.clone();
                let order = record.order.clone();
                let repeated = record.refunds.iter().any(|refund| {
                    refund.amount_refunded == amount_refunded && refund.refunded_in_full == in_full
                });
                if repeated {
                    return Ok(LedgerEvent::Repeated {
                        seq: entry.seq,
                        order,
                    });
                }
                record.refunds.push(RefundRecord {
                    seq: entry.seq,
                    amount_refunded,
                    refunded_in_full: in_full,
                    recorded_at: entry.recorded_at,
                    applied_at: now,
                });
                Ok(LedgerEvent::Refunded {
                    order,
                    user,
                    amount_refunded,
                    in_full,
                    granted,
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
                false,
            ),
            Some(user) => match user.status {
                UserStatus::RevokePending | UserStatus::Revoked => (
                    GrantOutcome::Held {
                        reason: HeldReason::UserRevoked,
                    },
                    false,
                ),
                UserStatus::Active | UserStatus::Suspended { .. } => (
                    self.outcome_for(user, terms, livemode, now),
                    matches!(user.status, UserStatus::Suspended { .. }),
                ),
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
    /// (`UserPolicy::expires_at`); with one, the later of its end and the
    /// record. A live grant builds on live periods only, so a rehearsal
    /// never moves real time; a test-mode grant builds on every period.
    fn paid_expiry(&self, user: &User, livemode: bool) -> Option<UnixTime> {
        let last_end = self
            .orders
            .values()
            .filter(|record| record.terms.user == user.id && (record.livemode || !livemode))
            .filter_map(OrderRecord::period)
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
    for (index, refund) in record.refunds.iter().enumerate() {
        let again = record.refunds[..index].iter().any(|earlier| {
            earlier.amount_refunded == refund.amount_refunded
                && earlier.refunded_in_full == refund.refunded_in_full
        });
        if again {
            return Err(inconsistent("a refund is recorded twice"));
        }
    }
    Ok(())
}
