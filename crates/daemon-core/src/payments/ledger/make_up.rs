// SPDX-License-Identifier: GPL-3.0-or-later

//! Make-ups (design §9.6; the agreement's clauses 1 and 3): service time or
//! traffic the operator gives a user without a payment, to make up an
//! outage on the operator's side, a mistaken cut, a mistaken ban, or a
//! refund the paying card can no longer take. The daemon records each at
//! the operator's word (`user make-up`), in the ledger beside the orders,
//! so that it counts wherever paid time and traffic count, and the grants
//! after it build on it.
//!
//! - **Time** is a service period from the later of the make-up's time and
//!   the user's paid expiry, where a live grant would start
//!   ([`PaymentLedger::paid_expiry`]), for the days asked, with the quota of
//!   each billing cycle of the user's live period that ends last. It
//!   extends the time the user paid for, so a user without a live period
//!   is refused ([`MakeUpRefusal::NoPaidPeriod`]).
//! - **Traffic** counts in the billing cycle it is given in, and in no
//!   other, as a traffic pack does.
//! - **It always counts**, whatever the rehearsal, as a live order does.
//! - **Nothing takes it back**: no payment gave it, so no refund reaches
//!   it. Its period moves earlier, as any period does, when a refund in
//!   full takes back time of the period it follows
//!   ([`TakeBacks`](crate::payments::TakeBacks)).
//! - **Each is numbered**, from 1; a number is never given again, not even
//!   after its make-up went with the user's other payment records.

use std::collections::BTreeMap;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};

use mooring_model::date::SECS_PER_DAY;
use mooring_model::user::SuspendReason;
use mooring_model::{CalendarDate, UnixTime, User, UserId, UserStatus};
use serde::{Deserialize, Serialize};

use super::{PaymentLedger, inconsistent};
use crate::payments::error::LedgerError;
use crate::payments::ids::OrderId;

/// What gave a service period or traffic: a paid order, or a make-up.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Granted {
    /// A paid order.
    Order(OrderId),
    /// A make-up.
    MakeUp(MakeUpNumber),
}

impl fmt::Display for Granted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Order(order) => write!(f, "order {order}"),
            Self::MakeUp(number) => write!(f, "make-up {number}"),
        }
    }
}

/// A make-up's number in the ledger: 1 for the first, one more for each
/// after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MakeUpNumber(NonZeroU64);

impl MakeUpNumber {
    /// The number `number`.
    #[must_use]
    pub const fn new(number: NonZeroU64) -> Self {
        Self(number)
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for MakeUpNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why the operator makes up a user's service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakeUpReason {
    /// An outage on the operator's side of 8 hours or more (clause 1).
    Outage,
    /// A cut that the review found mistaken, however short (clauses 1 and
    /// 3).
    MistakenCut,
    /// A refund that the card that paid can no longer take (clause 1).
    Unrefundable,
    /// A ban found to be a mistake: the days unused at the ban (clauses 1
    /// and 3).
    MistakenBan,
}

impl MakeUpReason {
    /// The reason as the ledger writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outage => "outage",
            Self::MistakenCut => "mistaken_cut",
            Self::Unrefundable => "unrefundable",
            Self::MistakenBan => "mistaken_ban",
        }
    }
}

/// What the operator asks a make-up to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakeUpAsk {
    /// Days of service.
    Days(NonZeroU32),
    /// Traffic, in decimal bytes.
    TrafficBytes(NonZeroU64),
}

/// What a make-up gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MakeUpGift {
    /// Service from `from` until `until`, with a quota of `quota_bytes` in
    /// each billing cycle while it lasts.
    Period {
        /// The period's first instant.
        from: UnixTime,
        /// The instant after its last.
        until: UnixTime,
        /// The quota of each billing cycle while the period lasts.
        quota_bytes: NonZeroU64,
    },
    /// Traffic for the billing cycle the make-up was given in.
    Traffic {
        /// Its bytes.
        bytes: NonZeroU64,
    },
}

/// A make-up, as the ledger records it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MakeUpRecord {
    /// Its number.
    pub number: MakeUpNumber,
    /// The user it was given to.
    pub user: UserId,
    /// Why.
    pub reason: MakeUpReason,
    /// When the daemon recorded it.
    pub granted_at: UnixTime,
    /// The ledger's cursor then: the portal's entries up to it were applied
    /// before the make-up, and those after it after.
    pub after: u64,
    /// What it gave.
    pub gift: MakeUpGift,
}

/// Why a make-up was refused. Nothing was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakeUpRefusal {
    /// The deployment holds no user of that id.
    UnknownUser,
    /// The user is being revoked or is revoked.
    UserRevoked,
    /// Service time was asked for a user without a live service period:
    /// there is no paid time to extend.
    NoPaidPeriod,
    /// Traffic was asked for a user without a quota now: there is nothing
    /// to add it to.
    NoQuota,
    /// The user's quota cannot be computed now, so whether traffic adds to
    /// one is not known.
    QuotaUnknown,
    /// The service period would end after 9999-12-31.
    BeyondCalendar,
    /// The ledger has numbered as many make-ups as a number holds.
    NumbersSpent,
}

/// A make-up recorded on a copy of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadeUp {
    /// The ledger to write.
    pub ledger: PaymentLedger,
    /// The make-up.
    pub record: MakeUpRecord,
    /// Why the user is suspended, if they are: as for a grant
    /// ([`LedgerEvent::Granted`](super::LedgerEvent::Granted)), the apply
    /// job resumes a suspension at expiry once the user's paid time runs
    /// past its run, and one for quota once their quota covers what they
    /// used this cycle; only the operator lifts the others.
    pub suspended: Option<SuspendReason>,
}

impl PaymentLedger {
    /// Records on a copy at `now` the make-up `ask` gives `user`, for
    /// `reason` ([`self`](self) module). Refused for a user being revoked
    /// or revoked, for time without a live service period to extend, and
    /// for a period that would end beyond the calendar. Whether `user` has
    /// a quota that traffic adds to is the caller's to know
    /// ([`crate::make_up`]): the ledger does not hold the user's quota.
    pub fn make_up(
        &self,
        user: &User,
        ask: MakeUpAsk,
        reason: MakeUpReason,
        now: UnixTime,
    ) -> Result<MadeUp, MakeUpRefusal> {
        let suspended = match user.status {
            UserStatus::RevokePending | UserStatus::Revoked { .. } => {
                return Err(MakeUpRefusal::UserRevoked);
            }
            UserStatus::Active => None,
            UserStatus::Suspended { reason, .. } => Some(reason),
        };
        let gift = match ask {
            MakeUpAsk::Days(days) => self.period_for(user, days, now)?,
            MakeUpAsk::TrafficBytes(bytes) => MakeUpGift::Traffic { bytes },
        };
        let number = self
            .last_make_up
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(MakeUpNumber)
            .ok_or(MakeUpRefusal::NumbersSpent)?;
        let record = MakeUpRecord {
            number,
            user: user.id.clone(),
            reason,
            granted_at: now,
            after: self.cursor,
            gift,
        };
        let mut ledger = self.clone();
        ledger.make_ups.insert(number, record.clone());
        ledger.last_make_up = number.get();
        Ok(MadeUp {
            ledger,
            record,
            suspended,
        })
    }

    /// Every make-up, in number order.
    #[must_use]
    pub const fn make_ups(&self) -> &BTreeMap<MakeUpNumber, MakeUpRecord> {
        &self.make_ups
    }

    /// The number of the last make-up recorded, 0 before the first; one
    /// deleted since keeps its number taken.
    #[must_use]
    pub const fn last_make_up(&self) -> u64 {
        self.last_make_up
    }

    /// The period `days` of service give `user` at `now`: from where a live
    /// grant would start, with the quota of the user's live period that
    /// ends last.
    fn period_for(
        &self,
        user: &User,
        days: NonZeroU32,
        now: UnixTime,
    ) -> Result<MakeUpGift, MakeUpRefusal> {
        let quota_bytes = self
            .last_live_quota(&user.id)
            .ok_or(MakeUpRefusal::NoPaidPeriod)?;
        let from = self
            .paid_expiry(user, true)
            .map_or(now, |expiry| expiry.max(now));
        let until = u64::from(days.get())
            .checked_mul(SECS_PER_DAY)
            .and_then(|length| from.checked_add_secs(length))
            .filter(|until| CalendarDate::utc_of(*until).is_ok())
            .ok_or(MakeUpRefusal::BeyondCalendar)?;
        Ok(MakeUpGift::Period {
            from,
            until,
            quota_bytes,
        })
    }

    /// The quota of each billing cycle of `user`'s live service period
    /// that ends last, as the refunds in full leave the periods, an
    /// order's or a make-up's. A period whose time was all taken back gave
    /// the user no service, so it is not one. `None` without a live period.
    fn last_live_quota(&self, user: &UserId) -> Option<NonZeroU64> {
        let take_backs = self.take_backs_of(user);
        let orders = self
            .orders
            .values()
            .filter(|record| record.terms.user == *user && record.livemode)
            .filter_map(|record| {
                take_backs
                    .period(record)
                    .map(|(from, until)| (from, until, record.terms.traffic_bytes))
            });
        let make_ups = self
            .make_ups
            .values()
            .filter(|record| record.user == *user)
            .filter_map(|record| match record.gift {
                MakeUpGift::Period { quota_bytes, .. } => take_backs
                    .make_up_period(record)
                    .map(|(from, until)| (from, until, quota_bytes)),
                MakeUpGift::Traffic { .. } => None,
            });
        // A user's live periods follow one another and never overlap, so
        // no two that cover time end together.
        orders
            .chain(make_ups)
            .filter(|(from, until, _)| from < until)
            .max_by_key(|(_, until, _)| *until)
            .map(|(_, _, quota)| quota)
    }
}

/// The rules one recorded make-up keeps (see [`PaymentLedger::decode`]),
/// in a ledger at `cursor` whose last make-up is numbered `last`.
pub(super) fn check_make_up(
    record: &MakeUpRecord,
    cursor: u64,
    last: u64,
) -> Result<(), LedgerError> {
    if record.number.get() > last {
        return Err(inconsistent("a make-up is numbered after the last one"));
    }
    if record.after > cursor {
        return Err(inconsistent("a make-up follows an entry after the cursor"));
    }
    if let MakeUpGift::Period { from, until, .. } = record.gift
        && (from >= until || CalendarDate::utc_of(until).is_err())
    {
        return Err(inconsistent(
            "a make-up's period does not end after it starts",
        ));
    }
    Ok(())
}
