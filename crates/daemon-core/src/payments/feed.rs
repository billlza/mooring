// SPDX-License-Identifier: GPL-3.0-or-later

//! The document the portal answers a pull with (`docs/portal-contract.md`
//! §5.3, the portal's `docs/contract/entitlements-v1.md`), decoded strictly
//! and checked whole before anything of it is used. A format or version
//! that is not this one, a key missing, added, repeated or of another type,
//! or any of Mooring's own checks refuses the whole document, so that the
//! cursor stays where it was (contract §5.5).

use std::num::{NonZeroU32, NonZeroU64};

use mooring_model::{CalendarDate, UnixTime, UserId};
use serde::{Deserialize, Serialize};

use super::error::{EntryFault, FeedError, printable};
use super::ids::{Currency, OrderId, PlanId};

/// What a document's `format` says, so that no other JSON is read as one.
pub const FEED_FORMAT: &str = "mooring-portal-entitlements";

/// The version of the contract this build reads.
pub const FEED_VERSION: u64 = 1;

/// The most entries a document holds.
pub const MAX_FEED_ENTRIES: usize = 200;

/// The largest document read, in bytes: 200 entries take about 100 KB.
pub const MAX_FEED_BYTES: usize = 1 << 20;

/// What a plan sells (`plan_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalPlanKind {
    /// Days of service, paid once.
    Month,
    /// Days of service, which Stripe charges for again every period: each
    /// renewal is an order of its own, naming the first (`renewal_of`).
    MonthAuto,
    /// Extra traffic.
    Traffic,
}

impl PortalPlanKind {
    /// Every kind, in the contract's order.
    pub const ALL: [Self; 3] = [Self::Month, Self::MonthAuto, Self::Traffic];

    /// The kind as the contract writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Month => "month",
            Self::MonthAuto => "month_auto",
            Self::Traffic => "traffic",
        }
    }

    /// Whether the plan buys days of service (`month`, `month_auto`) rather
    /// than traffic.
    #[must_use]
    pub const fn buys_service(self) -> bool {
        match self {
            Self::Month | Self::MonthAuto => true,
            Self::Traffic => false,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
}

/// An order's terms, as every entry naming the order carries them whole
/// (contract §1): the portal never changes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderTerms {
    /// The Mooring user the order's account was bound to when it was
    /// placed, and still was when it was granted.
    pub user: UserId,
    /// The plan, by the catalogue's id.
    pub plan: PlanId,
    /// What the plan sells.
    pub plan_kind: PortalPlanKind,
    /// Days of service; of a pack, the days its traffic is meant to last,
    /// which Mooring records and does not apply (design §9.6).
    pub days: NonZeroU32,
    /// The quota of each billing cycle of the service, or the extra
    /// traffic; decimal bytes.
    pub traffic_bytes: NonZeroU64,
    /// The plan's price, in the currency's hundredths.
    pub amount: NonZeroU64,
    /// The currency.
    pub currency: Currency,
    /// When Stripe told of the payment.
    pub paid_at: UnixTime,
    /// The order that began the subscription this order renews, for a
    /// `month_auto` renewal; otherwise `None`. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub renewal_of: Option<OrderId>,
}

/// What an entry tells about its order (`kind`, with the amounts of that
/// kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryEvent {
    /// The order was paid and passed the portal's checks: grant it.
    Grant,
    /// The order's payment was refunded, in part or whole.
    Refund {
        /// Everything refunded so far, in the currency's hundredths.
        amount_refunded: u64,
        /// Whether Stripe says that is all of the payment; the amount
        /// alone does not tell (contract §3).
        in_full: bool,
    },
    /// The payer disputes the payment with their bank.
    Dispute {
        /// The amount disputed.
        amount_disputed: u64,
    },
}

/// One entry of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    /// The entry's number in the portal's journal.
    pub seq: u64,
    /// The order.
    pub order: OrderId,
    /// The order's terms.
    pub terms: OrderTerms,
    /// What the entry tells.
    pub event: EntryEvent,
    /// When the portal wrote the entry.
    pub recorded_at: UnixTime,
}

/// One page of the portal's journal, checked whole: the entries after the
/// cursor asked with, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPage {
    generated_at: UnixTime,
    livemode: bool,
    after: u64,
    entries: Vec<FeedEntry>,
    next: u64,
    more: bool,
}

impl FeedPage {
    /// Decodes the body of a 200 answer to a pull that asked for the
    /// entries after `asked`.
    ///
    /// The document's format and version are checked first, so that
    /// another document is named as such; then it is decoded with every key
    /// required, none added or repeated, each of its type; then it is
    /// checked: `after` is `asked`, the time and every entry's are within
    /// 1970-01-01 to 9999-12-31, at most [`MAX_FEED_ENTRIES`] entries
    /// numbered upwards from above `after`, each valid ([`EntryFault`]),
    /// `next` the last entry's number (or `after` when there is none), and
    /// `more` only with an entry.
    pub fn decode(body: &[u8], asked: u64) -> Result<Self, FeedError> {
        if body.len() > MAX_FEED_BYTES {
            return Err(FeedError::TooLarge);
        }
        let probe: Probe = serde_json::from_slice(body).map_err(malformed)?;
        if probe.format.as_str() != Some(FEED_FORMAT) {
            return Err(FeedError::WrongFormat);
        }
        match probe.version.as_u64() {
            Some(FEED_VERSION) => {}
            found => return Err(FeedError::WrongVersion { found }),
        }
        let raw: RawPage = serde_json::from_slice(body).map_err(malformed)?;
        if raw.after != asked {
            return Err(FeedError::AfterMismatch {
                asked,
                found: raw.after,
            });
        }
        let generated_at = instant(raw.generated_at).ok_or(FeedError::GeneratedOutOfRange)?;
        if raw.entries.len() > MAX_FEED_ENTRIES {
            return Err(FeedError::TooManyEntries {
                count: raw.entries.len(),
            });
        }
        let mut last = raw.after;
        let mut entries = Vec::with_capacity(raw.entries.len());
        for raw_entry in raw.entries {
            let seq = raw_entry.seq;
            if seq <= last {
                return Err(FeedError::SeqNotAscending { seq, after: last });
            }
            last = seq;
            entries.push(entry(raw_entry).map_err(|fault| FeedError::Entry { seq, fault })?);
        }
        if raw.next != last {
            return Err(FeedError::NextMismatch {
                next: raw.next,
                expected: last,
            });
        }
        if raw.more && entries.is_empty() {
            return Err(FeedError::MoreWithoutEntries);
        }
        Ok(Self {
            generated_at,
            livemode: raw.livemode,
            after: raw.after,
            entries,
            next: raw.next,
            more: raw.more,
        })
    }

    /// When the portal made the document.
    #[must_use]
    pub const fn generated_at(&self) -> UnixTime {
        self.generated_at
    }

    /// Whether the orders were paid in Stripe's live mode: `false` is its
    /// test mode, where anyone can pay with a test card.
    #[must_use]
    pub const fn livemode(&self) -> bool {
        self.livemode
    }

    /// The cursor the entries follow.
    #[must_use]
    pub const fn after(&self) -> u64 {
        self.after
    }

    /// The entries, in their order.
    #[must_use]
    pub fn entries(&self) -> &[FeedEntry] {
        &self.entries
    }

    /// The cursor to ask with next.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.next
    }

    /// Whether the journal holds entries after these.
    #[must_use]
    pub const fn more(&self) -> bool {
        self.more
    }
}

/// The two keys read first, whatever else the document holds.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    format: serde_json::Value,
    #[serde(default)]
    version: serde_json::Value,
}

/// The document as written: every key required, none other.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPage {
    #[serde(rename = "format")]
    _format: String,
    #[serde(rename = "version")]
    _version: u64,
    generated_at: u64,
    livemode: bool,
    after: u64,
    entries: Vec<RawEntry>,
    next: u64,
    more: bool,
}

/// An entry as written: every key required, none other.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    seq: u64,
    kind: String,
    order: String,
    user: String,
    plan: String,
    plan_kind: String,
    days: u64,
    traffic_bytes: u64,
    amount: u64,
    currency: String,
    paid_at: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    renewal_of: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    amount_refunded: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    refunded_in_full: Option<bool>,
    #[serde(deserialize_with = "Option::deserialize")]
    amount_disputed: Option<u64>,
    recorded_at: u64,
}

/// `seconds` as an instant, if it lies between 1970-01-01 and 9999-12-31.
fn instant(seconds: u64) -> Option<UnixTime> {
    let at = UnixTime::from_secs(seconds);
    CalendarDate::utc_of(at).is_ok().then_some(at)
}

fn malformed(error: serde_json::Error) -> FeedError {
    FeedError::Malformed {
        detail: printable(&error.to_string()),
    }
}

/// An entry, checked.
fn entry(raw: RawEntry) -> Result<FeedEntry, EntryFault> {
    let order = OrderId::parse(&raw.order).map_err(|_| EntryFault::Order)?;
    let user = UserId::parse(&raw.user).map_err(|_| EntryFault::User)?;
    let plan = PlanId::parse(&raw.plan).map_err(|_| EntryFault::Plan)?;
    let plan_kind = PortalPlanKind::parse(&raw.plan_kind).ok_or(EntryFault::PlanKind)?;
    let days = u32::try_from(raw.days)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(EntryFault::Days)?;
    let traffic_bytes = NonZeroU64::new(raw.traffic_bytes).ok_or(EntryFault::TrafficBytes)?;
    let amount = NonZeroU64::new(raw.amount).ok_or(EntryFault::Amount)?;
    let currency = Currency::parse(&raw.currency).map_err(|_| EntryFault::Currency)?;
    let paid_at = instant(raw.paid_at).ok_or(EntryFault::PaidAt)?;
    let recorded_at = instant(raw.recorded_at).ok_or(EntryFault::RecordedAt)?;
    let renewal_of = match raw.renewal_of {
        None => None,
        Some(text) => {
            let renewed = OrderId::parse(&text).map_err(|_| EntryFault::RenewalOf)?;
            if plan_kind != PortalPlanKind::MonthAuto {
                return Err(EntryFault::RenewalOfAnotherKind);
            }
            if renewed == order {
                return Err(EntryFault::RenewalOfItself);
            }
            Some(renewed)
        }
    };
    let event = match (
        raw.kind.as_str(),
        raw.amount_refunded,
        raw.refunded_in_full,
        raw.amount_disputed,
    ) {
        ("grant", None, None, None) => EntryEvent::Grant,
        ("refund", Some(amount_refunded), Some(in_full), None) => EntryEvent::Refund {
            amount_refunded,
            in_full,
        },
        ("dispute", None, None, Some(amount_disputed)) => EntryEvent::Dispute { amount_disputed },
        ("grant" | "refund" | "dispute", ..) => return Err(EntryFault::Amounts),
        _ => return Err(EntryFault::Kind),
    };
    Ok(FeedEntry {
        seq: raw.seq,
        order,
        terms: OrderTerms {
            user,
            plan,
            plan_kind,
            days,
            traffic_bytes,
            amount,
            currency,
            paid_at,
            renewal_of,
        },
        event,
        recorded_at,
    })
}
