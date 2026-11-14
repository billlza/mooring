// SPDX-License-Identifier: GPL-3.0-or-later

//! The plans on the Mac (design §9.6): the plans the operator sells, as
//! the portal's plan file lists them, which `mooringctl portal plans set`
//! stores from the operator's own copy of that file, never from the
//! portal. While any are stored, a live grant that would give a period or
//! a pack is granted only when its plan, kind, days, traffic, amount and
//! currency are those of a stored plan; and the check against Stripe, when
//! it is on, confirms it only when it was paid on a Payment Link of that
//! plan. The check against Stripe proves what was paid; this proves what
//! it buys.
//!
//! - **The file** is the portal's (its `docs/payments.md`, section 4:
//!   format `mooring-portal-payments`, version 1), refused wherever the
//!   portal refuses it (its `crates/core/src/payment/catalogue.rs`), and
//!   of Stripe's live mode only: a rehearsal's grants are not checked. The
//!   test mode's own keys (`renewal_amount`, `introductory`) are read only
//!   as absent, `null` or `false`, which a live file of any portal build
//!   may write.
//! - **Every plan stored stays known**: a new file marks its plans current
//!   and keeps those of the files before it, so that an order paid on a
//!   plan before a change still matches when it is pulled after the
//!   change. The plans no file lists any more are dropped, the longest
//!   unlisted first, past [`MAX_STORED_PLANS`].
//! - **One plan to a Payment Link**: a kept plan's link sells its terms
//!   only, so a file that lists other terms on the link of a plan kept is
//!   refused ([`LinkTaken`]), and a plan whose terms change is sold on a
//!   new link. With the check against Stripe, the link a payment was made
//!   on then decides what it buys, a renewal's as a first order's.
//! - **Not whom for**: neither the plans nor Stripe know Mooring's users.

use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use super::feed::{OrderTerms, PortalPlanKind};
use super::ids::{Currency, PlanId};
use super::stripe::StripeId;

/// What the portal's plan file says it is.
pub const PLAN_FILE_FORMAT: &str = "mooring-portal-payments";

/// The version of the portal's plan file this build reads.
pub const PLAN_FILE_VERSION: u32 = 1;

/// The largest plan file read, in bytes.
pub const MAX_PLAN_FILE_BYTES: usize = 64 * 1024;

/// The most plans a file lists, as the portal bounds them.
pub const MAX_FILE_PLANS: usize = 24;

/// The most plans kept: the current file's and those of the files before
/// it, the most recently listed first kept.
pub const MAX_STORED_PLANS: usize = 96;

/// The bytes of a decimal GB, as the portal counts a plan's traffic.
pub const GB: u64 = 1_000_000_000;

/// A plan's days, at most, as the portal bounds them.
const MAX_DAYS: u32 = 3660;

/// A plan's traffic, at most, in GB.
const MAX_TRAFFIC_GB: u64 = 100_000;

/// A plan's amount, at most, in the currency's hundredths.
const MAX_AMOUNT: u64 = 10_000_000;

/// How a Payment Link's address begins.
const PAYMENT_LINK_ADDRESS: &str = "https://buy.stripe.com/";

/// How a Payment Link's id begins.
const PAYMENT_LINK_ID: &str = "plink_";

/// How the page where a user cancels a renewal begins: Stripe's customer
/// portal.
const MANAGE_ADDRESS: &str = "https://billing.stripe.com/p/login/";

/// The most characters after a page's address or a Payment Link's
/// `plink_`, as the portal reads them.
const MAX_WORD_CHARS: usize = 128;

/// The currencies the portal prices in.
const CURRENCIES: [&str; 8] = ["aud", "cad", "cny", "eur", "gbp", "hkd", "sgd", "usd"];

/// The portal's plan file could not be read, or is not one the Mac keeps.
/// The file holds no secret: a refusal names a plan by its id, and a
/// decode error may quote what it could not read.
#[derive(Debug, thiserror::Error)]
pub enum PlanFileError {
    /// Larger than [`MAX_PLAN_FILE_BYTES`].
    #[error("the plan file is larger than {MAX_PLAN_FILE_BYTES} bytes")]
    TooLarge,
    /// Not JSON of the plan file's shape.
    #[error("the plan file does not decode as the portal's plan file")]
    Decode(#[source] serde_json::Error),
    /// Another document.
    #[error("the file is not the portal's plan file (format {PLAN_FILE_FORMAT})")]
    Format,
    /// Another version.
    #[error(
        "the plan file is of version {found}, and this build reads version {PLAN_FILE_VERSION}"
    )]
    Version {
        /// The version written.
        found: u32,
    },
    /// A file of Stripe's test mode.
    #[error(
        "the plan file is of Stripe's test mode; the Mac keeps the live plan file only, since a rehearsal's grants are not checked"
    )]
    TestMode,
    /// A currency the portal does not price in.
    #[error("the plan file's currency must be one of aud, cad, cny, eur, gbp, hkd, sgd, usd")]
    Currency,
    /// Too few or too many plans.
    #[error("the plan file lists {found} plans, and must list 1 to {MAX_FILE_PLANS}")]
    PlanCount {
        /// The plans listed.
        found: usize,
    },
    /// A plan the portal would refuse.
    #[error("plan {plan}: {why}")]
    Plan {
        /// The plan's id.
        plan: PlanId,
        /// What is wrong with it.
        why: &'static str,
    },
    /// The page where a user cancels a renewal is not Stripe's customer
    /// portal.
    #[error(
        "the plan file's manage_subscription_url must be https://billing.stripe.com/p/login/ and 1 to 128 letters, digits or _"
    )]
    ManageUrl,
    /// A `month_auto` plan, and no page where its user cancels it.
    #[error("the plan file sells a month_auto plan and names no manage_subscription_url")]
    NoManageUrl,
}

/// The kept plans could not be read: the settings were written by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanBookError {
    /// More than [`MAX_STORED_PLANS`].
    #[error("more than {MAX_STORED_PLANS} plans are kept")]
    TooMany,
    /// A plan out of the portal's bounds.
    #[error("a kept plan is out of the portal's bounds")]
    OutOfBounds,
    /// Two plans on one Payment Link, or one plan twice.
    #[error("two kept plans are sold on one Payment Link")]
    SharedLink,
}

/// A plan file's plan on the Payment Link of a plan kept at other terms,
/// which [`PlanBook::stored`] refuses: a Payment Link is kept for one plan,
/// so that the link a payment was made on decides what it buys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "plan {plan} is sold on {}, the Payment Link of plan {kept} kept at other terms; new terms need a new Payment Link",
    .link.as_str()
)]
pub struct LinkTaken {
    /// The file's plan.
    pub plan: PlanId,
    /// Its Payment Link.
    pub link: StripeId,
    /// The plan kept on that link.
    pub kept: PlanId,
}

/// A plan the Mac knows: one plan of a stored plan file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPlan {
    /// The plan's id, as grants name it.
    pub id: PlanId,
    /// What the plan sells.
    pub kind: PortalPlanKind,
    /// Days of service, or of a pack the days it is meant to last.
    pub days: NonZeroU32,
    /// The quota of each billing cycle of the service, or the pack's
    /// traffic, in decimal GB.
    pub traffic_gb: NonZeroU64,
    /// The price, in the currency's hundredths.
    pub amount: NonZeroU64,
    /// The currency.
    pub currency: Currency,
    /// The Payment Link the plan is sold on.
    pub payment_link_id: StripeId,
    /// Whether the latest file stored lists it. One no file lists any more
    /// is kept for the orders paid on it before.
    pub current: bool,
}

impl StoredPlan {
    /// Whether `other` is this plan, current or not.
    fn same_plan(&self, other: &Self) -> bool {
        Self {
            current: other.current,
            ..self.clone()
        } == *other
    }

    /// Whether a grant of `terms` buys this plan: its id, kind, days,
    /// traffic, amount and currency.
    fn sells(&self, terms: &OrderTerms) -> bool {
        self.id == terms.plan
            && self.kind == terms.plan_kind
            && self.days == terms.days
            && self.traffic_gb.get().checked_mul(GB) == Some(terms.traffic_bytes.get())
            && self.amount == terms.amount
            && self.currency == terms.currency
    }

    /// Why the portal would refuse the plan, if it would.
    fn fault(&self) -> Option<&'static str> {
        if self.days.get() > MAX_DAYS {
            return Some("its days must be between 1 and 3660");
        }
        if self.traffic_gb.get() > MAX_TRAFFIC_GB {
            return Some("its traffic_gb must be between 1 and 100000");
        }
        if self.amount.get() > MAX_AMOUNT {
            return Some("its amount must be between 1 and 10000000 hundredths");
        }
        if !CURRENCIES.contains(&self.currency.as_str()) {
            return Some("its currency is not one the portal prices in");
        }
        let link = self.payment_link_id.as_str().strip_prefix(PAYMENT_LINK_ID);
        if !link.is_some_and(|rest| word(rest, false)) {
            return Some("its payment_link_id must be plink_ and 1 to 128 letters or digits");
        }
        None
    }
}

/// The plans the Mac knows, the least recently listed first: none while
/// the plan check is off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<StoredPlan>", into = "Vec<StoredPlan>")]
pub struct PlanBook {
    plans: Vec<StoredPlan>,
}

/// What a grant's terms come to against the plans the Mac knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanVerdict {
    /// The Mac knows no plan: the plan check is off.
    Off,
    /// The terms are a known plan's, sold on these Payment Links (one, or
    /// more when the plan moved to another link at the same terms).
    Sells {
        /// The links.
        links: Vec<StripeId>,
    },
    /// No plan of the grant's id is known.
    Unknown,
    /// Plans of the grant's id are known, none at its terms.
    Differs,
}

/// What [`PlanBook::stored`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stored {
    /// The file's plans, now current.
    pub listed: usize,
    /// Those of them the Mac did not know.
    pub new: usize,
    /// The plans of earlier files kept, which the file does not list.
    pub earlier: usize,
    /// The plans of earlier files dropped past [`MAX_STORED_PLANS`].
    pub dropped: usize,
}

impl PlanBook {
    /// Whether the Mac knows no plan: the plan check is off.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }

    /// The plans, the least recently listed first.
    #[must_use]
    pub fn plans(&self) -> &[StoredPlan] {
        &self.plans
    }

    /// The plans with `file`'s as the current ones: a plan the Mac knew is
    /// moved to the end and marked current, a new one added; the plans of
    /// earlier files stay, unlisted, until more than [`MAX_STORED_PLANS`]
    /// are kept, when the least recently listed go first. The file's plans
    /// end the list, so those before them are the earlier files', and a
    /// file lists fewer than [`MAX_STORED_PLANS`] plans: none of its own is
    /// dropped. A file that lists other terms on the Payment Link of a plan
    /// kept, current or earlier, is refused ([`LinkTaken`]); the file's own
    /// plans are each on a link of their own.
    pub fn stored(&self, file: &PlanFile) -> Result<(Self, Stored), LinkTaken> {
        let mut plans: Vec<StoredPlan> = self
            .plans
            .iter()
            .map(|plan| StoredPlan {
                current: false,
                ..plan.clone()
            })
            .collect();
        let mut new = 0;
        for plan in &file.plans {
            let on_link = plans
                .iter()
                .position(|known| known.payment_link_id == plan.payment_link_id);
            match on_link {
                Some(at) if plans[at].same_plan(plan) => {
                    plans.remove(at);
                }
                Some(at) => {
                    return Err(LinkTaken {
                        plan: plan.id.clone(),
                        link: plan.payment_link_id.clone(),
                        kept: plans[at].id.clone(),
                    });
                }
                None => new += 1,
            }
            plans.push(plan.clone());
        }
        let dropped = plans.len().saturating_sub(MAX_STORED_PLANS);
        plans.drain(..dropped);
        let earlier = plans.len().saturating_sub(file.plans.len());
        let stored = Stored {
            listed: file.plans.len(),
            new,
            earlier,
            dropped,
        };
        Ok((Self { plans }, stored))
    }

    /// What a grant of `terms` comes to: the Payment Links of the known
    /// plans it buys, or why it buys none. Two kept plans that both sell
    /// the terms are on two links, since a link is kept for one plan.
    #[must_use]
    pub fn judge(&self, terms: &OrderTerms) -> PlanVerdict {
        if self.plans.is_empty() {
            return PlanVerdict::Off;
        }
        if !self.plans.iter().any(|plan| plan.id == terms.plan) {
            return PlanVerdict::Unknown;
        }
        let links: Vec<StripeId> = self
            .plans
            .iter()
            .filter(|plan| plan.sells(terms))
            .map(|plan| plan.payment_link_id.clone())
            .collect();
        if links.is_empty() {
            PlanVerdict::Differs
        } else {
            PlanVerdict::Sells { links }
        }
    }

    /// The Payment Links an order of `terms` may have been paid on: none
    /// while the plan check is off, or when no known plan is sold at them.
    #[must_use]
    pub fn links_for(&self, terms: &OrderTerms) -> Vec<StripeId> {
        match self.judge(terms) {
            PlanVerdict::Sells { links } => links,
            PlanVerdict::Off | PlanVerdict::Unknown | PlanVerdict::Differs => Vec::new(),
        }
    }
}

impl TryFrom<Vec<StoredPlan>> for PlanBook {
    type Error = PlanBookError;

    fn try_from(plans: Vec<StoredPlan>) -> Result<Self, Self::Error> {
        if plans.len() > MAX_STORED_PLANS {
            return Err(PlanBookError::TooMany);
        }
        if plans.iter().any(|plan| plan.fault().is_some()) {
            return Err(PlanBookError::OutOfBounds);
        }
        for (at, plan) in plans.iter().enumerate() {
            let shared = plans[..at]
                .iter()
                .any(|earlier| earlier.payment_link_id == plan.payment_link_id);
            if shared {
                return Err(PlanBookError::SharedLink);
            }
        }
        Ok(Self { plans })
    }
}

impl From<PlanBook> for Vec<StoredPlan> {
    fn from(book: PlanBook) -> Self {
        book.plans
    }
}

/// The portal's plan file, read: its plans, each current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanFile {
    plans: Vec<StoredPlan>,
}

/// The file's format and version, read first to choose how to read it.
#[derive(Debug, Deserialize)]
struct Header {
    format: String,
    version: u32,
}

/// The portal's plan file, as read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFileDoc {
    #[serde(rename = "format")]
    _format: String,
    #[serde(rename = "version")]
    _version: u32,
    livemode: bool,
    currency: Currency,
    plans: Vec<FilePlan>,
    manage_subscription_url: Option<String>,
}

/// A plan of the file, as read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePlan {
    id: PlanId,
    kind: PortalPlanKind,
    days: NonZeroU32,
    traffic_gb: NonZeroU64,
    amount: NonZeroU64,
    renewal_amount: Option<u64>,
    #[serde(default)]
    introductory: bool,
    payment_link: String,
    payment_link_id: StripeId,
}

impl PlanFile {
    /// Reads the portal's plan file as the portal reads it, of Stripe's
    /// live mode: in a currency the portal prices in, 1 to
    /// [`MAX_FILE_PLANS`] plans, each within the portal's bounds, with its
    /// own id, Payment Link and link id, and none of the test mode's keys
    /// set (`renewal_amount`, `introductory`); and the page where a user
    /// cancels a renewal, when a plan renews.
    pub fn parse(bytes: &[u8]) -> Result<Self, PlanFileError> {
        if bytes.len() > MAX_PLAN_FILE_BYTES {
            return Err(PlanFileError::TooLarge);
        }
        let Header { format, version } =
            serde_json::from_slice(bytes).map_err(PlanFileError::Decode)?;
        if format != PLAN_FILE_FORMAT {
            return Err(PlanFileError::Format);
        }
        if version != PLAN_FILE_VERSION {
            return Err(PlanFileError::Version { found: version });
        }
        let doc: PlanFileDoc = serde_json::from_slice(bytes).map_err(PlanFileError::Decode)?;
        if !doc.livemode {
            return Err(PlanFileError::TestMode);
        }
        if !CURRENCIES.contains(&doc.currency.as_str()) {
            return Err(PlanFileError::Currency);
        }
        if !(1..=MAX_FILE_PLANS).contains(&doc.plans.len()) {
            return Err(PlanFileError::PlanCount {
                found: doc.plans.len(),
            });
        }
        let mut plans: Vec<StoredPlan> = Vec::with_capacity(doc.plans.len());
        let mut pages: Vec<String> = Vec::with_capacity(doc.plans.len());
        for plan in doc.plans {
            let fault = |why| PlanFileError::Plan {
                plan: plan.id.clone(),
                why,
            };
            let stored = StoredPlan {
                id: plan.id.clone(),
                kind: plan.kind,
                days: plan.days,
                traffic_gb: plan.traffic_gb,
                amount: plan.amount,
                currency: doc.currency.clone(),
                payment_link_id: plan.payment_link_id,
                current: true,
            };
            if let Some(why) = stored.fault() {
                return Err(fault(why));
            }
            if plan.renewal_amount.is_some() {
                return Err(fault("a live plan has no renewal_amount"));
            }
            if plan.introductory {
                return Err(fault("a live plan is not introductory"));
            }
            if !page(&plan.payment_link, PAYMENT_LINK_ADDRESS) {
                return Err(fault(
                    "its payment_link must be https://buy.stripe.com/ and 1 to 128 letters, digits or _",
                ));
            }
            if plans.iter().any(|earlier| earlier.id == stored.id) {
                return Err(fault("it is listed twice"));
            }
            let shared = pages.contains(&plan.payment_link)
                || plans
                    .iter()
                    .any(|earlier| earlier.payment_link_id == stored.payment_link_id);
            if shared {
                return Err(fault("its Payment Link is another plan's"));
            }
            pages.push(plan.payment_link);
            plans.push(stored);
        }
        let manage = doc.manage_subscription_url;
        if manage
            .as_deref()
            .is_some_and(|url| !page(url, MANAGE_ADDRESS))
        {
            return Err(PlanFileError::ManageUrl);
        }
        let renews = plans
            .iter()
            .any(|plan| plan.kind == PortalPlanKind::MonthAuto);
        if manage.is_none() && renews {
            return Err(PlanFileError::NoManageUrl);
        }
        Ok(Self { plans })
    }

    /// The plans, in the file's order.
    #[must_use]
    pub fn plans(&self) -> &[StoredPlan] {
        &self.plans
    }
}

/// Whether `url` is `address` and then a word: a page there, with no
/// query, fragment or path of its own.
fn page(url: &str, address: &str) -> bool {
    url.strip_prefix(address)
        .is_some_and(|rest| word(rest, true))
}

/// Whether `text` is 1 to [`MAX_WORD_CHARS`] ASCII letters and digits, and
/// `_` when `underscores`, as the portal reads Stripe's pages and ids.
fn word(text: &str, underscores: bool) -> bool {
    (1..=MAX_WORD_CHARS).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || (underscores && byte == b'_'))
}
