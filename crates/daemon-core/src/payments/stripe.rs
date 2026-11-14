// SPDX-License-Identifier: GPL-3.0-or-later

//! The check against Stripe (design §9.6; contract §5.5): before the daemon
//! applies a live grant that would give a period or a pack, it looks up at
//! Stripe the payment that paid it, and a grant Stripe does not confirm is
//! held. It proves that the order was paid as listed, not whom it was for
//! or what it buys: Stripe knows neither Mooring's users nor the plans.
//!
//! - **A first order** (`month`, `traffic`, and a `month_auto` order that
//!   begins a subscription) is found among the completed checkouts created
//!   from [`CHECKOUT_BEFORE`] before its `paid_at` to [`CHECKOUT_AFTER`]
//!   after it, by its id, which is its checkout's `client_reference_id`.
//! - **A renewal** is found among the paid invoices of the subscriptions
//!   that its first order's paid checkouts began (two when that order was
//!   paid twice), by its id, which the portal works out from the invoice's
//!   ([`OrderId::for_renewal`]).
//!
//! Nothing here does I/O. A [`Lookup`] says what to ask ([`Lookup::url`])
//! and reads Stripe's answer ([`Lookup::read`]), page by page, until it has
//! a [`Verdict`]. An answer is read for the fields the check needs only;
//! the rest of each object, the payer's name, email and address among
//! them, is skipped unread.

use mooring_model::UnixTime;
use mooring_model::date::SECS_PER_DAY;
use serde::{Deserialize, Serialize};

use super::error::printable;
use super::feed::{OrderTerms, PortalPlanKind};
use super::ids::OrderId;
use super::ledger::HeldReason;

/// Stripe's API.
pub const STRIPE_API: &str = "https://api.stripe.com";

/// The API release every request names in its `Stripe-Version` header:
/// the one the portal's webhook endpoint uses (the portal's
/// `docs/payments.md` §3), so the objects keep the fields read here.
pub const STRIPE_VERSION: &str = "2026-10-28.endive";

/// Objects asked for on each page.
pub const PAGE_LIMIT: u32 = 20;

/// The most pages one lookup reads: 2000 objects, beyond anything this
/// service's account holds in a week of checkouts or one subscription's
/// invoices.
pub const MAX_PAGES: u32 = 100;

/// How long before an order's `paid_at` its checkout may have been
/// created. A checkout made through Stripe's API lives 24 hours at most;
/// Stripe does not say how long a Payment Link's lives, hence a week.
pub const CHECKOUT_BEFORE: u64 = 7 * SECS_PER_DAY;

/// How long after an order's `paid_at` its checkout may have been
/// created: `paid_at` is when Stripe told of the checkout's completion,
/// which follows its creation; the margin only absorbs rounding.
pub const CHECKOUT_AFTER: u64 = 300;

/// The most characters of an id Stripe gave an object.
pub const MAX_STRIPE_ID_CHARS: usize = 255;

/// The most characters of a value of Stripe's that a [`Difference`]
/// carries into the daemon's log.
const MAX_FOUND_CHARS: usize = 40;

/// An id Stripe gave an object (`cs_live_…`, `in_…`, `sub_…`): 1 to
/// [`MAX_STRIPE_ID_CHARS`] letters, digits and `_`, so that it is safe in
/// a request's query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct StripeId(String);

/// Text that is not a Stripe id. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a Stripe id: 1 to {MAX_STRIPE_ID_CHARS} letters, digits and underscores")]
pub struct NotAStripeId;

impl StripeId {
    /// Accepts 1 to [`MAX_STRIPE_ID_CHARS`] of `0-9`, `A-Z`, `a-z` and `_`.
    pub fn parse(text: &str) -> Result<Self, NotAStripeId> {
        let valid = (1..=MAX_STRIPE_ID_CHARS).contains(&text.len())
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(NotAStripeId)
        }
    }

    /// The id as Stripe wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for StripeId {
    type Error = NotAStripeId;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<StripeId> for String {
    fn from(id: StripeId) -> Self {
        id.0
    }
}

/// A grant the check must confirm ([`super::Checked::Unconfirmed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmable {
    /// The order.
    pub order: OrderId,
    /// Its terms.
    pub terms: OrderTerms,
    /// For a renewal (`renewal_of`), the terms of the order that began its
    /// subscription, when the ledger or the page holds that order; `None`
    /// for a first order.
    pub first: Option<OrderTerms>,
    /// The Payment Links of the plans the Mac knows at the order's terms
    /// (`PlanBook::links_for`): a first order's checkout must have been
    /// made on one, and a renewal's subscription begun on one, since the
    /// portal lists a renewal at its first order's terms. Empty, any link
    /// does: so it is while the plan check is off, since a grant the plan
    /// check lets through is at the terms of a known plan, which has its
    /// link.
    pub payment_links: Vec<StripeId>,
}

/// What Stripe said of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A payment at Stripe is the order's: the grant is applied.
    Confirmed,
    /// None is: the grant is held.
    Refused(Refusal),
}

/// Why Stripe did not confirm a grant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No completed checkout created around the order's payment names it.
    #[error("no completed checkout at Stripe names the order")]
    NoCheckout,
    /// A renewal whose first order neither the ledger nor the page holds.
    #[error("Mooring holds no record of the order whose subscription it renews")]
    NoFirstOrder,
    /// No paid checkout of a renewal's first order began a subscription.
    #[error("no paid checkout of its first order began a subscription at Stripe")]
    NoSubscription,
    /// No paid invoice of the subscriptions the first order began is the
    /// renewal's.
    #[error("no paid invoice of its subscription at Stripe is the renewal's")]
    NoInvoice,
    /// The checkouts or the invoice that name the order were not paid.
    #[error("its payment at Stripe is not paid")]
    Unpaid,
    /// What was paid is not what the order says.
    #[error("what Stripe says was paid differs from the order: {0}")]
    Differs(Difference),
}

impl Refusal {
    /// The reason the grant is held for.
    #[must_use]
    pub const fn held_reason(&self) -> HeldReason {
        match self {
            Self::NoCheckout | Self::NoSubscription | Self::NoInvoice => {
                HeldReason::StripeNoPayment
            }
            Self::NoFirstOrder => HeldReason::StripeNoFirstOrder,
            Self::Unpaid => HeldReason::StripeUnpaid,
            Self::Differs(_) => HeldReason::StripeDiffers,
        }
    }

    /// How close to a confirmation the refusal came: a payment that
    /// differs is closer than one not paid, which is closer than none.
    const fn closeness(&self) -> u8 {
        match self {
            Self::Differs(_) => 2,
            Self::Unpaid => 1,
            Self::NoCheckout | Self::NoFirstOrder | Self::NoSubscription | Self::NoInvoice => 0,
        }
    }
}

/// How what was paid differs from the order. A value of Stripe's is
/// carried escaped and cut to 40 characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Difference {
    /// Paid in Stripe's test mode.
    #[error("it was paid in Stripe's test mode")]
    TestMode,
    /// A checkout of another mode than the plan's.
    #[error("its checkout is of mode {found}, and the plan's is {wanted}")]
    Mode {
        /// Stripe's mode.
        found: String,
        /// The plan's: `subscription` for `month_auto`, else `payment`.
        wanted: &'static str,
    },
    /// Another currency.
    #[error("it was paid in {found}")]
    Currency {
        /// Stripe's currency, or `none`.
        found: String,
    },
    /// Another amount.
    #[error("{} was paid", .found.map_or_else(|| "no amount".to_owned(), |amount| amount.to_string()))]
    Amount {
        /// Stripe's amount, in the currency's hundredths.
        found: Option<u64>,
    },
    /// An invoice that does not renew a subscription.
    #[error("its invoice's billing reason is {found}, not subscription_cycle")]
    Reason {
        /// Stripe's billing reason, or `none`.
        found: String,
    },
    /// A checkout on a Payment Link of none of the order's plans.
    #[error("its checkout was on Payment Link {found}, not one of its plan's")]
    PaymentLink {
        /// Stripe's Payment Link, or `none`.
        found: String,
    },
}

/// Stripe's answer could not be read.
#[derive(Debug, thiserror::Error)]
pub enum StripeAnswerError {
    /// It is not a list of the objects asked for.
    #[error("Stripe's answer does not decode as a list of {what}")]
    Decode {
        /// The objects.
        what: &'static str,
        /// Why.
        #[source]
        source: serde_json::Error,
    },
    /// An object in it is of another kind.
    #[error("Stripe's answer lists an object that is not a {what}")]
    Object {
        /// The kind asked for.
        what: &'static str,
    },
    /// It says there is more, and lists nothing to go on from.
    #[error("Stripe's answer says there are more {what}, and lists none")]
    EmptyPage {
        /// The objects.
        what: &'static str,
    },
}

/// A page of a list Stripe returns.
#[derive(Debug, Deserialize)]
struct List<T> {
    object: String,
    data: Vec<T>,
    has_more: bool,
}

/// A checkout, as far as the check reads it. Every key read is required;
/// the others are skipped.
#[derive(Debug, Deserialize)]
struct Checkout {
    id: StripeId,
    object: String,
    #[serde(deserialize_with = "Option::deserialize")]
    client_reference_id: Option<String>,
    payment_status: String,
    mode: String,
    #[serde(deserialize_with = "Option::deserialize")]
    amount_total: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    currency: Option<String>,
    livemode: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    subscription: Option<StripeId>,
    #[serde(deserialize_with = "Option::deserialize")]
    payment_link: Option<StripeId>,
}

impl Checkout {
    /// Whether the checkout was on one of `links`; on any while there are
    /// none to hold it to.
    fn on_link(&self, links: &[StripeId]) -> bool {
        links.is_empty()
            || self
                .payment_link
                .as_ref()
                .is_some_and(|link| links.contains(link))
    }
}

/// An invoice, as far as the check reads it. Every key read is required;
/// the others are skipped.
#[derive(Debug, Deserialize)]
struct Invoice {
    id: StripeId,
    object: String,
    #[serde(deserialize_with = "Option::deserialize")]
    status: Option<String>,
    amount_paid: u64,
    currency: String,
    #[serde(deserialize_with = "Option::deserialize")]
    billing_reason: Option<String>,
    livemode: bool,
}

/// One lookup at Stripe, page by page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// Boxed: a lookup is handed on from page to page in [`Next`], whose
    /// other variant is small.
    target: Box<Confirmable>,
    step: Step,
    /// The pages read so far.
    pages: u32,
}

/// What a lookup lists. `after` is the last object of the page before.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// The completed checkouts created from `from` to `until`, for those
    /// that name the order `name`: `best` is the closest refusal so far.
    Checkouts {
        name: OrderId,
        from: u64,
        until: u64,
        after: Option<StripeId>,
        best: Option<Refusal>,
    },
    /// The same of a renewal's first order `name`, every page of them, for
    /// the subscriptions its paid checkouts began on a Payment Link of the
    /// renewal's plan (on any while the Mac knows none): `began`, in the
    /// order listed. An order is paid twice when its buyer finishes two
    /// checkouts of it; the portal keeps one subscription and the operator
    /// refunds the other, so either may be the renewal's. `elsewhere` is
    /// the Payment Link of the first checkout that began one on another
    /// link, the refusal when none began one on the plan's.
    Subscriptions {
        name: OrderId,
        from: u64,
        until: u64,
        after: Option<StripeId>,
        began: Vec<StripeId>,
        elsewhere: Option<String>,
    },
    /// The paid invoices of `subscription`; then those of `rest`, the other
    /// subscriptions the first order began.
    Invoices {
        subscription: StripeId,
        after: Option<StripeId>,
        rest: Vec<StripeId>,
    },
}

impl Step {
    /// The invoices of the first of `subscriptions`, then of the others;
    /// none when there are none.
    fn invoices(subscriptions: Vec<StripeId>) -> Option<Self> {
        let mut subscriptions = subscriptions.into_iter();
        let subscription = subscriptions.next()?;
        Some(Self::Invoices {
            subscription,
            after: None,
            rest: subscriptions.collect(),
        })
    }
}

/// When the checkouts of an order paid at `paid_at` were created: from
/// [`CHECKOUT_BEFORE`] before it to [`CHECKOUT_AFTER`] after it.
fn window(paid_at: UnixTime) -> (u64, u64) {
    let paid_at = paid_at.as_secs();
    (
        paid_at.saturating_sub(CHECKOUT_BEFORE),
        paid_at.saturating_add(CHECKOUT_AFTER),
    )
}

/// Where a lookup stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// It asks again: [`Lookup::url`].
    Ask(Lookup),
    /// It is done.
    Done(Verdict),
}

impl Lookup {
    /// The lookup of `target`, or its verdict when Stripe need not be
    /// asked: a renewal whose first order Mooring does not hold cannot be
    /// confirmed.
    #[must_use]
    pub fn start(target: Confirmable) -> Next {
        let step = match (&target.terms.renewal_of, &target.first) {
            (None, _) => {
                let (from, until) = window(target.terms.paid_at);
                Step::Checkouts {
                    name: target.order.clone(),
                    from,
                    until,
                    after: None,
                    best: None,
                }
            }
            (Some(first), Some(terms)) => {
                let (from, until) = window(terms.paid_at);
                Step::Subscriptions {
                    name: first.clone(),
                    from,
                    until,
                    after: None,
                    began: Vec::new(),
                    elsewhere: None,
                }
            }
            (Some(_), None) => return Next::Done(Verdict::Refused(Refusal::NoFirstOrder)),
        };
        Next::Ask(Self {
            target: Box::new(target),
            step,
            pages: 0,
        })
    }

    /// The grant looked up.
    #[must_use]
    pub fn target(&self) -> &Confirmable {
        &self.target
    }

    /// The request to make next: an address on [`STRIPE_API`].
    #[must_use]
    pub fn url(&self) -> String {
        let after = |after: &Option<StripeId>| {
            after
                .as_ref()
                .map_or_else(String::new, |id| format!("&starting_after={}", id.as_str()))
        };
        match &self.step {
            Step::Checkouts {
                from,
                until,
                after: last,
                ..
            }
            | Step::Subscriptions {
                from,
                until,
                after: last,
                ..
            } => format!(
                "{STRIPE_API}/v1/checkout/sessions?status=complete&created%5Bgte%5D={from}&created%5Blte%5D={until}&limit={PAGE_LIMIT}{}",
                after(last)
            ),
            Step::Invoices {
                subscription,
                after: last,
                ..
            } => format!(
                "{STRIPE_API}/v1/invoices?subscription={}&status=paid&limit={PAGE_LIMIT}{}",
                subscription.as_str(),
                after(last)
            ),
        }
    }

    /// Reads Stripe's answer to [`Self::url`]: what to ask next, or the
    /// verdict. Once a lookup has read [`MAX_PAGES`] pages it is over with
    /// what it found.
    pub fn read(self, body: &[u8]) -> Result<Next, StripeAnswerError> {
        let Self {
            target,
            step,
            pages,
        } = self;
        let pages = pages.saturating_add(1);
        let (step, over) = match step {
            Step::Checkouts {
                name,
                from,
                until,
                best,
                ..
            } => {
                let list: List<Checkout> = decode(body, "checkout.session")?;
                let page = Page::of(&list, "checkout.session")?;
                let mut best = best;
                for checkout in naming(&list, &name) {
                    match judge_checkout(checkout, &target.terms, &target.payment_links) {
                        Ok(()) => return Ok(Next::Done(Verdict::Confirmed)),
                        Err(refusal) => best = Some(closer(best, refusal)),
                    }
                }
                let over = Verdict::Refused(best.clone().unwrap_or(Refusal::NoCheckout));
                let Some(after) = page.more_after else {
                    return Ok(Next::Done(over));
                };
                let step = Step::Checkouts {
                    name,
                    from,
                    until,
                    after: Some(after),
                    best,
                };
                (step, over)
            }
            Step::Subscriptions {
                name,
                from,
                until,
                mut began,
                mut elsewhere,
                ..
            } => {
                let list: List<Checkout> = decode(body, "checkout.session")?;
                let page = Page::of(&list, "checkout.session")?;
                for checkout in naming(&list, &name) {
                    let Some(subscription) = began_subscription(checkout) else {
                        continue;
                    };
                    if checkout.on_link(&target.payment_links) {
                        began.push(subscription.clone());
                    } else if elsewhere.is_none() {
                        elsewhere =
                            Some(found(checkout.payment_link.as_ref().map(StripeId::as_str)));
                    }
                }
                let over = Verdict::Refused(match (began.is_empty(), &elsewhere) {
                    (false, _) => Refusal::NoInvoice,
                    (true, None) => Refusal::NoSubscription,
                    (true, Some(found)) => Refusal::Differs(Difference::PaymentLink {
                        found: found.clone(),
                    }),
                });
                let step = match page.more_after {
                    Some(after) => Step::Subscriptions {
                        name,
                        from,
                        until,
                        after: Some(after),
                        began,
                        elsewhere,
                    },
                    None => match Step::invoices(began) {
                        Some(step) => step,
                        None => return Ok(Next::Done(over)),
                    },
                };
                (step, over)
            }
            Step::Invoices {
                subscription, rest, ..
            } => {
                let list: List<Invoice> = decode(body, "invoice")?;
                let page = Page::of(&list, "invoice")?;
                if let Some(invoice) = list
                    .data
                    .iter()
                    .find(|invoice| OrderId::for_renewal(invoice.id.as_str()) == target.order)
                {
                    return Ok(Next::Done(match judge_invoice(invoice, &target.terms) {
                        Ok(()) => Verdict::Confirmed,
                        Err(refusal) => Verdict::Refused(refusal),
                    }));
                }
                let over = Verdict::Refused(Refusal::NoInvoice);
                let step = match page.more_after {
                    Some(after) => Step::Invoices {
                        subscription,
                        after: Some(after),
                        rest,
                    },
                    None => match Step::invoices(rest) {
                        Some(step) => step,
                        None => return Ok(Next::Done(over)),
                    },
                };
                (step, over)
            }
        };
        Ok(if pages < MAX_PAGES {
            Next::Ask(Self {
                target,
                step,
                pages,
            })
        } else {
            Next::Done(over)
        })
    }
}

/// What a page says of the pages after it.
struct Page {
    /// The last object's id, when Stripe has more after it.
    more_after: Option<StripeId>,
}

impl Page {
    /// Checks that every object of `list` is a `what`, and that a page that
    /// says there are more lists one to go on from.
    fn of<T: Kind>(list: &List<T>, what: &'static str) -> Result<Self, StripeAnswerError> {
        if list.data.iter().any(|object| object.object() != what) {
            return Err(StripeAnswerError::Object { what });
        }
        if !list.has_more {
            return Ok(Self { more_after: None });
        }
        let last = list
            .data
            .last()
            .ok_or(StripeAnswerError::EmptyPage { what })?;
        Ok(Self {
            more_after: Some(last.id().clone()),
        })
    }
}

/// The checkouts of `list` that name the order `name`.
fn naming<'a>(list: &'a List<Checkout>, name: &'a OrderId) -> impl Iterator<Item = &'a Checkout> {
    list.data
        .iter()
        .filter(move |checkout| checkout.client_reference_id.as_deref() == Some(name.as_str()))
}

/// An object of a list: its kind (`object`) and its id.
trait Kind {
    fn object(&self) -> &str;
    fn id(&self) -> &StripeId;
}

impl Kind for Checkout {
    fn object(&self) -> &str {
        &self.object
    }

    fn id(&self) -> &StripeId {
        &self.id
    }
}

impl Kind for Invoice {
    fn object(&self) -> &str {
        &self.object
    }

    fn id(&self) -> &StripeId {
        &self.id
    }
}

/// Decodes a list of `what`.
fn decode<T: for<'de> Deserialize<'de>>(
    body: &[u8],
    what: &'static str,
) -> Result<List<T>, StripeAnswerError> {
    let list: List<T> = serde_json::from_slice(body)
        .map_err(|source| StripeAnswerError::Decode { what, source })?;
    if list.object != "list" {
        return Err(StripeAnswerError::Object { what });
    }
    Ok(list)
}

/// The closer of two refusals; the earlier on a tie.
fn closer(best: Option<Refusal>, refusal: Refusal) -> Refusal {
    match best {
        Some(best) if best.closeness() >= refusal.closeness() => best,
        _ => refusal,
    }
}

/// A value of Stripe's for the log: escaped, cut, `none` when absent.
fn found(value: Option<&str>) -> String {
    let text = value.map_or_else(|| "none".to_owned(), printable);
    text.chars().take(MAX_FOUND_CHARS).collect()
}

/// Whether `checkout` pays the order of `terms`: paid, in live mode, of
/// the plan's mode, in its currency and for its amount, and on one of
/// `links` when the Mac knows the plan's.
fn judge_checkout(
    checkout: &Checkout,
    terms: &OrderTerms,
    links: &[StripeId],
) -> Result<(), Refusal> {
    if checkout.payment_status != "paid" {
        return Err(Refusal::Unpaid);
    }
    if !checkout.livemode {
        return Err(Refusal::Differs(Difference::TestMode));
    }
    let wanted = match terms.plan_kind {
        PortalPlanKind::MonthAuto => "subscription",
        PortalPlanKind::Month | PortalPlanKind::Traffic => "payment",
    };
    if checkout.mode != wanted {
        return Err(Refusal::Differs(Difference::Mode {
            found: found(Some(&checkout.mode)),
            wanted,
        }));
    }
    if checkout.currency.as_deref() != Some(terms.currency.as_str()) {
        return Err(Refusal::Differs(Difference::Currency {
            found: found(checkout.currency.as_deref()),
        }));
    }
    if checkout.amount_total != Some(terms.amount.get()) {
        return Err(Refusal::Differs(Difference::Amount {
            found: checkout.amount_total,
        }));
    }
    if !checkout.on_link(links) {
        return Err(Refusal::Differs(Difference::PaymentLink {
            found: found(checkout.payment_link.as_ref().map(StripeId::as_str)),
        }));
    }
    Ok(())
}

/// The subscription `checkout` began, when it is a paid live checkout of a
/// subscription.
fn began_subscription(checkout: &Checkout) -> Option<&StripeId> {
    let began =
        checkout.payment_status == "paid" && checkout.livemode && checkout.mode == "subscription";
    began.then_some(checkout.subscription.as_ref()).flatten()
}

/// Whether `invoice` pays the renewal of `terms`: paid, in live mode, a
/// renewal of its subscription, in its currency and for its amount.
fn judge_invoice(invoice: &Invoice, terms: &OrderTerms) -> Result<(), Refusal> {
    if invoice.status.as_deref() != Some("paid") {
        return Err(Refusal::Unpaid);
    }
    if !invoice.livemode {
        return Err(Refusal::Differs(Difference::TestMode));
    }
    if invoice.billing_reason.as_deref() != Some("subscription_cycle") {
        return Err(Refusal::Differs(Difference::Reason {
            found: found(invoice.billing_reason.as_deref()),
        }));
    }
    if invoice.currency != terms.currency.as_str() {
        return Err(Refusal::Differs(Difference::Currency {
            found: found(Some(&invoice.currency)),
        }));
    }
    if invoice.amount_paid != terms.amount.get() {
        return Err(Refusal::Differs(Difference::Amount {
            found: Some(invoice.amount_paid),
        }));
    }
    Ok(())
}
