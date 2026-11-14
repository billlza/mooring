// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's payment pull (design §9.6): on the deployed daemon's tick,
//! when its settings say so and it is due, one request for the portal's
//! entries after the ledger's cursor; a page that decodes is applied to a
//! copy of the ledger, which is written before it is kept, so the cursor
//! and everything the page did are one write (contract §5.1).
//!
//! - **When.** Every [`PULL_EVERY`]; at once while a page says `more`;
//!   after a failure that may pass, [`RETRY_FIRST`] doubling to
//!   [`RETRY_MOST`]; after 429, the portal's `Retry-After` ([`judge`]).
//! - **Only where it may.** The daemon passes a [`Gate`]: the room the next
//!   probe round leaves, and a check, made right before the request, that
//!   the Mac is on no foreign network (F15: the pull never crosses Janet).
//! - **A ledger that cannot be read** is said again every hour, since the
//!   console then shows each user's own record only, without what they
//!   paid for.
//! - **Stops.** 400, 401, 409 and a page that does not fit the ledger stop
//!   the pull, recorded in the ledger with the settings' revision, until
//!   the operator changes the settings. A 409 never lowers the cursor.
//! - **The check against Stripe** ([`super::confirm`]), while the settings
//!   have it on: a page waits in memory until Stripe has said what it
//!   knows of each live grant that would give, one request of Stripe's
//!   per tick, through the same gate; then it is applied whole. Stripe's
//!   400, 401, 403 and 404 stop the pull; its 429 waits; any other failure
//!   is tried again as the portal's are.
//! - **A ledger that cannot be read** at the daemon's start stops the pull
//!   until the daemon starts again: it is never read as an empty one, which
//!   would grant every order again.
//! - **Refunds that wait for the usage.** A refund in full of a traffic
//!   pack waits until the usage tells the user's use at its time, and
//!   that use takes in REALITY downloads counted later until each node's
//!   Xray has started again ([`Puller::settle`]): asked at most every
//!   [`SETTLE_EVERY`] while either lasts, whatever the pull's state. A
//!   fault of the usage is logged once while it lasts; usage that is only
//!   behind is not.
//!
//! The token, and Stripe's read key while the check is on, are read from
//! the keychain again whenever the settings change, and kept in memory in
//! zeroizing buffers; no note holds either.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_daemon_core::error::UsageErrorKind;
use mooring_daemon_core::payments::{
    Applied, ApplyRefusal, Entitlements, FeedPage, Lookup, MAX_LEDGER_BYTES, MAX_SETTINGS_BYTES,
    PaymentLedger, PullSettings, RefundUsage, RunBegan, Stop, StopReason,
};
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::usage::{DownlinkCount, ServedBefore};
use mooring_model::secret::{SecretMaterial, SecretRef};
use mooring_model::{Deployment, NodeId, PortalPullToken, StripeReadKey, UnixTime, User, UserId};
use mooring_store::{read_payment_ledger, read_payment_pull, write_payment_ledger};

use super::confirm::{Pending, Wanted};
use super::curl::{Credential, PullRequest};
use super::judge::{Judged, StripeJudged, judge, judge_stripe};
use super::notes::{describe, stamp};
use crate::app::Env;
use crate::collected_usage::Told;

pub(crate) use super::judge::PULL_EVERY;

/// The first wait after a failure that may pass.
pub(crate) const RETRY_FIRST: Duration = Duration::from_secs(60);

/// The longest wait after failures that may pass.
pub(crate) const RETRY_MOST: Duration = Duration::from_secs(1800);

/// The least room a request is started in.
pub(crate) const MIN_ROOM: Duration = Duration::from_secs(1);

/// How often a ledger that cannot be read is said again.
pub(crate) const FAULT_EVERY: Duration = Duration::from_secs(3600);

/// How often the usage is asked about the refunds that wait for it: as
/// often as the usage is collected.
pub(crate) const SETTLE_EVERY: Duration = Duration::from_secs(60);

/// What the daemon reads at one instant for the traffic packs refunded in
/// full (design §9.6): the usage collected, and each node's latest status.
pub(crate) trait RefundReadings {
    /// What `user` had served in the billing cycle before `at`, at most,
    /// with what each node had counted of their REALITY downlink.
    fn served_before(&self, user: &UserId, at: UnixTime) -> Told<ServedBefore>;

    /// What each node has counted of `user`'s REALITY downlink in the
    /// billing cycle.
    fn reality_downlink(&self, user: &UserId) -> Told<BTreeMap<NodeId, DownlinkCount>>;

    /// When the run of Xray that `node`'s latest status shows began;
    /// `None` without a status that shows Xray running.
    fn xray_began(&self, node: &NodeId) -> Option<RunBegan>;
}

/// The readings as the ledger asks them: a fault of the usage is no
/// answer, and the first of an asking is kept.
struct Asked<'a> {
    readings: &'a dyn RefundReadings,
    fault: Cell<Option<UsageErrorKind>>,
}

impl Asked<'_> {
    fn answer<T>(&self, told: Told<T>) -> Option<T> {
        told.unwrap_or_else(|kind| {
            self.fault.set(self.fault.get().or(Some(kind)));
            None
        })
    }
}

impl RefundUsage for Asked<'_> {
    fn served_before(&self, user: &UserId, at: UnixTime) -> Option<ServedBefore> {
        self.answer(self.readings.served_before(user, at))
    }

    fn reality_downlink(&self, user: &UserId) -> Option<BTreeMap<NodeId, DownlinkCount>> {
        self.answer(self.readings.reality_downlink(user))
    }

    fn xray_began(&self, node: &NodeId) -> Option<RunBegan> {
        self.readings.xray_began(node)
    }
}

/// What a tick applies a page with: the deployment's users, the time, and
/// the settings it read.
#[derive(Clone, Copy)]
struct Applying<'a> {
    users: &'a BTreeMap<UserId, User>,
    now: UnixTime,
    settings: &'a PullSettings,
}

/// Whether a request may be made on this tick.
pub(crate) struct Gate<'g> {
    /// The room the next probe round leaves, if there is any.
    pub(crate) room: Option<Duration>,
    /// Whether the Mac is on no foreign network: asked right before the
    /// request, and only then.
    pub(crate) network_clear: &'g mut dyn FnMut() -> bool,
}

impl std::fmt::Debug for Gate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("room", &self.room)
            .finish_non_exhaustive()
    }
}

/// The daemon's payment pull, between ticks.
pub(crate) struct Puller {
    support: PathBuf,
    /// The ledger: as on disk, with every page written since.
    ledger: PaymentLedger,
    /// Why the ledger could not be read at the start, if it could not: the
    /// pull then makes no request, and `ledger` is empty and unused.
    fault: Option<String>,
    /// The settings last read, if any.
    settings: Option<PullSettings>,
    /// The last failure to read the settings, logged once.
    settings_fault: Option<String>,
    /// When the next request is due; `None`: at once.
    next: Option<Instant>,
    /// The wait after the next failure that may pass.
    retry: Duration,
    /// The token, and the settings revision it was read for.
    token: Option<(u64, PortalPullToken)>,
    /// Stripe's read key, and the settings revision it was read for.
    stripe_key: Option<(u64, StripeReadKey)>,
    /// The page that waits for the check against Stripe, if one does.
    pending: Option<Pending>,
    /// The last state logged, so that each is logged once.
    state: Option<String>,
    /// When a prune whose write failed is tried again.
    prune_retry: Option<Instant>,
    /// When the usage is next asked about the refunds in full of traffic
    /// packs; `None`: at once.
    settle_next: Option<Instant>,
    /// The fault that kept the usage from telling at the latest asking, if
    /// one did: logged when it changes.
    settle_fault: Option<UsageErrorKind>,
}

/// Names the cursor and the schedule, never the token.
impl std::fmt::Debug for Puller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Puller")
            .field("support", &self.support)
            .field("cursor", &self.ledger.cursor())
            .field("fault", &self.fault)
            .field("settings", &self.settings)
            .field("next", &self.next)
            .field("retry", &self.retry)
            .field("waits_for_stripe", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl Puller {
    /// The pull of the support directory `support`, with the ledger as it
    /// is on disk: none is an empty ledger; one that cannot be read stops
    /// the pull until the daemon starts again.
    pub(crate) fn open(support: &Path) -> Self {
        let read = match read_payment_ledger(support, MAX_LEDGER_BYTES + 1) {
            Ok(None) => Ok(PaymentLedger::new()),
            Ok(Some(bytes)) => PaymentLedger::decode(&bytes).map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let (ledger, fault) = match read {
            Ok(ledger) => (ledger, None),
            Err(error) => (PaymentLedger::new(), Some(error)),
        };
        // The daemon says a fault at its start; it is said again an hour on.
        let next = fault.as_ref().map(|_| Instant::now() + FAULT_EVERY);
        Self {
            support: support.to_path_buf(),
            ledger,
            fault,
            settings: None,
            settings_fault: None,
            next,
            retry: RETRY_FIRST,
            token: None,
            stripe_key: None,
            pending: None,
            state: None,
            prune_retry: None,
            settle_next: None,
            settle_fault: None,
        }
    }

    /// Makes the next request due at once, as the wait after a failure
    /// would once it has passed.
    #[cfg(test)]
    pub(crate) fn due_now(&mut self) {
        self.next = None;
    }

    /// How long the pull waits before its next request, if it waits.
    #[cfg(test)]
    pub(crate) fn due_in(&self) -> Option<Duration> {
        self.next
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// Why the ledger could not be read at the start, if it could not.
    pub(crate) fn fault(&self) -> Option<String> {
        self.fault.as_ref().map(|error| {
            format!("payment pull: the payment ledger cannot be read ({error}); nothing is pulled until the daemon starts again, and the console shows each user's own record only, without what they paid for")
        })
    }

    /// What the users' paid orders give, by the ledger in memory and the
    /// rehearsal the settings last read say; none while the ledger cannot
    /// be read.
    pub(crate) fn entitlements(&self) -> Entitlements {
        if self.fault.is_some() {
            return Entitlements::none();
        }
        let rehearsal = self.settings.as_ref().is_some_and(PullSettings::rehearsal);
        self.ledger.entitlements(rehearsal)
    }

    /// Deletes the orders of users removed from `deployment` (design §9.6;
    /// the agreement's clause 4): the pruned ledger is written before it is
    /// kept; a write that fails is said and tried again [`RETRY_FIRST`]
    /// later. A ledger that could not be read is held as an empty one, so
    /// nothing is pruned, and its file is left as it is. Returns the lines
    /// to log, which count users and orders and name none.
    pub(crate) fn prune(&mut self, deployment: &Deployment) -> Vec<String> {
        if self.prune_retry.is_some_and(|at| Instant::now() < at) {
            return Vec::new();
        }
        let Some((pruned, counts)) = self.ledger.without_removed_users(deployment) else {
            return Vec::new();
        };
        match self.write(&pruned) {
            Ok(()) => {
                self.ledger = pruned;
                self.prune_retry = None;
                vec![format!(
                    "payment ledger: deleted {} order(s) of {} removed user(s)",
                    counts.orders, counts.users
                )]
            }
            Err(error) => {
                self.prune_retry = Some(Instant::now() + RETRY_FIRST);
                vec![format!(
                    "payment ledger: the orders of {} removed user(s) could not be deleted ({error}); trying again in {} s",
                    counts.users,
                    RETRY_FIRST.as_secs()
                )]
            }
        }
    }

    /// Records what can be told now of the traffic packs refunded in full
    /// (design §9.6; [`PaymentLedger::settle`]), on the tick at `tick`:
    /// the use at a refund that waits for the usage, and the end of the
    /// downloads that were open at a refund, node by node as its Xray is
    /// seen to have started again. `readings` tells what the usage
    /// collected and the nodes' statuses do at `now`, in `cycle`, the
    /// billing cycle `now` is in. A pack whose cycle has ended is settled
    /// unasked.
    ///
    /// - The ledger is asked at most every [`SETTLE_EVERY`], and only
    ///   while a refund waits or a use still takes in downloads.
    /// - The settled ledger is written before it is kept; a write that
    ///   fails is said and tried again.
    /// - A fault of the usage leaves things as they are and is logged, by
    ///   its kind, when it is not the fault of the asking before.
    ///
    /// Returns the lines to log, which name orders and no user.
    pub(crate) fn settle(
        &mut self,
        tick: Instant,
        now: UnixTime,
        cycle: BillingCycle,
        readings: &dyn RefundReadings,
    ) -> Vec<String> {
        let pending = self.ledger.awaiting_usage().next().is_some()
            || self.ledger.open_downloads().next().is_some();
        if !pending || self.settle_next.is_some_and(|at| tick < at) {
            return Vec::new();
        }
        self.settle_next = Some(tick + SETTLE_EVERY);
        let asked = Asked {
            readings,
            fault: Cell::new(None),
        };
        let settled = self.ledger.settle(now, cycle, &asked);
        let mut notes = Vec::new();
        let fault = asked.fault.get();
        if let Some(kind) = fault.filter(|_| fault != self.settle_fault) {
            notes.push(format!(
                "payment ledger: the usage collected cannot tell what the refund(s) in full of traffic packs wait for ({kind}); they wait on"
            ));
        }
        self.settle_fault = fault;
        let Some(settled) = settled else {
            return notes;
        };
        match self.write(&settled.ledger) {
            Ok(()) => {
                self.ledger = settled.ledger;
                notes.extend(settled.events.iter().map(describe));
            }
            Err(error) => notes.push(format!(
                "payment ledger: what was learned of the refund(s) in full of traffic packs ({} change(s)) could not be recorded ({error}); trying again in {} s",
                settled.events.len(),
                SETTLE_EVERY.as_secs()
            )),
        }
        notes
    }

    /// One tick of the pull: reads the settings, and when the pull is set
    /// up, not stopped, due and allowed by `gate`, makes one request at
    /// `now` for `users`: of Stripe's while a page waits for the check
    /// against Stripe, else of the portal's. Returns the lines to log.
    pub(crate) fn tick(
        &mut self,
        env: &Env<'_>,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
        gate: Gate<'_>,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        if self.fault.is_some() {
            if self.next.is_none_or(|at| Instant::now() >= at) {
                notes.extend(self.fault());
                self.next = Some(Instant::now() + FAULT_EVERY);
            }
            return notes;
        }
        self.read_settings(&mut notes);
        let Some(settings) = self.settings.clone() else {
            return notes;
        };
        let Some(origin) = settings.origin().cloned() else {
            self.say_state(&mut notes, "payment pull: disconnected");
            return notes;
        };
        if let Some(stop) = self.ledger.stopped() {
            if stop.settings_revision >= settings.revision() {
                self.say_state(
                    &mut notes,
                    &format!(
                        "payment pull: stopped ({}) since {}, until its settings change",
                        stop.reason.as_str(),
                        stamp(stop.at)
                    ),
                );
                return notes;
            }
            notes.push(format!(
                "payment pull: its settings changed since it stopped ({}); pulling again",
                stop.reason.as_str()
            ));
            let resumed = self.ledger.with_stop(None);
            if let Err(error) = self.write(&resumed) {
                notes.push(format!(
                    "payment pull: the stop's end could not be recorded in the payment ledger ({error}); `portal payments` shows it until a page is recorded"
                ));
            }
            self.ledger = resumed;
            self.next = None;
            self.retry = RETRY_FIRST;
        }
        if self.next.is_some_and(|at| Instant::now() < at) {
            return notes;
        }
        let Some(room) = gate.room.filter(|room| *room >= MIN_ROOM) else {
            return notes;
        };
        if !(gate.network_clear)() {
            self.say_state(
                &mut notes,
                "payment pull: waiting while the Mac is on a network other than the M7 and the declared own networks",
            );
            return notes;
        }
        let at = Applying {
            users,
            now,
            settings: &settings,
        };
        if let Some(pending) = self.pending.take() {
            self.ask_stripe(pending, env, at, room, &mut notes);
            return notes;
        }
        let token = match self.token(env, settings.revision()) {
            Ok(token) => token,
            Err(why) => {
                notes.push(format!("payment pull: {why}"));
                self.retry_later();
                return notes;
            }
        };
        let cursor = self.ledger.cursor();
        let request = PullRequest {
            url: origin.entitlements_url(cursor),
            credential: Credential::Portal(&token),
            within: room,
        };
        match env.portal.fetch(&request) {
            Err(failure) => {
                notes.push(format!(
                    "payment pull: no answer from the portal: {failure}"
                ));
                self.state = None;
                self.retry_later();
            }
            Ok(answer) => self.answered(judge(answer, cursor), at, &mut notes),
        }
        notes
    }

    fn answered(&mut self, judged: Judged, at: Applying<'_>, notes: &mut Vec<String>) {
        let Applying { now, settings, .. } = at;
        match judged {
            Judged::Page(page) => self.received(page, at, notes),
            Judged::Refused(error) => {
                self.failed(
                    notes,
                    format!(
                        "payment pull: the portal's document was refused, and the cursor stays: {error}"
                    ),
                );
            }
            Judged::Stop { reason, text } => {
                self.stop(reason, &text, now, settings.revision(), notes);
            }
            Judged::NotSelling => self.failed(
                notes,
                "payment pull: the portal answered 404: it sells nothing (it runs without its catalogue)"
                    .to_owned(),
            ),
            Judged::Throttled { wait, stated } => {
                notes.push(format!(
                    "payment pull: the portal answered 429 (Retry-After: {}); asking again in {} s",
                    stated.as_deref().unwrap_or("none"),
                    wait.as_secs()
                ));
                self.state = None;
                self.next = Some(Instant::now() + wait);
            }
            Judged::PortalFailed { status, text } => self.failed(
                notes,
                format!("payment pull: the portal failed ({status}: {text}); the cursor stays"),
            ),
            Judged::Unexpected { status, text } => self.failed(
                notes,
                format!(
                    "payment pull: the portal answered {status}, which the contract has no meaning for ({text}); the cursor stays"
                ),
            ),
        }
    }

    /// A page the portal sent: applied at once while the check against
    /// Stripe is off, else held until Stripe has said what it knows of
    /// its grants.
    fn received(&mut self, page: FeedPage, at: Applying<'_>, notes: &mut Vec<String>) {
        let Applying {
            users,
            now,
            settings,
        } = at;
        if settings.stripe_check() {
            let pending = Pending::new(page);
            self.confirm(pending, at, notes);
        } else {
            let applied = self.ledger.apply_planned(
                &page,
                users,
                now,
                settings.rehearsal(),
                settings.plans(),
            );
            self.record(&page, applied, now, settings, notes);
        }
    }

    /// Moves the page that waits for the check as far as it goes without
    /// a request: it is recorded once it needs nothing more of Stripe, or
    /// kept for the lookup that asks Stripe on a later tick.
    fn confirm(&mut self, mut pending: Pending, at: Applying<'_>, notes: &mut Vec<String>) {
        let Some((lookup, left)) = self.lookup_next(&mut pending, at, notes) else {
            return;
        };
        self.say_state(
            notes,
            &format!(
                "payment pull: asking Stripe about the payment of order {} ({left} grant(s) of the page wait for the check against Stripe)",
                lookup.target().order
            ),
        );
        self.pending = Some(pending);
        self.retry = RETRY_FIRST;
        self.next = None;
    }

    /// The lookup the page that waits asks Stripe with next, and how many
    /// of its grants wait; none once the page needs nothing more of
    /// Stripe, which is then recorded, applied as Stripe said or refused
    /// as without the check.
    fn lookup_next(
        &mut self,
        pending: &mut Pending,
        at: Applying<'_>,
        notes: &mut Vec<String>,
    ) -> Option<(Lookup, usize)> {
        let Applying {
            users,
            now,
            settings,
        } = at;
        match pending.wanted(
            &self.ledger,
            users,
            now,
            settings.rehearsal(),
            settings.plans(),
        ) {
            Wanted::Done(applied) => {
                self.record(pending.page(), applied, now, settings, notes);
                None
            }
            Wanted::Ask { lookup, left } => Some((lookup, left)),
        }
    }

    /// The one request of a tick while a page waits for the check: the next
    /// of the lookup under way, unless the page needs no more of Stripe.
    fn ask_stripe(
        &mut self,
        mut pending: Pending,
        env: &Env<'_>,
        at: Applying<'_>,
        room: Duration,
        notes: &mut Vec<String>,
    ) {
        let Some((lookup, _)) = self.lookup_next(&mut pending, at, notes) else {
            return;
        };
        let Applying { now, settings, .. } = at;
        let key = match self.stripe_key(env, settings.revision()) {
            Ok(key) => key,
            Err(why) => {
                self.pending = Some(pending);
                notes.push(format!("payment pull: {why}"));
                self.retry_later();
                return;
            }
        };
        let request = PullRequest {
            url: lookup.url(),
            credential: Credential::Stripe(&key),
            within: room,
        };
        let answer = match env.portal.fetch(&request) {
            Ok(answer) => answer,
            Err(failure) => {
                self.pending = Some(pending);
                notes.push(format!("payment pull: no answer from Stripe: {failure}"));
                self.state = None;
                self.retry_later();
                return;
            }
        };
        match judge_stripe(answer) {
            StripeJudged::Page(body) => match pending.read(lookup, &body) {
                Ok(()) => self.confirm(pending, at, notes),
                Err(error) => {
                    self.pending = Some(pending);
                    self.failed(
                        notes,
                        format!("payment pull: {error}; the page waits, and Stripe is asked again"),
                    );
                }
            },
            StripeJudged::Stop { reason, text } => {
                self.stop(reason, &text, now, settings.revision(), notes);
            }
            StripeJudged::Throttled { wait, stated } => {
                self.pending = Some(pending);
                notes.push(format!(
                    "payment pull: Stripe answered 429 (Retry-After: {}); asking again in {} s",
                    stated.as_deref().unwrap_or("none"),
                    wait.as_secs()
                ));
                self.state = None;
                self.next = Some(Instant::now() + wait);
            }
            StripeJudged::Failed { status, text } => {
                self.pending = Some(pending);
                self.failed(
                    notes,
                    format!(
                        "payment pull: Stripe answered {status} ({text}); the page waits, and Stripe is asked again"
                    ),
                );
            }
        }
    }

    /// Writes the ledger `applied` gave from `page`, and only then keeps
    /// it; or acts on why the page could not be applied. A refund in full
    /// of a traffic pack that the page holds waits for the usage
    /// ([`Self::settle`]).
    fn record(
        &mut self,
        page: &FeedPage,
        applied: Result<Applied, ApplyRefusal>,
        now: UnixTime,
        settings: &PullSettings,
        notes: &mut Vec<String>,
    ) {
        let applied = match applied {
            Ok(applied) => applied,
            Err(ApplyRefusal::TestMode) => {
                self.say_state(
                    notes,
                    "payment pull: the portal's payments are of Stripe's test mode and no rehearsal is on; nothing is granted and the cursor stays",
                );
                self.retry = RETRY_FIRST;
                self.next = Some(Instant::now() + PULL_EVERY);
                return;
            }
            // A page that does not fit the ledger: one that contradicts
            // it, or (which the decoding, checked against the cursor, does
            // not let through) one that follows another cursor.
            Err(
                refusal @ (ApplyRefusal::Contradicted { .. } | ApplyRefusal::CursorMoved { .. }),
            ) => {
                let detail = refusal.to_string();
                self.stop(
                    StopReason::Inconsistent,
                    &detail,
                    now,
                    settings.revision(),
                    notes,
                );
                return;
            }
        };
        if let Err(error) = self.write(&applied.ledger) {
            self.failed(
                notes,
                format!(
                    "payment pull: the payment ledger could not be written ({error}); nothing of the page is kept, and it is asked for again"
                ),
            );
            return;
        }
        notes.extend(applied.events.iter().map(describe));
        self.ledger = applied.ledger;
        self.retry = RETRY_FIRST;
        self.next = if page.more() {
            None
        } else {
            Some(Instant::now() + PULL_EVERY)
        };
        let cursor = self.ledger.cursor();
        self.say_state(
            notes,
            &format!("payment pull: pulling; the cursor is at {cursor}"),
        );
    }

    /// Stops the pull until the settings move past `revision`, and records
    /// the stop in the ledger.
    fn stop(
        &mut self,
        reason: StopReason,
        text: &str,
        now: UnixTime,
        revision: u64,
        notes: &mut Vec<String>,
    ) {
        let why = match reason {
            StopReason::Conflict => {
                "the portal answered 409: its journal ends before the cursor, so it is not the journal pulled before (a database restored from a backup, say); the cursor is never lowered"
            }
            StopReason::Unauthorized => {
                "the portal answered 401: the token is wrong, or the portal has none; make a new one with `mooring-portal pull-token` and give it to `mooringctl portal connect`"
            }
            StopReason::BadRequest => "the portal answered 400: it says this request is malformed",
            StopReason::Inconsistent => "a page does not fit the payment ledger",
            StopReason::StripeUnauthorized => {
                "Stripe answered 401: the read key is wrong or was revoked; make a new restricted key and give it to `mooringctl portal stripe-check on`"
            }
            StopReason::StripeForbidden => {
                "Stripe answered 403: the read key may not read checkouts or invoices; give it Read on Checkout Sessions and Invoices, or make a new one"
            }
            StopReason::StripeBadRequest => {
                "Stripe answered 400 or 404: it says the check's request is wrong"
            }
        };
        let change = match reason {
            StopReason::StripeUnauthorized
            | StopReason::StripeForbidden
            | StopReason::StripeBadRequest => {
                "`mooringctl portal stripe-check on` with a key, or `portal stripe-check off`"
            }
            StopReason::Conflict
            | StopReason::Unauthorized
            | StopReason::BadRequest
            | StopReason::Inconsistent => "`mooringctl portal connect` or `portal rehearsal`",
        };
        if reason == StopReason::Unauthorized {
            self.token = None;
        }
        self.ledger = self.ledger.with_stop(Some(Stop {
            reason,
            at: now,
            settings_revision: revision,
        }));
        notes.push(format!(
            "payment pull: stopped: {why} ({text}); it pulls again once its settings change ({change})"
        ));
        if let Err(error) = self.write(&self.ledger) {
            notes.push(format!(
                "payment pull: the stop could not be recorded in the payment ledger ({error}); it holds until the daemon starts again"
            ));
        }
        self.state = None;
        self.next = None;
    }

    /// Writes `ledger` durably.
    fn write(&self, ledger: &PaymentLedger) -> Result<(), String> {
        let bytes = ledger.encode().map_err(|error| error.to_string())?;
        write_payment_ledger(&self.support, &bytes).map_err(|error| error.to_string())
    }

    /// A failure that may pass: logs `text`, and waits before the next
    /// request.
    fn failed(&mut self, notes: &mut Vec<String>, text: String) {
        notes.push(text);
        self.state = None;
        self.retry_later();
    }

    /// The token for the settings `revision`, read from the keychain when
    /// the revision changed.
    fn token(&mut self, env: &Env<'_>, revision: u64) -> Result<PortalPullToken, String> {
        if let Some((read_for, token)) = &self.token
            && *read_for == revision
        {
            return Ok(token.clone());
        }
        match env.secrets.get(&SecretRef::PortalPullToken) {
            Ok(SecretMaterial::PortalPullToken(token)) => {
                self.token = Some((revision, token.clone()));
                Ok(token)
            }
            // The keychain decodes an item by its reference's kind.
            Ok(_) => Err("the keychain item portal/pull-token is not a pull token".to_owned()),
            Err(error) => Err(format!("the pull token cannot be read: {error}")),
        }
    }

    /// Stripe's read key for the settings `revision`, read from the keychain
    /// when the revision changed.
    fn stripe_key(&mut self, env: &Env<'_>, revision: u64) -> Result<StripeReadKey, String> {
        if let Some((read_for, key)) = &self.stripe_key
            && *read_for == revision
        {
            return Ok(key.clone());
        }
        match env.secrets.get(&SecretRef::StripeReadKey) {
            Ok(SecretMaterial::StripeReadKey(key)) => {
                self.stripe_key = Some((revision, key.clone()));
                Ok(key)
            }
            // The keychain decodes an item by its reference's kind.
            Ok(_) => Err("the keychain item stripe/read-key is not a Stripe read key".to_owned()),
            Err(error) => Err(format!(
                "the check against Stripe is on, and its read key cannot be read: {error}; the page waits"
            )),
        }
    }

    /// Reads the settings; a failure keeps none and is logged once.
    fn read_settings(&mut self, notes: &mut Vec<String>) {
        let read = read_payment_pull(&self.support, MAX_SETTINGS_BYTES + 1)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                bytes
                    .map(|bytes| PullSettings::decode(&bytes).map_err(|error| error.to_string()))
                    .transpose()
            });
        match read {
            Ok(settings) => {
                if self.settings_fault.take().is_some() {
                    notes.push("payment pull: its settings can be read again".to_owned());
                }
                if settings.as_ref().map(PullSettings::revision)
                    != self.settings.as_ref().map(PullSettings::revision)
                {
                    // A change of the settings may come with a new token
                    // or key, and a revision may come again after the file
                    // was lost: both are read again, and a page that waits
                    // for the check is fetched again under the new ones.
                    self.token = None;
                    self.stripe_key = None;
                    self.pending = None;
                    self.next = None;
                    self.retry = RETRY_FIRST;
                    self.state = None;
                }
                self.settings = settings;
            }
            Err(error) => {
                if self.settings_fault.as_deref() != Some(error.as_str()) {
                    notes.push(format!(
                        "payment pull: its settings cannot be read ({error}); nothing is pulled until they can"
                    ));
                    self.settings_fault = Some(error);
                }
                self.settings = None;
            }
        }
    }

    /// Logs `text` when it is not the state logged last.
    fn say_state(&mut self, notes: &mut Vec<String>, text: &str) {
        if self.state.as_deref() != Some(text) {
            notes.push(text.to_owned());
            self.state = Some(text.to_owned());
        }
    }

    /// Waits before the next request after a failure that may pass, and
    /// doubles the wait after that, to [`RETRY_MOST`].
    fn retry_later(&mut self) {
        self.next = Some(Instant::now() + self.retry);
        self.retry = (self.retry * 2).min(RETRY_MOST);
    }
}
