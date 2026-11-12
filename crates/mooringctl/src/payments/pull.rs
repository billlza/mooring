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
//! - **A ledger that cannot be read** at the daemon's start stops the pull
//!   until the daemon starts again: it is never read as an empty one, which
//!   would grant every order again.
//! - **Refunds that wait for the usage.** A refund in full of a traffic
//!   pack waits until the usage tells the user's use at its time
//!   ([`Puller::settle`]): asked at most every [`SETTLE_EVERY`] while one
//!   waits, whatever the pull's state. A fault of the usage is logged once
//!   while it lasts; usage that is only behind is not.
//!
//! The token is read from the keychain again whenever the settings change,
//! and kept in memory in a zeroizing buffer; no note holds it.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_daemon_core::error::UsageErrorKind;
use mooring_daemon_core::payments::{
    ApplyRefusal, Entitlements, FeedPage, MAX_LEDGER_BYTES, MAX_SETTINGS_BYTES, PaymentLedger,
    PullSettings, Stop, StopReason,
};
use mooring_daemon_core::period::BillingCycle;
use mooring_model::secret::{SecretMaterial, SecretRef};
use mooring_model::{Deployment, PortalPullToken, UnixTime, User, UserId};
use mooring_store::{read_payment_ledger, read_payment_pull, write_payment_ledger};

use super::curl::PullRequest;
use super::judge::{Judged, judge};
use super::notes::{describe, stamp};
use crate::app::Env;

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

/// What the usage tells of the bytes the nodes had counted for a user
/// before an instant: `Ok(None)` while it cannot tell yet, `Err` with the
/// kind of a fault.
pub(crate) type UseTold = Result<Option<u64>, UsageErrorKind>;

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
    /// The last state logged, so that each is logged once.
    state: Option<String>,
    /// When a prune whose write failed is tried again.
    prune_retry: Option<Instant>,
    /// When the usage is next asked about the refunds that wait for it;
    /// `None`: at once.
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
            state: None,
            prune_retry: None,
            settle_next: None,
            settle_fault: None,
        }
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

    /// Ends the wait of the refunds in full of traffic packs whose use
    /// the usage can tell now (design §9.6), on the tick at `tick`.
    /// `served_before` tells the bytes the nodes had counted for a user in
    /// `cycle`, the billing cycle `now` is in, before an instant:
    /// `Ok(None)` while the usage cannot tell yet, `Err` with the kind of
    /// a fault of the usage. A refund whose pack's cycle has ended takes
    /// nothing back, unasked.
    ///
    /// - The usage is asked at most every [`SETTLE_EVERY`], and only while
    ///   a refund waits.
    /// - The settled ledger is written before it is kept; a write that
    ///   fails is said and tried again.
    /// - A fault leaves its refund waiting and is logged, by its kind, when
    ///   it is not the fault of the asking before.
    ///
    /// Returns the lines to log, which name orders and no user.
    pub(crate) fn settle(
        &mut self,
        tick: Instant,
        now: UnixTime,
        cycle: BillingCycle,
        served_before: &dyn Fn(&UserId, UnixTime) -> UseTold,
    ) -> Vec<String> {
        if self.ledger.awaiting_usage().next().is_none()
            || self.settle_next.is_some_and(|at| tick < at)
        {
            return Vec::new();
        }
        self.settle_next = Some(tick + SETTLE_EVERY);
        // The first fault of this asking, if the usage had one.
        let fault = Cell::new(None);
        let settled = self.ledger.settle(now, cycle, &|user, at| {
            served_before(user, at).unwrap_or_else(|kind| {
                fault.set(fault.get().or(Some(kind)));
                None
            })
        });
        let mut notes = Vec::new();
        let fault = fault.get();
        if let Some(kind) = fault.filter(|_| fault != self.settle_fault) {
            notes.push(format!(
                "payment ledger: the usage collected cannot tell the use at the refund(s) of traffic packs that wait for it ({kind}); they wait on"
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
                "payment ledger: the use at {} refund(s) of traffic packs could not be recorded ({error}); trying again in {} s",
                settled.events.len(),
                SETTLE_EVERY.as_secs()
            )),
        }
        notes
    }

    /// One tick of the pull: reads the settings, and when the pull is set
    /// up, not stopped, due and allowed by `gate`, makes one request at
    /// `now` for `users`. Returns the lines to log.
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
            token: &token,
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
            Ok(answer) => self.answered(judge(answer, cursor), users, now, &settings, &mut notes),
        }
        notes
    }

    fn answered(
        &mut self,
        judged: Judged,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
        settings: &PullSettings,
        notes: &mut Vec<String>,
    ) {
        match judged {
            Judged::Page(page) => self.record(&page, users, now, settings, notes),
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

    /// Applies `page` to a copy of the ledger, writes it, and only then
    /// keeps it. A refund in full of a traffic pack that the page holds
    /// waits for the usage ([`Self::settle`]).
    fn record(
        &mut self,
        page: &FeedPage,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
        settings: &PullSettings,
        notes: &mut Vec<String>,
    ) {
        let applied = match self.ledger.apply(page, users, now, settings.rehearsal()) {
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
            "payment pull: stopped: {why} ({text}); it pulls again once its settings change (`mooringctl portal connect` or `portal rehearsal`)"
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
                    // A change of the settings may come with a new token,
                    // and a revision may come again after the file was
                    // lost: the token is read again.
                    self.token = None;
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
