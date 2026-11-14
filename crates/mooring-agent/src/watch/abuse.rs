// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard's part of a tick (design §11.8). Every
//! [`ABUSE_READ_EVERY_TICKS`] ticks, with a generation that carries the
//! guard, the watch reads the measured sets and judges each served user.
//! A finding at its cut level cuts the user at once, under `gate.lock`:
//! the cut and its record are written to the abuse state, then the user's
//! address is added to the cut set. A finding at its alert level is
//! recorded, once an hour per user and finding. Records past their
//! retention are pruned at the same reading, and the state is written only
//! when the reading changed it. A user whose cut was lifted is judged only
//! on what followed the lift ([`readings`]).
//!
//! A reading that fails, or that the parser cannot read, finds nothing and
//! is reported (`AbuseGuardUnavailable{ReadFailed}`) until one succeeds; it
//! never touches the gate, so a guard that cannot measure leaves every
//! user served and the cuts in force. An abuse state the watch cannot read
//! is a reading it needs, as the holds are: it ends the watch, and the
//! gate stays closed until the state can be read, since a gate opened
//! without the cuts could serve a cut user. A cut the state cannot take
//! ends the watch too, for the same reason; an alert or a prune it cannot
//! take is reported as a state write that failed (`StateWrite`) and tried
//! again at the next reading, without touching the gate.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    ABUSE_READ_EVERY_TICKS, ABUSE_SUSPECTED_SECS, AbuseAction, AbuseCutEntry, AbuseFigures,
    AbuseFindings, AbuseGuardFault, InstalledWatchConfig, OpaqueUserId, UnixTime, WatchError,
    user_source,
};

use super::nft::nft;
use super::{Fatal, Watch};
use crate::abuse::detect::{FloodMinutes, UserReading, Verdict, judge, readings};
use crate::abuse::state::AbuseState;
use crate::abuse::{add_words, as_args, served_sources, sets};
use crate::host::Node;
use crate::paths::Paths;
use crate::store::{Lock, errno};

/// The conditions the guard raises at a tick, at most one of each kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct AbuseConditions {
    /// How many users are cut, when any is.
    cut: Option<u16>,
    /// How many users are suspected, when any is.
    suspected: Option<u16>,
    /// Why the guard cannot measure, when it cannot.
    unavailable: Option<AbuseGuardFault>,
}

impl AbuseConditions {
    /// The conditions, as the watch reports them.
    pub(super) fn errors(self) -> impl Iterator<Item = WatchError> {
        [
            self.cut.map(|users| WatchError::AbuseCut { users }),
            self.suspected
                .map(|users| WatchError::AbuseSuspected { users }),
            self.unavailable
                .map(|cause| WatchError::AbuseGuardUnavailable { cause }),
        ]
        .into_iter()
        .flatten()
    }
}

/// The guard's memory between ticks.
#[derive(Debug, Default)]
pub(super) struct AbuseWatch {
    /// Ticks since the watch started, which time the readings.
    ticks: u64,
    /// Whether the latest reading failed.
    read_failed: bool,
    floods: FloodMinutes,
}

impl Watch {
    /// The guard's part of a tick, with a generation installed, and the
    /// conditions it raises: `NotInstalled` alone for a generation rendered
    /// before the guard.
    pub(super) fn abuse_tick(
        &mut self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
        config: &InstalledWatchConfig,
    ) -> Result<AbuseConditions, Fatal> {
        if config.abuse_guard().is_none() {
            return Ok(AbuseConditions {
                unavailable: Some(AbuseGuardFault::NotInstalled),
                ..AbuseConditions::default()
            });
        }
        let due = self.abuse.ticks.is_multiple_of(ABUSE_READ_EVERY_TICKS);
        self.abuse.ticks = self.abuse.ticks.wrapping_add(1);
        let mut state = AbuseState::read(paths)?;
        if due {
            match sets::read(node) {
                None => self.abuse.read_failed = true,
                Some(measured) => {
                    self.abuse.read_failed = false;
                    let served = served_sources(config);
                    let cleared = state.cleared();
                    let readings = readings(&measured, &served, &cleared, now);
                    self.abuse.floods.retain(&readings, &cleared, now);
                    let verdicts: Vec<_> = readings
                        .iter()
                        .map(|(user, reading)| {
                            (user, reading, judge(user, reading, &mut self.abuse.floods))
                        })
                        .filter(|(_, _, verdict)| *verdict != Verdict::default())
                        .collect();
                    if !verdicts.is_empty() || state.prune_due(now) {
                        let _lock = Lock::exclusive(&paths.gate_lock())?;
                        state = AbuseState::read(paths)?;
                        let held = state.clone();
                        state.prune(now);
                        let cut = act(&mut state, &cleared, now, &verdicts);
                        if state != held
                            && let Err(error) = state.write(paths)
                        {
                            // A cut the state cannot keep ends the watch,
                            // and its unit closes the gate. An alert or a
                            // prune is tried again at the next reading, and
                            // the failure reported as the watch's own are.
                            if !cut.is_empty() {
                                return Err(error.into());
                            }
                            self.write_failed = Some(errno(&error));
                            state = held;
                        }
                        if !cut.is_empty() {
                            nft(node, &as_args(&add_words(&cut)))?;
                        }
                    }
                }
            }
        }
        let count = |users: usize| (users > 0).then(|| u16::try_from(users).unwrap_or(u16::MAX));
        Ok(AbuseConditions {
            cut: count(state.cuts().len()),
            suspected: count(state.suspected(now)),
            unavailable: self
                .abuse
                .read_failed
                .then_some(AbuseGuardFault::ReadFailed),
        })
    }
}

/// Records the verdicts in `state`, the abuse state as it is under
/// `gate.lock`. `judged` holds the lifts the readings were taken with
/// ([`AbuseState::cleared`]): a user whose cut was lifted since is left to
/// the next reading, which leaves out what they did before the lift.
/// Otherwise, for a user not cut: findings at a cut level cut the user,
/// with a `Cut` record, and findings at an alert level are recorded as an
/// alert, leaving out those recorded for the user within the last
/// [`ABUSE_SUSPECTED_SECS`]. A user the node cannot cut, since it holds the
/// most cut users already, has the cut-level findings recorded as an alert
/// under the same rule. Returns the addresses newly cut.
fn act(
    state: &mut AbuseState,
    judged: &BTreeMap<OpaqueUserId, UnixTime>,
    now: UnixTime,
    verdicts: &[(&OpaqueUserId, &UserReading, Verdict)],
) -> Vec<Ipv4Addr> {
    let since = UnixTime::from_secs(now.as_secs().saturating_sub(ABUSE_SUSPECTED_SECS));
    let lifted = state.cleared();
    let mut cut = Vec::new();
    for (user, reading, verdict) in verdicts {
        if lifted.get(*user) != judged.get(*user) || state.cuts().get(user).is_some() {
            continue;
        }
        let figures = Some(reading.figures);
        if let Some(findings) = verdict.cut {
            let mut trial = state.clone();
            let record = trial.record(now, user, AbuseAction::Cut { findings }, figures);
            let entry = AbuseCutEntry {
                user: (*user).clone(),
                since: now,
                record,
            };
            if trial.cut(entry).is_ok() {
                *state = trial;
                cut.push(user_source(user));
            } else {
                alert(state, user, findings, figures, now, since);
            }
        } else if let Some(findings) = verdict.alert {
            alert(state, user, findings, figures, now, since);
        }
    }
    cut
}

/// Records `findings` for `user` as an alert at `now`, leaving out those
/// recorded for the user at or after `since`; nothing when none is left.
fn alert(
    state: &mut AbuseState,
    user: &OpaqueUserId,
    findings: AbuseFindings,
    figures: Option<AbuseFigures>,
    now: UnixTime,
    since: UnixTime,
) {
    let fresh = findings
        .iter()
        .filter(|finding| !state.found_since(user, *finding, since))
        .fold(None, |set: Option<AbuseFindings>, finding| {
            Some(set.map_or(AbuseFindings::of(finding), |set| set.with(finding)))
        });
    if let Some(findings) = fresh {
        state.record(now, user, AbuseAction::Alerted { findings }, figures);
    }
}
