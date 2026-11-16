// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's make-ups (design §9.6): the payment pull holds the ledger,
//! so it records a make-up the operator asks for, on the ledger in memory
//! and against the deployment as the state is now
//! ([`mooring_daemon_core::make_up::decide`]).
//!
//! - **Only for one who waits.** The decision goes to the connection that
//!   asked; the ledger is written only once that connection has heard
//!   that the make-up is taken, so a connection that has gone is told
//!   `LoopBusy` truly: nothing was recorded.
//! - **Written before it is kept**, as every change of the ledger: a write
//!   that fails is said, and the ledger in memory stays as it was.
//! - **A ledger that could not be read** at the start records nothing
//!   until the daemon starts again (`LedgerUnreadable`), as the pull pulls
//!   nothing: it is held as an empty one, which a write would put in place
//!   of the file.

use mooring_daemon_core::control::Refusal;
use mooring_daemon_core::make_up::decide;
use mooring_daemon_core::payments::{MadeUp, PullSettings};
use mooring_model::{Deployment, UnixTime};

use super::Puller;
use crate::daemon::MakeUpRequest;
use crate::payments::notes::made_up;

impl Puller {
    /// Answers `request` at `now`, for the users of `deployment`. Returns
    /// the lines to log: one for a make-up recorded, and one for a ledger
    /// that could not be written; none when nothing was recorded because
    /// the make-up was refused or whoever asked had gone.
    pub(crate) fn make_up(
        &mut self,
        deployment: &Deployment,
        request: &MakeUpRequest,
        now: UnixTime,
    ) -> Vec<String> {
        let made = match self.decide_make_up(deployment, request, now) {
            Ok(made) => made,
            Err(reason) => {
                // Nothing is recorded, whether or not anyone still waits.
                let _ = request.decided.send(Err(reason));
                return Vec::new();
            }
        };
        if request.decided.send(Ok(())).is_err() {
            return Vec::new();
        }
        let MadeUp {
            ledger,
            record,
            suspended,
        } = made;
        if let Err(error) = self.write(&ledger) {
            // The channel holds the answer, so this never waits; whoever
            // asked may have stopped waiting, and nothing was recorded.
            let _ = request.recorded.send(Err(Refusal::LedgerNotWritten));
            return vec![format!(
                "make-up for user {}: the payment ledger could not be written ({error}); nothing was recorded",
                record.user
            )];
        }
        self.ledger = ledger;
        let line = made_up(&record, suspended);
        let heard = request.recorded.send(Ok((record, suspended))).is_ok();
        vec![if heard {
            line
        } else {
            format!("{line}; whoever asked had stopped waiting before they heard it")
        }]
    }

    /// The make-up `request` asks for, on a copy of the ledger in memory,
    /// with the rehearsal the settings last read say; refused while the
    /// ledger cannot be read.
    fn decide_make_up(
        &self,
        deployment: &Deployment,
        request: &MakeUpRequest,
        now: UnixTime,
    ) -> Result<MadeUp, Refusal> {
        if self.fault.is_some() {
            return Err(Refusal::LedgerUnreadable);
        }
        let rehearsal = self.settings.as_ref().is_some_and(PullSettings::rehearsal);
        decide(
            &self.ledger,
            deployment,
            rehearsal,
            &request.user,
            request.ask,
            request.reason,
            now,
        )
        .map_err(Refusal::from)
    }
}
