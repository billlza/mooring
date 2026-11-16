// SPDX-License-Identifier: GPL-3.0-or-later

//! `user make-up <uid> (--days <n> | --gb <n>) --reason <why> [--yes]`
//! (design §9.6; the agreement's clauses 1 and 3): has the daemon give the
//! user service time or traffic without a payment, and record it in the
//! payment ledger, the file it alone writes.
//!
//! The command reads the state to name the user, by id and alias and never
//! by label, and refuses at once a user the deployment does not hold or is
//! revoking, and one who accepted no revision of the agreement that
//! provides for make-ups, revision 2 or a later one
//! ([`MAKE_UP_AGREEMENT_SINCE`]). It asks, then names the make-up to the
//! daemon, which decides it again against the state as it is then,
//! records it or says why not, and prints the make-up as recorded.
//!
//! A make-up cannot be undone. When the request was sent and no answer
//! came, whether it was recorded is not known, and the command says so
//! rather than guess ([`LocalError::MakeUpUnanswered`]); `portal payments`
//! lists every make-up recorded. A daemon it could not reach heard
//! nothing, and is reported as such. A make-up recorded whose line cannot
//! be written is reported as recorded ([`LocalError::MadeUpUnsaid`]), so
//! that no one asks for it again.

use std::io::Write;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use mooring_daemon_core::control::{DaemonReply, DaemonRequest};
use mooring_daemon_core::payments::{MAKE_UP_AGREEMENT_SINCE, MakeUpAsk, MakeUpReason};
use mooring_model::{RecordedAgreement, UserId, UserStatus};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::daemon::RunPaths;
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::payments::notes::{made_up, reason as reason_phrase};
use crate::state::{load, output};
use crate::status::{ask_on, open};

/// How long the command waits for the daemon's answer: longer than the
/// daemon's two waits for its loop together (the build checks it), so that
/// a loop held up is heard of as `LoopBusy`, not as silence.
pub(crate) const MAKE_UP_TIMEOUT: Duration = Duration::from_secs(20);

/// A decimal gigabyte, in bytes.
const GIGABYTE: NonZeroU64 = NonZeroU64::MIN.saturating_add(999_999_999);

/// `user make-up`.
pub(crate) fn make_up(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    user: &UserId,
    days: Option<NonZeroU32>,
    gb: Option<NonZeroU32>,
    reason: MakeUpReason,
    yes: bool,
) -> Result<(), CommandError> {
    let ask = asked(days, gb)?;
    let support = support_dir(env)?;
    let state = load(&Store::new(support.clone()))?;
    let record = state
        .deployment
        .users()
        .get(user)
        .ok_or_else(|| LocalError::UnknownUser { user: user.clone() })?;
    if matches!(
        record.status,
        UserStatus::RevokePending | UserStatus::Revoked { .. }
    ) {
        return Err(LocalError::MakeUpUserRevoked { user: user.clone() }.into());
    }
    record
        .accepted(MAKE_UP_AGREEMENT_SINCE)
        .map_err(
            |RecordedAgreement(recorded)| LocalError::MakeUpAgreementNotAccepted {
                user: user.clone(),
                recorded,
                required: MAKE_UP_AGREEMENT_SINCE,
            },
        )?;
    let named = match &record.alias {
        Some(alias) => format!("user {user} ({alias})"),
        None => format!("user {user}"),
    };
    writeln!(out, "{}", described(&named, ask, reason)).map_err(output)?;
    confirm(env, yes, "Record this make-up? It cannot be undone.")?;
    let request = DaemonRequest::MakeUp {
        user: user.clone(),
        ask,
        reason,
    };
    let socket = RunPaths::under(&support).socket;
    // Nothing is sent until the connection is made.
    let stream = open(&socket, MAKE_UP_TIMEOUT)?;
    let reply = ask_on(stream, &socket, request, MAKE_UP_TIMEOUT).map_err(unanswered)?;
    match reply {
        DaemonReply::MadeUp { record, suspended } => {
            writeln!(
                out,
                "recorded {}; the console shows it from the daemon's next status, and the portal once `portal export` is imported there again; no node apply is needed",
                made_up(&record, suspended)
            )
            .map_err(|source| LocalError::MadeUpUnsaid {
                number: record.number,
                source,
            })?;
            Ok(())
        }
        DaemonReply::Refused { reason } => Err(LocalError::DaemonRefused { reason }.into()),
        DaemonReply::Status(_) | DaemonReply::RetryQueued | DaemonReply::SimNetworkAccepted => {
            Err(LocalError::DaemonUnexpectedReply.into())
        }
    }
}

/// What `--days` or `--gb` ask for: one of them, as the command line
/// requires.
pub(crate) fn asked(
    days: Option<NonZeroU32>,
    gb: Option<NonZeroU32>,
) -> Result<MakeUpAsk, LocalError> {
    match (days, gb) {
        (Some(days), None) => Ok(MakeUpAsk::Days(days)),
        (None, Some(gb)) => Ok(MakeUpAsk::TrafficBytes(
            NonZeroU64::from(gb).saturating_mul(GIGABYTE),
        )),
        (Some(_), Some(_)) | (None, None) => Err(LocalError::MakeUpAsk),
    }
}

/// The line the command shows before it asks.
fn described(named: &str, ask: MakeUpAsk, reason: MakeUpReason) -> String {
    let what = match ask {
        MakeUpAsk::Days(days) => format!(
            "{days} day(s) of service, from the end of their paid time or from now once that has passed, with the quota of their last paid period"
        ),
        MakeUpAsk::TrafficBytes(bytes) => format!(
            "{} GB ({bytes} bytes) of traffic for this billing cycle",
            bytes.get() / GIGABYTE.get()
        ),
    };
    format!(
        "make-up: {named} is to be given {what}, {}",
        reason_phrase(reason)
    )
}

/// What a failed asking on a connection made means for a make-up. Nothing
/// was sent of a request that could not be encoded, and a daemon that
/// speaks no protocol or an older one cannot read the request. Anything
/// else came after the request was sent, or as it was, so the daemon may
/// have recorded the make-up.
fn unanswered(error: LocalError) -> LocalError {
    match error {
        LocalError::ClientEncode(_) | LocalError::DaemonProtocolMissing => error,
        LocalError::DaemonProtocolOther { daemon, client } if daemon < client => error,
        other => LocalError::MakeUpUnanswered {
            source: Box::new(other),
        },
    }
}
