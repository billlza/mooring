// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's payment commands (design §9.6): `portal connect`,
//! `portal rehearsal on|off`, `portal disconnect` and `portal payments`.
//!
//! The token is read at the terminal without echo, or from standard input,
//! never from an argument, and checked before anything is written. It is
//! stored before the settings that use it, and deleted only after the
//! settings stop using it, so the daemon never meets settings whose token
//! is missing. The settings are changed under the store's exclusive lock;
//! each change raises their revision above the ledger's stop, which ends
//! the stop. The ledger is read, never written, here.

use std::io::{self, Read, Write};
use std::path::Path;

use mooring_daemon_core::payments::{
    MAX_LEDGER_BYTES, MAX_SETTINGS_BYTES, PaymentLedger, PortalOrigin, PullSettings,
};
use mooring_model::secret::{SecretEntry, SecretRef};
use mooring_model::{PORTAL_PULL_TOKEN_CHARS, PortalPullToken};
use mooring_store::{
    ChangeError, SecretStoreError, read_payment_ledger, read_payment_pull, update_payment_pull,
};
use zeroize::Zeroizing;

use super::error::PaymentFileError;
use super::listing;
use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::paths::create_support_dir;
use crate::prompt::Console;

/// The most bytes read for the token from standard input: the token, a CR
/// and a LF.
const MAX_TOKEN_INPUT: usize = PORTAL_PULL_TOKEN_CHARS + 2;

fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

fn files(error: PaymentFileError) -> CommandError {
    CommandError::Local(LocalError::PaymentFiles(Box::new(error)))
}

/// The token `bytes` spell, with whitespace around them ignored (a paste
/// may bring a newline), or `PullToken`, which never echoes them.
pub(crate) fn token_of(bytes: &[u8]) -> Result<PortalPullToken, LocalError> {
    let invalid = || {
        LocalError::PullToken(mooring_model::ModelError::InvalidSecret {
            kind: mooring_model::secret::SecretKind::PortalPullToken,
        })
    };
    let text = std::str::from_utf8(bytes.trim_ascii()).map_err(|_| invalid())?;
    PortalPullToken::parse(text).map_err(LocalError::PullToken)
}

/// The token read from `stdin` to its end, at most [`MAX_TOKEN_INPUT`]
/// bytes.
pub(crate) fn stdin_token(stdin: &mut dyn Read) -> Result<PortalPullToken, LocalError> {
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_TOKEN_INPUT + 1]);
    let mut filled = 0;
    loop {
        let read = match stdin.read(&mut buffer[filled..]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(LocalError::Stdin(error)),
        };
        if read == 0 {
            break;
        }
        filled += read;
        if filled > MAX_TOKEN_INPUT {
            return Err(LocalError::PullToken(
                mooring_model::ModelError::InvalidSecret {
                    kind: mooring_model::secret::SecretKind::PortalPullToken,
                },
            ));
        }
    }
    token_of(&buffer[..filled])
}

/// The token typed (pasted) once at the terminal without echo.
pub(crate) fn terminal_token(console: &mut dyn Console) -> Result<PortalPullToken, LocalError> {
    let line = console.password("Pull token (from `mooring-portal pull-token`): ")?;
    token_of(&line)
}

/// The ledger's stop revision and the ledger as read, or none; a ledger
/// that cannot be read is an error, never none.
fn ledger(support: &Path) -> Result<Option<PaymentLedger>, PaymentFileError> {
    read_payment_ledger(support, MAX_LEDGER_BYTES + 1)
        .map_err(|source| PaymentFileError::Store {
            file: "payments/ledger.json",
            source: Box::new(source),
        })?
        .map(|bytes| PaymentLedger::decode(&bytes).map_err(PaymentFileError::Ledger))
        .transpose()
}

/// The pull's settings as read, or none.
fn settings(support: &Path) -> Result<Option<PullSettings>, PaymentFileError> {
    read_payment_pull(support, MAX_SETTINGS_BYTES + 1)
        .map_err(|source| PaymentFileError::Store {
            file: "payment-pull.json",
            source: Box::new(source),
        })?
        .map(|bytes| PullSettings::decode(&bytes).map_err(PaymentFileError::Settings))
        .transpose()
}

/// What a change of the settings did.
#[derive(Debug)]
enum Changed {
    /// The new settings were written.
    Written,
    /// The settings were left as they are.
    Kept,
}

/// Changes the settings under the lock: `change` gets the current ones and
/// the revision the change takes, and returns the new ones, or `None` to
/// leave them as they are.
fn change_settings(
    support: &Path,
    change: impl FnOnce(Option<PullSettings>, u64) -> Result<Option<PullSettings>, PaymentFileError>,
) -> Result<Changed, PaymentFileError> {
    let stop = ledger(support)?.and_then(|ledger| ledger.stopped());
    let written = update_payment_pull(support, MAX_SETTINGS_BYTES + 1, |current| {
        let current = current
            .map(PullSettings::decode)
            .transpose()
            .map_err(PaymentFileError::Settings)?;
        let revision = PullSettings::next_revision(current.as_ref(), stop);
        change(current, revision)?
            .map(|next| next.encode().map_err(PaymentFileError::Settings))
            .transpose()
    });
    match written {
        Ok(Some(_)) => Ok(Changed::Written),
        Ok(None) => Ok(Changed::Kept),
        Err(ChangeError::Refused(error)) => Err(error),
        Err(ChangeError::Store(source)) => Err(PaymentFileError::Store {
            file: "payment-pull.json",
            source: Box::new(source),
        }),
    }
}

/// `portal connect --origin <https://host[:port]> [--stdin]`: stores the
/// token and points the pull at `origin`, keeping the rehearsal as it is.
pub(crate) fn connect(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    origin: &PortalOrigin,
    stdin: bool,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    create_support_dir(&support)?;
    // A ledger or settings that cannot be read are reported before
    // anything is asked or written: the daemon pulls nothing while it
    // cannot read them, and a token stored for settings that cannot be
    // changed would be stored for nothing.
    ledger(&support).map_err(files)?;
    settings(&support).map_err(files)?;
    let token = if stdin {
        stdin_token(env.stdin)?
    } else {
        terminal_token(env.console)?
    };
    env.secrets
        .put(SecretEntry::PortalPullToken(token))
        .map_err(|error| CommandError::Local(LocalError::Keychain(error)))?;
    // What the change wrote, for the summary: a successful change ran it.
    let mut written = (0, false);
    change_settings(&support, |current, revision| {
        let rehearsal = current.as_ref().is_some_and(PullSettings::rehearsal);
        written = (revision, rehearsal);
        Ok(Some(PullSettings::connected(
            revision,
            origin.clone(),
            rehearsal,
        )))
    })
    .map_err(files)?;
    let (revision, rehearsal) = written;
    writeln!(
        out,
        "the payment pull reads {origin} with the token stored as {} (settings revision {revision}); the daemon asks within five minutes, while the Mac is on no foreign network",
        SecretRef::PortalPullToken,
    )
    .map_err(output)?;
    writeln!(out, "{}", rehearsal_line(rehearsal)).map_err(output)
}

/// What a rehearsal being on or off means.
fn rehearsal_line(rehearsal: bool) -> &'static str {
    if rehearsal {
        "rehearsal on: payments of Stripe's test mode are granted, and count only while it is on; turn it off (`mooringctl portal rehearsal off`) before real payments are taken"
    } else {
        "rehearsal off: payments of Stripe's test mode are not granted, and a portal in test mode is waited on"
    }
}

/// `portal rehearsal on|off`.
pub(crate) fn rehearsal(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    on: bool,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let changed = change_settings(&support, |current, revision| match current {
        Some(current) if current.origin().is_some() => {
            Ok((current.rehearsal() != on).then(|| current.rehearsing(revision, on)))
        }
        Some(_) | None => Err(PaymentFileError::NotConnected),
    })
    .map_err(|error| match error {
        PaymentFileError::NotConnected => LocalError::PaymentPullNotConnected.into(),
        error => files(error),
    })?;
    let prefix = match changed {
        Changed::Written => "",
        Changed::Kept => "unchanged; ",
    };
    writeln!(out, "{prefix}{}", rehearsal_line(on)).map_err(output)
}

/// `portal disconnect`: the pull stops, then the token is deleted. The
/// ledger stays: what was granted still counts.
pub(crate) fn disconnect(env: &mut Env<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    // Settings already without an origin are kept as they are.
    change_settings(&support, |current, revision| {
        Ok(current
            .filter(|current| current.origin().is_some())
            .map(|_| PullSettings::disconnected(revision)))
    })
    .map_err(files)?;
    match env.secrets.delete(&SecretRef::PortalPullToken) {
        Ok(()) | Err(SecretStoreError::SecretMissing { .. }) => {}
        Err(error) => return Err(LocalError::Keychain(error).into()),
    }
    writeln!(
        out,
        "the payment pull is disconnected and its token deleted; the payment ledger stays, and what it granted still counts"
    )
    .map_err(output)
}

/// `portal payments [--json]`: the settings, the ledger's cursor, last pull
/// and stop, and every order with what Mooring did about it.
pub(crate) fn payments(env: &Env<'_>, out: &mut dyn Write, json: bool) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let settings = settings(&support).map_err(files)?;
    let ledger = ledger(&support).map_err(files)?;
    let text = if json {
        listing::json_line(settings.as_ref(), ledger.as_ref()).map_err(files)?
    } else {
        listing::text(settings.as_ref(), ledger.as_ref())
    };
    out.write_all(text.as_bytes()).map_err(output)
}

/// What the users' paid orders give, from the files on disk, for the
/// portal snapshot: none without a ledger; a ledger or settings that cannot
/// be read is an error, never none.
pub(crate) fn entitlements(
    support: &Path,
) -> Result<mooring_daemon_core::payments::Entitlements, PaymentFileError> {
    entitlements_known(support).map(|(paid, _)| paid)
}

/// What the users' paid orders give, as [`entitlements`] reads it, and how
/// far the pull is known to reach, for the apply job's revocations at
/// expiry: with the pull set up (connected to a portal), the last pull that
/// succeeded, if any; without, no payment reaches Mooring.
pub(crate) fn entitlements_known(
    support: &Path,
) -> Result<
    (
        mooring_daemon_core::payments::Entitlements,
        mooring_daemon_core::apply::PaymentsKnown,
    ),
    PaymentFileError,
> {
    use mooring_daemon_core::apply::PaymentsKnown;
    let settings = settings(support)?;
    let ledger = ledger(support)?;
    let rehearsal = settings.as_ref().is_some_and(PullSettings::rehearsal);
    let paid = ledger.as_ref().map_or_else(
        mooring_daemon_core::payments::Entitlements::none,
        |ledger| ledger.entitlements(rehearsal),
    );
    let known = if settings
        .as_ref()
        .is_some_and(|settings| settings.origin().is_some())
    {
        PaymentsKnown::Pulled(ledger.as_ref().and_then(PaymentLedger::pulled_at))
    } else {
        PaymentsKnown::NoPull
    };
    Ok((paid, known))
}
