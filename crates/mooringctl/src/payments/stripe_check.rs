// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal stripe-check on [--stdin] | off` (design §9.6): the check against
//! Stripe, with which the daemon grants a live payment only once Stripe
//! confirms it.
//!
//! - **The key** is a restricted key of Stripe's live mode (`rk_live_…`)
//!   that may only read Checkout Sessions and Invoices, typed (pasted) at
//!   the terminal without echo or read from standard input, never an
//!   argument. A secret key (`sk_…`), which can move money, and a key of
//!   Stripe's test mode are refused before anything is written.
//! - **In order.** `on` stores the key before the settings that use it, and
//!   `off` changes the settings before it deletes the key, so the daemon
//!   never meets the check on without its key. Each change raises the
//!   settings' revision, which ends a stop: `on` with a new key ends a stop
//!   for Stripe's 401 or 403.
//! - **Connected or not.** The check may be turned on before `portal
//!   connect`, so that no live payment is granted unchecked, and it stays
//!   as it is, with its key, across `portal connect` and `portal
//!   disconnect`.

use std::io::{Read, Write};

use mooring_daemon_core::payments::PullSettings;
use mooring_model::secret::{SecretEntry, SecretRef};
use mooring_model::{
    MAX_STRIPE_READ_KEY_BODY, STRIPE_READ_KEY_PREFIX, StripeKeyError, StripeReadKey,
};
use mooring_store::SecretStoreError;

use super::command::{Changed, change_settings, files, ledger, output, settings, stdin_secret};
use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::paths::create_support_dir;
use crate::prompt::Console;

/// The most bytes read for the key from standard input: the longest key, a
/// CR and a LF.
const MAX_KEY_INPUT: usize = STRIPE_READ_KEY_PREFIX.len() + MAX_STRIPE_READ_KEY_BODY + 2;

/// The key `bytes` spell, with whitespace around them ignored (a paste may
/// bring a newline); refused for why, never echoed.
pub(crate) fn key_of(bytes: &[u8]) -> Result<StripeReadKey, LocalError> {
    let text = std::str::from_utf8(bytes.trim_ascii())
        .map_err(|_| LocalError::StripeKey(StripeKeyError::NotRestrictedLive))?;
    StripeReadKey::parse(text).map_err(LocalError::StripeKey)
}

/// The key read from `stdin` to its end, at most [`MAX_KEY_INPUT`] bytes.
pub(crate) fn stdin_key(stdin: &mut dyn Read) -> Result<StripeReadKey, LocalError> {
    match stdin_secret(stdin, MAX_KEY_INPUT)? {
        Some(bytes) => key_of(&bytes),
        None => Err(LocalError::StripeKey(StripeKeyError::NotRestrictedLive)),
    }
}

/// The key typed (pasted) once at the terminal without echo.
pub(crate) fn terminal_key(console: &mut dyn Console) -> Result<StripeReadKey, LocalError> {
    let line = console.password(
        "Stripe restricted key (rk_live_..., Read on Checkout Sessions and Invoices only): ",
    )?;
    key_of(&line)
}

/// What the check being on or off means.
pub(crate) const fn check_line(on: bool) -> &'static str {
    if on {
        "check against Stripe on: a live payment is granted only once Stripe confirms it, and one Stripe does not confirm is held"
    } else {
        "check against Stripe off: payments are granted as the portal lists them (`mooringctl portal stripe-check on` confirms each at Stripe first)"
    }
}

/// `portal stripe-check on [--stdin]`: stores the key, then turns the check
/// on, a new revision even when it was on, so that a new key ends a stop.
pub(crate) fn on(env: &mut Env<'_>, out: &mut dyn Write, stdin: bool) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    create_support_dir(&support)?;
    // Files that cannot be read are reported before anything is asked or
    // written, as `portal connect` does.
    ledger(&support).map_err(files)?;
    settings(&support).map_err(files)?;
    let key = if stdin {
        stdin_key(env.stdin)?
    } else {
        terminal_key(env.console)?
    };
    env.secrets
        .put(SecretEntry::StripeReadKey(key))
        .map_err(|error| CommandError::Local(LocalError::Keychain(error)))?;
    let mut written = 0;
    change_settings(&support, |current, revision| {
        written = revision;
        Ok(Some(match current {
            Some(current) => current.checking(revision, true),
            None => PullSettings::disconnected(revision, true),
        }))
    })
    .map_err(files)?;
    writeln!(
        out,
        "the read key is stored as {} (settings revision {written})",
        SecretRef::StripeReadKey
    )
    .map_err(output)?;
    writeln!(out, "{}", check_line(true)).map_err(output)
}

/// `portal stripe-check off`: turns the check off, then deletes the key.
pub(crate) fn off(env: &mut Env<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let changed = change_settings(&support, |current, revision| {
        Ok(current
            .filter(PullSettings::stripe_check)
            .map(|current| current.checking(revision, false)))
    })
    .map_err(files)?;
    match env.secrets.delete(&SecretRef::StripeReadKey) {
        Ok(()) | Err(SecretStoreError::SecretMissing { .. }) => {}
        Err(error) => return Err(LocalError::Keychain(error).into()),
    }
    let prefix = match changed {
        Changed::Written => "",
        Changed::Kept => "unchanged; ",
    };
    writeln!(
        out,
        "{prefix}{}; the read key is deleted",
        check_line(false)
    )
    .map_err(output)
}
