// SPDX-License-Identifier: GPL-3.0-or-later

//! `user set-quota <uid> (--gb <n> | --none)` (design §7, §9.6, §15.3):
//! sets or removes a user's own quota, the bytes served to the user in one
//! SIM billing cycle, as the bookkeeping record `QuotaRecorded`.
//!
//! A user's own quota takes the place of a paid period's and of the
//! automatic one, and the cycle's traffic packs add to it
//! (`mooring_daemon_core::policy::effective_policy`). It is a record on
//! this Mac: no node's bundle and no export carries it, so the record
//! keeps the configuration generation and needs no `node apply`.
//!
//! Nothing is suspended or resumed by the command. The apply job reads the
//! quota at its next run (design §13.6): it suspends an active user who
//! has used all of it, and resumes a user it suspended for quota in the
//! current billing cycle once the quota covers what they used. So the
//! operator gives a user more within a cycle by recording a larger quota
//! and running `apply --now`, and records the earlier quota again once
//! the cycle has ended.
//!
//! The quota is typed in whole GB of 1,000,000,000 bytes and carries the
//! warning share and the action of the pilot's automatic quota (decision
//! F4: a warning at 80 %, a suspension at all of it), as a paid period's
//! quota does. The command asks nothing: running it again replaces or
//! removes what it recorded.

use std::io::Write;
use std::num::NonZeroU64;

use mooring_model::quota::AutoQuotaPolicy;
use mooring_model::user::{QuotaAction, UserQuota};
use mooring_model::{Bookkeeping, UserId};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::CommandError;
use crate::state::{load, output, store_failure};

/// The bytes of the GB a quota is typed and printed in.
pub(crate) const BYTES_PER_GB: u64 = 1_000_000_000;

/// What follows a record that changed the user's quota.
const NEXT: &str = "the apply job acts on it at its next nightly run, or at once with `mooringctl apply --now`; this record suspends and resumes nobody, and needs no node apply";

/// `user set-quota`: records `bytes` served per billing cycle as the
/// user's own quota, or removes that quota when there are none.
pub(crate) fn set(
    env: &Env<'_>,
    out: &mut dyn Write,
    user: &UserId,
    bytes: Option<NonZeroU64>,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let before = state
        .deployment
        .users()
        .get(user)
        .and_then(|record| record.policy.quota);
    let quota = bytes.map(own_quota);
    store
        .record(
            state.deployment.config_generation(),
            Bookkeeping::QuotaRecorded {
                user: user.clone(),
                quota,
            },
        )
        .map_err(store_failure)?;
    out.write_all(report(user, before, quota).as_bytes())
        .map_err(output)
}

/// The quota the command records for `bytes`: with the warning share and
/// the action of the pilot's automatic quota, which a paid period's quota
/// has too (`mooring_daemon_core::policy::paid_quota`; the tests hold the
/// two together).
const fn own_quota(bytes: NonZeroU64) -> UserQuota {
    UserQuota {
        cycle_served_bytes: bytes,
        warn_percent: AutoQuotaPolicy::PILOT.warn_percent,
        action: AutoQuotaPolicy::PILOT.action,
    }
}

/// What the command prints: the quota recorded and the one it replaced,
/// or that the record was the same already.
fn report(user: &UserId, before: Option<UserQuota>, after: Option<UserQuota>) -> String {
    match (before, after) {
        (Some(old), Some(new)) if old == new => {
            format!("kept: user {user} already has a quota of {}\n", terms(new))
        }
        (None, None) => format!("kept: user {user} has no quota of their own\n"),
        (None, Some(new)) => format!(
            "recorded: user {user} has a quota of {}; they had none of their own\n{NEXT}\n",
            terms(new)
        ),
        (Some(old), Some(new)) => format!(
            "recorded: user {user} has a quota of {}; it replaces one of {}\n{NEXT}\n",
            terms(new),
            terms(old)
        ),
        (Some(old), None) => format!(
            "recorded: user {user} has no quota of their own any more; it was {}\n{NEXT}\n",
            terms(old)
        ),
    }
}

/// A quota in words: its amount per billing cycle, its warning share and
/// what reaching it does.
fn terms(quota: UserQuota) -> String {
    let reached = match quota.action {
        QuotaAction::Suspend => "a suspension at all of it",
        QuotaAction::Warn => "no suspension",
    };
    format!(
        "{} per billing cycle, with a warning at {} % and {reached}",
        amount(quota.cycle_served_bytes),
        quota.warn_percent.get()
    )
}

/// A quota's bytes: in GB where they are a whole number of GB, as every
/// quota this command records is, and in bytes otherwise.
fn amount(bytes: NonZeroU64) -> String {
    let bytes = bytes.get();
    if bytes.is_multiple_of(BYTES_PER_GB) {
        format!("{} GB", bytes / BYTES_PER_GB)
    } else {
        format!("{bytes} bytes")
    }
}
