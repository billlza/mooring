// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal plans set <FILE> | off` (design §9.6): the plans on the Mac,
//! with which the daemon grants a live payment only at the terms of a plan
//! the operator sells.
//!
//! - **The file** is the portal's live plan file: the operator's own copy
//!   of the file the portal runs, never the portal's answer, since a portal
//!   that is not to be trusted cannot be the one to say what it sells. It
//!   is read from a regular file, at most [`MAX_PLAN_FILE_BYTES`], and
//!   refused wherever the portal refuses it or when it is of Stripe's test
//!   mode, before anything is written.
//! - **Kept, not replaced.** `set` makes the file's plans the current ones
//!   and keeps those of the files before it, so that an order paid on a
//!   plan before a change still matches when it is pulled after it. A new
//!   file is kept here before the portal sells it: a grant of a plan the
//!   Mac does not keep is held, and a held grant is never granted.
//! - **One plan to a Payment Link.** A file that lists other terms on the
//!   link of a plan kept is refused, before anything is written: a plan
//!   whose terms change is sold on a new link, so that the link a payment
//!   was made on decides what it buys.
//! - **Off** forgets every plan: grants are then applied at the terms the
//!   portal lists. Each change raises the settings' revision, so a page
//!   that waits for the check against Stripe is fetched again under the
//!   new plans; `connect`, `rehearsal`, `stripe-check` and `disconnect`
//!   keep the plans.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use mooring_daemon_core::payments::{
    GB, MAX_PLAN_FILE_BYTES, PlanBook, PlanFile, PullSettings, Stored, StoredPlan,
};

use super::command::{Changed, change_settings, files, output};
use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::paths::create_support_dir;

/// The plan file at `path`, opened once with `O_NONBLOCK` so that a FIFO
/// cannot hold the open, a regular file by its own descriptor, and read to
/// one byte past the most the portal reads, so that a larger file is
/// refused as such.
pub(crate) fn read_plan_file(path: &Path) -> Result<PlanFile, LocalError> {
    let read = |source| LocalError::PlanFileRead {
        path: path.to_path_buf(),
        source,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(read)?;
    if !file.metadata().map_err(read)?.file_type().is_file() {
        return Err(LocalError::PlanFileNotAFile {
            path: path.to_path_buf(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_PLAN_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read)?;
    PlanFile::parse(&bytes).map_err(|source| LocalError::PlanFile {
        path: path.to_path_buf(),
        source,
    })
}

/// What the plans kept mean.
pub(crate) fn plans_line(book: &PlanBook) -> String {
    if book.is_empty() {
        return "plans kept: none: grants are applied at the terms the portal lists (`mooringctl portal plans set <file>` keeps the portal's live plan file)".to_owned();
    }
    let current = book.plans().iter().filter(|plan| plan.current).count();
    format!(
        "plans kept: {current} current, {} of earlier files: a live grant is granted only at the terms of a plan kept and, with the check against Stripe, only when it was paid on that plan's Payment Link; any other is held",
        book.plans().len() - current
    )
}

/// One plan kept, as `set` and `portal payments` list it.
pub(crate) fn plan_line(plan: &StoredPlan) -> String {
    format!(
        "  {} ({}): {}, {} days, {} GB ({} bytes), {} {}, Payment Link {}",
        plan.id,
        if plan.current { "current" } else { "earlier" },
        plan.kind.as_str(),
        plan.days,
        plan.traffic_gb,
        plan.traffic_gb.get().saturating_mul(GB),
        plan.amount,
        plan.currency.as_str(),
        plan.payment_link_id.as_str()
    )
}

/// `portal plans set <FILE>`: reads the file, then keeps its plans as the
/// current ones after those kept before. A file that lists other terms on
/// the Payment Link of a plan kept is refused, with nothing written.
pub(crate) fn set(env: &mut Env<'_>, out: &mut dyn Write, path: &Path) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let file = read_plan_file(path)?;
    create_support_dir(&support)?;
    // What the change made of the plans, for the summary, or the file's
    // plan on a link kept for other terms, when the change wrote nothing: a
    // successful change ran it.
    let mut kept = Ok((0, PlanBook::default(), Stored::default()));
    let changed = change_settings(&support, |current, revision| {
        let current = current.unwrap_or_else(|| PullSettings::disconnected(revision, false));
        let (book, stored) = match current.plans().stored(&file) {
            Ok(stored) => stored,
            Err(taken) => {
                kept = Err(taken);
                return Ok(None);
            }
        };
        let next = (book != *current.plans()).then(|| current.planning(revision, book.clone()));
        let shown = if next.is_some() {
            revision
        } else {
            current.revision()
        };
        kept = Ok((shown, book, stored));
        Ok(next)
    })
    .map_err(files)?;
    let (revision, book, stored) = kept.map_err(|source| LocalError::PlanLinkTaken {
        path: path.to_path_buf(),
        source,
    })?;
    let prefix = match changed {
        Changed::Written => "",
        Changed::Kept => "unchanged; ",
    };
    let dropped = if stored.dropped > 0 {
        format!(
            "; {} plan(s) of earlier files no file has listed for longest are forgotten",
            stored.dropped
        )
    } else {
        String::new()
    };
    writeln!(
        out,
        "{prefix}the plan file's {} plan(s) are kept as the current ones ({} new), with {} of earlier files{dropped} (settings revision {revision})",
        stored.listed, stored.new, stored.earlier
    )
    .map_err(output)?;
    for plan in book.plans() {
        writeln!(out, "{}", plan_line(plan)).map_err(output)?;
    }
    writeln!(out, "{}", plans_line(&book)).map_err(output)
}

/// `portal plans off`: forgets every plan kept.
pub(crate) fn off(env: &mut Env<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let changed = change_settings(&support, |current, revision| {
        Ok(current
            .filter(|current| !current.plans().is_empty())
            .map(|current| current.planning(revision, PlanBook::default())))
    })
    .map_err(files)?;
    let prefix = match changed {
        Changed::Written => "",
        Changed::Kept => "unchanged; ",
    };
    writeln!(out, "{prefix}{}", plans_line(&PlanBook::default())).map_err(output)
}
