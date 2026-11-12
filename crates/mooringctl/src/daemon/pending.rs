// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of pending applies (design §13.6, §15.3): every
//! tick dates each node behind the deployment's generation
//! (`daemon-core`'s [`PendingApplies`]) and the status carries the dates,
//! which the console shows with how long each has waited. The record is
//! written to `run/pending-applies.json` whenever it changes, so that a
//! restart does not restart a wait.
//!
//! A record that cannot be read at the start is said and replaced: each
//! wait is then dated from the start, which keeps every wait a lower bound
//! and holds nothing back. A write that fails is said, kept in memory for
//! the status, and tried again [`WRITE_RETRY`] later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_daemon_core::pending_applies::{MAX_PENDING_APPLIES_BYTES, PendingApplies};
use mooring_model::time::UnixTime;
use mooring_model::{Deployment, NodeId};
use mooring_store::{read_pending_applies, write_pending_applies};

/// How long after a failed write the record is written again.
pub(crate) const WRITE_RETRY: Duration = Duration::from_secs(60);

/// The record, between ticks.
#[derive(Debug)]
pub(crate) struct Pending {
    run_dir: PathBuf,
    record: PendingApplies,
    /// Whether the file differs from `record`.
    unwritten: bool,
    /// When a failed write is tried again.
    retry_at: Option<Instant>,
}

impl Pending {
    /// The record in `run_dir`, and what to say about one that cannot be
    /// read.
    pub(crate) fn open(run_dir: &Path) -> (Self, Option<String>) {
        let read = match read_pending_applies(run_dir, MAX_PENDING_APPLIES_BYTES + 1) {
            Ok(None) => Ok(PendingApplies::new()),
            Ok(Some(bytes)) => PendingApplies::decode(&bytes).map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let (record, note) = match read {
            Ok(record) => (record, None),
            Err(error) => (
                PendingApplies::new(),
                Some(format!(
                    "pending applies: the record cannot be read ({error}); each pending apply is dated from now, and the record is written again"
                )),
            ),
        };
        let unwritten = note.is_some();
        (
            Self {
                run_dir: run_dir.to_path_buf(),
                record,
                unwritten,
                retry_at: None,
            },
            note,
        )
    }

    /// Dates the nodes of `deployment` behind at `now`, and writes the
    /// record when it changed or a write is due again. Returns what to say.
    pub(crate) fn track(&mut self, deployment: &Deployment, now: UnixTime) -> Option<String> {
        let next = self.record.tracked(deployment, now);
        if next != self.record {
            self.record = next;
            self.unwritten = true;
            self.retry_at = None;
        }
        if !self.unwritten || self.retry_at.is_some_and(|at| Instant::now() < at) {
            return None;
        }
        let written = self
            .record
            .encode()
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                write_pending_applies(&self.run_dir, &bytes).map_err(|error| error.to_string())
            });
        match written {
            Ok(()) => {
                self.unwritten = false;
                self.retry_at = None;
                None
            }
            Err(error) => {
                self.retry_at = Some(Instant::now() + WRITE_RETRY);
                Some(format!(
                    "pending applies: the record could not be written ({error}); the status shows it, and it is written again in {} s",
                    WRITE_RETRY.as_secs()
                ))
            }
        }
    }

    /// Since when each node behind has been behind.
    pub(crate) fn since(&self) -> BTreeMap<NodeId, UnixTime> {
        self.record.since()
    }
}
