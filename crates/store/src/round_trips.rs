// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of direct-probe round trips (console spec B.2.8,
//! design §15.3): `run/round-trips.json`, each node's round trips over the
//! last day, whose 10th percentile is the capacity monitor's idle
//! reference, kept so that a restart of the daemon does not start the
//! reference again. `daemon-core`'s `RoundTrips` encodes and decodes it;
//! this module keeps the file.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock. The read is
//! bounded by the caller and opens only a regular file: anything else where
//! the record belongs, a link included, is `NotRegularFile`, and nothing is
//! read through it. A missing file is none.

use std::path::Path;

use crate::durable::{read_limited, write_durably};
use crate::error::{IoOp, StoreError};

/// The record's file name, in the daemon's run directory.
pub const ROUND_TRIPS_FILE: &str = "round-trips.json";

/// The record in `run_dir`, at most `limit` bytes of it (a longer file
/// reads as its first `limit` bytes, which the decoder then refuses), or
/// `None` when there is none.
pub fn read_round_trips(run_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_limited(&run_dir.join(ROUND_TRIPS_FILE), limit, IoOp::ReadRoundTrips)
}

/// Replaces the record in `run_dir` with `bytes` (the store's durable
/// write, mode 0600). The daemon makes `run_dir` before it writes.
pub fn write_round_trips(run_dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_durably(run_dir, ROUND_TRIPS_FILE, bytes)
}
