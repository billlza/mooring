// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of the SIM's network (design §10.2, §15.3):
//! `run/sim-network.json`, what the M7 reported of the SIM and its network
//! when the carrier check and the billing cycle were recorded, and what it
//! reports instead now, kept beside the latch so that a restart of the
//! daemon neither forgets the one nor dates the other anew. `daemon-core`'s
//! `SimNetworkRecord` encodes and decodes it; this module keeps the file.
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
pub const SIM_NETWORK_FILE: &str = "sim-network.json";

/// The record in `run_dir`, at most `limit` bytes of it (a longer file
/// reads as its first `limit` bytes, which the decoder then refuses), or
/// `None` when there is none.
pub fn read_sim_network(run_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_limited(&run_dir.join(SIM_NETWORK_FILE), limit, IoOp::ReadSimNetwork)
}

/// Replaces the record in `run_dir` with `bytes` (the store's durable
/// write, mode 0600). The daemon makes `run_dir` before it writes.
pub fn write_sim_network(run_dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_durably(run_dir, SIM_NETWORK_FILE, bytes)
}
