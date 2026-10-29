// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's document (design §10.1 step 5): `usage/sim-meter.json`
//! in the support directory, the line's bytes per UTC day. `daemon-core`'s
//! `SimMeter` encodes and decodes it; this module keeps the file: the
//! `usage/` directory (mode 0700, created when missing, never a link), the
//! durable write, and a read bounded by the caller.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::durable::{private_dir, write_durably};
use crate::error::{IoOp, StoreError};

/// The usage directory's name, in the support directory.
pub const USAGE_DIRECTORY: &str = "usage";

/// The meter's file name, in the usage directory.
pub const SIM_METER_FILE: &str = "sim-meter.json";

/// The meter document in `support_dir`, at most `limit` bytes of it (a
/// longer file reads as its first `limit` bytes, which the decoder then
/// refuses), or `None` when there is none.
pub fn read_sim_meter(support_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    let path = support_dir.join(USAGE_DIRECTORY).join(SIM_METER_FILE);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Io {
                op: IoOp::ReadSimMeter,
                path,
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            op: IoOp::ReadSimMeter,
            path,
            source,
        })?;
    Ok(Some(bytes))
}

/// Replaces the meter document with `bytes` (the store's durable write,
/// mode 0600), creating the usage directory first if it is missing; a
/// usage path that is not a directory (a link included) is
/// `DirNotDirectory`.
pub fn write_sim_meter(support_dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = private_dir(support_dir, USAGE_DIRECTORY, IoOp::CreateUsageDir)?;
    write_durably(&dir, SIM_METER_FILE, bytes)
}
