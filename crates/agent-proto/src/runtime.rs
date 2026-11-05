// SPDX-License-Identifier: GPL-3.0-or-later

//! Evidence about the running watch, independent of the executable link.

use serde::{Deserialize, Serialize};

use crate::{Sha256Hex, UnixTime};

/// A watch process sampled from systemd and `/proc`, with the same process
/// identity before and after hashing its open executable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchProcess {
    /// systemd's MainPID (nonzero for a running service).
    pub pid: std::num::NonZeroU32,
    /// Linux `/proc/PID/stat` field 22, to distinguish reused PIDs.
    pub start_ticks: u64,
    /// SHA-256 of `/proc/PID/exe`, not of the current-agent symlink.
    pub executable_sha: Sha256Hex,
}

/// The answering control agent and the watch it actually observed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchRuntime {
    /// The node clock when sampled.
    pub at: UnixTime,
    /// The answering agent's own executable.
    pub agent_sha: Sha256Hex,
    /// The stable watch process; null means systemd reports no main PID.
    #[serde(deserialize_with = "Option::deserialize")]
    pub watch: Option<WatchProcess>,
}
