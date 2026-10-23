// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooring-agent`, the VPS side of Mooring (design §5.2, §11): a static
//! Linux musl binary run by sshd's forced command and by its own systemd
//! units. Built so far (M4a to M4e):
//!
//! - `serve-ssh --role bootstrap|ops|viewer`: one request on stdin, one
//!   reply on stdout. `Hello`, `Bootstrap`, `RevokeBootstrap`, the blobs,
//!   the gate's requests, `Shutdown`, the transactions (`Apply`,
//!   `TxnStatus`, `Confirm`, `Rollback`), `ActivateAgent`, `Resume`,
//!   `Status`, `Usage`, `UsageSeries`, `Events`, `TargetCheck` and the Mac
//!   report are served;
//! - `reflect [--port 27900]`, the reflector unit, on the uplink's address;
//! - `halted-check`, the engines' `ExecCondition`: exit 0 when they may
//!   start, 1 while the node is halted (or its marker cannot be read);
//! - `gate-close`, the watch's `ExecStopPost`: close the gate;
//! - `self-test`: check the embedded host profile and the state files, and
//!   print the protocol number;
//! - `txn <N>`, `txn-revert <N>` and `txn-recover`: a transaction's unit,
//!   its confirm timer and the revert at boot;
//! - `watch`, the `mooring-watch` unit, which also keeps the accounting;
//! - `target-watch`, the hourly target check's unit.
//!
//! On any other OS than Linux it only says so and exits 1; its logic is
//! tested on any host with a stand-in node.

// The agent's logic is built for Linux and, on any host, for its tests.
#[cfg(any(target_os = "linux", test))]
mod accounting;
#[cfg(any(target_os = "linux", test))]
mod accounts;
#[cfg(any(target_os = "linux", test))]
mod agent;
#[cfg(any(target_os = "linux", test))]
mod blobs;
#[cfg(any(target_os = "linux", test))]
mod bootstrap;
#[cfg(any(target_os = "linux", test))]
mod gate;
#[cfg(any(target_os = "linux", test))]
mod hello;
#[cfg(any(target_os = "linux", test))]
mod host;
#[cfg(any(target_os = "linux", test))]
mod hostfiles;
#[cfg(any(target_os = "linux", test))]
mod journal;
#[cfg(any(target_os = "linux", test))]
mod layout;
#[cfg(any(target_os = "linux", test))]
mod paths;
#[cfg(any(target_os = "linux", test))]
mod reflect;
#[cfg(any(target_os = "linux", test))]
mod serve;
#[cfg(any(target_os = "linux", test))]
mod status;
#[cfg(any(target_os = "linux", test))]
mod store;
#[cfg(any(target_os = "linux", test))]
mod target;
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "linux", test))]
mod txn;
#[cfg(any(target_os = "linux", test))]
mod watch;
#[cfg(any(target_os = "linux", test))]
mod wg;

use std::io::{self, Write};
use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stderr = io::stderr().lock();
    match agent::parse(&args) {
        Ok(invocation) => agent::run(
            invocation,
            &paths::Paths::system(),
            &host::RealNode,
            &mut stderr,
        ),
        Err(usage) => fail(&mut stderr, &usage),
    }
}

/// Writes `message` to stderr and returns exit status 1.
pub(crate) fn fail(stderr: &mut dyn Write, message: &str) -> ExitCode {
    // Nothing else can report a failure to write stderr itself.
    let _unreported = writeln!(stderr, "mooring-agent: {message}");
    ExitCode::from(1)
}

/// On any OS but Linux the agent only says that it runs on Linux.
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    fail(
        &mut io::stderr().lock(),
        "mooring-agent runs on Linux (the VPS); this build is for its tests",
    )
}
