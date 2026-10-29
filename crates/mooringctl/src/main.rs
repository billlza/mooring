// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl`, Mooring's command-line tool (design §6, §15.3), macOS
//! only. Revision 7 builds its first slice, the M7 router commands, all
//! read only towards the M7:
//!
//! - `router pin --interface <bsd> [--yes] [--replace]` records the
//!   gateway's link-layer address as the M7's identity;
//! - `router set-password [--stdin]` stores the admin password in the
//!   login keychain (never from an argument);
//! - `router status --interface <bsd> [--json]` reads the M7's status
//!   over its JSON interface, sending the password only after the identity
//!   check;
//! - `router capture --interface <bsd> --out <path> [--anonymous]` writes
//!   the allowlist redactor's output, never a raw document.
//!
//! M5 adds the user commands to `state.json` (design §7, §15.3):
//!
//! - `user add [--client cfm05|cfm04] [--mlkem]` adds an active user with
//!   fresh credentials on every node that is not retiring, reading its
//!   label at the terminal;
//! - `user alias <uid>` gives a user without one a random public alias;
//! - `user agree <uid>` records that the user accepted the agreement
//!   revision this build ships, dated today (UTC), as a bookkeeping record
//!   that keeps the configuration generation;
//! - `user export <uid> [--format singbox|clash] --out <path>` writes the
//!   user's file for CFM with mode 0600, never overwriting one, reading
//!   only that user's secrets and only once every check has passed.
//!
//! M5a adds the deployment's creation and the SIM line's records (design
//! §7, §10.2):
//!
//! - `exit init --interface <bsd> --cycle-anchor <date> --flow-cap <n>
//!   [--yes]` creates the deployment with the pilot's decided values and
//!   the pinned M7 as the egress;
//! - `exit record-carrier --prefix <cidr>... --pairing paired|unpaired
//!   [--yes]` records the line's carrier check, once, as bookkeeping;
//! - `exit allow-network --interface <bsd> --name <label>
//!   [--personal-hotspot] [--yes]`, `exit disallow-network --name <label>`
//!   and `exit allowed-networks` (2026-10-29, design §10.2, P0-2) declare,
//!   withdraw and list the networks the operator contracts for themselves,
//!   which the exit keeps serving on; never an institutional network; the
//!   file holds at most 16 KiB of declarations (about 85), past which
//!   `allow-network` refuses until one is withdrawn;
//! - `sim set-anchor <date> [--yes]` moves fixed-length billing cycles.
//!
//! The console's first slice adds the daemon and its client (design §10.1,
//! §15):
//!
//! - `daemon`, which launchd runs, polls the M7 every 60 s on the interface
//!   the router pin records while no deployment exists and serves the
//!   console's status on `run/control.sock`;
//! - `status [--follow] [--json]` reads that status from the daemon, as
//!   Mooring.app does.
//!
//! The radio history (design §15.6 rule 11) adds, to the daemon, one
//! sample per poll of the M7 appended to `radio/<UTC day>.jsonl` under the
//! support directory (the newest 90 day files are kept), and:
//!
//! - `router history [--since <date>] [--until <date>] [--json]` prints
//!   those samples' days (yesterday and today by default): the changes
//!   between polls and the hourly signal, or the document Mooring.app
//!   charts. It reads the files and touches no network.
//!
//! Nothing is logged by a command: its only output is what it prints and
//! its error on stderr. The daemon writes its own log,
//! `~/Library/Logs/Mooring/daemon.log` (rotated at 5 MiB, standard error
//! pointed at it), one line when it starts and when the M7's poll fails or
//! recovers.
//!
//! On any other target the binary only says that it runs on macOS and
//! exits 1, so the workspace builds and its gates run on the ubuntu L0
//! lane (design §16).

#[cfg(target_os = "macos")]
mod app;
#[cfg(target_os = "macos")]
mod backup;
#[cfg(target_os = "macos")]
mod cli;
#[cfg(target_os = "macos")]
mod daemon;
#[cfg(target_os = "macos")]
mod error;
#[cfg(target_os = "macos")]
mod exit;
#[cfg(target_os = "macos")]
mod keychain;
#[cfg(target_os = "macos")]
mod node;
#[cfg(target_os = "macos")]
mod paths;
#[cfg(target_os = "macos")]
mod prompt;
#[cfg(target_os = "macos")]
mod router;
#[cfg(target_os = "macos")]
mod runtime;
#[cfg(target_os = "macos")]
mod sim;
#[cfg(target_os = "macos")]
mod state;
#[cfg(target_os = "macos")]
mod status;
#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests;
#[cfg(target_os = "macos")]
mod user;

use std::io;
use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    use clap::Parser;

    use crate::app::{Env, run, system_clock};
    use crate::backup::Tmutil;
    use crate::cli::Cli;
    use crate::keychain::LoginKeychain;
    use crate::node::ssh::SshLinks;
    use crate::prompt::TtyConsole;
    use crate::router::RouterEnv;
    use crate::router::http::{DEVICE_TIMEOUTS, HTTP_PORT};
    use crate::router::link::KernelLink;

    let cli = Cli::parse();
    let link = KernelLink;
    let mut keychain = LoginKeychain;
    let mut console = TtyConsole;
    let mut stdin = io::stdin().lock();
    let backups = Tmutil;
    let mut env = Env {
        router: RouterEnv {
            link: &link,
            port: HTTP_PORT,
            timeouts: DEVICE_TIMEOUTS,
        },
        secrets: &mut keychain,
        home: std::env::var_os("HOME"),
        clock: &system_clock,
        console: &mut console,
        stdin: &mut stdin,
        backups: &backups,
        parent: &std::os::unix::process::parent_id,
        nodes: &SshLinks::SYSTEM,
        engine_pins: &node::engines::PINS,
        mac_pins: &node::engines::MAC_PINS,
        power_helper: &runtime::power::spawn,
        meter_reader: &|| runtime::meter::kernel_reader(system_clock),
        probe: &runtime::probe::direct,
        redirect_stderr: &mooring_macsys::redirect_stderr,
    };
    let code = run(
        cli.command,
        &mut env,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code)
}

/// Elsewhere than macOS: says so on stderr and exits 1 (a local failure).
#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    use std::io::Write;

    if io::stderr()
        .write_all(b"mooringctl: runs only on macOS\n")
        .is_err()
    {
        // Nowhere left to report to: the exit code still says what failed.
    }
    ExitCode::FAILURE
}
