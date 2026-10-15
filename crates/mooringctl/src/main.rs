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
//! Nothing is logged: the only output is what a command prints and its
//! error on stderr.
//!
//! On any other target the binary only says that it runs on macOS and
//! exits 1, so the workspace builds and its gates run on the ubuntu L0
//! lane (design §16).

#[cfg(target_os = "macos")]
mod app;
#[cfg(target_os = "macos")]
mod cli;
#[cfg(target_os = "macos")]
mod error;
#[cfg(target_os = "macos")]
mod keychain;
#[cfg(target_os = "macos")]
mod paths;
#[cfg(target_os = "macos")]
mod prompt;
#[cfg(target_os = "macos")]
mod router;
#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests;

use std::io;
use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    use clap::Parser;

    use crate::app::{Env, run, system_clock};
    use crate::cli::Cli;
    use crate::keychain::LoginKeychain;
    use crate::prompt::TtyConsole;
    use crate::router::RouterEnv;
    use crate::router::http::{DEVICE_TIMEOUTS, HTTP_PORT};
    use crate::router::link::KernelLink;

    let cli = Cli::parse();
    let link = KernelLink;
    let mut keychain = LoginKeychain;
    let mut console = TtyConsole;
    let mut stdin = io::stdin().lock();
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
