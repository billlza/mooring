// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line (clap derive). No argument carries a secret: the M7's
//! admin password is read from the terminal or stdin only.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mooring_model::iface::BsdName;

/// Mooring's command-line tool. Revision 7 builds the M7 router commands,
/// which only read from the M7.
#[derive(Debug, Parser)]
#[command(name = "mooringctl", version)]
pub(crate) struct Cli {
    /// The command.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// A top-level command.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// The M7 router: its identity, admin password, status and redacted
    /// captures.
    #[command(subcommand)]
    Router(RouterCommand),
}

/// A router command.
#[derive(Debug, Subcommand)]
pub(crate) enum RouterCommand {
    /// Record the link-layer address of the interface's gateway as the M7's
    /// identity, which the login is bound to.
    Pin {
        /// The Mac's interface to the M7 (a BSD name, for example en9).
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// Record without asking.
        #[arg(long)]
        yes: bool,
        /// Replace a different identity already recorded.
        #[arg(long)]
        replace: bool,
    },
    /// Store the M7's admin password in the login keychain, typed twice at
    /// the terminal without echo, or read from stdin.
    SetPassword {
        /// Read the password from stdin (one trailing newline is removed).
        #[arg(long)]
        stdin: bool,
    },
    /// Read the M7's status through its JSON interface, logging in as
    /// needed after checking its identity.
    Status {
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// Print one JSON line (a router reading) instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Write the M7's status document, redacted through the allowlist, to a
    /// new file. There is no raw option.
    Capture {
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The file to create (never overwritten).
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Capture the anonymous answer: no password is read or sent.
        #[arg(long)]
        anonymous: bool,
    },
}
