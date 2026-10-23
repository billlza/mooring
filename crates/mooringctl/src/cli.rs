// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line (clap derive). No argument carries a secret: the M7's
//! admin password is read from the terminal or stdin only.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mooring_export::ExportFormat;
use mooring_model::exit::{FlowCap, Pairing};
use mooring_model::iface::BsdName;
use mooring_model::ipv4::CarrierPrefix;
use mooring_model::{CalendarDate, ClientLine, UserId};

/// Mooring's command-line tool. Revision 7 builds the M7 router commands,
/// which only read from the M7; M5 adds the user commands.
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
    /// Users: what the operator records about them.
    #[command(subcommand)]
    User(UserCommand),
    /// The exit: the deployment's creation and its carrier check.
    #[command(subcommand)]
    Exit(ExitCommand),
    /// The SIM line's billing cycles.
    #[command(subcommand)]
    Sim(SimCommand),
    /// The console's status, from the daemon.
    Status {
        /// Keep printing each new status while it is fresh, until the
        /// daemon stops.
        #[arg(long)]
        follow: bool,
        /// Print each status as one JSON line (what Mooring.app reads)
        /// instead of a summary.
        #[arg(long)]
        json: bool,
        /// With --follow, also end, with success, once the process that
        /// started this one has exited (Mooring.app passes it, so its
        /// follower never outlives it).
        #[arg(long, requires = "follow")]
        until_parent_exits: bool,
    },
    /// Run the daemon (launchd starts it): poll the M7 and serve the
    /// console's status on the control socket.
    Daemon {
        /// The Mac's interface to the M7, polled while no deployment
        /// exists (a BSD name, for example en9).
        #[arg(long, value_name = "BSD_NAME")]
        router_interface: Option<BsdName>,
    },
}

/// A user command.
#[derive(Debug, Subcommand)]
pub(crate) enum UserCommand {
    /// Add an active user with fresh credentials on every node that is not
    /// retiring. The label is asked at the terminal, never taken from an
    /// argument; it stays on this Mac. Every node then needs `node apply`.
    Add {
        /// The user's CFM line.
        #[arg(long, value_enum, default_value_t = ClientArg::Cfm05)]
        client: ClientArg,
        /// Opt the user in to the hybrid X25519MLKEM768 REALITY hello
        /// (CFM 0.5 only).
        #[arg(long)]
        mlkem: bool,
    },
    /// Give a user without one a random public alias (xxxx-xxxx), to quote
    /// instead of a name. Every node then needs `node apply`.
    Alias {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
    },
    /// Record that the user accepted the agreement revision this build
    /// ships, dated today (UTC). It takes neither a revision nor a date, so
    /// neither can be mistyped; it needs no node apply.
    Agree {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
    },
    /// Write the user's file for CFM to a new file with mode 0600 (never
    /// overwritten), and deliver it as docs/runbooks/delivery.md says.
    Export {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// The file format.
        #[arg(long, value_enum, default_value_t = FormatArg::Singbox)]
        format: FormatArg,
        /// The file to create, in a folder Time Machine excludes and outside
        /// iCloud Drive, the Desktop and Documents.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

/// A CFM line, as typed on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ClientArg {
    /// CFM 0.5 (the default).
    Cfm05,
    /// CFM 0.4.
    Cfm04,
}

impl From<ClientArg> for ClientLine {
    fn from(client: ClientArg) -> Self {
        match client {
            ClientArg::Cfm05 => Self::Cfm05,
            ClientArg::Cfm04 => Self::Cfm04,
        }
    }
}

/// An export format, as typed on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FormatArg {
    /// sing-box JSON (the default).
    Singbox,
    /// Clash YAML, only if the user asks for it.
    Clash,
}

impl From<FormatArg> for ExportFormat {
    fn from(format: FormatArg) -> Self {
        match format {
            FormatArg::Singbox => Self::SingBoxJson,
            FormatArg::Clash => Self::ClashYaml,
        }
    }
}

/// An exit command.
#[derive(Debug, Subcommand)]
pub(crate) enum ExitCommand {
    /// Create the deployment with the pilot's decided values: 1pMobile's
    /// Unlimited Data Boost on 30-day cycles, the pilot's SIM thresholds,
    /// cap, quotas and alert settings, and the M7 as the egress.
    Init {
        /// The Mac's interface to the M7 (a BSD name, for example en9); its
        /// gateway must be the pinned M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The first day of one billing cycle: the day the Boost was
        /// bought (YYYY-MM-DD).
        #[arg(long, value_name = "DATE")]
        cycle_anchor: CalendarDate,
        /// The node-wide cap on new flows into the tunnel (1..=65535), until
        /// M2 sizes it from the line's port ceiling.
        #[arg(long, value_name = "FLOWS", value_parser = parse_flow_cap)]
        flow_cap: FlowCap,
        /// Create without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Record the line's carrier check, observed on the line: its public
    /// pool prefixes (RIPE inetnum evidence) and the pairing mode.
    RecordCarrier {
        /// A carrier prefix (CIDR); give one --prefix per prefix.
        #[arg(long = "prefix", value_name = "CIDR", required = true)]
        prefixes: Vec<CarrierPrefix>,
        /// Whether an in-chain egress address must equal a bracketing
        /// direct probe's.
        #[arg(long, value_enum)]
        pairing: PairingArg,
        /// Record without asking.
        #[arg(long)]
        yes: bool,
    },
}

/// A flow cap, as the model accepts it.
fn parse_flow_cap(text: &str) -> Result<FlowCap, String> {
    let value: u32 = text.parse().map_err(|error| format!("{error}"))?;
    FlowCap::new(value).map_err(|error| error.to_string())
}

/// How in-chain egress addresses are bracketed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PairingArg {
    /// The in-chain address must equal a bracketing direct probe's.
    Paired,
    /// Only the carrier prefixes are checked (a line that pools addresses).
    Unpaired,
}

impl From<PairingArg> for Pairing {
    fn from(arg: PairingArg) -> Self {
        match arg {
            PairingArg::Paired => Self::Paired,
            PairingArg::Unpaired => Self::Unpaired,
        }
    }
}

/// A SIM command.
#[derive(Debug, Subcommand)]
pub(crate) enum SimCommand {
    /// Move the fixed-length billing cycles so that one starts on the given
    /// day, as when the Boost was bought on another day.
    SetAnchor {
        /// The first day of one billing cycle (YYYY-MM-DD).
        #[arg(value_name = "DATE")]
        anchor: CalendarDate,
        /// Move without asking.
        #[arg(long)]
        yes: bool,
    },
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
