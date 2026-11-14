// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line (clap derive). No argument carries a secret: the M7's
//! admin password is read from the terminal or stdin only.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use mooring_daemon_core::payments::PortalOrigin;
use mooring_export::ExportFormat;
use mooring_model::dns::DnsName;
use mooring_model::exit::{FlowCap, Pairing};
use mooring_model::ids::LocalLabel;
use mooring_model::iface::BsdName;
use mooring_model::ipv4::CarrierPrefix;
use mooring_model::node::NodeRole;
use mooring_model::{CalendarDate, ClientLine, NodeId, UserId};

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
    /// The SIM line: its billing cycles, and its network on record.
    #[command(subcommand)]
    Sim(SimCommand),
    /// The VPS nodes.
    #[command(subcommand)]
    Node(NodeCommand),
    /// The user portal: the files Mooring exports for it.
    #[command(subcommand)]
    Portal(PortalCommand),
    /// The abuse guard on the nodes (design §11.8): their cuts and records,
    /// and the operator's own cut and lift.
    #[command(subcommand)]
    Abuse(AbuseCommand),
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
    /// Relay standard input and output over the one-time socket of the
    /// mooringctl that started ssh, which opened the connection to the node
    /// through the M7: management SSH's ProxyCommand.
    #[command(hide = true)]
    SshRelay {
        /// The socket, in the node's private directory.
        socket: PathBuf,
    },
    /// Run the daemon (launchd starts it): poll the M7 on the interface
    /// the router pin records, and serve the console's status on the
    /// control socket. It logs to ~/Library/Logs/Mooring/daemon.log.
    Daemon,
    /// The nightly apply job: suspend the users whose expiry or quota says
    /// so, resume the lapsed suspensions the cap on active users leaves
    /// room for, remove users revoked 13 months ago, then apply every node
    /// behind the deployment's generation. launchd runs `--pending` every
    /// hour; it logs to ~/Library/Logs/Mooring/apply.log, by counts.
    #[command(group(clap::ArgGroup::new("when").required(true).args(["pending", "now"])))]
    Apply {
        /// Run only between 19:15 and 19:45 UTC (03:15 to 03:45 Beijing
        /// time), as launchd's hourly firing does; outside it, do nothing.
        #[arg(long)]
        pending: bool,
        /// Run at once, whatever the time.
        #[arg(long)]
        now: bool,
        /// Print the outcome as one JSON line instead of a report.
        #[arg(long)]
        json: bool,
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
    /// Suspend an active user: no node serves the user after its next
    /// `node apply`, and the user keeps the credentials, so a resume
    /// delivers nothing new. For an abuse case, the node's cut holds the
    /// user until then (design §11.8).
    Suspend {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// Why.
        #[arg(long, value_enum)]
        reason: SuspendArg,
    },
    /// Resume a suspended user, within the active-user cap. Every node then
    /// needs `node apply`.
    Resume {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
    },
    /// Give a user without one a random public alias (xxxx-xxxx), to quote
    /// instead of a name. Every node then needs `node apply`.
    Alias {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
    },
    /// Remove a revoked user at once, on the user's request, with its
    /// label, alias and agreement record; the daemon then deletes its usage
    /// history and payment orders. The bare id stays while a node may still
    /// name it. It cannot be undone, so it asks first.
    Forget {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// Do not ask before removing.
        #[arg(long)]
        yes: bool,
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
    /// Print what this Mac holds about one user's traffic: the hourly and
    /// daily bins of each node that may have counted it, and the monthly,
    /// folded and lifetime totals, as the daemon would keep them now. It
    /// names the user by id and alias, never by label, and changes
    /// nothing; only --out writes, to a new file with mode 0600 (never
    /// overwritten).
    Usage {
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// Print the document as one JSON line instead of a summary.
        #[arg(long)]
        json: bool,
        /// Leave out the monthly, folded and lifetime totals: the bins
        /// alone.
        #[arg(long)]
        bins_only: bool,
        /// Write the document, pretty-printed, to this new file instead of
        /// printing it, in a folder Time Machine excludes and outside
        /// iCloud Drive, the Desktop and Documents. Mooring never deletes
        /// the file: the retention of usage/users.json does not reach it.
        #[arg(long, value_name = "PATH", conflicts_with = "json")]
        out: Option<PathBuf>,
    },
    /// Write the portal's profile bundle, for `mooring-portal
    /// import-profiles`: for each user named, the CFM file (sing-box JSON,
    /// credentials included) or why it is withheld, to a new file with mode
    /// 0600 (never overwritten). Name every user bound to a portal account:
    /// the portal refuses a bundle that leaves one out, and `mooring-portal
    /// bound-users` on its host prints them as --user arguments. Refused
    /// until the user agreement covers the portal.
    ExportProfiles {
        /// A user bound to a portal account; give one --user per user. Only
        /// the users named are in the bundle.
        #[arg(long = "user", value_name = "USER_ID", required = true)]
        users: Vec<UserId>,
        /// The file to create, in a folder Time Machine excludes and outside
        /// iCloud Drive, the Desktop and Documents.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

/// An abuse guard command (design §11.8). Each asks one node over the
/// operations key, bound to the interface facing the M7.
#[derive(Debug, Subcommand)]
pub(crate) enum AbuseCommand {
    /// Print the users cut on a node and its abuse records, and keep the
    /// records it has not kept yet in this Mac's copy (abuse/records.json,
    /// kept 13 months; the node keeps them 30 days).
    Records {
        /// The node.
        node: NodeId,
        /// The interface facing the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// Print the node's replies, one JSON line per page of records,
        /// instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Cut a user on a node at once, as the guard does, recorded as the
    /// operator's: every flow of the user's is refused until `abuse clear`.
    /// It changes no state on this Mac; `user suspend` does.
    Cut {
        /// The node.
        node: NodeId,
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// The interface facing the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
    },
    /// Lift a user's cut on a node at once, recorded. The user need not be
    /// one this Mac still holds.
    Clear {
        /// The node.
        node: NodeId,
        /// The user's id.
        #[arg(value_name = "USER_ID")]
        user: UserId,
        /// The interface facing the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
    },
}

/// Why the operator suspends a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SuspendArg {
    /// An abuse case under review (design §11.8).
    AbuseReview,
    /// Any other reason of the operator's.
    Operator,
}

/// A portal command.
#[derive(Debug, Subcommand)]
pub(crate) enum PortalCommand {
    /// Point the daemon's payment pull at the portal and store its token,
    /// typed (pasted) at the terminal without echo or read from stdin:
    /// the 64 hexadecimal characters `mooring-portal pull-token` printed
    /// once on the portal's host. The daemon then asks the portal for the
    /// orders to grant every five minutes, while the Mac is on no foreign
    /// network, and keeps what it grants in payments/ledger.json.
    Connect {
        /// The portal's address: https:// and its DNS name, with an
        /// optional port, and nothing after it.
        #[arg(long, value_name = "URL", value_parser = parse_origin)]
        origin: PortalOrigin,
        /// Read the token from stdin (whitespace around it is ignored).
        #[arg(long)]
        stdin: bool,
    },
    /// Turn the rehearsal on or off. While it is on, payments made in
    /// Stripe's test mode are granted and count; turning it off takes
    /// them out at once. Turn it off before real payments are taken.
    Rehearsal {
        /// On or off.
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Stop the payment pull and delete its token. The payment ledger
    /// stays, and what it granted still counts.
    Disconnect,
    /// Print the payment pull's settings, the ledger's cursor, its last
    /// pull and any stop, and every order the portal listed with what
    /// Mooring did about it.
    Payments {
        /// Print the settings and the ledger as one JSON line instead of
        /// a summary.
        #[arg(long)]
        json: bool,
    },
    /// Write the portal snapshot of the users named, for `mooring-portal
    /// import`: their status, usage this billing cycle, quota and expiry,
    /// by user id and without credentials, to a new file with mode 0600
    /// (never overwritten). Refused until the user agreement covers the
    /// portal.
    Export {
        /// A user to include; give one --user per user. Only the users
        /// named are exported.
        #[arg(long = "user", value_name = "USER_ID", required = true)]
        users: Vec<UserId>,
        /// The file to create, in a folder Time Machine excludes and outside
        /// iCloud Drive, the Desktop and Documents.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

/// A switch, as typed on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OnOff {
    /// On.
    On,
    /// Off.
    Off,
}

/// The portal's origin, as `PortalOrigin` accepts it.
fn parse_origin(text: &str) -> Result<PortalOrigin, String> {
    PortalOrigin::parse(text).map_err(|error| error.to_string())
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
    /// Show the carrier address each adopted node's reflector sees through
    /// the M7, the address `record-carrier` records the prefixes for.
    Observe {
        /// The Mac's interface to the M7 (a BSD name, for example en9); its
        /// gateway must be the pinned M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
    },
    /// Let the daemon run the exit: it starts the engine once its
    /// preflight passes.
    Enable,
    /// Stop the exit: the daemon stops the engine at its next tick.
    Disable,
    /// Ask the daemon to clear a latched violation and the nodes' holds,
    /// and to run a fresh preflight.
    Retry,
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
        /// Replace the carrier check recorded already, as when the SIM
        /// changes: a configuration change, so every node then needs
        /// `node apply`.
        #[arg(long)]
        replace: bool,
        /// Record without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Declare the network joined on an interface as your own: a connection
    /// you contract for yourself (your phone's Personal Hotspot, your home
    /// broadband), so the exit keeps serving while this Mac is joined to it,
    /// even when it holds the default route. Never an institutional network
    /// (campus Wi-Fi, eduroam, Janet): on one the exit must stay down. The
    /// file holds about 85 declarations (16 KiB); past that, withdraw one.
    AllowNetwork {
        /// The interface joined to the network (a BSD name, for example
        /// en0); it is identified by its router, read from configd now.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// Your label for the network (1 to 64 characters); the SSID
        /// cannot be read.
        #[arg(long, value_name = "TEXT")]
        name: LocalLabel,
        /// The network is Apple's Personal Hotspot (router 172.20.10.1).
        #[arg(long)]
        personal_hotspot: bool,
        /// Declare without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Withdraw a declared own network by its name; the daemon treats it as
    /// foreign from its next tick (within 2 s), so withdrawing the network
    /// this Mac is joined to takes the exit down. To rename it or change
    /// its kind without that, allow it under the new name first (the same
    /// router may be declared under two names), then withdraw the old one.
    DisallowNetwork {
        /// The name it was declared under.
        #[arg(long, value_name = "TEXT")]
        name: LocalLabel,
    },
    /// List the declared own networks.
    AllowedNetworks,
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

/// A node command.
#[derive(Debug, Subcommand)]
pub(crate) enum NodeCommand {
    /// Inspect the actual watch executable and process identity on a node.
    Runtime {
        /// The node.
        node: NodeId,
        /// The interface facing the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// Print the typed runtime evidence as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Plan a node for a VPS that exists already, pinning its host key.
    New {
        /// The node's id, for example lon1.
        node: NodeId,
        /// Primary or standby.
        #[arg(long, value_enum)]
        role: RoleArg,
        /// The VPS's Ed25519 host key, as OpenSSH writes it
        /// (/etc/ssh/ssh_host_ed25519_key.pub).
        #[arg(long, value_name = "PATH")]
        host_key: PathBuf,
        /// Plan without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Install the agent on a planned node's VPS with the operator's root
    /// key, then hand the VPS to Mooring's keys (the operator's key stops
    /// working there).
    Adopt {
        /// The node's id.
        node: NodeId,
        /// The VPS's public IPv4 address.
        #[arg(long)]
        address: Ipv4Addr,
        /// The Mac's interface to the M7; the connection leaves through it.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The private key that logs in as root on the VPS now.
        #[arg(long, value_name = "PATH", required_unless_present = "resume")]
        root_identity: Option<PathBuf>,
        /// The mooring-agent release binary for the VPS's architecture.
        #[arg(long, value_name = "PATH")]
        agent: PathBuf,
        /// Resume after Bootstrap: start at the operations key's check.
        #[arg(long, conflicts_with = "root_identity")]
        resume: bool,
        /// Adopt without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Replace a planned node's pinned host key with the one in a file, as
    /// after reinstalling its VPS; check its fingerprint on the provider's
    /// console first.
    Repin {
        /// The node's id.
        node: NodeId,
        /// The VPS's Ed25519 host key, as OpenSSH writes it
        /// (/etc/ssh/ssh_host_ed25519_key.pub).
        #[arg(long, value_name = "PATH")]
        host_key: PathBuf,
        /// Re-pin without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Give a planned node up: remove it from the state with every user's
    /// credentials on it, and delete its keys from the keychain and its ssh
    /// files. No VPS is contacted; the id may be planned again. Given the id
    /// of a cancel that stopped midway, it removes the ssh files that cancel
    /// left.
    Cancel {
        /// The node's id.
        node: NodeId,
        /// Cancel without asking.
        #[arg(long)]
        yes: bool,
    },
    /// The node's REALITY target.
    #[command(subcommand)]
    Target(TargetCommand),
    /// Render the node's bundle for the current generation, install it
    /// with a transaction, confirm it and record what the node confirmed.
    Apply {
        /// The node's id.
        node: NodeId,
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The engine directory `cargo xtask engines-verify` accepted.
        #[arg(long, value_name = "DIR")]
        engines: PathBuf,
    },
    /// Upload a new agent, have the node activate it (its self-test first,
    /// the previous agent's revert timer armed) and confirm it from the
    /// new agent.
    UpgradeAgent {
        /// The node's id.
        node: NodeId,
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The mooring-agent release binary for the VPS's architecture.
        #[arg(long, value_name = "PATH")]
        agent: PathBuf,
    },
}

/// A target command.
#[derive(Debug, Subcommand)]
pub(crate) enum TargetCommand {
    /// Have the node measure a candidate target and print every rule it
    /// fails, the operator's attestation aside.
    Check {
        /// The node's id.
        node: NodeId,
        /// The candidate host.
        host: DnsName,
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The engine directory `cargo xtask engines-verify` accepted.
        #[arg(long, value_name = "DIR")]
        engines: PathBuf,
    },
    /// Measure the target again, qualify it with the attestation and
    /// store it.
    Set {
        /// The node's id.
        node: NodeId,
        /// The host.
        host: DnsName,
        /// The Mac's interface to the M7.
        #[arg(long, value_name = "BSD_NAME")]
        interface: BsdName,
        /// The engine directory `cargo xtask engines-verify` accepted.
        #[arg(long, value_name = "DIR")]
        engines: PathBuf,
        /// The target is announced by the VPS's ASN.
        #[arg(long)]
        same_asn: bool,
        /// The target is not served by a CDN.
        #[arg(long)]
        not_cdn: bool,
        /// Where the evidence for both lives (https).
        #[arg(long, value_name = "URL")]
        evidence: String,
        /// Store without asking.
        #[arg(long)]
        yes: bool,
    },
}

/// A node's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RoleArg {
    /// The node users are told to prefer.
    Primary,
    /// The standby, on a different ASN.
    Standby,
}

impl From<RoleArg> for NodeRole {
    fn from(arg: RoleArg) -> Self {
        match arg {
            RoleArg::Primary => Self::Primary,
            RoleArg::Standby => Self::Standby,
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
    /// Take the network the M7 reports as the SIM's network on record,
    /// which ends the console's notice of another SIM or network. The
    /// carrier check and the billing cycle stay as they are.
    AcceptNetwork {
        /// Take it without asking.
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
    /// Print the radio samples the daemon recorded, one per poll of the M7
    /// (UTC day files under the support directory): a summary of each
    /// day's polls, the changes between them and the hourly signal, or the
    /// document Mooring.app reads. Yesterday and today by default.
    History {
        /// The first UTC day (YYYY-MM-DD); the day before --until by
        /// default.
        #[arg(long, value_name = "DATE")]
        since: Option<CalendarDate>,
        /// The last UTC day (YYYY-MM-DD); today by default.
        #[arg(long, value_name = "DATE")]
        until: Option<CalendarDate>,
        /// Print one JSON line (a radio history document) instead of a
        /// summary.
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
