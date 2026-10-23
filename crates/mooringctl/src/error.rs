// SPDX-License-Identifier: GPL-3.0-or-later

//! The command's errors and exit codes (design §14): a router failure,
//! whose kind is the status's `RouterUnavailableReason`, or a failure on
//! the Mac itself.

use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use mooring_daemon_core::ControlError;
use mooring_daemon_core::control::Refusal;
use mooring_daemon_core::router::RouterUnavailableReason;
use mooring_export::ExportError;
use mooring_keys::KeysError;
use mooring_macsys::MacsysError;
use mooring_model::error::ModelError;
use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::{PublicAlias, UserId};
use mooring_store::{SecretStoreError, SnapshotReadError, StoreError};

use crate::router::error::RouterError;

/// A failure on the Mac rather than at the M7.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalError {
    /// `HOME` is unset or not an absolute path.
    #[error("HOME is not set to an absolute path")]
    Home,
    /// The support directory could not be created.
    #[error("cannot create {}", path.display())]
    SupportDir {
        /// The directory.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The keychain refused an operation.
    #[error("the keychain failed")]
    Keychain(#[source] SecretStoreError),
    /// The router identity file could not be read or written.
    #[error("the router identity file failed")]
    Store(#[source] StoreError),
    /// There is no deployment on this Mac yet: no `state.json`, or not
    /// even the support directory.
    #[error("no state at {}: there is no deployment on this Mac yet (`exit init` creates it)", path.display())]
    NoState {
        /// Where `state.json` would be.
        path: PathBuf,
    },
    /// `state.json` could not be read. (Boxed, as in `StateChange`: a
    /// second unboxed `StoreError` beside `Store` would grow every
    /// `CommandError` by the discriminant the niche no longer holds.)
    #[error("the state could not be read")]
    StateRead(#[source] Box<StoreError>),
    /// A change to `state.json` was refused or failed; the store leaves the
    /// state as it was.
    #[error("the state was not changed")]
    StateChange(#[source] Box<StoreError>),
    /// The label typed is not a valid local label.
    #[error("the label was not accepted")]
    Label(#[source] ModelError),
    /// No terminal is attached to ask for the label.
    #[error("no terminal to ask for the label (it is never taken from an argument)")]
    NoLabelTerminal,
    /// `--mlkem` was asked for a CFM 0.4 client, whose importer refuses it.
    #[error("CFM 0.4 does not accept the ML-KEM opt-in; drop --mlkem or use --client cfm05")]
    MlkemUnsupported,
    /// Random credentials could not be drawn.
    #[error("drawing random credentials failed")]
    Keys(#[source] KeysError),
    /// The user already has an alias; an alias is never replaced.
    #[error("user {user} already has the alias {alias}")]
    AliasExists {
        /// The user.
        user: UserId,
        /// The alias it has.
        alias: PublicAlias,
    },
    /// No user has this id.
    #[error("unknown user {user}")]
    UnknownUser {
        /// The id given.
        user: UserId,
    },
    /// The export's file already exists; an export never overwrites one.
    #[error("{} already exists; an export never overwrites a file", path.display())]
    ExportExists {
        /// The file.
        path: PathBuf,
    },
    /// The folder the export's file would go in cannot be resolved.
    #[error("cannot use the folder of {}", path.display())]
    ExportFolder {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The user has not accepted the agreement revision this build ships
    /// (decision F9).
    #[error(
        "no file was written: record the user's acceptance with `mooringctl user agree {user}` once the user has accepted the agreement (docs/runbooks/user-agreement.md)"
    )]
    AgreementNotRecorded {
        /// The user.
        user: UserId,
        /// The export's refusal.
        #[source]
        source: Box<ExportError>,
    },
    /// `mooring-export` refused the file for another reason.
    #[error("no file was written: the export was refused")]
    ExportRefused(#[source] Box<ExportError>),
    /// The user's secrets could not be read from the keychain.
    #[error("no file was written: reading the user's secrets from the keychain failed")]
    Secrets(#[source] Box<SnapshotReadError>),
    /// The export's file could not be written; what was written of it has
    /// been removed.
    #[error("cannot write the export to {}; no part of it is left", path.display())]
    ExportWrite {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The export's file could not be written, and what was written of it
    /// could not be removed either: it holds the user's credentials.
    #[error(
        "cannot write the export to {} and cannot remove what was written ({removal}): delete the file by hand",
        path.display()
    )]
    ExportLeftBehind {
        /// The file.
        path: PathBuf,
        /// Why the removal failed.
        removal: io::Error,
        /// The write's error.
        #[source]
        source: io::Error,
    },
    /// The kernel's interface, routing or neighbour tables could not be
    /// read.
    #[error("reading the kernel's network tables failed")]
    Kernel(#[source] MacsysError),
    /// The kernel returned an empty neighbour table although the gateway
    /// had been reached: after the anonymous `GET` (`status`, `capture`), or,
    /// for `router pin`, in the reads both before and after its warm-up
    /// connection, which succeeded. So the M7's link-layer address cannot be
    /// read. That the kernel hides the table from this binary is an
    /// inference (design §15.6 rule 10). Measured on macOS 27.0.1 (26A434):
    /// the table was empty to a binary whose code-signing identifier is not
    /// reverse-DNS, as a plain `cargo build` signs it, and to one with an
    /// ad-hoc-signed ancestor (a copy of bash, cargo or nextest). That an
    /// ad-hoc-signed terminal multiplexer above it hides the table as well,
    /// and that every such binary is refused it, are inferences.
    #[error(
        "the kernel returned an empty neighbour table to this binary; on macOS 27.0.1 that was seen when a binary's signing identifier is not reverse-DNS or an ad-hoc-signed program such as cargo is among its ancestors: build it with `cargo xtask mooringctl` and run the binary it names from Terminal.app's own shell"
    )]
    NeighbourTableHidden,
    /// No terminal is attached to ask for the password.
    #[error("no terminal to ask for the password (use --stdin)")]
    NoTerminal,
    /// The terminal could not be used.
    #[error("the terminal failed")]
    Terminal(#[source] io::Error),
    /// The terminal's echo could not be switched off or back on.
    #[error("the terminal's echo could not be controlled")]
    Echo(#[source] MacsysError),
    /// The pin was not confirmed.
    #[error("not recorded: {0}")]
    NotConfirmed(Unconfirmed),
    /// A different identity is already pinned.
    #[error("the M7's identity is already pinned as {pinned}; rerun with --replace to replace it")]
    PinExists {
        /// The pinned link-layer address.
        pinned: MacAddr,
    },
    /// The password is not 1 to 128 bytes of printable ASCII.
    #[error("the password is not 1 to 128 bytes of printable ASCII")]
    Password(#[source] ModelError),
    /// The two passwords typed differ.
    #[error("the two passwords differ")]
    PasswordsDiffer,
    /// Reading the password from stdin failed.
    #[error("reading the password from stdin failed")]
    Stdin(#[source] io::Error),
    /// The capture file already exists; it is never overwritten.
    #[error("{} already exists; a capture never overwrites a file", path.display())]
    CaptureExists {
        /// The file.
        path: PathBuf,
    },
    /// The capture file could not be written.
    #[error("cannot write the capture to {}", path.display())]
    CaptureWrite {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The Mac's clock is before 1970 or past the year 9999.
    #[error("the Mac's clock is outside 1970 to 9999")]
    Clock,
    /// The output could not be encoded or written.
    #[error("writing the output failed")]
    Output(#[source] io::Error),
    /// The daemon's run directory could not be created.
    #[error("cannot create the daemon's run directory {}", path.display())]
    RunDir {
        /// The directory.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// Something other than a directory, a symbolic link for one, is at
    /// the daemon's run directory's path.
    #[error(
        "the daemon's run directory {} is not a directory (a link or another file is there)",
        path.display()
    )]
    RunDirNotDirectory {
        /// The path.
        path: PathBuf,
    },
    /// The daemon's instance lock could not be opened or taken.
    #[error("cannot lock {}", path.display())]
    DaemonLock {
        /// The lock file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// Another daemon holds the instance lock.
    #[error("another mooringctl daemon is running (it holds {})", path.display())]
    DaemonAlreadyRunning {
        /// The lock file.
        path: PathBuf,
    },
    /// A deployment exists, and this build's daemon serves only the router
    /// console before `exit init`.
    #[error(
        "a deployment exists ({}), and this build's daemon serves only the router console, before `exit init`",
        path.display()
    )]
    DeploymentNotServed {
        /// The state file.
        path: PathBuf,
    },
    /// Whether `state.json` exists could not be told.
    #[error("cannot inspect {}", path.display())]
    StateInspect {
        /// The state file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// Something other than a socket is at the control socket's path; it is
    /// left as it is.
    #[error("{} exists and is not a socket; it is left as it is", path.display())]
    SocketPathTaken {
        /// The path.
        path: PathBuf,
    },
    /// The control socket could not be set up.
    #[error("cannot set up the control socket {}", path.display())]
    Socket {
        /// The socket's path.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The daemon's status could not be encoded as a reply line.
    #[error("the daemon could not encode its status")]
    StatusEncode(#[source] ControlError),
    /// A thread panicked while it held the daemon's status, so the status
    /// can no longer be trusted.
    #[error("the daemon's status was left inconsistent by a failed thread")]
    StatusPoisoned,
    /// The daemon's control socket stopped accepting connections.
    #[error("the daemon's control socket stopped accepting connections")]
    Acceptor(#[source] io::Error),
    /// No daemon listens on the control socket.
    #[error("the Mooring daemon is not running (nothing listens on {})", path.display())]
    DaemonNotRunning {
        /// The socket's path.
        path: PathBuf,
    },
    /// Talking to the daemon failed.
    #[error("talking to the daemon on {} failed", path.display())]
    DaemonIo {
        /// The socket's path.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The daemon refused the request.
    #[error("the daemon refused the request: {}", refusal_text(*reason))]
    DaemonRefused {
        /// Why.
        reason: Refusal,
    },
    /// A line from the daemon could not be read as a reply.
    #[error("the daemon's reply could not be read")]
    DaemonReply(#[source] ControlError),
    /// The daemon closed the status stream.
    #[error("the daemon closed the status stream")]
    DaemonClosed,
    /// The daemon sent nothing for longer than a poll takes.
    #[error("the daemon sent no status for {secs} s")]
    DaemonSilent {
        /// How long it was silent.
        secs: u64,
    },
    /// The daemon's newest status is older than a follow accepts: its poll
    /// has not finished since.
    #[error(
        "the daemon's latest status is from {at}, more than {max_secs} s ago: its poll of the M7 has not finished (macOS may be waiting for an answer to a keychain or local network prompt)"
    )]
    StatusStale {
        /// When the daemon made it, in UTC.
        at: String,
        /// The most a follow accepts.
        max_secs: u64,
    },
    /// The CLI could not encode a control line of its own (a request, or a
    /// status it prints).
    #[error("mooringctl could not encode a control line")]
    ClientEncode(#[source] ControlError),
    /// The daemon reported a deployment's status, which this build prints
    /// only as JSON.
    #[error("this build prints a deployment's status only as JSON (use --json)")]
    DeployedSummary,
    /// `exit init` found a deployment; it creates one only once.
    #[error("a deployment exists already ({}); `exit init` creates one only once", path.display())]
    DeploymentExists {
        /// The state file.
        path: PathBuf,
    },
    /// The interface's default gateway is not the pinned M7.
    #[error(
        "the gateway of {} is {found}, not the pinned M7 ({pinned}): give the interface that faces the M7",
        interface.as_str()
    )]
    EgressNotTheRouter {
        /// The interface given.
        interface: BsdName,
        /// Its gateway's link-layer address.
        found: MacAddr,
        /// The pinned one.
        pinned: MacAddr,
    },
    /// No address of the interface lies with its gateway in a private LAN
    /// subnet, which the egress selector records.
    #[error(
        "{} has no address in a private LAN subnet with its gateway {gateway}",
        interface.as_str()
    )]
    EgressSubnet {
        /// The interface given.
        interface: BsdName,
        /// Its default gateway.
        gateway: Ipv4Addr,
    },
    /// The pilot's values were refused by the model.
    #[error("the pilot's values were not accepted")]
    Pilot(#[source] ModelError),
    /// The carrier check is recorded already.
    #[error(
        "the carrier check is recorded already; replacing it is a configuration change, which this build does not make"
    )]
    CarrierRecorded,
    /// The carrier prefixes given were not accepted.
    #[error("the carrier prefixes were not accepted")]
    CarrierCheck(#[source] ModelError),
    /// The billing cycles are monthly, and `sim set-anchor` moves only
    /// fixed-length ones.
    #[error(
        "the SIM's billing cycles are monthly; `sim set-anchor` moves fixed-length cycles only"
    )]
    CycleNotFixed,
    /// The SIM policy the change would record was not accepted.
    #[error("the SIM policy was not accepted")]
    SimChange(#[source] ModelError),
}

/// What a refusal means, in words.
pub(crate) const fn refusal_text(reason: Refusal) -> &'static str {
    match reason {
        Refusal::Busy => "it already serves as many clients as it accepts; try again",
        Refusal::BadRequest => "the request was malformed",
        Refusal::NoStatusYet => "its first poll of the M7 has not finished yet",
    }
}

/// Why a pin was not confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unconfirmed {
    /// The operator did not answer yes.
    Declined,
    /// No terminal is attached and `--yes` was not given.
    NoTerminal,
}

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Declined => "the answer was not yes",
            Self::NoTerminal => "no terminal to ask and --yes was not given",
        })
    }
}

/// A command's failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommandError {
    /// At the M7, or on the way to it.
    #[error(transparent)]
    Router(#[from] RouterError),
    /// On the Mac.
    #[error(transparent)]
    Local(#[from] LocalError),
}

/// The exit code of a usage error (clap's own).
#[cfg(test)]
pub(crate) const EXIT_USAGE: u8 = 2;

/// The exit code of a local failure.
pub(crate) const EXIT_LOCAL: u8 = 1;

impl CommandError {
    /// The exit code: 1 for a local failure, 3 to 8 for a router failure
    /// in the order of `RouterUnavailableReason` (2 is clap's usage error).
    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::Local(_) => EXIT_LOCAL,
            Self::Router(error) => reason_exit_code(error.reason()),
        }
    }
}

/// The exit code of a router failure with `reason`. A command reports a
/// failure on the Mac as a `LocalError` (exit 1), never as a router
/// failure; `LocalFailure` is the daemon's reason for one, and maps to the
/// same code.
pub(crate) const fn reason_exit_code(reason: RouterUnavailableReason) -> u8 {
    match reason {
        RouterUnavailableReason::NotConfigured => 3,
        RouterUnavailableReason::Unreachable => 4,
        RouterUnavailableReason::AuthFailed => 5,
        RouterUnavailableReason::IdentityMismatch => 6,
        RouterUnavailableReason::Unsupported => 7,
        RouterUnavailableReason::Malformed => 8,
        RouterUnavailableReason::LocalFailure => EXIT_LOCAL,
    }
}
