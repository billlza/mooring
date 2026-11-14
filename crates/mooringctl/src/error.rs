// SPDX-License-Identifier: GPL-3.0-or-later

//! The command's errors and exit codes (design §14): a router failure,
//! whose kind is the status's `RouterUnavailableReason`, or a failure on
//! the Mac itself.

use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use mooring_agent_proto::{AgentError, Sha256Hex};
use mooring_daemon_core::ControlError;
use mooring_daemon_core::PortalError;
use mooring_daemon_core::RadioHistoryError;
use mooring_daemon_core::control::Refusal;
use mooring_daemon_core::exit::EgressFault;
use mooring_daemon_core::meter::MeterError;
use mooring_daemon_core::router::RouterUnavailableReason;
use mooring_daemon_core::sim_network::NotAccepted;
use mooring_daemon_core::snapshot::SnapshotError;
use mooring_export::{ExportError, ProfilesError};
use mooring_keys::{KeysError, SshPublicKey};
use mooring_macsys::MacsysError;
use mooring_model::dns::DnsName;
use mooring_model::error::ModelError;
use mooring_model::ids::LocalLabel;
use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::node::LifecycleStage;
use mooring_model::secret::SecretKind;
use mooring_model::{CalendarDate, NodeId, PortalNotCovered, PublicAlias, UserId};
use mooring_render::RenderError;
use mooring_store::{MAX_ALLOWED_NETWORKS_BYTES, SecretStoreError, SnapshotReadError, StoreError};

use crate::collected_usage::UsageFault;
use crate::node::NodeError;
use crate::node::adopt::Step;
use crate::node::planned::PlannedAction;
use crate::router::error::RouterError;

/// A failure on the Mac rather than at the M7.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalError {
    /// Collected usage is inconsistent or cannot be decoded.
    #[error("collected user usage is invalid")]
    CollectedUsage(#[source] mooring_daemon_core::error::UsageError),

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
    /// The state is no longer the one the command read and described:
    /// another command changed it meanwhile, as while a question waited
    /// (`state::unchanged`). What was described, and answered if the
    /// command asked, was about the state read, so the command stopped
    /// before acting on it.
    #[error(
        "the state changed since this command read it, so it stopped before acting: run the command again"
    )]
    StateChangedSinceRead,
    /// The change is committed, but deleting the keychain items it no
    /// longer references failed for some (`StoreError::SecretCleanup`,
    /// which names each: one that could not be deleted, or one that was
    /// gone already). Nothing references them any more.
    #[error(
        "the change is committed, but deleting the keychain items it no longer references failed for those named below; nothing uses them, and any that is still there can be deleted by hand"
    )]
    StateCommitted(#[source] Box<StoreError>),
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
    /// The agreement revision this build ships does not cover the portal,
    /// so no portal file is made (design §9.5).
    #[error(
        "no file was written: nothing goes to the portal before a revision of the user agreement covers it and the users accept that revision (docs/runbooks/user-agreement.md)"
    )]
    PortalNotCovered(#[source] PortalNotCovered),
    /// The usage the daemon collected cannot be read or is inconsistent, so
    /// no snapshot is written: it would show every figure as unknown and
    /// hide the fault (design §9.5).
    #[error(
        "no file was written: the usage the daemon collected (usage/users.json) cannot be read or is inconsistent"
    )]
    PortalUsage(#[source] Box<UsageFault>),
    /// `mooring-daemon-core` refused the portal snapshot.
    #[error("no file was written: the portal snapshot was refused")]
    PortalSnapshotRefused(#[source] Box<PortalError>),
    /// There is no collected usage to read a user's history from:
    /// `usage/users.json` does not exist. It is never read as a history
    /// with nothing in it.
    #[error(
        "no usage is collected at {}: the daemon writes it while it serves a deployment, and no history is shown without it",
        path.display()
    )]
    NoCollectedUsage {
        /// Where the file would be.
        path: PathBuf,
    },
    /// The usage the daemon collected cannot be read or is inconsistent,
    /// so no user's history is shown or written from it.
    #[error(
        "the usage the daemon collected (usage/users.json) cannot be read or is inconsistent: no history is shown or written"
    )]
    UserUsage(#[source] Box<UsageFault>),
    /// `mooring-export` refused the portal's profile bundle.
    #[error("no file was written: the profile bundle was refused")]
    ProfilesRefused(#[source] Box<ProfilesError>),
    /// The secrets of the bundle's users could not be read from the
    /// keychain.
    #[error("no file was written: reading the users' secrets from the keychain failed")]
    ProfilesSecrets(#[source] Box<SnapshotReadError>),
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
    /// Another `router pin` pinned a different identity while this one's
    /// question waited: the answer was to a question about no pin, or
    /// about another one.
    #[error(
        "another `router pin` pinned {pinned} as the M7's identity while this question waited, so nothing was written: check which device is the M7 before replacing either (`router pin --replace`)"
    )]
    PinnedMeanwhile {
        /// The link-layer address pinned meanwhile.
        pinned: MacAddr,
    },
    /// The password is not 1 to 128 bytes of printable ASCII.
    #[error("the password is not 1 to 128 bytes of printable ASCII")]
    Password(#[source] ModelError),
    /// The two passwords typed differ.
    #[error("the two passwords differ")]
    PasswordsDiffer,
    /// The pull token is not the portal's token.
    #[error(
        "the pull token is not the 64 lower-case hexadecimal characters `mooring-portal pull-token` printed"
    )]
    PullToken(#[source] ModelError),
    /// The key given to `portal stripe-check on` is not a restricted live
    /// key; the error says why without echoing it.
    #[error("the Stripe key was refused")]
    StripeKey(#[source] mooring_model::StripeKeyError),
    /// The payment pull's files could not be read or written.
    #[error("the payment pull's files failed")]
    PaymentFiles(#[source] Box<crate::payments::PaymentFileError>),
    /// `portal rehearsal` before `portal connect`.
    #[error("the payment pull is not connected: `mooringctl portal connect` first")]
    PaymentPullNotConnected,
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
    /// Another run of the apply job holds its lock.
    #[error("another apply job is running (it holds {}); nothing was done", path.display())]
    ApplyAlreadyRunning {
        /// The lock file.
        path: PathBuf,
    },
    /// The apply job's lock could not be opened or taken.
    #[error("the apply job's lock {} failed", path.display())]
    ApplyLock {
        /// The lock file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Parts of an apply job's run failed; its report says which, and the
    /// rest of it was done.
    #[error(
        "the apply job finished with {failures} failure(s); the report above and apply.log say which"
    )]
    ApplyFailed {
        /// How many parts failed.
        failures: usize,
    },
    /// The exit site refused the interfaces resolved for it.
    #[error("the interfaces resolved for the exit were refused")]
    ExitSite(#[source] ModelError),
    /// The billing cycle of the Mac's clock could not be computed.
    #[error("the SIM billing cycle could not be computed")]
    Cycle(#[source] ModelError),
    /// The exit's latch file (`run/latch.json`) failed. (Boxed, as
    /// `StateRead` is.)
    #[error("the exit's latch file failed")]
    Latch(#[source] Box<StoreError>),
    /// The SIM meter's file (`usage/sim-meter.json`) failed. (Boxed, as
    /// `StateRead` is.)
    #[error("the SIM meter's file failed")]
    MeterFile(#[source] Box<StoreError>),
    /// The radio history's files (`radio/<day>.jsonl`) failed. (Boxed, as
    /// `StateRead` is.)
    #[error("the radio history's files failed")]
    HistoryFile(#[source] Box<StoreError>),
    /// A radio sample could not be encoded as its line.
    #[error("a radio sample could not be encoded")]
    HistoryEncode(#[source] RadioHistoryError),
    /// `router history`'s range runs backwards.
    #[error("--since {since} is after --until {until}")]
    HistoryRange {
        /// The first day asked for.
        since: CalendarDate,
        /// The last day asked for.
        until: CalendarDate,
    },
    /// `router history`'s range covers more days than the daemon keeps.
    #[error(
        "the range covers {days} days; at most {max} can be read at once (narrow it with --since and --until)"
    )]
    HistoryRangeTooLong {
        /// The days the range covers.
        days: u32,
        /// The most it may cover.
        max: u32,
    },
    /// A line of a radio history day file is not a sample this build
    /// reads; the file is left as it is.
    #[error("radio history file {} cannot be read at line {line}", path.display())]
    HistoryLine {
        /// The day file.
        path: PathBuf,
        /// The line, counted from 1.
        line: usize,
        /// Why the decoder refused it.
        #[source]
        source: RadioHistoryError,
    },
    /// The SIM meter could not count a reading or read its document.
    /// (Boxed, as `StateRead` is, to keep `CommandError` small.)
    #[error("the SIM meter failed")]
    Meter(#[source] Box<MeterError>),
    /// The SIM meter's thread ended, or left its state inconsistent.
    #[error("the SIM meter's thread stopped")]
    MeterThread,
    /// The SIM meter's thread ended on a fault: the daemon can no longer
    /// count the line's bytes, so it stops.
    #[error("the SIM meter stopped: {fault}")]
    MeterFault {
        /// The fault, with its causes.
        fault: String,
    },
    /// The daemon could not assemble its status. (Boxed, as `StateRead`
    /// is, to keep `CommandError` small.)
    #[error("the daemon could not assemble its status")]
    Snapshot(#[source] Box<SnapshotError>),
    /// The exit's engine config could not be rendered.
    #[error("the exit's engine config could not be rendered")]
    ExitRender(#[source] Box<RenderError>),
    /// The exit's keys could not be read from the keychain.
    #[error("reading the exit's keys from the keychain failed")]
    ExitSecrets(#[source] Box<SnapshotReadError>),
    /// Waiting for or stopping the exit's engine failed.
    #[error("waiting for the exit's engine failed")]
    EngineWait(#[source] io::Error),
    /// The engine an earlier daemon left could not be checked or stopped.
    #[error("the engine an earlier daemon left (pid {pid}) could not be checked or stopped")]
    StaleEngine {
        /// Its process id.
        pid: u32,
        /// The kernel's error.
        #[source]
        source: MacsysError,
    },
    /// The engine's pid file could not be read, written or removed.
    #[error("the engine's pid file {} failed", path.display())]
    EnginePidFile {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The daemon's own path, beside which the power helper lies, could
    /// not be found.
    #[error("the daemon's own executable could not be found")]
    PowerHelperPath(#[source] io::Error),
    /// The power helper could not be started.
    #[error("the power helper {} could not be started", path.display())]
    PowerHelperSpawn {
        /// The helper.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// A command to the power helper could not be encoded.
    #[error("a command to the power helper could not be encoded")]
    PowerHelperLine(#[source] ControlError),
    /// A command could not be written to the power helper.
    #[error("a command could not be written to the power helper")]
    PowerHelperWrite(#[source] io::Error),
    /// The power helper did not report the power source in time after it
    /// started.
    #[error("the power helper did not report the power source within {waited:?}")]
    PowerHelperSilent {
        /// How long the daemon waited.
        waited: std::time::Duration,
    },
    /// The power helper ended before it reported the power source.
    #[error("the power helper ended before it reported the power source: {0}")]
    PowerHelperEnded(String),
    /// The power helper's first report was not the power source.
    #[error("the power helper's first report was {0:?}, not the power source")]
    PowerHelperFirstReport(mooring_daemon_core::power::HelperEvent),
    /// A node cannot be reached: the exit's interfaces, the egress that
    /// faces the M7 among them, do not resolve.
    #[error("the node cannot be reached: the exit's interfaces do not resolve: {fault}")]
    NodeUnreachableWithoutEgress {
        /// Why.
        fault: EgressFault,
    },
    /// The prober's config serves a node without a site, which only an
    /// applied node can be rendered for.
    #[error("the prober's config serves {node}, which has no site")]
    ProberTarget {
        /// The node.
        node: NodeId,
    },
    /// The kernel lists an interface whose name is not a BSD name, so the
    /// foreign-network check cannot name it.
    #[error("the kernel lists an interface named {name:?}, which is not a BSD name")]
    InterfaceName {
        /// The name, as the kernel gave it.
        name: String,
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
    /// The daemon's log directory could not be created.
    #[error("cannot create the daemon's log directory {}", path.display())]
    LogDir {
        /// The directory.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The daemon's log could not be opened.
    #[error("cannot open the daemon's log {}", path.display())]
    LogFile {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// Standard error could not be pointed at the daemon's log.
    #[error("cannot send the daemon's standard error to its log")]
    LogRedirect(#[source] MacsysError),
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
    /// The daemon's first line did not name its control protocol (design
    /// §15.1): a daemon built before the protocol line, or something else
    /// on the socket.
    #[error(
        "the daemon did not name its control protocol on its first line, as a daemon built before this mooringctl may not: restart the daemon (Stop the Daemon, then Start the Daemon at Login, in Mooring's menu)"
    )]
    DaemonProtocolMissing,
    /// The daemon speaks another control protocol than this mooringctl.
    #[error(
        "the daemon speaks control protocol {daemon} and this mooringctl speaks {client}: use the mooringctl inside Mooring.app, and after updating the app restart the daemon (Stop the Daemon, then Start the Daemon at Login, in Mooring's menu)"
    )]
    DaemonProtocolOther {
        /// The daemon's.
        daemon: u32,
        /// This mooringctl's.
        client: u32,
    },
    /// No adopted node's reflector answered `exit observe`.
    #[error("no node's reflector answered; adopt a node first, and check the line")]
    NothingObserved,
    /// The daemon answered with a reply to another request.
    #[error("the daemon answered with a reply to another request")]
    DaemonUnexpectedReply,
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
    /// The carrier check is recorded already, and `--replace` was not given.
    #[error(
        "the carrier check is recorded already; give --replace to replace it (a configuration change)"
    )]
    CarrierRecorded,
    /// `--replace` was given, and no carrier check is recorded.
    #[error(
        "no carrier check is recorded, so there is none to replace; record it without --replace"
    )]
    CarrierNotRecorded,
    /// The carrier prefixes given were not accepted.
    #[error("the carrier prefixes were not accepted")]
    CarrierCheck(#[source] ModelError),
    /// configd's IPv4 services could not be read.
    #[error("reading configd's network services failed")]
    Configd(#[source] MacsysError),
    /// The allowed-networks file could not be read or written.
    #[error("the allowed-networks file failed")]
    AllowedNetworks(#[source] Box<StoreError>),
    /// `exit allow-network` named the interface facing the M7 or the
    /// separate uplink.
    #[error(
        "{} faces the M7 (the pinned interface or the separate uplink): it is the exit's own path, not a network to allow",
        interface.as_str()
    )]
    NetworkIsEgress {
        /// The interface given.
        interface: BsdName,
    },
    /// The interface has no IPv4 service with a router in configd.
    #[error(
        "{} has no IPv4 service with a router: join the network first and wait for its router to resolve",
        interface.as_str()
    )]
    NoRouterOnInterface {
        /// The interface given.
        interface: BsdName,
    },
    /// The interface has more than one IPv4 service with a router.
    #[error(
        "{} has {count} IPv4 services with a router, so the network cannot be told apart",
        interface.as_str()
    )]
    AmbiguousNetwork {
        /// The interface given.
        interface: BsdName,
        /// How many services have a router.
        count: usize,
    },
    /// configd has not resolved the router's link-layer address yet.
    #[error(
        "the router of {} has no resolved link-layer address yet: wait a few seconds after joining and try again",
        interface.as_str()
    )]
    RouterUnresolved {
        /// The interface given.
        interface: BsdName,
    },
    /// The router's link-layer address identifies no device: all zero, a
    /// group address, or the iOS privacy placeholder.
    #[error(
        "the router of {} shows a link-layer address that identifies no device",
        interface.as_str()
    )]
    RouterUnusable {
        /// The interface given.
        interface: BsdName,
        /// What the model refused.
        #[source]
        source: ModelError,
    },
    /// The router is the pinned M7 itself.
    #[error(
        "the router of {} is the pinned M7: the M7's network is the exit's own path, not a network to allow",
        interface.as_str()
    )]
    RouterIsTheM7 {
        /// The interface given.
        interface: BsdName,
    },
    /// The network publishes a UK academic (Janet) DNS domain.
    #[error(
        "{} is on {domain}, a UK academic network (Janet): the exit must stay down on it (P0-2), so it cannot be allowed",
        interface.as_str()
    )]
    InstitutionalDomain {
        /// The interface given.
        interface: BsdName,
        /// The domain it publishes.
        domain: DnsName,
    },
    /// `--personal-hotspot` was given for a network whose router is not
    /// Apple's.
    #[error(
        "--personal-hotspot names Apple's Personal Hotspot, whose router is 172.20.10.1; the router of {} is {router}",
        interface.as_str()
    )]
    NotAppleHotspot {
        /// The interface given.
        interface: BsdName,
        /// Its router.
        router: Ipv4Addr,
    },
    /// A network of that name is declared already.
    #[error(
        "a network named \"{name}\" is declared already; `exit disallow-network --name` withdraws it"
    )]
    NetworkDeclared {
        /// The name given.
        name: LocalLabel,
    },
    /// The declarations file cannot hold another network.
    #[error(
        "the allowed-networks file is full: {declared} networks are declared and another does not fit within its {} KiB; `exit disallow-network --name` withdraws one first",
        MAX_ALLOWED_NETWORKS_BYTES / 1024
    )]
    NetworksFull {
        /// How many networks are declared.
        declared: usize,
    },
    /// No declared network has that name.
    #[error("no declared network is named \"{name}\"; `exit allowed-networks` lists them")]
    NetworkUnknown {
        /// The name given.
        name: LocalLabel,
    },
    /// The billing cycles are monthly, and `sim set-anchor` moves only
    /// fixed-length ones.
    #[error(
        "the SIM's billing cycles are monthly; `sim set-anchor` moves fixed-length cycles only"
    )]
    CycleNotFixed,
    /// The SIM policy the change would record was not accepted.
    #[error("the SIM policy was not accepted")]
    SimChange(#[source] ModelError),
    /// `sim accept-network` with no deployment on this Mac: the daemon
    /// keeps no record of a SIM's network then.
    #[error(
        "there is no deployment yet (`exit init` creates it), so no SIM's network is on record"
    )]
    SimNetworkWithoutDeployment,
    /// `sim accept-network` found no network to take, in the status the
    /// daemon gave it.
    #[error("no network was taken: {0}")]
    SimNetworkNotTaken(NotAccepted),
    /// A node with this id exists already.
    #[error("node {node} exists already")]
    NodeExists {
        /// The id given.
        node: NodeId,
    },
    /// A public key's file (the host key's, or a node's own `.pub`) could
    /// not be read.
    #[error("cannot read the public key in {}", path.display())]
    HostKeyFile {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// A public key's file does not hold exactly one Ed25519 OpenSSH public
    /// key line: none, a malformed one, a second line, a character that
    /// ends a line on a screen, or more than one line's worth of bytes.
    #[error(
        "{} does not hold exactly one Ed25519 public key as OpenSSH writes it (`ssh-ed25519 <base64> [comment]`, one line)",
        path.display()
    )]
    HostKey {
        /// The file.
        path: PathBuf,
    },
    /// A public key's path (the host key's file, or a node's own `.pub`)
    /// is not a regular file: a directory, a FIFO or a device.
    #[error("{} is not a regular file, so no public key was read from it", path.display())]
    HostKeyNotAFile {
        /// The path.
        path: PathBuf,
    },
    /// `node new` found the ssh directory an earlier node with this id
    /// left, whose operations key the new node would otherwise inherit.
    /// It holds only what Mooring keeps there, which `node cancel` removes
    /// (anything else is `NodeFileUnexpected`).
    #[error(
        "{} exists already: an earlier node with this id left it; `node cancel {node}` removes the ssh files Mooring kept there, then plan the node again",
        path.display()
    )]
    NodeFilesExist {
        /// The id given.
        node: NodeId,
        /// The directory.
        path: PathBuf,
    },
    /// A node's ssh directory is not a directory, or holds something
    /// Mooring does not keep there. `node cancel` will not remove it, and
    /// `node new` will not plan a node beside it.
    #[error(
        "{} is not what Mooring keeps for a node; move it away, then run the command again",
        path.display()
    )]
    NodeFileUnexpected {
        /// The path.
        path: PathBuf,
    },
    /// The cancel is committed, but the node's ssh directory could not be
    /// removed.
    #[error(
        "node {node} is cancelled, but {} could not be removed; until it is removed, by `node cancel {node}` again or by hand, `node new {node}` refuses",
        dir.display()
    )]
    NodeFilesLeft {
        /// The cancelled node.
        node: NodeId,
        /// Its ssh directory.
        dir: PathBuf,
        /// The first removal that failed.
        #[source]
        source: io::Error,
    },
    /// The cancel is committed, but neither the node's ssh directory nor
    /// all of the keychain items the state stopped referencing could be
    /// removed.
    #[error(
        "node {node} is cancelled, but {} could not be removed ({removal}); until it is removed, by `node cancel {node}` again or by hand, `node new {node}` refuses; deleting the keychain items the state no longer references failed too, for those named below; nothing uses them, and any that is still there can be deleted by hand",
        dir.display()
    )]
    NodeFilesAndSecretsLeft {
        /// The cancelled node.
        node: NodeId,
        /// Its ssh directory.
        dir: PathBuf,
        /// The first removal that failed.
        removal: io::Error,
        /// The keychain deletions that failed.
        #[source]
        source: Box<StoreError>,
    },
    /// The node's plan was refused by the model.
    #[error("the node's plan was not accepted")]
    NodePlan(#[source] ModelError),
    /// No node has this id.
    #[error("unknown node {node}")]
    UnknownNode {
        /// The id given.
        node: NodeId,
    },
    /// The node is not planned, so the command does not act on it.
    #[error("node {node} is {stage}; only a planned node is {}", action.past())]
    NodeNotPlanned {
        /// The node.
        node: NodeId,
        /// Its stage.
        stage: LifecycleStage,
        /// What the command does to a planned node.
        action: PlannedAction,
    },
    /// A keychain item holds another kind of secret than its reference
    /// names.
    #[error("the keychain item holds a {found:?}, not a {expected:?}")]
    SecretKind {
        /// The kind the reference names.
        expected: SecretKind,
        /// The kind found.
        found: SecretKind,
    },
    /// This program's own path could not be found, for ssh's
    /// ProxyCommand.
    #[error("cannot find this mooringctl's path")]
    CurrentExe(#[source] io::Error),
    /// `Bootstrap` ran, so the VPS holds a new host key and lets in only
    /// Mooring's keys, but that key could not be recorded as the node's
    /// pin (the source says why): `--resume` would check the host against
    /// the old one.
    #[error(
        "Bootstrap ran, so node {node}'s VPS now holds host key {} and lets in only Mooring's keys, but that key was not recorded as the node's pin: if the node is still planned, save `{}` to a file, pin it with `node repin {node} --host-key <file>`, then run `node adopt {node} --resume`; if it was cancelled, reinstall the VPS or delete it from the provider's console",
        key.fingerprint(),
        key.authorized_key()
    )]
    BootstrapKeyUnpinned {
        /// The node.
        node: NodeId,
        /// The host key `Bootstrap` made.
        key: SshPublicKey,
        /// Why the pin was not recorded.
        #[source]
        source: Box<LocalError>,
    },
    /// The node is adopted, but the file of its one-time bootstrap key
    /// could not be removed. `RevokeBootstrap` ran before the commit, so
    /// the VPS no longer accepts that key.
    #[error(
        "node {node} is adopted, but its one-time bootstrap key could not be removed from {}: the VPS no longer accepts that key, so remove the file by hand",
        path.display()
    )]
    BootstrapKeyLeft {
        /// The adopted node.
        node: NodeId,
        /// The key's file.
        path: PathBuf,
        /// Why it stays.
        #[source]
        source: io::Error,
    },
    /// The node is adopted, but neither the file of its one-time bootstrap
    /// key nor the key's keychain item could be removed.
    #[error(
        "node {node} is adopted, but its one-time bootstrap key could not be removed from {} ({removal}): the VPS no longer accepts that key, so remove the file by hand; deleting the keychain items the state no longer references failed too, for those named below; nothing uses them, and any that is still there can be deleted by hand",
        path.display()
    )]
    BootstrapKeyAndSecretsLeft {
        /// The adopted node.
        node: NodeId,
        /// The key's file.
        path: PathBuf,
        /// Why the file stays.
        removal: io::Error,
        /// The keychain deletions that failed.
        #[source]
        source: Box<StoreError>,
    },
    /// `node adopt` without `--resume` needs the operator's root key.
    #[error("give --root-identity, the key that logs in as root on the VPS now, or --resume")]
    RootIdentityMissing,
    /// A value from or for a node was not accepted.
    #[error("a value from or for the node was not accepted")]
    Render(#[source] RenderError),
    /// An adoption step failed.
    #[error("adoption stopped at {}", step.name())]
    AdoptStep {
        /// The step.
        step: Step,
        /// Why.
        #[source]
        source: NodeError,
    },
    /// The operations key ran a command instead of the agent.
    #[error(
        "the operations key ran a command instead of the agent: its forced command is not active, so the node is not adopted"
    )]
    ForcedCommandNotActive,
    /// The agent binary could not be read.
    #[error("cannot read the agent binary {}", path.display())]
    AgentFile {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The agent binary is empty or larger than the limit.
    #[error("{} is empty or larger than 64 MiB; give the release build of mooring-agent", path.display())]
    AgentSize {
        /// The file.
        path: PathBuf,
    },
    /// After a confirmed activation the node's `Hello` names another agent
    /// than the one activated.
    #[error("{node} runs agent {found} after the confirm, not {expected}")]
    AgentNotSwitched {
        /// The node.
        node: NodeId,
        /// The agent activated and confirmed.
        expected: Sha256Hex,
        /// The agent the node's `Hello` names.
        found: Sha256Hex,
    },
    /// The control upgrade is committed, but watch convergence was not verified.
    #[error(
        "{node}: watch executable {found:?} is not the expected {expected}; the control agent activation may already be committed"
    )]
    WatchNotSwitched {
        /// The node.
        node: NodeId,
        /// The desired executable.
        expected: Sha256Hex,
        /// The running watch, if there was one.
        found: Option<Sha256Hex>,
    },
    /// The node does not run what Mooring supports.
    #[error("the node does not run {wanted}: it reports {found}")]
    HostUnsupported {
        /// What adoption asserts.
        wanted: &'static str,
        /// What the node reported.
        found: String,
    },
    /// A node file could not be written or read.
    #[error("cannot use {}", path.display())]
    NodeFile {
        /// The file or directory.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The node is not adopted or applied.
    #[error("node {node} is {stage}; it must be adopted first")]
    NodeNotDeployed {
        /// The node.
        node: NodeId,
        /// Its stage.
        stage: LifecycleStage,
    },
    /// An engine file is missing or unreadable.
    #[error("cannot read the engine {}", path.display())]
    EngineRead {
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// An engine file does not hash to its pin.
    #[error(
        "{} hashes to {actual}, not to engines.lock.toml's digest: give the directory `cargo xtask engines-verify` accepted",
        path.display()
    )]
    EngineDigest {
        /// The file.
        path: PathBuf,
        /// Its digest.
        actual: String,
    },
    /// The engine directory lacks a pinned file.
    #[error("no pinned engine file at {}", path.display())]
    EngineFile {
        /// Where it should be.
        path: PathBuf,
    },
    /// A blob the node lacks is neither a bundle file nor an engine.
    #[error("the node lacks the blob {sha256}, which this Mac cannot supply")]
    EngineMissing {
        /// The blob.
        sha256: Sha256Hex,
    },
    /// A target value was not accepted.
    #[error("the target value was not accepted")]
    Target(#[source] ModelError),
    /// The host name is not one the agent takes.
    #[error("{host} is not a host name the agent takes")]
    TargetHost {
        /// The host.
        host: DnsName,
    },
    /// The target failed a rule; nothing was stored.
    #[error("{host} was not stored: it fails the rules printed above")]
    TargetRefused {
        /// The host.
        host: DnsName,
    },
    /// The transaction failed on the node.
    #[error("the transaction for generation {generation} failed on the node")]
    TxnFailed {
        /// Its generation.
        generation: u64,
        /// The agent's error.
        #[source]
        source: AgentError,
    },
    /// The transaction was reverted by a `Rollback`.
    #[error("the transaction for generation {generation} was rolled back")]
    TxnReverted {
        /// Its generation.
        generation: u64,
    },
    /// The transaction was confirmed by someone else while this command
    /// waited.
    #[error("the transaction for generation {generation} was confirmed elsewhere")]
    TxnAlreadyCommitted {
        /// Its generation.
        generation: u64,
    },
    /// The transaction did not reach confirmation in time.
    #[error(
        "the transaction for generation {generation} did not await confirmation within {secs} s; the node reverts it unless it is confirmed"
    )]
    TxnTimeout {
        /// Its generation.
        generation: u64,
        /// How long the command waited.
        secs: u64,
    },
    /// A node's address is not a public IPv4 address.
    #[error("the node's address was not accepted")]
    NodeAddress(#[source] ModelError),
    /// Between the Mac and a node's agent.
    #[error("the node could not be reached or refused")]
    Node(#[source] NodeError),
}

impl From<NodeError> for CommandError {
    fn from(error: NodeError) -> Self {
        Self::Local(LocalError::Node(error))
    }
}

/// What a refusal means, in words.
pub(crate) const fn refusal_text(reason: Refusal) -> &'static str {
    match reason {
        Refusal::Busy => "it already serves as many clients as it accepts; try again",
        Refusal::BadRequest => "the request was malformed",
        Refusal::NoStatusYet => "its first poll of the M7 has not finished yet",
        Refusal::NotDeployed => "there is no deployment yet (`exit init` creates it)",
        Refusal::NoOtherSimNetwork => "there is no network other than the one on record",
        Refusal::M7NotAttached => "the latest poll of the M7 did not find it attached",
        Refusal::SimNetworkReportChanged => {
            "the M7 no longer reports the network that was to be taken"
        }
        Refusal::LoopBusy => {
            "its loop did not come to the request in time; nothing was changed, try again"
        }
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
