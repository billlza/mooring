// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs a parsed command against an [`Env`] and turns its result into
//! output and an exit code (design §14): 0 on success, 1 for a local
//! failure, 2 for a usage error (clap's), 3 to 8 for a router failure in
//! the order of `RouterUnavailableReason`.
//!
//! Everything the commands touch comes in through `Env`, so tests run them
//! against a loopback stub, a scripted link layer, an in-memory secret
//! store, a scripted console and a fixed clock.

use std::error::Error;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mooring_daemon_core::router::RouterReading;
use mooring_daemon_core::router::netgear::RedactedModelJson;
use mooring_model::iface::BsdName;
use mooring_model::secret::{SecretEntry, SecretRef};
use mooring_model::time::UnixTime;
use mooring_store::{ROUTER_PIN_FILE, RouterPin, SecretStore, read_router_pin, write_router_pin};

use crate::backup::BackupCheck;
use crate::cli::{
    Command, ExitCommand, NodeCommand, RouterCommand, SimCommand, TargetCommand, UserCommand,
};
use crate::error::{CommandError, LocalError, Unconfirmed};
use crate::paths;
use crate::prompt::{self, Answer, Console};
use crate::router::output::{json_line, summary};
use crate::router::{self, PinDecision, RouterEnv, decide_pin};

/// What a command runs against.
pub(crate) struct Env<'a> {
    /// The router adapter's link layer, port and limits.
    pub(crate) router: RouterEnv<'a>,
    /// The secret store (the login keychain in the binary).
    pub(crate) secrets: &'a mut dyn SecretStore,
    /// `HOME`, from which the support directory is derived.
    pub(crate) home: Option<OsString>,
    /// The Mac's clock.
    pub(crate) clock: &'a dyn Fn() -> Result<UnixTime, LocalError>,
    /// The operator's terminal.
    pub(crate) console: &'a mut dyn Console,
    /// Standard input.
    pub(crate) stdin: &'a mut dyn Read,
    /// Whether Time Machine excludes a folder (`tmutil` in the binary).
    pub(crate) backups: &'a dyn BackupCheck,
    /// The id of this process's parent (`getppid` in the binary): when the
    /// parent exits, launchd adopts the process and the id changes.
    pub(crate) parent: &'a dyn Fn() -> u32,
    /// How nodes are reached (`/usr/bin/ssh` in the binary).
    pub(crate) nodes: &'a dyn crate::node::NodeLinks,
    /// The engine files' pins (`node::engines::PINS` in the binary).
    pub(crate) engine_pins: crate::node::engines::Pins<'a>,
    /// The Mac engines' pins (`node::engines::MAC_PINS` in the binary).
    pub(crate) mac_pins: crate::node::engines::Pins<'a>,
    /// The Mac's power source (`/usr/bin/pmset` in the binary, until M7's
    /// power helper reports it).
    pub(crate) power: &'a dyn Fn() -> Result<mooring_daemon_core::status::PowerSource, LocalError>,
    /// Makes the SIM meter's counter reader (the kernel's counters in the
    /// binary), which the meter's thread owns.
    pub(crate) meter_reader: &'a dyn Fn() -> crate::runtime::meter::Reader,
    /// The direct probe: a TCP connection bound to an interface to a
    /// node's reflector (`runtime::probe::direct` in the binary).
    pub(crate) probe: &'a dyn Fn(
        mooring_model::iface::InterfaceIndex,
        std::net::SocketAddrV4,
    )
        -> Result<std::net::Ipv4Addr, crate::runtime::probe::ProbeFailure>,
}

/// The system clock, in whole seconds since the epoch.
pub(crate) fn system_clock() -> Result<UnixTime, LocalError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| UnixTime::from_secs(since.as_secs()))
        .map_err(|_| LocalError::Clock)
}

fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

pub(crate) fn support_dir(env: &Env<'_>) -> Result<PathBuf, CommandError> {
    paths::support_dir(env.home.clone()).map_err(CommandError::Local)
}

/// Runs `command`, writing its output to `out` and any error to `err`;
/// returns the exit code.
pub(crate) fn run(
    command: Command,
    env: &mut Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let json = matches!(
        command,
        Command::Router(RouterCommand::Status { json: true, .. })
    );
    let result = match command {
        Command::Router(command) => execute(command, env, out),
        Command::User(UserCommand::Add { client, mlkem }) => {
            crate::user::add(env, out, client.into(), mlkem)
        }
        Command::User(UserCommand::Alias { user }) => crate::user::alias(env, out, &user),
        Command::User(UserCommand::Agree { user }) => crate::user::agree(env, out, &user),
        Command::User(UserCommand::Export {
            user,
            format,
            out: path,
        }) => crate::user::export(env, out, err, &user, format.into(), &path),
        Command::Exit(ExitCommand::Init {
            interface,
            cycle_anchor,
            flow_cap,
            yes,
        }) => crate::exit::init(env, out, &interface, cycle_anchor, flow_cap, yes),
        Command::Exit(ExitCommand::RecordCarrier {
            prefixes,
            pairing,
            replace,
            yes,
        }) => crate::exit::record_carrier(env, out, prefixes, pairing.into(), replace, yes),
        Command::Exit(ExitCommand::Observe { interface }) => {
            crate::exit::observe(env, out, &interface)
        }
        Command::Exit(ExitCommand::Enable) => crate::exit::set_enabled(env, out, true),
        Command::Exit(ExitCommand::Disable) => crate::exit::set_enabled(env, out, false),
        Command::Exit(ExitCommand::Retry) => crate::exit::retry(env, out),
        Command::Node(NodeCommand::New {
            node,
            role,
            host_key,
            yes,
        }) => crate::node::new::new(env, out, node, role.into(), &host_key, yes),
        Command::Node(NodeCommand::Adopt {
            node,
            address,
            interface,
            root_identity,
            agent,
            resume,
            yes,
        }) => crate::node::adopt::adopt(
            env,
            out,
            &crate::node::adopt::AdoptArgs {
                node: &node,
                address,
                interface: &interface,
                root_identity: root_identity.as_deref(),
                agent: &agent,
                resume,
                yes,
            },
        ),
        Command::Node(NodeCommand::Target(TargetCommand::Check {
            node,
            host,
            interface,
            engines,
        })) => crate::node::target::check(
            env,
            out,
            &crate::node::target::TargetArgs {
                node: &node,
                host: &host,
                interface: &interface,
                engines: &engines,
            },
        ),
        Command::Node(NodeCommand::Target(TargetCommand::Set {
            node,
            host,
            interface,
            engines,
            same_asn,
            not_cdn,
            evidence,
            yes,
        })) => crate::node::target::set(
            env,
            out,
            &crate::node::target::TargetArgs {
                node: &node,
                host: &host,
                interface: &interface,
                engines: &engines,
            },
            &crate::node::target::Attested {
                same_asn,
                not_cdn,
                evidence: &evidence,
            },
            yes,
        ),
        Command::Node(NodeCommand::Apply {
            node,
            interface,
            engines,
        }) => crate::node::apply::apply(env, out, &node, &interface, &engines),
        Command::Sim(SimCommand::SetAnchor { anchor, yes }) => {
            crate::sim::set_anchor(env, out, anchor, yes)
        }
        Command::Status {
            follow,
            json,
            until_parent_exits,
        } => crate::status::status(
            env,
            out,
            if follow {
                crate::status::Reading::Follow { until_parent_exits }
            } else {
                crate::status::Reading::Once
            },
            json,
        ),
        Command::DialBound {
            interface,
            address,
            port,
        } => crate::node::dial::dial_bound(env, &interface, address, port),
        Command::Daemon { router_interface } => {
            crate::daemon::run(env, err, router_interface.as_ref())
        }
    };
    let Err(error) = result else {
        return 0;
    };
    if json && let CommandError::Router(router) = &error {
        let reading = RouterReading::Unavailable {
            reason: router.reason(),
            last_polled_at: None,
        };
        let written = json_line(&reading)
            .map_err(io::Error::other)
            .and_then(|line| out.write_all(line.as_bytes()));
        if let Err(write) = written {
            // The reading could not be written; say so as well.
            report(err, &output(write));
        }
    }
    report(err, &error);
    error.exit_code()
}

/// Writes `error` and its causes to `err`, one per line. If `err` itself
/// cannot be written, the exit code is the only report left.
fn report(err: &mut dyn Write, error: &CommandError) {
    let mut text = format!("mooringctl: {error}\n");
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(&format!("  caused by: {cause}\n"));
        source = cause.source();
    }
    if err.write_all(text.as_bytes()).is_err() {
        // Nowhere left to report to: the exit code still says what failed.
    }
}

fn execute(
    command: RouterCommand,
    env: &mut Env<'_>,
    out: &mut dyn Write,
) -> Result<(), CommandError> {
    match command {
        RouterCommand::Pin {
            interface,
            yes,
            replace,
        } => pin(env, out, &interface, yes, replace),
        RouterCommand::SetPassword { stdin } => set_password(env, out, stdin),
        RouterCommand::Status { interface, json } => status(env, out, &interface, json),
        RouterCommand::Capture {
            interface,
            out: path,
            anonymous,
        } => capture(env, out, &interface, &path, anonymous),
    }
}

fn pin(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
    yes: bool,
    replace: bool,
) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let candidate = router::pin_candidate(&env.router, interface)?;
    writeln!(
        out,
        "interface {}: gateway {}, link-layer address {}",
        interface.as_str(),
        candidate.attachment.gateway,
        candidate.lladdr
    )
    .map_err(output)?;
    let existing =
        read_router_pin(&dir).map_err(|error| CommandError::Local(LocalError::Store(error)))?;
    if decide_pin(existing.as_ref(), candidate.lladdr, replace)? == PinDecision::AlreadyPinned {
        writeln!(out, "already pinned; nothing was written").map_err(output)?;
        return Ok(());
    }
    if !yes {
        match env
            .console
            .confirm("Record this link-layer address as the M7's identity?")?
        {
            Answer::Yes => {}
            Answer::No => return Err(LocalError::NotConfirmed(Unconfirmed::Declined).into()),
            Answer::NoTerminal => {
                return Err(LocalError::NotConfirmed(Unconfirmed::NoTerminal).into());
            }
        }
    }
    paths::create_support_dir(&dir)?;
    let pin = RouterPin {
        gateway_lladdr: candidate.lladdr,
        pinned_at: (env.clock)()?,
    };
    write_router_pin(&dir, &pin).map_err(|error| CommandError::Local(LocalError::Store(error)))?;
    writeln!(
        out,
        "pinned as the M7's identity in {}",
        dir.join(ROUTER_PIN_FILE).display()
    )
    .map_err(output)
}

fn set_password(env: &mut Env<'_>, out: &mut dyn Write, stdin: bool) -> Result<(), CommandError> {
    let password = if stdin {
        prompt::stdin_password(env.stdin)?
    } else {
        prompt::terminal_password(env.console)?
    };
    env.secrets
        .put(SecretEntry::RouterAdmin(password))
        .map_err(|error| CommandError::Local(LocalError::Keychain(error)))?;
    writeln!(
        out,
        "the M7 admin password is stored as {}",
        SecretRef::RouterAdmin
    )
    .map_err(output)
}

fn status(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
    json: bool,
) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let status = router::status(&env.router, &dir, &*env.secrets, interface)?;
    let polled_at = (env.clock)()?;
    let text = if json {
        json_line(&RouterReading::Available {
            polled_at,
            status: Box::new(status),
        })
        .map_err(|error| output(io::Error::other(error)))?
    } else {
        summary(Some(interface), polled_at, &status).map_err(|_| LocalError::Clock)?
    };
    out.write_all(text.as_bytes()).map_err(output)
}

/// Writes the capture to a new file (mode 0600), never over an existing
/// one, and flushes it to stable storage.
fn write_capture(path: &Path, capture: &RedactedModelJson) -> Result<(), LocalError> {
    let write_error = |source: io::Error| LocalError::CaptureWrite {
        path: path.to_path_buf(),
        source,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                LocalError::CaptureExists {
                    path: path.to_path_buf(),
                }
            } else {
                write_error(error)
            }
        })?;
    file.write_all(capture.as_bytes()).map_err(write_error)?;
    file.write_all(b"\n").map_err(write_error)?;
    file.sync_all().map_err(write_error)
}

fn capture(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
    path: &Path,
    anonymous: bool,
) -> Result<(), CommandError> {
    // Refused before the M7 is asked; `create_new` refuses it again if the
    // file appears meanwhile.
    match path.symlink_metadata() {
        Ok(_) => {
            return Err(LocalError::CaptureExists {
                path: path.to_path_buf(),
            }
            .into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(LocalError::CaptureWrite {
                path: path.to_path_buf(),
                source,
            }
            .into());
        }
    }
    let dir = support_dir(env)?;
    let capture = router::capture(&env.router, &dir, &*env.secrets, interface, anonymous)?;
    write_capture(path, &capture)?;
    writeln!(
        out,
        "wrote the redacted capture ({} bytes) to {}",
        capture.as_bytes().len() + 1,
        path.display()
    )
    .map_err(output)?;
    // Values the shape check refused are placeholders in the file; their
    // paths (never their values) say which.
    for withheld in capture.withheld() {
        writeln!(out, "withheld (a placeholder in the capture): {withheld}").map_err(output)?;
    }
    Ok(())
}
