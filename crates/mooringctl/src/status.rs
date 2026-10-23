// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl status [--follow [--until-parent-exits]] [--json]` (design
//! §15.1): the console's status, read from the daemon over its control
//! socket. `--json` prints each status as one line, a `ConsoleStatus`
//! document, which is what Mooring.app reads. `--follow` keeps printing
//! each new one while it is fresh, until the daemon stops; with
//! `--until-parent-exits` it also ends once the process that started it
//! has exited. The CLI never polls the M7 itself here: the daemon does.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use mooring_daemon_core::ControlError;
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{
    CONTROL_PROTOCOL, DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES,
    ProtocolLine, decode_protocol_line, decode_reply, encode_line,
};
use mooring_daemon_core::router::RouterReading;
use mooring_model::time::UnixTime;
use socket2::{Domain, SockAddr, Socket, Type};

use crate::app::{Env, support_dir};
use crate::daemon::RunPaths;
use crate::error::{CommandError, LocalError};
use crate::router::error::reason_phrase;
use crate::router::output::{summary, utc_stamp};

/// How long a one-shot `status` waits for the daemon's answer.
pub(crate) const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// How old the newest status may be while `--follow` reads, and how long
/// it waits for the first: three polls and a margin for a slow one (design
/// §15.6 rule 7 bounds a read of the M7 to 45 s). An older status means
/// the daemon's poll has not finished (it keeps its last status meanwhile),
/// so the follow ends with `StatusStale` rather than pass it off as live.
pub(crate) const FOLLOW_SILENCE: Duration = Duration::from_secs(3 * 60 + 60);

/// How often `--follow` looks at the time and, with `--until-parent-exits`,
/// asks whether the process that started it is still there.
pub(crate) const PARENT_CHECK: Duration = Duration::from_secs(2);

/// The process id of launchd, which adopts a process whose parent has
/// exited.
const LAUNCHD_PID: u32 = 1;

/// How `status` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reading {
    /// The latest status, once.
    Once,
    /// Each status while it is fresh, until the daemon stops; with
    /// `until_parent_exits`, also until the process that started this one
    /// exits (Mooring.app asks for that, so its follower never outlives it).
    Follow { until_parent_exits: bool },
}

/// `status`: one status, or each fresh status until the daemon closes the
/// stream (`DaemonClosed`), its newest status grows older than
/// [`FOLLOW_SILENCE`] (`StatusStale`, and such a status is not printed),
/// or, if asked, the process that started this one exits (then it ends
/// with success, printing nothing more: nothing reads it any more).
pub(crate) fn status(
    env: &Env<'_>,
    out: &mut dyn Write,
    reading: Reading,
    json: bool,
) -> Result<(), CommandError> {
    let socket = RunPaths::under(&support_dir(env)?).socket;
    // The parent is asked about only when the caller wants the follow to
    // end with it.
    let started_by = match reading {
        Reading::Follow {
            until_parent_exits: true,
        } => Some((env.parent)()),
        Reading::Follow {
            until_parent_exits: false,
        }
        | Reading::Once => None,
    };
    if started_by == Some(LAUNCHD_PID) {
        // The process that started this one has exited already.
        return Ok(());
    }
    let parent_there = || started_by.is_none_or(|id| (env.parent)() == id);
    let (request, first_wait, tick) = match reading {
        Reading::Once => (DaemonRequest::Status, ANSWER_TIMEOUT, ANSWER_TIMEOUT),
        Reading::Follow { .. } => (DaemonRequest::Subscribe, FOLLOW_SILENCE, PARENT_CHECK),
    };
    let mut reader = connect(&socket, request, tick)?;
    let mut deadline = Instant::now() + first_wait;
    let mut newest: Option<UnixTime> = None;
    loop {
        let line = match read_reply_line(&mut reader, &socket, deadline, &parent_there)? {
            Next::Line(line) => line,
            Next::ParentGone => return Ok(()),
            Next::Deadline => {
                return Err(CommandError::Local(match newest {
                    None => LocalError::DaemonSilent {
                        secs: first_wait.as_secs(),
                    },
                    Some(at) => stale(at)?,
                }));
            }
        };
        let status = match decode_reply(&line).map_err(LocalError::DaemonReply)? {
            DaemonReply::Refused { reason } => {
                return Err(CommandError::Local(LocalError::DaemonRefused { reason }));
            }
            DaemonReply::Status(status) => status,
            DaemonReply::RetryQueued => {
                return Err(CommandError::Local(LocalError::DaemonUnexpectedReply));
            }
        };
        if reading == Reading::Once {
            return print(out, &status, json);
        }
        let Some(fresh_for) = FOLLOW_SILENCE.checked_sub(age(env, status.at())?) else {
            return Err(CommandError::Local(stale(status.at())?));
        };
        if !parent_there() {
            return Ok(());
        }
        print(out, &status, json)?;
        newest = Some(status.at());
        deadline = Instant::now() + fresh_for;
    }
}

/// How long ago, by the Mac's clock, the daemon made a status at `at`; a
/// status from the future is new.
fn age(env: &Env<'_>, at: UnixTime) -> Result<Duration, LocalError> {
    let now = (env.clock)()?;
    Ok(Duration::from_secs(
        now.as_secs().saturating_sub(at.as_secs()),
    ))
}

/// `StatusStale` for the newest status, made at `at`.
fn stale(at: UnixTime) -> Result<LocalError, LocalError> {
    Ok(LocalError::StatusStale {
        at: utc_stamp(at).map_err(|_| LocalError::Clock)?,
        max_secs: FOLLOW_SILENCE.as_secs(),
    })
}

/// What the stream gave next.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// A reply line, its newline included.
    Line(Vec<u8>),
    /// The process that started this one is gone.
    ParentGone,
    /// The deadline passed with no line.
    Deadline,
}

/// Connects to the daemon, sends `request` and reads the daemon's protocol
/// line (see [`check_protocol`]); each read then waits at most `tick`. No
/// socket, or no one listening on it, is `DaemonNotRunning`. The time
/// limits are set before connecting: a busy daemon writes its refusal and
/// closes at once, and setsockopt(2) fails on macOS once the peer has shut
/// the socket down.
pub(crate) fn connect(
    socket: &Path,
    request: DaemonRequest,
    tick: Duration,
) -> Result<BufReader<UnixStream>, LocalError> {
    let io_error = |source| LocalError::DaemonIo {
        path: socket.to_path_buf(),
        source,
    };
    let address = SockAddr::unix(socket).map_err(io_error)?;
    let client = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(io_error)?;
    client
        .set_read_timeout(Some(tick))
        .and_then(|()| client.set_write_timeout(Some(ANSWER_TIMEOUT)))
        .map_err(io_error)?;
    client
        .connect(&address)
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound | ErrorKind::ConnectionRefused => LocalError::DaemonNotRunning {
                path: socket.to_path_buf(),
            },
            _ => io_error(error),
        })?;
    let mut reader = BufReader::new(send_request(UnixStream::from(client), request, socket)?);
    check_protocol(&mut reader, socket)?;
    Ok(reader)
}

/// Reads the daemon's first line, within [`ANSWER_TIMEOUT`]: it must name
/// this build's control protocol (design §15.1). A first line that names
/// none is `DaemonProtocolMissing`, and one that names another protocol
/// `DaemonProtocolOther`; either way no reply is read.
pub(crate) fn check_protocol(
    reader: &mut BufReader<UnixStream>,
    socket: &Path,
) -> Result<(), LocalError> {
    let line = match read_reply_line(reader, socket, Instant::now() + ANSWER_TIMEOUT, &|| true)? {
        Next::Line(line) => line,
        Next::Deadline | Next::ParentGone => {
            return Err(LocalError::DaemonSilent {
                secs: ANSWER_TIMEOUT.as_secs(),
            });
        }
    };
    match decode_protocol_line(&line) {
        Ok(ProtocolLine { control_protocol }) if control_protocol == CONTROL_PROTOCOL => Ok(()),
        Ok(ProtocolLine { control_protocol }) => Err(LocalError::DaemonProtocolOther {
            daemon: control_protocol,
            client: CONTROL_PROTOCOL,
        }),
        Err(_) => Err(LocalError::DaemonProtocolMissing),
    }
}

/// Sends `request` on `stream`. A busy daemon writes its refusal and
/// closes without reading the request, so a broken pipe here is not the
/// answer: the refusal is still there to read, and the read that follows
/// reports it (or the end of the stream).
pub(crate) fn send_request(
    mut stream: UnixStream,
    request: DaemonRequest,
    socket: &Path,
) -> Result<UnixStream, LocalError> {
    let line = encode_line(&request, MAX_REQUEST_LINE_BYTES).map_err(LocalError::ClientEncode)?;
    match stream.write_all(&line) {
        Ok(()) => Ok(stream),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
            ) =>
        {
            Ok(stream)
        }
        Err(source) => Err(LocalError::DaemonIo {
            path: socket.to_path_buf(),
            source,
        }),
    }
}

/// The next reply line within [`MAX_REPLY_LINE_BYTES`]. The end of the
/// stream, before or within a line, is `DaemonClosed`, and a longer line is
/// refused before it is read whole. A line may arrive in parts: each time
/// a socket read waits out its timeout (the tick `connect` set) the parent
/// is asked after, and past `deadline` the answer is `Next::Deadline`.
pub(crate) fn read_reply_line(
    reader: &mut BufReader<UnixStream>,
    socket: &Path,
    deadline: Instant,
    parent_there: &dyn Fn() -> bool,
) -> Result<Next, LocalError> {
    let mut line = Vec::new();
    loop {
        // One byte past the bound is read, so a longer line is detected
        // without reading it all; a part read before a tick counts
        // (usize to u64 is lossless on every target).
        let room = (MAX_REPLY_LINE_BYTES + 1 - line.len()) as u64;
        match reader.by_ref().take(room).read_until(b'\n', &mut line) {
            Ok(_) if line.len() > MAX_REPLY_LINE_BYTES => {
                return Err(LocalError::DaemonReply(ControlError::LineTooLong {
                    bytes: line.len(),
                    max: MAX_REPLY_LINE_BYTES,
                }));
            }
            Ok(_) if line.last() == Some(&b'\n') => return Ok(Next::Line(line)),
            Ok(_) => return Err(LocalError::DaemonClosed),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if !parent_there() {
                    return Ok(Next::ParentGone);
                }
                if Instant::now() >= deadline {
                    return Ok(Next::Deadline);
                }
            }
            Err(source) => {
                return Err(LocalError::DaemonIo {
                    path: socket.to_path_buf(),
                    source,
                });
            }
        }
    }
}

/// Prints one status: its document as one JSON line, or a summary. Each
/// is flushed at once, so a reader of `--follow` sees it when it comes.
fn print(out: &mut dyn Write, status: &ConsoleStatus, json: bool) -> Result<(), CommandError> {
    let text = if json {
        encode_line(status, MAX_REPLY_LINE_BYTES).map_err(LocalError::ClientEncode)?
    } else {
        summary_of(status)?.into_bytes()
    };
    out.write_all(&text)
        .and_then(|()| out.flush())
        .map_err(|error| CommandError::Local(LocalError::Output(error)))
}

/// The human summary: when the status was made, that there is no
/// deployment yet, and the router panel.
fn summary_of(status: &ConsoleStatus) -> Result<String, LocalError> {
    let ConsoleStatus::NoDeployment(undeployed) = status else {
        return Err(LocalError::DeployedSummary);
    };
    let stamp = |time| utc_stamp(time).map_err(|_| LocalError::Clock);
    let mut text = format!(
        "status at {}: no deployment on this Mac yet (`exit init` creates it)\n",
        stamp(undeployed.at())?
    );
    match undeployed.router() {
        RouterReading::Available { polled_at, status } => {
            text.push_str(&summary(None, *polled_at, status).map_err(|_| LocalError::Clock)?);
        }
        RouterReading::Unavailable {
            reason,
            last_polled_at,
        } => {
            let last = match last_polled_at {
                Some(time) => format!("last read {}", stamp(*time)?),
                None => "never read yet".to_owned(),
            };
            text.push_str(&format!(
                "M7 unavailable: {}; {last}\n",
                reason_phrase(*reason)
            ));
        }
    }
    Ok(text)
}
