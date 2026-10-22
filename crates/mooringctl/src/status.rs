// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl status [--follow] [--json]` (design §15.1): the console's
//! status, read from the daemon over its control socket. `--json` prints
//! each status as one line, a `ConsoleStatus` document, which is what
//! Mooring.app reads; `--follow` keeps printing each new one until the
//! daemon stops, or until the process that started it is gone. The CLI
//! never polls the M7 itself here: the daemon does.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use mooring_daemon_core::ControlError;
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{
    DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES, decode_reply,
    encode_line,
};
use mooring_daemon_core::router::RouterReading;

use crate::app::{Env, support_dir};
use crate::daemon::RunPaths;
use crate::error::{CommandError, LocalError};
use crate::router::error::reason_phrase;
use crate::router::output::{summary, utc_stamp};

/// How long a one-shot `status` waits for the daemon's answer.
pub(crate) const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `--follow` waits for the next status before it calls the
/// daemon silent: three polls and a margin for a slow one (design §15.6
/// rule 7 bounds a read of the M7 to 45 s).
pub(crate) const FOLLOW_SILENCE: Duration = Duration::from_secs(3 * 60 + 60);

/// How often `--follow` asks whether the process that started it is still
/// there. Once it is gone (Mooring.app quit, crashed or was killed),
/// nothing reads what it prints, and it ends rather than wait for its next
/// write to fail.
pub(crate) const PARENT_CHECK: Duration = Duration::from_secs(2);

/// `status`: one status, or with `follow` each status until the daemon
/// closes the stream (`DaemonClosed`) or the process that started this one
/// is gone (then it ends with success: nothing reads it any more).
pub(crate) fn status(
    env: &Env<'_>,
    out: &mut dyn Write,
    follow: bool,
    json: bool,
) -> Result<(), CommandError> {
    let socket = RunPaths::under(&support_dir(env)?).socket;
    let started_by = (env.parent)();
    let (request, wait) = if follow {
        (
            DaemonRequest::Subscribe,
            Wait {
                silence: FOLLOW_SILENCE,
                tick: PARENT_CHECK,
            },
        )
    } else {
        (
            DaemonRequest::Status,
            Wait {
                silence: ANSWER_TIMEOUT,
                tick: ANSWER_TIMEOUT,
            },
        )
    };
    let parent_there = || (env.parent)() == started_by;
    let mut reader = BufReader::new(connect(&socket, request, wait.tick)?);
    loop {
        let line = match read_reply_line(&mut reader, &socket, wait, &parent_there)? {
            Next::Line(line) => line,
            Next::ParentGone => return Ok(()),
        };
        match decode_reply(&line).map_err(LocalError::DaemonReply)? {
            DaemonReply::Refused { reason } => {
                return Err(CommandError::Local(LocalError::DaemonRefused { reason }));
            }
            DaemonReply::Status(status) => print(out, &status, json)?,
        }
        if !follow {
            return Ok(());
        }
    }
}

/// How long a read waits: the stream may be silent for `silence`, and
/// every `tick` of it the parent is asked after.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Wait {
    pub(crate) silence: Duration,
    pub(crate) tick: Duration,
}

/// What the stream gave next.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// A reply line, its newline included.
    Line(Vec<u8>),
    /// The process that started this one is gone.
    ParentGone,
}

/// Connects to the daemon and sends `request`; each read then waits at
/// most `tick`. No socket, or no one listening on it, is
/// `DaemonNotRunning`.
fn connect(
    socket: &Path,
    request: DaemonRequest,
    tick: Duration,
) -> Result<UnixStream, LocalError> {
    let io_error = |source| LocalError::DaemonIo {
        path: socket.to_path_buf(),
        source,
    };
    let mut stream = UnixStream::connect(socket).map_err(|error| match error.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => LocalError::DaemonNotRunning {
            path: socket.to_path_buf(),
        },
        _ => io_error(error),
    })?;
    stream
        .set_read_timeout(Some(tick))
        .and_then(|()| stream.set_write_timeout(Some(ANSWER_TIMEOUT)))
        .map_err(io_error)?;
    let line = encode_line(&request, MAX_REQUEST_LINE_BYTES).map_err(LocalError::DaemonReply)?;
    stream.write_all(&line).map_err(io_error)?;
    Ok(stream)
}

/// The next reply line within [`MAX_REPLY_LINE_BYTES`]. The end of the
/// stream, before or within a line, is `DaemonClosed`, and a longer line is
/// refused before it is read whole. A line may arrive in parts: after each
/// `tick` without a byte the parent is asked after, and silence beyond
/// `silence` is `DaemonSilent`.
pub(crate) fn read_reply_line(
    reader: &mut BufReader<UnixStream>,
    socket: &Path,
    wait: Wait,
    parent_there: &dyn Fn() -> bool,
) -> Result<Next, LocalError> {
    let started = Instant::now();
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
                if started.elapsed() >= wait.silence {
                    return Err(LocalError::DaemonSilent {
                        secs: wait.silence.as_secs(),
                    });
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
        encode_line(status, MAX_REPLY_LINE_BYTES).map_err(LocalError::DaemonReply)?
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
