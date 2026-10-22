// SPDX-License-Identifier: GPL-3.0-or-later

//! The node's event journal (design §15.7), `/var/lib/mooring/watch/
//! journal.jsonl`: one [`AgentEvent`] per line, numbered one apart from
//! [`EventSeq::FIRST`]. Only the watch writes it, appending the changes it
//! observes; the agent reads it for `Events{since}`.
//!
//! The writer creates the file, and syncs it and its directory, before its
//! first append. An append is a write and an `fsync` of whole lines, so a
//! crash can leave at most a last line without its newline, which was never
//! durable: a reader ignores it and the writer cuts it off before its next
//! append. The journal is pruned from its oldest end only, never below its
//! newest event (so the next number is never reused), of the events older
//! than [`RETENTION_SECS`] and beyond [`MAX_KEPT`].

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AgentError, AgentEvent, AgentEventKind, EventSeq, EventsV1, IoOp, MAX_EVENTS, UnixTime,
};

use crate::paths::Paths;
use crate::store::{ensure_dir, io_error, malformed, write_atomic};

/// How long an event is kept: 393 days, the shortest thirteen calendar
/// months, so that no event outlives the thirteen months the user
/// agreement states (design §15.7, F7).
pub(crate) const RETENTION_SECS: u64 = 393 * 86_400;

/// The most events kept, whatever their age: a condition that flaps cannot
/// grow the journal without bound. Pruning keeps three quarters of it.
pub(crate) const MAX_KEPT: usize = 4 * MAX_EVENTS;

/// The journal is read by the `mooring` group as well.
const MODE: u32 = 0o640;

/// The watch's handle on the journal: where the next event goes.
#[derive(Debug)]
pub(crate) struct Journal {
    path: PathBuf,
    /// The number the next event gets.
    next: EventSeq,
    /// How many events the file holds.
    len: usize,
    /// The oldest event's time.
    oldest: Option<UnixTime>,
}

impl Journal {
    /// Opens the journal for appending, creating it if there is none and
    /// cutting off a torn last line.
    pub(crate) fn open(paths: &Paths) -> Result<Self, AgentError> {
        let path = paths.journal();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create(&path).map_err(|error| io_error(IoOp::WriteState, &error))?;
                Vec::new()
            }
            Err(error) => return Err(io_error(IoOp::ReadState, &error)),
        };
        let complete = complete_len(&bytes);
        if complete < bytes.len() {
            let file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|error| io_error(IoOp::WriteState, &error))?;
            file.set_len(complete as u64)
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error(IoOp::WriteState, &error))?;
        }
        let events = parse(&bytes[..complete])?;
        Ok(Self {
            path,
            next: events
                .last()
                .map_or(EventSeq::FIRST, |last| EventSeq::new(last.seq.get() + 1)),
            len: events.len(),
            oldest: events.first().map(|first| first.at),
        })
    }

    /// Appends `kinds`, in order, recorded at `at`, then prunes if the
    /// journal has grown past [`MAX_KEPT`] or holds an event older than
    /// [`RETENTION_SECS`].
    pub(crate) fn append(
        &mut self,
        at: UnixTime,
        kinds: &[AgentEventKind],
    ) -> Result<(), AgentError> {
        if kinds.is_empty() {
            return Ok(());
        }
        let mut lines = Vec::new();
        let mut seq = self.next;
        for &kind in kinds {
            let event = AgentEvent { seq, at, kind };
            serde_json::to_writer(&mut lines, &event).map_err(|_| malformed(IoOp::WriteState))?;
            lines.push(b'\n');
            seq = EventSeq::new(seq.get() + 1);
        }
        let write = |path: &Path| -> io::Result<()> {
            let mut file = OpenOptions::new().append(true).open(path)?;
            file.write_all(&lines)?;
            file.sync_data()
        };
        write(&self.path).map_err(|error| io_error(IoOp::WriteState, &error))?;
        self.next = seq;
        self.len += kinds.len();
        self.oldest.get_or_insert(at);
        if beyond_bound(self.len) || self.oldest.is_some_and(|oldest| expired(at, oldest)) {
            self.prune(at)?;
        }
        Ok(())
    }

    /// Rewrites the journal without the events older than
    /// [`RETENTION_SECS`] at `now`, and without the oldest beyond three
    /// quarters of [`MAX_KEPT`] when it holds more than that. The newest
    /// event is the one just appended at `now`, so it is always kept.
    fn prune(&mut self, now: UnixTime) -> Result<(), AgentError> {
        let events = read(&self.path)?;
        let mut first = events
            .iter()
            .position(|event| !expired(now, event.at))
            .unwrap_or(events.len());
        if beyond_bound(events.len() - first) {
            first = events.len() - MAX_KEPT / 4 * 3;
        }
        let kept = &events[first..];
        let mut bytes = Vec::new();
        for event in kept {
            serde_json::to_writer(&mut bytes, event).map_err(|_| malformed(IoOp::WriteState))?;
            bytes.push(b'\n');
        }
        write_atomic(&self.path, &bytes, MODE)
            .map_err(|error| io_error(IoOp::WriteState, &error))?;
        self.len = kept.len();
        self.oldest = kept.first().map(|event| event.at);
        Ok(())
    }
}

/// Whether an event recorded `at` is older than [`RETENTION_SECS`] at
/// `now`.
fn expired(now: UnixTime, at: UnixTime) -> bool {
    now.secs_since(at).is_some_and(|age| age > RETENTION_SECS)
}

/// Whether `len` events are more than [`MAX_KEPT`].
const fn beyond_bound(len: usize) -> bool {
    len > MAX_KEPT
}

/// Creates the journal empty, durably: the file, then its directory entry.
fn create(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    ensure_dir(dir)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE)
        .open(path)?
        .sync_all()?;
    File::open(dir)?.sync_all()
}

/// `Events{since}`: the journal's events numbered `since` or later, at most
/// [`MAX_EVENTS`], and the number the next event will get.
pub(crate) fn page(paths: &Paths, since: EventSeq) -> Result<EventsV1, AgentError> {
    let events = read(&paths.journal())?;
    let end = events
        .last()
        .map_or(EventSeq::FIRST, |last| EventSeq::new(last.seq.get() + 1));
    let page: Vec<AgentEvent> = events
        .into_iter()
        .filter(|event| event.seq >= since)
        .take(MAX_EVENTS)
        .collect();
    EventsV1::new(page, end).map_err(|_| malformed(IoOp::ReadState))
}

/// The journal's complete lines; none if it does not exist yet.
fn read(path: &Path) -> Result<Vec<AgentEvent>, AgentError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(IoOp::ReadState, &error)),
    };
    parse(&bytes[..complete_len(&bytes)])
}

/// The length of `bytes` up to and including its last newline.
fn complete_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |last| last + 1)
}

/// Parses whole lines, which must be numbered one apart.
fn parse(bytes: &[u8]) -> Result<Vec<AgentEvent>, AgentError> {
    let events: Vec<AgentEvent> = bytes
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| malformed(IoOp::ReadState)))
        .collect::<Result<_, _>>()?;
    let consecutive = events
        .windows(2)
        .all(|pair| pair[0].seq.get().checked_add(1) == Some(pair[1].seq.get()));
    if consecutive {
        Ok(events)
    } else {
        Err(malformed(IoOp::ReadState))
    }
}
