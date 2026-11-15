// SPDX-License-Identifier: GPL-3.0-or-later

//! The event journals (design §15.7, console spec B.2.9): the Mac's own,
//! which the daemon appends as one JSON line per [`MacEvent`] to the file
//! of the event's UTC day (`events/mac/<YYYY-MM-DD>.jsonl`, kept by
//! `mooring-store`); each node's as the Mac reads it with
//! `Events{since}`, one [`NodeLine`] per event, gap or reset, in the file
//! of the read's UTC day (`events/nodes/<node>/<YYYY-MM-DD>.jsonl`); and
//! the document `mooringctl events --json` prints from both
//! ([`EventsDocument`]).
//!
//! The Mac's events are what its status shows changing ([`MacSeen`]):
//! the exit's phase, the power source, a sleep with its drain, a wake, and
//! a node's agent lost and answering again; and the daemon's start. Like
//! a node's events they are Level 0 (design §15.5): no user, address,
//! label or destination; the exit's phase keeps the kinds of its reasons
//! only.
//!
//! A node's copy keeps no cursor of its own: the number the Mac asks from
//! next follows from the copy's newest line ([`Cursor::after`]), so a
//! crash between a read and its append reads the events again rather than
//! skip them, and an append cut short is cut back by the next. A page is
//! checked against the number asked from ([`accept`]): events the node
//! pruned before the Mac read them are a gap, a journal that ends before
//! the number asked from was reset, and a page that starts before it, or
//! leaves out the events after it, is refused.
//!
//! Each line carries its version, so a day file may span two builds; the
//! document carries [`EVENTS_DOCUMENT_VERSION`]. The journals keep the
//! day files of the last [`JOURNAL_DAYS`] UTC days ([`oldest_kept`]),
//! within F7's 13 months for entries that name no user. Nothing here reads
//! a file or a clock.

use std::collections::BTreeMap;

use mooring_agent_proto::{AgentEvent, EventSeq, EventsV1};
use mooring_model::collections::NonEmptySet;
use mooring_model::{CalendarDate, NodeId, UnixTime};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::alert::DegradedReasonKind;
use crate::error::EventsError;
use crate::status::{
    AgentUnreachable, DownReasonKind, DrainOutcome, DrainRecord, ExitState, MacStatusV2,
    NodeAgentState, PowerSource, degraded_kinds,
};
use crate::wire::mac_time;

/// The version every line of the Mac's journal carries.
pub const MAC_EVENT_VERSION: u32 = 1;

/// The version every line of a node's copy carries.
pub const NODE_LINE_VERSION: u32 = 1;

/// The version an [`EventsDocument`] carries.
pub const EVENTS_DOCUMENT_VERSION: u32 = 1;

/// The longest line of either journal, its newline included: the longest
/// line the closed types can give is under 500 bytes.
pub const MAX_EVENT_LINE_BYTES: usize = 1024;

/// How many UTC days of day files the journals keep, today's included:
/// 393 days is the shortest thirteen calendar months, the node's own
/// journal's age bound, so no entry is kept past F7's 13 months.
pub const JOURNAL_DAYS: u32 = 393;

/// The most entries a document holds; the oldest of a range that has more
/// are left out and counted.
pub const MAX_DOCUMENT_ENTRIES: usize = 5_000;

/// The oldest day whose day files the journals keep on `today`: the day
/// files of the [`JOURNAL_DAYS`] days up to and including `today` are
/// kept, the older ones removed.
#[must_use]
pub const fn oldest_kept(today: CalendarDate) -> CalendarDate {
    today.saturating_sub_days(JOURNAL_DAYS - 1)
}

/// The exit's phase as the journal keeps it: its state without the egress
/// address, the times and the details of its reasons.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitPhase {
    /// The operator disabled the exit.
    Disabled,
    /// Preflight is running.
    Preflight,
    /// The engine is starting.
    Starting,
    /// The engine runs and the first verdicts are pending.
    Verifying,
    /// Serving through a verified carrier address.
    Serving,
    /// Serving, with problems.
    Degraded {
        /// The kinds of the problems.
        reasons: NonEmptySet<DegradedReasonKind>,
    },
    /// Not serving.
    Down {
        /// The kind of the reason.
        reason: DownReasonKind,
    },
    /// The Mac is asleep; the exit drained before it slept.
    Paused,
}

impl ExitPhase {
    /// The phase of `state`.
    #[must_use]
    pub fn of(state: &ExitState) -> Self {
        match state {
            ExitState::Disabled => Self::Disabled,
            ExitState::Preflight => Self::Preflight,
            ExitState::Starting => Self::Starting,
            ExitState::Verifying => Self::Verifying,
            ExitState::Serving { .. } => Self::Serving,
            ExitState::Degraded { reasons } => Self::Degraded {
                reasons: degraded_kinds(reasons),
            },
            ExitState::Down { reason } => Self::Down {
                reason: reason.kind(),
            },
            ExitState::Paused => Self::Paused,
        }
    }
}

/// An event of the Mac's journal: when it happened, by the Mac's clock,
/// and what happened.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacEvent {
    /// When it happened.
    pub at: UnixTime,
    /// What happened.
    pub kind: MacEventKind,
}

/// What happened on the Mac.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MacEventKind {
    /// The daemon started with a deployment.
    DaemonStarted,
    /// The power source changed, or the daemon learnt it at its start.
    PowerSource {
        /// The source.
        source: PowerSource,
    },
    /// The Mac went to sleep, after the exit drained (design §10.3).
    Slept {
        /// How the drain ended.
        drain: DrainOutcome,
    },
    /// The Mac woke.
    Woke,
    /// The exit's phase changed, or the daemon's first status showed it.
    Exit {
        /// The phase.
        phase: ExitPhase,
    },
    /// A node's agent could not be polled, at the first failed poll of the
    /// run of failures.
    NodeUnreachable {
        /// The node.
        node: NodeId,
        /// The first failure the Mac's status showed.
        cause: AgentUnreachable,
    },
    /// A node's agent answered a poll after polls had failed.
    NodeReachable {
        /// The node.
        node: NodeId,
    },
}

/// What the Mac last saw of the facts its events follow, so that each of
/// its statuses gives only what changed. One lives as long as the daemon:
/// a new daemon starts from nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacSeen {
    power: Option<PowerSource>,
    drain: Option<DrainRecord>,
    wake: Option<UnixTime>,
    exit: Option<ExitPhase>,
    agents: BTreeMap<NodeId, Reach>,
}

/// A node's agent as the Mac last saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The latest poll was answered.
    Answered,
    /// Polls have failed since `since`.
    Unreachable { since: UnixTime },
}

impl MacSeen {
    /// The events `status` shows since the status last given, in this
    /// order: the power source, a sleep (dated by its drain), a wake, the
    /// exit's phase, then each node in id order. The first status gives
    /// its power source and its exit's phase, and a sleep or a wake it
    /// shows; a node's first answer is no event, and a node that is not
    /// polled is forgotten. A run of failed polls is one event, dated at
    /// its first failure; a run that starts at another time than the one
    /// last seen is another run, so a recovery between two statuses is
    /// not lost.
    pub fn changes(&mut self, status: &MacStatusV2) -> Vec<MacEvent> {
        let parts = status.parts();
        let at = parts.at;
        let power = parts.exit.power;
        let mut events = Vec::new();
        if self.power != Some(power.source) {
            self.power = Some(power.source);
            events.push(MacEvent {
                at,
                kind: MacEventKind::PowerSource {
                    source: power.source,
                },
            });
        }
        if let Some(drain) = power.last_drain
            && self.drain != Some(drain)
        {
            self.drain = Some(drain);
            events.push(MacEvent {
                at: drain.at,
                kind: MacEventKind::Slept {
                    drain: drain.outcome,
                },
            });
        }
        if let Some(wake) = power.last_wake
            && self.wake != Some(wake)
        {
            self.wake = Some(wake);
            events.push(MacEvent {
                at: wake,
                kind: MacEventKind::Woke,
            });
        }
        let phase = ExitPhase::of(&parts.exit.state);
        if self.exit.as_ref() != Some(&phase) {
            events.push(MacEvent {
                at,
                kind: MacEventKind::Exit {
                    phase: phase.clone(),
                },
            });
            self.exit = Some(phase);
        }
        for (node, row) in &parts.nodes {
            match &row.agent {
                NodeAgentState::NotPolled => {
                    self.agents.remove(node);
                }
                NodeAgentState::Reported(report) => {
                    let before = self.agents.insert(node.clone(), Reach::Answered);
                    if matches!(before, Some(Reach::Unreachable { .. })) {
                        events.push(MacEvent {
                            at: report.polled_at,
                            kind: MacEventKind::NodeReachable { node: node.clone() },
                        });
                    }
                }
                NodeAgentState::Unreachable { since, cause } => {
                    let reach = Reach::Unreachable { since: *since };
                    if self.agents.insert(node.clone(), reach) != Some(reach) {
                        events.push(MacEvent {
                            at: *since,
                            kind: MacEventKind::NodeUnreachable {
                                node: node.clone(),
                                cause: *cause,
                            },
                        });
                    }
                }
            }
        }
        self.agents.retain(|node, _| parts.nodes.contains_key(node));
        events
    }
}

/// A line of the Mac's journal as the file holds it: the event behind its
/// version.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacLineRepr {
    version: u32,
    at: UnixTime,
    kind: MacEventKind,
}

/// The line of `event`: one compact JSON document, its version first, and
/// a newline. `LineTooLong` past [`MAX_EVENT_LINE_BYTES`] (unreachable for
/// these closed types; kept as the invariant the reader relies on).
pub fn encode_mac_line(event: &MacEvent) -> Result<Vec<u8>, EventsError> {
    line(&MacLineRepr {
        version: MAC_EVENT_VERSION,
        at: event.at,
        kind: event.kind.clone(),
    })
}

/// The event of one whole line of the Mac's journal, its newline
/// included: `LineTooLong` past the bound, `UnsupportedVersion` for
/// another version, and `Undecodable` for anything else. No error holds a
/// byte of the line.
pub fn decode_mac_line(line: &[u8]) -> Result<MacEvent, EventsError> {
    let repr: MacLineRepr = versioned(line, MAC_EVENT_VERSION)?;
    Ok(MacEvent {
        at: repr.at,
        kind: repr.kind,
    })
}

/// A line of a node's copy of its journal: when the Mac read it, by the
/// Mac's clock, and what it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLine {
    /// When the Mac read it.
    pub read_at: UnixTime,
    /// What it read.
    pub entry: NodeEntry,
}

/// What a line of a node's copy holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeEntry {
    /// An event of the node's journal, with the node's number and clock.
    Event(AgentEvent),
    /// The events numbered `from` up to (not including) `to` were pruned
    /// from the node's journal before the Mac read them.
    Gap {
        /// The first number missing.
        from: EventSeq,
        /// The number after the last one missing.
        to: EventSeq,
    },
    /// The node's journal ended before the number the Mac asked from, so
    /// it was started anew (a host reinstalled, or a state put back); the
    /// Mac reads it again from its first number.
    Reset {
        /// The number the node's next event would get.
        end: EventSeq,
    },
}

impl NodeLine {
    /// When the line's entry happened: an event's own time (the node's
    /// clock), or the read's (the Mac's) for a gap or a reset.
    #[must_use]
    pub const fn at(&self) -> UnixTime {
        match self.entry {
            NodeEntry::Event(event) => mac_time(event.at),
            NodeEntry::Gap { .. } | NodeEntry::Reset { .. } => self.read_at,
        }
    }
}

/// A line of a node's copy as the file holds it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeLineRepr {
    version: u32,
    read_at: UnixTime,
    entry: NodeEntry,
}

/// The line of `line`, as [`encode_mac_line`] writes one.
pub fn encode_node_line(line: &NodeLine) -> Result<Vec<u8>, EventsError> {
    self::line(&NodeLineRepr {
        version: NODE_LINE_VERSION,
        read_at: line.read_at,
        entry: line.entry,
    })
}

/// The line of a node's copy of one whole line, as [`decode_mac_line`]
/// reads one; a gap that misses no number is `Undecodable` too.
pub fn decode_node_line(line: &[u8]) -> Result<NodeLine, EventsError> {
    let repr: NodeLineRepr = versioned(line, NODE_LINE_VERSION)?;
    if let NodeEntry::Gap { from, to } = repr.entry
        && from >= to
    {
        return Err(EventsError::Undecodable);
    }
    Ok(NodeLine {
        read_at: repr.read_at,
        entry: repr.entry,
    })
}

/// One compact JSON document and a newline, within the bound.
fn line(repr: &impl Serialize) -> Result<Vec<u8>, EventsError> {
    let mut line = serde_json::to_vec(repr).map_err(|_| EventsError::Unencodable)?;
    line.push(b'\n');
    if line.len() > MAX_EVENT_LINE_BYTES {
        return Err(EventsError::LineTooLong { bytes: line.len() });
    }
    Ok(line)
}

/// The version alone, read first and leniently, so a line of another
/// version is refused as such whatever keys it adds.
#[derive(Deserialize)]
struct LineVersion {
    version: u32,
}

/// One whole line of `version`, as the decoders read it.
fn versioned<T: DeserializeOwned>(line: &[u8], version: u32) -> Result<T, EventsError> {
    if line.len() > MAX_EVENT_LINE_BYTES {
        return Err(EventsError::LineTooLong { bytes: line.len() });
    }
    let body = line.strip_suffix(b"\n").ok_or(EventsError::Undecodable)?;
    let probe: LineVersion = serde_json::from_slice(body).map_err(|_| EventsError::Undecodable)?;
    if probe.version != version {
        return Err(EventsError::UnsupportedVersion {
            version: probe.version,
        });
    }
    serde_json::from_slice(body).map_err(|_| EventsError::Undecodable)
}

/// Where the Mac's copy of a node's journal stands: the number it asks
/// from next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cursor {
    /// The copy holds no line yet: the Mac asks from the journal's first
    /// number, and events the node pruned before it is no gap, since the
    /// Mac never read up to them.
    Fresh,
    /// The Mac asks from this number.
    At(EventSeq),
}

impl Cursor {
    /// Where a copy stands whose newest whole line is `newest` (`None`:
    /// no line yet): after an event, at its number plus one; after a gap,
    /// at its end; after a reset, at the first number.
    /// `NumbersExhausted` after an event with the last number there is.
    pub fn after(newest: Option<&NodeLine>) -> Result<Self, EventsError> {
        let Some(line) = newest else {
            return Ok(Self::Fresh);
        };
        match line.entry {
            NodeEntry::Event(event) => event
                .seq
                .get()
                .checked_add(1)
                .map(|next| Self::At(EventSeq::new(next)))
                .ok_or(EventsError::NumbersExhausted),
            NodeEntry::Gap { to, .. } => Ok(Self::At(to)),
            NodeEntry::Reset { .. } => Ok(Self::At(EventSeq::FIRST)),
        }
    }

    /// The number to ask from: `Events{since}`.
    #[must_use]
    pub const fn since(self) -> EventSeq {
        match self {
            Self::Fresh => EventSeq::FIRST,
            Self::At(since) => since,
        }
    }
}

/// What a page of a node's journal gives the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The lines to append, in order.
    pub lines: Vec<NodeLine>,
    /// Where the copy stands once they are appended.
    pub next: Cursor,
    /// Whether the node's journal holds events after them, to ask for at
    /// once.
    pub more: bool,
}

/// The lines `page` gives a copy that stands at `cursor`, read at
/// `read_at` (the Mac's clock):
///
/// - a journal that ends before the number asked from was reset: a
///   [`NodeEntry::Reset`], and the copy asks again from the first number;
/// - events numbered past the number asked from were pruned before the
///   Mac read them: a [`NodeEntry::Gap`] before them, unless the copy is
///   fresh;
/// - each event, in order, and the copy then stands after the last.
///
/// A page that starts before the number asked from is `PageBeforeSince`,
/// and one that holds no event although the journal ends after it is
/// `PageWithoutEvents`: the agent keeps its newest event, so either is a
/// fault of the agent's, and nothing of the page is taken.
pub fn accept(cursor: Cursor, page: &EventsV1, read_at: UnixTime) -> Result<Accepted, EventsError> {
    let since = cursor.since();
    let end = page.end();
    if end < since {
        // The page holds events below `end` only, so none at or after
        // `since`: there is nothing of it to take.
        let next = Cursor::At(EventSeq::FIRST);
        return Ok(Accepted {
            lines: vec![NodeLine {
                read_at,
                entry: NodeEntry::Reset { end },
            }],
            next,
            more: next.since() < end,
        });
    }
    let (Some(first), Some(last)) = (page.events().first(), page.events().last()) else {
        if end > since {
            return Err(EventsError::PageWithoutEvents {
                since: since.get(),
                end: end.get(),
            });
        }
        return Ok(Accepted {
            lines: Vec::new(),
            next: cursor,
            more: false,
        });
    };
    if first.seq < since {
        return Err(EventsError::PageBeforeSince {
            since: since.get(),
            first: first.seq.get(),
        });
    }
    let mut lines = Vec::with_capacity(page.events().len() + 1);
    if first.seq > since && cursor != Cursor::Fresh {
        lines.push(NodeLine {
            read_at,
            entry: NodeEntry::Gap {
                from: since,
                to: first.seq,
            },
        });
    }
    lines.extend(page.events().iter().map(|event| NodeLine {
        read_at,
        entry: NodeEntry::Event(*event),
    }));
    // Every event of a page is numbered below its end, so the number after
    // the last is at most the end.
    let next = EventSeq::new(last.seq.get() + 1);
    Ok(Accepted {
        lines,
        next: Cursor::At(next),
        more: next < end,
    })
}

/// An entry of the document: an event of the Mac's journal, or a line of
/// a node's copy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEntry {
    /// An event of the Mac's journal.
    Mac(MacEvent),
    /// A line of a node's copy.
    Node {
        /// The node.
        node: NodeId,
        /// The line.
        line: NodeLine,
    },
}

impl JournalEntry {
    /// When the entry happened: a Mac event's time, or the line's
    /// ([`NodeLine::at`]).
    #[must_use]
    pub const fn at(&self) -> UnixTime {
        match self {
            Self::Mac(event) => event.at,
            Self::Node { line, .. } => line.at(),
        }
    }
}

/// A day file that ended in an incomplete line: the Mac's (`node` is
/// `None`) or a node's copy's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalDay {
    /// The node whose copy it is, or `None` for the Mac's journal.
    #[serde(deserialize_with = "Option::deserialize")]
    pub node: Option<NodeId>,
    /// The day.
    pub day: CalendarDate,
}

/// What `mooringctl events --json` prints: the UTC days asked for, the
/// entries of those days' files (the Mac's events of those days, and the
/// lines each node's copy took on those days) in the order of their times,
/// the newest [`MAX_DOCUMENT_ENTRIES`] of them with a count of the older
/// ones left out, and the day files that ended in an incomplete line. On
/// the wire it carries its version, which must be
/// [`EVENTS_DOCUMENT_VERSION`], refuses an unknown key, and refuses
/// entries out of order or past the bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EventsRepr", into = "EventsRepr")]
pub struct EventsDocument {
    since: CalendarDate,
    until: CalendarDate,
    entries: Vec<JournalEntry>,
    omitted: u64,
    incomplete_days: Vec<JournalDay>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsRepr {
    version: u32,
    since: CalendarDate,
    until: CalendarDate,
    entries: Vec<JournalEntry>,
    omitted: u64,
    incomplete_days: Vec<JournalDay>,
}

impl EventsDocument {
    /// The document of the days `since` to `until` with `entries`, which
    /// it puts in the order of their times (entries of one time keep the
    /// order given) and cuts to the newest [`MAX_DOCUMENT_ENTRIES`], and
    /// the day files that ended in an incomplete line.
    #[must_use]
    pub fn new(
        since: CalendarDate,
        until: CalendarDate,
        mut entries: Vec<JournalEntry>,
        incomplete_days: Vec<JournalDay>,
    ) -> Self {
        entries.sort_by_key(JournalEntry::at);
        let omitted = entries.len().saturating_sub(MAX_DOCUMENT_ENTRIES);
        entries.drain(..omitted);
        Self {
            since,
            until,
            entries,
            omitted: omitted as u64,
            incomplete_days,
        }
    }

    /// The first day asked for.
    #[must_use]
    pub const fn since(&self) -> CalendarDate {
        self.since
    }

    /// The last day asked for.
    #[must_use]
    pub const fn until(&self) -> CalendarDate {
        self.until
    }

    /// The entries, in the order of their times.
    #[must_use]
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// How many older entries of the days were left out.
    #[must_use]
    pub const fn omitted(&self) -> u64 {
        self.omitted
    }

    /// The day files that ended in an incomplete line.
    #[must_use]
    pub fn incomplete_days(&self) -> &[JournalDay] {
        &self.incomplete_days
    }
}

impl TryFrom<EventsRepr> for EventsDocument {
    type Error = EventsError;

    fn try_from(repr: EventsRepr) -> Result<Self, Self::Error> {
        if repr.version != EVENTS_DOCUMENT_VERSION {
            return Err(EventsError::UnsupportedDocumentVersion {
                found: repr.version,
            });
        }
        if repr.entries.len() > MAX_DOCUMENT_ENTRIES {
            return Err(EventsError::TooManyEntries {
                count: repr.entries.len(),
            });
        }
        if !repr
            .entries
            .windows(2)
            .all(|pair| pair[0].at() <= pair[1].at())
        {
            return Err(EventsError::EntriesNotOrdered);
        }
        Ok(Self {
            since: repr.since,
            until: repr.until,
            entries: repr.entries,
            omitted: repr.omitted,
            incomplete_days: repr.incomplete_days,
        })
    }
}

impl From<EventsDocument> for EventsRepr {
    fn from(document: EventsDocument) -> Self {
        Self {
            version: EVENTS_DOCUMENT_VERSION,
            since: document.since,
            until: document.until,
            entries: document.entries,
            omitted: document.omitted,
            incomplete_days: document.incomplete_days,
        }
    }
}
