// SPDX-License-Identifier: GPL-3.0-or-later

//! `events` (design §15.7): the Mac's event journal and each node's copy,
//! read from the day files `mooring-store` keeps and printed in the order
//! of their times, as the document Mooring.app reads (`--json`, one line)
//! or as text: a header, a line per entry (its time, the Mac or the node,
//! what happened), and the files that end in an incomplete line.
//!
//! The command reads and never writes: a torn last line is reported, not
//! cut (the daemon's next append does that). It reads the Mac's day files
//! of the range, then each node's, one at a time; a line the decoder
//! refuses ends it with an error naming the file and the line, never the
//! bytes. The days are those of the files: the Mac's events of those days,
//! and what the daemon read of each node on those days, whose events can
//! be older. The range is at most the days the journals keep; the default
//! is the last seven days, UTC, by the Mac's clock.

use std::io::{self, Write};
use std::path::Path;

use mooring_agent_proto::{AgentEventKind, GateReason, ShutdownReason};
use mooring_daemon_core::events::{
    EventsDocument, ExitPhase, JOURNAL_DAYS, JournalDay, JournalEntry, MacEventKind, NodeEntry,
    decode_mac_line, decode_node_line,
};
use mooring_daemon_core::status::{AgentUnreachable, DrainOutcome, PowerSource};
use mooring_model::error::ModelError;
use mooring_model::{CalendarDate, NodeId};
use mooring_store::{
    DayLines, event_nodes, mac_events_path, node_events_path, read_mac_events, read_node_events,
};

use crate::app::{Env, support_dir};
use crate::daemon::events::files;
use crate::error::{CommandError, LocalError};
use crate::router::output::{json_line, utc_stamp};

/// The days the command reads by default, today's included.
pub(crate) const DEFAULT_DAYS: u32 = 7;

fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

/// `events [--since <date>] [--until <date>] [--json]`.
pub(crate) fn events(
    env: &Env<'_>,
    out: &mut dyn Write,
    since: Option<CalendarDate>,
    until: Option<CalendarDate>,
    json: bool,
) -> Result<(), CommandError> {
    let today = CalendarDate::utc_of((env.clock)()?).map_err(|_| LocalError::Clock)?;
    let (since, until) = range(today, since, until)?;
    let dir = support_dir(env)?;
    let mut entries = Vec::new();
    let mut incomplete = Vec::new();
    read_journal(&dir, None, since, until, &mut entries, &mut incomplete)?;
    for node in event_nodes(&dir).map_err(files)?.nodes {
        read_journal(
            &dir,
            Some(&node),
            since,
            until,
            &mut entries,
            &mut incomplete,
        )?;
    }
    let document = EventsDocument::new(since, until, entries, incomplete);
    let text = if json {
        json_line(&document).map_err(|error| output(io::Error::other(error)))?
    } else {
        summary(&document).map_err(|_| LocalError::Clock)?
    };
    out.write_all(text.as_bytes()).map_err(output)
}

/// The range asked for: `until` defaults to today and `since` to
/// [`DEFAULT_DAYS`] days up to `until`; it must not run backwards nor
/// cover more days than the journals keep.
pub(crate) fn range(
    today: CalendarDate,
    since: Option<CalendarDate>,
    until: Option<CalendarDate>,
) -> Result<(CalendarDate, CalendarDate), LocalError> {
    let until = until.unwrap_or(today);
    let since = since.unwrap_or_else(|| until.saturating_sub_days(DEFAULT_DAYS - 1));
    if since > until {
        return Err(LocalError::HistoryRange { since, until });
    }
    let days = until.days_since_epoch() - since.days_since_epoch() + 1;
    if days > JOURNAL_DAYS {
        return Err(LocalError::HistoryRangeTooLong {
            days,
            max: JOURNAL_DAYS,
        });
    }
    Ok((since, until))
}

/// Reads the day files of the range of the Mac's journal (`node` is
/// `None`) or of a node's copy, in turn, into `entries`, and the days whose
/// file ends in an incomplete line into `incomplete`.
fn read_journal(
    dir: &Path,
    node: Option<&NodeId>,
    since: CalendarDate,
    until: CalendarDate,
    entries: &mut Vec<JournalEntry>,
    incomplete: &mut Vec<JournalDay>,
) -> Result<(), CommandError> {
    let mut day = since;
    loop {
        let read = match node {
            None => read_mac_events(dir, day),
            Some(node) => read_node_events(dir, node, day),
        };
        if let Some(DayLines { lines, torn }) = read.map_err(files)? {
            for (index, line) in lines.split_inclusive(|&byte| byte == b'\n').enumerate() {
                let refused = |source| LocalError::EventsLine {
                    path: match node {
                        None => mac_events_path(dir, day),
                        Some(node) => node_events_path(dir, node, day),
                    },
                    line: index + 1,
                    source,
                };
                entries.push(match node {
                    None => JournalEntry::Mac(decode_mac_line(line).map_err(refused)?),
                    Some(node) => JournalEntry::Node {
                        node: node.clone(),
                        line: decode_node_line(line).map_err(refused)?,
                    },
                });
            }
            if torn {
                incomplete.push(JournalDay {
                    node: node.cloned(),
                    day,
                });
            }
        }
        if day == until {
            return Ok(());
        }
        day = day.checked_add_days(1).map_err(|_| LocalError::Clock)?;
    }
}

/// The text: a header, one line per entry in time order, then the files
/// that end in an incomplete line. `Err` only past the year 9999.
fn summary(document: &EventsDocument) -> Result<String, ModelError> {
    let mut text = format!(
        "events {} to {} UTC: {} entries",
        document.since(),
        document.until(),
        document.entries().len()
    );
    if document.omitted() > 0 {
        text.push_str(&format!(
            " (the newest; {} older left out)",
            document.omitted()
        ));
    }
    text.push('\n');
    for entry in document.entries() {
        let (source, what) = match entry {
            JournalEntry::Mac(event) => ("mac".to_owned(), mac_text(&event.kind)),
            JournalEntry::Node { node, line } => (node.to_string(), node_text(line.entry)),
        };
        text.push_str(&format!(
            "  {}  {source:<12}  {what}\n",
            utc_stamp(entry.at())?
        ));
    }
    for day in document.incomplete_days() {
        let journal = day.node.as_ref().map_or_else(
            || "the Mac's journal".to_owned(),
            |node| format!("{node}'s copy"),
        );
        text.push_str(&format!(
            "{}, {journal}: the last line is incomplete (the daemon may be writing it, or stopped while writing it)\n",
            day.day
        ));
    }
    Ok(text)
}

/// What a Mac event says.
fn mac_text(kind: &MacEventKind) -> String {
    match kind {
        MacEventKind::DaemonStarted => "the daemon started".to_owned(),
        MacEventKind::PowerSource { source } => match source {
            PowerSource::Ac => "power: mains".to_owned(),
            PowerSource::Battery => "power: battery".to_owned(),
        },
        MacEventKind::Slept { drain } => format!(
            "the Mac slept; the exit's drain {}",
            match drain {
                DrainOutcome::Completed => "completed",
                DrainOutcome::TimedOut => "ran out of time",
                DrainOutcome::Failed => "could not reach a node",
            }
        ),
        MacEventKind::Woke => "the Mac woke".to_owned(),
        MacEventKind::Exit { phase } => format!("exit: {}", phase_text(phase)),
        MacEventKind::NodeUnreachable { node, cause } => {
            format!("{node}'s agent cannot be polled: {}", cause_text(*cause))
        }
        MacEventKind::NodeReachable { node } => format!("{node}'s agent answers again"),
    }
}

/// The exit's phase, with its reasons' kinds by name.
fn phase_text(phase: &ExitPhase) -> String {
    match phase {
        ExitPhase::Disabled => "disabled".to_owned(),
        ExitPhase::Preflight => "preflight".to_owned(),
        ExitPhase::Starting => "starting".to_owned(),
        ExitPhase::Verifying => "verifying".to_owned(),
        ExitPhase::Serving => "serving".to_owned(),
        ExitPhase::Degraded { reasons } => {
            let names: Vec<&str> = reasons.iter().map(|reason| reason.name()).collect();
            format!("degraded ({})", names.join(", "))
        }
        ExitPhase::Down { reason } => format!("down ({})", reason.name()),
        ExitPhase::Paused => "paused".to_owned(),
    }
}

/// Why a node's agent could not be polled.
fn cause_text(cause: AgentUnreachable) -> &'static str {
    match cause {
        AgentUnreachable::Spawn => "ssh could not be started",
        AgentUnreachable::HostKeyMismatch => "its host key does not match the pin",
        AgentUnreachable::AuthFailed => "it refused the key",
        AgentUnreachable::Transport => "the connection failed",
        AgentUnreachable::Timeout => "no answer in time",
        AgentUnreachable::ProtocolMismatch => "it speaks another protocol version",
        AgentUnreachable::Decode => "its answer could not be decoded",
        AgentUnreachable::ResponseTooLarge => "its answer was too large",
        AgentUnreachable::ForcedCommandNotActive => "its forced command is not active",
    }
}

/// What a line of a node's copy says.
fn node_text(entry: NodeEntry) -> String {
    match entry {
        NodeEntry::Event(event) => match event.kind {
            AgentEventKind::ConditionRaised { condition } => format!("raised: {condition}"),
            AgentEventKind::ConditionCleared { condition } => format!("cleared: {condition:?}"),
            AgentEventKind::GateOpened => "the gate opened".to_owned(),
            AgentEventKind::GateClosed => "the gate closed".to_owned(),
            AgentEventKind::HoldRecorded { hold } => format!("hold recorded: {}", hold_text(hold)),
            AgentEventKind::HoldCleared { hold } => format!("hold cleared: {}", hold_text(hold)),
            AgentEventKind::Halted { reason } => format!("halted: {}", halt_text(reason)),
            AgentEventKind::Resumed { generation } => {
                format!("resumed, running generation {generation}")
            }
            AgentEventKind::Committed { generation } => {
                format!("generation {generation} committed")
            }
            AgentEventKind::EngineRestarted { engine } => {
                format!("{} restarted", engine.name())
            }
            AgentEventKind::HostBooted => "the host booted".to_owned(),
        },
        NodeEntry::Gap { from, to } => format!(
            "events {} to {} were pruned before the Mac read them",
            from.get(),
            to.get().saturating_sub(1)
        ),
        NodeEntry::Reset { end } => format!(
            "the journal was started anew (it ends before event {}); read again from its start",
            end.get()
        ),
    }
}

/// A hold, as the operator knows it.
fn hold_text(hold: GateReason) -> &'static str {
    match hold {
        GateReason::MacDrain => "the Mac's sleep drain",
        GateReason::EgressViolation => "an egress violation",
        GateReason::Operator => "the operator's",
    }
}

/// Why a node was halted.
fn halt_text(reason: ShutdownReason) -> &'static str {
    match reason {
        ShutdownReason::EgressIsNodeAddress => "the egress was a node's address",
        ShutdownReason::Operator => "by the operator",
        ShutdownReason::Retire => "being retired",
    }
}
