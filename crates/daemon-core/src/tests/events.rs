// SPDX-License-Identifier: GPL-3.0-or-later

//! The event journals (design §15.7): the exit's phase of each state, the
//! Mac's events its statuses give, the lines of both journals and their
//! faults, the number a copy asks from after its newest line, the pages a
//! copy takes or refuses, the document and its bounds, the oldest day the
//! journals keep, the error kinds and texts, and
//! `contract/events-fixtures/events.json`: one entry of every variant the
//! document carries, pinned byte for byte for Mooring.app's mirror. To
//! change it, change [`fixture`], write [`encode`]'s output over the file,
//! and review the diff.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AgentEvent, AgentEventKind, EngineUser, EventSeq, EventsV1, GateReason, Generation,
    ShutdownReason, UnixTime as WireTime, WatchErrorKind,
};
use mooring_model::collections::{NonEmpty, NonEmptySet};
use mooring_model::{NodeId, UnixTime};
use serde_json::Value;

use super::snapshot::assembled;
use super::support::{date, node, status as node_status};
use super::variants::{
    degraded_reasons, down_reasons, each_object_denies_unknown_keys, watch_errors,
};
use crate::alert::DegradedReasonKind;
use crate::error::{EventsError, EventsErrorKind};
use crate::events::{
    Accepted, Cursor, EVENTS_DOCUMENT_VERSION, EventsDocument, ExitPhase, JOURNAL_DAYS, JournalDay,
    JournalEntry, MAC_EVENT_VERSION, MAX_DOCUMENT_ENTRIES, MAX_EVENT_LINE_BYTES, MacEvent,
    MacEventKind, MacSeen, NODE_LINE_VERSION, NodeEntry, NodeLine, accept, decode_mac_line,
    decode_node_line, encode_mac_line, encode_node_line, oldest_kept,
};
use crate::snapshot::Ledgers;
use crate::status::{
    AgentUnreachable, DegradedReason, DownReason, DownReasonKind, DrainOutcome, DrainRecord,
    ExitState, MacStatusParts, MacStatusV2, NodeAgentState, NodeReport, PowerSource,
};

const FIXTURE: &[u8] = include_bytes!("../../../../contract/events-fixtures/events.json");

/// 2026-11-15 00:00:00 UTC.
const DAY: u64 = 1_794_700_800;

fn t(secs: u64) -> UnixTime {
    UnixTime::from_secs(DAY + secs)
}

fn wt(secs: u64) -> WireTime {
    WireTime::from_secs(DAY + secs)
}

fn seq(number: u64) -> EventSeq {
    EventSeq::new(number)
}

/// The event numbered `number`, recorded `number` seconds into the day.
fn event(number: u64, kind: AgentEventKind) -> AgentEvent {
    AgentEvent {
        seq: seq(number),
        at: wt(number),
        kind,
    }
}

/// A page of the events numbered `numbers`, before `end`.
fn page(numbers: std::ops::Range<u64>, end: u64) -> EventsV1 {
    EventsV1::new(
        numbers
            .map(|number| event(number, AgentEventKind::GateOpened))
            .collect(),
        seq(end),
    )
    .unwrap()
}

/// The lines of the events numbered `numbers`, read at `read_at`.
fn event_lines(numbers: std::ops::Range<u64>, read_at: UnixTime) -> Vec<NodeLine> {
    numbers
        .map(|number| NodeLine {
            read_at,
            entry: NodeEntry::Event(event(number, AgentEventKind::GateOpened)),
        })
        .collect()
}

fn mac(secs: u64, kind: MacEventKind) -> JournalEntry {
    JournalEntry::Mac(MacEvent { at: t(secs), kind })
}

fn on_node(name: &str, line: NodeLine) -> JournalEntry {
    JournalEntry::Node {
        node: node(name),
        line,
    }
}

#[test]
fn the_exit_phase_keeps_the_kinds_of_a_states_reasons_only() {
    let mut reasons = degraded_reasons();
    // A second failed probe, of the other node: one kind still.
    reasons.push(DegradedReason::WatchStale { node: node("lon1") });
    let first = reasons.remove(0);
    for (state, phase) in [
        (ExitState::Disabled, ExitPhase::Disabled),
        (ExitState::Preflight, ExitPhase::Preflight),
        (ExitState::Starting, ExitPhase::Starting),
        (ExitState::Verifying, ExitPhase::Verifying),
        (
            ExitState::Serving {
                ip: Ipv4Addr::new(198, 51, 100, 17),
                verified_at: t(60),
            },
            ExitPhase::Serving,
        ),
        (
            ExitState::Degraded {
                reasons: NonEmpty::from_parts(first, reasons),
            },
            ExitPhase::Degraded {
                reasons: every_degraded_kind(),
            },
        ),
        (
            ExitState::Down {
                reason: DownReason::SecretsUnavailable,
            },
            ExitPhase::Down {
                reason: DownReasonKind::SecretsUnavailable,
            },
        ),
        (ExitState::Paused, ExitPhase::Paused),
    ] {
        assert_eq!(ExitPhase::of(&state), phase, "{state:?}");
    }
}

/// Every kind of degraded reason, as one set.
fn every_degraded_kind() -> NonEmptySet<DegradedReasonKind> {
    let mut kinds = NonEmptySet::new(DegradedReasonKind::ALL[0]);
    for kind in DegradedReasonKind::ALL {
        kinds.insert(*kind);
    }
    kinds
}

#[test]
fn every_down_reason_has_its_own_kind() {
    let kinds: Vec<DownReasonKind> = down_reasons().iter().map(DownReason::kind).collect();
    assert_eq!(
        kinds,
        [
            DownReasonKind::EgressInterfaceAbsent,
            DownReasonKind::EgressAmbiguous,
            DownReasonKind::EgressNoIpv4,
            DownReasonKind::EgressSubnetMismatch,
            DownReasonKind::UplinkAbsent,
            DownReasonKind::UplinkEqualsEgress,
            DownReasonKind::NoAppliedNode,
            DownReasonKind::DirectProbeFailed,
            DownReasonKind::CarrierCheckUnrecorded,
            DownReasonKind::SimPlanUnrecorded,
            DownReasonKind::SecretsUnavailable,
            DownReasonKind::AgentNotEnabled,
            DownReasonKind::EngineSpawnFailed,
            DownReasonKind::EngineConfigRejected,
            DownReasonKind::EngineStartFailed,
            DownReasonKind::EngineCrashLoop,
            DownReasonKind::Violation,
            DownReasonKind::SimCapReached,
            DownReasonKind::ForeignNetworkAttached,
        ]
    );
    assert_eq!(kinds, DownReasonKind::ALL);
    // The kind is written by its name, as the alert machine's kinds are.
    assert_eq!(
        serde_json::to_string(&DownReasonKind::EngineCrashLoop).unwrap(),
        r#""EngineCrashLoop""#
    );
}

#[test]
fn mac_lines_are_pinned_and_read_back() {
    assert_eq!(MAC_EVENT_VERSION, 1);
    for (event, line) in [
        (
            MacEvent {
                at: t(1),
                kind: MacEventKind::DaemonStarted,
            },
            "{\"version\":1,\"at\":1794700801,\"kind\":\"daemon_started\"}\n",
        ),
        (
            MacEvent {
                at: t(2),
                kind: MacEventKind::Exit {
                    phase: ExitPhase::Degraded {
                        reasons: NonEmptySet::new(DegradedReasonKind::OnBattery),
                    },
                },
            },
            "{\"version\":1,\"at\":1794700802,\"kind\":{\"exit\":{\"phase\":{\"degraded\":{\"reasons\":[\"OnBattery\"]}}}}}\n",
        ),
        (
            MacEvent {
                at: t(3),
                kind: MacEventKind::NodeUnreachable {
                    node: node("lon1"),
                    cause: AgentUnreachable::Timeout,
                },
            },
            "{\"version\":1,\"at\":1794700803,\"kind\":{\"node_unreachable\":{\"node\":\"lon1\",\"cause\":\"timeout\"}}}\n",
        ),
    ] {
        assert_eq!(encode_mac_line(&event).unwrap(), line.as_bytes());
        assert_eq!(decode_mac_line(line.as_bytes()), Ok(event));
    }
}

#[test]
fn node_lines_are_pinned_and_read_back() {
    assert_eq!(NODE_LINE_VERSION, 1);
    for (line, text) in [
        (
            NodeLine {
                read_at: t(100),
                entry: NodeEntry::Event(event(7, AgentEventKind::HostBooted)),
            },
            "{\"version\":1,\"read_at\":1794700900,\"entry\":{\"event\":{\"seq\":7,\"at\":1794700807,\"kind\":\"HostBooted\"}}}\n",
        ),
        (
            NodeLine {
                read_at: t(100),
                entry: NodeEntry::Gap {
                    from: seq(3),
                    to: seq(7),
                },
            },
            "{\"version\":1,\"read_at\":1794700900,\"entry\":{\"gap\":{\"from\":3,\"to\":7}}}\n",
        ),
        (
            NodeLine {
                read_at: t(100),
                entry: NodeEntry::Reset { end: seq(2) },
            },
            "{\"version\":1,\"read_at\":1794700900,\"entry\":{\"reset\":{\"end\":2}}}\n",
        ),
    ] {
        assert_eq!(encode_node_line(&line).unwrap(), text.as_bytes());
        assert_eq!(decode_node_line(text.as_bytes()), Ok(line));
    }
}

/// A line out of its rule is refused by its fault, which holds no byte of
/// it.
#[test]
fn a_line_out_of_its_rule_is_refused() {
    let mac_line = "{\"version\":1,\"at\":1794700801,\"kind\":\"woke\"}\n";
    let node_line = "{\"version\":1,\"read_at\":1794700900,\"entry\":{\"reset\":{\"end\":2}}}\n";
    assert!(decode_mac_line(mac_line.as_bytes()).is_ok());
    assert!(decode_node_line(node_line.as_bytes()).is_ok());
    for line in [mac_line, node_line] {
        let undecodable = [
            // Without its newline: a torn line is never read.
            line.trim_end().to_owned(),
            line.replacen("{\"version\":1,", "{\"version\":1,\"extra\":0,", 1),
            line.replacen("\"version\":1,", "", 1),
            "not json\n".to_owned(),
            "{\"version\":1}\n".to_owned(),
        ];
        for bad in undecodable {
            assert_eq!(
                decode_mac_line(bad.as_bytes()),
                Err(EventsError::Undecodable),
                "{bad}"
            );
            assert_eq!(
                decode_node_line(bad.as_bytes()),
                Err(EventsError::Undecodable),
                "{bad}"
            );
        }
        // Another version is refused as such, whatever keys it brings.
        let newer = line.replacen("{\"version\":1,", "{\"version\":2,\"extra\":0,", 1);
        assert_eq!(
            decode_mac_line(newer.as_bytes()),
            Err(EventsError::UnsupportedVersion { version: 2 })
        );
        assert_eq!(
            decode_node_line(newer.as_bytes()),
            Err(EventsError::UnsupportedVersion { version: 2 })
        );
    }
    // Each journal's lines are its own.
    assert_eq!(
        decode_mac_line(node_line.as_bytes()),
        Err(EventsError::Undecodable)
    );
    assert_eq!(
        decode_node_line(mac_line.as_bytes()),
        Err(EventsError::Undecodable)
    );
    // A gap misses at least one number.
    for gap in ["{\"from\":7,\"to\":7}", "{\"from\":8,\"to\":7}"] {
        let line =
            format!("{{\"version\":1,\"read_at\":1794700900,\"entry\":{{\"gap\":{gap}}}}}\n");
        assert_eq!(
            decode_node_line(line.as_bytes()),
            Err(EventsError::Undecodable),
            "{line}"
        );
    }
    // The bound holds before anything is parsed.
    let mut long = vec![b' '; MAX_EVENT_LINE_BYTES];
    long[..mac_line.len() - 1].copy_from_slice(&mac_line.as_bytes()[..mac_line.len() - 1]);
    *long.last_mut().unwrap() = b'\n';
    assert!(decode_mac_line(&long).is_ok());
    long.insert(0, b' ');
    assert_eq!(
        decode_mac_line(&long),
        Err(EventsError::LineTooLong {
            bytes: MAX_EVENT_LINE_BYTES + 1
        })
    );
    assert_eq!(
        decode_node_line(&long),
        Err(EventsError::LineTooLong {
            bytes: MAX_EVENT_LINE_BYTES + 1
        })
    );
}

/// The longest lines the closed types can give are well within the
/// bound: every degraded kind at once, the longest node id and cause, and
/// the largest numbers and times.
#[test]
fn the_longest_lines_fit_their_bound() {
    assert_eq!(MAX_EVENT_LINE_BYTES, 1024);
    let longest_node = NodeId::parse("abcdefghijkl").unwrap();
    let mac_lines = [
        MacEventKind::Exit {
            phase: ExitPhase::Degraded {
                reasons: every_degraded_kind(),
            },
        },
        MacEventKind::NodeUnreachable {
            node: longest_node,
            cause: AgentUnreachable::ForcedCommandNotActive,
        },
    ]
    .map(|kind| {
        encode_mac_line(&MacEvent {
            at: UnixTime::from_secs(u64::MAX),
            kind,
        })
        .unwrap()
        .len()
    });
    let node_lines = watch_errors().into_iter().map(|condition| {
        encode_node_line(&NodeLine {
            read_at: UnixTime::from_secs(u64::MAX),
            entry: NodeEntry::Event(AgentEvent {
                seq: seq(u64::MAX - 1),
                at: WireTime::from_secs(u64::MAX),
                kind: AgentEventKind::ConditionRaised { condition },
            }),
        })
        .unwrap()
        .len()
    });
    let longest = mac_lines.into_iter().chain(node_lines).max().unwrap();
    assert!(longest < 500, "{longest}");
}

#[test]
fn a_copy_asks_after_its_newest_line() {
    let line = |entry| NodeLine {
        read_at: t(100),
        entry,
    };
    assert_eq!(Cursor::after(None), Ok(Cursor::Fresh));
    assert_eq!(
        Cursor::after(Some(&line(NodeEntry::Event(event(
            5,
            AgentEventKind::GateClosed
        ))))),
        Ok(Cursor::At(seq(6)))
    );
    assert_eq!(
        Cursor::after(Some(&line(NodeEntry::Gap {
            from: seq(2),
            to: seq(9),
        }))),
        Ok(Cursor::At(seq(9)))
    );
    // After a reset the journal is read again from its first number.
    assert_eq!(
        Cursor::after(Some(&line(NodeEntry::Reset { end: seq(4) }))),
        Ok(Cursor::At(EventSeq::FIRST))
    );
    let last = AgentEvent {
        seq: seq(u64::MAX),
        ..event(0, AgentEventKind::GateClosed)
    };
    assert_eq!(
        Cursor::after(Some(&line(NodeEntry::Event(last)))),
        Err(EventsError::NumbersExhausted)
    );
    assert_eq!(Cursor::Fresh.since(), EventSeq::FIRST);
    assert_eq!(Cursor::At(seq(7)).since(), seq(7));
}

#[test]
fn a_page_is_taken_after_the_number_asked_from() {
    let read_at = t(500);
    // A fresh copy takes the journal as it is, pruned or not.
    assert_eq!(
        accept(Cursor::Fresh, &page(3..6, 6), read_at),
        Ok(Accepted {
            lines: event_lines(3..6, read_at),
            next: Cursor::At(seq(6)),
            more: false,
        })
    );
    // A page that does not reach the journal's end asks for more.
    assert_eq!(
        accept(Cursor::At(seq(3)), &page(3..6, 10), read_at),
        Ok(Accepted {
            lines: event_lines(3..6, read_at),
            next: Cursor::At(seq(6)),
            more: true,
        })
    );
    // Events pruned before the Mac read them are a gap before the rest.
    let mut lines = vec![NodeLine {
        read_at,
        entry: NodeEntry::Gap {
            from: seq(3),
            to: seq(5),
        },
    }];
    lines.extend(event_lines(5..7, read_at));
    assert_eq!(
        accept(Cursor::At(seq(3)), &page(5..7, 7), read_at),
        Ok(Accepted {
            lines,
            next: Cursor::At(seq(7)),
            more: false,
        })
    );
    // A journal that ends before the number asked from was reset: the copy
    // reads it again from its first number, at once when it holds events.
    for (end, more) in [(4, true), (0, false)] {
        assert_eq!(
            accept(Cursor::At(seq(10)), &page(0..0, end), read_at),
            Ok(Accepted {
                lines: vec![NodeLine {
                    read_at,
                    entry: NodeEntry::Reset { end: seq(end) },
                }],
                next: Cursor::At(EventSeq::FIRST),
                more,
            }),
            "end {end}"
        );
    }
    // Nothing new: nothing to append, and the copy stays where it is.
    for cursor in [Cursor::At(seq(4)), Cursor::Fresh] {
        let end = cursor.since().get();
        assert_eq!(
            accept(cursor, &page(0..0, end), read_at),
            Ok(Accepted {
                lines: Vec::new(),
                next: cursor,
                more: false,
            })
        );
    }
}

#[test]
fn a_page_that_does_not_follow_the_number_asked_from_is_refused() {
    assert_eq!(
        accept(Cursor::At(seq(4)), &page(2..6, 6), t(500)),
        Err(EventsError::PageBeforeSince { since: 4, first: 2 })
    );
    assert_eq!(
        accept(Cursor::At(seq(4)), &page(0..0, 6), t(500)),
        Err(EventsError::PageWithoutEvents { since: 4, end: 6 })
    );
    assert_eq!(
        accept(Cursor::Fresh, &page(0..0, 3), t(500)),
        Err(EventsError::PageWithoutEvents { since: 0, end: 3 })
    );
}

/// The document puts its entries in the order of their times, each by its
/// own clock, keeping the order given among entries of one time, and keeps
/// the newest of a range that has more than it holds.
#[test]
fn the_document_orders_its_entries_by_time_and_keeps_the_newest() {
    let gap = NodeLine {
        read_at: t(30),
        entry: NodeEntry::Gap {
            from: seq(1),
            to: seq(2),
        },
    };
    let booted = NodeLine {
        read_at: t(40),
        entry: NodeEntry::Event(event(10, AgentEventKind::HostBooted)),
    };
    let reset = NodeLine {
        read_at: t(20),
        entry: NodeEntry::Reset { end: seq(0) },
    };
    assert_eq!(on_node("lon1", gap).at(), t(30));
    assert_eq!(on_node("lon1", booted).at(), t(10));
    assert_eq!(on_node("lon1", reset).at(), t(20));
    assert_eq!(mac(25, MacEventKind::Woke).at(), t(25));
    let given = vec![
        mac(25, MacEventKind::Woke),
        on_node("lon1", gap),
        mac(10, MacEventKind::DaemonStarted),
        on_node("lon1", booted),
        on_node("ams1", reset),
        mac(20, MacEventKind::DaemonStarted),
    ];
    let incomplete = vec![JournalDay {
        node: None,
        day: date("2026-11-15"),
    }];
    let document = EventsDocument::new(
        date("2026-11-09"),
        date("2026-11-15"),
        given.clone(),
        incomplete.clone(),
    );
    assert_eq!(
        document.entries(),
        [
            given[2].clone(),
            given[3].clone(),
            given[4].clone(),
            given[5].clone(),
            given[0].clone(),
            given[1].clone(),
        ]
    );
    assert_eq!(
        (document.since(), document.until(), document.omitted()),
        (date("2026-11-09"), date("2026-11-15"), 0)
    );
    assert_eq!(document.incomplete_days(), incomplete);
    let text = serde_json::to_string(&document).unwrap();
    assert!(text.starts_with("{\"version\":1,\"since\":\"2026-11-09\",\"until\":\"2026-11-15\",\"entries\":[{\"mac\":{\"at\":1794700810,\"kind\":\"daemon_started\"}},{\"node\":{\"node\":\"lon1\",\"line\":{\"read_at\":1794700840,"), "{text}");
    assert!(
        text.ends_with(
            "],\"omitted\":0,\"incomplete_days\":[{\"node\":null,\"day\":\"2026-11-15\"}]}"
        ),
        "{text}"
    );
    assert_eq!(
        serde_json::from_str::<EventsDocument>(&text).unwrap(),
        document
    );
    // Past the bound, the oldest are left out and counted.
    let many: Vec<JournalEntry> = (0..MAX_DOCUMENT_ENTRIES as u64 + 3)
        .rev()
        .map(|secs| mac(secs, MacEventKind::Woke))
        .collect();
    let document = EventsDocument::new(date("2026-11-15"), date("2026-11-15"), many, Vec::new());
    assert_eq!(document.entries().len(), MAX_DOCUMENT_ENTRIES);
    assert_eq!(document.omitted(), 3);
    assert_eq!(document.entries()[0].at(), t(3));
    assert_eq!(
        document.entries().last().unwrap().at(),
        t(MAX_DOCUMENT_ENTRIES as u64 + 2)
    );
    let text = serde_json::to_string(&document).unwrap();
    assert_eq!(
        serde_json::from_str::<EventsDocument>(&text).unwrap(),
        document
    );
}

#[test]
fn a_document_out_of_its_rule_is_refused() {
    assert_eq!(EVENTS_DOCUMENT_VERSION, 1);
    let document = EventsDocument::new(
        date("2026-11-15"),
        date("2026-11-15"),
        vec![
            mac(1, MacEventKind::DaemonStarted),
            mac(2, MacEventKind::Woke),
        ],
        Vec::new(),
    );
    let json = serde_json::to_value(&document).unwrap();
    let refused = |value: &Value| {
        serde_json::from_value::<EventsDocument>(value.clone())
            .unwrap_err()
            .to_string()
    };
    let mut newer = json.clone();
    newer["version"] = Value::from(2);
    assert_eq!(
        refused(&newer),
        EventsError::UnsupportedDocumentVersion { found: 2 }.to_string()
    );
    let mut unknown = json.clone();
    unknown["extra"] = Value::from(0);
    assert!(refused(&unknown).contains("unknown field"));
    let mut reversed = json.clone();
    reversed["entries"].as_array_mut().unwrap().reverse();
    assert_eq!(
        refused(&reversed),
        EventsError::EntriesNotOrdered.to_string()
    );
    let mut too_many = json;
    let entry = too_many["entries"][0].clone();
    too_many["entries"] = Value::Array(vec![entry; MAX_DOCUMENT_ENTRIES + 1]);
    assert_eq!(
        refused(&too_many),
        EventsError::TooManyEntries {
            count: MAX_DOCUMENT_ENTRIES + 1
        }
        .to_string()
    );
}

#[test]
fn the_journals_keep_the_last_393_days() {
    assert_eq!(JOURNAL_DAYS, 393);
    assert_eq!(oldest_kept(date("2026-11-15")), date("2025-10-19"));
    assert_eq!(
        date("2026-11-15").days_since_epoch() - oldest_kept(date("2026-11-15")).days_since_epoch(),
        JOURNAL_DAYS - 1
    );
    assert_eq!(oldest_kept(date("1970-01-05")), date("1970-01-01"));
}

#[test]
fn event_journal_errors_have_kinds_and_texts() {
    for (error, kind, text) in [
        (
            EventsError::LineTooLong { bytes: 1025 },
            EventsErrorKind::LineTooLong,
            "an event journal line of 1025 bytes is longer than 1024",
        ),
        (
            EventsError::Undecodable,
            EventsErrorKind::Undecodable,
            "an event journal line is not an entry of its journal",
        ),
        (
            EventsError::UnsupportedVersion { version: 2 },
            EventsErrorKind::UnsupportedVersion,
            "an event journal line names version 2, which this build does not read",
        ),
        (
            EventsError::UnsupportedDocumentVersion { found: 2 },
            EventsErrorKind::UnsupportedDocumentVersion,
            "an event journal document names version 2; this build reads version 1",
        ),
        (
            EventsError::EntriesNotOrdered,
            EventsErrorKind::EntriesNotOrdered,
            "an event journal document's entries are not in the order of their times",
        ),
        (
            EventsError::TooManyEntries { count: 5001 },
            EventsErrorKind::TooManyEntries,
            "an event journal document holds 5001 entries, more than 5000",
        ),
        (
            EventsError::Unencodable,
            EventsErrorKind::Unencodable,
            "an event journal line or document could not be written as JSON",
        ),
        (
            EventsError::PageBeforeSince { since: 4, first: 2 },
            EventsErrorKind::PageBeforeSince,
            "the node's page starts at event 2, before event 4 that was asked for",
        ),
        (
            EventsError::PageWithoutEvents { since: 4, end: 6 },
            EventsErrorKind::PageWithoutEvents,
            "the node's page holds no event, although its journal ends at 6, after event 4 that was asked for",
        ),
        (
            EventsError::NumbersExhausted,
            EventsErrorKind::NumbersExhausted,
            "the newest event of a node's copy has the last number there is",
        ),
    ] {
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), text);
    }
}

/// The status before any node poll (nodes ams1 and lon1), with `edit`
/// applied to its parts.
fn status(edit: impl FnOnce(&mut MacStatusParts)) -> MacStatusV2 {
    let mut parts = assembled(Ledgers::NotPulled, &BTreeMap::new()).into_parts();
    edit(&mut parts);
    MacStatusV2::new(parts).unwrap()
}

fn set_agent(parts: &mut MacStatusParts, name: &str, agent: NodeAgentState) {
    parts.nodes.get_mut(&node(name)).unwrap().agent = agent;
}

fn reported(polled_at: UnixTime) -> NodeAgentState {
    NodeAgentState::Reported(Box::new(NodeReport::of(
        polled_at,
        &node_status(polled_at, None, Vec::new()),
    )))
}

fn unreachable(since: UnixTime, cause: AgentUnreachable) -> NodeAgentState {
    NodeAgentState::Unreachable { since, cause }
}

fn kinds(events: &[MacEvent]) -> Vec<(UnixTime, MacEventKind)> {
    events
        .iter()
        .map(|event| (event.at, event.kind.clone()))
        .collect()
}

#[test]
fn the_first_status_gives_its_power_source_and_its_exits_phase() {
    let mut seen = MacSeen::default();
    let first = status(|parts| set_agent(parts, "lon1", reported(t(5))));
    let at = first.parts().at;
    assert_eq!(
        kinds(&seen.changes(&first)),
        [
            (
                at,
                MacEventKind::PowerSource {
                    source: PowerSource::Ac
                }
            ),
            (
                at,
                MacEventKind::Exit {
                    phase: ExitPhase::Disabled
                }
            ),
        ]
    );
    // The same status again shows nothing new.
    assert_eq!(seen.changes(&first), []);
}

#[test]
fn a_status_gives_what_changed_since_the_last_in_order() {
    let mut seen = MacSeen::default();
    seen.changes(&status(|_| {}));
    let serving = |ip, verified_at| {
        status(|parts| {
            parts.exit.state = ExitState::Serving { ip, verified_at };
        })
    };
    let first = serving(Ipv4Addr::new(198, 51, 100, 17), t(60));
    let at = first.parts().at;
    assert_eq!(
        kinds(&seen.changes(&first)),
        [(
            at,
            MacEventKind::Exit {
                phase: ExitPhase::Serving
            }
        )]
    );
    // Another address or another verification is the same phase.
    assert_eq!(
        seen.changes(&serving(Ipv4Addr::new(198, 51, 100, 18), t(90))),
        []
    );
    // A degraded exit's reasons are its phase by their kinds: another
    // reason of a kind already there is no change, another kind is.
    let degraded = |reasons: Vec<DegradedReason>| {
        status(|parts| {
            let mut reasons = reasons;
            let first = reasons.remove(0);
            parts.exit.state = ExitState::Degraded {
                reasons: NonEmpty::from_parts(first, reasons),
            };
        })
    };
    let stale = |name| DegradedReason::WatchStale { node: node(name) };
    assert_eq!(
        kinds(&seen.changes(&degraded(vec![stale("lon1")]))),
        [(
            at,
            MacEventKind::Exit {
                phase: ExitPhase::Degraded {
                    reasons: NonEmptySet::new(DegradedReasonKind::WatchStale)
                }
            }
        )]
    );
    assert_eq!(
        seen.changes(&degraded(vec![stale("lon1"), stale("ams1")])),
        []
    );
    let mut both = NonEmptySet::new(DegradedReasonKind::WatchStale);
    both.insert(DegradedReasonKind::OnBattery);
    // The power source comes before the exit's phase.
    let on_battery = status(|parts| {
        parts.exit.power.source = PowerSource::Battery;
        parts.exit.state = ExitState::Degraded {
            reasons: NonEmpty::from_parts(stale("lon1"), vec![DegradedReason::OnBattery]),
        };
    });
    assert_eq!(
        kinds(&seen.changes(&on_battery)),
        [
            (
                at,
                MacEventKind::PowerSource {
                    source: PowerSource::Battery
                }
            ),
            (
                at,
                MacEventKind::Exit {
                    phase: ExitPhase::Degraded { reasons: both }
                }
            ),
        ]
    );
}

#[test]
fn a_sleep_and_a_wake_are_dated_by_their_own_times() {
    let mut seen = MacSeen::default();
    seen.changes(&status(|_| {}));
    let drained = DrainRecord {
        at: t(100),
        outcome: DrainOutcome::TimedOut,
    };
    let asleep = status(|parts| {
        parts.exit.power.last_sleep = Some(t(100));
        parts.exit.power.last_drain = Some(drained);
        parts.exit.state = ExitState::Paused;
    });
    let at = asleep.parts().at;
    assert_eq!(
        kinds(&seen.changes(&asleep)),
        [
            (
                t(100),
                MacEventKind::Slept {
                    drain: DrainOutcome::TimedOut
                }
            ),
            (
                at,
                MacEventKind::Exit {
                    phase: ExitPhase::Paused
                }
            ),
        ]
    );
    let woken = |wake| {
        status(|parts| {
            parts.exit.power.last_sleep = Some(t(100));
            parts.exit.power.last_drain = Some(drained);
            parts.exit.power.last_wake = Some(wake);
            parts.exit.state = ExitState::Preflight;
        })
    };
    assert_eq!(
        kinds(&seen.changes(&woken(t(400)))),
        [
            (t(400), MacEventKind::Woke),
            (
                at,
                MacEventKind::Exit {
                    phase: ExitPhase::Preflight
                }
            ),
        ]
    );
    // The next sleep and wake are new: each record is its own.
    assert_eq!(
        kinds(&seen.changes(&status(|parts| {
            parts.exit.power.last_drain = Some(DrainRecord {
                at: t(900),
                outcome: DrainOutcome::Completed,
            });
            parts.exit.power.last_wake = Some(t(950));
            parts.exit.state = ExitState::Preflight;
        }))),
        [
            (
                t(900),
                MacEventKind::Slept {
                    drain: DrainOutcome::Completed
                }
            ),
            (t(950), MacEventKind::Woke),
        ]
    );
}

#[test]
fn a_nodes_run_of_failed_polls_is_one_event_at_its_first_failure() {
    let mut seen = MacSeen::default();
    seen.changes(&status(|_| {}));
    let with = |lon1: NodeAgentState, ams1: NodeAgentState| {
        status(|parts| {
            set_agent(parts, "lon1", lon1);
            set_agent(parts, "ams1", ams1);
        })
    };
    // A node's first answer is no event; its first failure is, at the
    // failure, and each node is told apart.
    assert_eq!(seen.changes(&with(reported(t(10)), reported(t(10)))), []);
    assert_eq!(
        kinds(&seen.changes(&with(
            unreachable(t(20), AgentUnreachable::Transport),
            unreachable(t(25), AgentUnreachable::Timeout),
        ))),
        [
            (
                t(25),
                MacEventKind::NodeUnreachable {
                    node: node("ams1"),
                    cause: AgentUnreachable::Timeout
                }
            ),
            (
                t(20),
                MacEventKind::NodeUnreachable {
                    node: node("lon1"),
                    cause: AgentUnreachable::Transport
                }
            ),
        ]
    );
    // The same run, failing otherwise, is not another event.
    assert_eq!(
        seen.changes(&with(
            unreachable(t(20), AgentUnreachable::AuthFailed),
            unreachable(t(25), AgentUnreachable::Timeout),
        )),
        []
    );
    // An answer ends the run, at the poll that was answered.
    assert_eq!(
        kinds(&seen.changes(&with(
            reported(t(30)),
            unreachable(t(25), AgentUnreachable::Timeout)
        ))),
        [(t(30), MacEventKind::NodeReachable { node: node("lon1") })]
    );
    // A run that starts at another time is another run, even when the
    // answer between the two was never shown.
    assert_eq!(
        kinds(&seen.changes(&with(
            unreachable(t(40), AgentUnreachable::Transport),
            unreachable(t(45), AgentUnreachable::Timeout),
        ))),
        [
            (
                t(45),
                MacEventKind::NodeUnreachable {
                    node: node("ams1"),
                    cause: AgentUnreachable::Timeout
                }
            ),
            (
                t(40),
                MacEventKind::NodeUnreachable {
                    node: node("lon1"),
                    cause: AgentUnreachable::Transport
                }
            ),
        ]
    );
    // A node that is not polled is forgotten: its next answer is a first
    // answer again.
    assert_eq!(
        seen.changes(&with(
            NodeAgentState::NotPolled,
            unreachable(t(45), AgentUnreachable::Timeout)
        )),
        []
    );
    assert_eq!(
        seen.changes(&with(
            reported(t(60)),
            unreachable(t(45), AgentUnreachable::Timeout)
        )),
        []
    );
    // A node the status no longer has is forgotten too.
    let without_ams1 = status(|parts| {
        parts.nodes.remove(&node("ams1"));
        for row in parts.users.values_mut() {
            row.nodes.remove(&node("ams1"));
        }
        set_agent(parts, "lon1", reported(t(60)));
    });
    assert_eq!(seen.changes(&without_ams1), []);
    assert_eq!(seen.changes(&with(reported(t(60)), reported(t(70)))), []);
}

/// The fixture document: one entry of every variant, in time order.
fn fixture() -> EventsDocument {
    let mut kinds = vec![
        MacEventKind::DaemonStarted,
        MacEventKind::PowerSource {
            source: PowerSource::Ac,
        },
        MacEventKind::PowerSource {
            source: PowerSource::Battery,
        },
    ];
    kinds.extend(
        [
            DrainOutcome::Completed,
            DrainOutcome::TimedOut,
            DrainOutcome::Failed,
        ]
        .map(|drain| MacEventKind::Slept { drain }),
    );
    kinds.push(MacEventKind::Woke);
    let mut phases = vec![
        ExitPhase::Disabled,
        ExitPhase::Preflight,
        ExitPhase::Starting,
        ExitPhase::Verifying,
        ExitPhase::Serving,
        ExitPhase::Degraded {
            reasons: every_degraded_kind(),
        },
    ];
    phases.extend(
        DownReasonKind::ALL
            .iter()
            .map(|reason| ExitPhase::Down { reason: *reason }),
    );
    phases.push(ExitPhase::Paused);
    kinds.extend(phases.into_iter().map(|phase| MacEventKind::Exit { phase }));
    kinds.extend(agent_unreachable_causes().into_iter().map(|cause| {
        MacEventKind::NodeUnreachable {
            node: node("lon1"),
            cause,
        }
    }));
    kinds.push(MacEventKind::NodeReachable { node: node("lon1") });
    let mut entries: Vec<JournalEntry> = kinds
        .into_iter()
        .zip(0..)
        .map(|(kind, minute)| mac(minute * 60, kind))
        .collect();
    let start = entries.len() as u64 * 60;
    let mut node_kinds: Vec<AgentEventKind> = watch_errors()
        .into_iter()
        .map(|condition| AgentEventKind::ConditionRaised { condition })
        .collect();
    node_kinds.extend(WatchErrorKind::ALL.iter().map(|condition| {
        AgentEventKind::ConditionCleared {
            condition: *condition,
        }
    }));
    node_kinds.extend([AgentEventKind::GateOpened, AgentEventKind::GateClosed]);
    node_kinds.extend(
        GateReason::ALL
            .iter()
            .map(|hold| AgentEventKind::HoldRecorded { hold: *hold }),
    );
    node_kinds.extend(
        GateReason::ALL
            .iter()
            .map(|hold| AgentEventKind::HoldCleared { hold: *hold }),
    );
    node_kinds.extend(
        ShutdownReason::ALL
            .iter()
            .map(|reason| AgentEventKind::Halted { reason: *reason }),
    );
    node_kinds.extend([
        AgentEventKind::Resumed {
            generation: Generation::new(7),
        },
        AgentEventKind::Committed {
            generation: Generation::new(8),
        },
    ]);
    node_kinds.extend(
        EngineUser::ALL
            .iter()
            .map(|engine| AgentEventKind::EngineRestarted { engine: *engine }),
    );
    node_kinds.push(AgentEventKind::HostBooted);
    // Read after the node's last event, numbered from 2: the two before
    // were pruned, and the journal was later reset.
    let read_at = t(start + node_kinds.len() as u64 * 60);
    entries.extend(node_kinds.into_iter().zip(0..).map(|(kind, number)| {
        on_node(
            "lon1",
            NodeLine {
                read_at,
                entry: NodeEntry::Event(AgentEvent {
                    seq: seq(number + 2),
                    at: wt(start + number * 60),
                    kind,
                }),
            },
        )
    }));
    for entry in [
        NodeEntry::Gap {
            from: seq(0),
            to: seq(2),
        },
        NodeEntry::Reset { end: seq(42) },
    ] {
        entries.push(on_node("lon1", NodeLine { read_at, entry }));
    }
    EventsDocument::new(
        date("2026-11-15"),
        date("2026-11-15"),
        entries,
        vec![
            JournalDay {
                node: None,
                day: date("2026-11-15"),
            },
            JournalDay {
                node: Some(node("lon1")),
                day: date("2026-11-15"),
            },
        ],
    )
}

/// Every cause of an unreachable agent, in declaration order.
fn agent_unreachable_causes() -> Vec<AgentUnreachable> {
    vec![
        AgentUnreachable::Spawn,
        AgentUnreachable::HostKeyMismatch,
        AgentUnreachable::AuthFailed,
        AgentUnreachable::Transport,
        AgentUnreachable::Timeout,
        AgentUnreachable::ProtocolMismatch,
        AgentUnreachable::Decode,
        AgentUnreachable::ResponseTooLarge,
        AgentUnreachable::ForcedCommandNotActive,
    ]
}

/// The fixture file's content: the pretty-printed document and a newline.
fn encode(document: &EventsDocument) -> String {
    let mut text = serde_json::to_string_pretty(document).unwrap();
    text.push('\n');
    text
}

#[test]
fn the_events_fixture_is_what_its_builder_generates() {
    let document = fixture();
    assert!(
        encode(&document).as_bytes() == FIXTURE,
        "contract/events-fixtures/events.json is not what `fixture` generates"
    );
    let decoded: EventsDocument = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(decoded, document);
    assert!(encode(&decoded).as_bytes() == FIXTURE);
}

/// The fixture holds every variant: the matches are exhaustive, so a new
/// variant stops this from compiling until the fixture holds it.
#[test]
fn the_events_fixture_lists_every_variant() {
    let document: EventsDocument = serde_json::from_slice(FIXTURE).unwrap();
    let mut mac_kinds = Vec::new();
    let mut phases = Vec::new();
    let mut downs = Vec::new();
    let mut causes = Vec::new();
    let mut node_entries = Vec::new();
    let mut agent_kinds = Vec::new();
    for entry in document.entries() {
        match entry {
            JournalEntry::Mac(event) => {
                mac_kinds.push(match &event.kind {
                    MacEventKind::DaemonStarted => 0,
                    MacEventKind::PowerSource { .. } => 1,
                    MacEventKind::Slept { .. } => 2,
                    MacEventKind::Woke => 3,
                    MacEventKind::Exit { phase } => {
                        phases.push(match phase {
                            ExitPhase::Disabled => 0,
                            ExitPhase::Preflight => 1,
                            ExitPhase::Starting => 2,
                            ExitPhase::Verifying => 3,
                            ExitPhase::Serving => 4,
                            ExitPhase::Degraded { reasons } => {
                                assert_eq!(*reasons, every_degraded_kind());
                                5
                            }
                            ExitPhase::Down { reason } => {
                                downs.push(*reason);
                                6
                            }
                            ExitPhase::Paused => 7,
                        });
                        4
                    }
                    MacEventKind::NodeUnreachable { cause, .. } => {
                        causes.push(*cause);
                        5
                    }
                    MacEventKind::NodeReachable { .. } => 6,
                });
            }
            JournalEntry::Node { line, .. } => node_entries.push(match line.entry {
                NodeEntry::Event(event) => {
                    agent_kinds.push(match event.kind {
                        AgentEventKind::ConditionRaised { .. } => 0,
                        AgentEventKind::ConditionCleared { .. } => 1,
                        AgentEventKind::GateOpened => 2,
                        AgentEventKind::GateClosed => 3,
                        AgentEventKind::HoldRecorded { .. } => 4,
                        AgentEventKind::HoldCleared { .. } => 5,
                        AgentEventKind::Halted { .. } => 6,
                        AgentEventKind::Resumed { .. } => 7,
                        AgentEventKind::Committed { .. } => 8,
                        AgentEventKind::EngineRestarted { .. } => 9,
                        AgentEventKind::HostBooted => 10,
                    });
                    0
                }
                NodeEntry::Gap { .. } => 1,
                NodeEntry::Reset { .. } => 2,
            }),
        }
    }
    mac_kinds.dedup();
    phases.dedup();
    node_entries.sort_unstable();
    node_entries.dedup();
    agent_kinds.dedup();
    assert_eq!(mac_kinds, (0..7).collect::<Vec<_>>());
    assert_eq!(phases, (0..8).collect::<Vec<_>>());
    assert_eq!(downs, DownReasonKind::ALL);
    assert_eq!(causes, agent_unreachable_causes());
    assert_eq!(node_entries, (0..3).collect::<Vec<_>>());
    assert_eq!(agent_kinds, (0..11).collect::<Vec<_>>());
    assert_eq!(document.incomplete_days().len(), 2);
    // Each agent kind's data comes in every variant: the watch errors and
    // their kinds, the holds, the halts and the engines.
    let count = |wanted: fn(&AgentEventKind) -> bool| {
        document
            .entries()
            .iter()
            .filter(|entry| {
                matches!(entry, JournalEntry::Node { line: NodeLine { entry: NodeEntry::Event(event), .. }, .. } if wanted(&event.kind))
            })
            .count()
    };
    assert_eq!(
        count(|kind| matches!(kind, AgentEventKind::ConditionRaised { .. })),
        watch_errors().len()
    );
    assert_eq!(
        count(|kind| matches!(kind, AgentEventKind::ConditionCleared { .. })),
        WatchErrorKind::ALL.len()
    );
    assert_eq!(
        count(|kind| matches!(kind, AgentEventKind::HoldRecorded { .. })),
        GateReason::ALL.len()
    );
    assert_eq!(
        count(|kind| matches!(kind, AgentEventKind::Halted { .. })),
        ShutdownReason::ALL.len()
    );
    assert_eq!(
        count(|kind| matches!(kind, AgentEventKind::EngineRestarted { .. })),
        EngineUser::ALL.len()
    );
}

#[test]
fn every_object_of_the_events_fixture_denies_unknown_keys() {
    let objects = each_object_denies_unknown_keys::<EventsDocument>(FIXTURE);
    assert!(objects > 200, "{objects}");
}
