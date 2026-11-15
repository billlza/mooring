// SPDX-License-Identifier: GPL-3.0-or-later

//! `events` (design §15.7): the Mac's journal and the nodes' copies read
//! through the store and printed as the document the app reads, or as
//! text; the range's rules; the days being the files'; the bound; what a
//! corrupt line does; and that the command never writes.

use std::fs;
use std::path::Path;

use mooring_daemon_core::events::{
    EventsDocument, JournalEntry, MacEvent, MacEventKind, NodeEntry, NodeLine, encode_mac_line,
    encode_node_line,
};
use mooring_model::{CalendarDate, NodeId, UnixTime};
use mooring_store::{
    EVENTS_DIRECTORY, append_mac_events, append_node_events, mac_events_path, node_events_path,
};

use super::support::{Harness, NOW};
use crate::error::EXIT_LOCAL;

const FIXTURE: &[u8] = include_bytes!("../../../../contract/events-fixtures/events.json");

/// The fixture's day, 2026-11-15, at noon UTC.
const FIXTURE_NOON: u64 = 1_794_744_000;

fn day(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn fixture() -> EventsDocument {
    serde_json::from_slice(FIXTURE).unwrap()
}

/// Makes the support directory, which is the daemon's to make.
fn support(harness: &Harness) -> std::path::PathBuf {
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    support
}

/// Appends `entries` to their files: a Mac event to its day's, a node's
/// line to its read's day's.
fn plant(support: &Path, entries: &[JournalEntry]) {
    for entry in entries {
        match entry {
            JournalEntry::Mac(event) => append_mac_events(
                support,
                CalendarDate::utc_of(event.at).unwrap(),
                &encode_mac_line(event).unwrap(),
            )
            .unwrap(),
            JournalEntry::Node { node, line } => append_node_events(
                support,
                node,
                CalendarDate::utc_of(line.read_at).unwrap(),
                &encode_node_line(line).unwrap(),
            )
            .unwrap(),
        }
    }
}

/// Ends `path` in a torn line, as a write in progress.
fn tear(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes.extend_from_slice(b"{\"version\":1,\"at\":17");
    fs::write(path, bytes).unwrap();
}

/// Every entry of the contract fixture, planted in the day files, is read
/// back as the fixture itself: the command is what produces it.
#[test]
fn the_files_of_the_fixtures_entries_are_read_back_as_the_fixture() {
    let mut harness = Harness::new(0);
    harness.now.set(FIXTURE_NOON);
    let support = support(&harness);
    plant(&support, fixture().entries());
    tear(&mac_events_path(&support, day("2026-11-15")));
    tear(&node_events_path(
        &support,
        &node("lon1"),
        day("2026-11-15"),
    ));
    let outcome = harness.run(&[
        "events",
        "--json",
        "--since",
        "2026-11-15",
        "--until",
        "2026-11-15",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!("{}\n", serde_json::to_string(&fixture()).unwrap())
    );
    assert_eq!(outcome.stdout.matches('\n').count(), 1);
    // The files were left as they were: the torn lines stay.
    assert!(
        fs::read(mac_events_path(&support, day("2026-11-15")))
            .unwrap()
            .ends_with(b"\"at\":17")
    );
}

/// The text of the fixture's entries: a line per entry in time order,
/// then the files that end in an incomplete line.
#[test]
fn the_text_lists_every_entry_in_time_order() {
    let mut harness = Harness::new(0);
    harness.now.set(FIXTURE_NOON);
    let support = support(&harness);
    plant(&support, fixture().entries());
    tear(&mac_events_path(&support, day("2026-11-15")));
    tear(&node_events_path(
        &support,
        &node("lon1"),
        day("2026-11-15"),
    ));
    let outcome = harness.run(&["events", "--since", "2026-11-15"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, include_str!("golden/events.txt"));
}

/// Without dates the range is the last seven days; `--since` alone runs to
/// today, `--until` alone from six days before it; days without a file
/// are empty, and nothing is made for them.
#[test]
fn the_range_defaults_to_the_last_seven_days_and_absent_days_are_empty() {
    let mut harness = Harness::new(0);
    let empty = |since: &str, until: &str| {
        format!(
            "{{\"version\":1,\"since\":\"{since}\",\"until\":\"{until}\",\"entries\":[],\"omitted\":0,\"incomplete_days\":[]}}\n"
        )
    };
    for (args, since, until) in [
        (vec![], "2026-10-07", "2026-10-13"),
        (vec!["--since", "2026-10-10"], "2026-10-10", "2026-10-13"),
        (vec!["--until", "2026-10-10"], "2026-10-04", "2026-10-10"),
        (
            vec!["--since", "2026-10-13", "--until", "2026-10-13"],
            "2026-10-13",
            "2026-10-13",
        ),
        // The most the journals keep: 393 days.
        (
            vec!["--since", "2025-09-16", "--until", "2026-10-13"],
            "2025-09-16",
            "2026-10-13",
        ),
    ] {
        let mut full = vec!["events", "--json"];
        full.extend(args.iter().copied());
        let outcome = harness.run(&full);
        assert_eq!(outcome.code, 0, "{args:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, empty(since, until), "{args:?}");
    }
    assert!(!harness.support_dir().join(EVENTS_DIRECTORY).exists());
    let outcome = harness.run(&["events"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "events 2026-10-07 to 2026-10-13 UTC: 0 entries\n"
    );
}

/// A range that runs backwards, or over more days than the journals keep,
/// is refused before any file is read.
#[test]
fn a_range_that_is_inverted_or_too_long_is_refused() {
    let mut harness = Harness::new(0);
    for (args, text) in [
        (
            vec!["--since", "2026-10-14"],
            "mooringctl: --since 2026-10-14 is after --until 2026-10-13\n",
        ),
        (
            vec!["--since", "2025-09-15", "--until", "2026-10-13"],
            "mooringctl: the range covers 394 days; at most 393 can be read at once (narrow it with --since and --until)\n",
        ),
    ] {
        let mut full = vec!["events"];
        full.extend(args.iter().copied());
        let outcome = harness.run(&full);
        assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, text);
    }
}

/// The days are the files': the Mac's events of those days, and what the
/// daemon read of a node on those days, whose events can be older; each
/// is listed by its own time.
#[test]
fn the_days_are_those_of_the_files() {
    let mut harness = Harness::new(0);
    let support = support(&harness);
    let at = UnixTime::from_secs;
    let before_the_range = MacEvent {
        at: at(NOW - 8 * 86_400),
        kind: MacEventKind::Woke,
    };
    let started = MacEvent {
        at: at(NOW - 60),
        kind: MacEventKind::DaemonStarted,
    };
    // Read today, of an event ten days old.
    let booted = mooring_agent_proto::AgentEvent {
        seq: mooring_agent_proto::EventSeq::new(0),
        at: mooring_agent_proto::UnixTime::from_secs(NOW - 10 * 86_400),
        kind: mooring_agent_proto::AgentEventKind::HostBooted,
    };
    let read = NodeLine {
        read_at: at(NOW),
        entry: NodeEntry::Event(booted),
    };
    plant(
        &support,
        &[
            JournalEntry::Mac(before_the_range),
            JournalEntry::Mac(started.clone()),
            JournalEntry::Node {
                node: node("lon1"),
                line: read,
            },
        ],
    );
    let outcome = harness.run(&["events", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let document: EventsDocument = serde_json::from_str(outcome.stdout.trim_end()).unwrap();
    assert_eq!(
        document.entries(),
        [
            JournalEntry::Node {
                node: node("lon1"),
                line: read,
            },
            JournalEntry::Mac(started),
        ]
    );
}

/// Past the bound, the newest entries are listed, and the older ones
/// counted.
#[test]
fn past_its_bound_the_newest_entries_are_listed() {
    let mut harness = Harness::new(0);
    let support = support(&harness);
    let mut lines = Vec::new();
    for secs in 0..5_003 {
        lines.extend(
            encode_mac_line(&MacEvent {
                at: UnixTime::from_secs(NOW - 6_000 + secs),
                kind: MacEventKind::Woke,
            })
            .unwrap(),
        );
    }
    append_mac_events(&support, day("2026-10-13"), &lines).unwrap();
    let outcome = harness.run(&["events", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let document: EventsDocument = serde_json::from_str(outcome.stdout.trim_end()).unwrap();
    assert_eq!(document.omitted(), 3);
    assert_eq!(document.entries().len(), 5_000);
    assert_eq!(
        document.entries()[0].at(),
        UnixTime::from_secs(NOW - 6_000 + 3)
    );
    let outcome = harness.run(&["events"]);
    assert!(
        outcome.stdout.starts_with(
            "events 2026-10-07 to 2026-10-13 UTC: 5000 entries (the newest; 3 older left out)\n"
        ),
        "{}",
        &outcome.stdout[..200]
    );
}

/// A line the decoder refuses is a typed error naming the file and the
/// line, never its bytes; nothing is printed, in either form, and the file
/// is left as it is.
#[test]
fn a_corrupt_line_is_a_typed_error_naming_file_and_line() {
    let mut harness = Harness::new(0);
    let support = support(&harness);
    let started = MacEvent {
        at: UnixTime::from_secs(NOW),
        kind: MacEventKind::DaemonStarted,
    };
    let line = encode_mac_line(&started).unwrap();
    let mut bytes = line.clone();
    bytes.extend_from_slice(b"not json canary\n");
    append_mac_events(&support, day("2026-10-13"), &bytes).unwrap();
    let path = mac_events_path(&support, day("2026-10-13"));
    for args in [&["events"][..], &["events", "--json"]] {
        let outcome = harness.run(args);
        assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
        assert_eq!(outcome.stdout, "");
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: event journal file {} cannot be read at line 2\n  caused by: an event journal line is not an entry of its journal\n",
                path.display()
            )
        );
        assert!(!outcome.stderr.contains("canary"));
    }
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // A node's copy: a Mac line there is not one of its lines.
    fs::write(&path, &line).unwrap();
    append_node_events(&support, &node("ams1"), day("2026-10-12"), &line).unwrap();
    let outcome = harness.run(&["events"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: event journal file {} cannot be read at line 1\n  caused by: an event journal line is not an entry of its journal\n",
            node_events_path(&support, &node("ams1"), day("2026-10-12")).display()
        )
    );
}
