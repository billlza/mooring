// SPDX-License-Identifier: GPL-3.0-or-later

//! The nodes' event journals read into the Mac's copies (design §15.7),
//! through the real store and the scripted sessions: the first read from
//! the journal's start, the number asked from after the copy's newest line
//! (in memory, and from the file at a run's first read or after a failed
//! append), a page that holds more asked for at once, pruned events as a
//! gap, a reset journal read again, the day file the lines go to, which
//! nodes are read and in what order, the request's deadline, and each
//! failure logged once while it lasts.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    AgentEvent, AgentEventKind, EventSeq, EventsV1, LineRequest, RequestKind, Response,
    UnixTime as WireTime,
};
use mooring_daemon_core::events::{NodeEntry, NodeLine, decode_node_line, encode_node_line};
use mooring_model::node::NodeLifecycle;
use mooring_model::{CalendarDate, Deployment, NodeId, UnixTime};
use mooring_store::{append_node_events, node_events_path, read_node_events};

use super::support::{Answered, Expected, ExpectedRemote, Harness, NOW, PINNED, Sent, lo0_name};
use super::user::{fixture, harness_with};
use crate::daemon::node_events::NodeEvents;
use crate::node::NodeError;

/// The interval of a node read once.
const ONCE: Duration = Duration::from_secs(300);

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn day(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

/// The fixed clock's day.
fn today() -> CalendarDate {
    day("2026-10-13")
}

fn seq(number: u64) -> EventSeq {
    EventSeq::new(number)
}

/// The node's event numbered `number`, recorded `number` seconds into the
/// fixed clock's day.
fn event(number: u64) -> AgentEvent {
    AgentEvent {
        seq: seq(number),
        at: WireTime::from_secs(NOW - 19 * 3600 + number),
        kind: AgentEventKind::GateOpened,
    }
}

/// The page of the events numbered `numbers`, before `end`.
fn page(numbers: std::ops::Range<u64>, end: u64) -> Result<Response, NodeError> {
    Ok(Response::Events(Box::new(
        EventsV1::new(numbers.map(event).collect(), seq(end)).unwrap(),
    )))
}

/// The lines of the events numbered `numbers`, read at the fixed clock.
fn read(numbers: std::ops::Range<u64>) -> Vec<NodeLine> {
    numbers
        .map(|number| NodeLine {
            read_at: UnixTime::from_secs(NOW),
            entry: NodeEntry::Event(event(number)),
        })
        .collect()
}

fn line_at(read_at: UnixTime, entry: NodeEntry) -> NodeLine {
    NodeLine { read_at, entry }
}

/// The fixture with ams1 planned: lon1 alone is read.
fn lon1_alone() -> Deployment {
    fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|candidate| candidate.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
    })
}

/// A harness on `deployment` facing the M7, and a reader whose first read
/// is due at once.
fn ready(deployment: &Deployment) -> (Harness, NodeEvents) {
    let mut harness = harness_with(deployment.clone());
    harness.pin(PINNED);
    let reader = NodeEvents::open(&harness.support_dir(), Duration::ZERO);
    (harness, reader)
}

/// Scripts the next `Events` answer.
fn answer(harness: &Harness, reply: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Events,
        },
        Answered::Replied(reply),
    );
}

/// One tick with `interval`: whether a node was asked, and the log.
fn tick(
    harness: &mut Harness,
    reader: &mut NodeEvents,
    deployment: &Deployment,
    interval: Duration,
) -> (bool, String) {
    let mut log = Vec::new();
    let asked = harness.with_env(|env| {
        reader
            .tick(
                env,
                &mut log,
                deployment,
                &lo0_name(),
                Duration::from_secs(10),
                interval,
            )
            .unwrap()
    });
    (asked, String::from_utf8(log).unwrap())
}

/// The numbers asked from, and the node asked, in order.
fn asked(harness: &Harness) -> Vec<(String, u64)> {
    harness
        .nodes
        .seen
        .borrow()
        .iter()
        .map(|(target, sent)| match sent {
            Sent::Request(LineRequest::Events { since }) => (
                target
                    .relay_dir
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                since.get(),
            ),
            other => panic!("{other:?}"),
        })
        .collect()
}

/// lon1's copy's lines of `date`.
fn copy(harness: &Harness, date: CalendarDate) -> Vec<NodeLine> {
    read_node_events(&harness.support_dir(), &node("lon1"), date)
        .unwrap()
        .map_or_else(Vec::new, |day| {
            day.lines
                .split_inclusive(|&byte| byte == b'\n')
                .map(|line| decode_node_line(line).unwrap())
                .collect()
        })
}

/// Puts `lines` in lon1's copy's file of `date`, as an earlier run left
/// them.
fn plant(harness: &Harness, date: CalendarDate, lines: &[NodeLine]) {
    let bytes: Vec<u8> = lines
        .iter()
        .flat_map(|line| encode_node_line(line).unwrap())
        .collect();
    append_node_events(&harness.support_dir(), &node("lon1"), date, &bytes).unwrap();
}

fn earlier(secs: u64) -> UnixTime {
    UnixTime::from_secs(NOW - secs)
}

/// A node no line of which is kept is read from its journal's first
/// number, whatever the node pruned, into the file of the read's day; it
/// is not read again before the interval, and nothing is logged.
#[test]
fn a_node_is_read_from_its_journals_start_into_the_day_of_the_read() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    answer(&harness, page(3..6, 6));
    assert_eq!(
        tick(&mut harness, &mut reader, &deployment, ONCE),
        (true, String::new())
    );
    assert_eq!(asked(&harness), [("lon1".to_owned(), 0)]);
    assert_eq!(copy(&harness, today()), read(3..6));
    assert_eq!(
        tick(&mut harness, &mut reader, &deployment, ONCE),
        (false, String::new())
    );
    assert_eq!(asked(&harness).len(), 1);
}

/// The run's first read waits an interval after the daemon opened.
#[test]
fn the_first_read_waits_an_interval_after_the_daemon_opened() {
    let deployment = lon1_alone();
    let (mut harness, _) = ready(&deployment);
    let mut reader = NodeEvents::open(&harness.support_dir(), ONCE);
    assert_eq!(
        tick(&mut harness, &mut reader, &deployment, Duration::ZERO),
        (false, String::new())
    );
    assert!(harness.nodes.seen.borrow().is_empty());
}

/// A copy an earlier run left asks on after its newest line, in its newest
/// day file that holds one; a page that leaves events after it is followed
/// at once by the next, while one that reaches the journal's end is not.
#[test]
fn a_copy_asks_on_after_its_newest_line_and_again_at_once_while_more_is_held() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    let gap = line_at(
        earlier(86_400),
        NodeEntry::Gap {
            from: seq(0),
            to: seq(9),
        },
    );
    let older = line_at(
        earlier(86_400),
        NodeEntry::Event(AgentEvent {
            seq: seq(9),
            ..event(0)
        }),
    );
    plant(&harness, day("2026-10-12"), &[gap, older]);
    // A newer day file that holds only a torn line gives no number.
    let torn = node_events_path(&harness.support_dir(), &node("lon1"), today());
    fs::write(&torn, b"{\"version\":1,\"read_").unwrap();
    answer(&harness, page(10..12, 20));
    answer(&harness, page(12..20, 20));
    for _ in 0..3 {
        tick(&mut harness, &mut reader, &deployment, ONCE);
    }
    assert_eq!(
        asked(&harness),
        [("lon1".to_owned(), 10), ("lon1".to_owned(), 12)]
    );
    // The torn line was cut by the first append.
    assert_eq!(copy(&harness, today()), read(10..20));
    assert_eq!(copy(&harness, day("2026-10-12")), [gap, older]);
}

/// Events the node pruned before the Mac read them are a gap before the
/// rest; a journal that ends before the number asked from was reset, and
/// is read again from its start at once.
#[test]
fn pruned_events_are_a_gap_and_a_reset_journal_is_read_again_from_its_start() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    plant(
        &harness,
        today(),
        &[line_at(earlier(60), NodeEntry::Event(event(4)))],
    );
    answer(&harness, page(8..10, 10));
    answer(&harness, page(0..0, 3));
    answer(&harness, page(0..3, 3));
    for _ in 0..3 {
        tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    }
    assert_eq!(
        asked(&harness),
        [
            ("lon1".to_owned(), 5),
            ("lon1".to_owned(), 10),
            ("lon1".to_owned(), 0)
        ]
    );
    let now = UnixTime::from_secs(NOW);
    let mut expected = vec![
        line_at(earlier(60), NodeEntry::Event(event(4))),
        line_at(
            now,
            NodeEntry::Gap {
                from: seq(5),
                to: seq(8),
            },
        ),
    ];
    expected.extend(read(8..10));
    expected.push(line_at(now, NodeEntry::Reset { end: seq(3) }));
    expected.extend(read(0..3));
    assert_eq!(copy(&harness, today()), expected);
    // Nothing new is no line.
    answer(&harness, page(0..0, 3));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert_eq!(asked(&harness).last(), Some(&("lon1".to_owned(), 3)));
    assert_eq!(copy(&harness, today()), expected);
}

/// The lines go to the file of the read's day, or of the copy's newest day
/// when the clock reads an earlier one, so the newest line stays in the
/// newest file.
#[test]
fn the_lines_go_to_the_copys_newest_day_when_the_clock_reads_an_earlier_one() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    let later = line_at(
        UnixTime::from_secs(NOW + 86_400),
        NodeEntry::Event(event(1)),
    );
    plant(&harness, day("2026-10-14"), &[later]);
    answer(&harness, page(2..3, 3));
    answer(&harness, page(3..4, 4));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    let mut expected = vec![later];
    expected.extend(read(2..3));
    assert_eq!(copy(&harness, day("2026-10-14")), expected);
    assert_eq!(copy(&harness, today()), []);
    // The run remembers the newest day as well as the number.
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    expected.extend(read(3..4));
    assert_eq!(copy(&harness, day("2026-10-14")), expected);
    assert_eq!(copy(&harness, today()), []);
    // On the clock's next day the lines go to that day's file.
    harness.now.set(NOW + 2 * 86_400);
    answer(&harness, page(4..5, 5));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    let next_day = line_at(
        UnixTime::from_secs(NOW + 2 * 86_400),
        NodeEntry::Event(event(4)),
    );
    assert_eq!(copy(&harness, day("2026-10-15")), [next_day]);
    // That day is the copy's newest now: with the clock back on an earlier
    // one, the lines go to its file.
    harness.now.set(NOW);
    answer(&harness, page(5..6, 6));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    let mut newest = vec![next_day];
    newest.extend(read(5..6));
    assert_eq!(copy(&harness, day("2026-10-15")), newest);
    assert_eq!(copy(&harness, day("2026-10-14")), expected);
    assert_eq!(copy(&harness, today()), []);
}

/// A newer day file that holds no whole line is the copy's newest day all
/// the same, whether an older file holds one or none does: with the clock
/// on an earlier day, the lines go to it, its torn line cut.
#[test]
fn a_newer_day_file_without_a_whole_line_is_still_the_copys_newest_day() {
    let deployment = lon1_alone();
    let older = line_at(earlier(86_400), NodeEntry::Event(event(1)));
    for (planted, numbers) in [(vec![older], 2..3), (Vec::new(), 0..1)] {
        let (mut harness, mut reader) = ready(&deployment);
        plant(&harness, day("2026-10-12"), &planted);
        let torn = node_events_path(&harness.support_dir(), &node("lon1"), day("2026-10-14"));
        fs::write(&torn, b"{\"version\":1,\"read_").unwrap();
        answer(&harness, page(numbers.clone(), numbers.end));
        tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
        assert_eq!(asked(&harness), [("lon1".to_owned(), numbers.start)]);
        assert_eq!(copy(&harness, day("2026-10-14")), read(numbers));
        assert_eq!(copy(&harness, today()), []);
        assert_eq!(copy(&harness, day("2026-10-12")), planted);
    }
}

/// A failed read, a page of another kind or a refused page is logged once
/// while it lasts, and the end of it once; the node is read again an
/// interval later, from where its copy stands.
#[test]
fn a_failure_is_logged_once_while_it_lasts_and_the_node_is_read_again_an_interval_later() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    plant(
        &harness,
        today(),
        &[line_at(earlier(60), NodeEntry::Event(event(4)))],
    );
    let mut ask = |harness: &mut Harness, reply, interval| {
        answer(harness, reply);
        let (was_asked, log) = tick(harness, &mut reader, &deployment, interval);
        assert!(was_asked);
        log
    };
    let deadline = "lon1: its event journal was not read: the node could not be reached or refused: the ssh session was ended at its deadline, before a whole reply\n";
    let log = ask(&mut harness, Err(NodeError::PastDeadline), Duration::ZERO);
    assert!(log.ends_with(deadline), "{log}");
    assert_eq!(
        ask(&mut harness, Err(NodeError::PastDeadline), Duration::ZERO),
        ""
    );
    let log = ask(&mut harness, Ok(Response::BootstrapRevoked), Duration::ZERO);
    assert!(
        log.ends_with("lon1: the agent answered Events with BootstrapRevoked\n"),
        "{log}"
    );
    let log = ask(&mut harness, page(2..6, 6), Duration::ZERO);
    assert!(
        log.ends_with("lon1: its event journal's page was refused: the node's page starts at event 2, before event 5 that was asked for\n"),
        "{log}"
    );
    assert_eq!(ask(&mut harness, page(2..6, 6), Duration::ZERO), "");
    let log = ask(&mut harness, page(5..6, 6), Duration::ZERO);
    assert!(
        log.ends_with("lon1: its event journal is read again\n"),
        "{log}"
    );
    assert_eq!(ask(&mut harness, page(6..7, 7), Duration::ZERO), "");
    // A failure with an interval: logged, and not asked again before it.
    let log = ask(&mut harness, Err(NodeError::PastDeadline), ONCE);
    assert!(log.ends_with(deadline), "{log}");
    assert_eq!(
        tick(&mut harness, &mut reader, &deployment, ONCE),
        (false, String::new())
    );
    assert_eq!(
        asked(&harness)
            .iter()
            .map(|(_, since)| *since)
            .collect::<Vec<_>>(),
        [5, 5, 5, 5, 5, 5, 6, 7]
    );
    let mut expected = vec![line_at(earlier(60), NodeEntry::Event(event(4)))];
    expected.extend(read(5..7));
    assert_eq!(copy(&harness, today()), expected);
}

/// A copy whose newest line cannot be read is not asked for: the node is
/// not read, and that is logged once, until the file is put right.
#[test]
fn a_copy_whose_newest_line_cannot_be_read_is_not_asked_for() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    plant(&harness, today(), &read(0..1));
    let path = node_events_path(&harness.support_dir(), &node("lon1"), today());
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"not json canary\n");
    fs::write(&path, &bytes).unwrap();
    let (was_asked, log) = tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert!(!was_asked);
    assert!(
        log.ends_with(&format!(
            "lon1: the copy of its event journal cannot be read: event journal file {} cannot be read at line 2: an event journal line is not an entry of its journal\n",
            path.display()
        )),
        "{log}"
    );
    assert!(!log.contains("canary"));
    assert_eq!(
        tick(&mut harness, &mut reader, &deployment, Duration::ZERO),
        (false, String::new())
    );
    // An event with the last number there is leaves none to ask from.
    let last = NodeLine {
        read_at: UnixTime::from_secs(NOW),
        entry: NodeEntry::Event(AgentEvent {
            seq: seq(u64::MAX),
            ..event(0)
        }),
    };
    fs::write(&path, encode_node_line(&last).unwrap()).unwrap();
    let (was_asked, log) = tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert!(!was_asked);
    assert!(
        log.ends_with("cannot be read at line 1: the newest event of a node's copy has the last number there is\n"),
        "{log}"
    );
    assert!(harness.nodes.seen.borrow().is_empty());
    // Put right, the copy is read again.
    fs::write(&path, encode_node_line(&read(0..1)[0]).unwrap()).unwrap();
    answer(&harness, page(1..2, 2));
    let (was_asked, log) = tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert!(was_asked);
    assert!(
        log.ends_with("lon1: its event journal is read again\n"),
        "{log}"
    );
    assert_eq!(asked(&harness), [("lon1".to_owned(), 1)]);
}

/// An append that fails is logged, and the next read asks from where the
/// copy's file stands, not from what the run last appended.
#[test]
fn an_append_that_fails_sends_the_next_read_back_to_the_copys_file() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    answer(&harness, page(0..3, 3));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    let path = node_events_path(&harness.support_dir(), &node("lon1"), today());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    answer(&harness, page(3..5, 5));
    let (_, log) = tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert!(
        log.contains("lon1: its event journal was not written: the event journals' files failed: "),
        "{log}"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    // Only the first line is left: the next read asks after it.
    fs::write(&path, encode_node_line(&read(0..1)[0]).unwrap()).unwrap();
    answer(&harness, page(1..5, 5));
    tick(&mut harness, &mut reader, &deployment, Duration::ZERO);
    assert_eq!(
        asked(&harness)
            .iter()
            .map(|(_, since)| *since)
            .collect::<Vec<_>>(),
        [0, 3, 1]
    );
    assert_eq!(copy(&harness, today()), read(0..5));
}

/// Adopted and applied nodes are read, the one longest due first (a node
/// never read before any), each by its own copy; a node that leaves them
/// is forgotten, so its copy is read from its file when it comes back.
#[test]
fn adopted_and_applied_nodes_are_read_the_longest_due_first() {
    let both = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|candidate| candidate.id == node("ams1"))
            .unwrap();
        if let NodeLifecycle::Applied { site, .. } = &ams1.lifecycle {
            ams1.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
        }
    });
    let (mut harness, mut reader) = ready(&both);
    for _ in 0..3 {
        answer(&harness, page(0..1, 1));
    }
    for _ in 0..3 {
        tick(&mut harness, &mut reader, &both, Duration::ZERO);
    }
    assert_eq!(
        asked(&harness),
        [
            ("ams1".to_owned(), 0),
            ("lon1".to_owned(), 0),
            ("ams1".to_owned(), 1)
        ]
    );
    // ams1 planned: lon1 alone is read, and ams1's copy is forgotten.
    let lon1_only = lon1_alone();
    answer(&harness, page(1..2, 2));
    tick(&mut harness, &mut reader, &lon1_only, Duration::ZERO);
    assert_eq!(asked(&harness).last(), Some(&("lon1".to_owned(), 1)));
    // Back, ams1 asks from where its file stands: cut back to its start.
    let ams1_path = node_events_path(&harness.support_dir(), &node("ams1"), today());
    fs::write(&ams1_path, b"").unwrap();
    answer(&harness, page(0..1, 1));
    tick(&mut harness, &mut reader, &both, Duration::ZERO);
    assert_eq!(asked(&harness).last(), Some(&("ams1".to_owned(), 0)));
}

/// The request ends within the budget it is given.
#[test]
fn the_request_ends_within_its_budget() {
    let deployment = lon1_alone();
    let (mut harness, mut reader) = ready(&deployment);
    answer(&harness, page(0..0, 0));
    let began = Instant::now();
    tick(&mut harness, &mut reader, &deployment, ONCE);
    let seen = harness.nodes.seen.borrow();
    let deadline = seen[0].0.deadline.unwrap();
    assert!(deadline >= began + Duration::from_secs(10));
    assert!(deadline <= Instant::now() + Duration::from_secs(10));
}
