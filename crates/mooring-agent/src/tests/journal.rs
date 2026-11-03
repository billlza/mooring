// SPDX-License-Identifier: GPL-3.0-or-later

//! The event journal (design §15.7): numbered one apart and continued
//! across openings, a torn last line cut off, pruned from its oldest end,
//! and each way reading or writing it fails reported as such.

use std::fs;

use mooring_agent_proto::{AgentError, AgentEvent, AgentEventKind, EventSeq, IoOp, UnixTime};

use super::{EACCES, EEXIST, EISDIR, ModeFault, occupy_temporary, scratch};
use crate::journal::{self, Journal, MAX_KEPT, RETENTION_SECS};

#[test]
fn the_journal_continues_its_numbers_and_cuts_off_a_torn_line() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(
            UnixTime::from_secs(5),
            &[AgentEventKind::GateOpened, AgentEventKind::GateClosed],
        )
        .unwrap();
    let mut torn = fs::read(paths.journal()).unwrap();
    torn.extend_from_slice(br#"{"seq":2,"at":6,"ki"#);
    fs::write(paths.journal(), &torn).unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(page.events().len(), 2, "a reader ignores the torn line");
    assert_eq!(page.end(), EventSeq::new(2));
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(7), &[AgentEventKind::HostBooted])
        .unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST).unwrap().events(),
        &[
            event(0, 5, AgentEventKind::GateOpened),
            event(1, 5, AgentEventKind::GateClosed),
            event(2, 7, AgentEventKind::HostBooted),
        ]
    );
    let page = journal::page(&paths, EventSeq::new(9)).unwrap();
    assert!(page.events().is_empty());
    assert_eq!(page.end(), EventSeq::new(3));
    // A gap is refused rather than served.
    let text = fs::read_to_string(paths.journal()).unwrap();
    let gapped: String = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    fs::write(paths.journal(), gapped).unwrap();
    let refused = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    assert_eq!(journal::page(&paths, EventSeq::FIRST), Err(refused.clone()));
    assert_eq!(Journal::open(&paths).unwrap_err(), refused, "nor continued");
}

#[test]
fn the_journal_is_created_empty_and_group_readable_when_opened() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, paths) = scratch();
    let _journal = Journal::open(&paths).unwrap();
    let meta = fs::metadata(paths.journal()).unwrap();
    assert_eq!(meta.len(), 0);
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert!(page.events().is_empty());
    assert_eq!(page.end(), EventSeq::FIRST);
}

fn event(seq: u64, at: u64, kind: AgentEventKind) -> AgentEvent {
    AgentEvent {
        seq: EventSeq::new(seq),
        at: UnixTime::from_secs(at),
        kind,
    }
}

#[test]
fn the_journal_keeps_thirteen_months_and_a_bounded_count() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(1_000), &[AgentEventKind::GateOpened])
        .unwrap();
    journal
        .append(UnixTime::from_secs(2_000), &[AgentEventKind::GateClosed])
        .unwrap();
    journal
        .append(
            UnixTime::from_secs(1_000 + RETENTION_SECS),
            &[AgentEventKind::GateOpened],
        )
        .unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST)
            .unwrap()
            .events()
            .len(),
        3,
        "exactly 393 days old is kept"
    );
    journal
        .append(
            UnixTime::from_secs(1_001 + RETENTION_SECS),
            &[AgentEventKind::GateClosed],
        )
        .unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.seq.get())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // Long after, only the newest stays, so its number is never reused.
    journal
        .append(
            UnixTime::from_secs(10 * RETENTION_SECS),
            &[AgentEventKind::HostBooted],
        )
        .unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(
        page.events(),
        &[event(4, 10 * RETENTION_SECS, AgentEventKind::HostBooted)]
    );
    assert_eq!(page.end(), EventSeq::new(5));

    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    let many = vec![AgentEventKind::GateOpened; MAX_KEPT];
    journal.append(UnixTime::from_secs(5), &many).unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST).unwrap().events()[0].seq,
        EventSeq::FIRST,
        "at the bound nothing is pruned"
    );
    journal
        .append(UnixTime::from_secs(5), &[AgentEventKind::GateClosed])
        .unwrap();
    let first = journal::page(&paths, EventSeq::FIRST).unwrap().events()[0].seq;
    assert_eq!(first.get(), (MAX_KEPT + 1 - MAX_KEPT / 4 * 3) as u64);
    let text = fs::read_to_string(paths.journal()).unwrap();
    assert_eq!(text.lines().count(), MAX_KEPT / 4 * 3);
}

/// An append that must prune rewrites the journal in one atomic write, so
/// a rewrite that fails records none of its events: the watch, which
/// takes the failure as nothing recorded, appends them again at its next
/// tick, and they must not be recorded twice.
#[test]
fn an_append_that_cannot_prune_records_nothing_and_takes_no_number() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(1_000), &[AgentEventKind::GateOpened])
        .unwrap();
    let before = fs::read(paths.journal()).unwrap();
    // The rewrite's temporary name is taken.
    let blocker = occupy_temporary(&paths.journal());
    let later = 1_001 + RETENTION_SECS;
    assert_eq!(
        journal.append(UnixTime::from_secs(later), &[AgentEventKind::GateClosed]),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert_eq!(
        fs::read(paths.journal()).unwrap(),
        before,
        "nothing recorded"
    );
    // Nothing was written, so the same handle may go on: its number for the
    // event is still the next.
    fs::remove_dir(&blocker).unwrap();
    journal
        .append(UnixTime::from_secs(later), &[AgentEventKind::GateClosed])
        .unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(
        page.events(),
        &[event(1, later, AgentEventKind::GateClosed)],
        "recorded once, after the expired event"
    );
    assert_eq!(page.end(), EventSeq::new(2));
}

#[test]
fn an_append_that_cannot_be_written_takes_no_number() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(5), &[AgentEventKind::GateOpened])
        .unwrap();
    // A directory stands where the journal was opened.
    let aside = paths.watch_dir().join("journal.aside");
    fs::rename(paths.journal(), &aside).unwrap();
    fs::create_dir(paths.journal()).unwrap();
    assert_eq!(
        journal.append(UnixTime::from_secs(6), &[AgentEventKind::GateClosed]),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EISDIR)
        })
    );
    // Nothing was written, so the same handle may go on.
    fs::remove_dir(paths.journal()).unwrap();
    fs::rename(&aside, paths.journal()).unwrap();
    journal
        .append(UnixTime::from_secs(7), &[AgentEventKind::HostBooted])
        .unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST).unwrap().events(),
        &[
            event(0, 5, AgentEventKind::GateOpened),
            event(1, 7, AgentEventKind::HostBooted),
        ]
    );
}

#[test]
fn appending_nothing_touches_nothing() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    fs::remove_file(paths.journal()).unwrap();
    fs::create_dir(paths.journal()).unwrap();
    assert_eq!(journal.append(UnixTime::from_secs(5), &[]), Ok(()));
    assert!(paths.journal().is_dir());
}

#[test]
fn a_journal_that_cannot_be_created_is_a_state_write() {
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.watch_dir()).unwrap();
    // A link to nothing: reading finds no journal, and creating one finds
    // the name taken.
    let target = paths.watch_dir().join("elsewhere.jsonl");
    std::os::unix::fs::symlink(&target, paths.journal()).unwrap();
    assert_eq!(
        Journal::open(&paths).unwrap_err(),
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        }
    );
    assert!(!target.exists(), "nothing was created through the link");
}

#[test]
fn a_torn_line_that_cannot_be_cut_off_is_a_state_write() {
    let (_dir, paths) = scratch();
    Journal::open(&paths)
        .unwrap()
        .append(UnixTime::from_secs(5), &[AgentEventKind::GateOpened])
        .unwrap();
    let mut torn = fs::read(paths.journal()).unwrap();
    torn.extend_from_slice(br#"{"seq":1,"at":6,"ki"#);
    fs::write(paths.journal(), &torn).unwrap();
    let _read_only = ModeFault::set(&paths.journal(), 0o444);
    assert_eq!(
        Journal::open(&paths).unwrap_err(),
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES)
        }
    );
    assert_eq!(fs::read(paths.journal()).unwrap(), torn, "left as it was");
}

#[test]
fn a_journal_that_cannot_be_read_is_refused_not_served_empty() {
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.journal()).unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EISDIR)
        })
    );
}

#[test]
fn a_line_that_is_not_an_event_is_refused_and_not_continued() {
    let (_dir, paths) = scratch();
    Journal::open(&paths)
        .unwrap()
        .append(UnixTime::from_secs(5), &[AgentEventKind::GateOpened])
        .unwrap();
    let mut damaged = fs::read(paths.journal()).unwrap();
    damaged.extend_from_slice(b"not an event\n");
    fs::write(paths.journal(), damaged).unwrap();
    let refused = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    assert_eq!(journal::page(&paths, EventSeq::FIRST), Err(refused.clone()));
    assert_eq!(Journal::open(&paths).unwrap_err(), refused);
}
