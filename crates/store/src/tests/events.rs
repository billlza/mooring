// SPDX-License-Identifier: GPL-3.0-or-later

//! The event journals' day files (design §15.7): the Mac's under
//! `events/mac/` and each node's under `events/nodes/<node>/`, every level
//! private; the listings of days and of nodes, which name strays without
//! failing; the bound; the prunes, each journal on its own; the refusal
//! of anything but a directory where a level belongs; and the fixed texts.
//! (The day-file mechanics they share with the radio history, the torn
//! tail and the regular-file checks, are `tests::radio_history`'s and
//! `tests::regular_files`'.)

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use mooring_model::{CalendarDate, NodeId};

use super::{assert_dir_not_directory, assert_io_error, mode_of};
use crate::day_files::{DayLines, Listed};
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::events::{
    EVENTS_DIRECTORY, EventNodes, MAC_EVENTS_DIRECTORY, MAX_EVENTS_DAY_BYTES,
    NODE_EVENTS_DIRECTORY, append_mac_events, append_node_events, event_nodes, list_mac_event_days,
    list_node_event_days, mac_events_path, node_events_path, prune_mac_events_before,
    prune_node_events_before, read_mac_events, read_node_events,
};

fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn events_dir(support: &Path) -> PathBuf {
    support.join(EVENTS_DIRECTORY)
}

fn nodes_dir(support: &Path) -> PathBuf {
    events_dir(support).join(NODE_EVENTS_DIRECTORY)
}

fn whole(lines: &[u8]) -> Option<DayLines> {
    Some(DayLines {
        lines: lines.to_vec(),
        torn: false,
    })
}

#[test]
fn the_macs_journal_and_each_nodes_are_kept_apart_in_private_directories() {
    assert_eq!(
        (
            EVENTS_DIRECTORY,
            MAC_EVENTS_DIRECTORY,
            NODE_EVENTS_DIRECTORY
        ),
        ("events", "mac", "nodes")
    );
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-11-15");
    let (lon1, mac) = (node("lon1"), node("mac"));
    assert_eq!(
        mac_events_path(support.path(), day),
        support.path().join("events/mac/2026-11-15.jsonl")
    );
    assert_eq!(
        node_events_path(support.path(), &lon1, day),
        support.path().join("events/nodes/lon1/2026-11-15.jsonl")
    );
    // Nothing yet: no day, no days, no nodes, and nothing made.
    assert_eq!(read_mac_events(support.path(), day).unwrap(), None);
    assert_eq!(read_node_events(support.path(), &lon1, day).unwrap(), None);
    assert_eq!(
        list_mac_event_days(support.path()).unwrap(),
        Listed::default()
    );
    assert_eq!(
        list_node_event_days(support.path(), &lon1).unwrap(),
        Listed::default()
    );
    assert_eq!(event_nodes(support.path()).unwrap(), EventNodes::default());
    assert!(!events_dir(support.path()).exists());
    append_mac_events(support.path(), day, b"m1\n").unwrap();
    append_mac_events(support.path(), day, b"m2\nm3\n").unwrap();
    append_node_events(support.path(), &lon1, day, b"n1\n").unwrap();
    // A node may be called "mac": its journal is still a node's.
    append_node_events(support.path(), &mac, day, b"x1\n").unwrap();
    for dir in [
        events_dir(support.path()),
        events_dir(support.path()).join("mac"),
        nodes_dir(support.path()),
        nodes_dir(support.path()).join("lon1"),
        nodes_dir(support.path()).join("mac"),
    ] {
        assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
    }
    assert_eq!(mode_of(&mac_events_path(support.path(), day)), 0o600);
    assert_eq!(
        mode_of(&node_events_path(support.path(), &lon1, day)),
        0o600
    );
    assert_eq!(
        read_mac_events(support.path(), day).unwrap(),
        whole(b"m1\nm2\nm3\n")
    );
    assert_eq!(
        read_node_events(support.path(), &lon1, day).unwrap(),
        whole(b"n1\n")
    );
    assert_eq!(
        read_node_events(support.path(), &mac, day).unwrap(),
        whole(b"x1\n")
    );
    assert_eq!(
        list_mac_event_days(support.path()).unwrap().days,
        [date("2026-11-15")]
    );
    assert_eq!(
        list_node_event_days(support.path(), &node("ams1")).unwrap(),
        Listed::default()
    );
    assert_eq!(
        event_nodes(support.path()).unwrap(),
        EventNodes {
            nodes: vec![lon1, mac],
            strays: Vec::new(),
        }
    );
}

/// The nodes are the directories of `events/nodes/` named by node ids;
/// anything else there is a stray, named and left alone.
#[test]
fn the_nodes_are_the_directories_named_by_node_ids() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-11-15");
    for name in ["lon1", "ams1"] {
        append_node_events(support.path(), &node(name), day, b"n\n").unwrap();
    }
    let dir = nodes_dir(support.path());
    fs::write(dir.join("notes.txt"), b"").unwrap();
    fs::write(dir.join("fra1"), b"").unwrap();
    fs::create_dir(dir.join("Not-A-Node")).unwrap();
    fs::create_dir(dir.join("a")).unwrap();
    symlink(nodes_dir(support.path()).join("lon1"), dir.join("par1")).unwrap();
    let found = event_nodes(support.path()).unwrap();
    assert_eq!(found.nodes, [node("ams1"), node("lon1")]);
    let mut strays: Vec<PathBuf> = ["Not-A-Node", "a", "fra1", "notes.txt", "par1"]
        .iter()
        .map(|name| dir.join(name))
        .collect();
    strays.sort();
    assert_eq!(found.strays, strays);
    for stray in &strays {
        assert!(fs::symlink_metadata(stray).is_ok(), "{}", stray.display());
    }
}

/// The bound holds on both sides, with its own fault and text.
#[test]
fn an_events_day_file_is_bounded_on_append_and_on_read() {
    assert_eq!(MAX_EVENTS_DAY_BYTES, 4 * 1024 * 1024);
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-11-15");
    let lon1 = node("lon1");
    let path = node_events_path(support.path(), &lon1, day);
    let mut full = vec![b'x'; MAX_EVENTS_DAY_BYTES - 1];
    full.push(b'\n');
    append_node_events(support.path(), &lon1, day, &full).unwrap();
    let error = append_node_events(support.path(), &lon1, day, b"y\n").unwrap_err();
    assert!(
        matches!(&error, StoreError::EventsDayTooLarge { path: found } if *found == path),
        "{error:?}"
    );
    assert_eq!(error.kind(), StoreErrorKind::EventsDayTooLarge);
    assert_eq!(
        error.to_string(),
        format!(
            "event journal file {} is larger than 4194304 bytes",
            path.display()
        )
    );
    assert_eq!(fs::read(&path).unwrap(), full);
    assert!(
        read_node_events(support.path(), &lon1, day)
            .unwrap()
            .is_some()
    );
    let mac_path = mac_events_path(support.path(), day);
    append_mac_events(support.path(), day, b"m\n").unwrap();
    let mut over = vec![b'x'; MAX_EVENTS_DAY_BYTES];
    over.push(b'\n');
    fs::write(&mac_path, &over).unwrap();
    assert!(matches!(
        read_mac_events(support.path(), day).unwrap_err(),
        StoreError::EventsDayTooLarge { path: found } if found == mac_path
    ));
}

/// Each journal keeps the day files of its oldest kept day and later, by
/// name: pruning one leaves the others as they are, a day file dated
/// after the clock's day is kept, and a stray is named and left alone.
#[test]
fn each_journal_is_pruned_of_the_days_before_the_oldest_kept_on_its_own() {
    let support = tempfile::tempdir().unwrap();
    let (lon1, ams1) = (node("lon1"), node("ams1"));
    let days = ["2026-11-12", "2026-11-13", "2026-11-14", "2026-11-15"];
    for day in days {
        append_mac_events(support.path(), date(day), b"m\n").unwrap();
        append_node_events(support.path(), &lon1, date(day), b"n\n").unwrap();
        append_node_events(support.path(), &ams1, date(day), b"n\n").unwrap();
    }
    let stray = events_dir(support.path())
        .join("mac")
        .join("2026-11-01.txt");
    fs::write(&stray, b"").unwrap();
    let pruned = prune_mac_events_before(support.path(), date("2026-11-14")).unwrap();
    assert_eq!(pruned.removed, [date("2026-11-12"), date("2026-11-13")]);
    assert_eq!(pruned.strays, std::slice::from_ref(&stray));
    assert!(stray.exists());
    assert_eq!(
        prune_node_events_before(support.path(), &lon1, date("2026-11-13"))
            .unwrap()
            .removed,
        [date("2026-11-12")]
    );
    assert_eq!(
        list_mac_event_days(support.path()).unwrap().days,
        [date("2026-11-14"), date("2026-11-15")]
    );
    assert_eq!(
        list_node_event_days(support.path(), &lon1).unwrap().days,
        [date("2026-11-13"), date("2026-11-14"), date("2026-11-15")]
    );
    assert_eq!(
        list_node_event_days(support.path(), &ams1)
            .unwrap()
            .days
            .len(),
        4
    );
    // The oldest kept day itself is kept, and so is every later one, even
    // past it by more than the journals keep: no count is kept to.
    assert_eq!(
        prune_node_events_before(support.path(), &ams1, date("2026-11-12"))
            .unwrap()
            .removed,
        []
    );
    assert_eq!(
        prune_node_events_before(support.path(), &ams1, date("2026-11-16"))
            .unwrap()
            .removed,
        days.map(date)
    );
    assert_eq!(
        list_node_event_days(support.path(), &ams1).unwrap(),
        Listed::default()
    );
    // No journal yet is nothing to prune, and none is made.
    assert_eq!(
        prune_node_events_before(support.path(), &node("fra1"), date("2026-11-15"))
            .unwrap()
            .removed,
        []
    );
    assert!(!nodes_dir(support.path()).join("fra1").exists());
}

/// Every level of `events/` must be a directory: a link or a file where
/// one belongs is refused by the append, the read, the listings and the
/// prune alike, and nothing is read or written through it.
#[test]
fn a_level_of_the_events_directory_that_is_not_a_directory_is_refused() {
    let day = date("2026-11-15");
    let lon1 = node("lon1");
    // `events/` a link to a directory holding a journal.
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    append_mac_events(elsewhere.path(), day, b"m\n").unwrap();
    append_node_events(elsewhere.path(), &lon1, day, b"n\n").unwrap();
    let events = events_dir(support.path());
    symlink(events_dir(elsewhere.path()), &events).unwrap();
    assert_dir_not_directory(&read_mac_events(support.path(), day).unwrap_err(), &events);
    assert_dir_not_directory(
        &append_mac_events(support.path(), day, b"x\n").unwrap_err(),
        &events,
    );
    assert_dir_not_directory(&list_mac_event_days(support.path()).unwrap_err(), &events);
    assert_dir_not_directory(
        &prune_mac_events_before(support.path(), day).unwrap_err(),
        &events,
    );
    assert_dir_not_directory(&event_nodes(support.path()).unwrap_err(), &events);
    assert_dir_not_directory(
        &read_node_events(support.path(), &lon1, day).unwrap_err(),
        &events,
    );
    assert_eq!(
        read_mac_events(elsewhere.path(), day).unwrap(),
        whole(b"m\n")
    );
    // A node's directory a link to another node's.
    let support = tempfile::tempdir().unwrap();
    append_node_events(support.path(), &lon1, day, b"n\n").unwrap();
    let ams1 = node("ams1");
    let ams1_dir = nodes_dir(support.path()).join("ams1");
    symlink(nodes_dir(support.path()).join("lon1"), &ams1_dir).unwrap();
    assert_dir_not_directory(
        &read_node_events(support.path(), &ams1, day).unwrap_err(),
        &ams1_dir,
    );
    assert_dir_not_directory(
        &append_node_events(support.path(), &ams1, day, b"x\n").unwrap_err(),
        &ams1_dir,
    );
    assert_dir_not_directory(
        &list_node_event_days(support.path(), &ams1).unwrap_err(),
        &ams1_dir,
    );
    assert_dir_not_directory(
        &prune_node_events_before(support.path(), &ams1, day).unwrap_err(),
        &ams1_dir,
    );
    assert_eq!(
        read_node_events(support.path(), &lon1, day).unwrap(),
        whole(b"n\n")
    );
    // `events/nodes` a file: no node is listed through it.
    let support = tempfile::tempdir().unwrap();
    fs::create_dir(events_dir(support.path())).unwrap();
    fs::write(nodes_dir(support.path()), b"").unwrap();
    assert_dir_not_directory(
        &event_nodes(support.path()).unwrap_err(),
        &nodes_dir(support.path()),
    );
    // A support path that cannot be looked at is an error naming the
    // listing, never no node.
    let not_a_directory = support.path().join("not-a-directory");
    fs::write(&not_a_directory, b"").unwrap();
    assert_io_error(
        &event_nodes(&not_a_directory).unwrap_err(),
        IoOp::ListEventsDays,
        &events_dir(&not_a_directory),
        io::ErrorKind::NotADirectory,
    );
    assert_io_error(
        &append_mac_events(&not_a_directory, day, b"m\n").unwrap_err(),
        IoOp::CreateEventsDir,
        &events_dir(&not_a_directory),
        io::ErrorKind::NotADirectory,
    );
}

#[test]
fn event_journal_operations_have_fixed_texts() {
    for (op, text) in [
        (IoOp::CreateEventsDir, "create the event journal directory"),
        (IoOp::OpenEventsDay, "open an event journal day file"),
        (IoOp::ReadEventsDay, "read an event journal day file"),
        (IoOp::WriteEventsDay, "write an event journal day file"),
        (IoOp::ListEventsDays, "list the event journals' day files"),
        (IoOp::RemoveEventsDay, "remove an event journal day file"),
    ] {
        assert_eq!(op.to_string(), text);
    }
}
