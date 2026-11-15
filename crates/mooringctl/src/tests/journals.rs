// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's event journal and the journals' retention (design §15.7):
//! the daemon's start and the changes its statuses show, each in the file
//! of its UTC day; the deployed loop's journal; the old days of the Mac's
//! journal and of every node's copy removed once a UTC day, the strays
//! named once; and a journal that cannot be written or pruned, logged once
//! while that lasts and once when it recovers.

use std::fs;
use std::path::Path;

use mooring_daemon_core::MacStatusV2;
use mooring_daemon_core::events::{ExitPhase, MacEvent, MacEventKind, decode_mac_line};
use mooring_daemon_core::status::{
    DownReasonKind, DrainOutcome, DrainRecord, ExitState, PowerSource,
};
use mooring_model::{CalendarDate, NodeId, UnixTime};
use mooring_store::{
    EVENTS_DIRECTORY, append_mac_events, append_node_events, list_mac_event_days,
    list_node_event_days, read_mac_events,
};

use super::deployed::{CARRIER, deployed, shared, statuses, with_exit_on};
use super::support::{Harness, NOW};
use crate::daemon::Intervals;
use crate::daemon::events::Journals;

fn day(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

/// The Mac's events in the file of `date`.
fn journal(support: &Path, date: CalendarDate) -> Vec<MacEvent> {
    read_mac_events(support, date)
        .unwrap()
        .map_or_else(Vec::new, |day| {
            day.lines
                .split_inclusive(|&byte| byte == b'\n')
                .map(|line| decode_mac_line(line).unwrap())
                .collect()
        })
}

/// The serving scenario's status (2026-10-08 10:00:30 UTC), without its
/// sleep and wake, with `edit` applied.
fn status(edit: impl FnOnce(&mut mooring_daemon_core::MacStatusParts)) -> MacStatusV2 {
    let serving: MacStatusV2 = serde_json::from_slice(include_bytes!(
        "../../../../contract/status-fixtures/serving.json"
    ))
    .unwrap();
    let mut parts = serving.into_parts();
    parts.exit.power.last_sleep = None;
    parts.exit.power.last_wake = None;
    parts.exit.power.last_drain = None;
    edit(&mut parts);
    MacStatusV2::new(parts).unwrap()
}

fn support(harness: &Harness) -> std::path::PathBuf {
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    support
}

fn mac(at: UnixTime, kind: MacEventKind) -> MacEvent {
    MacEvent { at, kind }
}

/// The daemon's start is the journal's first event; each status then
/// gives what changed since the last, each event in the file of its own
/// UTC day, and nothing when nothing changed.
#[test]
fn the_daemons_start_and_what_its_statuses_show_changing_are_journaled() {
    let harness = Harness::new(0);
    let support = support(&harness);
    let mut log = Vec::new();
    let mut journals = Journals::open(&mut log, &support, at(NOW)).unwrap();
    let first = status(|_| {});
    let shown = first.parts().at;
    journals
        .record(&mut log, &support, &first, at(NOW))
        .unwrap();
    journals
        .record(&mut log, &support, &first, at(NOW))
        .unwrap();
    // A sleep the evening before, past midnight UTC, goes to its own day.
    let slept = status(|parts| {
        parts.exit.power.last_drain = Some(DrainRecord {
            at: at(NOW - 86_400),
            outcome: DrainOutcome::Completed,
        });
        parts.exit.state = ExitState::Paused;
    });
    journals
        .record(&mut log, &support, &slept, at(NOW))
        .unwrap();
    assert_eq!(
        journal(&support, day("2026-10-13")),
        [mac(at(NOW), MacEventKind::DaemonStarted)]
    );
    assert_eq!(CalendarDate::utc_of(shown).unwrap(), day("2026-10-08"));
    assert_eq!(
        journal(&support, day("2026-10-08")),
        [
            mac(
                shown,
                MacEventKind::PowerSource {
                    source: PowerSource::Ac
                }
            ),
            mac(
                shown,
                MacEventKind::Exit {
                    phase: ExitPhase::Serving
                }
            ),
            mac(
                shown,
                MacEventKind::Exit {
                    phase: ExitPhase::Paused
                }
            ),
        ]
    );
    assert_eq!(
        journal(&support, day("2026-10-12")),
        [mac(
            at(NOW - 86_400),
            MacEventKind::Slept {
                drain: DrainOutcome::Completed
            }
        )]
    );
    assert_eq!(log, b"");
}

/// The deployed loop journals its start and the exit's phases as its
/// statuses show them.
#[test]
fn the_deployed_loop_journals_its_start_and_its_exits_phases() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        exit.tick(&control, log, false).unwrap();
    });
    let kinds: Vec<MacEventKind> = journal(&harness.support_dir(), day("2026-10-13"))
        .into_iter()
        .map(|event| event.kind)
        .collect();
    assert_eq!(kinds[0], MacEventKind::DaemonStarted);
    assert_eq!(
        kinds[1],
        MacEventKind::PowerSource {
            source: PowerSource::Ac
        }
    );
    assert!(matches!(kinds[2], MacEventKind::Exit { .. }), "{kinds:?}");
    assert_eq!(kinds.len(), 3, "{kinds:?}");
}

/// The day files before the oldest kept (393 days up to the clock's day)
/// are removed from the Mac's journal and from every node's copy at the
/// first record of a UTC day, and only then; what is not a day file is
/// named once and left alone.
#[test]
fn the_old_days_of_every_journal_are_removed_once_a_day() {
    let harness = Harness::new(0);
    let support = support(&harness);
    // 393 days up to 2026-10-13 start on 2025-09-16.
    for date in ["2025-09-15", "2025-09-16"] {
        append_mac_events(&support, day(date), b"{}\n").unwrap();
        for name in ["lon1", "ams1"] {
            append_node_events(&support, &node(name), day(date), b"{}\n").unwrap();
        }
    }
    let stray = support.join(EVENTS_DIRECTORY).join("mac").join("notes.txt");
    fs::write(&stray, b"").unwrap();
    let mut log = Vec::new();
    let mut journals = Journals::open(&mut log, &support, at(NOW)).unwrap();
    let kept = |support: &Path| {
        (
            list_mac_event_days(support).unwrap().days,
            list_node_event_days(support, &node("lon1")).unwrap().days,
            list_node_event_days(support, &node("ams1")).unwrap().days,
        )
    };
    assert_eq!(
        kept(&support),
        (
            vec![day("2025-09-16"), day("2026-10-13")],
            vec![day("2025-09-16")],
            vec![day("2025-09-16")]
        )
    );
    let text = String::from_utf8(log.clone()).unwrap();
    assert!(
        text.ends_with(&format!(
            "the event journals' directories hold files that are not theirs: {}\n",
            stray.display()
        )),
        "{text}"
    );
    assert!(stray.exists());
    // Not again the same day: an old file put back stays.
    append_mac_events(&support, day("2025-09-15"), b"{}\n").unwrap();
    log.clear();
    journals
        .record(&mut log, &support, &status(|_| {}), at(NOW + 60))
        .unwrap();
    assert!(
        list_mac_event_days(&support)
            .unwrap()
            .days
            .contains(&day("2025-09-15"))
    );
    // The next day, it goes, with the day that is now too old; the strays,
    // named already, are not named again.
    journals
        .record(&mut log, &support, &status(|_| {}), at(NOW + 86_400))
        .unwrap();
    let days = list_mac_event_days(&support).unwrap().days;
    assert_eq!(days, [day("2026-10-08"), day("2026-10-13")]);
    assert_eq!(
        list_node_event_days(&support, &node("lon1")).unwrap().days,
        []
    );
    assert_eq!(log, b"");
    // Once the strays are gone, nothing is said of them; one that comes
    // back is named again.
    fs::remove_file(&stray).unwrap();
    journals
        .record(&mut log, &support, &status(|_| {}), at(NOW + 2 * 86_400))
        .unwrap();
    assert_eq!(log, b"");
    fs::write(&stray, b"").unwrap();
    journals
        .record(&mut log, &support, &status(|_| {}), at(NOW + 3 * 86_400))
        .unwrap();
    let text = String::from_utf8(log).unwrap();
    assert!(
        text.ends_with(&format!(
            "the event journals' directories hold files that are not theirs: {}\n",
            stray.display()
        )),
        "{text}"
    );
}

/// A journal that cannot be written, or pruned, is logged once while that
/// lasts and once when it recovers; the daemon goes on.
#[test]
fn a_journal_that_cannot_be_written_or_pruned_is_logged_once() {
    let harness = Harness::new(0);
    let support = support(&harness);
    let events = support.join(EVENTS_DIRECTORY);
    fs::write(&events, b"").unwrap();
    let mut log = Vec::new();
    let mut journals = Journals::open(&mut log, &support, at(NOW)).unwrap();
    let text = String::from_utf8(log.clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].contains(
            "the Mac's event journal was not written: the event journals' files failed: "
        ),
        "{text}"
    );
    assert!(
        lines[1].contains(
            "old event journal days were not removed: the event journals' files failed: "
        ),
        "{text}"
    );
    // While it lasts, nothing more is said, however many events and days.
    log.clear();
    let down = status(|parts| {
        parts.exit.state = ExitState::Down {
            reason: mooring_daemon_core::status::DownReason::SecretsUnavailable,
        };
    });
    journals.record(&mut log, &support, &down, at(NOW)).unwrap();
    journals
        .record(&mut log, &support, &status(|_| {}), at(NOW + 86_400))
        .unwrap();
    assert_eq!(log, b"");
    // Put right: both recover, each said once, and the next event is
    // written.
    fs::remove_file(&events).unwrap();
    journals
        .record(&mut log, &support, &down, at(NOW + 86_400))
        .unwrap();
    let text = String::from_utf8(log.clone()).unwrap();
    assert!(
        text.contains("the Mac's event journal is written again"),
        "{text}"
    );
    assert!(
        text.contains("old event journal days are removed again"),
        "{text}"
    );
    let shown = down.parts().at;
    assert_eq!(
        journal(&support, CalendarDate::utc_of(shown).unwrap()),
        [mac(
            shown,
            MacEventKind::Exit {
                phase: ExitPhase::Down {
                    reason: DownReasonKind::SecretsUnavailable
                }
            }
        )]
    );
}
