// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's capacity samples (console spec B.2.8, design §15.3): the
//! status carries the monitor's view while the exit probes and the SIM
//! meter's readings cover a minute, with the egress rates and the
//! answering node's round trip against its idle reference; none before a
//! minute is covered or while the exit is disabled, and no sample from a
//! tick that does not probe; a failed round leaves only the rates; the
//! recorded uplink baseline measures the use, and a change of it is said; a
//! clock that stepped back is said and times saturation anew; and the
//! record of round trips outlives a restart, is written at most once per
//! interval, keeps only nodes with a site, and is replaced or written again
//! when it cannot be read or written.

use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mooring_daemon_core::capacity::rates::EgressRate;
use mooring_daemon_core::capacity::round_trips::{MAX_ROUND_TRIPS_BYTES, RoundTrips};
use mooring_daemon_core::capacity::{CapacityStatus, Saturation, UplinkUse};
use mooring_daemon_core::exit::RoundTrip;
use mooring_daemon_core::meter::CounterReading;
use mooring_model::iface::MacAddr;
use mooring_model::{Deployment, NodeId, NodeLifecycle, UnixTime, UplinkBaseline};
use mooring_store::{ROUND_TRIPS_FILE, Store, read_round_trips, write_round_trips};

use super::deployed::{
    CARRIER, deployed, deployed_with, published, shared, statuses, with_exit_on,
};
use super::support::{Harness, NOW, lo0};
use super::user::fixture;
use crate::daemon::capacity::{Capacity, Probed, WRITE_RETRY};
use crate::daemon::deployed::Deployed;
use crate::daemon::{Control, Intervals, RunPaths};

/// A reading of the fixture's egress as the harness gives it: lo0, with
/// the selector's link-layer address.
fn reading(at: u64, rx: u64, tx: u64) -> CounterReading {
    CounterReading {
        at: UnixTime::from_secs(at),
        boot: UnixTime::from_secs(NOW - 86_400),
        index: lo0(),
        lladdr: MacAddr::from_bytes([0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x01]).unwrap(),
        rx,
        tx,
    }
}

/// Scripts `steps` readings 2 s apart ending at `end`, 100 kB received
/// and 25 kB sent between each two.
fn readings_until(harness: &Harness, end: u64, steps: u64) {
    let mut readings = harness.readings.lock().unwrap();
    for step in 0..=steps {
        readings.push_back(reading(
            end - 2 * steps + 2 * step,
            100_000 * step,
            25_000 * step,
        ));
    }
}

/// The loop's intervals, every tick publishing and the meter reading at
/// once.
fn quick() -> Intervals {
    Intervals {
        publish: Duration::ZERO,
        meter_tick: Duration::from_millis(1),
        ..Intervals::DAEMON
    }
}

/// Ticks until the status carries a capacity view, for at most 5 s.
fn until_sampled(
    exit: &mut Deployed<'_, '_>,
    control: &Control,
    log: &mut Vec<u8>,
) -> CapacityStatus {
    let started = Instant::now();
    loop {
        exit.tick(control, log, false).unwrap();
        if let Some(capacity) = published(control).parts().capacity {
            return capacity;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "no sample");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The record of round trips in `run_dir`, as written.
fn record(run_dir: &std::path::Path) -> Option<String> {
    read_round_trips(run_dir, MAX_ROUND_TRIPS_BYTES + 1)
        .unwrap()
        .map(|bytes| String::from_utf8(bytes).unwrap())
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// The status carries the view: the minute's rates and the round trip of
/// the node that answered (ams1, the first), which, alone in the record,
/// is its own idle reference.
#[test]
fn the_status_carries_the_capacity_while_the_exit_probes() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    harness.probe_rtt.set(Duration::from_millis(48));
    statuses(&harness);
    readings_until(&harness, NOW, 30);
    let run_dir = RunPaths::under(&harness.support_dir()).dir;
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        assert_eq!(
            until_sampled(exit, &control, log),
            CapacityStatus {
                at: UnixTime::from_secs(NOW),
                tx_bps: 100_000,
                rx_bps: 400_000,
                uplink_use: UplinkUse::NoBaseline,
                rtt_inflation_ms: Some(0),
                saturation: Saturation::Clear,
            }
        );
    });
    assert_eq!(
        record(&run_dir).unwrap(),
        format!("{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},48]]}}}}\n")
    );
}

/// Less than a minute of readings gives no view; two seconds more do; and
/// a disabled exit, which probes nothing, gives none.
#[test]
fn no_sample_before_a_minute_is_read_or_while_the_exit_is_disabled() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    readings_until(&harness, NOW, 29);
    let readings = Arc::clone(&harness.readings);
    let store = Store::new(harness.support_dir());
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        let started = Instant::now();
        while !readings.lock().unwrap().is_empty() {
            exit.tick(&control, log, false).unwrap();
            assert_eq!(published(&control).parts().capacity, None);
            assert!(started.elapsed() < Duration::from_secs(5), "not read");
        }
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(5));
            exit.tick(&control, log, false).unwrap();
            assert_eq!(published(&control).parts().capacity, None, "58 s");
        }
        readings
            .lock()
            .unwrap()
            .push_back(reading(NOW + 2, 100_000 * 30, 25_000 * 30));
        assert_eq!(until_sampled(exit, &control, log).tx_bps, 100_000);
        let state = store.load().unwrap();
        store
            .set_exit_enabled(state.runtime.revision, false)
            .unwrap();
        exit.tick(&control, log, false).unwrap();
        assert_eq!(published(&control).parts().capacity, None);
    });
}

/// A round no node answered leaves the view with the rates alone: no
/// round trip, and so, without a baseline, no evidence either way; and
/// nothing is recorded.
#[test]
fn a_failed_round_leaves_only_the_rates() {
    let mut harness = deployed();
    statuses(&harness);
    readings_until(&harness, NOW, 30);
    let run_dir = RunPaths::under(&harness.support_dir()).dir;
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        let capacity = until_sampled(exit, &control, log);
        assert_eq!((capacity.tx_bps, capacity.rx_bps), (100_000, 400_000));
        assert_eq!(capacity.rtt_inflation_ms, None);
        assert_eq!(capacity.saturation, Saturation::NoEvidence);
    });
    assert_eq!(record(&run_dir), None);
}

/// The deployment's uplink baseline of `p50_bps`.
fn with_baseline(p50_bps: u64) -> Deployment {
    fixture(|parts| {
        parts.exit.uplink_baseline =
            Some(UplinkBaseline::new(p50_bps / 2, p50_bps, UnixTime::from_secs(NOW)).unwrap());
    })
}

/// The recorded baseline measures the uplink's use: 100 kbit/s of a
/// 1 Mbit/s median is 10.0%.
#[test]
fn the_recorded_baseline_measures_the_use() {
    let mut harness = deployed_with(with_baseline(1_000_000));
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    readings_until(&harness, NOW, 30);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        assert_eq!(
            until_sampled(exit, &control, log).uplink_use,
            UplinkUse::Measured {
                permille: 100,
                baseline_p50_bps: 1_000_000
            }
        );
    });
}

/// The rates of 100 kbit/s sent and 400 kbit/s received.
const RATES: EgressRate = EgressRate {
    tx_bps: 100_000,
    rx_bps: 400_000,
};

/// A probing tick's view of a round that ran at `probed` seconds and took
/// `rtt_ms`, answered by `name`.
fn round(name: &str, probed: u64, rtt_ms: u64) -> Probed {
    Probed {
        probing: true,
        round_trip: Some(RoundTrip {
            node: node(name),
            rtt: Duration::from_millis(rtt_ms),
            probed: Duration::from_secs(probed),
        }),
    }
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(NOW + secs)
}

/// A change of the recorded baseline is said, and the monitor starts
/// again with it: the run building before it is timed anew.
#[test]
fn a_change_of_the_baseline_is_said_and_times_saturation_anew() {
    let run = tempfile::tempdir().unwrap();
    let begun = Instant::now();
    let (mut capacity, note) = Capacity::open(run.path(), None, Duration::from_secs(600));
    assert_eq!(note, None);
    let none = fixture(|_| {});
    // 40 ms, then 300 ms: inflated by 260 ms, a run building.
    assert!(
        capacity
            .track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun)
            .is_empty()
    );
    capacity.track(&none, at(30), &round("ams1", 31, 300), Some(RATES), begun);
    assert_eq!(
        capacity.status().unwrap().saturation,
        Saturation::Building { since: at(30) }
    );
    let baseline = with_baseline(1_000_000);
    assert_eq!(
        capacity.track(
            &baseline,
            at(32),
            &round("ams1", 31, 300),
            Some(RATES),
            begun
        ),
        [
            "capacity: the uplink baseline is now a median of 1000000 bit/s; saturation is timed anew"
        ]
    );
    let status = capacity.status().unwrap();
    assert_eq!(status.saturation, Saturation::Building { since: at(32) });
    assert_eq!(
        status.uplink_use,
        UplinkUse::Measured {
            permille: 100,
            baseline_p50_bps: 1_000_000
        }
    );
    assert_eq!(
        capacity.track(&none, at(34), &round("ams1", 31, 300), Some(RATES), begun),
        ["capacity: no uplink baseline is recorded any more; saturation is timed anew"]
    );
    assert_eq!(capacity.status().unwrap().uplink_use, UplinkUse::NoBaseline);
}

/// Each round is recorded once, however many ticks see it; a tick in the
/// same second as the last sample keeps the view; one that is not probing,
/// or has no rates, carries none.
#[test]
fn a_round_is_recorded_once_and_a_second_keeps_its_view() {
    let run = tempfile::tempdir().unwrap();
    let begun = Instant::now();
    let (mut capacity, _) = Capacity::open(run.path(), None, Duration::ZERO);
    let none = fixture(|_| {});
    capacity.track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun);
    capacity.track(&none, at(2), &round("ams1", 1, 40), Some(RATES), begun);
    assert!(
        capacity
            .track(&none, at(2), &round("ams1", 1, 40), Some(RATES), begun)
            .is_empty(),
        "the same second is no clock that stepped back"
    );
    assert_eq!(
        record(run.path()).unwrap(),
        format!("{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},40]]}}}}\n")
    );
    assert_eq!(capacity.status().unwrap().at, at(2));
    let quiet = Probed {
        probing: false,
        round_trip: None,
    };
    capacity.track(&none, at(4), &quiet, Some(RATES), begun);
    assert_eq!(capacity.status(), None);
    capacity.track(&none, at(6), &round("ams1", 1, 40), None, begun);
    assert_eq!(capacity.status(), None);
    capacity.track(&none, at(8), &round("ams1", 1, 40), Some(RATES), begun);
    assert_eq!(capacity.status().unwrap().at, at(8));
}

/// A clock that stepped back is said, and saturation is timed anew from
/// the sample.
#[test]
fn a_clock_that_steps_back_is_said_and_times_saturation_anew() {
    let run = tempfile::tempdir().unwrap();
    let begun = Instant::now();
    let (mut capacity, _) = Capacity::open(run.path(), None, Duration::from_secs(600));
    let none = fixture(|_| {});
    capacity.track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun);
    capacity.track(&none, at(30), &round("ams1", 31, 300), Some(RATES), begun);
    capacity.track(&none, at(60), &round("ams1", 31, 300), Some(RATES), begun);
    assert_eq!(
        capacity.status().unwrap().saturation,
        Saturation::Building { since: at(30) }
    );
    let notes = capacity.track(&none, at(45), &round("ams1", 31, 300), Some(RATES), begun);
    assert_eq!(
        notes,
        [format!(
            "capacity: the capacity sample at {} is not after the previous one at {}: the clock stepped back, and saturation is timed anew from this sample",
            at(45),
            at(60)
        )]
    );
    let status = capacity.status().unwrap();
    assert_eq!(status.at, at(45));
    assert_eq!(status.saturation, Saturation::Building { since: at(45) });
}

/// The daemon started again keeps the idle reference: 40 ms before the
/// restart, 300 ms after it, is 260 ms over idle.
#[test]
fn a_restart_keeps_the_idle_reference() {
    let mut harness = deployed();
    harness.probe_rtt.set(Duration::from_millis(40));
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    readings_until(&harness, NOW, 30);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        assert_eq!(until_sampled(exit, &control, log).rtt_inflation_ms, Some(0));
    });
    let later = NOW + 600;
    harness.now.set(later);
    harness.probe_rtt.set(Duration::from_millis(300));
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    readings_until(&harness, later, 31);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, quick(), |exit, log| {
        let capacity = until_sampled(exit, &control, log);
        assert_eq!(capacity.rtt_inflation_ms, Some(260));
        assert_eq!(
            capacity.saturation,
            Saturation::Building {
                since: UnixTime::from_secs(later)
            }
        );
    });
}

/// After a write, the next waits its interval; a change made meanwhile is
/// written once it has passed.
#[test]
fn the_record_is_written_at_most_once_an_interval() {
    let run = tempfile::tempdir().unwrap();
    let begun = Instant::now();
    let every = Duration::from_secs(600);
    let (mut capacity, _) = Capacity::open(run.path(), None, every);
    let none = fixture(|_| {});
    capacity.track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun);
    let first = record(run.path()).unwrap();
    capacity.track(&none, at(30), &round("ams1", 31, 50), Some(RATES), begun);
    let second = Duration::from_secs(1);
    capacity.track(
        &none,
        at(32),
        &round("ams1", 31, 50),
        Some(RATES),
        begun + every - second,
    );
    assert_eq!(record(run.path()).unwrap(), first);
    capacity.track(
        &none,
        at(34),
        &round("ams1", 31, 50),
        Some(RATES),
        begun + every,
    );
    assert_eq!(
        record(run.path()).unwrap(),
        format!(
            "{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},40],[{},50]]}}}}\n",
            NOW + 30
        )
    );
}

/// The record keeps only nodes with a site: one the deployment does not
/// have, and one it plans but has no site for, are dropped, and the record
/// written again.
#[test]
fn a_node_without_a_site_is_dropped_from_the_record() {
    let run = tempfile::tempdir().unwrap();
    let mut kept = RoundTrips::new();
    kept.record(&node("ams1"), at(0), 40);
    kept.record(&node("gone1"), at(0), 90);
    kept.record(&node("lon1"), at(0), 60);
    write_round_trips(run.path(), &kept.encode().unwrap()).unwrap();
    let (mut capacity, note) = Capacity::open(run.path(), None, Duration::from_secs(600));
    assert_eq!(note, None);
    let quiet = Probed {
        probing: true,
        round_trip: None,
    };
    let lon1_planned = fixture(|parts| {
        let lon1 = parts
            .nodes
            .iter_mut()
            .find(|candidate| candidate.id == node("lon1"))
            .unwrap();
        lon1.lifecycle = NodeLifecycle::Planned;
    });
    capacity.track(&lon1_planned, at(30), &quiet, Some(RATES), Instant::now());
    assert_eq!(
        record(run.path()).unwrap(),
        format!("{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},40]]}}}}\n")
    );
}

/// A record that cannot be read is said at the start, and replaced by the
/// first write.
#[test]
fn an_unreadable_record_is_said_and_replaced() {
    let run = tempfile::tempdir().unwrap();
    fs::write(run.path().join(ROUND_TRIPS_FILE), b"not a record").unwrap();
    let (mut capacity, note) = Capacity::open(run.path(), None, Duration::from_secs(600));
    assert_eq!(
        note.as_deref(),
        Some(
            "capacity: the record of direct-probe round trips cannot be read (the record of direct-probe round trips is corrupt); the idle reference starts again, and the record is written again"
        )
    );
    let quiet = Probed {
        probing: true,
        round_trip: None,
    };
    assert!(
        capacity
            .track(&fixture(|_| {}), at(0), &quiet, Some(RATES), Instant::now())
            .is_empty()
    );
    assert_eq!(
        record(run.path()).unwrap(),
        "{\"version\":1,\"nodes\":{}}\n"
    );
}

/// A link where the record belongs is not read through: it is said at the
/// start like any record that cannot be read, and the first write puts the
/// record in its place.
#[test]
fn a_link_where_the_record_belongs_is_said_and_replaced() {
    let run = tempfile::tempdir().unwrap();
    let elsewhere = run.path().join("elsewhere.json");
    fs::write(&elsewhere, b"{\"version\":1,\"nodes\":{}}\n").unwrap();
    let path = run.path().join(ROUND_TRIPS_FILE);
    std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
    let (mut capacity, note) = Capacity::open(run.path(), None, Duration::from_secs(600));
    assert_eq!(
        note,
        Some(format!(
            "capacity: the record of direct-probe round trips cannot be read ({} is not a regular file); the idle reference starts again, and the record is written again",
            path.display()
        ))
    );
    let quiet = Probed {
        probing: true,
        round_trip: None,
    };
    assert!(
        capacity
            .track(&fixture(|_| {}), at(0), &quiet, Some(RATES), Instant::now())
            .is_empty()
    );
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
    assert_eq!(
        record(run.path()).unwrap(),
        "{\"version\":1,\"nodes\":{}}\n"
    );
}

/// A tick that does not probe takes no sample, so a run building holds
/// across it, as across any gap within the monitor's bound.
#[test]
fn a_tick_that_does_not_probe_takes_no_sample() {
    let run = tempfile::tempdir().unwrap();
    let begun = Instant::now();
    let (mut capacity, _) = Capacity::open(run.path(), None, Duration::from_secs(600));
    let none = fixture(|_| {});
    capacity.track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun);
    capacity.track(&none, at(30), &round("ams1", 31, 300), Some(RATES), begun);
    let quiet = Probed {
        probing: false,
        round_trip: None,
    };
    capacity.track(&none, at(32), &quiet, Some(RATES), begun);
    assert_eq!(capacity.status(), None);
    capacity.track(&none, at(34), &round("ams1", 31, 300), Some(RATES), begun);
    assert_eq!(
        capacity.status().unwrap().saturation,
        Saturation::Building { since: at(30) }
    );
}

/// A write that fails is said; the view still has the reference, and the
/// write is tried again only [`WRITE_RETRY`] later; once it is written,
/// the next write waits its interval again.
#[test]
fn a_write_that_fails_is_said_and_tried_again_later() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    let begun = Instant::now();
    let (mut capacity, note) = Capacity::open(&missing, None, Duration::from_secs(600));
    assert_eq!(note, None);
    let none = fixture(|_| {});
    let notes = capacity.track(&none, at(0), &round("ams1", 1, 40), Some(RATES), begun);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0]
            .starts_with("capacity: the record of direct-probe round trips could not be written ("),
        "{notes:?}"
    );
    assert!(
        notes[0].ends_with(
            "); the idle reference is kept in memory, and the record is written again in 60 s"
        ),
        "{notes:?}"
    );
    assert_eq!(capacity.status().unwrap().rtt_inflation_ms, Some(0));
    fs::create_dir(&missing).unwrap();
    let second = Duration::from_secs(1);
    let before = capacity.track(
        &none,
        at(30),
        &round("ams1", 31, 300),
        Some(RATES),
        begun + WRITE_RETRY - second,
    );
    assert!(before.is_empty(), "{before:?}");
    assert_eq!(record(&missing), None);
    assert_eq!(
        capacity.status().unwrap().rtt_inflation_ms,
        Some(260),
        "the reference held in memory"
    );
    assert!(
        capacity
            .track(
                &none,
                at(32),
                &round("ams1", 31, 300),
                Some(RATES),
                begun + WRITE_RETRY
            )
            .is_empty()
    );
    let written = record(&missing).unwrap();
    assert_eq!(
        written,
        format!(
            "{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},40],[{},300]]}}}}\n",
            NOW + 30
        )
    );
    let retried = begun + WRITE_RETRY;
    capacity.track(
        &none,
        at(60),
        &round("ams1", 61, 50),
        Some(RATES),
        retried + second,
    );
    assert_eq!(record(&missing).unwrap(), written);
    capacity.track(
        &none,
        at(62),
        &round("ams1", 61, 50),
        Some(RATES),
        retried + Duration::from_secs(600),
    );
    assert_eq!(
        record(&missing).unwrap(),
        format!(
            "{{\"version\":1,\"nodes\":{{\"ams1\":[[{NOW},40],[{},300],[{},50]]}}}}\n",
            NOW + 30,
            NOW + 60
        )
    );
}
