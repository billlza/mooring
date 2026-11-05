// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's thread when it dies or cannot date what it read, and
//! the kernel's counters it reads (design §10.1 step 5). Its counting and
//! writing otherwise are the runtime tests'.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mooring_daemon_core::meter::{CounterReading, SimMeter};
use mooring_model::iface::{InterfaceIndex, MacAddr};
use mooring_model::time::UnixTime;

use super::support::{NOW, lo0};
use crate::error::LocalError;
use crate::runtime::meter::{MeterThread, Reader, Watched, kernel_reader};

const WATCHED: [u8; 6] = [0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x01];

fn watched() -> Watched {
    Watched {
        index: InterfaceIndex::new(8).unwrap(),
        lladdr: MacAddr::from_bytes(WATCHED).unwrap(),
    }
}

/// Waits until `done` holds, for at most 5 s.
fn until(done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn start(support: &std::path::Path, reader: Reader) -> MeterThread {
    let meter = MeterThread::start(
        support.to_path_buf(),
        SimMeter::new(),
        reader,
        Duration::from_millis(5),
        Duration::from_millis(5),
    )
    .unwrap();
    meter.watch(Some(watched())).unwrap();
    meter
}

/// A thread that died without a fault of its own (its reader panicked)
/// is the daemon's error: the meter is never read as if it still counted.
#[test]
fn a_meter_thread_that_died_is_an_error() {
    let support = tempfile::tempdir().unwrap();
    let reader: Reader = Box::new(|_| std::panic::resume_unwind(Box::new("the reader broke")));
    let meter = start(support.path(), reader);
    until(|| meter.meter().is_err());
    assert!(
        matches!(meter.meter(), Err(LocalError::MeterThread)),
        "{:?}",
        meter.meter()
    );
}

/// A meter whose latest reading lies past the year 9999 cannot be dated,
/// so it is not written, and the failure says why.
#[test]
fn a_meter_that_cannot_be_dated_is_not_written() {
    let support = tempfile::tempdir().unwrap();
    let readings = Arc::new(Mutex::new(vec![CounterReading {
        at: UnixTime::from_secs(300_000_000_000),
        boot: UnixTime::from_secs(NOW - 3_600),
        index: watched().index,
        lladdr: watched().lladdr,
        rx: 1,
        tx: 1,
    }]));
    let reader: Reader = Box::new(move |_| Ok(readings.lock().unwrap().pop()));
    let meter = start(support.path(), reader);
    until(|| meter.write_failure().unwrap().is_some());
    let failure = meter.write_failure().unwrap().unwrap();
    assert!(failure.starts_with("the SIM meter failed: "), "{failure}");
}

fn clock() -> Result<UnixTime, LocalError> {
    Ok(UnixTime::from_secs(NOW))
}

/// The kernel's counters: none for an index no interface has, none for an
/// interface whose link-layer address is not the watched one (lo0 has
/// none), and the counters of the watched interface, stamped by the clock
/// and the boot time. Read only, from the live interface table.
#[test]
fn the_kernel_reader_reads_only_the_watched_interface() {
    let mut reader = kernel_reader(clock);
    let absent = Watched {
        index: InterfaceIndex::new(0x7fff_fffe).unwrap(),
        lladdr: MacAddr::from_bytes(WATCHED).unwrap(),
    };
    assert_eq!(reader(absent).unwrap(), None);
    let loopback = Watched {
        index: lo0(),
        lladdr: MacAddr::from_bytes(WATCHED).unwrap(),
    };
    assert_eq!(reader(loopback).unwrap(), None);
    let listed = mooring_macsys::interfaces().unwrap();
    let (index, lladdr) = listed
        .iter()
        .find_map(|interface| {
            let lladdr = MacAddr::from_bytes(interface.lladdr?).ok()?;
            Some((InterfaceIndex::from(interface.index), lladdr))
        })
        .expect("an interface with a link-layer address");
    let reading = reader(Watched { index, lladdr }).unwrap().unwrap();
    assert_eq!((reading.index, reading.lladdr), (index, lladdr));
    assert_eq!(reading.at, UnixTime::from_secs(NOW));
    assert!(reading.boot.as_secs() > 0 && reading.boot.as_secs() < NOW + 3_600 * 24 * 3_650);
}
