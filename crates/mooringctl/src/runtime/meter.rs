// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's thread (design §10.1 step 5): it reads the egress
//! interface's counters every [`METER_TICK`] on its own, so that nothing
//! the daemon's loop waits for (a probe, a router poll, a node call) widens
//! the gap between two readings, and it writes `usage/sim-meter.json`
//! every [`PERSIST_EVERY`] and when it stops. The loop tells it which
//! interface the egress is and reads the meter back.
//!
//! A reading the meter refuses (a counter of 2^32 or more) or a counter
//! that cannot be read is the thread's fault, which ends it: the daemon
//! then stops, since it can no longer enforce the hard stop. A write that
//! fails is kept as a note for the daemon to log, and tried again.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mooring_daemon_core::meter::{CounterReading, SimMeter};
use mooring_macsys::MacsysError;
use mooring_model::CalendarDate;
use mooring_model::iface::{InterfaceIndex, MacAddr};
use mooring_model::time::UnixTime;
use mooring_store::write_sim_meter;

use crate::error::LocalError;

/// How often the counters are read.
pub(crate) const METER_TICK: Duration = Duration::from_secs(2);

/// How often the meter is written.
pub(crate) const PERSIST_EVERY: Duration = Duration::from_secs(60);

/// The days of bins the meter keeps, before the latest reading's day.
pub(crate) const KEPT_DAYS: u32 = 400;

/// The interface the meter reads: the egress, by index and link-layer
/// address, so a reading of another interface at that index is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Watched {
    /// Its index.
    pub(crate) index: InterfaceIndex,
    /// Its link-layer address.
    pub(crate) lladdr: MacAddr,
}

/// Reads the counters of the watched interface: `None` while it is not
/// there (unplugged, or another interface at its index).
pub(crate) type Reader =
    Box<dyn FnMut(Watched) -> Result<Option<CounterReading>, LocalError> + Send>;

#[derive(Debug)]
struct Shared {
    meter: SimMeter,
    watched: Option<Watched>,
    /// The fault that ended the thread.
    fault: Option<String>,
    /// Why the latest write failed, while that lasts.
    write_failure: Option<String>,
    stop: bool,
}

/// The running meter.
#[derive(Debug)]
pub(crate) struct MeterThread {
    shared: Arc<(Mutex<Shared>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl MeterThread {
    /// Starts the thread on `meter` (as read from the file), writing it
    /// under `support_dir`.
    pub(crate) fn start(
        support_dir: PathBuf,
        meter: SimMeter,
        reader: Reader,
        tick: Duration,
        persist_every: Duration,
    ) -> Result<Self, LocalError> {
        let shared = Arc::new((
            Mutex::new(Shared {
                meter,
                watched: None,
                fault: None,
                write_failure: None,
                stop: false,
            }),
            Condvar::new(),
        ));
        let worker = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("mooring-meter".to_owned())
            .spawn(move || run(&worker, &support_dir, reader, tick, persist_every))
            .map_err(|_| LocalError::MeterThread)?;
        Ok(Self {
            shared,
            handle: Some(handle),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Shared>, LocalError> {
        self.shared.0.lock().map_err(|_| LocalError::MeterThread)
    }

    /// Tells the thread which interface the egress is now.
    pub(crate) fn watch(&self, watched: Option<Watched>) -> Result<(), LocalError> {
        self.lock()?.watched = watched;
        Ok(())
    }

    /// The meter as counted so far; the thread's fault, if it has ended,
    /// is the error.
    pub(crate) fn meter(&self) -> Result<SimMeter, LocalError> {
        let shared = self.lock()?;
        if let Some(fault) = &shared.fault {
            return Err(LocalError::MeterFault {
                fault: fault.clone(),
            });
        }
        if self.handle.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(LocalError::MeterThread);
        }
        Ok(shared.meter.clone())
    }

    /// Why the latest write failed, while it does.
    pub(crate) fn write_failure(&self) -> Result<Option<String>, LocalError> {
        Ok(self.lock()?.write_failure.clone())
    }
}

impl Drop for MeterThread {
    /// Stops the thread, which writes the meter a last time.
    fn drop(&mut self) {
        if let Ok(mut shared) = self.shared.0.lock() {
            shared.stop = true;
        }
        self.shared.1.notify_all();
        if let Some(handle) = self.handle.take() {
            // A thread that panicked has nothing more to write.
            let _ = handle.join();
        }
    }
}

/// The thread: a reading every `tick`, a write every `persist_every` and
/// at the end.
fn run(
    shared: &(Mutex<Shared>, Condvar),
    support_dir: &std::path::Path,
    mut reader: Reader,
    tick: Duration,
    persist_every: Duration,
) {
    let (lock, wake) = shared;
    let mut written = Instant::now();
    loop {
        let Ok(guard) = lock.lock() else {
            return;
        };
        let Ok((guard, _)) = wake.wait_timeout_while(guard, tick, |shared| !shared.stop) else {
            return;
        };
        let (stop, watched) = (guard.stop, guard.watched);
        drop(guard);
        if let Some(watched) = watched
            && let Err(fault) = read_once(lock, &mut reader, watched)
        {
            if let Ok(mut shared) = lock.lock() {
                shared.fault = Some(fault);
            }
            return;
        }
        if stop || written.elapsed() >= persist_every {
            write(lock, support_dir);
            written = Instant::now();
        }
        if stop {
            return;
        }
    }
}

/// One reading, counted; a fault as text.
fn read_once(lock: &Mutex<Shared>, reader: &mut Reader, watched: Watched) -> Result<(), String> {
    let Some(reading) = reader(watched).map_err(|error| chain(&error))? else {
        return Ok(());
    };
    let mut shared = lock
        .lock()
        .map_err(|_| "the meter's lock is poisoned".to_owned())?;
    shared
        .meter
        .observe(reading)
        .map_err(|error| chain(&LocalError::Meter(Box::new(error))))
}

/// Writes the meter, keeping the [`KEPT_DAYS`] before its latest
/// reading's day; a failure is noted.
fn write(lock: &Mutex<Shared>, support_dir: &std::path::Path) {
    let encoded = {
        let Ok(mut shared) = lock.lock() else {
            return;
        };
        let first = shared
            .meter
            .last()
            .map(|last| CalendarDate::utc_of(last.at))
            .transpose()
            .and_then(|today| {
                today
                    .map(|today| {
                        CalendarDate::from_days_since_epoch(
                            today.days_since_epoch().saturating_sub(KEPT_DAYS),
                        )
                    })
                    .transpose()
            });
        match first {
            Ok(Some(first)) => {
                shared.meter.retain_from(first);
                shared.meter.encode()
            }
            Ok(None) => shared.meter.encode(),
            Err(error) => Err(error.into()),
        }
    };
    let outcome = encoded
        .map_err(|error| chain(&LocalError::Meter(Box::new(error))))
        .and_then(|bytes| {
            write_sim_meter(support_dir, &bytes)
                .map_err(|error| chain(&LocalError::MeterFile(Box::new(error))))
        });
    if let Ok(mut shared) = lock.lock() {
        shared.write_failure = outcome.err();
    }
}

/// An error and its causes on one line.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The kernel's counters of the watched interface (`macsys`): `None` when
/// no interface has its index, or another interface does.
pub(crate) fn kernel_reader(clock: fn() -> Result<UnixTime, LocalError>) -> Reader {
    Box::new(move |watched: Watched| {
        let interface = match mooring_macsys::interface(watched.index.into()) {
            Ok(interface) => interface,
            Err(MacsysError::InterfaceAbsent) => return Ok(None),
            Err(error) => return Err(LocalError::Kernel(error)),
        };
        if interface.lladdr != Some(watched.lladdr.octets()) {
            return Ok(None);
        }
        let boot = mooring_macsys::boot_time().map_err(LocalError::Kernel)?;
        Ok(Some(CounterReading {
            at: clock()?,
            boot: UnixTime::from_secs(boot),
            index: watched.index,
            lladdr: watched.lladdr,
            rx: interface.ibytes,
            tx: interface.obytes,
        }))
    })
}
