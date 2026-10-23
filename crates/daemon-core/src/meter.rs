// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter (design §10.1 step 5): the line's bytes per UTC day, from
//! the egress interface's counters. A billing cycle starts at UTC midnight
//! (§7), so a cycle's bytes are the sum of its days, whatever cycle rule is
//! recorded when they are summed: `sim set-anchor` moves no byte.
//!
//! # The counters
//!
//! The kernel gives the daemon each counter modulo 2^32 and rounded down to
//! 1 KiB (`macsys`), so a delta is taken modulo 2^32. The daemon reads every
//! 2 s, far less time than 4 GiB takes on the line, so a reading below the
//! one before is a wrap when the bytes it implies fit in what the line could
//! carry since ([`MAX_LINE_BYTES_PER_SEC`]), and otherwise counters that
//! restarted (the interface came back), whose value is then counted whole.
//! A reading of another boot or another interface (index or link-layer
//! address) is restarted counters too. Every byte on the egress went over
//! the SIM, so counting a restarted counter whole can only over-count, the
//! safe direction for a hard stop.
//!
//! # Short days
//!
//! A day is marked short when its figures may miss bytes: a gap between two
//! readings long enough for a whole wrap to pass unseen (the daemon was not
//! running, or the Mac slept), and restarted counters, which lose what they
//! counted after the last reading and may have wrapped before the first.
//! A cycle with a short day is a lower bound.

use std::collections::BTreeMap;

use mooring_model::date::CalendarDate;
use mooring_model::iface::{InterfaceIndex, MacAddr};
use mooring_model::{ModelError, UnixTime};
use serde::{Deserialize, Serialize};

use crate::forecast::DailySimBytes;
use crate::period::BillingCycle;
use crate::router::{RouterAdvisory, RouterReading};
use crate::status::MeterAccuracy;

/// The counters' modulus as the kernel gives them to the daemon.
pub const COUNTER_MODULUS: u64 = 1 << 32;

/// The most bytes per second the line can carry in one direction, which
/// tells a counter that wrapped from one that restarted: 2.5 Gbit/s, above
/// any rate the M7 reaches *(inference: its 5G peak is not measured)*.
pub const MAX_LINE_BYTES_PER_SEC: u64 = 312_500_000;

/// The meter document's version.
pub const SIM_METER_VERSION: u32 = 1;

/// The largest meter document read, in bytes: about 400 days of bins.
pub const MAX_SIM_METER_BYTES: usize = 256 * 1024;

/// One reading of the egress interface's byte counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterReading {
    /// When it was taken, by the Mac's clock.
    pub at: UnixTime,
    /// When the Mac booted (`kern.boottime`): a reading of another boot
    /// has restarted counters.
    pub boot: UnixTime,
    /// The interface's index.
    pub index: InterfaceIndex,
    /// The interface's link-layer address.
    pub lladdr: MacAddr,
    /// Bytes received (`ifi_ibytes`), modulo 2^32.
    pub rx: u64,
    /// Bytes sent (`ifi_obytes`), modulo 2^32.
    pub tx: u64,
}

impl CounterReading {
    /// Whether `other` reads the same counters: same boot, same interface.
    fn same_counters(&self, other: &Self) -> bool {
        self.boot == other.boot && self.index == other.index && self.lladdr == other.lladdr
    }
}

/// The bytes of one UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DayBytes {
    /// Bytes received.
    pub rx: u64,
    /// Bytes sent.
    pub tx: u64,
    /// Whether the figures may miss bytes (see the module documentation).
    pub short: bool,
}

/// A cycle's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CycleBytes {
    /// Bytes received.
    pub rx: u64,
    /// Bytes sent.
    pub tx: u64,
    /// Whether any of its days is short, so the figures are a lower bound.
    pub short: bool,
}

impl CycleBytes {
    /// Bytes in both directions.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.rx.saturating_add(self.tx)
    }
}

/// Whether `cycle`'s figures count every byte of the SIM (design §10.1
/// step 5): only when none of its days is short and the router's latest
/// reading shows the M7's Wi-Fi radio and both offloads off, since the
/// egress counters miss whatever the M7 carries another way. Without a
/// reading that shows it, the figures are a lower bound.
#[must_use]
pub fn accuracy(cycle: CycleBytes, router: &RouterReading) -> MeterAccuracy {
    let bypassed = match router {
        RouterReading::Available { status, .. } => status.advisories().iter().any(|advisory| {
            matches!(
                advisory,
                RouterAdvisory::WifiRadioOn
                    | RouterAdvisory::WifiOffloadOn
                    | RouterAdvisory::EthernetOffloadOn
            )
        }),
        RouterReading::Unavailable { .. } => true,
    };
    if cycle.short || bypassed {
        MeterAccuracy::LowerBound
    } else {
        MeterAccuracy::Exact
    }
}

/// Why the meter refused a reading or a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeterError {
    /// A counter read 2^32 or more: the kernel no longer gives the counters
    /// modulo 2^32, so no delta can be taken as this meter takes them.
    #[error("an egress counter read {value}, which is not below 2^32")]
    CounterOutOfRange {
        /// The value read.
        value: u64,
    },
    /// A day's bytes do not fit in 64 bits.
    #[error("the SIM meter's bytes for {date} overflowed")]
    Overflow {
        /// The day.
        date: CalendarDate,
    },
    /// A time lies outside the calendar.
    #[error(transparent)]
    Calendar(#[from] ModelError),
    /// The meter document is not a version-1 meter.
    #[error("the SIM meter document is corrupt")]
    Corrupt,
}

/// The line's bytes per UTC day, and the reading the next one is compared
/// with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SimMeter {
    days: BTreeMap<CalendarDate, DayBytes>,
    last: Option<CounterReading>,
}

impl SimMeter {
    /// A meter that has counted nothing: its first reading only sets the
    /// counters it compares with, since what they held before it was not
    /// necessarily the SIM's.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The reading the next one is compared with.
    #[must_use]
    pub const fn last(&self) -> Option<&CounterReading> {
        self.last.as_ref()
    }

    /// Counts `reading` against the one before it, into the UTC day it was
    /// taken.
    pub fn observe(&mut self, reading: CounterReading) -> Result<(), MeterError> {
        for value in [reading.rx, reading.tx] {
            if value >= COUNTER_MODULUS {
                return Err(MeterError::CounterOutOfRange { value });
            }
        }
        let Some(last) = self.last else {
            self.last = Some(reading);
            return Ok(());
        };
        let date = CalendarDate::utc_of(reading.at)?;
        let (rx, tx, short) = if last.same_counters(&reading) {
            // A clock that stepped back gives no bound on the gap.
            let elapsed = reading.at.as_secs().checked_sub(last.at.as_secs());
            let (rx, rx_short) = delta(last.rx, reading.rx, elapsed);
            let (tx, tx_short) = delta(last.tx, reading.tx, elapsed);
            (rx, tx, rx_short || tx_short)
        } else {
            (reading.rx, reading.tx, true)
        };
        let day = self.days.entry(date).or_default();
        let overflow = MeterError::Overflow { date };
        day.rx = day.rx.checked_add(rx).ok_or_else(|| overflow.clone())?;
        day.tx = day.tx.checked_add(tx).ok_or(overflow)?;
        day.short |= short;
        self.last = Some(reading);
        Ok(())
    }

    /// The bytes of `cycle`'s days.
    #[must_use]
    pub fn cycle_bytes(&self, cycle: BillingCycle) -> CycleBytes {
        self.days.range(cycle.start()..cycle.next_start()).fold(
            CycleBytes::default(),
            |sum, (_, day)| CycleBytes {
                rx: sum.rx.saturating_add(day.rx),
                tx: sum.tx.saturating_add(day.tx),
                short: sum.short || day.short,
            },
        )
    }

    /// The forecast's bins for `cycle` as of `as_of`: every elapsed day of
    /// the cycle, from its first to the day of the last second before
    /// `as_of`, a day with no bytes counted as zero. None before the cycle
    /// has begun.
    pub fn daily(
        &self,
        cycle: BillingCycle,
        as_of: UnixTime,
    ) -> Result<Vec<DailySimBytes>, MeterError> {
        let mut bins = Vec::new();
        let Some(last_second) = as_of.checked_sub_secs(1) else {
            return Ok(bins);
        };
        if as_of <= cycle.starts_at() {
            return Ok(bins);
        }
        let last = CalendarDate::utc_of(last_second)?.min(CalendarDate::from_days_since_epoch(
            cycle.next_start().days_since_epoch() - 1,
        )?);
        let mut date = cycle.start();
        while date <= last {
            let day = self.days.get(&date).copied().unwrap_or_default();
            bins.push(DailySimBytes {
                date,
                bytes: day.rx.saturating_add(day.tx),
            });
            date = date.checked_add_days(1)?;
        }
        Ok(bins)
    }

    /// Drops the days before `first`.
    pub fn retain_from(&mut self, first: CalendarDate) {
        self.days = self.days.split_off(&first);
    }

    /// The document `usage/sim-meter.json` holds.
    pub fn encode(&self) -> Result<Vec<u8>, MeterError> {
        let repr = SimMeterRepr {
            version: SIM_METER_VERSION,
            days: self
                .days
                .iter()
                .map(|(date, day)| DayRepr {
                    date: *date,
                    rx_bytes: day.rx,
                    tx_bytes: day.tx,
                    short: day.short,
                })
                .collect(),
            last: self.last,
        };
        let mut bytes = serde_json::to_vec_pretty(&repr).map_err(|_| MeterError::Corrupt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Reads a meter document: version 1, days in strictly increasing
    /// order, counters below 2^32; anything else is `Corrupt`.
    pub fn decode(bytes: &[u8]) -> Result<Self, MeterError> {
        if bytes.len() > MAX_SIM_METER_BYTES {
            return Err(MeterError::Corrupt);
        }
        let repr: SimMeterRepr = serde_json::from_slice(bytes).map_err(|_| MeterError::Corrupt)?;
        if repr.version != SIM_METER_VERSION {
            return Err(MeterError::Corrupt);
        }
        if repr
            .last
            .is_some_and(|last| last.rx >= COUNTER_MODULUS || last.tx >= COUNTER_MODULUS)
        {
            return Err(MeterError::Corrupt);
        }
        let mut days = BTreeMap::new();
        let mut previous = None;
        for day in repr.days {
            if previous.is_some_and(|previous| previous >= day.date) {
                return Err(MeterError::Corrupt);
            }
            previous = Some(day.date);
            days.insert(
                day.date,
                DayBytes {
                    rx: day.rx_bytes,
                    tx: day.tx_bytes,
                    short: day.short,
                },
            );
        }
        Ok(Self {
            days,
            last: repr.last,
        })
    }
}

/// The bytes between two readings of the same counter, `elapsed` seconds
/// apart (`None`: unknown), and whether they may be short.
fn delta(old: u64, new: u64, elapsed: Option<u64>) -> (u64, bool) {
    // The most the line could carry in the gap, when that is less than a
    // whole wrap; otherwise a wrap may have passed unseen.
    let window = elapsed
        .and_then(|secs| secs.checked_mul(MAX_LINE_BYTES_PER_SEC))
        .filter(|&bytes| bytes < COUNTER_MODULUS);
    match window {
        Some(_) if new >= old => (new - old, false),
        Some(window) if new + (COUNTER_MODULUS - old) <= window => {
            (new + (COUNTER_MODULUS - old), false)
        }
        // Counters that restarted: what they hold now is counted whole, and
        // what they counted after the last reading is lost.
        Some(_) => (new, true),
        None if new >= old => (new - old, true),
        None => (new, true),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimMeterRepr {
    version: u32,
    days: Vec<DayRepr>,
    #[serde(deserialize_with = "Option::deserialize")]
    last: Option<CounterReading>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DayRepr {
    date: CalendarDate,
    rx_bytes: u64,
    tx_bytes: u64,
    short: bool,
}
