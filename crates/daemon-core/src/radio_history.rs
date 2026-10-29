// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history (design §15.6 rule 11, §15.7): what each poll of the M7
//! leaves behind, one [`RadioSample`] per poll, which the daemon appends as
//! one JSON line to the poll day's file (`radio/<YYYY-MM-DD>.jsonl`, kept by
//! `mooring-store`); and the pure analysis `mooringctl router history`
//! prints from the samples: the events between them ([`events`]), hourly
//! statistics ([`hourly`]), and the document Mooring.app reads
//! ([`RadioHistory`]).
//!
//! A sample keeps only what varies and names no one: the readings, the
//! service types, the band, the network's codes (PLMN), the session and
//! uptime counters, the temperature and thermal state, or why a poll
//! failed. The network's display name, the carrier list, the counters,
//! power, Wi-Fi, settings and SMS count stay in the status; cell identity
//! is never recorded (design §15.5).
//!
//! The line carries [`RADIO_SAMPLE_VERSION`], so a day file may span two
//! builds; the document carries [`RADIO_HISTORY_VERSION`]. Nothing here
//! reads a file: the store keeps the bytes and the CLI joins the two.

use std::collections::BTreeMap;

use mooring_model::{CalendarDate, UnixTime};
use serde::{Deserialize, Serialize};

use crate::error::RadioHistoryError;
use crate::router::{
    Band, Celsius, DataService, LteSignal, NetworkService, NrSignal, Plmn, RadioState,
    RouterStatus, RouterUnavailableReason, Rsrp, Sinr, ThermalState,
};

/// The version every sample line carries.
pub const RADIO_SAMPLE_VERSION: u32 = 1;

/// The version a [`RadioHistory`] document carries.
pub const RADIO_HISTORY_VERSION: u32 = 1;

/// The longest sample line, its newline included: the longest line the
/// closed types can give is about 340 bytes.
pub const MAX_RADIO_LINE_BYTES: usize = 1024;

const SECS_PER_HOUR: u64 = 3_600;

/// What one poll of the M7 left: when the Mac polled (its own clock), and
/// what it read or why it could not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioSample {
    /// When the Mac polled.
    pub at: UnixTime,
    /// What the poll gave.
    pub poll: RadioPoll,
}

/// A poll's outcome, as the history keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RadioPoll {
    /// The M7 answered with a status.
    Read(RadioReading),
    /// The poll failed, for the reason the router panel shows.
    Failed {
        /// Why.
        reason: RouterUnavailableReason,
    },
}

/// What a status contributes to the history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioReading {
    /// Seconds since the M7 booted; a decrease shows a reboot.
    pub uptime_secs: u64,
    /// The device temperature.
    pub temperature_c: Celsius,
    /// The modem's thermal state.
    pub thermal: ThermalState,
    /// The radio.
    pub radio: SampledRadio,
}

/// The M7's attachment, as the history keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SampledRadio {
    /// Not attached: no service.
    NoService,
    /// Attached.
    Attached(SampledAttachment),
}

/// The attachment without the network's display name and the carrier
/// list, which the history drops on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampledAttachment {
    /// The network service type.
    pub network_service: NetworkService,
    /// The data service type.
    pub data_service: DataService,
    /// The band in use.
    pub band: Band,
    /// How many secondary carriers the M7 counts.
    pub ca_secondary_count: u8,
    /// The LTE readings.
    pub lte: LteSignal,
    /// The NR readings.
    pub nr: NrSignal,
    /// The network's codes.
    pub plmn: Plmn,
    /// Seconds the data session has lasted; a decrease shows a restart.
    pub session_secs: u64,
}

impl RadioSample {
    /// The sample of a poll at `polled_at` that gave `outcome`.
    #[must_use]
    pub fn of(
        polled_at: UnixTime,
        outcome: Result<&RouterStatus, RouterUnavailableReason>,
    ) -> Self {
        let poll = match outcome {
            Err(reason) => RadioPoll::Failed { reason },
            Ok(status) => {
                let parts = status.parts();
                let radio = match &parts.radio {
                    RadioState::NoService => SampledRadio::NoService,
                    RadioState::Attached(radio) => SampledRadio::Attached(SampledAttachment {
                        network_service: radio.network_service,
                        data_service: radio.data_service,
                        band: radio.band,
                        ca_secondary_count: radio.ca_secondary_count,
                        lte: radio.lte,
                        nr: radio.nr,
                        plmn: radio.plmn,
                        session_secs: radio.session_secs,
                    }),
                };
                RadioPoll::Read(RadioReading {
                    uptime_secs: parts.uptime_secs,
                    temperature_c: parts.temperature_c,
                    thermal: parts.thermal,
                    radio,
                })
            }
        };
        Self {
            at: polled_at,
            poll,
        }
    }
}

/// A line as the file holds it: the sample behind its version.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineRepr {
    version: u32,
    at: UnixTime,
    poll: RadioPoll,
}

/// The version alone, read first and leniently, so a line of another
/// version is refused as such whatever keys it adds.
#[derive(Deserialize)]
struct LineVersion {
    version: u32,
}

/// The line of `sample`: one compact JSON document, its version first, and
/// a newline. `LineTooLong` past [`MAX_RADIO_LINE_BYTES`] (unreachable for
/// these closed types; kept as the invariant the reader relies on).
pub fn encode_line(sample: &RadioSample) -> Result<Vec<u8>, RadioHistoryError> {
    let repr = LineRepr {
        version: RADIO_SAMPLE_VERSION,
        at: sample.at,
        poll: sample.poll,
    };
    let mut line = serde_json::to_vec(&repr).map_err(|_| RadioHistoryError::Unencodable)?;
    line.push(b'\n');
    if line.len() > MAX_RADIO_LINE_BYTES {
        return Err(RadioHistoryError::LineTooLong { bytes: line.len() });
    }
    Ok(line)
}

/// The sample of one whole line, its newline included: `LineTooLong` past
/// the bound, `UnsupportedVersion` for another version, and `Undecodable`
/// for anything else (a line without its newline, a key the sample does
/// not name, a value outside its rule). No error holds a byte of the line.
pub fn decode_line(line: &[u8]) -> Result<RadioSample, RadioHistoryError> {
    if line.len() > MAX_RADIO_LINE_BYTES {
        return Err(RadioHistoryError::LineTooLong { bytes: line.len() });
    }
    let body = line
        .strip_suffix(b"\n")
        .ok_or(RadioHistoryError::Undecodable)?;
    let probe: LineVersion =
        serde_json::from_slice(body).map_err(|_| RadioHistoryError::Undecodable)?;
    if probe.version != RADIO_SAMPLE_VERSION {
        return Err(RadioHistoryError::UnsupportedVersion {
            version: probe.version,
        });
    }
    let repr: LineRepr =
        serde_json::from_slice(body).map_err(|_| RadioHistoryError::Undecodable)?;
    Ok(RadioSample {
        at: repr.at,
        poll: repr.poll,
    })
}

/// A change between two polls, at the poll that shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioEvent {
    /// The poll that showed the change.
    pub at: UnixTime,
    /// The change.
    pub kind: RadioEventKind,
}

/// What changed between two polls. At one poll several may show; they come
/// in this order: the poll's own outcome, a reboot, then the radio's
/// changes in field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RadioEventKind {
    /// A poll failed after a read, or for another reason than the failed
    /// poll before it.
    PollFailed {
        /// Why.
        reason: RouterUnavailableReason,
    },
    /// A read after a failed poll.
    PollRecovered,
    /// The uptime is shorter than at the last read: the M7 rebooted (its
    /// data session restarted with it, which is not reported again).
    RouterRebooted,
    /// Attached at the last read, no service now.
    ServiceLost,
    /// No service at the last read, attached now. It is compared with the
    /// no-service read, so what differs across the gap is no event.
    ServiceRegained,
    /// The network service type changed (`Nr5gService` to `LteService` is
    /// the 5G to 4G fallback).
    NetworkServiceChanged {
        /// Before.
        from: NetworkService,
        /// After.
        to: NetworkService,
    },
    /// The data service type changed.
    DataServiceChanged {
        /// Before.
        from: DataService,
        /// After.
        to: DataService,
    },
    /// The band changed.
    BandChanged {
        /// Before.
        from: Band,
        /// After.
        to: Band,
    },
    /// The network's codes changed.
    PlmnChanged {
        /// Before.
        from: Plmn,
        /// After.
        to: Plmn,
    },
    /// The data session is shorter than at the last read, while the uptime
    /// is not: the session restarted.
    SessionRestarted,
}

/// The changes `samples` show, in the samples' order (the poll order, which
/// a clock that stepped back does not change). The first sample is never
/// an event. A poll's outcome is compared with the poll before it; the
/// radio and the uptime with the last *read*, so a reboot or a band change
/// behind failed polls shows at the recovery.
#[must_use]
pub fn events(samples: &[RadioSample]) -> Vec<RadioEvent> {
    let mut events = Vec::new();
    let mut previous: Option<&RadioPoll> = None;
    let mut last_read: Option<&RadioReading> = None;
    for sample in samples {
        let at = sample.at;
        let mut push = |kind| events.push(RadioEvent { at, kind });
        match (&sample.poll, previous) {
            (_, None) | (RadioPoll::Read(_), Some(RadioPoll::Read(_))) => {}
            (RadioPoll::Failed { reason }, Some(RadioPoll::Failed { reason: before })) => {
                if reason != before {
                    push(RadioEventKind::PollFailed { reason: *reason });
                }
            }
            (RadioPoll::Failed { reason }, Some(RadioPoll::Read(_))) => {
                push(RadioEventKind::PollFailed { reason: *reason });
            }
            (RadioPoll::Read(_), Some(RadioPoll::Failed { .. })) => {
                push(RadioEventKind::PollRecovered);
            }
        }
        if let RadioPoll::Read(reading) = &sample.poll {
            if let Some(before) = last_read {
                radio_changes(before, reading, &mut push);
            }
            last_read = Some(reading);
        }
        previous = Some(&sample.poll);
    }
    events
}

/// The changes from `before` to `after`, in their fixed order.
fn radio_changes(
    before: &RadioReading,
    after: &RadioReading,
    push: &mut impl FnMut(RadioEventKind),
) {
    let rebooted = after.uptime_secs < before.uptime_secs;
    if rebooted {
        push(RadioEventKind::RouterRebooted);
    }
    match (&before.radio, &after.radio) {
        (SampledRadio::NoService, SampledRadio::NoService) => {}
        (SampledRadio::Attached(_), SampledRadio::NoService) => push(RadioEventKind::ServiceLost),
        (SampledRadio::NoService, SampledRadio::Attached(_)) => {
            push(RadioEventKind::ServiceRegained);
        }
        (SampledRadio::Attached(a), SampledRadio::Attached(b)) => {
            if a.network_service != b.network_service {
                push(RadioEventKind::NetworkServiceChanged {
                    from: a.network_service,
                    to: b.network_service,
                });
            }
            if a.data_service != b.data_service {
                push(RadioEventKind::DataServiceChanged {
                    from: a.data_service,
                    to: b.data_service,
                });
            }
            if a.band != b.band {
                push(RadioEventKind::BandChanged {
                    from: a.band,
                    to: b.band,
                });
            }
            if a.plmn != b.plmn {
                push(RadioEventKind::PlmnChanged {
                    from: a.plmn,
                    to: b.plmn,
                });
            }
            if b.session_secs < a.session_secs && !rebooted {
                push(RadioEventKind::SessionRestarted);
            }
        }
    }
}

/// The minimum, median and maximum of some readings. The median of an even
/// count is the lower middle value, so it is a reading that was reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stats<T> {
    /// The lowest reading.
    pub min: T,
    /// The median reading.
    pub median: T,
    /// The highest reading.
    pub max: T,
}

/// One UTC hour with at least one poll.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HourBin {
    /// The hour's first second.
    pub start: UnixTime,
    /// How many polls fell in the hour.
    pub polls: usize,
    /// How many of them read a status.
    pub read: usize,
    /// How many of those read no service.
    pub no_service: usize,
    /// The network service types seen, each once, in the vocabulary's
    /// order.
    pub services: Vec<NetworkService>,
    /// LTE RSRP over the readings reported.
    pub lte_rsrp: Option<Stats<Rsrp>>,
    /// LTE SINR over the readings reported.
    pub lte_sinr: Option<Stats<Sinr>>,
    /// NR RSRP over the readings reported.
    pub nr_rsrp: Option<Stats<Rsrp>>,
    /// NR SINR over the readings reported.
    pub nr_sinr: Option<Stats<Sinr>>,
}

/// The samples per UTC hour, by their times, in time order; hours without
/// a sample are left out, and a reading the M7 did not report is skipped.
#[must_use]
pub fn hourly(samples: &[RadioSample]) -> Vec<HourBin> {
    let mut hours: BTreeMap<u64, Vec<&RadioSample>> = BTreeMap::new();
    for sample in samples {
        hours
            .entry(sample.at.as_secs() / SECS_PER_HOUR)
            .or_default()
            .push(sample);
    }
    hours
        .into_iter()
        .map(|(hour, samples)| bin(UnixTime::from_secs(hour * SECS_PER_HOUR), &samples))
        .collect()
}

fn bin(start: UnixTime, samples: &[&RadioSample]) -> HourBin {
    let mut read = 0;
    let mut no_service = 0;
    let mut services: Vec<NetworkService> = Vec::new();
    let mut lte_rsrp = Vec::new();
    let mut lte_sinr = Vec::new();
    let mut nr_rsrp = Vec::new();
    let mut nr_sinr = Vec::new();
    for sample in samples {
        let RadioPoll::Read(reading) = &sample.poll else {
            continue;
        };
        read += 1;
        match &reading.radio {
            SampledRadio::NoService => no_service += 1,
            SampledRadio::Attached(radio) => {
                if !services.contains(&radio.network_service) {
                    services.push(radio.network_service);
                }
                lte_rsrp.extend(radio.lte.rsrp);
                lte_sinr.extend(radio.lte.sinr);
                nr_rsrp.extend(radio.nr.rsrp);
                nr_sinr.extend(radio.nr.sinr);
            }
        }
    }
    services.sort_by_key(|service| NetworkService::ALL.iter().position(|v| v == service));
    HourBin {
        start,
        polls: samples.len(),
        read,
        no_service,
        services,
        lte_rsrp: stats(lte_rsrp),
        lte_sinr: stats(lte_sinr),
        nr_rsrp: stats(nr_rsrp),
        nr_sinr: stats(nr_sinr),
    }
}

/// The statistics of `values`; none of none.
fn stats<T: Copy + Ord>(mut values: Vec<T>) -> Option<Stats<T>> {
    values.sort_unstable();
    let (Some(&min), Some(&max)) = (values.first(), values.last()) else {
        return None;
    };
    let median = *values.get((values.len() - 1) / 2)?;
    Some(Stats { min, median, max })
}

/// What `mooringctl router history --json` prints: the UTC days asked for,
/// the samples of those days in their order, the events they show, and
/// the days whose file ends in an incomplete line. On the wire it carries
/// its version, which must be [`RADIO_HISTORY_VERSION`], refuses an unknown
/// key, and refuses events that do not follow from its samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RadioHistoryRepr", into = "RadioHistoryRepr")]
pub struct RadioHistory {
    since: CalendarDate,
    until: CalendarDate,
    samples: Vec<RadioSample>,
    events: Vec<RadioEvent>,
    incomplete_days: Vec<CalendarDate>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RadioHistoryRepr {
    version: u32,
    since: CalendarDate,
    until: CalendarDate,
    samples: Vec<RadioSample>,
    events: Vec<RadioEvent>,
    incomplete_days: Vec<CalendarDate>,
}

impl RadioHistory {
    /// The history of the days `since` to `until` with `samples`, whose
    /// events it computes, and the days whose file ends in an incomplete
    /// line.
    #[must_use]
    pub fn new(
        since: CalendarDate,
        until: CalendarDate,
        samples: Vec<RadioSample>,
        incomplete_days: Vec<CalendarDate>,
    ) -> Self {
        let events = events(&samples);
        Self {
            since,
            until,
            samples,
            events,
            incomplete_days,
        }
    }

    /// The first day asked for.
    #[must_use]
    pub const fn since(&self) -> CalendarDate {
        self.since
    }

    /// The last day asked for.
    #[must_use]
    pub const fn until(&self) -> CalendarDate {
        self.until
    }

    /// The samples, in their order.
    #[must_use]
    pub fn samples(&self) -> &[RadioSample] {
        &self.samples
    }

    /// The events the samples show.
    #[must_use]
    pub fn events(&self) -> &[RadioEvent] {
        &self.events
    }

    /// The days whose file ends in an incomplete line.
    #[must_use]
    pub fn incomplete_days(&self) -> &[CalendarDate] {
        &self.incomplete_days
    }
}

impl TryFrom<RadioHistoryRepr> for RadioHistory {
    type Error = RadioHistoryError;

    fn try_from(repr: RadioHistoryRepr) -> Result<Self, Self::Error> {
        if repr.version != RADIO_HISTORY_VERSION {
            return Err(RadioHistoryError::UnsupportedDocumentVersion {
                found: repr.version,
            });
        }
        let history = Self::new(repr.since, repr.until, repr.samples, repr.incomplete_days);
        if history.events != repr.events {
            return Err(RadioHistoryError::EventsMismatch);
        }
        Ok(history)
    }
}

impl From<RadioHistory> for RadioHistoryRepr {
    fn from(history: RadioHistory) -> Self {
        Self {
            version: RADIO_HISTORY_VERSION,
            since: history.since,
            until: history.until,
            samples: history.samples,
            events: history.events,
            incomplete_days: history.incomplete_days,
        }
    }
}
