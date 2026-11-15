// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's capacity samples (console spec B.2.8, design §15.3). On
//! every tick on which the exit probes and the SIM meter's readings cover
//! the last minute, a sample of the egress rates over that minute and of
//! the latest direct-probe round's round trip goes to `daemon-core`'s
//! [`CapacityMonitor`], and the status carries the monitor's view; on any
//! other tick it carries none. A sample is dated by the tick's clock: a
//! tick in the same second as the last sample takes none and keeps its
//! view, and a clock that stepped back is said, and saturation is timed
//! anew from the sample.
//!
//! The round trip of each round that passed is recorded once, against the
//! node that answered ([`RoundTrips`]), with its idle reference: that
//! node's 10th percentile over the last day. A round that failed leaves
//! the sample without a round trip. Only nodes with a site are kept. The
//! record is written to `run/round-trips.json` when it changed, at most
//! every `Intervals::round_trips_persist`, so that a restart keeps the
//! reference; a record that cannot be read at the start is said and
//! replaced, and a write that fails is said, kept in memory, and tried
//! again [`WRITE_RETRY`] later.
//!
//! The uplink baseline is the deployment's (`ExitSite::uplink_baseline`),
//! read at every tick: a change of it is said, and the monitor starts
//! again with it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_daemon_core::capacity::rates::EgressRate;
use mooring_daemon_core::capacity::round_trips::{MAX_ROUND_TRIPS_BYTES, RoundTrips};
use mooring_daemon_core::capacity::{
    CapacityMonitor, CapacitySample, CapacityStatus, CapacityThresholds, RttSample,
};
use mooring_daemon_core::error::CapacityError;
use mooring_daemon_core::exit::RoundTrip;
use mooring_model::time::UnixTime;
use mooring_model::{Deployment, UplinkBaseline};
use mooring_store::{read_round_trips, write_round_trips};

/// How long after a failed write the record is written again.
pub(crate) const WRITE_RETRY: Duration = Duration::from_secs(60);

/// What the exit machine says of the direct probes after a tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probed {
    /// Whether the tick reached them.
    pub(crate) probing: bool,
    /// The latest round's round trip, when it passed.
    pub(crate) round_trip: Option<RoundTrip>,
}

/// The capacity monitor and the record of round trips, between ticks.
#[derive(Debug)]
pub(crate) struct Capacity {
    run_dir: PathBuf,
    persist_every: Duration,
    baseline: Option<UplinkBaseline>,
    monitor: CapacityMonitor,
    /// The monitor's latest view.
    view: Option<CapacityStatus>,
    /// Whether the latest tick took a sample.
    sampling: bool,
    round_trips: RoundTrips,
    /// The round last recorded, by when it ran, with its round trip and
    /// idle reference.
    recorded: Option<(Duration, RttSample)>,
    /// Whether the file differs from `round_trips`.
    unwritten: bool,
    /// When the record was last written.
    written_at: Option<Instant>,
    /// When a failed write is tried again.
    retry_at: Option<Instant>,
}

impl Capacity {
    /// The monitor on `baseline`, with the record in `run_dir`, written at
    /// most every `persist_every`; and what to say about a record that
    /// cannot be read.
    pub(crate) fn open(
        run_dir: &Path,
        baseline: Option<UplinkBaseline>,
        persist_every: Duration,
    ) -> (Self, Option<String>) {
        let read = match read_round_trips(run_dir, MAX_ROUND_TRIPS_BYTES + 1) {
            Ok(None) => Ok(RoundTrips::new()),
            Ok(Some(bytes)) => RoundTrips::decode(&bytes).map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let (round_trips, note) = match read {
            Ok(round_trips) => (round_trips, None),
            Err(error) => (
                RoundTrips::new(),
                Some(format!(
                    "capacity: the record of direct-probe round trips cannot be read ({error}); the idle reference starts again, and the record is written again"
                )),
            ),
        };
        let unwritten = note.is_some();
        (
            Self {
                run_dir: run_dir.to_path_buf(),
                persist_every,
                baseline,
                monitor: CapacityMonitor::new(CapacityThresholds::DEFAULT, baseline),
                view: None,
                sampling: false,
                round_trips,
                recorded: None,
                unwritten,
                written_at: None,
                retry_at: None,
            },
            note,
        )
    }

    /// One tick at `now`, after the exit machine's: records the round's
    /// round trip, samples while the exit probes and `rates` cover the
    /// last minute, and writes the record when it changed and a write is
    /// due. Returns what to say.
    pub(crate) fn track(
        &mut self,
        deployment: &Deployment,
        now: UnixTime,
        probed: &Probed,
        rates: Option<EgressRate>,
        instant: Instant,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let baseline = deployment.exit().uplink_baseline;
        if baseline != self.baseline {
            self.baseline = baseline;
            self.monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, baseline);
            notes.push(match baseline {
                Some(baseline) => format!(
                    "capacity: the uplink baseline is now a median of {} bit/s; saturation is timed anew",
                    baseline.p50_bps()
                ),
                None => "capacity: no uplink baseline is recorded any more; saturation is timed anew"
                    .to_owned(),
            });
        }
        if self.round_trips.retain(|id| {
            deployment
                .nodes()
                .get(id)
                .is_some_and(|node| node.lifecycle.site().is_some())
        }) {
            self.unwritten = true;
        }
        let rtt = probed
            .round_trip
            .as_ref()
            .map(|round| self.round_sample(round, now));
        self.sampling = probed.probing && rates.is_some();
        if let (true, Some(rates)) = (probed.probing, rates) {
            let sample = CapacitySample {
                at: now,
                tx_bps: rates.tx_bps,
                rx_bps: rates.rx_bps,
                rtt,
            };
            match self.monitor.observe(sample) {
                Ok(view) => self.view = Some(view),
                // Another tick in the same second: its view stands.
                Err(CapacityError::SampleOutOfOrder { previous, at }) if previous == at => {}
                Err(error) => {
                    notes.push(format!(
                        "capacity: {error}: the clock stepped back, and saturation is timed anew from this sample"
                    ));
                    self.view = Some(self.monitor.restart(sample));
                }
            }
        }
        notes.extend(self.write(instant));
        notes
    }

    /// The view the status carries: the monitor's, while the latest tick
    /// took a sample.
    pub(crate) fn status(&self) -> Option<CapacityStatus> {
        self.view.filter(|_| self.sampling)
    }

    /// `round`'s round trip with its idle reference, recorded the first
    /// time the round is seen.
    fn round_sample(&mut self, round: &RoundTrip, now: UnixTime) -> RttSample {
        if let Some((probed, sample)) = self.recorded
            && probed == round.probed
        {
            return sample;
        }
        let ms = u64::try_from(round.rtt.as_millis()).unwrap_or(u64::MAX);
        let sample = self.round_trips.record(&round.node, now, ms);
        self.recorded = Some((round.probed, sample));
        self.unwritten = true;
        sample
    }

    /// Writes the record when it changed and its interval has passed since
    /// the last write, or a failed write is due again; what to say about a
    /// write that fails.
    fn write(&mut self, instant: Instant) -> Option<String> {
        if !self.unwritten {
            return None;
        }
        let due = match self.retry_at {
            Some(at) => instant >= at,
            None => self
                .written_at
                .is_none_or(|at| instant.saturating_duration_since(at) >= self.persist_every),
        };
        if !due {
            return None;
        }
        let written = self
            .round_trips
            .encode()
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                write_round_trips(&self.run_dir, &bytes).map_err(|error| error.to_string())
            });
        match written {
            Ok(()) => {
                self.unwritten = false;
                self.written_at = Some(instant);
                self.retry_at = None;
                None
            }
            Err(error) => {
                self.retry_at = Some(instant + WRITE_RETRY);
                Some(format!(
                    "capacity: the record of direct-probe round trips could not be written ({error}); the idle reference is kept in memory, and the record is written again in {} s",
                    WRITE_RETRY.as_secs()
                ))
            }
        }
    }
}
