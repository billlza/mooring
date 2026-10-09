// SPDX-License-Identifier: GPL-3.0-or-later

//! The capacity monitor (console spec B.2.8): whether the uplink over the
//! mobile line (SMARTY, decision F1) is saturated.
//!
//! Saturation looks like a uniformly slow service while every probe stays
//! green (spec D.1), so two signals are watched: the egress transmit rate as
//! a share of the measured uplink median (`UplinkBaseline::p50_bps`), and
//! how far the direct-probe round trip has risen above its idle 10th
//! percentile. The line counts as saturated once either signal has been at
//! or above its threshold for a hold time, measured over samples that
//! follow each other closely enough to show it held.
//!
//! The defaults ([`CapacityThresholds::DEFAULT`]: 85%, 200 ms, 10 minutes,
//! samples at most 2 minutes apart) are inference from the console spec,
//! to be calibrated with M8's measurements; they are values the daemon
//! passes in, not constants of the logic.

use std::num::{NonZeroU16, NonZeroU64};

use mooring_model::{UnixTime, UplinkBaseline};
use serde::{Deserialize, Serialize};

use crate::error::CapacityError;

/// The thresholds of the saturation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityThresholds {
    /// Uplink use, as a percentage of the baseline median, at or above
    /// which the uplink counts as full.
    pub uplink_use_percent: NonZeroU16,
    /// Round-trip inflation, in milliseconds, at or above which the queue
    /// counts as full.
    pub rtt_inflation_ms: NonZeroU64,
    /// How long, in seconds, a signal must stay at or above its threshold.
    pub hold_secs: NonZeroU64,
    /// The longest gap between samples, in seconds, across which a signal
    /// still counts as having held; a longer gap restarts the hold.
    pub max_sample_gap_secs: NonZeroU64,
}

impl CapacityThresholds {
    /// 85%, 200 ms, held 10 minutes over samples at most 2 minutes apart
    /// (inference; calibrated in M8).
    pub const DEFAULT: Self = Self {
        uplink_use_percent: match NonZeroU16::new(85) {
            Some(percent) => percent,
            None => panic!("85 is not zero"),
        },
        rtt_inflation_ms: match NonZeroU64::new(200) {
            Some(ms) => ms,
            None => panic!("200 is not zero"),
        },
        hold_secs: match NonZeroU64::new(600) {
            Some(secs) => secs,
            None => panic!("600 is not zero"),
        },
        max_sample_gap_secs: match NonZeroU64::new(120) {
            Some(secs) => secs,
            None => panic!("120 is not zero"),
        },
    };
}

/// One direct-probe round trip and the idle reference it is compared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RttSample {
    /// The latest direct-probe round trip, in milliseconds.
    pub loaded_ms: u64,
    /// The 10th percentile of the direct-probe round trip over the last
    /// 24 hours, in milliseconds: the idle reference.
    pub idle_p10_ms: u64,
}

impl RttSample {
    /// How far the round trip is above its idle reference, in milliseconds;
    /// zero when it is not above it.
    #[must_use]
    pub const fn inflation_ms(self) -> u64 {
        self.loaded_ms.saturating_sub(self.idle_p10_ms)
    }
}

/// One reading of the egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacitySample {
    /// When the reading was taken.
    pub at: UnixTime,
    /// The egress transmit rate (towards the carrier), in bit/s, averaged over the
    /// last minute.
    pub tx_bps: u64,
    /// The egress receive rate, in bit/s, averaged over the last minute.
    pub rx_bps: u64,
    /// The latest direct-probe round trip; `None` when the probe failed,
    /// which leaves only the rate signal.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rtt: Option<RttSample>,
}

/// The uplink's use against its measured baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UplinkUse {
    /// No baseline is recorded yet (`ExitSite::uplink_baseline` is `None`
    /// until M2 measures it), so the use cannot be expressed as a share.
    NoBaseline,
    /// The transmit rate as a share of the baseline median.
    Measured {
        /// The share in tenths of a percent (1000 is the median itself);
        /// it can exceed 1000.
        permille: u64,
        /// The baseline median it is measured against, in bit/s.
        baseline_p50_bps: u64,
    },
}

/// Whether the uplink is saturated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Saturation {
    /// Neither signal is available (no baseline and no round trip), so
    /// nothing can be said either way.
    NoEvidence,
    /// No available signal is at its threshold.
    Clear,
    /// A signal has been at its threshold since `since`, for less than the
    /// hold time.
    Building {
        /// When the current run started.
        since: UnixTime,
    },
    /// A signal has been at its threshold since `since`, for at least the
    /// hold time.
    Saturated {
        /// When the current run started.
        since: UnixTime,
    },
}

/// The capacity view after a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityStatus {
    /// The sample's time.
    pub at: UnixTime,
    /// The egress transmit rate, in bit/s.
    pub tx_bps: u64,
    /// The egress receive rate, in bit/s.
    pub rx_bps: u64,
    /// The uplink's use against its baseline.
    pub uplink_use: UplinkUse,
    /// The round-trip inflation in milliseconds; `None` when the probe
    /// failed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rtt_inflation_ms: Option<u64>,
    /// The saturation verdict.
    pub saturation: Saturation,
}

/// The saturation rule as a state machine over time-ordered samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityMonitor {
    thresholds: CapacityThresholds,
    baseline: Option<UplinkBaseline>,
    last_at: Option<UnixTime>,
    run_since: Option<UnixTime>,
}

impl CapacityMonitor {
    /// A monitor with no samples yet. `baseline` is the exit site's
    /// recorded uplink baseline, if any.
    #[must_use]
    pub const fn new(thresholds: CapacityThresholds, baseline: Option<UplinkBaseline>) -> Self {
        Self {
            thresholds,
            baseline,
            last_at: None,
            run_since: None,
        }
    }

    /// Takes in the next sample, which must be later than the previous one
    /// (`SampleOutOfOrder` otherwise, leaving the monitor unchanged), and
    /// returns the view after it.
    pub fn observe(&mut self, sample: CapacitySample) -> Result<CapacityStatus, CapacityError> {
        if let Some(previous) = self.last_at
            && sample.at <= previous
        {
            return Err(CapacityError::SampleOutOfOrder {
                previous,
                at: sample.at,
            });
        }
        let uplink_use = match self.baseline {
            None => UplinkUse::NoBaseline,
            Some(baseline) => UplinkUse::Measured {
                permille: permille(sample.tx_bps, &baseline),
                baseline_p50_bps: baseline.p50_bps(),
            },
        };
        let rtt_inflation_ms = sample.rtt.map(RttSample::inflation_ms);
        let use_full = match uplink_use {
            UplinkUse::NoBaseline => None,
            UplinkUse::Measured { permille, .. } => {
                Some(permille >= u64::from(self.thresholds.uplink_use_percent.get()) * 10)
            }
        };
        let queue_full =
            rtt_inflation_ms.map(|inflation| inflation >= self.thresholds.rtt_inflation_ms.get());
        let continuous = self.last_at.is_some_and(|previous| {
            sample.at.as_secs() - previous.as_secs() <= self.thresholds.max_sample_gap_secs.get()
        });
        let saturation = match (use_full, queue_full) {
            (None, None) => {
                self.run_since = None;
                Saturation::NoEvidence
            }
            (Some(true), _) | (_, Some(true)) => {
                let since = match self.run_since {
                    Some(since) if continuous => since,
                    _ => sample.at,
                };
                self.run_since = Some(since);
                if sample.at.as_secs() - since.as_secs() >= self.thresholds.hold_secs.get() {
                    Saturation::Saturated { since }
                } else {
                    Saturation::Building { since }
                }
            }
            _ => {
                self.run_since = None;
                Saturation::Clear
            }
        };
        self.last_at = Some(sample.at);
        Ok(CapacityStatus {
            at: sample.at,
            tx_bps: sample.tx_bps,
            rx_bps: sample.rx_bps,
            uplink_use,
            rtt_inflation_ms,
            saturation,
        })
    }
}

/// `rate` as tenths of a percent of the baseline median, rounded down.
/// The model keeps the median positive (`0 < p10 <= p50`), so the division
/// is defined. A share beyond `u64::MAX` tenths of a percent (a rate over
/// 10^16 times the median) is reported as `u64::MAX`, which is just as far
/// above every threshold.
fn permille(rate: u64, baseline: &UplinkBaseline) -> u64 {
    let value = u128::from(rate) * 1000 / u128::from(baseline.p50_bps());
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::error::CapacityErrorKind;

    const MBIT: u64 = 1_000_000;

    fn baseline() -> UplinkBaseline {
        UplinkBaseline::new(5 * MBIT, 16 * MBIT, UnixTime::from_secs(1)).unwrap()
    }

    fn sample(at: u64, tx_bps: u64, rtt: Option<(u64, u64)>) -> CapacitySample {
        CapacitySample {
            at: UnixTime::from_secs(at),
            tx_bps,
            rx_bps: 3 * tx_bps,
            rtt: rtt.map(|(loaded_ms, idle_p10_ms)| RttSample {
                loaded_ms,
                idle_p10_ms,
            }),
        }
    }

    fn run(monitor: &mut CapacityMonitor, samples: &[CapacitySample]) -> Vec<Saturation> {
        samples
            .iter()
            .map(|&sample| monitor.observe(sample).unwrap().saturation)
            .collect()
    }

    #[test]
    fn the_uplink_saturates_after_ten_minutes_at_85_percent() {
        let mut monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, Some(baseline()));
        // 13.6 Mbit/s is exactly 85% of the 16 Mbit/s median.
        let full = 13_600_000;
        let samples: Vec<_> = (0..=10)
            .map(|minute| sample(1_000 + minute * 60, full, None))
            .collect();
        let seen = run(&mut monitor, &samples);
        let since = UnixTime::from_secs(1_000);
        assert!(
            seen[..10]
                .iter()
                .all(|state| *state == Saturation::Building { since })
        );
        assert_eq!(seen[10], Saturation::Saturated { since });
        let status = monitor
            .observe(sample(1_700, full - 1, Some((40, 30))))
            .unwrap();
        assert_eq!(
            status.uplink_use,
            UplinkUse::Measured {
                permille: 849,
                baseline_p50_bps: 16 * MBIT
            }
        );
        assert_eq!(status.rtt_inflation_ms, Some(10));
        assert_eq!(status.saturation, Saturation::Clear);
    }

    #[test]
    fn round_trip_inflation_alone_saturates_without_a_baseline() {
        let mut monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, None);
        let samples: Vec<_> = (0..=10)
            .map(|minute| sample(minute * 60 + 60, MBIT, Some((230, 30))))
            .collect();
        let seen = run(&mut monitor, &samples);
        assert_eq!(
            seen[10],
            Saturation::Saturated {
                since: UnixTime::from_secs(60)
            }
        );
        let status = monitor.observe(sample(800, MBIT, Some((229, 30)))).unwrap();
        assert_eq!(status.uplink_use, UplinkUse::NoBaseline);
        assert_eq!(status.saturation, Saturation::Clear);
        // No baseline and a failed probe: no evidence either way.
        let status = monitor.observe(sample(860, 100 * MBIT, None)).unwrap();
        assert_eq!(status.saturation, Saturation::NoEvidence);
        assert_eq!(status.rtt_inflation_ms, None);
    }

    #[test]
    fn a_gap_between_samples_restarts_the_hold() {
        let mut monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, Some(baseline()));
        let full = 15 * MBIT;
        let seen = run(
            &mut monitor,
            &[
                sample(0, full, None),
                sample(120, full, None),
                // 121 s after the last sample: the run restarts.
                sample(241, full, None),
                sample(841, full, None),
            ],
        );
        assert_eq!(
            seen[1],
            Saturation::Building {
                since: UnixTime::from_secs(0)
            }
        );
        assert_eq!(
            seen[2],
            Saturation::Building {
                since: UnixTime::from_secs(241)
            }
        );
        // 600 s after 241, but the gap to 841 is 600 s: the run restarts again.
        assert_eq!(
            seen[3],
            Saturation::Building {
                since: UnixTime::from_secs(841)
            }
        );
    }

    #[test]
    fn samples_must_move_forward() {
        let mut monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, Some(baseline()));
        monitor.observe(sample(100, MBIT, None)).unwrap();
        let before = monitor.clone();
        let error = monitor.observe(sample(100, MBIT, None)).unwrap_err();
        assert_eq!(
            error,
            CapacityError::SampleOutOfOrder {
                previous: UnixTime::from_secs(100),
                at: UnixTime::from_secs(100)
            }
        );
        assert_eq!(error.kind(), CapacityErrorKind::SampleOutOfOrder);
        assert!(!error.to_string().is_empty());
        assert_eq!(monitor, before, "a refused sample changes nothing");
        assert_eq!(
            CapacityErrorKind::ALL,
            [CapacityErrorKind::SampleOutOfOrder]
        );
    }

    #[test]
    fn use_is_measured_in_tenths_of_a_percent() {
        assert_eq!(permille(16 * MBIT, &baseline()), 1000);
        assert_eq!(permille(0, &baseline()), 0);
        assert_eq!(permille(24 * MBIT, &baseline()), 1500);
        let tiny = UplinkBaseline::new(1, 1, UnixTime::from_secs(1)).unwrap();
        assert_eq!(permille(u64::MAX, &tiny), u64::MAX);
        assert_eq!(
            serde_json::to_string(&CapacityThresholds::DEFAULT).unwrap(),
            r#"{"uplink_use_percent":85,"rtt_inflation_ms":200,"hold_secs":600,"max_sample_gap_secs":120}"#
        );
    }

    proptest! {
        /// Over any time-ordered samples: the verdict is Saturated exactly
        /// when every sample from its start to now was at a threshold, the
        /// samples were at most the maximum gap apart, and the run lasted
        /// the hold time; and a run starts at its first hot sample.
        #[test]
        fn saturation_follows_its_definition(
            steps in proptest::collection::vec((1_u64..200, 0_u64..20, proptest::option::of((0_u64..600, 0_u64..100))), 1..60),
            with_baseline in any::<bool>(),
        ) {
            let thresholds = CapacityThresholds::DEFAULT;
            let mut monitor = CapacityMonitor::new(thresholds, with_baseline.then(baseline));
            let mut at = 0;
            let mut history: Vec<(u64, Option<bool>)> = Vec::new();
            for (gap, mbit, rtt) in steps {
                at += gap;
                let sample = sample(at, mbit * MBIT, rtt);
                let use_full = with_baseline.then(|| mbit * MBIT * 1000 / (16 * MBIT) >= 850);
                let queue_full = rtt.map(|(loaded, idle)| loaded.saturating_sub(idle) >= 200);
                let hot = match (use_full, queue_full) {
                    (None, None) => None,
                    (a, b) => Some(a == Some(true) || b == Some(true)),
                };
                history.push((at, hot));
                // The expected run start: walk back over hot samples that
                // follow each other within the gap.
                let expected = if hot == Some(true) {
                    let mut start = history.len() - 1;
                    while start > 0
                        && history[start - 1].1 == Some(true)
                        && history[start].0 - history[start - 1].0 <= 120
                    {
                        start -= 1;
                    }
                    let since = UnixTime::from_secs(history[start].0);
                    if at - history[start].0 >= 600 {
                        Saturation::Saturated { since }
                    } else {
                        Saturation::Building { since }
                    }
                } else if hot.is_none() {
                    Saturation::NoEvidence
                } else {
                    Saturation::Clear
                };
                prop_assert_eq!(monitor.observe(sample).unwrap().saturation, expected);
            }
        }
    }
}
