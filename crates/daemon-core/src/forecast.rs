// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM forecast (console spec B.2.6): from the SIM meter's bytes per
//! UTC day in the current billing cycle, the cycle-to-date daily average,
//! a linear projection to the end of the cycle, and the day each threshold
//! was crossed or is projected to be crossed.
//!
//! The projection is linear in the cycle-to-date average rate. That is an
//! inference, not a model of how use varies through a cycle: early in a
//! cycle it rests on few days, and it does not know about a planned change
//! of use. It is shown next to the elapsed days so the reader can weigh it.
//!
//! The meter's bins must cover every elapsed day of the cycle, in order,
//! each exactly once. A missing day is refused rather than read as zero,
//! and an empty input is refused rather than projected as zero.

use mooring_model::sim::{PlanLineKind, SimThresholds};
use mooring_model::{CalendarDate, SimPolicy, UnixTime};
use serde::{Deserialize, Serialize};

use crate::error::ForecastError;
use crate::period::BillingCycle;

/// The SIM bytes (both directions) the meter counted on one UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailySimBytes {
    /// The UTC day.
    pub date: CalendarDate,
    /// The bytes counted on it; for the day of the reading, up to the
    /// reading.
    pub bytes: u64,
}

/// A threshold the SIM meter is compared with, as a forecast crossing
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimThreshold {
    /// The warning threshold (`SimWarn`).
    Warn,
    /// The hard stop (`SimCapReached`).
    HardStop,
    /// An unlimited plan's fair-use line.
    FairUse,
    /// A capped plan's allowance.
    Allowance,
}

/// Every threshold of `thresholds` with its bytes, in increasing order of
/// bytes (the model's `SimThresholds` invariant orders them: warning, hard
/// stop, line). The status stream carries the model's `SimThresholds`
/// itself, with its stop policy and the line's kind, checked on decode as
/// the policy is.
#[must_use]
pub fn ordered(thresholds: &SimThresholds) -> Vec<(SimThreshold, u64)> {
    let mut ordered = vec![(SimThreshold::Warn, thresholds.warn_bytes())];
    if let Some(bytes) = thresholds.stop().hard_stop_bytes() {
        ordered.push((SimThreshold::HardStop, bytes));
    }
    if let Some(line) = thresholds.plan_line() {
        let threshold = match line.kind {
            PlanLineKind::FairUse => SimThreshold::FairUse,
            PlanLineKind::Allowance => SimThreshold::Allowance,
        };
        ordered.push((threshold, line.bytes.get()));
    }
    ordered
}

/// When a threshold is crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Crossing {
    /// Already crossed, on this day (the first day whose cumulative bytes
    /// reached it).
    Reached {
        /// The day.
        on: CalendarDate,
    },
    /// Projected to be crossed on this UTC day of the cycle.
    Projected {
        /// The day.
        on: CalendarDate,
    },
    /// Not projected to be crossed before the cycle ends.
    NotThisCycle,
}

/// One threshold and when it is crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdCrossing {
    /// The threshold.
    pub threshold: SimThreshold,
    /// Its bytes.
    pub bytes: u64,
    /// When it is crossed.
    pub crossing: Crossing,
}

/// The forecast for the billing cycle containing a meter reading.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimForecast {
    /// The billing cycle.
    pub cycle: BillingCycle,
    /// The reading's time.
    pub as_of: UnixTime,
    /// The bytes used in the cycle up to `as_of`.
    pub used_bytes: u64,
    /// The cycle-to-date average per day: `used_bytes` over the elapsed
    /// time, scaled to one day (rounded down).
    pub daily_average_bytes: u64,
    /// The bytes projected for the whole cycle at that average (rounded
    /// down); never below `used_bytes`.
    pub projected_bytes: u64,
    /// Every threshold, in increasing order of bytes.
    pub crossings: Vec<ThresholdCrossing>,
}

impl SimForecast {
    /// Projects the cycle containing `as_of` under `policy` from the meter's
    /// daily bins. The bins must be exactly the cycle's elapsed UTC days,
    /// from its first day to the day of the last second before `as_of`, in
    /// order and each once.
    pub fn project(
        policy: &SimPolicy,
        as_of: UnixTime,
        daily: &[DailySimBytes],
    ) -> Result<Self, ForecastError> {
        let cycle = BillingCycle::of_instant(policy.bill_day(), as_of)?;
        let start = cycle.starts_at().as_secs();
        let elapsed = as_of.as_secs() - start;
        if elapsed == 0 {
            return Err(ForecastError::NothingElapsed { as_of });
        }
        if daily.is_empty() {
            return Err(ForecastError::NoBins);
        }
        let last = CalendarDate::utc_of(UnixTime::from_secs(as_of.as_secs() - 1))?;
        let thresholds = ordered(&policy.thresholds());
        let mut reached: Vec<Option<CalendarDate>> = vec![None; thresholds.len()];
        let mut expected = Some(cycle.start());
        let mut used: u64 = 0;
        for bin in daily {
            if bin.date < cycle.start() || bin.date > last {
                return Err(ForecastError::BinOutsideCycle {
                    date: bin.date,
                    first: cycle.start(),
                    last,
                });
            }
            match expected {
                Some(day) if bin.date < day => {
                    return Err(ForecastError::BinsOutOfOrder { date: bin.date });
                }
                Some(day) if bin.date > day => {
                    return Err(ForecastError::MissingDay { date: day });
                }
                // `expected` is None only after the last elapsed day, which
                // the range check above already refuses.
                _ => {}
            }
            used = used
                .checked_add(bin.bytes)
                .ok_or(ForecastError::CounterOverflow)?;
            for ((_, bytes), on) in thresholds.iter().zip(reached.iter_mut()) {
                if on.is_none() && used >= *bytes {
                    *on = Some(bin.date);
                }
            }
            expected = (bin.date < last)
                .then(|| bin.date.checked_add_days(1))
                .transpose()?;
        }
        if let Some(day) = expected {
            return Err(ForecastError::MissingDay { date: day });
        }
        let end = cycle.ends_at().as_secs();
        let remaining = end - as_of.as_secs();
        let used_wide = u128::from(used);
        let elapsed_wide = u128::from(elapsed);
        let projected = used_wide + used_wide * u128::from(remaining) / elapsed_wide;
        let daily_average =
            used_wide * u128::from(mooring_model::date::SECS_PER_DAY) / elapsed_wide;
        let crossings = thresholds
            .iter()
            .zip(reached)
            .map(|(&(threshold, bytes), reached)| {
                let crossing = match reached {
                    Some(on) => Crossing::Reached { on },
                    None => projected_crossing(start, end, elapsed_wide, used_wide, bytes)?,
                };
                Ok(ThresholdCrossing {
                    threshold,
                    bytes,
                    crossing,
                })
            })
            .collect::<Result<Vec<_>, ForecastError>>()?;
        Ok(Self {
            cycle,
            as_of,
            used_bytes: used,
            daily_average_bytes: u64::try_from(daily_average)
                .map_err(|_| ForecastError::CounterOverflow)?,
            projected_bytes: u64::try_from(projected)
                .map_err(|_| ForecastError::CounterOverflow)?,
            crossings,
        })
    }
}

/// When a threshold not yet reached is crossed at the average rate: the
/// cycle start plus the time the average takes to reach it (rounded up to
/// the second), if that is before the cycle ends. With nothing used yet the
/// rate is zero and nothing is crossed.
fn projected_crossing(
    start: u64,
    end: u64,
    elapsed: u128,
    used: u128,
    threshold: u64,
) -> Result<Crossing, ForecastError> {
    if used == 0 {
        return Ok(Crossing::NotThisCycle);
    }
    let offset = (u128::from(threshold) * elapsed).div_ceil(used);
    let at = u128::from(start) + offset;
    if at < u128::from(end) {
        // `at` is before `end`, a u64, so it fits.
        let on = CalendarDate::utc_of(UnixTime::from_secs(at as u64))?;
        Ok(Crossing::Projected { on })
    } else {
        Ok(Crossing::NotThisCycle)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use mooring_model::sim::{AfterAllowance, Carrier, EvidenceRef, PlanKind, SimPlan};
    use mooring_model::target::EvidenceUrl;
    use mooring_model::{
        BillDay, ModelError, PILOT_SIM_HARD_STOP_BYTES, PILOT_SIM_WARN_BYTES, StopPolicy,
    };
    use proptest::prelude::*;

    use super::*;
    use crate::error::ForecastErrorKind;

    const GB: u64 = 1_000_000_000;

    /// A fair-use line for the rules only a line exercises: 600 × 1024³
    /// bytes.
    const TEST_FAIR_USE_BYTES: NonZeroU64 = match NonZeroU64::new(600 << 30) {
        Some(bytes) => bytes,
        None => panic!("the test line is not zero"),
    };

    fn date(text: &str) -> CalendarDate {
        CalendarDate::parse(text).unwrap()
    }

    fn plan(kind: PlanKind) -> SimPlan {
        SimPlan {
            carrier: Carrier::Smarty,
            kind,
            speed_cap_mbps: None,
            terms: EvidenceRef {
                url: EvidenceUrl::parse("https://evidence.mooring.test/sim-plan").unwrap(),
                dated: date("2026-08-07"),
            },
        }
    }

    fn fair_use() -> PlanKind {
        PlanKind::UnlimitedFairUse {
            fair_use_bytes: TEST_FAIR_USE_BYTES,
        }
    }

    /// Bill day 1, warning 450 GB, hard stop 560 GB, a 600 GiB fair-use
    /// line.
    fn policy() -> SimPolicy {
        SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(fair_use()),
            450 * GB,
            StopPolicy::HardStop { bytes: 560 * GB },
        )
        .unwrap()
    }

    fn days(first: &str, bytes: &[u64]) -> Vec<DailySimBytes> {
        let first = date(first);
        bytes
            .iter()
            .enumerate()
            .map(|(index, &bytes)| DailySimBytes {
                date: first
                    .checked_add_days(u32::try_from(index).unwrap())
                    .unwrap(),
                bytes,
            })
            .collect()
    }

    fn at(text: &str, secs: u64) -> UnixTime {
        UnixTime::from_secs(date(text).utc_start().as_secs() + secs)
    }

    #[test]
    fn a_steady_burn_projects_linearly_and_dates_each_crossing() {
        // Ten full days of October at 20 GB a day, read at midnight.
        let forecast = SimForecast::project(
            &policy(),
            at("2026-10-11", 0),
            &days("2026-10-01", &[20 * GB; 10]),
        )
        .unwrap();
        assert_eq!(forecast.cycle.start(), date("2026-10-01"));
        assert_eq!(forecast.cycle.next_start(), date("2026-11-01"));
        assert_eq!(forecast.used_bytes, 200 * GB);
        assert_eq!(forecast.daily_average_bytes, 20 * GB);
        assert_eq!(forecast.projected_bytes, 31 * 20 * GB);
        assert_eq!(
            forecast.crossings,
            vec![
                ThresholdCrossing {
                    threshold: SimThreshold::Warn,
                    bytes: 450 * GB,
                    // 450 / 20 = 22.5 days after 1 October.
                    crossing: Crossing::Projected {
                        on: date("2026-10-23")
                    },
                },
                ThresholdCrossing {
                    threshold: SimThreshold::HardStop,
                    bytes: 560 * GB,
                    // Exactly 28 days: the first second of 29 October.
                    crossing: Crossing::Projected {
                        on: date("2026-10-29")
                    },
                },
                ThresholdCrossing {
                    threshold: SimThreshold::FairUse,
                    bytes: TEST_FAIR_USE_BYTES.get(),
                    // 644.2 GB needs 32.2 days: after the cycle.
                    crossing: Crossing::NotThisCycle,
                },
            ]
        );
    }

    /// SMARTY's Unlimited plan has no line (decision F1), so the pilot's
    /// policy (decision F2) has exactly two thresholds: the warning and the
    /// hard stop, and no line row.
    #[test]
    fn a_lineless_plan_projects_warn_and_hard_stop_only() {
        let pilot = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(PlanKind::Unlimited),
            PILOT_SIM_WARN_BYTES,
            StopPolicy::HardStop {
                bytes: PILOT_SIM_HARD_STOP_BYTES,
            },
        )
        .unwrap();
        assert_eq!(pilot.thresholds().plan_line(), None);
        // Ten full October days at 10 GB a day, read at midnight.
        let forecast = SimForecast::project(
            &pilot,
            at("2026-10-11", 0),
            &days("2026-10-01", &[10 * GB; 10]),
        )
        .unwrap();
        assert_eq!(forecast.daily_average_bytes, 10 * GB);
        assert_eq!(forecast.projected_bytes, 310 * GB);
        assert_eq!(
            forecast.crossings,
            vec![
                ThresholdCrossing {
                    threshold: SimThreshold::Warn,
                    bytes: 240 * GB,
                    // Exactly 24 days: the first second of 25 October.
                    crossing: Crossing::Projected {
                        on: date("2026-10-25")
                    },
                },
                ThresholdCrossing {
                    threshold: SimThreshold::HardStop,
                    bytes: 300 * GB,
                    // Exactly 30 days: the first second of 31 October.
                    crossing: Crossing::Projected {
                        on: date("2026-10-31")
                    },
                },
            ]
        );
    }

    #[test]
    fn a_threshold_already_crossed_reports_the_day_it_was_reached() {
        let mut bytes = vec![100 * GB; 4];
        bytes.push(160 * GB);
        let forecast = SimForecast::project(
            &policy(),
            at("2026-10-05", 43_200),
            &days("2026-10-01", &bytes),
        )
        .unwrap();
        assert_eq!(forecast.used_bytes, 560 * GB);
        assert_eq!(
            forecast.crossings[0].crossing,
            Crossing::Reached {
                on: date("2026-10-05")
            }
        );
        assert_eq!(
            forecast.crossings[1].crossing,
            Crossing::Reached {
                on: date("2026-10-05")
            }
        );
        assert!(matches!(
            forecast.crossings[2].crossing,
            Crossing::Projected { .. }
        ));
    }

    #[test]
    fn zero_use_is_a_real_reading_and_crosses_nothing() {
        let forecast = SimForecast::project(
            &policy(),
            at("2026-10-03", 3_600),
            &days("2026-10-01", &[0, 0, 0]),
        )
        .unwrap();
        assert_eq!(forecast.projected_bytes, 0);
        assert!(
            forecast
                .crossings
                .iter()
                .all(|crossing| crossing.crossing == Crossing::NotThisCycle)
        );
    }

    /// The crossing instant is rounded up: a threshold the average reaches
    /// half a second before midnight is crossed on the next day, not in
    /// the last second of the day before.
    #[test]
    fn a_crossing_is_dated_by_the_second_it_is_reached() {
        // 172.8 GB in two days (1 MB/s); the warning at 431.9995 GB is
        // reached 431,999.5 s after the cycle starts, so in the first
        // second of 6 October.
        let warn = 431_999_500_000;
        let policy = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(PlanKind::Unlimited),
            warn,
            StopPolicy::HardStop { bytes: warn + GB },
        )
        .unwrap();
        let forecast = SimForecast::project(
            &policy,
            at("2026-10-03", 0),
            &days("2026-10-01", &[86_400_000_000; 2]),
        )
        .unwrap();
        assert_eq!(
            forecast.crossings[0].crossing,
            Crossing::Projected {
                on: date("2026-10-06")
            }
        );
    }

    /// A threshold the average reaches exactly when the cycle ends belongs
    /// to the next cycle.
    #[test]
    fn a_crossing_at_the_cycle_end_is_not_this_cycle() {
        // 10 GB on 1 October; 310 GB is reached after exactly 31 days.
        let policy = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(fair_use()),
            310 * GB,
            StopPolicy::HardStop { bytes: 400 * GB },
        )
        .unwrap();
        let forecast = SimForecast::project(
            &policy,
            at("2026-10-02", 0),
            &days("2026-10-01", &[10 * GB]),
        )
        .unwrap();
        assert_eq!(forecast.projected_bytes, 310 * GB);
        assert_eq!(forecast.crossings[0].crossing, Crossing::NotThisCycle);
        // 200 kB less is reached 1.728 s earlier: in the cycle's last
        // second.
        let earlier = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(fair_use()),
            310 * GB - 200_000,
            StopPolicy::HardStop { bytes: 400 * GB },
        )
        .unwrap();
        let forecast = SimForecast::project(
            &earlier,
            at("2026-10-02", 0),
            &days("2026-10-01", &[10 * GB]),
        )
        .unwrap();
        assert_eq!(
            forecast.crossings[0].crossing,
            Crossing::Projected {
                on: date("2026-10-31")
            }
        );
    }

    #[test]
    fn thresholds_follow_the_policy_and_its_plan() {
        let capped = PlanKind::Capped {
            allowance_bytes: NonZeroU64::new(100 * GB).unwrap(),
            after: AfterAllowance::Blocked,
        };
        let policy = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(capped),
            50 * GB,
            StopPolicy::HardStop { bytes: 90 * GB },
        )
        .unwrap();
        assert_eq!(
            ordered(&policy.thresholds()),
            vec![
                (SimThreshold::Warn, 50 * GB),
                (SimThreshold::HardStop, 90 * GB),
                (SimThreshold::Allowance, 100 * GB)
            ]
        );
        // No plan recorded (a policy lifted from version 1): only the
        // warning and the hard stop.
        let unrecorded: SimPolicy = serde_json::from_str(
            r#"{"bill_day":1,"plan":null,"warn_bytes":50000000000,"stop":{"hard_stop":{"bytes":90000000000}}}"#,
        )
        .unwrap();
        assert_eq!(unrecorded.plan(), None);
        assert_eq!(unrecorded.thresholds().plan_line(), None);
        assert_eq!(
            ordered(&unrecorded.thresholds()),
            vec![
                (SimThreshold::Warn, 50 * GB),
                (SimThreshold::HardStop, 90 * GB)
            ]
        );
        // Accepting deprioritisation: no hard stop.
        let accepting = SimPolicy::new(
            BillDay::new(1).unwrap(),
            plan(fair_use()),
            50 * GB,
            StopPolicy::AcceptDeprioritisation,
        )
        .unwrap();
        assert_eq!(
            ordered(&accepting.thresholds()),
            vec![
                (SimThreshold::Warn, 50 * GB),
                (SimThreshold::FairUse, TEST_FAIR_USE_BYTES.get())
            ]
        );
    }

    /// Every way the bins can fail to be the elapsed days, refused with the
    /// day at fault.
    #[test]
    fn bins_must_be_exactly_the_elapsed_days() {
        let policy = policy();
        let as_of = at("2026-10-04", 60);
        let refuse =
            |bins: Vec<DailySimBytes>| SimForecast::project(&policy, as_of, &bins).unwrap_err();
        assert_eq!(refuse(Vec::new()), ForecastError::NoBins);
        // 4 October has a minute elapsed, so it needs a bin.
        assert_eq!(
            refuse(days("2026-10-01", &[1, 1, 1])),
            ForecastError::MissingDay {
                date: date("2026-10-04")
            }
        );
        assert_eq!(
            refuse(days("2026-10-02", &[1, 1, 1])),
            ForecastError::MissingDay {
                date: date("2026-10-01")
            }
        );
        let mut gap = days("2026-10-01", &[1, 1, 1, 1]);
        gap.remove(2);
        assert_eq!(
            refuse(gap),
            ForecastError::MissingDay {
                date: date("2026-10-03")
            }
        );
        let mut repeated = days("2026-10-01", &[1, 1, 1, 1]);
        repeated.insert(2, repeated[1]);
        assert_eq!(
            refuse(repeated),
            ForecastError::BinsOutOfOrder {
                date: date("2026-10-02")
            }
        );
        let mut swapped = days("2026-10-01", &[1, 1, 1, 1]);
        swapped.swap(1, 2);
        assert_eq!(
            refuse(swapped),
            ForecastError::MissingDay {
                date: date("2026-10-02")
            }
        );
        assert_eq!(
            refuse(days("2026-09-30", &[1, 1, 1, 1, 1])),
            ForecastError::BinOutsideCycle {
                date: date("2026-09-30"),
                first: date("2026-10-01"),
                last: date("2026-10-04")
            }
        );
        assert_eq!(
            refuse(days("2026-10-01", &[1, 1, 1, 1, 1])),
            ForecastError::BinOutsideCycle {
                date: date("2026-10-05"),
                first: date("2026-10-01"),
                last: date("2026-10-04")
            }
        );
        assert_eq!(
            refuse(days("2026-10-01", &[u64::MAX, 1, 1, 1])),
            ForecastError::CounterOverflow
        );
        // At the cycle's first instant nothing has elapsed.
        let start = at("2026-10-01", 0);
        assert_eq!(
            SimForecast::project(&policy, start, &days("2026-10-01", &[1])).unwrap_err(),
            ForecastError::NothingElapsed { as_of: start }
        );
        // A cycle before 1970 does not exist.
        let early = SimPolicy::new(
            BillDay::new(20).unwrap(),
            plan(PlanKind::Unlimited),
            1,
            StopPolicy::HardStop { bytes: 2 },
        )
        .unwrap();
        assert_eq!(
            SimForecast::project(&early, UnixTime::from_secs(86_400), &[]).unwrap_err(),
            ForecastError::Model(ModelError::InvalidDate)
        );
    }

    #[test]
    fn every_kind_is_produced_by_the_error_named_with_it() {
        let errors = [
            (ForecastErrorKind::NoBins, ForecastError::NoBins),
            (
                ForecastErrorKind::NothingElapsed,
                ForecastError::NothingElapsed {
                    as_of: UnixTime::from_secs(0),
                },
            ),
            (
                ForecastErrorKind::BinOutsideCycle,
                ForecastError::BinOutsideCycle {
                    date: date("2026-09-30"),
                    first: date("2026-10-01"),
                    last: date("2026-10-04"),
                },
            ),
            (
                ForecastErrorKind::BinsOutOfOrder,
                ForecastError::BinsOutOfOrder {
                    date: date("2026-10-02"),
                },
            ),
            (
                ForecastErrorKind::MissingDay,
                ForecastError::MissingDay {
                    date: date("2026-10-02"),
                },
            ),
            (
                ForecastErrorKind::CounterOverflow,
                ForecastError::CounterOverflow,
            ),
            (
                ForecastErrorKind::Model,
                ForecastError::Model(ModelError::InvalidDate),
            ),
        ];
        for (kind, error) in &errors {
            assert_eq!(error.kind(), *kind);
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(
            errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            ForecastErrorKind::ALL
        );
        assert_eq!(
            serde_json::to_string(&ForecastErrorKind::NothingElapsed).unwrap(),
            "\"NothingElapsed\""
        );
    }

    fn arbitrary_policy() -> impl Strategy<Value = SimPolicy> {
        (1_u8..=31, 1_u64..400, 1_u64..100, any::<bool>()).prop_map(|(day, warn, gap, capped)| {
            let warn = warn * GB;
            let stop = warn + gap * GB;
            let kind = if capped {
                PlanKind::Capped {
                    allowance_bytes: NonZeroU64::new(stop + GB).unwrap(),
                    after: AfterAllowance::Blocked,
                }
            } else {
                fair_use()
            };
            SimPolicy::new(
                BillDay::new(day).unwrap(),
                plan(kind),
                warn,
                StopPolicy::HardStop { bytes: stop },
            )
            .unwrap()
        })
    }

    proptest! {
        /// For any policy, reading time and daily bytes covering the elapsed
        /// days: the projection never falls below what was used, a crossing
        /// is reported as reached exactly when the bytes reached it (on the
        /// first such day), and a projected crossing lies in the rest of the
        /// cycle and only when the projection reaches the threshold.
        #[test]
        fn projections_are_consistent_with_the_bins(
            policy in arbitrary_policy(),
            as_of in 1_000_000_000_u64..4_000_000_000,
            per_day in proptest::collection::vec(0_u64..60 * GB, 31),
        ) {
            let as_of = UnixTime::from_secs(as_of);
            let cycle = BillingCycle::of_instant(policy.bill_day(), as_of).unwrap();
            prop_assume!(as_of > cycle.starts_at());
            let last = CalendarDate::utc_of(UnixTime::from_secs(as_of.as_secs() - 1)).unwrap();
            let count = (last.days_since_epoch() - cycle.start().days_since_epoch() + 1) as usize;
            let bins: Vec<DailySimBytes> = (0..count)
                .map(|index| DailySimBytes {
                    date: cycle.start().checked_add_days(u32::try_from(index).unwrap()).unwrap(),
                    bytes: per_day[index],
                })
                .collect();
            let forecast = SimForecast::project(&policy, as_of, &bins).unwrap();
            let used: u64 = per_day[..count].iter().sum();
            prop_assert_eq!(forecast.used_bytes, used);
            prop_assert!(forecast.projected_bytes >= used);
            for crossing in &forecast.crossings {
                let first_reached = bins.iter().scan(0_u64, |sum, bin| {
                    *sum += bin.bytes;
                    Some((*sum >= crossing.bytes, bin.date))
                }).find(|(reached, _)| *reached).map(|(_, on)| on);
                match crossing.crossing {
                    Crossing::Reached { on } => prop_assert_eq!(Some(on), first_reached),
                    Crossing::Projected { on } => {
                        prop_assert_eq!(first_reached, None);
                        prop_assert!(on >= last && on < cycle.next_start());
                        prop_assert!(forecast.projected_bytes >= crossing.bytes);
                    }
                    Crossing::NotThisCycle => {
                        prop_assert_eq!(first_reached, None);
                    }
                }
                if first_reached.is_none() && forecast.projected_bytes < crossing.bytes {
                    prop_assert_eq!(crossing.crossing, Crossing::NotThisCycle);
                }
            }
            // Dropping any one elapsed day is refused, never projected.
            for index in 0..bins.len() {
                let mut short = bins.clone();
                short.remove(index);
                prop_assert_eq!(
                    SimForecast::project(&policy, as_of, &short).map_err(|error| error.kind()),
                    Err(if short.is_empty() { ForecastErrorKind::NoBins } else { ForecastErrorKind::MissingDay })
                );
            }
        }
    }
}
