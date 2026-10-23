// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter (design §10.1 step 5, §16 L1 "SIM arithmetic across
//! counter resets"): deltas modulo 2^32, wraps told from restarted
//! counters by what the line could carry, other boots and interfaces,
//! short days, cycles as sums of days under either rule, the forecast's
//! bins, and the document's format and refusals.

use mooring_model::date::CalendarDate;
use mooring_model::iface::{InterfaceIndex, MacAddr};
use mooring_model::sim::{CycleRule, PeriodDays};
use mooring_model::{BillDay, UnixTime};
use proptest::prelude::*;

use crate::meter::{
    COUNTER_MODULUS, CounterReading, CycleBytes, MAX_LINE_BYTES_PER_SEC, MAX_SIM_METER_BYTES,
    MeterError, SimMeter,
};
use crate::period::BillingCycle;

/// 2026-10-24T00:00:00Z.
const MIDNIGHT: u64 = 1_792_800_000;
const BOOT: u64 = MIDNIGHT - 86_400;

fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn reading(at: u64, rx: u64, tx: u64) -> CounterReading {
    CounterReading {
        at: UnixTime::from_secs(at),
        boot: UnixTime::from_secs(BOOT),
        index: InterfaceIndex::new(12).unwrap(),
        lladdr: MacAddr::parse("02:6d:6f:6f:72:08").unwrap(),
        rx,
        tx,
    }
}

fn day(meter: &SimMeter, cycle: BillingCycle) -> CycleBytes {
    meter.cycle_bytes(cycle)
}

/// The one-day cycle of `text` under a 1-day fixed rule.
fn one_day(text: &str) -> BillingCycle {
    BillingCycle::containing(
        CycleRule::FixedDays {
            days: PeriodDays::new(1).unwrap(),
            anchor: date("2026-10-01"),
        },
        date(text),
    )
    .unwrap()
}

#[test]
fn the_first_reading_only_sets_the_counters_and_deltas_follow() {
    let mut meter = SimMeter::new();
    meter.observe(reading(MIDNIGHT + 10, 5_000, 7_000)).unwrap();
    assert_eq!(day(&meter, one_day("2026-10-24")), CycleBytes::default());
    meter.observe(reading(MIDNIGHT + 12, 8_000, 7_500)).unwrap();
    meter.observe(reading(MIDNIGHT + 14, 9_024, 9_500)).unwrap();
    assert_eq!(
        day(&meter, one_day("2026-10-24")),
        CycleBytes {
            rx: 4_024,
            tx: 2_500,
            short: false
        }
    );
    assert_eq!(meter.last(), Some(&reading(MIDNIGHT + 14, 9_024, 9_500)));
    // A reading after midnight counts into the next day.
    meter
        .observe(reading(MIDNIGHT + 86_400, 10_024, 9_500))
        .unwrap();
    assert_eq!(day(&meter, one_day("2026-10-25")).rx, 1_000);
    assert_eq!(day(&meter, one_day("2026-10-24")).rx, 4_024);
}

#[test]
fn a_wrap_the_line_could_carry_is_counted_across_2_pow_32() {
    let mut meter = SimMeter::new();
    let near = COUNTER_MODULUS - 1_024;
    meter.observe(reading(MIDNIGHT, near, near)).unwrap();
    meter.observe(reading(MIDNIGHT + 2, 2_048, 0)).unwrap();
    assert_eq!(
        day(&meter, one_day("2026-10-24")),
        CycleBytes {
            rx: 3_072,
            tx: 1_024,
            short: false
        }
    );
    // The largest wrap two seconds allow is still a wrap.
    let mut edge = SimMeter::new();
    edge.observe(reading(MIDNIGHT, near, 0)).unwrap();
    let window = 2 * MAX_LINE_BYTES_PER_SEC;
    edge.observe(reading(MIDNIGHT + 2, window - 1_024, 0))
        .unwrap();
    assert_eq!(day(&edge, one_day("2026-10-24")).rx, window);
    assert!(!day(&edge, one_day("2026-10-24")).short);
}

#[test]
fn counters_that_restarted_are_counted_whole_and_the_day_is_short() {
    let mut meter = SimMeter::new();
    meter
        .observe(reading(MIDNIGHT, 3_000_000_000, 1_000))
        .unwrap();
    // A drop the line could not have wrapped in two seconds.
    meter.observe(reading(MIDNIGHT + 2, 4_096, 2_048)).unwrap();
    assert_eq!(
        day(&meter, one_day("2026-10-24")),
        CycleBytes {
            rx: 4_096,
            tx: 1_048,
            short: true
        }
    );
    // A good reading later that day leaves the day short.
    meter.observe(reading(MIDNIGHT + 4, 5_120, 2_048)).unwrap();
    assert_eq!(
        day(&meter, one_day("2026-10-24")),
        CycleBytes {
            rx: 5_120,
            tx: 1_048,
            short: true
        }
    );
    // Another boot, index or link-layer address: restarted counters.
    for changed in [
        CounterReading {
            boot: UnixTime::from_secs(BOOT + 600),
            ..reading(MIDNIGHT + 86_400 + 4, 9_000, 9_000)
        },
        CounterReading {
            index: InterfaceIndex::new(13).unwrap(),
            ..reading(MIDNIGHT + 86_400 + 4, 9_000, 9_000)
        },
        CounterReading {
            lladdr: MacAddr::parse("02:6d:6f:6f:72:09").unwrap(),
            ..reading(MIDNIGHT + 86_400 + 4, 9_000, 9_000)
        },
    ] {
        let mut meter = SimMeter::new();
        meter
            .observe(reading(MIDNIGHT + 86_400 + 2, 8_000, 1))
            .unwrap();
        meter.observe(changed).unwrap();
        assert_eq!(
            day(&meter, one_day("2026-10-25")),
            CycleBytes {
                rx: 9_000,
                tx: 9_000,
                short: true
            },
            "{changed:?}"
        );
    }
}

#[test]
fn a_gap_a_wrap_could_hide_in_marks_the_day_short() {
    // 14 s at the line's peak exceed 2^32 bytes.
    let long = COUNTER_MODULUS.div_ceil(MAX_LINE_BYTES_PER_SEC);
    let mut meter = SimMeter::new();
    meter.observe(reading(MIDNIGHT, 1_000, 1_000)).unwrap();
    meter.observe(reading(MIDNIGHT + long, 5_000, 500)).unwrap();
    assert_eq!(
        day(&meter, one_day("2026-10-24")),
        CycleBytes {
            rx: 4_000,
            tx: 500,
            short: true
        }
    );
    // One second less is not a gap.
    let mut close = SimMeter::new();
    close.observe(reading(MIDNIGHT, 1_000, 1_000)).unwrap();
    close
        .observe(reading(MIDNIGHT + long - 1, 5_000, 1_000))
        .unwrap();
    assert!(!day(&close, one_day("2026-10-24")).short);
    // A clock that stepped back bounds nothing.
    let mut back = SimMeter::new();
    back.observe(reading(MIDNIGHT + 100, 1_000, 1_000)).unwrap();
    back.observe(reading(MIDNIGHT + 50, 2_000, 1_000)).unwrap();
    assert_eq!(
        day(&back, one_day("2026-10-24")),
        CycleBytes {
            rx: 1_000,
            tx: 0,
            short: true
        }
    );
}

#[test]
fn a_counter_of_2_pow_32_or_more_is_refused_and_counts_nothing() {
    let mut meter = SimMeter::new();
    meter.observe(reading(MIDNIGHT, 1_000, 1_000)).unwrap();
    for (rx, tx) in [(COUNTER_MODULUS, 0), (0, u64::MAX)] {
        assert_eq!(
            meter.observe(reading(MIDNIGHT + 2, rx, tx)),
            Err(MeterError::CounterOutOfRange { value: rx.max(tx) })
        );
    }
    assert_eq!(meter.last(), Some(&reading(MIDNIGHT, 1_000, 1_000)));
    assert_eq!(day(&meter, one_day("2026-10-24")), CycleBytes::default());
}

#[test]
fn a_cycle_is_the_sum_of_its_days_under_either_rule() {
    let mut meter = SimMeter::new();
    let mut counter = 0;
    meter.observe(reading(MIDNIGHT, 0, 0)).unwrap();
    // 1 MiB a day on each of ten days from 2026-10-24.
    for offset in 1..=10 {
        counter += 1 << 20;
        meter
            .observe(reading(MIDNIGHT + offset * 86_400 - 1, counter, 0))
            .unwrap();
    }
    let fixed = |anchor: &str| CycleRule::FixedDays {
        days: PeriodDays::new(30).unwrap(),
        anchor: date(anchor),
    };
    let cycle = |rule, on: &str| BillingCycle::containing(rule, date(on)).unwrap();
    assert_eq!(
        meter
            .cycle_bytes(cycle(fixed("2026-10-01"), "2026-10-24"))
            .rx,
        7 << 20
    );
    // `sim set-anchor` to the 29th: the days from then on form the cycle.
    assert_eq!(
        meter
            .cycle_bytes(cycle(fixed("2026-10-29"), "2026-10-29"))
            .rx,
        5 << 20
    );
    let monthly = CycleRule::Monthly {
        bill_day: BillDay::new(1).unwrap(),
    };
    assert_eq!(
        meter.cycle_bytes(cycle(monthly, "2026-11-01")).total(),
        2 << 20
    );
    meter.retain_from(date("2026-11-01"));
    assert_eq!(
        meter
            .cycle_bytes(cycle(fixed("2026-10-01"), "2026-10-24"))
            .rx,
        0
    );
    assert_eq!(meter.cycle_bytes(cycle(monthly, "2026-11-01")).rx, 2 << 20);
}

#[test]
fn the_forecast_bins_are_every_elapsed_day_with_zeros() {
    let mut meter = SimMeter::new();
    meter.observe(reading(MIDNIGHT, 0, 0)).unwrap();
    meter
        .observe(reading(MIDNIGHT + 2 * 86_400 + 5, 300, 700))
        .unwrap();
    let rule = CycleRule::FixedDays {
        days: PeriodDays::new(30).unwrap(),
        anchor: date("2026-10-24"),
    };
    let cycle = BillingCycle::containing(rule, date("2026-10-24")).unwrap();
    let bins = meter
        .daily(cycle, UnixTime::from_secs(MIDNIGHT + 2 * 86_400 + 60))
        .unwrap();
    let bytes: Vec<(CalendarDate, u64)> = bins.iter().map(|bin| (bin.date, bin.bytes)).collect();
    assert_eq!(
        bytes,
        [
            (date("2026-10-24"), 0),
            (date("2026-10-25"), 0),
            (date("2026-10-26"), 1_000)
        ]
    );
    // At midnight the day that starts then has not elapsed.
    assert_eq!(
        meter
            .daily(cycle, UnixTime::from_secs(MIDNIGHT + 2 * 86_400))
            .unwrap()
            .len(),
        2
    );
    assert!(
        meter
            .daily(cycle, UnixTime::from_secs(MIDNIGHT))
            .unwrap()
            .is_empty()
    );
    // The forecast takes them as they are.
    let policy = mooring_model::sim::SimPolicy::new(
        rule,
        mooring_model::sim::SimPlan::one_p_mobile_unlimited().unwrap(),
        200_000_000_000,
        mooring_model::sim::StopPolicy::HardStop {
            bytes: 240_000_000_000,
        },
    )
    .unwrap();
    let at = UnixTime::from_secs(MIDNIGHT + 2 * 86_400 + 60);
    let forecast = crate::forecast::SimForecast::project(&policy, at, &bins).unwrap();
    assert_eq!(forecast.used_bytes, 1_000);
}

#[test]
fn the_document_round_trips_and_refuses_anything_else() {
    let mut meter = SimMeter::new();
    meter.observe(reading(MIDNIGHT, 0, 0)).unwrap();
    meter.observe(reading(MIDNIGHT + 2, 4_096, 1_024)).unwrap();
    meter
        .observe(CounterReading {
            index: InterfaceIndex::new(13).unwrap(),
            ..reading(MIDNIGHT + 86_400, 2_048, 0)
        })
        .unwrap();
    let bytes = meter.encode().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        text.starts_with("{\n  \"version\": 1,\n  \"days\": [\n"),
        "{text}"
    );
    assert!(text.contains("\"date\": \"2026-10-24\",\n      \"rx_bytes\": 4096,\n      \"tx_bytes\": 1024,\n      \"short\": false"), "{text}");
    assert!(text.ends_with("}\n"));
    assert_eq!(SimMeter::decode(&bytes).unwrap(), meter);
    assert_eq!(
        SimMeter::decode(&SimMeter::new().encode().unwrap()).unwrap(),
        SimMeter::new()
    );
    let second_day = "\"date\": \"2026-10-25\"";
    for bad in [
        String::new(),
        text.replace("\"version\": 1", "\"version\": 2"),
        text.replace(second_day, "\"date\": \"2026-10-24\""),
        text.replace(second_day, "\"date\": \"2026-10-23\""),
        text.replace("\"short\": false", "\"short\": false, \"extra\": 1"),
        text.replace("\"rx\": 2048", "\"rx\": 4294967296"),
        text.replace("\"tx\": 0\n", "\"tx\": 4294967296\n"),
        text.replace(",\n  \"last\"", ",\n  \"lost\""),
        " ".repeat(MAX_SIM_METER_BYTES + 1),
    ] {
        assert_eq!(
            SimMeter::decode(bad.as_bytes()),
            Err(MeterError::Corrupt),
            "{bad:.80}"
        );
    }
    // A document padded to the bound is read; one byte more is refused.
    let mut padded = text.clone().into_bytes();
    padded.resize(MAX_SIM_METER_BYTES, b' ');
    assert_eq!(SimMeter::decode(&padded).unwrap(), meter);
    padded.push(b' ');
    assert_eq!(SimMeter::decode(&padded), Err(MeterError::Corrupt));
}

#[test]
fn a_day_that_would_overflow_is_refused() {
    let mut meter = SimMeter::decode(
        format!(
            "{{\"version\": 1, \"days\": [{{\"date\": \"2026-10-24\", \"rx_bytes\": {}, \"tx_bytes\": 0, \"short\": false}}], \"last\": {}}}",
            u64::MAX,
            serde_json::to_string(&reading(MIDNIGHT, 0, 0)).unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        meter.observe(reading(MIDNIGHT + 2, 1_024, 0)),
        Err(MeterError::Overflow {
            date: date("2026-10-24")
        })
    );
    assert_eq!(
        meter.cycle_bytes(one_day("2026-10-24")),
        CycleBytes {
            rx: u64::MAX,
            tx: 0,
            short: false
        }
    );
}

proptest! {
    /// Read every 2 s, the meter reproduces a 64-bit counter exactly from
    /// its value modulo 2^32, whatever the line carries up to its peak.
    #[test]
    fn readings_modulo_2_pow_32_add_up_to_the_true_count(
        start in 0..COUNTER_MODULUS,
        steps in prop::collection::vec((0..=2 * MAX_LINE_BYTES_PER_SEC, 0..=2 * MAX_LINE_BYTES_PER_SEC), 1..200),
    ) {
        let mut meter = SimMeter::new();
        let (mut rx, mut tx) = (start, 0_u64);
        meter.observe(reading(MIDNIGHT, rx % COUNTER_MODULUS, tx % COUNTER_MODULUS)).unwrap();
        let (mut want_rx, mut want_tx) = (0_u64, 0_u64);
        for (index, (drx, dtx)) in steps.iter().enumerate() {
            rx += drx;
            tx += dtx;
            want_rx += drx;
            want_tx += dtx;
            let at = MIDNIGHT + 2 * (index as u64 + 1);
            meter.observe(reading(at, rx % COUNTER_MODULUS, tx % COUNTER_MODULUS)).unwrap();
        }
        let cycle = one_day("2026-10-24");
        prop_assert_eq!(
            meter.cycle_bytes(cycle),
            CycleBytes { rx: want_rx, tx: want_tx, short: false }
        );
    }
}
