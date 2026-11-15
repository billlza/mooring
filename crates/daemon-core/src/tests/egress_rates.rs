// SPDX-License-Identifier: GPL-3.0-or-later

//! The egress rates a capacity sample carries (console spec B.2.8): the
//! bytes the SIM meter counted over the last minute, per second; none
//! before a minute is covered, after a short count or a count that does
//! not follow the one before, from a window gone stale, or past the
//! window's bound of counts; and a rate past the largest reads as the
//! largest.

use mooring_model::UnixTime;
use proptest::prelude::*;

use crate::capacity::rates::{
    EgressRate, EgressRates, MAX_RATE_AGE_SECS, MAX_RATE_COUNTS, RATE_WINDOW_SECS,
};
use crate::meter::Counted;

/// 2026-10-24T00:00:00Z.
const AT: u64 = 1_792_800_000;

/// A count of `rx` and `tx` bytes from `since` to `at`.
fn count(since: u64, at: u64, rx: u64, tx: u64) -> Counted {
    Counted {
        since: UnixTime::from_secs(since),
        at: UnixTime::from_secs(at),
        rx,
        tx,
        short: false,
    }
}

/// Feeds the counts of readings every 2 s from `from` to `to`, each of `rx`
/// and `tx` bytes.
fn feed(rates: &mut EgressRates, from: u64, to: u64, rx: u64, tx: u64) {
    let mut since = from;
    while since < to {
        rates.observe(count(since, since + 2, rx, tx));
        since += 2;
    }
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

#[test]
fn the_rates_are_the_last_minute_per_second() {
    assert_eq!(RATE_WINDOW_SECS, 60);
    let mut rates = EgressRates::new();
    // 30 counts of 2 s, each 25 kB sent and 100 kB received.
    feed(&mut rates, AT, AT + 60, 100_000, 25_000);
    assert_eq!(
        rates.over_last_minute(at(AT + 60)),
        Some(EgressRate {
            tx_bps: 100_000,
            rx_bps: 400_000
        })
    );
    // Half a minute of twice the bytes: the minute is half of each.
    feed(&mut rates, AT + 60, AT + 90, 200_000, 50_000);
    assert_eq!(
        rates.over_last_minute(at(AT + 90)),
        Some(EgressRate {
            tx_bps: 150_000,
            rx_bps: 600_000
        })
    );
    // A whole minute of them: the first minute's counts are gone.
    feed(&mut rates, AT + 90, AT + 120, 200_000, 50_000);
    assert_eq!(
        rates.over_last_minute(at(AT + 120)),
        Some(EgressRate {
            tx_bps: 200_000,
            rx_bps: 800_000
        })
    );
    // A count within one second spans no time and its bytes still count.
    rates.observe(count(AT + 120, AT + 120, 750_000, 0));
    assert_eq!(
        rates.over_last_minute(at(AT + 120)),
        Some(EgressRate {
            tx_bps: 200_000,
            rx_bps: 900_000
        })
    );
}

#[test]
fn a_short_count_starts_the_minute_again() {
    let mut rates = EgressRates::new();
    feed(&mut rates, AT, AT + 60, 100_000, 25_000);
    // Restarted counters, counted whole: no rate from them.
    rates.observe(Counted {
        short: true,
        ..count(AT + 60, AT + 62, 4_000_000_000, 0)
    });
    assert_eq!(rates.over_last_minute(at(AT + 62)), None);
    feed(&mut rates, AT + 62, AT + 120, 100_000, 25_000);
    assert_eq!(rates.over_last_minute(at(AT + 120)), None, "58 s");
    feed(&mut rates, AT + 120, AT + 122, 100_000, 25_000);
    assert_eq!(
        rates.over_last_minute(at(AT + 122)),
        Some(EgressRate {
            tx_bps: 100_000,
            rx_bps: 400_000
        })
    );
}

#[test]
fn a_count_that_does_not_follow_the_one_before_starts_the_minute_again() {
    let mut rates = EgressRates::new();
    feed(&mut rates, AT, AT + 60, 100_000, 25_000);
    // A count from 4 s after the last one ended: the 4 s are not counted.
    rates.observe(count(AT + 64, AT + 66, 100_000, 25_000));
    assert_eq!(rates.over_last_minute(at(AT + 66)), None);
    feed(&mut rates, AT + 66, AT + 122, 100_000, 25_000);
    assert_eq!(rates.over_last_minute(at(AT + 122)), None, "58 s");
    feed(&mut rates, AT + 122, AT + 124, 100_000, 25_000);
    assert_eq!(
        rates.over_last_minute(at(AT + 124)),
        Some(EgressRate {
            tx_bps: 100_000,
            rx_bps: 400_000
        })
    );
    // A count that ends before it starts: the counts that follow it make a
    // minute of their own.
    rates.observe(count(AT + 124, AT + 120, 100_000, 25_000));
    assert_eq!(rates.over_last_minute(at(AT + 124)), None);
    feed(&mut rates, AT + 120, AT + 178, 100_000, 25_000);
    assert_eq!(rates.over_last_minute(at(AT + 178)), None, "58 s");
    feed(&mut rates, AT + 178, AT + 180, 100_000, 25_000);
    assert!(rates.over_last_minute(at(AT + 180)).is_some());
    // One that starts before the last one ended.
    rates.observe(count(AT + 178, AT + 182, 100_000, 25_000));
    assert_eq!(rates.over_last_minute(at(AT + 182)), None);
}

#[test]
fn no_rate_before_a_minute_or_from_a_window_gone_stale() {
    let mut rates = EgressRates::new();
    assert_eq!(rates.over_last_minute(at(AT)), None);
    feed(&mut rates, AT, AT + 58, 1_000, 1_000);
    assert_eq!(rates.over_last_minute(at(AT + 58)), None);
    feed(&mut rates, AT + 58, AT + 60, 1_000, 1_000);
    let fresh = AT + 60 + MAX_RATE_AGE_SECS;
    assert!(rates.over_last_minute(at(fresh)).is_some());
    assert_eq!(rates.over_last_minute(at(fresh + 1)), None);
    // A clock read just before the newest count is no reason to refuse.
    assert!(rates.over_last_minute(at(AT + 59)).is_some());
}

#[test]
fn the_window_keeps_at_most_its_bound_of_counts() {
    let mut rates = EgressRates::new();
    rates.observe(count(AT, AT + 60, 6_000, 6_000));
    for _ in 1..MAX_RATE_COUNTS {
        rates.observe(count(AT + 60, AT + 60, 15, 15));
    }
    // The minute's count and the counts within its last second, the
    // bound's worth.
    let bytes = 6_000 + 15 * (MAX_RATE_COUNTS as u64 - 1);
    assert_eq!(
        rates.over_last_minute(at(AT + 60)),
        Some(EgressRate {
            tx_bps: bytes * 8 / 60,
            rx_bps: bytes * 8 / 60
        })
    );
    // One more drops the oldest, the minute with it.
    rates.observe(count(AT + 60, AT + 60, 15, 15));
    assert_eq!(rates.over_last_minute(at(AT + 60)), None);
}

/// A rate past `u64::MAX` bit/s reads as `u64::MAX`: no meter counts so
/// much (its counts are below 2^32 bytes), but the window takes any count.
#[test]
fn a_rate_past_the_largest_reads_as_the_largest() {
    let mut rates = EgressRates::new();
    rates.observe(count(AT, AT + 60, u64::MAX, 0));
    for _ in 0..7 {
        rates.observe(count(AT + 60, AT + 60, u64::MAX, 0));
    }
    assert_eq!(
        rates.over_last_minute(at(AT + 60)),
        Some(EgressRate {
            tx_bps: 0,
            rx_bps: u64::MAX
        })
    );
}

/// The rate the window should give, worked out from every count fed:
/// the shortest run of the latest counts that spans a minute, unless it
/// holds more counts than the bound.
fn expected(history: &[Counted]) -> Option<EgressRate> {
    let newest = history.last()?;
    let start = (0..history.len())
        .rev()
        .find(|&index| newest.at.as_secs() - history[index].since.as_secs() >= RATE_WINDOW_SECS)?;
    if history.len() - start > MAX_RATE_COUNTS {
        return None;
    }
    let window = &history[start..];
    let span = newest.at.as_secs() - window[0].since.as_secs();
    let rx: u64 = window.iter().map(|counted| counted.rx).sum();
    let tx: u64 = window.iter().map(|counted| counted.tx).sum();
    Some(EgressRate {
        tx_bps: tx * 8 / span,
        rx_bps: rx * 8 / span,
    })
}

proptest! {
    /// Over any counts that follow each other, readings 0 to 4 s apart:
    /// the rate is the bytes of the shortest run of the latest counts that
    /// spans a minute, per second over that run's span.
    #[test]
    fn the_rate_is_the_bytes_of_the_last_minute_over_its_span(
        steps in proptest::collection::vec((0_u64..5, 0_u64..10_000_000, 0_u64..10_000_000), 1..200),
    ) {
        let mut rates = EgressRates::new();
        let mut history = Vec::new();
        let mut since = AT;
        for (gap, rx, tx) in steps {
            let counted = count(since, since + gap, rx, tx);
            since += gap;
            rates.observe(counted);
            history.push(counted);
            prop_assert_eq!(rates.over_last_minute(at(since)), expected(&history));
        }
    }
}
