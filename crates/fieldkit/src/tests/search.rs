// SPDX-License-Identifier: GPL-3.0-or-later

//! The NAT-timeout search and the keepalive it admits, against a stand-in
//! line whose mappings die after a set idle time.

use std::time::Duration;

use crate::error::FieldkitError;
use crate::measure::nat_timeout::{bracket, max_keepalive};
use crate::wire::Delay;

fn delay(seconds: u64) -> Delay {
    Delay::new(Duration::from_secs(seconds)).unwrap()
}

/// The bracket against a line whose mappings live `timeout` seconds, and
/// the idle times it tried.
fn search(
    timeout: u64,
    min: u64,
    max: u64,
    resolution: u64,
) -> ((Option<u64>, Option<u64>), Vec<u64>) {
    let mut tried = Vec::new();
    let (alive, dead) = bracket(
        delay(min),
        delay(max),
        Duration::from_secs(resolution),
        |delay| {
            let seconds = delay.duration().as_secs();
            tried.push(seconds);
            Ok(seconds <= timeout)
        },
    )
    .unwrap();
    let seconds = |delay: Delay| delay.duration().as_secs();
    ((alive.map(seconds), dead.map(seconds)), tried)
}

#[test]
fn the_search_brackets_the_timeout_within_the_resolution() {
    for timeout in [10, 11, 29, 30, 31, 117, 299] {
        let ((alive, dead), tried) = search(timeout, 10, 300, 5);
        let (alive, dead) = (alive.unwrap(), dead.unwrap());
        assert!(
            alive <= timeout && timeout < dead,
            "timeout {timeout}: {alive}..{dead}"
        );
        assert!(dead - alive <= 5, "timeout {timeout}: {alive}..{dead}");
        assert!(
            tried.len() <= 2 + 6,
            "timeout {timeout}: {} probes",
            tried.len()
        );
    }
}

#[test]
fn the_search_reports_a_timeout_outside_its_range() {
    assert_eq!(search(5, 10, 300, 5).0, (None, Some(10)));
    assert_eq!(search(5, 10, 300, 5).1, vec![10]);
    assert_eq!(search(900, 10, 300, 5).0, (Some(300), None));
    assert_eq!(search(900, 10, 300, 5).1, vec![10, 300]);
}

#[test]
fn the_search_ends_when_the_bracket_cannot_narrow() {
    let ((alive, dead), _) = search(10, 10, 11, 0);
    assert_eq!((alive, dead), (Some(10), Some(11)));
}

#[test]
fn a_failed_probe_stops_the_search() {
    let outcome = bracket(delay(10), delay(300), Duration::from_secs(5), |_| {
        Err(FieldkitError::Clock)
    });
    assert!(matches!(outcome, Err(FieldkitError::Clock)));
}

#[test]
fn the_keepalive_is_half_the_timeout_within_5_to_60_seconds() {
    let seconds = |alive_ms| max_keepalive(alive_ms).map(|keepalive| keepalive.seconds());
    assert_eq!(seconds(30_000), Some(15));
    assert_eq!(seconds(31_999), Some(15));
    assert_eq!(seconds(10_000), Some(5));
    assert_eq!(seconds(9_999), None);
    assert_eq!(seconds(120_000), Some(60));
    assert_eq!(seconds(300_000), Some(60));
    assert_eq!(seconds(0), None);
}
