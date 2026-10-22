// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac-side measurements of design §22 M2b, each against
//! `fieldkit serve` on the VPS and each from a socket bound to the M7's
//! interface.

#[cfg(target_os = "macos")]
pub(crate) mod env;
pub(crate) mod nat_behaviour;
pub(crate) mod nat_timeout;
pub(crate) mod pooling;
pub(crate) mod port_ceiling;
pub(crate) mod public_ips;
pub(crate) mod rtt;
pub(crate) mod uplink;

use std::thread;
use std::time::{Duration, Instant};

use crate::error::FieldkitError;

/// Runs `round` at the start and then every `interval` until `duration`
/// has passed (a round that would start at or after the end does not; a
/// round that overruns its interval skips the starts it missed), stopping
/// at the first error. Returns the number of rounds run.
pub(crate) fn every<F>(
    duration: Duration,
    interval: Duration,
    mut round: F,
) -> Result<u64, FieldkitError>
where
    F: FnMut(u64) -> Result<(), FieldkitError>,
{
    let start = Instant::now();
    let end = start + duration;
    let mut rounds = 0_u64;
    let mut next = start;
    while next < end {
        thread::sleep(next.saturating_duration_since(Instant::now()));
        round(rounds)?;
        rounds += 1;
        next += interval;
        while next < Instant::now() && next < end {
            next += interval;
        }
    }
    Ok(rounds)
}

/// Milliseconds of a duration, rounded down, for reports.
pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Microseconds of a duration, rounded down, for reports.
pub(crate) fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
