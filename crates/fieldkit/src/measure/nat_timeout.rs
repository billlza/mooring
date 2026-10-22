// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit udp-nat-timeout`: how long the line's NAT keeps an idle UDP
//! mapping, which bounds the WireGuard keepalive (design §3: it must lie in
//! [5 s, NAT_timeout/2], and never above 60 s).
//!
//! Each probe takes a fresh socket (so a fresh mapping), asks the echo
//! server to answer after a delay, and stays silent meanwhile: the answer
//! arrives only if the mapping outlived the delay. A binary search between
//! `--min` and `--max` narrows the timeout to `--resolution`. A probe that
//! gets no answer is repeated once before it counts, so one lost datagram
//! does not shorten the result.

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use mooring_model::{Keepalive, UnixTime};
use serde::Serialize;

use crate::error::FieldkitError;
use crate::net::{Bind, Nonces, echo_now, exchange, now_unix};
use crate::output::Output;
use crate::wire::{Delay, EchoKind, EchoRequest};

/// How long past the delay a probe waits for its answer.
const SLACK: Duration = Duration::from_secs(5);

/// What to measure.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    /// The echo server (port A).
    pub(crate) echo: SocketAddrV4,
    /// The shortest idle time tried.
    pub(crate) min: Delay,
    /// The longest idle time tried.
    pub(crate) max: Delay,
    /// The bracket's width at which the search stops.
    pub(crate) resolution: Duration,
}

#[derive(Debug, Serialize)]
struct Probe {
    measure: &'static str,
    at: UnixTime,
    idle_ms: u64,
    alive: bool,
}

/// The result: the mapping lived through `alive_up_to_ms` and died by
/// `dead_from_ms` (either may be unknown when the search hit its bounds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// The longest idle time a mapping survived.
    pub(crate) alive_up_to_ms: Option<u64>,
    /// The shortest idle time a mapping did not survive.
    pub(crate) dead_from_ms: Option<u64>,
    /// The largest keepalive design §3 admits, from `alive_up_to_ms`:
    /// half of it, at most 60 s; `None` if that is below 5 s or unknown.
    pub(crate) max_keepalive: Option<Keepalive>,
    probes: u32,
}

/// The largest admissible keepalive for a mapping that survives `alive_ms`.
pub(crate) fn max_keepalive(alive_ms: u64) -> Option<Keepalive> {
    let half = (alive_ms / 2_000).min(u64::from(Keepalive::MAX_SECONDS));
    Keepalive::from_seconds(u16::try_from(half).ok()?).ok()
}

/// Runs the search.
pub(crate) fn run(
    bind: &Bind,
    plan: Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let nonces = Nonces::new();
    echo_now(&bind.udp()?, plan.echo, &nonces)?;
    let mut probes = 0_u32;
    let mut alive = |delay: Delay, output: &mut Output<'_>| -> Result<bool, FieldkitError> {
        let mut verdict = false;
        for _attempt in 0..2 {
            probes += 1;
            verdict = survives(bind, plan.echo, delay, &nonces)?;
            output.record(&Probe {
                measure: "udp-nat-timeout",
                at: now_unix()?,
                idle_ms: super::millis(delay.duration()),
                alive: verdict,
            })?;
            if verdict {
                break;
            }
        }
        Ok(verdict)
    };
    let (alive_up_to, dead_from) = bracket(plan.min, plan.max, plan.resolution, |delay| {
        alive(delay, output)
    })?;
    let alive_up_to_ms = alive_up_to.map(|delay| super::millis(delay.duration()));
    let summary = Summary {
        measure: "udp-nat-timeout",
        interface: bind.name().to_owned(),
        alive_up_to_ms,
        dead_from_ms: dead_from.map(|delay| super::millis(delay.duration())),
        max_keepalive: alive_up_to_ms.and_then(max_keepalive),
        probes,
    };
    output.record(&summary)?;
    Ok(summary)
}

/// The bracket around the timeout: the longest idle time found alive and
/// the shortest found dead, searching between `min` and `max` until they
/// are at most `resolution` apart. `min` dead gives `(None, Some(min))`;
/// `max` alive gives `(Some(max), None)`.
pub(crate) fn bracket<F>(
    min: Delay,
    max: Delay,
    resolution: Duration,
    mut alive: F,
) -> Result<(Option<Delay>, Option<Delay>), FieldkitError>
where
    F: FnMut(Delay) -> Result<bool, FieldkitError>,
{
    if !alive(min)? {
        return Ok((None, Some(min)));
    }
    if alive(max)? {
        return Ok((Some(max), None));
    }
    let (mut lo, mut hi) = (min, max);
    while hi.duration().saturating_sub(lo.duration()) > resolution {
        let mid = lo.midpoint(hi);
        if mid == lo {
            break;
        }
        if alive(mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok((Some(lo), Some(hi)))
}

/// Whether a fresh mapping survives `delay` of silence.
fn survives(
    bind: &Bind,
    echo: SocketAddrV4,
    delay: Delay,
    nonces: &Nonces,
) -> Result<bool, FieldkitError> {
    let socket = bind.udp()?;
    let request = EchoRequest {
        kind: EchoKind::Delayed(delay),
        nonce: nonces.next(),
    };
    let deadline = Instant::now() + delay.duration() + SLACK;
    Ok(exchange(
        &socket,
        echo,
        echo,
        &request,
        3,
        Duration::from_millis(100),
        deadline,
    )?
    .is_some())
}
