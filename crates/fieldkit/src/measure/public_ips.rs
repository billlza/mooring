// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit public-ips`: the public addresses the carrier gives the line
//! over a day, from a fresh reflector connection every interval. The
//! distinct addresses, looked up in RIPE (`whois`), give `EgressCheck`'s
//! carrier prefixes (design §10.2, §22 M2b).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use mooring_model::UnixTime;
use serde::Serialize;

use crate::error::FieldkitError;
use crate::net::{Bind, Failure, ask_reflector, now_unix};
use crate::output::Output;

/// What to measure.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    /// The reflector.
    pub(crate) reflector: SocketAddrV4,
    /// How long.
    pub(crate) duration: Duration,
    /// How often.
    pub(crate) interval: Duration,
}

#[derive(Debug, Serialize)]
struct Sample {
    measure: &'static str,
    at: UnixTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    public: Option<SocketAddrV4>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<Failure>,
}

/// One public address and when it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Seen {
    /// The address.
    pub(crate) ip: Ipv4Addr,
    /// How many samples saw it.
    pub(crate) samples: u64,
    /// The first sample that saw it.
    pub(crate) first: UnixTime,
    /// The last sample that saw it.
    pub(crate) last: UnixTime,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// Samples taken.
    pub(crate) samples: u64,
    /// Samples whose connection failed.
    pub(crate) failures: u64,
    /// Each distinct address, in address order.
    pub(crate) addresses: Vec<Seen>,
}

/// Samples the public address until the plan's duration has passed. The
/// first sample must succeed, so a wrong address or a closed port stops the
/// run at once; later failures are recorded as samples.
pub(crate) fn run(
    bind: &Bind,
    plan: Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let timeout = Duration::from_secs(10);
    let mut seen: BTreeMap<Ipv4Addr, Seen> = BTreeMap::new();
    let mut failures = 0_u64;
    let samples = super::every(plan.duration, plan.interval, |round| {
        let at = now_unix()?;
        let sample = match ask_reflector(bind, plan.reflector, timeout)? {
            Ok(public) => {
                seen.entry(*public.ip())
                    .and_modify(|entry| {
                        entry.samples += 1;
                        entry.last = at;
                    })
                    .or_insert(Seen {
                        ip: *public.ip(),
                        samples: 1,
                        first: at,
                        last: at,
                    });
                Sample {
                    measure: "public-ips",
                    at,
                    public: Some(public),
                    failure: None,
                }
            }
            Err(failure) if round == 0 => {
                return Err(FieldkitError::Peer {
                    peer: plan.reflector,
                    what: "the first reflector sample",
                    source: std::io::Error::other(failure.reason),
                });
            }
            Err(failure) => {
                failures += 1;
                Sample {
                    measure: "public-ips",
                    at,
                    public: None,
                    failure: Some(failure),
                }
            }
        };
        output.record(&sample)
    })?;
    let summary = Summary {
        measure: "public-ips",
        interface: bind.name().to_owned(),
        samples,
        failures,
        addresses: seen.into_values().collect(),
    };
    output.record(&summary)?;
    Ok(summary)
}
