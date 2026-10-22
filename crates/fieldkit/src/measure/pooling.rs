// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit pooling`: whether the carrier gives every flow the Mac opens
//! at the same moment one public address ("paired" pooling, RFC 4787), or
//! spreads them over several. That decides `EgressCheck::pairing` (design
//! §10.2): the in-chain probe's egress address can be checked against a
//! direct probe's only if they are paired.
//!
//! Each round opens `--flows` TCP connections to each reflector at once,
//! and as many UDP echoes when `--echo` is given (the tunnel itself is
//! UDP), and records the distinct public addresses the round saw.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::Duration;

use mooring_model::{Pairing, UnixTime};
use serde::Serialize;

use crate::error::FieldkitError;
use crate::net::{Bind, Nonces, ask_reflector, echo_now, now_unix};
use crate::output::Output;

/// What to measure.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// The first reflector.
    pub(crate) reflector: SocketAddrV4,
    /// Any further reflectors (on other addresses, ideally).
    pub(crate) more_reflectors: Vec<SocketAddrV4>,
    /// The echo server, for UDP flows.
    pub(crate) echo: Option<SocketAddrV4>,
    /// Flows per destination per round.
    pub(crate) flows: u16,
    /// How long.
    pub(crate) duration: Duration,
    /// How often.
    pub(crate) interval: Duration,
}

#[derive(Debug, Serialize)]
struct Round {
    measure: &'static str,
    at: UnixTime,
    addresses: BTreeSet<Ipv4Addr>,
    tcp_addresses: BTreeSet<Ipv4Addr>,
    udp_addresses: BTreeSet<Ipv4Addr>,
    flows_answered: u32,
    flows_failed: u32,
}

/// Which protocol a flow used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Over {
    Tcp,
    Udp,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// Rounds run.
    pub(crate) rounds: u64,
    /// Rounds in which every answered flow saw one and the same address.
    pub(crate) single_address_rounds: u64,
    /// Rounds in which no flow was answered.
    pub(crate) silent_rounds: u64,
    /// Whether UDP flows took part.
    pub(crate) udp: bool,
    /// Every address seen.
    pub(crate) addresses: BTreeSet<Ipv4Addr>,
    /// `Paired` when every round that was answered saw one address.
    pub(crate) pairing: Pairing,
}

/// One flow's answer: its protocol and the address it was seen from, or
/// `None` when it got no answer.
type FlowResult = Result<Option<(Over, Ipv4Addr)>, FieldkitError>;

/// Runs the rounds. The first round must be answered.
pub(crate) fn run(
    bind: &Bind,
    plan: &Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let nonces = Nonces::new();
    let timeout = Duration::from_secs(10);
    let mut addresses = BTreeSet::new();
    let (mut single, mut silent) = (0_u64, 0_u64);
    let rounds = super::every(plan.duration, plan.interval, |round| {
        let at = now_unix()?;
        let results: Vec<FlowResult> = thread::scope(|scope| {
            let mut flows = Vec::new();
            for &reflector in std::iter::once(&plan.reflector).chain(&plan.more_reflectors) {
                for _ in 0..plan.flows {
                    flows.push(scope.spawn(move || {
                        Ok(ask_reflector(bind, reflector, timeout)?
                            .ok()
                            .map(|public| (Over::Tcp, *public.ip())))
                    }));
                }
            }
            if let Some(echo) = plan.echo {
                for _ in 0..plan.flows {
                    let nonces = &nonces;
                    flows.push(
                        scope.spawn(move || match echo_now(&bind.udp()?, echo, nonces) {
                            Ok((answer, _)) => Ok(Some((Over::Udp, *answer.observed.ip()))),
                            Err(FieldkitError::Silent { .. }) => Ok(None),
                            Err(error) => Err(error),
                        }),
                    );
                }
            }
            flows
                .into_iter()
                .map(|flow| {
                    flow.join().unwrap_or(Err(FieldkitError::Worker {
                        what: "pooling flow",
                    }))
                })
                .collect()
        });
        let (mut seen, mut tcp, mut udp) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let (mut answered, mut failed) = (0_u32, 0_u32);
        for result in results {
            match result? {
                Some((over, ip)) => {
                    answered += 1;
                    seen.insert(ip);
                    match over {
                        Over::Tcp => tcp.insert(ip),
                        Over::Udp => udp.insert(ip),
                    };
                }
                None => failed += 1,
            }
        }
        if answered == 0 && round == 0 {
            return Err(FieldkitError::Silent {
                peer: plan.reflector,
            });
        }
        match seen.len() {
            0 => silent += 1,
            1 => single += 1,
            _ => {}
        }
        addresses.extend(seen.iter().copied());
        output.record(&Round {
            measure: "pooling",
            at,
            addresses: seen,
            tcp_addresses: tcp,
            udp_addresses: udp,
            flows_answered: answered,
            flows_failed: failed,
        })
    })?;
    let summary = Summary {
        measure: "pooling",
        interface: bind.name().to_owned(),
        rounds,
        single_address_rounds: single,
        silent_rounds: silent,
        udp: plan.echo.is_some(),
        addresses,
        pairing: if single + silent == rounds {
            Pairing::Paired
        } else {
            Pairing::Unpaired
        },
    };
    output.record(&summary)?;
    Ok(summary)
}
