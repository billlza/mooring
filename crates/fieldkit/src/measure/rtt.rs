// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit rtt`: the TCP connect time from the line to each candidate
//! address (for choosing a VPS location, design §22 M2b), `--count`
//! connects a second apart per target.

use std::net::SocketAddrV4;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::FieldkitError;
use crate::net::{Bind, Connect};
use crate::output::Output;
use crate::stats::Spread;

/// What to measure.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// The targets.
    pub(crate) targets: Vec<SocketAddrV4>,
    /// Connects per target.
    pub(crate) count: u16,
    /// The connect timeout.
    pub(crate) timeout: Duration,
}

/// One target's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Target {
    /// The target.
    pub(crate) target: SocketAddrV4,
    /// The connect times of the connects that succeeded, in microseconds.
    pub(crate) connect_us: Option<Spread>,
    /// Connects that failed.
    pub(crate) failures: u16,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// Each target, in the order given.
    pub(crate) targets: Vec<Target>,
}

/// Measures every target in turn.
pub(crate) fn run(
    bind: &Bind,
    plan: &Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let mut targets = Vec::with_capacity(plan.targets.len());
    for &target in &plan.targets {
        let mut times = Vec::new();
        let mut failures = 0_u16;
        for index in 0..plan.count {
            if index > 0 {
                thread::sleep(Duration::from_secs(1));
            }
            let started = Instant::now();
            match bind.connect(target, plan.timeout) {
                Ok(stream) => {
                    times.push(super::micros(started.elapsed()));
                    drop(stream);
                }
                Err(Connect::Setup(error)) => return Err(error),
                Err(Connect::Failed(_)) => failures += 1,
            }
        }
        targets.push(Target {
            target,
            connect_us: Spread::of(&times),
            failures,
        });
    }
    let summary = Summary {
        measure: "rtt",
        interface: bind.name().to_owned(),
        targets,
    };
    output.record(&summary)?;
    Ok(summary)
}
