// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit port-ceiling`: how many TCP connections the carrier's NAT lets
//! the line hold open at once, which sizes `FlowCap`, the node-wide cap on
//! new flows (design §11, §22 M2b).
//!
//! Connections are opened one after another and each is held once the
//! target acknowledges it with one byte, until `--max` are held or three
//! in a row fail. A failure to connect is the carrier's (or the path's)
//! limit; a connection the target closes or never acknowledges is the
//! target's, so the result says which one stopped the count.

use std::io::{self, Read};
use std::net::{SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::FieldkitError;
use crate::limits::ensure_open_files;
use crate::net::{Bind, Connect, Failure};
use crate::output::Output;
use crate::wire::CEILING_ACK;

/// Consecutive failures that end the count.
const FAILURES_TO_STOP: u8 = 3;

/// Open files the probe needs beyond the connections it holds.
const SPARE_FILES: u64 = 64;

/// What to measure.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    /// The port-ceiling target.
    pub(crate) target: SocketAddrV4,
    /// The most connections to hold.
    pub(crate) max: u16,
    /// The connect and acknowledgement timeout.
    pub(crate) timeout: Duration,
}

/// What ended the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stop {
    /// `--max` connections were held.
    ReachedMax,
    /// Connects kept failing: the line's limit.
    ConnectFailed,
    /// The target kept closing connections or not acknowledging them: the
    /// target's limit, not the line's.
    TargetRefused,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// The connections held at the end.
    pub(crate) held: u16,
    /// What ended the count.
    pub(crate) stopped_by: Stop,
    /// The last failure, when one ended the count.
    pub(crate) last_failure: Option<Failure>,
    /// How long the count took.
    pub(crate) elapsed_ms: u64,
}

enum Attempt {
    Held(TcpStream),
    ConnectFailed(Failure),
    TargetRefused(Failure),
}

/// Counts. Every connection is closed when the count ends.
pub(crate) fn run(
    bind: &Bind,
    plan: Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    ensure_open_files(u64::from(plan.max) + SPARE_FILES)?;
    let started = Instant::now();
    let mut held: Vec<TcpStream> = Vec::with_capacity(usize::from(plan.max));
    let mut count = 0_u16;
    let mut failures = 0_u8;
    let mut stopped_by = Stop::ReachedMax;
    let mut last_failure = None;
    while count < plan.max {
        let (stop, failure) = match attempt(bind, plan)? {
            Attempt::Held(stream) => {
                held.push(stream);
                count += 1;
                failures = 0;
                if count.is_multiple_of(1000) {
                    output.note(&format!("{count} connections held"))?;
                }
                continue;
            }
            Attempt::ConnectFailed(failure) => (Stop::ConnectFailed, failure),
            Attempt::TargetRefused(failure) => (Stop::TargetRefused, failure),
        };
        failures += 1;
        last_failure = Some(failure);
        if failures >= FAILURES_TO_STOP {
            stopped_by = stop;
            break;
        }
    }
    let summary = Summary {
        measure: "port-ceiling",
        interface: bind.name().to_owned(),
        held: count,
        stopped_by,
        last_failure: if stopped_by == Stop::ReachedMax {
            None
        } else {
            last_failure
        },
        elapsed_ms: super::millis(started.elapsed()),
    };
    drop(held);
    output.record(&summary)?;
    Ok(summary)
}

fn attempt(bind: &Bind, plan: Plan) -> Result<Attempt, FieldkitError> {
    let mut stream = match bind.connect(plan.target, plan.timeout) {
        Ok(stream) => stream,
        Err(Connect::Setup(error)) => return Err(error),
        Err(Connect::Failed(error)) => {
            return Ok(Attempt::ConnectFailed(Failure::of("connect", &error)));
        }
    };
    stream
        .set_read_timeout(Some(plan.timeout))
        .map_err(|source| FieldkitError::socket("set a read timeout", source))?;
    let mut ack = [0_u8; 1];
    Ok(match stream.read(&mut ack) {
        Ok(1) if ack[0] == CEILING_ACK => Attempt::Held(stream),
        Ok(1) => {
            return Err(FieldkitError::Protocol {
                peer: plan.target,
                source: crate::wire::WireError::Line,
            });
        }
        Ok(_) => Attempt::TargetRefused(Failure::of(
            "acknowledge",
            &io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the target closed the connection",
            ),
        )),
        Err(error) => Attempt::TargetRefused(Failure::of("acknowledge", &error)),
    })
}
