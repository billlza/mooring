// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit uplink`: the line's upload rate over a day, which gives
//! `UplinkBaseline` (its 10th and 50th percentiles, design §7, §22 M2) and
//! decides the go/no-go of design §22 "Reading the results".
//!
//! Each sample sends to the sink for `--seconds` over `--flows` TCP
//! connections at once; the sink counts what arrives in each second, and
//! the first `--warmup` seconds (slow start) are left out of the rate.
//! Meanwhile one UDP echo every 200 ms measures the loaded round-trip time,
//! against five echoes taken idle just before (design §22 M2b: the loaded
//! RTT while the uplink is saturated). On macOS the interface's own byte
//! counter is read before and after, so the bytes the line carried can be
//! set against the bytes the probe wrote (the SIM-factor reconciliation).

use std::io::{self, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use mooring_model::{UnixTime, UplinkBaseline};
use serde::Serialize;
use socket2::SockRef;

use crate::error::FieldkitError;
use crate::net::{Bind, Connect, Failure, Nonces, exchange, now_unix, read_line};
use crate::output::Output;
use crate::stats::{Spread, jain_index_permille, percentile};
use crate::wire::{EchoKind, EchoRequest, MAX_REPORT, SinkReport, sink_line};

/// How often the loaded RTT is sampled.
const PING_EVERY: Duration = Duration::from_millis(200);

/// Idle echoes before each sample.
const IDLE_PINGS: u8 = 5;

/// The size of each write.
const CHUNK: usize = 64 * 1024;

/// What to measure.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    /// The sink.
    pub(crate) sink: SocketAddrV4,
    /// The echo server, for the RTT.
    pub(crate) echo: SocketAddrV4,
    /// How long.
    pub(crate) duration: Duration,
    /// How often.
    pub(crate) interval: Duration,
    /// The length of each sample, 1 to 120 s, longer than `warmup`.
    pub(crate) seconds: u16,
    /// The seconds at the start of each sample left out of its rate.
    pub(crate) warmup: u16,
    /// Connections per sample.
    pub(crate) flows: u16,
}

#[derive(Debug, Serialize)]
struct Sample {
    measure: &'static str,
    at: UnixTime,
    #[serde(flatten)]
    result: SampleResult,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum SampleResult {
    Measured(Measured),
    Failed { failure: Failure },
}

/// One sample's measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Measured {
    /// The upload rate, all flows together, in bit/s.
    pub(crate) goodput_bps: u64,
    /// Each flow's rate, in bit/s.
    pub(crate) per_flow_bps: Vec<u64>,
    /// Jain's index of the flows' rates, in thousandths.
    pub(crate) fairness_permille: Option<u16>,
    /// The idle round-trip times, in microseconds.
    pub(crate) idle_rtt_us: Option<Spread>,
    /// The round-trip times while sending, in microseconds.
    pub(crate) loaded_rtt_us: Option<Spread>,
    /// The echoes sent while loaded that got no answer.
    pub(crate) loaded_rtt_lost: u32,
    /// The bytes the probe wrote to its sockets (more than the line
    /// carried in the window: the sockets' buffers hold the rest).
    pub(crate) app_bytes: u64,
    /// The bytes the sink counted in its window.
    pub(crate) delivered_bytes: u64,
    /// The bytes the interface counted out over the sample (macOS), good
    /// to 1 KiB and while a sample moves under 4 GiB (see
    /// `mooring_macsys::Interface::obytes`).
    pub(crate) interface_bytes: Option<u64>,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    measure: &'static str,
    interface: String,
    /// Samples measured.
    pub(crate) samples: u64,
    /// Samples that failed.
    pub(crate) failures: u64,
    /// The spread of the samples' rates, in bit/s.
    pub(crate) goodput_bps: Option<Spread>,
    /// `UplinkBaseline` from the rates' 10th and 50th percentiles, when the
    /// 10th is above zero.
    pub(crate) baseline: Option<UplinkBaseline>,
    /// The median of the samples' idle RTT medians, in microseconds.
    pub(crate) idle_rtt_p50_us: Option<u64>,
    /// The median of the samples' loaded RTT medians, in microseconds.
    pub(crate) loaded_rtt_p50_us: Option<u64>,
    /// The bytes the probe wrote in all.
    pub(crate) app_bytes: u64,
    /// The bytes the sink counted in all.
    pub(crate) delivered_bytes: u64,
    /// The bytes the interface counted out in all (macOS).
    pub(crate) interface_bytes: Option<u64>,
}

/// Samples until the plan's duration has passed. The first sample must
/// succeed; later failures are recorded as samples.
pub(crate) fn run(
    bind: &Bind,
    plan: Plan,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let nonces = Nonces::new();
    let mut measured: Vec<Measured> = Vec::new();
    let mut failures = 0_u64;
    let samples = super::every(plan.duration, plan.interval, |round| {
        let at = now_unix()?;
        let result = match sample(bind, plan, &nonces)? {
            Ok(sample) => {
                if round == 0 {
                    output.note(&volume_note(&sample, plan))?;
                }
                measured.push(sample.clone());
                SampleResult::Measured(sample)
            }
            Err(failure) if round == 0 => {
                return Err(FieldkitError::Peer {
                    peer: plan.sink,
                    what: "the first uplink sample",
                    source: io::Error::other(failure.reason),
                });
            }
            Err(failure) => {
                failures += 1;
                SampleResult::Failed { failure }
            }
        };
        output.record(&Sample {
            measure: "uplink",
            at,
            result,
        })
    })?;
    let rates: Vec<u64> = measured.iter().map(|sample| sample.goodput_bps).collect();
    let goodput = Spread::of(&rates);
    let medians = |pick: fn(&Measured) -> Option<Spread>| {
        let values: Vec<u64> = measured
            .iter()
            .filter_map(pick)
            .map(|spread| spread.p50)
            .collect();
        percentile(&values, 50)
    };
    let summary = Summary {
        measure: "uplink",
        interface: bind.name().to_owned(),
        samples: samples - failures,
        failures,
        goodput_bps: goodput,
        baseline: match goodput {
            Some(spread) if spread.p10 > 0 => {
                Some(UplinkBaseline::new(spread.p10, spread.p50, now_unix()?)?)
            }
            Some(_) | None => None,
        },
        idle_rtt_p50_us: medians(|sample| sample.idle_rtt_us),
        loaded_rtt_p50_us: medians(|sample| sample.loaded_rtt_us),
        app_bytes: measured.iter().map(|sample| sample.app_bytes).sum(),
        delivered_bytes: measured.iter().map(|sample| sample.delivered_bytes).sum(),
        interface_bytes: measured
            .iter()
            .map(|sample| sample.interface_bytes)
            .sum::<Option<u64>>(),
    };
    output.record(&summary)?;
    Ok(summary)
}

/// What the whole run will send at the first sample's rate, so the
/// operator can weigh it against the SIM's budget before it is spent.
pub(crate) fn volume_note(first: &Measured, plan: Plan) -> String {
    let interval = plan.interval.as_secs().max(1);
    let samples = plan.duration.as_secs().div_ceil(interval).max(1);
    let total = first.delivered_bytes.saturating_mul(samples);
    format!(
        "the first sample carried {} MB; {samples} samples at that rate carry about {} MB",
        first.delivered_bytes / 1_000_000,
        total / 1_000_000
    )
}

/// One sample: idle echoes, then the flows with loaded echoes alongside.
fn sample(
    bind: &Bind,
    plan: Plan,
    nonces: &Nonces,
) -> Result<Result<Measured, Failure>, FieldkitError> {
    let echo = bind.udp()?;
    let mut idle = Vec::new();
    for _ in 0..IDLE_PINGS {
        if let Some(rtt) = ping(&echo, plan.echo, nonces)? {
            idle.push(super::micros(rtt));
        }
        thread::sleep(PING_EVERY);
    }
    let before = interface_obytes(bind)?;
    let (flows, loaded, lost) = thread::scope(|scope| {
        let flows: Vec<_> = (0..plan.flows)
            .map(|_| scope.spawn(move || flow(bind, plan)))
            .collect();
        let mut loaded = Vec::new();
        let mut lost = 0_u32;
        while flows.iter().any(|flow| !flow.is_finished()) {
            let started = Instant::now();
            match ping(&echo, plan.echo, nonces) {
                Ok(Some(rtt)) => loaded.push(super::micros(rtt)),
                Ok(None) => lost += 1,
                Err(error) => return Err(error),
            }
            thread::sleep(PING_EVERY.saturating_sub(started.elapsed()));
        }
        let flows = flows
            .into_iter()
            .map(|flow| {
                flow.join().unwrap_or(Err(FieldkitError::Worker {
                    what: "uplink flow",
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((flows, loaded, lost))
    })?;
    let after = interface_obytes(bind)?;
    let mut per_flow = Vec::with_capacity(flows.len());
    let (mut app_bytes, mut delivered_bytes) = (0_u64, 0_u64);
    for flow in flows {
        match flow {
            Ok(flow) => {
                per_flow.push(flow.rate_bps);
                app_bytes += flow.written;
                delivered_bytes += flow.delivered;
            }
            Err(failure) => return Ok(Err(failure)),
        }
    }
    Ok(Ok(Measured {
        goodput_bps: per_flow.iter().sum(),
        fairness_permille: jain_index_permille(&per_flow),
        per_flow_bps: per_flow,
        idle_rtt_us: Spread::of(&idle),
        loaded_rtt_us: Spread::of(&loaded),
        loaded_rtt_lost: lost,
        app_bytes,
        delivered_bytes,
        interface_bytes: before
            .zip(after)
            .and_then(|(before, after)| counter_delta(before, after)),
    }))
}

/// How far an interface byte counter moved between two reads. macsys reads
/// the counters modulo 2^32, so a smaller second read below 2^32 wrapped
/// once; a smaller second read of a larger counter is a reset, and `None`.
pub(crate) fn counter_delta(before: u64, after: u64) -> Option<u64> {
    const WRAP: u64 = 1 << 32;
    if after >= before {
        Some(after - before)
    } else if before < WRAP {
        Some(after + WRAP - before)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn interface_obytes(bind: &Bind) -> Result<Option<u64>, FieldkitError> {
    mooring_macsys::interface(bind.index())
        .map(|interface| Some(interface.obytes))
        .map_err(|error| FieldkitError::Interface {
            name: bind.name().to_owned(),
            reason: error.to_string(),
        })
}

#[cfg(target_os = "linux")]
fn interface_obytes(_bind: &Bind) -> Result<Option<u64>, FieldkitError> {
    Ok(None)
}

/// One echo: the round trip, or `None` if no answer came within a second.
fn ping(
    socket: &std::net::UdpSocket,
    echo: SocketAddrV4,
    nonces: &Nonces,
) -> Result<Option<Duration>, FieldkitError> {
    let request = EchoRequest {
        kind: EchoKind::Now,
        nonce: nonces.next(),
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    Ok(exchange(socket, echo, echo, &request, 1, Duration::ZERO, deadline)?.map(|(_, rtt)| rtt))
}

/// What one flow measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowResult {
    /// Its rate after the warm-up, in bit/s.
    rate_bps: u64,
    /// The bytes the sink counted in its window.
    delivered: u64,
    /// The bytes the probe wrote to the socket.
    written: u64,
}

/// One flow: sends until the sink's report arrives (so the line is busy
/// for the sink's whole window), then stops.
fn flow(bind: &Bind, plan: Plan) -> Result<Result<FlowResult, Failure>, FieldkitError> {
    let mut stream = match bind.connect(plan.sink, Duration::from_secs(10)) {
        Ok(stream) => stream,
        Err(Connect::Setup(error)) => return Err(error),
        Err(Connect::Failed(error)) => return Ok(Err(Failure::of("connect", &error))),
    };
    let opened = stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| stream.write_all(sink_line(plan.seconds).as_bytes()));
    if let Err(error) = opened {
        return Ok(Err(Failure::of("send", &error)));
    }
    let writer = stream
        .try_clone()
        .map_err(|source| FieldkitError::socket("clone the sink connection", source))?;
    let patience = Duration::from_secs(u64::from(plan.seconds) + 40);
    stream
        .set_read_timeout(Some(patience))
        .map_err(|source| FieldkitError::socket("set a read timeout", source))?;
    let stop = AtomicBool::new(false);
    let (line, written) = thread::scope(|scope| {
        let sending = scope.spawn(|| send(&writer, &stop, Instant::now() + patience));
        let line = read_line(&mut stream, MAX_REPORT);
        stop.store(true, Ordering::Relaxed);
        let written = sending
            .join()
            .unwrap_or(Err(io::Error::other("the sending thread panicked")));
        (line, written)
    });
    // Abort rather than close: what the socket still holds would keep the
    // line busy after the sample, slowing the next one and delaying its
    // opening lines (measured on 2026-10-22). Discarding it is the point.
    SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .map_err(|source| FieldkitError::socket("set the linger time", source))?;
    drop(writer);
    drop(stream);
    let line = match line {
        Ok(Some(line)) => line,
        Ok(None) => {
            let closed = io::Error::new(io::ErrorKind::UnexpectedEof, "closed without a report");
            return Ok(Err(Failure::of("report", &closed)));
        }
        Err(error) => return Ok(Err(Failure::of("report", &error))),
    };
    let written = match written {
        Ok(written) => written,
        Err(error) => return Ok(Err(Failure::of("send", &error))),
    };
    let report =
        SinkReport::parse(&line, plan.seconds).map_err(|source| FieldkitError::Protocol {
            peer: plan.sink,
            source,
        })?;
    Ok(Ok(FlowResult {
        rate_bps: rate_after_warmup(&report.bytes_per_second, plan.warmup),
        delivered: report.bytes_per_second.iter().sum(),
        written,
    }))
}

/// The rate in bit/s over the seconds after the first `warmup`; 0 when no
/// second is left (the plan keeps `warmup` below the sample's length).
pub(crate) fn rate_after_warmup(bytes_per_second: &[u64], warmup: u16) -> u64 {
    let counted = bytes_per_second.get(usize::from(warmup)..).unwrap_or(&[]);
    if counted.is_empty() {
        return 0;
    }
    counted.iter().sum::<u64>() * 8 / counted.len() as u64
}

/// Writes noise until `stop` is set or `until` passes; the bytes written.
/// A write error after `stop` (the sink closing once it has reported) ends
/// the flow normally.
fn send(mut stream: &TcpStream, stop: &AtomicBool, until: Instant) -> io::Result<u64> {
    let chunk = noise(CHUNK);
    let mut written = 0_u64;
    while !stop.load(Ordering::Relaxed) && Instant::now() < until {
        match stream.write(&chunk) {
            Ok(count) => written += count as u64,
            Err(error) if crate::net::timed_out(&error) => {}
            Err(_) if stop.load(Ordering::Relaxed) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(written)
}

/// `len` bytes of xorshift noise, so nothing on the path can compress them.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}
