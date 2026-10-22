// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line. Durations are written `90s`, `15m`, `24h` (or plain
//! seconds); addresses are IPv4 `address:port`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

/// Mooring's M2b field measurements (design §22 M2b). Every probe binds
/// its sockets to `--bind`, the M7's interface, and writes one JSON line
/// per sample and a summary line last.
#[derive(Debug, Parser)]
#[command(name = "fieldkit", version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// The VPS side: the reflector, two echo ports, the port-ceiling target
    /// and the sink, for a fixed time.
    Serve(Serve),
    /// The Mac's interfaces, and the M7 interface's selectors (macOS only).
    #[cfg(target_os = "macos")]
    Env(Env),
    /// The line's UDP NAT timeout, and the keepalive it admits.
    UdpNatTimeout(UdpNatTimeout),
    /// The line's NAT mapping and filtering.
    NatBehaviour(NatBehaviour),
    /// The public addresses the line gets over time.
    PublicIps(PublicIps),
    /// Whether simultaneous flows share one public address.
    Pooling(Pooling),
    /// How many TCP connections the line can hold open.
    PortCeiling(PortCeiling),
    /// The line's upload rate over time, with the loaded RTT.
    Uplink(Uplink),
    /// TCP connect times to candidate addresses.
    Rtt(Rtt),
}

/// `fieldkit serve`.
#[derive(Debug, Args)]
pub(crate) struct Serve {
    /// The address to listen on (the VPS's public IPv4).
    #[arg(long)]
    pub(crate) listen: Ipv4Addr,
    /// How long to serve before stopping (at most 48h).
    #[arg(long = "for", value_parser = parse_serve_duration)]
    pub(crate) serve_for: Duration,
    /// The TCP reflector's port.
    #[arg(long, default_value_t = 27900)]
    pub(crate) reflector_port: u16,
    /// UDP echo port A.
    #[arg(long, default_value_t = 27950)]
    pub(crate) echo_port: u16,
    /// UDP echo port B.
    #[arg(long, default_value_t = 27951)]
    pub(crate) echo_alt_port: u16,
    /// The TCP port-ceiling target's port.
    #[arg(long, default_value_t = 27960)]
    pub(crate) ceiling_port: u16,
    /// The most connections the port-ceiling target holds.
    #[arg(long, default_value_t = 8192)]
    pub(crate) ceiling_max: u16,
    /// The TCP sink's port.
    #[arg(long, default_value_t = 27970)]
    pub(crate) sink_port: u16,
    /// How often to record the counts.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    pub(crate) report_every: Duration,
}

/// The interface every probe binds to.
#[derive(Debug, Args)]
pub(crate) struct BindArg {
    /// The M7's interface (`en9`).
    #[arg(long = "bind")]
    pub(crate) interface: String,
}

/// `fieldkit env`.
#[derive(Debug, Args)]
pub(crate) struct Env {
    /// The M7's interface, described in detail.
    #[arg(long = "bind")]
    pub(crate) interface: Option<String>,
    /// An earlier `env` output to compare the interface with.
    #[arg(long)]
    pub(crate) compare: Option<PathBuf>,
}

/// `fieldkit udp-nat-timeout`.
#[derive(Debug, Args)]
pub(crate) struct UdpNatTimeout {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The VPS's echo port A.
    #[arg(long)]
    pub(crate) echo: SocketAddrV4,
    /// The shortest idle time tried.
    #[arg(long, default_value = "10s", value_parser = parse_echo_delay)]
    pub(crate) min: Duration,
    /// The longest idle time tried (at most 10m).
    #[arg(long, default_value = "300s", value_parser = parse_echo_delay)]
    pub(crate) max: Duration,
    /// The width of the bracket at which the search stops.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    pub(crate) resolution: Duration,
}

/// `fieldkit nat-behaviour`.
#[derive(Debug, Args)]
pub(crate) struct NatBehaviour {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The VPS's echo port A.
    #[arg(long)]
    pub(crate) echo: SocketAddrV4,
    /// The VPS's echo port B (default: A's port + 1).
    #[arg(long)]
    pub(crate) alt_port: Option<u16>,
}

/// `fieldkit public-ips`.
#[derive(Debug, Args)]
pub(crate) struct PublicIps {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The VPS's reflector.
    #[arg(long)]
    pub(crate) reflector: SocketAddrV4,
    /// How long.
    #[arg(long, default_value = "24h", value_parser = parse_duration)]
    pub(crate) duration: Duration,
    /// How often.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    pub(crate) interval: Duration,
}

/// `fieldkit pooling`.
#[derive(Debug, Args)]
pub(crate) struct Pooling {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The reflectors, comma-separated (ideally on two VPSs).
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) reflectors: Vec<SocketAddrV4>,
    /// The echo port A, for UDP flows alongside the TCP ones.
    #[arg(long)]
    pub(crate) echo: Option<SocketAddrV4>,
    /// Flows per destination per round (1 to 256).
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub(crate) flows: u16,
    /// How long.
    #[arg(long, default_value = "1h", value_parser = parse_duration)]
    pub(crate) duration: Duration,
    /// How often.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    pub(crate) interval: Duration,
}

/// `fieldkit port-ceiling`.
#[derive(Debug, Args)]
pub(crate) struct PortCeiling {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The VPS's port-ceiling target.
    #[arg(long)]
    pub(crate) target: SocketAddrV4,
    /// The most connections to hold.
    #[arg(long, default_value_t = 8192, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) max: u16,
    /// The connect and acknowledgement timeout.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    pub(crate) timeout: Duration,
}

/// `fieldkit uplink`.
#[derive(Debug, Args)]
pub(crate) struct Uplink {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The VPS's sink.
    #[arg(long)]
    pub(crate) sink: SocketAddrV4,
    /// The VPS's echo port A, for the loaded RTT.
    #[arg(long)]
    pub(crate) echo: SocketAddrV4,
    /// How long.
    #[arg(long, default_value = "24h", value_parser = parse_duration)]
    pub(crate) duration: Duration,
    /// How often.
    #[arg(long, default_value = "15m", value_parser = parse_duration)]
    pub(crate) interval: Duration,
    /// The length of each sample in seconds (2 to 120).
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(2..=120))]
    pub(crate) seconds: u16,
    /// The seconds at the start of each sample left out of its rate.
    #[arg(long, default_value_t = 3)]
    pub(crate) warmup: u16,
    /// TCP connections per sample (1 to 16).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=16))]
    pub(crate) flows: u16,
}

/// `fieldkit rtt`.
#[derive(Debug, Args)]
pub(crate) struct Rtt {
    #[command(flatten)]
    pub(crate) bind: BindArg,
    /// The targets, comma-separated.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) targets: Vec<SocketAddrV4>,
    /// Connects per target (1 to 100).
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..=100))]
    pub(crate) count: u16,
    /// The connect timeout.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    pub(crate) timeout: Duration,
}

/// A duration of at least a second: `90s`, `15m`, `24h`, or plain seconds.
pub(crate) fn parse_duration(text: &str) -> Result<Duration, String> {
    let (digits, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, "s"),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a duration like 90s, 15m or 24h"))?;
    let seconds = match unit {
        "s" => Some(value),
        "m" => value.checked_mul(60),
        "h" => value.checked_mul(3600),
        _ => None,
    }
    .ok_or_else(|| format!("{text:?} is not a duration like 90s, 15m or 24h"))?;
    if seconds == 0 {
        return Err("a duration must be at least 1s".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

/// How long `serve` may run: at least a second and at most 48 hours.
fn parse_serve_duration(text: &str) -> Result<Duration, String> {
    let duration = parse_duration(text)?;
    if duration > Duration::from_secs(48 * 3600) {
        return Err("serve runs for at most 48h".to_owned());
    }
    Ok(duration)
}

/// An echo delay: at least a second and at most ten minutes.
fn parse_echo_delay(text: &str) -> Result<Duration, String> {
    let duration = parse_duration(text)?;
    if duration > Duration::from_secs(600) {
        return Err("an idle time is at most 10m".to_owned());
    }
    Ok(duration)
}
