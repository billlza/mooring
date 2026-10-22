// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit`, Mooring's M2b field measurements (design §6, §22 M2b): a
//! dev-only tool, never shipped, built for macOS (the probes, run on the
//! Mac against the M7's interface) and Linux musl (`serve`, run on the
//! VPS). It never touches the Mac's configuration or the M7's: it binds
//! sockets, sends test traffic to the VPS and reports what it measured.
//!
//! - `serve --listen <vps4> --for <duration>`: the reflector (TCP 27900),
//!   the echo ports (UDP 27950 and 27951), the port-ceiling target (TCP
//!   27960) and the sink (TCP 27970), stopped after `--for`;
//! - `env [--bind <bsd>] [--compare <earlier.json>]`: the interface list
//!   and the M7 interface's selectors (macOS only; the Linux build has no
//!   such command);
//! - `udp-nat-timeout`, `nat-behaviour`, `public-ips`, `pooling`,
//!   `port-ceiling`, `uplink` and `rtt`, each with `--bind <bsd>`.
//!
//! Results go to stdout as JSON lines, notes and errors to stderr. A
//! measurement exits 0 when it measured something, whatever it found, and
//! 1 when it could not measure.

mod cli;
mod error;
mod limits;
mod measure;
mod net;
mod output;
mod serve;
mod stats;
#[cfg(test)]
mod tests;
mod wire;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("fieldkit is built for macOS and Linux only");

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::error::FieldkitError;
use crate::net::Bind;
use crate::output::Output;
use crate::serve::{ServeConfig, Server};
use crate::wire::Delay;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let outcome = run(cli.command, &mut Output::new(&mut stdout, &mut stderr));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Nothing else can report a failure to write stderr itself.
            let _ignored = writeln!(stderr, "fieldkit: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs one command.
fn run(command: Command, output: &mut Output<'_>) -> Result<(), FieldkitError> {
    match command {
        Command::Serve(args) => {
            let server = Server::start(ServeConfig {
                listen: args.listen,
                reflector: args.reflector_port,
                echo: (args.echo_port, args.echo_alt_port),
                ceiling: args.ceiling_port,
                ceiling_max: args.ceiling_max,
                sink: args.sink_port,
            })?;
            output.record(&server.ports())?;
            let counts = server.serve_for(args.serve_for, args.report_every, output)?;
            output.record(&counts)
        }
        #[cfg(target_os = "macos")]
        Command::Env(args) => {
            measure::env::run(args.interface.as_deref(), args.compare.as_deref(), output).map(drop)
        }
        Command::UdpNatTimeout(args) => {
            if args.min >= args.max {
                return Err(FieldkitError::Input {
                    path: "--min/--max".to_owned(),
                    reason: "--min must be shorter than --max".to_owned(),
                });
            }
            let plan = measure::nat_timeout::Plan {
                echo: args.echo,
                min: delay(args.min)?,
                max: delay(args.max)?,
                resolution: args.resolution,
            };
            measure::nat_timeout::run(&Bind::interface(&args.bind.interface)?, plan, output)
                .map(drop)
        }
        Command::NatBehaviour(args) => {
            let alt = match args.alt_port {
                Some(port) => port,
                None => args
                    .echo
                    .port()
                    .checked_add(1)
                    .ok_or_else(|| FieldkitError::Input {
                        path: "--alt-port".to_owned(),
                        reason: "echo port A is 65535, so port B must be given".to_owned(),
                    })?,
            };
            let b = std::net::SocketAddrV4::new(*args.echo.ip(), alt);
            measure::nat_behaviour::run(
                &Bind::interface(&args.bind.interface)?,
                args.echo,
                b,
                output,
            )
            .map(drop)
        }
        Command::PublicIps(args) => {
            let plan = measure::public_ips::Plan {
                reflector: args.reflector,
                duration: args.duration,
                interval: args.interval,
            };
            measure::public_ips::run(&Bind::interface(&args.bind.interface)?, plan, output)
                .map(drop)
        }
        Command::Pooling(args) => {
            let mut reflectors = args.reflectors.into_iter();
            let reflector = reflectors.next().ok_or_else(|| FieldkitError::Input {
                path: "--reflectors".to_owned(),
                reason: "no reflector given".to_owned(),
            })?;
            let plan = measure::pooling::Plan {
                reflector,
                more_reflectors: reflectors.collect(),
                echo: args.echo,
                flows: args.flows,
                duration: args.duration,
                interval: args.interval,
            };
            measure::pooling::run(&Bind::interface(&args.bind.interface)?, &plan, output).map(drop)
        }
        Command::PortCeiling(args) => {
            let plan = measure::port_ceiling::Plan {
                target: args.target,
                max: args.max,
                timeout: args.timeout,
            };
            measure::port_ceiling::run(&Bind::interface(&args.bind.interface)?, plan, output)
                .map(drop)
        }
        Command::Uplink(args) => {
            if args.warmup >= args.seconds {
                return Err(FieldkitError::Input {
                    path: "--warmup".to_owned(),
                    reason: "the warm-up must be shorter than --seconds".to_owned(),
                });
            }
            let plan = measure::uplink::Plan {
                sink: args.sink,
                echo: args.echo,
                duration: args.duration,
                interval: args.interval,
                seconds: args.seconds,
                warmup: args.warmup,
                flows: args.flows,
            };
            measure::uplink::run(&Bind::interface(&args.bind.interface)?, plan, output).map(drop)
        }
        Command::Rtt(args) => {
            let plan = measure::rtt::Plan {
                targets: args.targets,
                count: args.count,
                timeout: args.timeout,
            };
            measure::rtt::run(&Bind::interface(&args.bind.interface)?, &plan, output).map(drop)
        }
    }
}

fn delay(duration: std::time::Duration) -> Result<Delay, FieldkitError> {
    Delay::new(duration).map_err(|error| FieldkitError::Input {
        path: "--min/--max".to_owned(),
        reason: error.to_string(),
    })
}
