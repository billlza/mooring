// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line: durations, bounds, and the commands as documented in
//! design §22 M2b.

use std::time::Duration;

use clap::Parser;

use crate::cli::{Cli, Command, parse_duration};

fn parse(args: &[&str]) -> Result<Command, clap::Error> {
    Cli::try_parse_from(std::iter::once("fieldkit").chain(args.iter().copied()))
        .map(|cli| cli.command)
}

#[test]
fn durations_take_seconds_minutes_and_hours() {
    assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
    assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
    assert_eq!(parse_duration("24h"), Ok(Duration::from_secs(86_400)));
    for bad in [
        "",
        "0",
        "0s",
        "5d",
        "m",
        "1.5h",
        "-1s",
        "1 h",
        "18446744073709551615h",
    ] {
        assert!(parse_duration(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_design_commands_parse() {
    let commands: [&[&str]; 8] = [
        &["serve", "--listen", "203.0.113.7", "--for", "26h"],
        &[
            "udp-nat-timeout",
            "--bind",
            "en9",
            "--echo",
            "203.0.113.7:27950",
            "--min",
            "10",
            "--max",
            "300",
        ],
        &[
            "nat-behaviour",
            "--bind",
            "en9",
            "--echo",
            "203.0.113.7:27950",
        ],
        &[
            "public-ips",
            "--bind",
            "en9",
            "--reflector",
            "203.0.113.7:27900",
            "--duration",
            "24h",
            "--interval",
            "5m",
        ],
        &[
            "pooling",
            "--bind",
            "en9",
            "--reflectors",
            "203.0.113.7:27900,198.51.100.9:27900",
            "--flows",
            "32",
            "--duration",
            "1h",
        ],
        &[
            "port-ceiling",
            "--bind",
            "en9",
            "--target",
            "203.0.113.7:27960",
            "--max",
            "8192",
        ],
        &[
            "uplink",
            "--bind",
            "en9",
            "--sink",
            "203.0.113.7:27970",
            "--echo",
            "203.0.113.7:27950",
            "--duration",
            "24h",
            "--interval",
            "15m",
        ],
        &[
            "rtt",
            "--bind",
            "en9",
            "--targets",
            "203.0.113.7:22,198.51.100.9:443",
        ],
    ];
    for args in commands {
        assert!(parse(args).is_ok(), "{args:?}: {:?}", parse(args).err());
    }
    let Ok(Command::Pooling(pooling)) = parse(commands[4]) else {
        panic!("pooling");
    };
    assert_eq!(pooling.reflectors.len(), 2);
    #[cfg(target_os = "macos")]
    assert!(parse(&["env", "--bind", "en9", "--compare", "before.json"]).is_ok());
}

#[test]
fn bounds_are_enforced_by_the_parser() {
    let refused: [&[&str]; 9] = [
        &["serve", "--listen", "203.0.113.7", "--for", "49h"],
        &["serve", "--listen", "203.0.113.7"],
        &["serve", "--listen", "::1", "--for", "1h"],
        &[
            "udp-nat-timeout",
            "--bind",
            "en9",
            "--echo",
            "203.0.113.7:27950",
            "--max",
            "11m",
        ],
        &[
            "pooling",
            "--bind",
            "en9",
            "--reflectors",
            "203.0.113.7:27900",
            "--flows",
            "0",
        ],
        &["pooling", "--bind", "en9", "--flows", "4"],
        &[
            "port-ceiling",
            "--bind",
            "en9",
            "--target",
            "203.0.113.7:27960",
            "--max",
            "0",
        ],
        &[
            "uplink",
            "--bind",
            "en9",
            "--sink",
            "203.0.113.7:27970",
            "--echo",
            "203.0.113.7:27950",
            "--seconds",
            "121",
        ],
        &["rtt", "--bind", "en9", "--targets", "example.com:443"],
    ];
    for args in refused {
        assert!(parse(args).is_err(), "{args:?} was accepted");
    }
}
