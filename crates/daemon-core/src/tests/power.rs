// SPDX-License-Identifier: GPL-3.0-or-later

//! The power helper's protocol: every event and command, and their lines,
//! pinned in `contract/power-fixtures/protocol.json`, which the helper's
//! Swift tests read too. A line is one JSON value of a known variant within
//! [`MAX_HELPER_LINE_BYTES`]; anything else is refused, never guessed.
//!
//! To change the fixture, change [`protocol`], write [`encode`]'s output
//! over the file, and review the diff.

use serde::{Deserialize, Serialize};

use crate::error::{ControlError, ControlErrorKind};
use crate::power::{
    HelperCommand, HelperEvent, MAX_HELPER_LINE_BYTES, decode_command, decode_event,
    encode_command, encode_event,
};
use crate::status::PowerSource;

const FIXTURE: &[u8] = include_bytes!("../../../../contract/power-fixtures/protocol.json");

/// Every event and command, once each, in declaration order.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    events: Vec<HelperEvent>,
    commands: Vec<HelperCommand>,
}

fn protocol() -> Protocol {
    Protocol {
        events: vec![
            HelperEvent::PowerSource(PowerSource::Ac),
            HelperEvent::Assertions { held: true },
            HelperEvent::WillSleep { id: 7 },
            HelperEvent::DidWake,
        ],
        commands: vec![
            HelperCommand::Hold(true),
            HelperCommand::AllowSleep { id: 7 },
        ],
    }
}

fn encode(protocol: &Protocol) -> String {
    let mut text = serde_json::to_string_pretty(protocol).unwrap();
    text.push('\n');
    text
}

#[test]
fn the_protocol_fixture_is_what_its_builder_generates() {
    assert!(
        encode(&protocol()).as_bytes() == FIXTURE,
        "contract/power-fixtures/protocol.json is not what its builder generates"
    );
    let decoded: Protocol = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(decoded, protocol());
}

/// Every variant is in the fixture once, in declaration order: the matches
/// are exhaustive, so a new variant cannot be left out.
#[test]
fn the_fixture_lists_every_variant() {
    let events: Vec<usize> = protocol()
        .events
        .iter()
        .map(|event| match event {
            HelperEvent::PowerSource(_) => 0,
            HelperEvent::Assertions { .. } => 1,
            HelperEvent::WillSleep { .. } => 2,
            HelperEvent::DidWake => 3,
        })
        .collect();
    assert_eq!(events, [0, 1, 2, 3]);
    let commands: Vec<usize> = protocol()
        .commands
        .iter()
        .map(|command| match command {
            HelperCommand::Hold(_) => 0,
            HelperCommand::AllowSleep { .. } => 1,
        })
        .collect();
    assert_eq!(commands, [0, 1]);
}

/// Each line is the compact JSON with a newline, as both sides write it,
/// and reads back as itself, with or without the newline.
#[test]
fn every_line_round_trips() {
    let lines = [
        (
            HelperEvent::PowerSource(PowerSource::Ac),
            "{\"power_source\":\"ac\"}\n",
        ),
        (
            HelperEvent::PowerSource(PowerSource::Battery),
            "{\"power_source\":\"battery\"}\n",
        ),
        (
            HelperEvent::Assertions { held: false },
            "{\"assertions\":{\"held\":false}}\n",
        ),
        (
            HelperEvent::WillSleep { id: 1 },
            "{\"will_sleep\":{\"id\":1}}\n",
        ),
        (HelperEvent::DidWake, "\"did_wake\"\n"),
    ];
    for (event, line) in lines {
        assert_eq!(encode_event(&event).unwrap(), line.as_bytes());
        assert_eq!(decode_event(line.as_bytes()).unwrap(), event);
        assert_eq!(decode_event(line.trim_end().as_bytes()).unwrap(), event);
    }
    for (command, line) in [
        (HelperCommand::Hold(false), "{\"hold\":false}\n"),
        (
            HelperCommand::AllowSleep { id: u64::MAX },
            "{\"allow_sleep\":{\"id\":18446744073709551615}}\n",
        ),
    ] {
        assert_eq!(encode_command(&command).unwrap(), line.as_bytes());
        assert_eq!(decode_command(line.as_bytes()).unwrap(), command);
    }
}

/// An unknown variant or key, a wrong type, two lines in one, or a line
/// past the bound is refused.
#[test]
fn anything_else_is_refused() {
    for line in [
        "",
        "\"did_sleep\"\n",
        "{\"power_source\":\"ups\"}\n",
        "{\"assertions\":{\"held\":true,\"since\":1}}\n",
        "{\"assertions\":{}}\n",
        "{\"will_sleep\":{\"id\":-1}}\n",
        "{\"will_sleep\":7}\n",
        "\"did_wake\"\n\"did_wake\"\n",
        "{\"power_source\":\"ac\",\"did_wake\":null}\n",
    ] {
        let error = decode_event(line.as_bytes()).unwrap_err();
        assert_eq!(error, ControlError::Malformed, "{line:?}");
    }
    for line in ["{\"hold\":1}\n", "{\"allow_sleep\":{}}\n", "\"hold\"\n"] {
        assert_eq!(
            decode_command(line.as_bytes()).unwrap_err(),
            ControlError::Malformed,
            "{line:?}"
        );
    }
    let long = format!("{{\"hold\":true}}{}\n", " ".repeat(MAX_HELPER_LINE_BYTES));
    let error = decode_command(long.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), ControlErrorKind::LineTooLong);
}
