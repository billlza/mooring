// SPDX-License-Identifier: GPL-3.0-or-later

//! The control channel's lines (design §10.1): their exact encodings, their
//! bounds, and what is refused as malformed.

use serde::{Serialize, Serializer};

use super::router;
use crate::console::{ConsoleStatus, UndeployedStatus};
use crate::control::{
    CONTROL_PROTOCOL, DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES,
    ProtocolLine, Refusal, decode_protocol_line, decode_reply, decode_request, encode_line,
};
use crate::error::{ControlError, ControlErrorKind};
use crate::router::{CarrierName, Mcc, Mnc, Plmn};
use crate::sim_network::{NotAccepted, SimNetwork};
use mooring_model::UnixTime;

fn status() -> ConsoleStatus {
    ConsoleStatus::NoDeployment(UndeployedStatus::new(
        UnixTime::from_secs(1_791_919_260),
        router::reading(),
    ))
}

/// What the M7 reports of a SIM named `spn`, or of one without a name, on
/// the network `mcc` `mnc`.
fn network(spn: Option<&str>, mcc: &str, mnc: &str) -> SimNetwork {
    SimNetwork {
        spn: spn.map(|name| CarrierName::parse(name).unwrap()),
        plmn: Plmn {
            mcc: Mcc::parse(mcc).unwrap(),
            mnc: Mnc::parse(mnc).unwrap(),
        },
    }
}

/// Each request is one short JSON document and a newline, both ways: a
/// string, or for the request that names a network an object with it.
#[test]
fn requests_have_fixed_lines() {
    for (request, line) in [
        (DaemonRequest::Status, "\"status\"\n"),
        (DaemonRequest::Subscribe, "\"subscribe\"\n"),
        (DaemonRequest::Retry, "\"retry\"\n"),
        (
            DaemonRequest::AcceptSimNetwork {
                network: network(Some("1p"), "234", "30"),
            },
            "{\"accept_sim_network\":{\"network\":{\"spn\":\"1p\",\"plmn\":{\"mcc\":\"234\",\"mnc\":\"30\"}}}}\n",
        ),
        (
            DaemonRequest::AcceptSimNetwork {
                network: network(None, "234", "020"),
            },
            "{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":\"234\",\"mnc\":\"020\"}}}}\n",
        ),
    ] {
        let encoded = encode_line(&request, MAX_REQUEST_LINE_BYTES).unwrap();
        assert_eq!(encoded, line.as_bytes());
        assert_eq!(decode_request(line.as_bytes()).unwrap(), request);
        // The newline is optional on decode (the last line before EOF).
        assert_eq!(decode_request(line.trim_end().as_bytes()).unwrap(), request);
    }
}

/// A reply is a status or a refusal, externally tagged, one line each.
#[test]
fn replies_have_fixed_lines() {
    let refused = DaemonReply::Refused {
        reason: Refusal::Busy,
    };
    let line = encode_line(&refused, MAX_REPLY_LINE_BYTES).unwrap();
    assert_eq!(line, b"{\"refused\":{\"reason\":\"busy\"}}\n");
    assert_eq!(decode_reply(&line).unwrap(), refused);
    for (reason, name) in [
        (Refusal::Busy, "busy"),
        (Refusal::BadRequest, "bad_request"),
        (Refusal::NoStatusYet, "no_status_yet"),
        (Refusal::NotDeployed, "not_deployed"),
        (Refusal::NoOtherSimNetwork, "no_other_sim_network"),
        (Refusal::M7NotAttached, "m7_not_attached"),
        (
            Refusal::SimNetworkReportChanged,
            "sim_network_report_changed",
        ),
        (Refusal::LoopBusy, "loop_busy"),
    ] {
        let reply = DaemonReply::Refused { reason };
        let line = encode_line(&reply, MAX_REPLY_LINE_BYTES).unwrap();
        assert_eq!(
            line,
            format!("{{\"refused\":{{\"reason\":\"{name}\"}}}}\n").as_bytes()
        );
        assert_eq!(decode_reply(&line).unwrap(), reply);
    }
    let queued = encode_line(&DaemonReply::RetryQueued, MAX_REPLY_LINE_BYTES).unwrap();
    assert_eq!(queued, b"\"retry_queued\"\n");
    assert_eq!(decode_reply(&queued).unwrap(), DaemonReply::RetryQueued);
    let accepted = encode_line(&DaemonReply::SimNetworkAccepted, MAX_REPLY_LINE_BYTES).unwrap();
    assert_eq!(accepted, b"\"sim_network_accepted\"\n");
    assert_eq!(
        decode_reply(&accepted).unwrap(),
        DaemonReply::SimNetworkAccepted
    );
    let reply = DaemonReply::Status(status());
    let line = encode_line(&reply, MAX_REPLY_LINE_BYTES).unwrap();
    assert!(line.starts_with(b"{\"status\":{\"no_deployment\":{\"version\":1,"));
    assert_eq!(line.iter().filter(|&&byte| byte == b'\n').count(), 1);
    assert_eq!(decode_reply(&line).unwrap(), reply);
}

/// Each reason a network is not taken is a refusal of its own on the
/// wire.
#[test]
fn each_reason_a_network_is_not_taken_is_its_own_refusal() {
    assert_eq!(
        [
            NotAccepted::NoOtherNetwork,
            NotAccepted::NotAttached,
            NotAccepted::ReportChanged,
        ]
        .map(Refusal::from),
        [
            Refusal::NoOtherSimNetwork,
            Refusal::M7NotAttached,
            Refusal::SimNetworkReportChanged,
        ]
    );
}

/// The longest request there is fits a request line: the one that names a
/// network, with a SIM's name of 32 characters that JSON writes as two
/// bytes each and codes of three digits, is 143 bytes.
#[test]
fn the_longest_request_fits_a_request_line() {
    for escaped in ["\\", "\""] {
        let request = DaemonRequest::AcceptSimNetwork {
            network: network(Some(&escaped.repeat(32)), "234", "030"),
        };
        let line = encode_line(&request, MAX_REQUEST_LINE_BYTES).unwrap();
        assert_eq!(line.len(), 143);
        assert_eq!(decode_request(&line).unwrap(), request);
    }
    // One character more is not a SIM's name.
    assert!(CarrierName::parse(&"\\".repeat(33)).is_err());
}

/// The first line of a connection names the protocol, protocol 4 in this
/// build, and only that line is read as one: a reply, a line with another
/// key or another type is not.
#[test]
fn the_protocol_line_is_fixed() {
    assert_eq!(CONTROL_PROTOCOL, 4);
    let line = encode_line(&ProtocolLine::CURRENT, MAX_REPLY_LINE_BYTES).unwrap();
    assert_eq!(line, b"{\"control_protocol\":4}\n");
    assert_eq!(decode_protocol_line(&line).unwrap(), ProtocolLine::CURRENT);
    assert_eq!(
        decode_protocol_line(b"{\"control_protocol\":7}").unwrap(),
        ProtocolLine {
            control_protocol: 7
        }
    );
    for line in [
        &b"{\"refused\":{\"reason\":\"busy\"}}\n"[..],
        b"\"retry_queued\"\n",
        b"{\"control_protocol\":1,\"zz\":1}\n",
        b"{\"control_protocol\":\"1\"}\n",
        b"{\"control_protocol\":-1}\n",
        b"{\"control_protocol\":1}\n{\"control_protocol\":1}\n",
        b"{}\n",
    ] {
        assert_eq!(
            decode_protocol_line(line),
            Err(ControlError::Malformed),
            "{line:?}"
        );
    }
    // A protocol line is not a reply either.
    assert_eq!(decode_reply(&line), Err(ControlError::Malformed));
}

/// Anything but one known document on one line is malformed, and nothing
/// of the line is echoed.
#[test]
fn malformed_lines_are_refused_without_echo() {
    for line in [
        &b""[..],
        b"\n",
        b"status\n",
        b"\"Status\"\n",
        b"\"poll_now\"\n",
        b"\"status\"\"subscribe\"\n",
        b"\"status\"\n\"subscribe\"\n",
        b"\"sta\ntus\"\n",
        b"{\"status\":1}\n",
        b"\xff\xfe\n",
        // The request that names a network: without one, with a key too
        // many beside it or inside it, with a name that is not a SIM's,
        // with codes that are not a network's, and as a bare string.
        b"\"accept_sim_network\"\n",
        b"{\"accept_sim_network\":{}}\n",
        b"{\"accept_sim_network\":{\"network\":null}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":\"234\",\"mnc\":\"30\"}},\"force\":true}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":\"234\",\"mnc\":\"30\"},\"iccid\":\"1\"}}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"plmn\":{\"mcc\":\"234\",\"mnc\":\"30\"}}}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"spn\":\"447700900123\",\"plmn\":{\"mcc\":\"234\",\"mnc\":\"30\"}}}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":\"23\",\"mnc\":\"30\"}}}}\n",
        b"{\"accept_sim_network\":{\"network\":{\"spn\":null,\"plmn\":{\"mcc\":234,\"mnc\":30}}}}\n",
    ] {
        let error = decode_request(line).unwrap_err();
        assert_eq!(error, ControlError::Malformed, "{line:?}");
        assert_eq!(error.kind(), ControlErrorKind::Malformed);
        assert_eq!(
            error.to_string(),
            "a control line is not a well-formed request or reply"
        );
    }
    for line in [
        &b"{\"refused\":{\"reason\":\"busy\",\"zz\":1}}\n"[..],
        b"{\"refused\":{\"reason\":\"tired\"}}\n",
        b"{\"refused\":{}}\n",
        b"{\"status\":{\"no_deployment\":{\"version\":1}}}\n",
        b"\"status\"\n",
        // Valid JSON across two lines is still not one line.
        b"{\"refused\":\n{\"reason\":\"busy\"}}\n",
    ] {
        assert_eq!(decode_reply(line), Err(ControlError::Malformed), "{line:?}");
    }
    assert_eq!(
        decode_reply(b"{\"refused\":{\"reason\":\"busy\"}}\n"),
        Ok(DaemonReply::Refused {
            reason: Refusal::Busy
        })
    );
}

/// A line longer than its bound is refused before it is parsed, on decode
/// and on encode, the newline counted.
#[test]
fn lines_are_bounded() {
    let mut long = vec![b' '; MAX_REQUEST_LINE_BYTES - "\"status\"\n".len()];
    long.extend_from_slice(b"\"status\"\n");
    assert_eq!(long.len(), MAX_REQUEST_LINE_BYTES);
    assert_eq!(decode_request(&long).unwrap(), DaemonRequest::Status);
    long.insert(0, b' ');
    let error = decode_request(&long).unwrap_err();
    assert_eq!(
        error,
        ControlError::LineTooLong {
            bytes: MAX_REQUEST_LINE_BYTES + 1,
            max: MAX_REQUEST_LINE_BYTES
        }
    );
    assert_eq!(error.kind(), ControlErrorKind::LineTooLong);
    assert_eq!(
        error.to_string(),
        "a control line of 257 bytes is longer than 256"
    );
    // `"subscribe"` and its newline are 12 bytes.
    assert_eq!(
        encode_line(&DaemonRequest::Subscribe, 11),
        Err(ControlError::LineTooLong { bytes: 12, max: 11 })
    );
    assert!(encode_line(&DaemonRequest::Subscribe, 12).is_ok());
    let reply = DaemonReply::Status(status());
    let line = encode_line(&reply, MAX_REPLY_LINE_BYTES).unwrap();
    assert_eq!(
        encode_line(&reply, line.len() - 1),
        Err(ControlError::LineTooLong {
            bytes: line.len(),
            max: line.len() - 1
        })
    );
    let mut padded = vec![b' '; MAX_REPLY_LINE_BYTES + 1 - line.len()];
    padded.extend_from_slice(&line);
    assert_eq!(
        decode_reply(&padded),
        Err(ControlError::LineTooLong {
            bytes: MAX_REPLY_LINE_BYTES + 1,
            max: MAX_REPLY_LINE_BYTES
        })
    );
    assert_eq!(
        (MAX_REQUEST_LINE_BYTES, MAX_REPLY_LINE_BYTES),
        (256, 1 << 20)
    );
}

/// A value that cannot be written as JSON is a typed error, not a panic.
#[test]
fn an_unencodable_value_is_an_error() {
    struct Refusing;

    impl Serialize for Refusing {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("refused"))
        }
    }

    let error = encode_line(&Refusing, MAX_REPLY_LINE_BYTES).unwrap_err();
    assert_eq!(error, ControlError::Unencodable);
    assert_eq!(error.kind(), ControlErrorKind::Unencodable);
}
