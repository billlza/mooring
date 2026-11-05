// SPDX-License-Identifier: GPL-3.0-or-later

//! The words of the router's failures, as `router status`, the daemon's
//! log and the console's panel give them (design §14, §15.6): why the M7
//! could not be reached, every HTTP framing fault, the login form's fields,
//! the panel's reasons, and the daemon's refusals.

use std::collections::BTreeSet;
use std::io;

use mooring_daemon_core::control::Refusal;
use mooring_daemon_core::exit::EgressFault;
use mooring_daemon_core::router::RouterUnavailableReason;

use crate::error::LocalError;
use crate::router::error::{HttpFault, LoginField, Phase, UnreachableCause, reason_phrase};

#[test]
fn each_cause_of_an_unreachable_m7_says_which_step_failed() {
    for (cause, text) in [
        (
            UnreachableCause::ExitInterfacesUnresolved {
                fault: EgressFault::Absent,
            },
            "the exit's interfaces do not resolve: no interface matches the egress selector",
        ),
        (
            UnreachableCause::InterfaceAbsent,
            "the interface does not exist",
        ),
        (
            UnreachableCause::NoDefaultRoute,
            "the interface has no IPv4 default route through a gateway",
        ),
        (
            UnreachableCause::AmbiguousDefaultRoute,
            "the interface has IPv4 default routes through more than one gateway",
        ),
        (
            UnreachableCause::GatewayUnresolved,
            "the gateway's link-layer address is not in the neighbour table",
        ),
        (
            UnreachableCause::Socket {
                kind: io::ErrorKind::PermissionDenied,
            },
            "a socket could not be set up (permission denied)",
        ),
        (
            UnreachableCause::Bind {
                kind: io::ErrorKind::AddrNotAvailable,
            },
            "the socket could not be bound to the interface (address not available)",
        ),
        (
            UnreachableCause::Connect {
                kind: io::ErrorKind::ConnectionRefused,
            },
            "connecting failed (connection refused)",
        ),
        (
            UnreachableCause::Send {
                kind: io::ErrorKind::BrokenPipe,
            },
            "sending the request failed (broken pipe)",
        ),
        (
            UnreachableCause::Receive {
                kind: io::ErrorKind::ConnectionReset,
            },
            "receiving the answer failed (connection reset)",
        ),
        (
            UnreachableCause::Timeout {
                phase: Phase::Connect,
            },
            "timed out connecting",
        ),
        (
            UnreachableCause::Timeout { phase: Phase::Send },
            "timed out sending",
        ),
        (
            UnreachableCause::Timeout {
                phase: Phase::Receive,
            },
            "timed out receiving",
        ),
        (
            UnreachableCause::Closed,
            "the connection closed before an answer",
        ),
    ] {
        assert_eq!(cause.to_string(), text);
    }
}

#[test]
fn each_framing_fault_says_what_was_wrong_with_the_answer() {
    let named = [
        (
            HttpFault::TruncatedHead,
            "the connection closed inside the HTTP head",
        ),
        (
            HttpFault::TruncatedBody,
            "the connection closed inside the body",
        ),
        (
            HttpFault::HeadTooLarge,
            "the HTTP head is larger than 16 KiB",
        ),
        (
            HttpFault::TooManyHeaders,
            "the HTTP head has more than 64 header lines",
        ),
        (HttpFault::StatusLine, "the HTTP status line is malformed"),
        (HttpFault::HeaderLine, "an HTTP header line is malformed"),
        (HttpFault::ObsFold, "an HTTP header line is folded"),
        (
            HttpFault::ConflictingLength,
            "the body's length is given twice in conflicting ways",
        ),
        (
            HttpFault::BadContentLength,
            "the Content-Length is not a decimal number",
        ),
        (
            HttpFault::TransferEncoding,
            "the Transfer-Encoding is not exactly chunked",
        ),
        (
            HttpFault::ContentEncoding,
            "the body has a Content-Encoding",
        ),
        (HttpFault::ChunkSize, "a chunk size is malformed"),
        (
            HttpFault::ChunkTerminator,
            "a chunk is not followed by a line end",
        ),
        (
            HttpFault::Cookie,
            "a Set-Cookie is malformed or longer than 4096 bytes",
        ),
        (HttpFault::TooManyCookies, "the M7 set more than 16 cookies"),
        (
            HttpFault::RepeatedLocation,
            "the HTTP head has more than one Location",
        ),
        (HttpFault::TooLarge, "the body is larger than 1 MiB"),
    ];
    for (fault, text) in named {
        assert_eq!(fault.to_string(), text);
    }
    let listed: BTreeSet<String> = named
        .iter()
        .map(|(fault, _)| format!("{fault:?}"))
        .collect();
    let all: BTreeSet<String> = HttpFault::ALL
        .iter()
        .map(|fault| format!("{fault:?}"))
        .collect();
    assert_eq!(listed, all, "every framing fault has its words here");
}

/// Only the login form's own field names are ever printed.
#[test]
fn a_login_field_is_named_only_when_it_is_one_of_the_form_s() {
    for (field, text) in [
        (LoginField::Token, "field token"),
        (LoginField::ErrRedirect, "field err_redirect"),
        (LoginField::OkRedirect, "field ok_redirect"),
        (LoginField::Password, "field session.password"),
        (LoginField::Other, "another field"),
    ] {
        assert_eq!(field.to_string(), text);
    }
}

#[test]
fn each_panel_reason_and_refusal_has_its_words() {
    for (reason, text) in [
        (
            RouterUnavailableReason::NotConfigured,
            "the router adapter is not set up",
        ),
        (
            RouterUnavailableReason::Unreachable,
            "the M7 is unreachable",
        ),
        (
            RouterUnavailableReason::AuthFailed,
            "the M7 did not grant an administrator's session",
        ),
        (
            RouterUnavailableReason::IdentityMismatch,
            "the gateway is not the pinned M7",
        ),
        (
            RouterUnavailableReason::Unsupported,
            "the device is not a supported M7",
        ),
        (
            RouterUnavailableReason::Malformed,
            "the M7's answer is malformed",
        ),
        (
            RouterUnavailableReason::LocalFailure,
            "the Mac could not poll the M7",
        ),
    ] {
        assert_eq!(reason_phrase(reason), text);
    }
    for (reason, text) in [
        (
            Refusal::Busy,
            "it already serves as many clients as it accepts; try again",
        ),
        (Refusal::BadRequest, "the request was malformed"),
        (
            Refusal::NoStatusYet,
            "its first poll of the M7 has not finished yet",
        ),
        (
            Refusal::NotDeployed,
            "there is no deployment yet (`exit init` creates it)",
        ),
    ] {
        assert_eq!(
            LocalError::DaemonRefused { reason }.to_string(),
            format!("the daemon refused the request: {text}")
        );
    }
}
