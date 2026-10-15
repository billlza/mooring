// SPDX-License-Identifier: GPL-3.0-or-later

//! The HTTP client against the loopback stub, through `lo0` with
//! `IP_BOUND_IF`: framing, limits, timeouts, status policy, the M7's
//! session set-up and every other redirect refused, and the login and
//! redirect answers' bodies left unread.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use mooring_model::iface::{InterfaceIndex, MacAddr};
use mooring_model::time::UnixTime;
use mooring_store::RouterPin;

use super::stub::{Received, Reply, Stub, json, response};
use super::support::{
    FakeLink, JSON_TARGET, PINNED, REDIRECT_BODY_CANARY, RefusingPort, SESSION_A, SESSION_B,
    SET_UP_TARGET, TEST_TIMEOUTS, anonymous, lo0, lo0_name, observed_document,
    observed_login_acceptance, observed_login_refusal, observed_redirect, session_set_up,
};
use crate::router::cookies::{CookieJar, parse_set_cookie};
use crate::router::error::{
    AuthCause, HttpFault, Location, LoginAnswer, LoginFailure, LoginField, MalformedCause, Phase,
    RedirectStep, RouterError, UnreachableCause, UnsupportedCause,
};
use crate::router::http::{
    Body, Client, Endpoint, HTTP_PORT, MAX_BODY_BYTES, Request, Timeouts, request_bytes,
};
use crate::router::link::{Attachment, VerifiedIdentity, check_identity};

fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        interface: lo0(),
    }
}

fn get_with(reply: Reply, timeouts: Timeouts) -> Result<Body, RouterError> {
    let stub = Stub::start(vec![reply]);
    let result = Client::new(endpoint(stub.port()), timeouts).model_json();
    stub.finish();
    result
}

fn get(reply: Reply) -> Result<Body, RouterError> {
    get_with(reply, TEST_TIMEOUTS)
}

fn fault(fault: HttpFault) -> Result<Vec<u8>, RouterError> {
    Err(RouterError::http(fault))
}

fn get_bytes(raw: &[u8]) -> Result<Vec<u8>, RouterError> {
    get(Reply::Bytes(raw.to_vec())).map(|body| body.as_bytes().to_vec())
}

/// A verified identity for the stub: the checked way, through a link
/// layer whose gateway has the pinned address.
pub(crate) fn verified(port: u16) -> VerifiedIdentity {
    let attachment = Attachment {
        interface: lo0_name(),
        index: lo0(),
        gateway: Ipv4Addr::LOCALHOST,
    };
    let pin = RouterPin {
        gateway_lladdr: MacAddr::from_bytes(PINNED).unwrap(),
        pinned_at: UnixTime::from_secs(0),
    };
    check_identity(&FakeLink::pinned(), &attachment, &pin, port).unwrap()
}

#[test]
fn a_content_length_body_is_read() {
    assert_eq!(
        get_bytes(&response("200 OK", &[], b"{\"a\":1}")),
        Ok(b"{\"a\":1}".to_vec())
    );
    // An empty body, and identical repeated lengths.
    assert_eq!(get_bytes(&response("200 OK", &[], b"")), Ok(Vec::new()));
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2, 2\r\n\r\n{}"),
        Ok(b"{}".to_vec())
    );
    // Bytes after the body are never read.
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}trailing"),
        Ok(b"{}".to_vec())
    );
}

#[test]
fn chunked_bodies_are_decoded() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n\
        4\r\n{\"a\"\r\n\
        3;name=value\r\n:12\r\n\
        A \t;ext\r\n3456789012\r\n\
        1\r\n}\r\n\
        0\r\nTrailer: dropped\r\n\r\n";
    assert_eq!(get_bytes(raw), Ok(b"{\"a\":123456789012}".to_vec()));
}

#[test]
fn close_delimited_bodies_are_read() {
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"closed\":true}"),
        Ok(b"{\"closed\":true}".to_vec())
    );
}

#[test]
fn http_1_0_and_bare_lf_are_accepted() {
    assert_eq!(
        get_bytes(b"HTTP/1.0 200 OK\nContent-Length: 2\n\n{}"),
        Ok(b"{}".to_vec())
    );
    assert_eq!(get_bytes(b"HTTP/1.1 200\r\n\r\n[]"), Ok(b"[]".to_vec()));
}

#[test]
fn truncated_bodies_are_malformed() {
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345"),
        fault(HttpFault::TruncatedBody)
    );
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12"),
        fault(HttpFault::TruncatedBody)
    );
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n"),
        fault(HttpFault::TruncatedBody)
    );
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: x\r\n"),
        fault(HttpFault::TruncatedBody)
    );
    assert_eq!(
        get_bytes(b"HTTP/1.1 200 OK\r\nContent-"),
        fault(HttpFault::TruncatedHead)
    );
    assert_eq!(get_bytes(b"HTTP/1.1 2"), fault(HttpFault::TruncatedHead));
    // Nothing at all: the connection closed before an answer.
    assert_eq!(
        get_bytes(b""),
        Err(RouterError::unreachable(UnreachableCause::Closed))
    );
}

#[test]
fn oversized_bodies_are_refused_before_reading() {
    // The length alone is refused: the stub sends no body, and the client
    // does not wait for one.
    let started = Instant::now();
    let declared = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY_BYTES + 1
    );
    assert_eq!(get_bytes(declared.as_bytes()), fault(HttpFault::TooLarge));
    assert!(started.elapsed() < Duration::from_secs(1));
    let huge = b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n";
    assert_eq!(get_bytes(huge), fault(HttpFault::TooLarge));
    // Exactly the limit is accepted.
    let mut at_limit =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\n").into_bytes();
    at_limit.extend(vec![b'x'; MAX_BODY_BYTES]);
    assert_eq!(
        get_bytes(&at_limit).map(|body| body.len()),
        Ok(MAX_BODY_BYTES)
    );
    // A chunk that would grow the body past the limit.
    let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    chunked.extend(format!("{:x}\r\n", MAX_BODY_BYTES).as_bytes());
    chunked.extend(vec![b'x'; MAX_BODY_BYTES]);
    chunked.extend(b"\r\n1\r\n");
    assert_eq!(get_bytes(&chunked), fault(HttpFault::TooLarge));
    // A close-delimited body past the limit.
    let mut closing = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    closing.extend(vec![b'x'; MAX_BODY_BYTES + 1]);
    assert_eq!(get_bytes(&closing), fault(HttpFault::TooLarge));
}

#[test]
fn a_silent_server_times_out() {
    let timeouts = Timeouts {
        connect: Duration::from_secs(2),
        io: Duration::from_millis(200),
        total: Duration::from_secs(5),
    };
    let started = Instant::now();
    assert_eq!(
        get_with(Reply::Silent(Duration::from_secs(3)), timeouts).unwrap_err(),
        RouterError::unreachable(UnreachableCause::Timeout {
            phase: Phase::Receive
        })
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[test]
fn a_drip_feed_hits_the_total_deadline() {
    let timeouts = Timeouts {
        connect: Duration::from_secs(2),
        io: Duration::from_millis(200),
        total: Duration::from_secs(1),
    };
    // Every byte arrives within the per-read limit, but the whole answer
    // would take about 4.5 s.
    let raw = response("200 OK", &[], b"{}");
    let pieces = raw.iter().map(|byte| vec![*byte]).collect();
    let started = Instant::now();
    assert_eq!(
        get_with(
            Reply::Drip {
                pieces,
                pause: Duration::from_millis(100),
            },
            timeouts
        )
        .unwrap_err(),
        RouterError::unreachable(UnreachableCause::Timeout {
            phase: Phase::Receive
        })
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1600), "{elapsed:?}");
}

#[test]
fn refused_connections_are_unreachable() {
    let refusing = RefusingPort::new();
    assert_eq!(
        Client::new(endpoint(refusing.port()), TEST_TIMEOUTS)
            .model_json()
            .unwrap_err(),
        RouterError::unreachable(UnreachableCause::Connect {
            kind: io::ErrorKind::ConnectionRefused
        })
    );
}

#[test]
fn framing_faults_are_typed() {
    let mut long_head = b"HTTP/1.1 200 OK\r\nX-Long: ".to_vec();
    long_head.extend(vec![b'a'; 16 * 1024]);
    long_head.extend(b"\r\n\r\n");
    let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
    for index in 0..65 {
        many.extend(format!("X-{index}: v\r\n").as_bytes());
    }
    many.extend(b"\r\n");
    let mut sixty_four = b"HTTP/1.1 200 OK\r\n".to_vec();
    for index in 0..63 {
        sixty_four.extend(format!("X-{index}: v\r\n").as_bytes());
    }
    sixty_four.extend(b"Content-Length: 0\r\n\r\n");
    assert_eq!(get_bytes(&sixty_four), Ok(Vec::new()));
    let mut cookies = b"HTTP/1.1 200 OK\r\n".to_vec();
    for index in 0..17 {
        cookies.extend(format!("Set-Cookie: c{index}=v\r\n").as_bytes());
    }
    cookies.extend(b"Content-Length: 0\r\n\r\n");
    let cases: Vec<(Vec<u8>, HttpFault)> = vec![
        (long_head, HttpFault::HeadTooLarge),
        (many, HttpFault::TooManyHeaders),
        (
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n folded\r\nContent-Length: 0\r\n\r\n".to_vec(),
            HttpFault::ObsFold,
        ),
        (b"HTTP/2 200 OK\r\n\r\n".to_vec(), HttpFault::StatusLine),
        (b"HTTP/1.1 20 OK\r\n\r\n".to_vec(), HttpFault::StatusLine),
        (b"HTTP/1.1 200OK\r\n\r\n".to_vec(), HttpFault::StatusLine),
        (b"http/1.1 200 OK\r\n\r\n".to_vec(), HttpFault::StatusLine),
        (
            b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n".to_vec(),
            HttpFault::HeaderLine,
        ),
        (
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n".to_vec(),
            HttpFault::HeaderLine,
        ),
        (
            b"HTTP/1.1 200 OK\r\n: x\r\n\r\n".to_vec(),
            HttpFault::HeaderLine,
        ),
        (
            b"HTTP/1.1 200 OK\r\nX-A: a\x01b\r\n\r\n".to_vec(),
            HttpFault::HeaderLine,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}"
                .to_vec(),
            HttpFault::ConflictingLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}".to_vec(),
            HttpFault::ConflictingLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\n{}".to_vec(),
            HttpFault::ConflictingLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: two\r\n\r\n{}".to_vec(),
            HttpFault::BadContentLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\n{}".to_vec(),
            HttpFault::BadContentLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n{}".to_vec(),
            HttpFault::BadContentLength,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}".to_vec(),
            HttpFault::TransferEncoding,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{}".to_vec(),
            HttpFault::TransferEncoding,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec(),
            HttpFault::TransferEncoding,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            HttpFault::ContentEncoding,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(),
            HttpFault::ChunkSize,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000000\r\n".to_vec(),
            HttpFault::ChunkSize,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 x\r\n".to_vec(),
            HttpFault::ChunkSize,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345XX0\r\n\r\n".to_vec(),
            HttpFault::ChunkTerminator,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\rX".to_vec(),
            HttpFault::ChunkTerminator,
        ),
        (
            b"HTTP/1.1 200 OK\r\nSet-Cookie: novalue\r\nContent-Length: 0\r\n\r\n".to_vec(),
            HttpFault::Cookie,
        ),
        (cookies, HttpFault::TooManyCookies),
        (
            b"HTTP/1.1 200 OK\r\nLocation: /a\r\nlocation: /a\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            HttpFault::RepeatedLocation,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".to_vec(),
            HttpFault::TruncatedBody,
        ),
        (b"HTTP/1.1 200 OK\r\n".to_vec(), HttpFault::TruncatedHead),
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                2 * MAX_BODY_BYTES
            )
            .into_bytes(),
            HttpFault::TooLarge,
        ),
    ];
    let mut named = std::collections::BTreeSet::new();
    for (raw, expected) in cases {
        assert_eq!(
            get_bytes(&raw),
            fault(expected),
            "{}",
            String::from_utf8_lossy(&raw[..raw.len().min(80)])
        );
        named.insert(format!("{expected:?}"));
    }
    let all: std::collections::BTreeSet<String> = HttpFault::ALL
        .iter()
        .map(|fault| format!("{fault:?}"))
        .collect();
    assert_eq!(
        named, all,
        "every framing fault is produced by a real answer"
    );
}

#[test]
fn status_codes_map_to_kinds() {
    let refused = |status| {
        Err(RouterError::AuthFailed {
            cause: AuthCause::Refused { status },
        })
    };
    assert_eq!(
        get_bytes(&response("401 Unauthorized", &[], b"no")),
        refused(401)
    );
    assert_eq!(
        get_bytes(&response("403 Forbidden", &[], b"no")),
        refused(403)
    );
    assert_eq!(
        get_bytes(&response(
            "404 Not Found",
            &["Content-Type: text/html"],
            b"<html>"
        )),
        Err(RouterError::Unsupported {
            cause: UnsupportedCause::EndpointMissing
        })
    );
    // A `Location` matters only for a redirect (3xx).
    for (status, code) in [
        ("500 Internal Server Error", 500),
        ("400 Bad Request", 400),
        ("299 Unassigned", 299),
        ("204 No Content", 204),
        ("100 Continue", 100),
    ] {
        assert_eq!(
            get_bytes(&response(status, &["Location: /index.html"], b"")),
            Err(RouterError::Malformed {
                cause: MalformedCause::Status { code }
            }),
            "{status}"
        );
    }
    // A redirect other than the M7's session set-up is never followed.
    assert_eq!(
        get_bytes(&response("302 Found", &["Location: /index.html"], b"")),
        Err(RouterError::Malformed {
            cause: MalformedCause::Redirect {
                step: RedirectStep::First,
                status: 302
            }
        })
    );
    for content_type in [
        "text/html",
        "TEXT/HTML; charset=utf-8",
        "text/html;charset=UTF-8",
    ] {
        let header = format!("Content-Type: {content_type}");
        assert_eq!(
            get_bytes(&response("200 OK", &[&header], b"<html>IMEI</html>")),
            Err(RouterError::Malformed {
                cause: MalformedCause::Html
            }),
            "{content_type}"
        );
    }
    assert_eq!(
        get(json(&[], b"{}")).map(|body| body.as_bytes().to_vec()),
        Ok(b"{}".to_vec())
    );
}

/// The login's answer is never followed: the client keeps its cookies,
/// its status and where its `Location` points (the form's two targets on
/// the M7, judged byte for byte), and sends nothing more. The first two are
/// the M7's answers as observed on 2026-10-14 (the refusal without its
/// parameters): an accepted login sets a new `sessionId`, a refused one no
/// cookie.
#[test]
fn the_login_redirect_is_never_followed() {
    /// One login answer: what the stub sends, what the client keeps of it,
    /// and the cookies the client then holds.
    struct Case<'a> {
        reply: &'a dyn Fn(u16) -> Reply,
        answer: LoginAnswer,
        cookies: &'a [&'a str],
    }
    let answer = |status, location| LoginAnswer { status, location };
    let cases: [Case<'_>; 6] = [
        Case {
            reply: &observed_login_acceptance,
            answer: answer(302, Some(Location::LoginAccepted)),
            cookies: &["sessionId"],
        },
        Case {
            reply: &|port| observed_login_refusal(port, ""),
            answer: answer(302, Some(Location::LoginRefused { reported: None })),
            cookies: &[],
        },
        Case {
            reply: &|_| {
                Reply::Bytes(response(
                    "302 Found",
                    &["Location: /index.html", "Set-Cookie: auth=xyz; Path=/"],
                    b"",
                ))
            },
            answer: answer(302, Some(Location::Elsewhere)),
            cookies: &["auth"],
        },
        Case {
            reply: &|port| {
                let location = format!("Location: http://127.0.0.1:{port}/index.html?loginfailed");
                Reply::Bytes(response(
                    "303 See Other",
                    &[&location, "Set-Cookie: auth=xyz; Path=/"],
                    b"",
                ))
            },
            answer: answer(303, Some(Location::LoginRefused { reported: None })),
            cookies: &["auth"],
        },
        Case {
            reply: &|_| {
                Reply::Bytes(response(
                    "302 Found",
                    &["Set-Cookie: auth=xyz; Path=/"],
                    b"",
                ))
            },
            answer: answer(302, None),
            cookies: &["auth"],
        },
        Case {
            reply: &|_| Reply::Bytes(response("200 OK", &["Set-Cookie: auth=xyz; Path=/"], b"")),
            answer: answer(200, None),
            cookies: &["auth"],
        },
    ];
    for Case {
        reply,
        answer: expected,
        cookies,
    } in cases
    {
        let stub = Stub::start_for(|port| vec![reply(port)]);
        let verified = verified(stub.port());
        let mut client = Client::new(endpoint(stub.port()), TEST_TIMEOUTS);
        let body = super::form::login_body(&verified);
        assert_eq!(client.login(&verified, &body), Ok(expected));
        assert_eq!(client.cookie_names(), cookies);
        let received = stub.finish();
        assert_eq!(received.len(), 1, "only the login was sent");
        assert_eq!(received[0].request_line(), "POST /Forms/config HTTP/1.1");
    }
}

#[test]
fn the_login_body_is_never_read() {
    // A login answer with a large body holding a canary: the client reads
    // only the head and closes, so neither the canary nor the size matters.
    let mut body = b"BODY-CANARY-".to_vec();
    body.extend(vec![b'x'; 4 * MAX_BODY_BYTES]);
    let stub = Stub::start(vec![Reply::Bytes(response(
        "200 OK",
        &["Content-Type: text/html", "Content-Encoding: gzip"],
        &body,
    ))]);
    let verified = verified(stub.port());
    let mut client = Client::new(endpoint(stub.port()), TEST_TIMEOUTS);
    let login = super::form::login_body(&verified);
    let started = Instant::now();
    assert_eq!(
        client.login(&verified, &login),
        Ok(LoginAnswer {
            status: 200,
            location: None
        })
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!format!("{client:?}").contains("CANARY"));
    stub.finish();
}

/// The session set-up as the M7 answered it on 2026-10-14, byte for byte
/// (design §15.6 rule 9): exactly three requests, the set-up carrying the
/// first redirect's cookie and the retried request the set-up's, which
/// replaced it; the `text/plain` document is returned, and the client's
/// `Debug` shows the cookie's name, never its value.
#[test]
fn the_observed_session_set_up_is_followed_once() {
    let document = anonymous("Guest", 0, "MR7450");
    let stub = Stub::start_for(|port| {
        let mut script = Vec::from(session_set_up(port, SESSION_A, SESSION_B));
        script.push(observed_document(&document));
        script
    });
    let port = stub.port();
    let mut client = Client::new(endpoint(port), TEST_TIMEOUTS);
    let body = client.model_json().map(|body| body.as_bytes().to_vec());
    let received = stub.finish();
    assert_eq!(body, Ok(document));
    let version = env!("CARGO_PKG_VERSION");
    let get = |target: &str, cookie: &str| {
        format!(
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: mooringctl/{version}\r\nAccept: application/json\r\n{cookie}Connection: close\r\n\r\n"
        )
    };
    let texts: Vec<String> = received.iter().map(Received::text).collect();
    assert_eq!(
        texts,
        [
            get(JSON_TARGET, ""),
            get(SET_UP_TARGET, &format!("Cookie: sessionId={SESSION_A}\r\n")),
            get(JSON_TARGET, &format!("Cookie: sessionId={SESSION_B}\r\n")),
        ]
    );
    assert_eq!(client.cookie_names(), ["sessionId"]);
    let shown = format!("{client:?}");
    assert!(!shown.contains("COOKIE-"), "{shown}");
}

/// Neither redirect's body is read: bodies far past the limit, and
/// encoded, change nothing, and take no time.
#[test]
fn the_redirects_bodies_are_never_read() {
    let stub = Stub::start_for(|port| {
        let redirect = |cookie: &str, target: &str| {
            let mut body = REDIRECT_BODY_CANARY.as_bytes().to_vec();
            body.extend(vec![b'x'; 4 * MAX_BODY_BYTES]);
            let set_cookie = format!("Set-Cookie: sessionId={cookie}; path=/; HttpOnly");
            let location = format!("Location: http://127.0.0.1:{port}{target}");
            Reply::Bytes(response(
                "302 Found",
                &[
                    &set_cookie,
                    &location,
                    "Content-Type: text/html",
                    "Content-Encoding: gzip",
                ],
                &body,
            ))
        };
        vec![
            redirect(SESSION_A, SET_UP_TARGET),
            redirect(SESSION_B, JSON_TARGET),
            json(&[], b"{}"),
        ]
    });
    let mut client = Client::new(endpoint(stub.port()), TEST_TIMEOUTS);
    let started = Instant::now();
    let body = client.model_json().map(|body| body.as_bytes().to_vec());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(body, Ok(b"{}".to_vec()));
    assert_eq!(stub.finish().len(), 3);
}

/// One read of the JSON endpoint through the stub that `script` scripts:
/// the body or the error, and the number of requests made.
fn read_through(script: impl FnOnce(u16) -> Vec<Reply>) -> (Result<Vec<u8>, RouterError>, usize) {
    let stub = Stub::start_for(script);
    let result = Client::new(endpoint(stub.port()), TEST_TIMEOUTS)
        .model_json()
        .map(|body| body.as_bytes().to_vec());
    (result, stub.finish().len())
}

/// A refused redirect keeps only the request it answered and its status:
/// neither its `Location`, nor a cookie, nor its body is in the error or
/// its `Debug`.
#[test]
fn refused_redirects_keep_only_the_request_and_the_status() {
    let refused = |step, status| {
        Err(RouterError::Malformed {
            cause: MalformedCause::Redirect { step, status },
        })
    };
    let first = read_through(|port| vec![observed_redirect(port, SESSION_A, "/index.html", 254)]);
    let set_up = read_through(|port| {
        vec![
            observed_redirect(port, SESSION_A, SET_UP_TARGET, 254),
            observed_document(b"{}"),
        ]
    });
    let retried = read_through(|port| {
        let mut script = Vec::from(session_set_up(port, SESSION_A, SESSION_B));
        script.push(observed_redirect(port, "COOKIE-C-5b0e", SET_UP_TARGET, 254));
        script
    });
    let results = [first, set_up, retried];
    assert_eq!(
        results,
        [
            (refused(RedirectStep::First, 302), 1),
            (refused(RedirectStep::SessionSetup, 200), 2),
            (refused(RedirectStep::Retried, 302), 3),
        ]
    );
    for (result, _) in results {
        let error = result.unwrap_err();
        let shown = format!("{error} {error:?}");
        for answer_bytes in ["COOKIE-", "sess_cd_tmp", "127.0.0.1", REDIRECT_BODY_CANARY] {
            assert!(!shown.contains(answer_bytes), "{shown}");
        }
    }
}

/// The M7 on port 80, as on 2026-10-14.
fn m7() -> Endpoint {
    Endpoint {
        addr: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), HTTP_PORT),
        interface: lo0(),
    }
}

/// The M7 on port 80, as on 2026-10-14: its `Location`s name it as
/// `http://192.168.1.1`, without a port, as the client's `Host` header
/// does, and only the exact URLs of the session set-up, of the JSON
/// endpoint and of the start page are recognised, and the login-failed
/// page exactly, alone or followed by `&` and parameters.
#[test]
fn locations_are_judged_against_the_m7s_own_urls() {
    let m7 = m7();
    assert_eq!(
        Location::of(
            b"http://192.168.1.1/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
            &m7
        ),
        Location::SessionSetup
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/api/model.json?internalapi=1", &m7),
        Location::ModelJson
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/index.html", &m7),
        Location::LoginAccepted
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/index.html?loginfailed", &m7),
        Location::LoginRefused { reported: None }
    );
    // As the M7 answered a refused login on 2026-10-14.
    assert_eq!(
        Location::of(
            b"http://192.168.1.1/index.html?loginfailed&errno=2&errdetail=session.password",
            &m7
        ),
        Location::LoginRefused {
            reported: Some(LoginFailure::NumberOnField(2, LoginField::Password))
        }
    );
    // A parameter other than `errno` and `errdetail` is ignored.
    assert_eq!(
        Location::of(b"http://192.168.1.1/index.html?loginfailed&x=1", &m7),
        Location::LoginRefused { reported: None }
    );
    for elsewhere in [
        &b"http://192.168.1.1:80/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1"[..],
        b"http://192.168.1.10/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        b"HTTP://192.168.1.1/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        b"http://192.168.1.1/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1/",
        b"http://192.168.1.1/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson",
        b"//192.168.1.1/api/model.json?internalapi=1",
        b"/api/model.json?internalapi=1",
        b"http://192.168.1.1/api/model.json",
        b"http://192.168.1.1/",
        b"",
        // The login form's targets: only the exact absolute URLs.
        b"/index.html",
        b"/index.html?loginfailed",
        b"//192.168.1.1/index.html?loginfailed",
        b"http://192.168.1.1:80/index.html?loginfailed",
        b"http://192.168.1.10/index.html?loginfailed",
        b"https://192.168.1.1/index.html?loginfailed",
        b"http://192.168.1.1/index.html?loginFailed",
        b"http://192.168.1.1/index.html?loginfailedX",
        b"http://192.168.1.1/index.html?loginfailed2",
        b"http://192.168.1.1/index.html?loginfailed=1&errno=2",
        b"http://192.168.1.1/index.html?loginfailed?errno=2",
        b"http://192.168.1.1/index.html?loginfailed;errno=2",
        b"http://192.168.1.1/index.html?loginfailed%26errno=2",
        b"http://192.168.1.1/index.htmlx?loginfailed&errno=2",
        b"http://192.168.1.1/index.html?errno=2&errdetail=session.password",
        b"http://192.168.1.1/index.html&errno=2",
        b"/index.html?loginfailed&errno=2",
        b"//192.168.1.1/index.html?loginfailed&errno=2",
        b"http://192.168.1.10/index.html?loginfailed&errno=2",
        b"http://192.168.1.1:80/index.html?loginfailed&errno=2",
        b"http://192.168.1.1/index.html%3Floginfailed",
        b"http://192.168.1.1/index.html?",
        b"http://192.168.1.1/index.html/",
        b"http://192.168.1.1/Index.html",
        b"http://192.168.1.1/index.htm",
    ] {
        assert_eq!(
            Location::of(elsewhere, &m7),
            Location::Elsewhere,
            "{}",
            String::from_utf8_lossy(elsewhere)
        );
    }
    // On another port, the port is part of the host, as in `Host`.
    let other = Endpoint {
        addr: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080),
        interface: lo0(),
    };
    assert_eq!(
        Location::of(
            b"http://192.168.1.1:8080/api/model.json?internalapi=1",
            &other
        ),
        Location::ModelJson
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/api/model.json?internalapi=1", &other),
        Location::Elsewhere
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1:8080/index.html?loginfailed", &other),
        Location::LoginRefused { reported: None }
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/index.html?loginfailed", &other),
        Location::Elsewhere
    );
    assert_eq!(
        Location::of(
            b"http://192.168.1.1:8080/index.html?loginfailed&errno=2",
            &other
        ),
        Location::LoginRefused {
            reported: Some(LoginFailure::Number(2))
        }
    );
    assert_eq!(
        Location::of(b"http://192.168.1.1/index.html?loginfailed&errno=2", &other),
        Location::Elsewhere
    );
    // The set-up request names the M7 the same way, with its cookie.
    let mut jar = CookieJar::default();
    let cookie = format!("sessionId={SESSION_A}; path=/; HttpOnly");
    jar.store(parse_set_cookie(cookie.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(
        request_bytes(Request::SessionSetup, &m7, &jar).as_str(),
        format!(
            "GET /sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1 HTTP/1.1\r\nHost: 192.168.1.1\r\nUser-Agent: mooringctl/{}\r\nAccept: application/json\r\nCookie: sessionId={SESSION_A}\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}

/// What the login-failed page reports is read from the parameters after
/// `?loginfailed&`, split at `&` and, in each, at its first `=`, and never
/// decoded: `errno` only as 1 to 4 ASCII digits (a number), and `errdetail`,
/// when not empty, only as one of the four fields the login form sends on
/// an exact byte match, any other value being "another field"; each only
/// when its name is given exactly once. Every other parameter is ignored,
/// and a number out of shape, or a parameter given twice, is not given;
/// none of their bytes is kept, so none can be shown.
#[test]
fn only_the_forms_fields_and_numbers_in_shape_are_kept_from_the_login_failed_page() {
    let m7 = m7();
    let longest = format!("LONGEST.{}", "f".repeat(40));
    let too_long = format!("TOOLONG_{}", "f".repeat(41));
    assert_eq!((longest.len(), too_long.len()), (48, 49));
    let number = |errno| Some(LoginFailure::Number(errno));
    let named = |field| Some(LoginFailure::Field(field));
    let both = |errno, field| Some(LoginFailure::NumberOnField(errno, field));
    let other = Some(LoginFailure::Field(LoginField::Other));
    let cases: Vec<(String, Option<LoginFailure>)> = vec![
        (String::new(), None),
        ("&".to_owned(), None),
        ("&&".to_owned(), None),
        ("&x=1".to_owned(), None),
        (
            "&errno=2&errdetail=session.password".to_owned(),
            both(2, LoginField::Password),
        ),
        (
            "&errdetail=session.password&errno=2".to_owned(),
            both(2, LoginField::Password),
        ),
        ("&errno=7".to_owned(), number(7)),
        // The form's four fields, by their exact names.
        ("&errdetail=token".to_owned(), named(LoginField::Token)),
        (
            "&errdetail=err_redirect".to_owned(),
            named(LoginField::ErrRedirect),
        ),
        (
            "&errdetail=ok_redirect".to_owned(),
            named(LoginField::OkRedirect),
        ),
        (
            "&errdetail=session.password".to_owned(),
            named(LoginField::Password),
        ),
        // The number's bounds: one to four digits, read as a number.
        ("&errno=0".to_owned(), number(0)),
        ("&errno=0042".to_owned(), number(42)),
        ("&errno=9999".to_owned(), number(9999)),
        ("&errno=12345".to_owned(), None),
        ("&errno=".to_owned(), None),
        ("&errno".to_owned(), None),
        ("&errno=x".to_owned(), None),
        ("&errno=2x".to_owned(), None),
        ("&errno=+2".to_owned(), None),
        ("&errno=-2".to_owned(), None),
        ("&errno= 2".to_owned(), None),
        ("&errno==2".to_owned(), None),
        ("&errno=%32".to_owned(), None),
        ("&errno=2&errno=2".to_owned(), None),
        ("&errno=2&errno=3".to_owned(), None),
        ("&errno&errno=2".to_owned(), None),
        ("&errno==2&errno=7".to_owned(), None),
        // Any other value is another field, whatever its shape, and an
        // empty one is not given.
        ("&errdetail=a".to_owned(), other),
        ("&errdetail=_.Az09".to_owned(), other),
        (format!("&errdetail={longest}"), other),
        (format!("&errdetail={too_long}"), other),
        ("&errdetail=SECRET.password_2026".to_owned(), other),
        ("&errdetail=".to_owned(), None),
        ("&errdetail".to_owned(), None),
        ("&errdetail=a%3Cb%3E".to_owned(), other),
        ("&errdetail=session%2Epassword".to_owned(), other),
        ("&errdetail=session+password".to_owned(), other),
        ("&errdetail=session-password".to_owned(), other),
        ("&errdetail=session/password".to_owned(), other),
        ("&errdetail=session=password".to_owned(), other),
        ("&errdetail=Session.Password".to_owned(), other),
        ("&errdetail=session.password.".to_owned(), other),
        ("&errdetail=caf\u{e9}".to_owned(), other),
        ("&errdetail=token&errdetail=token".to_owned(), None),
        // A number out of shape leaves the field.
        (
            "&errno=12345&errdetail=token".to_owned(),
            named(LoginField::Token),
        ),
        (
            "&errno=2&errdetail=a%3Cb%3E".to_owned(),
            both(2, LoginField::Other),
        ),
        (
            "&errno=2&errdetail=session.password#top".to_owned(),
            both(2, LoginField::Other),
        ),
        // Names are exact; other parameters are ignored.
        ("&ERRNO=2&Errdetail=token".to_owned(), None),
        (
            "&errno2=5&xerrno=6&errnoerrno=7&errdetailx=a&xerrdetail=b&errno=2".to_owned(),
            number(2),
        ),
        (
            "&&errno=2&&errdetail=token&".to_owned(),
            both(2, LoginField::Token),
        ),
        (
            "&lang=en&errno=2&token=SECRET-TOKEN&errdetail=session.password&session.password=SECRET-PASSWORD"
                .to_owned(),
            both(2, LoginField::Password),
        ),
    ];
    for (query, reported) in cases {
        let url = format!("http://192.168.1.1/index.html?loginfailed{query}");
        let location = Location::of(url.as_bytes(), &m7);
        assert_eq!(location, Location::LoginRefused { reported }, "{url}");
        let shown = format!("{location:?}");
        for never in [
            "SECRET", "TOOLONG", "LONGEST", "Az09", "%3C", "%2E", "12345", "=", "&", "caf",
        ] {
            assert!(!shown.contains(never), "{url}: {shown}");
        }
    }
    // What is kept is shown in its type, never as the page's bytes.
    let observed = Location::of(
        b"http://192.168.1.1/index.html?loginfailed&errno=2&errdetail=session.password",
        &m7,
    );
    assert_eq!(
        format!("{observed:?}"),
        "LoginRefused { reported: Some(NumberOnField(2, Password)) }"
    );
}

#[test]
fn bodies_and_clients_never_show_their_bytes_in_debug() {
    let body = get(json(
        &["Set-Cookie: sid=SECRET-COOKIE"],
        b"{\"x\":\"DOC-CANARY\"}",
    ))
    .unwrap();
    assert_eq!(format!("{body:?}"), "Body(<18 bytes>)");
    let stub = Stub::start(vec![json(&["Set-Cookie: sid=SECRET-COOKIE"], b"{}")]);
    let mut client = Client::new(endpoint(stub.port()), TEST_TIMEOUTS);
    client.model_json().unwrap();
    stub.finish();
    let shown = format!("{client:?}");
    assert!(shown.contains("sid"), "{shown}");
    assert!(!shown.contains("SECRET-COOKIE"), "{shown}");
}

/// Every socket is bound to its endpoint's interface (`IP_BOUND_IF`): an
/// index no interface has cannot be bound, and nothing is sent.
#[test]
fn an_index_no_interface_has_cannot_be_bound() {
    let stub = Stub::start(vec![json(&[], b"{}")]);
    let absent = InterfaceIndex::from(NonZeroU32::new(99_999).unwrap());
    let endpoint = Endpoint {
        addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, stub.port()),
        interface: absent,
    };
    let result = Client::new(endpoint, TEST_TIMEOUTS).model_json();
    assert!(
        matches!(
            result,
            Err(RouterError::Unreachable {
                cause: UnreachableCause::Bind { .. }
            })
        ),
        "{result:?}"
    );
    assert!(stub.finish().is_empty(), "no connection was made");
}

/// A socket bound to another interface than the loopback cannot reach
/// `127.0.0.1`: the bind decides the path, so the request never leaves
/// through whichever interface the routing table prefers (critique C-8).
/// `en0` is the Mac's first built-in interface, present on every Mac.
#[test]
fn a_socket_bound_to_another_interface_does_not_reach_loopback() {
    let stub = Stub::start(vec![json(&[], b"{}")]);
    let en0 = InterfaceIndex::from(mooring_macsys::interface_index("en0").unwrap());
    let endpoint = Endpoint {
        addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, stub.port()),
        interface: en0,
    };
    assert_eq!(
        Client::new(endpoint, TEST_TIMEOUTS)
            .model_json()
            .map(|_| ()),
        Err(RouterError::unreachable(UnreachableCause::Connect {
            kind: io::ErrorKind::AddrNotAvailable
        }))
    );
    assert!(stub.finish().is_empty(), "no connection reached the stub");
}
