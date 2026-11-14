// SPDX-License-Identifier: GPL-3.0-or-later

//! The pull's request: what curl is given, and what its answers and
//! failures come to, with the system's curl against a stub on the loopback
//! interface and with stand-ins that record what they were given.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::payments::{MAX_FEED_BYTES, MAX_STRIPE_ID_CHARS};
use mooring_model::{MAX_STRIPE_READ_KEY_BODY, PortalPullToken, StripeReadKey};

use crate::payments::PortalLink;
use crate::payments::curl::{
    CURL, Credential, Curl, FetchFailure, PortalAnswer, PullRequest, grace, split_status,
};

fn token() -> PortalPullToken {
    PortalPullToken::parse(&"5a".repeat(32)).unwrap()
}

/// A stub that answers one request with `answer` after `delay`, and gives
/// back the request it read.
fn stub(answer: Vec<u8>, delay: Duration) -> (SocketAddr, thread::JoinHandle<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_head(&mut stream);
        thread::sleep(delay);
        let _ = stream.write_all(&answer);
        let _ = stream.flush();
        request
    });
    (addr, served)
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

fn http(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut answer = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for header in headers {
        answer.push_str(header);
        answer.push_str("\r\n");
    }
    answer.push_str("Connection: close\r\n\r\n");
    let mut bytes = answer.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn fetch(addr: SocketAddr, within: Duration) -> Result<PortalAnswer, FetchFailure> {
    let token = token();
    Curl::plain_http(PathBuf::from(CURL)).fetch(&PullRequest {
        url: format!("http://{addr}/api/mooring/entitlements?after=7"),
        credential: Credential::Portal(&token),
        within,
    })
}

/// curl is started as `curl -q --config -`; the address, the header and
/// every option are on its standard input, HTTPS only, with no proxy and
/// within the request's limit.
#[test]
fn every_option_and_the_token_are_on_curls_standard_input() {
    assert_eq!(Curl::arguments(), ["-q", "--config", "-"]);
    let token = token();
    let request = PullRequest {
        url: "https://portal.example.org/api/mooring/entitlements?after=7".to_owned(),
        credential: Credential::Portal(&token),
        within: Duration::from_millis(12_345),
    };
    let config = Curl::system().config(&request);
    assert_eq!(
        config.as_str(),
        format!(
            "url = \"https://portal.example.org/api/mooring/entitlements?after=7\"\n\
             header = \"Authorization: Bearer {}\"\n\
             proto = \"=https\"\n\
             proto-redir = \"=https\"\n\
             tlsv1.2\n\
             noproxy = \"*\"\n\
             globoff\n\
             silent\n\
             show-error\n\
             max-time = \"10.345\"\n\
             connect-timeout = \"10.000\"\n\
             max-filesize = \"1048576\"\n\
             write-out = \"%{{stderr}}mooring-pull-status %{{response_code}} %header{{retry-after}}\\n\"\n",
            "5a".repeat(32)
        )
    );
    let short = Curl::system().config(&PullRequest {
        within: Duration::from_millis(1_500),
        ..request
    });
    // curl's own limit ends half the slot before it when the slot is short.
    assert!(short.contains("max-time = \"0.750\"\n"));
    assert!(short.contains("connect-timeout = \"0.750\"\n"));
    assert_eq!(grace(Duration::from_secs(10)), Duration::from_secs(2));
    assert_eq!(grace(Duration::from_secs(1)), Duration::from_millis(500));
    // The configuration's buffer never grows, so the token is never left
    // behind in a buffer it outgrew.
    let long = Curl::system().config(&PullRequest {
        url: format!(
            "https://{}.example:65535/api/mooring/entitlements?after={}",
            "a".repeat(240),
            u64::MAX
        ),
        credential: Credential::Portal(&token),
        within: Duration::from_secs(15),
    });
    assert!(
        long.capacity() == 4096 && long.len() < 2048,
        "{}",
        long.len()
    );
}

/// A request to Stripe carries the read key as its bearer and names the
/// API release it reads; the longest such configuration fits the buffer.
#[test]
fn a_request_to_stripe_carries_the_key_and_the_api_release() {
    let key = StripeReadKey::parse(&format!("rk_live_{}", "Z".repeat(99))).unwrap();
    let request = PullRequest {
        url: "https://api.stripe.com/v1/invoices?subscription=sub_1&status=paid&limit=20"
            .to_owned(),
        credential: Credential::Stripe(&key),
        within: Duration::from_secs(10),
    };
    assert_eq!(request.credential.peer(), "Stripe");
    let config = Curl::system().config(&request);
    assert!(
        config.starts_with(&format!(
            "url = \"https://api.stripe.com/v1/invoices?subscription=sub_1&status=paid&limit=20\"\n\
             header = \"Authorization: Bearer rk_live_{}\"\n\
             proto = \"=https\"\n",
            "Z".repeat(99)
        )),
        "{}",
        config.as_str()
    );
    assert!(
        config.ends_with("header = \"Stripe-Version: 2026-10-28.endive\"\n"),
        "{}",
        config.as_str()
    );
    let token = token();
    let portal = Curl::system().config(&PullRequest {
        url: "https://portal.example.org/api/mooring/entitlements?after=7".to_owned(),
        credential: Credential::Portal(&token),
        within: Duration::from_secs(10),
    });
    assert!(!portal.contains("Stripe-Version"));
    // The longest key and the longest page of Stripe's.
    let longest =
        StripeReadKey::parse(&format!("rk_live_{}", "Z".repeat(MAX_STRIPE_READ_KEY_BODY))).unwrap();
    let long = Curl::system().config(&PullRequest {
        url: format!(
            "https://api.stripe.com/v1/checkout/sessions?status=complete&created%5Bgte%5D={0}&created%5Blte%5D={0}&limit=20&starting_after={1}",
            u64::MAX,
            "a".repeat(MAX_STRIPE_ID_CHARS)
        ),
        credential: Credential::Stripe(&longest),
        within: Duration::from_secs(15),
    });
    assert!(
        long.capacity() == 4096 && long.len() < 2048,
        "{}",
        long.len()
    );
}

/// curl's failures of a request to Stripe name Stripe, and the key, were
/// curl ever to print it, is cut out.
#[test]
fn curl_s_failures_name_stripe_and_never_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = StripeReadKey::parse(&format!("rk_live_{}", "Q".repeat(40))).unwrap();
    let leaky = Curl::plain_http(stand_in(
        dir.path(),
        "leaky-stripe",
        &format!(
            "/bin/cat > /dev/null\necho 'Authorization: Bearer {}' >&2\nexit 7",
            key.expose_str()
        ),
    ));
    let failure = leaky
        .fetch(&PullRequest {
            url: "http://127.0.0.1:9/v1/invoices".to_owned(),
            credential: Credential::Stripe(&key),
            within: Duration::from_secs(5),
        })
        .unwrap_err();
    assert_eq!(
        failure.to_string(),
        "Stripe did not accept the connection: Authorization: Bearer <redacted>"
    );
    for (code, text) in [
        (6, "Stripe's name did not resolve"),
        (35, "the TLS handshake with Stripe failed"),
        (60, "Stripe's certificate was not trusted"),
    ] {
        let failure = FetchFailure::Curl {
            peer: "Stripe",
            code: Some(code),
            message: String::new(),
        };
        assert_eq!(failure.to_string(), text);
    }
}

/// The status line is found among curl's other error text; a status of
/// `000` (no answer) is none, and the rest is kept escaped.
#[test]
fn the_status_line_is_read_out_of_curls_error_text() {
    assert_eq!(
        split_status("mooring-pull-status 200 \n"),
        (Some((200, None)), String::new())
    );
    assert_eq!(
        split_status("mooring-pull-status 429 3600\n"),
        (Some((429, Some("3600".to_owned()))), String::new())
    );
    assert_eq!(
        split_status("curl: (7) Failed to connect\nmooring-pull-status 000 \n"),
        (None, "curl: (7) Failed to connect".to_owned())
    );
    assert_eq!(
        split_status("mooring-pull-status 2000 \n").0,
        None,
        "not a status"
    );
    assert_eq!(split_status("").0, None);
    let (_, rest) = split_status("one\n\ntwo\u{1b}\n");
    assert_eq!(rest, "one / two\\u{1b}");
}

/// The system's curl against a stub: the request is a GET of the path
/// with the bearer header, and the status, `Retry-After` and body come
/// back as sent.
#[test]
fn the_systems_curl_asks_and_reads_the_answer() {
    let body = br#"{"format":"mooring-portal-entitlements"}"#;
    let (addr, served) = stub(http("200 OK", &[], body), Duration::ZERO);
    let answer = fetch(addr, Duration::from_secs(5)).unwrap();
    assert_eq!(
        answer,
        PortalAnswer {
            status: 200,
            retry_after: None,
            body: body.to_vec()
        }
    );
    let request = served.join().unwrap();
    assert!(
        request.starts_with("GET /api/mooring/entitlements?after=7 HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains(&format!(
        "\r\nAuthorization: Bearer {}\r\n",
        "5a".repeat(32)
    )));
    assert!(request.contains(&format!("\r\nHost: {addr}\r\n")));
    let (addr, _served) = stub(
        http(
            "429 Too Many Requests",
            &["Retry-After: 3600"],
            b"too many requests; try again later\n",
        ),
        Duration::ZERO,
    );
    let answer = fetch(addr, Duration::from_secs(5)).unwrap();
    assert_eq!(answer.status, 429);
    assert_eq!(answer.retry_after.as_deref(), Some("3600"));
    let (addr, _served) = stub(
        http(
            "409 Conflict",
            &[],
            b"the cursor is beyond this journal's last entry\n",
        ),
        Duration::ZERO,
    );
    let answer = fetch(addr, Duration::from_secs(5)).unwrap();
    assert_eq!(answer.status, 409);
    assert_eq!(
        answer.body,
        b"the cursor is beyond this journal's last entry\n"
    );
    // A redirect is not followed.
    let (addr, _served) = stub(
        http(
            "302 Found",
            &["Location: http://127.0.0.1:1/elsewhere"],
            b"",
        ),
        Duration::ZERO,
    );
    assert_eq!(fetch(addr, Duration::from_secs(5)).unwrap().status, 302);
}

/// curl's own failures: a refused connection, a body past the bound and an
/// answer slower than the request's limit, each named.
#[test]
fn the_systems_curl_failures_are_named() {
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let refused = fetch(addr, Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(refused, FetchFailure::Curl { code: Some(7), .. }),
        "{refused:?}"
    );
    assert!(
        refused
            .to_string()
            .starts_with("the portal did not accept the connection"),
        "{refused}"
    );
    let big = vec![b'x'; MAX_FEED_BYTES + 1];
    let (addr, _served) = stub(http("200 OK", &[], &big), Duration::ZERO);
    assert!(matches!(
        fetch(addr, Duration::from_secs(5)),
        Err(FetchFailure::TooLarge)
    ));
    let (addr, _served) = stub(http("200 OK", &[], b"{}"), Duration::from_secs(3));
    let started = Instant::now();
    let slow = fetch(addr, Duration::from_millis(500)).unwrap_err();
    assert!(
        matches!(slow, FetchFailure::Curl { code: Some(28), .. }),
        "{slow:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// A stand-in for curl, written to `dir` as `name`: the shell script
/// `body`, made executable.
fn stand_in(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// curl is given nothing but its three arguments, an empty environment and
/// the configuration on its standard input.
#[test]
fn curl_gets_no_environment_and_the_token_only_on_its_standard_input() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().display().to_string();
    let program = stand_in(
        dir.path(),
        "recording",
        &format!(
            "/usr/bin/env > '{record}/env'\nfor argument in \"$@\"; do echo \"$argument\"; done > '{record}/args'\n/bin/cat > '{record}/stdin'\nprintf 'mooring-pull-status 200 \\n' >&2\nprintf '{{}}'"
        ),
    );
    let token = token();
    let curl = Curl::plain_http(program);
    let request = PullRequest {
        url: "http://127.0.0.1:9/api/mooring/entitlements?after=0".to_owned(),
        credential: Credential::Portal(&token),
        within: Duration::from_secs(5),
    };
    let answer = curl.fetch(&request).unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{}");
    let env = fs::read_to_string(dir.path().join("env")).unwrap();
    // `/bin/sh` itself sets PWD, SHLVL and `_`; nothing comes from this
    // process.
    for line in env.lines() {
        let name = line.split('=').next().unwrap();
        assert!(["PWD", "SHLVL", "_", "OLDPWD"].contains(&name), "{line}");
    }
    assert_eq!(
        fs::read_to_string(dir.path().join("args")).unwrap(),
        "-q\n--config\n-\n"
    );
    let stdin = fs::read_to_string(dir.path().join("stdin")).unwrap();
    assert_eq!(stdin, curl.config(&request).as_str());
    assert!(!env.contains(token.expose_str()));
}

/// A curl that runs past its own limit is killed once the grace is over;
/// one that prints the token has it cut out of what is kept; one that ends
/// well without a status line, or ends badly, is named.
#[test]
fn a_stand_in_that_hangs_or_misbehaves_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let token = token();
    let request = |within| PullRequest {
        url: "http://127.0.0.1:9/".to_owned(),
        credential: Credential::Portal(&token),
        within,
    };
    let hanging = Curl::plain_http(stand_in(
        dir.path(),
        "hanging",
        "/bin/cat > /dev/null\nexec /bin/sleep 30",
    ));
    let started = Instant::now();
    assert!(matches!(
        hanging.fetch(&request(Duration::from_millis(100))),
        Err(FetchFailure::TimedOut)
    ));
    assert!(started.elapsed() < Duration::from_secs(10));
    let leaky = Curl::plain_http(stand_in(
        dir.path(),
        "leaky",
        &format!(
            "/bin/cat > /dev/null\necho 'Authorization: Bearer {}' >&2\nexit 2",
            "5a".repeat(32)
        ),
    ));
    let failure = leaky.fetch(&request(Duration::from_secs(5))).unwrap_err();
    let FetchFailure::Curl { code, message, .. } = &failure else {
        panic!("{failure:?}")
    };
    assert_eq!(*code, Some(2));
    assert_eq!(message, "Authorization: Bearer <redacted>");
    assert!(!failure.to_string().contains(token.expose_str()));
    let silent = Curl::plain_http(stand_in(
        dir.path(),
        "silent",
        "/bin/cat > /dev/null\necho said >&2",
    ));
    assert!(matches!(
        silent.fetch(&request(Duration::from_secs(5))),
        Err(FetchFailure::NoStatus { message }) if message == "said"
    ));
    let killed = Curl::plain_http(stand_in(
        dir.path(),
        "killed",
        "/bin/cat > /dev/null\nkill -9 $$",
    ));
    let failure = killed.fetch(&request(Duration::from_secs(5))).unwrap_err();
    assert!(matches!(failure, FetchFailure::Curl { code: None, .. }));
    assert_eq!(failure.to_string(), "curl was ended by a signal");
    let missing = Curl::plain_http(dir.path().join("nothing"));
    assert!(matches!(
        missing.fetch(&request(Duration::from_secs(5))),
        Err(FetchFailure::Spawn(_))
    ));
    let flooding = Curl::plain_http(stand_in(
        dir.path(),
        "flooding",
        "/bin/cat > /dev/null\n/usr/bin/head -c 1048577 /dev/zero\nprintf 'mooring-pull-status 200 \\n' >&2",
    ));
    assert!(matches!(
        flooding.fetch(&request(Duration::from_secs(5))),
        Err(FetchFailure::TooLarge)
    ));
    for (code, text) in [
        (6, "the portal's name did not resolve"),
        (7, "the portal did not accept the connection"),
        (28, "the request timed out"),
        (35, "the TLS handshake with the portal failed"),
        (60, "the portal's certificate was not trusted"),
        (22, "curl exited with 22"),
    ] {
        let failure = FetchFailure::Curl {
            peer: "the portal",
            code: Some(code),
            message: String::new(),
        };
        assert_eq!(failure.to_string(), text);
    }
}
