// SPDX-License-Identifier: GPL-3.0-or-later

//! `router status` end to end against the loopback stub: the request
//! order, the M7's session set-up, the identity check before any secret is
//! sent, the login's outcomes, and the password, token and cookies only
//! where they belong.

use mooring_daemon_core::router::netgear::parse_netgear_model_json;
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_macsys::MacsysError;
use mooring_model::time::UnixTime;

use super::form::{ENCODED_PASSWORD, ENCODED_TOKEN};
use super::stub::{Received, Reply, Stub, json, response};
use super::support::{
    FIXTURE, FakeLink, HIDDEN_TABLE, Harness, JSON_TARGET, NOW, OBSERVED_REFUSAL_QUERY, OTHER,
    Outcome, PASSWORD, PINNED, PLACEHOLDER, PLACEHOLDER_FOUND, REDIRECT_BODY_CANARY, SESSION_A,
    SESSION_B, SESSION_L, SET_UP_TARGET, TOKEN, anonymous, lo0_name, observed_document,
    observed_login_acceptance, observed_login_refusal, session_set_up,
};
use crate::router::output::summary;

const STATUS: &[&str] = &["router", "status", "--interface", "lo0"];

/// The login's answer when the M7 accepts it, as observed on 2026-10-14: a
/// redirect to the start page on the stub at `port` with a new `sessionId`.
fn login_answer(port: u16) -> Reply {
    observed_login_acceptance(port)
}

/// A refusal without parameters: the observed refusal with its
/// login-failed page alone, and no cookie (the M7 was seen adding `errno`
/// and `errdetail`: [`observed_login_refusal`]).
pub(crate) fn refused_login_answer(port: u16) -> Reply {
    observed_login_refusal(port, "")
}

/// An anonymous answer that sets the session cookie itself, without the
/// set-up (made up: the M7 sets it in its set-up), so that the login's new
/// `sessionId` replaces it.
pub(crate) fn anonymous_answer() -> Reply {
    json(
        &["Set-Cookie: sessionId=COOKIE-ONE; Path=/; HttpOnly"],
        &anonymous("Guest", 0, "MR7450"),
    )
}

/// The script, for the stub's port, of the anonymous answer (with a
/// session cookie), the login's answer as the M7 accepts it (a redirect to
/// the start page with a new `sessionId`), and `second`.
pub(crate) fn login_script(second: Reply) -> impl FnOnce(u16) -> Vec<Reply> {
    move |port| vec![anonymous_answer(), login_answer(port), second]
}

/// What a command prints when the M7 sends the login to its login-failed
/// page, reporting nothing.
pub(crate) const PASSWORD_REFUSED: &str = "mooringctl: the M7 did not grant an administrator's session: it refused the stored admin password (the login was sent to its login-failed page); store the password again with `mooringctl router set-password`\n";

/// What a command prints when the M7 refuses the login as it did on
/// 2026-10-14: error 2 on the password's field.
pub(crate) const PASSWORD_FIELD_REFUSED: &str = "mooringctl: the M7 did not grant an administrator's session: it refused the login (error 2 on field session.password, read as the stored admin password being wrong); store the password again with `mooringctl router set-password`\n";

/// The admin's document, as the stub serves it.
pub(crate) fn admin_document() -> Reply {
    json(&[], FIXTURE)
}

/// The password, the token and the cookies appear nowhere but where they
/// belong: the password and the token only percent-encoded in a login
/// body, each cookie (every test cookie's value starts `COOKIE-`) only in a
/// later request's `Cookie` header, and none of them in what the command
/// printed.
pub(crate) fn assert_secrets_kept(outcome: &Outcome, received: &[Received]) {
    let printed = format!("{}{}", outcome.stdout, outcome.stderr);
    for secret in [PASSWORD, ENCODED_PASSWORD, TOKEN, ENCODED_TOKEN, "COOKIE-"] {
        assert!(!printed.contains(secret), "{secret} was printed");
    }
    for request in received {
        let text = request.text();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        assert!(!text.contains(PASSWORD), "the raw password was sent");
        assert!(!text.contains(TOKEN), "the raw token was sent");
        assert!(
            !head.contains(ENCODED_PASSWORD),
            "the password is in a head"
        );
        assert!(!head.contains(ENCODED_TOKEN), "the token is in a head");
        if request.request_line().starts_with("POST ") {
            assert_eq!(body.matches(ENCODED_PASSWORD).count(), 1);
            assert_eq!(body.matches(ENCODED_TOKEN).count(), 1);
        } else {
            assert!(body.is_empty(), "a GET has no body");
        }
        for line in head.lines().filter(|line| !line.starts_with("Cookie: ")) {
            assert!(!line.contains("COOKIE-"), "a cookie outside Cookie: {line}");
        }
    }
}

fn run_status(
    script: impl FnOnce(u16) -> Vec<Reply>,
    link: Option<FakeLink>,
) -> (Outcome, Vec<Received>, Harness) {
    let stub = Stub::start_for(script);
    let mut harness = Harness::configured(stub.port());
    if let Some(link) = link {
        harness.link = link;
    }
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    (outcome, received, harness)
}

pub(crate) fn request_lines(received: &[Received]) -> Vec<String> {
    received.iter().map(Received::request_line).collect()
}

/// Each request's `Cookie` header lines.
pub(crate) fn cookie_lines(received: &[Received]) -> Vec<Vec<String>> {
    received
        .iter()
        .map(|request| {
            let text = request.text();
            let head = text
                .split_once("\r\n\r\n")
                .map_or(text.as_str(), |(head, _)| head);
            head.lines()
                .filter(|line| line.starts_with("Cookie: "))
                .map(str::to_owned)
                .collect()
        })
        .collect()
}

/// The request lines: the JSON endpoint's, the session set-up's and the
/// login's.
pub(crate) const GET: &str = "GET /api/model.json?internalapi=1 HTTP/1.1";
pub(crate) const SET_UP: &str =
    "GET /sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1 HTTP/1.1";
pub(crate) const POST: &str = "POST /Forms/config HTTP/1.1";

#[test]
fn login_success_reads_the_status() {
    let (outcome, received, harness) = run_status(login_script(admin_document()), None);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let status = parse_netgear_model_json(FIXTURE).unwrap();
    let expected = summary(&lo0_name(), UnixTime::from_secs(NOW), &status).unwrap();
    assert_eq!(outcome.stdout, expected);
    assert_eq!(request_lines(&received), [GET, POST, GET]);
    assert_eq!(harness.link.neighbour_calls.get(), 1);
}

#[test]
fn requests_are_exactly_the_documented_bytes() {
    let stub = Stub::start_for(login_script(admin_document()));
    let port = stub.port();
    let mut harness = Harness::configured(port);
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let version = env!("CARGO_PKG_VERSION");
    let host = format!("127.0.0.1:{port}");
    let body = format!(
        "token={ENCODED_TOKEN}&err_redirect=%2Findex.html%3Floginfailed&ok_redirect=%2Findex.html&session.password={ENCODED_PASSWORD}"
    );
    let expected = [
        format!(
            "GET /api/model.json?internalapi=1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mooringctl/{version}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        ),
        format!(
            "POST /Forms/config HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mooringctl/{version}\r\nAccept: */*\r\nOrigin: http://{host}\r\nReferer: http://{host}/index.html\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: sessionId=COOKIE-ONE\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "GET /api/model.json?internalapi=1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mooringctl/{version}\r\nAccept: application/json\r\nCookie: sessionId={SESSION_L}\r\nConnection: close\r\n\r\n"
        ),
    ];
    let texts: Vec<String> = received.iter().map(Received::text).collect();
    assert_eq!(texts, expected);
}

/// Runs `router status` against a stub that answers the login with
/// `refusal` and would answer another `GET` with the administrator's
/// document: plain, with `--json`, and after the M7's session set-up. Each
/// run stops at once: exit 5, `stderr`, the unavailable reading saying
/// `auth_failed` with `--json`, the login the last request, the password
/// sent once, at the end of the login's body, and the identity checked once.
fn assert_stops_at_the_login(refusal: impl Fn(u16) -> Reply, stderr: &str) {
    let json_args: &[&str] = &["router", "status", "--interface", "lo0", "--json"];
    let unavailable = "{\"unavailable\":{\"reason\":\"auth_failed\",\"last_polled_at\":null}}\n";
    for (args, stdout, through_set_up) in [
        (STATUS, "", false),
        (json_args, unavailable, false),
        (STATUS, "", true),
    ] {
        let stub = Stub::start_for(|port| {
            if through_set_up {
                after_session_set_up(
                    port,
                    [
                        observed_document(&anonymous("Guest", 0, "MR7450")),
                        refusal(port),
                        admin_document(),
                    ],
                )
            } else {
                vec![anonymous_answer(), refusal(port), admin_document()]
            }
        });
        let requests: &[&str] = if through_set_up {
            &[GET, SET_UP, GET, POST]
        } else {
            &[GET, POST]
        };
        let mut harness = Harness::configured(stub.port());
        let outcome = harness.run(args);
        let received = stub.finish();
        assert_secrets_kept(&outcome, &received);
        assert_eq!(outcome.code, 5, "{args:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, stdout, "{args:?}");
        assert_eq!(outcome.stderr, stderr, "{args:?}");
        assert_eq!(request_lines(&received), requests, "{args:?}");
        let texts: Vec<String> = received.iter().map(Received::text).collect();
        assert_eq!(texts.concat().matches(ENCODED_PASSWORD).count(), 1);
        assert!(
            texts
                .last()
                .unwrap()
                .ends_with(&format!("&session.password={ENCODED_PASSWORD}"))
        );
        assert_eq!(harness.link.neighbour_calls.get(), 1);
    }
}

/// A login the M7 sends to its login-failed page without parameters (a
/// `302` there, the observed refusal without its `errno` and `errdetail`)
/// stops `router status` at once with the generic refusal.
#[test]
fn a_login_sent_to_the_login_failed_page_stops_at_once() {
    assert_stops_at_the_login(refused_login_answer, PASSWORD_REFUSED);
}

/// The M7's refusal of 2026-10-14 as observed (a `302` to the login-failed
/// page followed by `&errno=2&errdetail=session.password`, `text/html`, no
/// cookie): `router status` stops at once, and the error names what the
/// page reported, read as the stored password being wrong.
#[test]
fn the_observed_refusal_names_the_password_field() {
    assert_stops_at_the_login(
        |port| observed_login_refusal(port, OBSERVED_REFUSAL_QUERY),
        PASSWORD_FIELD_REFUSED,
    );
}

/// A `302` to the login-failed page followed by `&` and parameters stops
/// `router status` at the login whatever they hold. The error names the
/// page's `errno` (1 to 4 ASCII digits, read as a number) only when it is
/// given once in that shape, and its `errdetail` only as one of the four
/// field names the login form sends (`LOGIN_FIELDS`), given once: any other
/// value is "another field", whatever its shape, so nothing a device echoes
/// back (the password, the token, a cookie) can be printed. It reads the
/// refusal as the stored password being wrong only for `session.password`,
/// and with nothing given it is the generic refusal.
#[test]
fn the_login_failed_page_names_only_codes_in_their_shape() {
    let refused = |reported: &str| {
        format!(
            "mooringctl: the M7 did not grant an administrator's session: it refused the login ({reported})\n"
        )
    };
    let password = |reported: &str| {
        format!(
            "mooringctl: the M7 did not grant an administrator's session: it refused the login ({reported}, read as the stored admin password being wrong); store the password again with `mooringctl router set-password`\n"
        )
    };
    let too_long = format!("TOOLONG_{}", "f".repeat(41));
    assert_eq!(too_long.len(), 49);
    let cases: Vec<(&str, String, String, Vec<&str>)> = vec![
        (
            "nothing after the page",
            String::new(),
            PASSWORD_REFUSED.to_owned(),
            vec![],
        ),
        (
            "the observed codes",
            OBSERVED_REFUSAL_QUERY.to_owned(),
            PASSWORD_FIELD_REFUSED.to_owned(),
            vec![],
        ),
        (
            "the codes the other way round",
            "&errdetail=session.password&errno=2".to_owned(),
            PASSWORD_FIELD_REFUSED.to_owned(),
            vec![],
        ),
        (
            "the password's field alone",
            "&errdetail=session.password".to_owned(),
            password("an error on field session.password"),
            vec![],
        ),
        (
            "another field",
            "&errno=7&errdetail=token".to_owned(),
            refused("error 7 on field token"),
            vec!["password"],
        ),
        (
            "another field alone",
            "&errdetail=token".to_owned(),
            refused("an error on field token"),
            vec!["password"],
        ),
        (
            "a number alone",
            "&errno=7".to_owned(),
            refused("error 7"),
            vec!["password"],
        ),
        (
            "a number of four digits and a field the form does not send",
            "&errno=0042&errdetail=LONGEST.field_name".to_owned(),
            refused("error 42 on another field"),
            vec!["0042", "LONGEST", "field_name", "password"],
        ),
        (
            "a value shaped like a field's name but no form field (an echoed secret)",
            "&errno=2&errdetail=Mooring.2026_secret".to_owned(),
            refused("error 2 on another field"),
            vec!["Mooring", "2026", "secret", "password"],
        ),
        (
            "the form's other fields by name",
            "&errno=3&errdetail=ok_redirect".to_owned(),
            refused("error 3 on field ok_redirect"),
            vec!["password"],
        ),
        (
            "other parameters among the codes",
            format!(
                "&lang=en&errno=2&errno2=5&xerrdetail=token&token={ENCODED_TOKEN}&errdetail=session.password&session.password={ENCODED_PASSWORD}&sid=COOKIE-ONE"
            ),
            PASSWORD_FIELD_REFUSED.to_owned(),
            vec!["lang", "en&", "errno2", "xerrdetail", "token"],
        ),
        (
            "a field that is not a name",
            "&errno=2&errdetail=a%3Cb%3E".to_owned(),
            refused("error 2 on another field"),
            vec!["a%3Cb%3E", "a<b>", "3C", "password"],
        ),
        (
            "a number of five digits",
            "&errno=12345&errdetail=session.password".to_owned(),
            password("an error on field session.password"),
            vec!["12345", "1234", "2345"],
        ),
        (
            "a number that is not digits",
            "&errno=x&errdetail=token".to_owned(),
            refused("an error on field token"),
            vec!["error x", "password"],
        ),
        (
            "a field of 49 bytes",
            format!("&errno=2&errdetail={too_long}"),
            refused("error 2 on another field"),
            vec!["TOOLONG", "ffff", "password"],
        ),
        (
            "the password echoed as the field",
            format!("&errno=2&errdetail={ENCODED_PASSWORD}"),
            refused("error 2 on another field"),
            vec!["password"],
        ),
        (
            "an empty field",
            "&errno=2&errdetail=".to_owned(),
            refused("error 2"),
            vec!["password"],
        ),
        (
            "a repeated number",
            "&errno=2&errno=3&errdetail=token".to_owned(),
            refused("an error on field token"),
            vec!["error 2", "error 3"],
        ),
        (
            "a repeated field",
            "&errno=2&errdetail=token&errdetail=session.password".to_owned(),
            refused("error 2"),
            vec!["token", "password"],
        ),
        (
            "a field the form does not send and no number in shape",
            "&errno=x&errdetail=a%3Cb%3E&".to_owned(),
            refused("an error on another field"),
            vec!["a%3Cb%3E", "a<b>", "error x", "password"],
        ),
        (
            "nothing given",
            "&errno=x&errdetail&".to_owned(),
            PASSWORD_REFUSED.to_owned(),
            vec!["error x"],
        ),
    ];
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (name, query, stderr, never) in cases {
        let (outcome, received, _) = run_status(
            |port| {
                vec![
                    anonymous_answer(),
                    observed_login_refusal(port, &query),
                    admin_document(),
                ]
            },
            None,
        );
        let printed = format!("{}{}", outcome.stdout, outcome.stderr);
        let shown: Vec<&str> = never
            .iter()
            .chain(&[
                "errno",
                "errdetail",
                "loginfailed",
                "127.0.0.1",
                REDIRECT_BODY_CANARY,
            ])
            .copied()
            .filter(|text| printed.contains(text))
            .collect();
        actual.push((
            name,
            outcome.code,
            outcome.stdout,
            outcome.stderr,
            request_lines(&received),
            shown,
        ));
        expected.push((
            name,
            5,
            String::new(),
            stderr,
            vec![GET.to_owned(), POST.to_owned()],
            Vec::new(),
        ));
    }
    assert_eq!(actual, expected);
}

/// Unless the login's answer is a `302` to the login-failed page, the read
/// after it decides: here its session is not an administrator's (exit 5),
/// and the error reports the login answer's status and where its
/// `Location` points, judged byte for byte against the M7's own URLs and
/// never quoted. Every case makes the three requests.
#[test]
fn the_login_answer_is_reported_when_the_session_decides() {
    let not_admin = |answer: &str| {
        format!(
            "mooringctl: the M7 did not grant an administrator's session: the router's session is not an administrator's (the login was answered with {answer})\n"
        )
    };
    let elsewhere = "status 302 and a Location elsewhere";
    let cases: Vec<(&str, &str, Vec<&str>, &str)> = vec![
        (
            "the start page",
            "302 Found",
            vec!["Location: http://127.0.0.1:{port}/index.html"],
            "status 302 and a Location to the start page",
        ),
        (
            "the login-failed page, with 303",
            "303 See Other",
            vec!["Location: http://127.0.0.1:{port}/index.html?loginfailed"],
            "status 303 and a Location to the login-failed page",
        ),
        (
            "the login-failed page, with 301",
            "301 Moved Permanently",
            vec!["Location: http://127.0.0.1:{port}/index.html?loginfailed"],
            "status 301 and a Location to the login-failed page",
        ),
        (
            "the login-failed page, with 200",
            "200 OK",
            vec!["Location: http://127.0.0.1:{port}/index.html?loginfailed"],
            "status 200 and a Location to the login-failed page",
        ),
        (
            "a relative login-failed page",
            "302 Found",
            vec!["Location: /index.html?loginfailed"],
            elsewhere,
        ),
        (
            "a relative start page",
            "302 Found",
            vec!["Location: /index.html"],
            elsewhere,
        ),
        (
            "the login-failed page on another host",
            "302 Found",
            vec!["Location: http://127.0.0.2:{port}/index.html?loginfailed"],
            elsewhere,
        ),
        (
            "the login-failed page without the stub's port",
            "302 Found",
            vec!["Location: http://127.0.0.1/index.html?loginfailed"],
            elsewhere,
        ),
        (
            "the login-failed page by another scheme",
            "302 Found",
            vec!["Location: https://127.0.0.1:{port}/index.html?loginfailed"],
            elsewhere,
        ),
        (
            "the login-failed page with more query",
            "302 Found",
            vec!["Location: http://127.0.0.1:{port}/index.html?loginfailed=1"],
            elsewhere,
        ),
        (
            "the login-failed page with codes, with 303",
            "303 See Other",
            vec![
                "Location: http://127.0.0.1:{port}/index.html?loginfailed&errno=2&errdetail=session.password",
            ],
            "status 303 and a Location to the login-failed page with error 2 on field session.password",
        ),
        (
            "the login-failed page followed by a letter",
            "302 Found",
            vec![
                "Location: http://127.0.0.1:{port}/index.html?loginfailedX&errno=2&errdetail=session.password",
            ],
            elsewhere,
        ),
        (
            "the login-failed page followed by a digit",
            "302 Found",
            vec![
                "Location: http://127.0.0.1:{port}/index.html?loginfailed2&errno=2&errdetail=session.password",
            ],
            elsewhere,
        ),
        (
            "the login-failed page's query on another path",
            "302 Found",
            vec![
                "Location: http://127.0.0.1:{port}/index.htmlx?loginfailed&errno=2&errdetail=session.password",
            ],
            elsewhere,
        ),
        (
            "a relative login-failed page with codes",
            "302 Found",
            vec!["Location: /index.html?loginfailed&errno=2&errdetail=session.password"],
            elsewhere,
        ),
        (
            "the login-failed page with codes on another host",
            "302 Found",
            vec![
                "Location: http://127.0.0.2:{port}/index.html?loginfailed&errno=2&errdetail=session.password",
            ],
            elsewhere,
        ),
        (
            "the login-failed page with codes after another ?",
            "302 Found",
            vec![
                "Location: http://127.0.0.1:{port}/index.html?loginfailed?errno=2&errdetail=session.password",
            ],
            elsewhere,
        ),
        (
            "the start page with codes",
            "302 Found",
            vec!["Location: http://127.0.0.1:{port}/index.html?errno=2&errdetail=session.password"],
            elsewhere,
        ),
        (
            "the login-failed page in capitals",
            "302 Found",
            vec!["Location: http://127.0.0.1:{port}/index.html?LOGINFAILED"],
            elsewhere,
        ),
        (
            "an empty Location",
            "302 Found",
            vec!["Location:"],
            elsewhere,
        ),
        (
            "the session set-up",
            "302 Found",
            vec![TO_SET_UP],
            "status 302 and a Location to the M7's session set-up",
        ),
        (
            "the JSON endpoint",
            "302 Found",
            vec![TO_JSON],
            "status 302 and a Location to the JSON endpoint",
        ),
        (
            "no Location",
            "302 Found",
            vec![],
            "status 302 and no Location",
        ),
        (
            "a document without a Location",
            "200 OK",
            vec![],
            "status 200 and no Location",
        ),
    ];
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (name, status, headers, answer) in cases {
        let (outcome, received, _) = run_status(
            |port| {
                let headers: Vec<String> = headers
                    .iter()
                    .map(|header| header.replace("{port}", &port.to_string()))
                    .collect();
                let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
                vec![
                    anonymous_answer(),
                    Reply::Bytes(response(status, &headers, b"")),
                    json(&[], &anonymous("Guest", 0, "MR7450")),
                ]
            },
            None,
        );
        actual.push((
            name,
            outcome.code,
            outcome.stdout,
            outcome.stderr,
            request_lines(&received),
        ));
        expected.push((
            name,
            5,
            String::new(),
            not_admin(answer),
            vec![GET.to_owned(), POST.to_owned(), GET.to_owned()],
        ));
    }
    assert_eq!(actual, expected);
}

/// The login accepted as the M7 accepted it on 2026-10-14, and then a
/// session that is not an administrator's: a failed login.
#[test]
fn a_non_admin_session_is_auth_failed() {
    let guest = String::from_utf8(FIXTURE.to_vec())
        .unwrap()
        .replace("\"userRole\":\"Admin\"", "\"userRole\":\"Guest\"");
    assert!(guest.contains("\"userRole\":\"Guest\""));
    let (outcome, received, _) = run_status(login_script(json(&[], guest.as_bytes())), None);
    assert_eq!(outcome.code, 5, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the M7 did not grant an administrator's session: the router's session is not an administrator's (the login was answered with status 302 and a Location to the start page)\n"
    );
    assert_eq!(request_lines(&received), [GET, POST, GET]);
    // A refused status request after the login is a failed login too.
    let (outcome, _, _) = run_status(
        login_script(Reply::Bytes(response("401 Unauthorized", &[], b""))),
        None,
    );
    assert_eq!(outcome.code, 5, "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("refused (401)"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn a_cool_off_sends_no_password() {
    let (outcome, received, _) =
        run_status(|_| vec![json(&[], &anonymous("Guest", 30, "MR7450"))], None);
    assert_eq!(outcome.code, 5, "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("cool-off (30)"),
        "{}",
        outcome.stderr
    );
    assert_eq!(request_lines(&received), [GET]);
}

#[test]
fn identity_mismatch_sends_no_password() {
    let (outcome, received, harness) = run_status(
        |_| vec![json(&[], &anonymous("Guest", 0, "MR7450"))],
        Some(FakeLink::answering(&[Ok(OTHER)])),
    );
    assert_eq!(outcome.code, 6, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the gateway is not the pinned M7 (pinned 02:00:5e:10:20:30, found 02:00:5e:99:99:99); no password was sent\n"
    );
    assert_eq!(request_lines(&received), [GET]);
    assert_eq!(harness.link.neighbour_calls.get(), 1);
    // Addresses that cannot identify a device are mismatches as well.
    for (answer, found) in [
        (
            Ok([0x01, 0x00, 0x5e, 0, 0, 1]),
            "01:00:5e:00:00:01, which is not a unicast address",
        ),
        (
            Ok([0; 6]),
            "00:00:00:00:00:00, which is not a unicast address",
        ),
        (Ok(PLACEHOLDER), PLACEHOLDER_FOUND),
        (
            Err(MacsysError::NotEthernet { alen: 8 }),
            "a link-layer address of 8 bytes",
        ),
        (
            Err(MacsysError::AmbiguousNeighbour),
            "more than one link-layer address",
        ),
    ] {
        let (outcome, received, _) = run_status(
            |_| vec![json(&[], &anonymous("Guest", 0, "MR7450"))],
            Some(FakeLink::answering(&[answer])),
        );
        assert_eq!(outcome.code, 6, "{}", outcome.stderr);
        assert!(outcome.stderr.contains(found), "{}", outcome.stderr);
        assert_eq!(request_lines(&received), [GET]);
    }
}

#[test]
fn an_unresolved_gateway_sends_no_password() {
    for answer in [
        MacsysError::NeighbourAbsent,
        MacsysError::NeighbourIncomplete,
    ] {
        let (outcome, received, _) = run_status(
            |_| vec![json(&[], &anonymous("Guest", 0, "MR7450"))],
            Some(FakeLink::answering(&[Err(answer)])),
        );
        assert_eq!(outcome.code, 4, "{}", outcome.stderr);
        assert!(
            outcome.stderr.contains("not in the neighbour table"),
            "{}",
            outcome.stderr
        );
        assert_eq!(request_lines(&received), [GET]);
    }
    // A kernel table that cannot be read is a local failure.
    let (outcome, _, _) = run_status(
        |_| vec![json(&[], &anonymous("Guest", 0, "MR7450"))],
        Some(FakeLink::answering(&[Err(MacsysError::Sysctl {
            errno: 1,
        })])),
    );
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: reading the kernel's network tables failed\n  caused by: sysctl failed with errno 1\n"
    );
}

/// The placeholder address never matches, even when it is what was
/// pinned (a pin written before the rule, or by hand): no password is sent.
#[test]
fn a_pinned_placeholder_is_never_a_match() {
    let stub = Stub::start_for(login_script(admin_document()));
    let mut harness = Harness::configured(stub.port());
    harness.pin(PLACEHOLDER);
    harness.link = FakeLink::answering(&[Ok(PLACEHOLDER)]);
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 6, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the gateway is not the pinned M7 (pinned 02:00:00:00:00:00, found {PLACEHOLDER_FOUND}); no password was sent\n"
        )
    );
    assert_eq!(request_lines(&received), [GET]);
}

/// An empty neighbour table after the anonymous `GET` reached the gateway
/// is read as one the kernel hides from this binary (design §15.6 rule 10):
/// it stops `status` at the identity check, before any password is sent, as
/// a local failure (exit 1) naming the cause, not an unreachable M7, so
/// `--json` prints no router reading. The stub would answer a login, so
/// going on to log in would be seen.
#[test]
fn an_empty_neighbour_table_after_the_get_sends_no_password() {
    for args in [
        STATUS,
        &["router", "status", "--interface", "lo0", "--json"],
    ] {
        let stub = Stub::start_for(login_script(admin_document()));
        let mut harness = Harness::configured(stub.port());
        harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourTableEmpty)]);
        let outcome = harness.run(args);
        let received = stub.finish();
        assert_secrets_kept(&outcome, &received);
        assert_eq!(outcome.code, 1, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, HIDDEN_TABLE);
        assert_eq!(request_lines(&received), [GET]);
        assert_eq!(harness.link.neighbour_calls.get(), 1);
    }
}

#[test]
fn an_admin_anonymous_answer_sends_no_password() {
    let (outcome, received, _) = run_status(|_| vec![admin_document()], None);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.stdout.starts_with("M7 MR7450 on lo0"));
    assert_eq!(request_lines(&received), [GET]);
}

#[test]
fn another_model_is_unsupported_before_login() {
    let (outcome, received, harness) =
        run_status(|_| vec![json(&[], &anonymous("Guest", 0, "MR6400"))], None);
    assert_eq!(outcome.code, 7, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the device is not a supported M7: the router is not an MR7450 speaking API 2.0 (general.model)\n"
    );
    assert_eq!(request_lines(&received), [GET]);
    assert_eq!(harness.link.neighbour_calls.get(), 0);
    // So is a missing endpoint.
    let (outcome, received, _) = run_status(
        |_| vec![Reply::Bytes(response("404 Not Found", &[], b""))],
        None,
    );
    assert_eq!(outcome.code, 7, "{}", outcome.stderr);
    assert_eq!(request_lines(&received), [GET]);
}

#[test]
fn missing_pin_or_password_touches_no_network() {
    let stub = Stub::start(vec![admin_document()]);
    let mut harness = Harness::new(stub.port());
    let outcome = harness.run(STATUS);
    assert_eq!(outcome.code, 3, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the router adapter is not set up: no router identity is pinned (mooringctl router pin)\n"
    );
    harness.pin(PINNED);
    let outcome = harness.run(STATUS);
    assert_eq!(outcome.code, 3, "{}", outcome.stderr);
    assert!(outcome.stderr.contains("no M7 admin password is stored"));
    assert_eq!(harness.link.neighbour_calls.get(), 0);
    assert!(stub.finish().is_empty(), "nothing was sent");
}

#[test]
fn the_attachment_must_exist() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::configured(stub.port());
    let outcome = harness.run(&["router", "status", "--interface", "en99"]);
    assert_eq!(outcome.code, 4, "{}", outcome.stderr);
    assert!(outcome.stderr.contains("the interface does not exist"));
    for (gateway, text) in [
        (MacsysError::NoDefaultRoute, "no IPv4 default route"),
        (MacsysError::AmbiguousDefaultRoute, "more than one gateway"),
    ] {
        harness.link.gateway = Err(gateway);
        let outcome = harness.run(STATUS);
        assert_eq!(outcome.code, 4, "{}", outcome.stderr);
        assert!(outcome.stderr.contains(text), "{}", outcome.stderr);
    }
    assert!(stub.finish().is_empty());
}

#[test]
fn json_output_is_one_reading_line() {
    let stub = Stub::start_for(login_script(admin_document()));
    let mut harness = Harness::configured(stub.port());
    let outcome = harness.run(&["router", "status", "--interface", "lo0", "--json"]);
    stub.finish();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout.matches('\n').count(), 1);
    assert!(outcome.stdout.ends_with('\n'));
    let reading: RouterReading = serde_json::from_str(outcome.stdout.trim_end()).unwrap();
    assert_eq!(
        reading,
        RouterReading::Available {
            polled_at: UnixTime::from_secs(NOW),
            status: Box::new(parse_netgear_model_json(FIXTURE).unwrap()),
        }
    );
    // A router failure is the unavailable reading on stdout, the error on
    // stderr, and the reason's exit code.
    let stub = Stub::start(vec![json(&[], &anonymous("Guest", 0, "MR7450"))]);
    let mut harness = Harness::configured(stub.port());
    harness.link = FakeLink::answering(&[Ok(OTHER)]);
    let outcome = harness.run(&["router", "status", "--interface", "lo0", "--json"]);
    stub.finish();
    assert_eq!(outcome.code, 6);
    assert_eq!(
        outcome.stdout,
        "{\"unavailable\":{\"reason\":\"identity_mismatch\",\"last_polled_at\":null}}\n"
    );
    let reading: RouterReading = serde_json::from_str(outcome.stdout.trim_end()).unwrap();
    assert_eq!(
        reading,
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::IdentityMismatch,
            last_polled_at: None,
        }
    );
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the gateway is not the pinned M7")
    );
}

/// The administrator's document with `edit` applied, as the stub serves it.
fn edited_admin_document(edit: impl FnOnce(&mut serde_json::Value)) -> Reply {
    let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    edit(&mut document);
    json(&[], &serde_json::to_vec(&document).unwrap())
}

/// A state the parser does not know (Wi-Fi on) is a malformed answer
/// after the login: exit 8, the field named and its value not, and the
/// unavailable reading with reason `malformed`.
#[test]
fn an_unknown_device_state_is_malformed() {
    let script = || {
        login_script(edited_admin_document(|document| {
            document["wifi"]["status"] = serde_json::json!("On");
        }))
    };
    let (outcome, received, _) = run_status(script(), None);
    assert_eq!(outcome.code, 8, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the M7's answer is malformed: router field wifi.status: not a value the MR7450 has been seen to report (the login was answered with status 302 and a Location to the start page)\n"
    );
    assert_eq!(request_lines(&received), [GET, POST, GET]);
    let stub = Stub::start_for(script());
    let mut harness = Harness::configured(stub.port());
    let outcome = harness.run(&["router", "status", "--interface", "lo0", "--json"]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 8, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "{\"unavailable\":{\"reason\":\"malformed\",\"last_polled_at\":null}}\n"
    );
}

/// The empty SPN and web app version the M7 reported with the SMARTY SIM
/// (2026-10-16, when `router status` exited 8) are read as not reported,
/// each alone and both at once: exit 0, the
/// summary says so, and `--json` spells each `null`, with no empty string
/// anywhere.
#[test]
fn an_empty_spn_or_web_app_version_is_read_as_not_reported() {
    let spn = (
        "/sim/SPN",
        "; SIM name not reported\n",
        r#""sim_spn":null,"#,
    );
    let web_app = (
        "/general/webAppVersion",
        ", web app version not reported; ",
        r#""web_app":null,"#,
    );
    for emptied in [&[spn][..], &[web_app], &[spn, web_app]] {
        let edit = |document: &mut serde_json::Value| {
            for (at, _, _) in emptied {
                *document.pointer_mut(at).unwrap() = serde_json::json!("");
            }
        };
        let (outcome, received, _) = run_status(login_script(edited_admin_document(edit)), None);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stderr, "");
        assert_eq!(request_lines(&received), [GET, POST, GET]);
        let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        edit(&mut document);
        let status = parse_netgear_model_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        let expected = summary(&lo0_name(), UnixTime::from_secs(NOW), &status).unwrap();
        assert_eq!(outcome.stdout, expected);
        let stub = Stub::start_for(login_script(edited_admin_document(edit)));
        let mut harness = Harness::configured(stub.port());
        let json_outcome = harness.run(&["router", "status", "--interface", "lo0", "--json"]);
        let received = stub.finish();
        assert_secrets_kept(&json_outcome, &received);
        assert_eq!(json_outcome.code, 0, "{}", json_outcome.stderr);
        let line = json_outcome.stdout.trim_end();
        for (_, said, null) in emptied {
            assert!(outcome.stdout.contains(said), "{}", outcome.stdout);
            assert!(line.contains(null), "{line}");
        }
        assert!(!line.contains(r#""""#), "{line}");
        assert_eq!(
            serde_json::from_str::<RouterReading>(line).unwrap(),
            RouterReading::Available {
                polled_at: UnixTime::from_secs(NOW),
                status: Box::new(status),
            }
        );
    }
}

/// Another API version, which only the administrator's document reports,
/// is unsupported: exit 7, the leaf named.
#[test]
fn another_api_version_is_unsupported() {
    let (outcome, received, _) = run_status(
        login_script(edited_admin_document(|document| {
            document["general"]["apiVersion"] = serde_json::json!("3.0");
        })),
        None,
    );
    assert_eq!(outcome.code, 7, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the device is not a supported M7: the router is not an MR7450 speaking API 2.0 (general.apiVersion) (the login was answered with status 302 and a Location to the start page)\n"
    );
    assert_eq!(request_lines(&received), [GET, POST, GET]);
}

/// The observed session set-up, then `rest`, on the stub at `port`.
fn after_session_set_up(port: u16, rest: impl IntoIterator<Item = Reply>) -> Vec<Reply> {
    let mut script = Vec::from(session_set_up(port, SESSION_A, SESSION_B));
    script.extend(rest);
    script
}

/// `router status` when the M7 asks for its session set-up first, as it
/// did on 2026-10-14 (design §15.6 rule 9): the set-up's three requests,
/// the identity check, then the login and the administrator's read, each
/// request exactly these bytes. The set-up's cookie replaces the first
/// one, the login's (as the M7 accepted the login on 2026-10-14) replaces
/// the set-up's, and the password is sent once, in the login's body.
#[test]
fn status_follows_the_session_set_up_then_logs_in() {
    let stub = Stub::start_for(|port| {
        after_session_set_up(
            port,
            [
                observed_document(&anonymous("Guest", 0, "MR7450")),
                login_answer(port),
                admin_document(),
            ],
        )
    });
    let port = stub.port();
    let mut harness = Harness::configured(port);
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let status = parse_netgear_model_json(FIXTURE).unwrap();
    let expected = summary(&lo0_name(), UnixTime::from_secs(NOW), &status).unwrap();
    assert_eq!(outcome.stdout, expected);
    assert!(!outcome.stdout.contains(REDIRECT_BODY_CANARY));
    let version = env!("CARGO_PKG_VERSION");
    let host = format!("127.0.0.1:{port}");
    let get = |target: &str, cookie: &str| {
        format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mooringctl/{version}\r\nAccept: application/json\r\n{cookie}Connection: close\r\n\r\n"
        )
    };
    let body = format!(
        "token={ENCODED_TOKEN}&err_redirect=%2Findex.html%3Floginfailed&ok_redirect=%2Findex.html&session.password={ENCODED_PASSWORD}"
    );
    let expected = [
        get(JSON_TARGET, ""),
        get(SET_UP_TARGET, &format!("Cookie: sessionId={SESSION_A}\r\n")),
        get(JSON_TARGET, &format!("Cookie: sessionId={SESSION_B}\r\n")),
        format!(
            "POST /Forms/config HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mooringctl/{version}\r\nAccept: */*\r\nOrigin: http://{host}\r\nReferer: http://{host}/index.html\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: sessionId={SESSION_B}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        get(JSON_TARGET, &format!("Cookie: sessionId={SESSION_L}\r\n")),
    ];
    let texts: Vec<String> = received.iter().map(Received::text).collect();
    assert_eq!(texts, expected);
    // The password, encoded, appears once in all that was sent: at the end
    // of the login's body.
    assert_eq!(texts.concat().matches(ENCODED_PASSWORD).count(), 1);
    assert!(texts[3].ends_with(&format!("&session.password={ENCODED_PASSWORD}")));
    assert_eq!(harness.link.neighbour_calls.get(), 1);
}

/// A session set-up asked for again before the administrator's read is
/// followed the same way: once per read of the JSON endpoint, so seven
/// requests in all, each new `sessionId` (the set-up's, the login's, then
/// the second set-up's) replacing the one before it. Whether the M7 ever
/// redirects the read after a login through its set-up, and whether that
/// session would still be an administrator's, is unobserved: on 2026-10-14
/// it answered that read `200` at once. The stub here serves the
/// administrator's document after it.
#[test]
fn a_session_set_up_before_the_authenticated_read_is_followed_too() {
    let stub = Stub::start_for(|port| {
        let mut script = after_session_set_up(
            port,
            [
                observed_document(&anonymous("Guest", 0, "MR7450")),
                login_answer(port),
            ],
        );
        script.extend(session_set_up(port, "COOKIE-C-5b0e", "COOKIE-D-c4a1"));
        script.push(observed_document(FIXTURE));
        script
    });
    let mut harness = Harness::configured(stub.port());
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.stdout.starts_with("M7 MR7450 on lo0"));
    assert_eq!(
        request_lines(&received),
        [GET, SET_UP, GET, POST, GET, SET_UP, GET]
    );
    let cookie = |value: &str| vec![format!("Cookie: {value}")];
    assert_eq!(
        cookie_lines(&received),
        [
            Vec::new(),
            cookie(&format!("sessionId={SESSION_A}")),
            cookie(&format!("sessionId={SESSION_B}")),
            cookie(&format!("sessionId={SESSION_B}")),
            cookie(&format!("sessionId={SESSION_L}")),
            cookie("sessionId=COOKIE-C-5b0e"),
            cookie("sessionId=COOKIE-D-c4a1"),
        ]
    );
}

/// The identity check runs after the session set-up and before anything
/// secret is sent: another gateway stops the command with no login, though
/// the stub would answer one.
#[test]
fn a_mismatch_after_the_session_set_up_sends_no_password() {
    let stub = Stub::start_for(|port| {
        after_session_set_up(
            port,
            [
                observed_document(&anonymous("Guest", 0, "MR7450")),
                login_answer(port),
                admin_document(),
            ],
        )
    });
    let mut harness = Harness::configured(stub.port());
    harness.link = FakeLink::answering(&[Ok(OTHER)]);
    let outcome = harness.run(STATUS);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 6, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the gateway is not the pinned M7 (pinned 02:00:5e:10:20:30, found 02:00:5e:99:99:99); no password was sent\n"
    );
    assert_eq!(request_lines(&received), [GET, SET_UP, GET]);
    assert_eq!(harness.link.neighbour_calls.get(), 1);
}

/// A `Location` to the session set-up on the stub, as the M7 names it.
const TO_SET_UP: &str =
    "Location: http://127.0.0.1:{port}/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1";

/// A `Location` to the JSON endpoint on the stub.
const TO_JSON: &str = "Location: http://127.0.0.1:{port}/api/model.json?internalapi=1";

/// The session cookie a refused redirect sets.
const REFUSED_COOKIE: &str = "Set-Cookie: sessionId=COOKIE-R-77d2; path=/; HttpOnly";

/// One answer of a refusal: a status line's status and header lines, in
/// which `{port}` stands for the stub's port; its body is empty.
type StubAnswer = (&'static str, Vec<&'static str>);

/// Answers `router status` refuses, and what it does with them: its exit
/// code, what it prints on stderr and the requests it makes.
struct Refusal {
    name: &'static str,
    answers: Vec<StubAnswer>,
    code: u8,
    stderr: String,
    requests: Vec<&'static str>,
}

/// What `router status` prints when the M7's answer is malformed for
/// `cause`.
fn malformed(cause: &str) -> String {
    format!("mooringctl: the M7's answer is malformed: {cause}\n")
}

/// What the refusal of a redirect answering the first request prints.
fn first_refused(status: u16) -> String {
    malformed(&format!(
        "the status request was answered by a redirect other than the M7's session set-up (status {status})"
    ))
}

/// The refusals at the first `GET` of the JSON endpoint: one request.
fn first_request_refusals() -> Vec<Refusal> {
    let elsewhere = [
        (
            "another host",
            "Location: http://127.0.0.2:{port}/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        ),
        (
            "the host without the stub's port",
            "Location: http://127.0.0.1/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        ),
        (
            "another path",
            "Location: http://127.0.0.1:{port}/sess_cd_tmp?op=%2F&oq=",
        ),
        (
            "a relative reference",
            "Location: /sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        ),
        (
            "a decoded dot",
            "Location: http://127.0.0.1:{port}/sess_cd_tmp?op=%2Fapi%2Fmodel.json&oq=internalapi%3D1",
        ),
        (
            "lower-case escapes",
            "Location: http://127.0.0.1:{port}/sess_cd_tmp?op=%2fapi%2fmodel%2ejson&oq=internalapi%3d1",
        ),
        (
            "another scheme",
            "Location: https://127.0.0.1:{port}/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1",
        ),
        (
            "a longer URL",
            "Location: http://127.0.0.1:{port}/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1&x=1",
        ),
        ("the JSON endpoint itself", TO_JSON),
        ("an empty Location", "Location:"),
    ];
    let mut refusals: Vec<Refusal> = elsewhere
        .into_iter()
        .map(|(name, location)| Refusal {
            name,
            answers: vec![("302 Found", vec![REFUSED_COOKIE, location])],
            code: 8,
            stderr: first_refused(302),
            requests: vec![GET],
        })
        .collect();
    refusals.push(Refusal {
        name: "no Location",
        answers: vec![("302 Found", vec![REFUSED_COOKIE])],
        code: 8,
        stderr: first_refused(302),
        requests: vec![GET],
    });
    refusals.push(Refusal {
        name: "two Locations",
        answers: vec![("302 Found", vec![REFUSED_COOKIE, TO_SET_UP, TO_SET_UP])],
        code: 8,
        stderr: malformed("the HTTP head has more than one Location"),
        requests: vec![GET],
    });
    for (status, code) in [
        ("300 Multiple Choices", 300),
        ("301 Moved Permanently", 301),
        ("303 See Other", 303),
        ("304 Not Modified", 304),
        ("307 Temporary Redirect", 307),
        ("308 Permanent Redirect", 308),
        ("399 Unassigned", 399),
    ] {
        refusals.push(Refusal {
            name: status,
            answers: vec![(status, vec![REFUSED_COOKIE, TO_SET_UP])],
            code: 8,
            stderr: first_refused(code),
            requests: vec![GET],
        });
    }
    refusals
}

/// The refusals at the session set-up: two requests.
fn session_set_up_refusals() -> Vec<Refusal> {
    let refused = |status: u16| {
        malformed(&format!(
            "the M7's session set-up was not answered by a redirect back to the status request (status {status})"
        ))
    };
    let refusal = |name: &'static str, answer: StubAnswer, stderr: String| Refusal {
        name,
        answers: vec![("302 Found", vec![REFUSED_COOKIE, TO_SET_UP]), answer],
        code: 8,
        stderr,
        requests: vec![GET, SET_UP],
    };
    vec![
        refusal(
            "a set-up answered by a document",
            ("200 OK", vec!["Content-Type: application/json"]),
            refused(200),
        ),
        refusal(
            "a set-up redirected to a relative reference",
            ("302 Found", vec!["Location: /api/model.json?internalapi=1"]),
            refused(302),
        ),
        refusal(
            "a set-up redirected to itself",
            ("302 Found", vec![TO_SET_UP]),
            refused(302),
        ),
        refusal(
            "a set-up redirected without a Location",
            ("302 Found", vec![REFUSED_COOKIE]),
            refused(302),
        ),
        refusal(
            "a set-up moved permanently to the endpoint",
            ("301 Moved Permanently", vec![TO_JSON]),
            refused(301),
        ),
        refusal(
            "a set-up redirected temporarily to the endpoint",
            ("307 Temporary Redirect", vec![TO_JSON]),
            refused(307),
        ),
        refusal(
            "a set-up refused",
            ("401 Unauthorized", vec![]),
            refused(401),
        ),
        refusal(
            "a set-up with two Locations",
            ("302 Found", vec![TO_JSON, TO_JSON]),
            malformed("the HTTP head has more than one Location"),
        ),
    ]
}

/// The refusals at the `GET` of the JSON endpoint after the set-up: three
/// requests, never a fourth. A redirect is refused, and every other status
/// is judged as at the first request.
fn retried_request_refusals() -> Vec<Refusal> {
    let redirected = |status: u16| {
        malformed(&format!(
            "the status request after the M7's session set-up was answered by another redirect (status {status})"
        ))
    };
    let refused = |status: u16| {
        format!(
            "mooringctl: the M7 did not grant an administrator's session: the status request was refused ({status})\n"
        )
    };
    let refusal = |name: &'static str, answer: StubAnswer, code: u8, stderr: String| Refusal {
        name,
        answers: vec![
            ("302 Found", vec![REFUSED_COOKIE, TO_SET_UP]),
            ("302 Found", vec![TO_JSON]),
            answer,
        ],
        code,
        stderr,
        requests: vec![GET, SET_UP, GET],
    };
    vec![
        refusal(
            "a retried request redirected to the set-up again",
            ("302 Found", vec![TO_SET_UP]),
            8,
            redirected(302),
        ),
        refusal(
            "a retried request redirected to itself",
            ("307 Temporary Redirect", vec![TO_JSON]),
            8,
            redirected(307),
        ),
        refusal(
            "a retried request redirected without a Location",
            ("302 Found", vec![]),
            8,
            redirected(302),
        ),
        refusal(
            "a retried request refused (401)",
            ("401 Unauthorized", vec![]),
            5,
            refused(401),
        ),
        refusal(
            "a retried request refused (403)",
            ("403 Forbidden", vec![]),
            5,
            refused(403),
        ),
        refusal(
            "a retried request without the endpoint",
            ("404 Not Found", vec![]),
            7,
            "mooringctl: the device is not a supported M7: its JSON endpoint answered 404\n"
                .to_owned(),
        ),
        refusal(
            "a retried request failing",
            ("500 Internal Server Error", vec![]),
            8,
            malformed("unexpected HTTP status 500"),
        ),
        refusal(
            "a retried request answered by a web page",
            ("200 OK", vec!["Content-Type: text/html"]),
            8,
            malformed("it is a web page (text/html), which is never read"),
        ),
    ]
}

/// Every redirect but the M7's session set-up is refused (design §15.6
/// rule 9), naming the request it answered and its status. Each case runs
/// `router status` with the password stored: the requests made are exactly
/// those listed, so no login is sent and nothing past the one set-up is
/// followed, the identity is never checked, and nothing is printed on
/// stdout.
#[test]
fn redirects_other_than_the_session_set_up_are_refused() {
    let refusals = first_request_refusals()
        .into_iter()
        .chain(session_set_up_refusals())
        .chain(retried_request_refusals());
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for refusal in refusals {
        let stub = Stub::start_for(|port| {
            refusal
                .answers
                .iter()
                .map(|(status, headers)| {
                    let headers: Vec<String> = headers
                        .iter()
                        .map(|header| header.replace("{port}", &port.to_string()))
                        .collect();
                    let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
                    Reply::Bytes(response(status, &headers, b""))
                })
                .collect()
        });
        let mut harness = Harness::configured(stub.port());
        let outcome = harness.run(STATUS);
        let received = stub.finish();
        assert_secrets_kept(&outcome, &received);
        actual.push((
            refusal.name,
            outcome.code,
            outcome.stdout,
            outcome.stderr,
            request_lines(&received),
            harness.link.neighbour_calls.get(),
        ));
        let requests: Vec<String> = refusal
            .requests
            .iter()
            .map(|line| (*line).to_owned())
            .collect();
        expected.push((
            refusal.name,
            refusal.code,
            String::new(),
            refusal.stderr,
            requests,
            0,
        ));
    }
    assert_eq!(actual, expected);
}
