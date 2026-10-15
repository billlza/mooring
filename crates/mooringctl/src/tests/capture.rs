// SPDX-License-Identifier: GPL-3.0-or-later

//! `router capture`: only the redactor's output is ever written, never over
//! an existing file, and an anonymous capture reads no password and sends
//! no login.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use mooring_daemon_core::router::netgear::redact_netgear_model_json;
use mooring_macsys::MacsysError;
use serde_json::{Value, json as value};

use super::flow::{
    GET, PASSWORD_FIELD_REFUSED, PASSWORD_REFUSED, POST, SET_UP, admin_document, anonymous_answer,
    assert_secrets_kept, cookie_lines, login_script, refused_login_answer, request_lines,
};
use super::stub::{Stub, json};
use super::support::{
    FIXTURE, FakeLink, HIDDEN_TABLE, Harness, OBSERVED_REFUSAL_QUERY, Outcome, PINNED, PLACEHOLDER,
    PLACEHOLDER_FOUND, REDIRECT_BODY_CANARY, SESSION_A, SESSION_B, anonymous, observed_document,
    observed_login_refusal, session_set_up,
};

/// A canary in each kind of plaintext secret and identifier the M7's
/// administrator document holds (M2a), at the fixture's own paths.
const CANARIES: &[(&str, &str)] = &[
    ("/webd/adminPassword", "CANARY-admin-pw-61c"),
    ("/wifi/passPhrase", "CANARY-wifi-pass-1d9"),
    ("/wifi/guest/passPhrase", "CANARY-guest-pass-e04"),
    ("/general/IMEI", "CANARY-imei-358240051111110"),
    ("/general/InstallID", "CANARY-install-a3f"),
    ("/general/ESN", "CANARY-esn-77b"),
    ("/sim/iccid", "CANARY-iccid-8944110068256270054"),
    ("/sim/imsi", "CANARY-imsi-234301234567890"),
    ("/sim/phoneNumber", "CANARY-phone-447700900123"),
    ("/sms/msgs/0/text", "CANARY-sms-meet-at-the-dock"),
    ("/session/secToken", "CANARY-session-token-0b7"),
    ("/session/clientIP", "CANARY-client-ip-192"),
    ("/wwan/IP", "CANARY-wwan-ip-10"),
    ("/ethernet/mac", "CANARY-ethernet-mac-aa"),
    ("/router/clientList/0/MAC", "CANARY-client-mac-bb"),
    ("/lbs/latitude", "CANARY-latitude-51"),
    ("/wwan/lteBandInfo/0/phyCid", "CANARY-phy-cid-417"),
];

/// The fixture with a canary at every path of [`CANARIES`], a second SMS
/// (arrays keep only their first element) and a cell identifier, as the
/// M7 would serve it.
fn canaried_admin_document() -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
    for (at, canary) in CANARIES {
        *document
            .pointer_mut(at)
            .unwrap_or_else(|| panic!("the fixture has {at}")) = value!(canary);
    }
    let messages = document.pointer_mut("/sms/msgs").unwrap();
    let mut second = messages[0].clone();
    second["text"] = value!("CANARY-second-sms");
    messages.as_array_mut().unwrap().push(second);
    *document.pointer_mut("/wwanadv/cellId").unwrap() = value!(31_415_926);
    serde_json::to_vec(&document).unwrap()
}

/// No canary in the written file, nor in what the command printed.
fn assert_no_canary(outcome: &Outcome, written: &[u8]) {
    let written = String::from_utf8(written.to_vec()).unwrap();
    let printed = format!("{}{}", outcome.stdout, outcome.stderr);
    for (_, canary) in CANARIES
        .iter()
        .chain([&("", "CANARY-second-sms"), &("", "31415926")])
    {
        assert!(!written.contains(canary), "{canary} was written");
        assert!(!printed.contains(canary), "{canary} was printed");
    }
}

#[test]
fn capture_writes_only_the_redactors_output() {
    let document = canaried_admin_document();
    let redacted = redact_netgear_model_json(&document).unwrap();
    // The capture differs from what the M7 sent, so writing the raw
    // document instead would fail this test.
    assert_ne!(redacted.as_bytes(), document.as_slice());
    assert_eq!(redacted.withheld(), []);
    let stub = Stub::start_for(login_script(json(&[], &document)));
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    let path = out.to_str().unwrap();
    let outcome = harness.run(&["router", "capture", "--interface", "lo0", "--out", path]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let mut expected = redacted.as_bytes().to_vec();
    expected.push(b'\n');
    let written = fs::read(&out).unwrap();
    assert_eq!(written, expected);
    assert_no_canary(&outcome, &written);
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote the redacted capture ({} bytes) to {path}\n",
            expected.len()
        )
    );
    assert_eq!(received.len(), 3);
}

/// A state whose allowlisted leaves change form (here an empty carrier
/// name and an identifier where the network name belongs) is captured with
/// those values withheld and named, and a value the parser does not know
/// yet (Wi-Fi `On`) is captured as it is.
#[test]
fn a_capture_withholds_values_whose_form_is_refused() {
    let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
    document["sim"]["SPN"] = value!("");
    document["wwan"]["registerNetworkDisplay"] = value!("447700900123");
    document["wifi"]["status"] = value!("On");
    let document = serde_json::to_vec(&document).unwrap();
    let stub = Stub::start_for(login_script(json(&[], &document)));
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    let path = out.to_str().unwrap();
    let outcome = harness.run(&["router", "capture", "--interface", "lo0", "--out", path]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let written: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(written["sim"]["SPN"], value!(""));
    assert_eq!(
        written["wwan"]["registerNetworkDisplay"],
        value!("REDACTED")
    );
    assert_eq!(written["wifi"]["status"], value!("On"));
    let size = fs::metadata(&out).unwrap().len();
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote the redacted capture ({size} bytes) to {path}\n\
             withheld (a placeholder in the capture): router field sim.SPN: not text of its form\n\
             withheld (a placeholder in the capture): router field wwan.registerNetworkDisplay: not text of its form\n"
        )
    );
    assert!(!outcome.stdout.contains("447700900123"));
}

/// A key that is data refuses the whole capture: nothing is written, and
/// the error says why without the key.
#[test]
fn a_key_that_is_data_writes_nothing() {
    let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
    document["router"]
        .as_object_mut()
        .unwrap()
        .insert("aa:bb:cc:dd:ee:ff".to_owned(), value!("laptop"));
    let document = serde_json::to_vec(&document).unwrap();
    let stub = Stub::start_for(login_script(json(&[], &document)));
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        out.to_str().unwrap(),
    ]);
    stub.finish();
    assert_eq!(outcome.code, 8, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the M7's answer is malformed: a key of the router's answer is not a plain name, so nothing was captured (the login was answered with status 302 and a Location to the start page)\n"
    );
    assert_eq!(outcome.stdout, "");
    assert!(!out.exists());
}

#[test]
fn capture_never_overwrites() {
    let stub = Stub::start_for(login_script(admin_document()));
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    fs::write(&out, b"earlier").unwrap();
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} already exists; a capture never overwrites a file\n",
            out.display()
        )
    );
    assert_eq!(fs::read(&out).unwrap(), b"earlier");
    assert!(stub.finish().is_empty(), "the M7 was not asked");
    // A dangling link is a file too.
    let link = harness.home.path().join("link.json");
    std::os::unix::fs::symlink(harness.home.path().join("absent"), &link).unwrap();
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        link.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert!(!harness.home.path().join("absent").exists());
}

#[test]
fn anonymous_capture_reads_no_password_and_sends_no_post() {
    let document = anonymous("Guest", 0, "MR7450");
    let stub = Stub::start(vec![json(&[], &document)]);
    let mut harness = Harness::new(stub.port());
    harness.pin(PINNED);
    let out = harness.home.path().join("anonymous.json");
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        out.to_str().unwrap(),
        "--anonymous",
    ]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let mut expected = redact_netgear_model_json(&document)
        .unwrap()
        .as_bytes()
        .to_vec();
    expected.push(b'\n');
    assert_eq!(fs::read(&out).unwrap(), expected);
    assert_eq!(received.len(), 1);
    assert_eq!(
        harness.link.neighbour_calls.get(),
        1,
        "the identity is still checked"
    );
}

/// The live finding of 2026-10-14: the M7 answers the anonymous `GET`
/// with its session set-up, observed byte for byte (design §15.6 rule 9).
/// The capture follows it, once: three requests, the set-up carrying the
/// first redirect's cookie only and the retried `GET` the set-up's only,
/// which replaced it; then the identity check, and the redactor's output
/// of the `text/plain` document is written.
#[test]
fn an_anonymous_capture_follows_the_session_set_up() {
    let document = anonymous("Guest", 0, "MR7450");
    let stub = Stub::start_for(|port| {
        let mut script = Vec::from(session_set_up(port, SESSION_A, SESSION_B));
        script.push(observed_document(&document));
        script
    });
    let mut harness = Harness::new(stub.port());
    harness.pin(PINNED);
    let out = harness.home.path().join("anonymous.json");
    let path = out.to_str().unwrap();
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        path,
        "--anonymous",
    ]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(request_lines(&received), [GET, SET_UP, GET]);
    assert_eq!(
        cookie_lines(&received),
        [
            Vec::new(),
            vec![format!("Cookie: sessionId={SESSION_A}")],
            vec![format!("Cookie: sessionId={SESSION_B}")],
        ]
    );
    let mut expected = redact_netgear_model_json(&document)
        .unwrap()
        .as_bytes()
        .to_vec();
    expected.push(b'\n');
    let written = fs::read(&out).unwrap();
    assert_eq!(written, expected);
    assert!(
        !String::from_utf8(written)
            .unwrap()
            .contains(REDIRECT_BODY_CANARY)
    );
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote the redacted capture ({} bytes) to {path}\n",
            expected.len()
        )
    );
    assert_eq!(
        harness.link.neighbour_calls.get(),
        1,
        "the identity is still checked"
    );
}

#[test]
fn a_capture_needs_an_administrators_document() {
    let failed_login = login_script(json(&[], &anonymous("Guest", 0, "MR7450")));
    let stub = Stub::start_for(failed_login);
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        out.to_str().unwrap(),
    ]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 5, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the M7 did not grant an administrator's session: the router's session is not an administrator's (the login was answered with status 302 and a Location to the start page)\n"
    );
    assert_eq!(request_lines(&received), [GET, POST, GET]);
    assert!(!out.exists());
}

/// A login the M7 sends to its login-failed page stops a capture as it
/// stops `router status`: exit 5, nothing written, and no request after the
/// login although the stub would answer one with the administrator's
/// document.
#[test]
fn a_capture_stops_at_a_login_sent_to_the_login_failed_page() {
    let stub = Stub::start_for(|port| {
        vec![
            anonymous_answer(),
            refused_login_answer(port),
            admin_document(),
        ]
    });
    let mut harness = Harness::configured(stub.port());
    let out = harness.home.path().join("model.json");
    let outcome = harness.run(&[
        "router",
        "capture",
        "--interface",
        "lo0",
        "--out",
        out.to_str().unwrap(),
    ]);
    let received = stub.finish();
    assert_secrets_kept(&outcome, &received);
    assert_eq!(outcome.code, 5, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, PASSWORD_REFUSED);
    assert_eq!(request_lines(&received), [GET, POST]);
    assert!(!out.exists());
}

/// The M7's refusal as observed on 2026-10-14 (a `302` to its login-failed
/// page with `errno` and `errdetail`, no cookie), and one naming another
/// field, stop an administrator's capture as they stop `router status`:
/// exit 5, the error naming what the page reported, nothing written, and no
/// request after the login although the stub would answer one with a
/// canaried administrator's document.
#[test]
fn a_capture_stops_at_the_observed_refusal() {
    for (query, stderr) in [
        (OBSERVED_REFUSAL_QUERY, PASSWORD_FIELD_REFUSED),
        (
            "&errno=7&errdetail=token",
            "mooringctl: the M7 did not grant an administrator's session: it refused the login (error 7 on field token)\n",
        ),
    ] {
        let document = canaried_admin_document();
        let stub = Stub::start_for(|port| {
            vec![
                anonymous_answer(),
                observed_login_refusal(port, query),
                json(&[], &document),
            ]
        });
        let mut harness = Harness::configured(stub.port());
        let out = harness.home.path().join("model.json");
        let outcome = harness.run(&[
            "router",
            "capture",
            "--interface",
            "lo0",
            "--out",
            out.to_str().unwrap(),
        ]);
        let received = stub.finish();
        assert_secrets_kept(&outcome, &received);
        assert_no_canary(&outcome, b"");
        assert_eq!(outcome.code, 5, "{query}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, "", "{query}");
        assert_eq!(outcome.stderr, stderr, "{query}");
        assert_eq!(request_lines(&received), [GET, POST], "{query}");
        assert!(!out.exists(), "{query}");
    }
}

/// An empty neighbour table after the anonymous `GET` reached the gateway
/// (read as one the kernel hides from this binary, design §15.6 rule 10)
/// stops a capture at the identity check as a local failure, and the
/// placeholder address as a mismatch, logged in or `--anonymous`: one
/// `GET`, no login, and nothing written.
#[test]
fn an_empty_table_or_the_placeholder_captures_nothing() {
    let mismatch = format!(
        "mooringctl: the gateway is not the pinned M7 (pinned 02:00:5e:10:20:30, found {PLACEHOLDER_FOUND}); no password was sent\n"
    );
    for anonymous_capture in [false, true] {
        for (answer, code, expected) in [
            (Err(MacsysError::NeighbourTableEmpty), 1, HIDDEN_TABLE),
            (Ok(PLACEHOLDER), 6, mismatch.as_str()),
        ] {
            let (stub, mut harness) = if anonymous_capture {
                let stub = Stub::start(vec![json(&[], &anonymous("Guest", 0, "MR7450"))]);
                let mut harness = Harness::new(stub.port());
                harness.pin(PINNED);
                (stub, harness)
            } else {
                let stub = Stub::start_for(login_script(admin_document()));
                let harness = Harness::configured(stub.port());
                (stub, harness)
            };
            harness.link = FakeLink::answering(&[answer]);
            let out = harness.home.path().join("model.json");
            let path = out.to_str().unwrap();
            let mut args = vec!["router", "capture", "--interface", "lo0", "--out", path];
            if anonymous_capture {
                args.push("--anonymous");
            }
            let outcome = harness.run(&args);
            let received = stub.finish();
            assert_secrets_kept(&outcome, &received);
            assert_eq!(outcome.code, code, "{args:?}: {}", outcome.stderr);
            assert_eq!(outcome.stdout, "");
            assert_eq!(outcome.stderr, expected);
            assert_eq!(received.len(), 1, "{args:?}");
            assert!(received[0].request_line().starts_with("GET "));
            assert_eq!(harness.link.neighbour_calls.get(), 1);
            assert!(!out.exists());
        }
    }
}
