// SPDX-License-Identifier: GPL-3.0-or-later

//! The health gate's and the validators' readings of tool output.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use crate::txn::health::{Listener, all_listening, expected_listeners, owner_guards_present};
use crate::txn::validate::has_warning;

fn listener(udp: bool, address: Option<[u8; 4]>, port: u16) -> Listener {
    Listener {
        udp,
        address: address.map(Ipv4Addr::from),
        port,
    }
}

#[test]
fn the_golden_bundle_expects_its_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let golden = |name: &str, text: &str| {
        let body: Vec<&str> = text.lines().skip(4).collect();
        std::fs::write(dir.path().join(name), body.join("\n")).unwrap();
    };
    golden(
        "xray.json",
        include_str!("../../../../contract/golden/1-node-1-user/vps-lon1-xray.json.snap"),
    );
    golden(
        "hy2.json",
        include_str!("../../../../contract/golden/1-node-1-user/vps-lon1-hy2.json.snap"),
    );
    golden(
        "wgexit.conf",
        include_str!("../../../../contract/golden/1-node-1-user/vps-lon1-wgexit.conf.snap"),
    );
    let vps = Some([45, 67, 89, 10]);
    assert_eq!(
        expected_listeners(dir.path()).unwrap(),
        BTreeSet::from([
            listener(false, vps, 443),
            listener(false, Some([127, 0, 0, 1]), 10443),
            listener(false, vps, 80),
            listener(true, vps, 443),
            listener(true, vps, 61000),
            listener(true, None, 27820),
        ])
    );
}

#[test]
fn listeners_match_by_protocol_port_and_address_or_wildcard() {
    let want = BTreeSet::from([
        listener(false, Some([1, 2, 3, 4]), 443),
        listener(true, None, 27820),
    ]);
    let ss = "tcp LISTEN 0 4096 1.2.3.4:443 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n";
    assert!(all_listening(ss, &want));
    let wildcard = "tcp LISTEN 0 4096 *:443 *:*\nudp UNCONN 0 0 [::]:27820 [::]:*\n";
    assert!(
        all_listening(wildcard, &want),
        "a wildcard listener serves every address"
    );
    for wrong in [
        "udp UNCONN 0 0 1.2.3.4:443 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n",
        "tcp LISTEN 0 4096 5.6.7.8:443 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n",
        "tcp LISTEN 0 4096 1.2.3.4:443 0.0.0.0:*\nudp UNCONN 0 0 1.2.3.4:27820 0.0.0.0:*\n",
        "tcp LISTEN 0 4096 1.2.3.4:443 0.0.0.0:*\n",
        "",
    ] {
        assert!(!all_listening(wrong, &want), "{wrong:?}");
    }
}

#[test]
fn both_owner_guards_must_be_present() {
    let rule = |user: &str, counter: &str, verdict: &str| {
        format!(
            r#"{{"rule":{{"expr":[{{"match":{{"right":"{user}"}}}},{{"counter":"{counter}"}},{{"{verdict}":null}}]}}}}"#
        )
    };
    let chain = |rules: &[String]| format!(r#"{{"nftables":[{}]}}"#, rules.join(",")).into_bytes();
    let both = [
        rule("mooring-xray", "xray_guard", "reject"),
        rule("mooring-hy2", "hy2_guard", "reject"),
    ];
    assert!(owner_guards_present(&chain(&both)));
    assert!(!owner_guards_present(&chain(&both[..1])));
    assert!(!owner_guards_present(&chain(&[
        rule("mooring-xray", "xray_guard", "accept"),
        rule("mooring-hy2", "hy2_guard", "reject"),
    ])));
    assert!(!owner_guards_present(&chain(&[
        rule("mooring-hy2", "xray_guard", "reject"),
        rule("mooring-xray", "hy2_guard", "reject"),
    ])));
    assert!(!owner_guards_present(b"not json"));
}

#[test]
fn any_warning_or_error_word_fails_validation() {
    assert!(!has_warning(b"Xray 26.9.30\nConfiguration OK.\n"));
    assert!(!has_warning(b""));
    for noisy in [
        "2026/10/22 [Warning] infra/conf: deprecated",
        "WARN[0000] legacy field",
        "ERROR something",
        "+0000 FATAL[0000] decode config",
        "warning: x",
    ] {
        assert!(has_warning(noisy.as_bytes()), "{noisy}");
    }
    assert!(
        !has_warning(b"errors=0 warnings_total=0"),
        "not the words themselves"
    );
}
