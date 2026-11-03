// SPDX-License-Identifier: GPL-3.0-or-later

//! The health gate's and the validators' readings of tool output.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use mooring_agent_proto::{AgentError, EngineUser, IoOp};

use super::ENOENT;
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

/// The owner-guard rules as `nft -j list chain inet mooring output` lists
/// them on Debian 13: a match is `{"op": "==", "left", "right"}`, and a uid
/// is the number, since nft names it only when given `-u` (`--guid`,
/// nft(8)). Here `mooring-xray` is uid 998 and `mooring-hy2` uid 997.
const LISTED_GUARDS: &str = r#"{"nftables":[{"chain":{"family":"inet","table":"mooring","name":"output","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"mooring","chain":"output","handle":17,"expr":[{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":998}},{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},{"counter":"xray_guard"},{"reject":null}]}},{"rule":{"family":"inet","table":"mooring","chain":"output","handle":19,"expr":[{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":997}},{"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},{"counter":"hy2_guard"},{"reject":null}]}}]}"#;

/// `/etc/passwd` of the listing above.
fn listed_uid(user: EngineUser) -> Option<u32> {
    match user {
        EngineUser::Xray => Some(998),
        EngineUser::Hy2 => Some(997),
    }
}

#[test]
fn the_guards_are_found_as_nft_lists_them() {
    assert!(owner_guards_present(LISTED_GUARDS.as_bytes(), &listed_uid));
}

#[test]
fn both_owner_guards_must_be_present() {
    let rule = |owner: &str, counter: &str, verdict: &str| {
        format!(
            r#"{{"rule":{{"expr":[{{"match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{owner}}}}},{{"counter":"{counter}"}},{{"{verdict}":null}}]}}}}"#
        )
    };
    let chain = |rules: &[String]| format!(r#"{{"nftables":[{}]}}"#, rules.join(",")).into_bytes();
    let both = [
        rule("998", "xray_guard", "reject"),
        rule("997", "hy2_guard", "reject"),
    ];
    assert!(owner_guards_present(&chain(&both), &listed_uid));
    assert!(!owner_guards_present(&chain(&both[..1]), &listed_uid));
    assert!(!owner_guards_present(
        &chain(&[
            rule("998", "xray_guard", "accept"),
            rule("997", "hy2_guard", "reject"),
        ]),
        &listed_uid
    ));
    assert!(!owner_guards_present(
        &chain(&[
            rule("997", "xray_guard", "reject"),
            rule("998", "hy2_guard", "reject"),
        ]),
        &listed_uid
    ));
    assert!(
        !owner_guards_present(
            &chain(&[
                rule(r#""mooring-xray""#, "xray_guard", "reject"),
                rule(r#""mooring-hy2""#, "hy2_guard", "reject"),
            ]),
            &listed_uid
        ),
        "nft lists the uid, so a name is not taken for it"
    );
    let negated = |owner: &str, counter: &str| {
        format!(
            r#"{{"rule":{{"expr":[{{"match":{{"op":"!=","left":{{"meta":{{"key":"skuid"}}}},"right":{owner}}}}},{{"counter":"{counter}"}},{{"reject":null}}]}}}}"#
        )
    };
    assert!(
        !owner_guards_present(
            &chain(&[negated("998", "xray_guard"), negated("997", "hy2_guard")]),
            &listed_uid
        ),
        "a rule for every other owner is no guard"
    );
    assert!(
        !owner_guards_present(&chain(&both), &|user| match user {
            EngineUser::Xray => Some(998),
            EngineUser::Hy2 => None,
        }),
        "an account /etc/passwd lacks has no guard"
    );
    assert!(!owner_guards_present(b"not json", &listed_uid));
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

/// A generation's three configurations, in a directory of their own.
fn configs(xray: &str, hy2: &str, wg: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("xray.json"), xray).unwrap();
    std::fs::write(dir.path().join("hy2.json"), hy2).unwrap();
    std::fs::write(dir.path().join("wgexit.conf"), wg).unwrap();
    dir
}

const XRAY_ON: &str = r#"{"inbounds":[{"listen":"1.2.3.4","port":443}]}"#;
const HY2_ON: &str = r#"{"inbounds":[{"listen":"1.2.3.4","listen_port":443}]}"#;
const WG_ON: &str = "[Interface]\nListenPort = 27820\n";

#[test]
fn an_inbound_that_names_no_address_listens_on_every_address() {
    let dir = configs(
        r#"{"inbounds":[{"port":80,"settings":{"network":"tcp, udp"}}]}"#,
        r#"{"inbounds":[{"listen_port":443}]}"#,
        WG_ON,
    );
    assert_eq!(
        expected_listeners(dir.path()).unwrap(),
        BTreeSet::from([
            listener(false, None, 80),
            listener(true, None, 80),
            listener(true, None, 443),
            listener(true, None, 27820),
        ])
    );
}

/// A configuration whose listeners cannot be told is malformed, never an
/// empty set the health gate would pass.
#[test]
fn configurations_that_do_not_say_their_listeners_are_malformed() {
    let malformed = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    for (xray, hy2, wg) in [
        ("not json", HY2_ON, WG_ON),
        (r#"{"inbounds":{}}"#, HY2_ON, WG_ON),
        (
            r#"{"inbounds":[{"port":443,"settings":{"network":1}}]}"#,
            HY2_ON,
            WG_ON,
        ),
        (
            r#"{"inbounds":[{"port":443,"settings":{"network":"quic"}}]}"#,
            HY2_ON,
            WG_ON,
        ),
        (r#"{"inbounds":[{"listen":1,"port":443}]}"#, HY2_ON, WG_ON),
        (
            r#"{"inbounds":[{"listen":"vps","port":443}]}"#,
            HY2_ON,
            WG_ON,
        ),
        (
            r#"{"inbounds":[{"listen":"1.2.3.4","port":70000}]}"#,
            HY2_ON,
            WG_ON,
        ),
        (r#"{"inbounds":[{"listen":"1.2.3.4"}]}"#, HY2_ON, WG_ON),
        (XRAY_ON, r#"{"inbounds":null}"#, WG_ON),
        (XRAY_ON, r#"{"inbounds":[{"listen":"1.2.3.4"}]}"#, WG_ON),
        (XRAY_ON, HY2_ON, "[Interface]\nPrivateKey = x\n"),
        (XRAY_ON, HY2_ON, "[Interface]\nListenPort = every\n"),
    ] {
        let dir = configs(xray, hy2, wg);
        assert_eq!(
            expected_listeners(dir.path()),
            Err(malformed.clone()),
            "{xray} {hy2} {wg:?}"
        );
    }
}

#[test]
fn configurations_that_cannot_be_read_say_why() {
    for file in ["xray.json", "wgexit.conf"] {
        let dir = configs(XRAY_ON, HY2_ON, WG_ON);
        std::fs::remove_file(dir.path().join(file)).unwrap();
        assert_eq!(
            expected_listeners(dir.path()),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: Some(ENOENT),
            }),
            "{file}"
        );
    }
}

#[test]
fn lines_of_other_protocols_are_no_listeners() {
    let want = BTreeSet::from([listener(true, None, 27820)]);
    let ss = "raw UNCONN 0 0 0.0.0.0:255 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n";
    assert!(all_listening(ss, &want));
    assert!(!all_listening(
        "raw UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n",
        &want
    ));
}
