// SPDX-License-Identifier: GPL-3.0-or-later

//! The allowlist table: its paths, its tree shape, which leaves are secret,
//! which parse reads which leaf, and its copy in `docs/measurements/M2.md`.

use std::collections::BTreeSet;

use crate::router::netgear::{LeafSet, LeafShape, LeafUse, NetgearLeaf, Segment};

const PATHS: [&str; 49] = [
    "session.userRole",
    "session.passwordCooloff",
    "session.secToken",
    "general.model",
    "general.apiVersion",
    "general.FWversion",
    "general.webAppVersion",
    "general.devTemperature",
    "general.upTime",
    "power.PMState",
    "power.battChargeLevel",
    "power.batteryState",
    "power.charging",
    "power.battChargeSource",
    "power.batteryTemperature",
    "sim.SPN",
    "wwan.connection",
    "wwan.currentNWserviceType",
    "wwan.currentPSserviceType",
    "wwan.registerNetworkDisplay",
    "wwan.sessDuration",
    "wwan.dataTransferredRx",
    "wwan.dataTransferredTx",
    "wwan.thermalState",
    "wwan.ca.SCCcount",
    "wwan.lteBandInfo[].isPcc",
    "wwan.lteBandInfo[].band",
    "wwan.lteBandInfo[].dlBandwidth",
    "wwan.signalStrength.rsrp",
    "wwan.signalStrength.rsrq",
    "wwan.signalStrength.sinr",
    "wwan.signalStrength.rssi",
    "wwan.signalStrength.nr5gRsrp",
    "wwan.signalStrength.nr5gRsrq",
    "wwan.signalStrength.nr5gSinr",
    "wwanadv.MCC",
    "wwanadv.MNC",
    "wwanadv.curBand",
    "wifi.enabled",
    "wifi.status",
    "wifi.guest.status",
    "wifi.aux.status",
    "wifi.clientCount",
    "wifi.offload.enabled",
    "ethernet.offload.enabled",
    "router.UPNPenabled",
    "ra.enabled",
    "insight.active",
    "sms.unreadMsgs",
];

/// The allowlist is exactly these 49 paths, in this order; nothing else of
/// `model.json` is ever read.
#[test]
fn the_allowlist_holds_exactly_the_documented_paths() {
    let paths: Vec<String> = NetgearLeaf::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(paths, PATHS);
}

/// The table is a tree the walk follows without ambiguity: distinct paths,
/// none a prefix of another, and the only element segment is the carrier
/// list's (`wwan.lteBandInfo[]`). The same rule is asserted at compile
/// time; this checks it independently, on the rendered paths.
#[test]
fn the_allowlist_is_a_tree_of_distinct_leaves() {
    let paths: Vec<String> = NetgearLeaf::ALL.iter().map(ToString::to_string).collect();
    let distinct: BTreeSet<&String> = paths.iter().collect();
    assert_eq!(distinct.len(), paths.len());
    for a in &paths {
        for b in &paths {
            if a != b {
                assert!(
                    !b.starts_with(&format!("{a}.")) && !b.starts_with(&format!("{a}[")),
                    "{a} is a prefix of {b}"
                );
            }
        }
    }
    for leaf in NetgearLeaf::ALL {
        let segments = leaf.segments();
        let each: Vec<usize> = segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| **segment == Segment::Each)
            .map(|(index, _)| index)
            .collect();
        match each.as_slice() {
            [] => {}
            [2] => assert_eq!(
                &segments[..2],
                [Segment::Key("wwan"), Segment::Key("lteBandInfo")],
                "{leaf}"
            ),
            _ => panic!("{leaf} iterates an array other than the carrier list"),
        }
    }
}

/// Only the session token is secret, so it is the only allowlisted leaf
/// the redactor does not keep.
#[test]
fn only_the_session_token_is_secret() {
    let secret: Vec<NetgearLeaf> = NetgearLeaf::ALL
        .iter()
        .copied()
        .filter(|leaf| leaf.is_secret())
        .collect();
    assert_eq!(secret, [NetgearLeaf::SessionToken]);
    assert_eq!(
        NetgearLeaf::SessionToken.shape(),
        LeafShape::Secret { max: 128 }
    );
}

fn set(set: LeafSet) -> BTreeSet<NetgearLeaf> {
    NetgearLeaf::ALL
        .iter()
        .copied()
        .filter(|leaf| set.contains(*leaf))
        .collect()
}

/// The session parse reads the login fields and the model; the status
/// parse reads everything else and the role and model, never the token or
/// the cool-off; together they read the whole table, and the redactor
/// keeps exactly what they read minus the token.
#[test]
fn session_and_status_leaves_cover_the_allowlist_and_status_never_reads_the_token() {
    use NetgearLeaf as L;
    let session = set(LeafSet::Session);
    let status = set(LeafSet::Status);
    let kept = set(LeafSet::Kept);
    assert_eq!(
        session,
        BTreeSet::from([
            L::SessionUserRole,
            L::SessionPasswordCooloff,
            L::SessionToken,
            L::GeneralModel
        ])
    );
    assert!(!status.contains(&L::SessionToken));
    assert!(!status.contains(&L::SessionPasswordCooloff));
    assert_eq!(status.len(), 47);
    let all: BTreeSet<NetgearLeaf> = NetgearLeaf::ALL.iter().copied().collect();
    assert_eq!(
        session.union(&status).copied().collect::<BTreeSet<_>>(),
        all
    );
    let mut read = session.union(&status).copied().collect::<BTreeSet<_>>();
    read.remove(&L::SessionToken);
    assert_eq!(kept, read);
    for leaf in [L::SessionUserRole, L::GeneralModel] {
        assert_eq!(leaf.used_by(), LeafUse::Both, "{leaf}");
    }
}

/// A leaf's row as `docs/measurements/M2.md` writes it.
fn row(number: usize, leaf: NetgearLeaf) -> String {
    let shape = match leaf.shape() {
        LeafShape::Bool => "Bool".to_owned(),
        LeafShape::Int => "Int".to_owned(),
        LeafShape::Text {
            min,
            max,
            digit_run,
        } => format!("Text {min}..={max}, digit run ≤ {digit_run}"),
        LeafShape::Line { max, digit_run } => {
            format!("Line 1..={max} + LF, digit run ≤ {digit_run}")
        }
        LeafShape::Digits { min, max } => format!("Digits {min}..={max}"),
        LeafShape::Secret { max } => format!("Secret 1..={max}"),
    };
    let read_by = match leaf.used_by() {
        LeafUse::Session => "session",
        LeafUse::Status => "status",
        LeafUse::Both => "session, status",
    };
    format!("| {number} | `{leaf:?}` | `{leaf}` | {shape} | {read_by} |")
}

/// `docs/measurements/M2.md` lists the allowlist between its markers, one
/// row per leaf, exactly as the table in the code has it.
#[test]
fn the_m2_allowlist_table_is_the_code() {
    let document = include_str!("../../../../../docs/measurements/M2.md");
    let (_, rest) = document
        .split_once("<!-- allowlist:start -->\n")
        .expect("M2.md has the allowlist start marker");
    let (table, _) = rest
        .split_once("<!-- allowlist:end -->")
        .expect("M2.md has the allowlist end marker");
    let rows: Vec<&str> = table
        .lines()
        .filter(|line| line.starts_with("| ") && !line.starts_with("| #"))
        .collect();
    let expected: Vec<String> = NetgearLeaf::ALL
        .iter()
        .enumerate()
        .map(|(index, leaf)| row(index + 1, *leaf))
        .collect();
    assert_eq!(rows, expected);
}
