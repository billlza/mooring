// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/usage-fixtures/`: the `mooring-user-usage` document that
//! `mooringctl user usage` writes with `--out` (`UserUsageHistory::pretty`,
//! as here) and prints with `--json` as one line, generated here and
//! pinned byte for byte: `all.json` with every part, `bins-only.json`
//! without the totals. Between them every key holds a value somewhere, and
//! every key that can be `null` but `alias` is `null` somewhere; the CLI's
//! tests show a user without an alias.
//!
//! To change one, change the builder, write [`encode`]'s output over the
//! file, and review the diff.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use mooring_model::{Deployment, PublicAlias};

use super::{
    Hy2, Reality, detail, email, later_than_midnight, monthly, node, now, other, subject, traffic,
};
use crate::tests::support::{at, edited, probe};
use crate::usage::history::{UsageScope, UserUsageHistory};
use crate::usage::{CollectedUsage, NodeUsageHistory};

const ALL: &[u8] = include_bytes!("../../../../../contract/usage-fixtures/all.json");
const BINS_ONLY: &[u8] = include_bytes!("../../../../../contract/usage-fixtures/bins-only.json");

/// A fixture file's content: the document as `--out` writes it.
fn encode(history: &UserUsageHistory) -> Vec<u8> {
    history.pretty().unwrap()
}

/// The fixture with the subject given an alias.
fn aliased() -> Deployment {
    let subject = subject();
    edited(|parts| {
        for user in &mut parts.users {
            if user.id == subject {
                user.alias = Some(PublicAlias::from_random_bytes([
                    0x9b, 0x18, 0x6d, 0x0e, 0x55,
                ]));
            }
        }
    })
}

/// The stored document, read back as `user usage` reads it:
/// - lon1, observed before it served on 2026-10-01: the day of 2026-11-03
///   and the 24 hours from 2026-11-04 12:00 in detail, so a gap in the
///   hours and one day; October, final, and November so far, so a
///   lifetime.
/// - ams1, adopted before origins were recorded: September 2025, folded
///   by now, and November so far; no detail and no lifetime.
fn stored() -> CollectedUsage {
    let (subject, other) = (subject(), other());
    let mut collected = CollectedUsage::default();
    collected.observe_unserved(node("lon1"), at("2026-10-01", 0));
    let mut lon = collected.node(&node("lon1")).unwrap().clone();
    detail(
        &mut lon,
        "lon1",
        at("2026-11-03", 0),
        at("2026-11-04", 0),
        &[
            (
                at("2026-11-03", 20 * 3600 + 900),
                vec![
                    (email(&subject, Reality), traffic(1200, 34_000)),
                    (email(&other, Reality), traffic(50, 60)),
                ],
            ),
            (
                at("2026-11-03", 21 * 3600),
                vec![(email(&subject, Hy2), traffic(300, 4_100))],
            ),
        ],
    );
    detail(
        &mut lon,
        "lon1",
        at("2026-11-04", 12 * 3600),
        now(),
        &[
            (
                at("2026-11-04", 14 * 3600 + 300),
                vec![(probe(Reality), traffic(0, 500))],
            ),
            (
                at("2026-11-05", 9 * 3600 + 1800),
                vec![
                    (email(&subject, Reality), traffic(80, 2_400)),
                    (email(&subject, Hy2), traffic(7, 90)),
                ],
            ),
        ],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-10",
        at("2026-10-31", 86_340),
        at("2026-11-01", 180),
        vec![(email(&subject, Reality), traffic(9_000, 120_000))],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![
            (email(&subject, Reality), traffic(1_300, 36_500)),
            (email(&subject, Hy2), traffic(307, 4_190)),
            (email(&other, Reality), traffic(50, 60)),
            (probe(Reality), traffic(0, 500)),
        ],
    );
    collected.set_node(node("lon1"), lon);
    let mut ams = NodeUsageHistory::default();
    monthly(
        &mut ams,
        "ams1",
        "2025-09",
        at("2025-09-30", 86_340),
        at("2025-10-01", 120),
        vec![(email(&subject, Hy2), traffic(640, 18_000))],
    );
    monthly(
        &mut ams,
        "ams1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![],
    );
    collected.set_node(node("ams1"), ams);
    CollectedUsage::decode(&collected.encode().unwrap()).unwrap()
}

fn generated(scope: UsageScope) -> Vec<u8> {
    encode(
        &stored()
            .user_history(&aliased(), &subject(), now(), scope)
            .unwrap(),
    )
}

#[test]
fn the_fixtures_are_what_their_builder_generates() {
    for (name, scope, fixture) in [
        ("all.json", UsageScope::All, ALL),
        ("bins-only.json", UsageScope::BinsOnly, BINS_ONLY),
    ] {
        let generated = generated(scope);
        assert!(
            generated == fixture,
            "contract/usage-fixtures/{name} is not what its builder generates:\n{}",
            String::from_utf8_lossy(&generated)
        );
    }
}

/// The keys of the object `value`. Their order is the fixtures' own,
/// pinned byte for byte above; this says which keys an object has.
fn keys(value: &serde_json::Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

/// Every key of the document is there in both fixtures, `null` for what is
/// absent, and nothing else is.
#[test]
fn every_key_is_always_present() {
    let all: serde_json::Value = serde_json::from_slice(ALL).unwrap();
    let bins: serde_json::Value = serde_json::from_slice(BINS_ONLY).unwrap();
    let set = |names: &[&'static str]| names.iter().copied().collect::<BTreeSet<_>>();
    let top = [
        "format",
        "version",
        "scope",
        "generated_at",
        "user",
        "alias",
        "status",
        "retention",
        "nodes",
    ];
    assert_eq!(keys(&all), set(&top));
    assert_eq!(keys(&bins), set(&top));
    assert_eq!(all["format"], "mooring-user-usage");
    assert_eq!(all["version"], 1);
    assert_eq!(bins["scope"], "bins_only");
    for document in [&all, &bins] {
        for node in document["nodes"].as_array().unwrap() {
            assert_eq!(
                keys(node),
                set(&["node", "stage", "hourly", "daily", "totals"])
            );
            for tier in ["hourly", "daily"] {
                assert_eq!(keys(&node[tier]), set(&["held", "bins"]));
            }
        }
    }
    for node in all["nodes"].as_array().unwrap() {
        assert_eq!(
            keys(&node["totals"]),
            set(&["months", "folded", "lifetime"])
        );
        for month in node["totals"]["months"].as_array().unwrap() {
            assert_eq!(
                keys(month),
                set(&["month", "counted_through", "final", "bytes"])
            );
        }
    }
    for node in bins["nodes"].as_array().unwrap() {
        assert!(node["totals"].is_null());
    }
    // ams1 has folded months and no lifetime, lon1 the other way round.
    assert_eq!(
        keys(&all["nodes"][0]["totals"]["folded"]),
        set(&["before", "complete", "bytes"])
    );
    assert_eq!(all["nodes"][0]["totals"]["folded"]["complete"], false);
    assert!(all["nodes"][0]["totals"]["lifetime"].is_null());
    assert!(all["nodes"][1]["totals"]["folded"].is_null());
    assert_eq!(
        keys(&all["nodes"][1]["totals"]["lifetime"]),
        set(&["reality", "hy2"])
    );
    // The document holds neither the subject's label nor another user's id.
    let text = String::from_utf8(ALL.to_vec()).unwrap();
    let deployment = aliased();
    let row = deployment.users().get(&subject()).unwrap();
    assert!(!text.contains(row.label.as_str()));
    assert!(!text.contains(other().as_str()));
}

/// The directory holds exactly the fixtures and their licence sidecars.
#[test]
fn the_fixture_directory_holds_exactly_the_fixtures() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/usage-fixtures");
    let found: BTreeSet<String> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected: BTreeSet<String> = [
        "all.json",
        "all.json.license",
        "bins-only.json",
        "bins-only.json.license",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(found, expected);
    for licence in ["all.json.license", "bins-only.json.license"] {
        assert_eq!(
            fs::read_to_string(directory.join(licence)).unwrap(),
            "SPDX-License-Identifier: GPL-3.0-or-later\n"
        );
    }
}
