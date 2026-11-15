// SPDX-License-Identifier: GPL-3.0-or-later

//! Whom the abuse guard covers (design §11.8): the users served who
//! accepted an agreement revision that states it, by the render's gate.
//! Only they leave Xray from a source address of their own, and
//! `watch.json` lists them; every other identity served leaves through
//! `exit`, as before the guard, and the files that name no coverage render
//! the same whoever is covered.

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use mooring_agent_proto::{ManagedFile, OpaqueUserId, WatchConfig, user_source};
use mooring_fixtures::Fixture;
use mooring_model::user::SuspendReason;
use mooring_model::{
    AbuseGuardAgreement, AgreementRecord, AgreementVersion, CalendarDate, NodeId, User, UserId,
};

use crate::tests::support::{GUARD_CLOSED, GUARD_OPEN, edit, fixtures, node, vps_under};
use crate::vps::VpsBundle;
use crate::vps::xray::{OutboundTag, XrayConfig, XrayOutbound, XrayRule};

fn xray(bundle: &VpsBundle) -> XrayConfig {
    serde_json::from_slice(bundle.file(ManagedFile::XrayConfig).expose_bytes()).unwrap()
}

fn watch(bundle: &VpsBundle) -> WatchConfig {
    serde_json::from_slice(bundle.file(ManagedFile::WatchConfig).expose_bytes()).unwrap()
}

fn emails(rule: &XrayRule) -> Vec<String> {
    rule.user
        .iter()
        .flatten()
        .map(ToString::to_string)
        .collect()
}

fn both_inbounds(user: &str) -> [String; 2] {
    [format!("{user}@reality"), format!("{user}@hy2")]
}

/// The users `node` serves, in id order, split into those `guard` covers
/// and the others.
fn split(
    fixture: &Fixture,
    node: &NodeId,
    guard: AbuseGuardAgreement,
) -> (Vec<String>, Vec<String>) {
    let (covered, uncovered): (Vec<_>, Vec<_>) = fixture
        .deployment
        .users()
        .values()
        .filter(|user| user.is_served_on(node))
        .partition(|user| guard.covers(user));
    let names = |users: Vec<&User>| {
        users
            .into_iter()
            .map(|user| user.id.as_str().to_owned())
            .collect()
    };
    (names(covered), names(uncovered))
}

/// `bundle` gives exactly the `covered` users a way out of their own, by
/// one rule each naming both of their emails, sends exactly the
/// `uncovered` users and then the probe through `exit` by its last rule,
/// lists the `covered` users in `watch.json`, and keeps accounting every
/// identity served.
fn assert_coverage(bundle: &VpsBundle, covered: &[String], uncovered: &[String]) {
    let xray = xray(bundle);
    let rules = xray.routing.rules.clone();
    let outbounds: Vec<XrayOutbound> = xray.outbounds.into();
    let sources: Vec<_> = outbounds
        .iter()
        .filter_map(|outbound| match outbound {
            XrayOutbound::UserExit(_, source) => Some(source.address()),
            _ => None,
        })
        .collect();
    let expected_sources: Vec<_> = covered
        .iter()
        .map(|user| user_source(&OpaqueUserId::new(user).unwrap()))
        .collect();
    assert_eq!(sources, expected_sources);
    let user_rules: Vec<Vec<String>> = rules
        .iter()
        .filter(|rule| matches!(rule.outbound_tag, OutboundTag::UserExit(_)))
        .map(emails)
        .collect();
    let expected_rules: Vec<Vec<String>> = covered
        .iter()
        .map(|user| both_inbounds(user).to_vec())
        .collect();
    assert_eq!(user_rules, expected_rules);
    let last = rules.last().unwrap();
    assert_eq!(last.outbound_tag, OutboundTag::Exit);
    assert!(last.ip.is_none() && last.inbound_tag.is_none() && last.port.is_none());
    let through_exit: Vec<String> = uncovered
        .iter()
        .flat_map(|user| both_inbounds(user))
        .chain(both_inbounds("probe"))
        .collect();
    assert_eq!(emails(last), through_exit);
    let watch = watch(bundle);
    let guarded: BTreeSet<OpaqueUserId> = covered
        .iter()
        .map(|user| OpaqueUserId::new(user).unwrap())
        .collect();
    assert_eq!(watch.guarded_users, guarded);
    assert_eq!(
        watch.emails.len(),
        2 * (covered.len() + uncovered.len() + 1)
    );
}

/// A closed gate covers no user, so every identity served leaves through
/// `exit`; a gate open at the revision every fixture user accepted covers
/// every user served. The files that name no coverage are the same.
#[test]
fn a_closed_gate_covers_no_user_and_an_open_one_every_user_served() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let closed = vps_under(&fixture, id, GUARD_CLOSED);
            let open = vps_under(&fixture, id, GUARD_OPEN);
            let (none, all) = split(&fixture, id, GUARD_CLOSED);
            assert!(none.is_empty());
            assert!(!all.is_empty(), "every fixture node serves a user");
            assert_coverage(&closed, &[], &all);
            assert_eq!(split(&fixture, id, GUARD_OPEN), (all.clone(), Vec::new()));
            assert_coverage(&open, &all, &[]);
            for file in [
                ManagedFile::Hy2Config,
                ManagedFile::WgConf,
                ManagedFile::Nftables,
                ManagedFile::ViewerKeys,
            ] {
                assert_eq!(
                    closed.file(file).expose_bytes(),
                    open.file(file).expose_bytes(),
                    "{id} {file:?}"
                );
            }
            assert_ne!(closed.digest(), open.digest());
        }
    }
}

/// Only an acceptance of the first stating revision or a later one brings
/// a user under the guard: no acceptance and an earlier revision leave the
/// user outside it. A user who is not served is in neither list.
#[test]
fn only_users_who_accepted_a_stating_revision_are_covered() {
    let revision = |number: u16| AgreementRecord {
        version: AgreementVersion::new(NonZeroU16::new(number).unwrap()),
        accepted_on: CalendarDate::parse("2026-11-15").unwrap(),
    };
    let from_two =
        AbuseGuardAgreement::since(Some(AgreementVersion::new(NonZeroU16::new(2).unwrap())));
    let mut fixture = mooring_fixtures::two_nodes_twenty_users().unwrap();
    let mut suspended = None;
    fixture.deployment = edit(&fixture.deployment, |parts| {
        for (index, user) in parts.users.iter_mut().enumerate() {
            user.agreement = match index % 4 {
                0 => Some(revision(2)),
                1 => None,
                2 => Some(revision(3)),
                _ => Some(revision(1)),
            };
        }
        parts.users[4]
            .suspend(SuspendReason::Operator, mooring_fixtures::FIXTURE_NOW)
            .unwrap();
        suspended = Some(parts.users[4].id.as_str().to_owned());
    });
    let suspended = suspended.unwrap();
    for id in [node("lon1"), node("ams1")] {
        let (covered, uncovered) = split(&fixture, &id, from_two);
        assert!(!covered.is_empty() && !uncovered.is_empty(), "{id}");
        assert!(!covered.contains(&suspended) && !uncovered.contains(&suspended));
        let version = |user: &String| {
            fixture.deployment.users()[&UserId::parse(user).unwrap()]
                .agreement
                .map(|record| record.version.get())
        };
        assert!(
            covered.iter().all(|user| version(user) >= Some(2)),
            "{covered:?}"
        );
        assert!(
            uncovered.iter().all(|user| version(user) < Some(2)),
            "{uncovered:?}"
        );
        assert_coverage(&vps_under(&fixture, &id, from_two), &covered, &uncovered);
    }
}
