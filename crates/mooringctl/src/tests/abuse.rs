// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard's commands (design §11.8): `user suspend` and `user
//! resume` against the state, the new user's id drawn clear of every
//! user's source address, and `abuse records | cut | clear` against a
//! scripted node, with this Mac's copy of the records.

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroU16;

use mooring_agent_proto::{
    AbuseAction, AbuseCutEntry, AbuseCuts, AbuseFigures, AbuseFinding, AbuseFindings,
    AbuseGuardVersion, AbuseRecord, AbuseRecordsV1, AbuseSeq, AgentError, LineRequest,
    OpaqueUserId, RequestKind, Response, UnixTime as WireTime, user_source,
};
use mooring_daemon_core::abuse::MacAbuseRecords;
use mooring_model::{CapacityPolicy, SuspendReason, UnixTime, UserId, UserStatus};

use super::support::{Answered, Expected, ExpectedRemote, Harness, NOW, PINNED, Sent};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::{EXIT_LOCAL, LocalError};
use crate::node::NodeError;
use crate::user::fresh_user_id_from;

fn users(harness: &Harness) -> Vec<UserId> {
    store(harness)
        .load()
        .unwrap()
        .deployment
        .users()
        .keys()
        .cloned()
        .collect()
}

fn status(harness: &Harness, user: &UserId) -> UserStatus {
    store(harness).load().unwrap().deployment.users()[user].status
}

#[test]
fn suspend_and_resume_change_one_users_status_with_the_generation() {
    let mut harness = harness_with(fixture(|_| {}));
    let user = users(&harness)[0].clone();
    let before = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation();
    let outcome = harness.run(&["user", "suspend", user.as_str(), "--reason", "abuse-review"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("abuse review"),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        status(&harness, &user),
        UserStatus::Suspended {
            reason: SuspendReason::AbuseReview,
            since: UnixTime::from_secs(NOW),
        }
    );
    let after = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation();
    assert!(after > before, "a configuration change");
    // A suspended user is not suspended again, nor relabelled.
    let bytes = state_bytes(&harness);
    let outcome = harness.run(&["user", "suspend", user.as_str(), "--reason", "operator"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("cannot change this way"),
        "{}",
        outcome.stderr
    );
    assert_eq!(state_bytes(&harness), bytes);
    let outcome = harness.run(&["user", "resume", user.as_str()]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(status(&harness, &user), UserStatus::Active);
    let bytes = state_bytes(&harness);
    let outcome = harness.run(&["user", "resume", user.as_str()]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), bytes);
    let outcome = harness.run(&["user", "suspend", "aaaaaaaaaa", "--reason", "operator"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("unknown user aaaaaaaaaa"),
        "{}",
        outcome.stderr
    );
    assert_eq!(state_bytes(&harness), bytes);
}

/// A resume past the active-user cap is the store's refusal, and changes
/// nothing.
#[test]
fn a_resume_past_the_cap_is_refused() {
    let first = fixture(|_| {}).users().keys().next().unwrap().clone();
    let mut harness = harness_with(fixture(|parts| {
        for user in &mut parts.users {
            if user.id == first {
                user.status = UserStatus::Suspended {
                    reason: SuspendReason::AbuseReview,
                    since: UnixTime::from_secs(NOW - 60),
                };
            }
        }
        parts.capacity = CapacityPolicy {
            max_active_users: NonZeroU16::new(2),
        };
    }));
    let bytes = state_bytes(&harness);
    let outcome = harness.run(&["user", "resume", first.as_str()]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), bytes);
}

fn source(user: &UserId) -> std::net::Ipv4Addr {
    user_source(&OpaqueUserId::new(user.as_str()).unwrap())
}

/// A drawn id whose source address an existing user has, whatever the
/// user's status, is drawn again; a source that never stops colliding is
/// refused rather than looped on.
#[test]
fn a_new_users_id_is_drawn_clear_of_every_users_source_address() {
    let deployment = fixture(|_| {});
    let existing = deployment.users().keys().next().unwrap().clone();
    let twin = (0..u64::MAX)
        .map(UserId::from_low_bits)
        .find(|candidate| *candidate != existing && source(candidate) == source(&existing))
        .unwrap();
    let fresh = UserId::from_low_bits(7);
    assert!(
        deployment
            .users()
            .keys()
            .all(|user| source(user) != source(&fresh))
    );
    let mut draws = vec![twin.clone(), fresh.clone()].into_iter();
    assert_eq!(
        fresh_user_id_from(&deployment, || Ok(draws.next().unwrap())).unwrap(),
        fresh
    );
    let mut count = 0;
    let refused = fresh_user_id_from(&deployment, || {
        count += 1;
        Ok(twin.clone())
    })
    .unwrap_err();
    assert!(matches!(refused, LocalError::NoFreeUserSource));
    assert_eq!(count, 16);
}

fn expect(harness: &Harness, kind: RequestKind, reply: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind,
        },
        Answered::Replied(reply),
    );
}

fn figures() -> AbuseFigures {
    AbuseFigures {
        destination_buckets: 1_650,
        port_buckets: 4,
        busiest_destination_flows: 3,
        busiest_login_flows: 0,
        submission_buckets: 0,
        new_flows_per_min: Some(1_480),
        datagrams_per_sec: Some(2),
        udp_share_permille: Some(9),
        received_per_sent_permille: Some(410),
        received_bytes_per_flow: Some(132),
        refused_packets: 212,
    }
}

fn record(seq: u64, user: &UserId, action: AbuseAction) -> AbuseRecord {
    AbuseRecord {
        seq: AbuseSeq::new(seq),
        at: WireTime::from_secs(NOW - 600 + seq),
        user: OpaqueUserId::new(user.as_str()).unwrap(),
        guard: AbuseGuardVersion::V1,
        action,
        figures: match action {
            AbuseAction::Cut { .. } | AbuseAction::Alerted { .. } => Some(figures()),
            AbuseAction::OperatorCut | AbuseAction::Cleared => None,
        },
    }
}

fn cut_action() -> AbuseAction {
    AbuseAction::Cut {
        findings: AbuseFindings::of(AbuseFinding::MassContact),
    }
}

fn cuts(user: &UserId, record: u64) -> AbuseCuts {
    AbuseCuts::new(vec![AbuseCutEntry {
        user: OpaqueUserId::new(user.as_str()).unwrap(),
        since: WireTime::from_secs(NOW - 600 + record),
        record: AbuseSeq::new(record),
    }])
    .unwrap()
}

fn ready() -> (Harness, UserId) {
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    let user = users(&harness)[0].clone();
    (harness, user)
}

fn copy(harness: &Harness) -> MacAbuseRecords {
    let path = harness.support_dir().join("abuse/records.json");
    MacAbuseRecords::decode(Some(&fs::read(path).unwrap())).unwrap()
}

#[test]
fn records_are_printed_and_kept_in_the_macs_copy_once() {
    let (mut harness, user) = ready();
    let page = AbuseRecordsV1::new(
        cuts(&user, 1),
        vec![
            record(
                0,
                &user,
                AbuseAction::Alerted {
                    findings: AbuseFindings::of(AbuseFinding::PortSweep),
                },
            ),
            record(1, &user, cut_action()),
        ],
        AbuseSeq::new(2),
    )
    .unwrap();
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(page.clone()))),
    );
    let outcome = harness.run(&["abuse", "records", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with("lon1: 1 users cut\n"),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.contains(&format!("  {user} cut since ")));
    assert!(
        outcome
            .stdout
            .contains("lon1: 2 records kept on the node, 2 new to this Mac's copy")
    );
    assert!(
        outcome.stdout.contains(": cut for mass-contact [about "),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.contains(": alert for port-sweep ["));
    let node = mooring_model::NodeId::parse("lon1").unwrap();
    assert_eq!(copy(&harness).records(&node), page.records());
    let mode = fs::metadata(harness.support_dir().join("abuse/records.json"))
        .unwrap()
        .permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o600
    );
    // Again: nothing new; as JSON, the page as the node gave it.
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(page.clone()))),
    );
    let outcome = harness.run(&["abuse", "records", "lon1", "--interface", "lo0", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let printed: AbuseRecordsV1 = serde_json::from_str(outcome.stdout.trim_end()).unwrap();
    assert_eq!(printed, page);
    assert_eq!(copy(&harness).records(&node).len(), 2);
}

/// Pages are read until the node's end, each from the number after the
/// last one read.
#[test]
fn records_are_read_page_by_page() {
    let (mut harness, user) = ready();
    let page = |range: std::ops::Range<u64>, end: u64| {
        AbuseRecordsV1::new(
            AbuseCuts::EMPTY,
            range
                .map(|seq| record(seq, &user, AbuseAction::Cleared))
                .collect(),
            AbuseSeq::new(end),
        )
        .unwrap()
    };
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(page(0..512, 600)))),
    );
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(page(512..600, 600)))),
    );
    let outcome = harness.run(&["abuse", "records", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let sinces: Vec<u64> = harness
        .nodes
        .seen
        .borrow()
        .iter()
        .filter_map(|(_, sent)| match sent {
            Sent::Request(LineRequest::AbuseRecords { since }) => Some(since.get()),
            _ => None,
        })
        .collect();
    assert_eq!(sinces, [0, 512]);
    let node = mooring_model::NodeId::parse("lon1").unwrap();
    assert_eq!(copy(&harness).records(&node).len(), 600);
}

/// A record the node gives with other content than the Mac's copy holds
/// for its number is refused, and the copy is left as it was.
#[test]
fn a_record_contradicting_the_macs_copy_is_refused() {
    let (mut harness, user) = ready();
    let first = AbuseRecordsV1::new(
        AbuseCuts::EMPTY,
        vec![record(0, &user, AbuseAction::Cleared)],
        AbuseSeq::new(1),
    )
    .unwrap();
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(first))),
    );
    assert_eq!(
        harness
            .run(&["abuse", "records", "lon1", "--interface", "lo0"])
            .code,
        0
    );
    let before = fs::read(harness.support_dir().join("abuse/records.json")).unwrap();
    let other = AbuseRecordsV1::new(
        AbuseCuts::EMPTY,
        vec![record(0, &user, AbuseAction::OperatorCut)],
        AbuseSeq::new(1),
    )
    .unwrap();
    expect(
        &harness,
        RequestKind::AbuseRecords,
        Ok(Response::AbuseRecords(Box::new(other))),
    );
    let outcome = harness.run(&["abuse", "records", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("cannot be kept"),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("unlike the copy"),
        "{}",
        outcome.stderr
    );
    assert_eq!(
        fs::read(harness.support_dir().join("abuse/records.json")).unwrap(),
        before
    );
}

#[test]
fn the_operator_cuts_and_lifts_on_a_node() {
    let (mut harness, user) = ready();
    expect(
        &harness,
        RequestKind::AbuseCut,
        Ok(Response::AbuseCutDone {
            record: AbuseSeq::new(3),
            cuts: cuts(&user, 3),
        }),
    );
    let outcome = harness.run(&["abuse", "cut", "lon1", user.as_str(), "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with(&format!("lon1: user {user} is cut (record 3)")),
        "{}",
        outcome.stdout
    );
    expect(
        &harness,
        RequestKind::AbuseClear,
        Ok(Response::AbuseCleared {
            record: Some(AbuseSeq::new(4)),
            cuts: AbuseCuts::EMPTY,
        }),
    );
    let outcome = harness.run(&[
        "abuse",
        "clear",
        "lon1",
        user.as_str(),
        "--interface",
        "lo0",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!("lon1: user {user}'s cut is lifted (record 4)\nlon1: 0 users cut\n")
    );
    expect(
        &harness,
        RequestKind::AbuseClear,
        Ok(Response::AbuseCleared {
            record: None,
            cuts: AbuseCuts::EMPTY,
        }),
    );
    let outcome = harness.run(&[
        "abuse",
        "clear",
        "lon1",
        user.as_str(),
        "--interface",
        "lo0",
    ]);
    assert_eq!(
        outcome.stdout,
        format!("lon1: user {user} was not cut\nlon1: 0 users cut\n")
    );
    let sent: BTreeMap<String, String> = harness
        .nodes
        .seen
        .borrow()
        .iter()
        .filter_map(|(_, sent)| match sent {
            Sent::Request(LineRequest::AbuseCut { user }) => {
                Some(("cut".to_owned(), user.to_string()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(sent["cut"], user.as_str());
}

/// A user the deployment does not know is refused before any node is
/// asked; the node's own refusal is reported as it gives it.
#[test]
fn refusals_are_reported_and_an_unknown_user_asks_no_node() {
    let (mut harness, _) = ready();
    let outcome = harness.run(&["abuse", "cut", "lon1", "aaaaaaaaaa", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("unknown user aaaaaaaaaa"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.seen.borrow().is_empty());
    let (mut harness, user) = ready();
    expect(
        &harness,
        RequestKind::AbuseCut,
        Err(NodeError::Agent(AgentError::AbuseGuardNotInstalled)),
    );
    let outcome = harness.run(&["abuse", "cut", "lon1", user.as_str(), "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("carries no abuse guard"),
        "{}",
        outcome.stderr
    );
    let outcome = harness.run(&["abuse", "records", "ams9", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("unknown node ams9"),
        "{}",
        outcome.stderr
    );
}
