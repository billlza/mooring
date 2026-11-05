// SPDX-License-Identifier: GPL-3.0-or-later

//! `node apply`'s transaction (design §11.2): the wait for confirmation,
//! with each stage printed once and a deadline; a transaction confirmed
//! elsewhere, rolled back, or answered with another reply, which records
//! nothing; an engine blob the node lacks uploaded from the pinned
//! directory; and a keychain that cannot be read.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use mooring_agent_proto::{Generation, RequestKind, Response, TxnStage, TxnState};
use mooring_model::ipv4::PublicIpv4;

use super::apply::{apply_args, bundle_and_header, pin_of, ready, run, script_hello_and_blobs};
use super::support::{Answered, Expected, ExpectedRemote, FakeNodes, Refusals, Sent, lo0};
use super::user::{fixture, state_bytes};
use crate::error::{CommandError, EXIT_LOCAL, LocalError};
use crate::node::NodeLinks;
use crate::node::apply::wait_for_confirm;
use crate::node::dial::M7Egress;
use crate::node::ssh::{Remote, SshTarget};

fn status(harness_nodes: &FakeNodes, generation: Generation, state: TxnState) {
    harness_nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::TxnStatus,
        },
        Answered::Replied(Ok(Response::TxnStatus { generation, state })),
    );
}

fn target() -> SshTarget {
    SshTarget {
        address: PublicIpv4::new("45.67.89.10".parse().unwrap()).unwrap(),
        identity: PathBuf::from("/s/ssh/lon1/ops_ed25519"),
        known_hosts: PathBuf::from("/s/ssh/lon1/known_hosts"),
        egress: M7Egress::for_tests(lo0()),
        relay_dir: PathBuf::from("/s/ssh/lon1"),
        mooringctl: PathBuf::from("/Applications/Mooring.app/Contents/MacOS/mooringctl"),
        remote: Remote::ForcedCommand,
        deadline: None,
    }
}

/// Each stage is printed when it is first reported, however often it is
/// reported; the wait ends when the transaction awaits confirmation.
#[test]
fn each_stage_is_printed_once_until_the_transaction_awaits_confirmation() {
    let nodes = FakeNodes::default();
    let generation = Generation::new(4);
    for state in [
        TxnState::Running {
            stage: TxnStage::Validate,
        },
        TxnState::Running {
            stage: TxnStage::Validate,
        },
        TxnState::Running {
            stage: TxnStage::Swap,
        },
        TxnState::AwaitingConfirm,
    ] {
        status(&nodes, generation, state);
    }
    let mut out = Vec::new();
    wait_for_confirm(
        nodes.open(target()).as_mut(),
        &mut out,
        generation,
        Duration::ZERO,
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "  Validate\n  Swap\n");
    assert!(nodes.script.borrow().is_empty());
}

/// A transaction still running when the wait's limit has passed is the
/// error, which says the node reverts it unless it is confirmed.
#[test]
fn a_transaction_still_running_past_the_limit_is_the_error() {
    let nodes = FakeNodes::default();
    let generation = Generation::new(4);
    status(
        &nodes,
        generation,
        TxnState::Running {
            stage: TxnStage::HealthGate,
        },
    );
    let mut out = Vec::new();
    let error = wait_for_confirm(
        nodes.open(target()).as_mut(),
        &mut out,
        generation,
        Duration::ZERO,
        Duration::ZERO,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            CommandError::Local(LocalError::TxnTimeout {
                generation: 4,
                secs: 0
            })
        ),
        "{error:?}"
    );
    assert_eq!(String::from_utf8(out).unwrap(), "  HealthGate\n");
}

/// A transaction confirmed elsewhere or rolled back while the command
/// waited, and a reply to another request at any step, are the error, and
/// nothing is recorded.
#[test]
fn a_transaction_ended_elsewhere_or_another_reply_records_nothing() {
    let deployment = fixture(|_| {});
    let generation = Generation::new(deployment.config_generation().get());
    let launched = Response::TxnLaunched { generation };
    let cases: [(Vec<(RequestKind, Response)>, &str); 5] = [
        (
            vec![
                (RequestKind::Apply, launched.clone()),
                (
                    RequestKind::TxnStatus,
                    Response::TxnStatus {
                        generation,
                        state: TxnState::Committed,
                    },
                ),
            ],
            "the transaction for generation {g} was confirmed elsewhere",
        ),
        (
            vec![
                (RequestKind::Apply, launched.clone()),
                (
                    RequestKind::TxnStatus,
                    Response::TxnStatus {
                        generation,
                        state: TxnState::Reverted,
                    },
                ),
            ],
            "the transaction for generation {g} was rolled back",
        ),
        (
            vec![
                (RequestKind::Apply, launched.clone()),
                (RequestKind::TxnStatus, Response::BootstrapRevoked),
            ],
            "the node could not be reached or refused\n  caused by: the agent answered TxnStatus with BootstrapRevoked",
        ),
        (
            vec![(RequestKind::Apply, Response::BootstrapRevoked)],
            "the node could not be reached or refused\n  caused by: the agent answered Apply with BootstrapRevoked",
        ),
        (
            vec![
                (RequestKind::Apply, launched),
                (
                    RequestKind::TxnStatus,
                    Response::TxnStatus {
                        generation,
                        state: TxnState::AwaitingConfirm,
                    },
                ),
                (RequestKind::Confirm, Response::BootstrapRevoked),
            ],
            "the node could not be reached or refused\n  caused by: the agent answered Confirm with BootstrapRevoked",
        ),
    ];
    for (replies, said) in cases {
        let (mut harness, engines) = ready(deployment.clone());
        let before = state_bytes(&harness);
        let (_, header) = bundle_and_header(&harness, &engines, &deployment);
        script_hello_and_blobs(&harness, header.blobs());
        for (kind, reply) in replies {
            harness.nodes.expect(
                Expected::Request {
                    identity: "ops_ed25519",
                    remote: ExpectedRemote::Forced,
                    kind,
                },
                Answered::Replied(Ok(reply)),
            );
        }
        let outcome = run(&mut harness, &apply_args(&engines));
        let said = said.replace("{g}", &generation.get().to_string());
        assert_eq!(outcome.code, EXIT_LOCAL, "{said}");
        assert_eq!(outcome.stderr, format!("mooringctl: {said}\n"));
        assert!(harness.nodes.script.borrow().is_empty(), "{said}");
        assert_eq!(state_bytes(&harness), before, "{said}");
    }
}

/// A node that answers `Hello` with another reply is refused before
/// anything is uploaded.
#[test]
fn a_reply_to_another_request_than_hello_stops_the_apply_first() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Hello,
        },
        Answered::Replied(Ok(Response::BootstrapRevoked)),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the node could not be reached or refused\n  caused by: the agent answered Hello with BootstrapRevoked\n"
    );
    assert_eq!(harness.nodes.seen.borrow().len(), 1);
}

/// An engine the node lacks is uploaded from the pinned directory, its
/// bytes checked against the pin again as they are read.
#[test]
fn an_engine_the_node_lacks_is_uploaded_from_the_pinned_directory() {
    let deployment = fixture(|_| {});
    let (mut harness, engines) = ready(deployment.clone());
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    let xray = pin_of(&harness, "linux-amd64/xray");
    let mut present: BTreeSet<_> = header.blobs();
    assert!(present.remove(&xray), "the bundle names the node's Xray");
    script_hello_and_blobs(&harness, present);
    harness.nodes.expect(
        Expected::PutBlob {
            identity: "ops_ed25519",
        },
        Answered::Replied(Ok(Response::BlobStored { sha256: xray })),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(deployment.config_generation().get()),
        })),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains(", 1 blob(s) uploaded\n"),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        harness.nodes.seen.borrow()[2].1,
        Sent::PutBlob(xray, "stand-in for linux-amd64/xray".len())
    );
}

/// A keychain that cannot be read stops the apply before any session.
#[test]
fn a_keychain_that_cannot_be_read_stops_the_apply_before_any_session() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    *harness.keychain.lock().unwrap() = Refusals {
        get: Some(-25_293),
        put: None,
    };
    let before = state_bytes(&harness);
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .ends_with("caused by: keychain get failed with OSStatus -25293\n"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.seen.borrow().is_empty());
    assert_eq!(state_bytes(&harness), before);
    assert!(!harness.secrets.is_empty(), "the secrets are still held");
}

/// What the node confirmed cannot be recorded when the state cannot be
/// written: the apply says the state was not changed, and leaves it as it
/// was (an apply run again finds the bundle unchanged and records it).
#[test]
fn a_confirmed_apply_whose_record_fails_says_the_state_was_not_changed() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let deployment = fixture(|_| {});
    let (mut harness, engines) = ready(deployment.clone());
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(deployment.config_generation().get()),
        })),
    );
    // The node's directory and the state's lock file are there, as after
    // the node's adoption; the support directory then takes no new file.
    let support = harness.support_dir();
    fs::create_dir_all(support.join("ssh").join("lon1")).unwrap();
    super::user::store(&harness).load().unwrap();
    let before = state_bytes(&harness);
    fs::set_permissions(&support, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = run(&mut harness, &apply_args(&engines));
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state was not changed\n"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(state_bytes(&harness), before);
}
