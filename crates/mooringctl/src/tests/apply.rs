// SPDX-License-Identifier: GPL-3.0-or-later

//! `node target check|set` and `node apply` against the fixture deployment,
//! its secrets and scripted node sessions (design §11.2, §11.7, §13.2), and
//! the engine pins they check files against.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use mooring_agent_proto::{
    AgentError, CertName, Generation, HttpProbe, HttpStatus, HttpVersion, RequestKind, Response,
    Sha256Hex, TargetFacts, TargetHost, TlsGroup, TlsProbe, TlsSession, TlsVersion, TxnStage,
    TxnState,
};
use mooring_model::secret::SecretEntry;
use mooring_model::{Deployment, NodeId, Sha256Digest};
use mooring_store::{InMemorySecretStore, SecretStore};

use super::support::{Answered, Expected, ExpectedRemote, Harness, PINNED, Sent};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::node::engines::{MAC_PINS, PINS};

fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn fill(secrets: &mut InMemorySecretStore) {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    for secret_ref in fixture.secrets.refs() {
        let material = fixture.secrets.material(&secret_ref).unwrap();
        secrets
            .put(SecretEntry::new(secret_ref, material).unwrap())
            .unwrap();
    }
}

/// The fixture with its secrets, the M7 pinned, and an engine directory of
/// stand-in files pinned for the harness.
fn ready(deployment: Deployment) -> (Harness, PathBuf) {
    let mut harness = harness_with(deployment);
    harness.pin(PINNED);
    fill(&mut harness.secrets);
    let dir = harness.home.path().join("engines");
    let mut pins = Vec::new();
    for (path, _) in PINS {
        let file = dir.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let bytes = format!("stand-in for {path}");
        fs::write(&file, &bytes).unwrap();
        pins.push((
            path,
            Sha256Hex::from_bytes(*Sha256Digest::of(bytes.as_bytes()).as_bytes()).to_string(),
        ));
    }
    harness.engine_pins = pins;
    (harness, dir)
}

fn pin_of(harness: &Harness, path: &str) -> Sha256Hex {
    harness
        .engine_pins
        .iter()
        .find(|(pinned, _)| *pinned == path)
        .unwrap()
        .1
        .parse()
        .unwrap()
}

const HOST: &str = "www.quiet-target.co.uk";

/// What a node reports about a target that passes every rule.
fn good_facts() -> TargetFacts {
    TargetFacts {
        host: TargetHost::new(HOST).unwrap(),
        resolved: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 201)]),
        tls: TlsProbe::Completed(TlsSession {
            version: TlsVersion::Tls13,
            group: Some(TlsGroup::X25519),
            chain_bytes: 3100,
            chain_certs: 2,
            leaf_names: vec![CertName::new(HOST).unwrap()],
            handshake_p95_micros: 2100,
            first_flight_bytes: 4200,
        }),
        http: HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        },
    }
}

fn script_measure(harness: &Harness, present: bool, facts: TargetFacts) {
    let xray = pin_of(harness, "linux-amd64/xray");
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::HaveBlobs,
        },
        Answered::Replied(Ok(Response::Blobs {
            present: if present {
                BTreeSet::from([xray])
            } else {
                BTreeSet::new()
            },
        })),
    );
    if !present {
        harness.nodes.expect(
            Expected::PutBlob {
                identity: "ops_ed25519",
            },
            Answered::Replied(Ok(Response::BlobStored { sha256: xray })),
        );
    }
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::TargetCheck,
        },
        Answered::Replied(Ok(Response::TargetFacts(Box::new(facts)))),
    );
}

#[test]
fn target_check_uploads_xray_and_reports_the_rules_without_the_attestation() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    let before = state_bytes(&harness);
    script_measure(&harness, false, good_facts());
    let outcome = harness.run(&[
        "node",
        "target",
        "check",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with(&format!("{HOST}: resolves to 45.67.89.201\nTLS: ")),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.ends_with(&format!(
            "HTTP: 200 over Http2\n{HOST} passes every rule; `node target set` stores it with your attestation (same ASN, not a CDN)\n"
        )),
        "{}",
        outcome.stdout
    );
    let seen = harness.nodes.seen.borrow();
    assert_eq!(
        seen[1].1,
        Sent::PutBlob(
            pin_of(&harness, "linux-amd64/xray"),
            "stand-in for linux-amd64/xray".len()
        )
    );
    drop(seen);
    assert_eq!(state_bytes(&harness), before, "check stores nothing");
    // A target that redirects and is too slow is refused on both rules.
    let mut facts = good_facts();
    facts.http = HttpProbe::Responded {
        status: HttpStatus::new(301).unwrap(),
        version: HttpVersion::Http2,
        redirect: None,
    };
    if let TlsProbe::Completed(session) = &mut facts.tls {
        session.handshake_p95_micros = 9000;
    }
    script_measure(&harness, true, facts);
    let outcome = harness.run(&[
        "node",
        "target",
        "check",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("refused: HandshakeTooSlow"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("refused: Redirect"),
        "{}",
        outcome.stdout
    );
    assert!(!outcome.stdout.contains("passes every rule"));
    assert!(!outcome.stdout.contains("Attested"));
}

#[test]
fn target_set_stores_a_qualified_target_with_the_attestation() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    let generation = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation();
    script_measure(&harness, true, good_facts());
    let outcome = harness.run(&[
        "node",
        "target",
        "set",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
        "--same-asn",
        "--not-cdn",
        "--evidence",
        "https://bgp.example.net/AS0",
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("this replaces "),
        "the fixture's node had a target: {}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    let target = after.nodes()[&node_id("lon1")]
        .reality
        .target
        .clone()
        .unwrap();
    assert_eq!(target.host().as_str(), HOST);
    assert_eq!(target.ipv4().get(), Ipv4Addr::new(45, 67, 89, 201));
    assert_eq!(after.config_generation().get(), generation.get() + 1);
    // Without the attestation nothing is stored.
    let before = state_bytes(&harness);
    script_measure(&harness, true, good_facts());
    let outcome = harness.run(&[
        "node",
        "target",
        "set",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
        "--not-cdn",
        "--evidence",
        "https://bgp.example.net/AS0",
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stdout.contains("refused: SameAsnNotAttested"),
        "{}",
        outcome.stdout
    );
    assert_eq!(state_bytes(&harness), before);
}

#[test]
fn an_engine_file_that_does_not_match_its_pin_is_refused_before_any_session() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    fs::write(engines.join("linux-amd64/xray"), b"changed after the check").unwrap();
    let outcome = harness.run(&[
        "node",
        "target",
        "check",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("not to engines.lock.toml's digest"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.seen.borrow().is_empty());
}

fn script_hello_and_blobs(harness: &Harness, present: BTreeSet<Sha256Hex>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Hello,
        },
        Answered::Replied(Ok(super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)))),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::HaveBlobs,
        },
        Answered::Replied(Ok(Response::Blobs { present })),
    );
}

fn apply_args(engines: &std::path::Path) -> Vec<String> {
    [
        "node",
        "apply",
        "lon1",
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]
    .map(str::to_owned)
    .to_vec()
}

fn run(harness: &mut Harness, args: &[String]) -> super::support::Outcome {
    harness.run(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// An upload acknowledged for another blob stops the apply, which records
/// nothing.
#[test]
fn apply_refuses_an_acknowledgement_of_another_blob() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    let before = state_bytes(&harness);
    script_hello_and_blobs(&harness, BTreeSet::new());
    harness.nodes.expect(
        Expected::PutBlob {
            identity: "ops_ed25519",
        },
        Answered::Replied(Ok(Response::BlobStored {
            sha256: Sha256Hex::from_bytes([0; 32]),
        })),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("answered PutBlob with BlobStored"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(state_bytes(&harness), before);
}

/// A whole apply: every blob present, the transaction launched, one
/// running stage, awaiting confirmation, confirmed, and the node recorded
/// applied at the deployment's generation with the bundle's digest.
#[test]
fn apply_confirms_the_transaction_and_records_the_bundle() {
    let deployment = fixture(|_| {});
    let generation = deployment.config_generation();
    let (mut harness, engines) = ready(deployment.clone());
    let fixture_secrets = mooring_fixtures::two_nodes_three_users().unwrap().secrets;
    let catalog = crate::node::engines::Engines::open(
        &engines,
        &harness
            .engine_pins
            .iter()
            .map(|(path, hex)| (*path, hex.as_str()))
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .catalog()
    .clone();
    let bundle =
        mooring_render::vps::bundle(&deployment, &node_id("lon1"), &fixture_secrets, &catalog)
            .unwrap();
    let header = bundle
        .header(
            &match super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)) {
                Response::Hello(hello) => hello.host,
                _ => unreachable!(),
            },
        )
        .unwrap();
    let wire_generation = Generation::new(generation.get());
    let nodes = &harness.nodes;
    nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Hello,
        },
        Answered::Replied(Ok(super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)))),
    );
    nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::HaveBlobs,
        },
        Answered::Replied(Ok(Response::Blobs {
            present: header.blobs(),
        })),
    );
    nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::TxnLaunched {
            generation: wire_generation,
        })),
    );
    for state in [
        TxnState::Running {
            stage: TxnStage::Validate,
        },
        TxnState::AwaitingConfirm,
    ] {
        nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::TxnStatus,
            },
            Answered::Replied(Ok(Response::TxnStatus {
                generation: wire_generation,
                state,
            })),
        );
    }
    nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Confirm,
        },
        Answered::Replied(Ok(Response::Confirmed {
            generation: wire_generation,
        })),
    );
    let outcome = harness.run(&[
        "node",
        "apply",
        "lon1",
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(
        outcome.stdout,
        format!(
            "lon1: generation {generation}, bundle {}, 0 blob(s) uploaded\n  Validate\napplied: lon1 confirmed generation {generation} (node generation {}); users holding it can be exported\n",
            bundle.digest(),
            generation.get()
        )
    );
    let seen = harness.nodes.seen.borrow();
    assert_eq!(
        seen[2].1,
        Sent::Request(mooring_agent_proto::LineRequest::Apply(Box::new(header)))
    );
    drop(seen);
    let after = store(&harness).load().unwrap().deployment;
    let node = &after.nodes()[&node_id("lon1")];
    let mooring_model::node::NodeLifecycle::Applied { applied, .. } = &node.lifecycle else {
        panic!("{:?}", node.lifecycle);
    };
    assert_eq!(applied.config_generation, generation);
    assert_eq!(applied.digest, bundle.digest());
    assert_eq!(after.config_generation(), generation);
}

/// The bundle of `deployment`'s lon1 with the harness's engine pins, and
/// its header after the scripted `Hello`.
fn bundle_and_header(
    harness: &Harness,
    engines: &std::path::Path,
    deployment: &Deployment,
) -> (mooring_render::VpsBundle, mooring_agent_proto::BundleHeader) {
    let pins: Vec<(&str, &str)> = harness
        .engine_pins
        .iter()
        .map(|(path, hex)| (*path, hex.as_str()))
        .collect();
    let catalog = crate::node::engines::Engines::open(engines, &pins)
        .unwrap()
        .catalog()
        .clone();
    let secrets = mooring_fixtures::two_nodes_three_users().unwrap().secrets;
    let bundle =
        mooring_render::vps::bundle(deployment, &node_id("lon1"), &secrets, &catalog).unwrap();
    let Response::Hello(hello) = super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)) else {
        unreachable!()
    };
    let header = bundle.header(&hello.host).unwrap();
    (bundle, header)
}

/// A failed transaction is the error, and nothing is recorded.
#[test]
fn a_failed_transaction_records_nothing() {
    let deployment = fixture(|_| {});
    let (mut harness, engines) = ready(deployment.clone());
    let before = state_bytes(&harness);
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    let generation = Generation::new(deployment.config_generation().get());
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::TxnLaunched { generation })),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::TxnStatus,
        },
        Answered::Replied(Ok(Response::TxnStatus {
            generation,
            state: TxnState::Failed {
                error: AgentError::RevertedUnconfirmed { generation },
            },
        })),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: the transaction for generation {} failed on the node\n",
            generation.get()
        )),
        "{}",
        outcome.stderr
    );
    assert_eq!(state_bytes(&harness), before);
}

/// A bundle the node serves already is recorded without a transaction.
#[test]
fn an_unchanged_bundle_is_recorded_without_a_transaction() {
    let mut deployment = fixture(|_| {});
    // The deployment moved on a generation since the node applied.
    let mut parts = deployment.into_parts();
    parts.config_generation = parts.config_generation.next().unwrap();
    deployment = Deployment::try_from(parts).unwrap();
    let (mut harness, engines) = ready(deployment.clone());
    let (bundle, header) = bundle_and_header(&harness, &engines, &deployment);
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(1),
        })),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("lon1 already serves this bundle (its generation 1)")
    );
    let after = store(&harness).load().unwrap().deployment;
    let mooring_model::node::NodeLifecycle::Applied { applied, .. } =
        &after.nodes()[&node_id("lon1")].lifecycle
    else {
        panic!("not applied");
    };
    assert_eq!(applied.config_generation, deployment.config_generation());
    assert_eq!(applied.digest, bundle.digest());
}

/// The pins compiled into mooringctl are `engines.lock.toml`'s own.
#[test]
fn the_engine_pins_are_the_locks() {
    let lock = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../engines.lock.toml"),
    )
    .unwrap();
    for (path, digest) in PINS.iter().chain(&MAC_PINS) {
        let (target, file) = path.split_once('/').unwrap();
        let key = match (target, file) {
            ("geodata", file) => format!("\"{file}\" = \"{digest}\""),
            (target, "xray") => format!("\"{target}\" = \"{digest}\""),
            (target, role) => format!("\"{role}/{target}\" = \"{digest}\""),
        };
        assert!(lock.contains(&key), "{key}");
    }
}

/// A status about another generation, and a confirmation of another
/// generation, are refused, and nothing is recorded.
#[test]
fn replies_about_another_generation_are_refused() {
    let deployment = fixture(|_| {});
    let generation = Generation::new(deployment.config_generation().get());
    let other = Generation::new(generation.get() + 7);
    for (status, confirm) in [(other, generation), (generation, other)] {
        let (mut harness, engines) = ready(deployment.clone());
        let before = state_bytes(&harness);
        let (_, header) = bundle_and_header(&harness, &engines, &deployment);
        script_hello_and_blobs(&harness, header.blobs());
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::Apply,
            },
            Answered::Replied(Ok(Response::TxnLaunched { generation })),
        );
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::TxnStatus,
            },
            Answered::Replied(Ok(Response::TxnStatus {
                generation: status,
                state: TxnState::AwaitingConfirm,
            })),
        );
        if status == generation {
            harness.nodes.expect(
                Expected::Request {
                    identity: "ops_ed25519",
                    remote: ExpectedRemote::Forced,
                    kind: RequestKind::Confirm,
                },
                Answered::Replied(Ok(Response::Confirmed {
                    generation: confirm,
                })),
            );
        }
        let outcome = run(&mut harness, &apply_args(&engines));
        assert_eq!(outcome.code, EXIT_LOCAL, "{status:?} {confirm:?}");
        assert!(
            outcome.stderr.contains("the agent answered"),
            "{}",
            outcome.stderr
        );
        assert!(harness.nodes.script.borrow().is_empty());
        assert_eq!(state_bytes(&harness), before);
    }
}
