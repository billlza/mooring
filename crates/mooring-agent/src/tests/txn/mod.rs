// SPDX-License-Identifier: GPL-3.0-or-later

//! Transactions with commit-confirm, against the stand-in node of
//! [`world`], which runs every tool successfully unless a test says
//! otherwise, and the rendered golden bundle. This file holds a
//! transaction's whole path and its preconditions (design §11.2 step 1);
//! each other topic has a file of its own.

mod activation;
mod changes;
mod ending;
mod host_profile;
mod launch;
mod links;
mod prune;
mod resume;
mod rollback;
mod staging;
mod units;
mod validation;
mod world;

pub(super) use world::{WATCH, facts, golden};
use world::{WG, World, XRAY, index_of, same};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, Generation, Halt, HostFact, HostProfile, KernelIdent, PortRange, Sha256Hex,
    ShutdownReason, TxnState, UnixTime,
};

use crate::store::write_json;
use crate::txn::record::{Change, Pending, Phase, pending, set_pending};
use crate::txn::stage::BUNDLE_FILE;
use crate::txn::{self, Launched};

#[test]
fn a_transaction_stages_validates_arms_swaps_applies_and_awaits_confirmation() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, same);
    let engines = header.engines.clone();
    assert_eq!(
        world.apply_and_run(&node, header),
        TxnState::AwaitingConfirm
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let dir = world.paths.generation(Generation::new(1));
    let mode = |name: &str| fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("wgexit.conf"), 0o600);
    assert_eq!(mode("viewer_authorized_keys"), 0o644);
    assert_eq!(mode("xray.json"), 0o640);
    assert_eq!(
        fs::read_to_string(dir.join("xray.json")).unwrap(),
        golden(XRAY)
    );
    assert!(dir.join(BUNDLE_FILE).exists());
    let xray = fs::read_link(dir.join("engines/xray")).unwrap();
    assert!(xray.ends_with(format!("store/{}/xray", engines.xray)));
    assert_eq!(fs::read(&xray).unwrap(), b"xray binary");
    assert_eq!(
        fs::read_link(world.paths.nft_conf_link()).unwrap(),
        Path::new("mooring/current/nftables.conf")
    );
    assert_eq!(
        fs::read_to_string(world.paths.at("/etc/nftables.conf.pre-mooring")).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n",
        "Debian's ruleset file is kept"
    );
    assert_eq!(
        fs::read_to_string(world.paths.wg_conf_link()).unwrap(),
        golden(WG),
        "the WireGuard link resolves to the current generation"
    );
    assert!(
        fs::read_link(world.paths.geodata_link())
            .unwrap()
            .ends_with("etc/mooring/current/geodata")
    );
    let calls = node.calls();
    let validated = index_of(&calls, "xray run -test");
    assert!(
        calls[validated].starts_with("XRAY_LOCATION_ASSET="),
        "{}",
        calls[validated]
    );
    let armed = index_of(&calls, "--on-active=120");
    assert!(calls[armed].ends_with("/usr/local/lib/mooring/agent/current txn-revert 1"));
    let loaded = index_of(&calls, "/usr/sbin/nft -f ");
    assert!(
        validated < armed && armed < loaded,
        "validate, arm, then apply"
    );
    index_of(&calls, "mooring-hy2 check -c");
    index_of(&calls, "/usr/sbin/nft -c -f");
    index_of(&calls, "/usr/bin/wg-quick strip");
    index_of(&calls, "/usr/bin/systemctl restart wg-quick@wgexit.service");
    index_of(&calls, "/usr/bin/systemctl restart mooring-xray.service");
    index_of(&calls, "/usr/bin/systemctl restart mooring-hy2.service");
    index_of(&calls, "xray api statssys --server=127.0.0.1:10085");
    assert_eq!(
        pending(&world.paths).unwrap().map(|pending| pending.phase),
        Some(Phase::AwaitingConfirm)
    );
    assert!(
        !world.paths.validate_dir().join("xray.json").exists(),
        "the warning-level copies are removed"
    );
}

#[test]
fn preconditions_refuse_a_bundle_for_another_host_or_with_missing_blobs() {
    let world = World::new();
    let node = world.node(1000);
    let mut header = world.bundle(1, same);
    header.host_facts.qdisc = KernelIdent::new("fq_codel").unwrap();
    assert_eq!(
        world.apply_and_run(&node, header),
        TxnState::Failed {
            error: AgentError::HostFactsChanged {
                field: HostFact::Qdisc
            }
        }
    );
    let mut header = world.bundle(2, same);
    header.host_facts.ip_local_port_range = PortRange::new(1024, 65000).unwrap();
    let TxnState::Failed {
        error: AgentError::PortPlanConflict { .. },
    } = world.apply_and_run(&node, header)
    else {
        panic!("not a port plan conflict");
    };
    let mut header = world.bundle(3, same);
    header.engines.geoip = Sha256Hex::from_bytes([7; 32]);
    assert_eq!(
        world.apply_and_run(&node, header),
        TxnState::Failed {
            error: AgentError::BlobMissing {
                sha256: Sha256Hex::from_bytes([7; 32])
            }
        }
    );
    assert_eq!(world.current(), None);
}

#[test]
fn a_halt_during_a_transaction_keeps_the_engines_stopped() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1)))
    );
    write_json(
        &world.paths.halted(),
        &Halt {
            at: UnixTime::from_secs(1),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
    txn::run(&world.paths, &node, Generation::new(1)).unwrap();
    assert_eq!(
        world.state(1),
        TxnState::Failed {
            error: AgentError::NodeHalted
        }
    );
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("restart mooring-"))
    );
    let pending_activation = Pending {
        generation: Generation::ZERO,
        change: Change::Apply {
            previous: Generation::ZERO,
        },
        phase: Phase::AwaitingConfirm,
    };
    set_pending(&world.paths, &pending_activation).unwrap();
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(1)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(1)
        }),
        "the unit refuses a transaction that is not the pending one"
    );
}

#[test]
fn a_bundle_that_needs_a_newer_host_profile_is_refused() {
    let world = World::new();
    let node = world.node(1000);
    let mut header = world.bundle(1, same);
    let supported = HostProfile::CURRENT.version;
    header.host_profile_version = mooring_agent_proto::HostProfileVersion::new(supported.get() + 1);
    assert_eq!(
        world.apply_and_run(&node, header),
        TxnState::Failed {
            error: AgentError::HostProfileUnsupported {
                required: mooring_agent_proto::HostProfileVersion::new(supported.get() + 1),
                supported,
            }
        }
    );
    assert!(!world.paths.generation(Generation::new(1)).exists());
}
