// SPDX-License-Identifier: GPL-3.0-or-later

//! Transactions with commit-confirm, against the stand-in node of
//! [`world`], which runs every tool successfully unless a test says
//! otherwise, and the rendered golden bundle.

mod activation;
mod launch;
mod rollback;
mod staging;
mod timer;
mod units;
mod validation;
mod world;

use world::{TUNNEL_START_FAILED, WG, WG_PRIVATE_KEY, World, XRAY, idle, index_of, same};
pub(super) use world::{WATCH, facts, golden};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BundleHeader, Generation, Halt, HealthCheck, HostFact, HostFile,
    HostProfile, IoOp, KernelIdent, ManagedFile, PortRange, RollbackCause, Sha256Hex,
    ShutdownReason, StderrTail, TxnStage, TxnState, UnixTime, ValidationTool,
};

use super::FakeNode;
use crate::blobs::digest_of;
use crate::store::write_json;
use crate::txn::record::{Change, Pending, Phase, pending, set_pending};
use crate::txn::stage::BUNDLE_FILE;
use crate::txn::{self, Launched, Why};

#[test]
fn apply_records_the_transaction_and_launches_its_unit() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, same);
    assert_eq!(
        txn::apply(&world.paths, &node, header),
        Ok(Launched::Launched(Generation::new(1)))
    );
    assert_eq!(
        world.state(1),
        TxnState::Running {
            stage: TxnStage::Preconditions
        }
    );
    assert_eq!(
        fs::metadata(world.paths.txn_record(Generation::new(1)))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "the watch reads the records"
    );
    assert_eq!(
        pending(&world.paths).unwrap(),
        Some(Pending {
            generation: Generation::new(1),
            change: Change::Apply {
                previous: Generation::ZERO
            },
            phase: Phase::Launched,
        })
    );
    assert_eq!(
        node.calls(),
        vec!["/usr/bin/systemd-run --unit=mooring-txn-1 --collect --quiet /usr/local/lib/mooring/agent/current txn 1".to_owned()]
    );
}

#[test]
fn apply_refuses_while_busy_halted_or_not_newer() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, same)),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    let held = crate::store::Lock::exclusive(&world.paths.txn_lock()).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    drop(held);
    fs::remove_file(world.paths.pending()).unwrap();
    let held = crate::store::Lock::exclusive(&world.paths.txn_lock()).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::ZERO
        }),
        "the lock held with nothing pending: a confirm or revert finishing"
    );
    drop(held);
    write_json(
        &world.paths.halted(),
        &Halt {
            at: UnixTime::from_secs(1),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::NodeHalted)
    );
    fs::remove_file(world.paths.halted()).unwrap();
    world.commit(
        &node,
        world.bundle(5, |file, text| {
            if file == ManagedFile::WatchConfig {
                text.replace("10", "12")
            } else {
                text
            }
        }),
    );
    for older_or_same in [4, 5] {
        assert_eq!(
            txn::apply(&world.paths, &node, world.bundle(older_or_same, same)),
            Err(AgentError::GenerationNotNewer {
                current: Generation::new(5)
            }),
            "generation {older_or_same}"
        );
    }
}

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
fn a_change_applies_only_what_changed() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    let node = world.node(2000);
    let xray_only = world.bundle(2, idle(301));
    assert_eq!(
        world.apply_and_run(&node, xray_only),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    index_of(&calls, "restart mooring-xray.service");
    for absent in [
        "restart mooring-hy2.service",
        "/usr/sbin/nft -f ",
        "restart wg-quick@wgexit",
        "syncconf",
    ] {
        assert!(
            calls.iter().all(|call| !call.contains(absent)),
            "{absent} ran: {calls:#?}"
        );
    }
    txn::confirm(&world.paths, &node, Generation::new(2)).unwrap();
    let node = world.node(3000);
    let peer_only = world.bundle(3, |file, text| {
        if file == ManagedFile::WgConf {
            text.replace(
                "AllowedIPs = 0.0.0.0/0",
                "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 10",
            )
        } else {
            text
        }
    });
    assert_eq!(
        world.apply_and_run(&node, peer_only),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    index_of(&calls, "/usr/bin/wg syncconf wgexit");
    assert!(
        calls
            .iter()
            .all(|call| !call.contains("restart wg-quick@wgexit"))
    );
    assert!(
        !world.paths.validate_dir().join("wgexit.stripped").exists(),
        "the stripped key copy is removed"
    );
    txn::confirm(&world.paths, &node, Generation::new(3)).unwrap();
    let node = world.node(4000);
    let mtu = world.bundle(4, |file, text| {
        if file == ManagedFile::WgConf {
            text.replace("MTU = 1280", "MTU = 1300")
        } else {
            text
        }
    });
    assert_eq!(world.apply_and_run(&node, mtu), TxnState::AwaitingConfirm);
    index_of(&node.calls(), "restart wg-quick@wgexit.service");
}

#[test]
fn a_bundle_the_node_already_runs_is_unchanged() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, same);
    world.commit(&node, header.clone());
    let again = BundleHeader {
        config_generation: Generation::new(9),
        ..header
    };
    let node = world.node(2000);
    assert_eq!(
        txn::apply(&world.paths, &node, again),
        Ok(Launched::Unchanged(Generation::new(1)))
    );
    assert!(node.calls().is_empty(), "nothing ran");
    assert_eq!(
        txn::status(&world.paths, Generation::new(9)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(9)
        })
    );
}

#[test]
fn a_validator_warning_switches_nothing_and_its_output_is_scrubbed() {
    let world = World::new();
    world.faults.borrow_mut().xray_test = Some(format!(
        "[Warning] infra/conf: privateKey {WG_PRIVATE_KEY} looks weak\nConfiguration OK.\n"
    ));
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    let TxnState::Failed {
        error: AgentError::StageValidation { tool, stderr_tail },
    } = state
    else {
        panic!("{state:?}");
    };
    assert_eq!(tool, ValidationTool::Xray);
    assert!(
        !stderr_tail.as_str().contains(WG_PRIVATE_KEY),
        "{}",
        stderr_tail.as_str()
    );
    assert!(stderr_tail.as_str().contains("<redacted>"));
    assert_eq!(world.current(), None);
    assert!(!world.paths.generation(Generation::new(1)).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("--on-active")),
        "armed although nothing was switched"
    );
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("mooring-txn-revert")),
        "no timer to stop"
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
fn a_failed_health_gate_rolls_back_to_the_previous_generation() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow().missing_listeners.set(21);
    let node = world.node(2000);
    let next = world.bundle(2, |file, text| {
        if file == ManagedFile::Hy2Config {
            text.replace("fatal", "panic")
        } else {
            text
        }
    });
    assert_eq!(
        world.apply_and_run(&node, next),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!world.paths.generation(Generation::new(2)).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(node.slept(), 20, "the gate waited its whole budget once");
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-2.timer")
            > index_of(&calls, "--on-active=120"),
        "the failed transaction's timer is stopped, so the generation can be retried"
    );
}

#[test]
fn a_failed_apply_step_rolls_back_with_its_scrubbed_output() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().nft_load = true;
    let node = world.node(2000);
    let next = world.bundle(2, |file, text| {
        if file == ManagedFile::Nftables {
            text.replace("ct count over 4096", "ct count over 4000")
        } else {
            text
        }
    });
    let state = world.apply_and_run(&node, next);
    let TxnState::Failed {
        error:
            AgentError::RollbackFailed {
                cause: RollbackCause::Apply { step, stderr_tail },
                ..
            },
    } = state
    else {
        panic!("{state:?}");
    };
    assert_eq!(step, ApplyStep::Nftables);
    assert!(stderr_tail.as_str().contains("syntax error"));
    let calls = node.calls();
    let stops = calls
        .iter()
        .filter(|call| {
            call.contains("systemctl stop mooring-xray")
                || call.contains("systemctl stop mooring-hy2")
        })
        .count();
    assert_eq!(
        stops, 2,
        "a rollback that fails too stops both engines: {calls:#?}"
    );
    index_of(&calls, "add element inet mooring exit_closed");
}

#[test]
fn the_first_generation_rolls_back_to_serving_nothing() {
    let world = World::new();
    world.faults.borrow().missing_listeners.set(100);
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    let calls = node.calls();
    for unit in [
        "mooring-xray.service",
        "mooring-hy2.service",
        "wg-quick@wgexit.service",
    ] {
        index_of(&calls, &format!("systemctl stop {unit}"));
    }
    assert_eq!(
        fs::read_to_string(world.paths.nft_conf_link()).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n",
        "the node's own ruleset file is back"
    );
    assert!(!world.paths.at("/etc/nftables.conf.pre-mooring").exists());
    let reloaded = calls
        .iter()
        .rposition(|call| call.starts_with("/usr/sbin/nft -f "))
        .unwrap();
    assert!(
        reloaded > index_of(&calls, "systemctl stop wg-quick@wgexit.service"),
        "reloaded last"
    );
}

/// The tunnel's stop (`wg-quick down`) reads `/etc/wireguard/wgexit.conf`,
/// a link through `current`, so the units stop before `current` goes: the
/// rollback leaves no interface, and the next apply starts the tunnel.
#[test]
fn a_rolled_back_first_generation_leaves_no_tunnel_interface() {
    let world = World::new();
    world.follow_tunnel();
    world.faults.borrow().missing_listeners.set(100);
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert!(
        !world.paths.wgexit_accept_local().exists(),
        "the rollback took the tunnel down"
    );
    let calls = node.calls();
    assert!(
        calls.iter().all(|call| !call.contains("wg-quick down")),
        "the unit's own stop took it down: {calls:#?}"
    );
    world.faults.borrow().missing_listeners.set(0);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
    assert!(world.paths.wgexit_accept_local().exists());
}

/// An interface left by an earlier failure (lon1, 2026-10-25: a rollback
/// whose stop could not read the configuration) makes `wg-quick up` refuse.
/// The rollback to nothing takes it down with `wg-quick down` while the
/// configuration is still in place, and the next apply works.
#[test]
fn a_tunnel_interface_left_over_is_taken_down_by_the_rollback_to_nothing() {
    let world = World::new();
    world.follow_tunnel();
    fs::write(world.paths.wgexit_accept_local(), "1\n").unwrap();
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::Apply {
                    step: ApplyStep::WireGuard,
                    stderr_tail: StderrTail::scrubbed(TUNNEL_START_FAILED, &[]),
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    assert!(
        !world.paths.wgexit_accept_local().exists(),
        "the rollback took the interface down"
    );
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/wg-quick down wgexit")
            > index_of(&calls, "systemctl stop wg-quick@wgexit.service"),
        "taken down once the unit's stop had left it: {calls:#?}"
    );
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
}

/// An interface whose `wg-quick down` fails fails the rollback.
#[test]
fn a_tunnel_interface_whose_down_fails_fails_the_rollback() {
    let world = World::new();
    world.follow_tunnel();
    fs::write(world.paths.wgexit_accept_local(), "1\n").unwrap();
    world.faults.borrow_mut().wg_down_fails = true;
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RollbackFailed {
                generation: Generation::new(1),
                cause: RollbackCause::Apply {
                    step: ApplyStep::WireGuard,
                    stderr_tail: StderrTail::scrubbed(TUNNEL_START_FAILED, &[]),
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    assert!(world.paths.wgexit_accept_local().exists());
}

#[test]
fn confirm_commits_only_the_change_awaiting_it() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1)))
    );
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotAwaitingConfirm),
        "still running"
    );
    txn::run(&world.paths, &node, Generation::new(1)).unwrap();
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Err(AgentError::NotAwaitingConfirm)
    );
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Ok(Generation::new(1))
    );
    index_of(
        &node.calls(),
        "/usr/bin/systemctl stop mooring-txn-revert-1.timer",
    );
    assert_eq!(world.state(1), TxnState::Committed);
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotAwaitingConfirm)
    );
}

#[test]
fn an_unconfirmed_change_is_reverted_by_the_timer() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let next = world.bundle(2, idle(302));
    assert_eq!(world.apply_and_run(&node, next), TxnState::AwaitingConfirm);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Ok(Generation::new(2))
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(2)
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Err(AgentError::NotAwaitingConfirm),
        "a timer firing after the fact changes nothing"
    );
}

#[test]
fn rollback_reverts_now_and_disarms_the_timer() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::NotAwaitingConfirm)
    );
    let next = world.bundle(2, idle(303));
    world.apply_and_run(&node, next);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    index_of(&node.calls(), "systemctl stop mooring-txn-revert-2.timer");
}

#[test]
fn two_previous_generations_and_their_engines_are_kept() {
    let world = World::new();
    let old_xray = world.put(b"an older xray binary");
    for generation in 1..=5 {
        let node = world.node(1000 * generation);
        let mut header = world.bundle(generation, move |file, text| {
            if file == ManagedFile::WatchConfig {
                format!("{text} ") + &"x".repeat(generation as usize)
            } else {
                text
            }
        });
        if generation == 1 {
            header.engines.xray = old_xray;
        }
        world.commit(&node, header);
    }
    let kept: Vec<bool> = (1..=5)
        .map(|generation| world.paths.generation(Generation::new(generation)).exists())
        .collect();
    assert_eq!(
        kept,
        vec![false, true, true, true, true],
        "pruned before staging gen 5: gen 1 only"
    );
    assert_eq!(
        fs::read_dir(world.paths.engine_store()).unwrap().count(),
        4,
        "generation 1's own xray went with it"
    );
    assert!(
        !world
            .paths
            .engine_store()
            .join(old_xray.to_string())
            .exists()
    );
}

#[test]
fn an_agent_is_activated_after_its_self_test_and_reverted_to_the_one_before() {
    let world = World::new();
    let node = world.node(1000);
    fs::create_dir_all(world.paths.agent_dir()).unwrap();
    std::os::unix::fs::symlink("old-agent", world.paths.agent_current()).unwrap();
    let missing = Sha256Hex::from_bytes([3; 32]);
    assert_eq!(
        txn::activate::activate(&world.paths, &node, missing),
        Err(AgentError::BlobMissing { sha256: missing })
    );
    let sha = world.put(b"new agent binary");
    world.faults.borrow_mut().self_test = Some("0\n".to_owned());
    let refused = txn::activate::activate(&world.paths, &world.node(1000), sha);
    assert!(
        matches!(refused, Err(AgentError::AgentSelfTestFailed { .. })),
        "{refused:?}"
    );
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new("old-agent")
    );
    world.faults.borrow_mut().self_test = None;
    let node = world.node(1000);
    assert_eq!(
        txn::activate::activate(&world.paths, &node, sha),
        Ok(Generation::ZERO)
    );
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new(&sha.to_string())
    );
    let installed = world.paths.agent_dir().join(sha.to_string());
    assert_eq!(
        fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let calls = node.calls();
    let armed = index_of(&calls, "--on-active=120");
    assert!(
        calls[armed].ends_with("/usr/local/lib/mooring/agent/old-agent txn-revert 0"),
        "{}",
        calls[armed]
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::ZERO)
    );
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new("old-agent")
    );
    assert_eq!(
        txn::activate::activate(&world.paths, &node, sha),
        Ok(Generation::ZERO)
    );
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::ZERO),
        Ok(Generation::ZERO)
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn resume_restarts_the_current_generation_only_when_halted() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotHalted)
    );
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(2)),
        Err(AgentError::GenerationMismatch {
            current: Generation::new(1)
        })
    );
    assert!(
        world.paths.halted().exists(),
        "a refused resume keeps the marker"
    );
    let node = world.node(2000);
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Ok(Generation::new(1))
    );
    assert!(!world.paths.halted().exists());
    index_of(&node.calls(), "systemctl start mooring-xray.service");
    index_of(&node.calls(), "systemctl start mooring-hy2.service");
    world.faults.borrow_mut().restart = true;
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    let refused = txn::resume::resume(&world.paths, &world.node(3000), Generation::new(1));
    assert!(
        matches!(refused, Err(AgentError::Systemd { .. })),
        "{refused:?}"
    );
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
fn a_halt_that_arrives_mid_transaction_stops_engine_restarts() {
    let world = World::new();
    world.faults.borrow_mut().halt_on_validate = Some(world.paths.halted());
    let node = world.node(1000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    index_of(&calls, "/usr/sbin/nft -f ");
    assert!(
        calls.iter().all(|call| !call.contains("restart mooring-")),
        "an engine was restarted on a halted node: {calls:#?}"
    );
}

#[test]
fn every_credential_of_the_bundle_is_a_secret() {
    let world = World::new();
    let header = world.bundle(1, same);
    let dir = txn::stage::stage(&world.paths, Generation::new(1), &header).unwrap();
    let secrets: Vec<String> = txn::validate::secrets(&dir)
        .unwrap()
        .into_iter()
        .map(|secret| String::from_utf8(secret).unwrap())
        .collect();
    for secret in [
        WG_PRIVATE_KEY,
        "qAr2x8Vah8WO2JdHLUnMUUjqHpzO0vbDn7gKWAh17E8",
        "5f1e310100000001",
        "5f1e320100000000",
        "6d6f6f72-0101-4001-8000-000000010101",
        "6d6f6f72-0201-4001-8000-000000020101",
        "bW9vcmluZy1maXh0dXJlLXNlY3JldCEBAFpaWlpaWlo",
        "bW9vcmluZy1maXh0dXJlLXNlY3JldAMBAVpaWlpaWlo",
        "6d6f6f72-1201-4000-8000-000000120100",
    ] {
        assert!(
            secrets.iter().any(|known| known == secret),
            "{secret} is not a secret: {secrets:?}"
        );
    }
    assert!(
        !secrets.iter().any(|known| known.contains("harbour-target")),
        "a server name is no secret"
    );
}

#[test]
fn an_engine_change_restarts_both_engines() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let mut next = world.bundle(2, same);
    next.engines.xray = world.put(b"xray binary, next release");
    next.digest = digest_of(&b"a bundle with the next xray"[..]).unwrap();
    assert_eq!(world.apply_and_run(&node, next), TxnState::AwaitingConfirm);
    let calls = node.calls();
    index_of(&calls, "restart mooring-xray.service");
    index_of(&calls, "restart mooring-hy2.service");
    for absent in ["/usr/sbin/nft -f ", "restart wg-quick@wgexit", "syncconf"] {
        assert!(
            calls.iter().all(|call| !call.contains(absent)),
            "{absent} ran: {calls:#?}"
        );
    }
}

#[test]
fn a_previous_tunnel_configuration_that_cannot_be_read_restarts_the_tunnel() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    fs::remove_file(
        world
            .paths
            .generation(Generation::new(1))
            .join(ManagedFile::WgConf.file_name()),
    )
    .unwrap();
    let node = world.node(2000);
    let peer_only = world.bundle(2, |file, text| {
        if file == ManagedFile::WgConf {
            text.replace(
                "AllowedIPs = 0.0.0.0/0",
                "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 10",
            )
        } else {
            text
        }
    });
    assert_eq!(
        world.apply_and_run(&node, peer_only),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    index_of(&calls, "restart wg-quick@wgexit.service");
    assert!(calls.iter().all(|call| !call.contains("syncconf")));
}

#[test]
fn a_transaction_unit_runs_only_its_own_launched_transaction() {
    let world = World::new();
    world.faults.borrow_mut().launch = true;
    let node = world.node(1000);
    let unlaunched = txn::apply(&world.paths, &node, world.bundle(3, idle(313)));
    assert!(
        matches!(unlaunched, Err(AgentError::Systemd { .. })),
        "{unlaunched:?}"
    );
    let recorded = world.state(3);
    world.faults.borrow_mut().launch = false;
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, same)),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(3)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(3)
        }),
        "a unit for a recorded generation that is not the pending one"
    );
    assert_eq!(world.state(3), recorded);
    assert_eq!(world.current(), None);
    txn::run(&world.paths, &node, Generation::new(2)).unwrap();
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(2)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(2)
        }),
        "a second run of the unit does nothing"
    );
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
}

#[test]
fn a_unit_that_cannot_be_launched_leaves_nothing_pending() {
    let world = World::new();
    world.faults.borrow_mut().launch = true;
    let node = world.node(1000);
    let refused = txn::apply(&world.paths, &node, world.bundle(1, same));
    let Err(error @ AgentError::Systemd { .. }) = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(world.state(1), TxnState::Failed { error });
    assert_eq!(pending(&world.paths).unwrap(), None);
    world.faults.borrow_mut().launch = false;
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1))),
        "the generation can be launched again"
    );
}

#[test]
fn resume_reports_a_unit_that_does_not_come_up() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    world.faults.borrow_mut().unit_failed = true;
    let node = world.node(2000);
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Err(AgentError::HealthGate {
            failed: HealthCheck::UnitsActive
        })
    );
    assert_eq!(node.slept(), 20);
}

#[test]
fn rollback_cancels_a_transaction_that_died_before_its_swap() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, idle(311))),
        Ok(Launched::Launched(Generation::new(2)))
    );
    // What a unit that died while staging leaves behind.
    let staged = world.paths.generation(Generation::new(2));
    fs::create_dir_all(&staged).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, idle(312))),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!staged.exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert!(
        node.calls().is_empty(),
        "nothing was switched, so nothing is undone and no timer stopped: {:#?}",
        node.calls()
    );
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(2)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(2)
        }),
        "a unit that starts late finds nothing to run"
    );
}

#[test]
fn rollback_reverts_a_transaction_that_died_after_its_swap() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let next = world.bundle(2, idle(303));
    assert_eq!(
        world.apply_and_run(&world.node(2000), next),
        TxnState::AwaitingConfirm
    );
    // The unit died after the swap, before it recorded `AwaitingConfirm`.
    set_pending(
        &world.paths,
        &Pending {
            generation: Generation::new(2),
            change: Change::Apply {
                previous: Generation::new(1),
            },
            phase: Phase::Armed,
        },
    )
    .unwrap();
    let node = world.node(3000);
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Err(AgentError::NotAwaitingConfirm),
        "a transaction that never passed its health gate cannot be confirmed"
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-2.timer")
            > index_of(&calls, "restart mooring-xray.service"),
        "the timer is stopped last, once the revert is recorded"
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn a_timer_reverts_only_the_change_it_was_armed_for() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let next = world.bundle(2, idle(304));
    assert_eq!(
        txn::apply(&world.paths, &node, next),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Err(AgentError::NotAwaitingConfirm),
        "a stale timer of an earlier attempt leaves a launched retry alone"
    );
    assert!(pending(&world.paths).unwrap().is_some());
    txn::run(&world.paths, &node, Generation::new(2)).unwrap();
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(3))),
        Err(AgentError::NotAwaitingConfirm),
        "another generation's timer"
    );
    assert_eq!(world.current().as_deref(), Some("gen-2"));
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
}

#[test]
fn a_reboot_reverts_whatever_was_pending() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let next = world.bundle(2, idle(305));
    assert_eq!(
        world.apply_and_run(&world.node(2000), next),
        TxnState::AwaitingConfirm
    );
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Ok(Generation::new(2))
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(2)
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("mooring-txn-revert")),
        "the reboot took the timer with it"
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Err(AgentError::NotAwaitingConfirm)
    );
    let cut_short = world.bundle(3, idle(306));
    assert_eq!(
        txn::apply(&world.paths, &node, cut_short),
        Ok(Launched::Launched(Generation::new(3)))
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Ok(Generation::new(3)),
        "a transaction the reboot cut short"
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
}

#[test]
fn an_activation_needs_a_forced_command_to_revert_to() {
    let world = World::new();
    let node = world.node(1000);
    let sha = world.put(b"new agent binary");
    let refused = txn::activate::activate(&world.paths, &node, sha);
    assert!(
        matches!(
            refused,
            Err(AgentError::Io {
                op: IoOp::ReadState,
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
    assert!(!world.paths.agent_dir().join(sha.to_string()).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn an_activation_that_cannot_switch_stops_its_timer() {
    let world = World::new();
    fs::create_dir_all(world.paths.agent_dir()).unwrap();
    std::os::unix::fs::symlink("old-agent", world.paths.agent_current()).unwrap();
    let sha = world.put(b"new agent binary");
    let node = world.node(1000);
    txn::activate::activate(&world.paths, &node, sha).unwrap();
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap();
    // The new agent stays installed; the link cannot be replaced.
    let read_only = fs::Permissions::from_mode(0o555);
    fs::set_permissions(world.paths.agent_dir(), read_only).unwrap();
    let node = world.node(2000);
    let refused = txn::activate::activate(&world.paths, &node, sha);
    fs::set_permissions(world.paths.agent_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(
            refused,
            Err(AgentError::Io {
                op: IoOp::WriteState,
                ..
            })
        ),
        "{refused:?}"
    );
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-0.timer")
            > index_of(&calls, "--on-active=120")
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new("old-agent")
    );
}

/// Overwrites the installed copy of `file` with `text`.
fn drift(world: &World, file: HostFile, text: &str) {
    fs::write(world.paths.host_file(file), text).unwrap();
}

#[test]
fn a_transaction_converges_the_host_profile_and_applies_what_it_needs() {
    let world = World::new();
    let node = world.node(1000);
    // A node bootstrapped to the profile: nothing of it to do.
    world.commit(&node, world.bundle(1, same));
    for absent in [
        "daemon-reload",
        "sysctl",
        "reload ssh",
        "journald",
        "tmpfiles",
    ] {
        assert!(
            node.calls().iter().all(|call| !call.contains(absent)),
            "{absent}"
        );
    }
    // Local changes since, and an older recorded version.
    drift(&world, HostFile::Sysctl, "net.ipv4.ip_forward = 1\n");
    drift(
        &world,
        HostFile::WatchUnit,
        "[Service]\nExecStart=/bin/true\n",
    );
    drift(&world, HostFile::SshdDropIn, "PasswordAuthentication yes\n");
    write_json(
        &world.paths.host_profile(),
        &mooring_agent_proto::HostProfileVersion::new(1),
        0o640,
    )
    .unwrap();
    let node = world.node(2000);
    world.commit(&node, world.bundle(2, idle(100)));
    for (file, text) in HostProfile::CURRENT.files() {
        assert_eq!(
            fs::read_to_string(world.paths.host_file(file)).unwrap(),
            text,
            "{file:?}"
        );
    }
    assert_eq!(
        crate::store::read_json(&world.paths.host_profile()).unwrap(),
        Some(HostProfile::CURRENT.version)
    );
    let calls = node.calls();
    let order = [
        "txn-revert 2",
        "/usr/sbin/sysctl --system",
        "/usr/bin/systemctl daemon-reload",
        "/usr/bin/systemctl enable nftables.service wg-quick@wgexit.service mooring-xray.service mooring-hy2.service mooring-watch.service mooring-reflect.service mooring-txn-recover.service mooring-target-check.timer",
        "/usr/bin/systemctl restart mooring-watch.service",
        "/usr/bin/systemctl reload ssh.service",
        "/usr/bin/systemctl restart mooring-xray.service",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|fragment| index_of(&calls, fragment))
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{calls:#?}"
    );
    for absent in [
        "restart mooring-reflect",
        "systemd-tmpfiles",
        "systemd-journald",
    ] {
        assert!(calls.iter().all(|call| !call.contains(absent)), "{absent}");
    }
    // The generation keeps what it staged.
    let staged = world
        .paths
        .generation(Generation::new(2))
        .join(crate::hostfiles::HOST_DIR);
    for (file, text) in HostProfile::CURRENT.files() {
        assert_eq!(
            fs::read_to_string(staged.join(file.staged_name())).unwrap(),
            text
        );
    }
}

#[test]
fn a_changed_engine_unit_restarts_its_engine_alone() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    drift(&world, HostFile::Hy2Unit, "[Service]\nMemoryMax=1G\n");
    let node = world.node(2000);
    // A bundle that changes neither engine's configuration.
    world.commit(
        &node,
        world.bundle(2, |file, text| {
            if file == ManagedFile::WatchConfig {
                text.replace("\"keepalive_secs\": 10", "\"keepalive_secs\": 11")
            } else {
                text
            }
        }),
    );
    let calls = node.calls();
    index_of(&calls, "/usr/bin/systemctl restart mooring-hy2.service");
    assert!(
        calls
            .iter()
            .all(|call| !call.contains("restart mooring-xray.service")),
        "{calls:#?}"
    );
}

#[test]
fn a_rollback_puts_the_previous_generations_profile_files_back() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    // Generation 1 installed an older profile's kernel parameters.
    let older = "# an older profile\nnet.ipv4.ip_forward = 0\n";
    let staged = world
        .paths
        .generation(Generation::new(1))
        .join(crate::hostfiles::HOST_DIR);
    fs::write(staged.join(HostFile::Sysctl.staged_name()), older).unwrap();
    drift(&world, HostFile::Sysctl, older);
    world.faults.borrow().missing_listeners.set(21);
    let node = world.node(2000);
    assert!(matches!(
        world.apply_and_run(&node, world.bundle(2, idle(100))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                cause: RollbackCause::HealthGate { .. },
                ..
            }
        }
    ));
    assert_eq!(
        fs::read_to_string(world.paths.host_file(HostFile::Sysctl)).unwrap(),
        older
    );
    let applied = node
        .calls()
        .iter()
        .filter(|call| call.as_str() == "/usr/sbin/sysctl --system")
        .count();
    assert_eq!(applied, 2, "once forward, once back");
}

#[test]
fn the_host_validators_check_the_staged_generation() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    let generation = world.paths.generation(Generation::new(1));
    let staged_dir = generation.display().to_string();
    let faults = world.faults.borrow();
    assert_eq!(
        faults.sshd_config.borrow().as_deref(),
        Some(
            format!("Include {staged_dir}/host/sshd.conf\nInclude /etc/ssh/sshd_config\n").as_str()
        )
    );
    let verified = faults.verified.borrow();
    assert_eq!(verified.len(), 7);
    let check = verified
        .iter()
        .find(|text| text.contains("target-watch"))
        .unwrap();
    assert!(check.contains(&format!("ConditionPathExists={staged_dir}/watch.json")));
    let xray = verified
        .iter()
        .find(|text| text.contains("Description=Mooring Xray"))
        .unwrap();
    assert!(xray.contains(&format!(
        "ExecStart={staged_dir}/engines/xray run -c {staged_dir}/xray.json"
    )));
    assert!(!xray.contains("/etc/mooring/current"), "{xray}");
    assert!(
        verified
            .iter()
            .all(|text| !text.contains("/etc/mooring/current"))
    );
    let calls = node.calls();
    let order = [
        "/usr/bin/wg-quick strip ",
        "/usr/sbin/sshd -t -f ",
        "/usr/bin/systemd-analyze verify ",
        "txn-revert 1",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|fragment| index_of(&calls, fragment))
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    // The scratch copies are gone.
    assert!(!world.paths.validate_dir().join("sshd_config").exists());
    assert!(!world.paths.validate_dir().join("units").exists());
}

/// A host validator's rejection, before anything is switched: the staged
/// generation goes and no timer is armed.
fn rejected(world: &World, node: &FakeNode) -> (ValidationTool, String) {
    let state = world.apply_and_run(node, world.bundle(1, same));
    let TxnState::Failed {
        error: AgentError::StageValidation { tool, stderr_tail },
    } = state
    else {
        panic!("not a validation failure: {state:?}");
    };
    assert_eq!(world.current(), None);
    assert!(!world.paths.generation(Generation::new(1)).exists());
    assert!(node.calls().iter().all(|call| !call.contains("txn-revert")));
    (tool, stderr_tail.as_str().to_owned())
}

#[test]
fn a_missing_kernel_parameter_is_rejected_by_name() {
    let world = World::new();
    fs::remove_file(world.paths.at("/proc/sys/net/ipv4/tcp_notsent_lowat")).unwrap();
    let (tool, tail) = rejected(&world, &world.node(1000));
    assert_eq!(tool, ValidationTool::SysctlKeys);
    assert!(
        tail.contains("/proc/sys/net/ipv4/tcp_notsent_lowat"),
        "{tail}"
    );
}

#[test]
fn an_sshd_warning_is_rejected() {
    let world = World::new();
    world.faults.borrow_mut().sshd_warns = true;
    let (tool, tail) = rejected(&world, &world.node(1000));
    assert_eq!(tool, ValidationTool::Sshd);
    assert!(tail.contains("Deprecated option"), "{tail}");
}

#[test]
fn a_unit_systemd_complains_about_is_rejected_even_with_a_zero_exit() {
    let world = World::new();
    world.faults.borrow_mut().analyze_errors = true;
    let (tool, tail) = rejected(&world, &world.node(1000));
    assert_eq!(tool, ValidationTool::SystemdAnalyze);
    assert!(tail.contains("Unknown key name"), "{tail}");
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

#[test]
fn a_missing_engine_group_fails_the_stage_with_its_account() {
    let world = World::new();
    let group = fs::read_to_string(world.paths.group()).unwrap();
    let kept: String = group
        .lines()
        .filter(|line| !line.starts_with("mooring-xray:"))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(world.paths.group(), kept).unwrap();
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::AccountMissing {
                account: mooring_agent_proto::HostAccount::Xray,
            }
        }
    );
}

/// The groups the tests' user is in besides its primary one.
fn other_groups(primary: u32) -> Vec<u32> {
    let output = std::process::Command::new("id").arg("-G").output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|gid| gid.parse().unwrap())
        .filter(|gid| *gid != primary)
        .collect()
}

#[test]
fn each_configuration_belongs_to_its_readers_group_and_no_one_elses() {
    use std::os::unix::fs::MetadataExt;
    let world = World::new();
    let (_, primary) = super::own_ids(&world.paths);
    let others = other_groups(primary);
    let [xray, hy2, state, ..] = others.as_slice() else {
        panic!("this test needs a user in three groups besides its own: {others:?}");
    };
    fs::write(
        world.paths.group(),
        format!(
            "root:x:{primary}:\nmooring:x:{state}:\nmooring-xray:x:{xray}:\nmooring-hy2:x:{hy2}:\n"
        ),
    )
    .unwrap();
    let dir = txn::stage::stage(&world.paths, Generation::new(1), &world.bundle(1, same)).unwrap();
    let owner = |file: ManagedFile| {
        let meta = fs::metadata(dir.join(file.file_name())).unwrap();
        (meta.gid(), meta.mode() & 0o777)
    };
    assert_eq!(owner(ManagedFile::XrayConfig), (*xray, 0o640));
    assert_eq!(owner(ManagedFile::Hy2Config), (*hy2, 0o640));
    assert_eq!(owner(ManagedFile::WatchConfig), (*state, 0o640));
    assert_eq!(owner(ManagedFile::WgConf), (primary, 0o600));
    assert_eq!(owner(ManagedFile::Nftables), (primary, 0o640));
    assert_eq!(owner(ManagedFile::ViewerKeys), (primary, 0o644));
}

#[test]
fn a_validator_that_fails_without_a_word_is_still_a_rejection() {
    let world = World::new();
    world.faults.borrow_mut().sshd_fails_silently = true;
    let (tool, tail) = rejected(&world, &world.node(1000));
    assert_eq!(tool, ValidationTool::Sshd);
    assert_eq!(tail, "");
}

#[test]
fn a_changed_tunnel_drop_in_reloads_systemd_alone() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    drift(&world, HostFile::TunnelDropIn, "[Unit]\n");
    let node = world.node(2000);
    world.commit(&node, world.bundle(2, idle(100)));
    let calls = node.calls();
    index_of(&calls, "/usr/bin/systemctl daemon-reload");
    index_of(&calls, "/usr/bin/systemctl enable ");
    for absent in [
        "restart mooring-watch",
        "restart mooring-reflect",
        "sysctl",
        "reload ssh",
    ] {
        assert!(calls.iter().all(|call| !call.contains(absent)), "{absent}");
    }
}
