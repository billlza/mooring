// SPDX-License-Identifier: GPL-3.0-or-later

//! The host profile's files (design §8.6) through a transaction: staged
//! with the generation, installed with the swap, what each needs once
//! installed (`sysctl --system`, a daemon reload, its service restarted or
//! reloaded), and the previous generation's files put back by a rollback.
//! A node's first generation applies the whole profile, its retry after a
//! rollback to nothing included; a later one only what changed.

use std::fs;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, HostFile, HostProfile, ManagedFile, RollbackCause, TxnState,
};

use super::world::{World, idle, index_of, same};
use crate::store::write_json;

/// Overwrites the installed copy of `file` with `text`.
fn drift(world: &World, file: HostFile, text: &str) {
    fs::write(world.paths.host_file(file), text).unwrap();
}

#[test]
fn a_transaction_converges_the_host_profile_and_applies_what_it_needs() {
    let world = World::new();
    let node = world.node(1000);
    // A node's first generation applies its whole profile, though
    // Bootstrap installed the same text.
    world.commit(&node, world.bundle(1, same));
    let calls = node.calls();
    for step in [
        "/usr/bin/systemd-tmpfiles --create",
        "/usr/sbin/sysctl --system",
        "/usr/bin/systemctl daemon-reload",
        "/usr/bin/systemctl restart mooring-watch.service",
        "/usr/bin/systemctl restart mooring-reflect.service",
        "/usr/bin/systemctl restart systemd-journald.service",
        "/usr/bin/systemctl reload ssh.service",
    ] {
        index_of(&calls, step);
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
fn a_later_generation_applies_none_of_an_unchanged_profile() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    world.commit(&node, world.bundle(2, idle(100)));
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

/// A first generation rolled back to nothing leaves the profile files it
/// installed in place, never applied: here the tunnel's start failed
/// before any of the profile's steps ran. Its retry applies the whole
/// profile, though the files' text is unchanged by then.
#[test]
fn a_retried_first_generation_applies_the_whole_profile() {
    let world = World::new();
    // Bootstrap installed an older profile's kernel parameters.
    drift(&world, HostFile::Sysctl, "# an older profile\n");
    world.faults.borrow_mut().restart = true;
    let node = world.node(1000);
    assert!(matches!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::RolledBack {
                cause: RollbackCause::Apply {
                    step: ApplyStep::WireGuard,
                    ..
                },
                ..
            }
        }
    ));
    assert!(
        node.calls().iter().all(|call| !call.contains("sysctl")),
        "the attempt stopped before the profile's steps"
    );
    let (_, text) = HostProfile::CURRENT
        .files()
        .into_iter()
        .find(|(file, _)| *file == HostFile::Sysctl)
        .unwrap();
    assert_eq!(
        fs::read_to_string(world.paths.host_file(HostFile::Sysctl)).unwrap(),
        text,
        "installed, never applied"
    );
    world.faults.borrow_mut().restart = false;
    let retry = world.node(2000);
    world.commit(&retry, world.bundle(1, same));
    let calls = retry.calls();
    for step in [
        "/usr/bin/systemd-tmpfiles --create",
        "/usr/sbin/sysctl --system",
        "/usr/bin/systemctl daemon-reload",
        "/usr/bin/systemctl restart systemd-journald.service",
        "/usr/bin/systemctl reload ssh.service",
    ] {
        index_of(&calls, step);
    }
}
