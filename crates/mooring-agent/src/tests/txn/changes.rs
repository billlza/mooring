// SPDX-License-Identifier: GPL-3.0-or-later

//! Applying only what changed between two generations (design §11.2 step
//! 5): the ruleset, the tunnel restarted or its peers synchronised, and
//! the engines restarted only when what they run changed, never while the
//! node is halted.

use std::fs;

use mooring_agent_proto::{Generation, ManagedFile, TxnState};

use super::world::{World, idle, index_of, same};
use crate::blobs::digest_of;
use crate::txn;

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

/// A hook only wg-quick runs changes nothing `wg syncconf` sets, so a
/// generation that adds, changes or removes one restarts the tunnel: the
/// abuse guard's `local` route for the users' source addresses is a
/// `PostUp` line (design §11.8), and with `syncconf` alone every user's
/// bind would fail until the next reboot.
#[test]
fn a_changed_hook_restarts_the_tunnel() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let accept_local = "PostUp = sysctl -qw net.ipv4.conf.%i.accept_local=1";
    let route = "PostUp = ip -4 route replace local 198.18.0.0/15 dev %i table local";
    let added = format!("{accept_local}\n{route}");
    let changed = added.replace("/15", "/16");
    for (generation, hooks) in [
        (2, added.as_str()),
        (3, changed.as_str()),
        (4, accept_local),
    ] {
        let node = world.node(1000 * (generation + 1));
        let bundle = world.bundle(generation, |file, text| {
            if file == ManagedFile::WgConf {
                text.replace(accept_local, hooks)
            } else {
                text
            }
        });
        assert_eq!(
            world.apply_and_run(&node, bundle),
            TxnState::AwaitingConfirm,
            "generation {generation}"
        );
        let calls = node.calls();
        index_of(&calls, "restart wg-quick@wgexit.service");
        assert!(
            calls.iter().all(|call| !call.contains("syncconf")),
            "generation {generation}: {calls:#?}"
        );
        txn::confirm(&world.paths, &node, Generation::new(generation)).unwrap();
    }
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
    // The watch and the reflector restart with the first generation's
    // profile: neither serves anyone, and the watch keeps the gate closed.
    for engine in ["mooring-xray.service", "mooring-hy2.service"] {
        assert!(
            calls
                .iter()
                .all(|call| !call.contains(&format!("restart {engine}"))),
            "an engine was restarted on a halted node: {calls:#?}"
        );
    }
}
