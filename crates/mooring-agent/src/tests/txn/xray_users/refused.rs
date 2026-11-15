// SPDX-License-Identifier: GPL-3.0-or-later

//! `Restarts::Refused` (design §13.6): a change the running engines take as
//! they run goes live; anything else is refused before anything is staged
//! for good, validated, armed or switched; and a change applied so is
//! undone through Xray's API, whatever undoes it, with no restart and no
//! stop.

use std::collections::BTreeSet;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, HealthCheck, HostFile, ManagedFile, RestartNeed, Restarts,
    RollbackCause, StderrTail, TxnState,
};
use serde_json::Value;

use super::super::world::{World, assert_unswitched, idle, same};
use super::{
    ADU, INBOUNDS, RESTART_XRAY, XRAY_ACTIVE, adding, client, count, exactly, held, listed,
};
use crate::blobs::digest_of;
use crate::tests::FakeNode;
use crate::txn::{self, Why};

/// What no transaction under `Refused` may run on a node that serves
/// users: a restart, start or stop of an engine or the tunnel, a reload of
/// the ruleset, a host-profile step, a tunnel's peers synchronised, or the
/// gate closed.
const DISRUPTIONS: [&str; 15] = [
    "systemctl restart mooring-",
    "systemctl start mooring-",
    "systemctl stop mooring-xray",
    "systemctl stop mooring-hy2",
    "systemctl restart wg-quick",
    "systemctl start wg-quick",
    "systemctl stop wg-quick",
    "wg-quick down",
    "nft -f",
    "daemon-reload",
    "sysctl --system",
    "systemd-tmpfiles",
    "systemctl reload",
    "wg syncconf",
    "add element inet mooring exit_closed",
];

/// Requires that `calls` hold none of [`DISRUPTIONS`].
fn assert_undisrupted(calls: &[String], why: &str) {
    for disruption in DISRUPTIONS {
        assert_eq!(
            count(calls, disruption),
            0,
            "{why}: {disruption}: {calls:#?}"
        );
    }
}

/// The removal `rmu` was asked: each inbound's tag and emails, in order.
fn removals(world: &World) -> Vec<(String, Vec<String>)> {
    world.faults.borrow().xray.removals.borrow().clone()
}

/// The clients user `n` holds, by live inbound, as `rmu` names them.
fn emails_of(n: u8) -> Vec<(String, Vec<String>)> {
    INBOUNDS
        .iter()
        .map(|(tag, inbound)| {
            let email = client(n, inbound)["email"].as_str().unwrap().to_owned();
            ((*tag).to_owned(), vec![email])
        })
        .collect()
}

/// Generation 1 made by `first` committed with restarts allowed, then
/// generation 2 made by `second` applied with restarts refused, on `node`.
fn refused_after(
    world: &World,
    first: impl Fn(ManagedFile, String) -> String,
    second: impl Fn(ManagedFile, String) -> String,
    node: &FakeNode,
) -> TxnState {
    world.commit(&world.node(1000), world.bundle(1, first));
    world.apply_and_run_with(node, world.bundle(2, second), Restarts::Refused)
}

/// The needs named, as a set.
fn needs(needs: &[RestartNeed]) -> AgentError {
    AgentError::RestartNotAllowed {
        needs: needs.iter().copied().collect::<BTreeSet<_>>(),
    }
}

/// Requires that generation 2, refused for `needs`, switched nothing and
/// ran nothing that serves users, validated nothing and armed no timer.
fn assert_refused(world: &World, node: &FakeNode, expected: &[RestartNeed], why: &str) {
    assert_unswitched(world, 2, Some("gen-1"), needs(expected));
    let calls = node.calls();
    assert_undisrupted(&calls, why);
    for absent in [
        "xray run -test",
        "txn-revert",
        "xray api adu",
        "xray api rmu",
    ] {
        assert_eq!(count(&calls, absent), 0, "{why}: {absent}: {calls:#?}");
    }
    for (tag, _) in INBOUNDS {
        assert_eq!(held(world, tag), listed(world, 1, tag), "{why}: {tag}");
    }
}

#[test]
fn clients_added_alone_go_live_with_restarts_refused() {
    let world = World::new();
    let node = world.node(2000);
    assert_eq!(
        refused_after(&world, same, adding(&[1, 2]), &node),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    assert_undisrupted(&calls, "an opening");
    assert_eq!(count(&calls, ADU), 1, "{calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{tag}");
    }
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Ok(Generation::new(2))
    );
}

/// An edit of `file` alone, by `edit`.
fn editing(
    file: ManagedFile,
    edit: fn(String) -> String,
) -> impl Fn(ManagedFile, String) -> String {
    move |edited, text| if edited == file { edit(text) } else { text }
}

fn hy2_edited(text: String) -> String {
    let edited = text.replace("\"level\": \"fatal\"", "\"level\": \"error\"");
    assert_ne!(edited, text);
    edited
}

fn nft_edited(text: String) -> String {
    text + "# a rule changed\n"
}

fn wg_edited(text: String) -> String {
    let edited = text.replace("MTU = 1280", "MTU = 1300");
    assert_ne!(edited, text);
    edited
}

fn watch_edited(text: String) -> String {
    let edited = text.replace("\"keepalive_secs\": 10", "\"keepalive_secs\": 11");
    assert_ne!(edited, text);
    edited
}

fn viewers_edited(text: String) -> String {
    text + "restrict,command=\"/usr/local/lib/mooring/agent/current --role viewer\" \
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH viewer\n"
}

/// An edit of a generation's files, file by file.
type Edit = Box<dyn Fn(ManagedFile, String) -> String>;

#[test]
fn a_change_the_engines_cannot_take_as_they_run_is_refused_unswitched() {
    let cases: [(&str, Edit, &[RestartNeed]); 5] = [
        (
            "hy2.json",
            Box::new(editing(ManagedFile::Hy2Config, hy2_edited)),
            &[RestartNeed::Hy2Config],
        ),
        (
            "nftables.conf",
            Box::new(editing(ManagedFile::Nftables, nft_edited)),
            &[RestartNeed::Nftables],
        ),
        (
            "wgexit.conf",
            Box::new(editing(ManagedFile::WgConf, wg_edited)),
            &[RestartNeed::WireGuard],
        ),
        (
            "an idle timeout with a client added",
            Box::new(|file, text| adding(&[1])(file, idle(301)(file, text))),
            &[RestartNeed::XrayConfig],
        ),
        (
            "the ruleset and Hysteria 2 with a client added",
            Box::new(|file, text| {
                let text = adding(&[1])(file, text);
                match file {
                    ManagedFile::Nftables => nft_edited(text),
                    ManagedFile::Hy2Config => hy2_edited(text),
                    _ => text,
                }
            }),
            &[RestartNeed::Nftables, RestartNeed::Hy2Config],
        ),
    ];
    for (why, edit, expected) in cases {
        let world = World::new();
        let node = world.node(2000);
        refused_after(&world, same, edit, &node);
        assert_refused(&world, &node, expected, why);
    }
}

#[test]
fn a_removed_client_is_refused_with_restarts_refused() {
    let world = World::new();
    let node = world.node(2000);
    refused_after(&world, adding(&[1]), same, &node);
    assert_refused(&world, &node, &[RestartNeed::XrayConfig], "a removal");
}

#[test]
fn a_running_generation_without_the_handler_service_is_refused() {
    let world = World::new();
    let node = world.node(2000);
    refused_after(
        &world,
        super::without_handler,
        |file, text| adding(&[1])(file, super::without_handler(file, text)),
        &node,
    );
    assert_refused(&world, &node, &[RestartNeed::XrayApi], "no HandlerService");
}

#[test]
fn a_stopped_xray_is_refused_rather_than_started() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow().xray.stopped.set(true);
    let node = world.node(2000);
    world.apply_and_run_with(&node, world.bundle(2, adding(&[1])), Restarts::Refused);
    assert_refused(&world, &node, &[RestartNeed::XrayStopped], "stopped");
    assert_eq!(exactly(&node.calls(), XRAY_ACTIVE).len(), 1);
}

/// An engine that runs anew is named by `Engines` alone, whatever else its
/// configuration changes, and Xray is asked nothing.
#[test]
fn an_engine_change_is_refused_with_restarts_refused() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let mut next = world.bundle(2, |file, text| match file {
        ManagedFile::Hy2Config => hy2_edited(text),
        _ => adding(&[1])(file, text),
    });
    next.engines.xray = world.put(b"xray binary, next release");
    next.digest = digest_of(&b"a bundle with the next xray and a client"[..]).unwrap();
    world.apply_and_run_with(&node, next, Restarts::Refused);
    assert_refused(&world, &node, &[RestartNeed::Engines], "the next xray");
    assert_eq!(exactly(&node.calls(), XRAY_ACTIVE), [] as [usize; 0]);
}

/// The agent the node runs carries another host profile's text than the
/// one installed, as after an upgrade: its files would be applied.
#[test]
fn a_host_profile_change_is_refused_with_restarts_refused() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let installed = world.paths.host_file(HostFile::ALL[0]);
    let text = std::fs::read_to_string(&installed).unwrap();
    std::fs::write(&installed, text + "# as an older profile had it\n").unwrap();
    let node = world.node(2000);
    world.apply_and_run_with(&node, world.bundle(2, adding(&[1])), Restarts::Refused);
    assert_refused(&world, &node, &[RestartNeed::HostProfile], "a host file");
}

/// The watch reads its configuration at each tick, and sshd the viewers'
/// keys at each login: a change of either alone restarts nothing, so it is
/// applied with restarts refused.
#[test]
fn files_their_readers_read_again_are_applied_with_restarts_refused() {
    for (why, file, edit) in [
        (
            "watch.json",
            ManagedFile::WatchConfig,
            watch_edited as fn(String) -> String,
        ),
        ("viewer keys", ManagedFile::ViewerKeys, viewers_edited),
    ] {
        let world = World::new();
        let node = world.node(2000);
        assert_eq!(
            refused_after(&world, same, editing(file, edit), &node),
            TxnState::AwaitingConfirm,
            "{why}"
        );
        let calls = node.calls();
        assert_undisrupted(&calls, why);
        assert_eq!(
            count(&calls, "xray api"),
            1,
            "only the health gate's statssys: {calls:#?}"
        );
        assert_eq!(world.current().as_deref(), Some("gen-2"), "{why}");
    }
}

/// With no generation in place nothing is served, so nothing can drop: a
/// node's first generation is applied as ever.
#[test]
fn a_first_generation_is_applied_with_restarts_refused() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        world.apply_and_run_with(&node, world.bundle(1, same), Restarts::Refused),
        TxnState::AwaitingConfirm
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
}

/// Generation 1 committed, then generation 2 adding user 1 applied live
/// with restarts refused, `fault` set on the stand-in before it runs.
fn opened_live(fault: impl Fn(&World)) -> (World, FakeNode, TxnState) {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    fault(&world);
    let node = world.node(2000);
    let state = world.apply_and_run_with(&node, world.bundle(2, adding(&[1])), Restarts::Refused);
    (world, node, state)
}

/// Requires the node back on generation 1, its running Xray holding
/// exactly generation 1's clients, with nothing that serves users
/// restarted, started or stopped.
fn assert_undone(world: &World, node: &FakeNode, why: &str) {
    assert_eq!(world.current().as_deref(), Some("gen-1"), "{why}");
    assert!(
        !world.paths.generation(Generation::new(2)).is_dir(),
        "{why}"
    );
    for (tag, _) in INBOUNDS {
        assert_eq!(held(world, tag), listed(world, 1, tag), "{why}: {tag}");
    }
    assert_undisrupted(&node.calls(), why);
}

#[test]
fn a_live_opening_the_engine_refuses_is_undone_without_a_restart() {
    let (world, node, state) = opened_live(|world| world.faults.borrow_mut().xray.refuses = true);
    let TxnState::Failed {
        error:
            AgentError::RolledBack {
                generation,
                cause: RollbackCause::Apply { step, .. },
            },
    } = state
    else {
        panic!("{state:?}");
    };
    assert_eq!(
        (generation, step),
        (Generation::new(2), ApplyStep::XrayUsers)
    );
    assert_undone(&world, &node, "refused by the engine");
    assert_eq!(removals(&world), [], "the engine took nothing to take back");
}

#[test]
fn a_live_opening_that_fails_its_health_gate_is_undone_through_the_api() {
    let (world, node, state) = opened_live(|world| world.faults.borrow().missing_listeners.set(21));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners,
                },
            }
        }
    );
    assert_undone(&world, &node, "the health gate");
    assert_eq!(removals(&world), emails_of(1));
    let calls = node.calls();
    assert!(
        super::super::world::index_of(&calls, "xray api rmu")
            > super::super::world::index_of(&calls, ADU),
        "{calls:#?}"
    );
}

/// What the confirm timer and a `Rollback` each leave of a change awaiting
/// confirmation that was applied live.
#[test]
fn every_revert_undoes_a_live_opening_through_the_api() {
    for (why, outcome) in [
        (
            Why::Unconfirmed(Generation::new(2)),
            TxnState::Failed {
                error: AgentError::RevertedUnconfirmed {
                    generation: Generation::new(2),
                },
            },
        ),
        (Why::Requested, TxnState::Reverted),
    ] {
        let (world, opening, state) = opened_live(|_| {});
        assert_eq!(state, TxnState::AwaitingConfirm, "{why:?}");
        assert_undisrupted(&opening.calls(), "the opening");
        let node = world.node(3000);
        assert_eq!(
            txn::revert_pending(&world.paths, &node, why),
            Ok(Generation::new(2)),
            "{why:?}"
        );
        assert_eq!(world.state(2), outcome, "{why:?}");
        assert_undone(&world, &node, &format!("{why:?}"));
        assert_eq!(removals(&world), emails_of(1), "{why:?}");
    }
}

/// After a reboot the change is reverted by restarting: the reboot dropped
/// every connection, and `txn-recover` runs as soon as the engines have
/// started, before Xray's API need answer. The restart loads the previous
/// file's clients.
#[test]
fn a_reboot_reverts_a_live_opening_by_restarting() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Ok(Generation::new(2))
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(2),
            },
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert_eq!(exactly(&calls, RESTART_XRAY).len(), 1, "{calls:#?}");
    assert_eq!(count(&calls, "xray api rmu"), 0, "{calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 1, tag), "{tag}");
    }
}

/// An undo the engine refuses fails as `LiveRollbackFailed`: the links are
/// back, and nothing is restarted or stopped, nor the gate closed.
#[test]
fn a_live_undo_that_fails_stops_nothing() {
    let (world, node, state) = opened_live(|world| {
        world.faults.borrow().missing_listeners.set(21);
        world.faults.borrow_mut().xray.rmu_refuses = true;
    });
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::LiveRollbackFailed {
                generation: Generation::new(2),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners,
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_undisrupted(&node.calls(), "a failed undo");
    for (tag, inbound) in INBOUNDS {
        assert!(
            held(&world, tag).contains(&client(1, inbound)),
            "the client the engine would not give up is still held: {tag}"
        );
    }
}

/// The timer's revert of a live opening whose undo fails reports the
/// undo's own failure, and stops nothing either.
#[test]
fn a_reverted_live_opening_whose_undo_fails_stops_nothing() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    world.faults.borrow_mut().xray.unreachable = true;
    let node = world.node(3000);
    let error = AgentError::LiveRollbackFailed {
        generation: Generation::new(2),
        cause: RollbackCause::Apply {
            step: ApplyStep::XrayUndo,
            stderr_tail: StderrTail::scrubbed(
                b"xray api inbounduser failed: failed to dial 127.0.0.1:10085\n",
                &[],
            ),
        },
    };
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Err(error.clone())
    );
    assert_eq!(world.state(2), TxnState::Failed { error });
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_undisrupted(&node.calls(), "a failed revert");
}

/// A stopped Xray holds nothing to take back, and reads the previous
/// files when it starts: the undo asks it nothing.
#[test]
fn a_live_undo_asks_a_stopped_xray_nothing() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    world.faults.borrow().xray.stopped.set(true);
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert_undisrupted(&calls, "a stopped xray");
    assert_eq!(count(&calls, "xray api"), 0, "{calls:#?}");
}

/// Xray stops between the check before the swap and the opening after it:
/// the live step refuses to start it, naming why, and the change is undone
/// live.
#[test]
fn an_xray_that_stops_after_the_check_is_not_started() {
    let (world, node, state) =
        opened_live(|world| world.faults.borrow().xray.stops_after_asked.set(Some(1)));
    let TxnState::Failed {
        error:
            AgentError::RolledBack {
                cause: RollbackCause::Apply { step, stderr_tail },
                ..
            },
    } = state
    else {
        panic!("{state:?}");
    };
    assert_eq!(step, ApplyStep::XrayUsers);
    assert!(
        stderr_tail.as_str().contains("XrayStopped"),
        "{}",
        stderr_tail.as_str()
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert_undisrupted(&calls, "stopped after the check");
    assert_eq!(count(&calls, "xray api"), 0, "{calls:#?}");
}

/// A live change that left `xray.json` as it was gave Xray nothing to take
/// back: its undo asks Xray nothing, even one whose API is gone.
#[test]
fn a_live_undo_of_files_xray_does_not_read_asks_it_nothing() {
    let world = World::new();
    let opening = world.node(2000);
    assert_eq!(
        refused_after(
            &world,
            same,
            editing(ManagedFile::WatchConfig, watch_edited),
            &opening
        ),
        TxnState::AwaitingConfirm
    );
    world.faults.borrow_mut().xray.unreachable = true;
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert_undisrupted(&calls, "a watch-only undo");
    assert_eq!(count(&calls, "xray api"), 0, "{calls:#?}");
}

/// The previous generation's host-profile files go back as text with the
/// links, and nothing is run for them.
#[test]
fn a_live_undo_puts_the_previous_host_files_back_as_text() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    let installed = world.paths.host_file(HostFile::Sysctl);
    std::fs::write(&installed, "# as a change might have left it\n").unwrap();
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    let staged = world
        .paths
        .generation(Generation::new(1))
        .join("host")
        .join(HostFile::Sysctl.staged_name());
    assert_eq!(
        std::fs::read_to_string(&installed).unwrap(),
        std::fs::read_to_string(staged).unwrap()
    );
    assert_undisrupted(&node.calls(), "host files as text");
}

/// A file to go back to whose clients are not as Mooring renders them
/// cannot be restored client by client: the undo fails, visibly, and
/// changes nothing in the engine.
#[test]
fn an_undo_to_a_file_not_as_rendered_fails_visibly() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    let file = world
        .paths
        .generation(Generation::new(1))
        .join(ManagedFile::XrayConfig.file_name());
    let mut config: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    for inbound in config["inbounds"].as_array_mut().unwrap() {
        if inbound["tag"] == "reality-in" {
            inbound["settings"]["fallbacks"] = Value::Array(Vec::new());
        }
    }
    std::fs::write(&file, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let node = world.node(3000);
    let error = AgentError::LiveRollbackFailed {
        generation: Generation::new(2),
        cause: RollbackCause::Apply {
            step: ApplyStep::XrayUndo,
            stderr_tail: StderrTail::scrubbed(
                b"reality-in in xray.json lists its clients otherwise than Mooring renders them",
                &[],
            ),
        },
    };
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(error.clone())
    );
    assert_eq!(world.state(2), TxnState::Failed { error });
    let calls = node.calls();
    assert_undisrupted(&calls, "a file not as rendered");
    assert_eq!(count(&calls, "xray api"), 0, "{calls:#?}");
}

/// A removal the engine refuses is the undo's own failure, which names the
/// user still held after the rest was done.
#[test]
fn a_removal_the_engine_refuses_names_who_is_still_held() {
    let (world, _, state) = opened_live(|_| {});
    assert_eq!(state, TxnState::AwaitingConfirm);
    world.faults.borrow_mut().xray.rmu_refuses = true;
    let node = world.node(3000);
    let Err(AgentError::LiveRollbackFailed {
        generation,
        cause: RollbackCause::Apply { step, stderr_tail },
    }) = txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2)))
    else {
        panic!("not a failed live undo");
    };
    assert_eq!(
        (generation, step),
        (Generation::new(2), ApplyStep::XrayUndo)
    );
    let tail = stderr_tail.as_str();
    assert!(tail.contains("failed to remove user"), "{tail}");
    assert!(
        tail.ends_with(
            "reality-in holds other users than the file it is back on: not held [], held but \
             not in the file [\"fxuserzzz1@reality\"], held otherwise []"
        ),
        "{tail}"
    );
    assert_eq!(removals(&world), emails_of(1));
    assert_undisrupted(&node.calls(), "a refused removal");
}

/// The undo brings the running Xray to the previous file's clients
/// whatever it holds: a client the previous file lists, held with another
/// id, is taken out and added back as the file has it.
#[test]
fn a_live_undo_adds_back_what_the_previous_file_lists() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, adding(&[1])));
    let mut other = client(1, "reality");
    other["id"] = Value::from("6ba7b811-9dad-41d1-80b4-00c04fd430c9");
    {
        let faults = world.faults.borrow();
        let mut held = faults.xray.held.borrow_mut();
        let reality = held.get_mut("reality-in").unwrap();
        reality.retain(|held| held["email"] != client(1, "reality")["email"]);
        reality.push(other);
    }
    let node = world.node(2000);
    let state =
        world.apply_and_run_with(&node, world.bundle(2, adding(&[1, 2])), Restarts::Refused);
    assert!(
        matches!(
            state,
            TxnState::Failed {
                error: AgentError::RolledBack {
                    cause: RollbackCause::Apply {
                        step: ApplyStep::XrayUsers,
                        ..
                    },
                    ..
                }
            }
        ),
        "{state:?}"
    );
    assert_undone(&world, &node, "held otherwise");
    assert_eq!(count(&node.calls(), ADU), 2, "the opening, then the undo's");
}
