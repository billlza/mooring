// SPDX-License-Identifier: GPL-3.0-or-later

//! Opening users on the running Xray (design §13.6): clients added and
//! nothing else reach the running engine through its API, with no restart,
//! and are read back; anything else restarts it, as do every rollback and
//! an engine that is not running. What the engine holds afterwards
//! decides.

mod classify;
#[cfg(target_os = "linux")]
mod lab;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, ManagedFile, RollbackCause, StderrTail, TxnState,
};
use serde_json::{Value, json};

use super::world::{World, idle, index_of, same};
use crate::blobs::digest_of;
use crate::txn;

/// User `n`'s client of the inbound whose emails end `@<inbound>`
/// (`reality` or `hy2`), as the renderer lists it.
pub(super) fn client(n: u8, inbound: &str) -> Value {
    let (prefix, flow) = match inbound {
        "reality" => ("6ba7b81", "xtls-rprx-vision"),
        _ => ("7ca7b81", ""),
    };
    json!({
        "id": format!("{prefix}{n}-9dad-41d1-80b4-00c04fd430c8"),
        "flow": flow,
        "level": 0,
        "email": format!("fxuserzzz{n}@{inbound}"),
    })
}

/// The live inbounds, by tag, with the email suffix of their clients.
const INBOUNDS: [(&str, &str); 2] = [("reality-in", "reality"), ("hy2-loop-in", "hy2")];

/// The clients of the inbound tagged `tag` in `config`.
pub(super) fn clients<'a>(config: &'a mut Value, tag: &str) -> &'a mut Vec<Value> {
    config["inbounds"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|inbound| inbound["tag"] == tag)
        .unwrap()["settings"]["clients"]
        .as_array_mut()
        .unwrap()
}

/// The rendered `xray.json` `text` with user `n`'s two clients added for
/// each `n` in `users`, as taking a spare user or resuming one changes it.
pub(super) fn with_clients(text: &str, users: &[u8]) -> String {
    let mut config: Value = serde_json::from_str(text).unwrap();
    for (tag, inbound) in INBOUNDS {
        clients(&mut config, tag).extend(users.iter().map(|n| client(*n, inbound)));
    }
    serde_json::to_string_pretty(&config).unwrap()
}

/// An edit that adds clients as [`with_clients`] does.
fn adding(users: &'static [u8]) -> impl Fn(ManagedFile, String) -> String {
    move |file, text| {
        if file == ManagedFile::XrayConfig {
            with_clients(&text, users)
        } else {
            text
        }
    }
}

/// An edit that leaves the running generation without `HandlerService`, as
/// every generation rendered before it was.
fn without_handler(file: ManagedFile, text: String) -> String {
    if file == ManagedFile::XrayConfig {
        let edited = text.replace("\"HandlerService\",\n", "");
        assert_ne!(edited, text);
        edited
    } else {
        text
    }
}

/// How many of `calls` contain `fragment`.
fn count(calls: &[String], fragment: &str) -> usize {
    calls.iter().filter(|call| call.contains(fragment)).count()
}

const RESTART_XRAY: &str = "/usr/bin/systemctl restart mooring-xray.service";
const ADU: &str = "xray api adu --server=127.0.0.1:10085 ";
/// Whether Xray runs, asked of its unit alone (the health gate asks of
/// every unit at once, in one call that begins with this one's text).
const XRAY_ACTIVE: &str = "/usr/bin/systemctl is-active mooring-xray.service";

/// The positions of the calls that are exactly `call`.
fn exactly(calls: &[String], call: &str) -> Vec<usize> {
    calls
        .iter()
        .enumerate()
        .filter_map(|(at, made)| (made == call).then_some(at))
        .collect()
}

/// The clients the stand-in Xray holds in the inbound tagged `tag`, in the
/// order it took them.
fn held(world: &World, tag: &str) -> Vec<Value> {
    world.faults.borrow().xray.held.borrow()[tag].clone()
}

/// The clients of `tag` in generation `generation`'s `xray.json`.
fn listed(world: &World, generation: u64, tag: &str) -> Vec<Value> {
    let file = world
        .paths
        .generation(Generation::new(generation))
        .join(ManagedFile::XrayConfig.file_name());
    let mut config: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    clients(&mut config, tag).clone()
}

#[test]
fn clients_added_alone_reach_the_running_xray_without_a_restart() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1, 2]))),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    for absent in [RESTART_XRAY, "restart mooring-hy2.service"] {
        assert_eq!(count(&calls, absent), 0, "{absent} ran: {calls:#?}");
    }
    let active = exactly(&calls, XRAY_ACTIVE);
    assert_eq!(active.len(), 1, "{calls:#?}");
    let active = active[0];
    let adu = index_of(&calls, ADU);
    let reality = index_of(
        &calls,
        "xray api inbounduser --server=127.0.0.1:10085 -tag=reality-in",
    );
    let hy2 = index_of(
        &calls,
        "xray api inbounduser --server=127.0.0.1:10085 -tag=hy2-loop-in",
    );
    assert!(active < adu && adu < reality && reality < hy2, "{calls:#?}");
    index_of(&calls, "xray api statssys");
    // The request holds the added clients and what builds them, nothing
    // else: no stream settings, so not REALITY's private key either.
    let requests = world.faults.borrow().xray.requests.borrow().clone();
    let request: Vec<Value> = requests
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .collect();
    let inbound = |tag: &str, listen: &str, port: u16, inbound: &str| {
        json!({
            "tag": tag,
            "listen": listen,
            "port": port,
            "protocol": "vless",
            "settings": {
                "decryption": "none",
                "clients": [client(1, inbound), client(2, inbound)],
            },
        })
    };
    assert_eq!(
        request,
        [json!({ "inbounds": [
            inbound("reality-in", "45.67.89.10", 443, "reality"),
            inbound("hy2-loop-in", "127.0.0.1", 10443, "hy2"),
        ]})]
    );
    assert!(
        !world.paths.validate_dir().join("xray-users.json").exists(),
        "the request, which holds the clients' ids, is removed"
    );
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{tag}");
    }
    // The generation is current, so a restart or a reboot loads the same
    // clients.
    assert_eq!(world.current().as_deref(), Some("gen-2"));
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Ok(Generation::new(2))
    );
}

/// A client the running engine holds already, as after a crash restart
/// that read the new file, is refused by `adu`, which still exits 0; the
/// inbounds then hold the file's clients, so the transaction goes on.
#[test]
fn a_client_held_already_is_no_failure() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world
        .faults
        .borrow()
        .xray
        .held
        .borrow_mut()
        .get_mut("reality-in")
        .unwrap()
        .push(client(1, "reality"));
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::AwaitingConfirm
    );
    assert_eq!(count(&node.calls(), RESTART_XRAY), 0);
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{tag}");
    }
}

/// Generation 1 made by `first` committed, then generation 2 made by
/// `second` applied: Xray is restarted, and nothing is added through its
/// API.
fn assert_restarted(
    first: impl Fn(ManagedFile, String) -> String,
    second: impl Fn(ManagedFile, String) -> String,
    why: &str,
) {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, first));
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, second)),
        TxnState::AwaitingConfirm,
        "{why}"
    );
    let calls = node.calls();
    assert_eq!(count(&calls, RESTART_XRAY), 1, "{why}: {calls:#?}");
    assert_eq!(count(&calls, "xray api adu"), 0, "{why}: {calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{why}: {tag}");
    }
}

#[test]
fn a_removed_client_restarts_xray() {
    assert_restarted(adding(&[1]), same, "a removal");
}

#[test]
fn clients_added_with_any_other_change_restart_xray() {
    assert_restarted(
        same,
        |file, text| adding(&[1])(file, idle(301)(file, text)),
        "an idle timeout changed too",
    );
    assert_restarted(
        adding(&[1]),
        |file, text| adding(&[1])(file, text).replace("6ba7b811-9dad", "6ba7b819-9dad"),
        "a client's id changed",
    );
}

/// The first generation an upgraded agent applies adds `HandlerService`,
/// which a running Xray cannot take: it restarts once, and its later
/// openings go live.
#[test]
fn a_running_xray_without_the_handler_service_restarts() {
    assert_restarted(
        without_handler,
        |file, text| adding(&[1])(file, without_handler(file, text)),
        "no HandlerService",
    );
}

#[test]
fn a_previous_configuration_that_cannot_be_read_restarts_xray() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    std::fs::remove_file(
        world
            .paths
            .generation(Generation::new(1))
            .join(ManagedFile::XrayConfig.file_name()),
    )
    .unwrap();
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    assert_eq!(count(&calls, RESTART_XRAY), 1, "{calls:#?}");
    assert_eq!(count(&calls, "xray api adu"), 0, "{calls:#?}");
}

#[test]
fn an_engine_change_with_clients_added_restarts_both_engines() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let mut next = world.bundle(2, adding(&[1]));
    next.engines.xray = world.put(b"xray binary, next release");
    next.digest = digest_of(&b"a bundle with the next xray and a client"[..]).unwrap();
    assert_eq!(world.apply_and_run(&node, next), TxnState::AwaitingConfirm);
    let calls = node.calls();
    index_of(&calls, RESTART_XRAY);
    index_of(&calls, "/usr/bin/systemctl restart mooring-hy2.service");
    assert_eq!(count(&calls, "xray api adu"), 0, "{calls:#?}");
}

/// An engine that is not running cannot take clients: it starts, with the
/// new file.
#[test]
fn a_stopped_xray_is_started_instead() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow().xray.stopped.set(true);
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    assert_eq!(
        exactly(&calls, XRAY_ACTIVE).len(),
        1,
        "asked once, before the restart: {calls:#?}"
    );
    assert!(index_of(&calls, RESTART_XRAY) > exactly(&calls, XRAY_ACTIVE)[0]);
    assert_eq!(count(&calls, "xray api adu"), 0, "{calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{tag}");
    }
}

/// `systemctl is-active` exits 0 for a unit that is reloading too, and
/// says so: only `active` is taken for a running engine, and a reloading
/// Xray is restarted with the new file.
#[test]
fn a_reloading_xray_is_restarted() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().xray.reloading = true;
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    let asked = exactly(&calls, XRAY_ACTIVE);
    assert_eq!(asked.len(), 1, "{calls:#?}");
    assert!(index_of(&calls, RESTART_XRAY) > asked[0], "{calls:#?}");
    assert_eq!(count(&calls, "xray api adu"), 0, "{calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 2, tag), "{tag}");
    }
}

/// An `is-active` that cannot be started fails the users' step before
/// anything reaches the engine, and the rollback restarts Xray.
#[test]
fn an_is_active_that_cannot_be_started_rolls_back_with_a_restart() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().xray.unstartable = true;
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::Apply {
                    step: ApplyStep::XrayUsers,
                    stderr_tail: StderrTail::scrubbed(b"SpawnProcess failed (errno 2)", &[]),
                },
            }
        }
    );
    let calls = node.calls();
    let asked = exactly(&calls, XRAY_ACTIVE);
    assert_eq!(asked.len(), 1, "{calls:#?}");
    assert!(index_of(&calls, RESTART_XRAY) > asked[0], "{calls:#?}");
    for absent in ["xray api adu", "xray api inbounduser"] {
        assert_eq!(count(&calls, absent), 0, "{absent}: {calls:#?}");
    }
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 1, tag), "{tag}");
    }
}

/// Nothing reaches an engine while the node is halted.
#[test]
fn a_halted_node_adds_no_users() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().halt_on_validate = Some(world.paths.halted());
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::AwaitingConfirm
    );
    let calls = node.calls();
    for absent in [RESTART_XRAY, "xray api adu", "xray api inbounduser"] {
        assert_eq!(count(&calls, absent), 0, "{absent}: {calls:#?}");
    }
    assert!(exactly(&calls, XRAY_ACTIVE).is_empty(), "{calls:#?}");
}

/// Generation 2 adds user 1 and fails at the users' step with `tail`: it
/// is rolled back, and the rollback restarts Xray with generation 1.
fn assert_rolled_back_with_a_restart(world: &World, tail: &[u8]) {
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::Apply {
                    step: ApplyStep::XrayUsers,
                    stderr_tail: StderrTail::scrubbed(tail, &[]),
                },
            }
        }
    );
    let calls = node.calls();
    assert!(index_of(&calls, RESTART_XRAY) > index_of(&calls, ADU));
    assert_eq!(
        count(&calls, ADU),
        1,
        "the rollback adds nothing: {calls:#?}"
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    for (tag, _) in INBOUNDS {
        assert_eq!(held(world, tag), listed(world, 1, tag), "{tag}");
    }
    assert!(!world.paths.validate_dir().join("xray-users.json").exists());
}

#[test]
fn clients_the_engine_did_not_take_roll_back_with_a_restart() {
    let world = World::new();
    world.faults.borrow_mut().xray.refuses = true;
    assert_rolled_back_with_a_restart(
        &world,
        b"xray api adu printed:\n\
          processing inbound: reality-in\nadd user: fxuserzzz1@reality\n\
          rpc error: code = Unknown desc = failed to add user\n\
          processing inbound: hy2-loop-in\nadd user: fxuserzzz1@hy2\n\
          rpc error: code = Unknown desc = failed to add user\n\
          Added 0 user(s) in total.\n\
          reality-in holds other users than the file: not held [\"fxuserzzz1@reality\"], \
          held but not in the file [], held otherwise []",
    );
}

/// A client the engine holds under the file's email but with another id,
/// flow or level is not the file's: `adu` refuses the file's as held
/// already and exits 0, and the read-back names it, so the transaction
/// rolls back with a restart.
#[test]
fn a_client_held_otherwise_rolls_back_with_a_restart() {
    let variants: [(&str, Value); 3] = [
        ("id", json!("6ba7b811-9dad-41d1-80b4-00c04fd430c9")),
        ("flow", json!("")),
        ("level", json!(1)),
    ];
    for (field, value) in variants {
        let world = World::new();
        world.commit(&world.node(1000), world.bundle(1, same));
        let mut other = client(1, "reality");
        other[field] = value;
        world
            .faults
            .borrow()
            .xray
            .held
            .borrow_mut()
            .get_mut("reality-in")
            .unwrap()
            .push(other);
        let node = world.node(2000);
        assert_eq!(
            world.apply_and_run(&node, world.bundle(2, adding(&[1]))),
            TxnState::Failed {
                error: AgentError::RolledBack {
                    generation: Generation::new(2),
                    cause: RollbackCause::Apply {
                        step: ApplyStep::XrayUsers,
                        stderr_tail: StderrTail::scrubbed(
                            b"xray api adu printed:\n\
                              processing inbound: reality-in\nadd user: fxuserzzz1@reality\n\
                              rpc error: code = Unknown desc = User fxuserzzz1@reality already exists.\n\
                              processing inbound: hy2-loop-in\nadd user: fxuserzzz1@hy2\nresult: ok\n\
                              Added 1 user(s) in total.\n\
                              reality-in holds other users than the file: not held [], \
                              held but not in the file [], held otherwise [\"fxuserzzz1@reality\"]",
                            &[],
                        ),
                    },
                }
            },
            "{field}"
        );
        let calls = node.calls();
        assert!(
            index_of(&calls, RESTART_XRAY) > index_of(&calls, ADU),
            "{field}"
        );
        assert_eq!(world.current().as_deref(), Some("gen-1"), "{field}");
        for (tag, _) in INBOUNDS {
            assert_eq!(held(&world, tag), listed(&world, 1, tag), "{field}: {tag}");
        }
    }
}

#[test]
fn an_api_that_cannot_be_reached_rolls_back_with_a_restart() {
    let world = World::new();
    world.faults.borrow_mut().xray.unreachable = true;
    assert_rolled_back_with_a_restart(
        &world,
        b"xray api adu failed: failed to dial 127.0.0.1:10085\n",
    );
}

#[test]
fn a_reply_the_pinned_xray_never_prints_rolls_back_with_a_restart() {
    let world = World::new();
    world.faults.borrow_mut().xray.prints = Some(
        r#"{"users": [{"email": "fxuserzzz1@reality", "account": {"_TypedMessage_": "xray.proxy.vmess.Account", "id": "6ba7b811-9dad-41d1-80b4-00c04fd430c8"}}]}"#
            .to_owned(),
    );
    assert_rolled_back_with_a_restart(
        &world,
        b"xray api inbounduser -tag=reality-in printed what the pinned Xray never prints",
    );
}

/// A rollback restarts Xray even when it adds clients back, as rolling
/// back a suspension does: a restart puts back what ran before as surely
/// as anything can.
#[test]
fn a_rollback_restarts_xray_for_clients_it_adds_back() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, adding(&[1])));
    world.faults.borrow().missing_listeners.set(21);
    let node = world.node(2000);
    assert!(matches!(
        world.apply_and_run(&node, world.bundle(2, same)),
        TxnState::Failed {
            error: AgentError::RolledBack {
                cause: RollbackCause::HealthGate { .. },
                ..
            }
        }
    ));
    let calls = node.calls();
    assert_eq!(
        count(&calls, RESTART_XRAY),
        2,
        "forward, then back: {calls:#?}"
    );
    assert_eq!(count(&calls, "xray api adu"), 0, "{calls:#?}");
    for (tag, _) in INBOUNDS {
        assert_eq!(held(&world, tag), listed(&world, 1, tag), "{tag}");
    }
}
