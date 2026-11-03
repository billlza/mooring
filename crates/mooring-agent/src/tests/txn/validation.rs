// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation (design §11.2 step 3) on the stand-in node. The host
//! validators run on the staged generation, and a refusal by the kernel
//! parameters, sshd or systemd-analyze fails the change, a warning or a
//! failure without a word included. Xray's check refuses on a warning too,
//! its output scrubbed of the bundle's secrets, every credential among
//! them; its refusal is reported even when the staged directory cannot then
//! be removed, which the next staging replaces. Validation also refuses an
//! engine configuration that is not JSON, before any validator runs, or
//! that cannot take a log level; fails when its scratch directory cannot be
//! made, a copy cannot be written or a validator cannot be started; gives a
//! configuration without a log section the warning level all the same
//! (Xray's copy is checked); and removes the copies holding the bundle's
//! secrets whatever happens.

use std::fs;

use mooring_agent_proto::{
    AgentError, Generation, IoOp, ManagedFile, StderrTail, TxnState, ValidationTool,
};
use serde_json::Value;

use super::world::{WG_PRIVATE_KEY, World, index_of, same};
use crate::host::Tool;
use crate::tests::{EEXIST, ENOENT, FakeNode, ModeFault, occupy_temporary};
use crate::txn;
use crate::txn::record::pending;

/// A bundle whose `file` reads `text`, the rest golden.
fn with(world: &World, file: ManagedFile, text: &str) -> mooring_agent_proto::BundleHeader {
    let text = text.to_owned();
    world.bundle(1, move |each, golden| {
        if each == file {
            text.clone()
        } else {
            same(each, golden)
        }
    })
}

/// The change failed with `error` before anything was switched or any
/// copy of the engine configurations was left.
fn assert_refused(world: &World, error: AgentError) {
    assert_eq!(world.state(1), TxnState::Failed { error });
    assert_eq!(world.current(), None);
    assert!(!world.paths.generation(Generation::new(1)).exists());
    let validate = world.paths.validate_dir();
    for file in [ManagedFile::XrayConfig, ManagedFile::Hy2Config] {
        assert!(!validate.join(file.file_name()).exists(), "{file:?}");
    }
}

const MALFORMED: AgentError = AgentError::Io {
    op: IoOp::ReadState,
    errno: None,
};

/// An engine configuration that is not JSON is refused before any
/// validator runs.
#[test]
fn a_configuration_that_is_not_json_is_refused_before_any_validator() {
    for file in [ManagedFile::XrayConfig, ManagedFile::Hy2Config] {
        let world = World::new();
        let node = world.node(1000);
        world.apply_and_run(&node, with(&world, file, "{\"log\":"));
        assert_refused(&world, MALFORMED);
        assert!(
            !node
                .calls()
                .iter()
                .any(|call| call.contains("-test") || call.contains("check")),
            "{:#?}",
            node.calls()
        );
    }
}

/// An engine configuration that is JSON but cannot be given a log level
/// (no object, or a `log` that is no object) is refused, and the Xray copy
/// made before a refused Hy2 one, which holds the bundle's secrets, is
/// removed all the same.
#[test]
fn a_configuration_that_cannot_take_a_log_level_is_refused_and_no_copy_is_left() {
    for (file, text) in [
        (ManagedFile::XrayConfig, "[]\n"),
        (ManagedFile::Hy2Config, "[]\n"),
        (ManagedFile::XrayConfig, "{\"log\": 1}\n"),
        (ManagedFile::Hy2Config, "{\"log\": \"warn\"}\n"),
    ] {
        let world = World::new();
        world.apply_and_run(&world.node(1000), with(&world, file, text));
        assert_refused(&world, MALFORMED);
    }
}

/// A configuration without a `log` section is checked at warning level
/// all the same: the copy the validator reads has one.
#[test]
fn a_configuration_without_a_log_section_is_checked_at_warning_level() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, |file, text| {
        if file == ManagedFile::XrayConfig {
            text.replacen("\"log\":", "\"unlogged\":", 1)
        } else {
            text
        }
    });
    assert_eq!(
        world.apply_and_run(&node, header),
        TxnState::AwaitingConfirm
    );
    let checked: Value =
        serde_json::from_str(world.faults.borrow().xray_copy.borrow().as_deref().unwrap()).unwrap();
    assert_eq!(checked["log"], serde_json::json!({ "loglevel": "warning" }));
    assert!(checked.get("unlogged").is_some());
}

#[test]
fn a_scratch_directory_that_cannot_be_made_fails_the_validation() {
    let world = World::new();
    let validate = world.paths.validate_dir();
    fs::create_dir_all(validate.parent().unwrap()).unwrap();
    fs::write(&validate, "").unwrap();
    world.apply_and_run(&world.node(1000), world.bundle(1, same));
    assert_eq!(
        world.state(1),
        TxnState::Failed {
            error: AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(EEXIST),
            }
        }
    );
    assert_eq!(world.current(), None);
}

#[test]
fn a_copy_that_cannot_be_written_fails_the_validation() {
    let world = World::new();
    occupy_temporary(
        &world
            .paths
            .validate_dir()
            .join(ManagedFile::XrayConfig.file_name()),
    );
    world.apply_and_run(&world.node(1000), world.bundle(1, same));
    assert_refused(
        &world,
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST),
        },
    );
}

#[test]
fn a_validator_that_cannot_be_started_fails_the_validation() {
    let world = World::new();
    world.faults.borrow_mut().unstartable = Some((Tool::Nft, "-c"));
    world.apply_and_run(&world.node(1000), world.bundle(1, same));
    assert_refused(
        &world,
        AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT),
        },
    );
}

/// A refused change is reported as refused even when its staged directory
/// cannot then be removed: the refusal is the first failure, and the next
/// staging replaces what is left.
#[test]
fn a_refusal_is_reported_even_when_the_staged_directory_stays() {
    let world = World::new();
    let engines = world.paths.generation(Generation::new(1)).join("engines");
    let warning = "[Warning] deprecated field\n";
    let read_only = ModeFault::restoring(&engines, 0o755);
    {
        let mut faults = world.faults.borrow_mut();
        faults.xray_test = Some(warning.to_owned());
        faults.read_only_on_validate = Some(engines.clone());
    }
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::StageValidation {
                tool: ValidationTool::Xray,
                stderr_tail: StderrTail::scrubbed(warning.as_bytes(), &[]),
            }
        }
    );
    assert!(engines.is_dir(), "left behind");
    drop(read_only);
    {
        let mut faults = world.faults.borrow_mut();
        faults.xray_test = None;
        faults.read_only_on_validate = None;
    }
    assert_eq!(
        world.apply_and_run(&world.node(1100), world.bundle(1, same)),
        TxnState::AwaitingConfirm,
        "the next staging replaces what was left"
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
fn a_validator_that_fails_without_a_word_is_still_a_rejection() {
    let world = World::new();
    world.faults.borrow_mut().sshd_fails_silently = true;
    let (tool, tail) = rejected(&world, &world.node(1000));
    assert_eq!(tool, ValidationTool::Sshd);
    assert_eq!(tail, "");
}
