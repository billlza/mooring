// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation (design §11.2 step 3) on the stand-in node: what it refuses
//! besides a validator's own output, the warning level it gives the engine
//! configurations it checks, and the copies holding the bundle's secrets,
//! which it removes whatever happens.

use std::fs;

use mooring_agent_proto::{
    AgentError, Generation, IoOp, ManagedFile, StderrTail, TxnState, ValidationTool,
};
use serde_json::Value;

use super::world::{World, same};
use crate::host::Tool;
use crate::tests::{EEXIST, ENOENT, ModeFault, occupy_temporary};

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
