// SPDX-License-Identifier: GPL-3.0-or-later

//! Optional values are written as `null` and must be present on receipt: a
//! missing field is rejected rather than read as "absent", so a truncated or
//! mismatched encoder cannot pass for one that reported nothing.

use std::fmt::Debug;

use mooring_agent_proto::{
    AgentError, Generation, Holds, IoOp, MacDrainHold, RollbackCause, TargetFacts, TlsProbe,
    WatchError,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::fixtures;

fn assert_required<T>(value: &T, path: &[&str])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let mut json = serde_json::to_value(value).unwrap();
    assert_eq!(&serde_json::from_value::<T>(json.clone()).unwrap(), value);
    let (last, parents) = path.split_last().unwrap();
    let mut node = &mut json;
    for key in parents {
        node = node.get_mut(*key).unwrap();
    }
    let removed = node.as_object_mut().unwrap().remove(*last);
    assert!(removed.is_some(), "{path:?} is not in the encoding");
    assert!(
        serde_json::from_value::<T>(json.clone()).is_err(),
        "{path:?} may be omitted: {json}"
    );
}

#[test]
fn absent_holds_must_be_spelled_out() {
    for field in ["mac_drain", "egress_violation", "operator"] {
        assert_required(&Holds::NONE, &[field]);
    }
    let drain = MacDrainHold {
        handshake_at_drain: None,
    };
    assert_required(&drain, &["handshake_at_drain"]);
}

#[test]
fn hello_and_status_options_must_be_spelled_out() {
    assert_required(&fixtures::hello_info(), &["halted"]);
    let status = fixtures::status();
    for field in ["halted", "latest_handshake", "applied"] {
        assert_required(&status, &[field]);
    }
}

#[test]
fn errno_must_be_spelled_out() {
    let io = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    assert_required(&io, &["Io", "errno"]);
    let swap = AgentError::RolledBack {
        generation: Generation::new(3),
        cause: RollbackCause::Swap { errno: None },
    };
    assert_required(&swap, &["RolledBack", "cause", "Swap", "errno"]);
    assert_required(
        &WatchError::StateWrite { errno: None },
        &["StateWrite", "errno"],
    );
}

#[test]
fn target_fact_options_must_be_spelled_out() {
    let facts: TargetFacts = fixtures::target_facts();
    assert!(matches!(facts.tls, TlsProbe::Completed(_)));
    assert_required(&facts, &["tls", "Completed", "group"]);
    assert_required(&facts, &["http", "Responded", "redirect"]);
}

#[test]
fn errno_reads_plainly_in_messages() {
    let with = AgentError::Io {
        op: IoOp::WriteBlob,
        errno: Some(28),
    };
    let without = WatchError::StateWrite { errno: None };
    assert_eq!(with.to_string(), "WriteBlob failed (errno 28)");
    assert_eq!(
        without.to_string(),
        "writing watch state failed (not an OS error)"
    );
}
