// SPDX-License-Identifier: GPL-3.0-or-later

//! Optional values are written as `null` and must be present on receipt: a
//! missing field is rejected rather than read as "absent", so a truncated or
//! mismatched encoder cannot pass for one that reported nothing.

use std::fmt::Debug;

use mooring_agent_proto::{
    AgentError, AgentErrorKind, EngineHealth, EngineRun, Generation, Holds, IoOp, MacDrainHold,
    MacReportV1, ReportRouter, ReportUsage, RollbackCause, TargetFacts, TlsProbe, UnixTime,
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
    for field in ["halted", "latest_handshake", "applied", "accounting_at"] {
        assert_required(&status, &[field]);
    }
    assert_required(&status, &["host", "last_unattended_upgrade"]);
    assert_required(
        &status,
        &["engines", "xray", "run", "Active", "go_heap_bytes"],
    );
    let mut never = status.clone();
    never.accounting_at = None;
    never.host.last_unattended_upgrade = None;
    for path in [&["accounting_at"][..], &["host", "last_unattended_upgrade"]] {
        assert_required(&never, path);
    }
}

#[test]
fn health_options_must_be_spelled_out() {
    let mut engines: EngineHealth = fixtures::engine_health();
    engines.xray.run = EngineRun::Active {
        uptime_secs: 5,
        go_heap_bytes: None,
    };
    assert_required(&engines, &["xray", "run", "Active", "go_heap_bytes"]);
    assert_required(&fixtures::host_health(), &["last_unattended_upgrade"]);
}

#[test]
fn series_and_condition_options_must_be_spelled_out() {
    for since in [None, Some(UnixTime::from_secs(9))] {
        assert_required(&WatchError::MacSilent { since }, &["MacSilent", "since"]);
    }
    let recorded = fixtures::agent_error(AgentErrorKind::SeriesNotRecorded);
    assert_required(&recorded, &["SeriesNotRecorded", "recorded"]);
    let none = AgentError::SeriesNotRecorded { recorded: None };
    assert_required(&none, &["SeriesNotRecorded", "recorded"]);
}

/// Every optional field of a report, present and absent.
#[test]
fn report_options_must_be_spelled_out() {
    let report = fixtures::mac_report();
    for path in [
        &["sim", "hard_stop_bytes"][..],
        &["sim", "line"],
        &["sim", "forecast"],
        &["capacity"],
        &["users", "fxuseraaab", "cycle"],
        &["users", "fxuseraaab", "last_seen"],
        &["users", "fxuseraaac", "last_seen"],
    ] {
        assert_required(&report, path);
    }
    // The radio's two signal objects, and every reading in each of them.
    let radio = ["router", "Available", "radio", "Attached"];
    for (signal, readings) in [
        (
            "lte",
            &["rsrp_tenths", "rsrq_tenths", "sinr_tenths", "rssi_tenths"][..],
        ),
        ("nr", &["rsrp_tenths", "rsrq_tenths", "sinr_tenths"]),
    ] {
        let object: Vec<&str> = radio.iter().copied().chain([signal]).collect();
        assert_required(&report, &object);
        for reading in readings {
            let path: Vec<&str> = object.iter().copied().chain([*reading]).collect();
            assert_required(&report, &path);
        }
    }
    for alert in &report.parts().alerts {
        assert_required(alert, &["node"]);
    }

    let mut parts = report.into_parts();
    parts.sim.hard_stop_bytes = None;
    parts.sim.line = None;
    parts.sim.forecast = None;
    parts.capacity = None;
    parts.usage = ReportUsage::Unavailable;
    for user in parts.users.values_mut() {
        user.cycle = None;
    }
    let mut unavailable = parts.clone();
    unavailable.router = ReportRouter::Unavailable {
        last_polled_at: None,
    };
    for (parts, path) in [
        (&parts, &["sim", "hard_stop_bytes"][..]),
        (&parts, &["sim", "line"]),
        (&parts, &["sim", "forecast"]),
        (&parts, &["capacity"]),
        (&parts, &["users", "fxuseraaab", "cycle"]),
        (&unavailable, &["router", "Unavailable", "last_polled_at"]),
    ] {
        assert_required(&MacReportV1::new(parts.clone()).unwrap(), path);
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
