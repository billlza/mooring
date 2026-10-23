// SPDX-License-Identifier: GPL-3.0-or-later

//! Builders shared by the cross-module tests.

use std::collections::BTreeMap;

use mooring_agent_proto::{
    EngineHealth, EngineRun, EngineState, GateState, Holds, HostHealth, Inbound, OpaqueUserId,
    Principal, Resolution, SeriesRange, StatsEmail, StatusV1, Traffic, UnixTime as WireTime,
    UplinkTransfer, UsageBin, UsageMonth, UsageSeriesV1, WatchConditions,
};
use mooring_model::{
    BillDay, CalendarDate, CycleRule, Deployment, DeploymentParts, NodeId, SimPolicy, UnixTime,
    User, UserId,
};

/// The fixture deployment with two nodes (lon1, ams1) and three users.
pub(crate) fn deployment() -> Deployment {
    mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
}

pub(crate) fn users() -> BTreeMap<UserId, User> {
    deployment().users().clone()
}

/// The fixture deployment with its SIM billing cycle starting on `day`.
pub(crate) fn deployment_billed_on(day: u8) -> Deployment {
    edited(|parts| {
        let sim = &parts.exit.sim;
        parts.exit.sim = SimPolicy::new(
            CycleRule::Monthly {
                bill_day: BillDay::new(day).unwrap(),
            },
            sim.plan().unwrap().clone(),
            sim.warn_bytes(),
            sim.stop(),
        )
        .unwrap();
    })
}

/// The fixture deployment after `edit`.
pub(crate) fn edited(edit: impl FnOnce(&mut DeploymentParts)) -> Deployment {
    let mut parts = deployment().into_parts();
    edit(&mut parts);
    Deployment::try_from(parts).unwrap()
}

/// The fixture's users in id order.
pub(crate) fn user_ids() -> Vec<UserId> {
    users().keys().cloned().collect()
}

pub(crate) fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

pub(crate) fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

/// `secs` seconds after UTC midnight of `day`.
pub(crate) fn at(day: &str, secs: u64) -> UnixTime {
    UnixTime::from_secs(date(day).utc_start().as_secs() + secs)
}

pub(crate) fn wire(time: UnixTime) -> WireTime {
    WireTime::from_secs(time.as_secs())
}

pub(crate) fn email(user: &UserId, inbound: Inbound) -> StatsEmail {
    StatsEmail {
        principal: Principal::User(OpaqueUserId::new(user.as_str()).unwrap()),
        inbound,
    }
}

pub(crate) fn probe(inbound: Inbound) -> StatsEmail {
    StatsEmail {
        principal: Principal::Probe,
        inbound,
    }
}

pub(crate) const fn traffic(uplink: u64, downlink: u64) -> Traffic {
    Traffic { uplink, downlink }
}

/// One series reply of `resolution` over `[from, to)` with the given bins.
pub(crate) fn series(
    from: UnixTime,
    to: UnixTime,
    resolution: Resolution,
    bins: Vec<(UnixTime, Vec<(StatsEmail, Traffic)>)>,
) -> UsageSeriesV1 {
    UsageSeriesV1::new(
        SeriesRange::new(wire(from), wire(to), resolution).unwrap(),
        bins.into_iter()
            .map(|(start, entries)| {
                UsageBin::new(wire(start), entries.into_iter().collect()).unwrap()
            })
            .collect(),
    )
    .unwrap()
}

/// A healthy node status at `now` with the given activity.
pub(crate) fn status(
    now: UnixTime,
    accounting_at: Option<UnixTime>,
    last_active: Vec<(StatsEmail, UnixTime)>,
) -> StatusV1 {
    let run = EngineState {
        restarts: 0,
        run: EngineRun::Active {
            uptime_secs: 86_400,
            go_heap_bytes: Some(48_000_000),
        },
    };
    StatusV1 {
        now: wire(now),
        watch_at: wire(UnixTime::from_secs(now.as_secs() - 2)),
        gate: GateState::Open,
        holds: Holds::NONE,
        halted: None,
        latest_handshake: Some(wire(UnixTime::from_secs(now.as_secs() - 20))),
        applied: None,
        conditions: WatchConditions::default(),
        accounting_at: accounting_at.map(wire),
        last_active: last_active
            .into_iter()
            .map(|(email, time)| (email, wire(time)))
            .collect(),
        engines: EngineHealth {
            xray: run,
            hy2: EngineState {
                restarts: 0,
                run: EngineRun::Active {
                    uptime_secs: 86_400,
                    go_heap_bytes: None,
                },
            },
        },
        host: HostHealth {
            uptime_secs: 400_000,
            load_milli: 120,
            mem_available_bytes: 600_000_000,
            disk_free_bytes: 18_000_000_000,
            journal_bytes: 90_000_000,
            reboot_required: false,
            last_unattended_upgrade: None,
            ntp_synced: true,
        },
        transfer: UplinkTransfer {
            month: UsageMonth::new(2026, 10).unwrap(),
            counted_from: wire(at("2026-10-01", 0)),
            rx_bytes: 41_000_000_000,
            tx_bytes: 40_000_000_000,
            counter_resets: 7,
        },
    }
}
