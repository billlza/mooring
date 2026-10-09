// SPDX-License-Identifier: GPL-3.0-or-later

//! Builders for the status scenarios: agent replies, ledgers and meter bins
//! shaped like the ones the daemon will receive.

use std::collections::BTreeMap;

use mooring_agent_proto::{
    AppliedGeneration, EngineHealth, EngineRun, EngineState, GateState, Generation, Holds,
    HostHealth, Inbound, OpaqueUserId, Principal, Resolution, SeriesRange, Sha256Hex, StatsEmail,
    StatusV1, Traffic, UnixTime as WireTime, UplinkTransfer, UsageBin, UsageMonth, UsageSeriesV1,
    WatchConditions, WatchError,
};
use mooring_daemon_core::forecast::DailySimBytes;
use mooring_model::{CalendarDate, Node, NodeId, UnixTime, UserId};

/// A label shaped like both a report user id (ten lowercase base32
/// letters) and a node name: the scans for leaked labels and identifiers
/// look for it, and the report tests plant it where the report drops
/// text, because the report's grammars alone would let it through.
pub(crate) const GRAMMAR_SHAPED_LABEL: &str = "alicesmith";

pub(crate) const MINUTE: u64 = 60;
pub(crate) const HOUR: u64 = 3600;
pub(crate) const GB: u64 = 1_000_000_000;

pub(crate) fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

/// `secs` seconds after UTC midnight of `day`.
pub(crate) fn at(day: &str, secs: u64) -> UnixTime {
    UnixTime::from_secs(date(day).utc_start().as_secs() + secs)
}

pub(crate) fn before(time: UnixTime, secs: u64) -> UnixTime {
    UnixTime::from_secs(time.as_secs() - secs)
}

pub(crate) fn wire(time: UnixTime) -> WireTime {
    WireTime::from_secs(time.as_secs())
}

pub(crate) fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
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

/// One series reply of `resolution` over `[from, to)`; repeated entries in
/// a bin are summed.
pub(crate) fn series(
    from: UnixTime,
    to: UnixTime,
    resolution: Resolution,
    entries: &[(UnixTime, StatsEmail, u64, u64)],
) -> UsageSeriesV1 {
    let mut bins: BTreeMap<u64, BTreeMap<StatsEmail, Traffic>> = BTreeMap::new();
    for (start, email, uplink, downlink) in entries {
        let total = bins
            .entry(start.as_secs())
            .or_default()
            .entry(email.clone())
            .or_default();
        total.uplink += uplink;
        total.downlink += downlink;
    }
    UsageSeriesV1::new(
        SeriesRange::new(wire(from), wire(to), resolution).unwrap(),
        bins.into_iter()
            .map(|(start, traffic)| UsageBin::new(WireTime::from_secs(start), traffic).unwrap())
            .collect(),
    )
    .unwrap()
}

/// The meter's bytes per day from `first`, one entry per day.
pub(crate) fn daily(first: &str, bytes: &[u64]) -> Vec<DailySimBytes> {
    let first = date(first);
    bytes
        .iter()
        .enumerate()
        .map(|(index, &bytes)| DailySimBytes {
            date: first
                .checked_add_days(u32::try_from(index).unwrap())
                .unwrap(),
            bytes,
        })
        .collect()
}

/// The generation and digest a fixture node last applied.
pub(crate) fn applied(node: &Node) -> AppliedGeneration {
    let applied = node.lifecycle.applied().unwrap();
    AppliedGeneration {
        generation: Generation::new(applied.config_generation.get()),
        digest: Sha256Hex::from_bytes(*applied.digest.as_bytes()),
    }
}

/// A node's `StatusV1` as its agent would answer at `now`.
pub(crate) struct NodeStatus {
    pub(crate) now: UnixTime,
    pub(crate) applied: AppliedGeneration,
    pub(crate) last_active: Vec<(StatsEmail, UnixTime)>,
    pub(crate) conditions: Vec<WatchError>,
    pub(crate) gate: GateState,
    pub(crate) holds: Holds,
    pub(crate) reboot_required: bool,
    pub(crate) handshake_age_secs: u64,
}

impl NodeStatus {
    pub(crate) fn build(self) -> StatusV1 {
        let accounting_at = before(self.now, 31);
        StatusV1 {
            now: wire(self.now),
            watch_at: wire(before(self.now, 3)),
            gate: self.gate,
            holds: self.holds,
            halted: None,
            latest_handshake: Some(wire(before(self.now, self.handshake_age_secs))),
            applied: Some(self.applied),
            conditions: WatchConditions::try_from(self.conditions).unwrap(),
            accounting_at: Some(wire(accounting_at)),
            last_active: self
                .last_active
                .into_iter()
                .map(|(email, time)| (email, wire(time)))
                .collect(),
            engines: EngineHealth {
                xray: EngineState {
                    restarts: 1,
                    run: EngineRun::Active {
                        uptime_secs: 52_380,
                        go_heap_bytes: Some(37_748_736),
                    },
                },
                hy2: EngineState {
                    restarts: 0,
                    run: EngineRun::Active {
                        uptime_secs: 52_391,
                        go_heap_bytes: None,
                    },
                },
            },
            host: HostHealth {
                uptime_secs: 52_420,
                load_milli: 180,
                mem_available_bytes: 612_368_384,
                disk_free_bytes: 19_327_352_832,
                journal_bytes: 88_080_384,
                reboot_required: self.reboot_required,
                last_unattended_upgrade: Some(wire(at("2026-10-07", 20 * HOUR + 4 * MINUTE))),
                ntp_synced: true,
            },
            transfer: UplinkTransfer {
                month: UsageMonth::new(2026, 10).unwrap(),
                counted_from: wire(at("2026-10-01", 0)),
                rx_bytes: 96_210_000_000,
                tx_bytes: 95_870_000_000,
                counter_resets: 7,
            },
        }
    }
}

/// The time a user was last active: the latest accounting poll before
/// `now`, or `minutes` earlier.
pub(crate) fn polled(now: UnixTime, minutes: u64) -> UnixTime {
    before(now, 31 + minutes * MINUTE)
}
