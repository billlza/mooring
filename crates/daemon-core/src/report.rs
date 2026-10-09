// SPDX-License-Identifier: GPL-3.0-or-later

//! The remote viewer's report (design §15.9, decision F5, 2026-10-08): the
//! projection of a [`MacStatusV1`] onto agent-proto's `MacReportV1`, which
//! the Mac sends a node with `PutMacReport` and the operator's phone reads
//! back with `MacReport`.
//!
//! # What it keeps
//!
//! The exit's phase and since when; the SIM meter (cycle, bytes, accuracy,
//! thresholds, plan line, forecast totals); the router's radio (access,
//! band, signal) and temperature; the uplink's rates and saturation; each
//! user that is not revoked, by id, with its status, cycle bytes and last
//! activity; and the open alerts by kind, severity, node and start.
//!
//! # What it drops
//!
//! Everything else, by construction: the report's types have no field for
//! it. That is the latches and their evidence (addresses); the egress facts
//! (interface name, link-layer address, LAN address); the carrier check
//! (the line's public address); the engines' processes; the power and
//! sleep record; the foreign networks; the details of a degraded or down
//! exit; the router's carrier name, firmware version, data counter,
//! clients, SMS count, power and uptime; the users' aliases, node sets,
//! quota and expiry states, per-node activity, day, month and lifetime
//! figures and shares; revoked users; and the node rows (a viewer reads a
//! node's own `Status`). Labels never reach a [`MacStatusV1`] at all.

use mooring_agent_proto::{
    ExitPhase, MacReportParts, MacReportV1, ReportAccuracy, ReportAlert, ReportBand,
    ReportCapacity, ReportExit, ReportForecast, ReportPlanLine, ReportRadio, ReportRadioAccess,
    ReportRadioSystem, ReportRouter, ReportSaturation, ReportSeverity, ReportSim, ReportUsage,
    ReportUser, ReportUserStatus,
};
use mooring_model::sim::{PlanLine, PlanLineKind};
use mooring_model::user::UserStatus;

use crate::alert::{OpenAlert, Severity};
use crate::capacity::{CapacityStatus, Saturation};
use crate::error::ReportError;
use crate::router::{Band, RadioAccess, RadioState, RouterReading};
use crate::status::{
    ExitState, ForecastView, MacStatusV1, MeterAccuracy, SimMeterStatus, UsageView, UserRow,
};
use crate::wire::{mac_alert_kind, node_name, report_band_number, report_user, wire_time};

/// The report of `status`. `Wire` when the projection breaks a report rule:
/// more than the report's user or alert bound (the ids and the band number
/// always convert, their rules being the model's and the router's).
pub fn project(status: &MacStatusV1) -> Result<MacReportV1, ReportError> {
    let parts = status.parts();
    let users = parts
        .users
        .iter()
        .filter_map(|(id, row)| report_user_row(row).map(|user| Ok((report_user(id)?, user))))
        .collect::<Result<_, ReportError>>()?;
    let alerts = parts
        .alerts
        .iter()
        .map(report_alert)
        .collect::<Result<_, ReportError>>()?;
    Ok(MacReportV1::new(MacReportParts {
        at: wire_time(parts.at),
        exit: ReportExit {
            phase: exit_phase(&parts.exit.state),
            since: wire_time(parts.exit.since),
        },
        sim: report_sim(&parts.sim),
        router: report_router(&parts.router)?,
        capacity: parts.capacity.as_ref().map(report_capacity),
        usage: match parts.usage {
            UsageView::Report { periods } => ReportUsage::Available {
                through: wire_time(periods.through),
            },
            UsageView::Unavailable { .. } => ReportUsage::Unavailable,
        },
        users,
        alerts,
    })?)
}

/// The exit's state without its details.
#[must_use]
pub(crate) const fn exit_phase(state: &ExitState) -> ExitPhase {
    match state {
        ExitState::Disabled => ExitPhase::Disabled,
        ExitState::Preflight => ExitPhase::Preflight,
        ExitState::Starting => ExitPhase::Starting,
        ExitState::Verifying => ExitPhase::Verifying,
        ExitState::Serving { .. } => ExitPhase::Serving,
        ExitState::Degraded { .. } => ExitPhase::Degraded,
        ExitState::Down { .. } => ExitPhase::Down,
        ExitState::Paused => ExitPhase::Paused,
    }
}

fn report_sim(sim: &SimMeterStatus) -> ReportSim {
    ReportSim {
        cycle_starts_at: wire_time(sim.cycle.starts_at()),
        cycle_ends_at: wire_time(sim.cycle.ends_at()),
        rx_bytes: sim.rx_bytes,
        tx_bytes: sim.tx_bytes,
        accuracy: match sim.accuracy {
            MeterAccuracy::Exact => ReportAccuracy::Exact,
            MeterAccuracy::LowerBound => ReportAccuracy::LowerBound,
        },
        warn_bytes: sim.thresholds.warn_bytes(),
        hard_stop_bytes: sim.thresholds.stop().hard_stop_bytes(),
        line: sim.thresholds.plan_line().map(report_line),
        forecast: match &sim.forecast {
            ForecastView::Projected(forecast) => Some(ReportForecast {
                daily_average_bytes: forecast.daily_average_bytes,
                projected_bytes: forecast.projected_bytes,
            }),
            ForecastView::Unavailable { .. } => None,
        },
    }
}

const fn report_line(line: PlanLine) -> ReportPlanLine {
    let bytes = line.bytes.get();
    match line.kind {
        PlanLineKind::FairUse => ReportPlanLine::FairUse { bytes },
        PlanLineKind::Allowance => ReportPlanLine::Allowance { bytes },
    }
}

fn report_router(router: &RouterReading) -> Result<ReportRouter, ReportError> {
    Ok(match router {
        RouterReading::Available(status) => ReportRouter::Available {
            polled_at: wire_time(status.polled_at),
            radio: report_radio(&status.radio)?,
            temperature_c: status.temperature_c.get(),
        },
        RouterReading::Unavailable { last_polled_at, .. } => ReportRouter::Unavailable {
            last_polled_at: last_polled_at.map(wire_time),
        },
    })
}

/// The radio without the carrier's name.
fn report_radio(radio: &RadioState) -> Result<ReportRadio, ReportError> {
    Ok(match radio {
        RadioState::NoService => ReportRadio::NoService,
        RadioState::Attached {
            access,
            band,
            carrier: _,
            signal,
        } => ReportRadio::Attached {
            access: match access {
                RadioAccess::Lte => ReportRadioAccess::Lte,
                RadioAccess::NrNsa => ReportRadioAccess::NrNsa,
                RadioAccess::NrSa => ReportRadioAccess::NrSa,
            },
            band: match band {
                Band::Lte(number) => ReportBand {
                    system: ReportRadioSystem::Lte,
                    number: report_band_number(*number)?,
                },
                Band::Nr(number) => ReportBand {
                    system: ReportRadioSystem::Nr,
                    number: report_band_number(*number)?,
                },
            },
            rsrp_tenths: signal.rsrp.map(|value| value.tenths()),
            rsrq_tenths: signal.rsrq.map(|value| value.tenths()),
            sinr_tenths: signal.sinr.map(|value| value.tenths()),
            rssi_tenths: signal.rssi.map(|value| value.tenths()),
        },
    })
}

const fn report_capacity(capacity: &CapacityStatus) -> ReportCapacity {
    ReportCapacity {
        at: wire_time(capacity.at),
        tx_bps: capacity.tx_bps,
        rx_bps: capacity.rx_bps,
        saturation: match capacity.saturation {
            Saturation::NoEvidence => ReportSaturation::NoEvidence,
            Saturation::Clear => ReportSaturation::Clear,
            Saturation::Building { since } => ReportSaturation::Building {
                since: wire_time(since),
            },
            Saturation::Saturated { since } => ReportSaturation::Saturated {
                since: wire_time(since),
            },
        },
    }
}

/// A user's report row; `None` for a revoked user, whom the report leaves
/// out.
fn report_user_row(row: &UserRow) -> Option<ReportUser> {
    let status = match row.status {
        UserStatus::Active => ReportUserStatus::Active,
        UserStatus::Suspended { .. } => ReportUserStatus::Suspended,
        UserStatus::RevokePending => ReportUserStatus::RevokePending,
        UserStatus::Revoked => return None,
    };
    Some(ReportUser {
        status,
        cycle: row.usage.as_ref().map(|usage| usage.cycle()),
        last_seen: row.activity.last_seen.map(wire_time),
    })
}

fn report_alert(alert: &OpenAlert) -> Result<ReportAlert, ReportError> {
    let kind = alert.condition.kind();
    Ok(ReportAlert {
        kind: mac_alert_kind(kind),
        severity: match kind.severity() {
            Severity::Critical => ReportSeverity::Critical,
            Severity::Warning => ReportSeverity::Warning,
        },
        node: alert.condition.node().map(node_name).transpose()?,
        active_since: wire_time(alert.active_since),
    })
}
