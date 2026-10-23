// SPDX-License-Identifier: GPL-3.0-or-later

//! The status line the daemon publishes (design §15.2), assembled from what
//! it holds at one instant with the core's own logic: usage aggregation and
//! activity, the SIM forecast, and quota and expiry evaluation. The daemon
//! gathers the inputs; nothing here invents what it lacks: no ledger makes
//! the usage view unavailable with its reason, a node never polled is
//! `NotPolled`, and a forecast that cannot be made says why.

use std::collections::BTreeMap;

use mooring_agent_proto::StatusV1;
use mooring_model::{Deployment, ModelError, NodeId, UnixTime, UserId};

use crate::alert::OpenAlert;
use crate::capacity::CapacityStatus;
use crate::error::{PolicyError, StatusError, UsageError};
use crate::forecast::{DailySimBytes, SimForecast};
use crate::period::BillingCycle;
use crate::policy::{ExpiryState, QuotaState, automatic_quota, effective_quota};
use crate::router::RouterReading;
use crate::status::{
    ExitSection, ForecastView, MacStatusParts, MacStatusV1, MeterAccuracy, NodeAgentState,
    NodeReport, NodeRow, ProtocolVerdicts, SimMeterStatus, UsageView, UserRow,
};
use crate::usage::{NodeLedger, UsageAccuracy, activity, aggregate};

/// The SIM meter's figures for the current cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimTotals<'a> {
    /// Bytes received this cycle.
    pub rx_bytes: u64,
    /// Bytes sent this cycle.
    pub tx_bytes: u64,
    /// The cycle's bytes per UTC day, for the forecast.
    pub daily: &'a [DailySimBytes],
    /// Whether the figures are exact.
    pub accuracy: MeterAccuracy,
}

/// A node's latest `Status` poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePoll {
    /// When the Mac polled it.
    pub polled_at: UnixTime,
    /// What it answered.
    pub status: StatusV1,
}

/// Everything one status line is made of.
#[derive(Debug, Clone)]
pub struct StatusInputs<'a> {
    /// The deployment.
    pub deployment: &'a Deployment,
    /// When the line is made.
    pub at: UnixTime,
    /// The exit Mac.
    pub exit: ExitSection,
    /// The SIM meter.
    pub sim: SimTotals<'a>,
    /// The router.
    pub router: RouterReading,
    /// The latest capacity view, if any.
    pub capacity: Option<CapacityStatus>,
    /// The nodes' accounting ledgers.
    pub ledgers: &'a [NodeLedger],
    /// The end of the usage report's periods.
    pub through: UnixTime,
    /// The nodes' latest polls.
    pub polls: &'a BTreeMap<NodeId, NodePoll>,
    /// The nodes the last poll did not reach, with what is known.
    pub unreachable: &'a BTreeMap<NodeId, NodeAgentState>,
    /// The latest in-chain verdicts per node.
    pub verdicts: &'a BTreeMap<NodeId, ProtocolVerdicts>,
    /// Since when each node has been behind the current generation.
    pub pending_apply: &'a BTreeMap<NodeId, UnixTime>,
    /// The open alerts, in key order.
    pub alerts: Vec<OpenAlert>,
}

/// Why no status line could be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// The users' activity could not be read from the polls.
    #[error("the users' activity could not be read")]
    Activity(#[source] UsageError),
    /// The automatic quota could not be evaluated.
    #[error("the automatic quota could not be evaluated")]
    Quota(#[source] PolicyError),
    /// The billing cycle could not be computed.
    #[error("the billing cycle could not be computed")]
    Cycle(#[source] ModelError),
    /// The usage report or the activity left a user out; both cover every
    /// user of the deployment, so this is a fault in the core.
    #[error("no usage or activity was computed for the user {user}")]
    RowMissing {
        /// The user.
        user: UserId,
    },
    /// The parts do not make a consistent status.
    #[error("the status is inconsistent")]
    Status(#[source] StatusError),
}

/// The status line of `inputs`.
pub fn assemble(inputs: StatusInputs<'_>) -> Result<MacStatusV1, SnapshotError> {
    let deployment = inputs.deployment;
    let sim = &deployment.exit().sim;
    let users = deployment.users();
    let forecast = match SimForecast::project(sim, inputs.at, inputs.sim.daily) {
        Ok(forecast) => ForecastView::Projected(forecast),
        Err(error) => ForecastView::Unavailable {
            reason: error.kind(),
        },
    };
    let report = aggregate(deployment, inputs.ledgers, inputs.through);
    let statuses: BTreeMap<NodeId, StatusV1> = inputs
        .polls
        .iter()
        .map(|(node, poll)| (node.clone(), poll.status.clone()))
        .collect();
    let mut activity = activity(users, &statuses, inputs.at).map_err(SnapshotError::Activity)?;
    let (usage, mut by_user) = match report {
        Ok(report) => (
            UsageView::Report {
                periods: report.periods,
            },
            Some(report.users),
        ),
        Err(error) => (
            UsageView::Unavailable {
                reason: error.kind(),
            },
            None,
        ),
    };
    let automatic = automatic_quota(deployment, inputs.at).map_err(SnapshotError::Quota)?;
    let mut rows = BTreeMap::new();
    for (id, user) in users {
        let missing = || SnapshotError::RowMissing { user: id.clone() };
        let usage = match &mut by_user {
            Some(by_user) => Some(by_user.remove(id).ok_or_else(missing)?),
            None => None,
        };
        let activity = activity.remove(id).ok_or_else(missing)?;
        let quota = effective_quota(user, automatic);
        let quota = match &usage {
            Some(usage) => QuotaState::of(quota, usage.cycle_served_bytes()),
            None => QuotaState::without_usage(quota),
        };
        rows.insert(
            id.clone(),
            UserRow {
                alias: user.alias.clone(),
                status: user.status,
                nodes: user.per_node.keys().cloned().collect(),
                activity,
                usage,
                quota,
                expiry: ExpiryState::of(&user.policy, inputs.at),
                accuracy: UsageAccuracy::of(user),
            },
        );
    }
    let nodes = deployment
        .nodes()
        .iter()
        .map(|(id, node)| {
            let agent = match inputs.polls.get(id) {
                Some(poll) => {
                    NodeAgentState::Reported(Box::new(NodeReport::of(poll.polled_at, &poll.status)))
                }
                None => inputs
                    .unreachable
                    .get(id)
                    .cloned()
                    .unwrap_or(NodeAgentState::NotPolled),
            };
            (
                id.clone(),
                NodeRow {
                    role: node.role,
                    stage: node.lifecycle.stage(),
                    current_generation: deployment.config_generation(),
                    pending_apply_since: inputs.pending_apply.get(id).copied(),
                    verdicts: inputs
                        .verdicts
                        .get(id)
                        .copied()
                        .unwrap_or(ProtocolVerdicts {
                            reality: None,
                            hy2: None,
                        }),
                    agent,
                },
            )
        })
        .collect();
    MacStatusV1::new(MacStatusParts {
        at: inputs.at,
        exit: inputs.exit,
        sim: SimMeterStatus {
            cycle: BillingCycle::of_instant(sim.cycle(), inputs.at)
                .map_err(SnapshotError::Cycle)?,
            rx_bytes: inputs.sim.rx_bytes,
            tx_bytes: inputs.sim.tx_bytes,
            accuracy: inputs.sim.accuracy,
            thresholds: sim.thresholds(),
            forecast,
        },
        router: inputs.router,
        capacity: inputs.capacity,
        usage,
        users: rows,
        nodes,
        alerts: inputs.alerts,
    })
    .map_err(SnapshotError::Status)
}
