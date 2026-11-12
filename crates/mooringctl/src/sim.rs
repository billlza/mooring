// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM commands (design §7, §10.2, §15.3): `sim set-anchor`, which
//! records the day a run of fixed-length billing cycles started from, as
//! when a 1pMobile Boost is bought on a day other than the one `exit
//! init` was given; and `sim accept-network`, which has the daemon take
//! the network the M7 reports as the SIM's network on record.

use std::io::Write;

use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{DaemonReply, DaemonRequest};
use mooring_daemon_core::sim_network::{BaselineOrigin, SimNetwork, SimNetworkStatus};
use mooring_model::time::UnixTime;
use mooring_model::{CalendarDate, CycleRule, ModelError, SimPolicy};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::daemon::RunPaths;
use crate::daemon::sim_network::shown;
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::router::output::utc_stamp;
use crate::state::{load, output, state_change};
use crate::status::ask;

/// `sim set-anchor <date> [--yes]`: moves the fixed-length cycles so that
/// one starts on `anchor`, keeping their length, the plan and the
/// thresholds. A configuration change: every node then needs `node apply`
/// before a user's file can be exported again (design §7). A monthly rule
/// is refused, and an anchor that is already the rule's changes nothing.
pub(crate) fn set_anchor(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    anchor: CalendarDate,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let sim = state.deployment.exit().sim.clone();
    let CycleRule::FixedDays {
        days,
        anchor: current,
    } = sim.cycle()
    else {
        return Err(LocalError::CycleNotFixed.into());
    };
    let rule = CycleRule::FixedDays { days, anchor };
    if rule.cycle_start(current).map_err(LocalError::SimChange)? == current {
        writeln!(
            out,
            "kept: cycles of {} days already start on {current} and {anchor}",
            days.get()
        )
        .map_err(output)?;
        return Ok(());
    }
    let plan = sim
        .plan()
        .ok_or(LocalError::SimChange(ModelError::PlanNotRecorded))?
        .clone();
    writeln!(
        out,
        "billing cycles: {} days, one starting on {anchor} (they started from {current}); every node then needs `node apply` before a user's file can be exported again",
        days.get()
    )
    .map_err(output)?;
    confirm(env, yes, "Move the billing cycles?")?;
    let next =
        SimPolicy::new(rule, plan, sim.warn_bytes(), sim.stop()).map_err(LocalError::SimChange)?;
    let state = store
        .update_config(state.deployment.config_generation(), |mut parts| {
            parts.exit.sim = next;
            Ok::<_, std::convert::Infallible>(parts)
        })
        .map_err(state_change)?;
    writeln!(
        out,
        "moved the billing cycles; the deployment is at generation {}",
        state.deployment.config_generation()
    )
    .map_err(output)?;
    Ok(())
}

/// `sim accept-network [--yes]` (design §10.2): has the daemon take the
/// network the M7 reports as the SIM's network on record, at the
/// operator's word, which ends the console's notice of another SIM or
/// network. It asks the daemon for its status, prints the network on
/// record and the one the daemon's latest poll of the M7 reported, asks,
/// and then names that network to the daemon, which takes it only while
/// its record and its latest poll still say that the M7 reports it. With
/// nothing to take it says why and asks nothing. It changes the record of
/// the SIM's network and nothing else: the carrier check, the billing
/// cycle, the latch and the exit stay as they are.
pub(crate) fn accept_network(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    yes: bool,
) -> Result<(), CommandError> {
    let socket = RunPaths::under(&support_dir(env)?).socket;
    let status = match ask(&socket, DaemonRequest::Status)? {
        DaemonReply::Status(ConsoleStatus::Deployed(status)) => status,
        DaemonReply::Status(ConsoleStatus::NoDeployment(_)) => {
            return Err(LocalError::SimNetworkWithoutDeployment.into());
        }
        DaemonReply::Refused { reason } => {
            return Err(LocalError::DaemonRefused { reason }.into());
        }
        DaemonReply::RetryQueued | DaemonReply::SimNetworkAccepted => {
            return Err(LocalError::DaemonUnexpectedReply.into());
        }
    };
    let recorded = &status.parts().sim.network;
    let reported = SimNetwork::polled(&status.parts().router);
    for line in shown_lines(recorded, reported.as_ref())? {
        writeln!(out, "{line}").map_err(output)?;
    }
    let network = recorded
        .acceptable(reported.as_ref().map(|(network, _)| network))
        .map_err(LocalError::SimNetworkNotTaken)?
        .network
        .clone();
    let name = shown(&network);
    confirm(
        env,
        yes,
        &format!(
            "Take {name} as the SIM's network on record? The carrier check and the billing cycle stay as they are."
        ),
    )?;
    match ask(&socket, DaemonRequest::AcceptSimNetwork { network })? {
        DaemonReply::SimNetworkAccepted => {
            writeln!(
                out,
                "taken: {name} is the SIM's network on record now; the console's notice ends with the daemon's next status"
            )
            .map_err(output)?;
            Ok(())
        }
        DaemonReply::Refused { reason } => Err(LocalError::DaemonRefused { reason }.into()),
        DaemonReply::Status(_) | DaemonReply::RetryQueued => {
            Err(LocalError::DaemonUnexpectedReply.into())
        }
    }
}

/// What `sim accept-network` shows before it asks: the network on record
/// with the time it was first reported or taken, the network the daemon's
/// latest poll of the M7 reported, and since when the M7 has reported a
/// network other than the one on record.
fn shown_lines(
    recorded: &SimNetworkStatus,
    reported: Option<&(SimNetwork, UnixTime)>,
) -> Result<Vec<String>, LocalError> {
    let stamp = |time| utc_stamp(time).map_err(|_| LocalError::Clock);
    let mut lines = Vec::with_capacity(3);
    lines.push(match &recorded.baseline {
        None => "on record: no network yet".to_owned(),
        Some(baseline) => format!(
            "on record: {}, {} {}",
            shown(baseline.network()),
            match recorded.origin {
                BaselineOrigin::Accepted => "taken at the operator's word",
                BaselineOrigin::NoRecord
                | BaselineOrigin::Recorded
                | BaselineOrigin::RecordUnreadable => "first reported",
            },
            stamp(baseline.first_seen())?
        ),
    });
    lines.push(match reported {
        None => "the M7 reports: no network (the daemon's latest poll did not find it attached)"
            .to_owned(),
        Some((network, polled_at)) => format!(
            "the M7 reports: {}, at the daemon's poll of {}",
            shown(network),
            stamp(*polled_at)?
        ),
    });
    if let Some(other) = recorded
        .baseline
        .as_ref()
        .and_then(|baseline| baseline.other())
    {
        lines.push(format!(
            "another network than the one on record since {}",
            stamp(other.since)?
        ));
    }
    Ok(lines)
}
