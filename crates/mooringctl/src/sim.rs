// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM commands (design §7, §15.3): `sim set-anchor`, which records
//! the day a run of fixed-length billing cycles started from, as when a
//! 1pMobile Boost is bought on a day other than the one `exit init` was
//! given.

use std::io::Write;

use mooring_model::{CalendarDate, CycleRule, ModelError, SimPolicy};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::state::{load, output, state_change};

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
