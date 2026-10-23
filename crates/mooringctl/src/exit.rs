// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit commands (design §7, §10.2): `exit init`, which creates the
//! deployment with the values decided for the pilot, and
//! `exit record-carrier`, which records the line's carrier check once it
//! has been observed on the line.

use std::io::Write;
use std::net::Ipv4Addr;

use mooring_macsys::InterfaceAddrV4;
use mooring_model::collections::NonEmpty;
use mooring_model::exit::{EgressCheck, FlowCap, Pairing};
use mooring_model::iface::{BsdName, InterfaceSelector, LanSubnet, MacAddr};
use mooring_model::ipv4::CarrierPrefix;
use mooring_model::{Bookkeeping, CalendarDate, CycleRule, DeploymentInit, PlanKind, StopPolicy};
use mooring_store::{Store, StoreError};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError, Unconfirmed};
use crate::prompt::Answer;
use crate::router;
use crate::state::{load, output};

/// `exit init --interface <bsd> --cycle-anchor <date> --flow-cap <n>
/// [--yes]` (design §7, "What `exit init` records"): creates the deployment
/// with [`DeploymentInit::pilot`]. The egress is the M7: the interface's
/// default gateway must be the pinned router (`router pin`), and the
/// selector records that gateway's link-layer address with the subnet of
/// the interface's address in the gateway's network. The carrier check is
/// not recorded yet, so the exit serves nothing until
/// `exit record-carrier` records it. Nothing is written unless the
/// operator confirms, and an existing deployment is refused before
/// anything is asked.
pub(crate) fn init(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
    cycle_anchor: CalendarDate,
    flow_cap: FlowCap,
    yes: bool,
) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let store = Store::new(dir.clone());
    let state_path = store.state_path();
    if state_path
        .try_exists()
        .map_err(|source| LocalError::StateInspect {
            path: state_path.clone(),
            source,
        })?
    {
        return Err(LocalError::DeploymentExists { path: state_path }.into());
    }
    let pinned = router::configured_pin(&dir)?;
    let candidate = router::pin_candidate(&env.router, interface)?;
    if candidate.lladdr != pinned.gateway_lladdr {
        return Err(LocalError::EgressNotTheRouter {
            interface: interface.clone(),
            found: candidate.lladdr,
            pinned: pinned.gateway_lladdr,
        }
        .into());
    }
    let gateway = candidate.attachment.gateway;
    let addresses = env
        .router
        .link
        .ipv4_addresses(candidate.attachment.index)
        .map_err(LocalError::Kernel)?;
    let subnet = gateway_subnet(&addresses, gateway).ok_or_else(|| LocalError::EgressSubnet {
        interface: interface.clone(),
        gateway,
    })?;
    let init = DeploymentInit::pilot(
        InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: pinned.gateway_lladdr,
            subnet,
        },
        cycle_anchor,
        flow_cap,
    )
    .map_err(LocalError::Pilot)?;
    describe(out, interface, pinned.gateway_lladdr, subnet, &init)?;
    confirm(env, yes, "Create the deployment with these values?")?;
    let state = store.init(init).map_err(|error| match error {
        StoreError::AlreadyInitialized { path } => LocalError::DeploymentExists { path },
        other => LocalError::StateChange(Box::new(other)),
    })?;
    writeln!(
        out,
        "created the deployment at generation {}; the exit serves nothing until `mooringctl exit record-carrier` records the line's carrier check",
        state.deployment.config_generation()
    )
    .map_err(output)?;
    Ok(())
}

/// The subnet of the interface's address in `gateway`'s network: the
/// network of the first address whose prefix holds the gateway, which must
/// be a private LAN subnet (`LanSubnet`).
fn gateway_subnet(addresses: &[InterfaceAddrV4], gateway: Ipv4Addr) -> Option<LanSubnet> {
    addresses.iter().find_map(|address| {
        let length = address.prefix_len?;
        let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
        let network = u32::from(address.addr) & mask;
        if u32::from(gateway) & mask != network {
            return None;
        }
        format!("{}/{length}", Ipv4Addr::from(network))
            .parse::<LanSubnet>()
            .ok()
    })
}

/// Prints what `exit init` is about to record.
fn describe(
    out: &mut dyn Write,
    interface: &BsdName,
    gateway: MacAddr,
    subnet: LanSubnet,
    init: &DeploymentInit,
) -> Result<(), CommandError> {
    let exit = &init.exit;
    let sim = &exit.sim;
    let mut lines = vec![format!(
        "egress: {} (the M7, gateway {gateway} on {}); the tunnel leaves the same way",
        interface.as_str(),
        subnet.get()
    )];
    if let Some(plan) = sim.plan() {
        let line = match plan.kind {
            PlanKind::UnlimitedFairUse { fair_use_bytes, .. } => {
                format!("fair-use line {} GB", fair_use_bytes.get() / 1_000_000_000)
            }
            PlanKind::Unlimited | PlanKind::Capped { .. } => "no fair-use line".to_owned(),
        };
        lines.push(format!(
            "line: {}, {line}, terms of {} ({})",
            plan.carrier.name(),
            plan.terms.dated,
            plan.terms.url.as_str()
        ));
    }
    if let CycleRule::FixedDays { days, anchor } = sim.cycle() {
        lines.push(format!(
            "billing cycles: {} days, one starting on {anchor}",
            days.get()
        ));
    }
    let stop = match sim.stop() {
        StopPolicy::HardStop { bytes } => format!("hard stop at {} GB", bytes / 1_000_000_000),
        StopPolicy::AcceptDeprioritisation => "no hard stop".to_owned(),
    };
    lines.push(format!(
        "SIM: warning at {} GB, {stop}, per cycle",
        sim.warn_bytes() / 1_000_000_000
    ));
    lines.push(format!(
        "users: at most {} active; automatic quotas on; alert digest at 09:00 Europe/London, no channel yet",
        init.capacity
            .max_active_users
            .map_or_else(|| "any number".to_owned(), |users| users.get().to_string())
    ));
    lines.push(format!("flow cap: {} new flows", exit.flow_cap.get()));
    lines.push("carrier check: not recorded yet".to_owned());
    for line in lines {
        writeln!(out, "{line}").map_err(output)?;
    }
    Ok(())
}

/// Asks `question` unless `yes`; anything but yes refuses.
pub(crate) fn confirm(env: &mut Env<'_>, yes: bool, question: &str) -> Result<(), CommandError> {
    if yes {
        return Ok(());
    }
    match env.console.confirm(question)? {
        Answer::Yes => Ok(()),
        Answer::No => Err(LocalError::NotConfirmed(Unconfirmed::Declined).into()),
        Answer::NoTerminal => Err(LocalError::NotConfirmed(Unconfirmed::NoTerminal).into()),
    }
}

/// `exit record-carrier --prefix <cidr>... --pairing paired|unpaired
/// [--yes]` (design §7, §10.2): records the line's carrier check, the
/// public pool prefixes observed on the line (RIPE inetnum evidence, never
/// a whole ASN) and the pairing mode, as the bookkeeping record
/// `CarrierRecorded`. It keeps the configuration generation, so no node
/// needs `node apply`. A check recorded already is refused before anything
/// is asked: replacing one is a configuration change.
pub(crate) fn record_carrier(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    prefixes: Vec<CarrierPrefix>,
    pairing: Pairing,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    if state.deployment.exit().egress_check.is_some() {
        return Err(LocalError::CarrierRecorded.into());
    }
    let carrier_prefixes = NonEmpty::try_from(prefixes).map_err(LocalError::CarrierCheck)?;
    let check = EgressCheck {
        carrier_prefixes,
        pairing,
    };
    let shown: Vec<String> = check
        .carrier_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    writeln!(
        out,
        "carrier check: every egress address in {}; pairing {}",
        shown.join(", "),
        match pairing {
            Pairing::Paired => "paired",
            Pairing::Unpaired => "unpaired",
        }
    )
    .map_err(output)?;
    confirm(env, yes, "Record this carrier check?")?;
    store
        .record(
            state.deployment.config_generation(),
            Bookkeeping::CarrierRecorded { check },
        )
        .map_err(|error| LocalError::StateChange(Box::new(error)))?;
    writeln!(out, "recorded the carrier check; no node apply is needed").map_err(output)?;
    Ok(())
}
