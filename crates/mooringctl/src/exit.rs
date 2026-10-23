// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit commands (design §7, §10.2, §13): `exit init`, which creates
//! the deployment with the values decided for the pilot;
//! `exit record-carrier`, which records the line's carrier check once it
//! has been observed on the line, and `exit observe`, which observes it;
//! `exit enable` and `exit disable`, the operator's runtime intent; and
//! `exit retry`, which asks the daemon to clear a latched violation.

use std::io::{BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;

use mooring_daemon_core::control::{DaemonReply, DaemonRequest, decode_reply};
use mooring_macsys::InterfaceAddrV4;
use mooring_model::collections::NonEmpty;
use mooring_model::exit::{EgressCheck, FlowCap, Pairing};
use mooring_model::iface::{BsdName, InterfaceSelector, LanSubnet, MacAddr};
use mooring_model::ipv4::CarrierPrefix;
use mooring_model::node::NodeAddress;
use mooring_model::{Bookkeeping, CalendarDate, CycleRule, DeploymentInit, PlanKind, StopPolicy};
use mooring_store::{Store, StoreError};

use crate::app::{Env, support_dir};
use crate::daemon::RunPaths;
use crate::error::{CommandError, LocalError, Unconfirmed};
use crate::node::dial::facing_the_m7;
use crate::prompt::Answer;
use crate::router;
use crate::state::{load, output, state_change};
use crate::status::{ANSWER_TIMEOUT, Next, connect, read_reply_line};

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
/// [--replace] [--yes]` (design §7, §10.2): records the line's carrier
/// check, the public pool prefixes observed on the line (RIPE inetnum
/// evidence, never a whole ASN) and the pairing mode, as the bookkeeping
/// record `CarrierRecorded`. It keeps the configuration generation, so no
/// node needs `node apply`. A check recorded already is refused before
/// anything is asked unless `--replace` is given, as when the SIM changes;
/// replacing it is a configuration change, after which every node needs
/// `node apply` (the daemon also clears a latch then, design §10.2).
pub(crate) fn record_carrier(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    prefixes: Vec<CarrierPrefix>,
    pairing: Pairing,
    replace: bool,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let recorded = state.deployment.exit().egress_check.clone();
    match (&recorded, replace) {
        (Some(_), false) => return Err(LocalError::CarrierRecorded.into()),
        (None, true) => return Err(LocalError::CarrierNotRecorded.into()),
        (Some(_), true) | (None, false) => {}
    }
    let carrier_prefixes = NonEmpty::try_from(prefixes).map_err(LocalError::CarrierCheck)?;
    let check = EgressCheck {
        carrier_prefixes,
        pairing,
    };
    writeln!(out, "carrier check: {}", describe_check(&check)).map_err(output)?;
    let Some(old) = recorded else {
        confirm(env, yes, "Record this carrier check?")?;
        store
            .record(
                state.deployment.config_generation(),
                Bookkeeping::CarrierRecorded { check },
            )
            .map_err(|error| LocalError::StateChange(Box::new(error)))?;
        writeln!(out, "recorded the carrier check; no node apply is needed").map_err(output)?;
        return Ok(());
    };
    writeln!(
        out,
        "it replaces: {}; every node then needs `node apply`",
        describe_check(&old)
    )
    .map_err(output)?;
    confirm(env, yes, "Replace the carrier check?")?;
    let state = store
        .update_config(state.deployment.config_generation(), |mut parts| {
            parts.exit.egress_check = Some(check);
            Ok::<_, std::convert::Infallible>(parts)
        })
        .map_err(state_change)?;
    writeln!(
        out,
        "replaced the carrier check; the deployment is at generation {}, and every node needs `node apply`",
        state.deployment.config_generation()
    )
    .map_err(output)?;
    Ok(())
}

/// A carrier check, as the operator reads it.
fn describe_check(check: &EgressCheck) -> String {
    let shown: Vec<String> = check
        .carrier_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    format!(
        "every egress address in {}; pairing {}",
        shown.join(", "),
        match check.pairing {
            Pairing::Paired => "paired",
            Pairing::Unpaired => "unpaired",
        }
    )
}

/// `exit enable` and `exit disable` (design §13): the operator's runtime
/// intent, recorded with its own revision so that it never makes a node
/// stale. The daemon starts or stops the engine at its next tick.
pub(crate) fn set_enabled(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    enabled: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let word = if enabled { "enabled" } else { "disabled" };
    if state.runtime.exit_enabled == enabled {
        writeln!(out, "the exit is {word} already").map_err(output)?;
        return Ok(());
    }
    store
        .set_exit_enabled(state.runtime.revision, enabled)
        .map_err(|error| LocalError::StateChange(Box::new(error)))?;
    writeln!(
        out,
        "the exit is {word}; the daemon {} the engine at its next tick",
        if enabled {
            "runs its preflight and starts"
        } else {
            "stops"
        }
    )
    .map_err(output)?;
    Ok(())
}

/// `exit retry` (design §10.2, "Retry flow"): asks the daemon to clear the
/// latched violation and the nodes' holds, and to run a fresh preflight at
/// its next tick; `mooringctl status` then shows what it found.
pub(crate) fn retry(env: &mut Env<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let socket = RunPaths::under(&support_dir(env)?).socket;
    let mut reader = BufReader::new(connect(&socket, DaemonRequest::Retry, ANSWER_TIMEOUT)?);
    let line = match read_reply_line(
        &mut reader,
        &socket,
        Instant::now() + ANSWER_TIMEOUT,
        &|| true,
    )? {
        Next::Line(line) => line,
        Next::Deadline | Next::ParentGone => {
            return Err(LocalError::DaemonSilent {
                secs: ANSWER_TIMEOUT.as_secs(),
            }
            .into());
        }
    };
    match decode_reply(&line).map_err(LocalError::DaemonReply)? {
        DaemonReply::RetryQueued => {
            writeln!(
                out,
                "retry queued: the daemon clears the latch and runs a fresh preflight at its next tick; `mooringctl status` shows the outcome"
            )
            .map_err(output)?;
            Ok(())
        }
        DaemonReply::Refused { reason } => Err(LocalError::DaemonRefused { reason }.into()),
        DaemonReply::Status(_) => Err(LocalError::DaemonUnexpectedReply.into()),
    }
}

/// `exit observe --interface <bsd>` (design §10.2): the address each
/// adopted node's reflector sees through `interface`, which must face the
/// pinned M7. It is the carrier's public address for this line, which the
/// operator looks up (RIPE inetnum) before `exit record-carrier`; with a
/// carrier check recorded it also says whether the address passes it. No
/// node answering is `NothingObserved`.
pub(crate) fn observe(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let index = facing_the_m7(env, interface)?;
    let check = state.deployment.exit().egress_check.as_ref();
    let mut observed = 0_usize;
    for node in state.deployment.nodes().values() {
        let Some(site) = node.lifecycle.site() else {
            continue;
        };
        let NodeAddress::Public(address) = site.address;
        let reflector = SocketAddrV4::new(address.get(), node.ports.reflector().get());
        match (env.probe)(index, reflector) {
            Ok(ip) => {
                observed += 1;
                let verdict = match check {
                    None => "no carrier check is recorded yet",
                    Some(check) if check.in_carrier(ip) => "inside the recorded carrier prefixes",
                    Some(_) => "OUTSIDE the recorded carrier prefixes",
                };
                writeln!(out, "{}: the reflector sees {ip} ({verdict})", node.id)
                    .map_err(output)?;
            }
            Err(failure) => {
                writeln!(
                    out,
                    "{}: no answer from {reflector} ({:?}{})",
                    node.id,
                    failure.stage,
                    failure
                        .kind
                        .map_or_else(String::new, |kind| format!(", {kind}"))
                )
                .map_err(output)?;
            }
        }
    }
    if observed == 0 {
        return Err(LocalError::NothingObserved.into());
    }
    Ok(())
}
