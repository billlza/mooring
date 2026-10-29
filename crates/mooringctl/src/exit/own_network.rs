// SPDX-License-Identifier: GPL-3.0-or-later

//! `exit allow-network`, `exit disallow-network` and `exit allowed-networks`
//! (design §10.2, P0-2): the operator declares a network they contract for
//! themselves (their own phone's Personal Hotspot, their home broadband) as
//! their own, so the exit keeps serving while this Mac is joined to it,
//! even when it holds the default route. Never an institutional network: on
//! campus Wi-Fi, eduroam or Janet the exit must stay down, and the command
//! refuses a network whose DNS domain is within `ac.uk`.
//!
//! The SSID is hidden from this process on macOS 27, so a network is
//! identified the way the M7 is: by its router's address and link-layer
//! address as configd resolved them, read while the Mac is joined to it;
//! `--name` is the operator's label only. The declaration is Mac-local
//! (`allowed-networks.json` beside `state.json`, mode 0600): never exported,
//! reported or rendered. Every refusal comes before anything is asked, and
//! writes nothing.

use std::io::Write;
use std::net::Ipv4Addr;

use mooring_daemon_core::network::institutional;
use mooring_macsys::Ipv4Service;
use mooring_model::dns::DnsName;
use mooring_model::exit::Uplink;
use mooring_model::ids::LocalLabel;
use mooring_model::iface::{BsdName, MacAddr, RouterIdentity};
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind, PERSONAL_HOTSPOT_ROUTER};
use mooring_store::{
    Declaration, Store, StoreError, allowed_networks_fit, declare_allowed_network,
    read_allowed_networks, revoke_allowed_network,
};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::router;
use crate::runtime::resolve::{ResolveError, resolve};
use crate::state::{load, output};

/// The policy the command states before it asks (P0-2).
const POLICY: &str = "only a connection you contract for yourself (your own phone's hotspot, your home broadband) may be allowed, never an institutional network (campus Wi-Fi, eduroam, Janet): on one the exit must stay down (P0-2)";

/// The one IPv4 service with a router on an interface: its router's
/// address and identity, and the DNS domain the network publishes.
struct Joined {
    router: Ipv4Addr,
    identity: RouterIdentity,
    domain: Option<DnsName>,
}

fn kind_text(kind: OwnNetworkKind) -> &'static str {
    match kind {
        OwnNetworkKind::PersonalHotspot => "personal hotspot",
        OwnNetworkKind::Broadband => "broadband",
    }
}

fn store_error(error: StoreError) -> CommandError {
    LocalError::AllowedNetworks(Box::new(error)).into()
}

/// The network joined on `interface`, as configd describes it, or the
/// refusal: no service with a router, more than one, or a router whose
/// link-layer address is unresolved or identifies no device.
fn joined(services: &[Ipv4Service], interface: &BsdName) -> Result<Joined, CommandError> {
    let routed: Vec<(&Ipv4Service, Ipv4Addr)> = services
        .iter()
        .filter(|service| service.interface == interface.as_str())
        .filter_map(|service| service.router.map(|router| (service, router)))
        .collect();
    let (service, router) = match routed.as_slice() {
        [] => {
            return Err(LocalError::NoRouterOnInterface {
                interface: interface.clone(),
            }
            .into());
        }
        [one] => *one,
        several => {
            return Err(LocalError::AmbiguousNetwork {
                interface: interface.clone(),
                count: several.len(),
            }
            .into());
        }
    };
    let Some(lladdr) = service.router_lladdr else {
        return Err(LocalError::RouterUnresolved {
            interface: interface.clone(),
        }
        .into());
    };
    let unusable = |source| LocalError::RouterUnusable {
        interface: interface.clone(),
        source,
    };
    let lladdr = MacAddr::from_bytes(lladdr).map_err(unusable)?;
    let identity = RouterIdentity::new(router, lladdr).map_err(unusable)?;
    let domain = service
        .domain
        .as_deref()
        .and_then(|domain| DnsName::parse(&domain.to_ascii_lowercase()).ok());
    Ok(Joined {
        router,
        identity,
        domain,
    })
}

/// `exit allow-network --interface <bsd> --name <label> [--personal-hotspot]
/// [--yes]`: declares the network joined on the interface as the
/// operator's own, after refusing the exit's own path (the pinned
/// interface, the separate uplink, a router that is the M7), a network that
/// cannot be identified (no router, more than one, an unresolved or
/// unusable link-layer address), an institutional domain, a hotspot whose
/// router is not Apple's, and a name in use.
pub(crate) fn allow_network(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    interface: &BsdName,
    name: LocalLabel,
    personal_hotspot: bool,
    yes: bool,
) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let state = load(&Store::new(&dir))?;
    let own_path = |interface: &BsdName| LocalError::NetworkIsEgress {
        interface: interface.clone(),
    };
    if *interface == router::pinned_interface(&dir)? {
        return Err(own_path(interface).into());
    }
    if let Uplink::Separate(selector) = &state.deployment.exit().uplink {
        match resolve(env.router.link, selector) {
            Ok((uplink, _)) if uplink.bsd_name == *interface => {
                return Err(own_path(interface).into());
            }
            Ok(_) => {}
            Err(ResolveError::Kernel(error)) => return Err(LocalError::Kernel(error).into()),
            // An uplink that does not resolve is not this interface.
            Err(_) => {}
        }
    }
    let services = env
        .router
        .link
        .ipv4_services()
        .map_err(LocalError::Configd)?;
    let network = joined(&services, interface)?;
    if network.identity.lladdr() == router::pinned_address(&dir)? {
        return Err(LocalError::RouterIsTheM7 {
            interface: interface.clone(),
        }
        .into());
    }
    if let Some(domain) = &network.domain
        && institutional(domain)
    {
        return Err(LocalError::InstitutionalDomain {
            interface: interface.clone(),
            domain: domain.clone(),
        }
        .into());
    }
    if personal_hotspot && network.router != PERSONAL_HOTSPOT_ROUTER {
        return Err(LocalError::NotAppleHotspot {
            interface: interface.clone(),
            router: network.router,
        }
        .into());
    }
    let declared = read_allowed_networks(&dir).map_err(store_error)?;
    if declared.get(&name).is_some() {
        return Err(LocalError::NetworkDeclared { name }.into());
    }
    let kind = if personal_hotspot {
        OwnNetworkKind::PersonalHotspot
    } else {
        OwnNetworkKind::Broadband
    };
    let declaration = OwnNetwork {
        kind,
        router: network.identity,
        declared_at: (env.clock)()?,
    };
    // The file is bounded: a declaration it cannot hold is refused here,
    // before anything is asked, as the store refuses it under the lock.
    let count = declared.len();
    let mut with_this = declared;
    with_this.insert(name.clone(), declaration.clone());
    if !allowed_networks_fit(&with_this).map_err(store_error)? {
        return Err(LocalError::NetworksFull { declared: count }.into());
    }
    writeln!(
        out,
        "network on {}: router {} ({}), DNS domain {}; the SSID cannot be read, so \"{name}\" is your label for it",
        interface.as_str(),
        network.router,
        network.identity.lladdr(),
        network.domain.as_ref().map_or("none", DnsName::as_str)
    )
    .map_err(output)?;
    writeln!(
        out,
        "allowed, it keeps the exit serving while this Mac is joined to it, even when it holds the default route; every exit connection stays bound to the M7"
    )
    .map_err(output)?;
    writeln!(out, "{POLICY}").map_err(output)?;
    confirm(env, yes, "Allow this network for the exit?")?;
    match declare_allowed_network(&dir, name.clone(), declaration).map_err(store_error)? {
        Declaration::Recorded => {}
        Declaration::AlreadyDeclared => return Err(LocalError::NetworkDeclared { name }.into()),
        Declaration::Full { declared } => {
            return Err(LocalError::NetworksFull { declared }.into());
        }
    }
    writeln!(
        out,
        "declared \"{name}\" ({}) as an own network; the daemon allows it from its next tick while {} keeps this router",
        kind_text(kind),
        interface.as_str()
    )
    .map_err(output)?;
    Ok(())
}

/// `exit disallow-network --name <label>`: withdraws a declaration.
pub(crate) fn disallow_network(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    name: &LocalLabel,
) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let Some(withdrawn) = revoke_allowed_network(&dir, name).map_err(store_error)? else {
        return Err(LocalError::NetworkUnknown { name: name.clone() }.into());
    };
    writeln!(
        out,
        "withdrew \"{name}\" ({}, router {}); the daemon treats that network as foreign from its next tick",
        kind_text(withdrawn.kind),
        withdrawn.router.addr()
    )
    .map_err(output)?;
    Ok(())
}

/// `exit allowed-networks`: one line per declaration, by name.
pub(crate) fn allowed_networks(env: &mut Env<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let dir = support_dir(env)?;
    let declared = read_allowed_networks(&dir).map_err(store_error)?;
    if declared.is_empty() {
        writeln!(out, "no network is declared").map_err(output)?;
        return Ok(());
    }
    for (name, network) in declared.iter() {
        writeln!(
            out,
            "\"{name}\": {}, router {} ({})",
            kind_text(network.kind),
            network.router.addr(),
            network.router.lladdr()
        )
        .map_err(output)?;
    }
    Ok(())
}
