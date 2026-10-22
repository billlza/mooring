// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit env`: the Mac's interfaces as the kernel lists them, and for
//! the M7's interface its own link-layer address, its default gateway and
//! the gateway's link-layer address, with the two `InterfaceSelector`s they
//! would make (design §7, §22 M2b). Run again after unplugging the adapter
//! and after a reboot with `--compare` to see which of them stay stable.
//!
//! The output holds link-layer addresses: keep it outside the repository,
//! as M2.md keeps the router identity (design §15.6).
//!
//! macOS only. The gateway's link-layer address comes from the neighbour
//! table, which macOS 27 hides from a binary that is not signed with a
//! reverse-DNS identifier (design §15.6 rule 10): build with `cargo xtask
//! fieldkit`, which signs a copy, and run that.

use std::net::Ipv4Addr;
use std::path::Path;

use mooring_model::iface::LanSubnet;
use mooring_model::{InterfaceSelector, MacAddr};
use serde::{Deserialize, Serialize};

use crate::error::FieldkitError;
use crate::output::Output;

/// One interface of the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Listed {
    /// Its name.
    pub(crate) name: String,
    /// Its index.
    pub(crate) index: u32,
    /// Its link type (6 is Ethernet).
    pub(crate) link_type: u8,
    /// Its own link-layer address.
    pub(crate) lladdr: Option<String>,
    /// `IFF_UP`.
    pub(crate) up: bool,
    /// `IFF_RUNNING`.
    pub(crate) running: bool,
    /// Its MTU.
    pub(crate) mtu: u32,
    /// Its IPv4 addresses with their prefix lengths.
    pub(crate) ipv4: Vec<String>,
}

/// The M7's interface in detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Bound {
    /// Its name.
    pub(crate) name: String,
    /// Its own link-layer address.
    pub(crate) lladdr: Option<MacAddr>,
    /// The LAN subnet of its IPv4 address, when it has exactly one that
    /// lies in a private LAN range.
    pub(crate) subnet: Option<LanSubnet>,
    /// Its IPv4 default gateway.
    pub(crate) gateway: Option<Ipv4Addr>,
    /// The gateway's link-layer address.
    pub(crate) gateway_lladdr: Option<MacAddr>,
    /// Why one of the above could not be read.
    pub(crate) problems: Vec<String>,
    /// The selectors these would make.
    pub(crate) selectors: Vec<InterfaceSelector>,
}

/// Which values stayed the same as in an earlier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Comparison {
    /// The interface's name.
    pub(crate) name: bool,
    /// Its own link-layer address.
    pub(crate) lladdr: bool,
    /// The subnet.
    pub(crate) subnet: bool,
    /// The gateway's link-layer address.
    pub(crate) gateway_lladdr: bool,
}

/// The result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Summary {
    measure: String,
    /// Every interface with a link-layer address, and every one that is up.
    pub(crate) interfaces: Vec<Listed>,
    /// The M7's interface, when `--bind` named it.
    pub(crate) bound: Option<Bound>,
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    summary: &'a Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    compared: Option<Comparison>,
}

/// Reads the tables and, with `compare`, sets the bound interface against
/// an earlier `env` output.
pub(crate) fn run(
    bound: Option<&str>,
    compare: Option<&Path>,
    output: &mut Output<'_>,
) -> Result<Summary, FieldkitError> {
    let list = mooring_macsys::interfaces().map_err(|error| FieldkitError::Interface {
        name: "*".to_owned(),
        reason: error.to_string(),
    })?;
    let interfaces = list
        .iter()
        .filter(|interface| interface.lladdr.is_some() || interface.up)
        .map(|interface| Listed {
            name: interface.name.clone(),
            index: interface.index.get(),
            link_type: interface.link_type,
            lladdr: interface.lladdr.map(|bytes| mac_text(&bytes)),
            up: interface.up,
            running: interface.running,
            mtu: interface.mtu,
            ipv4: interface
                .ipv4
                .iter()
                .map(|addr| match addr.prefix_len {
                    Some(len) => format!("{}/{len}", addr.addr),
                    None => addr.addr.to_string(),
                })
                .collect(),
        })
        .collect();
    let bound = match bound {
        Some(name) => {
            let interface = list
                .iter()
                .find(|interface| interface.name == name)
                .ok_or_else(|| FieldkitError::Interface {
                    name: name.to_owned(),
                    reason: "the kernel lists no interface of that name".to_owned(),
                })?;
            Some(describe(interface))
        }
        None => None,
    };
    let summary = Summary {
        measure: "env".to_owned(),
        interfaces,
        bound,
    };
    let compared = match compare {
        Some(path) => Some(compare_with(&summary, &earlier(path)?)?),
        None => None,
    };
    output.record(&Report {
        summary: &summary,
        compared,
    })?;
    Ok(summary)
}

fn describe(interface: &mooring_macsys::Interface) -> Bound {
    let mut problems = Vec::new();
    let lladdr = match interface.lladdr.map(MacAddr::from_bytes) {
        Some(Ok(mac)) => Some(mac),
        Some(Err(error)) => {
            problems.push(format!("its link-layer address: {error}"));
            None
        }
        None => {
            problems.push("it has no six-byte link-layer address".to_owned());
            None
        }
    };
    let subnet = match interface.ipv4.as_slice() {
        [one] => match one.prefix_len.map(|len| lan_subnet(one.addr, len)) {
            Some(Ok(subnet)) => Some(subnet),
            Some(Err(error)) => {
                problems.push(format!("its subnet: {error}"));
                None
            }
            None => {
                problems.push("its IPv4 address has no netmask".to_owned());
                None
            }
        },
        addresses => {
            problems.push(format!(
                "it has {} IPv4 addresses, not one",
                addresses.len()
            ));
            None
        }
    };
    let gateway = match mooring_macsys::default_gateway_v4(interface.index) {
        Ok(gateway) => Some(gateway),
        Err(error) => {
            problems.push(format!("its default gateway: {error}"));
            None
        }
    };
    let gateway_lladdr = gateway.and_then(|gateway| {
        match mooring_macsys::neighbour_v4(interface.index, gateway)
            .map_err(|error| error.to_string())
            .and_then(|bytes| MacAddr::from_bytes(bytes).map_err(|error| error.to_string()))
        {
            Ok(mac) => Some(mac),
            Err(error) => {
                problems.push(format!("the gateway's link-layer address: {error}"));
                None
            }
        }
    });
    let mut selectors = Vec::new();
    if let Some(subnet) = subnet {
        if let Some(lladdr) = lladdr {
            selectors.push(InterfaceSelector::LinkAddr { lladdr, subnet });
        }
        if let Some(gw_lladdr) = gateway_lladdr {
            selectors.push(InterfaceSelector::GatewayLinkAddr { gw_lladdr, subnet });
        }
    }
    Bound {
        name: interface.name.clone(),
        lladdr,
        subnet,
        gateway,
        gateway_lladdr,
        problems,
        selectors,
    }
}

/// The LAN subnet of `addr` with prefix length `len`: its network address.
pub(crate) fn lan_subnet(addr: Ipv4Addr, len: u8) -> Result<LanSubnet, mooring_model::ModelError> {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(len.min(32)))
        .unwrap_or(0);
    let network = Ipv4Addr::from(u32::from(addr) & mask);
    format!("{network}/{len}").parse()
}

/// A link-layer address as `aa:bb:cc:dd:ee:ff`.
fn mac_text(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn earlier(path: &Path) -> Result<Summary, FieldkitError> {
    let input = |reason: String| FieldkitError::Input {
        path: path.display().to_string(),
        reason,
    };
    let text = std::fs::read_to_string(path).map_err(|error| input(error.to_string()))?;
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| input("the file is empty".to_owned()))?;
    serde_json::from_str(line).map_err(|error| input(format!("not an env output: {error}")))
}

/// Compares the bound interfaces of two runs.
pub(crate) fn compare_with(now: &Summary, before: &Summary) -> Result<Comparison, FieldkitError> {
    let missing = |which: &str| FieldkitError::Input {
        path: which.to_owned(),
        reason: "the run has no --bind interface to compare".to_owned(),
    };
    let now = now.bound.as_ref().ok_or_else(|| missing("this run"))?;
    let before = before
        .bound
        .as_ref()
        .ok_or_else(|| missing("the earlier run"))?;
    Ok(Comparison {
        name: now.name == before.name,
        lladdr: now.lladdr.is_some() && now.lladdr == before.lladdr,
        subnet: now.subnet.is_some() && now.subnet == before.subnet,
        gateway_lladdr: now.gateway_lladdr.is_some() && now.gateway_lladdr == before.gateway_lladdr,
    })
}
