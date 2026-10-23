// SPDX-License-Identifier: GPL-3.0-or-later

//! The local health gate (design §11.2 step 6): every check, in gate order,
//! within a budget (20 s after a transaction, after `Resume` and after a
//! rollback). A check that cannot even be run has not passed.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, EngineUser, HealthCheck, IoOp, ManagedFile, NFT_TABLE, NftCounter,
};
use serde_json::Value;

use super::stage::{XRAY, program};
use crate::accounting::stats::XRAY_API_SERVER;
use crate::gate;
use crate::host::{Node, Tool};
use crate::paths::Paths;
use crate::store::io_error;

/// The health gate's budget (design §11.2 step 6).
pub(crate) const BUDGET: Duration = Duration::from_secs(20);

/// The units that must be active: both engines and the tunnel.
pub(crate) const UNITS: [&str; 3] = [
    "mooring-xray.service",
    "mooring-hy2.service",
    "wg-quick@wgexit.service",
];

/// A listener the generation's configuration opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Listener {
    /// UDP (else TCP).
    pub(crate) udp: bool,
    /// The address, or `None` for every address.
    pub(crate) address: Option<Ipv4Addr>,
    /// The port.
    pub(crate) port: u16,
}

/// The listeners the configuration in generation `dir` opens: Xray's
/// inbounds (TCP, or a tunnel's `network`), the Hysteria2 inbounds (UDP)
/// and the WireGuard port (UDP, every address).
pub(crate) fn expected_listeners(dir: &Path) -> Result<BTreeSet<Listener>, AgentError> {
    let malformed = || crate::store::malformed(IoOp::ReadState);
    let json = |file: ManagedFile| -> Result<Value, AgentError> {
        let bytes = fs::read(dir.join(file.file_name()))
            .map_err(|error| io_error(IoOp::ReadState, &error))?;
        serde_json::from_slice(&bytes).map_err(|_| malformed())
    };
    let mut listeners = BTreeSet::new();
    let address = |inbound: &Value, key: &str| -> Result<Option<Ipv4Addr>, AgentError> {
        match inbound.get(key) {
            None => Ok(None),
            Some(Value::String(text)) => text.parse().map(Some).map_err(|_| malformed()),
            Some(_) => Err(malformed()),
        }
    };
    let port = |inbound: &Value, key: &str| -> Result<u16, AgentError> {
        inbound
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(malformed)
    };
    for inbound in json(ManagedFile::XrayConfig)?["inbounds"]
        .as_array()
        .ok_or_else(malformed)?
    {
        let networks = match inbound.pointer("/settings/network") {
            None => "tcp",
            Some(Value::String(networks)) => networks.as_str(),
            Some(_) => return Err(malformed()),
        };
        for network in networks.split(',') {
            let udp = match network.trim() {
                "tcp" => false,
                "udp" => true,
                _ => return Err(malformed()),
            };
            listeners.insert(Listener {
                udp,
                address: address(inbound, "listen")?,
                port: port(inbound, "port")?,
            });
        }
    }
    for inbound in json(ManagedFile::Hy2Config)?["inbounds"]
        .as_array()
        .ok_or_else(malformed)?
    {
        listeners.insert(Listener {
            udp: true,
            address: address(inbound, "listen")?,
            port: port(inbound, "listen_port")?,
        });
    }
    let wg = fs::read_to_string(dir.join(ManagedFile::WgConf.file_name()))
        .map_err(|error| io_error(IoOp::ReadState, &error))?;
    let wg_port = wg
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "ListenPort").then(|| value.trim().parse::<u16>().ok())?
        })
        .ok_or_else(malformed)?;
    listeners.insert(Listener {
        udp: true,
        address: None,
        port: wg_port,
    });
    Ok(listeners)
}

/// Whether `ss -Hltnu`'s output shows every expected listener: the same
/// protocol and port, on the expected address or on every address.
pub(crate) fn all_listening(ss: &str, expected: &BTreeSet<Listener>) -> bool {
    let open: Vec<(bool, Option<Ipv4Addr>, u16)> = ss
        .lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let udp = match columns.next()? {
                "udp" => true,
                "tcp" => false,
                _ => return None,
            };
            let local = columns.nth(3)?;
            let (host, port) = local.rsplit_once(':')?;
            let host = host.split('%').next()?;
            let address = match host {
                "0.0.0.0" | "*" | "[::]" => None,
                host => Some(host.parse().ok()?),
            };
            Some((udp, address, port.parse().ok()?))
        })
        .collect();
    expected.iter().all(|want| {
        open.iter().any(|&(udp, address, port)| {
            udp == want.udp && port == want.port && (address.is_none() || address == want.address)
        })
    })
}

/// Whether the output chain holds each engine's owner-guard rule: a rule
/// matching the engine's user that counts into its guard counter and
/// rejects (design §8.5).
pub(crate) fn owner_guards_present(chain: &[u8]) -> bool {
    let Ok(listing) = serde_json::from_slice::<Value>(chain) else {
        return false;
    };
    let rules: Vec<String> = listing["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("rule"))
        .map(Value::to_string)
        .collect();
    [
        (EngineUser::Xray, NftCounter::XrayGuard),
        (EngineUser::Hy2, NftCounter::Hy2Guard),
    ]
    .iter()
    .all(|(user, counter)| {
        rules.iter().any(|rule| {
            rule.contains(&format!("\"{}\"", user.name()))
                && rule.contains(&format!("\"{}\"", counter.name()))
                && rule.contains("\"reject\"")
        })
    })
}

/// Whether `check` passes now, for the generation in `dir`.
fn passes(paths: &Paths, node: &dyn Node, dir: &Path, check: HealthCheck) -> bool {
    match check {
        HealthCheck::UnitsActive => {
            let mut args = vec!["is-active"];
            args.extend(UNITS);
            node.run(Tool::Systemctl, &args).is_ok_and(|output| {
                output.success
                    && String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .filter(|line| *line == "active")
                        .count()
                        == UNITS.len()
            })
        }
        HealthCheck::Listeners => {
            match (expected_listeners(dir), node.run(Tool::Ss, &["-Hltnu"])) {
                (Ok(expected), Ok(output)) if output.success => {
                    all_listening(&String::from_utf8_lossy(&output.stdout), &expected)
                }
                _ => false,
            }
        }
        HealthCheck::XrayApi => node
            .run_program(
                &program(dir, XRAY),
                &["api", "statssys", XRAY_API_SERVER],
                &[],
            )
            .is_ok_and(|output| output.success),
        HealthCheck::ExitClosedSet => gate::state(node).is_ok(),
        HealthCheck::OwnerGuard => node
            .run(
                Tool::Nft,
                &["-j", "list", "chain", "inet", NFT_TABLE, "output"],
            )
            .is_ok_and(|output| output.success && owner_guards_present(&output.stdout)),
        HealthCheck::AcceptLocal => {
            fs::read_to_string(paths.wgexit_accept_local()).is_ok_and(|text| text.trim_end() == "1")
        }
    }
}

/// The first check, in gate order, that does not pass now.
pub(crate) fn first_failing(paths: &Paths, node: &dyn Node, dir: &Path) -> Option<HealthCheck> {
    HealthCheck::ALL
        .iter()
        .copied()
        .find(|check| !passes(paths, node, dir, *check))
}

/// Waits, checking once a second, until every check passes, or until
/// `budget` has been slept, and then names the first check that had not
/// passed.
pub(crate) fn wait(
    paths: &Paths,
    node: &dyn Node,
    dir: &Path,
    budget: Duration,
) -> Result<(), HealthCheck> {
    let mut slept = Duration::ZERO;
    loop {
        match first_failing(paths, node, dir) {
            None => return Ok(()),
            Some(check) if slept >= budget => return Err(check),
            Some(_) => {
                node.sleep(Duration::from_secs(1));
                slept += Duration::from_secs(1);
            }
        }
    }
}
