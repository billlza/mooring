// SPDX-License-Identifier: GPL-3.0-or-later

//! Conversions between the model and the agent protocol. The render crate
//! is the one Mac-side crate that sees both (design §6.1), so each mapping
//! lives here once.
//!
//! - [`adoption_site`] turns the facts `Hello` reports at adoption into the
//!   node's recorded site (design §13.2 step 3.3).
//! - [`target_facts`] turns `TargetCheck`'s report into the facts
//!   `mooring_model::target::qualify` judges (design §11.7).
//! - The `Apply` header carries the recorded site (`VpsBundle::header`).
//! - [`ssh_ed25519_key`] and [`ssh_ed25519_pub`] convert an SSH host key
//!   between the model's pin and the protocol's `ssh-ed25519` line.
//!
//! Both sides validate the shared fields with the same rules (interface
//! names, port ranges, DNS names, certificate names, HTTP statuses, SSH
//! public key lines), so a
//! valid value on one side is valid on the other. Where a conversion is
//! still fallible in its types, the tests in `src/tests/wire_rules.rs` prove it
//! succeeds for every valid value; [`RenderError::WireValue`] then reports
//! a drift between the rules, never a normal input.

use mooring_agent_proto as wire;
use mooring_model::Ed25519Pub;
use mooring_model::dns::DnsName;
use mooring_model::iface::LinuxIfName;
use mooring_model::node::{Arch, HostFacts, NodeAddress, NodeSite};
use mooring_model::ports::PortRange;
use mooring_model::target::{
    CertificateName, HttpOutcome, HttpStatus, HttpVersion, KeyExchange, TargetFacts, TlsHandshake,
    TlsOutcome, TlsVersion,
};

use crate::error::{RenderError, WireField};

fn wire_value(field: WireField) -> RenderError {
    RenderError::WireValue { field }
}

/// The site a node is adopted with, from the facts `Hello` reported over
/// SSH to `address` (the address the operator gave `node adopt`): the
/// uplink interface, the architecture and the ephemeral port range are
/// recorded, and the node's address must be the one configured on the
/// uplink (`AddressNotOnUplink`).
///
/// The other facts `Hello` reports (Debian release, kernel, congestion
/// control, qdisc) are not recorded: adoption asserts them, and each
/// `Apply` header carries the values of the `Hello` just before it.
pub fn adoption_site(
    address: NodeAddress,
    hello: &wire::HostFacts,
) -> Result<NodeSite, RenderError> {
    if hello.vps4 != address.ipv4() {
        return Err(RenderError::AddressNotOnUplink {
            address: address.ipv4(),
            reported: hello.vps4,
        });
    }
    let range = hello.ip_local_port_range;
    Ok(NodeSite {
        address,
        host_facts: HostFacts {
            uplink_interface: LinuxIfName::parse(hello.uplink.as_str())
                .map_err(|_| wire_value(WireField::UplinkInterface))?,
            arch: model_arch(hello.arch),
            ephemeral_ports: PortRange::new(range.low(), range.high())
                .map_err(|_| wire_value(WireField::EphemeralPorts))?,
        },
    })
}

/// The host facts an `Apply` header carries: the recorded site's uplink,
/// address, architecture and port range, which the bundle was rendered for
/// and which the agent compares with its live facts, and the unrecorded
/// facts as `hello` (the `Hello` just before the `Apply`) reported them.
pub(crate) fn header_facts(
    site: &NodeSite,
    hello: &wire::HostFacts,
) -> Result<wire::HostFacts, RenderError> {
    let facts = &site.host_facts;
    let range = facts.ephemeral_ports;
    Ok(wire::HostFacts {
        uplink: wire::IfName::new(facts.uplink_interface.as_str())
            .map_err(|_| wire_value(WireField::UplinkInterface))?,
        vps4: site.address.ipv4(),
        arch: wire_arch(facts.arch),
        ip_local_port_range: wire::PortRange::new(range.start().get(), range.end().get())
            .map_err(|_| wire_value(WireField::EphemeralPorts))?,
        debian_major: hello.debian_major,
        kernel: hello.kernel.clone(),
        congestion_control: hello.congestion_control.clone(),
        qdisc: hello.qdisc.clone(),
    })
}

pub(crate) const fn wire_arch(arch: Arch) -> wire::Arch {
    match arch {
        Arch::Amd64 => wire::Arch::Amd64,
        Arch::Arm64 => wire::Arch::Arm64,
    }
}

const fn model_arch(arch: wire::Arch) -> Arch {
    match arch {
        wire::Arch::Amd64 => Arch::Amd64,
        wire::Arch::Arm64 => Arch::Arm64,
    }
}

/// The `ssh-ed25519 <base64>` line of `key`, as cloud-init and the agent
/// protocol carry it.
pub fn ssh_ed25519_key(key: &Ed25519Pub) -> Result<wire::SshEd25519Key, RenderError> {
    wire::SshEd25519Key::new(key.ssh_authorized_key())
        .map_err(|_| wire_value(WireField::SshEd25519Key))
}

/// The Ed25519 public key in a protocol `ssh-ed25519` line, such as the new
/// host key `Bootstrap` reports. The protocol checks only the line's shape,
/// so an all-zero key is refused here (`ModelError::InvalidPublicKey`).
pub fn ssh_ed25519_pub(line: &wire::SshEd25519Key) -> Result<Ed25519Pub, RenderError> {
    Ok(Ed25519Pub::parse_ssh_authorized_key(line.as_str())?)
}

/// The facts `qualify` judges, from what `TargetCheck{requested}`
/// reported. A report about another host than the one requested is refused
/// (`TargetFactsForOtherHost`); every outcome of the report has a model
/// counterpart, so nothing is invented.
pub fn target_facts(
    requested: &DnsName,
    reported: &wire::TargetFacts,
) -> Result<TargetFacts, RenderError> {
    if reported.host.as_str() != requested.as_str() {
        return Err(RenderError::TargetFactsForOtherHost {
            requested: requested.clone(),
            reported: reported.host.clone(),
        });
    }
    Ok(TargetFacts {
        host: requested.clone(),
        resolved_ipv4: reported.resolved.clone(),
        tls: tls_outcome(&reported.tls)?,
        http: http_outcome(&reported.http)?,
    })
}

fn tls_outcome(probe: &wire::TlsProbe) -> Result<TlsOutcome, RenderError> {
    Ok(match probe {
        wire::TlsProbe::ConnectFailed => TlsOutcome::ConnectFailed,
        wire::TlsProbe::HandshakeFailed => TlsOutcome::HandshakeFailed,
        wire::TlsProbe::Completed(session) => TlsOutcome::Completed(TlsHandshake {
            version: match session.version {
                wire::TlsVersion::Tls12 => TlsVersion::Tls12,
                wire::TlsVersion::Tls13 => TlsVersion::Tls13,
            },
            key_exchange: key_exchange(session.group),
            certificate_names: session
                .leaf_names
                .iter()
                .map(|name| {
                    CertificateName::parse(name.as_str())
                        .map_err(|_| wire_value(WireField::CertificateName))
                })
                .collect::<Result<_, _>>()?,
            handshake_p95_micros: session.handshake_p95_micros,
            first_flight_bytes: session.first_flight_bytes,
        }),
    })
}

/// X25519 and X25519MLKEM768 are the groups REALITY completes; any other
/// group, and no group at all (TLS 1.2 RSA key transport), is `Other`.
fn key_exchange(group: Option<wire::TlsGroup>) -> KeyExchange {
    match group {
        Some(wire::TlsGroup::X25519_MLKEM768) => KeyExchange::X25519MlKem768,
        Some(wire::TlsGroup::X25519) => KeyExchange::X25519,
        Some(_) | None => KeyExchange::Other,
    }
}

fn http_outcome(probe: &wire::HttpProbe) -> Result<HttpOutcome, RenderError> {
    Ok(match probe {
        wire::HttpProbe::Failed => HttpOutcome::Failed,
        wire::HttpProbe::Responded {
            status, version, ..
        } => HttpOutcome::Responded {
            status: HttpStatus::new(status.get()).map_err(|_| wire_value(WireField::HttpStatus))?,
            version: match version {
                wire::HttpVersion::Http10 => HttpVersion::Http10,
                wire::HttpVersion::Http11 => HttpVersion::Http11,
                wire::HttpVersion::Http2 => HttpVersion::Http2,
                wire::HttpVersion::Http3 => HttpVersion::Http3,
            },
        },
    })
}
