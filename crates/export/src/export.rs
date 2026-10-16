// SPDX-License-Identifier: GPL-3.0-or-later

//! User exports and the probe outbounds the Mac prober wraps.

use std::fmt;

use mooring_model::ports::ListenerIdx;
use mooring_model::secret::SecretSnapshot;
use mooring_model::{
    AgreementVersion, Deployment, Node, NodeId, NodeRole, UnixTime, User, UserId, UserStatus,
};
use zeroize::Zeroizing;

use crate::cert::{certificate_pins, check_certificate};
use crate::error::{ExportError, NotApplied};
use crate::proxy::{ClientHello, Endpoint, Hysteria2Proxy, Proxy, RealityProxy};
use crate::singbox::SingBoxOutbound;
use crate::tag::OutboundTag;
use crate::tree::{Scalar, Tree};
use crate::{clash, singbox};

/// The file format of a user export (design §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExportFormat {
    /// sing-box JSON with only `outbounds` (the default).
    SingBoxJson,
    /// Clash YAML with only `proxies:`.
    ClashYaml,
}

impl ExportFormat {
    /// Every format.
    pub const ALL: [Self; 2] = [Self::SingBoxJson, Self::ClashYaml];

    /// The stable name used in shape names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SingBoxJson => "sing-box-json",
            Self::ClashYaml => "clash-yaml",
        }
    }

    /// The file extension, without the dot.
    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::SingBoxJson => "json",
            Self::ClashYaml => "yaml",
        }
    }
}

/// One user's export file. It holds the user's credentials, so its bytes
/// live in a zeroizing buffer and its `Debug` output shows only the format
/// and length.
pub struct ExportDocument {
    format: ExportFormat,
    bytes: Zeroizing<Vec<u8>>,
}

impl ExportDocument {
    /// The format.
    #[must_use]
    pub const fn format(&self) -> ExportFormat {
        self.format
    }

    /// The file contents: UTF-8 text ending with one newline.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ExportDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportDocument")
            .field("format", &self.format)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Exports `user` in `format`, checking every certificate at `now`.
///
/// The file covers every node the user holds credentials on, primary nodes
/// first, then by node id; each node contributes its REALITY outbound and
/// then one Hysteria2 outbound per listener. The shape is selected by the
/// user's `ClientProfile`. Refused, in this order, when the user is not
/// active (suspended, pending revocation or revoked: `UserNotActive`), has
/// not accepted the agreement revision this build ships
/// (`AgreementNotAccepted`, decision F9), has a capability its CFM line does
/// not accept, holds no credentials, or when any of those nodes has not
/// confirmed the current generation or fails a certificate check.
///
/// Neither the day of the agreement record (a calendar day without a time
/// zone) nor the user's policy is compared with `now`: an expired or
/// over-quota user is refused only once an explicit operator or daemon
/// action has moved it to `Suspended { Expired | QuotaExceeded }`, so an
/// export never depends on the clock beyond the certificate check at
/// `now`.
///
/// An export reads only this user's credentials, so it does not compare
/// them with other identities'. That check belongs to rendering each
/// node's bundle (`mooring-render`'s `DuplicateCredential`), and every node
/// in the file must have confirmed the current generation, whose bundle
/// passed it.
pub fn export_user(
    deployment: &Deployment,
    secrets: &SecretSnapshot,
    user: &UserId,
    format: ExportFormat,
    now: UnixTime,
) -> Result<ExportDocument, ExportError> {
    let outbounds = user_outbounds(deployment, secrets, deployment.user(user)?, now)?;
    let bytes = match format {
        ExportFormat::SingBoxJson => singbox::render(&outbounds)?,
        ExportFormat::ClashYaml => clash::render(&clash_document(&outbounds)),
    };
    Ok(ExportDocument { format, bytes })
}

/// The probe identity's outbounds for one node, as the Mac prober runs them
/// (design §8.8): the REALITY outbound with the classical chrome hello and
/// the Hysteria2 outbound of listener 0, tagged `<node>-reality` and
/// `<node>-hy2` until the caller retags them.
///
/// The prober runs upstream sing-box, which has no
/// `support_x25519mlkem768`, so the hybrid hello is never used here. The
/// node must be adopted or applied and have a target; certificates are
/// checked at `node apply` and at user exports, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutbounds {
    /// The VLESS+REALITY+Vision outbound.
    pub reality: SingBoxOutbound,
    /// The Hysteria2 outbound of listener 0.
    pub hysteria2: SingBoxOutbound,
}

/// Builds the probe outbounds of `node`; see [`ProbeOutbounds`].
pub fn probe_outbounds(
    deployment: &Deployment,
    secrets: &SecretSnapshot,
    node: &NodeId,
) -> Result<ProbeOutbounds, ExportError> {
    let node = deployment.node(node)?;
    let endpoint = Endpoint::of(node)?;
    let reality = RealityProxy::new(
        endpoint,
        node,
        secrets.probe_vless_uuid(&node.id)?,
        node.reality.probe_short_id,
        ClientHello::Chrome,
    );
    let index = ListenerIdx::FIRST;
    let hysteria2 = Hysteria2Proxy::new(
        endpoint,
        &certificate_pins(node)?,
        node.ports.hy2().first(),
        secrets.probe_hy2_password(&node.id)?,
        secrets.hy2_obfs(&node.id, index)?,
    );
    Ok(ProbeOutbounds {
        reality: SingBoxOutbound::new(OutboundTag::reality(&node.id), Proxy::Reality(reality)),
        hysteria2: SingBoxOutbound::new(
            OutboundTag::hysteria2(&node.id, index),
            Proxy::Hysteria2(hysteria2),
        ),
    })
}

fn user_outbounds(
    deployment: &Deployment,
    secrets: &SecretSnapshot,
    user: &User,
    now: UnixTime,
) -> Result<Vec<SingBoxOutbound>, ExportError> {
    // Only the status decides. An expired or over-quota user is still
    // exported while `Active`: moving it to `Suspended` is an explicit
    // operator or daemon action, never a side effect of exporting.
    match user.status {
        UserStatus::Active => {}
        UserStatus::Suspended { .. } | UserStatus::RevokePending | UserStatus::Revoked => {
            return Err(ExportError::UserNotActive {
                user: user.id.clone(),
            });
        }
    }
    require_agreement(user)?;
    let hello = ClientHello::for_profile(&user.client)?;
    let mut nodes = user
        .per_node
        .iter()
        .map(|(id, public)| Ok((deployment.node(id)?, public.short_id)))
        .collect::<Result<Vec<_>, ExportError>>()?;
    if nodes.is_empty() {
        return Err(ExportError::NothingToExport {
            user: user.id.clone(),
        });
    }
    nodes.sort_by(|(left, _), (right, _)| {
        (role_rank(left.role), &left.id).cmp(&(role_rank(right.role), &right.id))
    });
    let mut outbounds = Vec::new();
    for (node, short_id) in nodes {
        require_current(deployment, node)?;
        let pins = check_certificate(node, now)?;
        let endpoint = Endpoint::of(node)?;
        let reality = RealityProxy::new(
            endpoint,
            node,
            secrets.user_vless_uuid(&user.id, &node.id)?,
            short_id,
            hello,
        );
        outbounds.push(SingBoxOutbound::new(
            OutboundTag::reality(&node.id),
            Proxy::Reality(reality),
        ));
        let password = secrets.user_hy2_password(&user.id, &node.id)?;
        for (index, listener) in node.ports.hy2_listeners() {
            let obfs = secrets.hy2_obfs(&node.id, index)?;
            let hysteria2 = Hysteria2Proxy::new(endpoint, &pins, listener, password, obfs);
            outbounds.push(SingBoxOutbound::new(
                OutboundTag::hysteria2(&node.id, index),
                Proxy::Hysteria2(hysteria2),
            ));
        }
    }
    Ok(outbounds)
}

/// Decision F9: a file goes only to a user who accepted the agreement
/// revision this build ships. The record's day is not compared with `now`:
/// it is a calendar day without a time zone, and `user agree` dates it.
fn require_agreement(user: &User) -> Result<(), ExportError> {
    let required = AgreementVersion::CURRENT;
    match user.agreement {
        Some(record) if record.version == required => Ok(()),
        recorded => Err(ExportError::AgreementNotAccepted {
            user: user.id.clone(),
            recorded: recorded.map(|record| record.version),
            required,
        }),
    }
}

/// Primary nodes come first in an export.
const fn role_rank(role: NodeRole) -> u8 {
    match role {
        NodeRole::Primary => 0,
        NodeRole::Standby => 1,
    }
}

/// Only a node that confirmed the deployment's current generation is known
/// to serve exactly the credentials, SNI and ports being exported.
fn require_current(deployment: &Deployment, node: &Node) -> Result<(), ExportError> {
    let reason = match node.lifecycle.applied() {
        None => NotApplied::Stage(node.lifecycle.stage()),
        Some(applied) if applied.config_generation < deployment.config_generation() => {
            NotApplied::Stale {
                applied: applied.config_generation,
                current: deployment.config_generation(),
            }
        }
        Some(_) => return Ok(()),
    };
    Err(ExportError::NodeNotApplied {
        node: node.id.clone(),
        reason,
    })
}

/// The Clash document of the same outbounds, in the same order.
fn clash_document(outbounds: &[SingBoxOutbound]) -> Tree<Scalar> {
    clash::document(
        outbounds
            .iter()
            .map(|outbound| match outbound.proxy() {
                Proxy::Reality(proxy) => clash::reality_item(proxy.hello())
                    .map(&mut |slot| proxy.resolve(outbound.tag(), slot)),
                Proxy::Hysteria2(proxy) => {
                    clash::hysteria2_item().map(&mut |slot| proxy.resolve(outbound.tag(), slot))
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use mooring_fixtures::{FIXTURE_NOW, two_nodes_twenty_users};

    use super::*;

    #[test]
    fn documents_are_written_into_exactly_sized_buffers() {
        let fixture = two_nodes_twenty_users().unwrap();
        for user in fixture.deployment.users().keys() {
            for format in ExportFormat::ALL {
                let document = export_user(
                    &fixture.deployment,
                    &fixture.secrets,
                    user,
                    format,
                    FIXTURE_NOW,
                )
                .unwrap();
                // No reallocation ever copied the credentials.
                assert_eq!(document.bytes.capacity(), document.bytes.len());
                assert!(document.bytes.ends_with(b"\n"));
            }
        }
    }
}
