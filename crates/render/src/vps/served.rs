// SPDX-License-Identifier: GPL-3.0-or-later

//! The identities a node serves and their per-node credentials: every
//! active user holding credentials on the node, in id order, then the
//! Mac's probe identity. Before anything is rendered, the credentials of
//! every identity holding them on the node are checked to be distinct as
//! the engines key them.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use mooring_agent_proto::{
    Inbound, OpaqueUserId, Principal, StatsEmail, is_user_source, user_source,
};
use mooring_model::ids::{NodeId, ShortId, UserId, Uuid};
use mooring_model::secret::{Password, Secret, SecretSnapshot};
use mooring_model::{Deployment, Node};

use crate::error::{CredentialHolder, CredentialKind, RenderError, WireField};
use crate::text_value::{TextValueError, display_serde};

/// Who a credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Identity {
    /// A user, by opaque id.
    User(UserId),
    /// The Mac's in-chain probe identity.
    Probe,
}

const PROBE: &str = "probe";

impl Identity {
    /// The accounting email `<id>@<inbound>` Xray keys traffic counters by,
    /// in the agent's own type so accounting parses what was rendered.
    pub(crate) fn email(&self, inbound: Inbound) -> Result<StatsEmail, RenderError> {
        let principal = match self {
            Self::Probe => Principal::Probe,
            Self::User(user) => {
                Principal::User(OpaqueUserId::new(user.as_str()).map_err(|_| {
                    RenderError::WireValue {
                        field: WireField::AccountingName(user.clone()),
                    }
                })?)
            }
        };
        Ok(StatsEmail { principal, inbound })
    }
}

/// A user's source address inside the node (design §11.8): always inside
/// `198.18.0.0/15` and off its ends (`mooring_agent_proto::is_user_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct UserSource(Ipv4Addr);

impl UserSource {
    /// The address, when it is one a user can be given.
    pub(crate) fn new(address: Ipv4Addr) -> Option<Self> {
        is_user_source(address).then_some(Self(address))
    }

    /// The address.
    pub(crate) const fn address(self) -> Ipv4Addr {
        self.0
    }
}

/// One served user's way out of the node: the accounting emails of both
/// inbounds, which its routing rule names, and its source address, which
/// its outbound binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserExit {
    pub(crate) emails: [StatsEmail; 2],
    pub(crate) source: UserSource,
}

/// The way out of every user `served` holds, in served order, refusing two
/// users with one source address (`UserSourceCollision`, naming both).
/// The probe has none: it leaves from the tunnel's own address.
pub(crate) fn user_exits(node: &NodeId, served: &[Served]) -> Result<Vec<UserExit>, RenderError> {
    let mut seen: BTreeMap<UserSource, &UserId> = BTreeMap::new();
    let mut exits = Vec::new();
    for served in served {
        let Identity::User(user) = &served.identity else {
            continue;
        };
        let emails = [
            served.identity.email(Inbound::Reality)?,
            served.identity.email(Inbound::Hy2)?,
        ];
        let Principal::User(opaque) = &emails[0].principal else {
            continue;
        };
        let source =
            UserSource::new(user_source(opaque)).ok_or_else(|| RenderError::WireValue {
                field: WireField::AccountingName(user.clone()),
            })?;
        if let Some(first) = seen.insert(source, user) {
            return Err(RenderError::UserSourceCollision {
                node: node.clone(),
                first: first.clone(),
                second: user.clone(),
            });
        }
        exits.push(UserExit { emails, source });
    }
    Ok(exits)
}

/// The name `hy2.json` gives the identity: the user id, or `probe`. A user
/// id has 10 characters, so it can never be `probe`.
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(user) => f.write_str(user.as_str()),
            Self::Probe => f.write_str(PROBE),
        }
    }
}

impl FromStr for Identity {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == PROBE {
            Ok(Self::Probe)
        } else {
            UserId::parse(text)
                .map(Self::User)
                .map_err(|_| TextValueError("a user id or probe"))
        }
    }
}

display_serde!(Identity);

impl From<&Identity> for CredentialHolder {
    fn from(identity: &Identity) -> Self {
        match identity {
            Identity::User(user) => Self::User(user.clone()),
            Identity::Probe => Self::Probe,
        }
    }
}

/// One identity's credentials on one node.
#[derive(Debug, Clone)]
pub(crate) struct Served {
    pub(crate) identity: Identity,
    /// The REALITY VLESS UUID (`reality-in`).
    pub(crate) vless: Secret<Uuid>,
    /// The REALITY short id.
    pub(crate) short_id: ShortId,
    /// The loopback VLESS UUID (`hy2-loop-in`, used by `hy2.json`).
    pub(crate) loopback: Secret<Uuid>,
    /// The Hysteria2 password.
    pub(crate) hy2: Password,
}

/// One identity holding credentials on the node, and whether the node
/// serves it.
struct Holder {
    /// Whether the engines list the identity: the probe, and a user that
    /// is active (`User::is_served_on`).
    is_served: bool,
    credentials: Served,
}

/// Every identity `node` serves, users in id order, then the probe.
///
/// First, every identity holding credentials on the node is checked
/// against every other: each user with credentials there, whether active,
/// suspended or pending revocation, and the probe. No two may share a
/// VLESS UUID, a loopback UUID or a Hysteria2 password as the engines key
/// them (`DuplicateCredential`). An identity that is not served is
/// included because its client still holds the credential: were it equal
/// to a served identity's, a suspended or revoked client would keep
/// working as that identity. The secrets of those identities are therefore
/// required too, as `Deployment::required_secrets` lists them.
pub(crate) fn served(
    deployment: &Deployment,
    node: &Node,
    secrets: &SecretSnapshot,
) -> Result<Vec<Served>, RenderError> {
    let id: &NodeId = &node.id;
    let mut holders = Vec::new();
    for user in deployment.users().values() {
        let Some(public) = user.per_node.get(id) else {
            continue;
        };
        holders.push(Holder {
            is_served: user.is_served_on(id),
            credentials: Served {
                identity: Identity::User(user.id.clone()),
                vless: secrets.user_vless_uuid(&user.id, id)?.clone(),
                short_id: public.short_id,
                loopback: secrets.user_loop_uuid(&user.id, id)?.clone(),
                hy2: secrets.user_hy2_password(&user.id, id)?.clone(),
            },
        });
    }
    holders.push(Holder {
        is_served: true,
        credentials: Served {
            identity: Identity::Probe,
            vless: secrets.probe_vless_uuid(id)?.clone(),
            short_id: node.reality.probe_short_id,
            loopback: secrets.probe_loop_uuid(id)?.clone(),
            hy2: secrets.probe_hy2_password(id)?.clone(),
        },
    });
    require_distinct(id, &holders)?;
    Ok(holders
        .into_iter()
        .filter(|holder| holder.is_served)
        .map(|holder| holder.credentials)
        .collect())
}

/// Refuses `DuplicateCredential`, naming both holders, when two holders
/// share a credential of one kind. The two UUID kinds belong to different
/// Xray inbounds, each with its own client table, so they are compared
/// within their kind.
fn require_distinct(node: &NodeId, holders: &[Holder]) -> Result<(), RenderError> {
    let mut vless = BTreeMap::new();
    let mut loopback = BTreeMap::new();
    let mut hy2 = BTreeMap::new();
    for holder in holders {
        let credentials = &holder.credentials;
        let identity = &credentials.identity;
        let earlier = [
            (
                first_holder(&mut vless, XrayUserKey::of(&credentials.vless), identity),
                CredentialKind::VlessUuid,
            ),
            (
                first_holder(
                    &mut loopback,
                    XrayUserKey::of(&credentials.loopback),
                    identity,
                ),
                CredentialKind::LoopbackUuid,
            ),
            (
                first_holder(&mut hy2, credentials.hy2.expose_bytes(), identity),
                CredentialKind::Hy2Password,
            ),
        ];
        if let Some((Some(first), kind)) = earlier.into_iter().find(|(first, _)| first.is_some()) {
            return Err(RenderError::DuplicateCredential {
                node: node.clone(),
                kind,
                first: first.into(),
                second: identity.into(),
            });
        }
    }
    Ok(())
}

/// Records `identity` as the holder of `key`, or returns the identity that
/// already holds it.
fn first_holder<'a, K: Ord>(
    seen: &mut BTreeMap<K, &'a Identity>,
    key: K,
    identity: &'a Identity,
) -> Option<&'a Identity> {
    match seen.entry(key) {
        Entry::Occupied(held) => Some(*held.get()),
        Entry::Vacant(slot) => {
            slot.insert(identity);
            None
        }
    }
}

/// A UUID as Xray's VLESS validator keys a client: bytes 6 and 7 are
/// ignored (`ProcessUUID`, v26.9.30 `proxy/vless/validator.go:21-25`, used
/// by `Add`, `Get` and `Del`), so two UUIDs that differ only there are one
/// client to Xray. It borrows the secret's bytes and copies nothing.
/// (sing-quic's Hysteria2 table is keyed by the whole password text,
/// `hysteria2/service.go:151-157` at the pinned v0.7.1-0.20260924092235,
/// so passwords are compared whole.)
struct XrayUserKey<'a>(&'a [u8; 16]);

impl<'a> XrayUserKey<'a> {
    fn of(uuid: &'a Secret<Uuid>) -> Self {
        Self(uuid.expose_secret().as_bytes())
    }

    fn significant(&self) -> (&[u8], &[u8]) {
        (&self.0[..6], &self.0[8..])
    }
}

impl PartialEq for XrayUserKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for XrayUserKey<'_> {}

impl PartialOrd for XrayUserKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for XrayUserKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.significant().cmp(&other.significant())
    }
}
