// SPDX-License-Identifier: GPL-3.0-or-later

//! The identities a node serves and their per-node credentials: every
//! active user holding credentials on the node, in id order, then the
//! Mac's probe identity.

use std::fmt;
use std::str::FromStr;

use mooring_agent_proto::{Inbound, OpaqueUserId, Principal, StatsEmail};
use mooring_model::ids::{NodeId, ShortId, UserId, Uuid};
use mooring_model::secret::{Password, Secret, SecretSnapshot};
use mooring_model::{Deployment, Node};

use crate::error::{RenderError, WireField};
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

/// Every identity `node` serves, users in id order, then the probe.
pub(crate) fn served(
    deployment: &Deployment,
    node: &Node,
    secrets: &SecretSnapshot,
) -> Result<Vec<Served>, RenderError> {
    let id: &NodeId = &node.id;
    let mut served = Vec::new();
    for (user, public) in deployment.served_users(id) {
        served.push(Served {
            identity: Identity::User(user.id.clone()),
            vless: secrets.user_vless_uuid(&user.id, id)?.clone(),
            short_id: public.short_id,
            loopback: secrets.user_loop_uuid(&user.id, id)?.clone(),
            hy2: secrets.user_hy2_password(&user.id, id)?.clone(),
        });
    }
    served.push(Served {
        identity: Identity::Probe,
        vless: secrets.probe_vless_uuid(id)?.clone(),
        short_id: node.reality.probe_short_id,
        loopback: secrets.probe_loop_uuid(id)?.clone(),
        hy2: secrets.probe_hy2_password(id)?.clone(),
    });
    Ok(served)
}
