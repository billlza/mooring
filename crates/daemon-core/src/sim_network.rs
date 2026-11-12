// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM's network (design §10.2, §15.3): what the M7 reported when the
//! carrier check and the billing cycle were recorded, and whether it
//! reports something else now.
//!
//! The carrier check (`exit record-carrier`) and the billing cycle
//! (`exit init`, `sim set-anchor`) are records about one SIM, and nothing
//! in the state ties them to it: when the SIM in the M7 is changed, both
//! are the old SIM's until the operator records them again, and nothing
//! said so (the record of 2026-11-12, design §15.3). So the daemon keeps a
//! record of its own. Its *baseline* is what the M7 reported at the first
//! poll that found it attached under the carrier check and the cycle rule
//! now recorded; while a later poll reports something else, the record
//! holds that too, and since when.
//!
//! What is compared is a [`SimNetwork`]: the SIM's service provider name
//! and the codes of the network the M7 is registered on, the two leaves of
//! the M7's allowlist that tell SIMs apart. Neither names a subscriber.
//! The ICCID and the IMSI would identify the card, and the adapter never
//! reads them (design §1.1, §15.5): two SIMs of one carrier therefore look
//! alike, and one SIM that its carrier moves to another network looks like
//! another.
//!
//! A baseline is taken anew when the carrier check or the cycle rule is no
//! longer the one it was taken under ([`RecordedUnder`]), which is how the
//! daemon sees that the operator recorded either again. The other network
//! goes when the M7 reports the baseline's again.
//!
//! Nothing here reads a clock or a file: [`SimNetworkRecord::observed`]
//! decides, and the daemon keeps the record's bytes in
//! `run/sim-network.json` through `mooring-store`, so that a restart
//! neither forgets the baseline nor dates a change anew.

use mooring_model::exit::{EgressCheck, ExitSite};
use mooring_model::{CycleRule, UnixTime};
use serde::{Deserialize, Serialize};

use crate::router::{CarrierName, Plmn, RadioState, RouterStatus};

/// The record's document version.
pub const SIM_NETWORK_VERSION: u32 = 1;

/// The largest record read, in bytes.
pub const MAX_SIM_NETWORK_BYTES: usize = 64 * 1024;

/// What the M7 reports that tells one SIM from another: the SIM's name
/// and the network it is registered on. It names a carrier and a network,
/// never a subscriber.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimNetwork {
    /// The SIM's service provider name; `None` for a SIM that carries
    /// none (the M7 reports the empty string, design §15.6 rule 2).
    #[serde(deserialize_with = "Option::deserialize")]
    pub spn: Option<CarrierName>,
    /// The codes of the network the M7 is registered on.
    pub plmn: Plmn,
}

impl SimNetwork {
    /// What `status` says of the SIM and its network; `None` without a
    /// data session, when the M7 names no network to compare.
    #[must_use]
    pub fn of(status: &RouterStatus) -> Option<Self> {
        let parts = status.parts();
        match &parts.radio {
            RadioState::NoService => None,
            RadioState::Attached(radio) => Some(Self {
                spn: parts.sim_spn.clone(),
                plmn: radio.plmn,
            }),
        }
    }
}

/// How the baseline came to be taken when it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineOrigin {
    /// The daemon found no record: the first run of a build that keeps
    /// one, or a run directory that was emptied. A SIM changed before
    /// then is not noticed.
    NoRecord,
    /// The carrier check or the cycle rule differed from the ones the
    /// record was taken under: the operator recorded one of them.
    Recorded,
    /// The record could not be read and was begun again. A SIM changed
    /// before then is not noticed.
    RecordUnreadable,
}

/// A network other than the baseline's, which the M7 reports now.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtherNetwork {
    /// What the M7 reported at the latest poll that found it attached.
    pub network: SimNetwork,
    /// Since when it has reported a network other than the baseline's: the
    /// first such poll after the last one that reported the baseline's.
    pub since: UnixTime,
}

/// `other` was given the baseline's own network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the other network is the baseline's own")]
pub struct OtherNetworkIsBaseline;

/// The baseline, and the other network the M7 reports now, if it does.
/// Built only by [`NetworkBaseline::new`] (also when decoded), so the
/// other network is never the baseline's own.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "NetworkBaselineRepr", into = "NetworkBaselineRepr")]
pub struct NetworkBaseline {
    network: SimNetwork,
    first_seen: UnixTime,
    other: Option<OtherNetwork>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBaselineRepr {
    network: SimNetwork,
    first_seen: UnixTime,
    #[serde(deserialize_with = "Option::deserialize")]
    other: Option<OtherNetwork>,
}

impl NetworkBaseline {
    /// The baseline `network`, first seen at `first_seen`, with the
    /// `other` network the M7 reports now; `OtherNetworkIsBaseline` when
    /// that is `network` itself.
    pub fn new(
        network: SimNetwork,
        first_seen: UnixTime,
        other: Option<OtherNetwork>,
    ) -> Result<Self, OtherNetworkIsBaseline> {
        if other.as_ref().is_some_and(|other| other.network == network) {
            return Err(OtherNetworkIsBaseline);
        }
        Ok(Self {
            network,
            first_seen,
            other,
        })
    }

    /// What the M7 reported when the baseline was taken.
    #[must_use]
    pub const fn network(&self) -> &SimNetwork {
        &self.network
    }

    /// When the baseline was taken: the poll's time, by the Mac's clock.
    #[must_use]
    pub const fn first_seen(&self) -> UnixTime {
        self.first_seen
    }

    /// The other network the M7 reports now; `None` while it reports the
    /// baseline's.
    #[must_use]
    pub const fn other(&self) -> Option<&OtherNetwork> {
        self.other.as_ref()
    }

    /// The baseline after a poll at `at` that found the M7 attached and
    /// reporting `network`. The baseline's own network ends an other one;
    /// any other is the other one now, since the first that was not the
    /// baseline's. No time is left after `at`, so that a clock that
    /// stepped back dates nothing in the future.
    fn seen(self, network: &SimNetwork, at: UnixTime) -> Self {
        let other = (*network != self.network).then(|| OtherNetwork {
            network: network.clone(),
            since: self.other.map_or(at, |other| other.since.min(at)),
        });
        Self {
            network: self.network,
            first_seen: self.first_seen.min(at),
            other,
        }
    }
}

impl TryFrom<NetworkBaselineRepr> for NetworkBaseline {
    type Error = OtherNetworkIsBaseline;

    fn try_from(repr: NetworkBaselineRepr) -> Result<Self, Self::Error> {
        Self::new(repr.network, repr.first_seen, repr.other)
    }
}

impl From<NetworkBaseline> for NetworkBaselineRepr {
    fn from(baseline: NetworkBaseline) -> Self {
        Self {
            network: baseline.network,
            first_seen: baseline.first_seen,
            other: baseline.other,
        }
    }
}

/// What the status says of the SIM's network (`sim.network`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimNetworkStatus {
    /// How the baseline came to be taken when it was.
    pub origin: BaselineOrigin,
    /// The baseline; `None` until a poll finds the M7 attached under the
    /// carrier check and the cycle rule now recorded.
    #[serde(deserialize_with = "Option::deserialize")]
    pub baseline: Option<NetworkBaseline>,
}

/// What a baseline is taken under: the two records about the SIM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedUnder {
    /// The carrier check; `None` before `exit record-carrier`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub check: Option<EgressCheck>,
    /// The billing cycles' rule.
    pub cycle: CycleRule,
}

impl RecordedUnder {
    /// The carrier check and the cycle rule `exit` records.
    #[must_use]
    pub fn of(exit: &ExitSite) -> Self {
        Self {
            check: exit.egress_check.clone(),
            cycle: exit.sim.cycle(),
        }
    }
}

/// The record is not a version-1 record of the SIM's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the record of the SIM's network is corrupt")]
pub struct SimNetworkCorrupt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    under: RecordedUnder,
    network: SimNetworkStatus,
}

/// The daemon's record: what the baseline was taken under, and what the
/// status says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimNetworkRecord {
    under: RecordedUnder,
    status: SimNetworkStatus,
}

impl SimNetworkRecord {
    /// A record without a baseline, begun under `under` for `origin`.
    #[must_use]
    pub const fn new(under: RecordedUnder, origin: BaselineOrigin) -> Self {
        Self {
            under,
            status: SimNetworkStatus {
                origin,
                baseline: None,
            },
        }
    }

    /// Reads a record the daemon wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self, SimNetworkCorrupt> {
        if bytes.len() > MAX_SIM_NETWORK_BYTES {
            return Err(SimNetworkCorrupt);
        }
        let document: Document = serde_json::from_slice(bytes).map_err(|_| SimNetworkCorrupt)?;
        if document.version != SIM_NETWORK_VERSION {
            return Err(SimNetworkCorrupt);
        }
        Ok(Self {
            under: document.under,
            status: document.network,
        })
    }

    /// The record as the daemon writes it.
    pub fn encode(&self) -> Result<Vec<u8>, SimNetworkCorrupt> {
        let mut bytes = serde_json::to_vec_pretty(&Document {
            version: SIM_NETWORK_VERSION,
            under: self.under.clone(),
            network: self.status.clone(),
        })
        .map_err(|_| SimNetworkCorrupt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// The record after the daemon read `under` from the state and, if it
    /// then polled the M7 and found it attached, `poll`: what the M7
    /// reported and when the Mac polled it.
    ///
    /// A carrier check or a cycle rule other than the record's begins the
    /// record again, without a baseline (`Recorded`). A poll then gives a
    /// record without a baseline its baseline, and one with a baseline
    /// its other network, or none when the M7 reports the baseline's.
    /// Without a poll nothing else changes: an M7 that is not attached,
    /// or does not answer, says nothing of its SIM.
    #[must_use]
    pub fn observed(&self, under: &RecordedUnder, poll: Option<(&SimNetwork, UnixTime)>) -> Self {
        let mut next = if self.under == *under {
            self.clone()
        } else {
            Self::new(under.clone(), BaselineOrigin::Recorded)
        };
        if let Some((network, at)) = poll {
            next.status.baseline = Some(match next.status.baseline {
                None => NetworkBaseline {
                    network: network.clone(),
                    first_seen: at,
                    other: None,
                },
                Some(baseline) => baseline.seen(network, at),
            });
        }
        next
    }

    /// What the record was taken under.
    #[must_use]
    pub const fn under(&self) -> &RecordedUnder {
        &self.under
    }

    /// What the status says.
    #[must_use]
    pub const fn status(&self) -> &SimNetworkStatus {
        &self.status
    }
}
