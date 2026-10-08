// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure Mooring domain types and invariants (design §7).
//!
//! Every newtype validates in its constructor and deserialises through the
//! same check, so an invalid value cannot be built or read. Invariants that
//! span entities are checked once, when a [`Deployment`] is built from its
//! [`DeploymentParts`]. Nothing here performs I/O, reads a clock or draws
//! randomness: producers in other crates pass entropy and times in.
//!
//! Secrets live only in [`secret::Secret`] and the typed materials of
//! [`secret`]; none of them implements `Serialize` or `Display`, and the
//! state types derive `Serialize`, so the state cannot hold a secret.

#![deny(missing_docs)]

mod encoding;
mod kinds;
#[cfg(test)]
mod testing;

pub mod cert;
pub mod collections;
pub mod counters;
pub mod deployment;
pub mod digest;
pub mod dns;
pub mod error;
pub mod exact;
pub mod exit;
pub mod ids;
pub mod iface;
pub mod ipv4;
pub mod keys;
pub mod node;
pub mod ports;
pub mod secret;
pub mod state;
pub mod target;
pub mod time;
pub mod user;
pub mod verdict;
pub mod wg;

pub use cert::{CertPins, CertificatePem, Hy2Sni};
pub use collections::NonEmpty;
pub use counters::{ConfigGeneration, RuntimeRevision};
pub use deployment::{Bookkeeping, Deployment, DeploymentParts, MAX_ACTIVE_NODES};
pub use digest::{Sha256Digest, SpkiSha256};
pub use dns::DnsName;
pub use error::{EntityId, ModelError, ModelErrorKind};
pub use exit::{
    EgressCheck, ExitSite, FlowCap, Pairing, ProbePolicy, SimPolicy, TrafficPolicy, Uplink,
};
pub use ids::{LocalLabel, NodeId, ShortId, UserId, Uuid};
pub use iface::{InterfaceSelector, MacAddr, ResolvedInterfaces};
pub use ipv4::{CarrierPrefix, PublicIpv4, SPECIAL_V4, SpecialClass, classify};
pub use keys::{Ed25519Pub, WgKey, X25519Pub};
pub use node::{
    HostFacts, Hy2Server, Node, NodeAddress, NodeLifecycle, NodeRole, RealityServer, SshPin,
};
pub use ports::{HopInterval, Hy2Listener, Hy2Obfs, ListenerIdx, Port, PortPlan, PortRange};
pub use secret::{
    Secret, SecretEntry, SecretKind, SecretKindMismatch, SecretMaterial, SecretRef, SecretSnapshot,
};
pub use state::{RuntimeIntent, StateFile, StateV1};
pub use target::{TargetAttestation, TargetSpec, qualify};
pub use time::UnixTime;
pub use user::{Capability, ClientLine, ClientProfile, User, UserNodePublic, UserStatus};
pub use verdict::{Verdict, Violation};
pub use wg::{Keepalive, WgIndex, WgLink};
