// SPDX-License-Identifier: GPL-3.0-or-later

//! [`RenderError`]: every way rendering can fail (design §14).

use std::fmt;
use std::net::Ipv4Addr;

use mooring_agent_proto::TargetHost;
use mooring_export::ExportError;
use mooring_model::dns::DnsName;
use mooring_model::node::LifecycleStage;
use mooring_model::secret::SecretSnapshotError;
use mooring_model::{ModelError, NodeId, UserId, kinds};

/// A field whose value one side accepted and the other side's rule for the
/// same field refused. The model and the agent protocol write the rules to
/// match, and `src/tests/wire_rules.rs` proves every valid value converts; the
/// variant exists so a drift between them fails loudly instead of rendering
/// something the agent would reject or recording something it did not say.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WireField {
    /// The node's REALITY target name as a `watch.json` `TargetHost`.
    TargetHost(NodeId),
    /// A user id as the opaque name in its Xray accounting email.
    AccountingName(UserId),
    /// A VPS uplink interface name, recorded or reported.
    UplinkInterface,
    /// A VPS ephemeral port range, recorded or reported.
    EphemeralPorts,
    /// A certificate name `TargetCheck` reported.
    CertificateName,
    /// An HTTP status `TargetCheck` reported.
    HttpStatus,
    /// An Ed25519 SSH public key as the protocol's `ssh-ed25519` line.
    SshEd25519Key,
}

impl fmt::Display for WireField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetHost(node) => write!(f, "the REALITY target name of node {node}"),
            Self::AccountingName(user) => write!(f, "the accounting name of user {user}"),
            Self::UplinkInterface => f.write_str("the VPS uplink interface name"),
            Self::EphemeralPorts => f.write_str("the VPS ephemeral port range"),
            Self::CertificateName => f.write_str("a target certificate name"),
            Self::HttpStatus => f.write_str("the target HTTP status"),
            Self::SshEd25519Key => f.write_str("an Ed25519 SSH public key line"),
        }
    }
}

/// Why a one-time SSH host private key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostKeyRule {
    /// The text does not start with the `OPENSSH PRIVATE KEY` BEGIN line and
    /// end with its END line, each followed by one newline.
    Armor,
    /// The body is empty, a line is empty, longer than 70 characters or
    /// holds a character outside standard base64, or the lines together are
    /// not padded standard base64.
    Body,
    /// The decoded body is not one unencrypted `openssh-key-v1` Ed25519 key
    /// (cipher and KDF `none`) whose private section repeats the public key
    /// of its header, followed by a comment and `1, 2, 3, …` padding to the
    /// 8-byte block.
    Contents,
}

impl fmt::Display for HostKeyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Armor => "the OPENSSH PRIVATE KEY armor lines are missing or malformed",
            Self::Body => "the body is not lines of at most 70 characters of padded base64",
            Self::Contents => "the body is not one unencrypted openssh-key-v1 Ed25519 key",
        })
    }
}

/// Rendering a VPS bundle, a Mac engine config or cloud-init user-data failed.
///
/// No variant carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// A model lookup or rule refused the request: an unknown node, a node
    /// that cannot be rendered in its lifecycle stage, a missing target, or
    /// more probed nodes than the probe port plan holds.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// The secret snapshot lacks a secret the configuration needs.
    #[error(transparent)]
    Secret(#[from] SecretSnapshotError),
    /// The export emitter refused a probe outbound.
    #[error(transparent)]
    Export(#[from] ExportError),
    /// No node is applied, so the Mac has no tunnel to serve or probe.
    #[error("no node has applied a configuration, so the Mac has no tunnel to serve or probe")]
    NoAppliedNodes,
    /// A value does not satisfy the other side's rule for its field.
    #[error("{field} does not satisfy both the model's and the agent protocol's rule")]
    WireValue {
        /// The value that was refused.
        field: WireField,
    },
    /// At adoption, the address `Hello` reports on the VPS uplink is not the
    /// address the Mac connected to (design §13.2: VPS4 must be on the
    /// uplink interface).
    #[error("the VPS reports {reported} on its uplink, not the node address {address}")]
    AddressNotOnUplink {
        /// The node address.
        address: Ipv4Addr,
        /// The address the VPS reported.
        reported: Ipv4Addr,
    },
    /// A `TargetCheck` report names another host than the one requested.
    #[error("the target report is about {reported}, not the requested {requested}")]
    TargetFactsForOtherHost {
        /// The host requested.
        requested: DnsName,
        /// The host the agent reported on.
        reported: TargetHost,
    },
    /// cloud-init user-data exists only for a planned node.
    #[error("node {node} is {stage}; cloud-init user-data is rendered only for planned nodes")]
    NodeNotPlanned {
        /// The node.
        node: NodeId,
        /// Its lifecycle stage.
        stage: LifecycleStage,
    },
    /// The one-time host private key is not the key pair of the SSH host
    /// key pinned for the node.
    #[error("the one-time host private key is not the SSH host key pinned for node {node}")]
    HostKeyNotPinned {
        /// The node.
        node: NodeId,
    },
    /// The one-time host private key is not an OpenSSH private key text.
    #[error("the one-time host private key was refused: {rule}")]
    InvalidHostKey {
        /// The rule it broke.
        rule: HostKeyRule,
    },
    /// Encoding a rendered JSON document failed.
    #[error("encoding a rendered JSON configuration failed")]
    Encode(#[source] serde_json::Error),
}

kinds! {
    /// The kind of a [`RenderError`], without its details.
    pub enum RenderErrorKind {
        /// See [`RenderError::Model`].
        Model,
        /// See [`RenderError::Secret`].
        Secret,
        /// See [`RenderError::Export`].
        Export,
        /// See [`RenderError::NoAppliedNodes`].
        NoAppliedNodes,
        /// See [`RenderError::WireValue`].
        WireValue,
        /// See [`RenderError::AddressNotOnUplink`].
        AddressNotOnUplink,
        /// See [`RenderError::TargetFactsForOtherHost`].
        TargetFactsForOtherHost,
        /// See [`RenderError::NodeNotPlanned`].
        NodeNotPlanned,
        /// See [`RenderError::HostKeyNotPinned`].
        HostKeyNotPinned,
        /// See [`RenderError::InvalidHostKey`].
        InvalidHostKey,
        /// See [`RenderError::Encode`].
        Encode,
    }
}

impl RenderError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> RenderErrorKind {
        match self {
            Self::Model(_) => RenderErrorKind::Model,
            Self::Secret(_) => RenderErrorKind::Secret,
            Self::Export(_) => RenderErrorKind::Export,
            Self::NoAppliedNodes => RenderErrorKind::NoAppliedNodes,
            Self::WireValue { .. } => RenderErrorKind::WireValue,
            Self::AddressNotOnUplink { .. } => RenderErrorKind::AddressNotOnUplink,
            Self::TargetFactsForOtherHost { .. } => RenderErrorKind::TargetFactsForOtherHost,
            Self::NodeNotPlanned { .. } => RenderErrorKind::NodeNotPlanned,
            Self::HostKeyNotPinned { .. } => RenderErrorKind::HostKeyNotPinned,
            Self::InvalidHostKey { .. } => RenderErrorKind::InvalidHostKey,
            Self::Encode(_) => RenderErrorKind::Encode,
        }
    }
}
