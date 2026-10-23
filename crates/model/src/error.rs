// SPDX-License-Identifier: GPL-3.0-or-later

//! The model's typed error taxonomy (design §14, domain `model`).

use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use ipnet::Ipv4Net;

use crate::alerting::WallClockTime;
use crate::cert::PemLabel;
use crate::counters::{ConfigGeneration, CounterKind};
use crate::digest::DigestEncoding;
use crate::dns::DnsNameRule;
use crate::ids::{NodeId, PublicAlias, UserId, UuidRule};
use crate::iface::{InterfaceNameKind, InterfaceRole, UplinkMode};
use crate::ipv4::{PrefixRule, SpecialClass};
use crate::keys::{Ed25519Pub, PublicKeyKind};
use crate::kinds;
use crate::node::LifecycleStage;
use crate::ports::{Port, PortConflict, PortRange};
use crate::secret::SecretKind;
use crate::user::AgreementVersion;
use crate::wg::WgIndex;

/// Identifies the entity behind a duplicate-id error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityId {
    /// A node id.
    Node(NodeId),
    /// A user id.
    User(UserId),
    /// A viewer, by its public key.
    Viewer(Ed25519Pub),
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(id) => write!(f, "node {id}"),
            Self::User(id) => write!(f, "user {id}"),
            Self::Viewer(key) => write!(f, "viewer {key}"),
        }
    }
}

/// A value or aggregate violates a model invariant.
///
/// Errors never echo secret material: variants about secrets, UUIDs and
/// short ids carry only the rule that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// The text is not a dotted-quad IPv4 address.
    #[error("not a dotted-quad IPv4 address")]
    InvalidIpv4,
    /// The address lies in a `SPECIAL_V4` range.
    #[error("{addr} is in the special-purpose range {class}")]
    InvalidAddress {
        /// The rejected address.
        addr: Ipv4Addr,
        /// The special-purpose class it belongs to.
        class: SpecialClass,
    },
    /// The text is not an IPv4 prefix in `a.b.c.d/len` form.
    #[error("not an IPv4 prefix in a.b.c.d/len form")]
    InvalidCidr,
    /// The prefix breaks a prefix rule.
    #[error("prefix {prefix} is invalid: {rule}")]
    InvalidPrefix {
        /// The rejected prefix.
        prefix: Ipv4Net,
        /// The rule it breaks.
        rule: PrefixRule,
    },
    /// The short id is not 16 lowercase hex characters of a non-zero value.
    #[error("short id must be 16 lowercase hex characters and not all zero")]
    InvalidShortId,
    /// The DNS name breaks an LDH rule.
    #[error("invalid DNS name: {rule}")]
    InvalidDnsName {
        /// The rule it breaks.
        rule: DnsNameRule,
    },
    /// The Hysteria2 SNI is not `n<16 lowercase hex>.internal`.
    #[error("Hysteria2 SNI must be n<16 lowercase hex>.internal")]
    InvalidHy2Sni,
    /// The node id does not match `^[a-z][a-z0-9]{1,11}$`.
    #[error("node id must match ^[a-z][a-z0-9]{{1,11}}$")]
    InvalidNodeId,
    /// The user id is not 10 lowercase RFC 4648 base32 characters.
    #[error("user id must be 10 lowercase base32 characters (a-z, 2-7)")]
    InvalidUserId,
    /// The local label is empty, too long, padded or contains control characters.
    #[error("label must be 1-64 characters, without control characters or surrounding whitespace")]
    InvalidLabel,
    /// The UUID breaks a credential UUID rule.
    #[error("invalid UUID: {rule}")]
    InvalidUuid {
        /// The rule it breaks.
        rule: UuidRule,
    },
    /// The public key text or bytes are invalid for its encoding.
    #[error("invalid {key} public key")]
    InvalidPublicKey {
        /// Which public key type was being parsed.
        key: PublicKeyKind,
    },
    /// The secret material is invalid for its kind; the material is not echoed.
    #[error("invalid {kind} secret material")]
    InvalidSecret {
        /// Which secret kind was being parsed.
        kind: SecretKind,
    },
    /// The text is not a secret reference.
    #[error("not a secret reference")]
    InvalidSecretRef,
    /// The PEM text is not one canonical block with the expected label.
    #[error("invalid {label} PEM block")]
    InvalidPem {
        /// The expected PEM label.
        label: PemLabel,
    },
    /// The SHA-256 digest text has the wrong length or alphabet.
    #[error("invalid SHA-256 digest ({encoding})")]
    InvalidDigest {
        /// The expected text encoding.
        encoding: DigestEncoding,
    },
    /// Port zero is not a port.
    #[error("port must be in 1..=65535")]
    InvalidPort,
    /// The port range is empty, inverted or starts at zero.
    #[error("port range {start}-{end} is invalid")]
    InvalidPortRange {
        /// The first port.
        start: u16,
        /// The last port.
        end: u16,
    },
    /// The hop interval is outside 5..=3600 seconds.
    #[error("hop interval {seconds}s is outside 5..=3600")]
    InvalidHopInterval {
        /// The rejected interval in seconds.
        seconds: u16,
    },
    /// The hop range does not start right after the listener port.
    #[error("Hysteria2 hop range {hop} must start right after listener port {port}")]
    InvalidHy2Listener {
        /// The listener port.
        port: Port,
        /// The hop range.
        hop: PortRange,
    },
    /// The port plan breaks a disjointness or ephemeral-range rule.
    #[error("port plan conflict: {conflict}")]
    PortPlanConflict {
        /// The conflict found.
        conflict: PortConflict,
    },
    /// The interface name is invalid for its platform.
    #[error("invalid {flavor} interface name")]
    InvalidInterfaceName {
        /// The platform naming rule applied.
        flavor: InterfaceNameKind,
    },
    /// The link-layer address is malformed, zero or multicast.
    #[error("link-layer address must be a unicast aa:bb:cc:dd:ee:ff")]
    InvalidMacAddr,
    /// Interface index zero does not name an interface.
    #[error("interface index must be non-zero")]
    InvalidInterfaceIndex,
    /// The uplink resolved to the egress interface itself.
    #[error("the Separate uplink resolved to the egress interface")]
    UplinkEqualsEgress,
    /// A resolved interface is not one its selector selects.
    #[error(
        "the resolved {role} interface does not match its selector's subnet or link-layer address"
    )]
    InterfaceNotSelected {
        /// Which interface.
        role: InterfaceRole,
    },
    /// The resolved uplink mode differs from the configured one.
    #[error("the uplink is configured {configured} but was resolved {resolved}")]
    UplinkModeMismatch {
        /// The configured mode.
        configured: UplinkMode,
        /// The resolved mode.
        resolved: UplinkMode,
    },
    /// The interfaces were resolved for another egress selector or uplink
    /// configuration than the deployment's.
    #[error("the interfaces were resolved for a different exit site configuration")]
    InterfacesForOtherSite,
    /// The WireGuard index is outside 1..=255.
    #[error("WireGuard index {value} is outside 1..=255")]
    InvalidWgIndex {
        /// The rejected value.
        value: u8,
    },
    /// Every WireGuard index has been allocated; indices are never reused.
    #[error("every WireGuard index has been allocated")]
    WgIndexExhausted,
    /// The keepalive is outside 5..=60 seconds.
    #[error("keepalive {seconds}s is outside 5..=60")]
    InvalidKeepalive {
        /// The rejected keepalive in seconds.
        seconds: u16,
    },
    /// A counter must start at 1.
    #[error("{counter} must be at least 1")]
    InvalidCounter {
        /// Which counter.
        counter: CounterKind,
    },
    /// A counter cannot be incremented further.
    #[error("{counter} overflowed")]
    CounterOverflow {
        /// Which counter.
        counter: CounterKind,
    },
    /// A collection that must hold at least one element is empty.
    #[error("collection must not be empty")]
    EmptyCollection,
    /// The text is not a `YYYY-MM-DD` calendar date between 1970 and 9999,
    /// or a computed date falls outside that range.
    #[error("not a YYYY-MM-DD calendar date between 1970-01-01 and 9999-12-31")]
    InvalidDate,
    /// The version-1 SIM billing cycle day is outside 1..=28.
    #[error("billing cycle day {day} is outside 1..=28")]
    InvalidCycleDay {
        /// The rejected day.
        day: u8,
    },
    /// The SIM bill day is outside 1..=31.
    #[error("bill day {day} is outside 1..=31")]
    InvalidBillDay {
        /// The rejected day.
        day: u8,
    },
    /// A cycle length or rolling window is outside 1..=366 days.
    #[error("{days} days is outside 1..=366")]
    InvalidPeriodDays {
        /// The rejected number of days.
        days: u16,
    },
    /// The SIM warning threshold is zero or not below the hard stop.
    #[error("SIM warning threshold {warn_bytes} must be positive and below any hard stop")]
    InvalidSimThresholds {
        /// The warning threshold in bytes.
        warn_bytes: u64,
        /// The hard-stop threshold in bytes, if one is set.
        hard_stop_bytes: Option<u64>,
    },
    /// A SIM threshold (the hard stop, or the warning when there is none)
    /// is not below the recorded plan's fair-use line or allowance.
    #[error(
        "SIM threshold {threshold_bytes} must be below the recorded plan's line of {line_bytes} bytes"
    )]
    SimThresholdAbovePlan {
        /// The threshold in bytes.
        threshold_bytes: u64,
        /// The plan's fair-use line or allowance, in bytes.
        line_bytes: u64,
    },
    /// Accepting deprioritisation needs a recorded plan with a fair-use
    /// line; an unlimited plan without a line, a capped plan and an
    /// unrecorded plan need a hard stop.
    #[error(
        "accepting deprioritisation needs a recorded plan with a fair-use line; set a hard stop instead"
    )]
    DeprioritisationNeedsFairUseLine,
    /// A hard stop, once in each of the cycles one window of a rolling
    /// fair-use line can overlap, is not below that line.
    #[error(
        "a hard stop of {stop_bytes} bytes in each of the {cycles} cycles a {window_days}-day window can overlap is not below the plan's rolling line of {line_bytes} bytes"
    )]
    SimStopAboveRollingLine {
        /// The hard stop in bytes, per cycle.
        stop_bytes: u64,
        /// The most cycles one window overlaps.
        cycles: u64,
        /// The window, in days.
        window_days: u16,
        /// The line per window, in bytes.
        line_bytes: u64,
    },
    /// A version-1 SIM policy without a hard stop cannot be lifted: version 2
    /// needs an explicit stop policy (critique C-10).
    #[error(
        "the version-1 SIM policy has no hard stop, and version 2 needs an explicit stop policy: give the version-1 document a hard stop to lift it, then record the plan with `sim set-plan`"
    )]
    StopPolicyUnchosen,
    /// A fresh deployment, and every change that edits the exit's SIM
    /// policy, needs the policy's plan recorded (P0-1): only a policy
    /// lifted from version 1 has none, and it keeps none only while it is
    /// left as it is.
    #[error(
        "the exit's SIM plan is not recorded; a fresh deployment and every edited SIM policy need a recorded plan (`sim set-plan`)"
    )]
    PlanNotRecorded,
    /// The quota warning share is outside 1..=99 percent.
    #[error("quota warning share {percent}% is outside 1..=99")]
    InvalidWarnPercent {
        /// The rejected percentage.
        percent: u8,
    },
    /// The share of the served budget is outside 1..=100 percent.
    #[error("budget share {percent}% is outside 1..=100")]
    InvalidBudgetPercent {
        /// The rejected percentage.
        percent: u8,
    },
    /// The SIM factor is below 1000 permille: every served byte crosses the
    /// SIM at least once.
    #[error("SIM factor {permille} permille is below 1000")]
    InvalidSimFactor {
        /// The rejected factor, in thousandths.
        permille: u16,
    },
    /// The text is not a wall-clock time `HH:MM` between 00:00 and 23:59.
    #[error("not an HH:MM wall-clock time between 00:00 and 23:59")]
    InvalidWallClockTime,
    /// The public alias is not two groups of four lowercase base32
    /// characters joined by a hyphen.
    #[error("public alias must be xxxx-xxxx with lowercase base32 characters (a-z, 2-7)")]
    InvalidPublicAlias,
    /// The uplink baseline's percentiles are zero or out of order.
    #[error("uplink baseline needs 0 < p10 ({p10_bps} bit/s) <= p50 ({p50_bps} bit/s)")]
    InvalidUplinkBaseline {
        /// The rejected 10th percentile.
        p10_bps: u64,
        /// The rejected median.
        p50_bps: u64,
    },
    /// The probe interval is outside 1..=86400 seconds.
    #[error("probe interval {seconds}s is outside 1..=86400")]
    InvalidProbeInterval {
        /// The rejected interval in seconds.
        seconds: u32,
    },
    /// The probe ports would be privileged or reach the macOS ephemeral range.
    #[error("probe base port {port} must leave every probe port in 1024..49152")]
    InvalidProbeBasePort {
        /// The rejected base port.
        port: u16,
    },
    /// The flow cap is outside 1..=65535.
    #[error("flow cap {value} is outside 1..=65535")]
    InvalidFlowCap {
        /// The rejected cap.
        value: u32,
    },
    /// The HTTP status code is outside 100..=599.
    #[error("HTTP status {status} is outside 100..=599")]
    InvalidHttpStatus {
        /// The rejected status code.
        status: u16,
    },
    /// A reported certificate name is not 1..=253 printable ASCII characters.
    #[error("certificate name must be 1-253 printable ASCII characters")]
    InvalidCertificateName,
    /// The evidence URL is not a bounded printable https URL.
    #[error("evidence URL must be a printable https:// URL of at most 2048 bytes")]
    InvalidEvidenceUrl,
    /// A stored REALITY target lacks a positive operator attestation.
    #[error("REALITY target is not attested as same-ASN and non-CDN")]
    TargetNotAttested,
    /// No node has this id.
    #[error("unknown node {id}")]
    UnknownNode {
        /// The missing node id.
        id: NodeId,
    },
    /// No user has this id.
    #[error("unknown user {id}")]
    UnknownUser {
        /// The missing user id.
        id: UserId,
    },
    /// The id is already taken.
    #[error("duplicate {id}")]
    DuplicateId {
        /// The duplicated id.
        id: EntityId,
    },
    /// More active nodes than v1 supports.
    #[error("at most {max} active nodes are supported")]
    TooManyNodes {
        /// The supported maximum.
        max: usize,
    },
    /// Two nodes hold the same public address.
    #[error("two nodes share the address {addr}")]
    DuplicateNodeAddress {
        /// The shared address.
        addr: Ipv4Addr,
    },
    /// Two nodes hold the same WireGuard index.
    #[error("two nodes share WireGuard index {index}")]
    DuplicateWgIndex {
        /// The shared index.
        index: WgIndex,
    },
    /// A node holds a WireGuard index that was never allocated.
    #[error("WireGuard index {index} is not below the next index {next}")]
    WgIndexNotAllocated {
        /// The node's index.
        index: WgIndex,
        /// The deployment's next index.
        next: WgIndex,
    },
    /// Two credentials on one node share a REALITY short id.
    #[error("duplicate REALITY short id on node {node}")]
    DuplicateShortId {
        /// The node whose short ids collide.
        node: NodeId,
    },
    /// Two users share a public alias.
    #[error("two users share the public alias {alias}")]
    DuplicateAlias {
        /// The shared alias.
        alias: PublicAlias,
    },
    /// More users are active than the deployment's cap allows.
    #[error("{active} users are active, more than the cap of {max}")]
    TooManyActiveUsers {
        /// The cap.
        max: NonZeroU16,
        /// The number of active users.
        active: usize,
    },
    /// The node has no REALITY target yet.
    #[error("node {node} has no REALITY target")]
    TargetNotSet {
        /// The node lacking a target.
        node: NodeId,
    },
    /// A node claims a generation newer than the deployment's.
    #[error("node {node} applied generation {applied}, newer than the current {current}")]
    GenerationAhead {
        /// The node.
        node: NodeId,
        /// The generation the node claims.
        applied: ConfigGeneration,
        /// The deployment's generation.
        current: ConfigGeneration,
    },
    /// An applied node would record a generation older than the one it
    /// already confirmed; a node's confirmed generation never goes back.
    #[error("node {node} already confirmed generation {recorded}; refusing the older {applied}")]
    GenerationRegressed {
        /// The node.
        node: NodeId,
        /// The generation the node already confirmed.
        recorded: ConfigGeneration,
        /// The older generation offered.
        applied: ConfigGeneration,
    },
    /// The node's lifecycle stage does not allow rendering an Apply.
    #[error("node {node} is {stage}; only adopted or applied nodes can be applied")]
    NodeNotDeployable {
        /// The node.
        node: NodeId,
        /// Its lifecycle stage.
        stage: LifecycleStage,
    },
    /// A user holds credentials on a node whose secrets have been deleted.
    #[error("user {user} holds credentials on inactive node {node}")]
    CredentialsOnInactiveNode {
        /// The user.
        user: UserId,
        /// The inactive node.
        node: NodeId,
    },
    /// The digest time is before its zone's earliest daily time
    /// (`WallClockZone::earliest_daily_time`): earlier, the time of day is
    /// skipped or repeated when the clocks change, or falls on the previous
    /// UTC date.
    #[error(
        "digest time {at} is before {earliest}: an earlier time is skipped or repeated when the clocks change, or falls on the previous UTC date"
    )]
    DigestTimeTooEarly {
        /// The digest time.
        at: WallClockTime,
        /// The zone's earliest daily time.
        earliest: WallClockTime,
    },
    /// Alert channels are set up for a node that is not active; retiring a
    /// node drops its channels.
    #[error("alert channels are set up for inactive node {node}")]
    AlertChannelsOnInactiveNode {
        /// The inactive node.
        node: NodeId,
    },
    /// A revocation step names a user who is not pending revocation.
    #[error("user {user} is not pending revocation")]
    NotRevoking {
        /// The user.
        user: UserId,
    },
    /// Only an active user can be suspended.
    #[error("user {user} is not active")]
    UserNotActive {
        /// The user.
        user: UserId,
    },
    /// Only a suspended user can be resumed.
    #[error("user {user} is not suspended")]
    UserNotSuspended {
        /// The user.
        user: UserId,
    },
    /// The user is already pending revocation or revoked; revocation never
    /// goes back.
    #[error("user {user} is already pending revocation or revoked")]
    RevocationAlreadyStarted {
        /// The user.
        user: UserId,
    },
    /// A revocation step names a node the user holds no credentials on.
    #[error("user {user} holds no credentials on node {node}")]
    NoCredentialsOnNode {
        /// The user.
        user: UserId,
        /// The node.
        node: NodeId,
    },
    /// An agreement record would replace the recorded revision with an
    /// older one, as after a downgrade; a recorded revision never goes back.
    #[error(
        "user {user} accepted agreement revision {recorded}; refusing to record the older revision {offered}"
    )]
    AgreementRegressed {
        /// The user.
        user: UserId,
        /// The revision already recorded.
        recorded: AgreementVersion,
        /// The older revision offered.
        offered: AgreementVersion,
    },
    /// The carrier check is recorded already; replacing it is not a
    /// bookkeeping record.
    #[error("the exit's carrier check is recorded already; replacing it is a configuration change")]
    CarrierAlreadyRecorded,
    /// A retirement step names a node that is not retiring.
    #[error("node {node} is {stage}, not retiring")]
    NodeNotRetiring {
        /// The node.
        node: NodeId,
        /// Its lifecycle stage.
        stage: LifecycleStage,
    },
    /// A revoked user still holds per-node credentials.
    #[error("revoked user {user} still holds credentials")]
    RevokedUserHoldsCredentials {
        /// The user.
        user: UserId,
    },
    /// A user pending revocation holds credentials on no node; with no node
    /// left to commit the removal the user is `Revoked`.
    #[error("user {user} is pending revocation but no node holds its credentials")]
    RevokePendingWithoutCredentials {
        /// The user.
        user: UserId,
    },
    /// The state document has a different schema version.
    #[error("state version {found} is not the expected {expected}")]
    StateVersionMismatch {
        /// The version this type reads.
        expected: u32,
        /// The version found.
        found: u32,
    },
    /// The state document's version is not one this build reads.
    #[error("state version {found} is not a version this build reads")]
    UnknownStateVersion {
        /// The version found.
        found: u32,
    },
}

kinds! {
    /// The kind of a [`ModelError`], without its details.
    pub enum ModelErrorKind {
        /// See [`ModelError::InvalidIpv4`].
        InvalidIpv4,
        /// See [`ModelError::InvalidAddress`].
        InvalidAddress,
        /// See [`ModelError::InvalidCidr`].
        InvalidCidr,
        /// See [`ModelError::InvalidPrefix`].
        InvalidPrefix,
        /// See [`ModelError::InvalidShortId`].
        InvalidShortId,
        /// See [`ModelError::InvalidDnsName`].
        InvalidDnsName,
        /// See [`ModelError::InvalidHy2Sni`].
        InvalidHy2Sni,
        /// See [`ModelError::InvalidNodeId`].
        InvalidNodeId,
        /// See [`ModelError::InvalidUserId`].
        InvalidUserId,
        /// See [`ModelError::InvalidLabel`].
        InvalidLabel,
        /// See [`ModelError::InvalidUuid`].
        InvalidUuid,
        /// See [`ModelError::InvalidPublicKey`].
        InvalidPublicKey,
        /// See [`ModelError::InvalidSecret`].
        InvalidSecret,
        /// See [`ModelError::InvalidSecretRef`].
        InvalidSecretRef,
        /// See [`ModelError::InvalidPem`].
        InvalidPem,
        /// See [`ModelError::InvalidDigest`].
        InvalidDigest,
        /// See [`ModelError::InvalidPort`].
        InvalidPort,
        /// See [`ModelError::InvalidPortRange`].
        InvalidPortRange,
        /// See [`ModelError::InvalidHopInterval`].
        InvalidHopInterval,
        /// See [`ModelError::InvalidHy2Listener`].
        InvalidHy2Listener,
        /// See [`ModelError::PortPlanConflict`].
        PortPlanConflict,
        /// See [`ModelError::InvalidInterfaceName`].
        InvalidInterfaceName,
        /// See [`ModelError::InvalidMacAddr`].
        InvalidMacAddr,
        /// See [`ModelError::InvalidInterfaceIndex`].
        InvalidInterfaceIndex,
        /// See [`ModelError::UplinkEqualsEgress`].
        UplinkEqualsEgress,
        /// See [`ModelError::InterfaceNotSelected`].
        InterfaceNotSelected,
        /// See [`ModelError::UplinkModeMismatch`].
        UplinkModeMismatch,
        /// See [`ModelError::InterfacesForOtherSite`].
        InterfacesForOtherSite,
        /// See [`ModelError::InvalidWgIndex`].
        InvalidWgIndex,
        /// See [`ModelError::WgIndexExhausted`].
        WgIndexExhausted,
        /// See [`ModelError::InvalidKeepalive`].
        InvalidKeepalive,
        /// See [`ModelError::InvalidCounter`].
        InvalidCounter,
        /// See [`ModelError::CounterOverflow`].
        CounterOverflow,
        /// See [`ModelError::EmptyCollection`].
        EmptyCollection,
        /// See [`ModelError::InvalidDate`].
        InvalidDate,
        /// See [`ModelError::InvalidCycleDay`].
        InvalidCycleDay,
        /// See [`ModelError::InvalidBillDay`].
        InvalidBillDay,
        /// See [`ModelError::InvalidPeriodDays`].
        InvalidPeriodDays,
        /// See [`ModelError::InvalidSimThresholds`].
        InvalidSimThresholds,
        /// See [`ModelError::SimThresholdAbovePlan`].
        SimThresholdAbovePlan,
        /// See [`ModelError::DeprioritisationNeedsFairUseLine`].
        DeprioritisationNeedsFairUseLine,
        /// See [`ModelError::SimStopAboveRollingLine`].
        SimStopAboveRollingLine,
        /// See [`ModelError::StopPolicyUnchosen`].
        StopPolicyUnchosen,
        /// See [`ModelError::PlanNotRecorded`].
        PlanNotRecorded,
        /// See [`ModelError::InvalidWarnPercent`].
        InvalidWarnPercent,
        /// See [`ModelError::InvalidBudgetPercent`].
        InvalidBudgetPercent,
        /// See [`ModelError::InvalidSimFactor`].
        InvalidSimFactor,
        /// See [`ModelError::InvalidWallClockTime`].
        InvalidWallClockTime,
        /// See [`ModelError::InvalidPublicAlias`].
        InvalidPublicAlias,
        /// See [`ModelError::InvalidUplinkBaseline`].
        InvalidUplinkBaseline,
        /// See [`ModelError::InvalidProbeInterval`].
        InvalidProbeInterval,
        /// See [`ModelError::InvalidProbeBasePort`].
        InvalidProbeBasePort,
        /// See [`ModelError::InvalidFlowCap`].
        InvalidFlowCap,
        /// See [`ModelError::InvalidHttpStatus`].
        InvalidHttpStatus,
        /// See [`ModelError::InvalidCertificateName`].
        InvalidCertificateName,
        /// See [`ModelError::InvalidEvidenceUrl`].
        InvalidEvidenceUrl,
        /// See [`ModelError::TargetNotAttested`].
        TargetNotAttested,
        /// See [`ModelError::UnknownNode`].
        UnknownNode,
        /// See [`ModelError::UnknownUser`].
        UnknownUser,
        /// See [`ModelError::DuplicateId`].
        DuplicateId,
        /// See [`ModelError::TooManyNodes`].
        TooManyNodes,
        /// See [`ModelError::DuplicateNodeAddress`].
        DuplicateNodeAddress,
        /// See [`ModelError::DuplicateWgIndex`].
        DuplicateWgIndex,
        /// See [`ModelError::WgIndexNotAllocated`].
        WgIndexNotAllocated,
        /// See [`ModelError::DuplicateShortId`].
        DuplicateShortId,
        /// See [`ModelError::DuplicateAlias`].
        DuplicateAlias,
        /// See [`ModelError::TooManyActiveUsers`].
        TooManyActiveUsers,
        /// See [`ModelError::TargetNotSet`].
        TargetNotSet,
        /// See [`ModelError::GenerationAhead`].
        GenerationAhead,
        /// See [`ModelError::GenerationRegressed`].
        GenerationRegressed,
        /// See [`ModelError::NodeNotDeployable`].
        NodeNotDeployable,
        /// See [`ModelError::CredentialsOnInactiveNode`].
        CredentialsOnInactiveNode,
        /// See [`ModelError::DigestTimeTooEarly`].
        DigestTimeTooEarly,
        /// See [`ModelError::AlertChannelsOnInactiveNode`].
        AlertChannelsOnInactiveNode,
        /// See [`ModelError::NotRevoking`].
        NotRevoking,
        /// See [`ModelError::UserNotActive`].
        UserNotActive,
        /// See [`ModelError::UserNotSuspended`].
        UserNotSuspended,
        /// See [`ModelError::RevocationAlreadyStarted`].
        RevocationAlreadyStarted,
        /// See [`ModelError::NoCredentialsOnNode`].
        NoCredentialsOnNode,
        /// See [`ModelError::AgreementRegressed`].
        AgreementRegressed,
        /// See [`ModelError::CarrierAlreadyRecorded`].
        CarrierAlreadyRecorded,
        /// See [`ModelError::NodeNotRetiring`].
        NodeNotRetiring,
        /// See [`ModelError::RevokedUserHoldsCredentials`].
        RevokedUserHoldsCredentials,
        /// See [`ModelError::RevokePendingWithoutCredentials`].
        RevokePendingWithoutCredentials,
        /// See [`ModelError::StateVersionMismatch`].
        StateVersionMismatch,
        /// See [`ModelError::UnknownStateVersion`].
        UnknownStateVersion,
    }
}

impl ModelError {
    /// The kind of this error, for stable machine-readable reporting.
    #[must_use]
    pub const fn kind(&self) -> ModelErrorKind {
        match self {
            Self::InvalidIpv4 => ModelErrorKind::InvalidIpv4,
            Self::InvalidAddress { .. } => ModelErrorKind::InvalidAddress,
            Self::InvalidCidr => ModelErrorKind::InvalidCidr,
            Self::InvalidPrefix { .. } => ModelErrorKind::InvalidPrefix,
            Self::InvalidShortId => ModelErrorKind::InvalidShortId,
            Self::InvalidDnsName { .. } => ModelErrorKind::InvalidDnsName,
            Self::InvalidHy2Sni => ModelErrorKind::InvalidHy2Sni,
            Self::InvalidNodeId => ModelErrorKind::InvalidNodeId,
            Self::InvalidUserId => ModelErrorKind::InvalidUserId,
            Self::InvalidLabel => ModelErrorKind::InvalidLabel,
            Self::InvalidUuid { .. } => ModelErrorKind::InvalidUuid,
            Self::InvalidPublicKey { .. } => ModelErrorKind::InvalidPublicKey,
            Self::InvalidSecret { .. } => ModelErrorKind::InvalidSecret,
            Self::InvalidSecretRef => ModelErrorKind::InvalidSecretRef,
            Self::InvalidPem { .. } => ModelErrorKind::InvalidPem,
            Self::InvalidDigest { .. } => ModelErrorKind::InvalidDigest,
            Self::InvalidPort => ModelErrorKind::InvalidPort,
            Self::InvalidPortRange { .. } => ModelErrorKind::InvalidPortRange,
            Self::InvalidHopInterval { .. } => ModelErrorKind::InvalidHopInterval,
            Self::InvalidHy2Listener { .. } => ModelErrorKind::InvalidHy2Listener,
            Self::PortPlanConflict { .. } => ModelErrorKind::PortPlanConflict,
            Self::InvalidInterfaceName { .. } => ModelErrorKind::InvalidInterfaceName,
            Self::InvalidMacAddr => ModelErrorKind::InvalidMacAddr,
            Self::InvalidInterfaceIndex => ModelErrorKind::InvalidInterfaceIndex,
            Self::UplinkEqualsEgress => ModelErrorKind::UplinkEqualsEgress,
            Self::InterfaceNotSelected { .. } => ModelErrorKind::InterfaceNotSelected,
            Self::UplinkModeMismatch { .. } => ModelErrorKind::UplinkModeMismatch,
            Self::InterfacesForOtherSite => ModelErrorKind::InterfacesForOtherSite,
            Self::InvalidWgIndex { .. } => ModelErrorKind::InvalidWgIndex,
            Self::WgIndexExhausted => ModelErrorKind::WgIndexExhausted,
            Self::InvalidKeepalive { .. } => ModelErrorKind::InvalidKeepalive,
            Self::InvalidCounter { .. } => ModelErrorKind::InvalidCounter,
            Self::CounterOverflow { .. } => ModelErrorKind::CounterOverflow,
            Self::EmptyCollection => ModelErrorKind::EmptyCollection,
            Self::InvalidDate => ModelErrorKind::InvalidDate,
            Self::InvalidCycleDay { .. } => ModelErrorKind::InvalidCycleDay,
            Self::InvalidBillDay { .. } => ModelErrorKind::InvalidBillDay,
            Self::InvalidPeriodDays { .. } => ModelErrorKind::InvalidPeriodDays,
            Self::InvalidSimThresholds { .. } => ModelErrorKind::InvalidSimThresholds,
            Self::SimThresholdAbovePlan { .. } => ModelErrorKind::SimThresholdAbovePlan,
            Self::DeprioritisationNeedsFairUseLine => {
                ModelErrorKind::DeprioritisationNeedsFairUseLine
            }
            Self::SimStopAboveRollingLine { .. } => ModelErrorKind::SimStopAboveRollingLine,
            Self::StopPolicyUnchosen => ModelErrorKind::StopPolicyUnchosen,
            Self::PlanNotRecorded => ModelErrorKind::PlanNotRecorded,
            Self::InvalidWarnPercent { .. } => ModelErrorKind::InvalidWarnPercent,
            Self::InvalidBudgetPercent { .. } => ModelErrorKind::InvalidBudgetPercent,
            Self::InvalidSimFactor { .. } => ModelErrorKind::InvalidSimFactor,
            Self::InvalidWallClockTime => ModelErrorKind::InvalidWallClockTime,
            Self::InvalidPublicAlias => ModelErrorKind::InvalidPublicAlias,
            Self::InvalidUplinkBaseline { .. } => ModelErrorKind::InvalidUplinkBaseline,
            Self::InvalidProbeInterval { .. } => ModelErrorKind::InvalidProbeInterval,
            Self::InvalidProbeBasePort { .. } => ModelErrorKind::InvalidProbeBasePort,
            Self::InvalidFlowCap { .. } => ModelErrorKind::InvalidFlowCap,
            Self::InvalidHttpStatus { .. } => ModelErrorKind::InvalidHttpStatus,
            Self::InvalidCertificateName => ModelErrorKind::InvalidCertificateName,
            Self::InvalidEvidenceUrl => ModelErrorKind::InvalidEvidenceUrl,
            Self::TargetNotAttested => ModelErrorKind::TargetNotAttested,
            Self::UnknownNode { .. } => ModelErrorKind::UnknownNode,
            Self::UnknownUser { .. } => ModelErrorKind::UnknownUser,
            Self::DuplicateId { .. } => ModelErrorKind::DuplicateId,
            Self::TooManyNodes { .. } => ModelErrorKind::TooManyNodes,
            Self::DuplicateNodeAddress { .. } => ModelErrorKind::DuplicateNodeAddress,
            Self::DuplicateWgIndex { .. } => ModelErrorKind::DuplicateWgIndex,
            Self::WgIndexNotAllocated { .. } => ModelErrorKind::WgIndexNotAllocated,
            Self::DuplicateShortId { .. } => ModelErrorKind::DuplicateShortId,
            Self::DuplicateAlias { .. } => ModelErrorKind::DuplicateAlias,
            Self::TooManyActiveUsers { .. } => ModelErrorKind::TooManyActiveUsers,
            Self::TargetNotSet { .. } => ModelErrorKind::TargetNotSet,
            Self::GenerationAhead { .. } => ModelErrorKind::GenerationAhead,
            Self::GenerationRegressed { .. } => ModelErrorKind::GenerationRegressed,
            Self::NodeNotDeployable { .. } => ModelErrorKind::NodeNotDeployable,
            Self::CredentialsOnInactiveNode { .. } => ModelErrorKind::CredentialsOnInactiveNode,
            Self::DigestTimeTooEarly { .. } => ModelErrorKind::DigestTimeTooEarly,
            Self::AlertChannelsOnInactiveNode { .. } => ModelErrorKind::AlertChannelsOnInactiveNode,
            Self::NotRevoking { .. } => ModelErrorKind::NotRevoking,
            Self::UserNotActive { .. } => ModelErrorKind::UserNotActive,
            Self::UserNotSuspended { .. } => ModelErrorKind::UserNotSuspended,
            Self::RevocationAlreadyStarted { .. } => ModelErrorKind::RevocationAlreadyStarted,
            Self::NoCredentialsOnNode { .. } => ModelErrorKind::NoCredentialsOnNode,
            Self::AgreementRegressed { .. } => ModelErrorKind::AgreementRegressed,
            Self::CarrierAlreadyRecorded => ModelErrorKind::CarrierAlreadyRecorded,
            Self::NodeNotRetiring { .. } => ModelErrorKind::NodeNotRetiring,
            Self::RevokedUserHoldsCredentials { .. } => ModelErrorKind::RevokedUserHoldsCredentials,
            Self::RevokePendingWithoutCredentials { .. } => {
                ModelErrorKind::RevokePendingWithoutCredentials
            }
            Self::StateVersionMismatch { .. } => ModelErrorKind::StateVersionMismatch,
            Self::UnknownStateVersion { .. } => ModelErrorKind::UnknownStateVersion,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::alerting::{AlertSettings, WallClockTime};
    use crate::cert::{CertificatePem, Hy2Sni};
    use crate::collections::NonEmpty;
    use crate::counters::RuntimeRevision;
    use crate::date::CalendarDate;
    use crate::deployment::{
        Bookkeeping, CapacityPolicy, Deployment, DeploymentInit, DeploymentParts,
    };
    use crate::dns::DnsName;
    use crate::exit::{
        FlowCap, ProbeBasePort, ProbeInterval, ProbePolicy, ProbeProtocol, UplinkBaseline,
    };
    use crate::ids::{LocalLabel, ShortId, Uuid};
    use crate::iface::{BsdName, InterfaceIndex, MacAddr, ResolvedInterface, ResolvedUplink};
    use crate::ipv4::{CarrierPrefix, PublicIpv4};
    use crate::keys::WgKey;
    use crate::node::NodeLifecycle;
    use crate::ports::{
        DEFAULT_HOP_INTERVAL, HopInterval, Hy2Listener, Hy2Obfs, Port, PortPlan, PortRange,
    };
    use crate::quota::{BudgetPercent, SimFactor};
    use crate::secret::{Password, SecretRef};
    use crate::sim::{BillDay, CycleRule, PeriodDays, SimPlan, SimPolicy, StopPolicy};
    use crate::state::StateVersion;
    use crate::target::{CertificateName, EvidenceUrl, HttpStatus, require_attested};
    use crate::testing::{self, attestation, node_id, two_node_parts, user, user_id};
    use crate::time::UnixTime;
    use crate::user::{AgreementRecord, UserStatus};
    use crate::user::{SuspendReason, WarnPercent};
    use crate::v1::StateV1;
    use crate::v1::{CycleDay, SimPolicyV1};
    use crate::wg::{Keepalive, WgIndex};

    fn deployment_error(edit: impl FnOnce(&mut DeploymentParts)) -> ModelError {
        let mut parts = two_node_parts();
        edit(&mut parts);
        Deployment::try_from(parts).unwrap_err()
    }

    fn record_error(entry: Bookkeeping) -> ModelError {
        Deployment::try_from(two_node_parts())
            .unwrap()
            .record(entry)
            .unwrap_err()
    }

    fn m7(ipv4: [u8; 4]) -> ResolvedInterface {
        ResolvedInterface {
            bsd_name: BsdName::parse("en8").unwrap(),
            index: InterfaceIndex::new(21).unwrap(),
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
            ipv4: Ipv4Addr::from(ipv4),
        }
    }

    /// Every `ModelErrorKind`, named, with an error of that kind produced
    /// through the public API (or the crate-private check a deserialiser
    /// runs).
    fn every_error() -> Vec<(ModelErrorKind, ModelError)> {
        use ModelErrorKind as K;
        let day = CycleRule::Monthly {
            bill_day: BillDay::new(1).unwrap(),
        };
        let mut revoked = user(1, &[]);
        revoked.status = UserStatus::Revoked;
        let deployment = Deployment::try_from(two_node_parts()).unwrap();
        let site = testing::exit_site();
        let mut separate_site = site.clone();
        separate_site.uplink = crate::exit::Uplink::Separate(site.egress);
        let same = site
            .resolve(m7([192, 168, 1, 20]), ResolvedUplink::SameAsExit)
            .unwrap();
        let mut unattested = attestation();
        unattested.not_cdn = false;
        vec![
            (K::InvalidIpv4, "1.2.3".parse::<PublicIpv4>().unwrap_err()),
            (
                K::InvalidAddress,
                PublicIpv4::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap_err(),
            ),
            (
                K::InvalidCidr,
                "31.120.0.0".parse::<CarrierPrefix>().unwrap_err(),
            ),
            (
                K::InvalidPrefix,
                CarrierPrefix::new("10.0.0.0/8".parse().unwrap()).unwrap_err(),
            ),
            (
                K::InvalidShortId,
                ShortId::parse("0000000000000000").unwrap_err(),
            ),
            (K::InvalidDnsName, DnsName::parse("").unwrap_err()),
            (K::InvalidHy2Sni, Hy2Sni::parse("n.internal").unwrap_err()),
            (K::InvalidNodeId, NodeId::parse("1").unwrap_err()),
            (K::InvalidUserId, UserId::parse("x").unwrap_err()),
            (K::InvalidLabel, LocalLabel::parse("").unwrap_err()),
            (K::InvalidUuid, Uuid::parse("x").unwrap_err()),
            (K::InvalidPublicKey, WgKey::parse("x").unwrap_err()),
            (K::InvalidSecret, Password::parse("x").unwrap_err()),
            (K::InvalidSecretRef, "x".parse::<SecretRef>().unwrap_err()),
            (K::InvalidPem, CertificatePem::parse("x").unwrap_err()),
            (
                K::InvalidDigest,
                crate::digest::Sha256Digest::parse("x").unwrap_err(),
            ),
            (K::InvalidPort, Port::new(0).unwrap_err()),
            (K::InvalidPortRange, PortRange::new(2, 1).unwrap_err()),
            (
                K::InvalidHopInterval,
                HopInterval::from_seconds(4).unwrap_err(),
            ),
            (
                K::InvalidHy2Listener,
                Hy2Listener::new(
                    Port::new(61000).unwrap(),
                    PortRange::new(61002, 62999).unwrap(),
                    DEFAULT_HOP_INTERVAL,
                    Hy2Obfs::Salamander,
                )
                .unwrap_err(),
            ),
            (
                K::PortPlanConflict,
                PortPlan::with_defaults(PortRange::new(1024, 65535).unwrap()).unwrap_err(),
            ),
            (K::InvalidInterfaceName, BsdName::parse("").unwrap_err()),
            (K::InvalidMacAddr, MacAddr::parse("x").unwrap_err()),
            (
                K::InvalidInterfaceIndex,
                InterfaceIndex::new(0).unwrap_err(),
            ),
            (
                K::UplinkEqualsEgress,
                separate_site
                    .resolve(
                        m7([192, 168, 1, 20]),
                        ResolvedUplink::Separate(m7([192, 168, 1, 21])),
                    )
                    .unwrap_err(),
            ),
            (
                K::InterfaceNotSelected,
                site.resolve(m7([192, 168, 2, 20]), ResolvedUplink::SameAsExit)
                    .unwrap_err(),
            ),
            (
                K::UplinkModeMismatch,
                separate_site
                    .resolve(m7([192, 168, 1, 20]), ResolvedUplink::SameAsExit)
                    .unwrap_err(),
            ),
            (
                K::InterfacesForOtherSite,
                separate_site.require_resolved(&same).unwrap_err(),
            ),
            (K::InvalidWgIndex, WgIndex::new(0).unwrap_err()),
            (
                K::WgIndexExhausted,
                WgIndex::new(255).unwrap().next().unwrap_err(),
            ),
            (K::InvalidKeepalive, Keepalive::from_seconds(0).unwrap_err()),
            (K::InvalidCounter, ConfigGeneration::new(0).unwrap_err()),
            (
                K::CounterOverflow,
                RuntimeRevision::new(u64::MAX).unwrap().next().unwrap_err(),
            ),
            (
                K::EmptyCollection,
                NonEmpty::<u8>::try_from(Vec::new()).unwrap_err(),
            ),
            (
                K::InvalidDate,
                CalendarDate::parse("2026-02-29").unwrap_err(),
            ),
            (K::InvalidCycleDay, CycleDay::new(0).unwrap_err()),
            (K::InvalidBillDay, BillDay::new(32).unwrap_err()),
            (K::InvalidPeriodDays, PeriodDays::new(0).unwrap_err()),
            (
                K::InvalidSimThresholds,
                SimPolicy::new(
                    day,
                    testing::smarty_unlimited_plan(),
                    0,
                    StopPolicy::HardStop { bytes: 1 },
                )
                .unwrap_err(),
            ),
            (
                K::SimThresholdAbovePlan,
                SimPolicy::new(
                    day,
                    testing::fair_use_plan(),
                    1,
                    StopPolicy::HardStop { bytes: u64::MAX },
                )
                .unwrap_err(),
            ),
            (
                K::DeprioritisationNeedsFairUseLine,
                SimPolicy::new(
                    day,
                    testing::smarty_unlimited_plan(),
                    1,
                    StopPolicy::AcceptDeprioritisation,
                )
                .unwrap_err(),
            ),
            (
                K::SimStopAboveRollingLine,
                SimPolicy::new(
                    day,
                    SimPlan::one_p_mobile_unlimited().unwrap(),
                    1,
                    StopPolicy::HardStop {
                        bytes: 250_000_000_000,
                    },
                )
                .unwrap_err(),
            ),
            (
                K::StopPolicyUnchosen,
                SimPolicy::try_from(SimPolicyV1::new(CycleDay::new(1).unwrap(), 1, None).unwrap())
                    .unwrap_err(),
            ),
            (
                K::PlanNotRecorded,
                Deployment::new(DeploymentInit {
                    exit: {
                        let mut site = testing::exit_site();
                        site.sim = SimPolicy::try_from(
                            SimPolicyV1::new(CycleDay::new(1).unwrap(), 1, Some(2)).unwrap(),
                        )
                        .unwrap();
                        site
                    },
                    policy: crate::exit::TrafficPolicy::default(),
                    capacity: CapacityPolicy::UNLIMITED,
                    auto_quota: None,
                    alerting: None,
                })
                .unwrap_err(),
            ),
            (K::InvalidWarnPercent, WarnPercent::new(100).unwrap_err()),
            (K::InvalidBudgetPercent, BudgetPercent::new(0).unwrap_err()),
            (K::InvalidSimFactor, SimFactor::new(999).unwrap_err()),
            (
                K::InvalidWallClockTime,
                WallClockTime::parse("24:00").unwrap_err(),
            ),
            (K::InvalidPublicAlias, PublicAlias::parse("x").unwrap_err()),
            (
                K::InvalidUplinkBaseline,
                UplinkBaseline::new(2, 1, UnixTime::from_secs(0)).unwrap_err(),
            ),
            (
                K::InvalidProbeInterval,
                ProbeInterval::from_seconds(0).unwrap_err(),
            ),
            (K::InvalidProbeBasePort, ProbeBasePort::new(0).unwrap_err()),
            (K::InvalidFlowCap, FlowCap::new(0).unwrap_err()),
            (K::InvalidHttpStatus, HttpStatus::new(0).unwrap_err()),
            (
                K::InvalidCertificateName,
                CertificateName::parse("a b").unwrap_err(),
            ),
            (K::InvalidEvidenceUrl, EvidenceUrl::parse("x").unwrap_err()),
            (
                K::TargetNotAttested,
                require_attested(&unattested).unwrap_err(),
            ),
            (
                K::UnknownNode,
                deployment.node(&node_id("par1")).unwrap_err(),
            ),
            (K::UnknownUser, deployment.user(&user_id(99)).unwrap_err()),
            (
                K::DuplicateId,
                deployment_error(|parts| parts.users.push(user(1, &[]))),
            ),
            (
                K::TooManyNodes,
                ProbePolicy::default()
                    .port_for(2, ProbeProtocol::Reality)
                    .unwrap_err(),
            ),
            (
                K::DuplicateNodeAddress,
                deployment_error(|parts| {
                    parts.nodes[1].lifecycle = testing::applied([45, 67, 89, 10], 1);
                }),
            ),
            (
                K::DuplicateWgIndex,
                deployment_error(|parts| parts.nodes[1].wg_index = WgIndex::new(1).unwrap()),
            ),
            (
                K::WgIndexNotAllocated,
                deployment_error(|parts| parts.next_wg_index = WgIndex::new(2).unwrap()),
            ),
            (
                K::DuplicateShortId,
                deployment_error(|parts| parts.users.push(user(3, &[("lon1", 1)]))),
            ),
            (
                K::DuplicateAlias,
                deployment_error(|parts| {
                    let alias = PublicAlias::parse("k7qd-m2xa").unwrap();
                    parts.users[0].alias = Some(alias.clone());
                    parts.users[1].alias = Some(alias);
                }),
            ),
            (
                K::TooManyActiveUsers,
                deployment_error(|parts| {
                    parts.capacity.max_active_users = NonZeroU16::new(1);
                }),
            ),
            (
                K::TargetNotSet,
                deployment_error(|parts| parts.nodes[0].reality.target = None),
            ),
            (
                K::GenerationAhead,
                deployment_error(|parts| {
                    parts.nodes[0].lifecycle = testing::applied([45, 67, 89, 10], 9);
                }),
            ),
            (
                K::GenerationRegressed,
                Deployment::try_from({
                    let mut parts = two_node_parts();
                    parts.config_generation = ConfigGeneration::new(2).unwrap();
                    parts.nodes[0].lifecycle = testing::applied([45, 67, 89, 10], 2);
                    parts
                })
                .unwrap()
                .record(Bookkeeping::Applied {
                    node: node_id("lon1"),
                    applied: crate::node::AppliedConfig {
                        config_generation: ConfigGeneration::INITIAL,
                        digest: crate::digest::Sha256Digest::from_bytes([0xd1; 32]),
                    },
                })
                .unwrap_err(),
            ),
            (
                K::NodeNotDeployable,
                testing::node("par1", 3, 30, NodeLifecycle::Planned)
                    .apply_inputs()
                    .unwrap_err(),
            ),
            (
                K::CredentialsOnInactiveNode,
                deployment_error(|parts| parts.nodes[0].lifecycle = NodeLifecycle::Retired),
            ),
            (
                K::DigestTimeTooEarly,
                deployment_error(|parts| {
                    parts.alerting = Some(AlertSettings {
                        digest_at: WallClockTime::parse("01:30").unwrap(),
                        ..AlertSettings::pilot()
                    });
                }),
            ),
            (
                K::AlertChannelsOnInactiveNode,
                deployment_error(|parts| {
                    parts.users.clear();
                    parts.nodes[0].lifecycle = NodeLifecycle::Retired;
                    parts.alerting = Some(AlertSettings {
                        channels: BTreeSet::from([node_id("lon1")]),
                        ..AlertSettings::pilot()
                    });
                }),
            ),
            (
                K::NotRevoking,
                record_error(Bookkeeping::RevocationCommitted {
                    user: user_id(1),
                    node: node_id("lon1"),
                }),
            ),
            (
                K::UserNotActive,
                revoked
                    .clone()
                    .suspend(SuspendReason::Operator, UnixTime::from_secs(0))
                    .unwrap_err(),
            ),
            (K::UserNotSuspended, user(1, &[]).resume().unwrap_err()),
            (
                K::RevocationAlreadyStarted,
                revoked.clone().revoke().unwrap_err(),
            ),
            (
                K::NoCredentialsOnNode,
                Deployment::try_from({
                    let mut parts = two_node_parts();
                    parts.users[0].status = UserStatus::RevokePending;
                    parts
                })
                .unwrap()
                .record(Bookkeeping::RevocationCommitted {
                    user: user_id(1),
                    node: node_id("par1"),
                })
                .unwrap_err(),
            ),
            (
                K::AgreementRegressed,
                Deployment::try_from({
                    let mut parts = two_node_parts();
                    parts.users[0].agreement = Some(AgreementRecord {
                        version: AgreementVersion::new(NonZeroU16::new(2).unwrap()),
                        accepted_on: CalendarDate::parse("2026-11-02").unwrap(),
                    });
                    parts
                })
                .unwrap()
                .record(Bookkeeping::AgreementRecorded {
                    user: user_id(1),
                    record: AgreementRecord {
                        version: AgreementVersion::CURRENT,
                        accepted_on: CalendarDate::parse("2026-11-03").unwrap(),
                    },
                })
                .unwrap_err(),
            ),
            (
                K::CarrierAlreadyRecorded,
                record_error(Bookkeeping::CarrierRecorded {
                    check: testing::exit_site().egress_check.unwrap(),
                }),
            ),
            (
                K::NodeNotRetiring,
                record_error(Bookkeeping::RetirementShutDown {
                    node: node_id("lon1"),
                }),
            ),
            (
                K::RevokedUserHoldsCredentials,
                deployment_error(|parts| parts.users[0].status = UserStatus::Revoked),
            ),
            (
                K::RevokePendingWithoutCredentials,
                deployment_error(|parts| {
                    parts.users[0].per_node.clear();
                    parts.users[0].status = UserStatus::RevokePending;
                }),
            ),
            (
                K::StateVersionMismatch,
                StateV1::require_version(2).unwrap_err(),
            ),
            (
                K::UnknownStateVersion,
                StateVersion::try_from(0).unwrap_err(),
            ),
        ]
    }

    #[test]
    fn every_kind_is_produced_by_the_error_named_with_it() {
        let errors = every_error();
        for (kind, error) in &errors {
            assert_eq!(error.kind(), *kind, "{error}");
            assert!(!error.to_string().is_empty());
        }
        let named: BTreeSet<ModelErrorKind> = errors.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(named.len(), errors.len(), "each kind is named once");
        assert_eq!(
            named,
            ModelErrorKind::ALL.iter().copied().collect(),
            "every kind is named"
        );
    }

    #[test]
    fn kind_names_are_the_variant_names() {
        assert_eq!(ModelErrorKind::InvalidAddress.name(), "InvalidAddress");
        assert_eq!(
            ModelErrorKind::StateVersionMismatch.to_string(),
            "StateVersionMismatch"
        );
        assert_eq!(
            ModelError::DuplicateId {
                id: EntityId::Node(node_id("lon1"))
            }
            .to_string(),
            "duplicate node lon1"
        );
        assert_eq!(
            ModelErrorKind::DeprioritisationNeedsFairUseLine.name(),
            "DeprioritisationNeedsFairUseLine"
        );
        // The stop texts name no carrier and no invented default.
        for error in [
            ModelError::StopPolicyUnchosen,
            ModelError::DeprioritisationNeedsFairUseLine,
            ModelError::SimThresholdAbovePlan {
                threshold_bytes: 2,
                line_bytes: 1,
            },
            ModelError::SimStopAboveRollingLine {
                stop_bytes: 2,
                cycles: 2,
                window_days: 30,
                line_bytes: 3,
            },
        ] {
            let text = error.to_string();
            assert!(
                !text.contains("EE") && !text.contains("560000000000"),
                "{text}"
            );
        }
    }

    #[test]
    fn secret_parse_errors_never_echo_the_input() {
        let candidate = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I";
        let error = Password::parse(&format!("{candidate}!")).unwrap_err();
        assert!(!format!("{error} {error:?}").contains(candidate));
        let uuid_text = "6D6F6F72-0101-4001-8000-000000010101";
        let error = Uuid::parse(uuid_text).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("6D6F6F72"));
        let error = ShortId::parse("5F1E000100000001").unwrap_err();
        assert!(!format!("{error} {error:?}").contains("5F1E"));
    }
}
