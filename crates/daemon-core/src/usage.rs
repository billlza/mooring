// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-user usage (console spec B.2.2): bytes served per opaque user for
//! the UTC day, the SIM billing cycle, the UTC month and the user's
//! lifetime, with the cycle split by node and by protocol; and "active now"
//! and "last seen" from the nodes' latest accounting polls.
//!
//! # Inputs
//!
//! Each node's history is a [`NodeLedger`]: where it starts
//! ([`LedgerStart`]: a [`LifetimeBase`], the totals of everything before
//! `as_of` into which the Mac's usage store folds old bins, or the instant
//! the node was first served, before which it counted nothing) followed by
//! the agent's `UsageSeriesV1` replies, which must follow on from it and
//! from each other with neither a gap nor an overlap. A bin the agent did
//! not send had no traffic (agent-proto refuses a range it does not hold
//! rather than sending zeros), so within a ledger's coverage an absent user
//! really used nothing. Outside it nothing is assumed: a period that starts
//! before a continued ledger's bins, or ends after an open ledger's last
//! bin, is refused. Every node of the deployment that may have counted
//! traffic (every node past `Planned`, retired ones included) needs a
//! ledger, so a node left out is refused rather than read as zero.
//!
//! # Accuracy
//!
//! Figures are proxied payload bytes as Xray counts them (design §11.5).
//! For REALITY with Vision, Xray splices the downlink of a TCP connection
//! on Linux and adds its bytes to the user's counter only when the
//! connection closes (critique A-2, C-6): a long download shows no growth
//! until it ends, and the bytes of connections cut by an Xray restart are
//! never counted. [`UsageAccuracy`] marks every row this affects.
//! Hysteria2 traffic reaches Xray over a non-splicing handoff, so it is
//! counted as it flows.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{
    ACCOUNTING_INTERVAL_SECS, Inbound, Principal, StatsEmail, StatusV1, Traffic,
    UnixTime as WireTime, UsageSeriesV1,
};
use mooring_model::node::LifecycleStage;
use mooring_model::{Deployment, NodeId, UnixTime, User, UserId};
use serde::{Deserialize, Serialize};

use crate::error::{FigureError, UsageError};
use crate::period::{BillingCycle, UsagePeriods};
use crate::share::{BasisPoints, basis_points, require_whole};
use crate::wire::{accounting_user, mac_time};

/// The totals of one node's accounting emails before `as_of`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeBase {
    /// The end of the folded history (exclusive): the node's bins start
    /// here.
    pub as_of: UnixTime,
    /// The totals per accounting email.
    pub totals: BTreeMap<StatsEmail, Traffic>,
}

/// Where a node's ledger starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerStart {
    /// The node may have counted traffic before the ledger's bins; all of
    /// it is folded into this base.
    Continued(LifetimeBase),
    /// The node was first served at `at`, so it counted nothing before: a
    /// period that starts earlier is covered from `at` on. The caller
    /// asserts this from the node's lifecycle (its adoption or first
    /// apply), as it asserts [`LedgerEnd::Final`].
    FirstServed {
        /// When the node's counting began.
        at: UnixTime,
    },
}

impl LedgerStart {
    /// Where the bins start.
    #[must_use]
    pub const fn from(&self) -> UnixTime {
        match self {
            Self::Continued(base) => base.as_of,
            Self::FirstServed { at } => *at,
        }
    }
}

/// Whether a node can still count traffic after its ledger ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerEnd {
    /// The node still serves: bytes after the ledger's last bin are unknown.
    Open,
    /// The node no longer serves (it is retired), so its ledger is
    /// complete: nothing was counted after it. The caller asserts this from
    /// the node's lifecycle.
    Final,
}

/// One node's usage history: where it starts and the bins after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLedger {
    node: NodeId,
    start: LedgerStart,
    series: Vec<UsageSeriesV1>,
    end: LedgerEnd,
}

impl NodeLedger {
    /// A ledger whose series start where `start` says and follow on from
    /// each other (`LedgerGap` otherwise).
    pub fn new(
        node: NodeId,
        start: LedgerStart,
        series: Vec<UsageSeriesV1>,
        end: LedgerEnd,
    ) -> Result<Self, UsageError> {
        let mut expected = start.from();
        for reply in &series {
            let span = reply.range().span();
            let found = mac_time(span.from());
            if found != expected {
                return Err(UsageError::LedgerGap {
                    node,
                    expected,
                    found,
                });
            }
            expected = mac_time(span.to());
        }
        Ok(Self {
            node,
            start,
            series,
            end,
        })
    }

    /// The node.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Where the ledger starts.
    #[must_use]
    pub const fn start(&self) -> &LedgerStart {
        &self.start
    }

    /// The series after the start, in time order.
    #[must_use]
    pub fn series(&self) -> &[UsageSeriesV1] {
        &self.series
    }

    /// Where the bins start.
    #[must_use]
    pub const fn covered_from(&self) -> UnixTime {
        self.start.from()
    }

    /// Where the bins end (exclusive).
    #[must_use]
    pub fn covered_to(&self) -> UnixTime {
        self.series.last().map_or(self.start.from(), |reply| {
            mac_time(reply.range().span().to())
        })
    }

    /// Whether the node can still count traffic.
    #[must_use]
    pub const fn end(&self) -> LedgerEnd {
        self.end
    }
}

/// Bytes per protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTraffic {
    /// VLESS + REALITY + Vision (`…@reality`).
    pub reality: Traffic,
    /// Hysteria2 (`…@hy2`).
    pub hy2: Traffic,
}

impl ProtocolTraffic {
    fn add(&mut self, inbound: Inbound, traffic: Traffic) -> Result<(), UsageError> {
        match inbound {
            Inbound::Reality => add(&mut self.reality, traffic),
            Inbound::Hy2 => add(&mut self.hy2, traffic),
        }
    }
}

/// Shares of the protocols, in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolShares {
    /// REALITY's share.
    pub reality: BasisPoints,
    /// Hysteria2's share.
    pub hy2: BasisPoints,
}

/// How a user's cycle bytes (both directions) divide between nodes and
/// between protocols. Each set of shares adds up to exactly 10,000, which
/// decoding checks (`SharesNotWhole`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "CycleSharesRepr", into = "CycleSharesRepr")]
pub struct CycleShares {
    by_node: BTreeMap<NodeId, BasisPoints>,
    by_protocol: ProtocolShares,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CycleSharesRepr {
    by_node: BTreeMap<NodeId, BasisPoints>,
    by_protocol: ProtocolShares,
}

impl CycleShares {
    /// Per node that carried any of the user's cycle bytes.
    #[must_use]
    pub const fn by_node(&self) -> &BTreeMap<NodeId, BasisPoints> {
        &self.by_node
    }

    /// Per protocol.
    #[must_use]
    pub const fn by_protocol(&self) -> ProtocolShares {
        self.by_protocol
    }
}

impl TryFrom<CycleSharesRepr> for CycleShares {
    type Error = FigureError;

    fn try_from(repr: CycleSharesRepr) -> Result<Self, Self::Error> {
        require_whole(repr.by_node.values())?;
        require_whole([&repr.by_protocol.reality, &repr.by_protocol.hy2])?;
        Ok(Self {
            by_node: repr.by_node,
            by_protocol: repr.by_protocol,
        })
    }
}

impl From<CycleShares> for CycleSharesRepr {
    fn from(shares: CycleShares) -> Self {
        Self {
            by_node: shares.by_node,
            by_protocol: shares.by_protocol,
        }
    }
}

/// One user's usage. "Up" is client to destination (Xray's uplink) and
/// "down" destination to client.
///
/// Built only by [`aggregate`], and checked again on decode: the cycle's
/// split by node and by protocol adds up to the cycle (`SplitMismatch`),
/// and the served bytes and the shares are the ones the cycle's figures
/// give (`DerivedMismatch`), so a decoded status cannot carry an
/// impossible figure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UserUsageRepr", into = "UserUsageRepr")]
pub struct UserUsage {
    today: Traffic,
    cycle: Traffic,
    month: Traffic,
    lifetime: Traffic,
    cycle_served_bytes: u64,
    cycle_by_node: BTreeMap<NodeId, Traffic>,
    cycle_by_protocol: ProtocolTraffic,
    cycle_shares: Option<CycleShares>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserUsageRepr {
    today: Traffic,
    cycle: Traffic,
    month: Traffic,
    lifetime: Traffic,
    cycle_served_bytes: u64,
    cycle_by_node: BTreeMap<NodeId, Traffic>,
    cycle_by_protocol: ProtocolTraffic,
    #[serde(deserialize_with = "Option::deserialize")]
    cycle_shares: Option<CycleShares>,
}

/// The figures a user's usage is counted into; the rest is derived.
#[derive(Debug, Default)]
struct Counted {
    today: Traffic,
    cycle: Traffic,
    month: Traffic,
    lifetime: Traffic,
    cycle_by_node: BTreeMap<NodeId, Traffic>,
    cycle_by_protocol: ProtocolTraffic,
}

impl UserUsage {
    /// The report's UTC day.
    #[must_use]
    pub const fn today(&self) -> Traffic {
        self.today
    }

    /// The billing cycle.
    #[must_use]
    pub const fn cycle(&self) -> Traffic {
        self.cycle
    }

    /// The UTC month.
    #[must_use]
    pub const fn month(&self) -> Traffic {
        self.month
    }

    /// Everything recorded.
    #[must_use]
    pub const fn lifetime(&self) -> Traffic {
        self.lifetime
    }

    /// The cycle's bytes in both directions: what a quota counts.
    #[must_use]
    pub const fn cycle_served_bytes(&self) -> u64 {
        self.cycle_served_bytes
    }

    /// The cycle per node that carried any of it.
    #[must_use]
    pub const fn cycle_by_node(&self) -> &BTreeMap<NodeId, Traffic> {
        &self.cycle_by_node
    }

    /// The cycle per protocol.
    #[must_use]
    pub const fn cycle_by_protocol(&self) -> ProtocolTraffic {
        self.cycle_by_protocol
    }

    /// The cycle's shares; `None` when the user used nothing this cycle.
    #[must_use]
    pub const fn cycle_shares(&self) -> Option<&CycleShares> {
        self.cycle_shares.as_ref()
    }

    /// Derives the served bytes and the shares from the counted figures.
    fn derive(counted: Counted) -> Result<Self, UsageError> {
        let cycle_served_bytes = both_ways(counted.cycle)?;
        let by_node: BTreeMap<NodeId, u64> = counted
            .cycle_by_node
            .iter()
            .map(|(node, &traffic)| Ok((node.clone(), both_ways(traffic)?)))
            .collect::<Result<_, UsageError>>()?;
        let protocols = counted.cycle_by_protocol;
        let by_protocol = BTreeMap::from([
            (Inbound::Reality, both_ways(protocols.reality)?),
            (Inbound::Hy2, both_ways(protocols.hy2)?),
        ]);
        let cycle_shares = match (basis_points(&by_node), basis_points(&by_protocol)) {
            (Some(by_node), Some(by_protocol)) => Some(CycleShares {
                by_node,
                by_protocol: ProtocolShares {
                    reality: by_protocol[&Inbound::Reality],
                    hy2: by_protocol[&Inbound::Hy2],
                },
            }),
            _ => None,
        };
        Ok(Self {
            today: counted.today,
            cycle: counted.cycle,
            month: counted.month,
            lifetime: counted.lifetime,
            cycle_served_bytes,
            cycle_by_node: counted.cycle_by_node,
            cycle_by_protocol: counted.cycle_by_protocol,
            cycle_shares,
        })
    }
}

impl TryFrom<UserUsageRepr> for UserUsage {
    type Error = FigureError;

    fn try_from(repr: UserUsageRepr) -> Result<Self, Self::Error> {
        let mut by_node = Traffic::default();
        let mut by_protocol = repr.cycle_by_protocol.reality;
        let split = repr
            .cycle_by_node
            .values()
            .try_for_each(|&traffic| add(&mut by_node, traffic))
            .and_then(|()| add(&mut by_protocol, repr.cycle_by_protocol.hy2));
        if split.is_err() || by_node != repr.cycle || by_protocol != repr.cycle {
            return Err(FigureError::SplitMismatch);
        }
        let stated = (repr.cycle_served_bytes, repr.cycle_shares);
        // Deriving fails only when the cycle's two directions overflow a
        // u64 together, so no stated served-bytes figure can match them.
        let derived = Self::derive(Counted {
            today: repr.today,
            cycle: repr.cycle,
            month: repr.month,
            lifetime: repr.lifetime,
            cycle_by_node: repr.cycle_by_node,
            cycle_by_protocol: repr.cycle_by_protocol,
        })
        .map_err(|_| FigureError::DerivedMismatch)?;
        if stated != (derived.cycle_served_bytes, derived.cycle_shares.clone()) {
            return Err(FigureError::DerivedMismatch);
        }
        Ok(derived)
    }
}

impl From<UserUsage> for UserUsageRepr {
    fn from(usage: UserUsage) -> Self {
        Self {
            today: usage.today,
            cycle: usage.cycle,
            month: usage.month,
            lifetime: usage.lifetime,
            cycle_served_bytes: usage.cycle_served_bytes,
            cycle_by_node: usage.cycle_by_node,
            cycle_by_protocol: usage.cycle_by_protocol,
            cycle_shares: usage.cycle_shares,
        }
    }
}

/// Every user's usage over [`UsagePeriods`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReport {
    /// The periods, all ending at `periods.through`.
    pub periods: UsagePeriods,
    /// Every user of the deployment, revoked ones included; a user with no
    /// recorded traffic has all-zero figures, which are real zeros: every
    /// node that may have counted traffic was covered.
    pub users: BTreeMap<UserId, UserUsage>,
    /// The Mac's in-chain probe traffic this cycle, per node (`probe@…`).
    pub probe_cycle: BTreeMap<NodeId, ProtocolTraffic>,
}

/// The cycle's served bytes per user, the input of quota evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleUsage {
    /// The billing cycle.
    pub cycle: BillingCycle,
    /// The end of the counted time (exclusive).
    pub through: UnixTime,
    /// Bytes served per user in `[cycle start, through)`.
    pub served: BTreeMap<UserId, u64>,
}

impl UsageReport {
    /// The cycle's served bytes per user.
    #[must_use]
    pub fn cycle_usage(&self) -> CycleUsage {
        CycleUsage {
            cycle: self.periods.cycle,
            through: self.periods.through,
            served: self
                .users
                .iter()
                .map(|(user, usage)| (user.clone(), usage.cycle_served_bytes()))
                .collect(),
        }
    }
}

/// Whose traffic an accounting email counts, resolved against the
/// deployment.
enum Owner {
    User(UserId),
    Probe,
}

fn resolve(
    node: &NodeId,
    email: &StatsEmail,
    users: &BTreeMap<UserId, User>,
) -> Result<Owner, UsageError> {
    match &email.principal {
        Principal::Probe => Ok(Owner::Probe),
        Principal::User(opaque) => {
            // A name that is no user id was not rendered by Mooring.
            let user = accounting_user(opaque).map_err(|_| UsageError::PrincipalNotAUser {
                node: node.clone(),
                email: email.clone(),
            })?;
            if users.contains_key(&user) {
                Ok(Owner::User(user))
            } else {
                Err(UsageError::UnknownUser {
                    node: node.clone(),
                    user,
                })
            }
        }
    }
}

fn add(total: &mut Traffic, traffic: Traffic) -> Result<(), UsageError> {
    total.uplink = total
        .uplink
        .checked_add(traffic.uplink)
        .ok_or(UsageError::CounterOverflow)?;
    total.downlink = total
        .downlink
        .checked_add(traffic.downlink)
        .ok_or(UsageError::CounterOverflow)?;
    Ok(())
}

fn both_ways(traffic: Traffic) -> Result<u64, UsageError> {
    traffic
        .uplink
        .checked_add(traffic.downlink)
        .ok_or(UsageError::CounterOverflow)
}

/// The running totals of an aggregation, with the instants each period
/// starts at.
struct Totals<'a> {
    users: &'a BTreeMap<UserId, User>,
    day: UnixTime,
    cycle: UnixTime,
    month: UnixTime,
    usage: BTreeMap<UserId, Counted>,
    probe_cycle: BTreeMap<NodeId, ProtocolTraffic>,
}

impl Totals<'_> {
    /// Adds a lifetime base entry: it precedes every period.
    fn base(
        &mut self,
        node: &NodeId,
        email: &StatsEmail,
        traffic: Traffic,
    ) -> Result<(), UsageError> {
        if let Owner::User(user) = resolve(node, email, self.users)? {
            add(&mut self.usage.entry(user).or_default().lifetime, traffic)?;
        }
        Ok(())
    }

    /// Adds one bin entry to the periods its bin starts in.
    fn bin(
        &mut self,
        node: &NodeId,
        email: &StatsEmail,
        traffic: Traffic,
        start: UnixTime,
    ) -> Result<(), UsageError> {
        match resolve(node, email, self.users)? {
            Owner::Probe => {
                if start >= self.cycle {
                    self.probe_cycle
                        .entry(node.clone())
                        .or_default()
                        .add(email.inbound, traffic)?;
                }
            }
            Owner::User(user) => {
                let row = self.usage.entry(user).or_default();
                add(&mut row.lifetime, traffic)?;
                if start >= self.month {
                    add(&mut row.month, traffic)?;
                }
                if start >= self.day {
                    add(&mut row.today, traffic)?;
                }
                if start >= self.cycle {
                    add(&mut row.cycle, traffic)?;
                    add(row.cycle_by_node.entry(node.clone()).or_default(), traffic)?;
                    row.cycle_by_protocol.add(email.inbound, traffic)?;
                }
            }
        }
        Ok(())
    }
}

/// Aggregates the usage of every user of `deployment` over the periods
/// ending at `through` (with the billing cycle of the deployment's bill
/// day) from the nodes' ledgers.
///
/// There is exactly one ledger per node of the deployment that may have
/// counted traffic, every node past `Planned` (`MissingLedger`,
/// `DuplicateLedger`), and none for another node (`LedgerForUnknownNode`).
/// Each ledger must cover every period: a continued ledger's bins start no
/// later than the earliest period start (`PeriodBeforeLedger`), and an
/// open ledger reaches `through` (`NotCoveredThrough`). A bin that starts
/// before `through` must end by it (`BinStraddlesThrough`). Every
/// accounting email must name the probe or a user of the deployment
/// (`PrincipalNotAUser`, `UnknownUser`).
pub fn aggregate(
    deployment: &Deployment,
    ledgers: &[NodeLedger],
    through: UnixTime,
) -> Result<UsageReport, UsageError> {
    let users = deployment.users();
    let periods = UsagePeriods::ending(deployment.exit().sim.bill_day(), through)?;
    let earliest = periods.earliest_start();
    let mut seen: BTreeSet<&NodeId> = BTreeSet::new();
    for ledger in ledgers {
        let node = ledger.node();
        if !seen.insert(node) {
            return Err(UsageError::DuplicateLedger { node: node.clone() });
        }
        if !deployment.nodes().contains_key(node) {
            return Err(UsageError::LedgerForUnknownNode { node: node.clone() });
        }
    }
    for (id, node) in deployment.nodes() {
        if node.lifecycle.stage() != LifecycleStage::Planned && !seen.contains(id) {
            return Err(UsageError::MissingLedger { node: id.clone() });
        }
    }
    let mut totals = Totals {
        users,
        day: periods.utc_day.utc_start(),
        cycle: periods.cycle.starts_at(),
        month: periods.utc_month_start.utc_start(),
        usage: users
            .keys()
            .map(|user| (user.clone(), Counted::default()))
            .collect(),
        probe_cycle: BTreeMap::new(),
    };
    for ledger in ledgers {
        let node = ledger.node();
        let first_served = matches!(ledger.start(), LedgerStart::FirstServed { .. });
        if earliest < ledger.covered_from() && !first_served {
            return Err(UsageError::PeriodBeforeLedger {
                node: node.clone(),
                period_start: earliest,
                ledger_from: ledger.covered_from(),
            });
        }
        if ledger.end() == LedgerEnd::Open && ledger.covered_to() < through {
            return Err(UsageError::NotCoveredThrough {
                node: node.clone(),
                covered_to: ledger.covered_to(),
                through,
            });
        }
        if let LedgerStart::Continued(base) = ledger.start() {
            for (email, &traffic) in &base.totals {
                totals.base(node, email, traffic)?;
            }
        }
        for reply in &ledger.series {
            let width = reply.range().span().resolution().bin_secs();
            for bin in reply.bins() {
                let start = mac_time(bin.start());
                if start >= through {
                    break;
                }
                if start.as_secs() + width > through.as_secs() {
                    return Err(UsageError::BinStraddlesThrough {
                        node: node.clone(),
                        bin_start: start,
                        through,
                    });
                }
                for (email, &traffic) in bin.traffic() {
                    totals.bin(node, email, traffic, start)?;
                }
            }
        }
    }
    Ok(UsageReport {
        periods,
        users: totals
            .usage
            .into_iter()
            .map(|(user, counted)| Ok((user, UserUsage::derive(counted)?)))
            .collect::<Result<_, UsageError>>()?,
        probe_cycle: totals.probe_cycle,
    })
}

/// When a user last showed traffic on one node, per protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolActivity {
    /// The latest accounting poll at which the user's REALITY counters
    /// grew; `None` when none is recorded.
    #[serde(deserialize_with = "Option::deserialize")]
    pub reality: Option<UnixTime>,
    /// The same for Hysteria2.
    #[serde(deserialize_with = "Option::deserialize")]
    pub hy2: Option<UnixTime>,
}

/// How old a node's latest accounting poll may be, against the node's own
/// status time, for "active now" to be read from it: two accounting
/// intervals. An older poll means the stats query is failing
/// (`StatsQueryFailed`), and growth recorded then is not "now".
pub const ACCOUNTING_FRESH_SECS: u64 = 2 * ACCOUNTING_INTERVAL_SECS;

/// How old a node's status may be, against the Mac's clock, for "active
/// now" to be read from it: the Mac's 10-minute status poll (design §10.5)
/// with five minutes' margin for a slow or retried poll. Inference; an
/// older status means the node has stopped answering.
pub const STATUS_FRESH_SECS: u64 = 15 * 60;

/// Whether a user is active now, or that it cannot be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveNow {
    /// The user's counters grew at a fresh accounting poll of some node.
    Active,
    /// Every node serving the user has a fresh accounting poll, and none
    /// shows growth (also for a user served nowhere).
    Idle,
    /// Some node serving the user has no fresh accounting poll (the stats
    /// query fails, the node does not answer, or its status is missing),
    /// and none shows growth: never read as idle.
    Unknown,
}

/// A user's recent activity, from the nodes' latest `StatusV1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserActivity {
    /// Whether the user is active now. A long REALITY download shows no
    /// growth until it ends (see the module documentation), so `Idle` can
    /// miss a user who is downloading.
    pub active_now: ActiveNow,
    /// The latest growth on any node and protocol.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_seen: Option<UnixTime>,
    /// Per node with any recorded growth.
    pub by_node: BTreeMap<NodeId, ProtocolActivity>,
}

/// The node's latest accounting poll, if it is fresh at `now`: no older
/// than [`ACCOUNTING_FRESH_SECS`] against the status's own time, in a
/// status no older than [`STATUS_FRESH_SECS`] against the Mac's clock.
fn fresh_poll(status: &StatusV1, now: UnixTime) -> Option<WireTime> {
    let polled = status.accounting_at?;
    let poll_age = status.now.secs_since(polled)?;
    let status_age = now.as_secs().saturating_sub(status.now.as_secs());
    (poll_age <= ACCOUNTING_FRESH_SECS && status_age <= STATUS_FRESH_SECS).then_some(polled)
}

/// Every user's activity at `now` (the Mac's clock) from the nodes' latest
/// statuses; a node absent from `statuses` has given none. Times are the
/// nodes' clocks (each `StatusV1` is self-consistent; design §11.1).
/// "Active now" follows [`ActiveNow`]: it is read only from fresh polls,
/// and a stale or missing one makes it unknown rather than idle.
pub fn activity(
    users: &BTreeMap<UserId, User>,
    statuses: &BTreeMap<NodeId, StatusV1>,
    now: UnixTime,
) -> Result<BTreeMap<UserId, UserActivity>, UsageError> {
    let fresh: BTreeMap<&NodeId, WireTime> = statuses
        .iter()
        .filter_map(|(node, status)| Some((node, fresh_poll(status, now)?)))
        .collect();
    let mut seen: BTreeMap<UserId, Growth> = BTreeMap::new();
    for (node, status) in statuses {
        for (email, &at) in &status.last_active {
            let Owner::User(user) = resolve(node, email, users)? else {
                continue;
            };
            let growth = seen.entry(user).or_default();
            let time = mac_time(at);
            let per_node = growth.by_node.entry(node.clone()).or_default();
            let slot = match email.inbound {
                Inbound::Reality => &mut per_node.reality,
                Inbound::Hy2 => &mut per_node.hy2,
            };
            *slot = Some(time);
            growth.last_seen = growth.last_seen.max(Some(time));
            growth.at_fresh_poll |= fresh.get(node) == Some(&at);
        }
    }
    Ok(users
        .iter()
        .map(|(id, user)| {
            // A user no node reports grew nowhere that is recorded.
            let growth = seen.remove(id).unwrap_or_default();
            let all_fresh = user
                .per_node
                .keys()
                .filter(|node| user.is_served_on(node))
                .all(|node| fresh.contains_key(node));
            let active_now = if growth.at_fresh_poll {
                ActiveNow::Active
            } else if all_fresh {
                ActiveNow::Idle
            } else {
                ActiveNow::Unknown
            };
            (
                id.clone(),
                UserActivity {
                    active_now,
                    last_seen: growth.last_seen,
                    by_node: growth.by_node,
                },
            )
        })
        .collect())
}

/// A user's recorded counter growth, gathered over the nodes' statuses.
#[derive(Debug, Default)]
struct Growth {
    last_seen: Option<UnixTime>,
    by_node: BTreeMap<NodeId, ProtocolActivity>,
    /// Whether it grew at some node's fresh accounting poll.
    at_fresh_poll: bool,
}

/// What limits the accuracy of a user's row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageAccuracy {
    /// The user may have REALITY connections open now, whose spliced
    /// downlink bytes are counted only when they close (critique A-2, C-6):
    /// the row's REALITY downlink, `active_now` and the latest bins may lag,
    /// and bytes of connections an Xray restart cuts are never counted.
    /// True while the user is served on some node; once suspended or
    /// revoked their connections are closed and the row stops changing.
    pub reality_downlink_counted_at_close: bool,
}

impl UsageAccuracy {
    /// The accuracy note for `user`.
    #[must_use]
    pub fn of(user: &User) -> Self {
        Self {
            reality_downlink_counted_at_close: user
                .per_node
                .keys()
                .any(|node| user.is_served_on(node)),
        }
    }
}
