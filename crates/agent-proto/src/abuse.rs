// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard's shared definitions (design §11.8): each served user's
//! source address inside the node, the nftables sets and limits the
//! renderer writes and the watch reads, the findings with their levels,
//! and the records a node keeps of what it found and did.
//!
//! Nothing here holds a destination, a port or a user's own address: a
//! record names an opaque user and aggregate figures only, and the sets
//! reduce a destination to one of [`DESTINATION_BUCKETS`] buckets.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{OpaqueUserId, UnixTime, ValueError};

/// The first address of the range the users' source addresses come from,
/// `198.18.0.0/15`: RFC 2544's benchmarking range, never routed and used
/// by no provider. Inside the node every address of it is local (a `local`
/// route the tunnel's `PostUp` adds), and the node rewrites it to its own
/// tunnel address before the tunnel, so it never leaves the node.
pub const USER_SOURCE_BASE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);

/// The range's prefix length.
pub const USER_SOURCE_PREFIX: u8 = 15;

/// How many addresses a user can be given: every address of the range but
/// its first and its last.
pub const USER_SOURCES: u32 = (1 << (32 - USER_SOURCE_PREFIX)) - 2;

/// The range in CIDR notation, as the rendered rules write it.
pub const USER_SOURCE_NET: &str = "198.18.0.0/15";

/// A served user's source address inside every node: the address after
/// the range's first, offset by the user id's 64-bit FNV-1a hash modulo
/// [`USER_SOURCES`]. It is a pure function of the id, the same on every
/// node and in every generation, so a cut follows the user across applies
/// and reboots with no slot to record; two users may share one (about one
/// pair in 131,070), which the renderer refuses and `user add` avoids
/// (design §11.8).
pub fn user_source(user: &OpaqueUserId) -> Ipv4Addr {
    let offset = 1 + fnv1a64(user.as_str().as_bytes()) % u64::from(USER_SOURCES);
    // The offset is at most USER_SOURCES, which fits the range's host part.
    let offset = u32::try_from(offset).unwrap_or(USER_SOURCES);
    Ipv4Addr::from(u32::from(USER_SOURCE_BASE) + offset)
}

/// Whether `address` is one a user can be given: inside the range, and
/// neither its first nor its last address.
pub fn is_user_source(address: Ipv4Addr) -> bool {
    let base = u32::from(USER_SOURCE_BASE);
    let value = u32::from(address);
    value > base && value - base <= USER_SOURCES
}

/// The 64-bit FNV-1a hash: a fixed, public mixing of the id's bytes. It
/// protects nothing (design §12, Level 0); it only spreads ids over the
/// range.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

/// The version of the guard a generation's rules carry, in `watch.json`
/// (`"abuse_guard": 1`). An agent refuses a version it does not know, so a
/// generation is never measured by rules other than the ones it was
/// rendered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub enum AbuseGuardVersion {
    /// The guard of 2026-11-11: per-user source addresses, the layer-1
    /// limits and the sets of [`AbuseSet`].
    V1,
}

impl AbuseGuardVersion {
    /// The version this crate renders and measures.
    pub const CURRENT: Self = Self::V1;

    /// The version's number.
    pub const fn number(self) -> u32 {
        match self {
            Self::V1 => 1,
        }
    }
}

impl TryFrom<u32> for AbuseGuardVersion {
    type Error = ValueError;

    fn try_from(number: u32) -> Result<Self, Self::Error> {
        match number {
            1 => Ok(Self::V1),
            _ => Err(ValueError::AbuseGuardVersion { number }),
        }
    }
}

impl From<AbuseGuardVersion> for u32 {
    fn from(version: AbuseGuardVersion) -> Self {
        version.number()
    }
}

/// New flows a user may open each second before layer 1 rejects them.
pub const NEW_FLOWS_PER_SEC: u32 = 50;
/// The burst of new flows above [`NEW_FLOWS_PER_SEC`] a user may open.
pub const NEW_FLOW_BURST: u32 = 500;
/// Flows a user may hold open at once (`ct count`).
pub const CONCURRENT_FLOWS: u32 = 1024;
/// UDP datagrams a user may send each second before layer 1 drops them.
pub const DATAGRAMS_PER_SEC: u32 = 1500;
/// The burst of datagrams above [`DATAGRAMS_PER_SEC`] a user may send.
pub const DATAGRAM_BURST: u32 = 3000;

/// The buckets a destination is hashed into (`jhash ip daddr mod 4096`):
/// each stands for about a million addresses, so a set of buckets counts
/// destinations without naming one.
pub const DESTINATION_BUCKETS: u16 = 4096;
/// The seed of the destination hash. It is public, as the whole guard is;
/// it keeps nothing secret.
pub const DESTINATION_HASH_SEED: u32 = 0x6d6f_6f72;
/// The mask that reduces a destination port to its bucket (its low ten
/// bits, so 1,024 buckets).
pub const PORT_BUCKET_MASK: u16 = 0x03ff;
/// The number of port buckets.
pub const PORT_BUCKETS: u16 = PORT_BUCKET_MASK + 1;

/// The TCP ports of login services whose new flows [`AbuseSet::Login`]
/// counts per destination: FTP, SSH, Telnet, POP3, IMAP, SMB, IMAPS,
/// POP3S, MS SQL, MySQL, RDP, PostgreSQL, VNC, Redis and MongoDB.
pub const LOGIN_PORTS: [u16; 15] = [
    21, 22, 23, 110, 143, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 27017,
];
/// The TCP ports of mail submission whose servers [`AbuseSet::Mail`]
/// counts. Port 25 is blocked outright (design §8.2).
pub const SUBMISSION_PORTS: [u16; 2] = [465, 587];

/// The watch reads the sets every this many ticks (15 s).
pub const ABUSE_READ_EVERY_TICKS: u64 = 3;
/// A meter element ([`AbuseSet::MeterNew`], [`AbuseSet::MeterOut`],
/// [`AbuseSet::MeterIn`]) younger than this gives no rate: too few seconds
/// for a rate to mean anything.
pub const METER_MIN_AGE_SECS: u64 = 10;
/// A meter element at least this old has covered most of its minute and
/// counts as one minute of [`AbuseFinding::DatagramFlood`] evidence.
pub const METER_SETTLED_SECS: u64 = 45;
/// How long an alert-level finding keeps a user counted in
/// [`crate::WatchError::AbuseSuspected`], and the shortest time between two
/// alert records of one finding for one user.
pub const ABUSE_SUSPECTED_SECS: u64 = 3600;
/// How long a node keeps a record (30 days).
pub const ABUSE_RECORD_KEEP_SECS: u64 = 30 * 86_400;
/// The most records a node keeps; the oldest go first.
pub const MAX_ABUSE_RECORDS_KEPT: usize = 4096;
/// The most users a node holds cut at once. A cut beyond it is refused
/// rather than drop another.
pub const MAX_ABUSE_CUTS: usize = 256;
/// The most records one [`AbuseRecordsV1`] carries.
pub const MAX_ABUSE_RECORDS: usize = 512;

closed_enum! {
    /// An nftables set of the guard, in [`crate::NFT_TABLE`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum AbuseSet {
        /// `abuse_cut`: the source addresses of the users cut on this node.
        Cut,
        /// `user_conns`: per-user `ct count` of open flows (layer 1).
        Conns,
        /// `user_rate`: per-user limit on new flows (layer 1).
        Rate,
        /// `user_datagrams`: per-user limit on datagrams sent (layer 1).
        Datagrams,
        /// `user_dst`: user . destination bucket, held 5 minutes since last
        /// used.
        Dst,
        /// `user_port`: user . port bucket, held 5 minutes since last used.
        Port,
        /// `user_burst`: user . destination bucket with a counter of new
        /// flows, held 2 minutes from the first.
        Burst,
        /// `user_login`: user . destination bucket with a counter of new
        /// flows to [`LOGIN_PORTS`], held 10 minutes from the first.
        Login,
        /// `user_mail`: user . destination bucket for
        /// [`SUBMISSION_PORTS`], held an hour since last used.
        Mail,
        /// `meter_new`: user . protocol with a counter of new flows, held a
        /// minute from the first.
        MeterNew,
        /// `meter_out`: user . protocol with a counter of what the user
        /// sent, held a minute from the first packet.
        MeterOut,
        /// `meter_in`: user with a counter of what the user received, held
        /// a minute from the first packet.
        MeterIn,
        /// `user_capped`: user with a counter of the packets layer 1
        /// refused, held 5 minutes from the first.
        Capped,
    }
}

impl AbuseSet {
    /// The set's name in [`crate::NFT_TABLE`].
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cut => "abuse_cut",
            Self::Conns => "user_conns",
            Self::Rate => "user_rate",
            Self::Datagrams => "user_datagrams",
            Self::Dst => "user_dst",
            Self::Port => "user_port",
            Self::Burst => "user_burst",
            Self::Login => "user_login",
            Self::Mail => "user_mail",
            Self::MeterNew => "meter_new",
            Self::MeterOut => "meter_out",
            Self::MeterIn => "meter_in",
            Self::Capped => "user_capped",
        }
    }

    /// How long an element stays, in seconds; `None` for the sets whose
    /// elements stay until the ruleset is loaded again.
    pub const fn timeout_secs(self) -> Option<u64> {
        match self {
            Self::Cut | Self::Conns => None,
            Self::Rate | Self::Datagrams | Self::MeterNew | Self::MeterOut | Self::MeterIn => {
                Some(60)
            }
            Self::Dst | Self::Port | Self::Capped => Some(300),
            Self::Burst => Some(120),
            Self::Login => Some(600),
            Self::Mail => Some(3600),
        }
    }

    /// The most elements the set holds. A full set adds none, so a
    /// measurement under-counts rather than grows without bound. A set
    /// keyed by user and bucket holds every bucket of eight users, since a
    /// user's elements are bounded by the buckets; one keyed by user and
    /// protocol, or by user alone, holds 4,096 users.
    pub const fn size(self) -> u32 {
        match self {
            Self::Cut => 256,
            Self::Conns
            | Self::Rate
            | Self::Datagrams
            | Self::MeterNew
            | Self::MeterOut
            | Self::MeterIn
            | Self::Capped => 4096,
            Self::Port => 8192,
            Self::Dst | Self::Burst | Self::Login | Self::Mail => 32_768,
        }
    }

    /// The sets the watch reads to measure; the others limit or cut.
    pub const fn is_measured(self) -> bool {
        !matches!(self, Self::Cut | Self::Conns | Self::Rate | Self::Datagrams)
    }
}

closed_enum! {
    /// What the guard found a user doing (design §11.8). Each has an alert
    /// level, which is recorded, and a cut level, which cuts the user on
    /// the node.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum AbuseFinding {
        /// Many destinations in 5 minutes: horizontal scans, and P2P at
        /// scale. Measured in destination buckets.
        MassContact,
        /// Many destination ports in 5 minutes: vertical scans. Measured in
        /// port buckets.
        PortSweep,
        /// Many datagrams a second: the alert over one settled minute, the
        /// cut over two minutes in a row.
        DatagramFlood,
        /// Many new flows to one destination within 2 minutes.
        ConnectionFlood,
        /// Many new flows to one login service within 10 minutes: brute
        /// force and credential stuffing.
        LoginGuessing,
        /// Many mail-submission servers within an hour. Measured in
        /// destination buckets.
        MailBlast,
    }
}

impl AbuseFinding {
    /// The level at which the finding is recorded as an alert, in the
    /// finding's own unit (buckets, flows or datagrams a second).
    pub const fn alert_at(self) -> u32 {
        match self {
            // 558 of 4,096 buckets: about 600 destinations.
            Self::MassContact => 558,
            Self::PortSweep => 50,
            Self::DatagramFlood => 400,
            Self::ConnectionFlood => 1200,
            Self::LoginGuessing => 60,
            Self::MailBlast => 5,
        }
    }

    /// The level at which the finding cuts the user.
    pub const fn cut_at(self) -> u32 {
        match self {
            // 1,583 of 4,096 buckets: about 2,000 destinations.
            Self::MassContact => 1583,
            Self::PortSweep => 200,
            Self::DatagramFlood => 1000,
            Self::ConnectionFlood => 2400,
            Self::LoginGuessing => 300,
            Self::MailBlast => 20,
        }
    }

    /// The finding's name, as the CLI prints it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MassContact => "mass-contact",
            Self::PortSweep => "port-sweep",
            Self::DatagramFlood => "datagram-flood",
            Self::ConnectionFlood => "connection-flood",
            Self::LoginGuessing => "login-guessing",
            Self::MailBlast => "mail-blast",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::MassContact => 1,
            Self::PortSweep => 2,
            Self::DatagramFlood => 4,
            Self::ConnectionFlood => 8,
            Self::LoginGuessing => 16,
            Self::MailBlast => 32,
        }
    }
}

/// The distinct values a linear-counting sketch of `buckets` buckets
/// estimates from `used` of them taken: `−buckets × ln(1 − used/buckets)`,
/// rounded. A full sketch gives `None`: it shows only that the count is at
/// least the estimate one bucket short of full.
pub fn estimate_distinct(used: u16, buckets: u16) -> Option<u32> {
    if used >= buckets {
        return None;
    }
    let total = f64::from(buckets);
    let estimate = -total * (1.0 - f64::from(used) / total).ln();
    // At most buckets × ln(buckets), far inside u32.
    Some(estimate.round().clamp(0.0, f64::from(u32::MAX)) as u32)
}

/// A non-empty set of findings. On the wire it is a list in
/// [`AbuseFinding::ALL`] order with each finding at most once; any other
/// list, the empty one included, is rejected ([`ValueError::AbuseFindings`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<AbuseFinding>", into = "Vec<AbuseFinding>")]
pub struct AbuseFindings(u8);

impl AbuseFindings {
    /// The set holding `finding`.
    pub const fn of(finding: AbuseFinding) -> Self {
        Self(finding.bit())
    }

    /// The set with `finding` added.
    pub const fn with(self, finding: AbuseFinding) -> Self {
        Self(self.0 | finding.bit())
    }

    /// Whether `finding` is in the set.
    pub const fn contains(self, finding: AbuseFinding) -> bool {
        self.0 & finding.bit() != 0
    }

    /// The findings, in [`AbuseFinding::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = AbuseFinding> {
        AbuseFinding::ALL
            .iter()
            .copied()
            .filter(move |finding| self.contains(*finding))
    }
}

impl TryFrom<Vec<AbuseFinding>> for AbuseFindings {
    type Error = ValueError;

    fn try_from(findings: Vec<AbuseFinding>) -> Result<Self, Self::Error> {
        let ordered = findings.windows(2).all(|pair| pair[0] < pair[1]);
        match findings.split_first() {
            Some((first, rest)) if ordered => Ok(rest
                .iter()
                .fold(Self::of(*first), |set, finding| set.with(*finding))),
            _ => Err(ValueError::AbuseFindings),
        }
    }
}

impl From<AbuseFindings> for Vec<AbuseFinding> {
    fn from(set: AbuseFindings) -> Self {
        set.iter().collect()
    }
}

closed_enum! {
    /// Why the guard cannot measure on a node
    /// ([`crate::WatchError::AbuseGuardUnavailable`]).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum AbuseGuardFault {
        /// The node runs no generation, or one rendered before the guard:
        /// there is no per-user identity to measure. The next apply
        /// installs it.
        NotInstalled,
        /// The sets could not be read or what nft printed could not be
        /// parsed. Detection is off until a read succeeds; the limits and
        /// the cuts stay.
        ReadFailed,
    }
}

impl AbuseGuardFault {
    /// The fault in words, as the condition's message gives it.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotInstalled => "the configuration carries no abuse guard",
            Self::ReadFailed => "its sets could not be read",
        }
    }
}

/// A record's number in a node's abuse records: numbers start at
/// [`AbuseSeq::FIRST`] and grow by one per record, and are never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AbuseSeq(u64);

impl AbuseSeq {
    /// The number of a node's first record.
    pub const FIRST: Self = Self(0);

    /// Wraps a record number.
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// The record number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What happened, in one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AbuseAction {
    /// The watch cut the user: these findings reached their cut levels.
    Cut {
        /// The findings at their cut levels.
        findings: AbuseFindings,
    },
    /// These findings reached their alert levels, none its cut level.
    Alerted {
        /// The findings at their alert levels.
        findings: AbuseFindings,
    },
    /// The operator cut the user (`AbuseCut`).
    OperatorCut,
    /// The operator lifted the user's cut (`AbuseClear`).
    Cleared,
}

/// The aggregate figures a finding was decided on, and the context the
/// operator's review reads (design §11.8). No destination, port or address
/// is among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawFigures")]
pub struct AbuseFigures {
    /// Destination buckets reached in the last 5 minutes, of
    /// [`DESTINATION_BUCKETS`].
    pub destination_buckets: u16,
    /// Port buckets reached in the last 5 minutes, of [`PORT_BUCKETS`].
    pub port_buckets: u16,
    /// The most new flows to one destination bucket within 2 minutes.
    pub busiest_destination_flows: u32,
    /// The most new flows to one login service within 10 minutes.
    pub busiest_login_flows: u32,
    /// Mail-submission destination buckets reached in the last hour.
    pub submission_buckets: u16,
    /// New flows a minute, from the current meters; `None` while no meter
    /// is old enough.
    pub new_flows_per_min: Option<u32>,
    /// UDP datagrams sent a second, from the current meter.
    pub datagrams_per_sec: Option<u32>,
    /// The share of UDP in the bytes sent, in thousandths; `None` when
    /// nothing was sent.
    pub udp_share_permille: Option<u16>,
    /// Bytes received per thousand bytes sent; `None` when nothing was
    /// sent.
    pub received_per_sent_permille: Option<u64>,
    /// Bytes received per new flow; `None` without new flows. A scan's
    /// flows carry almost nothing back.
    pub received_bytes_per_flow: Option<u64>,
    /// Packets layer 1 refused in the last 5 minutes.
    pub refused_packets: u64,
}

impl AbuseFigures {
    /// Checks the figures' bounds: buckets within their sketches and a
    /// share of at most 1,000 thousandths ([`ValueError::AbuseFigures`]).
    pub fn check(self) -> Result<Self, ValueError> {
        let within = self.destination_buckets <= DESTINATION_BUCKETS
            && self.port_buckets <= PORT_BUCKETS
            && self.submission_buckets <= DESTINATION_BUCKETS
            && self.udp_share_permille.is_none_or(|share| share <= 1000);
        if within {
            Ok(self)
        } else {
            Err(ValueError::AbuseFigures)
        }
    }
}

/// The unvalidated wire shape of [`AbuseFigures`]: every key required, an
/// absent value written `null`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFigures {
    destination_buckets: u16,
    port_buckets: u16,
    busiest_destination_flows: u32,
    busiest_login_flows: u32,
    submission_buckets: u16,
    #[serde(deserialize_with = "Option::deserialize")]
    new_flows_per_min: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")]
    datagrams_per_sec: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")]
    udp_share_permille: Option<u16>,
    #[serde(deserialize_with = "Option::deserialize")]
    received_per_sent_permille: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    received_bytes_per_flow: Option<u64>,
    refused_packets: u64,
}

impl TryFrom<RawFigures> for AbuseFigures {
    type Error = ValueError;

    fn try_from(raw: RawFigures) -> Result<Self, Self::Error> {
        Self {
            destination_buckets: raw.destination_buckets,
            port_buckets: raw.port_buckets,
            busiest_destination_flows: raw.busiest_destination_flows,
            busiest_login_flows: raw.busiest_login_flows,
            submission_buckets: raw.submission_buckets,
            new_flows_per_min: raw.new_flows_per_min,
            datagrams_per_sec: raw.datagrams_per_sec,
            udp_share_permille: raw.udp_share_permille,
            received_per_sent_permille: raw.received_per_sent_permille,
            received_bytes_per_flow: raw.received_bytes_per_flow,
            refused_packets: raw.refused_packets,
        }
        .check()
    }
}

/// One record: a finding or an action, kept to show that a case was
/// handled and when (design §11.8).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseRecord {
    /// The record's number.
    pub seq: AbuseSeq,
    /// The node's clock when it was recorded.
    pub at: UnixTime,
    /// The user it concerns.
    pub user: OpaqueUserId,
    /// The guard whose rules measured it.
    pub guard: AbuseGuardVersion,
    /// What happened.
    pub action: AbuseAction,
    /// The figures at the time; `None` for an operator's action, which is
    /// taken without a reading.
    #[serde(deserialize_with = "Option::deserialize")]
    pub figures: Option<AbuseFigures>,
}

/// A user cut on a node, and since when.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbuseCutEntry {
    /// The user.
    pub user: OpaqueUserId,
    /// When the cut was made.
    pub since: UnixTime,
    /// The record of the cut (a `Cut` or an `OperatorCut`).
    pub record: AbuseSeq,
}

/// The users cut on a node, in strictly ascending user order, at most
/// [`MAX_ABUSE_CUTS`] of them ([`ValueError::AbuseCuts`] otherwise).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<AbuseCutEntry>", into = "Vec<AbuseCutEntry>")]
pub struct AbuseCuts(Vec<AbuseCutEntry>);

impl AbuseCuts {
    /// No user cut.
    pub const EMPTY: Self = Self(Vec::new());

    /// Validates the list.
    pub fn new(cuts: Vec<AbuseCutEntry>) -> Result<Self, ValueError> {
        let ordered = cuts.windows(2).all(|pair| pair[0].user < pair[1].user);
        if ordered && cuts.len() <= MAX_ABUSE_CUTS {
            Ok(Self(cuts))
        } else {
            Err(ValueError::AbuseCuts)
        }
    }

    /// The cuts, in user order.
    pub fn entries(&self) -> &[AbuseCutEntry] {
        &self.0
    }

    /// The cut of `user`, if the user is cut.
    pub fn get(&self, user: &OpaqueUserId) -> Option<&AbuseCutEntry> {
        self.0
            .binary_search_by(|cut| cut.user.cmp(user))
            .ok()
            .and_then(|index| self.0.get(index))
    }

    /// How many users are cut.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no user is cut.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The list with `entry` added in user order. A user cut already keeps
    /// the cut made first; a list holding [`MAX_ABUSE_CUTS`] users already
    /// is refused ([`ValueError::AbuseCuts`]).
    pub fn with(&self, entry: AbuseCutEntry) -> Result<Self, ValueError> {
        match self.0.binary_search_by(|cut| cut.user.cmp(&entry.user)) {
            Ok(_) => Ok(self.clone()),
            Err(_) if self.0.len() >= MAX_ABUSE_CUTS => Err(ValueError::AbuseCuts),
            Err(at) => {
                let mut cuts = self.0.clone();
                cuts.insert(at, entry);
                Ok(Self(cuts))
            }
        }
    }

    /// The list without `user`'s cut, if any.
    pub fn without(&self, user: &OpaqueUserId) -> Self {
        Self(
            self.0
                .iter()
                .filter(|cut| cut.user != *user)
                .cloned()
                .collect(),
        )
    }
}

impl TryFrom<Vec<AbuseCutEntry>> for AbuseCuts {
    type Error = ValueError;

    fn try_from(cuts: Vec<AbuseCutEntry>) -> Result<Self, Self::Error> {
        Self::new(cuts)
    }
}

impl From<AbuseCuts> for Vec<AbuseCutEntry> {
    fn from(cuts: AbuseCuts) -> Self {
        cuts.0
    }
}

/// The reply to `AbuseRecords{since}`: the users cut now ([`AbuseCuts`])
/// and a page of the records numbered `since` or later, oldest first and
/// numbered consecutively, at most [`MAX_ABUSE_RECORDS`] of them, with the
/// number the next record will get. It pages as `EventsV1` does: a first
/// record above `since` means older ones were pruned, and an `end` below
/// `since` means the records were reset.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawAbuseRecords")]
pub struct AbuseRecordsV1 {
    cuts: AbuseCuts,
    records: Vec<AbuseRecord>,
    end: AbuseSeq,
}

impl AbuseRecordsV1 {
    /// Validates the page ([`ValueError::AbuseRecords`] otherwise): each
    /// cut made by a record below `end`; records numbered consecutively
    /// upwards, all below `end`, at most [`MAX_ABUSE_RECORDS`] of them.
    pub fn new(
        cuts: AbuseCuts,
        records: Vec<AbuseRecord>,
        end: AbuseSeq,
    ) -> Result<Self, ValueError> {
        let cuts_recorded = cuts.entries().iter().all(|cut| cut.record < end);
        let records_ordered = records
            .windows(2)
            .all(|pair| pair[0].seq.get().checked_add(1) == Some(pair[1].seq.get()));
        let below_end = records.last().is_none_or(|last| last.seq < end);
        if cuts_recorded && records_ordered && below_end && records.len() <= MAX_ABUSE_RECORDS {
            Ok(Self { cuts, records, end })
        } else {
            Err(ValueError::AbuseRecords)
        }
    }

    /// The users cut now, in user order.
    pub fn cuts(&self) -> &AbuseCuts {
        &self.cuts
    }

    /// The records, oldest first.
    pub fn records(&self) -> &[AbuseRecord] {
        &self.records
    }

    /// The number the next record will get.
    pub const fn end(&self) -> AbuseSeq {
        self.end
    }
}

/// The unvalidated wire shape of [`AbuseRecordsV1`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAbuseRecords {
    cuts: AbuseCuts,
    records: Vec<AbuseRecord>,
    end: AbuseSeq,
}

impl TryFrom<RawAbuseRecords> for AbuseRecordsV1 {
    type Error = ValueError;

    fn try_from(raw: RawAbuseRecords) -> Result<Self, Self::Error> {
        Self::new(raw.cuts, raw.records, raw.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str) -> OpaqueUserId {
        OpaqueUserId::new(id).unwrap()
    }

    /// FNV-1a's published test vectors pin the hash, and the address is
    /// the base plus one plus the hash modulo the span, so a change to
    /// either changes every user's address and fails here.
    #[test]
    fn a_users_source_is_the_fnv1a_hash_of_the_id_in_the_range() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
        let id = user("abcdefghij");
        let offset = 1 + fnv1a64(b"abcdefghij") % u64::from(USER_SOURCES);
        let expected = Ipv4Addr::from(u32::from(USER_SOURCE_BASE) + offset as u32);
        assert_eq!(user_source(&id), expected);
        assert_eq!(user_source(&id), user_source(&id));
        assert_ne!(user_source(&id), user_source(&user("abcdefghik")));
        assert_eq!(USER_SOURCES, 131_070);
        assert_eq!(
            USER_SOURCE_NET,
            format!("{USER_SOURCE_BASE}/{USER_SOURCE_PREFIX}")
        );
    }

    #[test]
    fn every_source_lies_inside_the_range_and_off_its_ends() {
        for index in 0..20_000_u32 {
            let source = user_source(&user(&format!("u{index}")));
            assert!(is_user_source(source), "{source}");
            let octets = source.octets();
            assert_eq!(octets[0], 198);
            assert!(octets[1] == 18 || octets[1] == 19);
        }
        assert!(!is_user_source(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_user_source(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_user_source(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_user_source(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!is_user_source(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_user_source(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_user_source(Ipv4Addr::new(10, 77, 3, 1)));
    }

    #[test]
    fn the_guard_version_travels_as_its_number() {
        assert_eq!(serde_json::to_string(&AbuseGuardVersion::V1).unwrap(), "1");
        assert_eq!(
            serde_json::from_str::<AbuseGuardVersion>("1").unwrap(),
            AbuseGuardVersion::CURRENT
        );
        for bad in ["0", "2", "\"1\"", "-1"] {
            assert!(
                serde_json::from_str::<AbuseGuardVersion>(bad).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            AbuseGuardVersion::try_from(7),
            Err(ValueError::AbuseGuardVersion { number: 7 })
        );
    }

    #[test]
    fn the_sets_have_distinct_names_and_bounded_sizes() {
        let mut names: Vec<_> = AbuseSet::ALL.iter().map(|set| set.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AbuseSet::ALL.len());
        for set in AbuseSet::ALL {
            assert!(
                set.name()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
            assert!(set.size() >= 256 && set.size() <= 32_768);
        }
        // Every bucket of eight users fits in each set keyed by bucket.
        for set in [
            AbuseSet::Dst,
            AbuseSet::Burst,
            AbuseSet::Login,
            AbuseSet::Mail,
        ] {
            assert_eq!(set.size(), 8 * u32::from(DESTINATION_BUCKETS), "{set:?}");
        }
        assert_eq!(AbuseSet::Port.size(), 8 * u32::from(PORT_BUCKETS));
        assert!(AbuseSet::Cut.size() as usize >= MAX_ABUSE_CUTS);
        let measured: Vec<_> = AbuseSet::ALL
            .iter()
            .filter(|set| set.is_measured())
            .collect();
        assert_eq!(measured.len(), 9);
        assert_eq!(AbuseSet::Cut.timeout_secs(), None);
        assert_eq!(AbuseSet::Mail.timeout_secs(), Some(3600));
    }

    /// Each finding's alert level lies below its cut level, and the
    /// bucket levels of `MassContact` are the estimates the design states.
    #[test]
    fn levels_are_ordered_and_match_the_design() {
        for finding in AbuseFinding::ALL {
            assert!(finding.alert_at() < finding.cut_at(), "{finding:?}");
        }
        // Each bucket level is the fewest buckets whose estimate reaches the
        // design's count of destinations.
        for (level, count) in [
            (AbuseFinding::MassContact.cut_at(), 2000),
            (AbuseFinding::MassContact.alert_at(), 600),
        ] {
            let level = u16::try_from(level).unwrap();
            assert!(estimate_distinct(level, DESTINATION_BUCKETS).unwrap() >= count);
            assert!(estimate_distinct(level - 1, DESTINATION_BUCKETS).unwrap() < count);
        }
        assert_eq!(estimate_distinct(0, DESTINATION_BUCKETS), Some(0));
        assert_eq!(estimate_distinct(1, DESTINATION_BUCKETS), Some(1));
        assert_eq!(estimate_distinct(4095, DESTINATION_BUCKETS), Some(34_070));
        assert_eq!(estimate_distinct(4096, DESTINATION_BUCKETS), None);
        assert_eq!(PORT_BUCKETS, 1024);
        let names: Vec<_> = AbuseFinding::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(
            names,
            [
                "mass-contact",
                "port-sweep",
                "datagram-flood",
                "connection-flood",
                "login-guessing",
                "mail-blast"
            ]
        );
    }

    #[test]
    fn findings_travel_as_an_ordered_non_empty_list() {
        let both = AbuseFindings::of(AbuseFinding::MassContact).with(AbuseFinding::PortSweep);
        assert_eq!(
            serde_json::to_string(&both).unwrap(),
            r#"["MassContact","PortSweep"]"#
        );
        assert_eq!(
            serde_json::from_str::<AbuseFindings>(r#"["MassContact","PortSweep"]"#).unwrap(),
            both
        );
        assert!(both.contains(AbuseFinding::PortSweep));
        assert!(!both.contains(AbuseFinding::MailBlast));
        for bad in [
            "[]",
            r#"["PortSweep","MassContact"]"#,
            r#"["MailBlast","MailBlast"]"#,
            r#"["Scan"]"#,
        ] {
            assert!(serde_json::from_str::<AbuseFindings>(bad).is_err(), "{bad}");
        }
        assert_eq!(
            AbuseFindings::try_from(Vec::new()),
            Err(ValueError::AbuseFindings)
        );
    }

    fn figures() -> AbuseFigures {
        AbuseFigures {
            destination_buckets: 1600,
            port_buckets: 3,
            busiest_destination_flows: 4,
            busiest_login_flows: 0,
            submission_buckets: 0,
            new_flows_per_min: Some(900),
            datagrams_per_sec: None,
            udp_share_permille: Some(12),
            received_per_sent_permille: Some(800),
            received_bytes_per_flow: Some(140),
            refused_packets: 30,
        }
    }

    #[test]
    fn figures_are_checked_on_receipt_and_every_key_is_required() {
        let json = serde_json::to_string(&figures()).unwrap();
        assert_eq!(
            json,
            r#"{"destination_buckets":1600,"port_buckets":3,"busiest_destination_flows":4,"busiest_login_flows":0,"submission_buckets":0,"new_flows_per_min":900,"datagrams_per_sec":null,"udp_share_permille":12,"received_per_sent_permille":800,"received_bytes_per_flow":140,"refused_packets":30}"#
        );
        assert_eq!(
            serde_json::from_str::<AbuseFigures>(&json).unwrap(),
            figures()
        );
        for bad in [
            json.replace(
                r#""destination_buckets":1600"#,
                r#""destination_buckets":4097"#,
            ),
            json.replace(r#""port_buckets":3"#, r#""port_buckets":1025"#),
            json.replace(r#""submission_buckets":0"#, r#""submission_buckets":4097"#),
            json.replace(r#""udp_share_permille":12"#, r#""udp_share_permille":1001"#),
            json.replace(r#""datagrams_per_sec":null,"#, ""),
            json.replace(r#""refused_packets":30"#, r#""refused_packets":30,"x":1"#),
        ] {
            assert!(serde_json::from_str::<AbuseFigures>(&bad).is_err(), "{bad}");
        }
        let full = AbuseFigures {
            destination_buckets: DESTINATION_BUCKETS,
            port_buckets: PORT_BUCKETS,
            submission_buckets: DESTINATION_BUCKETS,
            udp_share_permille: Some(1000),
            ..figures()
        };
        assert_eq!(full.check(), Ok(full));
    }

    fn record(seq: u64) -> AbuseRecord {
        AbuseRecord {
            seq: AbuseSeq::new(seq),
            at: UnixTime::from_secs(1_791_417_600),
            user: user("abcdefghij"),
            guard: AbuseGuardVersion::V1,
            action: AbuseAction::Cut {
                findings: AbuseFindings::of(AbuseFinding::MassContact),
            },
            figures: Some(figures()),
        }
    }

    fn cut(id: &str, record: u64) -> AbuseCutEntry {
        AbuseCutEntry {
            user: user(id),
            since: UnixTime::from_secs(1_791_417_600),
            record: AbuseSeq::new(record),
        }
    }

    #[test]
    fn a_page_holds_ordered_cuts_and_consecutive_records_below_its_end() {
        let cuts = |list: Vec<AbuseCutEntry>| AbuseCuts::new(list).unwrap();
        let page = AbuseRecordsV1::new(
            cuts(vec![cut("aaaaaaaaaa", 3), cut("bbbbbbbbbb", 4)]),
            vec![record(3), record(4)],
            AbuseSeq::new(5),
        )
        .unwrap();
        assert_eq!(page.cuts().len(), 2);
        assert_eq!(
            page.cuts().get(&user("bbbbbbbbbb")).map(|cut| cut.record),
            Some(AbuseSeq::new(4))
        );
        assert_eq!(page.cuts().get(&user("cccccccccc")), None);
        assert_eq!(page.records().len(), 2);
        assert_eq!(page.end(), AbuseSeq::new(5));
        assert!(AbuseRecordsV1::new(AbuseCuts::default(), Vec::new(), AbuseSeq::FIRST).is_ok());
        assert!(AbuseCuts::default().is_empty());
        for (list, records, end) in [
            (vec![cut("aaaaaaaaaa", 5)], vec![], 5),
            (vec![], vec![record(3), record(5)], 9),
            (vec![], vec![record(4), record(3)], 9),
            (vec![], vec![record(3), record(4)], 4),
        ] {
            assert_eq!(
                AbuseRecordsV1::new(cuts(list), records, AbuseSeq::new(end)),
                Err(ValueError::AbuseRecords)
            );
        }
        for list in [
            vec![cut("bbbbbbbbbb", 1), cut("aaaaaaaaaa", 1)],
            vec![cut("aaaaaaaaaa", 1), cut("aaaaaaaaaa", 2)],
        ] {
            assert_eq!(AbuseCuts::new(list), Err(ValueError::AbuseCuts));
        }
        let many: Vec<_> = (0..=MAX_ABUSE_RECORDS as u64).map(record).collect();
        assert!(
            AbuseRecordsV1::new(
                AbuseCuts::default(),
                many[..MAX_ABUSE_RECORDS].to_vec(),
                AbuseSeq::new(u64::MAX)
            )
            .is_ok()
        );
        assert_eq!(
            AbuseRecordsV1::new(AbuseCuts::default(), many, AbuseSeq::new(u64::MAX)),
            Err(ValueError::AbuseRecords)
        );
        let full: Vec<_> = (0..=MAX_ABUSE_CUTS)
            .map(|index| cut(&format!("u{index:05}"), 0))
            .collect();
        assert!(AbuseCuts::new(full[..MAX_ABUSE_CUTS].to_vec()).is_ok());
        assert_eq!(AbuseCuts::new(full), Err(ValueError::AbuseCuts));
        assert!(serde_json::from_str::<AbuseCuts>(
            r#"[{"user":"bbbbbbbbbb","since":1,"record":0},{"user":"aaaaaaaaaa","since":1,"record":0}]"#
        )
        .is_err());
    }

    #[test]
    fn cuts_are_added_in_user_order_once_and_removed() {
        let one = AbuseCuts::EMPTY.with(cut("bbbbbbbbbb", 1)).unwrap();
        let two = one.with(cut("aaaaaaaaaa", 2)).unwrap();
        let users: Vec<_> = two.entries().iter().map(|cut| cut.user.as_str()).collect();
        assert_eq!(users, ["aaaaaaaaaa", "bbbbbbbbbb"]);
        // A user cut already keeps the first cut's record.
        let again = two.with(cut("bbbbbbbbbb", 9)).unwrap();
        assert_eq!(again, two);
        assert_eq!(two.without(&user("aaaaaaaaaa")), one);
        assert_eq!(two.without(&user("cccccccccc")), two);
        assert!(AbuseCuts::EMPTY.without(&user("aaaaaaaaaa")).is_empty());
        let full = AbuseCuts::new(
            (0..MAX_ABUSE_CUTS)
                .map(|index| cut(&format!("u{index:05}"), 0))
                .collect(),
        )
        .unwrap();
        assert_eq!(full.with(cut("zzzzzzzzzz", 1)), Err(ValueError::AbuseCuts));
        assert_eq!(full.with(cut("u00000", 1)).unwrap(), full);
    }

    #[test]
    fn a_page_is_checked_on_receipt() {
        let page = AbuseRecordsV1::new(
            AbuseCuts::new(vec![cut("abcdefghij", 7)]).unwrap(),
            vec![record(7)],
            AbuseSeq::new(8),
        )
        .unwrap();
        let json = serde_json::to_string(&page).unwrap();
        assert_eq!(serde_json::from_str::<AbuseRecordsV1>(&json).unwrap(), page);
        assert!(
            serde_json::from_str::<AbuseRecordsV1>(&json.replace(r#""end":8"#, r#""end":7"#))
                .is_err()
        );
        let operator = AbuseRecord {
            action: AbuseAction::OperatorCut,
            figures: None,
            ..record(0)
        };
        let json = serde_json::to_string(&operator).unwrap();
        assert!(
            json.ends_with(r#""action":"OperatorCut","figures":null}"#),
            "{json}"
        );
        assert!(
            serde_json::from_str::<AbuseRecord>(&json.replace(r#","figures":null"#, "")).is_err()
        );
    }
}
