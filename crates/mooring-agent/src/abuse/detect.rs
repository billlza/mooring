// SPDX-License-Identifier: GPL-3.0-or-later

//! The findings (design §11.8): each served user's figures from one
//! reading of the sets, and which findings reach their alert and cut
//! levels. Pure functions of the reading, except the memory of settled
//! datagram minutes that `DatagramFlood`'s cut needs (two in a row), which
//! a watch that restarts loses: it then needs two more minutes.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AbuseFigures, AbuseFinding, AbuseFindings, AbuseSet, DESTINATION_BUCKETS, METER_MIN_AGE_SECS,
    METER_SETTLED_SECS, OpaqueUserId, PORT_BUCKETS, UnixTime,
};

use super::sets::{Measured, Proto};

/// One user's figures at one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserReading {
    /// The figures a record keeps.
    pub(crate) figures: AbuseFigures,
    /// The user's settled datagram minute, when its meter has covered at
    /// least [`METER_SETTLED_SECS`]: when the minute began, and its
    /// datagrams a second.
    pub(crate) settled_datagrams: Option<SettledMinute>,
}

/// A datagram meter's minute that has run long enough to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettledMinute {
    pub(crate) began: UnixTime,
    pub(crate) per_sec: u32,
}

/// The shortest and longest gap between the starts of two settled datagram
/// minutes that make two minutes in a row: a meter element lives 60 s, and
/// the next is made by the first datagram after it expires, so a flood
/// that pauses up to 30 s still counts as in a row, and a minute skipped
/// (a gap of about 120 s) never does.
const NEXT_MINUTE_SECS: std::ops::RangeInclusive<u64> = 50..=90;

/// The readings of every served user, by user, from `measured` at `now`.
/// `served` maps each served user's source address to the user; an element
/// whose address no served user has (a user removed since it was made)
/// counts for no one.
pub(crate) fn readings(
    measured: &Measured,
    served: &BTreeMap<Ipv4Addr, OpaqueUserId>,
    now: UnixTime,
) -> BTreeMap<OpaqueUserId, UserReading> {
    served
        .iter()
        .map(|(source, user)| (user.clone(), reading(measured, *source, now)))
        .collect()
}

fn reading(measured: &Measured, source: Ipv4Addr, now: UnixTime) -> UserReading {
    let of = |set: AbuseSet| {
        measured
            .elements(set)
            .iter()
            .filter(move |element| element.source == source)
    };
    let count = |set: AbuseSet, bound: u16| saturate_u16(of(set).count()).min(bound);
    let busiest = |set: AbuseSet| {
        of(set)
            .filter_map(|element| element.counter)
            .map(|counter| saturate_u32(counter.packets))
            .max()
            .unwrap_or(0)
    };
    let meters = |set: AbuseSet, proto: Option<Proto>| {
        of(set)
            .filter(move |element| proto.is_none_or(|proto| element.proto == Some(proto)))
            .filter_map(|element| Some((element.age?, element.counter?)))
            .collect::<Vec<_>>()
    };
    let new_flows = meters(AbuseSet::MeterNew, None);
    let new_flows_per_min = rate(&new_flows, 60, |counter| counter.packets);
    let udp_out = meters(AbuseSet::MeterOut, Some(Proto::Udp));
    let datagrams_per_sec = rate(&udp_out, 1, |counter| counter.packets);
    let bytes = |list: &[(u64, super::sets::Counter)]| {
        list.iter()
            .map(|(_, counter)| counter.bytes)
            .fold(0_u64, u64::saturating_add)
    };
    let sent_udp = bytes(&udp_out);
    let sent = bytes(&meters(AbuseSet::MeterOut, None));
    let received = bytes(&meters(AbuseSet::MeterIn, None));
    let flows = new_flows
        .iter()
        .map(|(_, counter)| counter.packets)
        .fold(0_u64, u64::saturating_add);
    let figures = AbuseFigures {
        destination_buckets: count(AbuseSet::Dst, DESTINATION_BUCKETS),
        port_buckets: count(AbuseSet::Port, PORT_BUCKETS),
        busiest_destination_flows: busiest(AbuseSet::Burst),
        busiest_login_flows: busiest(AbuseSet::Login),
        submission_buckets: count(AbuseSet::Mail, DESTINATION_BUCKETS),
        new_flows_per_min,
        datagrams_per_sec,
        udp_share_permille: per_mille(sent_udp, sent)
            .map(|share| u16::try_from(share.min(1000)).unwrap_or(1000)),
        received_per_sent_permille: per_mille(received, sent),
        received_bytes_per_flow: received.checked_div(flows),
        refused_packets: of(AbuseSet::Capped)
            .filter_map(|element| element.counter)
            .map(|counter| counter.packets)
            .fold(0_u64, u64::saturating_add),
    };
    let settled_datagrams = udp_out
        .iter()
        .filter(|(age, _)| *age >= METER_SETTLED_SECS)
        .max_by_key(|(age, _)| *age)
        .map(|(age, counter)| SettledMinute {
            began: UnixTime::from_secs(now.as_secs().saturating_sub(*age)),
            per_sec: saturate_u32(counter.packets / age),
        });
    UserReading {
        figures,
        settled_datagrams,
    }
}

/// The meters' total over their ages, per `per` seconds: `None` while no
/// meter has run [`METER_MIN_AGE_SECS`].
fn rate(
    meters: &[(u64, super::sets::Counter)],
    per: u64,
    of: impl Fn(&super::sets::Counter) -> u64,
) -> Option<u32> {
    let grown: Vec<_> = meters
        .iter()
        .filter(|(age, _)| *age >= METER_MIN_AGE_SECS)
        .collect();
    if grown.is_empty() {
        return None;
    }
    let total = grown.iter().fold(0_u64, |sum, (age, counter)| {
        sum.saturating_add(of(counter).saturating_mul(per) / age)
    });
    Some(saturate_u32(total))
}

/// `part` per thousand of `whole`; `None` when `whole` is zero.
fn per_mille(part: u64, whole: u64) -> Option<u64> {
    part.saturating_mul(1000).checked_div(whole)
}

fn saturate_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn saturate_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// What one user's reading reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Verdict {
    /// The findings at their cut levels.
    pub(crate) cut: Option<AbuseFindings>,
    /// The findings at their alert levels and below their cut levels.
    pub(crate) alert: Option<AbuseFindings>,
}

/// The watch's memory of each user's latest settled datagram minute at or
/// above `DatagramFlood`'s cut level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FloodMinutes(BTreeMap<OpaqueUserId, UnixTime>);

impl FloodMinutes {
    /// Forgets the users not in `served`, and minutes too old to be
    /// followed by the next.
    pub(crate) fn retain(&mut self, served: &BTreeMap<OpaqueUserId, UserReading>, now: UnixTime) {
        self.0.retain(|user, began| {
            served.contains_key(user)
                && now
                    .secs_since(*began)
                    .is_some_and(|age| age <= *NEXT_MINUTE_SECS.end() + 60)
        });
    }
}

/// Which of `user`'s findings reach their levels at this reading.
/// `DatagramFlood` alerts on one settled minute at its alert level, and
/// cuts on a second settled minute at its cut level that follows one
/// already seen at it (remembered in `floods`).
pub(crate) fn judge(
    user: &OpaqueUserId,
    reading: &UserReading,
    floods: &mut FloodMinutes,
) -> Verdict {
    let figures = &reading.figures;
    let mut cut = None;
    let mut alert = None;
    let mut reach = |finding: AbuseFinding, value: u32, cuts: bool| {
        if cuts {
            cut = Some(
                cut.map_or(AbuseFindings::of(finding), |set: AbuseFindings| {
                    set.with(finding)
                }),
            );
        } else if value >= finding.alert_at() {
            alert = Some(
                alert.map_or(AbuseFindings::of(finding), |set: AbuseFindings| {
                    set.with(finding)
                }),
            );
        }
    };
    for (finding, value) in [
        (
            AbuseFinding::MassContact,
            u32::from(figures.destination_buckets),
        ),
        (AbuseFinding::PortSweep, u32::from(figures.port_buckets)),
        (
            AbuseFinding::ConnectionFlood,
            figures.busiest_destination_flows,
        ),
        (AbuseFinding::LoginGuessing, figures.busiest_login_flows),
        (
            AbuseFinding::MailBlast,
            u32::from(figures.submission_buckets),
        ),
    ] {
        reach(finding, value, value >= finding.cut_at());
    }
    if let Some(minute) = reading.settled_datagrams {
        let flood = AbuseFinding::DatagramFlood;
        let at_cut = minute.per_sec >= flood.cut_at();
        let follows = floods.0.get(user).is_some_and(|previous| {
            minute
                .began
                .secs_since(*previous)
                .is_some_and(|gap| NEXT_MINUTE_SECS.contains(&gap))
        });
        reach(flood, minute.per_sec, at_cut && follows);
        if at_cut {
            let newer = floods
                .0
                .get(user)
                .is_none_or(|previous| minute.began > *previous);
            if newer {
                floods.0.insert(user.clone(), minute.began);
            }
        }
    }
    Verdict { cut, alert }
}
