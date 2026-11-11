// SPDX-License-Identifier: GPL-3.0-or-later

//! The findings (design §11.8): each user's figures from one reading, and
//! each finding's alert and cut levels at their exact boundaries, the
//! ordinary use below them, and `DatagramFlood`'s two minutes in a row.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AbuseFinding, AbuseFindings, AbuseSet, METER_MIN_AGE_SECS, METER_SETTLED_SECS, OpaqueUserId,
    UnixTime, user_source,
};

use crate::abuse::detect::{FloodMinutes, SettledMinute, UserReading, Verdict, judge, readings};
use crate::abuse::sets::{Counter, Element, Measured, Proto};

const NOW: u64 = 1_791_500_000;

fn user(id: &str) -> OpaqueUserId {
    OpaqueUserId::new(id).unwrap()
}

fn served(ids: &[&str]) -> BTreeMap<Ipv4Addr, OpaqueUserId> {
    ids.iter()
        .map(|id| (user_source(&user(id)), user(id)))
        .collect()
}

/// One element of a test reading: the user's address, the protocol, the
/// age and the counter's packets and bytes.
type Row = (Ipv4Addr, Option<Proto>, Option<u64>, Option<(u64, u64)>);

/// The elements of one set of a test reading.
fn elements(rows: &[Row]) -> Vec<Element> {
    rows.iter()
        .map(|&(source, proto, age, counter)| Element {
            source,
            proto,
            age,
            counter: counter.map(|(packets, bytes)| Counter { packets, bytes }),
        })
        .collect()
}

/// The sets of a reading where a finding's measure is the given value.
type SetsAt = Box<dyn Fn(u32) -> Vec<(AbuseSet, Vec<Row>)>>;

/// `count` elements of `source` in a bucket set.
fn many(source: Ipv4Addr, count: usize) -> Vec<Row> {
    (0..count).map(|_| (source, None, Some(10), None)).collect()
}

fn measured(sets: Vec<(AbuseSet, Vec<Row>)>) -> Measured {
    Measured::of(
        sets.into_iter()
            .map(|(set, rows)| (set, elements(&rows)))
            .collect(),
    )
}

fn reading_of(id: &str, sets: Vec<(AbuseSet, Vec<Row>)>) -> UserReading {
    readings(&measured(sets), &served(&[id]), UnixTime::from_secs(NOW))[&user(id)]
}

fn verdict(reading: &UserReading) -> Verdict {
    judge(&user("u01"), reading, &mut FloodMinutes::default())
}

fn of(findings: &[AbuseFinding]) -> Option<AbuseFindings> {
    findings.split_first().map(|(first, rest)| {
        rest.iter()
            .fold(AbuseFindings::of(*first), |set, finding| set.with(*finding))
    })
}

#[test]
fn figures_count_one_users_elements_and_ignore_the_rest() {
    let me = user_source(&user("u01"));
    let other = user_source(&user("u02"));
    let gone = Ipv4Addr::new(198, 18, 0, 9);
    let reading = reading_of(
        "u01",
        vec![
            (
                AbuseSet::Dst,
                [many(me, 7), many(other, 900), many(gone, 50)].concat(),
            ),
            (AbuseSet::Port, many(me, 3)),
            (
                AbuseSet::Burst,
                vec![
                    (me, None, Some(30), Some((40, 2_400))),
                    (me, None, Some(30), Some((300, 18_000))),
                    (other, None, Some(30), Some((5_000, 300_000))),
                ],
            ),
            (
                AbuseSet::Login,
                vec![(me, None, Some(30), Some((61, 3_660)))],
            ),
            (AbuseSet::Mail, many(me, 2)),
            (
                AbuseSet::MeterNew,
                vec![
                    (me, Some(Proto::Tcp), Some(30), Some((60, 3_600))),
                    (me, Some(Proto::Udp), Some(20), Some((10, 600))),
                ],
            ),
            (
                AbuseSet::MeterOut,
                vec![
                    (me, Some(Proto::Tcp), Some(30), Some((900, 300_000))),
                    (me, Some(Proto::Udp), Some(50), Some((5_000, 100_000))),
                ],
            ),
            (
                AbuseSet::MeterIn,
                vec![(me, None, Some(40), Some((800, 1_400_000)))],
            ),
            (
                AbuseSet::Capped,
                vec![(me, None, Some(100), Some((17, 1_020)))],
            ),
        ],
    );
    let figures = reading.figures;
    assert_eq!(figures.destination_buckets, 7);
    assert_eq!(figures.port_buckets, 3);
    assert_eq!(figures.busiest_destination_flows, 300);
    assert_eq!(figures.busiest_login_flows, 61);
    assert_eq!(figures.submission_buckets, 2);
    // 60 flows in 30 s and 10 in 20 s: 120 and 30 a minute.
    assert_eq!(figures.new_flows_per_min, Some(150));
    // 5,000 datagrams in 50 s.
    assert_eq!(figures.datagrams_per_sec, Some(100));
    // 100,000 of 400,000 bytes sent were UDP.
    assert_eq!(figures.udp_share_permille, Some(250));
    // 1,400,000 received for 400,000 sent.
    assert_eq!(figures.received_per_sent_permille, Some(3_500));
    // 1,400,000 received over 70 new flows.
    assert_eq!(figures.received_bytes_per_flow, Some(20_000));
    assert_eq!(figures.refused_packets, 17);
    assert_eq!(
        reading.settled_datagrams,
        Some(SettledMinute {
            began: UnixTime::from_secs(NOW - 50),
            per_sec: 100
        })
    );
    // A served user with nothing measured has every figure at zero, and no
    // rate or share.
    let quiet = readings(
        &Measured::default(),
        &served(&["u01"]),
        UnixTime::from_secs(NOW),
    );
    let quiet = quiet[&user("u01")].figures;
    assert_eq!(quiet.destination_buckets, 0);
    assert_eq!(quiet.new_flows_per_min, None);
    assert_eq!(quiet.udp_share_permille, None);
    assert_eq!(quiet.received_per_sent_permille, None);
    assert_eq!(quiet.received_bytes_per_flow, None);
    assert_eq!(quiet.check(), Ok(quiet));
}

/// A meter younger than `METER_MIN_AGE_SECS` gives no rate, and one younger
/// than `METER_SETTLED_SECS` no settled minute.
#[test]
fn young_meters_give_no_rate_and_no_settled_minute() {
    let me = user_source(&user("u01"));
    let young = METER_MIN_AGE_SECS - 1;
    let reading = reading_of(
        "u01",
        vec![
            (
                AbuseSet::MeterNew,
                vec![(me, Some(Proto::Tcp), Some(young), Some((90, 5_400)))],
            ),
            (
                AbuseSet::MeterOut,
                vec![(
                    me,
                    Some(Proto::Udp),
                    Some(METER_SETTLED_SECS - 1),
                    Some((44_000, 1)),
                )],
            ),
        ],
    );
    assert_eq!(reading.figures.new_flows_per_min, None);
    assert_eq!(reading.figures.datagrams_per_sec, Some(1_000));
    assert_eq!(reading.settled_datagrams, None);
}

/// Every finding measured by a count: one below its alert level is
/// nothing, its alert level an alert, one below its cut level still an
/// alert, its cut level a cut.
#[test]
fn each_count_finding_alerts_and_cuts_exactly_at_its_levels() {
    let me = user_source(&user("u01"));
    let counted: Vec<(AbuseFinding, SetsAt)> = vec![
        (
            AbuseFinding::MassContact,
            Box::new(move |count| vec![(AbuseSet::Dst, many(me, count as usize))]),
        ),
        (
            AbuseFinding::PortSweep,
            Box::new(move |count| vec![(AbuseSet::Port, many(me, count as usize))]),
        ),
        (
            AbuseFinding::ConnectionFlood,
            Box::new(move |count| {
                vec![(
                    AbuseSet::Burst,
                    vec![(me, None, Some(30), Some((u64::from(count), 0)))],
                )]
            }),
        ),
        (
            AbuseFinding::LoginGuessing,
            Box::new(move |count| {
                vec![(
                    AbuseSet::Login,
                    vec![(me, None, Some(30), Some((u64::from(count), 0)))],
                )]
            }),
        ),
        (
            AbuseFinding::MailBlast,
            Box::new(move |count| vec![(AbuseSet::Mail, many(me, count as usize))]),
        ),
    ];
    for (finding, sets) in counted {
        let at = |count: u32| verdict(&reading_of("u01", sets(count)));
        assert_eq!(
            at(finding.alert_at() - 1),
            Verdict::default(),
            "{finding:?}"
        );
        assert_eq!(
            at(finding.alert_at()),
            Verdict {
                cut: None,
                alert: of(&[finding])
            },
            "{finding:?}"
        );
        assert_eq!(
            at(finding.cut_at() - 1),
            Verdict {
                cut: None,
                alert: of(&[finding])
            },
            "{finding:?}"
        );
        assert_eq!(
            at(finding.cut_at()),
            Verdict {
                cut: of(&[finding]),
                alert: None
            },
            "{finding:?}"
        );
    }
}

/// A heavy but ordinary user stays below every level: a few hundred
/// destinations, a handful of ports, keep-alive connections, mail to one
/// provider, a video call's datagrams.
#[test]
fn heavy_ordinary_use_reaches_no_level() {
    let me = user_source(&user("u01"));
    let reading = reading_of(
        "u01",
        vec![
            (AbuseSet::Dst, many(me, 400)),
            (AbuseSet::Port, many(me, 6)),
            (AbuseSet::Burst, vec![(me, None, Some(110), Some((180, 0)))]),
            (AbuseSet::Login, vec![(me, None, Some(500), Some((20, 0)))]),
            (AbuseSet::Mail, many(me, 1)),
            (
                AbuseSet::MeterOut,
                vec![(me, Some(Proto::Udp), Some(55), Some((16_500, 19_800_000)))],
            ),
        ],
    );
    assert_eq!(reading.figures.datagrams_per_sec, Some(300));
    assert_eq!(verdict(&reading), Verdict::default());
}

/// A scan reaches several findings at once: the cut names every one at
/// its cut level, the alert those at their alert levels only.
#[test]
fn several_findings_are_judged_together() {
    let me = user_source(&user("u01"));
    let reading = reading_of(
        "u01",
        vec![
            (AbuseSet::Dst, many(me, 1_700)),
            (AbuseSet::Port, many(me, 250)),
            (AbuseSet::Mail, many(me, 6)),
        ],
    );
    assert_eq!(
        verdict(&reading),
        Verdict {
            cut: of(&[AbuseFinding::MassContact, AbuseFinding::PortSweep]),
            alert: of(&[AbuseFinding::MailBlast])
        }
    );
    let reading = reading_of(
        "u01",
        vec![
            (AbuseSet::Dst, many(me, 600)),
            (AbuseSet::Mail, many(me, 6)),
        ],
    );
    assert_eq!(
        verdict(&reading),
        Verdict {
            cut: None,
            alert: of(&[AbuseFinding::MassContact, AbuseFinding::MailBlast])
        }
    );
}

fn flood_minute(began: u64, per_sec: u32) -> UserReading {
    let mut reading = reading_of("u01", Vec::new());
    reading.settled_datagrams = Some(SettledMinute {
        began: UnixTime::from_secs(began),
        per_sec,
    });
    reading
}

/// One settled minute at the cut level alerts; the next one, a minute
/// later, cuts. The same minute seen again, a minute too far apart, or a
/// second minute below the cut level does not cut.
#[test]
fn a_datagram_flood_cuts_on_its_second_minute_in_a_row() {
    let flood = AbuseFinding::DatagramFlood;
    let me = user("u01");
    let alert = Verdict {
        cut: None,
        alert: of(&[flood]),
    };
    let cut = Verdict {
        cut: of(&[flood]),
        alert: None,
    };
    let mut floods = FloodMinutes::default();
    assert_eq!(
        judge(&me, &flood_minute(NOW, flood.cut_at()), &mut floods),
        alert
    );
    // The same minute at the next reading, its start a second off.
    assert_eq!(
        judge(&me, &flood_minute(NOW + 1, flood.cut_at()), &mut floods),
        alert
    );
    assert_eq!(
        judge(&me, &flood_minute(NOW + 61, flood.cut_at()), &mut floods),
        cut
    );

    let mut floods = FloodMinutes::default();
    judge(&me, &flood_minute(NOW, flood.cut_at()), &mut floods);
    assert_eq!(
        judge(&me, &flood_minute(NOW + 200, flood.cut_at()), &mut floods),
        alert,
        "not the next minute"
    );
    assert_eq!(
        judge(
            &me,
            &flood_minute(NOW + 260, flood.cut_at() - 1),
            &mut floods
        ),
        alert,
        "below the cut level"
    );
    assert_eq!(
        judge(&me, &flood_minute(NOW + 320, flood.cut_at()), &mut floods),
        alert,
        "the minute before was below the cut level"
    );
    assert_eq!(
        judge(&me, &flood_minute(NOW + 380, flood.cut_at()), &mut floods),
        cut
    );
    let mut floods = FloodMinutes::default();
    assert_eq!(
        judge(&me, &flood_minute(NOW, flood.alert_at() - 1), &mut floods),
        Verdict::default()
    );
    assert_eq!(
        judge(&me, &flood_minute(NOW + 60, flood.alert_at()), &mut floods),
        alert
    );
    assert_eq!(
        judge(
            &me,
            &flood_minute(NOW + 120, flood.cut_at() - 1),
            &mut floods
        ),
        alert
    );
}

/// The memory of flood minutes forgets users no longer served and minutes
/// too old to be followed.
#[test]
fn flood_minutes_forget_unserved_users_and_old_minutes() {
    let flood = AbuseFinding::DatagramFlood;
    let me = user("u01");
    let mut floods = FloodMinutes::default();
    judge(&me, &flood_minute(NOW, flood.cut_at()), &mut floods);
    let none: BTreeMap<OpaqueUserId, UserReading> = BTreeMap::new();
    floods.retain(&none, UnixTime::from_secs(NOW + 60));
    assert_eq!(floods, FloodMinutes::default());
    judge(&me, &flood_minute(NOW, flood.cut_at()), &mut floods);
    let served = BTreeMap::from([(me.clone(), flood_minute(NOW, 0))]);
    floods.retain(&served, UnixTime::from_secs(NOW + 60));
    assert_ne!(
        floods,
        FloodMinutes::default(),
        "kept while it can be followed"
    );
    floods.retain(&served, UnixTime::from_secs(NOW + 191));
    assert_eq!(floods, FloodMinutes::default());
}
