// SPDX-License-Identifier: GPL-3.0-or-later

//! The record of the SIM's network (design §10.2, §15.3): the first poll
//! that finds the M7 attached gives the baseline; a later poll that
//! reports another name or another network is held with the time the M7
//! first reported one, and goes when it reports the baseline's again; a
//! carrier check or a cycle rule other than the record's begins it again;
//! a poll that found no network changes nothing; no time is left after
//! the poll; and the record's document round-trips and refuses anything
//! else, a baseline that is its own other network included.

use mooring_model::collections::NonEmpty;
use mooring_model::exit::EgressCheck;
use mooring_model::{BillDay, CycleRule, Pairing, PeriodDays, UnixTime};
use proptest::prelude::*;

use super::router;
use super::support::{date, deployment, edited};
use crate::router::{CarrierName, Mcc, Mnc, Plmn, RadioState, RouterStatus};
use crate::sim_network::{
    BaselineOrigin, MAX_SIM_NETWORK_BYTES, NetworkBaseline, OtherNetwork, OtherNetworkIsBaseline,
    RecordedUnder, SimNetwork, SimNetworkCorrupt, SimNetworkRecord, SimNetworkStatus,
};

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(1_791_919_200 + secs)
}

/// What the M7 reports of a SIM named `spn`, or of one without a name, on
/// the network `mcc` `mnc`.
fn network(spn: Option<&str>, mcc: &str, mnc: &str) -> SimNetwork {
    SimNetwork {
        spn: spn.map(|name| CarrierName::parse(name).unwrap()),
        plmn: Plmn {
            mcc: Mcc::parse(mcc).unwrap(),
            mnc: Mnc::parse(mnc).unwrap(),
        },
    }
}

/// The SIM without a name on 234 20, as the M7 reported the first line's.
fn unnamed() -> SimNetwork {
    network(None, "234", "20")
}

/// The SIM named `1p` on 234 30, as the M7 reported the second line's.
fn one_p() -> SimNetwork {
    network(Some("1p"), "234", "30")
}

/// The fixture's carrier check and cycle rule.
fn under() -> RecordedUnder {
    RecordedUnder::of(deployment().exit())
}

/// A record begun under the fixture's records for `origin`, after `polls`.
fn after(origin: BaselineOrigin, polls: &[(SimNetwork, u64)]) -> SimNetworkRecord {
    polls.iter().fold(
        SimNetworkRecord::new(under(), origin),
        |record, (network, secs)| record.observed(&under(), Some((network, at(*secs)))),
    )
}

fn baseline(record: &SimNetworkRecord) -> &NetworkBaseline {
    record.status().baseline.as_ref().unwrap()
}

/// The other network and the seconds since `at(0)` it has been reported.
fn other(record: &SimNetworkRecord) -> Option<(SimNetwork, u64)> {
    baseline(record).other().map(|other| {
        (
            other.network.clone(),
            other.since.as_secs() - at(0).as_secs(),
        )
    })
}

fn status_with(change: impl FnOnce(&mut crate::router::RouterStatusParts)) -> RouterStatus {
    let mut parts = router::status().into_parts();
    change(&mut parts);
    RouterStatus::new(parts).unwrap()
}

/// The SIM's name and the network's codes are read from a status with a
/// data session, a SIM without a name as one without; a status without a
/// session names no network, whatever name the SIM has.
#[test]
fn the_network_is_read_from_an_attached_status_only() {
    assert_eq!(
        SimNetwork::of(&router::status()),
        Some(network(Some("CMLink"), "234", "30"))
    );
    let nameless = status_with(|parts| parts.sim_spn = None);
    assert_eq!(SimNetwork::of(&nameless), Some(network(None, "234", "30")));
    let elsewhere = status_with(|parts| {
        parts.sim_spn = Some(CarrierName::parse("1p").unwrap());
        let RadioState::Attached(radio) = &mut parts.radio else {
            panic!("the fixture is attached");
        };
        radio.plmn = Plmn {
            mcc: Mcc::parse("235").unwrap(),
            mnc: Mnc::parse("094").unwrap(),
        };
    });
    assert_eq!(
        SimNetwork::of(&elsewhere),
        Some(network(Some("1p"), "235", "094"))
    );
    let no_service = status_with(|parts| parts.radio = RadioState::NoService);
    assert!(no_service.parts().sim_spn.is_some());
    assert_eq!(SimNetwork::of(&no_service), None);
}

/// What a baseline is taken under is the exit's carrier check, none before
/// one is recorded, and its cycle rule.
#[test]
fn the_records_are_the_exits_carrier_check_and_cycle_rule() {
    let exit = deployment().exit().clone();
    let read = under();
    assert_eq!(read.check, exit.egress_check);
    assert!(read.check.is_some());
    assert_eq!(read.cycle, exit.sim.cycle());
    let unrecorded = edited(|parts| parts.exit.egress_check = None);
    assert_eq!(
        RecordedUnder::of(unrecorded.exit()),
        RecordedUnder {
            check: None,
            cycle: exit.sim.cycle(),
        }
    );
    let moved = super::support::deployment_billed_on(17);
    assert_eq!(
        RecordedUnder::of(moved.exit()),
        RecordedUnder {
            check: exit.egress_check,
            cycle: CycleRule::Monthly {
                bill_day: BillDay::new(17).unwrap(),
            },
        }
    );
}

/// A record has no baseline until a poll finds the M7 attached: that
/// poll's network and time are the baseline, and the origin stays what
/// the record was begun for.
#[test]
fn the_first_attached_poll_gives_the_baseline() {
    for origin in [
        BaselineOrigin::NoRecord,
        BaselineOrigin::Recorded,
        BaselineOrigin::RecordUnreadable,
    ] {
        let begun = SimNetworkRecord::new(under(), origin);
        assert_eq!(
            begun.status(),
            &SimNetworkStatus {
                origin,
                baseline: None,
            }
        );
        assert_eq!(begun.under(), &under());
        // No poll, or one that found no network: still no baseline.
        assert_eq!(begun.observed(&under(), None), begun);
        let taken = begun.observed(&under(), Some((&one_p(), at(70))));
        assert_eq!(taken.status().origin, origin);
        assert_eq!(taken.under(), &under());
        assert_eq!(baseline(&taken).network(), &one_p());
        assert_eq!(baseline(&taken).first_seen(), at(70));
        assert_eq!(baseline(&taken).other(), None);
    }
}

/// A poll that reports the baseline's network changes nothing, however
/// much later it is.
#[test]
fn the_baselines_network_again_changes_nothing() {
    let taken = after(BaselineOrigin::Recorded, &[(one_p(), 70)]);
    let later = taken.observed(&under(), Some((&one_p(), at(86_400))));
    assert_eq!(later, taken);
    assert_eq!(baseline(&later).first_seen(), at(70));
}

/// Another network is held from the poll that first reported one: a later
/// poll of the same network keeps that time, and one of a third network
/// is the other network now, since that same time. The baseline stays.
#[test]
fn another_network_is_held_since_the_m7_first_reported_one() {
    let taken = after(BaselineOrigin::Recorded, &[(unnamed(), 10)]);
    let swapped = taken.observed(&under(), Some((&one_p(), at(500))));
    assert_eq!(other(&swapped), Some((one_p(), 500)));
    assert_eq!(baseline(&swapped).network(), &unnamed());
    assert_eq!(baseline(&swapped).first_seen(), at(10));
    assert_eq!(swapped.status().origin, BaselineOrigin::Recorded);
    let still = swapped.observed(&under(), Some((&one_p(), at(560))));
    assert_eq!(still, swapped);
    let third = network(Some("CMLink"), "234", "30");
    let again = still.observed(&under(), Some((&third, at(900))));
    assert_eq!(other(&again), Some((third, 500)));
    assert_eq!(baseline(&again).network(), &unnamed());
    assert_eq!(baseline(&again).first_seen(), at(10));
}

/// The other network goes when the M7 reports the baseline's again, and
/// one reported after that is dated anew.
#[test]
fn the_baselines_network_again_ends_the_other() {
    let swapped = after(BaselineOrigin::Recorded, &[(unnamed(), 10), (one_p(), 500)]);
    let back = swapped.observed(&under(), Some((&unnamed(), at(700))));
    assert_eq!(back, after(BaselineOrigin::Recorded, &[(unnamed(), 10)]));
    let once_more = back.observed(&under(), Some((&one_p(), at(900))));
    assert_eq!(other(&once_more), Some((one_p(), 900)));
}

/// Another name on the same network is another network, and so is the
/// same name, or none, on other codes: either tells SIMs apart.
#[test]
fn another_name_or_other_codes_alone_is_another_network() {
    let first = network(Some("1p"), "234", "30");
    for differs in [
        network(Some("CMLink"), "234", "30"),
        network(None, "234", "30"),
        network(Some("1p"), "234", "33"),
        network(Some("1p"), "235", "30"),
        network(Some("1p"), "234", "030"),
    ] {
        let record = after(BaselineOrigin::Recorded, &[(first.clone(), 10)])
            .observed(&under(), Some((&differs, at(40))));
        assert_eq!(other(&record), Some((differs, 40)), "{record:?}");
    }
    let nameless = after(BaselineOrigin::Recorded, &[(unnamed(), 10)])
        .observed(&under(), Some((&network(None, "234", "15"), at(40))));
    assert_eq!(other(&nameless), Some((network(None, "234", "15"), 40)));
}

/// A poll that found no network, or no poll, changes nothing: neither the
/// baseline nor the other network nor since when.
#[test]
fn without_a_network_nothing_changes() {
    for record in [
        after(BaselineOrigin::NoRecord, &[]),
        after(BaselineOrigin::NoRecord, &[(unnamed(), 10)]),
        after(BaselineOrigin::NoRecord, &[(unnamed(), 10), (one_p(), 500)]),
    ] {
        assert_eq!(record.observed(&under(), None), record);
    }
}

/// The records the fixture's are changed to: another pairing, no check,
/// another bill day, and fixed cycles.
fn other_records() -> Vec<RecordedUnder> {
    let fixture = under();
    let check = fixture.check.clone().unwrap();
    vec![
        RecordedUnder {
            check: Some(EgressCheck {
                carrier_prefixes: check.carrier_prefixes.clone(),
                pairing: Pairing::Unpaired,
            }),
            cycle: fixture.cycle,
        },
        RecordedUnder {
            check: None,
            cycle: fixture.cycle,
        },
        RecordedUnder {
            check: Some(check.clone()),
            cycle: CycleRule::Monthly {
                bill_day: BillDay::new(2).unwrap(),
            },
        },
        RecordedUnder {
            check: Some(check),
            cycle: CycleRule::FixedDays {
                days: PeriodDays::new(30).unwrap(),
                anchor: date("2026-10-23"),
            },
        },
    ]
}

/// A carrier check or a cycle rule other than the record's begins the
/// record again under the new ones, as recorded: without a baseline when
/// no poll came with it, whatever the record held, and with that poll's
/// network as the baseline when one did, even the network that was the
/// other one.
#[test]
fn a_record_of_the_check_or_the_cycle_begins_the_record_again() {
    let swapped = after(BaselineOrigin::NoRecord, &[(unnamed(), 10), (one_p(), 500)]);
    for recorded in other_records() {
        assert_ne!(recorded, under());
        let begun = swapped.observed(&recorded, None);
        assert_eq!(
            begun,
            SimNetworkRecord::new(recorded.clone(), BaselineOrigin::Recorded)
        );
        let taken = swapped.observed(&recorded, Some((&one_p(), at(800))));
        assert_eq!(taken.under(), &recorded);
        assert_eq!(taken.status().origin, BaselineOrigin::Recorded);
        assert_eq!(baseline(&taken).network(), &one_p());
        assert_eq!(baseline(&taken).first_seen(), at(800));
        assert_eq!(baseline(&taken).other(), None);
        // Under the new records it goes on as any record does.
        assert_eq!(taken.observed(&recorded, None), taken);
        // And the old records again begin it once more.
        assert_eq!(
            taken.observed(&under(), None),
            SimNetworkRecord::new(under(), BaselineOrigin::Recorded)
        );
    }
    // A record without a baseline is begun again too, and one whose
    // records are unchanged keeps its origin.
    let waiting = SimNetworkRecord::new(under(), BaselineOrigin::RecordUnreadable);
    assert_eq!(
        waiting.observed(&other_records()[0], None).status().origin,
        BaselineOrigin::Recorded
    );
    assert_eq!(
        waiting.observed(&under(), None).status().origin,
        BaselineOrigin::RecordUnreadable
    );
}

/// The prefixes of the carrier check count, each of them and their order:
/// a check with one more prefix is another check.
#[test]
fn another_prefix_is_another_carrier_check() {
    let fixture = under();
    let check = fixture.check.clone().unwrap();
    let mut prefixes = check.carrier_prefixes.clone().into_vec();
    prefixes.push("31.94.0.0/16".parse().unwrap());
    let wider = RecordedUnder {
        check: Some(EgressCheck {
            carrier_prefixes: NonEmpty::try_from(prefixes).unwrap(),
            pairing: check.pairing,
        }),
        cycle: fixture.cycle,
    };
    let taken = after(BaselineOrigin::NoRecord, &[(unnamed(), 10)]);
    assert_eq!(
        taken.observed(&wider, None),
        SimNetworkRecord::new(wider, BaselineOrigin::Recorded)
    );
}

/// No time is left after a poll's: a baseline or another network dated
/// after it, by a clock that has stepped back since, is brought back to
/// it, whichever network the poll reports.
#[test]
fn no_time_is_left_after_the_poll() {
    let swapped = after(
        BaselineOrigin::Recorded,
        &[(unnamed(), 400), (one_p(), 500)],
    );
    let same = swapped.observed(&under(), Some((&one_p(), at(450))));
    assert_eq!(baseline(&same).first_seen(), at(400));
    assert_eq!(other(&same), Some((one_p(), 450)));
    let earlier = swapped.observed(&under(), Some((&one_p(), at(90))));
    assert_eq!(baseline(&earlier).first_seen(), at(90));
    assert_eq!(other(&earlier), Some((one_p(), 90)));
    let third = network(None, "234", "15");
    let another = swapped.observed(&under(), Some((&third, at(90))));
    assert_eq!(baseline(&another).first_seen(), at(90));
    assert_eq!(other(&another), Some((third, 90)));
    let back = swapped.observed(&under(), Some((&unnamed(), at(90))));
    assert_eq!(baseline(&back).first_seen(), at(90));
    assert_eq!(baseline(&back).other(), None);
}

/// A baseline is never its own other network: the constructor refuses
/// one, and so does a document that holds one, in the record and in the
/// status alike.
#[test]
fn a_baseline_is_never_its_own_other_network() {
    let own = OtherNetwork {
        network: one_p(),
        since: at(50),
    };
    assert_eq!(
        NetworkBaseline::new(one_p(), at(10), Some(own)),
        Err(OtherNetworkIsBaseline)
    );
    assert_eq!(
        OtherNetworkIsBaseline.to_string(),
        "the other network is the baseline's own"
    );
    let another = OtherNetwork {
        network: unnamed(),
        since: at(50),
    };
    let built = NetworkBaseline::new(one_p(), at(10), Some(another.clone())).unwrap();
    assert_eq!(built.network(), &one_p());
    assert_eq!(built.first_seen(), at(10));
    assert_eq!(built.other(), Some(&another));
    assert_eq!(
        NetworkBaseline::new(one_p(), at(10), None).unwrap().other(),
        None
    );
    let status = SimNetworkStatus {
        origin: BaselineOrigin::Recorded,
        baseline: Some(built),
    };
    let mut document = serde_json::to_value(&status).unwrap();
    assert_eq!(
        serde_json::from_value::<SimNetworkStatus>(document.clone()).unwrap(),
        status
    );
    document["baseline"]["other"]["network"] = document["baseline"]["network"].clone();
    let error = serde_json::from_value::<SimNetworkStatus>(document).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("the other network is the baseline's own"),
        "{error}"
    );
}

/// The document of the record after the first line's SIM was changed for
/// the second's.
fn swapped_document() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "under": {
            "check": {
                "carrier_prefixes": ["31.120.0.0/14"],
                "pairing": "paired",
            },
            "cycle": {"monthly": {"bill_day": 1}},
        },
        "network": {
            "origin": "no_record",
            "baseline": {
                "network": {"spn": null, "plmn": {"mcc": "234", "mnc": "20"}},
                "first_seen": at(10).as_secs(),
                "other": {
                    "network": {"spn": "1p", "plmn": {"mcc": "234", "mnc": "30"}},
                    "since": at(500).as_secs(),
                },
            },
        },
    })
}

/// The record round-trips through its document, with or without a
/// baseline, an other network and a carrier check.
#[test]
fn the_record_round_trips_through_its_document() {
    let swapped = after(BaselineOrigin::NoRecord, &[(unnamed(), 10), (one_p(), 500)]);
    let bytes = swapped.encode().unwrap();
    assert_eq!(SimNetworkRecord::decode(&bytes).unwrap(), swapped);
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.starts_with("{\n  \"version\": 1,\n  \"under\": {"),
        "{text}"
    );
    assert!(text.ends_with("}\n"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        swapped_document()
    );
    let unrecorded = RecordedUnder {
        check: None,
        cycle: CycleRule::FixedDays {
            days: PeriodDays::new(30).unwrap(),
            anchor: date("2026-10-23"),
        },
    };
    let begun = SimNetworkRecord::new(unrecorded.clone(), BaselineOrigin::RecordUnreadable);
    let text = String::from_utf8(begun.encode().unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        serde_json::json!({
            "version": 1,
            "under": {
                "check": null,
                "cycle": {"fixed_days": {"days": 30, "anchor": "2026-10-23"}},
            },
            "network": {"origin": "record_unreadable", "baseline": null},
        })
    );
    assert_eq!(SimNetworkRecord::decode(text.as_bytes()).unwrap(), begun);
    let taken = begun.observed(&unrecorded, Some((&one_p(), at(30))));
    assert_eq!(
        SimNetworkRecord::decode(&taken.encode().unwrap()).unwrap(),
        taken
    );
    assert_eq!(
        serde_json::to_value(taken.status()).unwrap()["baseline"]["other"],
        serde_json::Value::Null
    );
}

/// A document of another version, with a key it does not know or without
/// one it needs, with a value outside its type's rule, whose other
/// network is the baseline's own, too long or not JSON is refused.
#[test]
fn anything_but_a_version_one_record_is_refused() {
    let good = swapped_document();
    assert!(SimNetworkRecord::decode(&serde_json::to_vec(&good).unwrap()).is_ok());
    let edits: [fn(&mut serde_json::Value); 21] = [
        |document| document["version"] = 2.into(),
        |document| document["version"] = 0.into(),
        |document| document["extra"] = 0.into(),
        |document| document["under"]["extra"] = 0.into(),
        |document| document["network"]["extra"] = 0.into(),
        |document| document["network"]["baseline"]["extra"] = 0.into(),
        |document| document["network"]["baseline"]["network"]["extra"] = 0.into(),
        |document| document["network"]["baseline"]["other"]["extra"] = 0.into(),
        |document| drop(document.as_object_mut().unwrap().remove("version")),
        |document| drop(document.as_object_mut().unwrap().remove("under")),
        |document| drop(document["under"].as_object_mut().unwrap().remove("check")),
        |document| drop(document["under"].as_object_mut().unwrap().remove("cycle")),
        |document| {
            drop(
                document["network"]
                    .as_object_mut()
                    .unwrap()
                    .remove("origin"),
            )
        },
        |document| {
            drop(
                document["network"]
                    .as_object_mut()
                    .unwrap()
                    .remove("baseline"),
            )
        },
        |document| {
            let baseline = document["network"]["baseline"].as_object_mut().unwrap();
            drop(baseline.remove("other"));
        },
        |document| {
            let network = document["network"]["baseline"]["network"]
                .as_object_mut()
                .unwrap();
            drop(network.remove("spn"));
        },
        |document| document["network"]["origin"] = "unknown".into(),
        |document| document["network"]["baseline"]["network"]["plmn"]["mcc"] = "23".into(),
        |document| {
            document["network"]["baseline"]["network"]["spn"] = "447700900123".into();
        },
        |document| document["under"]["check"]["carrier_prefixes"] = serde_json::json!([]),
        |document| {
            document["network"]["baseline"]["other"]["network"] =
                document["network"]["baseline"]["network"].clone();
        },
    ];
    for (index, edit) in edits.iter().enumerate() {
        let mut document = good.clone();
        edit(&mut document);
        assert_ne!(document, good, "edit {index} changes nothing");
        assert_eq!(
            SimNetworkRecord::decode(&serde_json::to_vec(&document).unwrap()),
            Err(SimNetworkCorrupt),
            "edit {index}: {document}"
        );
    }
    for refused in [&b"not json"[..], b"", b"[]", b"{\"version\": 1}"] {
        assert_eq!(
            SimNetworkRecord::decode(refused),
            Err(SimNetworkCorrupt),
            "{}",
            String::from_utf8_lossy(refused)
        );
    }
    // The bound is the record's own, 64 KiB: a document a byte longer is
    // refused, and one at the bound is read.
    assert_eq!(MAX_SIM_NETWORK_BYTES, 65_536);
    let mut long = serde_json::to_vec(&good).unwrap();
    long.resize(MAX_SIM_NETWORK_BYTES, b' ');
    assert!(SimNetworkRecord::decode(&long).is_ok());
    long.push(b' ');
    assert_eq!(SimNetworkRecord::decode(&long), Err(SimNetworkCorrupt));
    assert_eq!(
        SimNetworkCorrupt.to_string(),
        "the record of the SIM's network is corrupt"
    );
}

/// One step of a daemon's life: the records it reads, and the network a
/// poll reports, if one does, a number of seconds after the step before.
#[derive(Debug, Clone)]
struct Step {
    /// Which records: the fixture's, or one of [`other_records`].
    records: usize,
    /// Which network, if the poll found one.
    network: Option<usize>,
    /// Seconds since the step before.
    after: u64,
}

fn step() -> impl Strategy<Value = Step> {
    (
        prop_oneof![9 => Just(0_usize), 1 => 1_usize..3],
        proptest::option::weighted(0.7, 0_usize..3),
        1_u64..5_000,
    )
        .prop_map(|(records, network, after)| Step {
            records,
            network,
            after,
        })
}

proptest! {
    /// Over any run of ticks and polls, with the clock going forward:
    /// the baseline is the first network reported under the records now
    /// read, with that poll's time; the other network is the latest
    /// reported under them when that is not the baseline's, since the
    /// first poll after the last that reported the baseline's; a record
    /// begun again is `Recorded`, and one never begun again keeps its
    /// origin; and every record along the way round-trips.
    #[test]
    fn the_record_follows_what_was_reported_under_the_records_now_read(
        steps in proptest::collection::vec(step(), 0..40),
    ) {
        let networks = [unnamed(), one_p(), network(Some("1p"), "234", "33")];
        let mut records = vec![under()];
        records.extend(other_records());
        let mut record = SimNetworkRecord::new(under(), BaselineOrigin::NoRecord);
        // The model: the records read last, whether they ever changed,
        // and every network reported under them with its time.
        let mut read = 0_usize;
        let mut begun_again = false;
        let mut reported: Vec<(usize, u64)> = Vec::new();
        let mut now = 0_u64;
        for step in steps {
            now += step.after;
            if step.records != read {
                read = step.records;
                begun_again = true;
                reported.clear();
            }
            if let Some(index) = step.network {
                reported.push((index, now));
            }
            record = record.observed(
                &records[read],
                step.network.map(|index| (&networks[index], at(now))),
            );
            prop_assert_eq!(record.under(), &records[read]);
            let origin = if begun_again {
                BaselineOrigin::Recorded
            } else {
                BaselineOrigin::NoRecord
            };
            prop_assert_eq!(record.status().origin, origin);
            match reported.first() {
                None => prop_assert_eq!(&record.status().baseline, &None),
                Some((first, seen)) => {
                    let held = baseline(&record);
                    prop_assert_eq!(held.network(), &networks[*first]);
                    prop_assert_eq!(held.first_seen(), at(*seen));
                    let (latest, _) = reported[reported.len() - 1];
                    let since = reported
                        .iter()
                        .rev()
                        .take_while(|(index, _)| index != first)
                        .last()
                        .map(|(_, seen)| *seen);
                    match since {
                        None => prop_assert_eq!(held.other(), None),
                        Some(since) => prop_assert_eq!(
                            held.other(),
                            Some(&OtherNetwork {
                                network: networks[latest].clone(),
                                since: at(since),
                            })
                        ),
                    }
                }
            }
            let bytes = record.encode().unwrap();
            prop_assert_eq!(SimNetworkRecord::decode(&bytes).unwrap(), record.clone());
        }
    }
}
