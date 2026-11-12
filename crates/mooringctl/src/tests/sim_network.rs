// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of the SIM's network (design §10.2, §15.3): the
//! first poll that finds the M7 attached is the baseline, another network
//! is said once and carried by the status with the time it was first
//! reported, a restart keeps both, a carrier check or a cycle recorded
//! again begins the record again, a record that cannot be read is said
//! and begun again with the status saying so, a write that fails is said
//! and tried again when it is due or the record changes, nothing is
//! written while the file holds the record, and a poll is set against the
//! record once. The M7 is the loopback stub.

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{Duration, Instant};

use mooring_daemon_core::router::netgear::parse_netgear_model_json;
use mooring_daemon_core::router::{
    CarrierName, Mcc, Mnc, Plmn, RadioState, RouterReading, RouterStatus, RouterStatusParts,
    RouterUnavailableReason,
};
use mooring_daemon_core::sim_network::{
    BaselineOrigin, MAX_SIM_NETWORK_BYTES, NetworkBaseline, OtherNetwork, RecordedUnder,
    SimNetwork, SimNetworkRecord, SimNetworkStatus,
};
use mooring_model::exit::EgressCheck;
use mooring_model::secret::{RouterAdminPassword, SecretEntry};
use mooring_model::{BillDay, CycleRule, Deployment, ExitSite, Pairing, SimPolicy, UnixTime};
use mooring_store::{SIM_NETWORK_FILE, SecretStore, Store, read_sim_network};

use super::deployed::{CARRIER, deployed, published, shared, statuses, with_exit_on};
use super::flow::anonymous_answer;
use super::stub::{Reply, Stub, json};
use super::support::{FIXTURE, Harness, NOW, PASSWORD, observed_login_acceptance};
use super::user::fixture;
use crate::daemon::deployed::Deployed;
use crate::daemon::sim_network::{NetworkWatch, WRITE_RETRY, said, shown};
use crate::daemon::{Control, Intervals, RunPaths};

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(NOW + secs)
}

fn network(spn: Option<&str>, mcc: &str, mnc: &str) -> SimNetwork {
    SimNetwork {
        spn: spn.map(|name| CarrierName::parse(name).unwrap()),
        plmn: Plmn {
            mcc: Mcc::parse(mcc).unwrap(),
            mnc: Mnc::parse(mnc).unwrap(),
        },
    }
}

/// The fixture's SIM: `CMLink` on 234 30.
fn cmlink() -> SimNetwork {
    network(Some("CMLink"), "234", "30")
}

/// A SIM without a name on 234 20.
fn unnamed() -> SimNetwork {
    network(None, "234", "20")
}

/// The fixture's status with `edit` applied, as a poll `secs` after
/// [`NOW`] read it.
fn reading(secs: u64, edit: impl FnOnce(&mut RouterStatusParts)) -> RouterReading {
    let mut parts = parse_netgear_model_json(FIXTURE).unwrap().into_parts();
    edit(&mut parts);
    RouterReading::Available {
        polled_at: at(secs),
        status: Box::new(RouterStatus::new(parts).unwrap()),
    }
}

/// A poll that found the M7 attached and reporting `network`.
fn reported(network: &SimNetwork, secs: u64) -> RouterReading {
    reading(secs, |parts| {
        parts.sim_spn.clone_from(&network.spn);
        let RadioState::Attached(radio) = &mut parts.radio else {
            panic!("the fixture is attached");
        };
        radio.plmn = network.plmn;
    })
}

/// The fixture's exit with another pairing in its carrier check: the same
/// prefixes recorded again count as another check.
fn checked_again() -> Deployment {
    fixture(|parts| {
        let check = parts.exit.egress_check.as_mut().unwrap();
        check.pairing = other_pairing(check.pairing);
    })
}

fn other_pairing(pairing: Pairing) -> Pairing {
    match pairing {
        Pairing::Paired => Pairing::Unpaired,
        Pairing::Unpaired => Pairing::Paired,
    }
}

/// The fixture's exit with its cycles anchored on another day.
fn anchored_again() -> Deployment {
    fixture(|parts| {
        let sim = &parts.exit.sim;
        let CycleRule::Monthly { bill_day } = sim.cycle() else {
            panic!("the fixture's cycles are monthly");
        };
        let day = if bill_day.get() == 17 { 18 } else { 17 };
        parts.exit.sim = SimPolicy::new(
            CycleRule::Monthly {
                bill_day: BillDay::new(day).unwrap(),
            },
            sim.plan().unwrap().clone(),
            sim.warn_bytes(),
            sim.stop(),
        )
        .unwrap();
    })
}

/// One tick of `watch` at the present time.
fn track(watch: &mut NetworkWatch, exit: &ExitSite, polled: Option<&RouterReading>) -> Vec<String> {
    watch.track(exit, polled, Instant::now())
}

/// The record on disk in `run_dir`.
fn on_disk(run_dir: &Path) -> SimNetworkRecord {
    let bytes = read_sim_network(run_dir, MAX_SIM_NETWORK_BYTES + 1)
        .unwrap()
        .unwrap();
    SimNetworkRecord::decode(&bytes).unwrap()
}

/// A status without a baseline.
fn no_baseline(origin: BaselineOrigin) -> SimNetworkStatus {
    SimNetworkStatus {
        origin,
        baseline: None,
    }
}

/// A status whose baseline is `network`, first seen `first_seen` seconds
/// after [`NOW`], with no other network.
fn baseline_of(origin: BaselineOrigin, network: SimNetwork, first_seen: u64) -> SimNetworkStatus {
    SimNetworkStatus {
        origin,
        baseline: Some(NetworkBaseline::new(network, at(first_seen), None).unwrap()),
    }
}

/// The fixture's SIM as the baseline of a record begun without one, seen
/// at [`NOW`], with the SIM without a name reported since `since` seconds
/// after it.
fn swapped_since(since: u64) -> SimNetworkStatus {
    SimNetworkStatus {
        origin: BaselineOrigin::NoRecord,
        baseline: Some(
            NetworkBaseline::new(
                cmlink(),
                at(0),
                Some(OtherNetwork {
                    network: unnamed(),
                    since: at(since),
                }),
            )
            .unwrap(),
        ),
    }
}

const NO_RECORD: &str = "sim network: no record yet; the next poll that finds the M7 attached gives the network the carrier check and the billing cycle are taken to go with, so a SIM changed before then is not noticed";
const TAKEN: &str = "sim network: the M7 reports CMLink (234-30); the carrier check and the billing cycle are taken to go with it";
const SWAPPED: &str = "sim network: the M7 reports a SIM without a name (234-20), where it reported CMLink (234-30) under the recorded carrier check and billing cycle; if the SIM was changed, record both again (swap-day.md, section 2, steps 3 to 6)";
const BACK: &str = "sim network: the M7 reports CMLink (234-30) again";
const RECORDED: &str = "sim network: the carrier check or the billing cycle changed; the next poll that finds the M7 attached gives the network they go with";
const RECORDED_AND_TAKEN: &str = "sim network: the carrier check or the billing cycle changed; they are taken to go with a SIM without a name (234-20), which the M7 reports";

/// The log names a network by the SIM's name, or says it has none, and by
/// the network's codes as the M7 gives them.
#[test]
fn a_network_is_named_by_the_sims_name_and_the_networks_codes() {
    assert_eq!(shown(&network(Some("1p"), "234", "30")), "1p (234-30)");
    assert_eq!(shown(&unnamed()), "a SIM without a name (234-20)");
    assert_eq!(
        shown(&network(Some("CMLink"), "235", "094")),
        "CMLink (235-094)"
    );
}

/// Each change of the record has its line, and a record of which only a
/// time moved has none.
#[test]
fn the_log_has_a_line_for_each_change_of_the_record() {
    let exit = fixture(|_| {});
    let under = RecordedUnder::of(exit.exit());
    let begun = SimNetworkRecord::new(under.clone(), BaselineOrigin::NoRecord);
    let taken = begun.observed(&under, Some((&cmlink(), at(10))));
    let swapped = taken.observed(&under, Some((&unnamed(), at(600))));
    let third = swapped.observed(&under, Some((&network(Some("1p"), "234", "30"), at(660))));
    let back = swapped.observed(&under, Some((&cmlink(), at(900))));
    assert_eq!(said(&begun, &begun), None);
    assert_eq!(said(&begun, &taken).as_deref(), Some(TAKEN));
    assert_eq!(said(&taken, &taken), None);
    assert_eq!(said(&taken, &swapped).as_deref(), Some(SWAPPED));
    assert_eq!(said(&swapped, &swapped), None);
    assert_eq!(
        said(&swapped, &third).as_deref(),
        Some("sim network: the M7 now reports 1p (234-30), and still not CMLink (234-30)")
    );
    assert_eq!(said(&swapped, &back).as_deref(), Some(BACK));
    assert_eq!(said(&third, &back).as_deref(), Some(BACK));
    // A clock that stepped back moves the times and nothing else.
    let earlier = swapped.observed(&under, Some((&unnamed(), at(5))));
    assert_ne!(earlier, swapped);
    assert_eq!(said(&swapped, &earlier), None);
    let earlier = taken.observed(&under, Some((&cmlink(), at(5))));
    assert_ne!(earlier, taken);
    assert_eq!(said(&taken, &earlier), None);
    // The check or the cycle recorded again, without a poll and with one.
    for recorded in [checked_again(), anchored_again()] {
        let other = RecordedUnder::of(recorded.exit());
        assert_ne!(other, under);
        for before in [&begun, &taken, &swapped] {
            assert_eq!(
                said(before, &before.observed(&other, None)).as_deref(),
                Some(RECORDED)
            );
            assert_eq!(
                said(
                    before,
                    &before.observed(&other, Some((&unnamed(), at(700))))
                )
                .as_deref(),
                Some(RECORDED_AND_TAKEN)
            );
        }
    }
}

/// Without a record the daemon says so and begins one for `NoRecord`; the
/// first tick writes it, and the first poll that finds the M7 attached is
/// its baseline, said once and written.
#[test]
fn without_a_record_one_is_begun_and_the_first_attached_poll_is_its_baseline() {
    let run = tempfile::tempdir().unwrap();
    let exit = fixture(|_| {});
    let (mut watch, note) = NetworkWatch::open(run.path(), exit.exit());
    assert_eq!(note.as_deref(), Some(NO_RECORD));
    assert_eq!(watch.status(), no_baseline(BaselineOrigin::NoRecord));
    assert_eq!(read_sim_network(run.path(), 64).unwrap(), None);
    assert_eq!(track(&mut watch, exit.exit(), None), Vec::<String>::new());
    assert_eq!(
        on_disk(run.path()),
        SimNetworkRecord::new(RecordedUnder::of(exit.exit()), BaselineOrigin::NoRecord)
    );
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 70))),
        [TAKEN]
    );
    let taken = baseline_of(BaselineOrigin::NoRecord, cmlink(), 70);
    assert_eq!(watch.status(), taken);
    assert_eq!(on_disk(run.path()).status(), &taken);
    assert_eq!(on_disk(run.path()).under(), &RecordedUnder::of(exit.exit()));
    // The same network again, a day later: nothing to say or to write,
    // not even where the file has gone since.
    fs::remove_file(run.path().join(SIM_NETWORK_FILE)).unwrap();
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 86_400))),
        Vec::<String>::new()
    );
    assert_eq!(track(&mut watch, exit.exit(), None), Vec::<String>::new());
    assert_eq!(watch.status(), taken);
    assert_eq!(read_sim_network(run.path(), 64).unwrap(), None);
}

/// A poll that failed, and one that found the M7 without a data session,
/// say nothing of the SIM: the record stays, before a baseline and after
/// one, whatever name the SIM then has.
#[test]
fn a_poll_without_a_network_changes_nothing() {
    let run = tempfile::tempdir().unwrap();
    let exit = fixture(|_| {});
    let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
    let failed = RouterReading::Unavailable {
        reason: RouterUnavailableReason::Unreachable,
        last_polled_at: Some(at(0)),
    };
    let no_service = reading(60, |parts| {
        parts.sim_spn = None;
        parts.radio = RadioState::NoService;
    });
    for held in [
        no_baseline(BaselineOrigin::NoRecord),
        baseline_of(BaselineOrigin::NoRecord, cmlink(), 100),
    ] {
        for polled in [&failed, &no_service] {
            assert_eq!(
                track(&mut watch, exit.exit(), Some(polled)),
                Vec::<String>::new()
            );
            assert_eq!(watch.status(), held);
            assert_eq!(on_disk(run.path()).status(), &held);
        }
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 100)));
    }
}

/// Another network is said once and held since the poll that first
/// reported one; the daemon started again reads the baseline and that
/// time from the record and says nothing; the baseline's network again
/// ends it.
#[test]
fn another_network_is_said_once_and_a_restart_keeps_it() {
    let run = tempfile::tempdir().unwrap();
    let exit = fixture(|_| {});
    let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
    track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 0)));
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 600))),
        [SWAPPED]
    );
    let swapped = swapped_since(600);
    assert_eq!(watch.status(), swapped);
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 660))),
        Vec::<String>::new()
    );
    assert_eq!(watch.status(), swapped);
    assert_eq!(on_disk(run.path()).status(), &swapped);
    drop(watch);

    let (mut watch, note) = NetworkWatch::open(run.path(), exit.exit());
    assert_eq!(note, None);
    assert_eq!(watch.status(), swapped);
    // The record was read from the file: it is not written again while
    // nothing changes, not even where the file has gone since.
    fs::remove_file(run.path().join(SIM_NETWORK_FILE)).unwrap();
    assert_eq!(track(&mut watch, exit.exit(), None), Vec::<String>::new());
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 7200))),
        Vec::<String>::new()
    );
    assert_eq!(watch.status(), swapped);
    assert_eq!(read_sim_network(run.path(), 64).unwrap(), None);
    assert_eq!(
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 7260))),
        [BACK]
    );
    let back = baseline_of(BaselineOrigin::NoRecord, cmlink(), 0);
    assert_eq!(watch.status(), back);
    assert_eq!(on_disk(run.path()).status(), &back);
}

/// A carrier check or a cycle rule other than the record's begins the
/// record again for `Recorded`: without a poll it waits for one, and with
/// one that poll is the new baseline, so the other network is gone. The
/// daemon started again under the new records keeps that record.
#[test]
fn the_check_or_the_cycle_recorded_again_begins_the_record_again() {
    for recorded in [checked_again(), anchored_again()] {
        let run = tempfile::tempdir().unwrap();
        let exit = fixture(|_| {});
        let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 0)));
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 600)));
        assert_eq!(track(&mut watch, recorded.exit(), None), [RECORDED]);
        let begun = no_baseline(BaselineOrigin::Recorded);
        assert_eq!(watch.status(), begun);
        assert_eq!(
            on_disk(run.path()),
            SimNetworkRecord::new(RecordedUnder::of(recorded.exit()), BaselineOrigin::Recorded)
        );
        assert_eq!(
            track(
                &mut watch,
                recorded.exit(),
                Some(&reported(&unnamed(), 900))
            ),
            [
                "sim network: the M7 reports a SIM without a name (234-20); the carrier check and the billing cycle are taken to go with it"
            ]
        );
        let taken = baseline_of(BaselineOrigin::Recorded, unnamed(), 900);
        assert_eq!(watch.status(), taken);
        drop(watch);
        let (watch, note) = NetworkWatch::open(run.path(), recorded.exit());
        assert_eq!(note, None);
        assert_eq!(watch.status(), taken);

        // The same, with the record and the poll at one tick.
        let run = tempfile::tempdir().unwrap();
        let (mut watch, _) = NetworkWatch::open(run.path(), exit.exit());
        track(&mut watch, exit.exit(), Some(&reported(&cmlink(), 0)));
        track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 600)));
        assert_eq!(
            track(
                &mut watch,
                recorded.exit(),
                Some(&reported(&unnamed(), 900))
            ),
            [RECORDED_AND_TAKEN]
        );
        assert_eq!(watch.status(), taken);
        assert_eq!(on_disk(run.path()).status(), &taken);
    }
}

/// A record that cannot be read (bytes that are no record, a record of
/// another version, one past the bound, a link where the file belongs) is
/// said at the start and begun again for `RecordUnreadable`: the status
/// says so with the new baseline, never that nothing changed, and the
/// file is a record again after the first tick.
#[test]
fn a_record_that_cannot_be_read_is_said_and_begun_again() {
    let exit = fixture(|_| {});
    let under = RecordedUnder::of(exit.exit());
    let held = SimNetworkRecord::new(under.clone(), BaselineOrigin::Recorded)
        .observed(&under, Some((&cmlink(), at(0))))
        .observed(&under, Some((&unnamed(), at(600))));
    let good = held.encode().unwrap();
    assert_eq!(SimNetworkRecord::decode(&good).unwrap(), held);
    let newer =
        String::from_utf8(good.clone())
            .unwrap()
            .replacen("\"version\": 1", "\"version\": 2", 1);
    assert_ne!(newer.as_bytes(), good);
    let mut long = good.clone();
    long.resize(MAX_SIM_NETWORK_BYTES + 1, b' ');
    let corrupt = "the record of the SIM's network is corrupt";
    let cases: [(&[u8], &str); 3] = [
        (b"not a record", corrupt),
        (newer.as_bytes(), corrupt),
        (&long, corrupt),
    ];
    for (bytes, error) in cases {
        let run = tempfile::tempdir().unwrap();
        fs::write(run.path().join(SIM_NETWORK_FILE), bytes).unwrap();
        let (mut watch, note) = NetworkWatch::open(run.path(), exit.exit());
        assert_eq!(
            note,
            Some(format!(
                "sim network: the record cannot be read ({error}); it is begun again, so a SIM changed before now is not noticed, and the status says so"
            ))
        );
        assert_eq!(
            watch.status(),
            no_baseline(BaselineOrigin::RecordUnreadable)
        );
        assert_eq!(
            track(&mut watch, exit.exit(), Some(&reported(&unnamed(), 700))),
            [
                "sim network: the M7 reports a SIM without a name (234-20); the carrier check and the billing cycle are taken to go with it"
            ]
        );
        let taken = baseline_of(BaselineOrigin::RecordUnreadable, unnamed(), 700);
        assert_eq!(watch.status(), taken);
        assert_eq!(on_disk(run.path()).status(), &taken);
    }

    let run = tempfile::tempdir().unwrap();
    let elsewhere = run.path().join("elsewhere.json");
    fs::write(&elsewhere, &good).unwrap();
    let file = run.path().join(SIM_NETWORK_FILE);
    symlink(&elsewhere, &file).unwrap();
    let (mut watch, note) = NetworkWatch::open(run.path(), exit.exit());
    assert_eq!(
        note,
        Some(format!(
            "sim network: the record cannot be read ({} is not a regular file); it is begun again, so a SIM changed before now is not noticed, and the status says so",
            file.display()
        ))
    );
    assert_eq!(
        watch.status(),
        no_baseline(BaselineOrigin::RecordUnreadable)
    );
    assert_eq!(track(&mut watch, exit.exit(), None), Vec::<String>::new());
    assert!(fs::symlink_metadata(&file).unwrap().is_file());
    assert_eq!(
        on_disk(run.path()),
        SimNetworkRecord::new(under, BaselineOrigin::RecordUnreadable)
    );
    assert_eq!(fs::read(&elsewhere).unwrap(), good);
}

/// A write that fails is said, and the status still has the record. The
/// write is tried again [`WRITE_RETRY`] after it failed and not before;
/// one that fails again is said again and waits as long again, and one
/// that succeeds says nothing.
#[test]
fn a_write_that_fails_is_said_and_tried_again_when_it_is_due() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    let exit = fixture(|_| {});
    let (mut watch, note) = NetworkWatch::open(&missing, exit.exit());
    assert_eq!(note.as_deref(), Some(NO_RECORD));
    let begun = Instant::now();
    let notes = watch.track(exit.exit(), Some(&reported(&cmlink(), 0)), begun);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!(notes[0], TAKEN);
    let failed = notes[1].clone();
    assert!(
        failed.starts_with("sim network: the record could not be written ("),
        "{notes:?}"
    );
    assert!(
        failed.ends_with("); the status shows it, and it is written again in 60 s"),
        "{notes:?}"
    );
    let taken = baseline_of(BaselineOrigin::NoRecord, cmlink(), 0);
    assert_eq!(watch.status(), taken);
    // A second before it is due nothing is tried, so nothing fails.
    assert_eq!(WRITE_RETRY, Duration::from_secs(60));
    let second = Duration::from_secs(1);
    assert_eq!(
        watch.track(exit.exit(), None, begun + WRITE_RETRY - second),
        Vec::<String>::new()
    );
    // When it is due it fails again: that is said again, and the wait
    // begins again.
    assert_eq!(
        watch.track(exit.exit(), None, begun + WRITE_RETRY),
        [failed]
    );
    fs::create_dir(&missing).unwrap();
    assert_eq!(
        watch.track(exit.exit(), None, begun + 2 * WRITE_RETRY - second),
        Vec::<String>::new()
    );
    assert_eq!(read_sim_network(&missing, 64).unwrap(), None);
    // Due again, the write succeeds: nothing to say, and the wait is over.
    assert_eq!(
        watch.track(exit.exit(), None, begun + 2 * WRITE_RETRY),
        Vec::<String>::new()
    );
    assert_eq!(on_disk(&missing).status(), &taken);
    assert_eq!(watch.status(), taken);
}

/// A record that changes while a failed write waits is written at once,
/// and one that does not change still waits.
#[test]
fn a_record_that_changes_while_a_write_waits_is_written_at_once() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    let exit = fixture(|_| {});
    let (mut watch, _) = NetworkWatch::open(&missing, exit.exit());
    let begun = Instant::now();
    let notes = watch.track(exit.exit(), Some(&reported(&cmlink(), 0)), begun);
    assert_eq!(notes.len(), 2, "{notes:?}");
    fs::create_dir(&missing).unwrap();
    assert_eq!(
        watch.track(exit.exit(), Some(&reported(&cmlink(), 60)), begun),
        Vec::<String>::new()
    );
    assert_eq!(read_sim_network(&missing, 64).unwrap(), None);
    assert_eq!(
        watch.track(exit.exit(), Some(&reported(&unnamed(), 600)), begun),
        [SWAPPED]
    );
    assert_eq!(on_disk(&missing).status(), &swapped_since(600));
    // That write succeeded, so nothing waits any more: the file is not
    // written again when the first write's retry would have been due.
    fs::remove_file(missing.join(SIM_NETWORK_FILE)).unwrap();
    assert_eq!(
        watch.track(exit.exit(), None, begun + WRITE_RETRY),
        Vec::<String>::new()
    );
    assert_eq!(read_sim_network(&missing, 64).unwrap(), None);
}

/// The stub's script for `polls` polls of the M7, each of which reads
/// `document`: the anonymous read, the login and the administrator's read.
fn polls_of(documents: Vec<Vec<u8>>) -> impl FnOnce(u16) -> Vec<Reply> {
    move |port| {
        documents
            .iter()
            .flat_map(|document| {
                [
                    anonymous_answer(),
                    observed_login_acceptance(port),
                    json(&[], document),
                ]
            })
            .collect()
    }
}

/// The M7's document for the fixture's SIM.
fn cmlink_document() -> Vec<u8> {
    FIXTURE.to_vec()
}

/// The M7's document with a SIM without a name on 234 20 in it.
fn unnamed_document() -> Vec<u8> {
    let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    document["sim"]["SPN"] = serde_json::json!("");
    document["wwanadv"]["MNC"] = serde_json::json!("20");
    serde_json::to_vec(&document).unwrap()
}

/// The daemon's lines about the SIM's network in `log`.
fn network_lines(log: &[u8]) -> Vec<String> {
    String::from_utf8(log.to_vec())
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once("mooringctl daemon: "))
        .map(|(_, text)| text.to_owned())
        .filter(|text| text.starts_with("sim network: "))
        .collect()
}

/// One run of the daemon at `secs` after [`NOW`] against an M7 that
/// serves `document` and is polled at every tick: the exit is opened and
/// ticked once, publishing to `control`, `then` runs, and the lines
/// about the SIM's network are returned with what `then` did.
fn run_against<T>(
    harness: &mut Harness,
    control: &Control,
    secs: u64,
    document: Vec<u8>,
    then: impl FnOnce(&mut Deployed<'_, '_>, &mut Vec<u8>) -> T,
) -> (Vec<String>, T) {
    let documents = vec![document; 4];
    let (lines, done, _) =
        run_polling_every(harness, control, Duration::ZERO, secs, documents, then);
    (lines, done)
}

/// [`run_against`] with the M7 polled at the start and then every
/// `router_poll`, its polls reading `documents` in turn; also returns
/// how many times the M7 was polled.
fn run_polling_every<T>(
    harness: &mut Harness,
    control: &Control,
    router_poll: Duration,
    secs: u64,
    documents: Vec<Vec<u8>>,
    then: impl FnOnce(&mut Deployed<'_, '_>, &mut Vec<u8>) -> T,
) -> (Vec<String>, T, usize) {
    let stub = Stub::start_for(polls_of(documents));
    harness.port = stub.port();
    harness.now.set(NOW + secs);
    for _ in 0..2 {
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
    }
    statuses(harness);
    let quick = Intervals {
        router_poll,
        publish: Duration::ZERO,
        ..Intervals::DAEMON
    };
    let (lines, done) = with_exit_on(harness, quick, |exit, log| {
        exit.tick(control, log, false).unwrap();
        let done = then(exit, log);
        (network_lines(log), done)
    });
    // A poll is three connections: the anonymous read, the login and
    // the administrator's read.
    let connections = stub.finish().len();
    assert_eq!(connections % 3, 0, "{connections} connections");
    (lines, done, connections / 3)
}

/// What the status `control` holds says of the SIM's network.
fn shown_by(control: &Control) -> SimNetworkStatus {
    published(control).parts().sim.network.clone()
}

/// A deployed daemon's harness whose M7 is the loopback stub.
fn harness_with_the_stub_m7() -> Harness {
    let mut harness = deployed();
    harness.link.gateway = Ok(Ipv4Addr::LOCALHOST);
    harness
        .secrets
        .put(SecretEntry::RouterAdmin(
            RouterAdminPassword::parse(PASSWORD).unwrap(),
        ))
        .unwrap();
    harness
}

/// Records the carrier check again with the other pairing, as
/// `exit record-carrier --replace` does.
fn record_the_check_again(store: &Store) {
    let generation = store.load().unwrap().deployment.config_generation();
    store
        .update_config(generation, |mut parts| {
            let check: &mut EgressCheck = parts.exit.egress_check.as_mut().unwrap();
            check.pairing = other_pairing(check.pairing);
            Ok::<_, std::convert::Infallible>(parts)
        })
        .unwrap();
}

/// The deployed daemon end to end, the M7 being the stub: the first run
/// takes the baseline from the M7's answer and writes it under `run/`;
/// with another SIM in the M7 the status carries both networks and the
/// time, and the log says so once; a restart keeps all of it; the carrier
/// check recorded again begins the record again, and the next poll is the
/// new baseline, which a further restart keeps.
#[test]
fn the_status_carries_the_network_from_the_m7_across_restarts_and_a_new_record() {
    let mut harness = harness_with_the_stub_m7();
    let support = harness.support_dir();
    let run_dir = RunPaths::under(&support).dir;
    let store = Store::new(&support);

    // The first run of a build that keeps the record.
    let (control, _retries) = shared();
    let (lines, ()) = run_against(&mut harness, &control, 0, cmlink_document(), |_, _| {});
    assert_eq!(lines, [NO_RECORD, TAKEN]);
    let taken = baseline_of(BaselineOrigin::NoRecord, cmlink(), 0);
    assert_eq!(shown_by(&control), taken);
    assert_eq!(on_disk(&run_dir).status(), &taken);
    assert_eq!(
        fs::metadata(run_dir.join(SIM_NETWORK_FILE)).unwrap().len(),
        on_disk(&run_dir).encode().unwrap().len() as u64
    );

    // Another SIM is in the M7.
    let (control, _retries) = shared();
    let (lines, ()) = run_against(&mut harness, &control, 600, unnamed_document(), |_, _| {});
    assert_eq!(lines, [SWAPPED]);
    let swapped = swapped_since(600);
    assert_eq!(shown_by(&control), swapped);

    // A restart keeps the baseline and the time; then the carrier check
    // is recorded again, and the next tick's poll is the new baseline.
    let (control, _retries) = shared();
    let document = unnamed_document();
    let (lines, before) = run_against(&mut harness, &control, 1200, document, |exit, log| {
        let before = shown_by(&control);
        record_the_check_again(&store);
        exit.tick(&control, log, false).unwrap();
        before
    });
    assert_eq!(before, swapped);
    assert_eq!(lines, [RECORDED_AND_TAKEN]);
    let recorded = baseline_of(BaselineOrigin::Recorded, unnamed(), 1200);
    assert_eq!(shown_by(&control), recorded);

    let (control, _retries) = shared();
    let (lines, ()) = run_against(&mut harness, &control, 1800, unnamed_document(), |_, _| {});
    assert_eq!(lines, Vec::<String>::new());
    assert_eq!(shown_by(&control), recorded);
    assert_eq!(on_disk(&run_dir).status(), &recorded);
}

/// A poll is set against the record once, by the first tick that holds
/// it. The M7 is polled at the start only: the first tick takes the
/// baseline from that poll; and a tick that then reads another carrier
/// check, without a poll of its own, begins the record again without a
/// baseline, because the poll it still holds was made before the check
/// was recorded and may be of the SIM before.
#[test]
fn a_poll_is_set_against_the_record_once_by_the_first_tick_that_holds_it() {
    let mut harness = harness_with_the_stub_m7();
    let support = harness.support_dir();
    let run_dir = RunPaths::under(&support).dir;
    let store = Store::new(&support);
    let (control, _retries) = shared();
    let hour = Duration::from_secs(3600);
    let (lines, (first, second), polls) = run_polling_every(
        &mut harness,
        &control,
        hour,
        0,
        vec![cmlink_document()],
        |exit, log| {
            let first = shown_by(&control);
            exit.tick(&control, log, false).unwrap();
            let second = shown_by(&control);
            record_the_check_again(&store);
            exit.tick(&control, log, false).unwrap();
            (first, second)
        },
    );
    assert_eq!(polls, 1);
    assert_eq!(lines, [NO_RECORD, TAKEN, RECORDED]);
    let taken = baseline_of(BaselineOrigin::NoRecord, cmlink(), 0);
    assert_eq!(first, taken);
    assert_eq!(second, taken);
    assert_eq!(shown_by(&control), no_baseline(BaselineOrigin::Recorded));
    let recorded = RecordedUnder::of(store.load().unwrap().deployment.exit());
    assert_eq!(
        on_disk(&run_dir),
        SimNetworkRecord::new(recorded, BaselineOrigin::Recorded)
    );
}

/// The SIM is changed and the carrier check recorded for the new one
/// between two polls. The tick that reads the new check polls the M7
/// before it sets the record against what it read, so the baseline of the
/// record begun again is the SIM now in the M7, never the one a poll
/// before the check was recorded found, and the status shows no other
/// network.
#[test]
fn a_tick_polls_before_it_sets_the_record_against_the_state_it_read() {
    let mut harness = harness_with_the_stub_m7();
    let support = harness.support_dir();
    let store = Store::new(&support);
    let (control, _retries) = shared();
    // The start's poll and the first tick's find the fixture's SIM; the
    // second tick's finds the one without a name.
    let documents = vec![cmlink_document(), cmlink_document(), unnamed_document()];
    let (lines, first, polls) = run_polling_every(
        &mut harness,
        &control,
        Duration::ZERO,
        0,
        documents,
        |exit, log| {
            let first = shown_by(&control);
            record_the_check_again(&store);
            exit.tick(&control, log, false).unwrap();
            first
        },
    );
    assert_eq!(polls, 3);
    assert_eq!(lines, [NO_RECORD, TAKEN, RECORDED_AND_TAKEN]);
    assert_eq!(first, baseline_of(BaselineOrigin::NoRecord, cmlink(), 0));
    assert_eq!(
        shown_by(&control),
        baseline_of(BaselineOrigin::Recorded, unnamed(), 0)
    );
}
