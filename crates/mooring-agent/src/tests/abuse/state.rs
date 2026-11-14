// SPDX-License-Identifier: GPL-3.0-or-later

//! The node's abuse state (design §11.8): cuts and records in one file,
//! numbered without reuse, pruned after 30 days and beyond its bound, read
//! only as a whole valid document; and the cut set built from it.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;

use mooring_agent_proto::{
    ABUSE_RECORD_KEEP_SECS, ABUSE_SUSPECTED_SECS, AbuseAction, AbuseCutEntry, AbuseCuts,
    AbuseFinding, AbuseFindings, AbuseSeq, AgentError, IoOp, MAX_ABUSE_CUTS, MAX_ABUSE_RECORDS,
    MAX_ABUSE_RECORDS_KEPT, OpaqueUserId, UnixTime, user_source,
};

use crate::abuse::state::AbuseState;
use crate::abuse::{add_words, cut_addresses, open_words, sync_words};
use crate::tests::scratch;

const NOW: u64 = 1_791_500_000;

fn user(id: &str) -> OpaqueUserId {
    OpaqueUserId::new(id).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn alerted(finding: AbuseFinding) -> AbuseAction {
    AbuseAction::Alerted {
        findings: AbuseFindings::of(finding),
    }
}

#[test]
fn a_node_that_recorded_nothing_has_an_empty_state() {
    let (_dir, paths) = scratch();
    let state = AbuseState::read(&paths).unwrap();
    assert_eq!(state, AbuseState::empty());
    assert!(state.cuts().is_empty());
    let page = state.page(AbuseSeq::FIRST).unwrap();
    assert_eq!(page.end(), AbuseSeq::FIRST);
    assert!(page.records().is_empty());
}

/// Records are numbered from 0 and a cut names its record; the state reads
/// back as written, in a file the `mooring` group reads.
#[test]
fn records_and_cuts_round_trip_through_the_file() {
    let (_dir, paths) = scratch();
    let mut state = AbuseState::empty();
    let first = state.record(
        at(NOW),
        &user("u01"),
        alerted(AbuseFinding::PortSweep),
        None,
    );
    let second = state.record(at(NOW + 15), &user("u01"), AbuseAction::OperatorCut, None);
    assert_eq!((first, second), (AbuseSeq::new(0), AbuseSeq::new(1)));
    state
        .cut(AbuseCutEntry {
            user: user("u01"),
            since: at(NOW + 15),
            record: second,
        })
        .unwrap();
    state.write(&paths).unwrap();
    let mode = fs::metadata(paths.abuse_state())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
    let read = AbuseState::read(&paths).unwrap();
    assert_eq!(read, state);
    let page = read.page(AbuseSeq::new(1)).unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.end(), AbuseSeq::new(2));
    assert_eq!(page.cuts().get(&user("u01")).unwrap().record, second);
    let mut cleared = read.clone();
    assert_eq!(cleared.clear(&user("u02")), None);
    assert_eq!(cleared.clear(&user("u01")).unwrap().record, second);
    assert!(cleared.cuts().is_empty());
}

/// Anything but a whole valid state is refused, never read as no cut.
#[test]
fn a_state_that_is_not_whole_and_valid_is_refused() {
    let (_dir, paths) = scratch();
    let malformed = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    let record = |seq: u64| {
        format!(
            r#"{{"seq":{seq},"at":{NOW},"user":"u01","guard":1,"action":"OperatorCut","figures":null}}"#
        )
    };
    let cut = |record: u64| format!(r#"{{"user":"u01","since":{NOW},"record":{record}}}"#);
    for text in [
        "garbled".to_owned(),
        format!(
            r#"{{"version":2,"next_record":1,"cuts":[],"records":[{}]}}"#,
            record(0)
        ),
        format!(
            r#"{{"version":1,"next_record":3,"cuts":[],"records":[{},{}]}}"#,
            record(0),
            record(2)
        ),
        format!(
            r#"{{"version":1,"next_record":1,"cuts":[],"records":[{}]}}"#,
            record(1)
        ),
        format!(
            r#"{{"version":1,"next_record":1,"cuts":[{}],"records":[]}}"#,
            cut(1)
        ),
        r#"{"version":1,"next_record":1,"cuts":[],"records":[],"x":1}"#.to_owned(),
        r#"{"version":1,"next_record":1,"cuts":[]}"#.to_owned(),
    ] {
        fs::create_dir_all(paths.watch_dir()).unwrap();
        fs::write(paths.abuse_state(), &text).unwrap();
        assert_eq!(AbuseState::read(&paths), Err(malformed.clone()), "{text}");
    }
    let many: Vec<String> = (0..=MAX_ABUSE_RECORDS_KEPT as u64).map(record).collect();
    fs::write(
        paths.abuse_state(),
        format!(
            r#"{{"version":1,"next_record":{},"cuts":[],"records":[{}]}}"#,
            many.len(),
            many.join(",")
        ),
    )
    .unwrap();
    assert_eq!(AbuseState::read(&paths), Err(malformed));
}

/// A record stays exactly 30 days and goes the second after; one dated
/// after now (a clock that stepped back) stays. Pruning takes the oldest
/// only, and the next number never goes back, even once none is left.
#[test]
fn records_are_kept_thirty_days_and_their_numbers_never_reused() {
    let mut state = AbuseState::empty();
    state.record(
        at(NOW),
        &user("u01"),
        alerted(AbuseFinding::MailBlast),
        None,
    );
    state.record(
        at(NOW + 10),
        &user("u02"),
        alerted(AbuseFinding::MailBlast),
        None,
    );
    let kept = at(NOW + ABUSE_RECORD_KEEP_SECS);
    assert!(!state.prune_due(kept));
    state.prune(kept);
    assert_eq!(state.records().len(), 2);
    let gone = at(NOW + ABUSE_RECORD_KEEP_SECS + 1);
    assert!(state.prune_due(gone));
    state.prune(gone);
    assert_eq!(state.records()[0].seq, AbuseSeq::new(1));
    state.prune(at(NOW + 10 + ABUSE_RECORD_KEEP_SECS + 1));
    assert!(state.records().is_empty());
    let next = state.record(
        at(NOW + 40 * 86_400),
        &user("u03"),
        AbuseAction::Cleared,
        None,
    );
    assert_eq!(next, AbuseSeq::new(2));
    let mut future = AbuseState::empty();
    future.record(at(NOW + 999), &user("u01"), AbuseAction::Cleared, None);
    assert!(!future.prune_due(at(NOW)));
    future.prune(at(NOW));
    assert_eq!(future.records().len(), 1);
}

/// A record past the bound drops the oldest as it is added, down to three
/// quarters of the bound, so no state the agent writes holds more records
/// than it reads back: a state written one past the bound would be refused
/// at every later reading, and the watch with it.
#[test]
fn a_record_past_the_bound_drops_the_oldest_to_three_quarters() {
    let (_dir, paths) = scratch();
    let mut state = AbuseState::empty();
    for index in 0..MAX_ABUSE_RECORDS_KEPT as u64 {
        state.record(at(NOW + index), &user("u01"), AbuseAction::Cleared, None);
    }
    assert_eq!(state.records().len(), MAX_ABUSE_RECORDS_KEPT);
    state.write(&paths).unwrap();
    assert_eq!(AbuseState::read(&paths).unwrap(), state);
    let past = AbuseSeq::new(MAX_ABUSE_RECORDS_KEPT as u64);
    let added = state.record(
        at(NOW + MAX_ABUSE_RECORDS_KEPT as u64),
        &user("u01"),
        AbuseAction::Cleared,
        None,
    );
    assert_eq!(added, past);
    assert_eq!(state.records().len(), MAX_ABUSE_RECORDS_KEPT / 4 * 3);
    assert_eq!(state.records().last().unwrap().seq, past);
    assert!(!state.prune_due(at(NOW + MAX_ABUSE_RECORDS_KEPT as u64)));
    state.write(&paths).unwrap();
    assert_eq!(AbuseState::read(&paths).unwrap(), state);
    // A page carries at most MAX_ABUSE_RECORDS.
    assert_eq!(
        state.page(AbuseSeq::FIRST).unwrap().records().len(),
        MAX_ABUSE_RECORDS
    );
}

/// Each user's latest lift, by user, from the records kept.
#[test]
fn the_lifts_are_each_users_latest() {
    let mut state = AbuseState::empty();
    state.record(at(NOW), &user("u01"), AbuseAction::Cleared, None);
    state.record(at(NOW + 5), &user("u02"), AbuseAction::OperatorCut, None);
    state.record(at(NOW + 9), &user("u01"), AbuseAction::Cleared, None);
    state.record(at(NOW + 12), &user("u01"), AbuseAction::OperatorCut, None);
    assert_eq!(
        state.cleared(),
        BTreeMap::from([(user("u01"), at(NOW + 9))])
    );
    assert!(AbuseState::empty().cleared().is_empty());
}

#[test]
fn a_node_holds_at_most_its_bound_of_cut_users() {
    let mut state = AbuseState::empty();
    for index in 0..MAX_ABUSE_CUTS {
        let record = state.record(
            at(NOW),
            &user(&format!("u{index:04}")),
            AbuseAction::OperatorCut,
            None,
        );
        state
            .cut(AbuseCutEntry {
                user: user(&format!("u{index:04}")),
                since: at(NOW),
                record,
            })
            .unwrap();
    }
    let record = state.record(at(NOW), &user("zzzz"), AbuseAction::OperatorCut, None);
    assert_eq!(
        state.cut(AbuseCutEntry {
            user: user("zzzz"),
            since: at(NOW),
            record,
        }),
        Err(AgentError::AbuseCutsFull)
    );
    // A user cut already keeps the cut made first.
    state
        .cut(AbuseCutEntry {
            user: user("u0000"),
            since: at(NOW + 1),
            record,
        })
        .unwrap();
    assert_eq!(
        state.cuts().get(&user("u0000")).unwrap().record,
        AbuseSeq::new(0)
    );
}

/// Who counts as suspected: a user with an alert within the last hour who
/// is not cut; and whether a finding was recorded since a time.
#[test]
fn suspected_users_are_those_alerted_within_the_hour_and_not_cut() {
    let mut state = AbuseState::empty();
    state.record(
        at(NOW),
        &user("u01"),
        alerted(AbuseFinding::PortSweep),
        None,
    );
    state.record(
        at(NOW),
        &user("u02"),
        alerted(AbuseFinding::PortSweep),
        None,
    );
    let cut = state.record(
        at(NOW),
        &user("u02"),
        AbuseAction::Cut {
            findings: AbuseFindings::of(AbuseFinding::MassContact),
        },
        None,
    );
    state
        .cut(AbuseCutEntry {
            user: user("u02"),
            since: at(NOW),
            record: cut,
        })
        .unwrap();
    assert_eq!(state.suspected(at(NOW + ABUSE_SUSPECTED_SECS)), 1);
    assert_eq!(state.suspected(at(NOW + ABUSE_SUSPECTED_SECS + 1)), 0);
    assert_eq!(state.suspected(at(NOW - 1)), 0, "a record from after now");
    assert!(state.found_since(&user("u01"), AbuseFinding::PortSweep, at(NOW)));
    assert!(!state.found_since(&user("u01"), AbuseFinding::PortSweep, at(NOW + 1)));
    assert!(!state.found_since(&user("u01"), AbuseFinding::MassContact, at(NOW)));
    assert!(state.found_since(&user("u02"), AbuseFinding::MassContact, at(NOW)));
    let mut operator = AbuseState::empty();
    operator.record(at(NOW), &user("u01"), AbuseAction::OperatorCut, None);
    assert!(!operator.found_since(&user("u01"), AbuseFinding::MassContact, at(NOW)));
    assert_eq!(operator.suspected(at(NOW)), 0);
}

fn cuts_of(ids: &[&str]) -> AbuseCuts {
    ids.iter().fold(AbuseCuts::EMPTY, |cuts, id| {
        cuts.with(AbuseCutEntry {
            user: user(id),
            since: at(NOW),
            record: AbuseSeq::FIRST,
        })
        .unwrap()
    })
}

/// The cut set holds every cut user's address, served or not, except one
/// that is a served, uncut user's.
#[test]
fn the_cut_set_holds_the_cut_users_addresses_and_spares_another_served_user() {
    let served: BTreeMap<Ipv4Addr, OpaqueUserId> = ["u01", "u02"]
        .iter()
        .map(|id| (user_source(&user(id)), user(id)))
        .collect();
    let cuts = cuts_of(&["u02", "u09"]);
    let mut expected = vec![user_source(&user("u02")), user_source(&user("u09"))];
    expected.sort_unstable();
    assert_eq!(cut_addresses(&cuts, &served), expected);
    // u09 is not served, and its address is u01's: cutting it would cut u01.
    let mut collision = served.clone();
    let u01 = user_source(&user("u01"));
    collision.remove(&u01);
    collision.insert(user_source(&user("u09")), user("u01"));
    assert_eq!(
        cut_addresses(&cuts_of(&["u09"]), &collision),
        Vec::<Ipv4Addr>::new()
    );
    // Unless that user is cut too.
    assert_eq!(
        cut_addresses(&cuts_of(&["u01", "u09"]), &collision),
        vec![user_source(&user("u09")), user_source(&user("u01"))]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    assert!(cut_addresses(&AbuseCuts::EMPTY, &served).is_empty());
}

/// The nft command lines: a flush then the elements, one transaction; the
/// open adds the gate's element last.
#[test]
fn the_cut_set_commands_are_one_line_each() {
    let a = Ipv4Addr::new(198, 18, 0, 5);
    let b = Ipv4Addr::new(198, 19, 3, 4);
    assert_eq!(
        sync_words(&[]).join(" "),
        "flush set inet mooring abuse_cut"
    );
    assert_eq!(
        sync_words(&[a, b]).join(" "),
        "flush set inet mooring abuse_cut ; add element inet mooring abuse_cut { 198.18.0.5, 198.19.3.4 }"
    );
    assert_eq!(
        open_words(&[a]).join(" "),
        "flush set inet mooring abuse_cut ; add element inet mooring abuse_cut { 198.18.0.5 } ; delete element inet mooring exit_closed { \"wgexit\" }"
    );
    assert_eq!(
        add_words(&[a]).join(" "),
        "add element inet mooring abuse_cut { 198.18.0.5 }"
    );
}
