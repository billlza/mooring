// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard's part of the watch (design §11.8): a finding at its cut
//! level cuts the user on the node at once, an alert is recorded once an
//! hour, the gate never opens with a cut missing, and a guard that cannot
//! measure is reported without touching the gate.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use mooring_agent_proto::{
    ABUSE_RECORD_KEEP_SECS, ABUSE_SUSPECTED_SECS, AbuseAction, AbuseCutEntry, AbuseFinding,
    AbuseFindings, AbuseGuardFault, AbuseSet, AgentError, AgentEventKind, IoOp, MAX_ABUSE_CUTS,
    MAX_ABUSE_RECORDS_KEPT, OpaqueUserId, TxnState, UnixTime, WatchError, WatchErrorKind,
    user_source,
};

use super::world::{World, listing, tick};
use crate::abuse::state::AbuseState;
use crate::host::{Node, Tool};
use crate::tests::{FakeNode, occupy_temporary};
use crate::watch::{Fatal, Watch};

fn u01() -> OpaqueUserId {
    OpaqueUserId::new("u01").unwrap()
}

/// `count` distinct destination buckets of `user`, as nft lists them.
fn buckets(user: &OpaqueUserId, count: u32) -> Vec<String> {
    let source = user_source(user);
    (0..count)
        .map(|bucket| {
            format!(r#"{{"elem":{{"val":{{"concat":["{source}",{bucket}]}},"expires":200}}}}"#)
        })
        .collect()
}

fn set_listing(world: &World, name: &'static str, elements: &[String]) {
    world
        .net
        .listings
        .borrow_mut()
        .insert(name, listing(name, elements));
}

/// The watch, its node at `now`, and the gate opened by two ticks of a
/// live peer (the first tick reads the sets).
fn opened(world: &World, now: u64) -> (Watch, FakeNode) {
    world.install(1, TxnState::Committed);
    let node = world.node(now);
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, world, &node);
    }
    assert!(!world.net.closed.get(), "the gate opened");
    (watch, node)
}

/// Ticks until the next reading of the sets (every third tick) has run.
fn until_read(watch: &mut Watch, world: &World, node: &FakeNode) {
    let before = reads(node);
    while reads(node) == before {
        world.traffic(node, 1);
        tick(watch, world, node);
    }
}

fn reads(node: &FakeNode) -> usize {
    node.calls()
        .iter()
        .filter(|call| call.ends_with("list set inet mooring user_dst"))
        .count()
}

fn in_kernel(world: &World, user: &OpaqueUserId) -> bool {
    world
        .net
        .cut
        .borrow()
        .contains(&user_source(user).to_string())
}

#[test]
fn a_scan_cuts_the_user_at_the_next_reading() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_700_000);
    assert!(world.conditions().is_empty());
    let cut_at = AbuseFinding::MassContact.cut_at();
    set_listing(&world, "user_dst", &buckets(&u01(), cut_at));
    until_read(&mut watch, &world, &node);
    assert!(in_kernel(&world, &u01()));
    let state = AbuseState::read(&world.paths).unwrap();
    let entry = state.cuts().get(&u01()).unwrap();
    let record = &state.records()[0];
    assert_eq!(record.seq, entry.record);
    assert_eq!(
        record.action,
        AbuseAction::Cut {
            findings: AbuseFindings::of(AbuseFinding::MassContact)
        }
    );
    assert_eq!(
        record.figures.unwrap().destination_buckets,
        u16::try_from(cut_at).unwrap()
    );
    assert_eq!(world.conditions(), vec![WatchErrorKind::AbuseCut]);
    assert!(world.events().contains(&AgentEventKind::ConditionRaised {
        condition: WatchError::AbuseCut { users: 1 }
    }));
    assert!(!world.net.closed.get(), "every other user is still served");
    // The next reading cuts no one again and records nothing more.
    until_read(&mut watch, &world, &node);
    assert_eq!(AbuseState::read(&world.paths).unwrap().records().len(), 1);
}

#[test]
fn an_alert_is_recorded_once_an_hour_and_counted_as_suspected() {
    let world = World::new();
    let start = 1_791_710_000;
    let (mut watch, node) = opened(&world, start);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.alert_at()),
    );
    until_read(&mut watch, &world, &node);
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records().len(), 1);
    assert_eq!(
        state.records()[0].action,
        AbuseAction::Alerted {
            findings: AbuseFindings::of(AbuseFinding::MassContact)
        }
    );
    assert!(state.cuts().is_empty());
    assert_eq!(world.conditions(), vec![WatchErrorKind::AbuseSuspected]);
    for _ in 0..5 {
        until_read(&mut watch, &world, &node);
    }
    assert_eq!(AbuseState::read(&world.paths).unwrap().records().len(), 1);
    node.sleep(Duration::from_secs(ABUSE_SUSPECTED_SECS));
    until_read(&mut watch, &world, &node);
    assert_eq!(AbuseState::read(&world.paths).unwrap().records().len(), 2);
}

/// A ruleset load empties the cut set and closes the gate together; the
/// watch opens it again only with the cut set restored, in one command
/// line, and a cut set changed by hand is set again at each re-read.
#[test]
fn a_ruleset_load_never_opens_the_gate_without_the_cuts() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_720_000);
    let mut state = AbuseState::read(&world.paths).unwrap();
    let record = state.record(
        UnixTime::from_secs(1_791_720_000),
        &u01(),
        AbuseAction::OperatorCut,
        None,
    );
    state
        .cut(AbuseCutEntry {
            user: u01(),
            since: UnixTime::from_secs(1_791_720_000),
            record,
        })
        .unwrap();
    state.write(&world.paths).unwrap();
    // A transaction's `nft -f`: the gate closed, the cut set empty.
    world.net.closed.set(true);
    world.net.cut.borrow_mut().clear();
    let opens_before = opens(&node).len();
    for _ in 0..13 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    let opens = opens(&node);
    assert_eq!(opens.len(), opens_before + 1, "reopened at the re-read");
    let source = user_source(&u01());
    assert_eq!(
        opens.last().unwrap(),
        &format!(
            "/usr/sbin/nft flush set inet mooring abuse_cut ; add element inet mooring abuse_cut {{ {source} }} ; delete element inet mooring exit_closed {{ \"wgexit\" }}"
        )
    );
    assert!(!world.net.closed.get());
    assert!(in_kernel(&world, &u01()));
    // Taken out by hand while the gate is open: set again at the re-read.
    world.net.cut.borrow_mut().clear();
    for _ in 0..12 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(in_kernel(&world, &u01()));
}

fn opens(node: &FakeNode) -> Vec<String> {
    node.calls()
        .into_iter()
        .filter(|call| call.contains("delete element inet mooring exit_closed"))
        .collect()
}

#[test]
fn a_generation_before_the_guard_is_reported_and_opens_alone() {
    let world = World::new();
    world.install_before_guard(1, TxnState::Committed);
    let node = world.node(1_791_730_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..4 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(!world.net.closed.get());
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![WatchError::AbuseGuardUnavailable {
            cause: AbuseGuardFault::NotInstalled
        }]
    );
    assert!(
        node.calls().iter().all(|call| !call.contains("abuse_cut")
            && !call.contains("user_")
            && !call.contains("meter_")),
        "{:#?}",
        node.calls()
    );
    assert!(
        opens(&node)
            .iter()
            .all(|call| call
                == "/usr/sbin/nft delete element inet mooring exit_closed { \"wgexit\" }")
    );
}

#[test]
fn a_reading_that_fails_is_reported_and_leaves_the_gate_and_the_cuts() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_740_000);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.cut_at()),
    );
    until_read(&mut watch, &world, &node);
    assert!(in_kernel(&world, &u01()));
    world.net.listing_fails.set(true);
    for _ in 0..3 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(
        world.conditions(),
        vec![
            WatchErrorKind::AbuseCut,
            WatchErrorKind::AbuseGuardUnavailable
        ]
    );
    assert!(!world.net.closed.get(), "the gate is untouched");
    assert!(in_kernel(&world, &u01()), "the cut stays");
    world.net.listing_fails.set(false);
    until_read(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::AbuseCut]);
}

/// The cuts are a reading the watch needs: a state it cannot read ends the
/// watch, so the gate is not opened without them.
#[test]
fn an_abuse_state_the_watch_cannot_read_ends_it() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    std::fs::create_dir_all(world.paths.watch_dir()).unwrap();
    std::fs::write(world.paths.abuse_state(), "garbled").unwrap();
    let node = world.node(1_791_750_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    assert_eq!(
        watch.tick(&world.paths, &node),
        Err(Fatal::Reading(AgentError::Io {
            op: IoOp::ReadState,
            errno: None
        }))
    );
    assert!(world.net.closed.get());
}

/// An alert the abuse state cannot take (a directory where its temporary
/// file goes) is a state write that failed, as the watch's own are: it is
/// reported at the next tick and recorded at the first reading after the
/// state can take it, and neither the watch nor the gate depends on it.
#[test]
fn an_alert_the_state_cannot_take_is_retried_and_leaves_the_gate() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_790_000);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.alert_at()),
    );
    let blocker = occupy_temporary(&world.paths.abuse_state());
    until_read(&mut watch, &world, &node);
    assert!(!world.net.closed.get(), "every user is still served");
    assert!(
        world.conditions().is_empty(),
        "the reading's conditions are the state's, without the alert it could not write"
    );
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::StateWrite],
        "no user is suspected on a record the state does not hold"
    );
    assert!(AbuseState::read(&world.paths).unwrap().records().is_empty());
    std::fs::remove_dir(&blocker).unwrap();
    until_read(&mut watch, &world, &node);
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records().len(), 1);
    assert_eq!(
        state.records()[0].action,
        AbuseAction::Alerted {
            findings: AbuseFindings::of(AbuseFinding::MassContact)
        }
    );
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::AbuseSuspected]);
    assert!(!world.net.closed.get());
}

/// A cut the abuse state cannot take ends the watch, as nft refusing one
/// does: its unit closes the gate for everyone and restarts it, rather
/// than serve a user it cannot keep cut. Once the state can take it, the
/// restarted watch cuts the user at its first reading.
#[test]
fn a_cut_the_state_cannot_take_ends_the_watch() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_795_000);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.cut_at()),
    );
    let blocker = occupy_temporary(&world.paths.abuse_state());
    let fatal = (0..3)
        .find_map(|_| {
            world.traffic(&node, 1);
            let result = watch.tick(&world.paths, &node);
            node.sleep(Duration::from_secs(5));
            result.err()
        })
        .unwrap();
    assert_eq!(
        fatal,
        Fatal::Reading(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(17)
        })
    );
    assert!(!in_kernel(&world, &u01()));
    assert!(AbuseState::read(&world.paths).unwrap().cuts().is_empty());
    // The unit's `ExecStopPost` closes the gate; the restarted watch cuts
    // the user at its first reading.
    world.net.closed.set(true);
    std::fs::remove_dir(&blocker).unwrap();
    let mut restarted = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut restarted, &world, &node);
    }
    assert!(in_kernel(&world, &u01()));
    assert!(!world.net.closed.get());
    assert!(
        AbuseState::read(&world.paths)
            .unwrap()
            .cuts()
            .get(&u01())
            .is_some()
    );
}

/// nft refusing the cut ends the watch (its unit restarts it with the gate
/// closed); the state already holds the cut, which the restarted watch
/// sets before it opens the gate.
#[test]
fn a_cut_nft_refuses_ends_the_watch_with_the_cut_recorded() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_760_000);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.cut_at()),
    );
    world.net.cut_fails.set(true);
    let fatal = (0..3)
        .find_map(|_| {
            world.traffic(&node, 1);
            let result = watch.tick(&world.paths, &node);
            node.sleep(Duration::from_secs(5));
            result.err()
        })
        .unwrap();
    assert!(matches!(fatal, Fatal::Nft(message) if message.contains("abuse_cut")));
    assert!(
        AbuseState::read(&world.paths)
            .unwrap()
            .cuts()
            .get(&u01())
            .is_some()
    );
    world.net.cut_fails.set(false);
    world.net.closed.set(true);
    let mut restarted = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut restarted, &world, &node);
    }
    assert!(!world.net.closed.get());
    assert!(in_kernel(&world, &u01()));
}

#[test]
fn records_past_their_retention_are_pruned_at_a_reading() {
    let world = World::new();
    let start = 1_791_770_000;
    let (mut watch, node) = opened(&world, start);
    let mut state = AbuseState::read(&world.paths).unwrap();
    state.record(
        UnixTime::from_secs(start - ABUSE_RECORD_KEEP_SECS - 100),
        &u01(),
        AbuseAction::Cleared,
        None,
    );
    state.write(&world.paths).unwrap();
    until_read(&mut watch, &world, &node);
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.records().is_empty());
    assert_eq!(
        state
            .page(mooring_agent_proto::AbuseSeq::FIRST)
            .unwrap()
            .end()
            .get(),
        1
    );
}

/// Two settled minutes of datagrams at the cut level, one after the other,
/// cut the user; the first alone is an alert. Between them the meter's
/// next element is too young to settle.
#[test]
fn two_minutes_of_datagram_flood_cut_the_user() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_780_000);
    let source = user_source(&u01());
    // The meter's element as nft lists it `expires` seconds before it goes,
    // having counted 1,000 datagrams for each second it has lived.
    let minute = |expires: u64| {
        let age = 60 - expires;
        vec![format!(
            r#"{{"elem":{{"val":{{"concat":["{source}","udp"]}},"expires":{expires},"counter":{{"packets":{},"bytes":{}}}}}}}"#,
            age * 1_000,
            age * 1_200_000
        )]
    };
    set_listing(&world, "meter_out", &minute(10));
    until_read(&mut watch, &world, &node);
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.cuts().is_empty());
    assert_eq!(
        state.records()[0].action,
        AbuseAction::Alerted {
            findings: AbuseFindings::of(AbuseFinding::DatagramFlood)
        }
    );
    // The next element, made by the first datagram after the first expired,
    // read 15, 30 and 45 s later: too young to settle.
    for expires in [55, 40, 25] {
        set_listing(&world, "meter_out", &minute(expires));
        until_read(&mut watch, &world, &node);
        assert!(AbuseState::read(&world.paths).unwrap().cuts().is_empty());
    }
    set_listing(&world, "meter_out", &minute(10));
    until_read(&mut watch, &world, &node);
    assert!(in_kernel(&world, &u01()));
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(
        state.records().last().unwrap().action,
        AbuseAction::Cut {
            findings: AbuseFindings::of(AbuseFinding::DatagramFlood)
        }
    );
    assert_eq!(
        state
            .records()
            .last()
            .unwrap()
            .figures
            .unwrap()
            .datagrams_per_sec,
        Some(1_000)
    );
}

/// `count` destination buckets of `user`, each last refreshed `age`
/// seconds ago (`user_dst` keeps an element 5 minutes after its last use).
fn aged_buckets(user: &OpaqueUserId, count: u32, age: u64) -> Vec<String> {
    let source = user_source(user);
    let expires = AbuseSet::Dst.timeout_secs().unwrap() - age;
    (0..count)
        .map(|bucket| {
            format!(
                r#"{{"elem":{{"val":{{"concat":["{source}",{bucket}]}},"expires":{expires}}}}}"#
            )
        })
        .collect()
}

/// A lift is not undone by what led to the cut. A cut refuses the user's
/// packets before they are measured, so the sets still hold the scan; the
/// readings after the lift leave out what was last refreshed before it.
/// What the user does after the lift is judged as before.
#[test]
fn a_lift_is_not_undone_by_what_led_to_the_cut() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_800_000);
    let cut_at = AbuseFinding::MassContact.cut_at();
    set_listing(&world, "user_dst", &aged_buckets(&u01(), cut_at, 290));
    until_read(&mut watch, &world, &node);
    assert!(in_kernel(&world, &u01()));
    let (lift, _) = crate::abuse::requests::clear(&world.paths, &node, &u01()).unwrap();
    assert!(lift.is_some());
    assert!(!in_kernel(&world, &u01()));
    for _ in 0..3 {
        until_read(&mut watch, &world, &node);
    }
    assert!(
        !in_kernel(&world, &u01()),
        "not cut again for the same scan"
    );
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.cuts().is_empty());
    assert_eq!(state.records().len(), 2, "the cut and its lift");
    set_listing(&world, "user_dst", &aged_buckets(&u01(), cut_at, 5));
    until_read(&mut watch, &world, &node);
    assert!(
        in_kernel(&world, &u01()),
        "a scan after the lift cuts again"
    );
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records().len(), 3);
    assert!(matches!(state.records()[2].action, AbuseAction::Cut { .. }));
}

/// A lift that lands while a reading is taken (after the sets are listed,
/// before the watch takes `gate.lock`) leaves the user to the next
/// reading, which leaves out what led to the cut: the reading judged the
/// user without the lift.
#[test]
fn a_lift_during_a_reading_leaves_the_user_to_the_next() {
    let world = World::new();
    let start = 1_791_805_000;
    world.install(1, TxnState::Committed);
    let armed = Rc::new(Cell::new(false));
    let node = {
        let armed = Rc::clone(&armed);
        let paths = world.paths.clone();
        world.node_answering(start, move |tool, args| {
            let listing_dst = matches!(args, ["-j", "list", "set", "inet", "mooring", "user_dst"]);
            if tool == Tool::Nft && listing_dst && armed.replace(false) {
                let mut state = AbuseState::read(&paths).unwrap();
                state.record(
                    UnixTime::from_secs(start + 20),
                    &u01(),
                    AbuseAction::Cleared,
                    None,
                );
                state.clear(&u01());
                state.write(&paths).unwrap();
            }
            None
        })
    };
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    let cut_at = AbuseFinding::MassContact.cut_at();
    set_listing(&world, "user_dst", &aged_buckets(&u01(), cut_at, 290));
    until_read(&mut watch, &world, &node);
    assert!(in_kernel(&world, &u01()));
    armed.set(true);
    for _ in 0..2 {
        until_read(&mut watch, &world, &node);
    }
    assert!(!armed.get(), "the lift landed");
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.cuts().is_empty(), "not cut again");
    assert_eq!(state.records().len(), 2, "the cut and its lift");
}

/// A node holding the most cut users records a further user's cut-level
/// findings as an alert, once an hour as any alert, not at every reading.
#[test]
fn a_node_at_its_bound_of_cuts_alerts_once_an_hour() {
    let world = World::new();
    let start = 1_791_810_000;
    let (mut watch, node) = opened(&world, start);
    let mut state = AbuseState::read(&world.paths).unwrap();
    let since = UnixTime::from_secs(start);
    for index in 0..MAX_ABUSE_CUTS {
        let other = OpaqueUserId::new(format!("x{index:04}")).unwrap();
        let record = state.record(since, &other, AbuseAction::OperatorCut, None);
        state
            .cut(AbuseCutEntry {
                user: other,
                since,
                record,
            })
            .unwrap();
    }
    state.write(&world.paths).unwrap();
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.cut_at()),
    );
    for _ in 0..4 {
        until_read(&mut watch, &world, &node);
    }
    let alerts = |state: &AbuseState| {
        state
            .records()
            .iter()
            .filter(|record| record.user == u01())
            .map(|record| record.action)
            .collect::<Vec<_>>()
    };
    let mass_contact = AbuseAction::Alerted {
        findings: AbuseFindings::of(AbuseFinding::MassContact),
    };
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.cuts().get(&u01()).is_none());
    assert_eq!(alerts(&state), vec![mass_contact]);
    node.sleep(Duration::from_secs(ABUSE_SUSPECTED_SECS));
    until_read(&mut watch, &world, &node);
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(alerts(&state), vec![mass_contact, mass_contact]);
}

/// A record log at its bound takes the next record and stays readable:
/// the oldest go as the record is added. A state written past the bound
/// would be refused at every later tick, and the watch with it.
#[test]
fn a_full_record_log_takes_the_next_record_and_stays_readable() {
    let world = World::new();
    let start = 1_791_815_000;
    let (mut watch, node) = opened(&world, start);
    let mut state = AbuseState::read(&world.paths).unwrap();
    let other = OpaqueUserId::new("x0001").unwrap();
    for _ in 0..MAX_ABUSE_RECORDS_KEPT {
        state.record(
            UnixTime::from_secs(start),
            &other,
            AbuseAction::OperatorCut,
            None,
        );
    }
    state.write(&world.paths).unwrap();
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.alert_at()),
    );
    until_read(&mut watch, &world, &node);
    for _ in 0..3 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records().len(), MAX_ABUSE_RECORDS_KEPT / 4 * 3);
    assert_eq!(state.records().last().unwrap().user, u01());
    assert!(!world.net.closed.get());
}

/// A reading that changes nothing writes nothing: with its alert recorded
/// within the hour, the same finding again leaves the state as it is, so
/// a state the watch could not write raises no failure.
#[test]
fn a_reading_that_changes_nothing_writes_nothing() {
    let world = World::new();
    let (mut watch, node) = opened(&world, 1_791_820_000);
    set_listing(
        &world,
        "user_dst",
        &buckets(&u01(), AbuseFinding::MassContact.alert_at()),
    );
    until_read(&mut watch, &world, &node);
    assert_eq!(AbuseState::read(&world.paths).unwrap().records().len(), 1);
    let blocker = occupy_temporary(&world.paths.abuse_state());
    for _ in 0..3 {
        until_read(&mut watch, &world, &node);
    }
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::AbuseSuspected]);
    std::fs::remove_dir(&blocker).unwrap();
}
