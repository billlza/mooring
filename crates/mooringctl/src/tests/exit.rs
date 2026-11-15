// SPDX-License-Identifier: GPL-3.0-or-later

//! `exit init`, `exit record-carrier` and `sim set-anchor` against the
//! harness's support directory (design §7, §10.2): what each records, the
//! generation it leaves, and the refusals that write nothing.

use std::fs;
use std::net::Ipv4Addr;

use clap::Parser;
use mooring_macsys::InterfaceAddrV4;
use mooring_model::collections::NonEmpty;
use mooring_model::exit::{EgressCheck, FlowCap, Pairing};
use mooring_model::iface::{InterfaceSelector, MacAddr};
use mooring_model::ipv4::CarrierPrefix;
use mooring_model::{Bookkeeping, CalendarDate, CycleRule, DeploymentInit, PeriodDays};
use mooring_store::Store;

use super::support::{Harness, PINNED, change_the_configuration_meanwhile, changed_since};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::prompt::Answer;

fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

/// A harness whose `lo0` faces the pinned M7 at 192.168.1.1, holding
/// 192.168.1.20/24 beside the loopback address.
fn facing_the_m7() -> Harness {
    let mut harness = Harness::new(0);
    harness.pin(PINNED);
    harness.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    harness.link.addresses = Ok(vec![
        InterfaceAddrV4 {
            addr: Ipv4Addr::LOCALHOST,
            prefix_len: Some(8),
        },
        InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 1, 20),
            prefix_len: Some(24),
        },
    ]);
    harness
}

const INIT: [&str; 8] = [
    "exit",
    "init",
    "--interface",
    "lo0",
    "--cycle-anchor",
    "2026-10-28",
    "--flow-cap",
    "1024",
];

#[test]
fn init_records_the_pilot_with_the_m7_as_the_egress() {
    let mut harness = facing_the_m7();
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&INIT);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        "egress: lo0 (the M7, gateway 02:00:5e:10:20:30 on 192.168.1.0/24); the tunnel leaves the same way\n\
         line: 1pMobile, fair-use line 500 GB, terms of 2026-07-24 (https://www.1pmobile.com/terms-and-conditions)\n\
         billing cycles: 30 days, one starting on 2026-10-28\n\
         SIM: warning at 200 GB, hard stop at 240 GB, per cycle\n\
         users: at most 5 active; automatic quotas on; alert digest at 09:00 Europe/London, no channel yet\n\
         flow cap: 1024 new flows\n\
         carrier check: not recorded yet\n\
         created the deployment at generation 1; the exit serves nothing until `mooringctl exit record-carrier` records the line's carrier check\n"
    );
    assert_eq!(
        harness.console.asked,
        ["Create the deployment with these values?"]
    );
    let state = store(&harness).load().unwrap();
    let expected = DeploymentInit::pilot(
        InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: MacAddr::from_bytes(PINNED).unwrap(),
            subnet: "192.168.1.0/24".parse().unwrap(),
        },
        date("2026-10-28"),
        FlowCap::new(1024).unwrap(),
    )
    .unwrap();
    assert_eq!(state.deployment.exit(), &expected.exit);
    assert_eq!(state.deployment.config_generation().get(), 1);
    assert!(state.deployment.nodes().is_empty());
    assert!(state.deployment.users().is_empty());
    assert!(!state.runtime.exit_enabled);
}

#[test]
fn init_with_yes_asks_nothing() {
    let mut harness = facing_the_m7();
    let mut args = INIT.to_vec();
    args.push("--yes");
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.console.asked.is_empty());
    assert!(store(&harness).state_path().exists());
}

/// Every refusal exits 1, names its cause and writes no state.
#[test]
fn init_refuses_without_the_pinned_m7_a_lan_subnet_or_a_yes() {
    // Declined.
    let mut declined = facing_the_m7();
    declined.console.answers.push_back(Answer::No);
    let outcome = declined.run(&INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: the answer was not yes\n"
    );
    assert!(!store(&declined).state_path().exists());
    // No terminal and no --yes.
    let mut unattended = facing_the_m7();
    unattended.console.answers.push_back(Answer::NoTerminal);
    let outcome = unattended.run(&INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: no terminal to ask and --yes was not given\n"
    );
    assert!(!store(&unattended).state_path().exists());
    // Another gateway than the pinned M7.
    let mut other = facing_the_m7();
    other.link = super::support::FakeLink::answering(&[Ok([0x02, 0, 0, 0, 0, 1])]);
    other.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    let outcome = other.run(&INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the gateway of lo0 is 02:00:00:00:00:01, not the pinned M7 (02:00:5e:10:20:30): give the interface that faces the M7\n"
    );
    assert!(other.console.asked.is_empty());
    assert!(!store(&other).state_path().exists());
    // No address in the gateway's network, and one outside the LAN
    // classes.
    for addresses in [
        vec![InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 2, 20),
            prefix_len: Some(24),
        }],
        vec![InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 1, 20),
            prefix_len: None,
        }],
        vec![InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 1, 20),
            prefix_len: Some(15),
        }],
    ] {
        let mut harness = facing_the_m7();
        harness.link.addresses = Ok(addresses.clone());
        let outcome = harness.run(&INIT);
        assert_eq!(outcome.code, EXIT_LOCAL, "{addresses:?}");
        assert_eq!(
            outcome.stderr,
            "mooringctl: lo0 has no address in a private LAN subnet with its gateway 192.168.1.1\n",
            "{addresses:?}"
        );
        assert!(!store(&harness).state_path().exists());
    }
    // No pin at all.
    let mut unpinned = Harness::new(0);
    let outcome = unpinned.run(&INIT);
    assert_ne!(outcome.code, 0);
    assert!(outcome.stderr.contains("pin"), "{}", outcome.stderr);
    // A flow cap out of range is a usage error.
    for cap in ["0", "65536", "many"] {
        let mut args = vec!["mooringctl"];
        args.extend(INIT);
        args[8] = cap;
        assert!(crate::cli::Cli::try_parse_from(args).is_err(), "{cap}");
    }
}

#[test]
fn init_refuses_an_existing_deployment_before_asking() {
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    let before = state_bytes(&harness);
    let outcome = harness.run(&INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: a deployment exists already ({}); `exit init` creates one only once\n",
            store(&harness).state_path().display()
        )
    );
    assert!(harness.console.asked.is_empty());
    assert_eq!(state_bytes(&harness), before);
}

/// The answer may have waited. A deployment that another `exit init`
/// created meanwhile is not replaced: the store refuses a second one under
/// its lock, and the command says what it says before it asks.
#[test]
fn init_answered_after_another_created_the_deployment_creates_none() {
    let mut harness = facing_the_m7();
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let theirs = DeploymentInit::pilot(
            InterfaceSelector::GatewayLinkAddr {
                gw_lladdr: MacAddr::from_bytes(PINNED).unwrap(),
                subnet: "192.168.1.0/24".parse().unwrap(),
            },
            date("2026-11-01"),
            FlowCap::new(512).unwrap(),
        )
        .unwrap();
        Store::new(support).init(theirs).unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: a deployment exists already ({}); `exit init` creates one only once\n",
            store(&harness).state_path().display()
        )
    );
    assert_eq!(
        harness.console.asked,
        ["Create the deployment with these values?"]
    );
    assert!(harness.console.meanwhile.is_none());
    assert!(
        !outcome.stdout.contains("created the deployment"),
        "{}",
        outcome.stdout
    );
    // The other command's deployment stands, with its flow cap.
    let kept = store(&harness).load().unwrap().deployment;
    assert_eq!(kept.exit().flow_cap, FlowCap::new(512).unwrap());
}

fn prefix(text: &str) -> CarrierPrefix {
    text.parse().unwrap()
}

#[test]
fn record_carrier_records_the_check_once_as_bookkeeping() {
    let deployment = fixture(|parts| parts.exit.egress_check = None);
    let mut harness = harness_with(deployment.clone());
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.120.0.0/14",
        "--prefix",
        "92.40.0.0/16",
        "--pairing",
        "unpaired",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "carrier check: every egress address in 31.120.0.0/14, 92.40.0.0/16; pairing unpaired\n\
         recorded the carrier check; no node apply is needed\n"
    );
    let after = store(&harness).load().unwrap().deployment;
    let mut prefixes = NonEmpty::new(prefix("31.120.0.0/14"));
    prefixes.push(prefix("92.40.0.0/16"));
    assert_eq!(
        after.exit().egress_check,
        Some(EgressCheck {
            carrier_prefixes: prefixes,
            pairing: Pairing::Unpaired,
        })
    );
    assert_eq!(after.config_generation(), deployment.config_generation());
    assert_eq!(after.nodes(), deployment.nodes());
    // A second record is refused before anything is asked.
    let before = state_bytes(&harness);
    let outcome = harness.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.120.0.0/14",
        "--pairing",
        "paired",
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the carrier check is recorded already; give --replace to replace it (a configuration change)\n"
    );
    assert_eq!(state_bytes(&harness), before);
    assert_eq!(harness.console.asked.len(), 1);
}

/// A carrier check that another `exit record-carrier` recorded while the
/// question waited is not recorded over: the model refuses a second
/// record, and replacing a check is a configuration change. The other
/// command's check stands.
#[test]
fn a_carrier_check_recorded_while_the_question_waits_refuses_the_record() {
    let deployment = fixture(|parts| parts.exit.egress_check = None);
    let mut harness = harness_with(deployment.clone());
    let support = harness.support_dir();
    let theirs = EgressCheck {
        carrier_prefixes: NonEmpty::new(prefix("92.40.0.0/16")),
        pairing: Pairing::Paired,
    };
    let recorded = theirs.clone();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let generation = store.load().unwrap().deployment.config_generation();
        store
            .record(generation, Bookkeeping::CarrierRecorded { check: recorded })
            .unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.120.0.0/14",
        "--pairing",
        "unpaired",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the state was not changed\n  caused by: the new or changed deployment is invalid\n  caused by: the exit's carrier check is recorded already; replacing it is a configuration change\n"
    );
    assert_eq!(harness.console.asked, ["Record this carrier check?"]);
    assert!(harness.console.meanwhile.is_none());
    assert!(
        !outcome.stdout.contains("recorded the carrier check"),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.exit().egress_check, Some(theirs));
    assert_eq!(after.config_generation(), deployment.config_generation());
}

/// A configuration change that another command made while the question
/// waited refuses a replacement of the carrier check and a move of the
/// billing cycles: each is one write for the generation its command read,
/// and the store finds another.
#[test]
fn a_configuration_change_while_the_question_waits_refuses_a_replacement_and_a_new_anchor() {
    let deployment = fixture(|_| {});
    let read = deployment.config_generation().get();
    let mut harness = harness_with(deployment.clone());
    change_the_configuration_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.94.0.0/16",
        "--pairing",
        "unpaired",
        "--replace",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, changed_since(read));
    assert_eq!(harness.console.asked, ["Replace the carrier check?"]);
    assert!(harness.console.meanwhile.is_none());
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.exit().egress_check, deployment.exit().egress_check);
    assert_eq!(after.config_generation().get(), read + 1);

    let deployment = fixed_cycles("2026-10-28");
    let read = deployment.config_generation().get();
    let mut harness = harness_with(deployment.clone());
    change_the_configuration_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["sim", "set-anchor", "2026-10-30"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, changed_since(read));
    assert_eq!(harness.console.asked, ["Move the billing cycles?"]);
    assert!(harness.console.meanwhile.is_none());
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.exit().sim.cycle(), deployment.exit().sim.cycle());
    assert_eq!(after.config_generation().get(), read + 1);
}

/// A new SIM's carrier check replaces the old one with `--replace`, as a
/// configuration change; without a check recorded there is nothing to
/// replace, and a declined replacement changes nothing.
#[test]
fn record_carrier_replaces_the_check_as_a_configuration_change() {
    let deployment = fixture(|_| {});
    let old = deployment.exit().egress_check.clone().unwrap();
    let mut harness = harness_with(deployment.clone());
    let replace = [
        "exit",
        "record-carrier",
        "--prefix",
        "31.94.0.0/16",
        "--pairing",
        "unpaired",
        "--replace",
    ];
    harness.console.answers.push_back(Answer::No);
    let before = state_bytes(&harness);
    let outcome = harness.run(&replace);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), before);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&replace);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "carrier check: every egress address in 31.94.0.0/16; pairing unpaired\n\
             it replaces: every egress address in 31.120.0.0/14; pairing paired; every node then needs `node apply`\n\
             replaced the carrier check; the deployment is at generation {}, and every node needs `node apply`\n",
            deployment.config_generation().get() + 1
        )
    );
    assert_eq!(
        harness.console.asked,
        ["Replace the carrier check?", "Replace the carrier check?"]
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.exit().egress_check,
        Some(EgressCheck {
            carrier_prefixes: NonEmpty::new(prefix("31.94.0.0/16")),
            pairing: Pairing::Unpaired,
        })
    );
    assert_ne!(after.exit().egress_check, Some(old));
    assert_eq!(
        after.config_generation().get(),
        deployment.config_generation().get() + 1
    );
    // Without a check recorded, `--replace` is refused before asking.
    let mut harness = harness_with(fixture(|parts| parts.exit.egress_check = None));
    let outcome = harness.run(&replace);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: no carrier check is recorded, so there is none to replace; record it without --replace\n"
    );
    assert!(harness.console.asked.is_empty());
}

#[test]
fn record_carrier_refuses_a_declined_answer_and_a_special_prefix() {
    let deployment = fixture(|parts| parts.exit.egress_check = None);
    let mut harness = harness_with(deployment);
    let before = state_bytes(&harness);
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.120.0.0/14",
        "--pairing",
        "paired",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), before);
    // A prefix inside SPECIAL_V4 is not a carrier prefix (clap refuses it).
    let parsed = crate::cli::Cli::try_parse_from([
        "mooringctl",
        "exit",
        "record-carrier",
        "--prefix",
        "100.64.0.0/10",
        "--pairing",
        "paired",
    ]);
    assert!(parsed.is_err());
    // A Mac without a deployment.
    let mut empty = Harness::new(0);
    let outcome = empty.run(&[
        "exit",
        "record-carrier",
        "--prefix",
        "31.120.0.0/14",
        "--pairing",
        "paired",
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("`exit init` creates it"),
        "{}",
        outcome.stderr
    );
}

/// The fixture's SIM policy on 30-day cycles from `anchor`, plan and
/// thresholds kept.
fn fixed_cycles(anchor: &str) -> mooring_model::Deployment {
    fixture(|parts| {
        let sim = &parts.exit.sim;
        parts.exit.sim = mooring_model::SimPolicy::new(
            CycleRule::FixedDays {
                days: PeriodDays::new(30).unwrap(),
                anchor: date(anchor),
            },
            sim.plan().unwrap().clone(),
            sim.warn_bytes(),
            sim.stop(),
        )
        .unwrap();
    })
}

#[test]
fn set_anchor_moves_the_cycles_as_a_configuration_change() {
    let deployment = fixed_cycles("2026-10-28");
    let mut harness = harness_with(deployment.clone());
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["sim", "set-anchor", "2026-10-30"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let generation = deployment.config_generation().get() + 1;
    assert_eq!(
        outcome.stdout,
        format!(
            "billing cycles: 30 days, one starting on 2026-10-30 (they started from 2026-10-28); every node then needs `node apply` before a user's file can be exported again\n\
             moved the billing cycles; the deployment is at generation {generation}\n"
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.exit().sim.cycle(),
        CycleRule::FixedDays {
            days: PeriodDays::new(30).unwrap(),
            anchor: date("2026-10-30"),
        }
    );
    assert_eq!(after.exit().sim.plan(), deployment.exit().sim.plan());
    assert_eq!(
        after.exit().sim.thresholds(),
        deployment.exit().sim.thresholds()
    );
    assert_eq!(after.config_generation().get(), generation);
}

#[test]
fn set_anchor_keeps_the_same_cycles_and_refuses_monthly_ones() {
    // An anchor a whole number of cycles away names the same cycles.
    let mut same = harness_with(fixed_cycles("2026-10-28"));
    let before = state_bytes(&same);
    let outcome = same.run(&["sim", "set-anchor", "2026-11-27"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "kept: cycles of 30 days already start on 2026-10-28 and 2026-11-27\n"
    );
    assert!(same.console.asked.is_empty());
    assert_eq!(state_bytes(&same), before);
    // The fixture's monthly cycles.
    let mut monthly = harness_with(fixture(|_| {}));
    let before = state_bytes(&monthly);
    let outcome = monthly.run(&["sim", "set-anchor", "2026-10-30", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the SIM's billing cycles are monthly; `sim set-anchor` moves fixed-length cycles only\n"
    );
    assert_eq!(state_bytes(&monthly), before);
    // Declined.
    let mut declined = harness_with(fixed_cycles("2026-10-28"));
    let before = state_bytes(&declined);
    declined.console.answers.push_back(Answer::No);
    let outcome = declined.run(&["sim", "set-anchor", "2026-10-30"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&declined), before);
    assert!(fs::metadata(store(&declined).state_path()).is_ok());
}

/// `exit enable` and `exit disable` change the runtime intent only: its
/// revision moves, the generation does not, and a second run says so and
/// changes nothing.
#[test]
fn enable_and_disable_record_the_runtime_intent_only() {
    let mut harness = harness_with(fixture(|_| {}));
    let before = store(&harness).load().unwrap();
    assert!(!before.runtime.exit_enabled);
    let outcome = harness.run(&["exit", "enable"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "the exit is enabled; the daemon runs its preflight and starts the engine at its next tick\n"
    );
    let enabled = store(&harness).load().unwrap();
    assert!(enabled.runtime.exit_enabled);
    assert_eq!(
        enabled.runtime.revision,
        before.runtime.revision.next().unwrap()
    );
    assert_eq!(enabled.deployment, before.deployment);
    let bytes = state_bytes(&harness);
    let again = harness.run(&["exit", "enable"]);
    assert_eq!(again.stdout, "the exit is enabled already\n");
    assert_eq!(state_bytes(&harness), bytes);
    let outcome = harness.run(&["exit", "disable"]);
    assert_eq!(
        outcome.stdout,
        "the exit is disabled; the daemon stops the engine at its next tick\n"
    );
    assert!(!store(&harness).load().unwrap().runtime.exit_enabled);
}

/// A harness with the fixture deployment whose `lo0` faces the pinned M7.
fn observing(edit: impl FnOnce(&mut mooring_model::DeploymentParts)) -> Harness {
    let mut harness = harness_with(fixture(edit));
    harness.pin(PINNED);
    harness.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    harness
}

fn connect_failure() -> crate::runtime::probe::ProbeFailure {
    crate::runtime::probe::ProbeFailure {
        stage: mooring_daemon_core::status::ProbeStage::Connect,
        kind: Some(std::io::ErrorKind::TimedOut),
    }
}

/// `exit observe` asks each adopted node's reflector through the M7 and
/// says whether the address passes a recorded carrier check.
#[test]
fn observe_prints_the_address_each_reflector_sees() {
    let mut harness = observing(|_| {});
    harness
        .probes
        .borrow_mut()
        .extend([Ok(Ipv4Addr::new(31, 120, 5, 6)), Err(connect_failure())]);
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "ams1: the reflector sees 31.120.5.6 (inside the recorded carrier prefixes)\n\
         lon1: no answer from 45.67.89.10:27900 (Connect, timed out)\n"
    );
    let probed: Vec<String> = harness
        .probed
        .borrow()
        .iter()
        .map(|(index, reflector)| {
            assert_eq!(*index, super::support::lo0());
            reflector.to_string()
        })
        .collect();
    assert_eq!(probed, ["46.78.90.12:27900", "45.67.89.10:27900"]);
    // Before the carrier check is recorded, and outside it.
    let mut harness = observing(|parts| parts.exit.egress_check = None);
    harness
        .probes
        .borrow_mut()
        .extend([Ok(Ipv4Addr::new(82, 10, 20, 30)), Err(connect_failure())]);
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert!(
        outcome.stdout.starts_with(
            "ams1: the reflector sees 82.10.20.30 (no carrier check is recorded yet)\n"
        )
    );
    let mut harness = observing(|_| {});
    harness
        .probes
        .borrow_mut()
        .extend([Ok(Ipv4Addr::new(82, 10, 20, 30)), Err(connect_failure())]);
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert!(outcome.stdout.starts_with(
        "ams1: the reflector sees 82.10.20.30 (OUTSIDE the recorded carrier prefixes)\n"
    ));
}

/// No answer from any reflector is a failure, and an interface that does
/// not face the pinned M7 is refused before any probe.
#[test]
fn observe_refuses_no_answer_and_another_gateway() {
    let mut harness = observing(|_| {});
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.ends_with(
            "mooringctl: no node's reflector answered; adopt a node first, and check the line\n"
        ),
        "{}",
        outcome.stderr
    );
    let mut harness = observing(|_| {});
    harness.link = super::support::FakeLink::answering(&[Ok([2, 0, 0, 0, 0, 9])]);
    harness.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(harness.probed.borrow().is_empty());
}

/// `exit retry` asks the daemon on the control socket, and reports a
/// refusal as the daemon's; a status in place of the answer, or no answer
/// before the daemon closes, is refused.
#[test]
fn retry_asks_the_daemon_and_reports_its_answer() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use mooring_daemon_core::console::{ConsoleStatus, UndeployedStatus};
    use mooring_daemon_core::control::{
        DaemonReply, MAX_REPLY_LINE_BYTES, ProtocolLine, Refusal, encode_line,
    };
    use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};

    let a_status = DaemonReply::Status(ConsoleStatus::NoDeployment(UndeployedStatus::new(
        mooring_model::UnixTime::from_secs(super::support::NOW),
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::Unreachable,
            last_polled_at: None,
        },
    )));
    for (reply, code, stdout, stderr) in [
        (
            Some(DaemonReply::RetryQueued),
            0,
            "retry queued: the daemon clears the latch and runs a fresh preflight at its next tick; `mooringctl status` shows the outcome\n",
            "",
        ),
        (
            Some(DaemonReply::Refused {
                reason: Refusal::NotDeployed,
            }),
            EXIT_LOCAL,
            "",
            "mooringctl: the daemon refused the request: there is no deployment yet (`exit init` creates it)\n",
        ),
        (
            Some(a_status),
            EXIT_LOCAL,
            "",
            "mooringctl: the daemon answered with a reply to another request\n",
        ),
        (
            Some(DaemonReply::SimNetworkAccepted),
            EXIT_LOCAL,
            "",
            "mooringctl: the daemon answered with a reply to another request\n",
        ),
        (
            None,
            EXIT_LOCAL,
            "",
            "mooringctl: the daemon closed the status stream\n",
        ),
    ] {
        // A home short enough for the control socket's path (SUN_LEN).
        let mut harness = harness_with(fixture(|_| {}));
        let state = fs::read(store(&harness).state_path()).unwrap();
        harness.home = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        fs::create_dir_all(harness.support_dir()).unwrap();
        fs::write(store(&harness).state_path(), state).unwrap();
        let paths = crate::daemon::RunPaths::under(&harness.support_dir());
        fs::create_dir_all(&paths.dir).unwrap();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let protocol = encode_line(&ProtocolLine::CURRENT, MAX_REPLY_LINE_BYTES).unwrap();
        let line = reply.map_or_else(Vec::new, |reply| {
            encode_line(&reply, MAX_REPLY_LINE_BYTES).unwrap()
        });
        let daemon = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&protocol).unwrap();
            let mut request = Vec::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_until(b'\n', &mut request)
                .unwrap();
            stream.write_all(&line).unwrap();
            request
        });
        let outcome = harness.run(&["exit", "retry"]);
        assert_eq!(daemon.join().unwrap(), b"\"retry\"\n");
        assert_eq!(outcome.code, code, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, stdout);
        assert_eq!(outcome.stderr, stderr);
    }
}

/// Runs `args` with the support directory's mode set to `mode`, then set
/// back to 0700.
fn with_support_mode(harness: &mut Harness, mode: u32, args: &[&str]) -> super::support::Outcome {
    use std::os::unix::fs::PermissionsExt;

    let support = harness.support_dir();
    fs::set_permissions(&support, fs::Permissions::from_mode(mode)).unwrap();
    let outcome = harness.run(args);
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();
    outcome
}

/// A support directory that cannot be searched or written stops `exit
/// init`: whether a deployment exists cannot be told, or the new state
/// cannot be written. Neither leaves a state behind.
#[test]
fn init_refuses_a_support_directory_it_cannot_use() {
    let mut harness = facing_the_m7();
    let outcome = with_support_mode(&mut harness, 0o000, &INIT);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: cannot inspect {}\n",
            store(&harness).state_path().display()
        )),
        "{}",
        outcome.stderr
    );
    let mut args = INIT.to_vec();
    args.push("--yes");
    let outcome = with_support_mode(&mut harness, 0o500, &args);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state was not changed\n"),
        "{}",
        outcome.stderr
    );
    assert!(!store(&harness).state_path().exists());
}

/// A state that cannot be written stops `exit enable` and `exit
/// record-carrier`, which change nothing.
#[test]
fn a_state_that_cannot_be_written_changes_nothing() {
    let deployment = fixture(|parts| parts.exit.egress_check = None);
    let mut harness = harness_with(deployment);
    // The lock file a first read makes is there, as after any command.
    store(&harness).load().unwrap();
    let before = state_bytes(&harness);
    for args in [
        &["exit", "enable"][..],
        &[
            "exit",
            "record-carrier",
            "--prefix",
            "31.120.0.0/14",
            "--pairing",
            "paired",
            "--yes",
        ],
    ] {
        let outcome = with_support_mode(&mut harness, 0o500, args);
        assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
        assert!(
            outcome
                .stderr
                .starts_with("mooringctl: the state was not changed\n"),
            "{args:?}: {}",
            outcome.stderr
        );
        assert_eq!(state_bytes(&harness), before, "{args:?}");
    }
}

/// A node without a site has no reflector to ask: `exit observe` passes it
/// by.
#[test]
fn observe_passes_a_node_without_a_site_by() {
    let mut harness = observing(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id.as_str() == "ams1")
            .unwrap();
        ams1.lifecycle = mooring_model::node::NodeLifecycle::Planned;
    });
    harness
        .probes
        .borrow_mut()
        .push_back(Ok(Ipv4Addr::new(31, 120, 5, 6)));
    let outcome = harness.run(&["exit", "observe", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "lon1: the reflector sees 31.120.5.6 (inside the recorded carrier prefixes)\n"
    );
    let probed: Vec<String> = harness
        .probed
        .borrow()
        .iter()
        .map(|(_, reflector)| reflector.to_string())
        .collect();
    assert_eq!(probed, ["45.67.89.10:27900"]);
}
