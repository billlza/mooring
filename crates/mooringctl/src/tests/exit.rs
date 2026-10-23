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
use mooring_model::{CalendarDate, CycleRule, DeploymentInit, PeriodDays};

use super::support::{Harness, PINNED};
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
        "mooringctl: the carrier check is recorded already; replacing it is a configuration change, which this build does not make\n"
    );
    assert_eq!(state_bytes(&harness), before);
    assert_eq!(harness.console.asked.len(), 1);
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
