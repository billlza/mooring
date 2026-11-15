// SPDX-License-Identifier: GPL-3.0-or-later

//! What `node apply` allows a node to restart (design §13.6): nothing
//! unless it is given `--restart`; an agent that could not be told is
//! refused before anything is uploaded; and a change that needs a restart
//! says what would restart, and the two ways on.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AgentError, Generation, LineRequest, RequestKind, Response, RestartNeed, Restarts, TxnState,
};

use super::apply::{apply_args, bundle_and_header, ready, run, script_hello_and_blobs};
use super::support::{Answered, Expected, ExpectedRemote, Sent};
use super::user::{fixture, state_bytes};
use crate::error::EXIT_LOCAL;

/// A request of the operations key, through the forced command.
fn ops(kind: RequestKind) -> Expected {
    Expected::Request {
        identity: "ops_ed25519",
        remote: ExpectedRemote::Forced,
        kind,
    }
}

/// What `node apply lon1`, given `extra` arguments, allows a node that
/// serves the bundle already.
fn restarts_sent(extra: &[&str]) -> Restarts {
    let deployment = fixture(|_| {});
    let (mut harness, engines) = ready(deployment.clone());
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        ops(RequestKind::Apply),
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(1),
        })),
    );
    let mut args = apply_args(&engines);
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let outcome = run(&mut harness, &args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let seen = harness.nodes.seen.borrow();
    let Sent::Request(LineRequest::Apply { bundle, restarts }) = &seen[2].1 else {
        panic!("{:?}", seen[2].1);
    };
    assert_eq!(**bundle, header);
    *restarts
}

#[test]
fn node_apply_refuses_restarts_unless_given_restart() {
    assert_eq!(restarts_sent(&[]), Restarts::Refused);
    assert_eq!(restarts_sent(&["--restart"]), Restarts::Allowed);
}

/// An agent of protocol 2 could not decode an `Apply` that says what it
/// may restart: `node apply` refuses it after `Hello`, before anything is
/// uploaded, and names the upgrade.
#[test]
fn an_agent_that_cannot_be_told_what_it_may_restart_is_refused() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    let before = state_bytes(&harness);
    let Response::Hello(mut hello) = super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)) else {
        unreachable!()
    };
    hello.protocol = 2;
    harness.nodes.expect(
        ops(RequestKind::Hello),
        Answered::Replied(Ok(Response::Hello(hello))),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: lon1's agent speaks protocol 2, which cannot be told what an apply may \
         restart (protocol 3): upgrade it first, with `mooringctl node upgrade-agent lon1`; \
         nothing was uploaded or applied\n"
    );
    assert_eq!(harness.nodes.seen.borrow().len(), 1);
    assert_eq!(state_bytes(&harness), before);
}

/// A change that needs a restart is refused on the node with nothing
/// changed: `node apply` says what would restart and the two ways on, and
/// records nothing.
#[test]
fn a_change_that_needs_a_restart_says_what_and_the_ways_on() {
    let deployment = fixture(|_| {});
    let (mut harness, engines) = ready(deployment.clone());
    let before = state_bytes(&harness);
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    let generation = Generation::new(deployment.config_generation().get());
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        ops(RequestKind::Apply),
        Answered::Replied(Ok(Response::TxnLaunched { generation })),
    );
    harness.nodes.expect(
        ops(RequestKind::TxnStatus),
        Answered::Replied(Ok(Response::TxnStatus {
            generation,
            state: TxnState::Failed {
                error: AgentError::RestartNotAllowed {
                    needs: BTreeSet::from([RestartNeed::Nftables, RestartNeed::XrayStopped]),
                },
            },
        })),
    );
    let outcome = run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: generation {} was not applied, and nothing changed on the node: it needs \
             a restart (the ruleset, Xray not running), which this apply does not allow. `node \
             apply` with `--restart` restarts now, and every connection on the node drops for a \
             few seconds; the night's run restarts in its window\n",
            generation.get()
        )
    );
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(state_bytes(&harness), before);
}

/// Every need is named in words.
#[test]
fn every_restart_need_has_its_words() {
    let named: Vec<&str> = RestartNeed::ALL
        .iter()
        .map(|need| crate::error::restart_need_text(*need))
        .collect();
    assert_eq!(
        named,
        [
            "the ruleset",
            "the tunnel",
            "the host profile",
            "an engine upgrade",
            "Xray's configuration",
            "an Xray that serves no HandlerService yet",
            "Xray not running",
            "Hysteria 2's configuration",
        ]
    );
}
