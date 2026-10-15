// SPDX-License-Identifier: GPL-3.0-or-later

//! `router pin`: the gateway's link-layer address, recorded only when
//! confirmed, never over a different pin without `--replace`, and resolved
//! with one connection that sends nothing when the neighbour table has no
//! address for the gateway yet or is empty. The table is read as hidden
//! from the binary only when it was empty both before and after that
//! connection reached the gateway, and the placeholder address is never
//! pinned.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use mooring_macsys::MacsysError;
use mooring_model::iface::MacAddr;
use mooring_model::time::UnixTime;
use mooring_store::{ROUTER_PIN_FILE, RouterPin, read_router_pin};

use super::stub::{Received, Stub};
use super::support::{
    FakeLink, HIDDEN_TABLE, Harness, NOW, OTHER, PINNED, PLACEHOLDER, PLACEHOLDER_FOUND,
    RefusingPort,
};
use crate::prompt::Answer;

const PIN: &[&str] = &["router", "pin", "--interface", "lo0"];

const PIN_YES: &[&str] = &["router", "pin", "--interface", "lo0", "--yes"];

/// What `router pin` prints when the table has no address for the gateway
/// after a warm-up connection that succeeded.
const UNRESOLVED: &str = "mooringctl: the M7 is unreachable: the gateway's link-layer address is not in the neighbour table\n";

/// What it prints when the warm-up connection was refused.
const REFUSED: &str = "mooringctl: the M7 is unreachable: connecting failed (connection refused)\n";

/// A kernel table that cannot be read.
const SYSCTL_FAILED: MacsysError = MacsysError::Sysctl { errno: 1 };

/// What it prints for [`SYSCTL_FAILED`].
const KERNEL_FAILED: &str = "mooringctl: reading the kernel's network tables failed\n  caused by: sysctl failed with errno 1\n";

/// The one warm-up connection, which sends nothing.
fn one_empty_connection() -> [Received; 1] {
    [Received(Vec::new())]
}

fn pinned(harness: &Harness) -> Option<RouterPin> {
    read_router_pin(&harness.support_dir()).unwrap()
}

fn pin_of(lladdr: [u8; 6], at: u64) -> RouterPin {
    RouterPin {
        gateway_lladdr: MacAddr::from_bytes(lladdr).unwrap(),
        pinned_at: UnixTime::from_secs(at),
    }
}

#[test]
fn pin_requires_confirmation_and_replace() {
    let mut harness = Harness::new(9);
    // Declined, or no terminal and no --yes: nothing is written.
    harness
        .console
        .answers
        .extend([Answer::No, Answer::NoTerminal]);
    let outcome = harness.run(PIN);
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "interface lo0: gateway 127.0.0.1, link-layer address 02:00:5e:10:20:30\n"
    );
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: the answer was not yes\n"
    );
    let outcome = harness.run(PIN);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: no terminal to ask and --yes was not given\n"
    );
    assert_eq!(pinned(&harness), None);
    assert!(!harness.support_dir().exists(), "nothing was created");
    assert_eq!(
        harness.console.asked,
        ["Record this link-layer address as the M7's identity?"; 2]
    );
    // Confirmed at the terminal: written, in a 0700 directory, mode 0600.
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(PIN);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
    let file = harness.support_dir().join(ROUTER_PIN_FILE);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(harness.support_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(outcome.stdout.ends_with(&format!(
        "pinned as the M7's identity in {}\n",
        file.display()
    )));
    // A different gateway is refused without --replace...
    harness.link = FakeLink::answering(&[Ok(OTHER)]);
    let outcome = harness.run(PIN_YES);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the M7's identity is already pinned as 02:00:5e:10:20:30; rerun with --replace to replace it\n"
    );
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
    // ...and replaced with it.
    let outcome = harness.run(&["router", "pin", "--interface", "lo0", "--yes", "--replace"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(pinned(&harness), Some(pin_of(OTHER, NOW)));
    assert_eq!(harness.console.asked.len(), 3, "--yes asks nothing");
}

#[test]
fn an_identical_pin_is_not_rewritten() {
    let mut harness = Harness::new(9);
    harness.pin(PINNED);
    let file = harness.support_dir().join(ROUTER_PIN_FILE);
    let before = fs::read(&file).unwrap();
    let outcome = harness.run(&["router", "pin", "--interface", "lo0", "--yes", "--replace"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .ends_with("already pinned; nothing was written\n")
    );
    assert_eq!(fs::read(&file).unwrap(), before);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW - 60)));
}

/// A first read that finds an address decides at once: the table is read
/// once and no connection is made.
#[test]
fn an_address_in_the_first_read_needs_no_connection() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[Ok(PINNED)]);
    let outcome = harness.run(PIN_YES);
    let received = stub.finish();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(received, [], "no connection");
    assert_eq!(harness.link.neighbour_calls.get(), 1);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
}

/// A first read the kernel fails is that failure, with no connection made
/// and nothing recorded.
#[test]
fn a_kernel_failure_of_the_first_read_makes_no_connection() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[Err(SYSCTL_FAILED)]);
    let outcome = harness.run(PIN_YES);
    let received = stub.finish();
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, KERNEL_FAILED);
    assert_eq!(received, [], "no connection");
    assert_eq!(harness.link.neighbour_calls.get(), 1);
    assert_eq!(pinned(&harness), None);
    assert!(!harness.support_dir().exists(), "nothing was created");
}

#[test]
fn pin_resolves_a_missing_gateway_entry_with_one_empty_connection() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourAbsent), Ok(PINNED)]);
    let outcome = harness.run(PIN_YES);
    let received = stub.finish();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(received, one_empty_connection());
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
}

#[test]
fn an_unresolvable_gateway_is_not_pinned() {
    // The connection succeeds but the table still has no address.
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourIncomplete)]);
    let outcome = harness.run(PIN_YES);
    assert_eq!(stub.finish(), one_empty_connection());
    assert_eq!(outcome.code, 4, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, UNRESOLVED);
    // The connection fails: its failure is the error.
    let refusing = RefusingPort::new();
    harness.port = refusing.port();
    let outcome = harness.run(PIN_YES);
    assert_eq!(outcome.code, 4, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, REFUSED);
    assert_eq!(pinned(&harness), None);
    // An address that cannot identify a device is not pinned.
    for answer in [
        Ok([0x01, 0, 0x5e, 0, 0, 1]),
        Err(MacsysError::NotEthernet { alen: 0x14 }),
        Err(MacsysError::AmbiguousNeighbour),
    ] {
        harness.link = FakeLink::answering(&[answer]);
        let outcome = harness.run(PIN_YES);
        assert_eq!(outcome.code, 7, "{}", outcome.stderr);
        assert!(
            outcome.stderr.contains("the gateway has"),
            "{}",
            outcome.stderr
        );
    }
    assert_eq!(pinned(&harness), None);
}

/// An empty table may only be cold, so it is warmed like a missing entry:
/// one connection that sends nothing, then a second read, which pins the
/// address it finds.
#[test]
fn the_warm_up_rescues_an_empty_table() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourTableEmpty), Ok(PINNED)]);
    let outcome = harness.run(PIN_YES);
    let received = stub.finish();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(received, one_empty_connection());
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
}

/// A table empty both before and after a warm-up connection that reached
/// the gateway is read as one the kernel hides from this binary (design
/// §15.6 rule 10): the local error naming the cause, after exactly that one
/// connection, and nothing recorded.
#[test]
fn a_table_empty_before_and_after_a_successful_warm_up_is_hidden() {
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&[
        Err(MacsysError::NeighbourTableEmpty),
        Err(MacsysError::NeighbourTableEmpty),
    ]);
    let outcome = harness.run(PIN_YES);
    let received = stub.finish();
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, HIDDEN_TABLE);
    assert_eq!(received, one_empty_connection());
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), None);
    assert!(!harness.support_dir().exists(), "nothing was created");
}

/// A first read that was not empty showed that this binary can read the
/// table, so an empty read after a warm-up that succeeded is no hidden
/// table but a gateway with no address (`GatewayUnresolved`, exit 4), as
/// is an empty first read followed by one without the entry.
#[test]
fn one_empty_read_around_a_successful_warm_up_is_an_unresolved_gateway() {
    for (first, second) in [
        (
            MacsysError::NeighbourAbsent,
            MacsysError::NeighbourTableEmpty,
        ),
        (
            MacsysError::NeighbourIncomplete,
            MacsysError::NeighbourTableEmpty,
        ),
        (
            MacsysError::NeighbourTableEmpty,
            MacsysError::NeighbourAbsent,
        ),
    ] {
        let stub = Stub::start(Vec::new());
        let mut harness = Harness::new(stub.port());
        harness.link = FakeLink::answering(&[Err(first), Err(second)]);
        let outcome = harness.run(PIN_YES);
        let received = stub.finish();
        assert_eq!(outcome.code, 4, "{first:?}, {second:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, UNRESOLVED);
        assert_eq!(received, one_empty_connection(), "{first:?}, {second:?}");
        assert_eq!(harness.link.neighbour_calls.get(), 2);
        assert_eq!(pinned(&harness), None);
        assert!(!harness.support_dir().exists(), "nothing was created");
    }
}

/// When the table still has no address for the gateway after a warm-up
/// connection that failed (here refused: the port answered with a reset),
/// that failure is the error, whichever read was empty: the warm-up failed,
/// so an empty table is not blamed on signing.
#[test]
fn an_empty_table_with_a_refused_warm_up_is_the_connection_failure() {
    let refusing = RefusingPort::new();
    for script in [
        [
            Err(MacsysError::NeighbourTableEmpty),
            Err(MacsysError::NeighbourTableEmpty),
        ],
        [
            Err(MacsysError::NeighbourAbsent),
            Err(MacsysError::NeighbourTableEmpty),
        ],
        [
            Err(MacsysError::NeighbourTableEmpty),
            Err(MacsysError::NeighbourAbsent),
        ],
    ] {
        let mut harness = Harness::new(refusing.port());
        harness.link = FakeLink::answering(&script);
        let outcome = harness.run(PIN_YES);
        assert_eq!(outcome.code, 4, "{script:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, REFUSED, "{script:?}");
        assert_eq!(harness.link.neighbour_calls.get(), 2);
        assert_eq!(pinned(&harness), None);
        assert!(!harness.support_dir().exists(), "nothing was created");
    }
}

/// An address the read after a failed warm-up finds is pinned as one the
/// first read finds would be: the operator's confirmation is the
/// safeguard.
#[test]
fn an_address_found_after_a_refused_warm_up_is_pinned() {
    let refusing = RefusingPort::new();
    let mut harness = Harness::new(refusing.port());
    harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourAbsent), Ok(PINNED)]);
    let outcome = harness.run(PIN_YES);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "interface lo0: gateway 127.0.0.1, link-layer address 02:00:5e:10:20:30\npinned as the M7's identity in {}\n",
            harness.support_dir().join(ROUTER_PIN_FILE).display()
        )
    );
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), Some(pin_of(PINNED, NOW)));
}

/// A kernel failure of the read after the warm-up is the error, and takes
/// precedence over a warm-up connection that failed.
#[test]
fn a_kernel_failure_of_the_second_read_is_the_error() {
    let script = [Err(MacsysError::NeighbourAbsent), Err(SYSCTL_FAILED)];
    let stub = Stub::start(Vec::new());
    let mut harness = Harness::new(stub.port());
    harness.link = FakeLink::answering(&script);
    let outcome = harness.run(PIN_YES);
    assert_eq!(stub.finish(), one_empty_connection());
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, KERNEL_FAILED);
    let refusing = RefusingPort::new();
    let mut harness = Harness::new(refusing.port());
    harness.link = FakeLink::answering(&script);
    let outcome = harness.run(PIN_YES);
    assert_eq!(outcome.code, 1, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, KERNEL_FAILED);
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), None);
}

/// The placeholder Apple's iOS reports in place of a real address is a
/// valid unicast address, but every network would match it: it is never
/// pinned, whether the first read finds it, or the read after a warm-up
/// that succeeded or failed.
#[test]
fn the_privacy_placeholder_is_never_pinned() {
    let refused = format!(
        "mooringctl: the device is not a supported M7: the gateway has {PLACEHOLDER_FOUND}\n"
    );
    for (script, connections) in [
        (vec![Ok(PLACEHOLDER)], 0),
        (vec![Err(MacsysError::NeighbourAbsent), Ok(PLACEHOLDER)], 1),
    ] {
        let stub = Stub::start(Vec::new());
        let mut harness = Harness::new(stub.port());
        harness.link = FakeLink::answering(&script);
        let outcome = harness.run(PIN_YES);
        assert_eq!(stub.finish().len(), connections, "{script:?}");
        assert_eq!(outcome.code, 7, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, refused);
        assert_eq!(pinned(&harness), None);
        assert!(!harness.support_dir().exists(), "nothing was created");
    }
    let refusing = RefusingPort::new();
    let mut harness = Harness::new(refusing.port());
    harness.link = FakeLink::answering(&[Err(MacsysError::NeighbourTableEmpty), Ok(PLACEHOLDER)]);
    let outcome = harness.run(PIN_YES);
    assert_eq!(outcome.code, 7, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, refused);
    assert_eq!(harness.link.neighbour_calls.get(), 2);
    assert_eq!(pinned(&harness), None);
    assert!(!harness.support_dir().exists(), "nothing was created");
}
