// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the kernel interfaces (design §16 L1): routing, neighbour and
//! interface-list messages built byte by byte, the live tables of this Mac
//! checked against the system's own tools, the open-files limit, and the
//! echo guard on a pseudo-terminal. None needs root, and none sends a
//! packet except one datagram on lo0, to see its counter move.

use std::ffi::OsStr;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod configd;
mod errors;
mod iflist;
mod limits;
mod live;
mod messages;
mod process;
mod sysctl;
mod terminal;

/// How long a child test may run before it is ended and its test fails.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// This test binary run again for `test` alone, with `variable` set to
/// `value` and its output uncaptured: how a test runs what must not happen
/// in its own process (pointing its standard error elsewhere, lowering its
/// open-files limit, leaving its session). Run without the variable, as the
/// whole suite runs it, the child test does nothing.
///
/// Returns the child's output once it has run exactly that test; a renamed
/// test would otherwise run none and pass. A child still running after
/// [`CHILD_DEADLINE`] is ended and the test fails, since one that left its
/// session is out of the reach of the runner's own timeout.
fn run_child(test: &str, variable: &str, value: impl AsRef<OsStr>) -> Output {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(variable, value)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + CHILD_DEADLINE;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("{test} was still running:\n{}", described(&output));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "{test} did not run alone:\n{}",
        described(&output)
    );
    output
}

/// Asserts that the child test `test` passed.
fn assert_passed(test: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{test} failed:\n{}",
        described(output)
    );
}

/// A child's exit status and output, for a failure message.
fn described(output: &Output) -> String {
    format!(
        "{}\n--- stdout\n{}--- stderr\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
