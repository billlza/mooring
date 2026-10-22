// SPDX-License-Identifier: GPL-3.0-or-later

//! `ci`: the L0 static and L1 unit gates, in order, stopping at the first failure.
//!
//! The in-process checks (graph-check, kinds-coverage, deny-skips,
//! acceptance) run before the tests, so a broken edge table or contract file
//! fails with its own typed diagnostic rather than first as a test failure.

use std::io::Write;

use crate::XtaskError;
use crate::acceptance::{self, Gate};
use crate::app;
use crate::cargo::Cargo;
use crate::output::say;
use crate::{deny_skips, graph_check, kinds};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Cargo(&'static [&'static str]),
    GraphCheck,
    KindsCoverage,
    DenySkips,
    Acceptance,
    SwiftTests,
}

/// `cargo deny` runs with `-D warnings` so its warn-level diagnostics (for
/// example an allowed licence nothing uses) fail the gate (design §6.2, §16).
const STEPS: &[Step] = &[
    Step::Cargo(&["fmt", "--all", "--check"]),
    Step::Cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]),
    Step::Cargo(&[
        "deny",
        "--all-features",
        "--locked",
        "check",
        "-D",
        "warnings",
    ]),
    Step::GraphCheck,
    Step::KindsCoverage,
    Step::DenySkips,
    Step::Acceptance,
    Step::Cargo(&["nextest", "run", "--workspace", "--locked"]),
    Step::Cargo(&["test", "--workspace", "--doc", "--locked"]),
    Step::SwiftTests,
];

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), XtaskError> {
    for (index, step) in STEPS.iter().enumerate() {
        let label = match step {
            Step::Cargo(args) => format!("cargo {}", args.join(" ")),
            Step::GraphCheck => "cargo xtask graph-check".to_owned(),
            Step::KindsCoverage => "cargo xtask kinds-coverage".to_owned(),
            Step::DenySkips => "cargo xtask deny-skips".to_owned(),
            Step::Acceptance => "cargo xtask acceptance".to_owned(),
            Step::SwiftTests => "xcrun swift test (MooringKit, macOS only)".to_owned(),
        };
        say!(out, "==> [{}/{}] {label}", index + 1, STEPS.len())?;
        out.flush().map_err(crate::output::OutputError)?;
        match step {
            Step::Cargo(args) => cargo.run(args)?,
            Step::GraphCheck => graph_check::run(cargo, out)?,
            Step::KindsCoverage => kinds::run(cargo, out)?,
            Step::DenySkips => deny_skips::run(cargo, out)?,
            Step::Acceptance => acceptance::run(cargo, out, Gate::Recorded)?,
            Step::SwiftTests => app::swift_tests(cargo, out)?,
        }
    }
    say!(out, "ci: all {} steps passed", STEPS.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{STEPS, Step};

    /// The gates run in this order: the static checks, the in-process
    /// checks, the Rust tests, and last MooringKit's tests, the console
    /// contract's other side.
    #[test]
    fn the_gates_end_with_the_swift_tests() {
        assert_eq!(STEPS.len(), 10);
        assert_eq!(STEPS[0], Step::Cargo(&["fmt", "--all", "--check"]));
        assert_eq!(
            STEPS[7],
            Step::Cargo(&["nextest", "run", "--workspace", "--locked"])
        );
        assert_eq!(STEPS.last(), Some(&Step::SwiftTests));
        assert_eq!(
            STEPS
                .iter()
                .filter(|step| **step == Step::SwiftTests)
                .count(),
            1
        );
    }
}
