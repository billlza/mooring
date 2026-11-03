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
    /// `cargo <args>`, giving every rustdoc it runs `rustdocflags` as its
    /// extra flags, whatever the environment or a cargo config says.
    CargoWithRustdocFlags {
        rustdocflags: &'static str,
        args: &'static [&'static str],
    },
    GraphCheck,
    KindsCoverage,
    DenySkips,
    Acceptance,
    SwiftTests,
}

/// `cargo deny` runs with `-D warnings` so its warn-level diagnostics (for
/// example an allowed licence nothing uses) fail the gate. So does rustdoc,
/// through `RUSTDOCFLAGS`, so that every warning it gives fails it too,
/// such as a public doc linking a private item or a link that resolves to
/// nothing (design §6.2, §16).
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
    Step::CargoWithRustdocFlags {
        rustdocflags: "-D warnings",
        args: &["doc", "--workspace", "--no-deps", "--locked"],
    },
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
        say!(out, "==> [{}/{}] {}", index + 1, STEPS.len(), label(step))?;
        out.flush().map_err(crate::output::OutputError)?;
        run_step(cargo, *step, out)?;
    }
    say!(out, "ci: all {} steps passed", STEPS.len())?;
    Ok(())
}

fn run_step(cargo: &Cargo, step: Step, out: &mut impl Write) -> Result<(), XtaskError> {
    match step {
        Step::Cargo(args) => cargo.run(args)?,
        Step::CargoWithRustdocFlags { rustdocflags, args } => {
            cargo.run_with_rustdocflags(rustdocflags, args)?;
        }
        Step::GraphCheck => graph_check::run(cargo, out)?,
        Step::KindsCoverage => kinds::run(cargo, out)?,
        Step::DenySkips => deny_skips::run(cargo, out)?,
        Step::Acceptance => acceptance::run(cargo, out, Gate::Recorded)?,
        Step::SwiftTests => app::swift_tests(cargo, out)?,
    }
    Ok(())
}

/// The line that announces `step`: the command it stands for.
fn label(step: &Step) -> String {
    match step {
        Step::Cargo(args) => format!("cargo {}", args.join(" ")),
        Step::CargoWithRustdocFlags { rustdocflags, args } => {
            format!("RUSTDOCFLAGS={rustdocflags:?} cargo {}", args.join(" "))
        }
        Step::GraphCheck => "cargo xtask graph-check".to_owned(),
        Step::KindsCoverage => "cargo xtask kinds-coverage".to_owned(),
        Step::DenySkips => "cargo xtask deny-skips".to_owned(),
        Step::Acceptance => "cargo xtask acceptance".to_owned(),
        Step::SwiftTests => "xcrun swift test (MooringKit, macOS only)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{STEPS, Step, label, run_step};
    use crate::XtaskError;
    use crate::cargo::{Cargo, CommandError};
    use crate::testing::workspace_root;

    /// The gates run in this order: the static checks, the in-process
    /// checks, the Rust tests, and last MooringKit's tests, the console
    /// contract's other side.
    #[test]
    fn the_gates_end_with_the_swift_tests() {
        assert_eq!(STEPS.len(), 11);
        assert_eq!(STEPS[0], Step::Cargo(&["fmt", "--all", "--check"]));
        assert_eq!(
            STEPS[8],
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

    /// The doc build is the one step that sets rustdoc's flags, to
    /// `-D warnings`, so every warning rustdoc gives fails it. It comes
    /// right after clippy, which has checked that the code compiles, and
    /// its line says how to run it by hand.
    #[test]
    fn every_rustdoc_warning_fails_the_doc_build() {
        let doc = Step::CargoWithRustdocFlags {
            rustdocflags: "-D warnings",
            args: &["doc", "--workspace", "--no-deps", "--locked"],
        };
        assert!(matches!(STEPS[1], Step::Cargo(["clippy", ..])));
        assert_eq!(STEPS[2], doc);
        assert_eq!(
            STEPS
                .iter()
                .filter(|step| matches!(step, Step::CargoWithRustdocFlags { .. }))
                .count(),
            1
        );
        assert_eq!(
            label(&doc),
            r#"RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked"#
        );
    }

    /// Each step announces the command it stands for, in this order.
    #[test]
    fn every_step_announces_its_command() {
        assert_eq!(
            STEPS.iter().map(label).collect::<Vec<_>>(),
            [
                "cargo fmt --all --check",
                "cargo clippy --workspace --all-targets --locked -- -D warnings",
                r#"RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked"#,
                "cargo deny --all-features --locked check -D warnings",
                "cargo xtask graph-check",
                "cargo xtask kinds-coverage",
                "cargo xtask deny-skips",
                "cargo xtask acceptance",
                "cargo nextest run --workspace --locked",
                "cargo test --workspace --doc --locked",
                "xcrun swift test (MooringKit, macOS only)",
            ]
        );
    }

    /// Such a step runs cargo with its flags: a shell stands in for cargo
    /// and exits 0 only when `RUSTDOCFLAGS` holds exactly them. A cargo
    /// step that fails stops `ci` with its command's error.
    #[test]
    fn a_step_runs_cargo_with_its_rustdoc_flags() {
        let shell = Cargo::stand_in(PathBuf::from("/bin/sh"), workspace_root());
        let step = Step::CargoWithRustdocFlags {
            rustdocflags: "--cfg xtask_ci_step",
            args: &["-c", r#"test "$RUSTDOCFLAGS" = "--cfg xtask_ci_step""#],
        };
        let mut out = Vec::new();
        run_step(&shell, step, &mut out).unwrap();
        let error = run_step(&shell, Step::Cargo(&["-c", "exit 3"]), &mut out).unwrap_err();
        assert!(
            matches!(
                &error,
                XtaskError::Command(CommandError::Failed { command, status })
                    if command == "-c exit 3" && status.code() == Some(3)
            ),
            "{error:?}"
        );
        assert!(out.is_empty());
    }
}
