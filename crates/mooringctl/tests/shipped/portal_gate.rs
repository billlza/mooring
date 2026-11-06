// SPDX-License-Identifier: GPL-3.0-or-later

// `mooringctl` runs its commands only on macOS; elsewhere it only says so.
#![cfg(target_os = "macos")]

//! The built binary passes both portal exports the gate it ships (design
//! §9.5): `main` passes `PortalAgreement::SHIPPED`. While that is closed,
//! both commands refuse before reading anything; once a revision of the
//! agreement covers the portal, they pass the gate and go on to read the
//! state.

use std::process::Command;

use mooring_model::{AgreementVersion, PortalAgreement};

/// What both commands print while the gate is closed.
fn refusal() -> String {
    format!(
        "mooringctl: no file was written: nothing goes to the portal before a revision of the user agreement covers it and the users accept that revision (docs/runbooks/user-agreement.md)\n  caused by: agreement revision {}, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links\n",
        AgreementVersion::CURRENT
    )
}

/// With an empty home, each command exits 1 and creates no file: refused
/// by the gate if the shipped gate is closed, and otherwise refused for the
/// state that an empty home lacks, past the gate.
#[test]
fn the_built_binary_passes_the_gate_it_ships() {
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("portal.json");
    let path = out.to_str().unwrap();
    for args in [
        vec!["portal", "export", "--user", "aaaaaaaaaa", "--out", path],
        vec![
            "user",
            "export-profiles",
            "--user",
            "aaaaaaaaaa",
            "--out",
            path,
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mooringctl"))
            .args(&args)
            .env("HOME", home.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "", "{args:?}");
        if PortalAgreement::SHIPPED.required().is_ok() {
            assert!(
                stderr.starts_with("mooringctl: no state at "),
                "{args:?}: {stderr}"
            );
        } else {
            assert_eq!(stderr, refusal(), "{args:?}");
        }
        assert!(!out.exists(), "{args:?}");
    }
}
