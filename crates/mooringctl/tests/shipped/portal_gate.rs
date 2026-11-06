// SPDX-License-Identifier: GPL-3.0-or-later

// `mooringctl` runs its commands only on macOS; elsewhere it only says so.
#![cfg(target_os = "macos")]

//! The built binary refuses both portal exports while the agreement it
//! ships does not cover the portal (design §9.5): `main` passes
//! `PortalAgreement::SHIPPED`, which is closed. Opening the gate for real
//! changes this test with the new revision of the agreement.

use std::process::Command;

/// What both commands print when the gate is closed.
const REFUSAL: &str = "mooringctl: no file was written: nothing goes to the portal before a revision of the user agreement covers it and the users accept that revision (docs/runbooks/user-agreement.md)\n  caused by: agreement revision 1, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links\n";

/// With an empty home, so the refusal must come before any state is read,
/// each command exits 1, prints the gate's refusal and creates no file.
#[test]
fn the_built_binary_refuses_both_portal_exports() {
    let home = tempfile::tempdir().unwrap();
    let out = home.path().join("portal.json");
    let path = out.to_str().unwrap();
    for args in [
        vec!["portal", "export", "--user", "aaaaaaaaaa", "--out", path],
        vec!["user", "export-profiles", "--out", path],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mooringctl"))
            .args(&args)
            .env("HOME", home.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "", "{args:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            REFUSAL,
            "{args:?}"
        );
        assert!(!out.exists(), "{args:?}");
    }
}
