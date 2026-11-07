// SPDX-License-Identifier: GPL-3.0-or-later

// `mooringctl` runs its commands only on macOS; elsewhere it only says so.
#![cfg(target_os = "macos")]

//! The built binary passes both portal exports the gate it ships (design
//! §9.5): `main` passes `PortalAgreement::SHIPPED`, which revision 2 of the
//! agreement opened and no later revision closes. So both commands pass the
//! gate and go on to read the state.

use std::process::Command;

use mooring_model::{AgreementVersion, PortalAgreement};

/// With an empty home, each command exits 1 and creates no file: past the
/// gate, it is refused for the state that an empty home lacks. A binary
/// that passed a closed gate would refuse with the gate's message instead.
#[test]
fn the_built_binary_passes_the_gate_it_ships() {
    assert_eq!(
        PortalAgreement::SHIPPED.required(),
        Ok(AgreementVersion::CURRENT)
    );
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
        assert!(
            stderr.starts_with("mooringctl: no state at "),
            "{args:?}: {stderr}"
        );
        assert!(!out.exists(), "{args:?}");
    }
}
