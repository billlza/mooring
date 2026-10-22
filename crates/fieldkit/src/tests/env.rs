// SPDX-License-Identifier: GPL-3.0-or-later

//! `env` on this Mac's loopback interface, the subnet arithmetic, and the
//! comparison of two runs. Failure messages never print a link-layer
//! address.

use std::net::Ipv4Addr;

use crate::error::FieldkitError;
use crate::measure::env::{compare_with, lan_subnet, run};
use crate::output::Output;

#[test]
fn the_subnet_is_the_network_of_a_lan_address() {
    let subnet = |addr: [u8; 4], len| {
        lan_subnet(Ipv4Addr::from(addr), len).map(|subnet| subnet.get().to_string())
    };
    assert_eq!(subnet([192, 168, 1, 60], 24).unwrap(), "192.168.1.0/24");
    assert_eq!(subnet([10, 249, 78, 65], 16).unwrap(), "10.249.0.0/16");
    assert_eq!(subnet([172, 16, 5, 9], 30).unwrap(), "172.16.5.8/30");
    assert_eq!(subnet([192, 168, 1, 60], 32).unwrap(), "192.168.1.60/32");
    assert!(subnet([92, 40, 201, 97], 24).is_err(), "a public address");
    assert!(
        subnet([192, 168, 1, 60], 0).is_err(),
        "the whole address space"
    );
}

#[test]
fn env_lists_lo0_and_describes_it_without_selectors() {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let summary = run(
        Some("lo0"),
        None,
        &mut Output::new(&mut stdout, &mut stderr),
    )
    .unwrap();
    assert!(
        summary
            .interfaces
            .iter()
            .any(|interface| interface.name == "lo0")
    );
    let bound = summary.bound.unwrap();
    assert_eq!(bound.name, "lo0");
    assert_eq!(bound.lladdr, None);
    assert!(bound.selectors.is_empty());
    assert!(
        bound
            .problems
            .iter()
            .any(|problem| problem.contains("no six-byte link-layer address")),
        "{:?}",
        bound.problems
    );
    let line: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(line["measure"], "env");
    assert!(line.get("compared").is_none());
}

#[test]
fn env_compares_with_an_earlier_run() {
    let scratch = tempfile::tempdir().unwrap();
    let earlier = scratch.path().join("earlier.json");
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let first = run(
        Some("lo0"),
        None,
        &mut Output::new(&mut stdout, &mut stderr),
    )
    .unwrap();
    std::fs::write(&earlier, &stdout).unwrap();
    let (mut again, mut stderr) = (Vec::new(), Vec::new());
    run(
        Some("lo0"),
        Some(&earlier),
        &mut Output::new(&mut again, &mut stderr),
    )
    .unwrap();
    let line: serde_json::Value = serde_json::from_slice(&again).unwrap();
    assert_eq!(line["compared"]["name"], true);
    assert_eq!(line["compared"]["lladdr"], false, "lo0 has none to match");
    let unbound = run(
        None,
        None,
        &mut Output::new(&mut Vec::new(), &mut Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        compare_with(&unbound, &first),
        Err(FieldkitError::Input { .. })
    ));
    assert!(matches!(
        compare_with(&first, &unbound),
        Err(FieldkitError::Input { .. })
    ));
}

#[test]
fn env_refuses_an_unknown_interface_and_a_bad_earlier_file() {
    let mut sink = (Vec::new(), Vec::new());
    let output = &mut Output::new(&mut sink.0, &mut sink.1);
    assert!(matches!(
        run(Some("zz9"), None, output),
        Err(FieldkitError::Interface { .. })
    ));
    let scratch = tempfile::tempdir().unwrap();
    let empty = scratch.path().join("empty.json");
    std::fs::write(&empty, "\n").unwrap();
    let garbage = scratch.path().join("garbage.json");
    std::fs::write(&garbage, "{\"measure\":1}\n").unwrap();
    for path in [&empty, &garbage, &scratch.path().join("absent.json")] {
        assert!(
            matches!(
                run(Some("lo0"), Some(path), output),
                Err(FieldkitError::Input { .. })
            ),
            "{}",
            path.display()
        );
    }
}
