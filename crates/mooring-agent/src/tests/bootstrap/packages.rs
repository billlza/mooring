// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's packages (design §13.2): when `dpkg-query` does not show
//! every one installed (a package it knows only as removed included),
//! `apt-get update` and `install` run without a question. An `apt-get`
//! that fails is reported with its stderr, and a package tool that cannot
//! start stops bootstrap at once, both before the layout is made.

use mooring_agent_proto::{AgentError, IoOp};

use super::world::Host;
use crate::host::Tool;
use crate::tests::ENOENT;

#[test]
fn missing_packages_are_installed_non_interactively() {
    let host = Host::new();
    host.faults.borrow_mut().missing_packages = true;
    let node = host.node();
    host.bootstrap(&node).unwrap();
    let calls = node.calls();
    assert_eq!(
        &calls[1..3],
        [
            "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update -q",
            "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y -q --no-install-recommends wireguard-tools nftables chrony unattended-upgrades curl",
        ]
    );
}

#[test]
fn an_apt_failure_is_reported_with_its_stderr_and_nothing_else_is_done() {
    let host = Host::new();
    {
        let mut faults = host.faults.borrow_mut();
        faults.missing_packages = true;
        faults.apt_fails = true;
    }
    let node = host.node();
    let Err(AgentError::Apt { stderr_tail }) = host.bootstrap(&node) else {
        panic!("not an apt failure");
    };
    assert!(stderr_tail.as_str().contains("Unable to locate package"));
    assert_eq!(node.calls().len(), 3);
    assert!(!host.paths.var_lib().exists());
}

#[test]
fn a_package_dpkg_knows_but_has_not_installed_is_installed() {
    let host = Host::new();
    host.faults.borrow_mut().last_package_removed = true;
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls()
            .iter()
            .any(|call| call.contains("/usr/bin/apt-get install")),
        "curl is only rc"
    );
}

#[test]
fn a_package_tool_that_cannot_start_stops_bootstrap_at_once() {
    let spawn = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    let host = Host::new();
    host.faults.borrow_mut().unstartable = Some(Tool::DpkgQuery);
    let node = host.node();
    assert_eq!(host.bootstrap(&node), Err(spawn.clone()));
    assert_eq!(node.calls().len(), 1);
    let host = Host::new();
    {
        let mut faults = host.faults.borrow_mut();
        faults.missing_packages = true;
        faults.unstartable = Some(Tool::AptGet);
    }
    let node = host.node();
    assert_eq!(host.bootstrap(&node), Err(spawn));
    assert_eq!(node.calls().len(), 2, "dpkg-query, then apt-get update");
    assert!(!host.paths.var_lib().exists());
}
