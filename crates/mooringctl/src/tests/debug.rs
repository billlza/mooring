// SPDX-License-Identifier: GPL-3.0-or-later

//! The hand-written `Debug` output of types that hold a credential or a
//! process: what each shows, and that a cookie's value never reaches it.

use std::io;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use mooring_model::ipv4::PublicIpv4;

use super::support::{FakeLink, TEST_TIMEOUTS, lo0};
use crate::node::NodeError;
use crate::node::dial::M7Egress;
use crate::node::ssh::{Remote, SshAgent, SshTarget};
use crate::router::RouterEnv;
use crate::router::cookies::parse_set_cookie;
use crate::runtime::power::PowerLink;

/// A cookie's value is a session credential: its debug output names the
/// cookie and redacts the value.
#[test]
fn a_cookie_s_value_never_reaches_its_debug_output() {
    let cookie = parse_set_cookie(b"sessionId=COOKIE-secret-81ae47; path=/; HttpOnly").unwrap();
    assert_eq!(
        format!("{cookie:?}"),
        "Cookie { name: \"sessionId\", value: \"<redacted>\" }"
    );
}

/// The router's environment shows its port and limits, not its link.
#[test]
fn the_router_environment_shows_its_port_and_limits() {
    let link = FakeLink::pinned();
    let env = RouterEnv {
        link: &link,
        port: 80,
        timeouts: TEST_TIMEOUTS,
    };
    assert_eq!(
        format!("{env:?}"),
        format!("RouterEnv {{ port: 80, timeouts: {TEST_TIMEOUTS:?}, .. }}")
    );
}

/// A power link shows its helper's process, if it has one.
#[test]
fn a_power_link_shows_its_helper_s_process() {
    let (_events, messages) = mpsc::channel();
    let link = PowerLink::new(messages, Box::new(io::sink()), None);
    assert_eq!(format!("{link:?}"), "PowerLink { child: None, .. }");
}

/// An ssh agent shows its target, not how it connects.
#[test]
fn an_ssh_agent_shows_its_target() {
    let target = SshTarget {
        address: PublicIpv4::new("45.67.89.10".parse().unwrap()).unwrap(),
        identity: PathBuf::from("/s/ssh/lon1/ops_ed25519"),
        known_hosts: PathBuf::from("/s/ssh/lon1/known_hosts"),
        egress: M7Egress::for_tests(lo0()),
        relay_dir: PathBuf::from("/s/ssh/lon1"),
        mooringctl: PathBuf::from("/Applications/Mooring.app/Contents/MacOS/mooringctl"),
        remote: Remote::ForcedCommand,
        deadline: None,
    };
    let connect = |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        Err(NodeError::Connect(io::Error::from(
            io::ErrorKind::ConnectionRefused,
        )))
    };
    let agent = SshAgent {
        target: target.clone(),
        connect: &connect,
    };
    assert_eq!(
        format!("{agent:?}"),
        format!("SshAgent {{ target: {target:?}, .. }}")
    );
}
