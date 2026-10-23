// SPDX-License-Identifier: GPL-3.0-or-later

//! `Hello`: every host fact read as the design names it from a node's
//! files and tools, each unreadable or ambiguous fact refused by name, and
//! sshd drift compared as multisets.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AcceptLocal, AgentError, Arch, HostFact, HostProfile, HostProfileVersion, IfName, IoOp,
    KernelIdent, KernelRelease, PROTOCOL, PortRange, SshdDirective,
};

use super::{FakeNode, failed, ok, scratch};
use crate::blobs::digest_of;
use crate::hello::{arch, client_ip, hello, host_facts, mismatches_in};
use crate::host::Tool;
use crate::paths::Paths;
use crate::store::write_json;

const ROUTE: &str = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t01F67EB0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
eth0\t00F67EB0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";

const IP_ADDR: &str = r#"[{"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.203","prefixlen":24,"scope":"global"}]}]"#;

/// `sshd -T` as Debian prints it with the profile in force, plus lines
/// for directives the profile does not set.
fn sshd_t(profile: &HostProfile) -> String {
    let mut lines = vec!["port 22".to_owned(), "usepam yes".to_owned()];
    for directive in SshdDirective::ALL {
        lines.extend(profile.sshd_effective_lines(*directive));
    }
    lines.join("\n") + "\n"
}

/// A node root holding every file `Hello` reads.
fn node_root(paths: &Paths) {
    let write = |path: &str, text: &str| {
        let path = paths.at(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write("/proc/net/route", ROUTE);
    write("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n");
    write("/proc/sys/kernel/osrelease", "6.12.113+deb13-cloud-amd64\n");
    write("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n");
    write("/proc/sys/net/core/default_qdisc", "fq\n");
    write(
        "/etc/os-release",
        "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n",
    );
    write("/proc/self/exe", "the agent binary");
    write_json(&paths.host_profile(), &HostProfile::CURRENT.version, 0o640).unwrap();
}

fn node() -> FakeNode {
    FakeNode::answering(
        0,
        Box::new(|tool, _| {
            Ok(match tool {
                Tool::Ip => ok(IP_ADDR.as_bytes()),
                Tool::Sshd => ok(sshd_t(&HostProfile::CURRENT).as_bytes()),
                _ => failed(b""),
            })
        }),
    )
}

#[test]
fn hello_reports_the_agent_the_host_and_the_gate() {
    let (_dir, paths) = scratch();
    node_root(&paths);
    let info = hello(
        &paths,
        &node(),
        Some("198.51.100.97 51234 203.0.113.203 22"),
    )
    .unwrap();
    assert_eq!(info.protocol, PROTOCOL);
    assert_eq!(info.agent_sha, digest_of(&b"the agent binary"[..]).unwrap());
    assert_eq!(info.host_profile_version, HostProfile::CURRENT.version);
    assert_eq!(info.host.uplink, IfName::new("eth0").unwrap());
    assert_eq!(info.host.vps4, Ipv4Addr::new(203, 0, 113, 203));
    assert_eq!(
        info.host.ip_local_port_range,
        PortRange::new(32768, 60999).unwrap()
    );
    assert_eq!(info.host.debian_major, 13);
    assert_eq!(
        info.host.kernel,
        KernelRelease::new("6.12.113+deb13-cloud-amd64").unwrap()
    );
    assert_eq!(
        info.host.congestion_control,
        KernelIdent::new("bbr").unwrap()
    );
    assert_eq!(info.host.qdisc, KernelIdent::new("fq").unwrap());
    assert_eq!(info.wgexit_accept_local, AcceptLocal::NoInterface);
    assert!(info.sshd_mismatches.is_empty());
    assert_eq!(info.halted, None);
    assert!(info.holds.is_empty());
    assert_eq!(info.client_ip, Ipv4Addr::new(198, 51, 100, 97));
}

#[test]
fn accept_local_is_read_from_the_interfaces_sysctl() {
    let (_dir, paths) = scratch();
    node_root(&paths);
    let path = paths.wgexit_accept_local();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for (text, expected) in [
        ("1\n", AcceptLocal::Enabled),
        ("0\n", AcceptLocal::Disabled),
    ] {
        std::fs::write(&path, text).unwrap();
        let info = hello(&paths, &node(), Some("1.2.3.4 1 5.6.7.8 22")).unwrap();
        assert_eq!(info.wgexit_accept_local, expected);
    }
    std::fs::write(&path, "2\n").unwrap();
    assert_eq!(
        hello(&paths, &node(), Some("1.2.3.4 1 5.6.7.8 22")).unwrap_err(),
        AgentError::Io {
            op: IoOp::ReadState,
            errno: None
        }
    );
}

#[test]
fn every_unreadable_fact_is_refused_by_name() {
    let cases: [(&str, Option<&str>, HostFact); 10] = [
        (
            "/etc/os-release",
            Some("ID=debian\nVERSION_ID=\"+13\"\n"),
            HostFact::DebianMajor,
        ),
        (
            "/proc/net/route",
            Some("Iface\tDestination\n"),
            HostFact::Uplink,
        ),
        (
            "/proc/net/route",
            Some(&*format!(
                "{ROUTE}eth1\t00000000\t01000000\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
            )),
            HostFact::Uplink,
        ),
        (
            "/proc/sys/net/ipv4/ip_local_port_range",
            Some("60999 32768\n"),
            HostFact::IpLocalPortRange,
        ),
        (
            "/proc/sys/net/ipv4/ip_local_port_range",
            Some("1024\n"),
            HostFact::IpLocalPortRange,
        ),
        (
            "/etc/os-release",
            Some("ID=ubuntu\nVERSION_ID=\"24\"\n"),
            HostFact::DebianMajor,
        ),
        (
            "/etc/os-release",
            Some("ID=debian\n"),
            HostFact::DebianMajor,
        ),
        ("/proc/sys/kernel/osrelease", None, HostFact::Kernel),
        (
            "/proc/sys/net/ipv4/tcp_congestion_control",
            Some("BBR!\n"),
            HostFact::CongestionControl,
        ),
        (
            "/proc/sys/net/core/default_qdisc",
            Some("fq\nfq\n"),
            HostFact::Qdisc,
        ),
    ];
    for (path, text, field) in cases {
        let (_dir, paths) = scratch();
        node_root(&paths);
        match text {
            Some(text) => std::fs::write(paths.at(path), text).unwrap(),
            None => std::fs::remove_file(paths.at(path)).unwrap(),
        }
        assert_eq!(
            host_facts(&paths, &node()),
            Err(AgentError::HostFactUnavailable { field }),
            "{path} = {text:?}"
        );
    }
}

#[test]
fn a_default_route_that_is_down_is_not_the_uplink() {
    let (_dir, paths) = scratch();
    node_root(&paths);
    let down = format!("{ROUTE}eth1\t00000000\t01000000\t0002\t0\t0\t0\t00000000\t0\t0\t0\n");
    std::fs::write(paths.at("/proc/net/route"), down).unwrap();
    assert_eq!(
        host_facts(&paths, &node()).unwrap().uplink,
        IfName::new("eth0").unwrap()
    );
}

#[test]
fn the_address_must_be_the_one_global_ipv4_on_the_uplink() {
    for listing in [
        "[]",
        r#"[{"addr_info":[]}]"#,
        r#"[{"addr_info":[{"family":"inet","local":"10.0.0.2","scope":"host"}]}]"#,
        r#"[{"addr_info":[{"family":"inet","local":"1.1.1.1","scope":"global"},{"family":"inet","local":"2.2.2.2","scope":"global"}]}]"#,
        "not json",
    ] {
        let (_dir, paths) = scratch();
        node_root(&paths);
        let listing = listing.to_owned();
        let node = FakeNode::answering(0, Box::new(move |_, _| Ok(ok(listing.as_bytes()))));
        assert_eq!(
            host_facts(&paths, &node),
            Err(AgentError::HostFactUnavailable {
                field: HostFact::Vps4
            })
        );
    }
}

#[test]
fn the_architecture_is_this_builds() {
    assert_eq!(arch("x86_64"), Ok(Arch::Amd64));
    assert_eq!(arch("aarch64"), Ok(Arch::Arm64));
    assert_eq!(
        arch("riscv64"),
        Err(AgentError::HostFactUnavailable {
            field: HostFact::Arch
        })
    );
}

#[test]
fn the_client_is_the_first_field_of_ssh_connection() {
    assert_eq!(
        client_ip(Some("198.51.100.97 51234 203.0.113.203 22")),
        Ok(Ipv4Addr::new(198, 51, 100, 97))
    );
    let refused = Err(AgentError::Io {
        op: IoOp::ReadRequest,
        errno: None,
    });
    assert_eq!(client_ip(None), refused);
    assert_eq!(client_ip(Some("2001:db8::1 51234 2001:db8::2 22")), refused);
    assert_eq!(client_ip(Some("")), refused);
}

#[test]
fn an_agent_without_an_installed_profile_cannot_answer() {
    let (_dir, paths) = scratch();
    node_root(&paths);
    std::fs::remove_file(paths.host_profile()).unwrap();
    assert_eq!(
        hello(&paths, &node(), Some("1.2.3.4 1 5.6.7.8 22")).unwrap_err(),
        AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(2)
        }
    );
    write_json(&paths.host_profile(), &HostProfileVersion::new(1), 0o640).unwrap();
    assert_eq!(
        hello(&paths, &node(), Some("1.2.3.4 1 5.6.7.8 22"))
            .unwrap()
            .host_profile_version,
        HostProfileVersion::new(1)
    );
}

#[test]
fn sshd_drift_is_compared_as_multisets() {
    let profile = HostProfile::CURRENT;
    let enforced = sshd_t(&profile);
    assert!(mismatches_in(&enforced, &profile).is_empty());
    let extra_user = format!("{enforced}allowusers debian\n");
    assert_eq!(
        mismatches_in(&extra_user, &profile),
        BTreeSet::from([SshdDirective::AllowUsers])
    );
    let weakened = enforced.replace("passwordauthentication no", "passwordauthentication yes");
    assert_eq!(
        mismatches_in(&weakened, &profile),
        BTreeSet::from([SshdDirective::PasswordAuthentication])
    );
    let missing = enforced.replace("maxauthtries 3\n", "");
    assert_eq!(
        mismatches_in(&missing, &profile),
        BTreeSet::from([SshdDirective::MaxAuthTries])
    );
    let doubled = format!("{enforced}x11forwarding no\n");
    assert_eq!(
        mismatches_in(&doubled, &profile),
        BTreeSet::from([SshdDirective::X11Forwarding])
    );
}
