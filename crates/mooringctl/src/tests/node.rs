// SPDX-License-Identifier: GPL-3.0-or-later

//! `node new` and `node adopt` against the harness's support directory and
//! scripted node sessions (design §13.2), and the ssh command line, reply
//! reading and relay they rest on (§10.5).

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AcceptLocal, AgentError, Arch, HelloInfo, Holds, HostFacts, HostProfileVersion, IfName,
    KernelIdent, KernelRelease, LineRequest, PortRange, RequestKind, Response, Sha256Hex,
    SshEd25519Key,
};
use mooring_keys::{SshComment, SshKeyPair, SshPublicKey};
use mooring_model::exit::FlowCap;
use mooring_model::iface::{InterfaceSelector, MacAddr};
use mooring_model::ipv4::PublicIpv4;
use mooring_model::node::{NodeLifecycle, NodeRole};
use mooring_model::secret::SecretRef;
use mooring_model::{CalendarDate, DeploymentInit, Ed25519Pub, NodeId, Sha256Digest, UserStatus};
use mooring_store::{SecretStore, Store};

use super::support::{Answered, Expected, ExpectedRemote, Harness, PINNED, Sent};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;
use crate::node::dial::relay;
use crate::node::ssh::{Remote, Session, SshTarget, escaped, reply};
use crate::prompt::Answer;

const ADDRESS: &str = "45.67.89.10";

fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// A host key file in the harness's home: `ssh-ed25519 <base64> comment`.
fn host_key_file(harness: &Harness, name: &str) -> (PathBuf, Ed25519Pub) {
    let (_, public) = SshKeyPair::generate().unwrap().into_parts();
    let path = harness.home.path().join(name);
    fs::write(
        &path,
        format!(
            "{}\n",
            public.line(&SshComment::parse("root@lon1").unwrap())
        ),
    )
    .unwrap();
    let key = Ed25519Pub::parse_ssh_authorized_key(&public.authorized_key()).unwrap();
    (path, key)
}

/// A harness whose `lo0` faces the pinned M7 and whose support directory
/// holds a fresh pilot deployment.
fn deployed() -> Harness {
    let mut harness = Harness::new(0);
    harness.pin(PINNED);
    harness.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    let init = DeploymentInit::pilot(
        InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: MacAddr::from_bytes(PINNED).unwrap(),
            subnet: "192.168.1.0/24".parse().unwrap(),
        },
        CalendarDate::parse("2026-10-28").unwrap(),
        FlowCap::new(1024).unwrap(),
    )
    .unwrap();
    Store::new(harness.support_dir()).init(init).unwrap();
    harness
}

/// `deployed()` with lon1 planned through `node new`.
fn planned() -> (Harness, Ed25519Pub) {
    let mut harness = deployed();
    let (path, key) = host_key_file(&harness, "lon1_host.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    (harness, key)
}

#[test]
fn new_plans_a_node_with_its_secrets_and_the_given_host_key() {
    let mut harness = deployed();
    let (path, key) = host_key_file(&harness, "host.pub");
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "node lon1: primary, tunnel 10.77.1.0/30, host key {} pinned; users served: none yet\nplanned node lon1; next: `mooringctl node adopt lon1`\n",
            SshPublicKey::from(key).fingerprint()
        )
    );
    let deployment = store(&harness).load().unwrap().deployment;
    let node = &deployment.nodes()[&node_id("lon1")];
    assert_eq!(node.lifecycle, NodeLifecycle::Planned);
    assert_eq!(node.role, NodeRole::Primary);
    assert_eq!(node.ssh.host_ed25519, key);
    assert_eq!(node.wg_index.get(), 1);
    assert_eq!(node.reality.target, None);
    assert_eq!(deployment.next_wg_index().get(), 2);
    assert_eq!(deployment.config_generation().get(), 2);
    // Every secret the planned node references is in the keychain.
    for secret in deployment.required_secrets() {
        assert!(harness.secrets.get(&secret).is_ok(), "{secret:?}");
    }
    assert!(
        deployment
            .required_secrets()
            .contains(&SecretRef::NodeSshBootstrapPrivate(node_id("lon1")))
    );
}

#[test]
fn new_gives_active_and_suspended_users_credentials_on_the_node() {
    // The fixture's three users on lon1 and ams1; a third node joins.
    let deployment = fixture(|parts| {
        parts.users[1].status = UserStatus::Suspended {
            reason: mooring_model::SuspendReason::AbuseReview,
            since: mooring_model::UnixTime::from_secs(1),
        };
        parts.nodes.retain(|node| node.id.as_str() == "lon1");
        for user in &mut parts.users {
            user.per_node.retain(|node, _| node.as_str() == "lon1");
        }
    });
    let mut harness = harness_with(deployment.clone());
    let (path, _) = host_key_file(&harness, "host.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "par1",
        "--role",
        "standby",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = store(&harness).load().unwrap().deployment;
    let par1 = node_id("par1");
    let served: BTreeSet<_> = after
        .users()
        .values()
        .filter(|user| user.per_node.contains_key(&par1))
        .map(|user| user.id.clone())
        .collect();
    let expected: BTreeSet<_> = deployment.users().keys().cloned().collect();
    assert_eq!(served, expected);
    for user in deployment.users().keys() {
        for secret in [
            SecretRef::UserVlessUuid(user.clone(), par1.clone()),
            SecretRef::UserHy2Password(user.clone(), par1.clone()),
            SecretRef::UserLoopUuid(user.clone(), par1.clone()),
        ] {
            assert!(harness.secrets.get(&secret).is_ok(), "{secret:?}");
        }
    }
    assert_eq!(after.nodes()[&par1].role, NodeRole::Standby);
}

#[test]
fn new_refuses_an_existing_id_a_bad_host_key_and_a_declined_answer() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let (path, _) = host_key_file(&harness, "other.pub");
    let path = path.to_str().unwrap().to_owned();
    let args = [
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        &path,
        "--yes",
    ];
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, "mooringctl: node lon1 exists already\n");
    assert_eq!(state_bytes(&harness), before);
    for (content, why) in [
        (
            "ssh-rsa AAAAB3NzaC1yc2E root@lon1\n",
            "does not hold an Ed25519 host key",
        ),
        ("", "does not hold an Ed25519 host key"),
    ] {
        let bad = harness.home.path().join("bad.pub");
        fs::write(&bad, content).unwrap();
        let outcome = harness.run(&[
            "node",
            "new",
            "par1",
            "--role",
            "standby",
            "--host-key",
            bad.to_str().unwrap(),
            "--yes",
        ]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert!(outcome.stderr.contains(why), "{}", outcome.stderr);
        assert_eq!(state_bytes(&harness), before);
    }
    let missing = harness.home.path().join("missing.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "par1",
        "--role",
        "standby",
        "--host-key",
        missing.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("cannot read the host key"),
        "{}",
        outcome.stderr
    );
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&[
        "node",
        "new",
        "par1",
        "--role",
        "standby",
        "--host-key",
        &path,
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), before);
}

/// The `Hello` a Debian 13 amd64 node at `address` answers.
fn hello(address: Ipv4Addr, debian: u16) -> Response {
    Response::Hello(Box::new(HelloInfo {
        protocol: mooring_agent_proto::PROTOCOL,
        agent_sha: Sha256Hex::from_bytes([7; 32]),
        host_profile_version: HostProfileVersion::new(2),
        host: HostFacts {
            uplink: IfName::new("eth0").unwrap(),
            vps4: address,
            arch: Arch::Amd64,
            ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
            debian_major: debian,
            kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
            congestion_control: KernelIdent::new("bbr").unwrap(),
            qdisc: KernelIdent::new("fq").unwrap(),
        },
        wgexit_accept_local: AcceptLocal::NoInterface,
        sshd_mismatches: BTreeSet::new(),
        halted: None,
        holds: Holds::NONE,
        client_ip: Ipv4Addr::new(92, 40, 201, 7),
    }))
}

/// The `Hello` of a Debian 13 amd64 node at `address`.
pub(crate) fn hello_at(address: Ipv4Addr) -> Response {
    hello(address, 13)
}

fn agent_file(harness: &Harness) -> PathBuf {
    let path = harness.home.path().join("mooring-agent");
    fs::write(&path, b"\x7fELF a static agent").unwrap();
    path
}

fn root_key(harness: &Harness) -> PathBuf {
    let path = harness.home.path().join("root_ed25519");
    fs::write(&path, b"the operator's own key").unwrap();
    path
}

fn adopt_args<'a>(agent: &'a str, root: Option<&'a str>) -> Vec<&'a str> {
    let mut args = vec![
        "node",
        "adopt",
        "lon1",
        "--address",
        ADDRESS,
        "--interface",
        "lo0",
        "--agent",
        agent,
        "--yes",
    ];
    match root {
        Some(root) => args.extend(["--root-identity", root]),
        None => args.push("--resume"),
    }
    args
}

/// The script of a whole adoption, the new host key `new_host`.
fn script_adoption(harness: &Harness, new_host: &Ed25519Pub, debian: u16) {
    let nodes = &harness.nodes;
    nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077 && cat > /root/.mooring-agent-",
        },
        Answered::Ran(Ok(())),
    );
    nodes.expect(
        Expected::Request {
            identity: "root_ed25519",
            remote: ExpectedRemote::Command("/root/.mooring-agent-"),
            kind: RequestKind::Bootstrap,
        },
        Answered::Replied(Ok(Response::BootstrapDone {
            host_pubkey: SshEd25519Key::new(new_host.ssh_authorized_key()).unwrap(),
        })),
    );
    script_after_bootstrap(harness, debian);
}

fn script_after_bootstrap(harness: &Harness, debian: u16) {
    let nodes = &harness.nodes;
    nodes.expect(
        Expected::Empty {
            identity: "ops_ed25519",
            command: "true",
        },
        Answered::Replied(Err(NodeError::Agent(AgentError::UnknownRequest))),
    );
    nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Hello,
        },
        Answered::Replied(Ok(hello(ADDRESS.parse().unwrap(), debian))),
    );
    if debian == 13 {
        nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::RevokeBootstrap,
            },
            Answered::Replied(Ok(Response::BootstrapRevoked)),
        );
    }
}

fn node_dir(harness: &Harness) -> PathBuf {
    harness.support_dir().join("ssh").join("lon1")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn adopt_bootstraps_with_the_root_key_and_records_the_node_adopted() {
    let (mut harness, old_host) = planned();
    // A key directory made earlier with a wider mode is narrowed to 0700.
    let keys = harness.support_dir().join("ssh");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o755)).unwrap();
    let new_host = host_key_file(&harness, "new_host.pub").1;
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    let seed = harness
        .secrets
        .get(&SecretRef::NodeSshBootstrapPrivate(node_id("lon1")))
        .unwrap();
    script_adoption(&harness, &new_host, 13);
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(
        outcome.stdout,
        format!(
            "adopting lon1 at {ADDRESS}: Bootstrap replaces root's authorized_keys there, so the key {} stops working and only Mooring's operations key, forced to the agent, logs in afterwards; the VPS gets a new host key\n\
             bootstrapped lon1: new host key {} pinned\n\
             adopted lon1: Debian 13, kernel 6.12.48+deb13-amd64, eth0 on {ADDRESS}; the Mac's address as the node saw it: 92.40.201.7\n\
             next: `mooringctl node target check lon1`, then `node apply lon1`\n",
            root.display(),
            SshPublicKey::from(new_host).fingerprint()
        )
    );
    // The state: adopted, with the new host key and the site Hello gave.
    let deployment = store(&harness).load().unwrap().deployment;
    let node = &deployment.nodes()[&node_id("lon1")];
    assert_eq!(node.ssh.host_ed25519, new_host);
    assert_ne!(node.ssh.host_ed25519, old_host);
    let NodeLifecycle::Adopted { site } = &node.lifecycle else {
        panic!("{:?}", node.lifecycle);
    };
    assert_eq!(site.address.ipv4(), ADDRESS.parse::<Ipv4Addr>().unwrap());
    assert_eq!(site.host_facts.uplink_interface.as_str(), "eth0");
    // The bootstrap key is gone from the keychain and from the disk.
    assert!(
        harness
            .secrets
            .get(&SecretRef::NodeSshBootstrapPrivate(node_id("lon1")))
            .is_err()
    );
    let dir = node_dir(&harness);
    assert!(!dir.join("bootstrap_ed25519").exists());
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&keys), 0o700);
    assert_eq!(mode(&dir.join("ops_ed25519")), 0o600);
    assert_eq!(mode(&dir.join("known_hosts")), 0o600);
    assert_eq!(
        fs::read_to_string(dir.join("known_hosts")).unwrap(),
        format!(
            "{}\n",
            SshPublicKey::from(new_host).known_hosts_line(ADDRESS.parse().unwrap())
        )
    );
    // What was sent: the agent's bytes, then Bootstrap with the agent's
    // digest, the bootstrap key from the keychain and the operations key
    // on disk; every session through lo0, checked against known_hosts.
    let seen = harness.nodes.seen.borrow();
    assert_eq!(seen[0].1, Sent::Run(b"\x7fELF a static agent".to_vec()));
    let ops = crate::node::files::read_public_key(&dir.join("ops_ed25519.pub")).unwrap();
    let mooring_model::secret::SecretMaterial::Ed25519Seed(seed) = seed else {
        panic!("not a seed");
    };
    let (_, bootstrap) = SshKeyPair::from_seed(seed).unwrap().into_parts();
    assert_eq!(
        seen[1].1,
        Sent::Request(LineRequest::Bootstrap {
            expected_agent_sha: Sha256Hex::from_bytes(
                *Sha256Digest::of(b"\x7fELF a static agent").as_bytes()
            ),
            bootstrap_pubkey: SshEd25519Key::new(bootstrap.authorized_key()).unwrap(),
            ops_pubkey: SshEd25519Key::new(ops.ssh_authorized_key()).unwrap(),
        })
    );
    for (target, _) in seen.iter() {
        assert_eq!(
            target.address,
            PublicIpv4::new(ADDRESS.parse().unwrap()).unwrap()
        );
        assert_eq!(target.interface.as_str(), "lo0");
        assert_eq!(target.known_hosts, dir.join("known_hosts"));
        assert_eq!(target.mooringctl, std::env::current_exe().unwrap());
    }
    let sha = Sha256Hex::from_bytes(*Sha256Digest::of(b"\x7fELF a static agent").as_bytes());
    let staged = format!("/root/.mooring-agent-{sha}");
    assert_eq!(
        seen[0].0.remote,
        Remote::Command(format!(
            "umask 077 && cat > {staged}.part && chmod 0700 {staged}.part && mv {staged}.part {staged}"
        ))
    );
    assert_eq!(
        seen[1].0.remote,
        Remote::Command(format!(
            "{staged} serve-ssh --role bootstrap; status=$?; rm -f {staged}; exit $status"
        ))
    );
    assert_eq!(seen[0].0.identity, root);
    assert_eq!(seen[2].0.identity, dir.join("ops_ed25519"));
}

#[test]
fn adopt_stops_when_the_forced_command_is_not_active_and_keeps_the_new_pin() {
    let (mut harness, _) = planned();
    let new_host = host_key_file(&harness, "new_host.pub").1;
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    let nodes = &harness.nodes;
    nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077",
        },
        Answered::Ran(Ok(())),
    );
    nodes.expect(
        Expected::Request {
            identity: "root_ed25519",
            remote: ExpectedRemote::Command("/root/.mooring-agent-"),
            kind: RequestKind::Bootstrap,
        },
        Answered::Replied(Ok(Response::BootstrapDone {
            host_pubkey: SshEd25519Key::new(new_host.ssh_authorized_key()).unwrap(),
        })),
    );
    nodes.expect(
        Expected::Empty {
            identity: "ops_ed25519",
            command: "true",
        },
        Answered::Replied(Err(NodeError::Ssh {
            code: Some(0),
            stderr: String::new(),
        })),
    );
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("its forced command is not active"),
        "{}",
        outcome.stderr
    );
    let node = store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    assert_eq!(node.lifecycle, NodeLifecycle::Planned);
    assert_eq!(node.ssh.host_ed25519, new_host);
    // The resume starts at the forced command's check, with no root key.
    script_after_bootstrap(&harness, 13);
    let outcome = harness.run(&adopt_args(agent.to_str().unwrap(), None));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let node = store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    assert!(matches!(node.lifecycle, NodeLifecycle::Adopted { .. }));
}

#[test]
fn adopt_refuses_an_unsupported_host_and_a_failed_upload() {
    let (mut harness, _) = planned();
    let new_host = host_key_file(&harness, "new_host.pub").1;
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    script_adoption(&harness, &new_host, 12);
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the node does not run Debian 13: it reports 12\n"
    );
    assert!(harness.nodes.script.borrow().is_empty());
    let node = store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    assert_eq!(node.lifecycle, NodeLifecycle::Planned);
    // A failed upload changes nothing in the state.
    let (mut fresh, host) = planned();
    let before = state_bytes(&fresh);
    fresh.nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077",
        },
        Answered::Ran(Err(NodeError::Ssh {
            code: Some(255),
            stderr: "Permission denied (publickey).\n".to_owned(),
        })),
    );
    let agent = agent_file(&fresh);
    let root = root_key(&fresh);
    let outcome = fresh.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: adoption stopped at uploading the agent\n  caused by: ssh ended without a reply (exit status 255):\nPermission denied (publickey).\n\n"
    );
    assert_eq!(state_bytes(&fresh), before);
    let node = store(&fresh).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    assert_eq!(node.ssh.host_ed25519, host);
}

#[test]
fn adopt_refuses_an_adopted_node_and_another_interface_before_any_session() {
    // Not planned: the fixture's nodes are applied.
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .contains("node lon1 is Applied; only a planned node is adopted"),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.seen.borrow().is_empty());
    // A gateway other than the pinned M7.
    let (mut planned, _) = planned();
    planned.link = super::support::FakeLink::answering(&[Ok([0x02, 0, 0, 0, 0, 9])]);
    planned.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    let agent = agent_file(&planned);
    let root = root_key(&planned);
    let outcome = planned.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("not the pinned M7"),
        "{}",
        outcome.stderr
    );
    assert!(planned.nodes.seen.borrow().is_empty());
}

#[test]
fn the_ssh_command_line_is_the_designs() {
    let target = SshTarget {
        address: PublicIpv4::new(ADDRESS.parse().unwrap()).unwrap(),
        identity: PathBuf::from("/s/ssh/lon1/ops_ed25519"),
        known_hosts: PathBuf::from("/s/ssh/lon1/known_hosts"),
        interface: mooring_model::iface::BsdName::parse("en9").unwrap(),
        mooringctl: PathBuf::from("/Applications/Mooring.app/Contents/MacOS/mooringctl"),
        remote: Remote::ForcedCommand,
        deadline: None,
    };
    let args: Vec<String> = target
        .args()
        .iter()
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        args,
        [
            "-F",
            "/dev/null",
            "-i",
            "/s/ssh/lon1/ops_ed25519",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ProxyCommand='/Applications/Mooring.app/Contents/MacOS/mooringctl' dial-bound --interface en9 %h %p",
            "-o",
            "UserKnownHostsFile='/s/ssh/lon1/known_hosts'",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=4",
            "-o",
            "BatchMode=yes",
            "root@45.67.89.10",
        ]
    );
    let quoted = SshTarget {
        mooringctl: PathBuf::from("/Users/o'brien/mooringctl"),
        remote: Remote::Command("true".to_owned()),
        ..target
    };
    let args: Vec<String> = quoted
        .args()
        .iter()
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        args[7],
        r"ProxyCommand='/Users/o'\''brien/mooringctl' dial-bound --interface en9 %h %p"
    );
    assert_eq!(args.last().map(String::as_str), Some("true"));
}

/// A session past its deadline is ended with its dialler, however long
/// ssh's own timeouts would wait, and fails as such: here the dialler never
/// connects, and ssh would wait 15 s (`ConnectTimeout`). Without a
/// deadline, a dialler that fails ends the session as ssh's own failure.
#[test]
fn a_session_past_its_deadline_is_ended_with_its_dialler() {
    use std::time::{Duration, Instant};

    use crate::node::NodeLinks;
    use crate::node::ssh::SshLinks;

    let dir = tempfile::tempdir().unwrap();
    let dialler = dir.path().join("dialler");
    let pid_file = dir.path().join("dialler.pid");
    fs::write(
        &dialler,
        format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\necho $$ > '{}'\nexec /bin/sleep 30\n",
            pid_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&dialler, fs::Permissions::from_mode(0o755)).unwrap();
    // A new script's first run waits on the system's scan of it, seconds on
    // a loaded Mac: that run is spent before the clock starts.
    assert!(
        std::process::Command::new(&dialler)
            .arg("warm")
            .status()
            .unwrap()
            .success()
    );
    let deadline = Duration::from_secs(3);
    let started = Instant::now();
    let target = SshTarget {
        address: PublicIpv4::new(ADDRESS.parse().unwrap()).unwrap(),
        identity: dir.path().join("ops_ed25519"),
        known_hosts: dir.path().join("known_hosts"),
        interface: mooring_model::iface::BsdName::parse("en9").unwrap(),
        mooringctl: dialler.clone(),
        remote: Remote::ForcedCommand,
        deadline: Some(started + deadline),
    };
    let session = std::thread::spawn({
        let target = target.clone();
        move || SshLinks.open(target).request(&LineRequest::Hello)
    });
    // The dialler runs while ssh waits for a banner that never comes.
    let until = started + deadline;
    let pid: u32 = loop {
        if let Some(pid) = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            break pid;
        }
        assert!(Instant::now() < until, "ssh did not start the dialler");
        std::thread::sleep(Duration::from_millis(10));
    };
    let error = session.join().unwrap().unwrap_err();
    let took = started.elapsed();
    assert!(matches!(error, NodeError::PastDeadline), "{error:?}");
    assert!(
        took >= deadline && took < deadline + Duration::from_secs(5),
        "{took:?}"
    );
    // The dialler, in ssh's group, went with it.
    let until = Instant::now() + Duration::from_secs(5);
    while mooring_macsys::process_path(pid).unwrap().is_some() {
        assert!(Instant::now() < until, "the dialler outlived the session");
        std::thread::sleep(Duration::from_millis(10));
    }

    fs::write(&dialler, "#!/bin/sh\nexit 1\n").unwrap();
    let error = SshLinks
        .open(SshTarget {
            deadline: None,
            ..target
        })
        .request(&LineRequest::Hello)
        .unwrap_err();
    assert!(
        matches!(
            error,
            NodeError::Ssh {
                code: Some(255),
                ..
            }
        ),
        "{error:?}"
    );
}

/// What a session left decides its outcome: a session killed at its
/// deadline is `PastDeadline` unless its reply had arrived whole, and one
/// that was not is ssh's own failure or the reply's.
#[test]
fn a_session_killed_at_its_deadline_is_past_it_unless_its_reply_was_whole() {
    let session = |past_deadline, stdout: &[u8]| Session {
        past_deadline,
        code: if past_deadline { None } else { Some(255) },
        stdout: stdout.to_vec(),
        stderr: "Connection closed".to_owned(),
        written: Ok(()),
    };
    let whole = b"{\"Ok\":\"BootstrapRevoked\"}\n";
    let cut = b"{\"Ok\":\"Bootst";
    for past_deadline in [true, false] {
        assert_eq!(
            session(past_deadline, whole).replied().unwrap(),
            Response::BootstrapRevoked
        );
    }
    assert!(matches!(
        session(true, cut).replied(),
        Err(NodeError::PastDeadline)
    ));
    assert!(matches!(
        session(false, cut).replied(),
        Err(NodeError::Reply(_))
    ));
    assert!(matches!(
        session(true, b"").replied(),
        Err(NodeError::PastDeadline)
    ));
    assert!(matches!(
        session(false, b"").replied(),
        Err(NodeError::Ssh { code: Some(255), stderr }) if stderr == "Connection closed"
    ));
    // A command session: killed, it is past its deadline; one that exited
    // 0 with nothing printed ran, deadline or not.
    assert!(matches!(
        session(true, b"").ran(),
        Err(NodeError::PastDeadline)
    ));
    assert!(matches!(
        session(false, b"").ran(),
        Err(NodeError::Ssh {
            code: Some(255),
            ..
        })
    ));
    let ran = Session {
        code: Some(0),
        ..session(false, b"")
    };
    ran.ran().unwrap();
}

#[test]
fn a_reply_is_one_line_and_remote_text_is_escaped() {
    assert_eq!(
        reply(b"{\"Ok\":\"BootstrapRevoked\"}\n").unwrap(),
        Response::BootstrapRevoked
    );
    assert!(matches!(
        reply(b"{\"Err\":\"UnknownRequest\"}\n"),
        Err(NodeError::Agent(AgentError::UnknownRequest))
    ));
    for bad in [
        &b"not json\n"[..],
        b"{\"Ok\":\"BootstrapRevoked\"}\nmore\n",
        b"{\"Ok\":\"BootstrapRevoked\"}",
    ] {
        assert!(matches!(reply(bad), Err(NodeError::Reply(_))), "{bad:?}");
    }
    assert_eq!(escaped(b"ok\n\x1b[31mred\\"), "ok\n\\x1b[31mred\\x5c");
    let long = escaped(&[b'a'; 5000]);
    assert!(long.ends_with("\\[…]"));
    assert!(long.len() < 4200);
}

#[test]
fn the_relay_copies_both_ways_until_both_end() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        stream.write_all(b"reply:").unwrap();
        stream.write_all(&received).unwrap();
    });
    let stream = crate::node::dial::connect(
        super::support::lo0(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
    )
    .unwrap();
    let mut output = Vec::new();
    relay(stream, &b"request bytes"[..], &mut output).unwrap();
    server.join().unwrap();
    assert_eq!(output, b"reply:request bytes");
}

/// Each fact adoption asserts refuses on its own.
#[test]
fn adoption_asserts_debian_13_a_6_12_kernel_bbr_and_fq() {
    let Response::Hello(good) = hello(ADDRESS.parse().unwrap(), 13) else {
        panic!("not a Hello");
    };
    assert!(crate::node::adopt::check_host(&good.host).is_ok());
    let mut kernel = good.host.clone();
    kernel.kernel = KernelRelease::new("6.1.0-26-amd64").unwrap();
    let mut longer = good.host.clone();
    longer.kernel = KernelRelease::new("6.120.1").unwrap();
    let mut cubic = good.host.clone();
    cubic.congestion_control = KernelIdent::new("cubic").unwrap();
    let mut codel = good.host.clone();
    codel.qdisc = KernelIdent::new("fq_codel").unwrap();
    let mut debian = good.host.clone();
    debian.debian_major = 14;
    for (host, wanted) in [
        (kernel, "a 6.12-series kernel"),
        (longer, "a 6.12-series kernel"),
        (cubic, "bbr congestion control"),
        (codel, "the fq queueing discipline"),
        (debian, "Debian 13"),
    ] {
        match crate::node::adopt::check_host(&host) {
            Err(crate::error::LocalError::HostUnsupported { wanted: found, .. }) => {
                assert_eq!(found, wanted);
            }
            other => panic!("{wanted}: {other:?}"),
        }
    }
}

/// A reply to another request stops adoption at its step, before the node
/// is recorded adopted.
#[test]
fn adopt_stops_at_a_reply_to_another_request() {
    let (mut harness, _) = planned();
    let new_host = host_key_file(&harness, "new_host.pub").1;
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    let nodes = &harness.nodes;
    nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077",
        },
        Answered::Ran(Ok(())),
    );
    nodes.expect(
        Expected::Request {
            identity: "root_ed25519",
            remote: ExpectedRemote::Command("/root/.mooring-agent-"),
            kind: RequestKind::Bootstrap,
        },
        Answered::Replied(Ok(Response::BootstrapRevoked)),
    );
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: adoption stopped at Bootstrap\n  caused by: the agent answered Bootstrap with BootstrapRevoked\n"
    );
    // After a Bootstrap that answered, RevokeBootstrap answered wrongly.
    let (mut second, _) = planned();
    let agent = agent_file(&second);
    let root = root_key(&second);
    script_adoption(&second, &new_host, 13);
    {
        let mut script = second.nodes.script.borrow_mut();
        let last = script.back_mut().unwrap();
        last.1 = Answered::Replied(Ok(Response::BootstrapDone {
            host_pubkey: SshEd25519Key::new(new_host.ssh_authorized_key()).unwrap(),
        }));
    }
    let outcome = second.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: adoption stopped at RevokeBootstrap\n  caused by: the agent answered RevokeBootstrap with BootstrapDone\n"
    );
    let node = store(&second).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    assert_eq!(node.lifecycle, NodeLifecycle::Planned);
}

#[test]
fn new_refuses_a_host_key_file_larger_than_one_line() {
    let mut harness = deployed();
    let (path, _) = host_key_file(&harness, "host.pub");
    let big = harness.home.path().join("big.pub");
    // A valid key line whose comment runs past the limit.
    let mut text = fs::read_to_string(&path).unwrap().trim_end().to_owned();
    text.push_str(&"a".repeat(5000));
    fs::write(&big, text).unwrap();
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        big.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("does not hold an Ed25519 host key"),
        "{}",
        outcome.stderr
    );
}
