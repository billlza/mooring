// SPDX-License-Identifier: GPL-3.0-or-later

//! `node new` and `node adopt` against the harness's support directory and
//! scripted node sessions (design §13.2), and the ssh command line, reply
//! reading and relay they rest on (§10.5).

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

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
use crate::node::dial::{CONNECT_TIMEOUT, M7Egress, RelaySocket, Served, relay};
use crate::node::ssh::{Connect, Remote, Session, SshLinks, SshTarget, escaped, reply};
use crate::node::{NodeError, NodeLinks};
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
        assert_eq!(target.egress, M7Egress::for_tests(super::support::lo0()));
        assert_eq!(target.relay_dir, dir);
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
        egress: M7Egress::for_tests(super::support::lo0()),
        relay_dir: PathBuf::from("/s/ssh/lon1"),
        mooringctl: PathBuf::from("/Applications/Mooring.app/Contents/MacOS/mooringctl"),
        remote: Remote::ForcedCommand,
        deadline: None,
    };
    let args: Vec<String> = target
        .args(Path::new("/s/ssh/lon1/relay-7-0.sock"))
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
            "ProxyCommand='/Applications/Mooring.app/Contents/MacOS/mooringctl' ssh-relay '/s/ssh/lon1/relay-7-0.sock'",
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
        .args(Path::new("/Users/o'brien/s/relay-7-1.sock"))
        .iter()
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        args[7],
        r"ProxyCommand='/Users/o'\''brien/mooringctl' ssh-relay '/Users/o'\''brien/s/relay-7-1.sock'"
    );
    assert_eq!(args.last().map(String::as_str), Some("true"));
}

/// A directory private to the operator, as a node's is.
fn private_dir(parent: &Path) -> PathBuf {
    let dir = parent.join("lon1");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// An executable script at `path`, run once with `warm`: a new script's
/// first run waits on the system's scan of it, seconds on a loaded Mac, and
/// that run is spent before a test's clock starts.
fn script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    std::process::Command::new(path)
        .arg("warm")
        .status()
        .unwrap();
}

/// A session's target through lo0, its relay socket in `relay_dir`, with
/// `mooringctl` standing in for the ProxyCommand.
fn session_target(
    dir: &Path,
    relay_dir: &Path,
    mooringctl: &Path,
    deadline: Option<Instant>,
) -> SshTarget {
    SshTarget {
        address: PublicIpv4::new(ADDRESS.parse().unwrap()).unwrap(),
        identity: dir.join("ops_ed25519"),
        known_hosts: dir.join("known_hosts"),
        egress: M7Egress::for_tests(super::support::lo0()),
        relay_dir: relay_dir.to_path_buf(),
        mooringctl: mooringctl.to_path_buf(),
        remote: Remote::ForcedCommand,
        deadline,
    }
}

/// `SshLinks` whose sessions open their connections with `connect`, for as
/// long as the test process lives.
fn links(
    connect: impl Fn(&M7Egress, SocketAddrV4, Duration) -> Result<TcpStream, NodeError> + Sync + 'static,
) -> SshLinks<'static> {
    let connect: &'static Connect = Box::leak(Box::new(connect));
    SshLinks { connect }
}

/// What `run` returns, or the test's failure when it takes longer than
/// `limit`: a session that never ends is a defect, not a test that hangs.
fn within<T: Send + 'static>(limit: Duration, run: impl FnOnce() -> T + Send + 'static) -> T {
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(run());
    });
    received
        .recv_timeout(limit)
        .expect("the session did not end")
}

/// A session's ssh reaches the node over the connection this process
/// opened to it, through the checked egress, on the node's SSH port, within
/// ssh's `ConnectTimeout`; its ProxyCommand only relays over the one-time
/// socket, which is unlinked once the ProxyCommand connected, before any of
/// ssh's bytes reach the node. Here nc stands in for `mooringctl
/// ssh-relay`, and the node answers ssh's identification with its own and
/// hangs up, so ssh fails after its own reached the node.
#[test]
fn a_session_runs_ssh_over_the_connection_this_process_opened() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    script(
        &helper,
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n[ \"$1\" = ssh-relay ] || exit 64\nexec /usr/bin/nc -U \"$2\"\n",
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let node = std::thread::spawn({
        let relay_dir = relay_dir.clone();
        move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut identification = Vec::new();
            let mut byte = [0_u8; 1];
            while !identification.ends_with(b"\r\n") && identification.len() < 255 {
                stream.read_exact(&mut byte).unwrap();
                identification.push(byte[0]);
            }
            let left = fs::read_dir(&relay_dir).unwrap().count();
            stream.write_all(b"SSH-2.0-node\r\n").unwrap();
            (identification, left)
        }
    });
    let asked = Arc::new(Mutex::new(Vec::new()));
    let links = links({
        let asked = Arc::clone(&asked);
        move |egress: &M7Egress, target: SocketAddrV4, within: Duration| {
            asked.lock().unwrap().push((*egress, target, within));
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
        }
    });
    let target = session_target(dir.path(), &relay_dir, &helper, None);
    let error = within(Duration::from_secs(30), move || {
        links.open(target).request(&LineRequest::Hello)
    })
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
    let (identification, left) = node.join().unwrap();
    assert!(
        identification.starts_with(b"SSH-2.0-OpenSSH"),
        "{identification:?}"
    );
    assert_eq!(
        left, 0,
        "the relay socket outlived the ProxyCommand's connection"
    );
    assert_eq!(
        *asked.lock().unwrap(),
        [(
            M7Egress::for_tests(super::support::lo0()),
            SocketAddrV4::new(ADDRESS.parse().unwrap(), 22),
            CONNECT_TIMEOUT
        )]
    );
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// A node that keeps its end open after ssh has ended does not hold the
/// session: the node's connection is shut, which ends the ProxyCommand.
/// Here the node answers with a protocol ssh refuses, and stays.
#[test]
fn a_node_that_keeps_its_end_open_does_not_hold_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    script(
        &helper,
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec /usr/bin/nc -U \"$2\"\n",
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (keep, kept) = mpsc::channel::<()>();
    let node = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"SSH-1.5-node\r\n").unwrap();
        // Holds the connection until the test ends.
        let _ = kept.recv();
    });
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
    });
    let target = session_target(dir.path(), &relay_dir, &helper, None);
    let error = within(Duration::from_secs(10), move || {
        links.open(target).request(&LineRequest::Hello)
    })
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
    drop(keep);
    node.join().unwrap();
}

/// A session past its deadline is ended with its ProxyCommand, however long
/// ssh's own timeouts would wait, and fails as such: here the ProxyCommand
/// never relays, and ssh would wait 15 s (`ConnectTimeout`) for the node's
/// identification. Without a deadline, a ProxyCommand that fails ends the
/// session as ssh's own failure. Neither leaves its relay socket behind.
#[test]
fn a_session_past_its_deadline_is_ended_with_its_proxy_command() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    let pid_file = dir.path().join("helper.pid");
    script(
        &helper,
        &format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\necho $$ > '{}'\nexec /bin/sleep 30\n",
            pid_file.display()
        ),
    );
    // The node takes the connection and says nothing.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
    });
    let deadline = Duration::from_secs(3);
    let started = Instant::now();
    let target = session_target(dir.path(), &relay_dir, &helper, Some(started + deadline));
    let (sent, session) = mpsc::channel();
    std::thread::spawn({
        let target = target.clone();
        move || {
            let _ = sent.send(links.open(target).request(&LineRequest::Hello));
        }
    });
    // The ProxyCommand runs while ssh waits for an identification that
    // never comes.
    let until = started + deadline;
    let pid: u32 = loop {
        if let Some(pid) = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            break pid;
        }
        assert!(Instant::now() < until, "ssh did not start its ProxyCommand");
        std::thread::sleep(Duration::from_millis(10));
    };
    let error = session
        .recv_timeout(deadline + Duration::from_secs(10))
        .expect("the session did not end")
        .unwrap_err();
    let took = started.elapsed();
    assert!(matches!(error, NodeError::PastDeadline), "{error:?}");
    assert!(
        took >= deadline && took < deadline + Duration::from_secs(5),
        "{took:?}"
    );
    // The ProxyCommand, in ssh's group, went with it.
    let until = Instant::now() + Duration::from_secs(5);
    while mooring_macsys::process_path(pid).unwrap().is_some() {
        assert!(
            Instant::now() < until,
            "the ProxyCommand outlived the session"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);

    script(&helper, "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexit 1\n");
    let error = within(Duration::from_secs(30), move || {
        links
            .open(SshTarget {
                deadline: None,
                ..target
            })
            .request(&LineRequest::Hello)
    })
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
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
    drop(listener);
}

/// A session whose connection to the node cannot be opened fails as that
/// connection's failure, before ssh starts, and binds no relay socket.
#[test]
fn a_session_whose_connection_fails_starts_no_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    let ran = dir.path().join("ran");
    script(
        &helper,
        &format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\ntouch '{}'\nexit 1\n",
            ran.display()
        ),
    );
    let links = links(|_: &M7Egress, _: SocketAddrV4, _: Duration| {
        Err(NodeError::Connect(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )))
    });
    let error = links
        .open(session_target(dir.path(), &relay_dir, &helper, None))
        .request(&LineRequest::Hello)
        .unwrap_err();
    assert!(
        matches!(&error, NodeError::Connect(source) if source.kind() == std::io::ErrorKind::ConnectionRefused),
        "{error:?}"
    );
    assert!(!ran.exists(), "ssh ran its ProxyCommand");
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// A session whose relay socket cannot be bound fails as that, before ssh
/// starts: here the node's directory cannot be written.
#[test]
fn a_session_whose_relay_socket_cannot_be_bound_starts_no_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    let ran = dir.path().join("ran");
    script(
        &helper,
        &format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\ntouch '{}'\nexit 1\n",
            ran.display()
        ),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
    });
    fs::set_permissions(&relay_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let error = links
        .open(session_target(dir.path(), &relay_dir, &helper, None))
        .request(&LineRequest::Hello)
        .unwrap_err();
    fs::set_permissions(&relay_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(&error, NodeError::Relay(source) if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
    assert!(!ran.exists(), "ssh ran its ProxyCommand");
    drop(listener);
}

/// A session whose deadline has passed opens no connection, and one whose
/// deadline passes while its connection opens gives the connection only
/// what was left: both are past their deadline, not a connection failure.
#[test]
fn a_session_whose_deadline_passes_while_connecting_is_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    script(&helper, "#!/bin/sh\nexit 1\n");
    let tries = Arc::new(AtomicUsize::new(0));
    let links = links({
        let tries = Arc::clone(&tries);
        move |_: &M7Egress, _: SocketAddrV4, within: Duration| {
            tries.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(within);
            Err(NodeError::Connect(std::io::Error::from(
                std::io::ErrorKind::TimedOut,
            )))
        }
    });
    let passed = session_target(dir.path(), &relay_dir, &helper, Some(Instant::now()));
    assert!(matches!(
        links.open(passed).request(&LineRequest::Hello),
        Err(NodeError::PastDeadline)
    ));
    assert_eq!(tries.load(Ordering::SeqCst), 0);
    let left = Duration::from_millis(300);
    let started = Instant::now();
    let passing = session_target(dir.path(), &relay_dir, &helper, Some(started + left));
    assert!(matches!(
        links.open(passing).request(&LineRequest::Hello),
        Err(NodeError::PastDeadline)
    ));
    assert_eq!(tries.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < left + Duration::from_secs(1));
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// A relay socket whose ssh ended before its ProxyCommand connected stops
/// waiting once stopped, and shuts the node's connection, which the node
/// then reads to its end; the socket is gone once it is dropped.
#[test]
fn a_relay_socket_stops_waiting_once_stopped_and_shuts_the_node_connection() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let relay = Arc::new(RelaySocket::bind(&relay_dir).unwrap());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let node = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut far, _) = listener.accept().unwrap();
    let handle = node.try_clone().unwrap();
    let (sent, served) = mpsc::channel();
    let serving = std::thread::spawn({
        let relay = Arc::clone(&relay);
        move || {
            let _ = sent.send(relay.serve(node));
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(served.try_recv().is_err(), "it stopped waiting unstopped");
    relay.stop(&handle).unwrap();
    let served = served
        .recv_timeout(Duration::from_secs(5))
        .expect("it kept waiting");
    assert!(matches!(served, Ok(Served::Stopped)), "{served:?}");
    serving.join().unwrap();
    let mut rest = Vec::new();
    far.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    drop(relay);
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// A relay socket splices its ProxyCommand to the node and passes each
/// direction's end on. The socket it accepts blocks though its listener
/// does not, so a ProxyCommand that writes only after a pause still reaches
/// the node; the node replies once it has read to the ProxyCommand's end,
/// and the ProxyCommand reads the reply to the node's end.
#[test]
fn a_relay_socket_splices_a_late_proxy_command_and_passes_each_end_on() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let relay = RelaySocket::bind(&relay_dir).unwrap();
    let path = relay.path().to_path_buf();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let node = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut far, _) = listener.accept().unwrap();
    let far_end = std::thread::spawn(move || {
        let mut received = Vec::new();
        far.read_to_end(&mut received).unwrap();
        far.write_all(b"reply:").unwrap();
        far.write_all(&received).unwrap();
    });
    let proxy_command = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&path).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        stream.write_all(b"request bytes").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).unwrap();
        output
    });
    let served = within(Duration::from_secs(10), move || relay.serve(node)).unwrap();
    assert!(matches!(served, Served::Spliced(Ok(()))), "{served:?}");
    far_end.join().unwrap();
    assert_eq!(proxy_command.join().unwrap(), b"reply:request bytes");
    assert_eq!(fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// What a session left decides its outcome: a session killed at its
/// deadline is `PastDeadline` unless its reply had arrived whole; one that
/// was not is, without a whole reply, its relay socket's own failure if it
/// had one, then ssh's own failure or the reply's.
#[test]
fn a_session_killed_at_its_deadline_is_past_it_unless_its_reply_was_whole() {
    let session = |past_deadline, stdout: &[u8]| Session {
        past_deadline,
        code: if past_deadline { None } else { Some(255) },
        stdout: stdout.to_vec(),
        stderr: "Connection closed".to_owned(),
        written: Ok(()),
        relay: Ok(()),
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
    // The relay socket's own failure is the cause of a session without its
    // outcome, after the deadline; a whole reply still stands.
    let relay_failed = |past_deadline, stdout: &[u8]| Session {
        relay: Err(NodeError::Relay(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))),
        ..session(past_deadline, stdout)
    };
    assert!(matches!(
        relay_failed(false, b"").replied(),
        Err(NodeError::Relay(source)) if source.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(matches!(
        relay_failed(false, b"").ran(),
        Err(NodeError::Relay(_))
    ));
    assert!(matches!(
        relay_failed(true, b"").replied(),
        Err(NodeError::PastDeadline)
    ));
    assert_eq!(
        relay_failed(false, whole).replied().unwrap(),
        Response::BootstrapRevoked
    );
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
        &M7Egress::for_tests(super::support::lo0()),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        CONNECT_TIMEOUT,
    )
    .unwrap();
    let mut output = Vec::new();
    relay(stream, &b"request bytes"[..], &mut output).unwrap();
    server.join().unwrap();
    assert_eq!(output, b"reply:request bytes");
}

/// The ProxyCommand's relay works the same over its Unix socket.
#[test]
fn the_relay_copies_both_ways_over_a_unix_socket_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        stream.write_all(b"reply:").unwrap();
        stream.write_all(&received).unwrap();
    });
    let mut output = Vec::new();
    relay(
        UnixStream::connect(&path).unwrap(),
        &b"request bytes"[..],
        &mut output,
    )
    .unwrap();
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
