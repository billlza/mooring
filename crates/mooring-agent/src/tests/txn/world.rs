// SPDX-License-Identifier: GPL-3.0-or-later

//! The stand-in node the transaction tests run against, its faults, and
//! the rendered golden bundle (contract/golden/1-node-1-user).

use std::cell::{Cell, RefCell};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::rc::Rc;

use mooring_agent_proto::{
    Arch, BlobLen, BundleFiles, BundleHeader, EngineSet, Generation, Halt, HostFacts, HostProfile,
    IfName, KernelIdent, KernelRelease, ManagedFile, PortRange, Sha256Hex, ShutdownReason,
    TxnState, UnixTime,
};

use crate::blobs::{digest_of, put};
use crate::host::Tool;
use crate::paths::Paths;
use crate::store::write_json;
use crate::tests::{
    ENOENT, FakeNode, failed, nft_set, occupy_temporary, ok, scratch, temporary_of,
};
use crate::txn::{self, Launched};

pub(crate) fn golden(text: &str) -> String {
    let body: Vec<&str> = text.lines().skip(4).collect();
    let body = body.join("\n");
    if body.is_empty() { body } else { body + "\n" }
}

pub(super) const XRAY: &str =
    include_str!("../../../../../contract/golden/1-node-1-user/vps-lon1-xray.json.snap");
pub(super) const HY2: &str =
    include_str!("../../../../../contract/golden/1-node-1-user/vps-lon1-hy2.json.snap");
pub(super) const WG: &str =
    include_str!("../../../../../contract/golden/1-node-1-user/vps-lon1-wgexit.conf.snap");
pub(super) const NFT: &str =
    include_str!("../../../../../contract/golden/1-node-1-user/vps-lon1-nftables.conf.snap");
pub(crate) const WATCH: &str =
    include_str!("../../../../../contract/golden/1-node-1-user/vps-lon1-watch.json.snap");
pub(super) const VIEWERS: &str = include_str!(
    "../../../../../contract/golden/1-node-1-user/vps-lon1-viewer_authorized_keys.snap"
);

/// The golden WireGuard private key, which must never leave the node.
pub(super) const WG_PRIVATE_KEY: &str = "kLHtzcgJYSDaWc3YAUUTHdXc1hGsKcrarNmI8FlXGVg=";

/// `ss -Hltnu` with every listener the golden bundle opens.
pub(super) const SS_ALL: &str = "tcp LISTEN 0 4096 45.67.89.10:443 0.0.0.0:*\n\
tcp LISTEN 0 4096 127.0.0.1:10443 0.0.0.0:*\n\
tcp LISTEN 0 4096 45.67.89.10:80 0.0.0.0:*\n\
udp UNCONN 0 0 45.67.89.10:443 0.0.0.0:*\n\
udp UNCONN 0 0 45.67.89.10:61000 0.0.0.0:*\n\
udp UNCONN 0 0 0.0.0.0:27820 0.0.0.0:*\n";

/// The owner-guard rules as nft lists them (`tests::health`), for engine
/// accounts that both have `uid`, as `bootstrapped` makes them.
pub(super) fn owner_guards(uid: u32) -> String {
    let rule = |counter: &str| {
        format!(
            r#"{{"rule":{{"chain":"output","expr":[{{"match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{uid}}}}},{{"counter":"{counter}"}},{{"reject":null}}]}}}}"#
        )
    };
    format!(
        r#"{{"nftables":[{},{}]}}"#,
        rule("xray_guard"),
        rule("hy2_guard")
    )
}

/// The tunnel's unit.
pub(super) const TUNNEL_UNIT: &str = "wg-quick@wgexit.service";

/// What a failed `systemctl restart` of an engine prints.
pub(super) const ENGINE_RESTART_FAILED: &[u8] =
    b"Job for mooring-xray.service failed because the control process exited with error code.\n";

/// What `systemctl restart` printed on lon1 (2026-10-25) when `wg-quick up`
/// refused the interface a rolled-back first generation had left.
pub(super) const TUNNEL_START_FAILED: &[u8] = b"Job for wg-quick@wgexit.service failed because the control process exited with error code.\n\
See \"systemctl status wg-quick@wgexit.service\" and \"journalctl -xeu wg-quick@wgexit.service\" for details.\n";

/// The tunnel as systemd and wg-quick run it, for the tests that follow
/// the interface instead of assuming it: `wgexit` (its `accept_local` file)
/// exists from a `wg-quick up` until a `wg-quick down`. `up` refuses an
/// interface that exists; `down` needs the interface and
/// `/etc/wireguard/wgexit.conf`; and `systemctl stop` returns 0 even when
/// its `down` failed, with the unit failed and the interface left.
#[derive(Debug, Default)]
pub(super) struct Tunnel {
    /// `wg-quick@wgexit.service` is active.
    pub(super) active: Cell<bool>,
}

/// How a tool fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolFault {
    /// It runs and exits 1.
    Fails,
    /// It cannot be started (`ENOENT`).
    Unstartable,
}

/// How the stand-in node misbehaves.
#[derive(Debug, Default)]
pub(super) struct Faults {
    /// The tunnel followed as systemd and wg-quick run it ([`Tunnel`]).
    pub(super) tunnel: Option<Tunnel>,
    /// A `wg-quick down` of the agent's own fails in a hook.
    pub(super) wg_down_fails: bool,
    /// Validator output that fails validation (Xray's `-test`).
    pub(super) xray_test: Option<String>,
    /// `nft -f` fails.
    pub(super) nft_load: bool,
    /// The listeners are missing for this many health checks.
    pub(super) missing_listeners: Cell<u32>,
    /// `systemctl start` / `restart` fails.
    pub(super) restart: bool,
    /// This many more `systemctl restart` of an engine fail.
    pub(super) failing_engine_restarts: Cell<u32>,
    /// `systemd-run` fails to arm a confirm timer.
    pub(super) arm: Option<ToolFault>,
    /// `systemctl stop` of a confirm timer fails.
    pub(super) disarm: bool,
    /// This tool cannot be started for this subcommand.
    pub(super) unstartable: Option<(Tool, &'static str)>,
    /// The first `systemctl restart` of an engine takes the temporary name
    /// of this state file ([`occupy_temporary`]), so that its next write
    /// fails; the next restart of an engine frees it again.
    pub(super) block_at_restart: Option<PathBuf>,
    /// A new agent's self-test prints this instead of the protocol.
    pub(super) self_test: Option<String>,
    /// Xray's `-test` halts the node while it runs (a `Shutdown` arriving
    /// mid-transaction), writing the marker here.
    pub(super) halt_on_validate: Option<PathBuf>,
    /// Xray's `-test` makes this directory read-only (0555) while it runs,
    /// so that nothing in it can then be removed.
    pub(super) read_only_on_validate: Option<PathBuf>,
    /// `systemd-run` cannot launch the transaction unit.
    pub(super) launch: bool,
    /// `systemctl is-active` reports one unit failed, with a zero exit, so
    /// that only its lines can tell.
    pub(super) unit_failed: bool,
    /// `sshd -t` warns about the staged configuration.
    pub(super) sshd_warns: bool,
    /// `sshd -t` fails without a word.
    pub(super) sshd_fails_silently: bool,
    /// `systemd-analyze verify` reports an error.
    pub(super) analyze_errors: bool,
    /// The configuration `sshd -t` was given, as it read it.
    pub(super) sshd_config: RefCell<Option<String>>,
    /// The unit files `systemd-analyze verify` was given, as it read them.
    pub(super) verified: RefCell<Vec<String>>,
    /// The configuration copy `xray run -test` was given, as it read it.
    pub(super) xray_copy: RefCell<Option<String>>,
    /// Staged programs (an engine, a new agent) cannot be started.
    pub(super) unstartable_programs: bool,
}

pub(super) struct World {
    _dir: tempfile::TempDir,
    pub(super) paths: Paths,
    pub(super) faults: Rc<RefCell<Faults>>,
}

impl World {
    pub(super) fn new() -> Self {
        let (dir, paths) = scratch();
        let write = |path: &str, text: &str| {
            let path = paths.at(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write(
            "/proc/net/route",
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             eth0\t00000000\t01F67EB0\t0003\t0\t0\t0\t00000000\n",
        );
        write("/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n");
        write("/proc/sys/kernel/osrelease", "6.12.113+deb13-cloud-amd64\n");
        write("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n");
        write("/proc/sys/net/core/default_qdisc", "fq\n");
        write("/proc/sys/net/ipv4/conf/wgexit/accept_local", "1\n");
        write("/etc/os-release", "ID=debian\nVERSION_ID=\"13\"\n");
        write("/etc/nftables.conf", "#!/usr/sbin/nft -f\nflush ruleset\n");
        crate::tests::bootstrapped(&paths);
        Self {
            _dir: dir,
            paths,
            faults: Rc::new(RefCell::new(Faults::default())),
        }
    }

    /// Follows the tunnel's interface ([`Tunnel`]) instead of assuming it:
    /// `wgexit` does not exist until its unit starts.
    pub(super) fn follow_tunnel(&self) {
        fs::remove_file(self.paths.wgexit_accept_local()).unwrap();
        self.faults.borrow_mut().tunnel = Some(Tunnel::default());
    }

    pub(super) fn node(&self, now: u64) -> FakeNode {
        let faults = Rc::clone(&self.faults);
        let programs = Rc::clone(&self.faults);
        let guards = owner_guards(crate::tests::own_ids(&self.paths).0);
        let interface = self.paths.wgexit_accept_local();
        let conf = self.paths.wg_conf_link();
        let validate = self.paths.validate_dir();
        FakeNode::answering(
            now,
            Box::new(move |tool, args| {
                let faults = faults.borrow();
                if faults.unstartable.is_some_and(|(unstartable, verb)| unstartable == tool && args.first() == Some(&verb)) {
                    return Err(std::io::Error::from_raw_os_error(ENOENT));
                }
                if let (Tool::Systemctl, ["restart", unit], Some(state)) = (tool, args, &faults.block_at_restart)
                    && unit.starts_with("mooring-")
                {
                    let blocker = temporary_of(state);
                    if blocker.exists() {
                        fs::remove_dir(&blocker).unwrap();
                    } else {
                        occupy_temporary(state);
                    }
                }
                Ok(match (tool, args) {
                    (Tool::SystemdRun, args) if args.contains(&"txn-revert") && faults.arm.is_some() => {
                        if faults.arm == Some(ToolFault::Unstartable) {
                            return Err(std::io::Error::from_raw_os_error(ENOENT));
                        }
                        failed(b"Failed to start transient timer unit.\n")
                    }
                    (Tool::Systemctl, ["stop", unit]) if faults.disarm && unit.ends_with(".timer") => {
                        failed(b"Failed to stop the timer.\n")
                    }
                    (Tool::Systemctl, ["restart", unit]) if unit.starts_with("mooring-") && faults.failing_engine_restarts.get() > 0 => {
                        faults.failing_engine_restarts.set(faults.failing_engine_restarts.get() - 1);
                        failed(ENGINE_RESTART_FAILED)
                    }
                    (Tool::Systemctl, ["restart" | "start", TUNNEL_UNIT]) if faults.tunnel.is_some() => {
                        if interface.exists() {
                            failed(TUNNEL_START_FAILED)
                        } else {
                            fs::write(&interface, "1\n").unwrap();
                            faults.tunnel.as_ref().unwrap().active.set(true);
                            ok(b"")
                        }
                    }
                    (Tool::Systemctl, ["stop", TUNNEL_UNIT]) if faults.tunnel.is_some() => {
                        // systemd runs `wg-quick down` for an active unit only, and
                        // `down` needs the configuration; the stop succeeds either way.
                        let was_active = faults.tunnel.as_ref().unwrap().active.replace(false);
                        if was_active && fs::read_to_string(&conf).is_ok() {
                            fs::remove_file(&interface).unwrap();
                        }
                        ok(b"")
                    }
                    (Tool::WgQuick, ["down", "wgexit"]) if faults.tunnel.is_some() => {
                        if !interface.exists() {
                            failed(b"wg-quick: `wgexit' is not a WireGuard interface\n")
                        } else if fs::read_to_string(&conf).is_err() {
                            failed(b"wg-quick: `/etc/wireguard/wgexit.conf' does not exist\n")
                        } else if faults.wg_down_fails {
                            failed(b"[#] ip -4 route flush table 77\nRTNETLINK answers: Operation not permitted\n")
                        } else {
                            fs::remove_file(&interface).unwrap();
                            ok(b"")
                        }
                    }
                    (Tool::Ip, _) => ok(br#"[{"addr_info":[{"family":"inet","local":"203.0.113.203","scope":"global"}]}]"#),
                    (Tool::Nft, ["-f", ..]) if faults.nft_load => failed(b"Error: syntax error\n"),
                    (Tool::Nft, ["-j", "list", "set", ..]) => ok(&nft_set(true)),
                    (Tool::Nft, ["-j", "list", "chain", ..]) => ok(guards.as_bytes()),
                    (Tool::Systemctl, ["restart" | "start", ..]) if faults.restart => failed(b"Job failed.\n"),
                    (Tool::SystemdRun, args) if faults.launch && args.contains(&"txn") => failed(b"Failed to start transient service unit.\n"),
                    (Tool::Systemctl, ["is-active", ..]) if faults.unit_failed => ok(b"active\nfailed\nactive\n"),
                    (Tool::Systemctl, ["is-active", ..]) => ok(b"active\nactive\nactive\n"),
                    (Tool::Ss, _) => {
                        let missing = faults.missing_listeners.get();
                        if missing > 0 {
                            faults.missing_listeners.set(missing - 1);
                            ok(b"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
                        } else {
                            ok(SS_ALL.as_bytes())
                        }
                    }
                    (Tool::WgQuick, ["strip", ..]) => ok(format!("[Interface]\nPrivateKey = {WG_PRIVATE_KEY}\n").as_bytes()),
                    // The stripped copy holds the tunnel's private key: root's
                    // alone, and there while `wg syncconf` reads it.
                    (Tool::Wg, ["syncconf", "wgexit", file]) => {
                        assert_eq!(mode(file), 0o600, "{file}");
                        assert!(fs::read_to_string(file).unwrap().contains(WG_PRIVATE_KEY));
                        ok(b"")
                    }
                    (Tool::Sshd, ["-t", "-f", config]) => {
                        for copy in ["xray.json", "hy2.json"] {
                            assert!(!validate.join(copy).exists(), "{copy} outlived the engine validators");
                        }
                        *faults.sshd_config.borrow_mut() = Some(fs::read_to_string(config).unwrap());
                        if faults.sshd_fails_silently {
                            failed(b"")
                        } else if faults.sshd_warns {
                            failed(b"/etc/ssh/sshd_config.d/50-cloud-init.conf line 1: Deprecated option UsePrivilegeSeparation\n")
                        } else {
                            ok(b"")
                        }
                    }
                    (Tool::SystemdAnalyze, ["verify", units @ ..]) => {
                        faults.verified.borrow_mut().extend(units.iter().map(|unit| fs::read_to_string(unit).unwrap()));
                        if faults.analyze_errors {
                            ok(b"mooring-watch.service:9: Unknown key name 'ReadWritePath' in section 'Service', ignoring.\nmooring-xray.service: Command /etc/mooring/gen-1/engines/xray is not executable: Permission denied\n")
                        } else {
                            ok(b"")
                        }
                    }
                    _ => ok(b""),
                })
            }),
        )
        .programs(Box::new(move |program, args| {
            let faults = programs.borrow();
            let name = program.file_name().unwrap().to_string_lossy().into_owned();
            if faults.unstartable_programs {
                return Err(std::io::Error::from_raw_os_error(ENOENT));
            }
            // The engines' copies hold the bundle's secrets: root's alone,
            // and there while their validator reads them.
            if let ("xray" | "mooring-hy2", ["run" | "check", .., copy]) = (name.as_str(), args) {
                assert_eq!(mode(copy), 0o600, "{copy}");
            }
            if let ("xray", ["run", "-test", "-c", copy]) = (name.as_str(), args) {
                *faults.xray_copy.borrow_mut() = Some(fs::read_to_string(copy).unwrap());
                if let Some(dir) = &faults.read_only_on_validate {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
                }
            }
            Ok(match (name.as_str(), args) {
                ("xray", ["run", "-test", ..]) if faults.halt_on_validate.is_some() => {
                    let marker = faults.halt_on_validate.as_ref().unwrap();
                    write_json(
                        marker,
                        &Halt {
                            at: UnixTime::from_secs(5),
                            reason: ShutdownReason::Operator,
                        },
                        0o640,
                    )
                    .unwrap();
                    ok(b"Configuration OK.\n")
                }
                ("xray", ["run", "-test", ..]) => match &faults.xray_test {
                    Some(output) => ok(output.as_bytes()),
                    None => ok(b"Xray 26.9.30\nConfiguration OK.\n"),
                },
                (_, ["self-test"]) => match &faults.self_test {
                    Some(output) => ok(output.as_bytes()),
                    None => ok(b"1\n"),
                },
                _ => ok(b""),
            })
        }))
    }

    pub(super) fn put(&self, bytes: &[u8]) -> Sha256Hex {
        let sha256 = digest_of(bytes).unwrap();
        put(
            &self.paths,
            sha256,
            BlobLen::new(bytes.len() as u64).unwrap(),
            &mut Cursor::new(bytes.to_vec()),
        )
        .unwrap();
        sha256
    }

    /// Uploads a bundle for `generation` whose files are the golden ones,
    /// with `edit` applied to their text, and returns its header.
    pub(super) fn bundle(
        &self,
        generation: u64,
        edit: impl Fn(ManagedFile, String) -> String,
    ) -> BundleHeader {
        let text = |file: ManagedFile| {
            let source = match file {
                ManagedFile::XrayConfig => XRAY,
                ManagedFile::Hy2Config => HY2,
                ManagedFile::WgConf => WG,
                ManagedFile::Nftables => NFT,
                ManagedFile::WatchConfig => WATCH,
                ManagedFile::ViewerKeys => VIEWERS,
            };
            edit(file, golden(source))
        };
        let files = BundleFiles::from_fn(|file| self.put(text(file).as_bytes()));
        let engines = EngineSet {
            xray: self.put(b"xray binary"),
            hy2: self.put(b"mooring-hy2 binary"),
            geoip: self.put(b"geoip data"),
            geosite: self.put(b"geosite data"),
        };
        let digest = digest_of(
            format!(
                "{:?}{:?}",
                files.iter().collect::<Vec<_>>(),
                engines.digests()
            )
            .as_bytes(),
        )
        .unwrap();
        BundleHeader {
            config_generation: Generation::new(generation),
            digest,
            host_facts: facts(),
            host_profile_version: HostProfile::CURRENT.version,
            files,
            engines,
        }
    }

    pub(super) fn current(&self) -> Option<String> {
        fs::read_link(self.paths.current())
            .ok()
            .map(|target| target.display().to_string())
    }

    pub(super) fn state(&self, generation: u64) -> TxnState {
        txn::status(&self.paths, Generation::new(generation)).unwrap()
    }

    /// Apply, then run the transaction unit, as systemd would.
    pub(super) fn apply_and_run(&self, node: &FakeNode, header: BundleHeader) -> TxnState {
        let generation = header.config_generation;
        assert_eq!(
            txn::apply(&self.paths, node, header),
            Ok(Launched::Launched(generation))
        );
        txn::run(&self.paths, node, generation).unwrap();
        self.state(generation.get())
    }

    /// A committed generation: applied, run and confirmed.
    pub(super) fn commit(&self, node: &FakeNode, header: BundleHeader) {
        let generation = header.config_generation;
        assert_eq!(self.apply_and_run(node, header), TxnState::AwaitingConfirm);
        assert_eq!(txn::confirm(&self.paths, node, generation), Ok(generation));
    }
}

pub(crate) fn facts() -> HostFacts {
    HostFacts {
        uplink: IfName::new("eth0").unwrap(),
        vps4: "203.0.113.203".parse().unwrap(),
        arch: crate::hello::arch(std::env::consts::ARCH).unwrap_or(Arch::Arm64),
        ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
        debian_major: 13,
        kernel: KernelRelease::new("6.12.113+deb13-cloud-amd64").unwrap(),
        congestion_control: KernelIdent::new("bbr").unwrap(),
        qdisc: KernelIdent::new("fq").unwrap(),
    }
}

pub(super) fn same(_: ManagedFile, text: String) -> String {
    text
}

/// An edit that changes only Xray's idle timeout, to `seconds`.
pub(super) fn idle(seconds: u32) -> impl Fn(ManagedFile, String) -> String {
    move |file, text| {
        if file == ManagedFile::XrayConfig {
            text.replace("\"connIdle\": 300", &format!("\"connIdle\": {seconds}"))
        } else {
            text
        }
    }
}

pub(super) fn index_of(calls: &[String], fragment: &str) -> usize {
    calls
        .iter()
        .position(|call| call.contains(fragment))
        .unwrap_or_else(|| panic!("no call with {fragment:?} in {calls:#?}"))
}

/// The permission bits of the file at `path`.
fn mode(path: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}
