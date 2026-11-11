// SPDX-License-Identifier: GPL-3.0-or-later

//! The stand-in node the watch tests run against: its WireGuard peer, gate
//! set, counters, filesystem, chrony, engine units and Xray API, each of
//! which a test sets, and what the watch left in its view and journal.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::num::NonZeroU16;
use std::rc::Rc;
use std::time::Duration;

use mooring_agent_proto::{
    AbuseGuardVersion, AbuseSet, AgentEventKind, BundleFiles, BundleHeader, EngineSet, EventSeq,
    Generation, Halt, HostProfile, Sha256Hex, ShutdownReason, StatsEmail, TargetHost, Traffic,
    TxnState, UnixTime, UsageMonth, WATCH_TICK_SECS, WatchConfig, WatchConfigBeforeGuard,
    WatchError, WatchErrorKind, WatchTarget,
};

use crate::accounting;
use crate::host::{Node, Tool, ToolOutput};
use crate::journal;
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::tests::{FakeNode, failed, nft_set, ok, scratch};
use crate::txn::record::{TxnRecord, set_record};
use crate::watch::status::WatchStatus;
use crate::watch::{self, HOST_READING_SECS, Watch};

pub(super) const BOOT: &str = "4f1b0d5e-7c39-4a8e-9a51-1c0e2b6d3f70";

/// What the stand-in node reports.
pub(crate) struct Net {
    /// The gate set holds `wgexit`.
    pub(crate) closed: Cell<bool>,
    /// The peer's latest handshake (0: none).
    pub(super) handshake: Cell<u64>,
    pub(super) rx: Cell<u64>,
    pub(super) wg_fails: Cell<bool>,
    pub(super) nft_fails: Cell<bool>,
    pub(super) flow_cap: Cell<u64>,
    /// `stat -f`: available blocks, block size, total blocks.
    pub(super) stat: RefCell<String>,
    /// `chronyc tracking`; `None` when chrony does not answer.
    pub(super) chrony: RefCell<Option<String>>,
    /// The `probe_flows` counter.
    pub(super) probe_flows: Cell<u64>,
    /// `mooring-xray.service` and its API.
    pub(super) xray: RefCell<Xray>,
    /// `mooring-hy2.service`'s `NRestarts`.
    pub(super) hy2_restarts: Cell<u32>,
    /// The abuse guard's cut set (design §11.8).
    pub(crate) cut: RefCell<BTreeSet<String>>,
    /// What `nft -j list set` prints of each measured set, by name; an
    /// empty set when none is given.
    pub(crate) listings: RefCell<BTreeMap<&'static str, String>>,
    /// Listing a measured set fails while set.
    pub(crate) listing_fails: Cell<bool>,
    /// Changing the cut set fails while set (the gate's own changes don't).
    pub(crate) cut_fails: Cell<bool>,
}

/// What nft prints of the measured set `name` holding `elements`, each a
/// JSON element as nft prints it.
pub(crate) fn listing(name: &str, elements: &[String]) -> String {
    let set = AbuseSet::ALL.iter().find(|set| set.name() == name).unwrap();
    let elem = if elements.is_empty() {
        String::new()
    } else {
        format!(r#","elem":[{}]"#, elements.join(","))
    };
    let timeout = set
        .timeout_secs()
        .map_or(String::new(), |secs| format!(r#","timeout":{secs}"#));
    format!(
        r#"{{"nftables":[{{"metainfo":{{"version":"1.1.3","release_name":"Commodore Bullmoose #4","json_schema_version":1}}}},{{"set":{{"family":"inet","name":"{name}","table":"mooring","type":"ipv4_addr","handle":9,"size":{size},"flags":["timeout","dynamic"]{timeout}{elem}}}}}]}}"#,
        size = set.size(),
    )
}

/// Applies one nft command line, as the stand-in kernel: its commands,
/// split at `;`, change the gate set and the cut set, all or nothing.
fn apply_commands(net: &Net, args: &[&str]) -> ToolOutput {
    let line = args.join(" ");
    let mut closed = net.closed.get();
    let mut cut = net.cut.borrow().clone();
    for command in line.split(';').map(str::trim) {
        let words: Vec<&str> = command.split_whitespace().collect();
        let elements = || -> Vec<String> {
            command
                .split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(inside, _)| {
                    inside
                        .split(',')
                        .map(|element| element.trim().trim_matches('"').to_owned())
                        .filter(|element| !element.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        };
        match words.as_slice() {
            ["add", "element", "inet", "mooring", "exit_closed", ..] => closed = true,
            ["delete", "element", "inet", "mooring", "exit_closed", ..] => {
                if !closed {
                    return failed(b"Error: Could not process rule: No such file or directory\n");
                }
                closed = false;
            }
            [_, _, "inet", "mooring", "abuse_cut", ..] if net.cut_fails.get() => {
                return failed(b"Error: Could not process rule: Operation not permitted\n");
            }
            ["flush", "set", "inet", "mooring", "abuse_cut"] => cut.clear(),
            ["add", "element", "inet", "mooring", "abuse_cut", ..] => cut.extend(elements()),
            ["destroy", "element", "inet", "mooring", "abuse_cut", ..] => {
                for element in elements() {
                    cut.remove(&element);
                }
            }
            _ => return failed(b"Error: syntax error\n"),
        }
    }
    net.closed.set(closed);
    *net.cut.borrow_mut() = cut;
    ok(b"")
}

/// Xray as the stand-in node runs it.
pub(super) struct Xray {
    /// The unit is active, since this second after boot.
    pub(super) active_since: Option<u64>,
    pub(super) restarts: u32,
    /// The API fails while set.
    pub(super) api_fails: bool,
    /// `statsquery` alone fails while set.
    pub(super) query_fails: bool,
    /// When the stats service started, in seconds since boot (the node's
    /// boot is `BOOT_SECS` old); `statssys` reports the difference.
    pub(super) started: u64,
    pub(super) counters: XrayCounters,
    pub(super) alloc: u64,
    /// Restarts the stats service at this second since boot right after
    /// the next `statsquery`, with its counters as given.
    pub(super) restart_after_query: Option<(u64, XrayCounters)>,
}

/// Xray's counters per email: uplink and downlink.
pub(super) type XrayCounters = BTreeMap<&'static str, (u64, u64)>;

/// The seconds since boot that `/proc/uptime` says.
pub(super) const BOOT_SECS: u64 = 350_735;

pub(crate) struct World {
    _dir: tempfile::TempDir,
    pub(crate) paths: Paths,
    pub(crate) net: Rc<Net>,
}

impl World {
    pub(crate) fn new() -> Self {
        let (dir, paths) = scratch();
        let world = Self {
            _dir: dir,
            paths,
            net: Rc::new(Net {
                closed: Cell::new(true),
                handshake: Cell::new(0),
                rx: Cell::new(0),
                wg_fails: Cell::new(false),
                nft_fails: Cell::new(false),
                flow_cap: Cell::new(0),
                stat: RefCell::new("2000000 4096 2500000".to_owned()),
                chrony: RefCell::new(Some(
                    "Reference ID    : C0A80001 (192.168.0.1)\nLeap status     : Normal\n"
                        .to_owned(),
                )),
                probe_flows: Cell::new(0),
                xray: RefCell::new(Xray {
                    active_since: Some(100),
                    restarts: 0,
                    api_fails: false,
                    query_fails: false,
                    started: 100,
                    counters: BTreeMap::new(),
                    alloc: 52_000_000,
                    restart_after_query: None,
                }),
                hy2_restarts: Cell::new(0),
                cut: RefCell::new(BTreeSet::new()),
                listings: RefCell::new(BTreeMap::new()),
                listing_fails: Cell::new(false),
                cut_fails: Cell::new(false),
            }),
        };
        world.write(
            "/proc/net/route",
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t01F67EB0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        );
        world.uplink(1_000, 2_000);
        world.write("/proc/uptime", "350735.47 234388.90\n");
        world.write("/proc/loadavg", "0.52 0.58 0.59 1/123 4567\n");
        world.write(
            "/proc/meminfo",
            "MemTotal:  2000000 kB\nMemAvailable:   1500000 kB\n",
        );
        world.write("/proc/sys/kernel/random/boot_id", &format!("{BOOT}\n"));
        world
    }

    pub(super) fn write(&self, path: &str, text: &str) {
        let path = self.paths.at(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// Installs generation `generation` with a 10 s keepalive and the
    /// abuse guard, its record in `state`, as the current one.
    pub(crate) fn install(&self, generation: u64, state: TxnState) {
        let config = WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: WatchTarget {
                host: TargetHost::new("www.example.com").unwrap(),
                ipv4: "198.51.100.7".parse().unwrap(),
            },
            emails: ["u01@reality", "u01@hy2", "probe@reality", "probe@hy2"]
                .into_iter()
                .map(|email| email.parse().unwrap())
                .collect(),
            abuse_guard: AbuseGuardVersion::V1,
        };
        self.install_config(generation, state, &config);
    }

    /// Installs generation `generation` as [`World::install`] does, but in
    /// the shape a Mac rendered before the abuse guard.
    pub(crate) fn install_before_guard(&self, generation: u64, state: TxnState) {
        let config = WatchConfigBeforeGuard {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: WatchTarget {
                host: TargetHost::new("www.example.com").unwrap(),
                ipv4: "198.51.100.7".parse().unwrap(),
            },
            emails: ["u01@reality", "u01@hy2", "probe@reality", "probe@hy2"]
                .into_iter()
                .map(|email| email.parse().unwrap())
                .collect(),
        };
        self.install_config(generation, state, &config);
    }

    fn install_config(&self, generation: u64, state: TxnState, config: &impl serde::Serialize) {
        let dir = self.paths.generation(Generation::new(generation));
        fs::create_dir_all(&dir).unwrap();
        write_json(&dir.join("watch.json"), config, 0o640).unwrap();
        let _replaced = fs::remove_file(self.paths.current());
        std::os::unix::fs::symlink(format!("gen-{generation}"), self.paths.current()).unwrap();
        self.record(generation, state);
    }

    pub(super) fn record(&self, generation: u64, state: TxnState) {
        let header = BundleHeader {
            config_generation: Generation::new(generation),
            digest: Sha256Hex::from_bytes([9; 32]),
            host_facts: crate::tests::txn::facts(),
            host_profile_version: HostProfile::CURRENT.version,
            files: BundleFiles::from_fn(|_| Sha256Hex::from_bytes([1; 32])),
            engines: EngineSet {
                xray: Sha256Hex::from_bytes([2; 32]),
                hy2: Sha256Hex::from_bytes([3; 32]),
                geoip: Sha256Hex::from_bytes([4; 32]),
                geosite: Sha256Hex::from_bytes([5; 32]),
            },
        };
        set_record(
            &self.paths,
            Generation::new(generation),
            &TxnRecord { header, state },
        )
        .unwrap();
    }

    /// The stand-in Xray.
    pub(super) fn xray(&self) -> std::cell::RefMut<'_, Xray> {
        self.net.xray.borrow_mut()
    }

    /// Generation `generation`'s accounting emails, in its `watch.json`.
    pub(super) fn applied(&self, generation: u64, emails: &[&str]) {
        let path = self
            .paths
            .generation(Generation::new(generation))
            .join("watch.json");
        let mut config: WatchConfig = read_json(&path).unwrap().unwrap();
        config.emails = emails.iter().map(|email| email.parse().unwrap()).collect();
        write_json(&path, &config, 0o640).unwrap();
    }

    /// This month's usage at `node`'s time.
    pub(super) fn usage(&self, node: &FakeNode) -> BTreeMap<StatsEmail, Traffic> {
        let month = UsageMonth::containing(node.now()).unwrap();
        accounting::usage(&self.paths, node.now(), month)
            .unwrap()
            .traffic
    }

    /// The uplink's kernel counters.
    pub(super) fn uplink(&self, rx: u64, tx: u64) {
        self.write(
            "/sys/class/net/eth0/statistics/rx_bytes",
            &format!("{rx}\n"),
        );
        self.write(
            "/sys/class/net/eth0/statistics/tx_bytes",
            &format!("{tx}\n"),
        );
    }

    pub(crate) fn node(&self, now: u64) -> FakeNode {
        self.node_answering(now, |_, _| None)
    }

    /// A node at `now` whose tools answer as `first` says where it says
    /// anything, and otherwise as [`World::node`]'s do.
    pub(super) fn node_answering(
        &self,
        now: u64,
        first: impl Fn(Tool, &[&str]) -> Option<io::Result<ToolOutput>> + 'static,
    ) -> FakeNode {
        let net = Rc::clone(&self.net);
        let api = Rc::clone(&self.net);
        FakeNode::answering(
            now,
            Box::new(move |tool, args| {
                if let Some(answer) = first(tool, args) {
                    return answer;
                }
                Ok(match (tool, args) {
                    (Tool::Nft, _) if net.nft_fails.get() => failed(b"netlink: Error: Operation not permitted\n"),
                    (Tool::Nft, ["-j", "list", "set", "inet", "mooring", "exit_closed"]) => ok(&nft_set(net.closed.get())),
                    (Tool::Nft, ["-j", "list", "set", "inet", "mooring", name]) => {
                        if net.listing_fails.get() {
                            return Ok(failed(b"Error: No such file or directory\n"));
                        }
                        match net.listings.borrow().get(name) {
                            Some(listing) => ok(listing.as_bytes()),
                            None => ok(listing(name, &[]).as_bytes()),
                        }
                    }
                    (Tool::Nft, ["-j", "list", "counter", "inet", "mooring", name]) => {
                        let packets = match *name {
                            "flow_cap" => net.flow_cap.get(),
                            "probe_flows" => net.probe_flows.get(),
                            _ => return Ok(failed(b"Error: No such file or directory\n")),
                        };
                        ok(format!(
                            r#"{{"nftables":[{{"metainfo":{{"version":"1.1.3"}}}},{{"counter":{{"family":"inet","name":"{name}","table":"mooring","handle":4,"packets":{packets},"bytes":0}}}}]}}"#,
                        ).as_bytes())
                    }
                    (Tool::Nft, ["add" | "delete" | "flush" | "destroy", ..]) => apply_commands(&net, args),
                    (Tool::Wg, _) if net.wg_fails.get() => failed(b"Unable to access interface: No such device\n"),
                    (Tool::Wg, ["show", "wgexit", "dump"]) => ok(format!(
                        "SECRETPRIVATEKEY=\tPUBLICKEY=\t27820\toff\nMACKEY=\t(none)\t198.51.100.7:4500\t10.66.0.2/32\t{}\t{}\t900\t10\n",
                        net.handshake.get(),
                        net.rx.get()
                    ).as_bytes()),
                    (Tool::Stat, _) => ok(net.stat.borrow().as_bytes()),
                    (Tool::Systemctl, ["show", "-p", "ActiveState,NRestarts,ActiveEnterTimestampMonotonic", unit]) => {
                        let xray = net.xray.borrow();
                        let (since, restarts) = match *unit {
                            "mooring-xray.service" => (xray.active_since, xray.restarts),
                            "mooring-hy2.service" => (Some(90), net.hy2_restarts.get()),
                            _ => return Ok(failed(b"")),
                        };
                        ok(format!(
                            "NRestarts={restarts}\nActiveState={}\nActiveEnterTimestampMonotonic={}\n",
                            if since.is_some() { "active" } else { "inactive" },
                            since.map_or(0, |since| since * 1_000_000 + 250_000),
                        ).as_bytes())
                    }
                    (Tool::Chronyc, _) => match net.chrony.borrow().as_deref() {
                        Some(report) => ok(report.as_bytes()),
                        None => failed(b"506 Cannot talk to daemon\n"),
                    },
                    _ => ok(b""),
                })
            }),
        )
        .programs(Box::new(move |program, args| {
            let mut xray = api.xray.borrow_mut();
            Ok(match args {
                _ if !program.ends_with("engines/xray") => failed(b""),
                _ if xray.api_fails => failed(b"failed to dial 127.0.0.1:10085\n"),
                ["api", "statssys", "--server=127.0.0.1:10085"] => ok(format!(
                    "{{\n    \"Alloc\": {},\n    \"NumGoroutine\": 40,\n    \"Uptime\": {}\n}}\n\n",
                    xray.alloc,
                    BOOT_SECS - xray.started
                )
                .as_bytes()),
                ["api", "statsquery", ..] if xray.query_fails => {
                    failed(b"rpc error: code = Unavailable\n")
                }
                ["api", "statsquery", "--server=127.0.0.1:10085", "-pattern=user>>>"] => {
                    let stats: Vec<serde_json::Value> = xray
                        .counters
                        .iter()
                        .flat_map(|(email, (up, down))| {
                            [("uplink", *up), ("downlink", *down)].map(|(direction, value)| {
                                let name = format!("user>>>{email}>>>traffic>>>{direction}");
                                // Xray leaves a zero out.
                                if value == 0 {
                                    serde_json::json!({ "name": name })
                                } else {
                                    serde_json::json!({ "name": name, "value": value })
                                }
                            })
                        })
                        .collect();
                    let reply = if stats.is_empty() {
                        serde_json::json!({})
                    } else {
                        serde_json::json!({ "stat": stats })
                    };
                    if let Some((started, counters)) = xray.restart_after_query.take() {
                        xray.started = started;
                        xray.counters = counters;
                    }
                    ok(format!("{reply:#}\n\n").as_bytes())
                }
                _ => failed(b""),
            })
        }))
    }

    pub(super) fn status(&self) -> WatchStatus {
        watch::status::read(&self.paths).unwrap().unwrap()
    }

    pub(super) fn conditions(&self) -> Vec<WatchErrorKind> {
        self.status()
            .observed
            .conditions
            .iter()
            .map(WatchError::kind)
            .collect()
    }

    pub(super) fn events(&self) -> Vec<AgentEventKind> {
        journal::page(&self.paths, EventSeq::FIRST)
            .unwrap()
            .events()
            .iter()
            .map(|event| event.kind)
            .collect()
    }

    /// The peer handshakes at `node`'s time and sends `bytes` more.
    pub(super) fn traffic(&self, node: &FakeNode, bytes: u64) {
        self.net.handshake.set(node.now().as_secs());
        self.net.rx.set(self.net.rx.get() + bytes);
    }
}

pub(super) fn tick(watch: &mut Watch, world: &World, node: &FakeNode) {
    watch.tick(&world.paths, node).unwrap();
    node.sleep(Duration::from_secs(5));
}

/// A minute of ticks, beginning with one that takes a reading.
pub(super) fn minute(watch: &mut Watch, world: &World, node: &FakeNode) {
    for _ in 0..HOST_READING_SECS / WATCH_TICK_SECS {
        tick(watch, world, node);
    }
}

pub(super) fn email(text: &str) -> StatsEmail {
    text.parse().unwrap()
}

pub(super) fn halt(paths: &Paths, at: u64) {
    write_json(
        &paths.halted(),
        &Halt {
            at: UnixTime::from_secs(at),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
}

/// 2026-10-08T00:00:00Z, and 2026-11-01T00:00:00Z.
pub(super) const OCT_8: u64 = 1_791_417_600;
pub(super) const NOV: u64 = 1_793_491_200;
