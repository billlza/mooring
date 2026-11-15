// SPDX-License-Identifier: GPL-3.0-or-later

//! The lab (design §13.6): opening users on the running Xray against the
//! pinned binary, where every other test of `txn::xray_users` has the
//! stand-in. Only the hosted `xray-lab` workflow runs it
//! (`.github/workflows/xray-lab.yml`): it downloads the engines the
//! `engines` workflow built on main, checks them against the digests
//! `engines.lock.toml` records, and names that Xray in `MOORING_LAB_XRAY`.
//! It never runs on the Mac or on a node.
//!
//! The lab's Xray runs the golden configuration's API, statistics, policy
//! and two VLESS inbounds, on free loopback ports and without REALITY (a
//! lab has no camouflage target), with a freedom outbound in place of the
//! rendered routing, which a final rule lets reach the echo server: the
//! pinned freedom refuses a VLESS client every private address, the
//! loopback's among them, unless a final rule allows it
//! (`proxy/freedom/freedom.go` `getDefaultFinalRule`), and holds the
//! connection unanswered for 30 to 90 seconds instead. The test speaks
//! VLESS itself, as the pinned
//! `proxy/vless/encoding` reads it: version 0, the client's UUID, no
//! addons, the TCP command, the port then the IPv4 address of an echo
//! server, then data; the engine answers version 0 and no addons ahead of
//! the echo. Vision clients need TLS or REALITY to carry data, so data
//! goes through the loopback inbound; the REALITY inbound's clients are
//! checked as the engine holds them.
//!
//! The second test takes a live opening back as the undo of a change
//! applied live does (`txn::xray_users::undo`), through `xray api rmu` and
//! `adu`, with the engine running throughout.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, thread};

use mooring_agent_proto::StatsEmail;
use serde_json::{Value, json};

use super::{INBOUNDS, client, clients};
use crate::accounting::stats::{XRAY_API_SERVER, query};
use crate::host::{Node, RealNode};
use crate::paths::Paths;
use crate::tests::txn::world::{XRAY, golden};
use crate::txn::stage::{self, program};
use crate::txn::xray_users::undo::restore;
use crate::txn::xray_users::{Client, LIVE_INBOUNDS, OpenError, classify, open, parse_held};

/// The variable naming the pinned Xray.
const LAB_XRAY: &str = "MOORING_LAB_XRAY";

/// How long the lab waits for the engine: to listen, to answer, to close.
const PATIENCE: Duration = Duration::from_secs(10);

/// The API port of the rendered configuration, which `open` reaches.
const API_PORT: u16 = 10085;

/// The lab's `xray.json` before the opening: the golden configuration's
/// API, statistics, policy and VLESS inbounds, these on the loopback ports
/// `ports` and over plain TCP, with a freedom outbound that may reach the
/// echo server `echo` and no other private address.
fn lab_config(ports: [u16; 2], echo: SocketAddrV4) -> Value {
    let rendered: Value = serde_json::from_str(&golden(XRAY)).unwrap();
    let inbounds: Vec<Value> = LIVE_INBOUNDS
        .iter()
        .zip(ports)
        .map(|(tag, port)| {
            let mut inbound = rendered["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|inbound| inbound["tag"] == *tag)
                .unwrap()
                .clone();
            inbound["listen"] = json!("127.0.0.1");
            inbound["port"] = json!(port);
            inbound["streamSettings"] = json!({"network": "raw", "security": "none"});
            inbound
        })
        .collect();
    json!({
        "log": {"access": "none", "loglevel": "info", "dnsLog": false},
        "api": rendered["api"],
        "stats": rendered["stats"],
        "policy": rendered["policy"],
        "inbounds": inbounds,
        "outbounds": [{
            "tag": "exit",
            "protocol": "freedom",
            "settings": {"finalRules": [{
                "action": "allow",
                "ip": [echo.ip().to_string()],
                "port": echo.port(),
            }]},
        }],
    })
}

/// `config` with user `n`'s two clients added, as taking a spare user
/// changes the rendered file.
fn with_user(config: &Value, n: u8) -> Value {
    let mut config = config.clone();
    for (tag, inbound) in INBOUNDS {
        clients(&mut config, tag).push(client(n, inbound));
    }
    config
}

/// The clients of the inbound tagged `tag` in `config`, as `classify`
/// reads them.
fn listed(config: &Value, tag: &str) -> BTreeSet<Client> {
    let mut config = config.clone();
    let listed = clients(&mut config, tag).clone();
    serde_json::from_value::<Vec<Client>>(Value::Array(listed))
        .unwrap()
        .into_iter()
        .collect()
}

/// A loopback port free now, for the engine to listen on.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An echo server on the loopback: each connection gets back what it
/// sends, until either end closes it.
fn echo_server() -> SocketAddrV4 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
        unreachable!("bound to an IPv4 address");
    };
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            thread::spawn(move || {
                let mut from = stream.try_clone().unwrap();
                // The connection ends either way: a reset comes when the
                // engine is stopped, and nothing waits for its end.
                let _ended = io::copy(&mut from, &mut stream);
            });
        }
    });
    address
}

/// The lab's Xray, started from `config`, writing its log next to it:
/// killed when dropped, and its log printed when the test panics, so that
/// a failed run shows what the engine said.
struct Engine {
    child: Child,
    log: PathBuf,
}

impl Engine {
    fn start(xray: &Path, dir: &Path, config: &Value, ports: &[u16]) -> Self {
        let file = dir.join("xray.json");
        fs::write(&file, config.to_string()).unwrap();
        let log = dir.join("xray.log");
        let output = File::create(&log).unwrap();
        let child = Command::new(xray)
            .arg("run")
            .arg("-c")
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .expect("the pinned xray starts");
        let mut engine = Self { child, log };
        for port in ports {
            engine.wait_for(*port);
        }
        engine
    }

    /// Waits until the engine listens on `port`.
    fn wait_for(&mut self, port: u16) {
        let deadline = Instant::now() + PATIENCE;
        while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            self.assert_running();
            assert!(
                Instant::now() < deadline,
                "xray did not listen on {port} within {PATIENCE:?}"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// The process the lab started still runs: it was never restarted.
    fn assert_running(&mut self) {
        assert_eq!(self.child.try_wait().unwrap(), None, "xray exited");
    }

    fn stop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // A panic cannot be raised from here: an engine that cannot be
        // ended is named, and the runner ends it with the job.
        if matches!(self.child.try_wait(), Ok(None))
            && let Err(error) = self.child.kill().and_then(|()| self.child.wait())
        {
            eprintln!("cannot end the lab's xray: {error}");
        }
        if thread::panicking() {
            match fs::read_to_string(&self.log) {
                Ok(log) => eprintln!("the lab's xray logged:\n{log}"),
                Err(error) => eprintln!("cannot read the lab's xray log: {error}"),
            }
        }
    }
}

/// The 16 bytes of the UUID `id` in canonical form.
fn uuid_bytes(id: &str) -> [u8; 16] {
    let digits: Vec<u8> = id.bytes().filter(|byte| *byte != b'-').collect();
    assert_eq!(digits.len(), 32, "{id}");
    let mut bytes = [0; 16];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

/// The request the pinned `proxy/vless/encoding` reads from the client
/// `id` with no flow, to `to` over TCP, then `data`.
fn request(id: &str, to: SocketAddrV4, data: &[u8]) -> Vec<u8> {
    const VERSION: u8 = 0;
    const NO_ADDONS: u8 = 0;
    const TCP: u8 = 1;
    const IPV4: u8 = 1;
    let mut bytes = vec![VERSION];
    bytes.extend(uuid_bytes(id));
    bytes.extend([NO_ADDONS, TCP]);
    bytes.extend(to.port().to_be_bytes());
    bytes.push(IPV4);
    bytes.extend(to.ip().octets());
    bytes.extend(data);
    bytes
}

/// A connection through the engine's inbound as one client, to the echo
/// server.
struct Tunnel(TcpStream);

impl Tunnel {
    /// Opens it through the inbound on `port` as the client `id`, with
    /// `data`: the engine must answer with its response header, then the
    /// echo.
    fn open(port: u16, id: &str, echo: SocketAddrV4, data: &[u8]) -> Self {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        stream.write_all(&request(id, echo, data)).unwrap();
        let mut header = [0; 2];
        stream
            .read_exact(&mut header)
            .unwrap_or_else(|error| panic!("the engine did not answer {id}: {error}"));
        assert_eq!(header, [0, 0], "VLESS version 0 and no addons");
        let mut tunnel = Self(stream);
        tunnel.expect_echo(data);
        tunnel
    }

    /// Sends `data` and reads it back.
    fn exchange(&mut self, data: &[u8]) {
        self.0.write_all(data).unwrap();
        self.expect_echo(data);
    }

    fn expect_echo(&mut self, data: &[u8]) {
        let mut echoed = vec![0; data.len()];
        self.0
            .read_exact(&mut echoed)
            .unwrap_or_else(|error| panic!("the echo did not come back: {error}"));
        assert_eq!(echoed, data);
    }
}

/// A connection through the inbound on `port` as the client `id` is closed
/// unanswered, as the engine closes one from a client it does not serve.
fn assert_refused(port: u16, id: &str, echo: SocketAddrV4) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    stream.write_all(&request(id, echo, b"knock")).unwrap();
    let mut answer = Vec::new();
    let read = stream.read_to_end(&mut answer);
    assert!(answer.is_empty(), "the engine answered {id}: {answer:?}");
    if let Err(error) = read {
        // Bytes it never read make the engine's close a reset.
        assert_eq!(error.kind(), ErrorKind::ConnectionReset, "{id}: {error}");
    }
}

/// The clients the engine holds in the inbound tagged `tag`, read as
/// `open` reads them.
fn held(xray: &Path, tag: &str) -> BTreeSet<Client> {
    let tag = format!("-tag={tag}");
    let output = RealNode
        .run_program(xray, &["api", "inbounduser", XRAY_API_SERVER, &tag], &[])
        .unwrap();
    assert!(
        output.success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    parse_held(&output.stdout)
        .unwrap_or_else(|| {
            let printed = String::from_utf8_lossy(&output.stdout);
            panic!("inbounduser printed what the agent cannot read: {printed}")
        })
        .into_iter()
        .collect()
}

/// The first client of the loopback inbound, which data goes through.
fn loopback_id(config: &Value) -> String {
    let mut config = config.clone();
    clients(&mut config, "hy2-loop-in")[0]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
#[ignore = "runs the pinned xray, which the xray-lab workflow names in MOORING_LAB_XRAY"]
fn users_opened_through_the_api_are_served_at_once_without_dropping_a_connection() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::under(root.path());
    let Lab {
        mut engine,
        xray,
        config: before,
        echo,
        loopback,
    } = Lab::start(root.path());

    // A client served from the start holds one connection throughout.
    let mut kept = Tunnel::open(loopback, &loopback_id(&before), echo, b"before the opening");
    let opened = client(1, "hy2");
    let opened_id = opened["id"].as_str().unwrap();
    assert_refused(loopback, opened_id, echo);

    let next = with_user(&before, 1);
    let opening = classify(&before, &next).expect("a user added is an opening");
    open(&RealNode, &xray, &paths.validate_dir(), &opening).expect("the running xray takes it");
    assert_eq!(
        fs::read_dir(paths.validate_dir()).unwrap().count(),
        0,
        "the request is removed"
    );
    for tag in LIVE_INBOUNDS {
        assert_eq!(held(&xray, tag), listed(&next, tag), "{tag}");
    }

    // The user opened is served at once, and counted as the agent counts;
    // the connection held throughout still carries data.
    Tunnel::open(loopback, opened_id, echo, b"opened").exchange(b"again");
    kept.exchange(b"after the opening");
    engine.assert_running();
    let counters = query(&paths, &RealNode).expect("the counters read as the agent reads them");
    let email: StatsEmail = opened["email"].as_str().unwrap().parse().unwrap();
    let traffic = counters
        .get(&email)
        .unwrap_or_else(|| panic!("no counters for {email}: {counters:?}"));
    let sent = (b"opened".len() + b"again".len()) as u64;
    assert!(
        traffic.uplink >= sent && traffic.downlink >= sent,
        "{traffic:?}"
    );

    // An opening repeated, as after a crash restart that read the new file,
    // is no failure: the engine holds the file's clients.
    open(&RealNode, &xray, &paths.validate_dir(), &opening).expect("clients held are no failure");

    // What the engine holds decides: a file without a client it holds is
    // refused, naming the client.
    let without = classify(&before, &with_user(&before, 2)).unwrap();
    let error = open(&RealNode, &xray, &paths.validate_dir(), &without).unwrap_err();
    assert!(
        matches!(
            &error,
            OpenError::Held { tag: "reality-in", unexpected, .. }
                if unexpected == &["fxuserzzz1@reality".to_owned()]
        ),
        "{error}"
    );

    // An engine that is not running fails the opening.
    engine.stop();
    let error = open(&RealNode, &xray, &paths.validate_dir(), &opening).unwrap_err();
    assert!(
        matches!(&error, OpenError::Api { command: "adu", .. }),
        "{error}"
    );
}

/// `config` with user 1's two clients added under other ids than
/// [`client`] gives them: the same emails, held otherwise.
fn with_user_1_otherwise(config: &Value) -> Value {
    let mut config = with_user(config, 1);
    for (tag, _) in INBOUNDS {
        let added = clients(&mut config, tag).last_mut().unwrap();
        let id = added["id"]
            .as_str()
            .unwrap()
            .replace("00c04fd430c8", "00c04fd430c9");
        added["id"] = Value::from(id);
    }
    config
}

/// The pinned xray running the lab configuration under a test's root, as
/// the current generation's own binary, which the agent runs.
struct Lab {
    engine: Engine,
    xray: PathBuf,
    config: Value,
    echo: SocketAddrV4,
    /// The loopback inbound's port, which data goes through.
    loopback: u16,
}

impl Lab {
    fn start(root: &Path) -> Self {
        let pinned = env::var_os(LAB_XRAY)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{LAB_XRAY} names the pinned xray"));
        let xray = program(&Paths::under(root).current(), stage::XRAY);
        fs::create_dir_all(xray.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&pinned, &xray).unwrap();
        let echo = echo_server();
        let ports = [free_port(), free_port()];
        let config = lab_config(ports, echo);
        let engine = Engine::start(&xray, root, &config, &[API_PORT, ports[0], ports[1]]);
        Self {
            engine,
            xray,
            config,
            echo,
            loopback: ports[1],
        }
    }
}

#[test]
#[ignore = "runs the pinned xray, which the xray-lab workflow names in MOORING_LAB_XRAY"]
fn a_live_opening_is_taken_back_through_the_api_without_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::under(root.path());
    let Lab {
        mut engine,
        xray,
        config: before,
        echo,
        loopback,
    } = Lab::start(root.path());
    let scratch = paths.validate_dir();

    // A user opened live, with a connection open through it.
    let next = with_user(&before, 1);
    let opening = classify(&before, &next).expect("a user added is an opening");
    open(&RealNode, &xray, &scratch, &opening).expect("the running xray takes it");
    let opened = client(1, "hy2");
    let opened_id = opened["id"].as_str().unwrap();
    let mut through = Tunnel::open(loopback, opened_id, echo, b"opened");

    // Taken back: the engine holds the previous file's clients again and
    // refuses the user's new connections. The connection already open stays
    // open, as the pinned `RemoveUser` cuts none.
    restore(&RealNode, &xray, &scratch, &before).expect("the running xray gives the user up");
    for tag in LIVE_INBOUNDS {
        assert_eq!(held(&xray, tag), listed(&before, tag), "{tag}");
    }
    assert_refused(loopback, opened_id, echo);
    through.exchange(b"after the undo");
    engine.assert_running();

    // Done again, it finds nothing to take back.
    restore(&RealNode, &xray, &scratch, &before).expect("nothing is left to take back");

    // A client held otherwise than the file lists it is taken out and added
    // back as the file has it, and served so.
    open(&RealNode, &xray, &scratch, &opening).expect("the running xray takes it again");
    let otherwise = with_user_1_otherwise(&before);
    restore(&RealNode, &xray, &scratch, &otherwise).expect("held otherwise is restored");
    for tag in LIVE_INBOUNDS {
        assert_eq!(held(&xray, tag), listed(&otherwise, tag), "{tag}");
    }
    let mut restored = otherwise.clone();
    let restored_id = clients(&mut restored, "hy2-loop-in").last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Tunnel::open(loopback, &restored_id, echo, b"as the file has it");
    assert_refused(loopback, opened_id, echo);
    assert_eq!(
        fs::read_dir(&scratch).unwrap().count(),
        0,
        "the request is removed"
    );
    engine.assert_running();

    // An engine that is not running fails the undo, at its first reading.
    engine.stop();
    let error = restore(&RealNode, &xray, &scratch, &before).unwrap_err();
    assert!(
        matches!(
            &error,
            OpenError::Api {
                command: "inbounduser",
                ..
            }
        ),
        "{error}"
    );
}
