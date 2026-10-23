// SPDX-License-Identifier: GPL-3.0-or-later

//! Fakes and fixtures: a scripted link layer that routes to the loopback
//! stub through the real `lo0`, a scripted console, the router fixture,
//! the M7's answers as observed on 2026-10-14 (its session set-up, a
//! refused login and an accepted one), and a harness that runs the command
//! line against them.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use clap::Parser;
use mooring_agent_proto::{LineRequest, RequestKind, Response, Sha256Hex};
use mooring_daemon_core::meter::CounterReading;
use mooring_daemon_core::power::HelperEvent;
use mooring_daemon_core::status::PowerSource;
use mooring_macsys::{Interface, InterfaceAddrV4, MacsysError};
use mooring_model::iface::{BsdName, InterfaceIndex, MacAddr};
use mooring_model::secret::{RouterAdminPassword, SecretEntry};
use mooring_model::time::UnixTime;
use mooring_store::{InMemorySecretStore, RouterPin, SecretStore, write_router_pin};
use socket2::{Domain, Protocol, Socket, Type};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::stub::{Reply, response};
use crate::app::{Env, run};
use crate::backup::{BackupCheck, BackupCheckError};
use crate::cli::Cli;
use crate::error::LocalError;
use crate::node::ssh::{Remote, SshTarget};
use crate::node::{AgentLink, NodeError, NodeLinks, NodeSession};
use crate::prompt::{Answer, Console, Line};
use crate::router::RouterEnv;
use crate::router::http::Timeouts;
use crate::router::link::LinkLayer;
use crate::runtime::power::{PowerLink, PowerMessage};
use crate::runtime::probe::ProbeFailure;

/// The router fixture: the M2a capture, re-redacted (an administrator's
/// session).
pub(crate) const FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contract/router-fixtures/mr7450-ntgx75-10.04.43.01.json"
));

/// The login token every anonymous answer carries here.
pub(crate) const TOKEN: &str = "tok-CANARY-7f3a;9b&=+ x";

/// The admin password used by the tests: it needs percent-encoding.
pub(crate) const PASSWORD: &str = "p@ss w&rd=+%";

/// The pinned (and, by default, found) link-layer address: made up,
/// locally administered.
pub(crate) const PINNED: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x20, 0x30];

/// Another device's link-layer address.
pub(crate) const OTHER: [u8; 6] = [0x02, 0x00, 0x5e, 0x99, 0x99, 0x99];

/// The fixed clock: 2026-10-13 19:20:00 UTC.
pub(crate) const NOW: u64 = 1_791_919_200;

/// What a command prints when the kernel returned it an empty neighbour
/// table after the gateway was reached (design §15.6 rule 10).
pub(crate) const HIDDEN_TABLE: &str = "mooringctl: the kernel returned an empty neighbour table to this binary; on macOS 27.0.1 that was seen when a binary's signing identifier is not reverse-DNS or an ad-hoc-signed program such as cargo is among its ancestors: build it with `cargo xtask mooringctl` and run the binary it names from Terminal.app's own shell\n";

/// The address Apple's iOS reports in place of a real one: a valid
/// unicast address, which every network would match.
pub(crate) const PLACEHOLDER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// How an error names [`PLACEHOLDER`] as the gateway's address.
pub(crate) const PLACEHOLDER_FOUND: &str =
    "02:00:00:00:00:00, the placeholder Apple's iOS reports in place of a real address";

/// Short limits, so timeout tests are quick.
pub(crate) const TEST_TIMEOUTS: Timeouts = Timeouts {
    connect: Duration::from_secs(2),
    io: Duration::from_secs(2),
    total: Duration::from_secs(5),
};

/// An anonymous answer: the login fields only, as M2a saw (the role's
/// anonymous spelling is not captured; `Guest` stands in).
pub(crate) fn anonymous(role: &str, cooloff: u32, model: &str) -> Vec<u8> {
    format!(
        "{{\"session\":{{\"userRole\":\"{role}\",\"lang\":\"en\",\"passwordCooloff\":{cooloff},\
         \"secToken\":\"{TOKEN}\",\"supportedLangList\":[],\"end\":\"\"}},\
         \"general\":{{\"model\":\"{model}\",\"productSKU\":\"x\",\"InstallID\":\"x\",\"end\":\"\"}}}}"
    )
    .into_bytes()
}

/// The JSON endpoint's target, as the M7 names it in a `Location`.
pub(crate) const JSON_TARGET: &str = "/api/model.json?internalapi=1";

/// The session set-up's target, as the M7 named it on 2026-10-14.
pub(crate) const SET_UP_TARGET: &str = "/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1";

/// The session cookie the M7's first redirect sets (made up; every test
/// cookie's value starts `COOKIE-`).
pub(crate) const SESSION_A: &str = "COOKIE-A-3f9d0c";

/// The session cookie the session set-up sets in its place (made up).
pub(crate) const SESSION_B: &str = "COOKIE-B-81ae47";

/// The session cookie the M7 sets when it accepts a login, in place of the
/// one before it (made up).
pub(crate) const SESSION_L: &str = "COOKIE-L-6d21c9";

/// What a redirect's body holds here; the client never reads it.
pub(crate) const REDIRECT_BODY_CANARY: &str = "REDIRECT-BODY-CANARY";

/// The M7's `Server` and `Date` headers on 2026-10-14.
const OBSERVED_HEADERS: [&str; 2] = [
    "Server: httpd/2.7 (Netgear; D86)",
    "Date: Wed, 14 Oct 2026 19:01:15 GMT",
];

/// One redirect of the M7's session set-up, as observed on 2026-10-14
/// (M2.md): `302 Found`, `sessionId` set to `cookie`, a `Location` of
/// `target` on the stub at `port` (the M7 names its own address), and a
/// `text/html` body of `length` bytes.
pub(crate) fn observed_redirect(port: u16, cookie: &str, target: &str, length: usize) -> Reply {
    let set_cookie = format!("Set-Cookie: sessionId={cookie}; path=/; HttpOnly");
    let location = format!("Location: http://127.0.0.1:{port}{target}");
    let [server, date] = OBSERVED_HEADERS;
    let mut body = format!("<html>{REDIRECT_BODY_CANARY}</html>").into_bytes();
    body.resize(length, b' ');
    Reply::Bytes(response(
        "302 Found",
        &[
            server,
            date,
            &set_cookie,
            &location,
            "Content-type: text/html",
        ],
        &body,
    ))
}

/// The M7's session set-up as observed on 2026-10-14, on the stub at
/// `port`: the first `GET` of the JSON endpoint is redirected to the
/// set-up, which sets `first` (254 bytes of body), and the set-up back to
/// the endpoint, which sets `second` in its place (605 bytes of body).
pub(crate) fn session_set_up(port: u16, first: &str, second: &str) -> [Reply; 2] {
    [
        observed_redirect(port, first, SET_UP_TARGET, 254),
        observed_redirect(port, second, JSON_TARGET, 605),
    ]
}

/// The login form's `ok_redirect`: the M7's start page.
pub(crate) const START_PAGE: &str = "/index.html";

/// The login form's `err_redirect`: the M7's login-failed page.
pub(crate) const LOGIN_FAILED_PAGE: &str = "/index.html?loginfailed";

/// The answer to a login the M7 accepts, as observed on 2026-10-14 (M2.md):
/// `302 Found`, a `Set-Cookie` with a new `sessionId` ([`SESSION_L`]) that
/// replaces the one before it, a `Location` of the start page on the stub
/// at `port` (the M7 named its own address), and `Content-type: text/html`.
/// The M7's `Server` and `Date`, as on its other answers *(the diagnostic
/// printed neither)*, and a body, which the client never reads.
pub(crate) fn observed_login_acceptance(port: u16) -> Reply {
    let set_cookie = format!("Set-Cookie: sessionId={SESSION_L}; path=/; HttpOnly");
    let location = format!("Location: http://127.0.0.1:{port}{START_PAGE}");
    let [server, date] = OBSERVED_HEADERS;
    let body = format!("<html>{REDIRECT_BODY_CANARY}</html>");
    Reply::Bytes(response(
        "302 Found",
        &[
            server,
            date,
            &set_cookie,
            &location,
            "Content-type: text/html",
        ],
        body.as_bytes(),
    ))
}

/// What the M7 appended to its login-failed page when it refused the
/// operator's login on 2026-10-14 (M2.md).
pub(crate) const OBSERVED_REFUSAL_QUERY: &str = "&errno=2&errdetail=session.password";

/// The login's refusal as observed on 2026-10-14 (M2.md): `302 Found`, a
/// `Location` of the login-failed page followed by `query` on the stub at
/// `port` (the M7 named its own address), `Content-type: text/html`, and no
/// `Set-Cookie`. The M7's `Server` and `Date`, as on its other answers *(the
/// diagnostic printed neither)*, and a body, which the client never reads.
pub(crate) fn observed_login_refusal(port: u16, query: &str) -> Reply {
    let location = format!("Location: http://127.0.0.1:{port}{LOGIN_FAILED_PAGE}{query}");
    let [server, date] = OBSERVED_HEADERS;
    let body = format!("<html>{REDIRECT_BODY_CANARY}</html>");
    Reply::Bytes(response(
        "302 Found",
        &[server, date, &location, "Content-type: text/html"],
        body.as_bytes(),
    ))
}

/// The JSON endpoint's `200` with `body`, its headers as observed on
/// 2026-10-14: the document is `text/plain`.
pub(crate) fn observed_document(body: &[u8]) -> Reply {
    let [server, date] = OBSERVED_HEADERS;
    Reply::Bytes(response(
        "200 OK",
        &[
            server,
            date,
            "Cache-Control: no-cache",
            "Content-type: text/plain",
            "Accept-Ranges: bytes",
        ],
        body,
    ))
}

/// The real `lo0` index: the client binds to it to reach the stub.
pub(crate) fn lo0() -> InterfaceIndex {
    InterfaceIndex::from(mooring_macsys::interface_index("lo0").unwrap())
}

pub(crate) fn lo0_name() -> BsdName {
    BsdName::parse("lo0").unwrap()
}

/// A loopback port that refuses every connection and that no other socket
/// is given while this lives, so no stub of a test running at the same
/// time listens on it.
///
/// Measured on macOS 27.0.1 (26A434) on 2026-10-14: a connection to a port
/// held by a socket that is only bound is dropped unanswered, so `connect`
/// times out instead of being refused, while a port held by a connected
/// socket is refused (the kernel answers with a reset); and a port held
/// either way was never given to a port-0 bind with `SO_REUSEADDR`, as
/// `TcpListener::bind` makes one (none of 150,000, while a free port came
/// up 9 times). So the socket here is bound and connected, to a throwaway
/// listener whose accepted end is kept, and it never listens. A client's
/// own port is picked the same way *(inference)*, so a client cannot be
/// connected to itself through this port either.
pub(crate) struct RefusingPort {
    held: Socket,
    _accepted: TcpStream,
}

impl RefusingPort {
    pub(crate) fn new() -> Self {
        let peer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let held = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        held.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .unwrap();
        held.connect(&peer.local_addr().unwrap().into()).unwrap();
        let (accepted, _) = peer.accept().unwrap();
        Self {
            held,
            _accepted: accepted,
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.held.local_addr().unwrap().as_socket().unwrap().port()
    }
}

/// A link layer whose `lo0` has the default gateway 127.0.0.1 and whose
/// neighbour answers are scripted (the last one repeats), as are its IPv4
/// addresses.
pub(crate) struct FakeLink {
    pub(crate) gateway: Result<Ipv4Addr, MacsysError>,
    pub(crate) neighbours: RefCell<VecDeque<Result<[u8; 6], MacsysError>>>,
    pub(crate) neighbour_calls: Cell<usize>,
    pub(crate) addresses: Result<Vec<InterfaceAddrV4>, MacsysError>,
    /// The kernel's interface list, as `interfaces()` answers it.
    pub(crate) listed: Result<Vec<Interface>, MacsysError>,
    /// Interfaces other than `lo0`, by index: each one's default gateway
    /// and that gateway's neighbour entry.
    pub(crate) routes: std::collections::BTreeMap<u32, Route>,
}

/// An interface's default gateway and that gateway's neighbour entry, as
/// the kernel answers them.
pub(crate) type Route = (Result<Ipv4Addr, MacsysError>, Result<[u8; 6], MacsysError>);

impl FakeLink {
    pub(crate) fn answering(neighbours: &[Result<[u8; 6], MacsysError>]) -> Self {
        Self {
            gateway: Ok(Ipv4Addr::LOCALHOST),
            neighbours: RefCell::new(neighbours.iter().copied().collect()),
            neighbour_calls: Cell::new(0),
            addresses: Ok(vec![InterfaceAddrV4 {
                addr: Ipv4Addr::LOCALHOST,
                prefix_len: Some(8),
            }]),
            listed: Ok(Vec::new()),
            routes: std::collections::BTreeMap::new(),
        }
    }

    pub(crate) fn pinned() -> Self {
        Self::answering(&[Ok(PINNED)])
    }
}

impl LinkLayer for FakeLink {
    fn interface_index(&self, name: &BsdName) -> Result<InterfaceIndex, MacsysError> {
        if name.as_str() == "lo0" {
            Ok(lo0())
        } else {
            Err(MacsysError::InterfaceAbsent)
        }
    }

    fn default_gateway(&self, index: InterfaceIndex) -> Result<Ipv4Addr, MacsysError> {
        match self.routes.get(&std::num::NonZeroU32::from(index).get()) {
            Some((gateway, _)) => *gateway,
            None => self.gateway,
        }
    }

    fn neighbour(&self, index: InterfaceIndex, addr: Ipv4Addr) -> Result<[u8; 6], MacsysError> {
        if let Some((gateway, neighbour)) =
            self.routes.get(&std::num::NonZeroU32::from(index).get())
        {
            assert_eq!(Ok(addr), *gateway);
            return *neighbour;
        }
        assert_eq!(index, lo0());
        assert_eq!(Ok(addr), self.gateway);
        self.neighbour_calls.set(self.neighbour_calls.get() + 1);
        let mut answers = self.neighbours.borrow_mut();
        if answers.len() > 1 {
            answers.pop_front().unwrap()
        } else {
            *answers.front().unwrap()
        }
    }

    fn ipv4_addresses(&self, index: InterfaceIndex) -> Result<Vec<InterfaceAddrV4>, MacsysError> {
        assert_eq!(index, lo0());
        self.addresses.clone()
    }

    fn interfaces(&self) -> Result<Vec<Interface>, MacsysError> {
        self.listed.clone()
    }
}

/// Which sessions a scripted node step accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expected {
    /// A remote command run with input, by the identity file named.
    Run {
        identity: &'static str,
        command_prefix: &'static str,
    },
    /// An agent request of this kind, by the identity file named and
    /// through this remote side.
    Request {
        identity: &'static str,
        remote: ExpectedRemote,
        kind: RequestKind,
    },
    /// A blob upload over the forced command.
    PutBlob { identity: &'static str },
    /// An empty request.
    Empty {
        identity: &'static str,
        command: &'static str,
    },
}

/// The remote side a scripted request expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpectedRemote {
    /// The key's forced command.
    Forced,
    /// A command starting with this text.
    Command(&'static str),
}

/// What a scripted step answers.
pub(crate) enum Answered {
    /// A remote command's outcome.
    Ran(Result<(), NodeError>),
    /// An agent's reply.
    Replied(Result<Response, NodeError>),
}

/// Nodes whose sessions follow a script, in order, recording each session's
/// target and what was sent.
#[derive(Default)]
pub(crate) struct FakeNodes {
    pub(crate) script: RefCell<VecDeque<(Expected, Answered)>>,
    pub(crate) seen: RefCell<Vec<(SshTarget, Sent)>>,
}

/// What a session sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sent {
    Run(Vec<u8>),
    Request(LineRequest),
    PutBlob(Sha256Hex, usize),
    Empty,
}

impl FakeNodes {
    pub(crate) fn expect(&self, expected: Expected, answered: Answered) {
        self.script.borrow_mut().push_back((expected, answered));
    }

    fn next(&self, target: &SshTarget, sent: Sent) -> Answered {
        let (expected, answered) = self
            .script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("no step scripted for {sent:?}"));
        let identity = target.identity.file_name().unwrap().to_str().unwrap();
        let remote = match &target.remote {
            Remote::ForcedCommand => None,
            Remote::Command(command) => Some(command.as_str()),
        };
        match (&expected, &sent) {
            (
                Expected::Run {
                    identity: wanted,
                    command_prefix,
                },
                Sent::Run(_),
            ) => {
                assert_eq!(identity, *wanted);
                assert!(remote.unwrap().starts_with(command_prefix), "{remote:?}");
            }
            (
                Expected::Request {
                    identity: wanted,
                    remote: wanted_remote,
                    kind,
                },
                Sent::Request(request),
            ) => {
                assert_eq!(identity, *wanted);
                assert_eq!(request.kind(), *kind);
                match wanted_remote {
                    ExpectedRemote::Forced => assert_eq!(remote, None),
                    ExpectedRemote::Command(prefix) => {
                        assert!(remote.unwrap().starts_with(prefix), "{remote:?}");
                    }
                }
            }
            (Expected::PutBlob { identity: wanted }, Sent::PutBlob(..)) => {
                assert_eq!(identity, *wanted);
                assert_eq!(remote, None);
            }
            (
                Expected::Empty {
                    identity: wanted,
                    command,
                },
                Sent::Empty,
            ) => {
                assert_eq!(identity, *wanted);
                assert_eq!(remote, Some(*command));
            }
            (expected, sent) => panic!("expected {expected:?}, the command sent {sent:?}"),
        }
        self.seen.borrow_mut().push((target.clone(), sent));
        answered
    }
}

impl NodeLinks for FakeNodes {
    fn open(&self, target: SshTarget) -> Box<dyn NodeSession + '_> {
        Box::new(FakeSession {
            nodes: self,
            target,
        })
    }
}

struct FakeSession<'a> {
    nodes: &'a FakeNodes,
    target: SshTarget,
}

impl FakeSession<'_> {
    fn replied(&self, sent: Sent) -> Result<Response, NodeError> {
        match self.nodes.next(&self.target, sent) {
            Answered::Replied(reply) => reply,
            Answered::Ran(_) => panic!("a reply was scripted as a run"),
        }
    }
}

impl AgentLink for FakeSession<'_> {
    fn request(&mut self, request: &LineRequest) -> Result<Response, NodeError> {
        self.replied(Sent::Request(request.clone()))
    }

    fn put_blob(&mut self, sha256: Sha256Hex, payload: &[u8]) -> Result<Response, NodeError> {
        self.replied(Sent::PutBlob(sha256, payload.len()))
    }
}

impl NodeSession for FakeSession<'_> {
    fn run(&mut self, input: &[u8]) -> Result<(), NodeError> {
        match self.nodes.next(&self.target, Sent::Run(input.to_vec())) {
            Answered::Ran(outcome) => outcome,
            Answered::Replied(_) => panic!("a run was scripted as a reply"),
        }
    }

    fn empty_request(&mut self) -> Result<Response, NodeError> {
        self.replied(Sent::Empty)
    }
}

/// A console with scripted answers and passwords, recording what it was
/// asked.
#[derive(Default)]
pub(crate) struct FakeConsole {
    pub(crate) answers: VecDeque<Answer>,
    pub(crate) passwords: VecDeque<Vec<u8>>,
    /// Lines to type, each `None` for no terminal.
    pub(crate) lines: VecDeque<Option<Vec<u8>>>,
    pub(crate) asked: Vec<String>,
}

impl Console for FakeConsole {
    fn confirm(&mut self, question: &str) -> Result<Answer, LocalError> {
        self.asked.push(question.to_owned());
        Ok(self.answers.pop_front().unwrap())
    }

    fn password(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, LocalError> {
        self.asked.push(prompt.to_owned());
        self.passwords
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(LocalError::NoTerminal)
    }

    fn line(&mut self, prompt: &str, limit: usize) -> Result<Line, LocalError> {
        self.asked.push(prompt.to_owned());
        Ok(match self.lines.pop_front().unwrap() {
            None => Line::NoTerminal,
            Some(line) if line.len() > limit => Line::Overlong,
            Some(line) => Line::Text(Zeroizing::new(line)),
        })
    }
}

/// A finished command: its exit code and what it wrote.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) code: u8,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// What the fake Time Machine check answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupAnswer {
    /// The folder is excluded.
    Excluded,
    /// The folder is backed up.
    Included,
    /// `tmutil` gave no answer.
    Unanswered,
}

/// A Time Machine check that answers `answer` and records each folder it
/// was asked about.
#[derive(Debug)]
pub(crate) struct FakeBackups {
    pub(crate) answer: BackupAnswer,
    pub(crate) asked: RefCell<Vec<PathBuf>>,
}

impl BackupCheck for FakeBackups {
    fn is_excluded(&self, dir: &Path) -> Result<bool, BackupCheckError> {
        self.asked.borrow_mut().push(dir.to_path_buf());
        match self.answer {
            BackupAnswer::Excluded => Ok(true),
            BackupAnswer::Included => Ok(false),
            BackupAnswer::Unanswered => Err(BackupCheckError::Unanswered),
        }
    }
}

/// The CLI's parent: the ids it reports, one per question, the last one
/// for ever after.
#[derive(Debug)]
pub(crate) struct FakeParent {
    pub(crate) ids: RefCell<VecDeque<u32>>,
}

impl FakeParent {
    /// A parent that stays.
    pub(crate) fn staying() -> Self {
        Self {
            ids: RefCell::new(VecDeque::from([700])),
        }
    }

    /// A parent the command must never ask about: asking fails the test.
    pub(crate) fn never_asked() -> Self {
        Self {
            ids: RefCell::new(VecDeque::new()),
        }
    }

    fn id(&self) -> u32 {
        let mut ids = self.ids.borrow_mut();
        if ids.len() > 1 {
            ids.pop_front().unwrap()
        } else {
            *ids.front().expect("the command asked about its parent")
        }
    }
}

/// A stand-in for the power helper: each start opens a channel whose first
/// event is the power source (unless `silent`), keeps its sender for the
/// test, and collects the commands the daemon writes; `refuse` makes the
/// next starts fail.
#[derive(Debug, Default)]
pub(crate) struct FakeHelper {
    pub(crate) handle: HelperHandle,
    pub(crate) starts: Cell<u32>,
    pub(crate) refuse: Cell<bool>,
    pub(crate) silent: Cell<bool>,
}

/// What a test keeps of the fake helper while the daemon holds the
/// harness: the running helper's event channel and every command written.
#[derive(Clone, Default)]
pub(crate) struct HelperHandle {
    events: Arc<Mutex<Option<mpsc::Sender<PowerMessage>>>>,
    commands: Arc<Mutex<Vec<u8>>>,
}

impl std::fmt::Debug for HelperHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperHandle").finish_non_exhaustive()
    }
}

impl HelperHandle {
    /// Sends `event` to the running helper's reader channel.
    pub(crate) fn send(&self, message: PowerMessage) {
        self.events
            .lock()
            .unwrap()
            .as_ref()
            .expect("a helper was started")
            .send(message)
            .unwrap();
    }

    /// The command lines the daemon wrote, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        String::from_utf8(self.commands.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// The commands' sink, shared with the test.
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl FakeHelper {
    fn start(&self, source: PowerSource) -> PowerLink {
        self.starts.set(self.starts.get() + 1);
        let (sender, messages) = mpsc::channel();
        if !self.silent.get() {
            sender
                .send(PowerMessage::Event(HelperEvent::PowerSource(source)))
                .unwrap();
        }
        *self.handle.events.lock().unwrap() = Some(sender);
        PowerLink::new(
            messages,
            Box::new(SharedSink(Arc::clone(&self.handle.commands))),
            None,
        )
    }
}

/// Everything a command runs against, owned by the test.
pub(crate) struct Harness {
    pub(crate) home: TempDir,
    pub(crate) secrets: InMemorySecretStore,
    pub(crate) link: FakeLink,
    pub(crate) console: FakeConsole,
    pub(crate) stdin: Cursor<Vec<u8>>,
    pub(crate) port: u16,
    pub(crate) timeouts: Timeouts,
    pub(crate) backups: FakeBackups,
    pub(crate) parent: FakeParent,
    pub(crate) nodes: FakeNodes,
    /// The engine pins the commands check files against.
    pub(crate) engine_pins: Vec<(&'static str, String)>,
    /// The Mac engine pins the daemon checks its engine against.
    pub(crate) mac_pins: Vec<(&'static str, String)>,
    /// The power source the fake power helper reports when it starts.
    pub(crate) power: PowerSource,
    /// The running fake helper's event channel, to send it more events,
    /// and every command the daemon wrote to any helper it started.
    pub(crate) helper: FakeHelper,
    /// The counter readings the SIM meter's thread is given, in order;
    /// once they are used up, the interface reads as absent.
    pub(crate) readings: Arc<Mutex<VecDeque<CounterReading>>>,
    /// The direct probes' answers, in order, and the reflectors asked.
    pub(crate) probes: RefCell<VecDeque<Result<Ipv4Addr, ProbeFailure>>>,
    pub(crate) probed: RefCell<Vec<(InterfaceIndex, SocketAddrV4)>>,
    /// How many times the daemon pointed standard error at its log; the
    /// test process's own stderr is never touched.
    pub(crate) redirected: Cell<u32>,
}

impl Harness {
    /// A harness for the stub on `port`: nothing pinned, no password.
    pub(crate) fn new(port: u16) -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            secrets: InMemorySecretStore::new(),
            link: FakeLink::pinned(),
            console: FakeConsole::default(),
            stdin: Cursor::new(Vec::new()),
            port,
            timeouts: TEST_TIMEOUTS,
            backups: FakeBackups {
                answer: BackupAnswer::Excluded,
                asked: RefCell::new(Vec::new()),
            },
            parent: FakeParent::staying(),
            nodes: FakeNodes::default(),
            engine_pins: Vec::new(),
            mac_pins: Vec::new(),
            power: PowerSource::Ac,
            helper: FakeHelper::default(),
            readings: Arc::default(),
            probes: RefCell::new(VecDeque::new()),
            probed: RefCell::new(Vec::new()),
            redirected: Cell::new(0),
        }
    }

    /// A harness with the identity pinned and the password stored.
    pub(crate) fn configured(port: u16) -> Self {
        let mut harness = Self::new(port);
        harness.pin(PINNED);
        harness
            .secrets
            .put(SecretEntry::RouterAdmin(
                RouterAdminPassword::parse(PASSWORD).unwrap(),
            ))
            .unwrap();
        harness
    }

    pub(crate) fn support_dir(&self) -> PathBuf {
        self.home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Mooring")
    }

    pub(crate) fn pin(&mut self, lladdr: [u8; 6]) {
        let dir = self.support_dir();
        std::fs::create_dir_all(&dir).unwrap();
        write_router_pin(
            &dir,
            &RouterPin {
                gateway_lladdr: MacAddr::from_bytes(lladdr).unwrap(),
                interface: BsdName::parse("lo0").unwrap(),
                pinned_at: UnixTime::from_secs(NOW - 60),
            },
        )
        .unwrap();
    }

    /// Runs `mooringctl <args>`.
    pub(crate) fn run(&mut self, args: &[&str]) -> Outcome {
        let cli =
            Cli::try_parse_from(std::iter::once("mooringctl").chain(args.iter().copied())).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = self.with_env(|env| run(cli.command, env, &mut stdout, &mut stderr));
        Outcome {
            code,
            stdout: String::from_utf8(stdout).unwrap(),
            stderr: String::from_utf8(stderr).unwrap(),
        }
    }

    /// Runs `work` against the environment a command gets.
    pub(crate) fn with_env<T>(&mut self, work: impl FnOnce(&mut Env<'_>) -> T) -> T {
        let clock = || Ok(UnixTime::from_secs(NOW));
        let parent = || self.parent.id();
        let pins: Vec<(&str, &str)> = self
            .engine_pins
            .iter()
            .map(|(path, hex)| (*path, hex.as_str()))
            .collect();
        let mac_pins: Vec<(&str, &str)> = self
            .mac_pins
            .iter()
            .map(|(path, hex)| (*path, hex.as_str()))
            .collect();
        let source = self.power;
        let helper = &self.helper;
        let power_helper = move || {
            if helper.refuse.get() {
                return Err(LocalError::PowerHelperSpawn {
                    path: PathBuf::from("mooring-power"),
                    source: std::io::Error::other("refused by the test"),
                });
            }
            Ok(helper.start(source))
        };
        let readings = Arc::clone(&self.readings);
        let meter_reader = move || -> crate::runtime::meter::Reader {
            let readings = Arc::clone(&readings);
            Box::new(move |_| {
                Ok(readings
                    .lock()
                    .map_err(|_| LocalError::MeterThread)?
                    .pop_front())
            })
        };
        let probe = |index: InterfaceIndex, reflector: SocketAddrV4| {
            self.probed.borrow_mut().push((index, reflector));
            self.probes
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(ProbeFailure {
                    stage: mooring_daemon_core::status::ProbeStage::Connect,
                    kind: Some(std::io::ErrorKind::ConnectionRefused),
                }))
        };
        let redirected = &self.redirected;
        let redirect = move |_: std::os::fd::BorrowedFd<'_>| {
            redirected.set(redirected.get() + 1);
            Ok(())
        };
        let mut env = Env {
            router: RouterEnv {
                link: &self.link,
                port: self.port,
                timeouts: self.timeouts,
            },
            secrets: &mut self.secrets,
            home: Some(self.home.path().as_os_str().to_owned()),
            clock: &clock,
            console: &mut self.console,
            stdin: &mut self.stdin,
            backups: &self.backups,
            parent: &parent,
            nodes: &self.nodes,
            engine_pins: &pins,
            mac_pins: &mac_pins,
            power_helper: &power_helper,
            meter_reader: &meter_reader,
            probe: &probe,
            redirect_stderr: &redirect,
        };
        work(&mut env)
    }
}
