// SPDX-License-Identifier: GPL-3.0-or-later

//! Fakes and fixtures: a scripted link layer that routes to the loopback
//! stub through the real `lo0`, a scripted console, the router fixture,
//! the M7's answers as observed on 2026-10-14 (its session set-up, a
//! refused login and an accepted one), and a harness that runs the command
//! line against them.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use mooring_macsys::{InterfaceAddrV4, MacsysError};
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
use crate::prompt::{Answer, Console, Line};
use crate::router::RouterEnv;
use crate::router::http::Timeouts;
use crate::router::link::LinkLayer;

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
}

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

    fn default_gateway(&self, _index: InterfaceIndex) -> Result<Ipv4Addr, MacsysError> {
        self.gateway
    }

    fn neighbour(&self, index: InterfaceIndex, addr: Ipv4Addr) -> Result<[u8; 6], MacsysError> {
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
        };
        work(&mut env)
    }
}
