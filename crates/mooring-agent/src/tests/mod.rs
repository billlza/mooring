// SPDX-License-Identifier: GPL-3.0-or-later

//! The agent's tests: every handler against a stand-in node (the tools it
//! runs, the clock and sleeping) and a scratch root holding the same file
//! layout as a node. The real tools run only on a node (M4's VM lane).

mod accounting;
mod blobs;
mod bootstrap;
mod cli;
mod gate;
mod health;
mod hello;
mod reflect;
mod requests;
mod serve;
mod store;
mod txn;
mod watch;

use std::cell::{Cell, RefCell};
use std::io;
use std::time::Duration;

use mooring_agent_proto::UnixTime;

use crate::host::{Node, Tool, ToolOutput};
use crate::paths::Paths;

/// What the stand-in node answers for one tool call.
pub(crate) type Responder = Box<dyn Fn(Tool, &[&str]) -> io::Result<ToolOutput>>;

/// What the stand-in node answers for one staged program.
pub(crate) type ProgramResponder = Box<dyn Fn(&std::path::Path, &[&str]) -> io::Result<ToolOutput>>;

/// A stand-in node: answers tool calls with `responder`, records them,
/// keeps a clock that sleeping advances, and lets a test act at each sleep.
pub(crate) struct FakeNode {
    clock: Cell<u64>,
    calls: RefCell<Vec<String>>,
    responder: Responder,
    program_responder: ProgramResponder,
    on_sleep: RefCell<Box<dyn FnMut(u64)>>,
    slept: Cell<u64>,
}

impl FakeNode {
    /// A node at time `now` whose tools all succeed with no output.
    pub(crate) fn new(now: u64) -> Self {
        Self::answering(now, Box::new(|_, _| Ok(ok(b""))))
    }

    /// A node at time `now` whose tools answer as `responder` says.
    pub(crate) fn answering(now: u64, responder: Responder) -> Self {
        Self {
            clock: Cell::new(now),
            calls: RefCell::new(Vec::new()),
            responder,
            program_responder: Box::new(|_, _| Ok(ok(b""))),
            on_sleep: RefCell::new(Box::new(|_| {})),
            slept: Cell::new(0),
        }
    }

    /// Answers staged programs as `responder` says.
    pub(crate) fn programs(mut self, responder: ProgramResponder) -> Self {
        self.program_responder = responder;
        self
    }

    /// Runs `action` after each sleep, with the number of sleeps so far.
    pub(crate) fn on_sleep(self, action: impl FnMut(u64) + 'static) -> Self {
        *self.on_sleep.borrow_mut() = Box::new(action);
        self
    }

    /// Every tool call so far, as `<tool path> <args>`.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    /// The seconds slept so far.
    pub(crate) fn slept(&self) -> u64 {
        self.slept.get()
    }
}

impl Node for FakeNode {
    fn run(&self, tool: Tool, args: &[&str]) -> io::Result<ToolOutput> {
        let mut call = tool.path().to_owned();
        for arg in args {
            call.push(' ');
            call.push_str(arg);
        }
        self.calls.borrow_mut().push(call);
        (self.responder)(tool, args)
    }

    fn run_program(
        &self,
        program: &std::path::Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<ToolOutput> {
        let mut call = String::new();
        for (key, value) in env {
            call.push_str(&format!("{key}={value} "));
        }
        call.push_str(&program.display().to_string());
        for arg in args {
            call.push(' ');
            call.push_str(arg);
        }
        self.calls.borrow_mut().push(call);
        (self.program_responder)(program, args)
    }

    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.clock.get())
    }

    fn sleep(&self, duration: Duration) {
        self.clock.set(self.clock.get() + duration.as_secs());
        self.slept.set(self.slept.get() + duration.as_secs());
        (self.on_sleep.borrow_mut())(self.slept.get());
    }
}

/// A successful tool run printing `stdout`.
pub(crate) fn ok(stdout: &[u8]) -> ToolOutput {
    ToolOutput {
        success: true,
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
    }
}

/// A failed tool run printing `stderr`.
pub(crate) fn failed(stderr: &[u8]) -> ToolOutput {
    ToolOutput {
        success: false,
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
    }
}

/// A scratch root and the layout under it.
pub(crate) fn scratch() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    (dir, paths)
}

/// The user and group ids the tests run as, which own the scratch root.
pub(crate) fn own_ids(paths: &Paths) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(paths.at("/")).unwrap();
    (meta.uid(), meta.gid())
}

/// A host that was bootstrapped: `/etc/passwd` and `/etc/group` with root
/// and every profile account, all mapped to the ids the tests run as (so
/// the agent may give them its files), every kernel parameter of the
/// profile under `/proc/sys`, and the profile's files installed with its
/// version recorded, as `Bootstrap` leaves them.
pub(crate) fn bootstrapped(paths: &Paths) {
    use mooring_agent_proto::{HostAccount, HostProfile};
    let (uid, gid) = own_ids(paths);
    let mut passwd = format!("root:x:{uid}:{gid}:root:/root:/bin/bash\n");
    let mut group = format!("root:x:{gid}:\n");
    let mut groups = std::collections::BTreeSet::new();
    for account in HostAccount::ALL {
        passwd.push_str(&format!(
            "{}:x:{uid}:{gid}::{}:{}\n",
            account.name(),
            account.home(),
            account.shell()
        ));
        if groups.insert(account.group()) {
            group.push_str(&format!("{}:x:{gid}:\n", account.group()));
        }
    }
    for (path, text) in [(paths.passwd(), passwd), (paths.group(), group)] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    for sysctl in HostProfile::CURRENT.sysctls {
        let path = paths.at(&sysctl.proc_path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        if !path.exists() {
            std::fs::write(path, format!("{}\n", sysctl.value)).unwrap();
        }
    }
    for (file, text) in HostProfile::CURRENT.files() {
        let path = paths.host_file(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    crate::store::write_json(&paths.host_profile(), &HostProfile::CURRENT.version, 0o640).unwrap();
}

/// `nft -j list set inet mooring exit_closed` with the gate closed or open.
pub(crate) fn nft_set(closed: bool) -> Vec<u8> {
    let elements = if closed { r#","elem":["wgexit"]"# } else { "" };
    format!(
        r#"{{"nftables":[{{"metainfo":{{"version":"1.1.3"}}}},{{"set":{{"family":"inet","name":"exit_closed","table":"mooring","type":"ifname","handle":3{elements}}}}}]}}"#
    )
    .into_bytes()
}
