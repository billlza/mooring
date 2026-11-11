// SPDX-License-Identifier: GPL-3.0-or-later

//! What xtask's tests share: the workspace's root, whose files some tests
//! read, and scratch directories. Test-only.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::app::{AGENT_LABEL, AppError, Capture, DITTO, Programs, Step};
use crate::cargo::Cargo;

/// The workspace's root: the parent of xtask's manifest directory.
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A fresh directory under the system temporary directory, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mooring-xtask-{name}-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// A step as the shell would be given it.
pub(crate) fn line(step: &Step) -> String {
    std::iter::once(step.program.as_os_str())
        .chain(step.args.iter().map(OsString::as_os_str))
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A stand-in for the programs: records each step, answers `run` from
/// `outputs` (the next one each time, and an empty success once they are
/// used up) and `outcome` from `outcomes`, and makes the app directory when
/// `ditto` is asked to copy one, with the daemon's plist in it when the
/// repository has one. `after` is what happens on the Mac right after the
/// step it names has run, once.
#[derive(Default)]
pub(crate) struct Fake {
    pub(crate) steps: Vec<(String, Capture)>,
    pub(crate) outputs: VecDeque<Result<Vec<u8>, AppError>>,
    pub(crate) outcomes: VecDeque<(Option<i32>, Vec<u8>)>,
    pub(crate) after: Option<(String, Box<dyn FnOnce()>)>,
}

impl Fake {
    fn happened(&mut self, step: &Step) {
        if let Some((named, happens)) = self.after.take() {
            if named == line(step) {
                happens();
            } else {
                self.after = Some((named, happens));
            }
        }
    }
}

impl Programs for Fake {
    fn run(&mut self, step: &Step, capture: Capture) -> Result<Vec<u8>, AppError> {
        self.steps.push((line(step), capture));
        if step.program == Path::new(DITTO) {
            let app = PathBuf::from(&step.args[1]);
            fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
            let source = step
                .dir
                .join("apple/App/LaunchAgents")
                .join(format!("{AGENT_LABEL}.plist"));
            if let Ok(plist) = fs::read(source) {
                let agents = app.join("Contents/Library/LaunchAgents");
                fs::create_dir_all(&agents).unwrap();
                fs::write(agents.join(format!("{AGENT_LABEL}.plist")), plist).unwrap();
            }
        }
        self.happened(step);
        self.outputs.pop_front().unwrap_or(Ok(Vec::new()))
    }

    fn outcome(&mut self, step: &Step) -> Result<(Option<i32>, Vec<u8>), AppError> {
        self.steps.push((line(step), Capture::Stdout));
        self.happened(step);
        Ok(self.outcomes.pop_front().unwrap())
    }
}

/// `command` having exited 1 with nothing on standard error.
pub(crate) fn failed(command: &str) -> AppError {
    AppError::Failed {
        command: command.to_owned(),
        status: ExitStatus::from_raw(1 << 8),
        message: String::new(),
    }
}

/// The daemon's service for the user the scripted `id -u` names.
pub(crate) fn service() -> String {
    format!("gui/501/{AGENT_LABEL}")
}

/// The pid the scripted launchd gives a running daemon.
pub(crate) const DAEMON_PID: u32 = 4242;

/// How the scripted launchd has the daemon.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Daemon<'a> {
    /// Not listed.
    NotRegistered,
    /// Listed, running this executable.
    Running(&'a Path),
    /// Listed with no process: its starts are refused.
    Refused,
}

/// Scripts `fake` to answer for `daemon`: `id -u`, `launchctl print`, and
/// for a running one `codesign -dv +4242`.
pub(crate) fn script_daemon(fake: &mut Fake, daemon: Daemon<'_>) {
    fake.outputs.push_back(Ok(b"501\n".to_vec()));
    match daemon {
        Daemon::NotRegistered => fake.outcomes.push_back((Some(113), Vec::new())),
        Daemon::Refused => fake.outcomes.push_back((
            Some(0),
            format!(
                "{} = {{\n\tstate = spawn scheduled\n\truns = 7\n\tlast exit code = 78: EX_CONFIG\n\tjob state = spawn failed\n}}\n",
                service()
            )
            .into_bytes(),
        )),
        Daemon::Running(executable) => {
            fake.outcomes.push_back((
                Some(0),
                format!(
                    "{} = {{\n\tstate = running\n\truns = 1\n\tpid = {DAEMON_PID}\n\tjob state = running\n}}\n",
                    service()
                )
                .into_bytes(),
            ));
            fake.outputs.push_back(Ok(examined_process(
                executable,
                "com.bill.mooring.mooringctl",
            )));
        }
    }
}

/// The steps [`script_daemon`]'s answers are asked for.
pub(crate) fn daemon_steps(daemon: Daemon<'_>) -> Vec<String> {
    let mut steps = vec![
        "/usr/bin/id -u".to_owned(),
        format!("/bin/launchctl print {}", service()),
    ];
    if matches!(daemon, Daemon::Running(_)) {
        steps.push(format!("/usr/bin/codesign -dv +{DAEMON_PID}"));
    }
    steps
}

/// A cargo, in `scratch`, that answers `metadata` with `target` as the
/// target and build directory and exits 9 for every other command, having
/// noted each command it was asked for ([`asked_of_cargo`]).
pub(crate) fn cargo_with_target(scratch: &Scratch, root: &Path, target: &Path) -> Cargo {
    let program = scratch.0.join("cargo");
    fs::write(
        &program,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{1}'\n[ \"$1\" = metadata ] || exit 9\nprintf '%s' '{{\"packages\":[],\"workspace_members\":[],\"resolve\":null,\"target_directory\":\"{0}\",\"build_directory\":\"{0}\"}}'\n",
            target.display(),
            asked_log(scratch).display()
        ),
    )
    .unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    Cargo::stand_in(program, root.to_path_buf())
}

fn asked_log(scratch: &Scratch) -> PathBuf {
    scratch.0.join("cargo-asked")
}

/// The commands [`cargo_with_target`]'s cargo was asked for since this was
/// last called, in order.
pub(crate) fn asked_of_cargo(scratch: &Scratch) -> Vec<String> {
    let log = asked_log(scratch);
    match fs::read_to_string(&log) {
        Ok(asked) => {
            fs::remove_file(log).unwrap();
            asked.lines().map(str::to_owned).collect()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("{}: {error}", log.display()),
    }
}

/// `codesign -dv +<pid>`'s report of a process that runs `executable`,
/// signed ad hoc with the hardened runtime as `identifier`, as macOS 27.2
/// wrote it for the daemon on 2026-11-10.
pub(crate) fn examined_process(executable: &Path, identifier: &str) -> Vec<u8> {
    format!(
        "Executable={}\nIdentifier={identifier}\nFormat=pid diskrep\nCodeDirectory v=20500 size=81084 flags=0x10002(adhoc,runtime) hashes=2528+2 location=embedded\nSignature=adhoc\nInfo.plist=not bound\nTeamIdentifier=not set\nRuntime Version=27.2.0\nSealed Resources=none\nInternal requirements count=0 size=12\n",
        executable.display()
    )
    .into_bytes()
}

/// `codesign -dv`'s report of an ad-hoc hardened-runtime signature with
/// `identifier`, as macOS 27 writes it.
pub(crate) fn signed_report(identifier: &str) -> Vec<u8> {
    format!(
        "Executable=x\nIdentifier={identifier}\nFormat=Mach-O thin (arm64)\nCodeDirectory v=20500 size=44028 flags=0x10002(adhoc,runtime) hashes=1370+2 location=embedded\nSignature=adhoc\n"
    )
    .into_bytes()
}
