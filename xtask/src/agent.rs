// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the registered daemon runs from (design §5.1), for the commands
//! that would take its executable away from under it.
//!
//! Since 2026-11-10 the daemon is registered from the installed app
//! (`cargo xtask install`, `~/Applications/Mooring.app`), outside the target
//! directory, so building the app again or cleaning the target directory
//! touches nothing it runs. Before, it was registered from the build itself
//! (`<target>/app/Mooring.app`), and a Mac that has not installed a build
//! since still runs it there.
//!
//! launchd names the daemon's program only relative to its bundle
//! (`launchctl print` shows `program identifier =
//! Contents/MacOS/mooringctl`), so where the daemon runs from is read from
//! its process: the pid `launchctl print` gives it, and what
//! `codesign -dv +<pid>` reports for that pid. `codesign` reports any
//! process, and the pid is not always the daemon's: launchd gives a
//! service its pid while `xpcproxy` has yet to become the service's
//! program, and the pid of a process that ended goes to another. So the
//! process is the daemon only when it is signed as `mooringctl`. A
//! registered daemon without such a process cannot be placed (launchd is
//! starting it, or refuses its starts, as after a rebuild; or its process
//! ended before it was examined), and is taken to be in the way.
//!
//! This is where the daemon runs now. Where launchd finds it at its next
//! start is macOS's own record of the registration, which this tool does
//! not read (design §5.1, "The installed app").

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::app::{AGENT_LABEL, AppError, Capture, LAUNCHCTL_NOT_FOUND, Programs, file_error, step};
use crate::mooringctl::{CODESIGN, SIGNING_IDENTIFIER, check_signed_as};

const LAUNCHCTL: &str = "/bin/launchctl";
const ID: &str = "/usr/bin/id";

/// The daemon, as launchd has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Agent {
    /// launchd does not list it.
    NotRegistered,
    /// launchd lists it, and its process runs `executable`.
    Running {
        /// `gui/<uid>/com.bill.mooring.daemon`.
        service: String,
        /// The process's executable, as the kernel names it.
        executable: PathBuf,
    },
    /// launchd lists it, and nothing tells which executable it runs.
    Unplaced {
        /// `gui/<uid>/com.bill.mooring.daemon`.
        service: String,
    },
}

/// The user's launchd domain, `gui/<uid>`.
fn gui_domain(programs: &mut impl Programs, root: &Path) -> Result<String, AppError> {
    let printed = programs.run(&step(ID, &[OsStr::new("-u")], root), Capture::Stdout)?;
    let text = String::from_utf8_lossy(&printed).trim().to_owned();
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(format!("gui/{text}"))
    } else {
        Err(AppError::UserId(text))
    }
}

/// The daemon's service, `gui/<uid>/com.bill.mooring.daemon`, with what
/// `launchctl print` says of it, if launchd lists it: found (exit 0) or
/// not found (113), and nothing else.
fn printed(
    programs: &mut impl Programs,
    root: &Path,
) -> Result<Option<(String, Vec<u8>)>, AppError> {
    let domain = gui_domain(programs, root)?;
    let service = format!("{domain}/{AGENT_LABEL}");
    let print = step(
        LAUNCHCTL,
        &[OsStr::new("print"), OsStr::new(&service)],
        root,
    );
    match programs.outcome(&print)? {
        (Some(0), printed) => Ok(Some((service, printed))),
        (Some(LAUNCHCTL_NOT_FOUND), _) => Ok(None),
        (code, _) => Err(AppError::AgentState { service, code }),
    }
}

/// The daemon's service if launchd lists it, wherever it runs from.
pub(crate) fn registered(
    programs: &mut impl Programs,
    root: &Path,
) -> Result<Option<String>, AppError> {
    Ok(printed(programs, root)?.map(|(service, _)| service))
}

/// The pid `launchctl print` gives a service that has a process: its
/// `pid = <n>` line, one tab in. The lines of the blocks nested in the
/// printout are further in.
pub(crate) fn printed_pid(printed: &[u8]) -> Option<u32> {
    String::from_utf8_lossy(printed)
        .lines()
        .find_map(|line| line.strip_prefix("\tpid = ")?.parse().ok())
}

/// The executable `codesign -dv` reports: its `Executable=<path>` line.
pub(crate) fn reported_executable(report: &[u8]) -> Option<PathBuf> {
    String::from_utf8_lossy(report)
        .lines()
        .find_map(|line| line.strip_prefix("Executable="))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// What `codesign -dv +<pid>` reports of the process `pid`, which it
/// writes to standard error. It reports any process there is, whoever
/// runs it, and fails for a pid that has none.
pub(crate) fn examined(
    programs: &mut impl Programs,
    root: &Path,
    pid: u32,
) -> Result<Vec<u8>, AppError> {
    let process = format!("+{pid}");
    programs.run(
        &step(CODESIGN, &[OsStr::new("-dv"), OsStr::new(&process)], root),
        Capture::Stderr,
    )
}

/// The daemon, as launchd has it now. The process launchd names is the
/// daemon when it is signed as `mooringctl`. One signed as anything else
/// is `xpcproxy` on its way to the daemon's program, or another process
/// that got the pid, and one `codesign` cannot report has ended since
/// launchd printed it: the daemon is then unplaced.
pub(crate) fn agent(programs: &mut impl Programs, root: &Path) -> Result<Agent, AppError> {
    let Some((service, printed)) = printed(programs, root)? else {
        return Ok(Agent::NotRegistered);
    };
    let Some(pid) = printed_pid(&printed) else {
        return Ok(Agent::Unplaced { service });
    };
    let executable = match examined(programs, root, pid) {
        Ok(report) => reported_executable(&report)
            .filter(|_| check_signed_as(&report, SIGNING_IDENTIFIER).is_ok()),
        Err(AppError::Failed { .. }) => None,
        Err(other) => return Err(other),
    };
    Ok(match executable {
        Some(executable) => Agent::Running {
            service,
            executable,
        },
        None => Agent::Unplaced { service },
    })
}

impl Agent {
    /// Nothing, when a command that replaces or removes `dirs` cannot
    /// take the daemon's executable away: the daemon is not registered,
    /// or runs from outside every one of them. A daemon that runs from
    /// inside one is `within`'s refusal, and one that cannot be placed is
    /// `AgentUnplaced`.
    pub(crate) fn clear_of(
        self,
        dirs: &[&Path],
        within: impl FnOnce(String, PathBuf) -> AppError,
    ) -> Result<(), AppError> {
        match self {
            Self::NotRegistered => Ok(()),
            Self::Unplaced { service } => Err(AppError::AgentUnplaced { service }),
            Self::Running {
                service,
                executable,
            } => {
                for dir in dirs {
                    if holds(dir, &executable)? {
                        return Err(within(service, executable));
                    }
                }
                Ok(())
            }
        }
    }
}

/// Whether `dir` holds `executable`, a process's executable as the kernel
/// names it: one of the directories above the executable is `dir` itself,
/// the same directory of the same volume. The two paths are not compared:
/// a directory may be given through a link (`/tmp`, `/var`), or through
/// the data volume's own mount point (`/System/Volumes/Data/Users/...`),
/// which resolves to itself while the kernel names what runs there
/// `/Users/...`. A directory that is not there holds nothing.
pub(crate) fn holds(dir: &Path, executable: &Path) -> Result<bool, AppError> {
    let Some(wanted) = identity(dir)? else {
        return Ok(false);
    };
    for above in executable.ancestors().skip(1) {
        if identity(above)? == Some(wanted) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The volume and the file number of what is at `path`, which no two
/// directories share; nothing when nothing is there.
fn identity(path: &Path) -> Result<Option<(u64, u64)>, AppError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(file_error("examine", path)(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use super::{Agent, agent, holds, printed_pid, registered, reported_executable};
    use crate::app::{AGENT_LABEL, AppError, Capture};
    use crate::testing::{Fake, Scratch, examined_process, failed};

    fn service() -> String {
        format!("gui/501/{AGENT_LABEL}")
    }

    /// `launchctl print` for the running daemon, as macOS 27.2 printed it
    /// on 2026-11-10 (the lines this tool does not read are cut).
    const RUNNING: &str = "gui/501/com.bill.mooring.daemon = {\n\tactive count = 1\n\tpath = (submitted by smd.570)\n\ttype = Submitted\n\tmanaged_by = com.apple.xpc.ServiceManagement\n\tstate = running\n\n\tprogram identifier = Contents/MacOS/mooringctl (mode: 2)\n\tparent bundle identifier = com.bill.mooring\n\targuments = {\n\t\tmooringctl\n\t\tdaemon\n\t}\n\n\tdomain = gui/501 [100017]\n\tminimum runtime = 60\n\texit timeout = 5\n\truns = 1\n\tpid = 36538\n\timmediate reason = speculative\n\tforks = 2\n\tlast exit code = (never exited)\n}\n";

    /// The same service while launchd refuses its starts, with a nested
    /// block that names a pid added: the printouts seen have none.
    const REFUSED: &str = "gui/501/com.bill.mooring.daemon = {\n\tactive count = 0\n\tstate = spawn scheduled\n\n\tprogram identifier = Contents/MacOS/mooringctl (mode: 2)\n\truns = 7\n\tlast exit code = 78: EX_CONFIG\n\n\tsemaphores = {\n\t\tpid = 1\n\t}\n\tjob state = spawn failed\n}\n";

    /// The executable of a daemon started from a build.
    const BUILT: &str = "/Users/op/mooring/target/app/Mooring.app/Contents/MacOS/mooringctl";

    /// `codesign -dv +<pid>` for the daemon, on standard error.
    fn examined() -> Vec<u8> {
        examined_process(Path::new(BUILT), "com.bill.mooring.mooringctl")
    }

    #[test]
    fn the_pid_is_the_services_own_line_and_no_nested_one() {
        assert_eq!(printed_pid(RUNNING.as_bytes()), Some(36538));
        // A nested block's `pid` is not the service's.
        assert_eq!(printed_pid(REFUSED.as_bytes()), None);
        for not_a_pid in [
            "",
            "pid = 7\n",
            "\tpid = \n",
            "\tpid = -4\n",
            "\tpid = 12 (exited)\n",
            "\tpid: 12\n",
            "\t pid = 12\n",
        ] {
            assert_eq!(printed_pid(not_a_pid.as_bytes()), None, "{not_a_pid:?}");
        }
    }

    #[test]
    fn the_executable_is_codesigns_own_line() {
        assert_eq!(reported_executable(&examined()), Some(PathBuf::from(BUILT)));
        for none in [
            "",
            "Executable=\n",
            "Identifier=com.bill.mooring.mooringctl\n",
            " Executable=/a\n",
            "executable=/a\n",
        ] {
            assert_eq!(reported_executable(none.as_bytes()), None, "{none:?}");
        }
    }

    /// launchd is asked once, and the process it names is examined once.
    #[test]
    fn a_running_daemon_is_placed_by_its_process() {
        let scratch = Scratch::new("agent-running");
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.outcomes
            .push_back((Some(0), RUNNING.as_bytes().to_vec()));
        fake.outputs.push_back(Ok(examined()));
        assert_eq!(
            agent(&mut fake, &scratch.0).unwrap(),
            Agent::Running {
                service: service(),
                executable: PathBuf::from(BUILT),
            }
        );
        assert_eq!(
            fake.steps,
            [
                ("/usr/bin/id -u".to_owned(), Capture::Stdout),
                (
                    format!("/bin/launchctl print {}", service()),
                    Capture::Stdout
                ),
                ("/usr/bin/codesign -dv +36538".to_owned(), Capture::Stderr),
            ]
        );
    }

    /// Not listed, the daemon is not registered, and no process is looked
    /// for; listed without a process, or with one that `codesign` cannot
    /// examine or reports no executable for, it is unplaced. So it is with
    /// a process that is not signed as `mooringctl` with the hardened
    /// runtime, as the daemon's program is: `xpcproxy`, which holds the
    /// service's pid until it becomes that program (its file's report on
    /// macOS 27.2, with a process's `Format` line), or whatever process
    /// got the pid after the daemon's ended (launchd's own report there).
    #[test]
    fn a_daemon_without_a_process_to_examine_is_unplaced() {
        let scratch = Scratch::new("agent-unplaced");
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.outcomes.push_back((Some(113), Vec::new()));
        assert_eq!(agent(&mut fake, &scratch.0).unwrap(), Agent::NotRegistered);
        assert_eq!(fake.steps.len(), 2);

        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.outcomes
            .push_back((Some(0), REFUSED.as_bytes().to_vec()));
        assert_eq!(
            agent(&mut fake, &scratch.0).unwrap(),
            Agent::Unplaced { service: service() }
        );
        assert_eq!(fake.steps.len(), 2, "no process, so none is examined");

        for report in [
            Err(failed("/usr/bin/codesign -dv +36538")),
            Ok(b"Identifier=com.bill.mooring.mooringctl\n".to_vec()),
            Ok(b"Executable=/usr/libexec/xpcproxy\nIdentifier=com.apple.xpc.proxy\nFormat=pid diskrep\nCodeDirectory v=20500 size=660 flags=0x10000(runtime) hashes=9+8 location=embedded\nPlatform identifier=27\nSignature size=4202\n".to_vec()),
            Ok(b"Executable=/sbin/launchd\nIdentifier=com.apple.xpc.launchd\nFormat=pid diskrep\nCodeDirectory v=20400 size=1646 flags=0x0(none) hashes=39+9 location=embedded\nPlatform identifier=27\nSignature size=4202\nSigned Time=Oct 4, 2026 at 01:03:45\nInfo.plist entries=18\nTeamIdentifier=not set\nSealed Resources=none\nInternal requirements count=1 size=72\n".to_vec()),
            Ok(String::from_utf8(examined())
                .unwrap()
                .replace("(adhoc,runtime)", "(adhoc)")
                .into_bytes()),
        ] {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.outcomes
                .push_back((Some(0), RUNNING.as_bytes().to_vec()));
            fake.outputs.push_back(report);
            assert_eq!(
                agent(&mut fake, &scratch.0).unwrap(),
                Agent::Unplaced { service: service() }
            );
            assert_eq!(fake.steps.len(), 3);
        }
    }

    /// `codesign` that cannot be started is that failure, not a daemon
    /// that cannot be placed; launchd answering neither found nor not
    /// found is `AgentState`; and a user id that is none stops before
    /// launchd is asked.
    #[test]
    fn what_cannot_be_asked_is_its_own_failure() {
        let scratch = Scratch::new("agent-failures");
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.outcomes
            .push_back((Some(0), RUNNING.as_bytes().to_vec()));
        fake.outputs.push_back(Err(AppError::XcodegenMissing));
        let error = agent(&mut fake, &scratch.0).unwrap_err();
        assert!(matches!(error, AppError::XcodegenMissing), "{error:?}");

        for ask in [agent_registered, agent_placed] {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.outcomes.push_back((Some(5), Vec::new()));
            let error = ask(&mut fake, &scratch.0).unwrap_err();
            assert!(
                matches!(&error, AppError::AgentState { service: named, code: Some(5) } if *named == service()),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                format!(
                    "`launchctl print {}` ended with Some(5), neither found (0) nor not found (113)",
                    service()
                )
            );

            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"root\n".to_vec()));
            let error = ask(&mut fake, &scratch.0).unwrap_err();
            assert!(
                matches!(&error, AppError::UserId(text) if text == "root"),
                "{error:?}"
            );
            assert_eq!(fake.steps.len(), 1);
        }
    }

    fn agent_registered(fake: &mut Fake, root: &Path) -> Result<(), AppError> {
        registered(fake, root).map(|_| ())
    }

    fn agent_placed(fake: &mut Fake, root: &Path) -> Result<(), AppError> {
        agent(fake, root).map(|_| ())
    }

    /// Whether launchd lists the daemon needs no process: it is asked
    /// once, and nothing is examined.
    #[test]
    fn registered_is_what_launchd_lists() {
        let scratch = Scratch::new("agent-registered");
        for (code, printed, listed) in [(0, RUNNING, true), (0, REFUSED, true), (113, "", false)] {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.outcomes
                .push_back((Some(code), printed.as_bytes().to_vec()));
            assert_eq!(
                registered(&mut fake, &scratch.0).unwrap(),
                listed.then(service)
            );
            assert_eq!(fake.steps.len(), 2);
        }
    }

    fn refusal(service: String, executable: PathBuf) -> AppError {
        AppError::AgentLoaded {
            service,
            executable,
        }
    }

    /// A daemon that is not registered is in no command's way, one that
    /// cannot be placed is in every command's, and a running one only in
    /// the way of a command whose directories hold its executable.
    #[test]
    fn a_daemon_is_in_the_way_only_from_inside_the_directories() {
        let scratch = Scratch::new("agent-within");
        let resolved = fs::canonicalize(&scratch.0).unwrap();
        let target = resolved.join("target");
        let build = resolved.join("build");
        fs::create_dir_all(target.join("app")).unwrap();
        fs::create_dir(&build).unwrap();
        let inside = target.join("app/Mooring.app/Contents/MacOS/mooringctl");
        let installed = resolved.join("Applications/Mooring.app/Contents/MacOS/mooringctl");
        let running = |executable: &Path| Agent::Running {
            service: service(),
            executable: executable.to_path_buf(),
        };

        Agent::NotRegistered.clear_of(&[&target], refusal).unwrap();
        let error = Agent::Unplaced { service: service() }
            .clear_of(&[], refusal)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{} is registered but has no process that tells where it runs from (launchd is starting it, or refuses its starts): run this again once it runs, or stop it first (Mooring.app's menu: Stop the Daemon)",
                service()
            )
        );

        running(&installed)
            .clear_of(&[&target, &build], refusal)
            .unwrap();
        for dirs in [
            vec![target.as_path()],
            vec![build.as_path(), target.as_path()],
            vec![target.join("app").as_path().to_path_buf().as_path()],
        ] {
            let error = running(&inside).clear_of(&dirs, refusal).unwrap_err();
            assert!(
                matches!(&error, AppError::AgentLoaded { service: named, executable } if *named == service() && *executable == inside),
                "{error:?}"
            );
        }
        // A sibling whose name the directory's begins is not inside it.
        running(&resolved.join("target-other/app/mooringctl"))
            .clear_of(&[&target], refusal)
            .unwrap();
        // A directory that is not there holds nothing, and neither does
        // a file.
        running(&inside)
            .clear_of(&[&resolved.join("absent")], refusal)
            .unwrap();
        let file = resolved.join("file");
        fs::write(&file, b"").unwrap();
        running(&file.join("app/mooringctl"))
            .clear_of(&[&target], refusal)
            .unwrap();
        // The daemon's app may be gone from under it: the directories
        // that are left above its executable still hold it.
        assert!(!inside.parent().unwrap().exists());
        assert!(holds(&target, &inside).unwrap());
        assert!(!holds(&build, &inside).unwrap());
    }

    /// A directory holds what runs in it by being the same directory, not
    /// by its path: a target directory given through a link holds what
    /// runs in the directory the link names, and so does one named plainly
    /// when the executable's own path goes through a link.
    #[test]
    fn a_directory_given_through_a_link_holds_what_runs_in_it() {
        let scratch = Scratch::new("agent-link");
        let resolved = fs::canonicalize(&scratch.0).unwrap();
        let real = resolved.join("real-target");
        fs::create_dir(&real).unwrap();
        let link = resolved.join("target");
        symlink(&real, &link).unwrap();
        let error = Agent::Running {
            service: service(),
            executable: real.join("app/Mooring.app/Contents/MacOS/mooringctl"),
        }
        .clear_of(&[&link], refusal)
        .unwrap_err();
        assert!(matches!(error, AppError::AgentLoaded { .. }), "{error:?}");
        assert!(
            holds(
                &real,
                &link.join("app/Mooring.app/Contents/MacOS/mooringctl")
            )
            .unwrap()
        );
        // A directory that cannot be examined is its own failure.
        let looped = resolved.join("loop");
        symlink(&looped, &looped).unwrap();
        let error = Agent::Running {
            service: service(),
            executable: real.join("mooringctl"),
        }
        .clear_of(&[&looped], refusal)
        .unwrap_err();
        assert!(
            matches!(&error, AppError::File { action: "examine", path, .. } if *path == looped),
            "{error:?}"
        );
    }

    /// The data volume's mount point resolves to itself, so a directory
    /// given through it never begins the path the kernel names a process's
    /// executable by. It is the same directory all the same.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_given_through_the_data_volume_holds_what_runs_in_it() {
        let scratch = Scratch::new("agent-data-volume");
        let resolved = fs::canonicalize(&scratch.0).unwrap();
        let target = resolved.join("target");
        fs::create_dir(&target).unwrap();
        let through = Path::new("/System/Volumes/Data").join(target.strip_prefix("/").unwrap());
        assert_eq!(fs::canonicalize(&through).unwrap(), through);
        let executable = target.join("app/Mooring.app/Contents/MacOS/mooringctl");
        assert!(!executable.starts_with(&through));
        assert!(holds(&through, &executable).unwrap());
        assert!(!holds(&through.join("app"), &executable).unwrap());
    }
}
