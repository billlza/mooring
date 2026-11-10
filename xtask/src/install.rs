// SPDX-License-Identifier: GPL-3.0-or-later

//! `install` (design §5.1), macOS only and not a `ci` step: moves the app
//! `cargo xtask app` built, `<target>/app/Mooring.app`, to
//! `~/Applications/Mooring.app`, which the daemon is started from.
//!
//! The daemon is registered from the app that carries it, and launchd runs
//! the `mooringctl` inside that app. Until 2026-11-10 that app was the
//! build itself, in the target directory, so a clean of the target
//! directory, which a plain `cargo clean` does without asking this tool,
//! deleted the app, its `mooringctl` and its power helper under the running
//! daemon, and the app could not be built while the daemon served. The
//! installed app is outside the target directory, and carries its own
//! `mooringctl`, the one build the daemon and the operator's commands then
//! share.
//!
//! The command refuses while launchd lists the daemon, wherever it runs
//! from: the registration pins the `mooringctl` it was made with by its
//! cdhash, so one installed over it would not start, and the build's app,
//! which the command moves away, is what a daemon started from the build
//! runs. It refuses while a process runs one of the three programs the app
//! carries from the build's app or from the installed one, since it
//! removes the one and replaces the other: Mooring.app open, the
//! `mooringctl` it keeps running for the console, an operator's own
//! `mooringctl` command, the power helper. The processes are found by
//! name and placed by the executable the kernel names for each, as the
//! daemon is ([`crate::agent`]): a command line tells less, since launchd
//! starts the daemon as plain `mooringctl`.
//!
//! It then checks the build's seal and the three identifiers, copies the
//! app beside its destination, checks the copy the same way, puts it in
//! place of the app installed before, and removes the build's app, so that
//! no app is left in `<target>/app` to open. One install runs at a time:
//! the command holds a lock on `~/Applications` from before the copy, so
//! that a second one cannot remove the copy the first is making, or put a
//! half-made one in place. A failure up to the copy's check leaves the app
//! installed before as it was.
//!
//! What is checked is then acted on, and a person can get in between: an
//! app opened, and the daemon started from it, while the copy is made is
//! not seen.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::agent;
use crate::app::{
    AGENT_LABEL, APP_EXECUTABLE, APP_IDENTIFIER, AppError, AppPaths, Bundle, CLI_EXECUTABLE,
    Capture, DITTO, POWER_EXECUTABLE, Programs, System, check_signatures, file_error, remove_tree,
    require_macos, step,
};
use crate::cargo::Cargo;
use crate::metadata;
use crate::output::say;

const PGREP: &str = "/usr/bin/pgrep";

/// `pgrep`'s exit status when no process matched.
const PGREP_NONE: i32 = 1;

/// Where the app is installed, under the operator's home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    /// `~/Applications`.
    pub(crate) dir: PathBuf,
    /// The installed app, `~/Applications/Mooring.app`.
    pub(crate) app: PathBuf,
    /// The copy on its way there, in the same directory, so that putting
    /// it in place is one rename; Finder does not show it.
    pub(crate) staging: PathBuf,
}

impl Installed {
    pub(crate) fn under(home: &Path) -> Self {
        let dir = home.join("Applications");
        Self {
            app: dir.join("Mooring.app"),
            staging: dir.join(".Mooring.app.installing"),
            dir,
        }
    }
}

/// The operator's home directory, from `HOME`: set, and absolute, since
/// the programs run in the workspace's root and the files are handled
/// from wherever the command was started.
pub(crate) fn home_from(home: Option<OsString>) -> Result<PathBuf, AppError> {
    let home = home
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or(AppError::HomeUnset)?;
    if home.is_absolute() {
        Ok(home)
    } else {
        Err(AppError::HomeRelative { home })
    }
}

/// `cargo xtask install`.
pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), AppError> {
    require_macos("install", std::env::consts::OS)?;
    let home = home_from(std::env::var_os("HOME"))?;
    install_with(&mut System, cargo, &home, out)
}

/// [`run`] past the host check, into `home`, with `programs` running every
/// step but cargo's.
fn install_with(
    programs: &mut impl Programs,
    cargo: &Cargo,
    home: &Path,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let root = cargo.workspace_root().to_path_buf();
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let built = AppPaths::new(&root, &target).bundle();
    place(programs, &root, &built, &Installed::under(home), out)
}

/// `pgrep -x`'s pattern for the processes that run the three programs an
/// app carries: a process is named after its program's file.
fn process_names() -> String {
    format!("{APP_EXECUTABLE}|{CLI_EXECUTABLE}|{POWER_EXECUTABLE}")
}

/// `AppInUse` while a process runs one of an app's three programs from
/// inside one of `apps`. The processes are found by name; each one's
/// executable is the one the kernel names (`codesign -dv +<pid>`), and
/// the app that holds it is found as the daemon's is ([`agent::holds`]).
/// A process that cannot be examined may have ended since it was listed,
/// and is not taken to have: `ProcessUnplaced`.
fn refuse_while_in_use(
    programs: &mut impl Programs,
    root: &Path,
    apps: [&Bundle; 2],
) -> Result<(), AppError> {
    let find = step(
        PGREP,
        &[OsStr::new("-x"), OsStr::new(&process_names())],
        root,
    );
    let listed = match programs.outcome(&find)? {
        (Some(PGREP_NONE), _) => return Ok(()),
        (Some(0), listed) => listed,
        (code, _) => return Err(AppError::ProcessState { code }),
    };
    for line in String::from_utf8_lossy(&listed).lines() {
        let pid: u32 = line
            .parse()
            .map_err(|_| AppError::ProcessList(line.to_owned()))?;
        let executable = match agent::examined(programs, root, pid) {
            Ok(report) => agent::reported_executable(&report),
            Err(AppError::Failed { .. }) => None,
            Err(other) => return Err(other),
        }
        .ok_or(AppError::ProcessUnplaced { pid })?;
        for app in apps {
            if agent::holds(&app.app, &executable)? {
                return Err(AppError::AppInUse {
                    app: app.app.clone(),
                    pid,
                    executable,
                });
            }
        }
    }
    Ok(())
}

/// The lock on `dir` that one install holds: another one, running now,
/// is `InstallRunning`. Dropping it gives the lock up.
fn alone_in(dir: &Path) -> Result<File, AppError> {
    let held = File::open(dir).map_err(file_error("open", dir))?;
    match held.try_lock() {
        Ok(()) => Ok(held),
        Err(TryLockError::WouldBlock) => Err(AppError::InstallRunning {
            dir: dir.to_path_buf(),
        }),
        Err(TryLockError::Error(error)) => Err(file_error("lock", dir)(error)),
    }
}

/// The install of `built` as `installed`: the refusals and the build's
/// check, which write nothing, then the lock, the copy and its check, the
/// swap, and the removal of the build's app.
pub(crate) fn place(
    programs: &mut impl Programs,
    root: &Path,
    built: &Bundle,
    installed: &Installed,
    out: &mut impl Write,
) -> Result<(), AppError> {
    if let Some(service) = agent::registered(programs, root)? {
        return Err(AppError::InstallWhileRegistered { service });
    }
    if !built.app.is_dir() {
        return Err(AppError::NotBuilt {
            path: built.app.clone(),
        });
    }
    let placed = Bundle::at(installed.app.clone());
    refuse_while_in_use(programs, root, [built, &placed])?;
    check_signatures(programs, root, built)?;
    fs::create_dir_all(&installed.dir).map_err(file_error("create", &installed.dir))?;
    let _alone = alone_in(&installed.dir)?;
    remove_tree(&installed.staging)?;
    programs.run(
        &step(
            DITTO,
            &[built.app.as_os_str(), installed.staging.as_os_str()],
            root,
        ),
        Capture::Inherit,
    )?;
    check_signatures(programs, root, &Bundle::at(installed.staging.clone()))?;
    remove_tree(&installed.app)?;
    fs::rename(&installed.staging, &installed.app).map_err(|source| AppError::NotPutInPlace {
        installed: installed.app.clone(),
        built: built.app.clone(),
        source,
    })?;
    remove_tree(&built.app).map_err(|error| match error {
        AppError::File { source, .. } => AppError::BuildCopyLeft {
            installed: installed.app.clone(),
            built: built.app.clone(),
            source,
        },
        other => other,
    })?;
    say!(
        out,
        "install: {} is installed, signed ad hoc as {APP_IDENTIFIER}, and the build's app is gone from {}; open it and choose Start the Daemon at Login. If the daemon was registered from another build, macOS refuses that first start under that build's launch constraint: once `launchctl print gui/$(id -u)/{AGENT_LABEL}` shows `last exit code = 78: EX_CONFIG` (about a minute later), choose Stop the Daemon, then Start the Daemon at Login again. Run the deployment's commands with {}, the build the daemon runs",
        placed.app.display(),
        built.app.display(),
        placed.embedded.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::{self, File, TryLockError};
    use std::io;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::{Installed, home_from, install_with, place};
    use crate::app::{AGENT_LABEL, AppError, AppPaths, Bundle};
    use crate::testing::{
        Daemon, Fake, Scratch, asked_of_cargo, cargo_with_target, daemon_steps, examined_process,
        failed, script_daemon, service, signed_report,
    };

    /// The processes are looked for by the names of the three programs
    /// the app carries.
    const PGREP: &str = "/usr/bin/pgrep -x Mooring|mooringctl|mooring-power";

    /// A built app in a scratch target directory, with one file in it, and
    /// where it is to be installed.
    fn built(scratch: &Scratch) -> (PathBuf, Bundle, Installed) {
        built_in(&scratch.0)
    }

    /// [`built`], with the scratch directory named `dir`.
    fn built_in(dir: &Path) -> (PathBuf, Bundle, Installed) {
        let root = dir.join("repo");
        fs::create_dir_all(&root).unwrap();
        let bundle = AppPaths::new(&root, &dir.join("target")).bundle();
        fs::create_dir_all(bundle.embedded.parent().unwrap()).unwrap();
        fs::write(&bundle.embedded, b"the build's mooringctl").unwrap();
        (root, bundle, Installed::under(&dir.join("home")))
    }

    /// Scripts one bundle's seal and three identifiers twice over, the
    /// build's and the copy's, with the copy between them.
    fn script_the_checks(fake: &mut Fake) {
        for _ in 0..2 {
            fake.outputs.push_back(Ok(Vec::new()));
            fake.outputs
                .push_back(Ok(signed_report("com.bill.mooring")));
            fake.outputs
                .push_back(Ok(signed_report("com.bill.mooring.mooringctl")));
            fake.outputs
                .push_back(Ok(signed_report("com.bill.mooring.power")));
            // After the build's checks, the copy.
            fake.outputs.push_back(Ok(Vec::new()));
        }
    }

    /// Scripts a daemon that launchd does not list, no process with one of
    /// the app's names, and the checks.
    fn script_a_clean_install(fake: &mut Fake) {
        script_daemon(fake, Daemon::NotRegistered);
        fake.outcomes.push_back((Some(1), Vec::new()));
        script_the_checks(fake);
    }

    /// The steps up to the look for the app's processes.
    fn first_steps() -> Vec<String> {
        let mut steps = daemon_steps(Daemon::NotRegistered);
        steps.push(PGREP.to_owned());
        steps
    }

    fn lines(fake: &Fake) -> Vec<String> {
        fake.steps.iter().map(|(line, _)| line.clone()).collect()
    }

    #[test]
    fn the_app_is_installed_under_the_home_directory() {
        let installed = Installed::under(Path::new("/Users/op"));
        assert_eq!(installed.dir, Path::new("/Users/op/Applications"));
        assert_eq!(
            installed.app,
            Path::new("/Users/op/Applications/Mooring.app")
        );
        assert_eq!(
            installed.staging,
            Path::new("/Users/op/Applications/.Mooring.app.installing")
        );
    }

    /// The home directory is `HOME`'s, which must be set and absolute: the
    /// programs run in the workspace's root, so a relative one would name
    /// two directories.
    #[test]
    fn the_home_directory_is_set_and_absolute() {
        assert_eq!(
            home_from(Some(OsString::from("/Users/op"))).unwrap(),
            Path::new("/Users/op")
        );
        for unset in [None, Some(OsString::new())] {
            let error = home_from(unset).unwrap_err();
            assert!(matches!(error, AppError::HomeUnset), "{error:?}");
            assert_eq!(
                error.to_string(),
                "HOME is not set, so there is no ~/Applications to install into"
            );
        }
        let error = home_from(Some(OsString::from("home/op"))).unwrap_err();
        assert!(
            matches!(&error, AppError::HomeRelative { home } if home == Path::new("home/op")),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "HOME is home/op, not an absolute path, so ~/Applications cannot be told from a directory of the repository"
        );
    }

    /// The build's app is checked, copied beside its destination, checked
    /// again there, put in place, and removed from the target directory,
    /// in that order, after launchd was found not to list the daemon and
    /// no process was found with one of the app's names.
    #[test]
    fn the_built_app_is_checked_copied_checked_and_moved_into_place() {
        let scratch = Scratch::new("install-place");
        let (root, bundle, installed) = built(&scratch);
        let mut fake = Fake::default();
        script_a_clean_install(&mut fake);
        let mut out = Vec::new();
        place(&mut fake, &root, &bundle, &installed, &mut out).unwrap();

        let app = bundle.app.display().to_string();
        let staging = installed.staging.display().to_string();
        let placed = Bundle::at(installed.app.clone());
        let mut steps = first_steps();
        steps.extend([
            format!("/usr/bin/codesign --verify --strict {app}"),
            format!("/usr/bin/codesign -dv {app}"),
            format!("/usr/bin/codesign -dv {app}/Contents/MacOS/mooringctl"),
            format!("/usr/bin/codesign -dv {app}/Contents/MacOS/mooring-power"),
            format!("/usr/bin/ditto {app} {staging}"),
            format!("/usr/bin/codesign --verify --strict {staging}"),
            format!("/usr/bin/codesign -dv {staging}"),
            format!("/usr/bin/codesign -dv {staging}/Contents/MacOS/mooringctl"),
            format!("/usr/bin/codesign -dv {staging}/Contents/MacOS/mooring-power"),
        ]);
        assert_eq!(lines(&fake), steps);
        assert!(installed.app.join("Contents/MacOS").is_dir());
        assert!(!installed.staging.exists());
        assert!(
            !bundle.app.exists(),
            "the build's app was moved, not copied"
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "install: {} is installed, signed ad hoc as com.bill.mooring, and the build's app is gone from {app}; open it and choose Start the Daemon at Login. If the daemon was registered from another build, macOS refuses that first start under that build's launch constraint: once `launchctl print gui/$(id -u)/{AGENT_LABEL}` shows `last exit code = 78: EX_CONFIG` (about a minute later), choose Stop the Daemon, then Start the Daemon at Login again. Run the deployment's commands with {}, the build the daemon runs\n",
                installed.app.display(),
                placed.embedded.display()
            )
        );
    }

    /// The app installed before is replaced whole, and a copy an earlier
    /// run left on its way is not installed.
    #[test]
    fn an_earlier_install_and_an_abandoned_copy_are_replaced() {
        let scratch = Scratch::new("install-replace");
        let (root, bundle, installed) = built(&scratch);
        fs::create_dir_all(installed.app.join("Contents/Old")).unwrap();
        fs::write(installed.app.join("Contents/Old/file"), b"old").unwrap();
        fs::create_dir_all(installed.staging.join("Contents/Abandoned")).unwrap();
        let mut fake = Fake::default();
        script_a_clean_install(&mut fake);
        place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap();
        assert!(installed.app.join("Contents/MacOS").is_dir());
        assert!(!installed.app.join("Contents/Old").exists());
        assert!(!installed.app.join("Contents/Abandoned").exists());
        assert!(!installed.staging.exists());
    }

    /// Nothing is installed from a target directory that holds no built
    /// app: launchd alone is asked, and nothing is made.
    #[test]
    fn an_app_that_is_not_built_is_not_installed() {
        let scratch = Scratch::new("install-unbuilt");
        let (root, bundle, installed) = built(&scratch);
        fs::remove_dir_all(&bundle.app).unwrap();
        let mut fake = Fake::default();
        script_daemon(&mut fake, Daemon::NotRegistered);
        let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::NotBuilt { path } if *path == bundle.app),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "{} is not there: `cargo xtask app` builds it",
                bundle.app.display()
            )
        );
        assert_eq!(lines(&fake), daemon_steps(Daemon::NotRegistered));
        assert!(!installed.dir.exists());
    }

    /// A process that runs one of the app's programs from the build's app
    /// or from the installed one stops the install before anything is
    /// checked or copied: the app itself, the `mooringctl` it carries,
    /// which launchd and the console start by name alone, or the power
    /// helper. Each process is placed by the executable the kernel names
    /// for it, and the ones before it that run from elsewhere are passed
    /// over. The apps are given through a link here, which the kernel's
    /// names do not go through. The link is the test's own: a temporary
    /// directory is behind one on macOS (`/var`) and behind none on Linux.
    #[test]
    fn an_app_in_use_is_not_replaced() {
        let scratch = Scratch::new("install-in-use");
        let named = fs::canonicalize(&scratch.0).unwrap().join("named");
        fs::create_dir(&named).unwrap();
        let link = scratch.0.join("link");
        symlink(&named, &link).unwrap();
        let (root, bundle, installed) = built_in(&link);
        fs::create_dir_all(installed.app.join("Contents/Old")).unwrap();
        // As the kernel names them.
        let build = Bundle::at(fs::canonicalize(&bundle.app).unwrap());
        assert_eq!(build.app, named.join("target/app/Mooring.app"));
        let placed = Bundle::at(fs::canonicalize(&installed.app).unwrap());
        assert_eq!(placed.app, named.join("home/Applications/Mooring.app"));
        let elsewhere =
            Path::new("/Users/op/mooring/target/app/Mooring.app/Contents/MacOS/Mooring");
        for (executable, identifier, app) in [
            (
                build.app.join("Contents/MacOS/Mooring"),
                "com.bill.mooring",
                &bundle.app,
            ),
            (
                build.embedded.clone(),
                "com.bill.mooring.mooringctl",
                &bundle.app,
            ),
            (build.power.clone(), "com.bill.mooring.power", &bundle.app),
            (
                placed.app.join("Contents/MacOS/Mooring"),
                "com.bill.mooring",
                &installed.app,
            ),
            (
                placed.embedded.clone(),
                "com.bill.mooring.mooringctl",
                &installed.app,
            ),
        ] {
            let mut fake = Fake::default();
            script_daemon(&mut fake, Daemon::NotRegistered);
            fake.outcomes
                .push_back((Some(0), b"401\n402\n403\n".to_vec()));
            fake.outputs
                .push_back(Ok(examined_process(elsewhere, "com.bill.mooring")));
            fake.outputs
                .push_back(Ok(examined_process(&executable, identifier)));
            let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(&error, AppError::AppInUse { app: named, pid: 402, executable: runs } if named == app && *runs == executable),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                format!(
                    "{} is in use: process 402 runs {}. Quit Mooring.app (its menu: Quit Mooring), let any `mooringctl` command started from that app end, then run `cargo xtask install` again",
                    app.display(),
                    executable.display()
                )
            );
            let mut steps = first_steps();
            steps.extend([
                "/usr/bin/codesign -dv +401".to_owned(),
                "/usr/bin/codesign -dv +402".to_owned(),
            ]);
            assert_eq!(lines(&fake), steps, "the third process was not reached");
            assert!(bundle.app.is_dir());
            assert!(installed.app.join("Contents/Old").is_dir());
            assert!(!installed.staging.exists());
        }
    }

    /// Processes with the app's names that run from elsewhere, as another
    /// checkout's daemon and console do, are not in the way: each is
    /// examined, and the install goes on.
    #[test]
    fn processes_that_run_from_elsewhere_are_not_in_the_way() {
        let scratch = Scratch::new("install-elsewhere");
        let (root, bundle, installed) = built(&scratch);
        let mut fake = Fake::default();
        script_daemon(&mut fake, Daemon::NotRegistered);
        fake.outcomes
            .push_back((Some(0), b"22571\n36538\n".to_vec()));
        fake.outputs.push_back(Ok(examined_process(
            Path::new("/Users/op/mooring/target/app/Mooring.app/Contents/MacOS/Mooring"),
            "com.bill.mooring",
        )));
        fake.outputs.push_back(Ok(examined_process(
            Path::new("/Users/op/mooring/target/app/Mooring.app/Contents/MacOS/mooringctl"),
            "com.bill.mooring.mooringctl",
        )));
        script_the_checks(&mut fake);
        place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap();
        assert_eq!(
            lines(&fake)[3..5],
            [
                "/usr/bin/codesign -dv +22571".to_owned(),
                "/usr/bin/codesign -dv +36538".to_owned(),
            ]
        );
        assert!(installed.app.join("Contents/MacOS").is_dir());
        assert!(!bundle.app.exists());
    }

    /// What cannot be found out about the app's processes stops the
    /// install too: `pgrep` answering neither a match nor none, or
    /// printing what is no process id, and a process that ended, or tells
    /// no executable, before it was placed.
    #[test]
    fn processes_that_cannot_be_placed_stop_the_install() {
        let scratch = Scratch::new("install-unplaced");
        let (root, bundle, installed) = built(&scratch);
        fs::create_dir_all(installed.app.join("Contents/Old")).unwrap();
        let refused = |listed: (Option<i32>, &[u8]), report: Option<Result<Vec<u8>, AppError>>| {
            let mut fake = Fake::default();
            script_daemon(&mut fake, Daemon::NotRegistered);
            fake.outcomes.push_back((listed.0, listed.1.to_vec()));
            let examined = usize::from(report.is_some());
            fake.outputs.extend(report);
            let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
            assert_eq!(fake.steps.len(), 3 + examined);
            assert!(bundle.app.is_dir());
            assert!(installed.app.join("Contents/Old").is_dir());
            assert!(!installed.staging.exists());
            error
        };

        for code in [Some(2), Some(3), None] {
            let error = refused((code, b""), None);
            assert!(
                matches!(&error, AppError::ProcessState { code: ended } if *ended == code),
                "{error:?}"
            );
        }
        assert_eq!(
            refused((Some(2), b""), None).to_string(),
            "`pgrep` for the app's processes ended with Some(2), neither a match (0) nor none (1)"
        );

        for listed in ["12a\n", " 12\n", "-4\n", "\n12\n"] {
            let error = refused((Some(0), listed.as_bytes()), None);
            let line = listed.lines().next().unwrap();
            assert!(
                matches!(&error, AppError::ProcessList(printed) if printed == line),
                "{error:?}"
            );
        }
        assert_eq!(
            refused((Some(0), b"12a\n"), None).to_string(),
            "`pgrep` printed \"12a\", not a process id"
        );

        for report in [
            Err(failed("/usr/bin/codesign -dv +402")),
            Ok(b"Identifier=com.bill.mooring\n".to_vec()),
        ] {
            let error = refused((Some(0), b"402\n"), Some(report));
            assert!(
                matches!(error, AppError::ProcessUnplaced { pid: 402 }),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                "process 402 has one of the app's names, and ended or could not be examined before it was known where it runs from: run `cargo xtask install` again"
            );
        }
        // `codesign` that cannot be started is that failure.
        let error = refused((Some(0), b"402\n"), Some(Err(AppError::XcodegenMissing)));
        assert!(matches!(error, AppError::XcodegenMissing), "{error:?}");
    }

    /// A build whose seal or identifiers do not check is not copied, and a
    /// copy that does not check is not put in place: the app installed
    /// before stays as it was, and the build's app is not removed.
    #[test]
    fn a_build_or_a_copy_that_does_not_check_installs_nothing() {
        let scratch = Scratch::new("install-unchecked");
        let (root, bundle, installed) = built(&scratch);
        fs::create_dir_all(installed.app.join("Contents/Old")).unwrap();
        // The runs before the failing one: the build's four checks, the
        // copy, and the copy's first check.
        for (passing, copied) in [(0, false), (2, false), (5, true), (7, true)] {
            let mut fake = Fake::default();
            script_daemon(&mut fake, Daemon::NotRegistered);
            fake.outcomes.push_back((Some(1), Vec::new()));
            let reports = [
                Vec::new(),
                signed_report("com.bill.mooring"),
                signed_report("com.bill.mooring.mooringctl"),
                signed_report("com.bill.mooring.power"),
                Vec::new(),
                Vec::new(),
                signed_report("com.bill.mooring"),
                signed_report("com.bill.mooring.mooringctl"),
            ];
            for report in reports.iter().take(passing) {
                fake.outputs.push_back(Ok(report.clone()));
            }
            fake.outputs.push_back(if passing == 0 || passing == 5 {
                Err(failed("codesign --verify --strict"))
            } else {
                Ok(signed_report("com.example.other"))
            });
            let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(error, AppError::Failed { .. } | AppError::Signature { .. }),
                "{error:?}"
            );
            assert_eq!(fake.steps.len(), 3 + passing + 1);
            assert!(bundle.app.is_dir(), "the build's app stays");
            assert!(
                installed.app.join("Contents/Old").is_dir(),
                "the app installed before stays"
            );
            assert_eq!(installed.staging.exists(), copied);
            if copied {
                fs::remove_dir_all(&installed.staging).unwrap();
            }
        }
    }

    /// One install runs at a time: while another holds `~/Applications`,
    /// nothing is copied, and once it has ended the install goes through
    /// and gives the directory up in its turn.
    #[test]
    fn one_install_runs_at_a_time() {
        let scratch = Scratch::new("install-alone");
        let (root, bundle, installed) = built(&scratch);
        fs::create_dir_all(&installed.dir).unwrap();
        let other = File::open(&installed.dir).unwrap();
        other.lock().unwrap();
        let mut fake = Fake::default();
        script_a_clean_install(&mut fake);
        let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::InstallRunning { dir } if *dir == installed.dir),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "another `cargo xtask install` is at work in {}: wait for it to end",
                installed.dir.display()
            )
        );
        assert_eq!(fake.steps.len(), 3 + 4, "the build was checked, not copied");
        assert!(bundle.app.is_dir());
        assert!(!installed.staging.exists());
        assert!(!installed.app.exists());

        drop(other);
        for _ in 0..2 {
            fs::create_dir_all(bundle.embedded.parent().unwrap()).unwrap();
            let mut fake = Fake::default();
            script_a_clean_install(&mut fake);
            // The directory is held while the copy is made.
            let dir = installed.dir.clone();
            fake.after = Some((
                format!(
                    "/usr/bin/ditto {} {}",
                    bundle.app.display(),
                    installed.staging.display()
                ),
                Box::new(move || {
                    let another = File::open(dir).unwrap();
                    assert!(matches!(another.try_lock(), Err(TryLockError::WouldBlock)));
                }),
            ));
            place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap();
            assert!(fake.after.is_none(), "the copy was made");
            assert!(installed.app.join("Contents/MacOS").is_dir());
        }
    }

    /// A checked copy that cannot be moved into place leaves no app
    /// installed, which the failure says, with the build's app, which is
    /// still there to install again.
    #[test]
    fn a_copy_that_cannot_be_put_in_place_is_named() {
        let scratch = Scratch::new("install-not-placed");
        let (root, bundle, installed) = built(&scratch);
        fs::create_dir_all(installed.app.join("Contents/Old")).unwrap();
        let mut fake = Fake::default();
        script_a_clean_install(&mut fake);
        // The copy is gone once its last check has run.
        let staging = installed.staging.clone();
        fake.after = Some((
            format!(
                "/usr/bin/codesign -dv {}/Contents/MacOS/mooring-power",
                staging.display()
            ),
            Box::new(move || fs::remove_dir_all(staging).unwrap()),
        ));
        let error = place(&mut fake, &root, &bundle, &installed, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::NotPutInPlace { installed: placed, built, source } if *placed == installed.app && *built == bundle.app && source.kind() == io::ErrorKind::NotFound),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "no app is installed at {}: the checked copy could not be moved there after the app installed before was removed. The build's app is still at {}; run `cargo xtask install` again",
                installed.app.display(),
                bundle.app.display()
            )
        );
        assert!(fake.after.is_none());
        assert!(!installed.app.exists());
        assert!(bundle.app.is_dir());
    }

    /// A build's app that cannot be removed once the copy is in place is
    /// said to be left, with the app installed.
    #[test]
    fn a_build_that_cannot_be_removed_is_named_as_left() {
        let scratch = Scratch::new("install-left");
        let (root, bundle, installed) = built(&scratch);
        let holder = bundle.app.parent().unwrap().to_path_buf();
        let mut fake = Fake::default();
        script_a_clean_install(&mut fake);
        // Nothing can be removed from a directory that cannot be written.
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o500)).unwrap();
        let result = place(&mut fake, &root, &bundle, &installed, &mut Vec::new());
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err();
        assert!(
            matches!(&error, AppError::BuildCopyLeft { installed: placed, built, .. } if *placed == installed.app && *built == bundle.app),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "{} is installed, but the build's copy at {} could not be removed: remove it by hand, so that only the installed app is there to open",
                installed.app.display(),
                bundle.app.display()
            )
        );
        assert!(installed.app.join("Contents/MacOS").is_dir());
    }

    /// A registered daemon refuses the install, wherever the daemon runs
    /// from and whether or not it has a process: cargo is asked only where
    /// the target directory is, launchd alone is asked after it, and
    /// nothing is made. Unregistered, the install goes on to the build's
    /// app, here one that is not there.
    #[test]
    fn an_install_is_refused_while_the_daemon_is_registered() {
        let scratch = Scratch::new("install-registered");
        let root = scratch.0.join("repo");
        fs::create_dir_all(&root).unwrap();
        let target = scratch.0.join("target");
        let cargo = cargo_with_target(&scratch, &root, &target);
        let home = scratch.0.join("home");
        let elsewhere =
            PathBuf::from("/Users/op/Applications/Mooring.app/Contents/MacOS/mooringctl");
        for daemon in [Daemon::Running(&elsewhere), Daemon::Refused] {
            let mut fake = Fake::default();
            script_daemon(&mut fake, daemon);
            let error = install_with(&mut fake, &cargo, &home, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(&error, AppError::InstallWhileRegistered { service: named } if *named == service()),
                "{error:?}"
            );
            assert_eq!(
                error.to_string(),
                format!(
                    "{} is registered, and launchd starts only the mooringctl it was registered with (an ad-hoc signature is pinned by its cdhash), so one installed over it would not start: choose Stop the Daemon in Mooring.app's menu and quit the app, then run `cargo xtask install` again, whose last line says how to start the installed build's daemon",
                    service()
                )
            );
            assert_eq!(fake.steps.len(), 2, "launchd alone was asked");
            assert_eq!(asked_of_cargo(&scratch), ["metadata"]);
            assert!(!home.exists());
        }
        let mut fake = Fake::default();
        script_daemon(&mut fake, Daemon::NotRegistered);
        let error = install_with(&mut fake, &cargo, &home, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::NotBuilt { path } if *path == target.join("app/Mooring.app")),
            "{error:?}"
        );
        assert!(!home.exists());
    }
}
