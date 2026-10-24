// SPDX-License-Identifier: GPL-3.0-or-later

//! The console's development build (design §5.1, M5, M7), macOS only and
//! not a `ci` step: `app` builds `Mooring.app` at
//! `<target>/app/Mooring.app`. It signs `mooringctl` as `cargo xtask
//! mooringctl` does, runs MooringKit's tests, generates the Xcode project
//! from `apple/project.yml`, builds the app unsigned (Swift warnings are
//! errors) and requires Xcode's own result bundle to report no error and no
//! warning, then copies the app with the signed `mooringctl` inside it
//! (`Contents/MacOS/mooringctl`, the same bytes, so one keychain approval
//! covers both copies), checks that the daemon's plist sits in
//! `Contents/Library/LaunchAgents` as `apple/App/LaunchAgents` has it,
//! signs the power helper Xcode built beside it (`mooring-power`, as
//! `com.bill.mooring.power`), signs the bundle ad hoc, and checks the three
//! signatures.
//!
//! The daemon is registered from the app itself, with `SMAppService`
//! (design §5.1, M7): launchd runs the `mooringctl` inside the bundle, and
//! only the one it was registered with. The registration pins that
//! executable's code signature, an ad-hoc one by its cdhash (launchd's
//! `LWCR`), so after a rebuild launchd refuses to start the new executable
//! (job state "spawn failed", last exit code 78) until the app registers
//! the daemon again (measured 2026-10-23 on macOS 27.0). `app` is
//! therefore refused while launchd lists the daemon, before anything is
//! built: the operator stops it from the app's menu, builds, and starts it
//! again from the new build.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use serde::Deserialize;

use crate::cargo::Cargo;
use crate::metadata::{self, MetadataError};
use crate::mooringctl::{
    self, CODESIGN, MooringctlError, SignatureFault, check_signed_as, signed_copy,
};
use crate::output::{OutputError, say};

/// The app's bundle identifier (`apple/project.yml`).
pub(crate) const APP_IDENTIFIER: &str = "com.bill.mooring";

/// The power helper's signing identifier (design §5.1).
pub(crate) const POWER_IDENTIFIER: &str = "com.bill.mooring.power";

/// The daemon's launchd label (design §5.1: `com.bill.mooring.daemon.plist`).
pub(crate) const AGENT_LABEL: &str = "com.bill.mooring.daemon";

/// `launchctl print`'s exit status for a service that is not loaded
/// (observed on macOS 27.0.1, 2026-10-22).
const LAUNCHCTL_NOT_FOUND: i32 = 113;

const XCRUN: &str = "/usr/bin/xcrun";

/// The one destination the app is built for: the exit Mac is Apple silicon
/// (design §2, a MacBookPro18,2). Naming it keeps xcodebuild from picking
/// the first of several matching destinations, which it warns about.
const DESTINATION: &str = "platform=macOS,arch=arm64";
const DITTO: &str = "/usr/bin/ditto";
const PLUTIL: &str = "/usr/bin/plutil";

/// The Info.plist keys whose text macOS shows in its own alerts, each of
/// which the built app must carry in Simplified Chinese
/// (`apple/App/InfoPlist.xcstrings`): the local network alert's.
const ALERT_KEYS: [&str; 1] = ["NSLocalNetworkUsageDescription"];
const LAUNCHCTL: &str = "/bin/launchctl";
const ID: &str = "/usr/bin/id";

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("`cargo xtask {command}` runs only on macOS, not on {os}")]
    NotMacos {
        command: &'static str,
        os: &'static str,
    },
    #[error(transparent)]
    Mooringctl(#[from] MooringctlError),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("`xcodegen` is not on PATH; install XcodeGen (`brew install xcodegen`)")]
    XcodegenMissing,
    #[error("failed to start {program}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("`{command}` failed ({status}){}", tail(.message))]
    Failed {
        command: String,
        status: ExitStatus,
        message: String,
    },
    #[error("Xcode's result bundle cannot be read")]
    ResultBundle(#[source] serde_json::Error),
    #[error("the app's build {0}")]
    BuildIssues(BuildIssues),
    #[error("cannot {action} {}", path.display())]
    File {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not signed as {expected}: {fault}", path.display())]
    Signature {
        path: PathBuf,
        expected: &'static str,
        fault: SignatureFault,
    },
    #[error("`id -u` printed {0:?}, not a user id")]
    UserId(String),
    #[error(
        "`launchctl print {service}` ended with {code:?}, neither found (0) nor not found ({LAUNCHCTL_NOT_FOUND})"
    )]
    AgentState { service: String, code: Option<i32> },
    #[error(
        "{service} is loaded and runs from the target directory; stop it first (Mooring.app's menu: Stop the Daemon)"
    )]
    AgentLoaded { service: String },
    #[error(
        "{service} is registered, and launchd starts only the mooringctl it was registered with (an ad-hoc signature is pinned by its cdhash), so a rebuilt one would not start: choose Stop the Daemon in Mooring.app's menu, run `cargo xtask app` again, then open the new build and choose Start the Daemon at Login"
    )]
    DaemonRegistered { service: String },
    #[error(
        "the built app's {} is not the daemon's plist {}",
        embedded.display(),
        source_plist.display()
    )]
    AgentPlistMismatch {
        embedded: PathBuf,
        source_plist: PathBuf,
    },
    #[error(
        "{} gives no Simplified Chinese text for {missing:?}, which macOS shows in its own alerts",
        path.display()
    )]
    AlertStrings { path: PathBuf, missing: Vec<String> },
    #[error("the app's strings {0}")]
    Catalog(CatalogFaults),
}

/// What is wrong between the strings the app's code localizes and the
/// catalog that translates them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CatalogFaults {
    /// Used in the code, absent from the catalog.
    pub(crate) missing: Vec<String>,
    /// In the catalog without a translated Simplified Chinese value, and
    /// not marked as not to be translated.
    pub(crate) untranslated: Vec<String>,
    /// Translated with other format specifiers than the source has.
    pub(crate) specifiers: Vec<String>,
    /// In the catalog, no longer used in the code.
    pub(crate) stale: Vec<String>,
    /// What cannot be read: an extracted file or the catalog, or a table
    /// other than `Localizable`, which no catalog covers.
    pub(crate) unreadable: Vec<String>,
}

impl fmt::Display for CatalogFaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        for (what, keys) in [
            ("are missing from the catalog", &self.missing),
            ("have no Simplified Chinese translation", &self.untranslated),
            (
                "are translated with other format specifiers",
                &self.specifiers,
            ),
            ("are in the catalog but no longer used", &self.stale),
            ("cannot be read or have no catalog", &self.unreadable),
        ] {
            if !keys.is_empty() {
                parts.push(format!("{what}: {keys:?}"));
            }
        }
        f.write_str(&parts.join("; "))
    }
}

/// What `stderr` adds to a failure: its last lines, if any.
fn tail(message: &str) -> String {
    let lines: Vec<&str> = message
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return String::new();
    }
    let last = &lines[lines.len().saturating_sub(10)..];
    format!(": {}", last.join(" | "))
}

/// The issues Xcode's result bundle reported for the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildIssues {
    pub(crate) status: String,
    pub(crate) messages: Vec<String>,
}

impl fmt::Display for BuildIssues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ended {}", self.status)?;
        if !self.messages.is_empty() {
            write!(f, " with: {}", self.messages.join(" | "))?;
        }
        Ok(())
    }
}

/// The part of `xcresulttool get build-results` this reads; Apple's other
/// keys are its own and are not refused.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuildResults {
    status: String,
    error_count: u64,
    warning_count: u64,
    analyzer_warning_count: u64,
    errors: Vec<Issue>,
    warnings: Vec<Issue>,
    analyzer_warnings: Vec<Issue>,
}

#[derive(Debug, Deserialize)]
struct Issue {
    message: String,
}

/// Requires a successful build with no error, warning or analyzer warning,
/// as Xcode's result bundle reports it.
pub(crate) fn check_build_results(json: &[u8]) -> Result<(), AppError> {
    let results: BuildResults = serde_json::from_slice(json).map_err(AppError::ResultBundle)?;
    let clean = results.status == "succeeded"
        && results.error_count == 0
        && results.warning_count == 0
        && results.analyzer_warning_count == 0;
    if clean {
        return Ok(());
    }
    let mut messages: Vec<String> = Vec::new();
    for (kind, issues) in [
        ("error", &results.errors),
        ("warning", &results.warnings),
        ("analyzer warning", &results.analyzer_warnings),
    ] {
        messages.extend(
            issues
                .iter()
                .map(|issue| format!("{kind}: {}", issue.message)),
        );
    }
    Err(AppError::BuildIssues(BuildIssues {
        status: results.status,
        messages,
    }))
}

/// Where everything is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppPaths {
    pub(crate) catalog: PathBuf,
    pub(crate) strings_data: PathBuf,
    pub(crate) package: PathBuf,
    pub(crate) spec: PathBuf,
    pub(crate) project: PathBuf,
    pub(crate) swift_scratch: PathBuf,
    pub(crate) derived_data: PathBuf,
    pub(crate) result_bundle: PathBuf,
    pub(crate) built: PathBuf,
    pub(crate) app: PathBuf,
    pub(crate) embedded: PathBuf,
    /// The power helper Xcode built into the app, beside `mooringctl`.
    pub(crate) power: PathBuf,
    pub(crate) signed: PathBuf,
    /// The daemon's plist in the repository.
    pub(crate) agent_plist_source: PathBuf,
    /// The daemon's plist in the built app, which `SMAppService` registers.
    pub(crate) agent_plist: PathBuf,
}

impl AppPaths {
    pub(crate) fn new(root: &Path, target: &Path) -> Self {
        let apple = root.join("apple");
        let app = target.join("app").join("Mooring.app");
        Self {
            catalog: apple.join("App").join("Localizable.xcstrings"),
            strings_data: target.join("apple").join(
                "DerivedData/Build/Intermediates.noindex/Mooring.build/Release/Mooring.build/Objects-normal/arm64",
            ),
            package: apple.join("Packages").join("MooringKit"),
            spec: apple.join("project.yml"),
            project: apple.join("Mooring.xcodeproj"),
            swift_scratch: target.join("swift").join("MooringKit"),
            derived_data: target.join("apple").join("DerivedData"),
            result_bundle: target.join("apple").join("result.xcresult"),
            built: target
                .join("apple")
                .join("DerivedData/Build/Products/Release/Mooring.app"),
            embedded: app.join("Contents").join("MacOS").join("mooringctl"),
            power: app.join("Contents").join("MacOS").join("mooring-power"),
            agent_plist_source: apple
                .join("App")
                .join("LaunchAgents")
                .join(format!("{AGENT_LABEL}.plist")),
            agent_plist: app
                .join("Contents")
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{AGENT_LABEL}.plist")),
            app,
            signed: signed_copy(target),
        }
    }
}

/// One program run: what to run, with which arguments, from where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
    pub(crate) dir: PathBuf,
}

fn step(program: impl Into<PathBuf>, args: &[&OsStr], dir: &Path) -> Step {
    Step {
        program: program.into(),
        args: args.iter().map(|arg| arg.to_os_string()).collect(),
        dir: dir.to_path_buf(),
    }
}

/// MooringKit's tests, built under the target directory.
fn swift_test_step(root: &Path, paths: &AppPaths) -> Step {
    step(
        XCRUN,
        &[
            OsStr::new("swift"),
            OsStr::new("test"),
            OsStr::new("--package-path"),
            paths.package.as_os_str(),
            OsStr::new("--scratch-path"),
            paths.swift_scratch.as_os_str(),
        ],
        root,
    )
}

/// `ci`'s last step: MooringKit's tests. They decode the console's
/// fixtures with the app's mirror, so a change to the documents on the
/// Rust side that the mirror does not follow fails `ci`, not only `app`.
/// They need macOS; elsewhere the step says that it did not run.
pub(crate) fn swift_tests(cargo: &Cargo, out: &mut impl Write) -> Result<(), AppError> {
    if std::env::consts::OS != "macos" {
        say!(
            out,
            "ci: MooringKit's Swift tests were not run: they need macOS"
        )?;
        return Ok(());
    }
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let root = cargo.workspace_root().to_path_buf();
    let paths = AppPaths::new(&root, &target);
    System.run(&swift_test_step(&root, &paths), Capture::Inherit)?;
    Ok(())
}

/// The builds, in order: MooringKit's tests, the Xcode project, the app.
/// Every path is absolute; build products stay under the target directory.
pub(crate) fn build_steps(root: &Path, paths: &AppPaths, xcodegen: &Path) -> [Step; 3] {
    [
        swift_test_step(root, paths),
        step(
            xcodegen,
            &[
                OsStr::new("generate"),
                OsStr::new("--quiet"),
                OsStr::new("--spec"),
                paths.spec.as_os_str(),
            ],
            root,
        ),
        step(
            XCRUN,
            &[
                OsStr::new("xcodebuild"),
                OsStr::new("-quiet"),
                OsStr::new("-project"),
                paths.project.as_os_str(),
                OsStr::new("-scheme"),
                OsStr::new("Mooring"),
                OsStr::new("-configuration"),
                OsStr::new("Release"),
                OsStr::new("-destination"),
                OsStr::new(DESTINATION),
                OsStr::new("-derivedDataPath"),
                paths.derived_data.as_os_str(),
                OsStr::new("-resultBundlePath"),
                paths.result_bundle.as_os_str(),
                OsStr::new("CODE_SIGNING_ALLOWED=NO"),
                OsStr::new("ONLY_ACTIVE_ARCH=YES"),
                // Clean first: Xcode reports a warning only from the task
                // that emits it, and skips tasks that are up to date, so an
                // incremental build would pass the warning gate a second
                // time without a fix.
                OsStr::new("clean"),
                OsStr::new("build"),
            ],
            root,
        ),
    ]
}

/// How a program's output is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capture {
    /// Shown as it comes.
    Inherit,
    /// Standard output is returned.
    Stdout,
    /// Standard error is returned (`codesign -dv` reports there).
    Stderr,
}

/// Runs programs; a test stands in for it.
pub(crate) trait Programs {
    /// Runs `step`; fails unless it exits 0. Returns the captured stream.
    fn run(&mut self, step: &Step, capture: Capture) -> Result<Vec<u8>, AppError>;
    /// Runs `step` and returns its exit code, whatever it is.
    fn status(&mut self, step: &Step) -> Result<Option<i32>, AppError>;
}

/// The real programs.
#[derive(Debug)]
struct System;

fn describe(step: &Step) -> String {
    std::iter::once(step.program.as_os_str())
        .chain(step.args.iter().map(OsString::as_os_str))
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

impl Programs for System {
    fn run(&mut self, step: &Step, capture: Capture) -> Result<Vec<u8>, AppError> {
        let mut command = Command::new(&step.program);
        command
            .args(&step.args)
            .current_dir(&step.dir)
            .stdin(Stdio::null());
        match capture {
            Capture::Inherit => command.stdout(Stdio::inherit()).stderr(Stdio::piped()),
            Capture::Stdout => command.stdout(Stdio::piped()).stderr(Stdio::piped()),
            Capture::Stderr => command.stdout(Stdio::inherit()).stderr(Stdio::piped()),
        };
        let output = command.output().map_err(|source| AppError::Spawn {
            program: step.program.display().to_string(),
            source,
        })?;
        if !output.status.success() {
            return Err(AppError::Failed {
                command: describe(step),
                status: output.status,
                message: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(match capture {
            Capture::Inherit => {
                // Shown after the run: a successful step's diagnostics.
                io::stderr()
                    .write_all(&output.stderr)
                    .map_err(|source| AppError::Output(OutputError(source)))?;
                Vec::new()
            }
            Capture::Stdout => output.stdout,
            Capture::Stderr => output.stderr,
        })
    }

    fn status(&mut self, step: &Step) -> Result<Option<i32>, AppError> {
        Command::new(&step.program)
            .args(&step.args)
            .current_dir(&step.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.code())
            .map_err(|source| AppError::Spawn {
                program: step.program.display().to_string(),
                source,
            })
    }
}

fn require_macos(command: &'static str, os: &'static str) -> Result<(), AppError> {
    if os == "macos" {
        Ok(())
    } else {
        Err(AppError::NotMacos { command, os })
    }
}

/// `xcodegen` on `PATH`, as an absolute path.
fn find_xcodegen(path: Option<OsString>) -> Result<PathBuf, AppError> {
    let path = path.ok_or(AppError::XcodegenMissing)?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("xcodegen"))
        .find(|candidate| candidate.is_file())
        .ok_or(AppError::XcodegenMissing)
}

fn file_error(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> AppError {
    let path = path.to_path_buf();
    move |source| AppError::File {
        action,
        path,
        source,
    }
}

/// Removes `path` and everything under it; a missing path is fine.
fn remove_tree(path: &Path) -> Result<(), AppError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(file_error("remove", path)(error)),
    }
}

/// `cargo xtask app`.
pub(crate) fn build(cargo: &Cargo, out: &mut impl Write) -> Result<(), AppError> {
    require_macos("app", std::env::consts::OS)?;
    build_with(&mut System, cargo, out)
}

/// [`build`] past the host check, with `programs` running every step but
/// cargo's. A registered daemon refuses the build before anything is built
/// or signed, so the CLI's copy, the app and the daemon stay one build.
fn build_with(
    programs: &mut impl Programs,
    cargo: &Cargo,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let root = cargo.workspace_root().to_path_buf();
    if let Some(service) = loaded_agent(programs, &root)? {
        return Err(AppError::DaemonRegistered { service });
    }
    mooringctl::run(cargo, mooringctl::MOORINGCTL, out)?;
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let paths = AppPaths::new(&root, &target);
    let xcodegen = find_xcodegen(std::env::var_os("PATH"))?;
    assemble(programs, &root, &paths, &xcodegen, out)
}

/// `AgentLoaded` while the daemon is loaded: removing the target directory
/// would pull its executable away from under it.
pub(crate) fn refuse_while_agent_loaded(
    programs: &mut impl Programs,
    root: &Path,
) -> Result<(), AppError> {
    match loaded_agent(programs, root)? {
        Some(service) => Err(AppError::AgentLoaded { service }),
        None => Ok(()),
    }
}

/// [`refuse_while_agent_loaded`] against the real `launchctl`, from
/// `root`.
pub(crate) fn refuse_while_agent_loaded_on_this_mac(root: &Path) -> Result<(), AppError> {
    refuse_while_agent_loaded(&mut System, root)
}

/// The build after `mooringctl` is signed: the steps, the result bundle's
/// check, the copy, the embedded CLI, the helper's signature, the bundle's,
/// and the checks of all three.
pub(crate) fn assemble(
    programs: &mut impl Programs,
    root: &Path,
    paths: &AppPaths,
    xcodegen: &Path,
    out: &mut impl Write,
) -> Result<(), AppError> {
    remove_tree(&paths.result_bundle)?;
    for step in build_steps(root, paths, xcodegen) {
        programs.run(&step, Capture::Inherit)?;
    }
    let results = programs.run(
        &step(
            XCRUN,
            &[
                OsStr::new("xcresulttool"),
                OsStr::new("get"),
                OsStr::new("build-results"),
                OsStr::new("--path"),
                paths.result_bundle.as_os_str(),
            ],
            root,
        ),
        Capture::Stdout,
    )?;
    check_build_results(&results)?;
    let catalog = fs::read(&paths.catalog).map_err(file_error("read", &paths.catalog))?;
    check_catalog(&extracted_strings(&paths.strings_data)?, &catalog).map_err(AppError::Catalog)?;
    remove_tree(&paths.app)?;
    if let Some(parent) = paths.app.parent() {
        fs::create_dir_all(parent).map_err(file_error("create", parent))?;
    }
    programs.run(
        &step(
            DITTO,
            &[paths.built.as_os_str(), paths.app.as_os_str()],
            root,
        ),
        Capture::Inherit,
    )?;
    fs::copy(&paths.signed, &paths.embedded).map_err(file_error("copy", &paths.signed))?;
    check_agent_plist(paths)?;
    check_alert_strings(programs, root, paths)?;
    // Xcode leaves the helper signed by the linker alone, under its file
    // name: it is signed as itself, before the bundle that seals it.
    programs.run(
        &step(
            CODESIGN,
            &[
                OsStr::new("--force"),
                OsStr::new("--sign"),
                OsStr::new("-"),
                OsStr::new("--options"),
                OsStr::new("runtime"),
                OsStr::new("--identifier"),
                OsStr::new(POWER_IDENTIFIER),
                paths.power.as_os_str(),
            ],
            root,
        ),
        Capture::Inherit,
    )?;
    // The hardened runtime refuses injected libraries, here as for the
    // `mooringctl` inside (`mooringctl::sign_args`).
    programs.run(
        &step(
            CODESIGN,
            &[
                OsStr::new("--force"),
                OsStr::new("--sign"),
                OsStr::new("-"),
                OsStr::new("--options"),
                OsStr::new("runtime"),
                paths.app.as_os_str(),
            ],
            root,
        ),
        Capture::Inherit,
    )?;
    programs.run(
        &step(
            CODESIGN,
            &[
                OsStr::new("--verify"),
                OsStr::new("--strict"),
                paths.app.as_os_str(),
            ],
            root,
        ),
        Capture::Inherit,
    )?;
    for (path, expected) in [
        (&paths.app, APP_IDENTIFIER),
        (&paths.embedded, mooringctl::SIGNING_IDENTIFIER),
        (&paths.power, POWER_IDENTIFIER),
    ] {
        let report = programs.run(
            &step(CODESIGN, &[OsStr::new("-dv"), path.as_os_str()], root),
            Capture::Stderr,
        )?;
        check_signed_as(&report, expected).map_err(|fault| AppError::Signature {
            path: path.clone(),
            expected,
            fault,
        })?;
    }
    say!(
        out,
        "app: {} is built and signed ad hoc as {APP_IDENTIFIER}, with {} and {} inside; open it and choose Start the Daemon at Login to run its daemon",
        paths.app.display(),
        paths.embedded.display(),
        paths.power.display()
    )?;
    Ok(())
}

/// Checks that the built app carries the daemon's plist exactly as the
/// repository has it: Xcode's copy phase copies it unprocessed
/// (`apple/project.yml`), and `SMAppService` registers this file.
fn check_agent_plist(paths: &AppPaths) -> Result<(), AppError> {
    let source = fs::read(&paths.agent_plist_source)
        .map_err(file_error("read", &paths.agent_plist_source))?;
    let embedded = fs::read(&paths.agent_plist).map_err(file_error("read", &paths.agent_plist))?;
    if embedded == source {
        Ok(())
    } else {
        Err(AppError::AgentPlistMismatch {
            embedded: paths.agent_plist.clone(),
            source_plist: paths.agent_plist_source.clone(),
        })
    }
}

/// Checks that the built app's Simplified Chinese `InfoPlist.strings`,
/// read as JSON through `plutil`, gives each of [`ALERT_KEYS`] a text.
fn check_alert_strings(
    programs: &mut impl Programs,
    root: &Path,
    paths: &AppPaths,
) -> Result<(), AppError> {
    let strings = paths
        .app
        .join("Contents/Resources/zh-Hans.lproj/InfoPlist.strings");
    let json = programs.run(
        &step(
            PLUTIL,
            &[
                OsStr::new("-convert"),
                OsStr::new("json"),
                OsStr::new("-o"),
                OsStr::new("-"),
                strings.as_os_str(),
            ],
            root,
        ),
        Capture::Stdout,
    )?;
    // Output that is not a table of texts gives none of them: every key is
    // then missing, and the assembly stops.
    let table: BTreeMap<String, String> = serde_json::from_slice(&json).unwrap_or_default();
    let missing: Vec<String> = ALERT_KEYS
        .iter()
        .filter(|key| table.get(**key).is_none_or(String::is_empty))
        .map(|key| (*key).to_owned())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::AlertStrings {
            path: strings,
            missing,
        })
    }
}

/// The `.stringsdata` files Xcode extracted the app's localizable strings
/// to, by path, each read whole.
fn extracted_strings(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(file_error("list", dir))? {
        let path = entry.map_err(file_error("list", dir))?.path();
        if path.extension() == Some(OsStr::new("stringsdata")) {
            let bytes = fs::read(&path).map_err(file_error("read", &path))?;
            files.push((path.display().to_string(), bytes));
        }
    }
    files.sort();
    Ok(files)
}

/// The part of a `.stringsdata` file read here: each table's keys.
#[derive(Debug, Deserialize)]
struct StringsData {
    tables: BTreeMap<String, Vec<ExtractedString>>,
}

#[derive(Debug, Deserialize)]
struct ExtractedString {
    key: String,
}

/// The part of a string catalog read here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    source_language: String,
    strings: BTreeMap<String, CatalogEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogEntry {
    #[serde(default = "translate_by_default")]
    should_translate: bool,
    #[serde(default)]
    localizations: BTreeMap<String, Localization>,
}

const fn translate_by_default() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Localization {
    string_unit: Option<StringUnit>,
}

#[derive(Debug, Deserialize)]
struct StringUnit {
    state: String,
    value: String,
}

/// The format specifiers of `text` by the argument each formats: a plain
/// one (`%@`, `%lld`, `%u`) takes the next argument, a positional one
/// (`%2$@`) the one it names. Each is listed as its argument's position
/// and its type without the position (`%2$@` is `(2, "%@")`), in the order
/// of positions, so a translation may reorder its arguments by position
/// but not change what type an argument is formatted as. `%%` is a
/// literal, not a specifier.
pub(crate) fn specifiers(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            continue;
        }
        let mut specifier = String::from('%');
        for next in chars.by_ref() {
            specifier.push(next);
            let modifier = matches!(next, 'l' | 'h' | 'q' | 'L' | 'z' | 'j' | 't');
            if next == '@' || (next.is_ascii_alphabetic() && !modifier) {
                break;
            }
        }
        let position = found.len() + 1;
        found.push(match specifier[1..].split_once('$') {
            Some((index, rest))
                if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (index.parse().unwrap_or(usize::MAX), format!("%{rest}"))
            }
            _ => (position, specifier),
        });
    }
    found.sort();
    found
}

/// Checks the catalog against the strings Xcode extracted from the app's
/// code (`extracted`: each `.stringsdata` file by name): every extracted
/// key is in the catalog, translated into Simplified Chinese with the same
/// format specifiers or marked as not to be translated, and the catalog
/// holds no key the code no longer uses.
pub(crate) fn check_catalog(
    extracted: &[(String, Vec<u8>)],
    catalog: &[u8],
) -> Result<(), CatalogFaults> {
    let mut faults = CatalogFaults::default();
    let mut used = BTreeSet::new();
    for (name, bytes) in extracted {
        let Ok(data) = serde_json::from_slice::<StringsData>(bytes) else {
            faults.unreadable.push(name.clone());
            continue;
        };
        for (table, strings) in data.tables {
            if table == "Localizable" {
                used.extend(strings.into_iter().map(|string| string.key));
            } else if !strings.is_empty() {
                faults.unreadable.push(format!("{name}: table {table}"));
            }
        }
    }
    let catalog = match serde_json::from_slice::<Catalog>(catalog) {
        Ok(catalog) if catalog.source_language == "en" => catalog,
        _ => {
            faults
                .unreadable
                .push("the catalog (not an English-sourced string catalog)".to_owned());
            return Err(faults);
        }
    };
    for key in &used {
        let Some(entry) = catalog.strings.get(key) else {
            faults.missing.push(key.clone());
            continue;
        };
        if !entry.should_translate {
            continue;
        }
        match entry
            .localizations
            .get("zh-Hans")
            .and_then(|localization| localization.string_unit.as_ref())
        {
            Some(unit) if unit.state == "translated" && !unit.value.is_empty() => {
                if specifiers(&unit.value) != specifiers(key) {
                    faults.specifiers.push(key.clone());
                }
            }
            _ => faults.untranslated.push(key.clone()),
        }
    }
    faults.stale = catalog
        .strings
        .keys()
        .filter(|key| !used.contains(*key))
        .cloned()
        .collect();
    if faults == CatalogFaults::default() {
        Ok(())
    } else {
        Err(faults)
    }
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

/// The daemon's service, `gui/<uid>/com.bill.mooring.daemon`, if launchd
/// lists it.
fn loaded_agent(programs: &mut impl Programs, root: &Path) -> Result<Option<String>, AppError> {
    let domain = gui_domain(programs, root)?;
    let service = format!("{domain}/{AGENT_LABEL}");
    Ok(agent_loaded(programs, root, &service)?.then_some(service))
}

/// Whether launchd lists `service`, by `launchctl print`'s exit status.
fn agent_loaded(
    programs: &mut impl Programs,
    root: &Path,
    service: &str,
) -> Result<bool, AppError> {
    let print = step(LAUNCHCTL, &[OsStr::new("print"), OsStr::new(service)], root);
    match programs.status(&print)? {
        Some(0) => Ok(true),
        Some(LAUNCHCTL_NOT_FOUND) => Ok(false),
        code => Err(AppError::AgentState {
            service: service.to_owned(),
            code,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        AGENT_LABEL, AppError, AppPaths, Capture, Programs, Step, assemble, build_steps,
        build_with, check_build_results, find_xcodegen, refuse_while_agent_loaded, require_macos,
        tail,
    };
    use crate::cargo::Cargo;
    use crate::mooringctl::SignatureFault;
    use crate::testing::Scratch;

    /// A stand-in for the programs: records each step, answers `run` from
    /// `outputs` (the next one each time) and `status` from `statuses`, and
    /// makes the app directory when `ditto` is asked to copy it, with the
    /// daemon's plist in it when the repository has one.
    #[derive(Default)]
    struct Fake {
        steps: Vec<(String, Capture)>,
        outputs: VecDeque<Result<Vec<u8>, AppError>>,
        statuses: VecDeque<Option<i32>>,
    }

    fn line(step: &Step) -> String {
        std::iter::once(step.program.as_os_str())
            .chain(step.args.iter().map(OsString::as_os_str))
            .map(|part| part.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    impl Programs for Fake {
        fn run(&mut self, step: &Step, capture: Capture) -> Result<Vec<u8>, AppError> {
            self.steps.push((line(step), capture));
            if step.program == Path::new(super::DITTO) {
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
            self.outputs.pop_front().unwrap_or(Ok(Vec::new()))
        }

        fn status(&mut self, step: &Step) -> Result<Option<i32>, AppError> {
            self.steps.push((line(step), Capture::Inherit));
            Ok(self.statuses.pop_front().unwrap())
        }
    }

    const CLEAN: &str = r#"{"actionTitle":"Build","status":"succeeded","errorCount":0,"errors":[],"warningCount":0,"warnings":[],"analyzerWarningCount":0,"analyzerWarnings":[],"destination":{}}"#;

    fn paths(scratch: &Scratch) -> (PathBuf, AppPaths) {
        let root = scratch.0.join("repo");
        let target = scratch.0.join("target");
        (root.clone(), AppPaths::new(&root, &target))
    }

    /// The daemon's plist in the scratch repository.
    fn agent_plist(paths: &AppPaths) {
        fs::create_dir_all(paths.agent_plist_source.parent().unwrap()).unwrap();
        fs::write(&paths.agent_plist_source, b"the daemon's plist").unwrap();
    }

    /// A one-string catalog and the extracted strings it matches.
    fn strings(paths: &AppPaths) {
        fs::create_dir_all(paths.catalog.parent().unwrap()).unwrap();
        fs::write(
            &paths.catalog,
            r#"{"sourceLanguage":"en","strings":{"Overview":{"localizations":{"zh-Hans":{"stringUnit":{"state":"translated","value":"概览"}}}}},"version":"1.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(&paths.strings_data).unwrap();
        fs::write(
            paths.strings_data.join("ConsoleView.stringsdata"),
            r#"{"source":"x","tables":{"Localizable":[{"key":"Overview"}]},"version":1}"#,
        )
        .unwrap();
    }

    #[test]
    fn the_build_steps_keep_every_product_under_the_target_directory() {
        let paths = AppPaths::new(Path::new("/r"), Path::new("/t"));
        let steps = build_steps(Path::new("/r"), &paths, Path::new("/opt/bin/xcodegen"));
        let lines: Vec<String> = steps.iter().map(line).collect();
        assert_eq!(
            lines,
            [
                "/usr/bin/xcrun swift test --package-path /r/apple/Packages/MooringKit --scratch-path /t/swift/MooringKit",
                "/opt/bin/xcodegen generate --quiet --spec /r/apple/project.yml",
                "/usr/bin/xcrun xcodebuild -quiet -project /r/apple/Mooring.xcodeproj -scheme Mooring -configuration Release -destination platform=macOS,arch=arm64 -derivedDataPath /t/apple/DerivedData -resultBundlePath /t/apple/result.xcresult CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=YES clean build",
            ]
        );
        assert!(steps.iter().all(|step| step.dir == Path::new("/r")));
        assert_eq!(paths.app, Path::new("/t/app/Mooring.app"));
        assert_eq!(
            paths.embedded,
            Path::new("/t/app/Mooring.app/Contents/MacOS/mooringctl")
        );
        assert_eq!(
            paths.power,
            Path::new("/t/app/Mooring.app/Contents/MacOS/mooring-power")
        );
        assert_eq!(paths.signed, Path::new("/t/signed/mooringctl"));
        assert_eq!(
            paths.agent_plist_source,
            Path::new("/r/apple/App/LaunchAgents/com.bill.mooring.daemon.plist")
        );
        assert_eq!(
            paths.agent_plist,
            Path::new(
                "/t/app/Mooring.app/Contents/Library/LaunchAgents/com.bill.mooring.daemon.plist"
            )
        );
        assert_eq!(
            paths.built,
            Path::new("/t/apple/DerivedData/Build/Products/Release/Mooring.app")
        );
    }

    /// Only a build Xcode reports as succeeded with no error and no warning
    /// of either kind passes; the messages it reports are named.
    #[test]
    fn the_result_bundle_gates_errors_and_warnings() {
        check_build_results(CLEAN.as_bytes()).unwrap();
        for (from, to, named) in [
            (
                r#""warningCount":0,"warnings":[]"#,
                r#""warningCount":1,"warnings":[{"message":"unused variable 'x'","sourceURL":"file:///a.swift"}]"#,
                "warning: unused variable 'x'",
            ),
            (
                r#""analyzerWarningCount":0,"analyzerWarnings":[]"#,
                r#""analyzerWarningCount":1,"analyzerWarnings":[{"message":"dead store"}]"#,
                "analyzer warning: dead store",
            ),
            (
                r#""status":"succeeded","errorCount":0,"errors":[]"#,
                r#""status":"failed","errorCount":1,"errors":[{"message":"no such module"}]"#,
                "error: no such module",
            ),
            (
                r#""status":"succeeded""#,
                r#""status":"failed""#,
                "ended failed",
            ),
        ] {
            let json = CLEAN.replace(from, to);
            assert_ne!(json, CLEAN);
            let error = check_build_results(json.as_bytes()).unwrap_err();
            assert!(matches!(error, AppError::BuildIssues(_)), "{error:?}");
            assert!(error.to_string().contains(named), "{error}");
        }
        assert!(matches!(
            check_build_results(b"{\"status\":\"succeeded\"}"),
            Err(AppError::ResultBundle(_))
        ));
    }

    /// The assembly runs the builds, checks the result bundle, copies the
    /// app, puts the signed CLI inside it, signs the helper and then the
    /// bundle, and checks the three identifiers, in that order.
    #[test]
    fn the_app_is_assembled_in_order_and_its_signatures_checked() {
        let scratch = Scratch::new("app-assemble");
        let (root, paths) = paths(&scratch);
        strings(&paths);
        agent_plist(&paths);
        fs::create_dir_all(paths.signed.parent().unwrap()).unwrap();
        fs::write(&paths.signed, b"signed mooringctl").unwrap();
        let mut fake = Fake::default();
        for output in [
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(CLEAN.as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(ALERT_STRINGS.to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(signed_report("com.bill.mooring")),
            Ok(signed_report("com.bill.mooring.mooringctl")),
            Ok(signed_report("com.bill.mooring.power")),
        ] {
            fake.outputs.push_back(output);
        }
        let mut out = Vec::new();
        assemble(&mut fake, &root, &paths, Path::new("/x/xcodegen"), &mut out).unwrap();
        let app = paths.app.display().to_string();
        let embedded = paths.embedded.display().to_string();
        let power = paths.power.display().to_string();
        let steps: Vec<String> = fake.steps.iter().map(|(line, _)| line.clone()).collect();
        assert_eq!(steps.len(), 12, "{steps:#?}");
        assert!(steps[0].starts_with("/usr/bin/xcrun swift test "));
        assert!(steps[1].starts_with("/x/xcodegen generate "));
        assert!(steps[2].starts_with("/usr/bin/xcrun xcodebuild "));
        assert!(steps[3].starts_with("/usr/bin/xcrun xcresulttool get build-results --path "));
        assert_eq!(
            steps[4],
            format!("/usr/bin/ditto {} {app}", paths.built.display())
        );
        assert_eq!(
            steps[5],
            format!(
                "/usr/bin/plutil -convert json -o - {app}/Contents/Resources/zh-Hans.lproj/InfoPlist.strings"
            )
        );
        assert_eq!(
            steps[6],
            format!(
                "/usr/bin/codesign --force --sign - --options runtime --identifier com.bill.mooring.power {power}"
            )
        );
        assert_eq!(
            steps[7],
            format!("/usr/bin/codesign --force --sign - --options runtime {app}")
        );
        assert_eq!(
            steps[8],
            format!("/usr/bin/codesign --verify --strict {app}")
        );
        assert_eq!(steps[9], format!("/usr/bin/codesign -dv {app}"));
        assert_eq!(steps[10], format!("/usr/bin/codesign -dv {embedded}"));
        assert_eq!(steps[11], format!("/usr/bin/codesign -dv {power}"));
        assert_eq!(fake.steps[3].1, Capture::Stdout);
        assert_eq!(fake.steps[5].1, Capture::Stdout);
        for checked in &fake.steps[9..] {
            assert_eq!(checked.1, Capture::Stderr);
        }
        assert_eq!(fs::read(&paths.embedded).unwrap(), b"signed mooringctl");
        assert_eq!(fs::read(&paths.agent_plist).unwrap(), b"the daemon's plist");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "app: {app} is built and signed ad hoc as com.bill.mooring, with {embedded} and {power} inside; open it and choose Start the Daemon at Login to run its daemon\n"
            )
        );
    }

    /// A build with a warning stops before anything is copied; an embedded
    /// CLI, or a helper, signed under another identifier fails the assembly.
    #[test]
    fn the_assembly_stops_at_a_warning_or_a_wrong_identifier() {
        let scratch = Scratch::new("app-refusals");
        let (root, paths) = paths(&scratch);
        strings(&paths);
        agent_plist(&paths);
        fs::create_dir_all(paths.signed.parent().unwrap()).unwrap();
        fs::write(&paths.signed, b"signed").unwrap();
        let mut fake = Fake::default();
        for _ in 0..3 {
            fake.outputs.push_back(Ok(Vec::new()));
        }
        let warned = CLEAN.replace(
            r#""warningCount":0,"warnings":[]"#,
            r#""warningCount":1,"warnings":[{"message":"w"}]"#,
        );
        fake.outputs.push_back(Ok(warned.into_bytes()));
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(matches!(error, AppError::BuildIssues(_)), "{error:?}");
        assert_eq!(fake.steps.len(), 4);
        assert!(!paths.app.exists());

        let mut fake = Fake::default();
        for output in [
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(CLEAN.as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(ALERT_STRINGS.to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(signed_report("com.bill.mooring")),
            Ok(signed_report("mooringctl-020ac5c52e8594c4")),
        ] {
            fake.outputs.push_back(output);
        }
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(
            matches!(
                &error,
                AppError::Signature { path, expected: "com.bill.mooring.mooringctl", fault: SignatureFault::Different(found) }
                    if *path == paths.embedded && found == "mooringctl-020ac5c52e8594c4"
            ),
            "{error:?}"
        );

        // A helper still under the linker's identifier, its file name.
        let mut fake = Fake::default();
        for output in [
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(CLEAN.as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(ALERT_STRINGS.to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(signed_report("com.bill.mooring")),
            Ok(signed_report("com.bill.mooring.mooringctl")),
            Ok(signed_report("mooring-power")),
        ] {
            fake.outputs.push_back(output);
        }
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(
            matches!(
                &error,
                AppError::Signature { path, expected: "com.bill.mooring.power", fault: SignatureFault::Different(found) }
                    if *path == paths.power && found == "mooring-power"
            ),
            "{error:?}"
        );

        // An app signed without the hardened runtime fails it too.
        let mut fake = Fake::default();
        for output in [
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(CLEAN.as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(ALERT_STRINGS.to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(String::from_utf8(signed_report("com.bill.mooring"))
                .unwrap()
                .replace("(adhoc,runtime)", "(adhoc)")
                .into_bytes()),
        ] {
            fake.outputs.push_back(output);
        }
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(
            matches!(
                &error,
                AppError::Signature { path, expected: "com.bill.mooring", fault: SignatureFault::NotHardened }
                    if *path == paths.app
            ),
            "{error:?}"
        );
    }

    /// The built app's Simplified Chinese Info.plist texts, as `plutil`
    /// prints them as JSON.
    const ALERT_STRINGS: &[u8] =
        "{\"NSLocalNetworkUsageDescription\":\"Mooring 守护进程读取路由器的状态。\"}".as_bytes();

    /// An app whose Chinese Info.plist texts lack the local network alert's,
    /// or give it none, or cannot be read, is not signed.
    #[test]
    fn an_alert_text_without_chinese_stops_the_assembly() {
        let scratch = Scratch::new("app-alert");
        let (root, paths) = paths(&scratch);
        strings(&paths);
        agent_plist(&paths);
        fs::create_dir_all(paths.signed.parent().unwrap()).unwrap();
        fs::write(&paths.signed, b"signed").unwrap();
        for answer in [
            &b"{\"CFBundleName\":\"Mooring\"}"[..],
            b"{\"NSLocalNetworkUsageDescription\":\"\"}",
            b"not json",
        ] {
            let mut fake = Fake::default();
            for output in [
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(Vec::new()),
                Ok(CLEAN.as_bytes().to_vec()),
                Ok(Vec::new()),
                Ok(answer.to_vec()),
            ] {
                fake.outputs.push_back(output);
            }
            let error =
                assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
            assert!(
                matches!(&error, AppError::AlertStrings { missing, .. } if *missing == ["NSLocalNetworkUsageDescription"]),
                "{error:?}"
            );
            assert!(
                fake.steps
                    .iter()
                    .all(|(line, _)| !line.starts_with("/usr/bin/codesign"))
            );
        }
    }

    /// `codesign -dv`'s report of an ad-hoc hardened-runtime signature with
    /// `identifier`, as macOS 27 writes it.
    fn signed_report(identifier: &str) -> Vec<u8> {
        format!(
            "Executable=x\nIdentifier={identifier}\nFormat=Mach-O thin (arm64)\nCodeDirectory v=20500 size=44028 flags=0x10002(adhoc,runtime) hashes=1370+2 location=embedded\nSignature=adhoc\n"
        )
        .into_bytes()
    }

    /// An app without the daemon's plist fails the assembly before the
    /// bundle is signed, and one whose plist differs from the repository's
    /// (as if Xcode had processed it) is refused.
    #[test]
    fn the_daemon_plist_must_be_the_repositorys() {
        let scratch = Scratch::new("app-plist");
        let (root, paths) = paths(&scratch);
        strings(&paths);
        fs::create_dir_all(paths.signed.parent().unwrap()).unwrap();
        fs::write(&paths.signed, b"signed").unwrap();
        // No plist in the repository, so the fake copies none into the app.
        let mut fake = Fake::default();
        for _ in 0..3 {
            fake.outputs.push_back(Ok(Vec::new()));
        }
        fake.outputs.push_back(Ok(CLEAN.as_bytes().to_vec()));
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(matches!(error, AppError::File { .. }), "{error:?}");
        assert!(
            fake.steps
                .iter()
                .all(|(line, _)| !line.contains("codesign"))
        );
        // The same bytes pass; any other bytes are refused.
        agent_plist(&paths);
        fs::create_dir_all(paths.agent_plist.parent().unwrap()).unwrap();
        fs::write(&paths.agent_plist, b"the daemon's plist").unwrap();
        super::check_agent_plist(&paths).unwrap();
        fs::write(&paths.agent_plist, b"<binary plist>").unwrap();
        let error = super::check_agent_plist(&paths).unwrap_err();
        assert!(
            matches!(&error, AppError::AgentPlistMismatch { embedded, source_plist }
                if *embedded == paths.agent_plist && *source_plist == paths.agent_plist_source),
            "{error:?}"
        );
        assert!(error.to_string().starts_with("the built app's "), "{error}");
    }

    /// The repository's daemon plist runs the `mooringctl` inside the app
    /// as `mooringctl daemon`, names the app for local network privacy,
    /// and names no interface and no log (design §5.1).
    #[test]
    fn the_repositorys_daemon_plist_runs_the_bundled_daemon() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let paths = AppPaths::new(root, &root.join("target"));
        let plist = fs::read_to_string(&paths.agent_plist_source).unwrap();
        for part in [
            "<key>Label</key>\n\t<string>com.bill.mooring.daemon</string>",
            "<key>AssociatedBundleIdentifiers</key>\n\t<array>\n\t\t<string>com.bill.mooring</string>\n\t</array>",
            "<key>BundleProgram</key>\n\t<string>Contents/MacOS/mooringctl</string>",
            "<key>ProgramArguments</key>\n\t<array>\n\t\t<string>mooringctl</string>\n\t\t<string>daemon</string>\n\t</array>",
            "<key>KeepAlive</key>\n\t<true/>\n\t<key>ProcessType</key>\n\t<string>Standard</string>",
            "<key>ThrottleInterval</key>\n\t<integer>60</integer>\n\t<key>ExitTimeOut</key>\n\t<integer>5</integer>",
        ] {
            assert!(plist.contains(part), "{part}\n{plist}");
        }
        for absent in [
            "router-interface",
            "StandardErrorPath",
            "StandardOutPath",
            "/Users/",
        ] {
            assert!(!plist.contains(absent), "{absent}");
        }
    }

    /// Clean is refused while the agent is loaded.
    #[test]
    fn clean_is_refused_while_the_agent_is_loaded() {
        let scratch = Scratch::new("app-clean");
        let (root, _) = paths(&scratch);
        for (status, refused) in [(113, false), (0, true)] {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.statuses.push_back(Some(status));
            let result = refuse_while_agent_loaded(&mut fake, &root);
            assert_eq!(
                matches!(&result, Err(AppError::AgentLoaded { service }) if *service == format!("gui/501/{AGENT_LABEL}")),
                refused,
                "{result:?}"
            );
            assert_eq!(result.is_ok(), !refused);
        }
    }

    /// `app` refuses before it builds anything while launchd lists the
    /// daemon: launchd starts only the `mooringctl` the daemon was
    /// registered with, so a rebuilt one would not start (design §5.1).
    /// Not listed, the build goes on to cargo, here one that is missing.
    #[test]
    fn a_build_is_refused_while_the_daemon_is_registered() {
        let scratch = Scratch::new("app-registered");
        let (root, _) = paths(&scratch);
        fs::create_dir_all(&root).unwrap();
        let cargo = Cargo::stand_in(scratch.0.join("no-cargo"), root);
        let service = format!("gui/501/{AGENT_LABEL}");
        let print = format!("/bin/launchctl print {service}");
        for (status, refused) in [(0, true), (113, false)] {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.statuses.push_back(Some(status));
            let mut out = Vec::new();
            let error = build_with(&mut fake, &cargo, &mut out).unwrap_err();
            assert_eq!(
                matches!(&error, AppError::DaemonRegistered { service: named } if *named == service),
                refused,
                "{error:?}"
            );
            assert_eq!(
                matches!(&error, AppError::Mooringctl(_)),
                !refused,
                "{error:?}"
            );
            // Only `id` and `launchctl print` ran: nothing was built,
            // copied, signed or restarted.
            let steps: Vec<&str> = fake.steps.iter().map(|(line, _)| line.as_str()).collect();
            assert_eq!(steps, ["/usr/bin/id -u", print.as_str()]);
            assert!(out.is_empty());
        }
        // launchd answering neither found nor not found stops the build too.
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.statuses.push_back(Some(5));
        let error = build_with(&mut fake, &cargo, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::AgentState { code: Some(5), .. }),
            "{error:?}"
        );
    }

    #[test]
    fn xcodegen_is_found_on_path_by_absolute_directories_only() {
        let scratch = Scratch::new("xcodegen");
        let bin = scratch.0.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("xcodegen"), b"#!/bin/sh\n").unwrap();
        let path = std::env::join_paths([Path::new("relative"), &scratch.0, &bin]).unwrap();
        assert_eq!(find_xcodegen(Some(path)).unwrap(), bin.join("xcodegen"));
        assert!(matches!(
            find_xcodegen(Some(OsString::from("relative:/nonexistent"))),
            Err(AppError::XcodegenMissing)
        ));
        assert!(matches!(
            find_xcodegen(None),
            Err(AppError::XcodegenMissing)
        ));
    }

    #[test]
    fn only_macos_runs_these_commands() {
        require_macos("app", "macos").unwrap();
        let error = require_macos("app", "linux").unwrap_err();
        assert_eq!(
            error.to_string(),
            "`cargo xtask app` runs only on macOS, not on linux"
        );
    }

    #[test]
    fn a_failures_message_keeps_its_last_lines() {
        assert_eq!(tail(""), "");
        assert_eq!(tail("\n  \n"), "");
        assert_eq!(tail("one\n\ntwo\n"), ": one | two");
        let many: String = (1..=12).map(|n| format!("line {n}\n")).collect();
        assert_eq!(
            tail(&many),
            format!(
                ": {}",
                (3..=12)
                    .map(|n| format!("line {n}"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
        );
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::{CatalogFaults, check_catalog, specifiers};

    fn extracted(keys: &[&str]) -> Vec<(String, Vec<u8>)> {
        let entries: Vec<String> = keys
            .iter()
            .map(|key| {
                format!(
                    r#"{{"comment":"","key":{}}}"#,
                    serde_json::to_string(key).unwrap()
                )
            })
            .collect();
        vec![(
            "View.stringsdata".to_owned(),
            format!(
                r#"{{"source":"/a/View.swift","tables":{{"Localizable":[{}]}},"version":1}}"#,
                entries.join(",")
            )
            .into_bytes(),
        )]
    }

    fn catalog(entries: &[(&str, Option<&str>)]) -> Vec<u8> {
        let strings: Vec<String> = entries
            .iter()
            .map(|(key, value)| {
                let entry = match value {
                    None => r#"{"shouldTranslate":false}"#.to_owned(),
                    Some(value) => format!(
                        r#"{{"localizations":{{"zh-Hans":{{"stringUnit":{{"state":"translated","value":{}}}}}}}}}"#,
                        serde_json::to_string(value).unwrap()
                    ),
                };
                format!("{}:{entry}", serde_json::to_string(key).unwrap())
            })
            .collect();
        format!(
            r#"{{"sourceLanguage":"en","strings":{{{}}},"version":"1.0"}}"#,
            strings.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn specifiers_are_read_as_cocoa_formats_are() {
        let s = |list: &[(usize, &str)]| -> Vec<(usize, String)> {
            list.iter().map(|(i, t)| (*i, (*t).to_owned())).collect()
        };
        assert_eq!(specifiers("Retrying in %lld s."), s(&[(1, "%lld")]));
        assert_eq!(specifiers("%u %%%@"), s(&[(1, "%u"), (2, "%@")]));
        assert_eq!(specifiers("%1$@ and %2$d"), s(&[(1, "%@"), (2, "%d")]));
        assert_eq!(specifiers("100%% done"), Vec::new());
        assert_eq!(specifiers("↓ %@  ↑ %@"), s(&[(1, "%@"), (2, "%@")]));
        // A translation may reorder its arguments by position...
        assert_eq!(specifiers("%2$lld then %1$@"), specifiers("%@ then %lld"));
        // ...but not swap their types.
        assert_ne!(specifiers("%lld then %@"), specifiers("%@ then %lld"));
    }

    #[test]
    fn a_complete_catalog_passes() {
        check_catalog(
            &extracted(&["Overview", "Retrying in %lld s.", "Mooring"]),
            &catalog(&[
                ("Overview", Some("概览")),
                ("Retrying in %lld s.", Some("%lld 秒后重试。")),
                ("Mooring", None),
            ]),
        )
        .unwrap();
    }

    #[test]
    fn every_kind_of_gap_is_named() {
        let faults = check_catalog(
            &extracted(&["Overview", "Router", "Retrying in %lld s.", "Users"]),
            [
                r#"{"sourceLanguage":"en","strings":{"#,
                r#""Overview":{"localizations":{"zh-Hans":{"stringUnit":{"state":"new","value":"概览"}}}},"#,
                r#""Retrying in %lld s.":{"localizations":{"zh-Hans":{"stringUnit":{"state":"translated","value":"%@ 秒后重试。"}}}},"#,
                r#""Users":{"localizations":{"de":{"stringUnit":{"state":"translated","value":"Benutzer"}}}},"#,
                r#""Gone":{"shouldTranslate":false}"#,
                r#"},"version":"1.0"}"#,
            ]
            .concat()
            .as_bytes(),
        )
        .unwrap_err();
        assert_eq!(
            faults,
            CatalogFaults {
                missing: vec!["Router".into()],
                untranslated: vec!["Overview".into(), "Users".into()],
                specifiers: vec!["Retrying in %lld s.".into()],
                stale: vec!["Gone".into()],
                unreadable: vec![],
            }
        );
        let text = faults.to_string();
        assert!(
            text.contains("are missing from the catalog: [\"Router\"]"),
            "{text}"
        );
        assert!(
            text.contains("are in the catalog but no longer used: [\"Gone\"]"),
            "{text}"
        );
    }

    #[test]
    fn unreadable_inputs_and_other_tables_are_faults() {
        let mut files = extracted(&["Overview"]);
        files.push(("Broken.stringsdata".to_owned(), b"{".to_vec()));
        files.push((
            "Other.stringsdata".to_owned(),
            br#"{"source":"x","tables":{"Errors":[{"key":"Boom"}]},"version":1}"#.to_vec(),
        ));
        let faults = check_catalog(&files, &catalog(&[("Overview", Some("概览"))])).unwrap_err();
        assert_eq!(
            faults.unreadable,
            ["Broken.stringsdata", "Other.stringsdata: table Errors"]
        );
        let faults = check_catalog(&extracted(&["Overview"]), b"{}").unwrap_err();
        assert_eq!(
            faults.unreadable,
            ["the catalog (not an English-sourced string catalog)"]
        );
        let german = br#"{"sourceLanguage":"de","strings":{},"version":"1.0"}"#;
        assert!(check_catalog(&extracted(&[]), german).is_err());
    }

    /// The repository's catalog is complete for the strings the app's
    /// source spells today, as far as the catalog's own keys show: each is
    /// translated or marked, with matching specifiers. (The build's own
    /// check compares it with what Xcode extracted.)
    #[test]
    fn the_repositorys_catalog_translates_every_key_it_holds() {
        let path = crate::testing::workspace_root().join("apple/App/Localizable.xcstrings");
        let bytes = std::fs::read(path).unwrap();
        let catalog: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let keys: Vec<String> = catalog["strings"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert!(keys.len() > 100);
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        check_catalog(&extracted(&refs), &bytes).unwrap();
    }
}

#[cfg(test)]
mod catalog_gate_tests {
    use std::fs;
    use std::path::Path;

    use super::{AppError, AppPaths, Capture, Programs, Step, assemble};
    use crate::testing::Scratch;

    /// Answers every run with a clean result bundle where one is read.
    struct Clean;

    impl Programs for Clean {
        fn run(&mut self, step: &Step, _: Capture) -> Result<Vec<u8>, AppError> {
            if step.args.first().map(|arg| arg == "xcresulttool") == Some(true) {
                return Ok(br#"{"status":"succeeded","errorCount":0,"errors":[],"warningCount":0,"warnings":[],"analyzerWarningCount":0,"analyzerWarnings":[]}"#.to_vec());
            }
            Ok(Vec::new())
        }

        fn status(&mut self, _: &Step) -> Result<Option<i32>, AppError> {
            Ok(Some(0))
        }
    }

    /// A string the code uses without a translation stops the build before
    /// the app is copied.
    #[test]
    fn an_untranslated_string_stops_the_build() {
        let scratch = Scratch::new("app-catalog");
        let root = scratch.0.join("repo");
        let paths = AppPaths::new(&root, &scratch.0.join("target"));
        fs::create_dir_all(paths.catalog.parent().unwrap()).unwrap();
        fs::write(
            &paths.catalog,
            r#"{"sourceLanguage":"en","strings":{},"version":"1.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(&paths.strings_data).unwrap();
        fs::write(
            paths.strings_data.join("RouterView.stringsdata"),
            r#"{"source":"x","tables":{"Localizable":[{"key":"Signal"}]},"version":1}"#,
        )
        .unwrap();
        let error =
            assemble(&mut Clean, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::Catalog(faults) if faults.missing == ["Signal"]),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "the app's strings are missing from the catalog: [\"Signal\"]"
        );
        assert!(!paths.app.exists());
    }
}
