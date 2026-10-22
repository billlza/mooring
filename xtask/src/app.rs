// SPDX-License-Identifier: GPL-3.0-or-later

//! The console's development build (design §5.1, M5, M7), macOS only and
//! not `ci` steps:
//!
//! - `app` builds `Mooring.app` at `<target>/app/Mooring.app`: it signs
//!   `mooringctl` as `cargo xtask mooringctl` does, runs MooringKit's
//!   tests, generates the Xcode project from `apple/project.yml`, builds
//!   the app unsigned (Swift warnings are errors) and requires Xcode's own
//!   result bundle to report no error and no warning, then copies the app
//!   with the signed `mooringctl` inside it (`Contents/MacOS/mooringctl`,
//!   the same bytes, so one keychain approval covers both copies), signs
//!   the bundle ad hoc, and checks both signatures.
//! - `agent-install <bsd>` runs the daemon as a per-session LaunchAgent,
//!   `com.bill.mooring.daemon`, polling the M7 on `<bsd>`, from the plist
//!   it writes to `<target>/launchd/` (loaded with `launchctl bootstrap`,
//!   so it is gone after logout: the app's `SMAppService` registration is
//!   M7's). The plist names the app in `AssociatedBundleIdentifiers`: macOS
//!   applies local network privacy to a LaunchAgent and asks the user
//!   about its responsible app (Apple TN3179, read 2026-10-22). Measured
//!   2026-10-22: without that, the agent's connection to the M7 failed
//!   with `EHOSTUNREACH` while the same binary run from a shell reached it.
//! - `agent-uninstall` stops it and removes the plist.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use mooring_model::iface::BsdName;
use serde::Deserialize;

use crate::cargo::Cargo;
use crate::metadata::{self, MetadataError};
use crate::mooringctl::{self, IdentifierFault, MooringctlError, check_identifier, signed_copy};
use crate::output::{OutputError, say};

/// The app's bundle identifier (`apple/project.yml`).
pub(crate) const APP_IDENTIFIER: &str = "com.bill.mooring";

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
        fault: IdentifierFault,
    },
    #[error("{interface:?} is not a BSD interface name (for example en9)")]
    Interface { interface: String },
    #[error("{} does not exist; run `cargo xtask app` first", path.display())]
    AppNotBuilt { path: PathBuf },
    #[error("HOME is not set to an absolute path")]
    Home,
    #[error("`id -u` printed {0:?}, not a user id")]
    UserId(String),
    #[error(
        "`launchctl print {service}` ended with {code:?}, neither found (0) nor not found ({LAUNCHCTL_NOT_FOUND})"
    )]
    AgentState { service: String, code: Option<i32> },
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
    pub(crate) signed: PathBuf,
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
            app,
            signed: signed_copy(target),
            agent_plist: target.join("launchd").join(format!("{AGENT_LABEL}.plist")),
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

/// The builds, in order: MooringKit's tests, the Xcode project, the app.
/// Every path is absolute; build products stay under the target directory.
pub(crate) fn build_steps(root: &Path, paths: &AppPaths, xcodegen: &Path) -> [Step; 3] {
    [
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
        ),
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
    mooringctl::run(cargo, out)?;
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let root = cargo.workspace_root().to_path_buf();
    let paths = AppPaths::new(&root, &target);
    let xcodegen = find_xcodegen(std::env::var_os("PATH"))?;
    assemble(&mut System, &root, &paths, &xcodegen, out)
}

/// The build after `mooringctl` is signed: the steps, the result bundle's
/// check, the copy, the embedded CLI, the signature and its checks.
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
    programs.run(
        &step(
            "/usr/bin/codesign",
            &[
                OsStr::new("--force"),
                OsStr::new("--sign"),
                OsStr::new("-"),
                paths.app.as_os_str(),
            ],
            root,
        ),
        Capture::Inherit,
    )?;
    programs.run(
        &step(
            "/usr/bin/codesign",
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
    ] {
        let report = programs.run(
            &step(
                "/usr/bin/codesign",
                &[OsStr::new("-dv"), path.as_os_str()],
                root,
            ),
            Capture::Stderr,
        )?;
        check_identifier(&report, expected).map_err(|fault| AppError::Signature {
            path: path.clone(),
            expected,
            fault,
        })?;
    }
    say!(
        out,
        "app: {} is built and signed ad hoc as {APP_IDENTIFIER}, with {} inside",
        paths.app.display(),
        paths.embedded.display()
    )?;
    Ok(())
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

/// The format specifiers of `text`, sorted: `%@`, `%lld`, `%u`, `%1$@` and
/// the like; `%%` is a literal, not a specifier.
pub(crate) fn specifiers(text: &str) -> Vec<String> {
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
        found.push(specifier);
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

/// Escapes text for an XML property list.
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The LaunchAgent's property list (design §5.1): the app's `mooringctl
/// daemon` polling `interface`, kept alive, its stderr appended to `log`,
/// and the app named as its responsible code for local network privacy.
pub(crate) fn agent_plist(program: &Path, interface: &BsdName, log: &Path) -> String {
    let program = xml(&program.to_string_lossy());
    let log = xml(&log.to_string_lossy());
    let interface = xml(interface.as_str());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{AGENT_LABEL}</string>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>{APP_IDENTIFIER}</string>
	</array>
	<key>ProgramArguments</key>
	<array>
		<string>{program}</string>
		<string>daemon</string>
		<string>--router-interface</string>
		<string>{interface}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Standard</string>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
</dict>
</plist>
"#
    )
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

/// Stops the agent if it is loaded; `true` if it was.
fn stop_agent(programs: &mut impl Programs, root: &Path, domain: &str) -> Result<bool, AppError> {
    let service = format!("{domain}/{AGENT_LABEL}");
    let print = step(
        LAUNCHCTL,
        &[OsStr::new("print"), OsStr::new(&service)],
        root,
    );
    match programs.status(&print)? {
        Some(0) => {
            programs.run(
                &step(
                    LAUNCHCTL,
                    &[OsStr::new("bootout"), OsStr::new(&service)],
                    root,
                ),
                Capture::Inherit,
            )?;
            Ok(true)
        }
        Some(LAUNCHCTL_NOT_FOUND) => Ok(false),
        code => Err(AppError::AgentState { service, code }),
    }
}

/// `cargo xtask agent-install <bsd>`.
pub(crate) fn install_agent(
    cargo: &Cargo,
    out: &mut impl Write,
    interface: &str,
) -> Result<(), AppError> {
    require_macos("agent-install", std::env::consts::OS)?;
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let root = cargo.workspace_root().to_path_buf();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or(AppError::Home)?;
    install(
        &mut System,
        &root,
        &AppPaths::new(&root, &target),
        &home,
        interface,
        out,
    )
}

/// The install after the paths are known.
pub(crate) fn install(
    programs: &mut impl Programs,
    root: &Path,
    paths: &AppPaths,
    home: &Path,
    interface: &str,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let interface = BsdName::parse(interface).map_err(|_| AppError::Interface {
        interface: interface.to_owned(),
    })?;
    if !paths.embedded.is_file() {
        return Err(AppError::AppNotBuilt {
            path: paths.embedded.clone(),
        });
    }
    let logs = home.join("Library").join("Logs").join("Mooring");
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&logs)
        .map_err(file_error("create", &logs))?;
    let log = logs.join("daemon.log");
    if let Some(parent) = paths.agent_plist.parent() {
        fs::create_dir_all(parent).map_err(file_error("create", parent))?;
    }
    fs::write(
        &paths.agent_plist,
        agent_plist(&paths.embedded, &interface, &log),
    )
    .map_err(file_error("write", &paths.agent_plist))?;
    let domain = gui_domain(programs, root)?;
    let replaced = stop_agent(programs, root, &domain)?;
    programs.run(
        &step(
            LAUNCHCTL,
            &[
                OsStr::new("bootstrap"),
                OsStr::new(&domain),
                paths.agent_plist.as_os_str(),
            ],
            root,
        ),
        Capture::Inherit,
    )?;
    say!(
        out,
        "agent-install: {AGENT_LABEL} {} in {domain}, polling the M7 on {}; its log is {}",
        if replaced { "restarted" } else { "started" },
        interface.as_str(),
        log.display()
    )?;
    say!(
        out,
        "agent-install: on its first poll macOS asks to let mooringctl use the keychain item and to let Mooring reach the local network; allow both"
    )?;
    Ok(())
}

/// `cargo xtask agent-uninstall`.
pub(crate) fn uninstall_agent(cargo: &Cargo, out: &mut impl Write) -> Result<(), AppError> {
    require_macos("agent-uninstall", std::env::consts::OS)?;
    let target = metadata::load(cargo, &["--no-deps"])?.target_directory;
    let root = cargo.workspace_root().to_path_buf();
    uninstall(&mut System, &root, &AppPaths::new(&root, &target), out)
}

/// The uninstall after the paths are known.
pub(crate) fn uninstall(
    programs: &mut impl Programs,
    root: &Path,
    paths: &AppPaths,
    out: &mut impl Write,
) -> Result<(), AppError> {
    let domain = gui_domain(programs, root)?;
    let stopped = stop_agent(programs, root, &domain)?;
    let removed = match fs::remove_file(&paths.agent_plist) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(file_error("remove", &paths.agent_plist)(error)),
    };
    say!(
        out,
        "agent-uninstall: {AGENT_LABEL} {}; {} {}",
        if stopped { "stopped" } else { "was not loaded" },
        paths.agent_plist.display(),
        if removed { "removed" } else { "was not there" }
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{
        AGENT_LABEL, AppError, AppPaths, Capture, Programs, Step, agent_plist, assemble,
        build_steps, check_build_results, find_xcodegen, install, require_macos, tail, uninstall,
    };
    use crate::mooringctl::IdentifierFault;
    use crate::testing::Scratch;
    use mooring_model::iface::BsdName;

    /// A stand-in for the programs: records each step, answers `run` from
    /// `outputs` (the next one each time) and `status` from `statuses`, and
    /// makes the app directory when `ditto` is asked to copy it.
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
                fs::create_dir_all(PathBuf::from(&step.args[1]).join("Contents/MacOS")).unwrap();
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
                "/usr/bin/xcrun xcodebuild -quiet -project /r/apple/Mooring.xcodeproj -scheme Mooring -configuration Release -destination platform=macOS,arch=arm64 -derivedDataPath /t/apple/DerivedData -resultBundlePath /t/apple/result.xcresult CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=YES build",
            ]
        );
        assert!(steps.iter().all(|step| step.dir == Path::new("/r")));
        assert_eq!(paths.app, Path::new("/t/app/Mooring.app"));
        assert_eq!(
            paths.embedded,
            Path::new("/t/app/Mooring.app/Contents/MacOS/mooringctl")
        );
        assert_eq!(paths.signed, Path::new("/t/signed/mooringctl"));
        assert_eq!(
            paths.agent_plist,
            Path::new("/t/launchd/com.bill.mooring.daemon.plist")
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
    /// app, puts the signed CLI inside it, signs the bundle and checks both
    /// identifiers, in that order.
    #[test]
    fn the_app_is_assembled_in_order_and_both_signatures_checked() {
        let scratch = Scratch::new("app-assemble");
        let (root, paths) = paths(&scratch);
        strings(&paths);
        fs::create_dir_all(paths.signed.parent().unwrap()).unwrap();
        fs::write(&paths.signed, b"signed mooringctl").unwrap();
        let mut fake = Fake::default();
        for output in [
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(CLEAN.as_bytes().to_vec()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(b"Executable=x\nIdentifier=com.bill.mooring\n".to_vec()),
            Ok(b"Identifier=com.bill.mooring.mooringctl\n".to_vec()),
        ] {
            fake.outputs.push_back(output);
        }
        let mut out = Vec::new();
        assemble(&mut fake, &root, &paths, Path::new("/x/xcodegen"), &mut out).unwrap();
        let app = paths.app.display().to_string();
        let embedded = paths.embedded.display().to_string();
        let steps: Vec<String> = fake.steps.iter().map(|(line, _)| line.clone()).collect();
        assert_eq!(steps.len(), 9, "{steps:#?}");
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
            format!("/usr/bin/codesign --force --sign - {app}")
        );
        assert_eq!(
            steps[6],
            format!("/usr/bin/codesign --verify --strict {app}")
        );
        assert_eq!(steps[7], format!("/usr/bin/codesign -dv {app}"));
        assert_eq!(steps[8], format!("/usr/bin/codesign -dv {embedded}"));
        assert_eq!(fake.steps[3].1, Capture::Stdout);
        assert_eq!(fake.steps[7].1, Capture::Stderr);
        assert_eq!(fs::read(&paths.embedded).unwrap(), b"signed mooringctl");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "app: {app} is built and signed ad hoc as com.bill.mooring, with {embedded} inside\n"
            )
        );
    }

    /// A build with a warning stops before anything is copied; an embedded
    /// CLI signed under another identifier fails the assembly.
    #[test]
    fn the_assembly_stops_at_a_warning_or_a_wrong_identifier() {
        let scratch = Scratch::new("app-refusals");
        let (root, paths) = paths(&scratch);
        strings(&paths);
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
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(b"Identifier=com.bill.mooring\n".to_vec()),
            Ok(b"Identifier=mooringctl-020ac5c52e8594c4\n".to_vec()),
        ] {
            fake.outputs.push_back(output);
        }
        let error =
            assemble(&mut fake, &root, &paths, Path::new("/x"), &mut Vec::new()).unwrap_err();
        assert!(
            matches!(
                &error,
                AppError::Signature { path, expected: "com.bill.mooring.mooringctl", fault: IdentifierFault::Different(found) }
                    if *path == paths.embedded && found == "mooringctl-020ac5c52e8594c4"
            ),
            "{error:?}"
        );
    }

    #[test]
    fn the_agent_plist_runs_the_apps_daemon_and_names_the_app() {
        let plist = agent_plist(
            Path::new("/t/app/Mooring.app/Contents/MacOS/mooringctl"),
            &BsdName::parse("en9").unwrap(),
            Path::new("/Users/u/Library/Logs/Mooring/daemon.log"),
        );
        for part in [
            "<key>Label</key>\n\t<string>com.bill.mooring.daemon</string>",
            "<key>AssociatedBundleIdentifiers</key>\n\t<array>\n\t\t<string>com.bill.mooring</string>\n\t</array>",
            "<string>/t/app/Mooring.app/Contents/MacOS/mooringctl</string>\n\t\t<string>daemon</string>\n\t\t<string>--router-interface</string>\n\t\t<string>en9</string>",
            "<key>KeepAlive</key>\n\t<true/>\n\t<key>ProcessType</key>\n\t<string>Standard</string>",
            "<key>StandardErrorPath</key>\n\t<string>/Users/u/Library/Logs/Mooring/daemon.log</string>",
        ] {
            assert!(plist.contains(part), "{part}\n{plist}");
        }
        assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        // Text is escaped for XML.
        let escaped = agent_plist(
            Path::new("/a&b/<c>/mooringctl"),
            &BsdName::parse("en9").unwrap(),
            Path::new("/l\"og"),
        );
        assert!(escaped.contains("<string>/a&amp;b/&lt;c&gt;/mooringctl</string>"));
        assert!(escaped.contains("<string>/l&quot;og</string>"));
    }

    /// Install writes the plist and the log folder, stops a loaded agent
    /// first, and bootstraps it into the user's domain.
    #[test]
    fn install_bootstraps_the_agent_and_replaces_a_loaded_one() {
        let scratch = Scratch::new("agent-install");
        let (root, paths) = paths(&scratch);
        let home = scratch.0.join("home");
        fs::create_dir_all(&home).unwrap();
        let mut fake = Fake::default();
        let error = install(&mut fake, &root, &paths, &home, "en9", &mut Vec::new()).unwrap_err();
        assert!(matches!(error, AppError::AppNotBuilt { .. }), "{error:?}");
        fs::create_dir_all(paths.embedded.parent().unwrap()).unwrap();
        fs::write(&paths.embedded, b"cli").unwrap();
        for bad in ["", "en 9", "../en9", "en9/x"] {
            assert!(
                matches!(
                    install(&mut fake, &root, &paths, &home, bad, &mut Vec::new()),
                    Err(AppError::Interface { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(fake.steps.is_empty());

        for (status, verb, booted_out) in
            [(Some(113), "started", false), (Some(0), "restarted", true)]
        {
            let mut fake = Fake::default();
            fake.outputs.push_back(Ok(b"501\n".to_vec()));
            fake.statuses.push_back(status);
            let mut out = Vec::new();
            install(&mut fake, &root, &paths, &home, "en9", &mut out).unwrap();
            let steps: Vec<&str> = fake.steps.iter().map(|(line, _)| line.as_str()).collect();
            let mut expected = vec![
                "/usr/bin/id -u".to_owned(),
                format!("/bin/launchctl print gui/501/{AGENT_LABEL}"),
            ];
            if booted_out {
                expected.push(format!("/bin/launchctl bootout gui/501/{AGENT_LABEL}"));
            }
            expected.push(format!(
                "/bin/launchctl bootstrap gui/501 {}",
                paths.agent_plist.display()
            ));
            assert_eq!(steps, expected);
            let log = home.join("Library/Logs/Mooring");
            assert_eq!(
                fs::metadata(&log).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let plist = fs::read_to_string(&paths.agent_plist).unwrap();
            assert!(plist.contains("<string>en9</string>"));
            assert!(plist.contains(&log.join("daemon.log").display().to_string()));
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.starts_with(&format!(
                    "agent-install: {AGENT_LABEL} {verb} in gui/501, polling the M7 on en9; its log is "
                )),
                "{out}"
            );
        }

        // Any other answer from `launchctl print` is an error, not a guess.
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.statuses.push_back(Some(5));
        let error = install(&mut fake, &root, &paths, &home, "en9", &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::AgentState { code: Some(5), .. }),
            "{error:?}"
        );
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"root\n".to_vec()));
        let error = install(&mut fake, &root, &paths, &home, "en9", &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, AppError::UserId(text) if text == "root"),
            "{error:?}"
        );
    }

    #[test]
    fn uninstall_stops_a_loaded_agent_and_removes_its_plist() {
        let scratch = Scratch::new("agent-uninstall");
        let (root, paths) = paths(&scratch);
        fs::create_dir_all(paths.agent_plist.parent().unwrap()).unwrap();
        fs::write(&paths.agent_plist, b"plist").unwrap();
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.statuses.push_back(Some(0));
        let mut out = Vec::new();
        uninstall(&mut fake, &root, &paths, &mut out).unwrap();
        assert!(!paths.agent_plist.exists());
        assert_eq!(
            fake.steps.last().unwrap().0,
            format!("/bin/launchctl bootout gui/501/{AGENT_LABEL}")
        );
        assert!(String::from_utf8(out).unwrap().contains(" stopped; "));
        // Again: nothing loaded, nothing to remove.
        let mut fake = Fake::default();
        fake.outputs.push_back(Ok(b"501\n".to_vec()));
        fake.statuses.push_back(Some(113));
        let mut out = Vec::new();
        uninstall(&mut fake, &root, &paths, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains(" was not loaded; ") && out.ends_with(" was not there\n"),
            "{out}"
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
        assert_eq!(specifiers("Retrying in %lld s."), ["%lld"]);
        assert_eq!(specifiers("%u %%%@"), ["%@", "%u"]);
        assert_eq!(specifiers("%1$@ and %2$d"), ["%1$@", "%2$d"]);
        assert_eq!(specifiers("100%% done"), Vec::<String>::new());
        assert_eq!(specifiers("↓ %@  ↑ %@"), ["%@", "%@"]);
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
