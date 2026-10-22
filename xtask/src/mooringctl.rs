// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl`: builds `mooringctl` and signs a copy of it ad hoc with
//! [`SIGNING_IDENTIFIER`] at `<target>/signed/mooringctl`, so that macOS
//! shows that copy the kernel's neighbour table (design §15.6 rule 10).
//!
//! On macOS 27.0.1 (26A434), measured on 2026-10-14, the kernel returned an
//! empty neighbour table (`sysctl` `NET_RT_FLAGS` with `RTF_LLINFO`) to a
//! process whose code-signing identifier is not reverse-DNS, and to
//! processes with an ad-hoc-signed ancestor (a copy of bash, cargo or
//! nextest), whatever their own identifier; that it does so to every such
//! process is an inference from the measured cases. The linker signs every
//! cargo binary ad hoc as `<name>-<hash>` and takes no identifier from an
//! embedded Info.plist, so no build script can change it: the binary is
//! signed again after it is linked, and the identifier `codesign -dv` then
//! reports must be exactly [`SIGNING_IDENTIFIER`].
//!
//! The executable is the one cargo reports for the build, so a target
//! directory set elsewhere is followed rather than guessed. It is never
//! signed where it is: on any later build of the package, even one with
//! nothing to compile, cargo replaces that file with a fresh copy of the
//! linker-signed binary in `deps/`, without linking it again (observed on
//! 2026-10-14: a new file each time). The command copies it to a temporary
//! file, `<target>/signed/mooringctl.<pid>.partial` (see [`SIGNED_DIR`]),
//! signs and checks that file, and only then renames it over
//! `<target>/signed/mooringctl`, so no later `cargo build` or
//! `cargo xtask ci` reverts the signature. A step that fails before the
//! rename leaves `<target>/signed/mooringctl` as it was and removes the
//! temporary file, or reports `PartialNotRemoved`, with the failure as its
//! cause, if that removal fails; once the rename has succeeded, only the
//! closing message can still fail. A run that is killed (Ctrl-C) can leave
//! `<target>/signed/mooringctl.<pid>.partial` behind, which
//! `cargo xtask clean` removes with the rest of the target directory.
//!
//! The signed copy does not follow later source changes: it is the build of
//! the run that made it. So it is run as
//! `cargo xtask mooringctl && ./target/signed/mooringctl router …` from the
//! workspace root (the path is the one the command prints), in
//! Terminal.app's own shell: xtask has exited before the copy starts, so it
//! is not among the copy's ancestors. No ad-hoc-signed shell or terminal
//! multiplexer may be in between, and the copy is never run through
//! `cargo run`: cargo is itself ad hoc signed, and `cargo run` runs the
//! linker-signed binary at cargo's path anyway.
//!
//! macOS only: elsewhere it fails before building anything. It is not a
//! `ci` step: `ci` runs the same steps on every host (the ubuntu L0 lane
//! included), and no test runs `mooringctl` against the kernel.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use serde::Deserialize;

use crate::cargo::{Cargo, CommandError};
use crate::metadata::{self, MetadataError};
use crate::output::{OutputError, say};

/// The code-signing identifier `mooringctl` is given: reverse-DNS, under
/// the product's bundle id `com.bill.mooring` (design §0).
///
/// It names the code. The development build's keychain service,
/// `com.bill.mooring.dev` (`crates/mooringctl/src/keychain.rs`), is of the
/// same family but names where the M7's admin password is stored; neither
/// depends on the other (an ad-hoc signature's designated requirement is
/// its code hash, not this identifier, as `codesign -d -r-` shows). This is
/// the one place the identifier is defined; `mooringctl` itself only names
/// this command.
pub(crate) const SIGNING_IDENTIFIER: &str = "com.bill.mooring.mooringctl";

/// The package, and its binary.
const PACKAGE: &str = "mooringctl";

/// `codesign`, by its absolute path.
const CODESIGN: &str = "/usr/bin/codesign";

/// The directory of the signed copy, under the target directory. Cargo
/// writes a profile's output to the directory named after the profile, so
/// `signed` stays clear of cargo only while no `[profile.signed]` exists.
/// With one, a build of that profile would write a linker-signed binary to
/// `<target>/signed/mooringctl`, which fails closed: the kernel returns it
/// an empty neighbour table, and it reports the hidden-table error.
const SIGNED_DIR: &str = "signed";

/// The build: the locked graph, the debug profile, and cargo's messages as
/// JSON on stdout (its diagnostics are still rendered on stderr), from
/// which the executable's path is read.
const BUILD_ARGS: [&str; 5] = [
    "build",
    "--locked",
    "--package",
    PACKAGE,
    "--message-format=json-render-diagnostics",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum MooringctlError {
    #[error("`cargo xtask mooringctl` runs only on macOS, not on {os}")]
    NotMacos { os: &'static str },
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("cannot read cargo's build messages")]
    Messages(#[source] serde_json::Error),
    #[error("cargo reported {count} `mooringctl` executables, not one")]
    Executables { count: usize },
    #[error("cargo reported the executable {}, which is not an absolute path", path.display())]
    RelativeExecutable { path: PathBuf },
    #[error(
        "cargo reported the target directory {}, which is not an absolute path",
        path.display()
    )]
    RelativeTargetDirectory { path: PathBuf },
    #[error("cannot create the directory {}", path.display())]
    SignedDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot copy {} to {}", from.display(), to.display())]
    Copy {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to start {CODESIGN}")]
    CodesignSpawn(#[source] io::Error),
    #[error("`codesign {args}` failed ({status}): {message}")]
    Codesign {
        args: String,
        status: ExitStatus,
        message: String,
    },
    #[error("{} is not signed as {SIGNING_IDENTIFIER}: {fault}", path.display())]
    Signature {
        path: PathBuf,
        fault: IdentifierFault,
    },
    #[error("cannot rename {} to {}", from.display(), to.display())]
    Rename {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot remove {} ({removal}) after this failure", path.display())]
    PartialNotRemoved {
        path: PathBuf,
        removal: io::Error,
        #[source]
        failure: Box<MooringctlError>,
    },
}

/// What is wrong with the identifier `codesign -dv` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentifierFault {
    /// No `Identifier=` line.
    Missing,
    /// More than one `Identifier=` line.
    Repeated,
    /// Another identifier.
    Different(String),
}

impl fmt::Display for IdentifierFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("codesign -dv reported no identifier"),
            Self::Repeated => f.write_str("codesign -dv reported more than one identifier"),
            Self::Different(found) => write!(f, "its identifier is {found:?}"),
        }
    }
}

/// The programs the command runs, so that a test can stand in for them.
trait Tools {
    /// Builds the package (`cargo` with [`BUILD_ARGS`]) and returns what
    /// cargo wrote to standard output: its JSON messages.
    fn build(&mut self) -> Result<Vec<u8>, MooringctlError>;

    /// The target directory `cargo metadata` reports.
    fn target_directory(&mut self) -> Result<PathBuf, MooringctlError>;

    /// Runs `codesign <args>` and returns what it wrote to standard error;
    /// fails, with that text, unless it exits 0.
    fn codesign(&mut self, args: &[&OsStr]) -> Result<Vec<u8>, MooringctlError>;
}

/// The real programs: the cargo that runs xtask, and [`CODESIGN`].
#[derive(Debug)]
struct System<'a> {
    cargo: &'a Cargo,
}

impl Tools for System<'_> {
    fn build(&mut self) -> Result<Vec<u8>, MooringctlError> {
        Ok(self.cargo.capture(&BUILD_ARGS)?)
    }

    fn target_directory(&mut self) -> Result<PathBuf, MooringctlError> {
        Ok(metadata::load(self.cargo, &["--no-deps"])?.target_directory)
    }

    fn codesign(&mut self, args: &[&OsStr]) -> Result<Vec<u8>, MooringctlError> {
        codesign(args)
    }
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), MooringctlError> {
    sign_copy(std::env::consts::OS, &mut System { cargo }, out)
}

/// A path known to be absolute. Cargo reports absolute paths, so a relative
/// executable or target directory is refused: that checks cargo kept to
/// its contract, and keeps every path `codesign` sees absolute. Only the
/// temporary file's path, under the target directory, reaches `codesign`,
/// and an absolute path, which begins with `/`, is never read as an option.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsolutePath(PathBuf);

impl AbsolutePath {
    /// `path`, if it is absolute; else `path` itself as the error.
    fn new(path: PathBuf) -> Result<Self, PathBuf> {
        if path.is_absolute() {
            Ok(Self(path))
        } else {
            Err(path)
        }
    }

    /// `name` under this path, absolute as well.
    fn join(&self, name: &str) -> Self {
        Self(self.0.join(name))
    }

    fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Where the signed copy is made.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedPaths {
    /// `<target>/signed`.
    dir: AbsolutePath,
    /// The copy being signed: `<target>/signed/mooringctl.<pid>.partial`,
    /// a name no other run uses at the same time.
    partial: AbsolutePath,
    /// The signed copy: `<target>/signed/mooringctl`.
    signed: AbsolutePath,
}

impl SignedPaths {
    fn under(target: &AbsolutePath) -> Self {
        let dir = target.join(SIGNED_DIR);
        Self {
            partial: dir.join(&format!("{PACKAGE}.{}.partial", std::process::id())),
            signed: dir.join(PACKAGE),
            dir,
        }
    }
}

/// The command on a host whose `std::env::consts::OS` is `os`, running
/// `tools`: checks the host, builds, finds the executable and the target
/// directory, and places the signed copy; then says where it is.
fn sign_copy(
    os: &'static str,
    tools: &mut impl Tools,
    out: &mut impl Write,
) -> Result<(), MooringctlError> {
    require_macos(os)?;
    let executable = AbsolutePath::new(built_executable(&tools.build()?)?)
        .map_err(|path| MooringctlError::RelativeExecutable { path })?;
    let target = AbsolutePath::new(tools.target_directory()?)
        .map_err(|path| MooringctlError::RelativeTargetDirectory { path })?;
    let paths = SignedPaths::under(&target);
    fs::create_dir_all(paths.dir.as_path()).map_err(|source| MooringctlError::SignedDirectory {
        path: paths.dir.as_path().to_path_buf(),
        source,
    })?;
    place_signed_copy(tools, &executable, &paths)
        .map_err(|failure| discard(&paths.partial, failure))?;
    say!(
        out,
        "mooringctl: {} is signed as {SIGNING_IDENTIFIER}",
        paths.signed.as_path().display()
    )?;
    Ok(())
}

/// Copies the executable to the temporary file, signs it, checks the
/// signature and renames the file over the signed copy.
fn place_signed_copy(
    tools: &mut impl Tools,
    executable: &AbsolutePath,
    paths: &SignedPaths,
) -> Result<(), MooringctlError> {
    fs::copy(executable.as_path(), paths.partial.as_path()).map_err(|source| {
        MooringctlError::Copy {
            from: executable.as_path().to_path_buf(),
            to: paths.partial.as_path().to_path_buf(),
            source,
        }
    })?;
    tools.codesign(&sign_args(&paths.partial))?;
    let report = tools.codesign(&display_args(&paths.partial))?;
    check_signature(&report).map_err(|fault| MooringctlError::Signature {
        path: paths.partial.as_path().to_path_buf(),
        fault,
    })?;
    fs::rename(paths.partial.as_path(), paths.signed.as_path()).map_err(|source| {
        MooringctlError::Rename {
            from: paths.partial.as_path().to_path_buf(),
            to: paths.signed.as_path().to_path_buf(),
            source,
        }
    })
}

/// After `failure`, removes the temporary file, so that nothing half
/// signed is left; a removal that fails is reported, with `failure` as its
/// cause. A file that is not there (the copy failed before making it) needs
/// no removal.
fn discard(partial: &AbsolutePath, failure: MooringctlError) -> MooringctlError {
    match fs::remove_file(partial.as_path()) {
        Ok(()) => failure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => failure,
        Err(removal) => MooringctlError::PartialNotRemoved {
            path: partial.as_path().to_path_buf(),
            removal,
            failure: Box::new(failure),
        },
    }
}

/// Fails unless `os` (the host's `std::env::consts::OS`) is macOS.
fn require_macos(os: &'static str) -> Result<(), MooringctlError> {
    if os == "macos" {
        Ok(())
    } else {
        Err(MooringctlError::NotMacos { os })
    }
}

/// One of cargo's JSON messages; only a compiler artifact is read.
#[derive(Debug, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
enum Message {
    CompilerArtifact {
        target: Target,
        executable: Option<PathBuf>,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
}

/// The executable of the `mooringctl` binary target among cargo's JSON
/// messages (one per line); there must be exactly one.
///
/// The parse is strict on purpose: every non-empty line must be one of
/// cargo's JSON messages, so a line that is not fails the command
/// (`Messages`) rather than being skipped. A stdout this does not
/// understand never names the file that is signed.
fn built_executable(messages: &[u8]) -> Result<PathBuf, MooringctlError> {
    let mut executables = Vec::new();
    for line in messages
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: Message = serde_json::from_slice(line).map_err(MooringctlError::Messages)?;
        if let Message::CompilerArtifact {
            target,
            executable: Some(executable),
        } = message
            && target.name == PACKAGE
            && target.kind.iter().any(|kind| kind == "bin")
        {
            executables.push(executable);
        }
    }
    match <[PathBuf; 1]>::try_from(executables) {
        Ok([executable]) => Ok(executable),
        Err(executables) => Err(MooringctlError::Executables {
            count: executables.len(),
        }),
    }
}

/// `codesign`'s arguments to replace the file's signature with an ad-hoc
/// one carrying [`SIGNING_IDENTIFIER`].
fn sign_args(file: &AbsolutePath) -> [&OsStr; 6] {
    [
        OsStr::new("--force"),
        OsStr::new("--sign"),
        OsStr::new("-"),
        OsStr::new("--identifier"),
        OsStr::new(SIGNING_IDENTIFIER),
        file.as_path().as_os_str(),
    ]
}

/// `codesign`'s arguments to report the file's signature (on stderr).
fn display_args(file: &AbsolutePath) -> [&OsStr; 2] {
    [OsStr::new("-dv"), file.as_path().as_os_str()]
}

/// Runs [`CODESIGN`] with `args` and returns what it wrote to standard
/// error; fails, with that text, unless it exits 0.
pub(crate) fn codesign(args: &[&OsStr]) -> Result<Vec<u8>, MooringctlError> {
    let output = Command::new(CODESIGN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()
        .map_err(MooringctlError::CodesignSpawn)?;
    if output.status.success() {
        Ok(output.stderr)
    } else {
        Err(MooringctlError::Codesign {
            args: args
                .iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            status: output.status,
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// Checks `codesign -dv`'s report: exactly one `Identifier=` line, naming
/// [`SIGNING_IDENTIFIER`].
fn check_signature(report: &[u8]) -> Result<(), IdentifierFault> {
    check_identifier(report, SIGNING_IDENTIFIER)
}

/// Checks `codesign -dv`'s report: exactly one `Identifier=` line, naming
/// `expected`.
pub(crate) fn check_identifier(report: &[u8], expected: &str) -> Result<(), IdentifierFault> {
    let mut identifiers = report
        .split(|&byte| byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"Identifier="));
    let identifier = identifiers.next().ok_or(IdentifierFault::Missing)?;
    if identifiers.next().is_some() {
        return Err(IdentifierFault::Repeated);
    }
    if identifier == expected.as_bytes() {
        Ok(())
    } else {
        Err(IdentifierFault::Different(
            String::from_utf8_lossy(identifier).into_owned(),
        ))
    }
}

/// The signed copy this command places under `target`:
/// `<target>/signed/mooringctl`.
pub(crate) fn signed_copy(target: &Path) -> PathBuf {
    target.join(SIGNED_DIR).join(PACKAGE)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;

    use super::{
        AbsolutePath, BUILD_ARGS, CODESIGN, IdentifierFault, MooringctlError, SIGNING_IDENTIFIER,
        Tools, built_executable, check_signature, display_args, require_macos, sign_args,
        sign_copy,
    };
    use crate::cargo::CommandError;
    use crate::cli::Command;
    use crate::metadata::MetadataError;
    use crate::output::OutputError;
    use crate::testing::{Scratch, workspace_root};

    /// `codesign -dv` of a binary this command signed (2026-10-14), its
    /// `Executable=` line naming the temporary file the command now signs.
    const SIGNED: &str = "Executable=/w/target/signed/mooringctl.7.partial
Identifier=com.bill.mooring.mooringctl
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=12788 flags=0x2(adhoc) hashes=394+2 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=0 size=12
";

    /// `codesign -dv` of the same binary as the linker signed it.
    const LINKER_SIGNED: &str = "Executable=/w/target/debug/deps/mooringctl-020ac5c52e8594c4
Identifier=mooringctl-020ac5c52e8594c4
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=50548 flags=0x20002(adhoc,linker-signed) hashes=1576+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
";

    fn absolute(path: &str) -> AbsolutePath {
        AbsolutePath::new(PathBuf::from(path)).unwrap()
    }

    #[test]
    fn builds_locked_and_signs_with_the_reverse_dns_identifier() {
        assert_eq!(SIGNING_IDENTIFIER, "com.bill.mooring.mooringctl");
        assert_eq!(CODESIGN, "/usr/bin/codesign");
        assert_eq!(
            BUILD_ARGS,
            [
                "build",
                "--locked",
                "--package",
                "mooringctl",
                "--message-format=json-render-diagnostics",
            ]
        );
        let file = absolute("/w/target/signed/mooringctl.7.partial");
        assert_eq!(
            sign_args(&file),
            [
                "--force",
                "--sign",
                "-",
                "--identifier",
                "com.bill.mooring.mooringctl",
                "/w/target/signed/mooringctl.7.partial",
            ]
            .map(OsStr::new)
        );
        assert_eq!(
            display_args(&file),
            ["-dv", "/w/target/signed/mooringctl.7.partial"].map(OsStr::new)
        );
    }

    #[test]
    fn only_the_one_identifier_codesign_reports_is_accepted() {
        assert_eq!(check_signature(SIGNED.as_bytes()), Ok(()));
        assert_eq!(
            check_signature(LINKER_SIGNED.as_bytes()),
            Err(IdentifierFault::Different(
                "mooringctl-020ac5c52e8594c4".to_owned()
            ))
        );
        // `TeamIdentifier=` is not the identifier, and a longer identifier is
        // another one.
        let missing = SIGNED.replace("Identifier=com.bill.mooring.mooringctl\n", "");
        assert_eq!(
            check_signature(missing.as_bytes()),
            Err(IdentifierFault::Missing)
        );
        let longer = SIGNED.replace(
            "Identifier=com.bill.mooring.mooringctl\n",
            "Identifier=com.bill.mooring.mooringctl.copy\n",
        );
        assert_eq!(
            check_signature(longer.as_bytes()),
            Err(IdentifierFault::Different(
                "com.bill.mooring.mooringctl.copy".to_owned()
            ))
        );
        let repeated = format!("{SIGNED}Identifier=com.bill.mooring.mooringctl\n");
        assert_eq!(
            check_signature(repeated.as_bytes()),
            Err(IdentifierFault::Repeated)
        );
        assert_eq!(check_signature(b""), Err(IdentifierFault::Missing));
    }

    /// Cargo's messages for `cargo build --package mooringctl`, shortened:
    /// a build script, its run, a library, the binary and the end.
    const MESSAGES: &str = r#"{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#quote@1.0.47","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build"},"filenames":["/w/target/debug/build/quote-0a164d27b241a4f2/build-script-build"],"executable":null,"fresh":true}
{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#quote@1.0.47","linked_libs":[],"out_dir":"/w/target/debug/build/quote-6b7a6e41fb22031a/out"}
{"reason":"compiler-artifact","package_id":"path+file:///w/crates/macsys#mooring-macsys@0.1.0","target":{"kind":["lib"],"crate_types":["lib"],"name":"mooring_macsys"},"filenames":["/w/target/debug/deps/libmooring_macsys-1.rlib"],"executable":null,"fresh":true}
{"reason":"compiler-artifact","package_id":"path+file:///w/crates/mooringctl#0.1.0","target":{"kind":["bin"],"crate_types":["bin"],"name":"mooringctl"},"filenames":["/w/target/debug/mooringctl"],"executable":"/w/target/debug/mooringctl","fresh":false}
{"reason":"build-finished","success":true}
"#;

    #[test]
    fn the_executable_is_the_one_cargo_reports() {
        assert_eq!(
            built_executable(MESSAGES.as_bytes()).unwrap(),
            PathBuf::from("/w/target/debug/mooringctl")
        );
        let none = MESSAGES.replace(r#""name":"mooringctl""#, r#""name":"mooringctl2""#);
        assert!(matches!(
            built_executable(none.as_bytes()),
            Err(MooringctlError::Executables { count: 0 })
        ));
        // A library of that name has no executable to sign.
        let library = MESSAGES.replace(
            r#""kind":["bin"],"crate_types":["bin"],"name":"mooringctl""#,
            r#""kind":["lib"],"crate_types":["lib"],"name":"mooringctl""#,
        );
        assert!(matches!(
            built_executable(library.as_bytes()),
            Err(MooringctlError::Executables { count: 0 })
        ));
        let line = MESSAGES.lines().nth(3).unwrap();
        let twice = format!("{MESSAGES}{line}\n");
        assert!(matches!(
            built_executable(twice.as_bytes()),
            Err(MooringctlError::Executables { count: 2 })
        ));
        assert!(matches!(
            built_executable(b"Compiling mooringctl\n"),
            Err(MooringctlError::Messages(_))
        ));
    }

    #[test]
    fn runs_only_on_macos() {
        assert!(require_macos("macos").is_ok());
        let error = require_macos("linux").unwrap_err();
        assert!(matches!(error, MooringctlError::NotMacos { os: "linux" }));
        assert_eq!(
            error.to_string(),
            "`cargo xtask mooringctl` runs only on macOS, not on linux"
        );
    }

    /// What the fake's signing appends to the file it signs.
    const SIGNATURE: &[u8] = b"+signature";

    /// The temporary file of this process's run.
    fn partial_name() -> String {
        format!("mooringctl.{}.partial", std::process::id())
    }

    /// A file's bytes, or `None` if there is no file at the path (nothing
    /// there, or a file where a directory of the path belongs).
    fn contents(path: &Path) -> Option<Vec<u8>> {
        match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                None
            }
            Err(error) => panic!("{}: {error}", path.display()),
        }
    }

    /// One call the command made, with what the signed directory held when
    /// it was made: the temporary file's bytes and whether the signed copy
    /// existed.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Call {
        what: String,
        partial: Option<Vec<u8>>,
        signed: bool,
    }

    /// Stands in for cargo and codesign over a scratch target directory.
    /// The build reports `messages`; signing appends [`SIGNATURE`] to the
    /// file, or fails if `refuse_signing`; `codesign -dv` reports `report`,
    /// after turning the temporary file into a directory, which cannot be
    /// removed as a file, if `wedge_partial`.
    struct FakeTools {
        messages: Vec<u8>,
        target: PathBuf,
        report: &'static str,
        refuse_signing: bool,
        wedge_partial: bool,
        calls: Vec<Call>,
    }

    impl FakeTools {
        fn new(executable: &Path, target: &Path) -> Self {
            Self {
                messages: messages_naming(&executable.to_string_lossy()),
                target: target.to_path_buf(),
                report: SIGNED,
                refuse_signing: false,
                wedge_partial: false,
                calls: Vec::new(),
            }
        }

        fn record(&mut self, what: String) {
            let dir = self.target.join("signed");
            self.calls.push(Call {
                what,
                partial: contents(&dir.join(partial_name())),
                signed: dir.join("mooringctl").exists(),
            });
        }

        fn whats(&self) -> Vec<&str> {
            self.calls.iter().map(|call| call.what.as_str()).collect()
        }
    }

    impl Tools for FakeTools {
        fn build(&mut self) -> Result<Vec<u8>, MooringctlError> {
            self.record("build".to_owned());
            Ok(self.messages.clone())
        }

        fn target_directory(&mut self) -> Result<PathBuf, MooringctlError> {
            self.record("metadata".to_owned());
            Ok(self.target.clone())
        }

        fn codesign(&mut self, args: &[&OsStr]) -> Result<Vec<u8>, MooringctlError> {
            let words: Vec<String> = args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            self.record(format!("codesign {}", words.join(" ")));
            let file = Path::new(args[args.len() - 1]);
            match words[0].as_str() {
                "--force" if self.refuse_signing => Err(MooringctlError::Codesign {
                    args: words.join(" "),
                    status: ExitStatus::from_raw(256),
                    message: "refused".to_owned(),
                }),
                "--force" => {
                    let mut bytes = fs::read(file).unwrap();
                    bytes.extend_from_slice(SIGNATURE);
                    fs::write(file, bytes).unwrap();
                    Ok(Vec::new())
                }
                "-dv" => {
                    if self.wedge_partial {
                        fs::remove_file(file).unwrap();
                        fs::create_dir(file).unwrap();
                        fs::write(file.join("wedge"), b"").unwrap();
                    }
                    Ok(self.report.as_bytes().to_vec())
                }
                other => panic!("unexpected codesign {other}"),
            }
        }
    }

    /// Cargo's messages naming `executable` as the binary's.
    fn messages_naming(executable: &str) -> Vec<u8> {
        format!(
            "{{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file:///w/crates/mooringctl#0.1.0\",\"target\":{{\"kind\":[\"bin\"],\"crate_types\":[\"bin\"],\"name\":\"mooringctl\"}},\"filenames\":[\"{executable}\"],\"executable\":\"{executable}\",\"fresh\":false}}\n{{\"reason\":\"build-finished\",\"success\":true}}\n"
        )
        .into_bytes()
    }

    /// A target directory in `scratch`, and a linker-signed executable
    /// (mode 0755) at the path cargo is to report, outside that directory,
    /// so that a path guessed under the target directory finds nothing:
    /// (target, executable).
    fn built(scratch: &Scratch) -> (PathBuf, PathBuf) {
        let target = scratch.0.join("target");
        let executable = scratch.0.join("reported").join("mooringctl");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"linker-signed").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        (target, executable)
    }

    /// The order: the host first, then the build, the executable cargo
    /// reports, the target directory, the copy, its signing and check, and
    /// only then the rename over the signed path and the message. Cargo's
    /// executable is never signed, and a second run replaces the signed
    /// copy with one of the new build.
    #[test]
    fn signs_a_copy_and_renames_it_over_the_signed_path() {
        let scratch = Scratch::new("sign-copy");
        let (target, executable) = built(&scratch);
        let partial = target.join("signed").join(partial_name());
        let signed = target.join("signed").join("mooringctl");
        let mut tools = FakeTools::new(&executable, &target);
        let mut out = Vec::new();
        sign_copy("macos", &mut tools, &mut out).unwrap();
        let call = |what: String, partial: Option<&[u8]>| Call {
            what,
            partial: partial.map(<[u8]>::to_vec),
            signed: false,
        };
        assert_eq!(
            tools.calls,
            [
                call("build".to_owned(), None),
                call("metadata".to_owned(), None),
                call(
                    format!(
                        "codesign --force --sign - --identifier com.bill.mooring.mooringctl {}",
                        partial.display()
                    ),
                    Some(b"linker-signed"),
                ),
                call(
                    format!("codesign -dv {}", partial.display()),
                    Some(b"linker-signed+signature"),
                ),
            ]
        );
        assert_eq!(contents(&signed).unwrap(), b"linker-signed+signature");
        assert_eq!(
            fs::metadata(&signed).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(contents(&partial), None);
        assert_eq!(contents(&executable).unwrap(), b"linker-signed");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!(
                "mooringctl: {} is signed as com.bill.mooring.mooringctl\n",
                signed.display()
            )
        );
        // A later build is signed over the earlier copy.
        fs::write(&executable, b"rebuilt").unwrap();
        let mut tools = FakeTools::new(&executable, &target);
        sign_copy("macos", &mut tools, &mut Vec::new()).unwrap();
        assert!(tools.calls[2].signed && tools.calls[3].signed);
        assert_eq!(contents(&signed).unwrap(), b"rebuilt+signature");
        assert_eq!(contents(&partial), None);
    }

    /// A copy `codesign -dv` reports under another identifier is
    /// `Signature`, is removed, and never reaches the signed path; a signed
    /// copy from an earlier run stays as it was.
    #[test]
    fn a_wrong_identifier_never_reaches_the_signed_path() {
        for earlier in [None, Some(&b"earlier"[..])] {
            let scratch = Scratch::new("wrong-identifier");
            let (target, executable) = built(&scratch);
            let partial = target.join("signed").join(partial_name());
            let signed = target.join("signed").join("mooringctl");
            if let Some(bytes) = earlier {
                fs::create_dir_all(signed.parent().unwrap()).unwrap();
                fs::write(&signed, bytes).unwrap();
            }
            let mut tools = FakeTools::new(&executable, &target);
            tools.report = LINKER_SIGNED;
            let mut out = Vec::new();
            let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
            assert!(
                matches!(
                    &error,
                    MooringctlError::Signature {
                        path,
                        fault: IdentifierFault::Different(found),
                    } if *path == partial && found == "mooringctl-020ac5c52e8594c4"
                ),
                "{error:?}"
            );
            assert_eq!(tools.whats().len(), 4);
            assert_eq!(contents(&signed).as_deref(), earlier);
            assert_eq!(contents(&partial), None);
            assert_eq!(contents(&executable).unwrap(), b"linker-signed");
            assert!(out.is_empty());
        }
    }

    /// A refused signing is codesign's failure; the copy is removed.
    #[test]
    fn a_refused_signing_leaves_no_signed_copy() {
        let scratch = Scratch::new("refused-signing");
        let (target, executable) = built(&scratch);
        let mut tools = FakeTools::new(&executable, &target);
        tools.refuse_signing = true;
        let mut out = Vec::new();
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(&error, MooringctlError::Codesign { message, .. } if message == "refused"),
            "{error:?}"
        );
        assert_eq!(tools.whats().len(), 3);
        assert_eq!(contents(&target.join("signed").join(partial_name())), None);
        assert_eq!(contents(&target.join("signed").join("mooringctl")), None);
        assert!(out.is_empty());
    }

    /// A signed copy that cannot be renamed into place (a directory holds
    /// the path) is `Rename`; the copy is removed and the directory kept.
    #[test]
    fn a_failed_rename_removes_the_copy() {
        let scratch = Scratch::new("failed-rename");
        let (target, executable) = built(&scratch);
        let partial = target.join("signed").join(partial_name());
        let signed = target.join("signed").join("mooringctl");
        fs::create_dir_all(&signed).unwrap();
        fs::write(signed.join("kept"), b"kept").unwrap();
        let mut tools = FakeTools::new(&executable, &target);
        let mut out = Vec::new();
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(&error, MooringctlError::Rename { from, to, .. } if *from == partial && *to == signed),
            "{error:?}"
        );
        assert_eq!(contents(&partial), None);
        assert_eq!(contents(&signed.join("kept")).unwrap(), b"kept");
        assert!(out.is_empty());
    }

    /// A copy that cannot be removed after a failure is reported with that
    /// failure as its cause, never dropped.
    #[test]
    fn a_copy_that_cannot_be_removed_is_reported_with_the_failure() {
        let scratch = Scratch::new("wedged-copy");
        let (target, executable) = built(&scratch);
        let partial = target.join("signed").join(partial_name());
        let mut tools = FakeTools::new(&executable, &target);
        tools.report = LINKER_SIGNED;
        tools.wedge_partial = true;
        let error = sign_copy("macos", &mut tools, &mut Vec::new()).unwrap_err();
        let MooringctlError::PartialNotRemoved { path, failure, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(*path, partial);
        assert!(
            matches!(**failure, MooringctlError::Signature { .. }),
            "{failure:?}"
        );
        assert_eq!(
            error.source().unwrap().to_string(),
            failure.to_string(),
            "the failure is the cause"
        );
        assert!(!target.join("signed").join("mooringctl").exists());
    }

    /// Elsewhere than macOS nothing is run and nothing is written.
    #[test]
    fn a_host_other_than_macos_runs_nothing() {
        let scratch = Scratch::new("not-macos");
        let (target, executable) = built(&scratch);
        let mut tools = FakeTools::new(&executable, &target);
        let mut out = Vec::new();
        let error = sign_copy("linux", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(error, MooringctlError::NotMacos { os: "linux" }),
            "{error:?}"
        );
        assert_eq!(tools.calls, []);
        assert!(!target.join("signed").exists());
        assert!(out.is_empty());
    }

    /// Cargo reports absolute paths. A relative executable or target
    /// directory is refused before anything is copied or signed. Each
    /// relative path here fails the next step, so a command that skipped
    /// the check would fail with another error instead of writing into the
    /// work tree: the executable is not there, and the target directory
    /// lies under a file (`Cargo.toml` in xtask's directory, where its tests
    /// run), so it cannot be created.
    #[test]
    fn relative_paths_from_cargo_are_refused() {
        let scratch = Scratch::new("relative-paths");
        let (target, executable) = built(&scratch);
        let mut tools = FakeTools::new(&executable, &target);
        tools.messages = messages_naming("-o/mooringctl");
        let mut out = Vec::new();
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(&error, MooringctlError::RelativeExecutable { path } if *path == Path::new("-o/mooringctl")),
            "{error:?}"
        );
        assert_eq!(tools.whats(), ["build"]);
        assert!(!Path::new("-o").exists());
        assert!(!target.join("signed").exists());
        assert!(
            Path::new("Cargo.toml").is_file(),
            "not in xtask's directory"
        );
        let relative = Path::new("Cargo.toml/-o/target");
        let mut tools = FakeTools::new(&executable, relative);
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(&error, MooringctlError::RelativeTargetDirectory { path } if path == relative),
            "{error:?}"
        );
        assert_eq!(tools.whats(), ["build", "metadata"]);
        assert!(Path::new("Cargo.toml").is_file());
        assert!(out.is_empty());
    }

    /// An executable cargo reports that is not there fails the copy with
    /// the operating system's error, before any `codesign` call; there is no
    /// temporary file to remove, and no signed copy.
    #[test]
    fn a_missing_executable_fails_the_copy() {
        let scratch = Scratch::new("missing-executable");
        let (target, executable) = built(&scratch);
        fs::remove_file(&executable).unwrap();
        let partial = target.join("signed").join(partial_name());
        let mut tools = FakeTools::new(&executable, &target);
        let mut out = Vec::new();
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(
                &error,
                MooringctlError::Copy { from, to, source }
                    if *from == executable
                        && *to == partial
                        && source.kind() == io::ErrorKind::NotFound
            ),
            "{error:?}"
        );
        assert_eq!(tools.whats(), ["build", "metadata"]);
        assert_eq!(contents(&partial), None);
        assert_eq!(contents(&target.join("signed").join("mooringctl")), None);
        assert!(out.is_empty());
    }

    /// A file where the signed copy's directory belongs fails before the
    /// copy, as `SignedDirectory`, after only the build and the target
    /// directory's lookup; the file is left as it was.
    #[test]
    fn a_file_in_place_of_the_signed_directory_fails_before_the_copy() {
        let scratch = Scratch::new("signed-file");
        let (target, executable) = built(&scratch);
        let dir = target.join("signed");
        fs::create_dir_all(&target).unwrap();
        fs::write(&dir, b"a file").unwrap();
        let mut tools = FakeTools::new(&executable, &target);
        let mut out = Vec::new();
        let error = sign_copy("macos", &mut tools, &mut out).unwrap_err();
        assert!(
            matches!(
                &error,
                MooringctlError::SignedDirectory { path, source }
                    if *path == dir && source.kind() == io::ErrorKind::AlreadyExists
            ),
            "{error:?}"
        );
        assert_eq!(tools.whats(), ["build", "metadata"]);
        assert_eq!(contents(&dir).unwrap(), b"a file");
        assert!(out.is_empty());
    }

    #[test]
    fn every_error_says_what_failed() {
        let status = ExitStatus::from_raw(256);
        let json = || serde_json::from_slice::<serde_json::Value>(b"x").unwrap_err();
        let os = |kind: io::ErrorKind| io::Error::from(kind);
        let path = PathBuf::from;
        let signature = || MooringctlError::Signature {
            path: path("/w/target/signed/mooringctl.7.partial"),
            fault: IdentifierFault::Different("mooringctl-020ac5c52e8594c4".to_owned()),
        };
        for (error, text) in [
            (
                MooringctlError::NotMacos { os: "linux" },
                "`cargo xtask mooringctl` runs only on macOS, not on linux".to_owned(),
            ),
            (
                MooringctlError::Command(CommandError::Failed {
                    command: "build --locked".to_owned(),
                    status,
                }),
                "`cargo build --locked` failed (exit status: 1)".to_owned(),
            ),
            (
                MooringctlError::Metadata(MetadataError::Parse(json())),
                "cannot parse the output of cargo metadata".to_owned(),
            ),
            (
                MooringctlError::Output(OutputError(os(io::ErrorKind::BrokenPipe))),
                "failed to write the report to standard output".to_owned(),
            ),
            (
                MooringctlError::Messages(json()),
                "cannot read cargo's build messages".to_owned(),
            ),
            (
                MooringctlError::Executables { count: 2 },
                "cargo reported 2 `mooringctl` executables, not one".to_owned(),
            ),
            (
                MooringctlError::RelativeExecutable {
                    path: path("-o/mooringctl"),
                },
                "cargo reported the executable -o/mooringctl, which is not an absolute path"
                    .to_owned(),
            ),
            (
                MooringctlError::RelativeTargetDirectory {
                    path: path("-o/target"),
                },
                "cargo reported the target directory -o/target, which is not an absolute path"
                    .to_owned(),
            ),
            (
                MooringctlError::SignedDirectory {
                    path: path("/w/target/signed"),
                    source: os(io::ErrorKind::PermissionDenied),
                },
                "cannot create the directory /w/target/signed".to_owned(),
            ),
            (
                MooringctlError::Copy {
                    from: path("/w/target/debug/mooringctl"),
                    to: path("/w/target/signed/mooringctl.7.partial"),
                    source: os(io::ErrorKind::NotFound),
                },
                "cannot copy /w/target/debug/mooringctl to /w/target/signed/mooringctl.7.partial"
                    .to_owned(),
            ),
            (
                MooringctlError::CodesignSpawn(os(io::ErrorKind::NotFound)),
                "failed to start /usr/bin/codesign".to_owned(),
            ),
            (
                MooringctlError::Codesign {
                    args: "-dv /w/target/signed/mooringctl.7.partial".to_owned(),
                    status,
                    message: "no such file".to_owned(),
                },
                "`codesign -dv /w/target/signed/mooringctl.7.partial` failed (exit status: 1): no such file"
                    .to_owned(),
            ),
            (
                signature(),
                "/w/target/signed/mooringctl.7.partial is not signed as com.bill.mooring.mooringctl: its identifier is \"mooringctl-020ac5c52e8594c4\""
                    .to_owned(),
            ),
            (
                MooringctlError::Rename {
                    from: path("/w/target/signed/mooringctl.7.partial"),
                    to: path("/w/target/signed/mooringctl"),
                    source: os(io::ErrorKind::PermissionDenied),
                },
                "cannot rename /w/target/signed/mooringctl.7.partial to /w/target/signed/mooringctl"
                    .to_owned(),
            ),
            (
                MooringctlError::PartialNotRemoved {
                    path: path("/w/target/signed/mooringctl.7.partial"),
                    removal: os(io::ErrorKind::PermissionDenied),
                    failure: Box::new(signature()),
                },
                "cannot remove /w/target/signed/mooringctl.7.partial (permission denied) after this failure"
                    .to_owned(),
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        for (fault, text) in [
            (
                IdentifierFault::Missing,
                "codesign -dv reported no identifier",
            ),
            (
                IdentifierFault::Repeated,
                "codesign -dv reported more than one identifier",
            ),
            (
                IdentifierFault::Different("x".to_owned()),
                "its identifier is \"x\"",
            ),
        ] {
            assert_eq!(fault.to_string(), text);
        }
    }

    /// `mooringctl`'s own error for an empty neighbour table names this
    /// command, by the name the command line parses: the message of
    /// `LocalError::NeighbourTableHidden`, its `#[error(...)]` string, holds
    /// it (a doc comment or another variant does not count).
    #[test]
    fn mooringctl_names_this_command() {
        let source =
            fs::read_to_string(workspace_root().join("crates/mooringctl/src/error.rs")).unwrap();
        let (before, _) = source
            .split_once("\n    NeighbourTableHidden,\n")
            .expect("LocalError has the unit variant NeighbourTableHidden");
        let attribute = &before[before.rfind("#[error(").unwrap()..];
        let message = attribute
            .strip_prefix("#[error(")
            .and_then(|rest| rest.trim_end().strip_suffix(")]"))
            .and_then(|literal| literal.trim().strip_prefix('"')?.strip_suffix('"'))
            .unwrap_or_else(|| panic!("not one string literal: {attribute}"));
        let command = format!("`cargo xtask {}`", Command::Mooringctl.name());
        assert!(message.contains(&command), "{message}");
    }
}
