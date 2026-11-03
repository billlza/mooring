// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the cargo that invoked `cargo xtask` (the pinned toolchain) from the
//! workspace root.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// The variable cargo takes rustdoc's flags from, in place of any
/// `build.rustdocflags` or `target.<triple>.rustdocflags` in a cargo config.
const RUSTDOCFLAGS: &str = "RUSTDOCFLAGS";

/// The variable cargo reads before [`RUSTDOCFLAGS`]: set, even to nothing,
/// it would replace the flags a run gives rustdoc.
const CARGO_ENCODED_RUSTDOCFLAGS: &str = "CARGO_ENCODED_RUSTDOCFLAGS";

#[derive(Debug)]
pub(crate) struct Cargo {
    program: PathBuf,
    workspace_root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EnvironmentError {
    #[error("the CARGO environment variable is not set; run this tool as `cargo xtask <command>`")]
    CargoUnset,
    #[error("the xtask manifest directory {} has no parent directory", .0.display())]
    NoWorkspaceRoot(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CommandError {
    #[error("failed to start `cargo {command}`")]
    Spawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("`cargo {command}` failed ({status})")]
    Failed { command: String, status: ExitStatus },
}

impl Cargo {
    /// The cargo binary comes from `CARGO`, which cargo sets for `cargo run`;
    /// the workspace root is the parent of this package's manifest directory.
    pub(crate) fn from_env() -> Result<Self, EnvironmentError> {
        let program = std::env::var_os("CARGO")
            .map(PathBuf::from)
            .ok_or(EnvironmentError::CargoUnset)?;
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .ok_or_else(|| EnvironmentError::NoWorkspaceRoot(manifest_dir.to_path_buf()))?
            .to_path_buf();
        Ok(Self {
            program,
            workspace_root,
        })
    }

    pub(crate) fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// A cargo at `program` for `workspace_root`, for a test that must not
    /// reach the real one.
    #[cfg(test)]
    pub(crate) const fn stand_in(program: PathBuf, workspace_root: PathBuf) -> Self {
        Self {
            program,
            workspace_root,
        }
    }

    /// Runs `cargo <args>` with inherited standard output and error.
    pub(crate) fn run(&self, args: &[&str]) -> Result<(), CommandError> {
        run_to_end(self.command(args), args)
    }

    /// Runs `cargo <args>` as [`Cargo::run`] does, with `rustdocflags` as
    /// the extra flags of every rustdoc it runs, whatever the environment
    /// or a cargo config says.
    pub(crate) fn run_with_rustdocflags(
        &self,
        rustdocflags: &str,
        args: &[&str],
    ) -> Result<(), CommandError> {
        run_to_end(self.rustdoc_command(rustdocflags, args), args)
    }

    /// Runs `cargo <args>` and returns its standard output; standard error is inherited.
    pub(crate) fn capture(&self, args: &[&str]) -> Result<Vec<u8>, CommandError> {
        let output = self
            .command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|source| CommandError::Spawn {
                command: args.join(" "),
                source,
            })?;
        check_status(args, output.status)?;
        Ok(output.stdout)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(args.iter().map(OsString::from))
            .current_dir(&self.workspace_root)
            .stdin(Stdio::null());
        command
    }

    /// `cargo <args>`, giving rustdoc `rustdocflags` as its extra flags, and
    /// none from the environment or a cargo config: they are set as
    /// [`RUSTDOCFLAGS`], and [`CARGO_ENCODED_RUSTDOCFLAGS`], which cargo
    /// would read instead, is removed. Cargo's own flags, those of the
    /// manifests' `[lints]` among them, still apply.
    fn rustdoc_command(&self, rustdocflags: &str, args: &[&str]) -> Command {
        let mut command = self.command(args);
        command
            .env(RUSTDOCFLAGS, rustdocflags)
            .env_remove(CARGO_ENCODED_RUSTDOCFLAGS);
        command
    }
}

/// Runs `command`, which is `cargo <args>`, to its end.
fn run_to_end(mut command: Command, args: &[&str]) -> Result<(), CommandError> {
    let status = command.status().map_err(|source| CommandError::Spawn {
        command: args.join(" "),
        source,
    })?;
    check_status(args, status)
}

fn check_status(args: &[&str], status: ExitStatus) -> Result<(), CommandError> {
    if status.success() {
        Ok(())
    } else {
        Err(CommandError::Failed {
            command: args.join(" "),
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{Cargo, CommandError};
    use crate::testing::workspace_root;

    /// A run that sets rustdoc's flags sets `RUSTDOCFLAGS` and removes
    /// `CARGO_ENCODED_RUSTDOCFLAGS`, which cargo reads first, so no extra
    /// flags reach rustdoc from the environment or a cargo config; it runs
    /// the same cargo, with the same arguments and in the same directory,
    /// as any run. Any other run leaves the environment as xtask found it.
    #[test]
    fn the_runs_rustdoc_flags_replace_any_from_the_environment() {
        let cargo = Cargo::stand_in(PathBuf::from("/c/cargo"), PathBuf::from("/w"));
        let command = cargo.rustdoc_command("-D warnings", &["doc", "--workspace"]);
        assert_eq!(command.get_program(), OsStr::new("/c/cargo"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["doc", "--workspace"].map(OsStr::new)
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/w")));
        assert_eq!(
            command.get_envs().collect::<BTreeMap<_, _>>(),
            BTreeMap::from([
                (OsStr::new("CARGO_ENCODED_RUSTDOCFLAGS"), None),
                (OsStr::new("RUSTDOCFLAGS"), Some(OsStr::new("-D warnings"))),
            ])
        );
        assert_eq!(cargo.command(&["doc", "--workspace"]).get_envs().count(), 0);
    }

    /// The flags reach the process: a shell stands in for cargo and exits 0
    /// only when `RUSTDOCFLAGS` is exactly `-D warnings`. A process that
    /// exits otherwise, or cannot start, is an error naming the command.
    #[test]
    fn the_flags_reach_the_process_and_its_end_is_reported() {
        let shell = Cargo::stand_in(PathBuf::from("/bin/sh"), workspace_root());
        let check = r#"test "$RUSTDOCFLAGS" = "-D warnings""#;
        shell
            .run_with_rustdocflags("-D warnings", &["-c", check])
            .unwrap();
        let error = shell
            .run_with_rustdocflags("-D missing-docs", &["-c", check])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("`cargo -c {check}` failed (exit status: 1)")
        );
        assert!(
            matches!(&error, CommandError::Failed { status, .. } if status.code() == Some(1)),
            "{error:?}"
        );

        let missing = Cargo::stand_in(workspace_root().join("no-such-cargo"), workspace_root());
        let error = missing
            .run_with_rustdocflags("-D warnings", &["doc"])
            .unwrap_err();
        assert_eq!(error.to_string(), "failed to start `cargo doc`");
        assert!(
            matches!(&error, CommandError::Spawn { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
            "{error:?}"
        );
    }
}
