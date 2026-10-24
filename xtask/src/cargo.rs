// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the cargo that invoked `cargo xtask` (the pinned toolchain) from the
//! workspace root.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

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
        let status = self
            .command(args)
            .status()
            .map_err(|source| CommandError::Spawn {
                command: args.join(" "),
                source,
            })?;
        check_status(args, status)
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

    fn command(&self, args: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command
            .args(args.iter().map(OsString::from))
            .current_dir(&self.workspace_root)
            .stdin(Stdio::null());
        command
    }
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
