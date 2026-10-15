// SPDX-License-Identifier: GPL-3.0-or-later

//! Mooring development task runner, invoked as `cargo xtask <command>`.
//!
//! Every command writes its report to standard output and exits non-zero on
//! any failure; the error and its causes go to standard error.

mod acceptance;
mod cargo;
mod ci;
mod clean;
mod cli;
mod deny_skips;
mod graph_check;
mod kinds;
#[cfg(test)]
mod lint_tables;
mod metadata;
mod mooringctl;
mod output;
#[cfg(test)]
mod testing;
mod version;

use std::error::Error as _;
use std::io::{self, Write};
use std::process::ExitCode;

use crate::acceptance::{AcceptanceError, Gate};
use crate::cargo::{Cargo, CommandError, EnvironmentError};
use crate::clean::CleanError;
use crate::cli::{Command, UsageError};
use crate::deny_skips::DenySkipsError;
use crate::graph_check::GraphCheckError;
use crate::kinds::KindsError;
use crate::mooringctl::MooringctlError;

/// Exit status when a command failed and its error report could not be written either.
const EXIT_REPORT_UNWRITABLE: u8 = 2;

#[derive(Debug, thiserror::Error)]
enum XtaskError {
    #[error(transparent)]
    Usage(#[from] UsageError),
    #[error(transparent)]
    Environment(#[from] EnvironmentError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    GraphCheck(#[from] GraphCheckError),
    #[error(transparent)]
    Kinds(#[from] KindsError),
    #[error(transparent)]
    DenySkips(#[from] DenySkipsError),
    #[error(transparent)]
    Acceptance(#[from] AcceptanceError),
    #[error(transparent)]
    Clean(#[from] CleanError),
    #[error(transparent)]
    Mooringctl(#[from] MooringctlError),
    #[error(transparent)]
    Output(#[from] output::OutputError),
}

fn main() -> ExitCode {
    match Command::parse(std::env::args_os().skip(1))
        .map_err(XtaskError::from)
        .and_then(run)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => match report(&mut io::stderr().lock(), &error) {
            Ok(()) => ExitCode::FAILURE,
            Err(_unwritable) => ExitCode::from(EXIT_REPORT_UNWRITABLE),
        },
    }
}

fn run(command: Command) -> Result<(), XtaskError> {
    let cargo = Cargo::from_env()?;
    let mut out = io::stdout().lock();
    match command {
        Command::Ci => ci::run(&cargo, &mut out),
        Command::GraphCheck => Ok(graph_check::run(&cargo, &mut out)?),
        Command::KindsCoverage => Ok(kinds::run(&cargo, &mut out)?),
        Command::DenySkips => Ok(deny_skips::run(&cargo, &mut out)?),
        Command::Acceptance => Ok(acceptance::run(&cargo, &mut out, Gate::Recorded)?),
        Command::ReleaseAcceptance => Ok(acceptance::run(&cargo, &mut out, Gate::Accepted)?),
        Command::Clean => Ok(clean::run(&cargo, &mut out)?),
        Command::Mooringctl => Ok(mooringctl::run(&cargo, &mut out)?),
    }
}

/// Writes the error and its chain of causes; usage errors also get the usage text.
fn report(err: &mut impl Write, error: &XtaskError) -> io::Result<()> {
    writeln!(err, "error: {error}")?;
    let mut cause = error.source();
    while let Some(source) = cause {
        writeln!(err, "  caused by: {source}")?;
        cause = source.source();
    }
    if matches!(error, XtaskError::Usage(_)) {
        writeln!(err)?;
        cli::write_usage(err)?;
    }
    Ok(())
}
