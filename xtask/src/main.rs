// SPDX-License-Identifier: GPL-3.0-or-later

//! Mooring development task runner, invoked as `cargo xtask <command>`.
//!
//! Every command writes its report to standard output and exits non-zero on
//! any failure; the error and its causes go to standard error.

mod acceptance;
mod app;
mod cargo;
mod ci;
mod clean;
mod cli;
mod deny_skips;
mod engines;
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
use crate::app::AppError;
use crate::cargo::{Cargo, CommandError, EnvironmentError};
use crate::clean::CleanError;
use crate::cli::{Command, Invocation, UsageError};
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
    App(#[from] AppError),
    #[error(transparent)]
    Engines(#[from] engines::EnginesError),
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

fn run(invocation: Invocation) -> Result<(), XtaskError> {
    let cargo = Cargo::from_env()?;
    let mut out = io::stdout().lock();
    match invocation.command {
        Command::Ci => ci::run(&cargo, &mut out),
        Command::GraphCheck => Ok(graph_check::run(&cargo, &mut out)?),
        Command::KindsCoverage => Ok(kinds::run(&cargo, &mut out)?),
        Command::DenySkips => Ok(deny_skips::run(&cargo, &mut out)?),
        Command::Acceptance => Ok(acceptance::run(&cargo, &mut out, Gate::Recorded)?),
        Command::ReleaseAcceptance => Ok(acceptance::run(&cargo, &mut out, Gate::Accepted)?),
        Command::Clean => Ok(clean::run(&cargo, &mut out)?),
        Command::Mooringctl => Ok(mooringctl::run(&cargo, mooringctl::MOORINGCTL, &mut out)?),
        Command::Fieldkit => Ok(mooringctl::run(&cargo, mooringctl::FIELDKIT, &mut out)?),
        Command::App => Ok(app::build(&cargo, &mut out)?),
        Command::AgentInstall => match invocation.argument.as_deref() {
            Some(interface) => Ok(app::install_agent(&cargo, &mut out, interface)?),
            // `Command::parse` gives `agent-install` its argument or fails.
            None => Err(XtaskError::Usage(UsageError::MissingArgument {
                command: Command::AgentInstall,
                argument: "<bsd>",
            })),
        },
        Command::AgentUninstall => Ok(app::uninstall_agent(&cargo, &mut out)?),
        Command::EnginesPins => Ok(engines::pins(cargo.workspace_root(), &mut out)?),
        Command::EnginesPrepare => Ok(engines::prepare(
            cargo.workspace_root(),
            dir_of(&invocation)?,
            &mut out,
        )?),
        Command::EnginesBuild => Ok(engines::build(
            cargo.workspace_root(),
            dir_of(&invocation)?,
            &mut out,
        )?),
        Command::EnginesVerify => Ok(engines::verify(
            cargo.workspace_root(),
            dir_of(&invocation)?,
            &mut out,
        )?),
        Command::EnginesMetadata => Ok(engines::metadata(
            cargo.workspace_root(),
            dir_of(&invocation)?,
            &mut out,
        )?),
    }
}

/// The `<dir>` an engines command takes; `Command::parse` gives it one or
/// fails.
fn dir_of(invocation: &Invocation) -> Result<&std::path::Path, XtaskError> {
    invocation
        .argument
        .as_deref()
        .map(std::path::Path::new)
        .ok_or(XtaskError::Usage(UsageError::MissingArgument {
            command: invocation.command,
            argument: "<dir>",
        }))
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
