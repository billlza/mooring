// SPDX-License-Identifier: GPL-3.0-or-later

//! Command-line parsing: exactly one command name and no further arguments.

use std::ffi::OsString;
use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Ci,
    GraphCheck,
    KindsCoverage,
    DenySkips,
    Acceptance,
    ReleaseAcceptance,
    Clean,
    Mooringctl,
}

impl Command {
    const ALL: [Self; 8] = [
        Self::Ci,
        Self::GraphCheck,
        Self::KindsCoverage,
        Self::DenySkips,
        Self::Acceptance,
        Self::ReleaseAcceptance,
        Self::Clean,
        Self::Mooringctl,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ci => "ci",
            Self::GraphCheck => "graph-check",
            Self::KindsCoverage => "kinds-coverage",
            Self::DenySkips => "deny-skips",
            Self::Acceptance => "acceptance",
            Self::ReleaseAcceptance => "release-acceptance",
            Self::Clean => "clean",
            Self::Mooringctl => "mooringctl",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Ci => {
                "fmt, clippy, cargo deny, graph-check, kinds-coverage, deny-skips, acceptance, nextest, doc tests"
            }
            Self::GraphCheck => "assert the workspace crate edges equal the allowed-edge table",
            Self::KindsCoverage => "require every error Kind variant to be named by a test",
            Self::DenySkips => "require deny.toml [bans] skip to list exactly the duplicates",
            Self::Acceptance => {
                "require contract/cfm-acceptance.toml to record every enumerated export shape"
            }
            Self::ReleaseAcceptance => {
                "release gate: require every enumerated export shape to be accepted by real CFM"
            }
            Self::Clean => "remove the target directory and report the freed bytes",
            Self::Mooringctl => {
                "build mooringctl and sign a copy, <target>/signed/mooringctl, with its reverse-DNS identifier (macOS only)"
            }
        }
    }

    pub(crate) fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, UsageError> {
        let first = args.next().ok_or(UsageError::MissingCommand)?;
        let name = first
            .to_str()
            .ok_or_else(|| UsageError::NotUnicode(first.clone()))?;
        let command = Self::ALL
            .into_iter()
            .find(|command| command.name() == name)
            .ok_or_else(|| UsageError::UnknownCommand(name.to_owned()))?;
        match args.next() {
            Some(extra) => Err(UsageError::UnexpectedArgument { command, extra }),
            None => Ok(command),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UsageError {
    #[error("no command given")]
    MissingCommand,
    #[error("command {0:?} is not valid Unicode")]
    NotUnicode(OsString),
    #[error("unknown command `{0}`")]
    UnknownCommand(String),
    #[error("`{}` takes no arguments, got {extra:?}", command.name())]
    UnexpectedArgument { command: Command, extra: OsString },
}

pub(crate) fn write_usage(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "usage: cargo xtask <command>")?;
    writeln!(out)?;
    writeln!(out, "commands:")?;
    for command in Command::ALL {
        writeln!(out, "  {:<16}{}", command.name(), command.summary())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Command, UsageError};
    use std::ffi::OsString;

    fn parse(args: &[&str]) -> Result<Command, UsageError> {
        Command::parse(args.iter().map(OsString::from))
    }

    #[test]
    fn parses_every_command_by_name() {
        for command in Command::ALL {
            assert_eq!(parse(&[command.name()]).unwrap(), command);
        }
    }

    /// `mooringctl`'s own error and the documents tell the operator to run
    /// `cargo xtask mooringctl`, so that spelling is pinned here.
    #[test]
    fn mooringctl_is_spelt_as_documented() {
        assert_eq!(parse(&["mooringctl"]).unwrap(), Command::Mooringctl);
    }

    #[test]
    fn rejects_missing_unknown_and_extra_arguments() {
        assert!(matches!(parse(&[]), Err(UsageError::MissingCommand)));
        assert!(matches!(
            parse(&["lint"]),
            Err(UsageError::UnknownCommand(name)) if name == "lint"
        ));
        assert!(matches!(
            parse(&["clean", "--all"]),
            Err(UsageError::UnexpectedArgument {
                command: Command::Clean,
                ..
            })
        ));
    }
}
