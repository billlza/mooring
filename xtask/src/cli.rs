// SPDX-License-Identifier: GPL-3.0-or-later

//! Command-line parsing: exactly one command name, and its one argument for
//! the commands that take one (`engines-… <dir>`).

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
    Fieldkit,
    App,
    EnginesPins,
    EnginesPrepare,
    EnginesBuild,
    EnginesVerify,
    EnginesMetadata,
    EnginesGovulncheck,
}

/// A parsed command line: the command, and its argument when it takes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) command: Command,
    pub(crate) argument: Option<String>,
}

impl Command {
    const ALL: [Self; 16] = [
        Self::Ci,
        Self::GraphCheck,
        Self::KindsCoverage,
        Self::DenySkips,
        Self::Acceptance,
        Self::ReleaseAcceptance,
        Self::Clean,
        Self::Mooringctl,
        Self::Fieldkit,
        Self::App,
        Self::EnginesPins,
        Self::EnginesPrepare,
        Self::EnginesBuild,
        Self::EnginesVerify,
        Self::EnginesMetadata,
        Self::EnginesGovulncheck,
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
            Self::Fieldkit => "fieldkit",
            Self::App => "app",
            Self::EnginesPins => "engines-pins",
            Self::EnginesPrepare => "engines-prepare",
            Self::EnginesBuild => "engines-build",
            Self::EnginesVerify => "engines-verify",
            Self::EnginesMetadata => "engines-metadata",
            Self::EnginesGovulncheck => "engines-govulncheck",
        }
    }

    /// The name of the one argument the command takes, if it takes one.
    pub(crate) const fn argument(self) -> Option<&'static str> {
        match self {
            Self::EnginesPrepare
            | Self::EnginesBuild
            | Self::EnginesVerify
            | Self::EnginesMetadata
            | Self::EnginesGovulncheck => Some("<dir>"),
            Self::EnginesPins
            | Self::Ci
            | Self::GraphCheck
            | Self::KindsCoverage
            | Self::DenySkips
            | Self::Acceptance
            | Self::ReleaseAcceptance
            | Self::Clean
            | Self::Mooringctl
            | Self::Fieldkit
            | Self::App => None,
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Ci => {
                "fmt, clippy, cargo deny, graph-check, kinds-coverage, deny-skips, acceptance, nextest, doc tests, MooringKit (macOS)"
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
            Self::Fieldkit => {
                "build fieldkit and sign a copy, <target>/signed/fieldkit, with its reverse-DNS identifier (macOS only)"
            }
            Self::App => {
                "build Mooring.app at <target>/app with the signed mooringctl, the power helper and the daemon's plist inside, Swift tests and warnings gated; refused while the daemon is registered (stop it from the app's menu first) (macOS only)"
            }
            Self::EnginesPins => {
                "print engines.lock.toml's pins as KEY=value lines for the hosted build"
            }
            Self::EnginesPrepare => {
                "apply each engine's pinned go.mod/go.sum patch, or make an unpinned one as <dir>/<engine>.patch for review (hosted runner)"
            }
            Self::EnginesBuild => {
                "build every engine from the pinned sources in <dir> into <dir>/out (hosted runner)"
            }
            Self::EnginesVerify => {
                "check <dir>/out against engines.lock.toml's output digests, printing them while none are pinned"
            }
            Self::EnginesMetadata => {
                "check each engine's go version -m build information against its recipe (hosted runner)"
            }
            Self::EnginesGovulncheck => {
                "run govulncheck on every engine output with its own tags and target (hosted runner)"
            }
        }
    }

    pub(crate) fn parse(
        mut args: impl Iterator<Item = OsString>,
    ) -> Result<Invocation, UsageError> {
        let first = args.next().ok_or(UsageError::MissingCommand)?;
        let name = first
            .to_str()
            .ok_or_else(|| UsageError::NotUnicode(first.clone()))?;
        let command = Self::ALL
            .into_iter()
            .find(|command| command.name() == name)
            .ok_or_else(|| UsageError::UnknownCommand(name.to_owned()))?;
        let argument = match command.argument() {
            None => None,
            Some(argument) => {
                let value = args
                    .next()
                    .ok_or(UsageError::MissingArgument { command, argument })?;
                Some(value.into_string().map_err(UsageError::NotUnicode)?)
            }
        };
        match args.next() {
            Some(extra) => Err(UsageError::UnexpectedArgument { command, extra }),
            None => Ok(Invocation { command, argument }),
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
    #[error("`{}` takes no further arguments, got {extra:?}", command.name())]
    UnexpectedArgument { command: Command, extra: OsString },
    #[error("`{}` takes {argument}", command.name())]
    MissingArgument {
        command: Command,
        argument: &'static str,
    },
}

pub(crate) fn write_usage(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "usage: cargo xtask <command>")?;
    writeln!(out)?;
    writeln!(out, "commands:")?;
    for command in Command::ALL {
        let usage = match command.argument() {
            Some(argument) => format!("{} {argument}", command.name()),
            None => command.name().to_owned(),
        };
        writeln!(out, "  {usage:<22}{}", command.summary())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Command, UsageError};
    use std::ffi::OsString;

    fn parse(args: &[&str]) -> Result<Command, UsageError> {
        Command::parse(args.iter().map(OsString::from)).map(|invocation| invocation.command)
    }

    #[test]
    fn parses_every_command_by_name() {
        for command in Command::ALL {
            let args: Vec<&str> = std::iter::once(command.name())
                .chain(command.argument().map(|_| "en9"))
                .collect();
            assert_eq!(parse(&args).unwrap(), command);
        }
    }

    /// The engines commands take exactly one argument, a directory; every
    /// other command takes none.
    #[test]
    fn the_engines_commands_take_their_directory() {
        let invocation =
            Command::parse(["engines-verify", "out"].into_iter().map(OsString::from)).unwrap();
        assert_eq!(invocation.command, Command::EnginesVerify);
        assert_eq!(invocation.argument.as_deref(), Some("out"));
        assert!(matches!(
            parse(&["engines-verify"]),
            Err(UsageError::MissingArgument {
                command: Command::EnginesVerify,
                argument: "<dir>"
            })
        ));
        assert!(matches!(
            parse(&["engines-verify", "out", "more"]),
            Err(UsageError::UnexpectedArgument {
                command: Command::EnginesVerify,
                ..
            })
        ));
        assert!(matches!(
            parse(&["app", "en9"]),
            Err(UsageError::UnexpectedArgument {
                command: Command::App,
                ..
            })
        ));
        assert!(matches!(
            parse(&["agent-install", "en9"]),
            Err(UsageError::UnknownCommand(name)) if name == "agent-install"
        ));
    }

    /// `mooringctl`'s own error and the documents tell the operator to run
    /// `cargo xtask mooringctl`, so that spelling is pinned here.
    #[test]
    fn mooringctl_is_spelt_as_documented() {
        assert_eq!(parse(&["mooringctl"]).unwrap(), Command::Mooringctl);
        assert_eq!(parse(&["fieldkit"]).unwrap(), Command::Fieldkit);
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
