// SPDX-License-Identifier: GPL-3.0-or-later

//! [`Role`]: which SSH key sent a request, and what it may ask for.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{RequestKind, ValueError};

/// The agent's installed path: the target of the forced command
/// (design §5.2).
macro_rules! agent_current_path {
    () => {
        "/usr/local/lib/mooring/agent/current"
    };
}

/// The installed agent that every forced command runs.
pub const AGENT_CURRENT_PATH: &str = agent_current_path!();

closed_enum! {
    /// The role an `authorized_keys` line passes to the forced command
    /// (`serve-ssh --role bootstrap|ops`, design §8.6 and §11.1).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Role {
        /// The one-time adoption key: it may only send `Bootstrap`.
        Bootstrap,
        /// The operations key: every request except `Bootstrap`.
        Ops,
    }
}

impl Role {
    /// The command-line spelling: `bootstrap` or `ops`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Ops => "ops",
        }
    }

    /// Whether this role may send `request`. The agent answers a refused
    /// request with [`crate::AgentError::RoleNotPermitted`].
    ///
    /// `Bootstrap` is accepted only from the bootstrap role; everything
    /// else, `RevokeBootstrap` included, only from the ops role. The match
    /// names every request, so a new request cannot be added without
    /// deciding its roles here.
    pub const fn permits(self, request: RequestKind) -> bool {
        match request {
            RequestKind::Bootstrap => matches!(self, Self::Bootstrap),
            RequestKind::Hello
            | RequestKind::HaveBlobs
            | RequestKind::PutBlob
            | RequestKind::ActivateAgent
            | RequestKind::Confirm
            | RequestKind::RevokeBootstrap
            | RequestKind::Apply
            | RequestKind::TxnStatus
            | RequestKind::Rollback
            | RequestKind::Status
            | RequestKind::Usage
            | RequestKind::TargetCheck
            | RequestKind::GateSet
            | RequestKind::ClearHold
            | RequestKind::Shutdown
            | RequestKind::Resume => matches!(self, Self::Ops),
        }
    }

    /// The forced command for this role's `authorized_keys` line.
    pub const fn forced_command(self) -> &'static str {
        match self {
            Self::Bootstrap => concat!(agent_current_path!(), " serve-ssh --role bootstrap"),
            Self::Ops => concat!(agent_current_path!(), " serve-ssh --role ops"),
        }
    }

    /// The options that prefix this role's `authorized_keys` line:
    /// `restrict,command="<forced command>"`.
    pub const fn authorized_keys_options(self) -> &'static str {
        match self {
            Self::Bootstrap => concat!(
                "restrict,command=\"",
                agent_current_path!(),
                " serve-ssh --role bootstrap\""
            ),
            Self::Ops => concat!(
                "restrict,command=\"",
                agent_current_path!(),
                " serve-ssh --role ops\""
            ),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = ValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|role| role.as_str() == text)
            .ok_or(ValueError::Role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_parse_only_their_command_line_spelling() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(*role));
            assert_eq!(role.to_string(), role.as_str());
        }
        for bad in ["", "Ops", "OPS", "root", "ops ", "bootstrap\n"] {
            assert_eq!(bad.parse::<Role>(), Err(ValueError::Role), "{bad:?}");
        }
    }

    #[test]
    fn forced_commands_pass_the_role_to_the_installed_agent() {
        for role in Role::ALL {
            let command = role.forced_command();
            assert!(command.starts_with(AGENT_CURRENT_PATH));
            assert_eq!(
                command
                    .strip_suffix(role.as_str())
                    .map(|rest| rest.ends_with(" serve-ssh --role ")),
                Some(true)
            );
            assert_eq!(
                role.authorized_keys_options(),
                format!("restrict,command=\"{command}\"")
            );
        }
    }
}
