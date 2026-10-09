// SPDX-License-Identifier: GPL-3.0-or-later

//! [`Role`]: which SSH key sent a request, and what it may ask for.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{GateReason, RequestKind, ValueError};

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
    /// (`serve-ssh --role bootstrap|ops|viewer`, design §8.6, §11.1 and
    /// §15.9).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Role {
        /// The one-time adoption key: it may only send `Bootstrap`.
        Bootstrap,
        /// The operations key: every request except `Bootstrap`, the
        /// accounting and journal reads (`UsageSeries`, `Events`) included.
        Ops,
        /// A remote viewer's key, from the operator's phone (decision F5,
        /// 2026-10-08): the status, accounting, journal and Mac-report
        /// reads, and an emergency stop that closes the gate for the
        /// operator hold only ([`Role::may_close_gate_for`]). It can never
        /// reopen the gate, clear a hold, apply, halt or resume, so resuming
        /// is done from the Mac. It logs in as the unprivileged
        /// [`crate::VIEWER_ACCOUNT`].
        Viewer,
    }
}

impl Role {
    /// The command-line spelling: `bootstrap`, `ops` or `viewer`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Ops => "ops",
            Self::Viewer => "viewer",
        }
    }

    /// Whether this role may send a request of this kind. The agent
    /// answers a refused request with
    /// [`crate::AgentError::RoleNotPermitted`]; [`crate::Request::authorize`]
    /// applies this table and then [`Role::may_close_gate_for`].
    ///
    /// `Bootstrap` is accepted only from the bootstrap role. The reads a
    /// remote viewer needs (`Status`, `Usage`, `UsageSeries`, `Events`,
    /// `MacReport`) and `GateSet` are accepted from the ops and viewer
    /// roles. Everything else, `RevokeBootstrap` and `PutMacReport`
    /// included, only from the ops role. The match names every request, so
    /// a new request cannot be added without deciding its roles here.
    pub const fn permits(self, request: RequestKind) -> bool {
        match request {
            RequestKind::Bootstrap => matches!(self, Self::Bootstrap),
            RequestKind::Status
            | RequestKind::Usage
            | RequestKind::UsageSeries
            | RequestKind::Events
            | RequestKind::MacReport
            | RequestKind::GateSet => matches!(self, Self::Ops | Self::Viewer),
            RequestKind::Hello
            | RequestKind::HaveBlobs
            | RequestKind::PutBlob
            | RequestKind::ActivateAgent
            | RequestKind::Confirm
            | RequestKind::RevokeBootstrap
            | RequestKind::Apply
            | RequestKind::TxnStatus
            | RequestKind::Rollback
            | RequestKind::TargetCheck
            | RequestKind::ClearHold
            | RequestKind::Shutdown
            | RequestKind::Resume
            | RequestKind::PutMacReport => matches!(self, Self::Ops),
        }
    }

    /// Whether this role may close the gate for `reason` with `GateSet`
    /// (decision F5: the viewer's emergency stop sets the operator hold
    /// only; it can never reopen the gate, clear a hold, apply, halt or
    /// resume). The agent answers a refused reason with
    /// [`crate::AgentError::GateReasonNotPermitted`].
    ///
    /// The match is exhaustive over every role and every reason, so a new
    /// role or reason cannot be added without deciding it here. It agrees
    /// with [`Role::permits`]: a role may send `GateSet` exactly when it may
    /// close the gate for some reason.
    pub const fn may_close_gate_for(self, reason: GateReason) -> bool {
        match (self, reason) {
            (
                Self::Ops,
                GateReason::MacDrain | GateReason::EgressViolation | GateReason::Operator,
            ) => true,
            (Self::Viewer, GateReason::Operator) => true,
            (Self::Viewer, GateReason::MacDrain | GateReason::EgressViolation) => false,
            (Self::Bootstrap, _) => false,
        }
    }

    /// The forced command for this role's `authorized_keys` line.
    pub const fn forced_command(self) -> &'static str {
        match self {
            Self::Bootstrap => concat!(agent_current_path!(), " serve-ssh --role bootstrap"),
            Self::Ops => concat!(agent_current_path!(), " serve-ssh --role ops"),
            Self::Viewer => concat!(agent_current_path!(), " serve-ssh --role viewer"),
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
            Self::Viewer => concat!(
                "restrict,command=\"",
                agent_current_path!(),
                " serve-ssh --role viewer\""
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
        let spellings: Vec<&str> = Role::ALL.iter().map(|role| role.as_str()).collect();
        assert_eq!(spellings, ["bootstrap", "ops", "viewer"]);
        for bad in [
            "",
            "Ops",
            "OPS",
            "root",
            "ops ",
            "bootstrap\n",
            "Viewer",
            "view",
        ] {
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
