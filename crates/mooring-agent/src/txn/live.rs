// SPDX-License-Identifier: GPL-3.0-or-later

//! `Restarts::Refused` (design §13.6): a change goes live, or not at all.
//! Right after staging, before anything is validated, armed or switched,
//! the agent works out what applying the staged generation would restart
//! or reload that serves users; a change that would is refused with what it
//! would. One that would not is applied by the live step alone, which
//! checks the same again after the swap, and is undone live too
//! ([`Way::Live`]).

use std::collections::BTreeSet;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BundleHeader, Generation, HostFile, ManagedFile, RestartNeed, Restarts,
    RollbackCause,
};

use super::changes::{Step, applied, host_to_apply, secrets};
use super::xray_users::{self, Opening, Takes};
use crate::host::Node;
use crate::paths::Paths;

/// How a change is applied and undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Way {
    /// Whatever the change needs restarts, and its rollback restarts what
    /// differs; a rollback that fails stops the node
    /// ([`AgentError::RollbackFailed`]).
    Restarting,
    /// Only what the running engines take as they run, and its undo
    /// likewise, through Xray's API; an undo that fails stops nothing
    /// ([`AgentError::LiveRollbackFailed`]).
    Live,
}

impl Way {
    /// The way of a change after `previous` whose `Apply` allowed
    /// `restarts`. A node's first generation restarts what it needs, as
    /// ever: with nothing in place nothing is served, so nothing can drop.
    pub(crate) fn of(restarts: Restarts, previous: Generation) -> Self {
        match restarts {
            Restarts::Refused if previous != Generation::ZERO => Self::Live,
            Restarts::Refused | Restarts::Allowed => Self::Restarting,
        }
    }

    /// The error of the change for `generation` whose revert failed, with
    /// `cause`.
    pub(crate) const fn failed(self, generation: Generation, cause: RollbackCause) -> AgentError {
        match self {
            Self::Restarting => AgentError::RollbackFailed { generation, cause },
            Self::Live => AgentError::LiveRollbackFailed { generation, cause },
        }
    }
}

/// What applying a generation would do to what serves users.
#[derive(Debug)]
enum Assessment {
    /// Nothing restarts: the running engines take the change as they run,
    /// Xray through its API when clients were added.
    Live(Option<Opening>),
    /// What would restart or reload.
    Restarts(BTreeSet<RestartNeed>),
}

/// What applying `next`, staged in `dir`, after `before` would restart or
/// reload, as step 5 applies it (design §11.2) with `host` the host-profile
/// files it applies. Every managed file is named, so that one added later
/// cannot compile without its decision. With no `before` everything counts
/// as changed. An engine that runs anew (the engine set or its unit
/// changed) is named by [`RestartNeed::Engines`] or
/// [`RestartNeed::HostProfile`], and Xray is then asked nothing.
fn assess(
    paths: &Paths,
    node: &dyn Node,
    before: Option<&BundleHeader>,
    next: &BundleHeader,
    dir: &Path,
    host: &BTreeSet<HostFile>,
) -> Result<Assessment, AgentError> {
    let engines_changed = before.is_none_or(|before| before.engines != next.engines);
    let runs_anew = |unit: HostFile| engines_changed || host.contains(&unit);
    let mut needs = BTreeSet::new();
    if engines_changed {
        needs.insert(RestartNeed::Engines);
    }
    if !host.is_empty() {
        needs.insert(RestartNeed::HostProfile);
    }
    let mut opening = None;
    for &file in ManagedFile::ALL {
        if before.is_some_and(|before| before.files.get(file) == next.files.get(file)) {
            continue;
        }
        match file {
            ManagedFile::Nftables => {
                needs.insert(RestartNeed::Nftables);
            }
            ManagedFile::WgConf => {
                needs.insert(RestartNeed::WireGuard);
            }
            ManagedFile::XrayConfig => {
                if let Some(before) = before.filter(|_| !runs_anew(HostFile::XrayUnit)) {
                    match xray_users::takes(paths, node, before, dir)? {
                        Takes::Live(live) => opening = Some(live),
                        Takes::Restart(need) => {
                            needs.insert(need);
                        }
                    }
                }
            }
            ManagedFile::Hy2Config => {
                if !runs_anew(HostFile::Hy2Unit) {
                    needs.insert(RestartNeed::Hy2Config);
                }
            }
            // The watch reads its configuration at each tick, and sshd the
            // viewers' keys at each login.
            ManagedFile::WatchConfig | ManagedFile::ViewerKeys => {}
        }
    }
    Ok(if needs.is_empty() {
        Assessment::Live(opening)
    } else {
        Assessment::Restarts(needs)
    })
}

/// Refuses the generation staged in `dir` (design §11.2 step 2) unless the
/// running engines take it as they run:
/// [`AgentError::RestartNotAllowed`], naming what would restart. Nothing is
/// installed, and Xray is asked only whether it runs.
pub(super) fn refuse_restarts(
    paths: &Paths,
    node: &dyn Node,
    before: Option<&BundleHeader>,
    next: &BundleHeader,
    dir: &Path,
) -> Result<(), AgentError> {
    let host = host_to_apply(paths, dir, applied(before))?;
    match assess(paths, node, before, next, dir, &host)? {
        Assessment::Live(_) => Ok(()),
        Assessment::Restarts(needs) => Err(AgentError::RestartNotAllowed { needs }),
    }
}

/// The live step, all a transaction under `Refused` applies (design §11.2
/// step 5): the same assessment again, with `host` the host-profile files
/// the swap installed, then the opening if clients were added. A change
/// that would now restart anything, which only a change since the check can
/// make (Xray stopping), fails the step, naming what would restart; nothing
/// is restarted for it. Every failure is [`ApplyStep::XrayUsers`]'s.
pub(super) fn apply(
    paths: &Paths,
    node: &dyn Node,
    before: Option<&BundleHeader>,
    next: &BundleHeader,
    dir: &Path,
    host: &BTreeSet<HostFile>,
) -> Result<(), RollbackCause> {
    let secrets = secrets(dir, ApplyStep::XrayUsers)?;
    let step = Step {
        node,
        secrets: &secrets,
    };
    let assessment = assess(paths, node, before, next, dir, host)
        .map_err(|error| step.failed(ApplyStep::XrayUsers, &error))?;
    match assessment {
        Assessment::Live(None) => Ok(()),
        Assessment::Live(Some(opening)) => xray_users::open_step(paths, &step, dir, &opening),
        Assessment::Restarts(needs) => Err(RollbackCause::Apply {
            step: ApplyStep::XrayUsers,
            stderr_tail: step.tail(
                format!("since the check the change needs a restart this apply does not allow: {needs:?}")
                    .as_bytes(),
            ),
        }),
    }
}
