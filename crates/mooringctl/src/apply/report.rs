// SPDX-License-Identifier: GPL-3.0-or-later

//! What one run of the apply job did, three ways: the operator's report on
//! standard output, which names users by id; the log's lines, which count
//! users and name none (design §15.7: a log line can outlive the 13 months
//! the agreement keeps a user's records); and, with `--json`, one JSON line
//! (version 1): `{"version":1,"at":<secs>,"ran":false}` for a firing outside
//! the window, otherwise `ran: true` with `policy`, `removals` and `nodes`.

use std::io::Write;

use mooring_daemon_core::apply::{Kept, Lapsed, Suspension};
use mooring_model::user::SuspendReason;
use mooring_model::{NodeId, UnixTime, UserId};
use serde::Serialize;

use crate::error::CommandError;
use crate::payments::notes::stamp;
use crate::state::output;

/// The version of the `--json` outcome.
pub(crate) const OUTCOME_VERSION: u32 = 1;

/// What refused the policy step, in words that name no user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefusalKind {
    /// The payment ledger or the pull's settings cannot be read.
    PaymentFiles,
    /// The collected usage cannot be read or is inconsistent.
    Usage,
    /// A suspension for quota is dated after the run's time.
    ClockSteppedBack,
    /// The policy could not be evaluated otherwise.
    Policy,
}

impl RefusalKind {
    const fn words(self) -> &'static str {
        match self {
            Self::PaymentFiles => {
                "the payment ledger or the pull's settings cannot be read, and a paid user would be read as unpaid"
            }
            Self::Usage => "the usage the daemon collected cannot be read or is inconsistent",
            Self::ClockSteppedBack => {
                "a suspension for quota is dated after now: the clock stepped back, or a record is wrong"
            }
            Self::Policy => "the users' policy could not be evaluated",
        }
    }
}

/// Why the policy step was not carried out.
#[derive(Debug, Serialize)]
pub(crate) struct Refusal {
    /// What refused it.
    pub(crate) kind: RefusalKind,
    /// The error, which may name a user.
    pub(crate) error: String,
}

/// Which change failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Change {
    /// A suspension.
    Suspend,
    /// A resume.
    Resume,
}

/// A change of the policy step that failed.
#[derive(Debug, Serialize)]
pub(crate) struct FailedChange {
    /// The user.
    pub(crate) user: UserId,
    /// Which change.
    pub(crate) change: Change,
    /// Why.
    pub(crate) error: String,
}

/// What the policy step carried out and reported.
#[derive(Debug, Default, Serialize)]
pub(crate) struct PolicyDone {
    /// The suspensions made, each at the run's time.
    pub(crate) suspended: Vec<Suspension>,
    /// The lapsed suspensions resumed.
    pub(crate) resumed: Vec<Lapsed>,
    /// The lapsed suspensions the cap on active users holds back.
    pub(crate) held_back: Vec<Lapsed>,
    /// The lapsed suspensions kept, since the user would be suspended
    /// again at once.
    pub(crate) kept: Vec<Kept>,
    /// The changes that failed.
    pub(crate) failed: Vec<FailedChange>,
    /// The users with a quota that was not checked, since their usage this
    /// cycle is unknown.
    pub(crate) quotas_unchecked: Vec<UserId>,
    /// Why no usage report could be made, if none could.
    pub(crate) usage_behind: Option<String>,
}

/// The policy step's outcome.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyOutcome {
    /// Nothing of it was carried out.
    Refused(Refusal),
    /// It was carried out.
    CarriedOut(Box<PolicyDone>),
}

impl PolicyOutcome {
    /// Whether the run's clock stepped back, so that removals wait.
    pub(crate) const fn clock_stepped_back(&self) -> bool {
        matches!(
            self,
            Self::Refused(Refusal {
                kind: RefusalKind::ClockSteppedBack,
                ..
            })
        )
    }

    /// The report's lines.
    pub(crate) fn lines(&self) -> Vec<String> {
        let done = match self {
            Self::Refused(refusal) => {
                return vec![format!(
                    "policy step not carried out: {}: {}",
                    refusal.kind.words(),
                    refusal.error
                )];
            }
            Self::CarriedOut(done) => done,
        };
        let mut lines = Vec::new();
        for suspension in &done.suspended {
            lines.push(format!(
                "suspended {}: {}",
                suspension.user,
                reason(suspension.reason)
            ));
        }
        for lapsed in &done.resumed {
            lines.push(format!("resumed {}, {}", lapsed.user, suspended(lapsed)));
        }
        for lapsed in &done.held_back {
            lines.push(format!(
                "held back by the cap on active users: {}, {}; still suspended",
                lapsed.user,
                suspended(lapsed)
            ));
        }
        for kept in &done.kept {
            lines.push(format!(
                "kept suspended: {}, {}, would be suspended again at once ({})",
                kept.lapsed.user,
                suspended(&kept.lapsed),
                reason(kept.again)
            ));
        }
        for failed in &done.failed {
            let change = match failed.change {
                Change::Suspend => "suspending",
                Change::Resume => "resuming",
            };
            lines.push(format!("{change} {} failed: {}", failed.user, failed.error));
        }
        if !done.quotas_unchecked.is_empty() {
            let users: Vec<String> = done
                .quotas_unchecked
                .iter()
                .map(ToString::to_string)
                .collect();
            lines.push(format!(
                "quotas not checked for {} user(s) ({}): {}",
                users.len(),
                users.join(", "),
                done.usage_behind
                    .as_deref()
                    .unwrap_or("their usage this cycle is unknown")
            ));
        }
        lines
    }

    /// The log's line, which names no user.
    pub(crate) fn log_line(&self) -> String {
        match self {
            Self::Refused(refusal) => {
                format!("policy step not carried out: {}", refusal.kind.words())
            }
            Self::CarriedOut(done) => {
                let mut line = format!(
                    "policy: {} suspended, {} resumed, {} held back by the cap, {} kept suspended, {} failed",
                    done.suspended.len(),
                    done.resumed.len(),
                    done.held_back.len(),
                    done.kept.len(),
                    done.failed.len()
                );
                if !done.quotas_unchecked.is_empty() {
                    line.push_str(&format!(
                        "; quotas not checked for {} user(s)",
                        done.quotas_unchecked.len()
                    ));
                }
                line
            }
        }
    }

    fn failures(&self) -> usize {
        match self {
            Self::Refused(_) => 1,
            Self::CarriedOut(done) => done.failed.len(),
        }
    }
}

/// A removal that failed.
#[derive(Debug, Serialize)]
pub(crate) struct FailedRemoval {
    /// The user, or none for the kept ids or for the step as a whole.
    pub(crate) user: Option<UserId>,
    /// Why.
    pub(crate) error: String,
}

/// What the removals did.
#[derive(Debug, Default, Serialize)]
pub(crate) struct RemovalsDone {
    /// The users removed, 13 months after their revocation.
    pub(crate) removed: Vec<UserId>,
    /// Whether kept ids whose records expired were dropped.
    pub(crate) kept_ids_dropped: bool,
    /// What failed.
    pub(crate) failed: Vec<FailedRemoval>,
}

/// The removals' outcome.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Removals {
    /// None was made: the clock stepped back.
    Skipped,
    /// They were made.
    Done(RemovalsDone),
}

impl Removals {
    /// The report's lines.
    pub(crate) fn lines(&self) -> Vec<String> {
        let done = match self {
            Self::Skipped => return vec![SKIPPED.to_owned()],
            Self::Done(done) => done,
        };
        let mut lines: Vec<String> = done
            .removed
            .iter()
            .map(|user| format!("removed {user}: revoked 13 months ago"))
            .collect();
        if done.kept_ids_dropped {
            lines.push("dropped the ids of removed users whose records have expired".to_owned());
        }
        for failed in &done.failed {
            lines.push(match &failed.user {
                Some(user) => format!("removing {user} failed: {}", failed.error),
                None => format!("removals failed: {}", failed.error),
            });
        }
        lines
    }

    /// The log's line, which names no user.
    pub(crate) fn log_line(&self) -> String {
        match self {
            Self::Skipped => SKIPPED.to_owned(),
            Self::Done(done) => format!(
                "removals: {} removed, {} failed{}",
                done.removed.len(),
                done.failed.len(),
                if done.kept_ids_dropped {
                    "; dropped the expired ids of removed users"
                } else {
                    ""
                }
            ),
        }
    }

    fn failures(&self) -> usize {
        match self {
            Self::Skipped => 0,
            Self::Done(done) => done.failed.len(),
        }
    }
}

const SKIPPED: &str = "removals skipped: the clock stepped back";

/// How one node's apply ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NodeResult {
    /// The node confirmed the deployment's generation.
    Applied,
    /// It did not.
    Failed {
        /// Why.
        error: String,
    },
}

/// One node's apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NodeOutcome {
    /// The node.
    pub(crate) node: NodeId,
    /// How it ended.
    pub(crate) result: NodeResult,
}

impl NodeOutcome {
    /// Its line, in the report and the log alike: it names a node only,
    /// and an error's lines (ssh's own, say) are joined into one.
    pub(crate) fn log_line(&self) -> String {
        match &self.result {
            NodeResult::Applied => format!("{}: applied", self.node),
            NodeResult::Failed { error } => format!(
                "{}: apply failed: {}",
                self.node,
                error.split('\n').collect::<Vec<_>>().join(" / ")
            ),
        }
    }
}

/// What one run did.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// The run's time.
    pub(crate) at: UnixTime,
    /// The policy step.
    pub(crate) policy: PolicyOutcome,
    /// The removals.
    pub(crate) removals: Removals,
    /// The node applies.
    pub(crate) nodes: Vec<NodeOutcome>,
}

#[derive(Serialize)]
struct Ran<'a> {
    version: u32,
    at: UnixTime,
    ran: bool,
    policy: &'a PolicyOutcome,
    removals: &'a Removals,
    nodes: &'a [NodeOutcome],
}

#[derive(Serialize)]
struct NotRan {
    version: u32,
    at: UnixTime,
    ran: bool,
}

impl Outcome {
    /// How many parts of the run failed: the policy step as a whole when it
    /// was refused, each change, removal and node apply that failed.
    pub(crate) fn failures(&self) -> usize {
        self.policy.failures()
            + self.removals.failures()
            + self
                .nodes
                .iter()
                .filter(|node| matches!(node.result, NodeResult::Failed { .. }))
                .count()
    }

    /// Writes the end of the report: each node's line and the summary, or
    /// the whole outcome as one JSON line.
    pub(crate) fn finish(&self, out: &mut dyn Write, json: bool) -> Result<(), CommandError> {
        if json {
            return json_line(
                out,
                &Ran {
                    version: OUTCOME_VERSION,
                    at: self.at,
                    ran: true,
                    policy: &self.policy,
                    removals: &self.removals,
                    nodes: &self.nodes,
                },
            );
        }
        let mut lines: Vec<String> = self.nodes.iter().map(NodeOutcome::log_line).collect();
        lines.push(self.summary());
        write_lines(out, &lines, &[])
    }

    fn summary(&self) -> String {
        let (suspended, resumed, held_back, kept) = match &self.policy {
            PolicyOutcome::Refused(_) => (0, 0, 0, 0),
            PolicyOutcome::CarriedOut(done) => (
                done.suspended.len(),
                done.resumed.len(),
                done.held_back.len(),
                done.kept.len(),
            ),
        };
        let removed = match &self.removals {
            Removals::Skipped => 0,
            Removals::Done(done) => done.removed.len(),
        };
        let applied = self
            .nodes
            .iter()
            .filter(|node| node.result == NodeResult::Applied)
            .count();
        format!(
            "apply at {}: {suspended} suspended, {resumed} resumed, {held_back} held back, {kept} kept suspended, {removed} removed, {applied} of {} node(s) behind applied; {} failure(s)",
            stamp(self.at),
            self.nodes.len(),
            self.failures()
        )
    }
}

/// Reports a firing outside the window, which does nothing.
pub(crate) fn outside_window(
    out: &mut dyn Write,
    at: UnixTime,
    json: bool,
) -> Result<(), CommandError> {
    if json {
        return json_line(
            out,
            &NotRan {
                version: OUTCOME_VERSION,
                at,
                ran: false,
            },
        );
    }
    write_lines(
        out,
        &[format!(
            "apply: {} is outside the apply window (19:15 to 19:45 UTC); nothing done",
            stamp(at)
        )],
        &[],
    )
}

/// Writes `first`, then `then`, one line each.
pub(crate) fn write_lines(
    out: &mut dyn Write,
    first: &[String],
    then: &[String],
) -> Result<(), CommandError> {
    for line in first.iter().chain(then) {
        writeln!(out, "{line}").map_err(output)?;
    }
    Ok(())
}

fn json_line(out: &mut dyn Write, document: &impl Serialize) -> Result<(), CommandError> {
    let mut line = serde_json::to_vec(document)
        .map_err(|error| output(std::io::Error::other(error.to_string())))?;
    line.push(b'\n');
    out.write_all(&line).map_err(output)
}

/// A suspension's reason, in the report's words.
fn reason(reason: SuspendReason) -> String {
    match reason {
        SuspendReason::Expired => "expired".to_owned(),
        SuspendReason::QuotaExceeded { cycle_start } => {
            format!("over quota in the billing cycle from {cycle_start}")
        }
        SuspendReason::Operator => "by the operator".to_owned(),
        SuspendReason::AbuseReview => "for an abuse review".to_owned(),
    }
}

/// A lapsed suspension, in the report's words.
fn suspended(lapsed: &Lapsed) -> String {
    format!(
        "suspended {} since {}",
        reason(lapsed.reason),
        stamp(lapsed.since)
    )
}
