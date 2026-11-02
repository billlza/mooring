// SPDX-License-Identifier: GPL-3.0-or-later

//! The journal's part of a tick (design §11.3, §15.7): what changed
//! between two observations, as events with causes before effects, and
//! the append that records them, on a journal reopened after an append
//! that failed.

use mooring_agent_proto::{
    AgentError, AgentEventKind, EngineUser, GateReason, GateState, Holds, UnixTime,
};

use super::Watch;
use super::status::Observed;
use crate::journal::Journal;
use crate::paths::Paths;

/// What changed from `before` to `after`, as journal events, causes before
/// effects: a boot; a halt; holds recorded; a commit; a resume; engine
/// restarts; holds cleared; conditions raised, then cleared; the gate.
pub(crate) fn changes(before: &Observed, after: &Observed) -> Vec<AgentEventKind> {
    let mut events = Vec::new();
    if before.boot_id != after.boot_id {
        events.push(AgentEventKind::HostBooted);
    }
    if let Some(halt) = after.halted
        && before.halted != after.halted
    {
        events.push(AgentEventKind::Halted {
            reason: halt.reason,
        });
    }
    let holds = hold_changes(&before.holds, &after.holds);
    for change in &holds {
        if change.recorded() {
            events.push(AgentEventKind::HoldRecorded { hold: change.hold });
        }
    }
    if let Some(generation) = after.committed
        && before.committed != after.committed
    {
        events.push(AgentEventKind::Committed { generation });
    }
    if before.halted.is_some() && after.halted.is_none() {
        events.push(AgentEventKind::Resumed {
            generation: after.generation,
        });
    }
    for &engine in EngineUser::ALL {
        if after.restarts.get(engine) > before.restarts.get(engine) {
            events.push(AgentEventKind::EngineRestarted { engine });
        }
    }
    for change in &holds {
        if change.cleared() {
            events.push(AgentEventKind::HoldCleared { hold: change.hold });
        }
    }
    for condition in after.conditions.iter() {
        if before.conditions.get(condition.kind()).is_none() {
            events.push(AgentEventKind::ConditionRaised {
                condition: *condition,
            });
        }
    }
    for condition in before.conditions.iter() {
        if after.conditions.get(condition.kind()).is_none() {
            events.push(AgentEventKind::ConditionCleared {
                condition: condition.kind(),
            });
        }
    }
    match (before.gate, after.gate) {
        (GateState::Closed, GateState::Open) => events.push(AgentEventKind::GateOpened),
        (GateState::Open, GateState::Closed) => events.push(AgentEventKind::GateClosed),
        (GateState::Open, GateState::Open) | (GateState::Closed, GateState::Closed) => {}
    }
    events
}

/// How one kind of hold differs between two observations.
#[derive(Debug, Clone, Copy)]
struct HoldChange {
    hold: GateReason,
    was: bool,
    is: bool,
    changed: bool,
}

impl HoldChange {
    /// Recorded: present now, and absent or different before (a hold
    /// recorded again, as by a second `GateSet`, is a new recording).
    const fn recorded(self) -> bool {
        self.is && self.changed
    }

    /// Cleared: present before, absent now.
    const fn cleared(self) -> bool {
        self.was && !self.is
    }
}

fn hold_changes(before: &Holds, after: &Holds) -> [HoldChange; 3] {
    [
        HoldChange {
            hold: GateReason::MacDrain,
            was: before.mac_drain.is_some(),
            is: after.mac_drain.is_some(),
            changed: before.mac_drain != after.mac_drain,
        },
        HoldChange {
            hold: GateReason::EgressViolation,
            was: before.egress_violation.is_some(),
            is: after.egress_violation.is_some(),
            changed: before.egress_violation != after.egress_violation,
        },
        HoldChange {
            hold: GateReason::Operator,
            was: before.operator.is_some(),
            is: after.operator.is_some(),
            changed: before.operator != after.operator,
        },
    ]
}

impl Watch {
    pub(super) fn append(
        &mut self,
        paths: &Paths,
        now: UnixTime,
        events: &[AgentEventKind],
    ) -> Result<(), AgentError> {
        if events.is_empty() {
            return Ok(());
        }
        let journal = match &mut self.journal {
            Some(journal) => journal,
            None => self.journal.insert(Journal::open(paths)?),
        };
        let appended = journal.append(now, events);
        if appended.is_err() {
            // Reopened at the next append, which cuts off anything torn.
            self.journal = None;
        }
        appended
    }
}
