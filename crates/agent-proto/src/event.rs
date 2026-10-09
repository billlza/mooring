// SPDX-License-Identifier: GPL-3.0-or-later

//! The agent's event journal (console spec B.2.9): what changed on the
//! node and when, the reply to `Events`. Events name conditions, holds,
//! generations and engines; none carries an address or a destination.
//!
//! Events are numbered in the order the agent records them, one apart, and
//! a number is never reused, so the Mac pages through the journal by
//! number rather than by time (many events can share a second). The
//! journal is pruned only from its oldest end, so a page holds
//! consecutive numbers: a reply that starts after the number asked for,
//! or a journal that ends before it, shows that events were pruned or the
//! journal was reset, and a gap inside a page is refused rather than
//! hidden.

use serde::{Deserialize, Serialize};

use crate::{
    EngineUser, GateReason, Generation, ShutdownReason, UnixTime, ValueError, WatchError,
    WatchErrorKind,
};

/// An event's number in the agent's journal: numbers start at
/// [`EventSeq::FIRST`] and grow by one per event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventSeq(u64);

impl EventSeq {
    /// The number of the journal's first event.
    pub const FIRST: Self = Self(0);

    /// Wraps an event number.
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// The event number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One journal entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    /// The event's number.
    pub seq: EventSeq,
    /// The agent's clock when it recorded the event.
    pub at: UnixTime,
    /// What happened.
    pub kind: AgentEventKind,
}

/// What happened on the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentEventKind {
    /// The watch raised a condition.
    ConditionRaised {
        /// The condition, with its data when it was raised.
        condition: WatchError,
    },
    /// A condition the watch had raised no longer holds. A change in a
    /// raised condition's data (a count, the inbounds it concerns) is not
    /// an event; the node's status shows the current data.
    ConditionCleared {
        /// The condition's kind.
        condition: WatchErrorKind,
    },
    /// The watch opened the gate.
    GateOpened,
    /// The gate closed: the watch closed it, a hold was recorded, or the
    /// node was halted.
    GateClosed,
    /// A hold was recorded (`GateSet`).
    HoldRecorded {
        /// The hold.
        hold: GateReason,
    },
    /// A hold was cleared: a sleep-drain hold by a new handshake, the
    /// others by `ClearHold`.
    HoldCleared {
        /// The hold.
        hold: GateReason,
    },
    /// The node was halted (`Shutdown`).
    Halted {
        /// Why.
        reason: ShutdownReason,
    },
    /// The node resumed (`Resume`).
    Resumed {
        /// The generation the engines run.
        generation: Generation,
    },
    /// A transaction was confirmed: `generation` is current.
    Committed {
        /// The confirmed generation.
        generation: Generation,
    },
    /// An engine's unit was restarted by its `Restart=` policy.
    EngineRestarted {
        /// The engine, by the user its unit runs as.
        engine: EngineUser,
    },
    /// The host booted.
    HostBooted,
}

/// The most events one [`EventsV1`] carries.
pub const MAX_EVENTS: usize = 4096;

/// A page of the agent's journal, the reply to `Events{since}`: the
/// recorded events numbered `since` or later, oldest first and numbered
/// consecutively, at most [`MAX_EVENTS`] of them, and the number the next
/// event will get.
///
/// The Mac asks next from the last event's number plus one, and has read
/// everything once that equals `end`. A first event numbered above `since`
/// means the events before it were pruned; an `end` below `since` means
/// the journal was reset.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawEvents")]
pub struct EventsV1 {
    events: Vec<AgentEvent>,
    end: EventSeq,
}

impl EventsV1 {
    /// Validates that the events are numbered consecutively upwards (each
    /// one more than the one before), all below `end`, and at most
    /// [`MAX_EVENTS`] of them ([`ValueError::Events`] otherwise).
    pub fn new(events: Vec<AgentEvent>, end: EventSeq) -> Result<Self, ValueError> {
        let ordered = events
            .windows(2)
            .all(|pair| pair[0].seq.get().checked_add(1) == Some(pair[1].seq.get()));
        let below_end = events.last().is_none_or(|last| last.seq < end);
        if ordered && below_end && events.len() <= MAX_EVENTS {
            Ok(Self { events, end })
        } else {
            Err(ValueError::Events)
        }
    }

    /// The events, oldest first.
    pub fn events(&self) -> &[AgentEvent] {
        &self.events
    }

    /// The number the next recorded event will get.
    pub const fn end(&self) -> EventSeq {
        self.end
    }
}

/// The unvalidated wire shape of [`EventsV1`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvents {
    events: Vec<AgentEvent>,
    end: EventSeq,
}

impl TryFrom<RawEvents> for EventsV1 {
    type Error = ValueError;

    fn try_from(raw: RawEvents) -> Result<Self, Self::Error> {
        Self::new(raw.events, raw.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> AgentEvent {
        AgentEvent {
            seq: EventSeq::new(seq),
            at: UnixTime::from_secs(1_791_417_600),
            kind: AgentEventKind::GateOpened,
        }
    }

    #[test]
    fn pages_are_numbered_upwards_below_their_end() {
        let page = EventsV1::new(vec![event(3), event(4), event(5)], EventSeq::new(10)).unwrap();
        assert_eq!(page.events().len(), 3);
        assert_eq!(page.end(), EventSeq::new(10));
        assert!(EventsV1::new(Vec::new(), EventSeq::FIRST).is_ok());
        for (events, end) in [
            (vec![event(4), event(3)], 10),
            (vec![event(4), event(4)], 10),
            (vec![event(3), event(9)], 10),
            // A gap inside a page would hide events: numbers are consecutive.
            (vec![event(3), event(4), event(9)], 10),
            (vec![event(3), event(5)], 10),
            (vec![event(3), event(8)], 9),
            (vec![event(0)], 0),
        ] {
            assert_eq!(
                EventsV1::new(events, EventSeq::new(end)),
                Err(ValueError::Events)
            );
        }
        let full: Vec<AgentEvent> = (0..=MAX_EVENTS as u64).map(event).collect();
        assert_eq!(
            EventsV1::new(full[..MAX_EVENTS].to_vec(), EventSeq::new(u64::MAX))
                .map(|page| page.events().len()),
            Ok(MAX_EVENTS)
        );
        assert_eq!(
            EventsV1::new(full, EventSeq::new(u64::MAX)),
            Err(ValueError::Events)
        );
    }

    #[test]
    fn a_page_is_checked_on_receipt() {
        let json = r#"{"events":[{"seq":5,"at":7,"kind":"HostBooted"}],"end":6}"#;
        let page: EventsV1 = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&page).unwrap(), json);
        assert!(
            serde_json::from_str::<EventsV1>(&json.replace(r#""end":6"#, r#""end":5"#)).is_err()
        );
    }
}
