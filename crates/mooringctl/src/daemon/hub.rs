// SPDX-License-Identifier: GPL-3.0-or-later

//! The latest status, shared between the poller that publishes it and the
//! connections that read it (design §10.1: "pushed to `status --follow`
//! subscribers").
//!
//! The hub keeps exactly one line, the latest encoded reply, and a sequence
//! number that grows with each publication. A subscriber remembers the
//! number it sent last and waits for a greater one, so a slow subscriber
//! skips to the latest status instead of queueing old ones: memory stays
//! bounded by one line whatever the number or speed of the clients.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// A panicking thread left the hub's lock poisoned. Nothing it guards can
/// be trusted after that, so the daemon stops (launchd restarts it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HubPoisoned;

/// One published line and its sequence number (the first is 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Published {
    /// The sequence number.
    pub(crate) seq: u64,
    /// The encoded reply line, its newline included.
    pub(crate) line: Arc<[u8]>,
}

#[derive(Debug, Default)]
struct Latest {
    published: Option<Published>,
}

/// The latest status line.
#[derive(Debug, Default)]
pub(crate) struct Hub {
    latest: Mutex<Latest>,
    changed: Condvar,
}

impl Hub {
    fn lock(&self) -> Result<MutexGuard<'_, Latest>, HubPoisoned> {
        self.latest.lock().map_err(|_| HubPoisoned)
    }

    /// Replaces the latest line and wakes every waiting subscriber.
    pub(crate) fn publish(&self, line: Arc<[u8]>) -> Result<(), HubPoisoned> {
        let mut latest = self.lock()?;
        let seq = latest
            .published
            .as_ref()
            .map_or(1, |published| published.seq.saturating_add(1));
        latest.published = Some(Published { seq, line });
        drop(latest);
        self.changed.notify_all();
        Ok(())
    }

    /// The latest line, if one was published.
    pub(crate) fn latest(&self) -> Result<Option<Published>, HubPoisoned> {
        Ok(self.lock()?.published.clone())
    }

    /// The first line published after `seen` (0 before any line), waiting
    /// at most `timeout` for it: `None` if none came in time.
    pub(crate) fn newer_than(
        &self,
        seen: u64,
        timeout: Duration,
    ) -> Result<Option<Published>, HubPoisoned> {
        let latest = self.lock()?;
        let (latest, _) = self
            .changed
            .wait_timeout_while(latest, timeout, |latest| {
                latest
                    .published
                    .as_ref()
                    .is_none_or(|published| published.seq <= seen)
            })
            .map_err(|_| HubPoisoned)?;
        Ok(latest
            .published
            .as_ref()
            .filter(|published| published.seq > seen)
            .cloned())
    }
}
