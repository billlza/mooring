// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's event journal and the journals' retention (design §15.7):
//! when the deployed daemon opens it records its start, and each status it
//! publishes gives the events the status shows since the last
//! (`daemon-core`'s `MacSeen`), each appended to the file of its UTC day
//! through `mooring-store`. On the daemon's first record and the first of
//! each new UTC day, the Mac's journal and every node's copy lose the day
//! files of the days before the oldest the journals keep
//! (`events::oldest_kept`, 13 months).
//!
//! The journal is for the operator: an event that cannot be written, or a
//! prune that fails, is logged once while that lasts and once when it
//! recovers, and the tick goes on. Files beside the day files that are not
//! day files, and directories of `events/nodes/` that are no node's, are
//! named once in the log and left alone. The daemon never reads the Mac's
//! journal back.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use mooring_daemon_core::MacStatusV2;
use mooring_daemon_core::events::{MacEvent, MacEventKind, MacSeen, encode_mac_line, oldest_kept};
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{
    StoreError, append_mac_events, event_nodes, prune_mac_events_before, prune_node_events_before,
};

use crate::error::{CommandError, LocalError};

use super::chain;
use super::noted::Noted;

/// The Mac's journal's writer, and the journals' retention.
#[derive(Debug, Default)]
pub(crate) struct Journals {
    /// What the statuses last showed.
    seen: MacSeen,
    /// The UTC day the journals were last pruned for; none before the
    /// first prune of the run, and after a prune that failed.
    pruned: Option<CalendarDate>,
    /// Events that could not be written.
    write_failure: Noted,
    /// A prune that failed.
    prune_failure: Noted,
    /// The strays the last prune named.
    strays: Noted,
}

impl Journals {
    /// The journals of a daemon that opened at `now`: its start is the
    /// Mac's first event, and the old days are pruned. Only a clock past
    /// the year 9999 or a log that cannot be written is an error.
    pub(crate) fn open(
        log: &mut dyn Write,
        support_dir: &Path,
        now: UnixTime,
    ) -> Result<Self, CommandError> {
        let mut journals = Self::default();
        let started = MacEvent {
            at: now,
            kind: MacEventKind::DaemonStarted,
        };
        journals.append(log, support_dir, &[started], now)?;
        journals.prune(log, support_dir, now)?;
        Ok(journals)
    }

    /// Records the events `status` shows since the status last recorded,
    /// and prunes the old days on the first record of a new UTC day.
    pub(crate) fn record(
        &mut self,
        log: &mut dyn Write,
        support_dir: &Path,
        status: &MacStatusV2,
        now: UnixTime,
    ) -> Result<(), CommandError> {
        let events = self.seen.changes(status);
        self.append(log, support_dir, &events, now)?;
        self.prune(log, support_dir, now)
    }

    /// Appends `events` to the files of their UTC days, in their order, one
    /// append per day.
    fn append(
        &mut self,
        log: &mut dyn Write,
        support_dir: &Path,
        events: &[MacEvent],
        now: UnixTime,
    ) -> Result<(), CommandError> {
        let mut days: BTreeMap<CalendarDate, Vec<u8>> = BTreeMap::new();
        for event in events {
            let day = CalendarDate::utc_of(event.at).map_err(|_| LocalError::Clock)?;
            match encode_mac_line(event) {
                Ok(line) => days.entry(day).or_default().extend(line),
                Err(error) => {
                    return self.write_failure.holds(
                        log,
                        now,
                        "the Mac's event journal was not written",
                        chain(&LocalError::EventsEncode(error)),
                    );
                }
            }
        }
        for (day, lines) in days {
            if let Err(error) = append_mac_events(support_dir, day, &lines) {
                return self.write_failure.holds(
                    log,
                    now,
                    "the Mac's event journal was not written",
                    chain(&files(error)),
                );
            }
        }
        if events.is_empty() {
            return Ok(());
        }
        self.write_failure
            .ended(log, now, Some("the Mac's event journal is written again"))
    }

    /// On the first call of a UTC day, removes the day files of the days
    /// before the oldest kept, the Mac's and every node's, and names the
    /// strays beside them.
    fn prune(
        &mut self,
        log: &mut dyn Write,
        support_dir: &Path,
        now: UnixTime,
    ) -> Result<(), CommandError> {
        let today = CalendarDate::utc_of(now).map_err(|_| LocalError::Clock)?;
        if self.pruned == Some(today) {
            return Ok(());
        }
        match prune_all(support_dir, oldest_kept(today)) {
            Ok(strays) => {
                self.pruned = Some(today);
                self.prune_failure.ended(
                    log,
                    now,
                    Some("old event journal days are removed again"),
                )?;
                if strays.is_empty() {
                    self.strays.ended(log, now, None)
                } else {
                    let names: Vec<String> = strays
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect();
                    self.strays.holds(
                        log,
                        now,
                        "the event journals' directories hold files that are not theirs",
                        names.join(", "),
                    )
                }
            }
            Err(error) => self.prune_failure.holds(
                log,
                now,
                "old event journal days were not removed",
                chain(&files(error)),
            ),
        }
    }
}

/// Removes the day files before `oldest` of the Mac's journal and of each
/// node's copy; the strays every listing named.
fn prune_all(support_dir: &Path, oldest: CalendarDate) -> Result<Vec<PathBuf>, StoreError> {
    let mut strays = prune_mac_events_before(support_dir, oldest)?.strays;
    let nodes = event_nodes(support_dir)?;
    strays.extend(nodes.strays);
    for node in &nodes.nodes {
        strays.extend(prune_node_events_before(support_dir, node, oldest)?.strays);
    }
    Ok(strays)
}

/// A store error of the journals' files.
pub(crate) fn files(error: StoreError) -> LocalError {
    LocalError::EventsFile(Box::new(error))
}
