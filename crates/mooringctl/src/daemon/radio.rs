// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history's writer (design §15.6 rule 11, §15.7): after every
//! poll of the M7, in both of the daemon's loops, one sample line goes to
//! the UTC day's file through `mooring-store`; `daemon-core` makes the
//! sample and its line. The first append of a run, and the first of each
//! new day, then keep the newest [`RADIO_HISTORY_DAYS`] day files and
//! remove the rest.
//!
//! The history is for diagnosis: a sample that cannot be written, or a
//! prune that fails, is logged once while that lasts and once when it
//! recovers, and the tick goes on. Files in the directory that are not
//! day files are named once in the log and left alone. The daemon never
//! reads the history back.

use std::io::Write;
use std::path::Path;

use mooring_daemon_core::RouterStatus;
use mooring_daemon_core::radio_history::{RadioSample, encode_line};
use mooring_daemon_core::router::RouterUnavailableReason;
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{Pruned, append_radio_line, prune_radio_days};

use crate::error::{CommandError, LocalError};

use super::{chain, say};

/// How many day files are kept: the newest 90, which is 90 days when the
/// daemon runs every day (count-based, so a clock that steps forward costs
/// one file, never all of them).
pub(crate) const RADIO_HISTORY_DAYS: u32 = 90;

/// [`RADIO_HISTORY_DAYS`] as the store counts files.
const KEEP_FILES: usize = RADIO_HISTORY_DAYS as usize;

/// A condition logged once while it lasts, and once when it ends.
#[derive(Debug, Default)]
struct Noted {
    text: Option<String>,
}

impl Noted {
    /// The condition holds with `text`: logged as `what: text` unless the
    /// same text was logged already.
    fn holds(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        what: &str,
        text: String,
    ) -> Result<(), CommandError> {
        if self.text.as_deref() != Some(text.as_str()) {
            say(log, now, &format!("{what}: {text}"))?;
            self.text = Some(text);
        }
        Ok(())
    }

    /// The condition no longer holds: `said` is logged if it did.
    fn ended(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        said: Option<&str>,
    ) -> Result<(), CommandError> {
        if self.text.take().is_some()
            && let Some(said) = said
        {
            say(log, now, said)?;
        }
        Ok(())
    }
}

/// The writer: what it carries from one poll to the next.
#[derive(Debug, Default)]
pub(crate) struct RadioHistoryWriter {
    /// The day whose file was last pruned for; none before the first
    /// append of the run, and after a prune that failed.
    day: Option<CalendarDate>,
    /// A sample that could not be written.
    write_failure: Noted,
    /// A prune that failed.
    prune_failure: Noted,
    /// The strays the last prune named.
    strays: Noted,
}

impl RadioHistoryWriter {
    /// Records the poll at `polled_at` that gave `outcome` in the file of
    /// the UTC day it was polled on, and on the first append of the run or
    /// of a new day prunes the old days. Only a clock past the year 9999
    /// or a log that cannot be written is an error.
    pub(crate) fn record(
        &mut self,
        log: &mut dyn Write,
        support_dir: &Path,
        polled_at: UnixTime,
        outcome: Result<&RouterStatus, RouterUnavailableReason>,
        now: UnixTime,
    ) -> Result<(), CommandError> {
        let day = CalendarDate::utc_of(polled_at).map_err(|_| LocalError::Clock)?;
        let sample = RadioSample::of(polled_at, outcome);
        match append(support_dir, day, &sample) {
            Ok(()) => {
                self.write_failure
                    .ended(log, now, Some("the radio history is written again"))?;
            }
            Err(error) => {
                return self.write_failure.holds(
                    log,
                    now,
                    "the radio history was not written",
                    chain(&error),
                );
            }
        }
        if self.day == Some(day) {
            return Ok(());
        }
        match prune_radio_days(support_dir, KEEP_FILES) {
            Ok(Pruned { strays, .. }) => {
                self.day = Some(day);
                self.prune_failure.ended(
                    log,
                    now,
                    Some("old radio history days are removed again"),
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
                        "the radio directory holds files that are not day files",
                        names.join(", "),
                    )
                }
            }
            Err(error) => self.prune_failure.holds(
                log,
                now,
                "old radio history days were not removed",
                chain(&LocalError::HistoryFile(Box::new(error))),
            ),
        }
    }
}

/// Encodes `sample` and appends its line to `day`'s file.
fn append(support_dir: &Path, day: CalendarDate, sample: &RadioSample) -> Result<(), LocalError> {
    let line = encode_line(sample).map_err(LocalError::HistoryEncode)?;
    append_radio_line(support_dir, day, &line)
        .map_err(|error| LocalError::HistoryFile(Box::new(error)))
}
