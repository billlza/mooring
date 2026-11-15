// SPDX-License-Identifier: GPL-3.0-or-later

//! A condition the daemon logs once while it lasts and once when it ends,
//! so a failure that repeats every tick (a file that cannot be written, a
//! node that cannot be read) is one line in the log, not one per tick.

use std::io::Write;

use mooring_model::UnixTime;

use crate::error::CommandError;

use super::say;

/// A condition logged once while it lasts, and once when it ends.
#[derive(Debug, Default)]
pub(crate) struct Noted {
    text: Option<String>,
}

impl Noted {
    /// The condition holds with `text`: logged as `what: text` unless the
    /// same text was logged already.
    pub(crate) fn holds(
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
    pub(crate) fn ended(
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
