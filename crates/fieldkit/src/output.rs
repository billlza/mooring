// SPDX-License-Identifier: GPL-3.0-or-later

//! Where results go: one JSON document per line on stdout (each sample as
//! it is taken, so a long run that is cut short keeps what it measured,
//! and the summary last), and short progress notes on stderr.

use std::io::Write;

use serde::Serialize;

use crate::error::FieldkitError;

/// The two output streams of a command.
pub(crate) struct Output<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

impl std::fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output").finish_non_exhaustive()
    }
}

impl<'a> Output<'a> {
    /// Results to `stdout`, notes to `stderr`.
    pub(crate) fn new(stdout: &'a mut dyn Write, stderr: &'a mut dyn Write) -> Self {
        Self { stdout, stderr }
    }

    /// One JSON document on its own line, flushed at once.
    pub(crate) fn record<T: Serialize>(&mut self, value: &T) -> Result<(), FieldkitError> {
        let mut line = serde_json::to_vec(value).map_err(|source| FieldkitError::Output {
            source: source.into(),
        })?;
        line.push(b'\n');
        self.stdout
            .write_all(&line)
            .and_then(|()| self.stdout.flush())
            .map_err(|source| FieldkitError::Output { source })
    }

    /// A progress note on stderr.
    pub(crate) fn note(&mut self, text: &str) -> Result<(), FieldkitError> {
        writeln!(self.stderr, "fieldkit: {text}")
            .and_then(|()| self.stderr.flush())
            .map_err(|source| FieldkitError::Output { source })
    }
}
