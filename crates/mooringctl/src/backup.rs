// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether Time Machine excludes a folder (design §12, "Backups"): the
//! export folder must be excluded, so that no backup keeps a user's file
//! after it is deleted. `user export` only warns; the exclusion is set by
//! hand (`delivery.md`, section 0) until M5's daemon sets it.

use std::fmt;
use std::io;
use std::path::Path;
use std::process::Command;

/// The answer `tmutil isexcluded` gave, or why there is none.
#[derive(Debug)]
pub(crate) enum BackupCheckError {
    /// `tmutil` could not be run.
    Run(io::Error),
    /// `tmutil` exited unsuccessfully.
    Failed(Option<i32>),
    /// `tmutil` answered neither `[Excluded]` nor `[Included]` (it says
    /// `[UNKNOWN]` for a path it cannot resolve).
    Unanswered,
}

impl fmt::Display for BackupCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run(error) => write!(f, "tmutil could not be run: {error}"),
            Self::Failed(Some(code)) => write!(f, "tmutil exited with status {code}"),
            Self::Failed(None) => f.write_str("tmutil was stopped by a signal"),
            Self::Unanswered => f.write_str("tmutil reported neither excluded nor included"),
        }
    }
}

/// Answers whether Time Machine excludes a folder.
pub(crate) trait BackupCheck {
    /// Whether `dir` (or a folder above it) is excluded from Time Machine.
    fn is_excluded(&self, dir: &Path) -> Result<bool, BackupCheckError>;
}

/// `/usr/bin/tmutil isexcluded <dir>`, which needs no root and reports a
/// sticky exclusion of the folder or of any folder above it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tmutil;

impl BackupCheck for Tmutil {
    fn is_excluded(&self, dir: &Path) -> Result<bool, BackupCheckError> {
        let output = Command::new("/usr/bin/tmutil")
            .arg("isexcluded")
            .arg(dir)
            .output()
            .map_err(BackupCheckError::Run)?;
        if !output.status.success() {
            return Err(BackupCheckError::Failed(output.status.code()));
        }
        parse_isexcluded(&output.stdout)
    }
}

/// `tmutil isexcluded`'s answer, as observed on macOS 27.0.1 on
/// 2026-10-18: one line, `[Excluded]` or `[Included]`, then the path.
pub(crate) fn parse_isexcluded(stdout: &[u8]) -> Result<bool, BackupCheckError> {
    if stdout.starts_with(b"[Excluded]") {
        Ok(true)
    } else if stdout.starts_with(b"[Included]") {
        Ok(false)
    } else {
        Err(BackupCheckError::Unanswered)
    }
}

#[cfg(test)]
mod tests {
    use super::{BackupCheckError, parse_isexcluded};

    /// The three answers seen on this Mac on 2026-10-18.
    #[test]
    fn the_observed_answers_parse() {
        assert!(parse_isexcluded(b"[Excluded]  /Users/bill/mooring/target\n").unwrap());
        assert!(!parse_isexcluded(b"[Included]  /Users/bill/Downloads\n").unwrap());
        assert!(matches!(
            parse_isexcluded(b"[UNKNOWN]   /nonexistent/path\n"),
            Err(BackupCheckError::Unanswered)
        ));
        assert!(matches!(
            parse_isexcluded(b""),
            Err(BackupCheckError::Unanswered)
        ));
    }
}
