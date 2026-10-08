// SPDX-License-Identifier: GPL-3.0-or-later

//! Report output. Every line goes through [`say!`] so a failed write becomes a
//! typed [`OutputError`] instead of a panic or a silently truncated report.

use std::io;

#[derive(Debug, thiserror::Error)]
#[error("failed to write the report to standard output")]
pub(crate) struct OutputError(#[source] pub(crate) io::Error);

/// `writeln!` that maps the I/O error into [`OutputError`].
macro_rules! say {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).map_err($crate::output::OutputError)
    };
}

pub(crate) use say;
