// SPDX-License-Identifier: GPL-3.0-or-later

//! The terminal echo guard: a password typed at a terminal is not shown.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::{MacsysError, TerminalCall, last_errno};

/// A terminal whose echo is off (`ECHO` cleared) while the newline is still
/// echoed (`ECHONL` set), so the cursor moves on when the user presses
/// return. [`EchoOff::restore`] puts the saved attributes back and reports
/// a failure; if the guard is dropped instead (an early return or a
/// panic), `Drop` restores them as well, but cannot report.
///
/// Both changes use `TCSAFLUSH`: input typed before the change is
/// discarded, so nothing typed with echo on is read as the password.
pub struct EchoOff<'fd> {
    fd: BorrowedFd<'fd>,
    saved: libc::termios,
    restored: bool,
}

impl fmt::Debug for EchoOff<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchoOff")
            .field("fd", &self.fd)
            .field("restored", &self.restored)
            .finish_non_exhaustive()
    }
}

impl<'fd> EchoOff<'fd> {
    /// Turns the echo of the terminal `fd` off, saving its attributes.
    /// `Terminal{GetAttributes}` if `fd` is not a terminal.
    pub fn new(fd: BorrowedFd<'fd>) -> Result<Self, MacsysError> {
        let saved = attributes(fd)?;
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        set_attributes(fd, &quiet)?;
        Ok(Self {
            fd,
            saved,
            restored: false,
        })
    }

    /// Restores the saved attributes.
    pub fn restore(mut self) -> Result<(), MacsysError> {
        self.restored = true;
        set_attributes(self.fd, &self.saved)
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        if !self.restored {
            // The unwinding or early-return path: `Drop` cannot report, so
            // a failure here is lost; the reporting path is `restore`.
            let _unreported = set_attributes(self.fd, &self.saved);
        }
    }
}

/// Opens the process's controlling terminal (`/dev/tty`) for reading and
/// writing; `Ok(None)` when the process has none (`ENXIO`, as when it runs
/// without a terminal), any other failure as it is.
pub fn controlling_terminal() -> io::Result<Option<File>> {
    match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => Ok(Some(tty)),
        Err(error) if error.raw_os_error() == Some(libc::ENXIO) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The terminal attributes of `fd` (`tcgetattr`).
pub(crate) fn attributes(fd: BorrowedFd<'_>) -> Result<libc::termios, MacsysError> {
    let mut attributes = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `fd` is an open descriptor for the borrow's lifetime, and
    // `attributes` is writable storage for one `termios`, which the call
    // fills.
    let status = unsafe { libc::tcgetattr(fd.as_raw_fd(), attributes.as_mut_ptr()) };
    if status != 0 {
        return Err(MacsysError::Terminal {
            call: TerminalCall::GetAttributes,
            errno: last_errno(),
        });
    }
    // SAFETY: `tcgetattr` returned 0, so it initialised every field.
    Ok(unsafe { attributes.assume_init() })
}

/// Sets the terminal attributes of `fd` after discarding pending input
/// (`tcsetattr` with `TCSAFLUSH`).
fn set_attributes(fd: BorrowedFd<'_>, attributes: &libc::termios) -> Result<(), MacsysError> {
    // SAFETY: `fd` is an open descriptor for the borrow's lifetime, and
    // `attributes` points to a whole `termios` that the call only reads.
    let status = unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, attributes) };
    if status == 0 {
        Ok(())
    } else {
        Err(MacsysError::Terminal {
            call: TerminalCall::SetAttributes,
            errno: last_errno(),
        })
    }
}
