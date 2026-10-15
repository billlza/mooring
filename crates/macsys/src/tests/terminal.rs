// SPDX-License-Identifier: GPL-3.0-or-later

//! The echo guard on a pseudo-terminal (`openpty`), and its refusal of a
//! descriptor that is not a terminal.

use std::fs::File;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::error::{MacsysError, TerminalCall};
use crate::terminal::{EchoOff, attributes, controlling_terminal};

/// A new pseudo-terminal pair (controller, terminal).
fn pty() -> (OwnedFd, OwnedFd) {
    let mut controller: libc::c_int = -1;
    let mut terminal: libc::c_int = -1;
    // SAFETY: both out-pointers are valid for writes; null name, termios
    // and window size ask for none to be returned or set.
    let status = unsafe {
        libc::openpty(
            &mut controller,
            &mut terminal,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(status, 0, "openpty failed");
    // SAFETY: `openpty` returned a new descriptor that nothing else owns.
    let controller = unsafe { OwnedFd::from_raw_fd(controller) };
    // SAFETY: as above, for the terminal side.
    let terminal = unsafe { OwnedFd::from_raw_fd(terminal) };
    (controller, terminal)
}

fn local_modes(fd: &OwnedFd) -> libc::tcflag_t {
    attributes(fd.as_fd()).unwrap().c_lflag
}

#[test]
fn echo_off_clears_echo_and_restores_it() {
    let (_controller, terminal) = pty();
    let before = local_modes(&terminal);
    assert_ne!(before & libc::ECHO, 0, "a new pseudo-terminal echoes");
    let guard = EchoOff::new(terminal.as_fd()).unwrap();
    let quiet = local_modes(&terminal);
    assert_eq!(quiet & libc::ECHO, 0, "echo is off");
    assert_ne!(quiet & libc::ECHONL, 0, "the newline is still echoed");
    assert_eq!(
        quiet & !(libc::ECHO | libc::ECHONL),
        before & !(libc::ECHO | libc::ECHONL),
        "nothing else changes"
    );
    assert!(format!("{guard:?}").starts_with("EchoOff"));
    guard.restore().unwrap();
    assert_eq!(local_modes(&terminal), before);
    // Dropping the guard restores the attributes too.
    let guard = EchoOff::new(terminal.as_fd()).unwrap();
    assert_eq!(local_modes(&terminal) & libc::ECHO, 0);
    drop(guard);
    assert_eq!(local_modes(&terminal), before);
}

#[test]
fn a_descriptor_that_is_not_a_terminal_is_refused() {
    let (reader, _writer) = std::io::pipe().unwrap();
    assert_eq!(
        EchoOff::new(reader.as_fd()).unwrap_err(),
        MacsysError::Terminal {
            call: TerminalCall::GetAttributes,
            errno: libc::ENOTTY,
        }
    );
    // A device that is not a terminal refuses with its own errno.
    let null = File::open("/dev/null").unwrap();
    assert!(matches!(
        EchoOff::new(null.as_fd()),
        Err(MacsysError::Terminal {
            call: TerminalCall::GetAttributes,
            errno,
        }) if errno != 0
    ));
}

/// The controlling terminal opens when there is one and is `None` without
/// one (as under a test harness started without a terminal); either way it
/// is not an error, and a terminal that opens is one.
#[test]
fn the_controlling_terminal_is_a_terminal_or_absent() {
    if let Some(tty) = controlling_terminal().unwrap() {
        attributes(tty.as_fd()).unwrap();
    }
}
