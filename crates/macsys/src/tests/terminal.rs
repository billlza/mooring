// SPDX-License-Identifier: GPL-3.0-or-later

//! The echo guard on a pseudo-terminal (`openpty`), its refusal of a
//! descriptor that is not a terminal, attributes that cannot be set, and
//! the controlling terminal of a session with and without one. A terminal
//! that cannot be opened for want of a descriptor is tested in
//! tests/process.rs, in the child that lowers its open-files limit.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use super::{assert_passed, run_child};
use crate::error::{MacsysError, TerminalCall};
use crate::terminal::{EchoOff, attributes, controlling_terminal, set_attributes};

/// `TIOCSCTTY`, `_IO('t', 97)` in `<sys/ttycom.h>`: the request that makes
/// a terminal its session's controlling terminal. libc 0.2.189 does not
/// define it for Apple targets.
const TIOCSCTTY: libc::c_ulong = 0x2000_7461;

/// The environment variable that makes [`session_child`] run.
const NEW_SESSION: &str = "MACSYS_TEST_NEW_SESSION";

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
    let (reader, _writer) = io::pipe().unwrap();
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

/// Attributes that cannot be set are an error naming `tcsetattr`: the
/// path by which [`EchoOff::restore`] reports a terminal it could not put
/// back.
#[test]
fn attributes_that_cannot_be_set_are_reported() {
    let (_controller, terminal) = pty();
    let saved = attributes(terminal.as_fd()).unwrap();
    let (reader, _writer) = io::pipe().unwrap();
    assert_eq!(
        set_attributes(reader.as_fd(), &saved),
        Err(MacsysError::Terminal {
            call: TerminalCall::SetAttributes,
            errno: libc::ENOTTY,
        })
    );
    set_attributes(terminal.as_fd(), &saved).unwrap();
}

/// Run as a child by [`the_controlling_terminal_is_the_sessions_own`]: in
/// a new session there is no controlling terminal, which is `None` and no
/// error; once a pseudo-terminal is made the session's, it is the terminal
/// that opens. Alone (no such variable) it does nothing.
#[test]
fn session_child() {
    if std::env::var_os(NEW_SESSION).is_none() {
        return;
    }
    // Opened before the new session, so that only `TIOCSCTTY` below can
    // make it the session's terminal, not the opening itself.
    let (_controller, terminal) = pty();
    // SAFETY: `setsid` has no memory preconditions; this process, a child
    // run for this test alone and not a group leader, leaves its session
    // for a new one without a terminal.
    let session = unsafe { libc::setsid() };
    assert_ne!(session, -1, "setsid failed: {}", io::Error::last_os_error());
    // Once the session has a terminal, closing the pseudo-terminal hangs it
    // up and sends SIGHUP to the session's leader, this process: ignored
    // from here, so that a failed assertion below still reports.
    // SAFETY: `signal` has no memory preconditions; ignoring SIGHUP
    // installs no handler.
    let previous = unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    assert_ne!(previous, libc::SIG_ERR, "ignoring SIGHUP failed");
    assert!(
        controlling_terminal().unwrap().is_none(),
        "a new session has no terminal"
    );
    // SAFETY: `terminal` is an open descriptor for the call, and
    // `TIOCSCTTY` reads no argument.
    let made = unsafe { libc::ioctl(terminal.as_raw_fd(), TIOCSCTTY, 0) };
    assert_eq!(made, 0, "TIOCSCTTY failed: {}", io::Error::last_os_error());
    let tty = controlling_terminal()
        .unwrap()
        .expect("the session's terminal opens");
    // It is this pseudo-terminal: echo switched off through one descriptor
    // is off through the other, and back on once restored.
    let quiet = EchoOff::new(terminal.as_fd()).unwrap();
    assert_eq!(attributes(tty.as_fd()).unwrap().c_lflag & libc::ECHO, 0);
    quiet.restore().unwrap();
    assert_ne!(attributes(tty.as_fd()).unwrap().c_lflag & libc::ECHO, 0);
}

/// The controlling terminal is the session's: absent from a session
/// without one, and the session's terminal once it has one. In a child,
/// as a test cannot leave its own session without leaving the harness's.
#[test]
fn the_controlling_terminal_is_the_sessions_own() {
    let test = "tests::terminal::session_child";
    assert_passed(test, &run_child(test, NEW_SESSION, "1"));
}
