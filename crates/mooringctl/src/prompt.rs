// SPDX-License-Identifier: GPL-3.0-or-later

//! Questions and passwords at the terminal, and the password on stdin.
//! The password is never an argument (design §15.6 rule 3, critique C-15):
//! it comes from the controlling terminal with echo off, or from stdin.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;

use mooring_macsys::{EchoOff, controlling_terminal};
use mooring_model::error::ModelError;
use mooring_model::secret::{MAX_ROUTER_ADMIN_PASSWORD_BYTES, RouterAdminPassword, SecretKind};
use zeroize::{Zeroize, Zeroizing};

use crate::error::LocalError;

/// The answer to a yes/no question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `y` or `yes`, in any case.
    Yes,
    /// Anything else.
    No,
    /// No terminal is attached to ask.
    NoTerminal,
}

/// A line typed at the terminal, with echo.
#[derive(Debug)]
pub(crate) enum Line {
    /// The line, without its newline.
    Text(Zeroizing<Vec<u8>>),
    /// The line was longer than the limit (and was read to its end).
    Overlong,
    /// No terminal is attached to ask.
    NoTerminal,
}

/// The operator's terminal.
pub(crate) trait Console {
    /// Asks `question` (the console adds `[y/N]`).
    fn confirm(&mut self, question: &str) -> Result<Answer, LocalError>;

    /// Asks for a password with echo off; the line without its newline.
    fn password(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, LocalError>;

    /// Asks for one line of at most `limit` bytes, with echo on.
    fn line(&mut self, prompt: &str, limit: usize) -> Result<Line, LocalError>;
}

/// The controlling terminal, `/dev/tty`, opened for each question.
#[derive(Debug)]
pub(crate) struct TtyConsole;

/// The controlling terminal, or `None` when the process has none.
fn open_tty() -> Result<Option<File>, LocalError> {
    controlling_terminal().map_err(LocalError::Terminal)
}

/// The most bytes read for an answer to a question.
pub(crate) const MAX_ANSWER_BYTES: usize = 64;

/// Reads one line from `source`, at most `limit` bytes before the newline
/// (more is `None`, after the rest of the line is consumed), into a
/// zeroizing buffer that never grows. The end of `source` ends the line.
pub(crate) fn read_line(
    source: &mut dyn Read,
    limit: usize,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(limit));
    let mut overlong = false;
    let mut byte = [0_u8; 1];
    loop {
        if source.read(&mut byte)? == 0 || byte[0] == b'\n' {
            break;
        }
        if line.len() == limit {
            overlong = true;
        } else {
            line.push(byte[0]);
        }
    }
    byte.zeroize();
    Ok((!overlong).then_some(line))
}

/// The answer a line spells: `y` or `yes` in any case, whitespace around
/// it ignored. Anything else, an empty or overlong (`None`) line included,
/// is `No`, so only an explicit yes confirms.
pub(crate) fn answer_of(line: Option<&[u8]>) -> Answer {
    match line.map(<[u8]>::trim_ascii) {
        Some(answer)
            if answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes") =>
        {
            Answer::Yes
        }
        Some(_) | None => Answer::No,
    }
}

fn invalid_password() -> LocalError {
    LocalError::Password(ModelError::InvalidSecret {
        kind: SecretKind::RouterAdminPassword,
    })
}

impl Console for TtyConsole {
    fn confirm(&mut self, question: &str) -> Result<Answer, LocalError> {
        let Some(tty) = open_tty()? else {
            return Ok(Answer::NoTerminal);
        };
        write!(&tty, "{question} [y/N] ").map_err(LocalError::Terminal)?;
        let line = read_line(&mut &tty, MAX_ANSWER_BYTES).map_err(LocalError::Terminal)?;
        Ok(answer_of(line.as_ref().map(|line| line.as_slice())))
    }

    fn password(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, LocalError> {
        let tty = open_tty()?.ok_or(LocalError::NoTerminal)?;
        write!(&tty, "{prompt}").map_err(LocalError::Terminal)?;
        let quiet = EchoOff::new(tty.as_fd()).map_err(LocalError::Echo)?;
        let line = read_line(&mut &tty, MAX_ROUTER_ADMIN_PASSWORD_BYTES);
        quiet.restore().map_err(LocalError::Echo)?;
        line.map_err(LocalError::Terminal)?
            .ok_or_else(invalid_password)
    }

    fn line(&mut self, prompt: &str, limit: usize) -> Result<Line, LocalError> {
        let Some(tty) = open_tty()? else {
            return Ok(Line::NoTerminal);
        };
        write!(&tty, "{prompt}").map_err(LocalError::Terminal)?;
        let line = read_line(&mut &tty, limit).map_err(LocalError::Terminal)?;
        Ok(line.map_or(Line::Overlong, Line::Text))
    }
}

/// The most bytes read from stdin: the longest password, a CR and a LF.
pub(crate) const MAX_STDIN_BYTES: usize = MAX_ROUTER_ADMIN_PASSWORD_BYTES + 2;

/// Reads the password from `stdin` to its end: at most
/// [`MAX_STDIN_BYTES`], exactly one trailing newline removed, nothing
/// else changed (a CR or a second newline is refused by the password's
/// own rule).
pub(crate) fn stdin_password(stdin: &mut dyn Read) -> Result<RouterAdminPassword, LocalError> {
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_STDIN_BYTES + 1]);
    let mut filled = 0;
    loop {
        let read = match stdin.read(&mut buffer[filled..]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(LocalError::Stdin(error)),
        };
        if read == 0 {
            break;
        }
        filled += read;
        if filled > MAX_STDIN_BYTES {
            return Err(invalid_password());
        }
    }
    let text = &buffer[..filled];
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    password_of(text)
}

/// The password `bytes` spell: UTF-8 and the password's rule, or
/// `Password(InvalidSecret)`, which never echoes them.
pub(crate) fn password_of(bytes: &[u8]) -> Result<RouterAdminPassword, LocalError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_password())?;
    RouterAdminPassword::parse(text).map_err(LocalError::Password)
}

/// Asks for the password twice at the terminal; `PasswordsDiffer` when the
/// two differ.
pub(crate) fn terminal_password(
    console: &mut dyn Console,
) -> Result<RouterAdminPassword, LocalError> {
    let first = console.password("M7 admin password: ")?;
    let second = console.password("Again: ")?;
    if *first != *second {
        return Err(LocalError::PasswordsDiffer);
    }
    password_of(&first)
}
