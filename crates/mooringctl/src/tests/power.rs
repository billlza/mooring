// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the daemon looks for its power helper, and a helper whose output
//! cannot be read (design §10.3). The helper's lines and pipes otherwise
//! are the runtime tests'.

use std::io::{self, BufRead, Read};

use crate::error::LocalError;
use crate::runtime::power::{helper_path, read_lines, spawn};

/// The helper is looked for beside this executable, and only there: here
/// beside the test binary, where there is none.
#[test]
fn the_helper_is_looked_for_beside_this_executable() {
    let expected = helper_path(&std::env::current_exe().unwrap());
    assert!(!expected.exists(), "{}", expected.display());
    let error = spawn().unwrap_err();
    assert!(
        matches!(&error, LocalError::PowerHelperSpawn { path, source } if *path == expected && source.kind() == io::ErrorKind::NotFound),
        "{error:?}"
    );
}

/// A reader whose every read fails.
struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the pipe broke"))
    }
}

impl BufRead for Failing {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::other("the pipe broke"))
    }

    fn consume(&mut self, _: usize) {}
}

/// Output that cannot be read ends the reading, saying so.
#[test]
fn output_that_cannot_be_read_ends_the_reading() {
    let mut events = 0;
    let ended = read_lines(&mut Failing, &mut |_| {
        events += 1;
        true
    });
    assert_eq!(
        ended,
        "the power helper's output could not be read: the pipe broke"
    );
    assert_eq!(events, 0);
}
