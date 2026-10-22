// SPDX-License-Identifier: GPL-3.0-or-later

//! The open-files limit of this test process (nextest runs each test in
//! its own process, so raising it touches no other test).

use crate::limits::{open_files_limit, raise_open_files};

#[test]
fn the_open_files_limit_is_read_and_raised_within_the_hard_limit() {
    let before = open_files_limit().unwrap();
    assert!(before.soft > 0);
    assert!(before.soft <= before.hard);
    assert_eq!(
        raise_open_files(before.soft).unwrap(),
        before,
        "no change at or below the soft limit"
    );
    assert_eq!(raise_open_files(1).unwrap(), before);
    let wanted = (before.soft + 16).min(before.hard);
    let after = raise_open_files(wanted).unwrap();
    assert_eq!(after.soft, wanted);
    assert_eq!(after.hard, before.hard);
    assert_eq!(open_files_limit().unwrap(), after);
}
