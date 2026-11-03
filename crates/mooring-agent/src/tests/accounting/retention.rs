// SPDX-License-Identifier: GPL-3.0-or-later

//! Retention (F7, design §11.5), which `accounting::prune` and the
//! requests share: a bin is served until 48 hours after it ends, to the
//! last second, and never after, pruned or not; a month's file is kept
//! until 7 days after its month, and a crash's temporary file is removed;
//! a usage directory that cannot be listed is reported; and names in it
//! that are not UTF-8 are judged like any other.

use std::fs;

use mooring_agent_proto::{AgentError, IoOp, UnixTime};

use super::{NOV, counters, five_min, month, poll, readings, usage};
use crate::accounting::series::SERIES_KEEP_SECS;
use crate::accounting::{self, MONTH_KEEP_SECS};
use crate::tests::{ENOTDIR, scratch};

#[test]
fn a_bin_is_gone_48_hours_after_it_ends_and_a_month_7_days_after_it_ends() {
    let (_dir, paths) = scratch();
    // From ten minutes before November to a minute into it, which gives
    // November a file.
    for minute in 0..=11 {
        poll(
            &paths,
            NOV - 600 + 60 * minute,
            readings(5, &[("u01@reality", minute, 0)], 0),
        );
    }
    let bin = five_min(NOV - 300, NOV);
    let kept_until = NOV + SERIES_KEEP_SECS;
    accounting::prune(&paths, UnixTime::from_secs(kept_until - 1)).unwrap();
    let kept = accounting::usage_series(&paths, UnixTime::from_secs(kept_until - 1), bin).unwrap();
    assert_eq!(
        kept.bins()[0].traffic(),
        &counters(&[("u01@reality", 5, 0)]),
        "kept to its last second"
    );
    assert_eq!(
        accounting::usage_series(&paths, UnixTime::from_secs(kept_until), bin),
        Err(AgentError::SeriesNotRecorded { recorded: None }),
        "never served once expired, whether or not it was pruned"
    );
    accounting::prune(&paths, UnixTime::from_secs(kept_until)).unwrap();
    assert_eq!(
        accounting::usage_series(&paths, UnixTime::from_secs(kept_until - 1), bin),
        Err(AgentError::SeriesNotRecorded { recorded: None }),
        "pruned"
    );

    let gone = NOV + MONTH_KEEP_SECS;
    assert!(usage(&paths, gone - 1, 2026, 10).is_ok());
    assert_eq!(
        usage(&paths, gone, 2026, 10),
        Err(AgentError::NoUsageRecorded {
            month: month(2026, 10)
        })
    );
    let leftover = paths.usage_dir().join(".2026-10.json.4242.tmp");
    fs::write(&leftover, "{}").unwrap();
    accounting::prune(&paths, UnixTime::from_secs(gone - 1)).unwrap();
    assert!(paths.usage_month(month(2026, 10)).exists());
    assert!(!leftover.exists(), "a crash's temporary file");
    accounting::prune(&paths, UnixTime::from_secs(gone)).unwrap();
    assert!(!paths.usage_month(month(2026, 10)).exists());
    assert!(paths.usage_month(month(2026, 11)).exists());
    assert!(paths.accounting().exists());
}

#[test]
fn retention_reports_a_usage_directory_it_cannot_list() {
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.var_lib()).unwrap();
    fs::write(paths.usage_dir(), "not a directory").unwrap();
    assert_eq!(
        accounting::prune(&paths, UnixTime::from_secs(NOV)),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOTDIR)
        })
    );
}

/// The usage directory's names are judged whatever their encoding: a
/// leftover temporary file whose name is not UTF-8 is removed, and any
/// other such file is no month and stays. APFS refuses such names, so this
/// runs on Linux only.
#[cfg(target_os = "linux")]
#[test]
fn usage_names_that_are_not_utf8_are_judged_like_any_other() {
    use std::os::unix::ffi::OsStrExt;
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.usage_dir()).unwrap();
    let leftover = paths
        .usage_dir()
        .join(std::ffi::OsStr::from_bytes(b".\xff.json.4242.tmp"));
    let stranger = paths
        .usage_dir()
        .join(std::ffi::OsStr::from_bytes(b"\xff.json"));
    fs::write(&leftover, "{}").unwrap();
    fs::write(&stranger, "{}").unwrap();
    accounting::prune(&paths, UnixTime::from_secs(NOV)).unwrap();
    assert!(!leftover.exists(), "a crash's temporary file");
    assert!(stranger.exists(), "no month, so not pruned");
}
