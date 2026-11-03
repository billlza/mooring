// SPDX-License-Identifier: GPL-3.0-or-later

//! The open-files limit of this test process, what a raise asks for, and
//! the descriptors the kernel in fact lets the process hold, checked
//! against `sysctl -n kern.maxfilesperproc` as the oracle. The limit is the
//! whole process's, so one test reads, lowers, raises and refuses it in
//! turn: nextest runs each test in a process of its own, but plain
//! `cargo test` runs them as threads of one.

use std::process::Command;

use crate::error::{MacsysError, RlimitCall};
use crate::limits::{
    descriptors_in_force, open_files_limit, raise_open_files, raised_soft, set_limit,
};

/// The kernel's per-process maximum of descriptors, as `sysctl` prints it.
fn kernel_maximum() -> u64 {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.maxfilesperproc"])
        .output()
        .unwrap();
    assert!(output.status.success(), "sysctl failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// The limit is raised to what is asked, never lowered by a raise, and
/// taken past the kernel's per-process maximum without an error, while the
/// descriptors in force stop at that maximum; a soft limit above the hard
/// one is refused and changes nothing.
#[test]
fn the_open_files_limit_is_raised_as_asked_and_in_force_to_the_kernels_maximum() {
    let maximum = kernel_maximum();
    let before = open_files_limit().unwrap();
    assert!(before.soft <= before.hard);
    assert_eq!(before.in_force, before.soft.min(maximum));
    assert!(
        before.hard >= maximum + 1000,
        "the hard limit ({}) leaves no room past kern.maxfilesperproc ({maximum})",
        before.hard
    );

    // From a known soft limit, below the kernel's maximum.
    set_limit(1024, before.hard).unwrap();
    let low = open_files_limit().unwrap();
    assert_eq!(
        (low.soft, low.hard, low.in_force),
        (1024, before.hard, 1024)
    );
    assert_eq!(raise_open_files(1024).unwrap(), low, "at the soft limit");
    assert_eq!(raise_open_files(1).unwrap(), low, "below it");
    let raised = raise_open_files(1040).unwrap();
    assert_eq!((raised.soft, raised.in_force), (1040, 1040));

    // Past the kernel's maximum: taken, but not in force.
    let past = raise_open_files(maximum + 1000).unwrap();
    assert_eq!(
        (past.soft, past.hard, past.in_force),
        (maximum + 1000, before.hard, maximum)
    );
    assert_eq!(open_files_limit().unwrap(), past);

    // Refused by the kernel: a soft limit above the hard one.
    assert_eq!(
        set_limit(before.hard, before.hard - 1),
        Err(MacsysError::Rlimit {
            call: RlimitCall::Set,
            errno: libc::EINVAL,
        })
    );
    assert_eq!(open_files_limit().unwrap(), past);

    set_limit(before.soft, before.hard).unwrap();
    assert_eq!(open_files_limit().unwrap(), before);
}

/// A raise asks for the wanted limit, or the hard one when that is lower,
/// and never for less than the soft limit already is.
#[test]
fn a_raise_asks_for_the_wanted_or_the_hard_limit_and_never_lowers() {
    assert_eq!(raised_soft(256, 4096, 1024), Some(1024));
    assert_eq!(raised_soft(256, 4096, 4096), Some(4096));
    assert_eq!(raised_soft(256, 4096, 8192), Some(4096));
    assert_eq!(raised_soft(256, 4096, 256), None);
    assert_eq!(raised_soft(256, 4096, 1), None);
    assert_eq!(raised_soft(4096, 4096, 8192), None);
}

/// `getdtablesize`'s answer is taken as it is, and one below 0, which the
/// kernel gives only when `kern.maxfilesperproc` is set below 0, is an
/// error rather than a count.
#[test]
fn the_descriptors_in_force_are_never_below_0() {
    assert_eq!(descriptors_in_force(0), Ok(0));
    assert_eq!(descriptors_in_force(122_880), Ok(122_880));
    assert_eq!(
        descriptors_in_force(libc::c_int::MAX),
        Ok(u64::from(libc::c_int::MAX.unsigned_abs()))
    );
    assert_eq!(
        descriptors_in_force(-1),
        Err(MacsysError::DescriptorTableSizeInvalid { size: -1 })
    );
}
