// SPDX-License-Identifier: GPL-3.0-or-later

//! The open-files limit a measurement needs, on this Mac: the descriptors
//! the kernel lets the process hold decide, not the soft limit, which
//! macOS takes above its per-process maximum (`kern.maxfilesperproc`, read
//! with `sysctl` as the oracle). nextest runs each test in its own process,
//! so the limit raised here is this test's alone.

use std::process::Command;

use crate::error::FieldkitError;
use crate::limits::{enough_open_files, ensure_open_files};

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

/// A measurement that needs more descriptors than the kernel lets a
/// process hold is refused before it starts, naming the kernel's maximum,
/// however high the soft limit was raised; one within it goes ahead.
#[test]
fn a_need_past_the_kernels_maximum_is_refused_whatever_the_soft_limit() {
    let maximum = kernel_maximum();
    let want = maximum + 1;
    let hard = mooring_macsys::open_files_limit().unwrap().hard;
    assert!(
        hard >= want,
        "the hard limit ({hard}) leaves no room past kern.maxfilesperproc ({maximum})"
    );
    match ensure_open_files(want) {
        Err(FieldkitError::OpenFilesKernelMaximum {
            maximum: found,
            want: asked,
        }) => assert_eq!((found, asked), (maximum, want)),
        other => panic!("{want} descriptors were not refused for the kernel's maximum: {other:?}"),
    }
    ensure_open_files(maximum).unwrap();
    ensure_open_files(64).unwrap();
}

/// Enough descriptors are enough at exactly the need; short of it, the
/// refusal names what stops them: the kernel's maximum when it holds them
/// below the soft limit, else the soft limit.
#[test]
fn a_shortfall_names_the_kernels_maximum_or_the_soft_limit() {
    assert!(matches!(enough_open_files(8256, 8256, 8256), Ok(())));
    assert!(matches!(
        enough_open_files(122_880, 1_048_576, 8256),
        Ok(())
    ));
    assert!(matches!(
        enough_open_files(122_880, 1_048_576, 122_881),
        Err(FieldkitError::OpenFilesKernelMaximum {
            maximum: 122_880,
            want: 122_881
        })
    ));
    assert!(matches!(
        enough_open_files(4096, 4096, 8256),
        Err(FieldkitError::OpenFilesLimit {
            have: 4096,
            want: 8256
        })
    ));
}
