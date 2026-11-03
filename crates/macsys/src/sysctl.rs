// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's `sysctl` reads: a value of a known size, and a PF_ROUTE
//! table, which may grow between being sized and being read. [`read`] is
//! the crate's one `sysctl` call; what is decided about its answers (the
//! table's bound, the room given it, the retries) is [`read_table`], which
//! takes the call as a parameter, so a test can answer for the kernel.

use std::ptr;

use crate::error::{MacsysError, last_errno};

/// The largest table read, in bytes.
pub(crate) const MAX_TABLE_BYTES: usize = 16 << 20;

/// How often a read that found the table grown since it was sized
/// (`ENOMEM`) is retried before `TableChanged`.
pub(crate) const GROWTH_RETRIES: usize = 3;

/// A PF_ROUTE `sysctl` name: six integers.
pub(crate) type Mib = [libc::c_int; 6];

/// One `sysctl` read of `name`: with no buffer, the size of the value;
/// with one, the bytes of the value written into it, as many as fit. `Err`
/// holds the call's `errno`.
pub(crate) fn read<const N: usize>(
    mut name: [libc::c_int; N],
    buffer: Option<&mut [u8]>,
) -> Result<usize, i32> {
    // A name is at most `CTL_MAXNAME` (12) integers, checked when the crate
    // is built, so the length converts without loss.
    let length = const {
        assert!(N <= 12, "a sysctl name is at most CTL_MAXNAME integers");
        N as libc::c_uint
    };
    let (into, mut size) = match buffer {
        Some(buffer) => (buffer.as_mut_ptr().cast(), buffer.len()),
        None => (ptr::null_mut(), 0),
    };
    // SAFETY: `name` holds `length` integers, which the call only reads
    // although it takes them by a mutable pointer; `into` is null, which asks
    // only for the size the kernel writes to `size`, or `size` writable
    // bytes, of which the kernel writes at most `size` and stores the count
    // in `size`; no new value is set.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            length,
            into,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status == 0 {
        Ok(size)
    } else {
        Err(last_errno())
    }
}

/// Reads one PF_ROUTE table.
pub(crate) fn dump(mib: Mib) -> Result<Vec<u8>, MacsysError> {
    read_table(|buffer| read(mib, buffer))
}

/// Reads a table through `read`, which answers as [`read`] does for the
/// table's name: its size first, then the table into a buffer with a
/// quarter more room, sized and read again when it grew past even that
/// (`ENOMEM`), at most [`GROWTH_RETRIES`] times before `TableChanged`. A
/// table larger than [`MAX_TABLE_BYTES`] is `TableTooLarge`, and an empty
/// one is no bytes.
pub(crate) fn read_table(
    mut read: impl FnMut(Option<&mut [u8]>) -> Result<usize, i32>,
) -> Result<Vec<u8>, MacsysError> {
    let failed = |errno| MacsysError::Sysctl { errno };
    for _attempt in 0..=GROWTH_RETRIES {
        let size = read(None).map_err(failed)?;
        if size > MAX_TABLE_BYTES {
            return Err(MacsysError::TableTooLarge);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let room = (size + size / 4).min(MAX_TABLE_BYTES);
        let mut table = vec![0_u8; room];
        match read(Some(&mut table)) {
            Ok(filled) => {
                table.truncate(filled);
                return Ok(table);
            }
            Err(libc::ENOMEM) => {}
            Err(errno) => return Err(failed(errno)),
        }
    }
    Err(MacsysError::TableChanged)
}
