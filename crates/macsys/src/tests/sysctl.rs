// SPDX-License-Identifier: GPL-3.0-or-later

//! The `sysctl` reads: a table read through a scripted kernel, so every
//! decision about the kernel's answers is held (the bound, the room offered,
//! the retries, the bytes kept), and the live kernel's answers to a name it
//! knows and one it does not.

use std::mem::size_of;

use self::Answer::{Size, Table};
use crate::error::MacsysError;
use crate::sysctl::{MAX_TABLE_BYTES, dump, read, read_table};

/// What the scripted kernel answers to one call.
#[derive(Debug)]
enum Answer {
    /// To a call without a buffer: the table's size, or an `errno`.
    Size(Result<usize, i32>),
    /// To a call with a buffer: the bytes it writes there, or an `errno`.
    Table(Result<Vec<u8>, i32>),
}

/// Reads a table from a kernel that gives `answers` in turn, every one of
/// them, and says what it was asked: `None` for a size, the room offered
/// for a read.
fn scripted(answers: Vec<Answer>) -> (Result<Vec<u8>, MacsysError>, Vec<Option<usize>>) {
    let mut answers = answers.into_iter();
    let mut asked = Vec::new();
    let table = read_table(|buffer| {
        asked.push(buffer.as_ref().map(|buffer| buffer.len()));
        match (buffer, answers.next()) {
            (None, Some(Size(size))) => size,
            (Some(buffer), Some(Table(written))) => written.map(|bytes| {
                buffer[..bytes.len()].copy_from_slice(&bytes);
                bytes.len()
            }),
            (buffer, answer) => panic!(
                "asked with a buffer of {:?}, scripted {answer:?}",
                buffer.map(|buffer| buffer.len())
            ),
        }
    });
    assert!(answers.next().is_none(), "the table was read too soon");
    (table, asked)
}

fn bytes(count: usize) -> Vec<u8> {
    (0..count)
        .map(|at| u8::try_from(at % 251 + 1).unwrap())
        .collect()
}

/// A table is read into a buffer a quarter larger than its size, and only
/// the bytes the kernel wrote are kept.
#[test]
fn a_table_is_read_with_a_quarter_more_room_and_kept_as_written() {
    let (table, asked) = scripted(vec![Size(Ok(100)), Table(Ok(bytes(90)))]);
    assert_eq!(table, Ok(bytes(90)));
    assert_eq!(asked, [None, Some(125)]);
}

/// An empty table is no bytes, and is not read.
#[test]
fn an_empty_table_is_no_bytes() {
    let (table, asked) = scripted(vec![Size(Ok(0))]);
    assert_eq!(table, Ok(Vec::new()));
    assert_eq!(asked, [None]);
}

/// A table that grew past its room since it was sized is sized and read
/// again, and the second read is kept.
#[test]
fn a_table_that_grew_is_sized_again() {
    let (table, asked) = scripted(vec![
        Size(Ok(100)),
        Table(Err(libc::ENOMEM)),
        Size(Ok(200)),
        Table(Ok(bytes(180))),
    ]);
    assert_eq!(table, Ok(bytes(180)));
    assert_eq!(asked, [None, Some(125), None, Some(250)]);
}

/// A table that grows past its room at every read is `TableChanged` after
/// the first read and three retries.
#[test]
fn a_table_that_keeps_growing_is_table_changed_after_three_retries() {
    let answers = (0..4)
        .flat_map(|_| [Size(Ok(100)), Table(Err(libc::ENOMEM))])
        .collect();
    let (table, asked) = scripted(answers);
    assert_eq!(table, Err(MacsysError::TableChanged));
    assert_eq!(asked, [None, Some(125)].repeat(4));
}

/// A table larger than 16 MiB is refused unread, also when it grew past
/// that between two reads; one of exactly 16 MiB is read into exactly 16
/// MiB, the room's bound.
#[test]
fn a_table_past_16_mib_is_refused_and_the_room_is_bounded() {
    assert_eq!(MAX_TABLE_BYTES, 16 * 1024 * 1024);
    let (table, asked) = scripted(vec![Size(Ok(MAX_TABLE_BYTES + 1))]);
    assert_eq!(table, Err(MacsysError::TableTooLarge));
    assert_eq!(asked, [None]);
    let (table, asked) = scripted(vec![
        Size(Ok(100)),
        Table(Err(libc::ENOMEM)),
        Size(Ok(MAX_TABLE_BYTES + 1)),
    ]);
    assert_eq!(table, Err(MacsysError::TableTooLarge));
    assert_eq!(asked, [None, Some(125), None]);
    let (table, asked) = scripted(vec![Size(Ok(MAX_TABLE_BYTES)), Table(Ok(bytes(3)))]);
    assert_eq!(table, Ok(bytes(3)));
    assert_eq!(asked, [None, Some(MAX_TABLE_BYTES)]);
}

/// A call that fails for any reason but growth is `Sysctl` with its
/// `errno`, and is not retried.
#[test]
fn a_failed_call_is_its_errno() {
    let (table, asked) = scripted(vec![Size(Err(libc::EPERM))]);
    assert_eq!(table, Err(MacsysError::Sysctl { errno: libc::EPERM }));
    assert_eq!(asked, [None]);
    let (table, asked) = scripted(vec![Size(Ok(10)), Table(Err(libc::EINVAL))]);
    assert_eq!(
        table,
        Err(MacsysError::Sysctl {
            errno: libc::EINVAL
        })
    );
    assert_eq!(asked, [None, Some(12)]);
}

/// The live kernel gives the size of a value it knows, and refuses a
/// routing-table operation it does not know with `EINVAL`.
#[test]
fn the_kernel_sizes_a_known_name_and_refuses_an_unknown_one() {
    assert_eq!(
        read([libc::CTL_KERN, libc::KERN_BOOTTIME], None),
        Ok(size_of::<libc::timeval>())
    );
    let unknown = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_INET, 99, 0];
    assert_eq!(
        dump(unknown),
        Err(MacsysError::Sysctl {
            errno: libc::EINVAL
        })
    );
}
