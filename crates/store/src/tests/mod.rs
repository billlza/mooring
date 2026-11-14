// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the store: CAS, locking, durability, decoding, migrations,
//! secret stores, the secret ordering rules, the router identity file, the
//! radio history's day files, and the refusal of anything but a regular
//! file where a store file belongs (design §7, §15.6, §16 L1).

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::store::Store;

mod abuse_records;
mod allowed_networks;
mod builders;
mod cas;
mod concurrency;
mod decode;
mod durability;
mod latch;
mod migration;
mod ordering;
mod payments;
mod pending_applies;
mod properties;
mod radio_history;
mod regular_files;
mod router_pin;
mod secrets;
mod sim_meter;
mod sim_network;
mod status_snapshot;
mod taxonomy;
mod user_usage;

/// How long a test lets an open run before it calls the open blocked: far
/// longer than an open that does not wait takes, under any load.
const BLOCKED_AFTER: Duration = Duration::from_secs(10);

/// The raw bytes of `state.json`.
fn state_bytes(store: &Store) -> Vec<u8> {
    fs::read(store.state_path()).unwrap()
}

/// The permission bits of `path`.
fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// `error` is the failure of `op` on `path` with the operating system's
/// error of kind `cause`: it names the operation and the path, and keeps
/// the system's error as its source.
fn assert_io_error(
    error: &crate::error::StoreError,
    op: crate::error::IoOp,
    path: &Path,
    cause: std::io::ErrorKind,
) {
    assert!(
        matches!(error, crate::error::StoreError::Io { op: found, path: at, source }
            if *found == op && at == path && source.kind() == cause),
        "{error:?}"
    );
    assert_eq!(error.kind(), crate::error::StoreErrorKind::Io);
    assert_eq!(
        error.to_string(),
        format!("failed to {op} at {}", path.display())
    );
}

/// `error` refuses `path`, where one of the store's private directories
/// belongs, as not a directory: it names the path, and its kind and message
/// say so.
fn assert_dir_not_directory(error: &crate::error::StoreError, path: &Path) {
    assert!(
        matches!(error, crate::error::StoreError::DirNotDirectory { path: found }
            if found == path),
        "{error:?}"
    );
    assert_eq!(error.kind(), crate::error::StoreErrorKind::DirNotDirectory);
    assert_eq!(
        error.to_string(),
        format!("{} is not a directory", path.display())
    );
}

/// `error` refuses `path`, where one of the store's files belongs, as not
/// a regular file: it names the path, and its kind and message say so.
fn assert_not_regular(error: &crate::error::StoreError, path: &Path) {
    assert!(
        matches!(error, crate::error::StoreError::NotRegularFile { path: found }
            if found == path),
        "{error:?}"
    );
    assert_eq!(error.kind(), crate::error::StoreErrorKind::NotRegularFile);
    assert_eq!(
        error.to_string(),
        format!("{} is not a regular file", path.display())
    );
}

/// Makes a FIFO at `path`.
fn make_fifo(path: &Path) {
    let made = Command::new("/usr/bin/mkfifo").arg(path).status().unwrap();
    assert!(made.success(), "{made}");
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
}

/// Makes a socket at `path`: bound beside it under a short name, as a
/// socket's path is short (104 bytes on macOS), then renamed into place.
fn make_socket(path: &Path) {
    let bound = path.with_file_name(".socket");
    drop(UnixListener::bind(&bound).unwrap());
    fs::rename(&bound, path).unwrap();
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_socket());
}

/// What `open` returns, run on a thread of its own, so that an open that
/// waits on the FIFO at `fifo` for a writer fails the test rather than
/// hang it: past [`BLOCKED_AFTER`] the FIFO is opened for writing and
/// closed, which lets a reader waiting in its open go on and its thread
/// end, and the test fails.
fn without_blocking<T: Send + 'static>(
    fifo: &Path,
    open: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // The test has failed already if no one receives this.
        let _ = sender.send(open());
    });
    match receiver.recv_timeout(BLOCKED_AFTER) {
        Ok(opened) => opened,
        Err(timeout) => {
            let released = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo);
            panic!(
                "{timeout}: the open waited on the FIFO {} for a writer (released: {})",
                fifo.display(),
                released.is_ok()
            );
        }
    }
}

/// The store error inside `error`; fails the test on a refused change.
fn store_error<E: std::fmt::Debug>(
    error: crate::error::ChangeError<E>,
) -> crate::error::StoreError {
    match error {
        crate::error::ChangeError::Store(error) => error,
        crate::error::ChangeError::Refused(refusal) => {
            panic!("expected a store error, got the refusal {refusal:?}")
        }
    }
}
