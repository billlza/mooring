// SPDX-License-Identifier: GPL-3.0-or-later

//! Only a regular file is a store file (design §7): every read of one
//! refuses a link where the file belongs, whether it leads to a good file,
//! which is then never read, or to nothing, which is never read as no file,
//! and a directory, a FIFO (without waiting on it), a socket or a device,
//! as `NotRegularFile` naming the path; so does every open of `state.lock`,
//! which never makes the lock through a link either.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::{Path, PathBuf};

use mooring_model::CalendarDate;

use super::allowed_networks::{home, label};
use super::builders::deployment_init;
use super::latch::latch;
use super::router_pin::pin;
use super::{assert_not_regular, make_fifo, make_socket, without_blocking};
use crate::allowed_networks::{
    ALLOWED_NETWORKS_FILE, Declaration, declare_allowed_network, read_allowed_networks,
    revoke_allowed_network,
};
use crate::durable::{existing_regular_file, regular_file};
use crate::error::{IoOp, StoreError};
use crate::latch::{LATCH_FILE, read_latch, write_latch};
use crate::radio_history::{append_radio_line, radio_day_path, read_radio_day};
use crate::router_pin::{ROUTER_PIN_FILE, read_router_pin, write_router_pin};
use crate::sim_meter::{SIM_METER_FILE, USAGE_DIRECTORY, read_sim_meter, write_sim_meter};
use crate::store::{LOCK_FILE, STATE_FILE, Store};

/// One of the store's reads of a file in a directory.
#[derive(Clone, Copy)]
struct Read {
    /// The file it reads in a directory.
    path: fn(&Path) -> PathBuf,
    /// Writes a good file there with the store's own writer, making the
    /// directories that hold it.
    write: fn(&Path),
    /// The read, giving what it found as text.
    read: fn(&Path) -> Result<String, StoreError>,
}

fn day() -> CalendarDate {
    CalendarDate::parse("2026-10-24").unwrap()
}

/// Every read of a store file: the exit's latch, the router identity, the
/// own-network declarations, the state, the SIM meter and a radio history
/// day file.
const READS: [Read; 6] = [
    Read {
        path: |dir| dir.join(LATCH_FILE),
        write: |dir| write_latch(dir, &latch()).unwrap(),
        read: |dir| read_latch(dir).map(|found| format!("{found:?}")),
    },
    Read {
        path: |dir| dir.join(ROUTER_PIN_FILE),
        write: |dir| write_router_pin(dir, &pin()).unwrap(),
        read: |dir| read_router_pin(dir).map(|found| format!("{found:?}")),
    },
    Read {
        path: |dir| dir.join(ALLOWED_NETWORKS_FILE),
        write: |dir| {
            let declared = declare_allowed_network(dir, label("home"), home()).unwrap();
            assert_eq!(declared, Declaration::Recorded);
        },
        read: |dir| read_allowed_networks(dir).map(|found| format!("{found:?}")),
    },
    Read {
        path: |dir| dir.join(STATE_FILE),
        write: |dir| drop(Store::new(dir).init(deployment_init()).unwrap()),
        read: |dir| Store::new(dir).load().map(|found| format!("{found:?}")),
    },
    Read {
        path: |dir| dir.join(USAGE_DIRECTORY).join(SIM_METER_FILE),
        write: |dir| write_sim_meter(dir, b"{\"version\": 1}\n").unwrap(),
        read: |dir| read_sim_meter(dir, 64).map(|found| format!("{found:?}")),
    },
    Read {
        path: |dir| radio_day_path(dir, day()),
        write: |dir| append_radio_line(dir, day(), b"a\n").unwrap(),
        read: |dir| read_radio_day(dir, day()).map(|found| format!("{found:?}")),
    },
];

/// The file `read` reads in `dir`, written and removed again, so that what
/// holds it is there and nothing is at its path.
fn emptied(read: Read, dir: &Path) -> PathBuf {
    (read.write)(dir);
    let path = (read.path)(dir);
    fs::remove_file(&path).unwrap();
    path
}

/// `read` refuses `path`, in `dir`, as not a regular file, and gives
/// nothing it read.
fn assert_refused(read: Read, dir: &Path, path: &Path) {
    match (read.read)(dir) {
        Err(error) => assert_not_regular(&error, path),
        Ok(found) => panic!("{} was read: {found}", path.display()),
    }
}

/// A link to a good file elsewhere is refused, and the file it leads to,
/// which the same read gives where it is, is never read through it.
#[test]
fn a_link_to_a_good_file_is_refused() {
    for read in READS {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let path = emptied(read, dir.path());
        (read.write)(elsewhere.path());
        let target = (read.path)(elsewhere.path());
        let good = fs::read(&target).unwrap();
        assert!((read.read)(elsewhere.path()).is_ok());
        symlink(&target, &path).unwrap();
        assert_refused(read, dir.path(), &path);
        assert_eq!(fs::read(&target).unwrap(), good);
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    }
}

/// A link to nothing is refused, never read as no file, and nothing is
/// made where it leads.
#[test]
fn a_dangling_link_is_refused_never_read_as_no_file() {
    for read in READS {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let path = emptied(read, dir.path());
        let target = elsewhere.path().join("nowhere");
        symlink(&target, &path).unwrap();
        assert_refused(read, dir.path(), &path);
        assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none());
    }
}

/// A FIFO is refused, and no read waits on it for a writer.
#[test]
fn a_fifo_is_refused_without_waiting_on_it() {
    for read in READS {
        let dir = tempfile::tempdir().unwrap();
        let path = emptied(read, dir.path());
        make_fifo(&path);
        let (at, reading) = (dir.path().to_path_buf(), read.read);
        let error = without_blocking(&path, move || reading(&at)).unwrap_err();
        assert_not_regular(&error, &path);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
    }
}

/// A directory or a socket is refused too, whether the open fails on it
/// (a socket) or succeeds and the check refuses it (a directory, opened
/// for reading).
#[test]
fn a_directory_or_a_socket_is_refused() {
    let make_dir: fn(&Path) = |path| fs::create_dir(path).unwrap();
    for read in READS {
        for make in [make_dir, make_socket] {
            let dir = tempfile::tempdir().unwrap();
            let path = emptied(read, dir.path());
            make(&path);
            assert_refused(read, dir.path(), &path);
        }
    }
}

/// A device is refused too: its open succeeds, and the check on the open
/// descriptor refuses it, for a read as for the lock's open, which creates
/// nothing where the device is. (No test can make a device where a store
/// file belongs, so the open is given `/dev/null` itself.)
#[test]
fn a_device_is_refused_by_the_check_on_its_descriptor() {
    let null = Path::new("/dev/null");
    let read = existing_regular_file(null, OpenOptions::new().read(true), IoOp::ReadState);
    assert_not_regular(&read.unwrap_err(), null);
    let lock = regular_file(
        null,
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        IoOp::OpenLock,
    );
    assert_not_regular(&lock.unwrap_err(), null);
    assert!(fs::metadata(null).unwrap().file_type().is_char_device());
}

/// An operation on the store in a directory, whatever it gives.
type Operation = fn(&Path) -> Result<(), StoreError>;

/// The operations that open `state.lock` in a directory, and make it when
/// it is missing: the state's reads and writes, and the writes of the
/// router identity and the declarations.
const LOCKING: [Operation; 5] = [
    |dir| Store::new(dir).load().map(drop),
    |dir| Store::new(dir).init(deployment_init()).map(drop),
    |dir| write_router_pin(dir, &pin()),
    |dir| declare_allowed_network(dir, label("home"), home()).map(drop),
    |dir| revoke_allowed_network(dir, &label("home")).map(drop),
];

/// Every open of `state.lock` refuses a link there, to a file or to
/// nothing, a directory, a FIFO (without waiting on it) and a socket: the
/// lock is never taken on a file elsewhere nor made where a link leads, and
/// the operation reads and writes nothing.
#[test]
fn the_lock_is_never_opened_or_made_through_anything_but_a_regular_file() {
    let link_to_a_file: fn(&Path, &Path) = |lock, elsewhere| {
        let target = elsewhere.join("lock");
        fs::write(&target, b"").unwrap();
        symlink(target, lock).unwrap();
    };
    let link_to_nothing: fn(&Path, &Path) = |lock, elsewhere| {
        symlink(elsewhere.join("nowhere"), lock).unwrap();
    };
    let directory: fn(&Path, &Path) = |lock, _| fs::create_dir(lock).unwrap();
    let fifo: fn(&Path, &Path) = |lock, _| make_fifo(lock);
    let socket: fn(&Path, &Path) = |lock, _| make_socket(lock);
    for operation in LOCKING {
        for place in [link_to_a_file, link_to_nothing, directory, fifo, socket] {
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = tempfile::tempdir().unwrap();
            let lock = dir.path().join(LOCK_FILE);
            place(&lock, elsewhere.path());
            let before: Vec<_> = fs::read_dir(elsewhere.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            let at = dir.path().to_path_buf();
            let error = without_blocking(&lock, move || operation(&at)).unwrap_err();
            assert_not_regular(&error, &lock);
            let names: Vec<_> = fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(names, [LOCK_FILE], "{error:?}");
            let after: Vec<_> = fs::read_dir(elsewhere.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(after, before, "{error:?}");
        }
    }
}
