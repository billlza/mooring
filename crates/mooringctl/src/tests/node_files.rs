// SPDX-License-Identifier: GPL-3.0-or-later

//! A node's files in the support directory (design §10.5, §12) when the
//! disk does not cooperate: a key directory that cannot be made, a public
//! key file that cannot be read or holds no key, a key half written, a
//! leftover temporary file, and a bootstrap key that is gone already or
//! cannot be removed.

use std::fs;
use std::io;
use std::net::Ipv4Addr;

use mooring_keys::SshKeyPair;
use mooring_model::{Ed25519Pub, NodeId};

use crate::error::LocalError;
use crate::node::files::{NodeFiles, read_public_key};

fn files() -> (tempfile::TempDir, NodeFiles) {
    let support = tempfile::tempdir().unwrap();
    let files = NodeFiles::of(support.path(), &NodeId::parse("lon1").unwrap());
    (support, files)
}

fn host_key() -> Ed25519Pub {
    let (_, public) = SshKeyPair::generate().unwrap().into_parts();
    Ed25519Pub::parse_ssh_authorized_key(&public.authorized_key()).unwrap()
}

/// A file where the key directory goes stops every node command that needs
/// it, naming the directory.
#[test]
fn a_key_directory_that_cannot_be_made_is_an_error() {
    let (support, files) = files();
    fs::write(support.path().join("ssh"), b"").unwrap();
    let error = files.create_dir().unwrap_err();
    assert!(
        matches!(&error, LocalError::NodeFile { path, .. } if path == files.dir()),
        "{error:?}"
    );
}

/// A public key file that cannot be read, is longer than a line, or does
/// not hold an Ed25519 key as OpenSSH writes one is refused, naming it.
#[test]
fn a_public_key_file_that_holds_no_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pub");
    let error = read_public_key(&missing).unwrap_err();
    assert!(
        matches!(&error, LocalError::HostKeyFile { path, source } if *path == missing && source.kind() == io::ErrorKind::NotFound),
        "{error:?}"
    );
    let key = host_key().ssh_authorized_key();
    for (name, text) in [
        ("long.pub", format!("{key} {}\n", "c".repeat(4096))),
        ("one-word.pub", "ssh-ed25519\n".to_owned()),
        (
            "not-a-key.pub",
            "ssh-ed25519 AAAAnotakey root@lon1\n".to_owned(),
        ),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, text).unwrap();
        let error = read_public_key(&path).unwrap_err();
        assert!(
            matches!(&error, LocalError::HostKey { path: named } if *named == path),
            "{name}: {error:?}"
        );
    }
    let good = dir.path().join("good.pub");
    fs::write(&good, format!("{key} root@lon1\n")).unwrap();
    assert_eq!(read_public_key(&good).unwrap().ssh_authorized_key(), key);
}

/// An operations key whose public half is there already, without the key,
/// was half written: the new key is not written over it.
#[test]
fn a_half_written_operations_key_is_not_written_over() {
    let (_support, files) = files();
    files.create_dir().unwrap();
    let public = files.dir().join("ops_ed25519.pub");
    fs::write(&public, b"left by an earlier run\n").unwrap();
    let error = files
        .ops_public(&NodeId::parse("lon1").unwrap())
        .unwrap_err();
    assert!(
        matches!(&error, LocalError::NodeFile { path, source } if *path == public && source.kind() == io::ErrorKind::AlreadyExists),
        "{error:?}"
    );
    assert_eq!(fs::read(&public).unwrap(), b"left by an earlier run\n");
}

/// A temporary file an interrupted pin left is replaced; one that cannot
/// be removed stops the pin, which leaves `known_hosts` as it was.
#[test]
fn a_leftover_temporary_file_is_replaced_unless_it_cannot_be_removed() {
    let (_support, files) = files();
    files.create_dir().unwrap();
    let address = Ipv4Addr::new(45, 67, 89, 10);
    let partial = files.dir().join("known_hosts.partial");
    fs::write(&partial, b"interrupted").unwrap();
    files.pin_host_key(address, host_key()).unwrap();
    assert!(!partial.exists());
    let pinned = fs::read(files.known_hosts()).unwrap();
    fs::create_dir(&partial).unwrap();
    let error = files.pin_host_key(address, host_key()).unwrap_err();
    assert!(
        matches!(&error, LocalError::NodeFile { path, .. } if *path == partial),
        "{error:?}"
    );
    assert_eq!(fs::read(files.known_hosts()).unwrap(), pinned);
}

/// A bootstrap key that is gone already is fine to remove; one that
/// cannot be removed is an error.
#[test]
fn a_bootstrap_key_gone_already_is_fine_and_one_that_stays_is_an_error() {
    let (_support, files) = files();
    files.create_dir().unwrap();
    files.remove_bootstrap_key().unwrap();
    fs::create_dir(files.bootstrap_key()).unwrap();
    let error = files.remove_bootstrap_key().unwrap_err();
    assert!(
        matches!(&error, LocalError::NodeFile { path, .. } if *path == files.bootstrap_key()),
        "{error:?}"
    );
}

/// A public key file holds one line of at most 4096 bytes, blank lines
/// aside, in a regular file; bytes that are not UTF-8 hold no key.
#[test]
fn a_public_key_file_is_one_line_of_at_most_4096_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let key = host_key().ssh_authorized_key();
    let padded = |total: usize| {
        let line = format!("{key} ");
        format!("{line}{}\n", "c".repeat(total - line.len() - 1))
    };
    for (name, text, holds) in [
        (
            "blank-lines.pub",
            format!("\n  \n{key} root@lon1\n\n"),
            true,
        ),
        ("at-the-limit.pub", padded(4096), true),
        ("past-the-limit.pub", padded(4097), false),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, &text).unwrap();
        let read = read_public_key(&path);
        if holds {
            assert_eq!(read.unwrap().ssh_authorized_key(), key, "{name}");
        } else {
            assert!(
                matches!(&read, Err(LocalError::HostKey { path: named }) if *named == path),
                "{name}: {read:?}"
            );
        }
    }
    let path = dir.path().join("not-utf8.pub");
    let mut bytes = format!("{key} ").into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
    fs::write(&path, bytes).unwrap();
    let read = read_public_key(&path);
    assert!(
        matches!(&read, Err(LocalError::HostKey { path: named }) if *named == path),
        "{read:?}"
    );
}

/// A node's directory is listed with Mooring's own files, every one, and
/// removed with them, leaving `ssh/`; with no directory there is nothing.
#[test]
fn a_node_directory_is_listed_with_moorings_own_files_and_removed_with_them() {
    let (support, files) = files();
    assert!(files.inspect().unwrap().is_none());
    files.create_dir().unwrap();
    for name in [
        "ops_ed25519",
        "ops_ed25519.pub",
        "known_hosts",
        "known_hosts.partial",
        "bootstrap_ed25519",
        "bootstrap_ed25519.partial",
    ] {
        fs::write(files.dir().join(name), b"").unwrap();
    }
    let listing = files.inspect().unwrap().unwrap();
    assert_eq!(listing.dir(), files.dir());
    listing.remove().unwrap();
    assert!(!files.dir().exists());
    assert!(support.path().join("ssh").is_dir());
}

/// The removal follows no link put where the directory was, keeps an
/// entry added since and with it the directory, and takes an entry or a
/// directory removed already as gone.
#[test]
fn a_removal_follows_no_link_and_keeps_what_was_added_since() {
    let (support, files) = files();
    files.create_dir().unwrap();
    fs::write(files.known_hosts(), b"pinned\n").unwrap();
    let listing = files.inspect().unwrap().unwrap();
    let moved = support.path().join("moved");
    fs::rename(files.dir(), &moved).unwrap();
    std::os::unix::fs::symlink(&moved, files.dir()).unwrap();
    let error = listing.remove().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotADirectory);
    assert_eq!(fs::read(moved.join("known_hosts")).unwrap(), b"pinned\n");
    fs::remove_file(files.dir()).unwrap();
    fs::rename(&moved, files.dir()).unwrap();

    let listing = files.inspect().unwrap().unwrap();
    let added = files.dir().join("ops_ed25519");
    fs::write(&added, b"").unwrap();
    let error = listing.remove().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
    assert!(!files.known_hosts().exists());
    assert!(added.exists());

    let listing = files.inspect().unwrap().unwrap();
    fs::remove_file(&added).unwrap();
    listing.remove().unwrap();
    assert!(!files.dir().exists());

    files.create_dir().unwrap();
    let listing = files.inspect().unwrap().unwrap();
    fs::remove_dir(files.dir()).unwrap();
    listing.remove().unwrap();
}
