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
