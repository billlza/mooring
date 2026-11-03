// SPDX-License-Identifier: GPL-3.0-or-later

//! The blob store: a blob is stored only once it hashes to its name, and
//! reported present only while it still does.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{self, Cursor, Read};

use mooring_agent_proto::{AgentError, BlobLen, IoOp, Sha256Hex};

use super::{EACCES, EEXIST, EISDIR, ENOTDIR, ModeFault, scratch};
use crate::blobs::{digest_of, present, put};
use crate::paths::Paths;

fn sha(bytes: &[u8]) -> Sha256Hex {
    digest_of(bytes).unwrap()
}

fn files_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn the_digest_is_sha_256() {
    assert_eq!(
        sha(b"abc").to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_blob_that_hashes_to_its_name_is_stored_and_present() {
    let (_dir, paths) = scratch();
    let payload = b"agent bytes";
    put(
        &paths,
        sha(payload),
        BlobLen::new(11).unwrap(),
        &mut Cursor::new(payload.to_vec()),
    )
    .unwrap();
    assert_eq!(fs::read(paths.blob(&sha(payload))).unwrap(), payload);
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(paths.blob(&sha(payload)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a blob may hold the bundle's secrets");
    }
    assert_eq!(files_in(&paths.blobs()), vec![sha(payload).to_string()]);
    let wanted: BTreeSet<Sha256Hex> = [sha(payload), sha(b"other")].into();
    assert_eq!(present(&paths, &wanted).unwrap(), [sha(payload)].into());
}

#[test]
fn a_payload_with_another_digest_leaves_nothing() {
    let (_dir, paths) = scratch();
    let error = put(
        &paths,
        sha(b"expected"),
        BlobLen::new(5).unwrap(),
        &mut Cursor::new(b"wrong".to_vec()),
    )
    .unwrap_err();
    assert_eq!(
        error,
        AgentError::BlobHash {
            expected: sha(b"expected"),
            actual: sha(b"wrong"),
        }
    );
    assert!(files_in(&paths.blobs()).is_empty());
}

#[test]
fn a_short_or_long_payload_is_refused_and_leaves_nothing() {
    let (_dir, paths) = scratch();
    let error = put(
        &paths,
        sha(b"twelve bytes"),
        BlobLen::new(12).unwrap(),
        &mut Cursor::new(b"twelve".to_vec()),
    )
    .unwrap_err();
    assert_eq!(
        error,
        AgentError::BlobTruncated {
            expected: 12,
            received: 6
        }
    );
    let error = put(
        &paths,
        sha(b"four"),
        BlobLen::new(4).unwrap(),
        &mut Cursor::new(b"four and more".to_vec()),
    )
    .unwrap_err();
    assert_eq!(error, AgentError::TrailingInput);
    assert!(files_in(&paths.blobs()).is_empty());
}

#[test]
fn a_damaged_blob_is_not_present_and_is_removed_for_reupload() {
    let (_dir, paths) = scratch();
    let payload = b"engine";
    put(
        &paths,
        sha(payload),
        BlobLen::new(6).unwrap(),
        &mut Cursor::new(payload.to_vec()),
    )
    .unwrap();
    fs::write(paths.blob(&sha(payload)), b"engin3").unwrap();
    assert!(present(&paths, &[sha(payload)].into()).unwrap().is_empty());
    assert!(!paths.blob(&sha(payload)).exists());
    put(
        &paths,
        sha(payload),
        BlobLen::new(6).unwrap(),
        &mut Cursor::new(payload.to_vec()),
    )
    .unwrap();
    assert_eq!(
        present(&paths, &[sha(payload)].into()).unwrap(),
        [sha(payload)].into()
    );
}

/// A reader that answers each read with the next of its answers, then
/// ends.
struct Scripted(VecDeque<io::Result<&'static [u8]>>);

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(Ok(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            Some(Err(error)) => Err(error),
        }
    }
}

#[test]
fn an_interrupted_read_is_retried_and_any_other_failure_reported() {
    let interrupted = || Err(io::Error::from(io::ErrorKind::Interrupted));
    let reads = [interrupted(), Ok(&b"ab"[..]), interrupted(), Ok(&b"c"[..])];
    assert_eq!(digest_of(Scripted(reads.into())).unwrap(), sha(b"abc"));
    let failing = [Ok(&b"ab"[..]), Err(io::Error::other("the disk failed"))];
    assert_eq!(
        digest_of(Scripted(failing.into())).unwrap_err().to_string(),
        "the disk failed"
    );
}

/// `payload` stored as a blob.
fn stored(paths: &Paths, payload: &'static [u8]) -> Sha256Hex {
    put(
        paths,
        sha(payload),
        BlobLen::new(u64::try_from(payload.len()).unwrap()).unwrap(),
        &mut Cursor::new(payload.to_vec()),
    )
    .unwrap();
    sha(payload)
}

#[test]
fn a_store_that_cannot_be_read_is_an_error_never_absent_blobs() {
    let (_dir, paths) = scratch();
    let blob = sha(b"engine");
    // A directory where the blob belongs.
    fs::create_dir_all(paths.blob(&blob)).unwrap();
    assert_eq!(
        present(&paths, &[blob].into()),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(EISDIR)
        })
    );
    // A file where the store belongs.
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.var_lib()).unwrap();
    fs::write(paths.blobs(), "not a directory").unwrap();
    assert_eq!(
        present(&paths, &[blob].into()),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(ENOTDIR)
        })
    );
}

#[test]
fn a_damaged_blob_that_cannot_be_removed_is_a_write_failure() {
    let (_dir, paths) = scratch();
    let blob = stored(&paths, b"engine");
    fs::write(paths.blob(&blob), b"engin3").unwrap();
    {
        let _kept = ModeFault::set(&paths.blobs(), 0o500);
        assert_eq!(
            present(&paths, &[blob].into()),
            Err(AgentError::Io {
                op: IoOp::WriteBlob,
                errno: Some(EACCES)
            })
        );
    }
    assert_eq!(fs::read(paths.blob(&blob)).unwrap(), b"engin3");
}

#[test]
fn a_blob_the_store_cannot_take_is_a_write_failure_and_leaves_no_partial() {
    let payload = b"engine";
    let upload = |paths: &Paths| {
        put(
            paths,
            sha(payload),
            BlobLen::new(6).unwrap(),
            &mut Cursor::new(payload.to_vec()),
        )
    };
    let failed = |errno| {
        Err(AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(errno),
        })
    };
    // A file where the store belongs.
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.var_lib()).unwrap();
    fs::write(paths.blobs(), "not a directory").unwrap();
    assert_eq!(upload(&paths), failed(EEXIST));
    // The upload's temporary name is taken.
    let (_dir, paths) = scratch();
    let partial = paths
        .blobs()
        .join(format!(".{}.{}.partial", sha(payload), std::process::id()));
    fs::create_dir_all(&partial).unwrap();
    assert_eq!(upload(&paths), failed(EEXIST));
    assert!(!paths.blob(&sha(payload)).exists());
    // A directory where the blob belongs: the rename fails.
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.blob(&sha(payload))).unwrap();
    assert_eq!(upload(&paths), failed(EISDIR));
    assert_eq!(
        files_in(&paths.blobs()),
        vec![sha(payload).to_string()],
        "the partial file removed"
    );
    assert!(paths.blob(&sha(payload)).is_dir());
}
