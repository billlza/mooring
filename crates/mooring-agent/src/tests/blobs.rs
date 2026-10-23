// SPDX-License-Identifier: GPL-3.0-or-later

//! The blob store: a blob is stored only once it hashes to its name, and
//! reported present only while it still does.

use std::collections::BTreeSet;
use std::io::Cursor;

use mooring_agent_proto::{AgentError, BlobLen, Sha256Hex};

use super::scratch;
use crate::blobs::{digest_of, present, put};

fn sha(bytes: &[u8]) -> Sha256Hex {
    digest_of(bytes).unwrap()
}

fn files_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
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
    assert_eq!(std::fs::read(paths.blob(&sha(payload))).unwrap(), payload);
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(paths.blob(&sha(payload)))
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
    std::fs::write(paths.blob(&sha(payload)), b"engin3").unwrap();
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
