// SPDX-License-Identifier: GPL-3.0-or-later

//! `viewer_authorized_keys` (design §15.9, decision F5): one line per
//! viewer with the viewer role's forced command, nothing else, and empty
//! without a viewer.

use mooring_agent_proto::{ManagedFile, Role};
use mooring_model::{CalendarDate, Ed25519Pub, LocalLabel, Viewer};

use crate::tests::support::{edit, mac_exit, mac_prober, node, vps};

/// A viewer with key bytes `byte` and a label that must never be rendered.
fn viewer(byte: u8, label: &str) -> Viewer {
    Viewer {
        key: Ed25519Pub::from_bytes([byte; 32]).unwrap(),
        label: LocalLabel::parse(label).unwrap(),
        added_on: CalendarDate::parse("2026-10-08").unwrap(),
    }
}

/// The keys in a rendered file, each line checked to be exactly the viewer
/// role's options, a space and an `ssh-ed25519` key with no comment.
fn keys_of(bytes: &[u8]) -> Vec<Ed25519Pub> {
    let text = std::str::from_utf8(bytes).unwrap();
    let prefix = format!("{} ", Role::Viewer.authorized_keys_options());
    text.split_terminator('\n')
        .map(|line| {
            let key = line
                .strip_prefix(&prefix)
                .expect("the viewer role's options");
            Ed25519Pub::parse_ssh_authorized_key(key).unwrap()
        })
        .collect()
}

/// Every line of every node's file parses back to the recorded viewer
/// keys, in key order; the Mac-only labels are never written; every node
/// carries the same file.
#[test]
fn every_line_is_the_viewer_role_and_a_recorded_key() {
    let mut fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    fixture.deployment = edit(&fixture.deployment, |parts| {
        parts.viewers.push(viewer(0x01, "Spare phone"));
    });
    let recorded: Vec<Ed25519Pub> = fixture.deployment.viewers().keys().copied().collect();
    assert_eq!(recorded.len(), 2);
    let mut files = Vec::new();
    for id in fixture.deployment.nodes().keys() {
        let bundle = vps(&fixture, id);
        let bytes = bundle.file(ManagedFile::ViewerKeys).expose_bytes().to_vec();
        assert_eq!(keys_of(&bytes), recorded);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        for viewer in fixture.deployment.viewers().values() {
            assert!(!text.contains(viewer.label.as_str()), "{}", viewer.label);
        }
        files.push(bytes);
    }
    assert_eq!(files.len(), 2);
    assert_eq!(files[0], files[1]);
}

/// The file is exactly the expected bytes: the viewer role's options, never
/// another role's, then the key.
#[test]
fn the_options_are_the_viewer_roles() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let only = fixture.deployment.viewers().values().next().unwrap();
    let bundle = vps(&fixture, &node("lon1"));
    let expected = format!(
        "{} {}\n",
        Role::Viewer.authorized_keys_options(),
        only.key.ssh_authorized_key()
    );
    assert_eq!(
        bundle.file(ManagedFile::ViewerKeys).expose_bytes(),
        expected.as_bytes()
    );
    assert!(expected.starts_with(
        "restrict,command=\"/usr/local/lib/mooring/agent/current serve-ssh --role viewer\" ssh-ed25519 "
    ));
    for other in [Role::Bootstrap, Role::Ops] {
        assert!(
            !expected.contains(other.authorized_keys_options()),
            "{other:?}"
        );
    }
}

/// Without a viewer the file is empty, on every node of every fixture
/// that has none.
#[test]
fn with_no_viewer_the_file_is_empty() {
    for fixture in mooring_fixtures::all().unwrap() {
        for id in fixture.deployment.nodes().keys() {
            let bytes = vps(&fixture, id)
                .file(ManagedFile::ViewerKeys)
                .expose_bytes()
                .to_vec();
            assert_eq!(
                bytes.is_empty(),
                fixture.deployment.viewers().is_empty(),
                "{} {id}",
                fixture.name
            );
        }
    }
}

/// Adding a viewer changes every node's bundle digest through
/// `viewer_authorized_keys` alone, and neither Mac engine config.
#[test]
fn adding_a_viewer_changes_only_the_viewer_keys() {
    let mut fixture = mooring_fixtures::one_node_three_users().unwrap();
    assert!(fixture.deployment.viewers().is_empty());
    let exit = mac_exit(&fixture).digest();
    let prober = mac_prober(&fixture).digest();
    let before = vps(&fixture, &node("lon1"));
    fixture.deployment = edit(&fixture.deployment, |parts| {
        parts.viewers.push(viewer(0x5a, "phone"));
    });
    let after = vps(&fixture, &node("lon1"));
    assert_ne!(after.digest(), before.digest());
    for file in ManagedFile::ALL {
        assert_eq!(
            after.file(*file) != before.file(*file),
            *file == ManagedFile::ViewerKeys,
            "{file:?}"
        );
    }
    assert_eq!(
        keys_of(after.file(ManagedFile::ViewerKeys).expose_bytes()),
        [Ed25519Pub::from_bytes([0x5a; 32]).unwrap()]
    );
    assert_eq!(mac_exit(&fixture).digest(), exit);
    assert_eq!(mac_prober(&fixture).digest(), prober);
}
