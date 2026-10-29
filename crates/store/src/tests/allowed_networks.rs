// SPDX-License-Identifier: GPL-3.0-or-later

//! The own-network declarations file (design §10.2, P0-2): its exact
//! format and mode, declaring and withdrawing under the lock, an absent file
//! read as no declaration, and the typed refusal of anything that is not a
//! version-1 declaration document.

use std::fs;
use std::net::Ipv4Addr;

use mooring_model::ids::LocalLabel;
use mooring_model::iface::{MacAddr, RouterIdentity};
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind, OwnNetworks};
use mooring_model::time::UnixTime;

use super::mode_of;
use crate::allowed_networks::{
    ALLOWED_NETWORKS_FILE, AllowedNetworksFault, Declaration, MAX_ALLOWED_NETWORKS_BYTES,
    declare_allowed_network, read_allowed_networks, revoke_allowed_network,
};
use crate::error::{IoOp, StoreError, StoreErrorKind};

fn label(text: &str) -> LocalLabel {
    LocalLabel::parse(text).unwrap()
}

/// Made-up, locally administered unicast addresses (not real devices).
fn router(addr: [u8; 4], lladdr: &str) -> RouterIdentity {
    RouterIdentity::new(Ipv4Addr::from(addr), MacAddr::parse(lladdr).unwrap()).unwrap()
}

fn home() -> OwnNetwork {
    OwnNetwork {
        kind: OwnNetworkKind::Broadband,
        router: router([192, 168, 0, 1], "02:00:5e:10:20:40"),
        declared_at: UnixTime::from_secs(1_793_300_000),
    }
}

fn phone() -> OwnNetwork {
    OwnNetwork {
        kind: OwnNetworkKind::PersonalHotspot,
        router: router([172, 20, 10, 1], "02:00:5e:10:20:41"),
        declared_at: UnixTime::from_secs(1_793_300_060),
    }
}

const TEXT: &str = "{\n  \"version\": 1,\n  \"networks\": [\n    {\n      \"name\": \"home\",\n      \"kind\": \"broadband\",\n      \"router\": {\n        \"addr\": \"192.168.0.1\",\n        \"lladdr\": \"02:00:5e:10:20:40\"\n      },\n      \"declared_at\": 1793300000\n    },\n    {\n      \"name\": \"my phone\",\n      \"kind\": \"personal_hotspot\",\n      \"router\": {\n        \"addr\": \"172.20.10.1\",\n        \"lladdr\": \"02:00:5e:10:20:41\"\n      },\n      \"declared_at\": 1793300060\n    }\n  ]\n}\n";

const ONLY_HOME: &str = "{\n  \"version\": 1,\n  \"networks\": [\n    {\n      \"name\": \"home\",\n      \"kind\": \"broadband\",\n      \"router\": {\n        \"addr\": \"192.168.0.1\",\n        \"lladdr\": \"02:00:5e:10:20:40\"\n      },\n      \"declared_at\": 1793300000\n    }\n  ]\n}\n";

#[test]
fn declarations_round_trip_with_mode_0600_and_are_sorted_by_name() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        read_allowed_networks(dir.path()).unwrap(),
        OwnNetworks::new()
    );
    // Declared in the other order, written sorted by name.
    assert_eq!(
        declare_allowed_network(dir.path(), label("my phone"), phone()).unwrap(),
        Declaration::Recorded
    );
    assert_eq!(
        declare_allowed_network(dir.path(), label("home"), home()).unwrap(),
        Declaration::Recorded
    );
    let path = dir.path().join(ALLOWED_NETWORKS_FILE);
    assert_eq!(fs::read_to_string(&path).unwrap(), TEXT);
    assert_eq!(mode_of(&path), 0o600);
    let read = read_allowed_networks(dir.path()).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(read.get(&label("home")), Some(&home()));
    assert_eq!(read.get(&label("my phone")), Some(&phone()));
    assert_eq!(
        read.matching(&phone().router)
            .map(|(name, _)| name.as_str()),
        Some("my phone")
    );
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["allowed-networks.json", "state.lock"]);
}

#[test]
fn a_name_in_use_is_not_redeclared_and_withdrawing_rewrites_the_file() {
    let dir = tempfile::tempdir().unwrap();
    declare_allowed_network(dir.path(), label("home"), home()).unwrap();
    declare_allowed_network(dir.path(), label("my phone"), phone()).unwrap();
    let path = dir.path().join(ALLOWED_NETWORKS_FILE);
    // The same name with another network: refused, the file untouched.
    assert_eq!(
        declare_allowed_network(dir.path(), label("home"), phone()).unwrap(),
        Declaration::AlreadyDeclared
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), TEXT);
    // Withdrawing an unknown name writes nothing either.
    assert_eq!(
        revoke_allowed_network(dir.path(), &label("office")).unwrap(),
        None
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), TEXT);
    assert_eq!(
        revoke_allowed_network(dir.path(), &label("my phone")).unwrap(),
        Some(phone())
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ONLY_HOME);
    assert_eq!(mode_of(&path), 0o600);
    // The last declaration withdrawn leaves an empty document, not no file.
    assert_eq!(
        revoke_allowed_network(dir.path(), &label("home")).unwrap(),
        Some(home())
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "{\n  \"version\": 1,\n  \"networks\": []\n}\n"
    );
    assert_eq!(
        read_allowed_networks(dir.path()).unwrap(),
        OwnNetworks::new()
    );
}

#[test]
fn a_corrupt_declarations_file_is_typed_and_read_as_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ALLOWED_NETWORKS_FILE);
    let padded_to = |text: &str, len: usize| {
        let mut padded = text.trim_end().to_owned();
        padded.push_str(&" ".repeat(len - padded.len()));
        padded
    };
    fs::write(&path, padded_to(TEXT, MAX_ALLOWED_NETWORKS_BYTES)).unwrap();
    assert_eq!(read_allowed_networks(dir.path()).unwrap().len(), 2);
    let sixty_five = "x".repeat(65);
    for (text, fault) in [
        ("garbage".to_owned(), AllowedNetworksFault::Undecodable),
        (String::new(), AllowedNetworksFault::Undecodable),
        (
            TEXT.replace("\"version\": 1", "\"version\": 2"),
            AllowedNetworksFault::UnsupportedVersion,
        ),
        (
            "{\"version\": 0, \"other\": true}".to_owned(),
            AllowedNetworksFault::UnsupportedVersion,
        ),
        (
            TEXT.replace("\"version\": 1,", "\"version\": 1, \"extra\": 1,"),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace(
                "\"kind\": \"broadband\",",
                "\"kind\": \"broadband\", \"ssid\": \"x\",",
            ),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("\"kind\": \"broadband\"", "\"kind\": \"campus\""),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("02:00:5e:10:20:40", "02:00:5E:10:20:40"),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("02:00:5e:10:20:40", "01:00:5e:00:00:01"),
            AllowedNetworksFault::Undecodable,
        ),
        // The privacy placeholder identifies no device.
        (
            TEXT.replace("02:00:5e:10:20:40", "02:00:00:00:00:00"),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("192.168.0.1", "192.168.0"),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("\"name\": \"home\"", &format!("\"name\": \"{sixty_five}\"")),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("\"name\": \"home\"", "\"name\": \" home\""),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace(",\n      \"declared_at\": 1793300000", ""),
            AllowedNetworksFault::Undecodable,
        ),
        (
            TEXT.replace("\"name\": \"my phone\"", "\"name\": \"home\""),
            AllowedNetworksFault::DuplicateName,
        ),
        (
            padded_to(TEXT, MAX_ALLOWED_NETWORKS_BYTES + 1),
            AllowedNetworksFault::TooLarge,
        ),
        (padded_to(TEXT, 20 * 1024), AllowedNetworksFault::TooLarge),
    ] {
        fs::write(&path, &text).unwrap();
        let error = read_allowed_networks(dir.path()).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::AllowedNetworksCorrupt);
        match &error {
            StoreError::AllowedNetworksCorrupt {
                path: found,
                fault: found_fault,
            } => {
                assert_eq!(found, &path);
                assert_eq!(*found_fault, fault, "{text}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            error.to_string(),
            format!(
                "allowed-networks file {} is corrupt: {fault}",
                path.display()
            )
        );
        // A corrupt file is not replaced or repaired by a declaration.
        assert_eq!(
            declare_allowed_network(dir.path(), label("office"), home())
                .unwrap_err()
                .kind(),
            StoreErrorKind::AllowedNetworksCorrupt
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }
    // A directory in place of the file is an I/O failure, not corruption.
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let error = read_allowed_networks(dir.path()).unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::Io);
    assert!(
        matches!(&error, StoreError::Io { op: IoOp::ReadAllowedNetworks, path: found, .. } if found == &path),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to read the allowed-networks file at {}",
            path.display()
        )
    );
}
