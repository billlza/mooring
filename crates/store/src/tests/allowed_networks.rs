// SPDX-License-Identifier: GPL-3.0-or-later

//! The own-network declarations file (design §10.2, P0-2): its exact
//! format and mode, declaring and withdrawing under the lock, an absent file
//! read as no declaration, the typed refusal of anything that is not a
//! version-1 declaration document, and the bound held on the writer's side
//! as on the reader's.

use std::fs;
use std::net::Ipv4Addr;

use mooring_model::ids::LocalLabel;
use mooring_model::iface::{MacAddr, RouterIdentity};
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind, OwnNetworks};
use mooring_model::time::UnixTime;

use super::mode_of;
use crate::allowed_networks::{
    ALLOWED_NETWORKS_FILE, AllowedNetworksFault, Declaration, MAX_ALLOWED_NETWORKS_BYTES,
    allowed_networks_fit, declare_allowed_network, read_allowed_networks, revoke_allowed_network,
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
    assert_eq!(
        declare_allowed_network(dir.path(), label("home"), home()).unwrap(),
        Declaration::Recorded
    );
    assert_eq!(
        declare_allowed_network(dir.path(), label("my phone"), phone()).unwrap(),
        Declaration::Recorded
    );
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

/// The bound holds on the writer's side as on the reader's: a declaration
/// that would take the document past `MAX_ALLOWED_NETWORKS_BYTES` is
/// refused as `Full` with the file unchanged, where a reader would have
/// refused the file it made; a document exactly at the bound is written,
/// read and withdrawn from, and the withdrawal makes room. The document is
/// grown to the bound from what the store writes: the first two
/// declarations give one entry's size, fixed-width labels fill the file,
/// and the last label's UTF-8 length lands it exactly on the bound (any
/// script is allowed, up to 64 characters: `a` is one byte, `家` three).
#[test]
fn a_declaration_the_file_cannot_hold_is_refused_and_the_bound_itself_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ALLOWED_NETWORKS_FILE);
    let len = || usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();
    let declare = |name: &str| declare_allowed_network(dir.path(), label(name), home()).unwrap();
    assert_eq!(declare("000"), Declaration::Recorded);
    let one = len();
    assert_eq!(declare("001"), Declaration::Recorded);
    // What one more entry with a three-character label adds, and what it
    // adds without its label.
    let entry = len() - one;
    let overhead = entry - 3;
    let mut next = 2;
    while MAX_ALLOWED_NETWORKS_BYTES - len() > overhead + 190 {
        assert_eq!(declare(&format!("{next:03}")), Declaration::Recorded);
        next += 1;
    }
    let room = MAX_ALLOWED_NETWORKS_BYTES - len() - overhead;
    assert!((2..=190).contains(&room), "{room}");
    let (narrow, wide) = (room % 3, room / 3);
    assert!(narrow + wide <= 64, "{narrow} + {wide}");
    let last = format!("{}{}", "a".repeat(narrow), "家".repeat(wide));
    assert_eq!(declare(&last), Declaration::Recorded);
    assert_eq!(len(), MAX_ALLOWED_NETWORKS_BYTES);
    let full = fs::read(&path).unwrap();
    let declared = read_allowed_networks(dir.path()).unwrap();
    assert_eq!(declared.len(), next + 1);
    assert_eq!(declared.get(&label(&last)), Some(&home()));
    assert!(allowed_networks_fit(&OwnNetworks::new()).unwrap());
    assert!(allowed_networks_fit(&declared).unwrap());
    // One more, of the shortest label, does not fit: refused, nothing
    // written, nothing read differently.
    let mut one_more = declared.clone();
    one_more.insert(label("z"), phone());
    assert!(!allowed_networks_fit(&one_more).unwrap());
    assert_eq!(
        declare_allowed_network(dir.path(), label("z"), phone()).unwrap(),
        Declaration::Full { declared: next + 1 }
    );
    assert_eq!(fs::read(&path).unwrap(), full);
    assert_eq!(read_allowed_networks(dir.path()).unwrap(), declared);
    // A name in use is still refused as such, before any size is weighed,
    // and the entry is not replaced.
    assert_eq!(
        declare_allowed_network(dir.path(), label("000"), phone()).unwrap(),
        Declaration::AlreadyDeclared
    );
    assert_eq!(fs::read(&path).unwrap(), full);
    // Withdrawing from the full file works and makes room: one entry's.
    assert_eq!(
        revoke_allowed_network(dir.path(), &label("000")).unwrap(),
        Some(home())
    );
    assert_eq!(len(), MAX_ALLOWED_NETWORKS_BYTES - entry);
    // (The phone's entry is a few bytes longer than the home's: the room
    // is in bytes, not entries.)
    assert_eq!(declare("z"), Declaration::Recorded);
    assert_eq!(len(), MAX_ALLOWED_NETWORKS_BYTES - entry + overhead + 1);
    assert_eq!(read_allowed_networks(dir.path()).unwrap().len(), next + 1);
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
