// SPDX-License-Identifier: GPL-3.0-or-later

//! The pull's settings: the portal's origin, the file, and revisions that a
//! stop never outlives.

use serde_json::json;

use super::NOW;
use crate::payments::{
    ENTITLEMENTS_PATH, OriginError, PortalOrigin, PullSettings, SettingsError, Stop, StopReason,
};

/// An origin is `https://`, a lower-case DNS name and an optional port, and
/// nothing else.
#[test]
fn an_origin_is_https_a_dns_name_and_an_optional_port() {
    for good in [
        "https://portal.example.org",
        "https://moorlight.example:8443",
        "https://a.b",
        "https://localhost",
        "https://p.example:1",
        "https://p.example:65535",
    ] {
        let origin = PortalOrigin::parse(good).unwrap();
        assert_eq!(origin.to_string(), good);
        assert_eq!(
            serde_json::to_value(&origin).unwrap(),
            json!(good),
            "{good}"
        );
    }
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    assert_eq!(origin.host().as_str(), "portal.example.org");
    assert_eq!(
        origin.entitlements_url(7),
        "https://portal.example.org/api/mooring/entitlements?after=7"
    );
    assert_eq!(ENTITLEMENTS_PATH, "/api/mooring/entitlements");
    for bad in [
        "",
        "portal.example.org",
        "http://portal.example.org",
        "HTTPS://portal.example.org",
        "https://",
        "https://Portal.example.org",
        "https://portal.example.org/",
        "https://portal.example.org/api",
        "https://portal.example.org?x=1",
        "https://portal.example.org#x",
        "https://user@portal.example.org",
        "https://portal.example.org.",
        "https://192.0.2.1",
        "https://[2001:db8::1]",
        "https://portal.example.org:",
        "https://portal.example.org:0",
        "https://portal.example.org:08443",
        "https://portal.example.org:65536",
        "https://portal.example.org:443:443",
        "https://portal.example.org:+443",
        "https://portal_example.org",
        "https://portal.example.org ",
    ] {
        assert_eq!(PortalOrigin::parse(bad), Err(OriginError), "{bad:?}");
        assert!(serde_json::from_value::<PortalOrigin>(json!(bad)).is_err());
    }
    // The refusal never echoes what was typed.
    assert!(!OriginError.to_string().contains("example"));
}

/// The settings round-trip; their file is of version 2 with every key and
/// no other. A change of the rehearsal keeps the check against Stripe, and
/// a change of the check keeps the origin and the rehearsal.
#[test]
fn the_settings_round_trip_and_refuse_another_shape() {
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let connected = PullSettings::connected(3, origin.clone(), false, false);
    let rehearsing = connected.rehearsing(4, true);
    let disconnected = PullSettings::disconnected(5, false);
    let checking = rehearsing.checking(6, true);
    let checking_rehearsal_off = checking.rehearsing(7, false);
    let disconnected_checking = PullSettings::disconnected(8, true);
    for settings in [
        &connected,
        &rehearsing,
        &disconnected,
        &checking,
        &checking_rehearsal_off,
        &disconnected_checking,
    ] {
        let bytes = settings.encode().unwrap();
        assert!(bytes.ends_with(b"}\n"));
        assert_eq!(&PullSettings::decode(&bytes).unwrap(), settings);
    }
    assert_eq!(connected.revision(), 3);
    assert_eq!(connected.origin(), Some(&origin));
    assert!(!connected.rehearsal());
    assert!(!connected.stripe_check());
    assert_eq!(rehearsing.revision(), 4);
    assert_eq!(rehearsing.origin(), Some(&origin));
    assert!(rehearsing.rehearsal());
    assert!(!rehearsing.stripe_check());
    assert_eq!(disconnected.origin(), None);
    assert!(!disconnected.rehearsal());
    assert!(!disconnected.stripe_check());
    assert_eq!(checking.revision(), 6);
    assert_eq!(checking.origin(), Some(&origin));
    assert!(checking.rehearsal());
    assert!(checking.stripe_check());
    assert_eq!(checking_rehearsal_off.revision(), 7);
    assert!(!checking_rehearsal_off.rehearsal());
    assert!(checking_rehearsal_off.stripe_check());
    assert_eq!(disconnected_checking.revision(), 8);
    assert_eq!(disconnected_checking.origin(), None);
    assert!(disconnected_checking.stripe_check());
    let all_on = PullSettings::connected(9, origin, true, true);
    assert_eq!(all_on.rehearsing(9, true).checking(9, true), all_on);
    assert_ne!(all_on.checking(9, false), all_on);
    assert_ne!(all_on.rehearsing(9, false), all_on);
    assert_eq!(
        String::from_utf8(checking.encode().unwrap()).unwrap(),
        "{\n  \"version\": 2,\n  \"revision\": 6,\n  \"origin\": \"https://portal.example.org\",\n  \"rehearsal\": true,\n  \"stripe_check\": true\n}\n"
    );
    let base = json!({"version": 2, "revision": 3, "origin": "https://portal.example.org", "rehearsal": false, "stripe_check": true});
    let decode =
        |value: &serde_json::Value| PullSettings::decode(&serde_json::to_vec(value).unwrap());
    assert!(decode(&base).unwrap().stripe_check());
    for found in [0, 3] {
        let mut version = base.clone();
        version["version"] = json!(found);
        assert!(matches!(
            decode(&version),
            Err(SettingsError::UnknownVersion { found: read }) if read == found
        ));
    }
    for key in ["revision", "origin", "rehearsal", "stripe_check", "version"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode(&missing), Err(SettingsError::Decode(_))),
            "{key}"
        );
    }
    let mut extra = base.clone();
    extra["token"] = json!("0".repeat(64));
    assert!(matches!(decode(&extra), Err(SettingsError::Decode(_))));
    let mut address = base.clone();
    address["origin"] = json!("http://portal.example.org");
    assert!(matches!(decode(&address), Err(SettingsError::Decode(_))));
    let mut not_a_flag = base;
    not_a_flag["stripe_check"] = json!("on");
    assert!(matches!(decode(&not_a_flag), Err(SettingsError::Decode(_))));
    assert!(matches!(
        PullSettings::decode(&vec![b' '; 4097]),
        Err(SettingsError::TooLarge)
    ));
}

/// Settings of version 1, from before the check against Stripe, are read
/// with the check off; version 1 knows no check, so a file of version 1
/// that names one is refused.
#[test]
fn settings_of_version_1_are_read_with_the_check_off() {
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let decode =
        |value: &serde_json::Value| PullSettings::decode(&serde_json::to_vec(value).unwrap());
    let version_1 = json!({"version": 1, "revision": 3, "origin": "https://portal.example.org", "rehearsal": true});
    assert_eq!(
        decode(&version_1).unwrap(),
        PullSettings::connected(3, origin, true, false)
    );
    let disconnected = json!({"version": 1, "revision": 4, "origin": null, "rehearsal": false});
    assert_eq!(
        decode(&disconnected).unwrap(),
        PullSettings::disconnected(4, false)
    );
    for key in ["revision", "origin", "rehearsal"] {
        let mut missing = version_1.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode(&missing), Err(SettingsError::Decode(_))),
            "{key}"
        );
    }
    let mut checked = version_1;
    checked["stripe_check"] = json!(false);
    assert!(matches!(decode(&checked), Err(SettingsError::Decode(_))));
    assert!(matches!(
        PullSettings::decode(b"{\"version\": \"1\"}"),
        Err(SettingsError::Decode(_))
    ));
}

/// A change's revision is above the settings' own and above the stop's, so
/// a stop never outlives a change, even when the file was lost.
#[test]
fn a_revision_is_above_the_settings_and_the_stop() {
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let stop = |revision| Stop {
        reason: StopReason::Conflict,
        at: NOW,
        settings_revision: revision,
    };
    assert_eq!(PullSettings::next_revision(None, None), 1);
    let settings = PullSettings::connected(4, origin, false, false);
    assert_eq!(PullSettings::next_revision(Some(&settings), None), 5);
    assert_eq!(
        PullSettings::next_revision(Some(&settings), Some(stop(2))),
        5
    );
    assert_eq!(
        PullSettings::next_revision(Some(&settings), Some(stop(9))),
        10
    );
    assert_eq!(PullSettings::next_revision(None, Some(stop(9))), 10);
    assert_eq!(
        PullSettings::next_revision(None, Some(stop(u64::MAX))),
        u64::MAX
    );
}
