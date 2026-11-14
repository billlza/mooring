// SPDX-License-Identifier: GPL-3.0-or-later

//! The pull's settings: the portal's origin, the file, and revisions that a
//! stop never outlives.

use serde_json::json;

use super::NOW;
use super::plans::{book_of, file_of, listed, parse, sold};
use crate::payments::{
    ENTITLEMENTS_PATH, MAX_FILE_PLANS, MAX_SETTINGS_BYTES, MAX_STORED_PLANS, OriginError, PlanBook,
    PortalOrigin, PullSettings, SettingsError, Stop, StopReason,
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
        "{\n  \"version\": 3,\n  \"revision\": 6,\n  \"origin\": \"https://portal.example.org\",\n  \"rehearsal\": true,\n  \"stripe_check\": true,\n  \"plans\": []\n}\n"
    );
    let base = json!({"version": 3, "revision": 3, "origin": "https://portal.example.org", "rehearsal": false, "stripe_check": true, "plans": []});
    let decode =
        |value: &serde_json::Value| PullSettings::decode(&serde_json::to_vec(value).unwrap());
    assert!(decode(&base).unwrap().stripe_check());
    for found in [0, 4] {
        let mut version = base.clone();
        version["version"] = json!(found);
        assert!(matches!(
            decode(&version),
            Err(SettingsError::UnknownVersion { found: read }) if read == found
        ));
    }
    for key in [
        "revision",
        "origin",
        "rehearsal",
        "stripe_check",
        "plans",
        "version",
    ] {
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
        PullSettings::decode(&vec![b' '; MAX_SETTINGS_BYTES + 1]),
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

/// The plans kept are in the settings from version 3: every other change
/// keeps them, they read back as written, and only a change of plans drops
/// them; plans no file leaves are refused. Version 2 is read with none,
/// and a file of version 2 that names any is refused.
#[test]
fn the_plans_kept_are_in_the_settings() {
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let book = book_of(sold());
    let planned = PullSettings::connected(3, origin.clone(), true, true).planning(4, book.clone());
    assert_eq!(planned.revision(), 4);
    assert_eq!(planned.plans(), &book);
    assert_eq!(planned.origin(), Some(&origin));
    assert!(planned.rehearsal());
    assert!(planned.stripe_check());
    assert_eq!(
        PullSettings::decode(&planned.encode().unwrap()).unwrap(),
        planned
    );
    assert_eq!(planned.rehearsing(5, false).plans(), &book);
    assert_eq!(planned.checking(6, false).plans(), &book);
    let away = planned.disconnecting(7);
    assert_eq!(away.revision(), 7);
    assert_eq!(away.origin(), None);
    assert!(!away.rehearsal());
    assert!(away.stripe_check());
    assert_eq!(away.plans(), &book);
    let back = away.connecting(8, origin.clone());
    assert_eq!(back.revision(), 8);
    assert_eq!(back.origin(), Some(&origin));
    assert!(!back.rehearsal());
    assert!(back.stripe_check());
    assert_eq!(back.plans(), &book);
    let unplanned = back.planning(9, PlanBook::default());
    assert_eq!(unplanned.revision(), 9);
    assert!(unplanned.plans().is_empty());
    assert_eq!(unplanned.origin(), Some(&origin));
    assert!(unplanned.stripe_check());
    assert!(
        PullSettings::connected(1, origin.clone(), false, false)
            .plans()
            .is_empty()
    );
    assert!(PullSettings::disconnected(1, true).plans().is_empty());
    let written: serde_json::Value = serde_json::from_slice(&planned.encode().unwrap()).unwrap();
    assert_eq!(
        written["plans"],
        serde_json::to_value(book.plans()).unwrap()
    );
    let decode =
        |value: &serde_json::Value| PullSettings::decode(&serde_json::to_vec(value).unwrap());
    let mut out_of_bounds = written.clone();
    out_of_bounds["plans"][0]["days"] = json!(3661);
    assert!(matches!(
        decode(&out_of_bounds),
        Err(SettingsError::Decode(_))
    ));
    let mut repeated = written;
    repeated["plans"][1] = repeated["plans"][0].clone();
    assert!(matches!(decode(&repeated), Err(SettingsError::Decode(_))));
    let version_2 = json!({"version": 2, "revision": 3, "origin": "https://portal.example.org", "rehearsal": false, "stripe_check": true});
    assert_eq!(
        decode(&version_2).unwrap(),
        PullSettings::connected(3, origin, false, true)
    );
    let mut planned_in_2 = version_2.clone();
    planned_in_2["plans"] = json!([]);
    assert!(matches!(
        decode(&planned_in_2),
        Err(SettingsError::Decode(_))
    ));
    for key in ["revision", "origin", "rehearsal", "stripe_check"] {
        let mut missing = version_2.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode(&missing), Err(SettingsError::Decode(_))),
            "{key}"
        );
    }
}

/// The most plans kept, each as long as the portal lets a plan be, with
/// the longest origin and revision, fit in a settings file the daemon
/// reads.
#[test]
fn the_most_plans_kept_fit_in_the_settings() {
    let longest_word = "a".repeat(124);
    let mut book = PlanBook::default();
    for file in 0..MAX_STORED_PLANS / MAX_FILE_PLANS {
        let plans = (0..MAX_FILE_PLANS)
            .map(|at| {
                let mut plan = listed(
                    &format!("{}{file:02}{at:02}", "p".repeat(28)),
                    "month_auto",
                    100_000,
                    10_000_000,
                    &format!("{file:02}{at:02}{longest_word}"),
                );
                plan["days"] = json!(3660);
                plan
            })
            .collect();
        book = book.stored(&parse(&file_of(plans)).unwrap()).unwrap().0;
    }
    assert_eq!(book.plans().len(), MAX_STORED_PLANS);
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let origin = PortalOrigin::parse(&format!("https://{host}:65535")).unwrap();
    let settings = PullSettings::connected(u64::MAX, origin, true, true).planning(u64::MAX, book);
    let bytes = settings.encode().unwrap();
    assert!(bytes.len() <= MAX_SETTINGS_BYTES, "{}", bytes.len());
    assert_eq!(PullSettings::decode(&bytes).unwrap(), settings);
}
