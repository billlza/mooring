// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal snapshot's refusals: the agreement's gate first, then the
//! users named, the contract's cross-field rules, its instants, the
//! report's rows, the automatic quota and the size bound, and every
//! error's kind. Nothing is encoded for any of them.

use std::collections::BTreeMap;
use std::num::NonZeroU16;

use mooring_model::{
    AgreementRecord, AgreementVersion, AutoQuotaPolicy, CalendarDate, NamedUsersError,
    PortalAgreement, PortalNotCovered, UnixTime, User, UserId, UserStatus,
};
use serde::ser::Error as _;

use super::super::support::{date, edited};
use super::{
    ALL, COUNTED_THROUGH, GENERATED_AT, id, ids, open, pilot, pilot_report, pilot_users, pilots,
};
use crate::error::PolicyError;
use crate::payments::Entitlements;
use crate::portal::{MAX_SNAPSHOT_BYTES, PortalError, PortalErrorKind, snapshot};

/// Nothing is made while the gate is closed, whatever the users accepted.
#[test]
fn nothing_is_made_while_the_agreement_does_not_cover_the_portal() {
    let deployment = pilots(|_| {});
    let closed = PortalAgreement::since(None);
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&ALL),
        GENERATED_AT,
        closed,
    )
    .unwrap_err();
    assert_eq!(error.kind(), PortalErrorKind::NotCovered);
    assert_eq!(
        error.to_string(),
        format!(
            "agreement revision {}, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links",
            AgreementVersion::CURRENT
        )
    );
}

/// A user goes to the portal only with an acceptance of the revision it
/// requires: none, or one of another revision, is refused by name; of
/// several such users, the first in id order, whatever the order named.
#[test]
fn a_user_without_the_required_acceptance_is_refused() {
    let deployment = pilots(|users| {
        users[1].agreement = None;
        users[3].agreement = None;
    });
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&["pilotuserd", "pilotuserb"]),
        GENERATED_AT,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(&error, PortalError::AgreementNotAccepted { user, .. } if *user == id("pilotuserb")),
        "{error:?}"
    );
    let current = AgreementVersion::CURRENT;
    let other = AgreementVersion::new(NonZeroU16::new(current.get() + 1).unwrap());
    for (record, said) in [
        (None, "no acceptance is recorded".to_owned()),
        (
            Some(AgreementRecord {
                version: other,
                accepted_on: date("2026-10-20"),
            }),
            format!("the recorded acceptance is of revision {other}"),
        ),
    ] {
        let deployment = pilots(|users| users[1].agreement = record);
        let error = snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &ids(&["pilotusera", "pilotuserb"]),
            GENERATED_AT,
            open(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, PortalError::AgreementNotAccepted { user, recorded, required }
                if *user == id("pilotuserb") && *recorded == record.map(|r| r.version)
                    && *required == AgreementVersion::CURRENT),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("user pilotuserb has not accepted agreement revision {current}: {said}")
        );
    }
}

/// The operator names at least one user, each known and once, by the
/// rule every portal export follows (`mooring_model::named_users`); a
/// list that breaks it is refused before any acceptance is looked at.
#[test]
fn users_are_named_at_least_once_each_and_known() {
    // pilotuserb has accepted nothing, so only the list's own fault can
    // be what refuses it.
    let deployment = pilots(|users| users[1].agreement = None);
    for (users, named) in [
        (&[][..], NamedUsersError::NoUsers),
        (
            &["pilotuserb", "pilotusera", "pilotuserb"][..],
            NamedUsersError::DuplicateUser {
                user: id("pilotuserb"),
            },
        ),
        (
            &["pilotuserb", "pilotuserz"][..],
            NamedUsersError::UnknownUser {
                user: id("pilotuserz"),
            },
        ),
    ] {
        let error = snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &ids(users),
            GENERATED_AT,
            open(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, PortalError::Named(found) if *found == named),
            "{error:?}"
        );
        assert_eq!(error.kind(), PortalErrorKind::Named);
        assert_eq!(error.to_string(), named.to_string());
    }
    assert_eq!(
        snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &ids(&[]),
            GENERATED_AT,
            open()
        )
        .unwrap_err()
        .to_string(),
        "no user was named; a portal export holds only the users named"
    );
    // The list comes before the snapshot's time, too.
    let past = UnixTime::from_secs(
        CalendarDate::parse("9999-12-31")
            .unwrap()
            .utc_start()
            .as_secs()
            + 86_400,
    );
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&[]),
        past,
        open(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), PortalErrorKind::Named, "{error:?}");
}

/// The contract's cross-field rules hold for every snapshot made: a
/// report that runs past the snapshot's time, or ends outside its own
/// cycle, and a suspension dated after it are refused.
#[test]
fn a_report_or_suspension_after_the_snapshots_time_is_refused() {
    let deployment = pilots(|_| {});
    let named = ids(&["pilotuserc"]);
    let early = UnixTime::from_secs(COUNTED_THROUGH.as_secs() - 1);
    let report = pilot_report(&deployment);
    let error = snapshot(
        &deployment,
        Some(&report),
        &Entitlements::none(),
        &named,
        early,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(error, PortalError::ReportAfterGeneration { through, generated_at }
            if through == COUNTED_THROUGH && generated_at == early),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the usage report runs to @1793879700, after the snapshot's time @1793879699"
    );
    // A report's end is in its cycle unless its periods were put together
    // by hand: both edges of the cycle are accepted, nothing beyond.
    let cycle = report.periods.cycle;
    for (through, accepted) in [
        (cycle.starts_at(), true),
        (cycle.ends_at(), true),
        (UnixTime::from_secs(cycle.starts_at().as_secs() - 1), false),
        (UnixTime::from_secs(cycle.ends_at().as_secs() + 1), false),
    ] {
        let mut moved = pilot_report(&deployment);
        moved.periods.through = through;
        let late = UnixTime::from_secs(cycle.ends_at().as_secs() + 1);
        let result = snapshot(
            &deployment,
            Some(&moved),
            &Entitlements::none(),
            &named,
            late,
            open(),
        );
        match result {
            Ok(made) => {
                assert!(accepted, "{through}");
                assert_eq!(made.counted_through(), Some(through));
                // The cycle is the report's, not the one the snapshot's
                // time is in.
                assert_eq!(made.cycle(), cycle);
            }
            Err(error) => {
                assert!(!accepted, "{through}: {error}");
                assert!(
                    matches!(error, PortalError::ReportOutsideCycle { through: reported } if reported == through),
                    "{error:?}"
                );
                assert_eq!(
                    error.to_string(),
                    format!("the usage report runs to {through}, outside its own billing cycle")
                );
            }
        }
    }
    // pilotuserc was suspended at 1793784600.
    let before = UnixTime::from_secs(1_793_784_599);
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &named,
        before,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(&error, PortalError::SuspendedAfterGeneration { user, since, generated_at }
            if *user == id("pilotuserc") && since.as_secs() == 1_793_784_600 && *generated_at == before),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "user pilotuserc was suspended at @1793784600, after the snapshot's time @1793784599"
    );
    // At the same instant it is accepted.
    let at = UnixTime::from_secs(1_793_784_600);
    assert!(snapshot(&deployment, None, &Entitlements::none(), &named, at, open()).is_ok());
}

/// The contract's instants end at 9999-12-31; a snapshot's time or an
/// expiry past it is refused, and a cycle that would end past it cannot be
/// computed.
#[test]
fn instants_past_9999_are_refused() {
    let last_day = CalendarDate::parse("9999-12-31").unwrap();
    let past = UnixTime::from_secs(last_day.utc_start().as_secs() + 86_400);
    let deployment = pilots(|users| users[0].policy.expires_at = Some(past));
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&["pilotuserb"]),
        past,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(error, PortalError::GeneratedOutOfRange { at } if at == past),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("the snapshot's time {past} is past 9999-12-31")
    );
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&["pilotusera"]),
        GENERATED_AT,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(&error, PortalError::ExpiryOutOfRange { user, at } if *user == id("pilotusera") && *at == past),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("user pilotusera's access expires at {past}, past 9999-12-31")
    );
    // An expiry on the last day is accepted.
    let deployment = pilots(|users| users[0].policy.expires_at = Some(last_day.utc_start()));
    assert!(
        snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &ids(&["pilotusera"]),
            GENERATED_AT,
            open()
        )
        .is_ok()
    );
    // In December 9999 the next cycle would start in 10000.
    let december = CalendarDate::parse("9999-12-15").unwrap().utc_start();
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&["pilotuserb"]),
        december,
        open(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), PortalErrorKind::Cycle);
    assert_eq!(error.to_string(), "the billing cycle could not be computed");
}

/// A report covers every user of its deployment, so one without a named
/// user's row is another deployment's.
#[test]
fn a_named_user_missing_from_the_report_is_refused() {
    let deployment = pilots(|_| {});
    let mut report = pilot_report(&deployment);
    report.users.remove(&id("pilotuserb"));
    let error = snapshot(
        &deployment,
        Some(&report),
        &Entitlements::none(),
        &ids(&["pilotusera", "pilotuserb"]),
        GENERATED_AT,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(&error, PortalError::RowMissing { user } if *user == id("pilotuserb")),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the usage report has no row for user pilotuserb"
    );
}

/// An automatic quota that cannot be evaluated refuses the snapshot rather
/// than leaving the quota out.
#[test]
fn a_failing_automatic_quota_is_refused() {
    let deployment = edited(|parts| {
        parts.users = pilot_users();
        parts.auto_quota = Some(AutoQuotaPolicy::PILOT);
    });
    // pilotuserc's suspension for quota is dated after this time.
    let before = UnixTime::from_secs(1_793_784_599);
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &ids(&["pilotusera"]),
        before,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            PortalError::Quota(PolicyError::QuotaSuspensionAfterNow { user, .. })
                if *user == id("pilotuserc")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the automatic quota could not be evaluated"
    );
}

/// The portal reads at most 1 MiB; a snapshot of more users than fit is
/// refused, not cut.
#[test]
fn a_snapshot_larger_than_the_portal_reads_is_refused() {
    const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let many: Vec<User> = (0_u32..6_000)
        .map(|number| {
            let mut text = String::from("bulk");
            for shift in (0..6).rev() {
                text.push(char::from(BASE32[(number >> (5 * shift)) as usize & 31]));
            }
            User {
                id: id(&text),
                status: UserStatus::Revoked,
                per_node: BTreeMap::new(),
                ..pilot(b'f', UserStatus::Revoked, None, None)
            }
        })
        .collect();
    let named: Vec<UserId> = many.iter().map(|user| user.id.clone()).collect();
    let deployment = edited(|parts| parts.users = many);
    let error = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
        &named,
        GENERATED_AT,
        open(),
    )
    .unwrap_err();
    assert!(
        matches!(error, PortalError::TooLarge { bytes, limit } if bytes > MAX_SNAPSHOT_BYTES && limit == MAX_SNAPSHOT_BYTES),
        "{error:?}"
    );
    // Fewer users fit.
    assert!(
        snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &named[..1_000],
            GENERATED_AT,
            open()
        )
        .is_ok()
    );
}

/// Every kind names its variant.
#[test]
fn every_error_has_its_kind() {
    let user = id("pilotusera");
    let at = UnixTime::from_secs(1);
    let cases = [
        (
            PortalError::NotCovered(PortalNotCovered {
                current: AgreementVersion::CURRENT,
            }),
            PortalErrorKind::NotCovered,
        ),
        (
            PortalError::Named(NamedUsersError::NoUsers),
            PortalErrorKind::Named,
        ),
        (
            PortalError::AgreementNotAccepted {
                user: user.clone(),
                recorded: None,
                required: AgreementVersion::CURRENT,
            },
            PortalErrorKind::AgreementNotAccepted,
        ),
        (
            PortalError::GeneratedOutOfRange { at },
            PortalErrorKind::GeneratedOutOfRange,
        ),
        (
            PortalError::ExpiryOutOfRange {
                user: user.clone(),
                at,
            },
            PortalErrorKind::ExpiryOutOfRange,
        ),
        (
            PortalError::Cycle(mooring_model::ModelError::InvalidDate),
            PortalErrorKind::Cycle,
        ),
        (
            PortalError::ReportAfterGeneration {
                through: at,
                generated_at: at,
            },
            PortalErrorKind::ReportAfterGeneration,
        ),
        (
            PortalError::ReportOutsideCycle { through: at },
            PortalErrorKind::ReportOutsideCycle,
        ),
        (
            PortalError::Quota(PolicyError::UsageAfterNow {
                through: at,
                now: at,
            }),
            PortalErrorKind::Quota,
        ),
        (
            PortalError::RowMissing { user: user.clone() },
            PortalErrorKind::RowMissing,
        ),
        (
            PortalError::SuspendedAfterGeneration {
                user,
                since: at,
                generated_at: at,
            },
            PortalErrorKind::SuspendedAfterGeneration,
        ),
        (
            PortalError::TooLarge { bytes: 2, limit: 1 },
            PortalErrorKind::TooLarge,
        ),
        (
            PortalError::Encode(serde_json::Error::custom("refused")),
            PortalErrorKind::Encode,
        ),
    ];
    assert_eq!(cases.len(), PortalErrorKind::ALL.len());
    for (error, kind) in cases {
        assert_eq!(error.kind(), kind, "{error:?}");
    }
    assert_eq!(
        PortalError::TooLarge { bytes: 2, limit: 1 }.to_string(),
        "the snapshot is 2 bytes, more than the portal's 1"
    );
    assert_eq!(
        PortalError::Encode(serde_json::Error::custom("refused")).to_string(),
        "the snapshot could not be encoded"
    );
}
