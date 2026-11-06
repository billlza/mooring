// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal snapshot (`docs/portal-contract.md`): the contract's own
//! goldens reproduced byte for byte, each field's source, the agreement's
//! gate and every refusal.
//!
//! The goldens in `contract/portal-fixtures/snapshot-v1/` are copies of the
//! portal repository's `contract/fixtures/v1/valid/` at its commit
//! c070413, synthetic data only; the pilot users below are the users they
//! describe.

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU64};

use mooring_agent_proto::{Inbound, StatsEmail, Traffic, UsageMonth, UsageV1};
use mooring_model::{
    AgreementRecord, AgreementVersion, AutoQuotaPolicy, CalendarDate, ClientLine, ClientProfile,
    Deployment, LocalLabel, PortalAgreement, QuotaAction, ShortId, SuspendReason, UnixTime, User,
    UserId, UserNodePublic, UserPolicy, UserQuota, UserStatus, WarnPercent,
};
use serde::ser::Error as _;
use serde_json::{Value, json};

use super::support::{date, edited, email, node, traffic, wire};
use crate::error::PolicyError;
use crate::period::{BillingCycle, UsagePeriods};
use crate::policy::automatic_quota;
use crate::portal::{MAX_SNAPSHOT_BYTES, PortalError, PortalErrorKind, PortalSnapshot, snapshot};
use crate::usage::{CollectedUsage, NodeUsageHistory, UsageReport, UserUsage};

const PILOT_GOLDEN: &str =
    include_str!("../../../../contract/portal-fixtures/snapshot-v1/pilot.json");
const NO_REPORT_GOLDEN: &str =
    include_str!("../../../../contract/portal-fixtures/snapshot-v1/no-usage-report.json");

/// The goldens' snapshot time, 2026-11-05T12:00:00Z.
const GENERATED_AT: UnixTime = UnixTime::from_secs(1_793_880_000);

/// The goldens' report end, five minutes earlier.
const COUNTED_THROUGH: UnixTime = UnixTime::from_secs(1_793_879_700);

/// The gate opened on the revision this build ships, as a build whose
/// agreement covers the portal would have it.
fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

fn ids(texts: &[&str]) -> Vec<UserId> {
    texts.iter().map(|text| id(text)).collect()
}

fn quota(gigabytes: u64, action: QuotaAction) -> Option<UserQuota> {
    Some(UserQuota {
        cycle_served_bytes: NonZeroU64::new(gigabytes * 1_000_000_000).unwrap(),
        warn_percent: WarnPercent::new(80).unwrap(),
        action,
    })
}

/// One pilot user: active on both fixture nodes unless `status` says
/// otherwise, accepted the shipped revision, no alias.
fn pilot(
    letter: u8,
    status: UserStatus,
    quota: Option<UserQuota>,
    expires_at: Option<u64>,
) -> User {
    let per_node = if status == UserStatus::Revoked {
        BTreeMap::new()
    } else {
        ["lon1", "ams1"]
            .into_iter()
            .map(|name| {
                (
                    node(name),
                    UserNodePublic {
                        short_id: ShortId::from_bytes([0x70, 0x6c, 0, 0, 0, 0, 0, letter]).unwrap(),
                    },
                )
            })
            .collect()
    };
    User {
        id: id(&format!("pilotuser{}", char::from(letter))),
        label: LocalLabel::parse("Pilot").unwrap(),
        client: ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: Default::default(),
        },
        status,
        per_node,
        policy: UserPolicy {
            expires_at: expires_at.map(UnixTime::from_secs),
            quota,
        },
        alias: None,
        agreement: Some(AgreementRecord {
            version: AgreementVersion::CURRENT,
            accepted_on: date("2026-10-20"),
        }),
    }
}

/// The seven users of the contract's `pilot.json`, in place of the
/// fixture's.
fn pilot_users() -> Vec<User> {
    vec![
        pilot(
            b'a',
            UserStatus::Active,
            quota(40, QuotaAction::Suspend),
            Some(1_809_129_600),
        ),
        pilot(
            b'b',
            UserStatus::Active,
            quota(40, QuotaAction::Suspend),
            None,
        ),
        pilot(
            b'c',
            UserStatus::Suspended {
                reason: SuspendReason::QuotaExceeded {
                    cycle_start: date("2026-11-01"),
                },
                since: UnixTime::from_secs(1_793_784_600),
            },
            quota(40, QuotaAction::Suspend),
            None,
        ),
        pilot(
            b'd',
            UserStatus::Active,
            quota(40, QuotaAction::Warn),
            Some(1_795_132_800),
        ),
        pilot(b'e', UserStatus::Active, None, None),
        pilot(b'f', UserStatus::Revoked, None, None),
        pilot(
            b'g',
            UserStatus::Suspended {
                reason: SuspendReason::Expired,
                since: UnixTime::from_secs(1_793_577_900),
            },
            None,
            Some(1_793_577_600),
        ),
    ]
}

/// The fixture deployment (two applied nodes, billed on the 1st) with the
/// pilot users, after `edit`.
fn pilots(edit: impl FnOnce(&mut Vec<User>)) -> Deployment {
    let mut users = pilot_users();
    edit(&mut users);
    edited(|parts| parts.users = users)
}

/// A user's usage with `cycle` bytes served this cycle (all REALITY
/// downlink, on lon1), or none known; the other periods unknown.
fn usage(cycle: Option<u64>) -> UserUsage {
    let none = json!({
        "today": null, "cycle": null, "month": null, "lifetime": null,
        "cycle_served_bytes": null, "cycle_by_node": null,
        "cycle_by_protocol": null, "cycle_shares": null,
    });
    let value = match cycle {
        None => none,
        Some(0) => json!({
            "today": null, "month": null, "lifetime": null,
            "cycle": {"uplink": 0, "downlink": 0},
            "cycle_served_bytes": 0,
            "cycle_by_node": {},
            "cycle_by_protocol": {
                "reality": {"uplink": 0, "downlink": 0},
                "hy2": {"uplink": 0, "downlink": 0},
            },
            "cycle_shares": null,
        }),
        Some(bytes) => json!({
            "today": null, "month": null, "lifetime": null,
            "cycle": {"uplink": 0, "downlink": bytes},
            "cycle_served_bytes": bytes,
            "cycle_by_node": {"lon1": {"uplink": 0, "downlink": bytes}},
            "cycle_by_protocol": {
                "reality": {"uplink": 0, "downlink": bytes},
                "hy2": {"uplink": 0, "downlink": 0},
            },
            "cycle_shares": {
                "by_node": {"lon1": 10_000},
                "by_protocol": {"reality": 10_000, "hy2": 0},
            },
        }),
    };
    serde_json::from_value(value).unwrap()
}

/// The pilot's usage report, made at [`COUNTED_THROUGH`].
fn pilot_report(deployment: &Deployment) -> UsageReport {
    let figures = [
        ("pilotusera", Some(12_345_678_901)),
        ("pilotuserb", Some(35_000_000_000)),
        ("pilotuserc", Some(40_100_000_000)),
        ("pilotuserd", None),
        ("pilotusere", Some(2_000_000_000)),
        ("pilotuserf", Some(0)),
        ("pilotuserg", Some(1_500_000_000)),
    ];
    UsageReport {
        periods: UsagePeriods::ending(deployment.exit().sim.cycle(), COUNTED_THROUGH).unwrap(),
        users: figures
            .into_iter()
            .map(|(user, cycle)| (id(user), usage(cycle)))
            .collect(),
        sampled_at: BTreeMap::new(),
        probe_cycle: BTreeMap::new(),
    }
}

fn text(snapshot: &PortalSnapshot) -> &str {
    std::str::from_utf8(snapshot.bytes()).unwrap()
}

fn parsed(snapshot: &PortalSnapshot) -> Value {
    serde_json::from_slice(snapshot.bytes()).unwrap()
}

const ALL: [&str; 7] = [
    "pilotusera",
    "pilotuserb",
    "pilotuserc",
    "pilotuserd",
    "pilotusere",
    "pilotuserf",
    "pilotuserg",
];

/// The contract's `pilot.json`, byte for byte: every status, a quota of
/// each action and none, an expiry past and to come, a known zero, a
/// revoked user's figure and an active user's unknown one.
#[test]
fn the_pilot_snapshot_is_the_contracts_golden() {
    let deployment = pilots(|_| {});
    let report = pilot_report(&deployment);
    let made = snapshot(&deployment, Some(&report), &ids(&ALL), GENERATED_AT, open()).unwrap();
    assert_eq!(text(&made), PILOT_GOLDEN);
    assert_eq!(made.users(), 7);
    // Its debug form gives the size, not the document.
    assert_eq!(
        format!("{made:?}"),
        format!(
            "PortalSnapshot {{ len: {}, users: 7, cycle: {:?}, counted_through: Some({COUNTED_THROUGH:?}) }}",
            PILOT_GOLDEN.len(),
            made.cycle()
        )
    );
    assert_eq!(made.counted_through(), Some(COUNTED_THROUGH));
    assert_eq!(
        made.cycle(),
        BillingCycle::containing(deployment.exit().sim.cycle(), date("2026-11-05")).unwrap()
    );
}

/// The contract's `no-usage-report.json`: without a report the cycle is
/// the one the snapshot's time is in, and every figure and
/// `counted_through` is `null`, never 0.
#[test]
fn without_a_report_every_figure_is_null() {
    let deployment = pilots(|users| users[0].policy.expires_at = None);
    let made = snapshot(
        &deployment,
        None,
        &ids(&["pilotusera", "pilotusere"]),
        GENERATED_AT,
        open(),
    )
    .unwrap();
    assert_eq!(text(&made), NO_REPORT_GOLDEN);
    assert_eq!(made.counted_through(), None);
    assert_eq!(made.users(), 2);
}

/// The users appear in id order, whatever order they are named in, and
/// only those named.
#[test]
fn only_the_named_users_appear_in_id_order() {
    let deployment = pilots(|_| {});
    let report = pilot_report(&deployment);
    let made = snapshot(
        &deployment,
        Some(&report),
        &ids(&["pilotuserg", "pilotuserb"]),
        GENERATED_AT,
        open(),
    )
    .unwrap();
    let users = parsed(&made)["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["user"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(users, ["pilotuserb", "pilotuserg"]);
}

/// A user being revoked is served nowhere, so it is shown as revoked; the
/// operator's and an abuse review's suspensions keep their reason.
#[test]
fn every_status_has_its_contract_form() {
    let suspended = |reason| UserStatus::Suspended {
        reason,
        since: UnixTime::from_secs(1_793_700_000),
    };
    let deployment = pilots(|users| {
        users[0].status = UserStatus::RevokePending;
        users[1].status = suspended(SuspendReason::Operator);
        users[4].status = suspended(SuspendReason::AbuseReview);
    });
    let made = snapshot(
        &deployment,
        None,
        &ids(&["pilotusera", "pilotuserb", "pilotusere"]),
        GENERATED_AT,
        open(),
    )
    .unwrap();
    let document = parsed(&made);
    let statuses: Vec<&Value> = document["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| &user["status"])
        .collect();
    assert_eq!(
        statuses,
        [
            &json!("revoked"),
            &json!({"suspended": {"reason": "operator", "since": 1_793_700_000}}),
            &json!({"suspended": {"reason": "abuse_review", "since": 1_793_700_000}}),
        ]
    );
    // None of them is served, so none counts REALITY at close.
    for user in document["users"].as_array().unwrap() {
        assert_eq!(user["reality_downlink_counted_at_close"], json!(false));
    }
}

/// Without a quota of their own, users get the deployment's automatic
/// quota, as the console shows it; a user's own quota still wins.
#[test]
fn the_automatic_quota_applies_to_users_without_their_own() {
    let deployment = edited(|parts| {
        parts.users = pilot_users();
        parts.auto_quota = Some(AutoQuotaPolicy {
            from_active_users: NonZeroU16::new(5).unwrap(),
            ..AutoQuotaPolicy::PILOT
        });
    });
    let automatic = automatic_quota(&deployment, GENERATED_AT).unwrap().unwrap();
    let made = snapshot(
        &deployment,
        None,
        &ids(&["pilotusera", "pilotusere"]),
        GENERATED_AT,
        open(),
    )
    .unwrap();
    let document = parsed(&made);
    assert_eq!(
        document["users"][0]["quota"],
        json!({"cycle_served_bytes": 40_000_000_000_u64, "warn_percent": 80, "action": "suspend"})
    );
    assert_eq!(
        document["users"][1]["quota"],
        json!({
            "cycle_served_bytes": automatic.cycle_served_bytes.get(),
            "warn_percent": automatic.warn_percent.get(),
            "action": "suspend",
        })
    );
}

fn month(text: &str, updated: UnixTime, entries: Vec<(StatsEmail, Traffic)>) -> UsageV1 {
    UsageV1 {
        month: text.parse::<UsageMonth>().unwrap(),
        updated_at: wire(updated),
        traffic: entries.into_iter().collect(),
    }
}

/// A report aggregated from collected usage, as the export reads it,
/// gives each user the cycle's bytes on every node and in both directions.
#[test]
fn collected_usage_gives_each_user_the_cycles_bytes() {
    let deployment = pilots(|_| {});
    let now = COUNTED_THROUGH;
    let user = id("pilotusera");
    let mut history = CollectedUsage::default();
    for (name, entries) in [
        (
            "lon1",
            vec![
                (email(&user, Inbound::Reality), traffic(1_000, 9_000)),
                (email(&user, Inbound::Hy2), traffic(500, 500)),
            ],
        ),
        (
            "ams1",
            vec![(email(&user, Inbound::Reality), traffic(0, 4_000))],
        ),
    ] {
        let mut node_history = NodeUsageHistory::default();
        node_history
            .record_month(&node(name), month("2026-11", now, entries), now)
            .unwrap();
        history.set_node(node(name), node_history);
    }
    let report = history.aggregate(&deployment, now).unwrap();
    let made = snapshot(
        &deployment,
        Some(&report),
        &ids(&["pilotusera", "pilotuserb"]),
        GENERATED_AT,
        open(),
    )
    .unwrap();
    let document = parsed(&made);
    assert_eq!(document["counted_through"], json!(now.as_secs()));
    assert_eq!(document["users"][0]["cycle_served_bytes"], json!(15_000));
    // A user with no traffic on any node has a real zero.
    assert_eq!(document["users"][1]["cycle_served_bytes"], json!(0));
}

/// Nothing is made while the shipped agreement does not cover the portal,
/// whatever the users accepted.
#[test]
fn nothing_is_made_while_the_agreement_does_not_cover_the_portal() {
    let deployment = pilots(|_| {});
    let error = snapshot(
        &deployment,
        None,
        &ids(&ALL),
        GENERATED_AT,
        PortalAgreement::SHIPPED,
    )
    .unwrap_err();
    assert_eq!(error.kind(), PortalErrorKind::NotCovered);
    assert_eq!(
        error.to_string(),
        "agreement revision 1, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links"
    );
}

/// A user goes to the portal only with an acceptance of the revision it
/// requires: none, or one of another revision, is refused by name.
#[test]
fn a_user_without_the_required_acceptance_is_refused() {
    let other = AgreementVersion::new(NonZeroU16::new(2).unwrap());
    for (record, said) in [
        (None, "no acceptance is recorded"),
        (
            Some(AgreementRecord {
                version: other,
                accepted_on: date("2026-10-20"),
            }),
            "the recorded acceptance is of revision 2",
        ),
    ] {
        let deployment = pilots(|users| users[1].agreement = record);
        let error = snapshot(
            &deployment,
            None,
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
            format!("user pilotuserb has not accepted agreement revision 1: {said}")
        );
    }
}

/// The operator names at least one user, each known and once.
#[test]
fn users_are_named_at_least_once_each_and_known() {
    let deployment = pilots(|_| {});
    let refused = |users: &[&str]| {
        snapshot(&deployment, None, &ids(users), GENERATED_AT, open()).unwrap_err()
    };
    let none = refused(&[]);
    assert_eq!(none.kind(), PortalErrorKind::NoUsers);
    assert_eq!(
        none.to_string(),
        "no user was named; a snapshot holds only the users named"
    );
    let twice = refused(&["pilotusera", "pilotuserb", "pilotusera"]);
    assert!(
        matches!(&twice, PortalError::DuplicateUser { user } if *user == id("pilotusera")),
        "{twice:?}"
    );
    assert_eq!(twice.to_string(), "user pilotusera is named twice");
    let unknown = refused(&["pilotusera", "pilotuserz"]);
    assert!(
        matches!(&unknown, PortalError::UnknownUser { user } if *user == id("pilotuserz")),
        "{unknown:?}"
    );
    assert_eq!(unknown.to_string(), "unknown user pilotuserz");
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
    let error = snapshot(&deployment, Some(&report), &named, early, open()).unwrap_err();
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
        let result = snapshot(&deployment, Some(&moved), &named, late, open());
        match result {
            Ok(made) => {
                assert!(accepted, "{through}");
                assert_eq!(made.counted_through(), Some(through));
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
    let error = snapshot(&deployment, None, &named, before, open()).unwrap_err();
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
    assert!(snapshot(&deployment, None, &named, at, open()).is_ok());
}

/// The contract's instants end at 9999-12-31; a snapshot's time or an
/// expiry past it is refused, and a cycle that would end past it cannot be
/// computed.
#[test]
fn instants_past_9999_are_refused() {
    let last_day = CalendarDate::parse("9999-12-31").unwrap();
    let past = UnixTime::from_secs(last_day.utc_start().as_secs() + 86_400);
    let deployment = pilots(|users| users[0].policy.expires_at = Some(past));
    let error = snapshot(&deployment, None, &ids(&["pilotuserb"]), past, open()).unwrap_err();
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
            &ids(&["pilotusera"]),
            GENERATED_AT,
            open()
        )
        .is_ok()
    );
    // In December 9999 the next cycle would start in 10000.
    let december = CalendarDate::parse("9999-12-15").unwrap().utc_start();
    let error = snapshot(&deployment, None, &ids(&["pilotuserb"]), december, open()).unwrap_err();
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
    let error = snapshot(&deployment, None, &ids(&["pilotusera"]), before, open()).unwrap_err();
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
    let error = snapshot(&deployment, None, &named, GENERATED_AT, open()).unwrap_err();
    assert!(
        matches!(error, PortalError::TooLarge { bytes, limit } if bytes > MAX_SNAPSHOT_BYTES && limit == MAX_SNAPSHOT_BYTES),
        "{error:?}"
    );
    // Fewer users fit.
    assert!(snapshot(&deployment, None, &named[..1_000], GENERATED_AT, open()).is_ok());
}

/// Every kind names its variant.
#[test]
fn every_error_has_its_kind() {
    let user = id("pilotusera");
    let at = UnixTime::from_secs(1);
    let cases = [
        (
            PortalError::NotCovered(PortalAgreement::SHIPPED.required().unwrap_err()),
            PortalErrorKind::NotCovered,
        ),
        (PortalError::NoUsers, PortalErrorKind::NoUsers),
        (
            PortalError::DuplicateUser { user: user.clone() },
            PortalErrorKind::DuplicateUser,
        ),
        (
            PortalError::UnknownUser { user: user.clone() },
            PortalErrorKind::UnknownUser,
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
