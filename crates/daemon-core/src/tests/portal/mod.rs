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
    AgreementRecord, AgreementVersion, AutoQuotaPolicy, ClientLine, ClientProfile, Deployment,
    LocalLabel, PortalAgreement, QuotaAction, ShortId, SuspendReason, UnixTime, User, UserId,
    UserNodePublic, UserPolicy, UserQuota, UserStatus, WarnPercent,
};
use serde_json::{Value, json};

use super::payments::{Terms, Told, live};
use super::support::{date, edited, email, node, traffic, wire};
use crate::payments::{Entitlements, PaymentLedger};
use crate::period::{BillingCycle, UsagePeriods};
use crate::policy::automatic_quota;
use crate::portal::{PortalSnapshot, snapshot};
use crate::usage::{CollectedUsage, NodeUsageHistory, ServedBefore, UsageReport, UserUsage};

mod refusals;

const PILOT_GOLDEN: &str =
    include_str!("../../../../../contract/portal-fixtures/snapshot-v1/pilot.json");
const NO_REPORT_GOLDEN: &str =
    include_str!("../../../../../contract/portal-fixtures/snapshot-v1/no-usage-report.json");

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
    let per_node = if status.is_revoked() {
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
        pilot(
            b'f',
            UserStatus::Revoked {
                since: UnixTime::from_secs(1_791_417_600),
            },
            None,
            None,
        ),
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
        cycle_reality_downlink: BTreeMap::new(),
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
    let made = snapshot(
        &deployment,
        Some(&report),
        &Entitlements::none(),
        &ids(&ALL),
        GENERATED_AT,
        open(),
    )
    .unwrap();
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
        &Entitlements::none(),
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
        &Entitlements::none(),
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
        users[4].policy.quota = Some(UserQuota {
            cycle_served_bytes: NonZeroU64::new(5_000_000_000).unwrap(),
            warn_percent: WarnPercent::new(75).unwrap(),
            action: QuotaAction::Warn,
        });
    });
    let made = snapshot(
        &deployment,
        None,
        &Entitlements::none(),
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
    // A quota keeps its own share and action.
    assert_eq!(
        document["users"][2]["quota"],
        json!({"cycle_served_bytes": 5_000_000_000_u64, "warn_percent": 75, "action": "warn"})
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
        &Entitlements::none(),
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
        &Entitlements::none(),
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

/// The quota the snapshot gives counts a download that was open at the
/// refund in full of a traffic pack (design §9.6), by the report the
/// snapshot's use comes from. `pilotusera` has 40 GB of quota and a 50 GB
/// pack refunded in full; the use learned was 45 GB, 10 GB of it REALITY
/// downlink on lon1, so the pack kept 5 GB. The report has lon1 at 13 GB:
/// the 3 GB more count as used of the pack, and the quota is 48 GB.
/// Without a report it is the 45 GB that was learned.
#[test]
fn the_quota_counts_what_a_node_counted_since_a_refunded_packs_use_was_learned() {
    const GB: u64 = 1_000_000_000;
    let deployment = pilots(|_| {});
    let hours_before = |hours: u64| UnixTime::from_secs(GENERATED_AT.as_secs() - hours * 3600);
    let pack = Terms::pack("aaaaaaaaaaaaaaaaaaaa", "pilotusera");
    let mut refund = pack.refund(2, 800, true);
    refund["recorded_at"] = json!(hours_before(2).as_secs());
    let ledger = PaymentLedger::new()
        .apply(
            &live(0, vec![pack.grant(1)]),
            deployment.users(),
            hours_before(3),
            false,
        )
        .unwrap()
        .ledger
        .apply(
            &live(1, vec![refund]),
            deployment.users(),
            hours_before(2),
            false,
        )
        .unwrap()
        .ledger;
    let told = Told {
        served: Some(ServedBefore {
            bytes: 45 * GB,
            reality_downlink: BTreeMap::from([(node("lon1"), 10 * GB), (node("ams1"), 0)]),
        }),
        ..Told::default()
    };
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), hours_before(1)).unwrap();
    let paid = ledger
        .settle(hours_before(1), cycle, &told)
        .unwrap()
        .ledger
        .entitlements(false);
    let mut report = pilot_report(&deployment);
    report
        .cycle_reality_downlink
        .insert(id("pilotusera"), BTreeMap::from([(node("lon1"), 13 * GB)]));
    let quota_of = |report: Option<&UsageReport>| {
        let made = snapshot(
            &deployment,
            report,
            &paid,
            &ids(&["pilotusera"]),
            GENERATED_AT,
            open(),
        )
        .unwrap();
        parsed(&made)["users"][0]["quota"]["cycle_served_bytes"].clone()
    };
    assert_eq!(quota_of(Some(&report)), json!(48 * GB));
    assert_eq!(quota_of(None), json!(45 * GB));
}
