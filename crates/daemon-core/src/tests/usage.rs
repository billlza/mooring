// SPDX-License-Identifier: GPL-3.0-or-later

//! Usage aggregation and activity.

use std::collections::BTreeMap;

use mooring_agent_proto::{
    Inbound, OpaqueUserId, Principal, Resolution, StatsEmail, StatusV1, Traffic,
};
use mooring_model::node::NodeLifecycle;
use mooring_model::user::{SuspendReason, UserStatus};
use mooring_model::{ModelError, NodeId, UnixTime, UserId};
use proptest::prelude::*;

use super::support::{
    at, date, deployment_billed_on, edited, email, node, probe, series, status, traffic, user_ids,
    users,
};
use crate::error::{FigureError, FigureErrorKind, UsageError, UsageErrorKind};
use crate::share::BasisPoints;
use crate::usage::{
    ACCOUNTING_FRESH_SECS, ActiveNow, CycleShares, LedgerEnd, LedgerStart, LifetimeBase,
    NodeLedger, ProtocolTraffic, STATUS_FRESH_SECS, UsageAccuracy, UserUsage, activity, aggregate,
};

const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

/// A ledger continued from a base at `as_of` holding `totals`.
fn continued(as_of: UnixTime, totals: Vec<(StatsEmail, Traffic)>) -> LedgerStart {
    LedgerStart::Continued(LifetimeBase {
        as_of,
        totals: totals.into_iter().collect(),
    })
}

/// A node first served at `at` that has counted nothing since.
fn nothing(id: &str, at: UnixTime) -> NodeLedger {
    NodeLedger::new(
        node(id),
        LedgerStart::FirstServed { at },
        Vec::new(),
        LedgerEnd::Open,
    )
    .unwrap()
}

/// `ledgers` with an empty ledger, first served at `through`, for each
/// fixture node they leave out.
fn covered(ledgers: &[NodeLedger], through: UnixTime) -> Vec<NodeLedger> {
    let mut all = ledgers.to_vec();
    for id in ["lon1", "ams1"] {
        if !ledgers.iter().any(|ledger| *ledger.node() == node(id)) {
            all.push(nothing(id, through));
        }
    }
    all
}

/// lon1's ledger in the worked example: a base to 1 September, day bins to
/// 6 October, hour bins to 10:00 on 8 October.
fn lon1(u1: &UserId, u2: &UserId, u3: &UserId) -> NodeLedger {
    NodeLedger::new(
        node("lon1"),
        continued(
            at("2026-09-01", 0),
            vec![
                (email(u1, Inbound::Reality), traffic(1000, 2000)),
                (probe(Inbound::Hy2), traffic(5, 5)),
            ],
        ),
        vec![
            series(
                at("2026-09-01", 0),
                at("2026-10-06", 0),
                Resolution::Day,
                vec![
                    (
                        at("2026-09-10", 0),
                        vec![(email(u1, Inbound::Reality), traffic(10, 20))],
                    ),
                    (
                        at("2026-09-25", 0),
                        vec![
                            (email(u1, Inbound::Reality), traffic(100, 200)),
                            (email(u2, Inbound::Hy2), traffic(1, 1)),
                        ],
                    ),
                    (
                        at("2026-10-03", 0),
                        vec![
                            (email(u1, Inbound::Hy2), traffic(30, 40)),
                            (probe(Inbound::Reality), traffic(7, 8)),
                        ],
                    ),
                ],
            ),
            series(
                at("2026-10-06", 0),
                at("2026-10-08", 10 * HOUR),
                Resolution::Hour,
                vec![
                    (
                        at("2026-10-07", 23 * HOUR),
                        vec![(email(u1, Inbound::Reality), traffic(1, 1))],
                    ),
                    (
                        at("2026-10-08", 3 * HOUR),
                        vec![
                            (email(u1, Inbound::Reality), traffic(5, 6)),
                            (email(u3, Inbound::Reality), traffic(9, 9)),
                        ],
                    ),
                ],
            ),
        ],
        LedgerEnd::Open,
    )
    .unwrap()
}

/// ams1, retired at the end of September: its ledger is final.
fn ams1(u1: &UserId) -> NodeLedger {
    NodeLedger::new(
        node("ams1"),
        continued(at("2026-09-01", 0), Vec::new()),
        vec![series(
            at("2026-09-01", 0),
            at("2026-09-30", 0),
            Resolution::Day,
            vec![(
                at("2026-09-22", 0),
                vec![(email(u1, Inbound::Hy2), traffic(50, 60))],
            )],
        )],
        LedgerEnd::Final,
    )
    .unwrap()
}

#[test]
fn each_period_counts_exactly_the_bins_that_start_in_it() {
    let ids = user_ids();
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let through = at("2026-10-08", 10 * HOUR);
    let report = aggregate(
        &deployment_billed_on(20),
        &[lon1(u1, u2, u3), ams1(u1)],
        through,
    )
    .unwrap();
    assert_eq!(report.periods.through, through);
    assert_eq!(report.periods.utc_day, date("2026-10-08"));
    assert_eq!(report.periods.cycle.start(), date("2026-09-20"));
    assert_eq!(report.periods.utc_month_start, date("2026-10-01"));

    let first = &report.users[u1];
    assert_eq!(first.lifetime(), traffic(1196, 2327));
    assert_eq!(first.cycle(), traffic(186, 307));
    assert_eq!(first.month(), traffic(36, 47));
    assert_eq!(first.today(), traffic(5, 6));
    assert_eq!(first.cycle_served_bytes(), 493);
    assert_eq!(
        *first.cycle_by_node(),
        BTreeMap::from([
            (node("ams1"), traffic(50, 60)),
            (node("lon1"), traffic(136, 247))
        ])
    );
    assert_eq!(
        first.cycle_by_protocol(),
        ProtocolTraffic {
            reality: traffic(106, 207),
            hy2: traffic(80, 100)
        }
    );
    let shares = first.cycle_shares().unwrap();
    let points = |share: BasisPoints| share.get();
    assert_eq!(points(shares.by_node()[&node("lon1")]), 7769);
    assert_eq!(points(shares.by_node()[&node("ams1")]), 2231);
    assert_eq!(points(shares.by_protocol().reality), 6349);
    assert_eq!(points(shares.by_protocol().hy2), 3651);

    let second = &report.users[u2];
    assert_eq!(second.lifetime(), traffic(1, 1));
    assert_eq!(second.cycle(), traffic(1, 1));
    assert_eq!(second.month(), Traffic::default());
    assert_eq!(second.today(), Traffic::default());
    assert_eq!(
        points(second.cycle_shares().unwrap().by_protocol().hy2),
        10_000
    );

    let third = &report.users[u3];
    for period in [
        third.today(),
        third.month(),
        third.cycle(),
        third.lifetime(),
    ] {
        assert_eq!(period, traffic(9, 9));
    }
    // The probe's cycle traffic is kept apart; its base is not a period.
    assert_eq!(
        report.probe_cycle,
        BTreeMap::from([(
            node("lon1"),
            ProtocolTraffic {
                reality: traffic(7, 8),
                hy2: Traffic::default()
            }
        )])
    );
    // The quota input is the cycle's served bytes per user.
    let cycle = report.cycle_usage();
    assert_eq!(cycle.cycle, report.periods.cycle);
    assert_eq!(cycle.through, through);
    assert_eq!(cycle.served[u1], 493);
    assert_eq!(cycle.served[u3], 18);
}

#[test]
fn a_user_without_traffic_has_a_zero_row_and_no_shares() {
    let ids = user_ids();
    let through = at("2026-10-08", 0);
    let report = aggregate(
        &deployment_billed_on(1),
        &covered(
            &[NodeLedger::new(
                node("lon1"),
                continued(at("2026-10-01", 0), Vec::new()),
                vec![series(
                    at("2026-10-01", 0),
                    through,
                    Resolution::Day,
                    vec![(
                        at("2026-10-02", 0),
                        vec![(email(&ids[0], Inbound::Hy2), traffic(1, 0))],
                    )],
                )],
                LedgerEnd::Open,
            )
            .unwrap()],
            through,
        ),
        through,
    )
    .unwrap();
    assert_eq!(report.users.len(), 3);
    let idle = &report.users[&ids[1]];
    assert_eq!(idle.lifetime(), Traffic::default());
    assert_eq!(idle.cycle_served_bytes(), 0);
    assert_eq!(idle.cycle_shares(), None);
    // At midnight, today has no time in it yet.
    assert_eq!(report.users[&ids[0]].today(), Traffic::default());
    assert_eq!(report.users[&ids[0]].cycle(), traffic(1, 0));
}

#[test]
fn ledgers_must_be_contiguous_from_their_base() {
    let ids = user_ids();
    let base = |as_of| continued(as_of, Vec::new());
    let day = |from, to| series(from, to, Resolution::Day, Vec::new());
    assert_eq!(
        NodeLedger::new(
            node("lon1"),
            base(at("2026-09-01", 0)),
            vec![day(at("2026-09-02", 0), at("2026-09-05", 0))],
            LedgerEnd::Open
        ),
        Err(UsageError::LedgerGap {
            node: node("lon1"),
            expected: at("2026-09-01", 0),
            found: at("2026-09-02", 0)
        })
    );
    assert_eq!(
        NodeLedger::new(
            node("lon1"),
            base(at("2026-09-01", 0)),
            vec![
                day(at("2026-09-01", 0), at("2026-09-05", 0)),
                day(at("2026-09-04", 0), at("2026-09-08", 0))
            ],
            LedgerEnd::Open
        ),
        Err(UsageError::LedgerGap {
            node: node("lon1"),
            expected: at("2026-09-05", 0),
            found: at("2026-09-04", 0)
        })
    );
    let ledger = NodeLedger::new(
        node("lon1"),
        base(at("2026-09-01", 0)),
        vec![
            day(at("2026-09-01", 0), at("2026-09-05", 0)),
            series(
                at("2026-09-05", 0),
                at("2026-09-05", 2 * HOUR),
                Resolution::Hour,
                Vec::new(),
            ),
        ],
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(ledger.covered_from(), at("2026-09-01", 0));
    assert_eq!(ledger.covered_to(), at("2026-09-05", 2 * HOUR));
    let empty = NodeLedger::new(
        node("lon1"),
        base(at("2026-09-01", 0)),
        Vec::new(),
        LedgerEnd::Final,
    )
    .unwrap();
    assert_eq!(empty.covered_to(), at("2026-09-01", 0));
    // An empty final ledger from before the periods counts as nothing.
    let through = at("2026-10-08", 0);
    let report = aggregate(
        &deployment_billed_on(20),
        &covered(&[empty], through),
        through,
    )
    .unwrap();
    assert_eq!(report.users[&ids[0]].lifetime(), Traffic::default());
    // A retired node whose whole history was folded into its base still
    // counts toward the lifetime, and toward no period.
    let folded = NodeLedger::new(
        node("lon1"),
        continued(
            at("2026-09-01", 0),
            vec![(email(&ids[0], Inbound::Reality), traffic(3, 4))],
        ),
        Vec::new(),
        LedgerEnd::Final,
    )
    .unwrap();
    let report = aggregate(
        &deployment_billed_on(20),
        &covered(&[folded], through),
        through,
    )
    .unwrap();
    assert_eq!(report.users[&ids[0]].lifetime(), traffic(3, 4));
    assert_eq!(report.users[&ids[0]].cycle(), Traffic::default());
}

/// Every refusal, each with the node and instants at fault.
#[test]
fn aggregation_refuses_what_it_cannot_count_exactly() {
    let ids = user_ids();
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let through = at("2026-10-08", 10 * HOUR);
    let refuse = |ledgers: &[NodeLedger], day: u8, through: UnixTime| {
        aggregate(
            &deployment_billed_on(day),
            &covered(ledgers, through),
            through,
        )
        .unwrap_err()
    };
    assert_eq!(
        refuse(&[lon1(u1, u2, u3), lon1(u1, u2, u3)], 20, through),
        UsageError::DuplicateLedger { node: node("lon1") }
    );
    // Bins from 2 October cannot give the cycle from 1 October.
    let late = NodeLedger::new(
        node("lon1"),
        continued(at("2026-10-02", 0), Vec::new()),
        vec![series(
            at("2026-10-02", 0),
            at("2026-10-09", 0),
            Resolution::Day,
            Vec::new(),
        )],
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(
        refuse(&[late], 1, through),
        UsageError::PeriodBeforeLedger {
            node: node("lon1"),
            period_start: at("2026-10-01", 0),
            ledger_from: at("2026-10-02", 0)
        }
    );
    // An open ledger must reach the end; a final one need not.
    let later = at("2026-10-08", 11 * HOUR);
    assert_eq!(
        refuse(&[lon1(u1, u2, u3)], 20, later),
        UsageError::NotCoveredThrough {
            node: node("lon1"),
            covered_to: through,
            through: later
        }
    );
    let retired = ams1(u1);
    let open_ams1 = NodeLedger::new(
        node("ams1"),
        retired.start().clone(),
        retired.series().to_vec(),
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(
        refuse(&[open_ams1], 20, through),
        UsageError::NotCoveredThrough {
            node: node("ams1"),
            covered_to: at("2026-09-30", 0),
            through
        }
    );
    // 03:30 cuts the 03:00 hour bin.
    let half = at("2026-10-08", 3 * HOUR + 1800);
    assert_eq!(
        refuse(&[lon1(u1, u2, u3)], 20, half),
        UsageError::BinStraddlesThrough {
            node: node("lon1"),
            bin_start: at("2026-10-08", 3 * HOUR),
            through: half
        }
    );
    // Before any bin, nothing is counted, and an earlier end is fine.
    let early = at("2026-10-08", 3 * HOUR);
    let report = aggregate(
        &deployment_billed_on(20),
        &covered(&[lon1(u1, u2, u3)], early),
        early,
    )
    .unwrap();
    assert_eq!(report.users[u1].today(), Traffic::default());
    // Accounting names Mooring never renders.
    let stranger = StatsEmail {
        principal: Principal::User(OpaqueUserId::new("u01").unwrap()),
        inbound: Inbound::Reality,
    };
    let foreign = |email: StatsEmail| {
        NodeLedger::new(
            node("lon1"),
            continued(at("2026-09-01", 0), vec![(email, traffic(1, 1))]),
            Vec::new(),
            LedgerEnd::Final,
        )
        .unwrap()
    };
    assert_eq!(
        refuse(&[foreign(stranger.clone())], 20, through),
        UsageError::PrincipalNotAUser {
            node: node("lon1"),
            email: stranger
        }
    );
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    assert_eq!(
        refuse(&[foreign(email(&unknown, Inbound::Hy2))], 20, through),
        UsageError::UnknownUser {
            node: node("lon1"),
            user: unknown
        }
    );
    let overflow = NodeLedger::new(
        node("lon1"),
        continued(
            at("2026-09-01", 0),
            vec![(email(u1, Inbound::Reality), traffic(u64::MAX, 0))],
        ),
        vec![series(
            at("2026-09-01", 0),
            at("2026-10-01", 0),
            Resolution::Day,
            vec![(
                at("2026-09-02", 0),
                vec![(email(u1, Inbound::Reality), traffic(1, 0))],
            )],
        )],
        LedgerEnd::Final,
    )
    .unwrap();
    assert_eq!(
        refuse(&[overflow], 20, through),
        UsageError::CounterOverflow
    );
    // Both directions of one cycle may overflow only when summed.
    let wide = NodeLedger::new(
        node("lon1"),
        continued(at("2026-10-01", 0), Vec::new()),
        vec![series(
            at("2026-10-01", 0),
            at("2026-10-08", 0),
            Resolution::Day,
            vec![(
                at("2026-10-02", 0),
                vec![(email(u1, Inbound::Reality), traffic(u64::MAX, 1))],
            )],
        )],
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(
        refuse(&[wide], 1, at("2026-10-08", 0)),
        UsageError::CounterOverflow
    );
    assert_eq!(
        refuse(&[], 20, UnixTime::from_secs(DAY)),
        UsageError::Model(ModelError::InvalidDate)
    );
}

#[test]
fn every_usage_error_kind_is_named_once() {
    let ids = user_ids();
    let errors = [
        (
            UsageErrorKind::LedgerGap,
            UsageError::LedgerGap {
                node: node("lon1"),
                expected: at("2026-09-01", 0),
                found: at("2026-09-02", 0),
            },
        ),
        (
            UsageErrorKind::DuplicateLedger,
            UsageError::DuplicateLedger { node: node("lon1") },
        ),
        (
            UsageErrorKind::MissingLedger,
            UsageError::MissingLedger { node: node("ams1") },
        ),
        (
            UsageErrorKind::LedgerForUnknownNode,
            UsageError::LedgerForUnknownNode { node: node("par1") },
        ),
        (
            UsageErrorKind::PeriodBeforeLedger,
            UsageError::PeriodBeforeLedger {
                node: node("lon1"),
                period_start: at("2026-08-31", 0),
                ledger_from: at("2026-09-01", 0),
            },
        ),
        (
            UsageErrorKind::NotCoveredThrough,
            UsageError::NotCoveredThrough {
                node: node("lon1"),
                covered_to: at("2026-09-01", 0),
                through: at("2026-09-02", 0),
            },
        ),
        (
            UsageErrorKind::BinStraddlesThrough,
            UsageError::BinStraddlesThrough {
                node: node("lon1"),
                bin_start: at("2026-09-01", 0),
                through: at("2026-09-01", 60),
            },
        ),
        (
            UsageErrorKind::PrincipalNotAUser,
            UsageError::PrincipalNotAUser {
                node: node("lon1"),
                email: "u01@hy2".parse().unwrap(),
            },
        ),
        (
            UsageErrorKind::UnknownUser,
            UsageError::UnknownUser {
                node: node("lon1"),
                user: ids[0].clone(),
            },
        ),
        (UsageErrorKind::CounterOverflow, UsageError::CounterOverflow),
        (
            UsageErrorKind::Model,
            UsageError::Model(ModelError::InvalidDate),
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        UsageErrorKind::ALL
    );
    assert_eq!(
        serde_json::to_string(&UsageErrorKind::NotCoveredThrough).unwrap(),
        "\"NotCoveredThrough\""
    );
}

/// Every node that may have counted traffic needs a ledger, retired ones
/// included, so a node left out is refused instead of reading as zero
/// usage (and zero quotas); a planned node needs none, and a ledger for a
/// node the deployment does not hold is refused.
#[test]
fn every_node_that_may_have_counted_traffic_needs_a_ledger() {
    let ids = user_ids();
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let through = at("2026-10-08", 10 * HOUR);
    let deployment = deployment_billed_on(20);
    assert_eq!(
        aggregate(&deployment, &[], through),
        Err(UsageError::MissingLedger { node: node("ams1") })
    );
    assert_eq!(
        aggregate(&deployment, &[lon1(u1, u2, u3)], through),
        Err(UsageError::MissingLedger { node: node("ams1") })
    );
    assert_eq!(
        aggregate(&deployment, &[ams1(u1)], through),
        Err(UsageError::MissingLedger { node: node("lon1") })
    );
    assert_eq!(
        aggregate(
            &deployment,
            &[lon1(u1, u2, u3), ams1(u1), nothing("par1", through)],
            through
        ),
        Err(UsageError::LedgerForUnknownNode { node: node("par1") })
    );
    // A retired node still needs its (final) ledger.
    let retired = edited(|parts| {
        for user in &mut parts.users {
            user.per_node.remove(&node("ams1"));
        }
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Retired;
    });
    assert_eq!(
        aggregate(&retired, &[lon1(u1, u2, u3)], through),
        Err(UsageError::MissingLedger { node: node("ams1") })
    );
    assert!(aggregate(&retired, &[lon1(u1, u2, u3), ams1(u1)], through).is_ok());
    // A planned node has counted nothing and needs none.
    let planned = edited(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
    });
    let report = aggregate(&planned, &[lon1(u1, u2, u3)], through).unwrap();
    assert_eq!(report.users[u1].cycle_by_node().len(), 1);
}

/// A node first served during a period is covered from then: nothing was
/// counted on it before, so the periods that started earlier still add
/// up, where a continued ledger with no bins for them is refused.
#[test]
fn a_node_first_served_mid_period_is_covered_from_then() {
    let ids = user_ids();
    let u1 = &ids[0];
    let through = at("2026-10-08", 0);
    let served = at("2026-10-05", 0);
    let bins = || {
        vec![series(
            served,
            through,
            Resolution::Day,
            vec![(
                at("2026-10-06", 0),
                vec![(email(u1, Inbound::Hy2), traffic(4, 6))],
            )],
        )]
    };
    let ams1 = NodeLedger::new(
        node("ams1"),
        LedgerStart::FirstServed { at: served },
        bins(),
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(ams1.covered_from(), served);
    let deployment = deployment_billed_on(1);
    let lon1 = NodeLedger::new(
        node("lon1"),
        continued(at("2026-09-01", 0), Vec::new()),
        vec![
            series(
                at("2026-09-01", 0),
                at("2026-10-01", 0),
                Resolution::Day,
                Vec::new(),
            ),
            series(at("2026-10-01", 0), through, Resolution::Day, Vec::new()),
        ],
        LedgerEnd::Open,
    )
    .unwrap();
    let report = aggregate(&deployment, &[lon1.clone(), ams1], through).unwrap();
    let row = &report.users[u1];
    assert_eq!(row.cycle(), traffic(4, 6));
    assert_eq!(row.month(), traffic(4, 6));
    assert_eq!(row.lifetime(), traffic(4, 6));
    assert_eq!(
        *row.cycle_by_node(),
        BTreeMap::from([(node("ams1"), traffic(4, 6))])
    );
    // The same bins as a continuation would hide what came before them.
    let continued_late = NodeLedger::new(
        node("ams1"),
        continued(served, Vec::new()),
        bins(),
        LedgerEnd::Open,
    )
    .unwrap();
    assert_eq!(
        aggregate(&deployment, &[lon1, continued_late], through),
        Err(UsageError::PeriodBeforeLedger {
            node: node("ams1"),
            period_start: at("2026-10-01", 0),
            ledger_from: served
        })
    );
}

/// A decoded usage row is checked as the aggregation built it: the
/// cycle's splits add up to the cycle, and the served bytes and shares are
/// the ones the figures give; a share is at most the whole and each set of
/// shares adds up to it.
#[test]
fn decoded_usage_figures_must_agree_with_the_cycle() {
    let ids = user_ids();
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let report = aggregate(
        &deployment_billed_on(20),
        &[lon1(u1, u2, u3), ams1(u1)],
        at("2026-10-08", 10 * HOUR),
    )
    .unwrap();
    let row = &report.users[u1];
    let json = serde_json::to_string(row).unwrap();
    assert_eq!(&serde_json::from_str::<UserUsage>(&json).unwrap(), row);
    let refused = |text: String| {
        assert_ne!(text, json);
        serde_json::from_str::<UserUsage>(&text)
            .unwrap_err()
            .to_string()
    };
    // The figures as `each_period_counts_exactly_the_bins_that_start_in_it`
    // pins them: cycle 186 up and 307 down, 493 served.
    assert!(json.contains(r#""cycle_served_bytes":493"#), "{json}");
    assert!(
        refused(json.replace(r#""cycle_served_bytes":493"#, r#""cycle_served_bytes":492"#))
            .contains(&FigureError::DerivedMismatch.to_string())
    );
    assert!(
        refused(
            json.replace(r#""lon1":7769"#, r#""lon1":7768"#)
                .replace(r#""ams1":2231"#, r#""ams1":2232"#)
        )
        .contains(&FigureError::DerivedMismatch.to_string())
    );
    assert!(
        refused(json.replace(r#""lon1":7769"#, r#""lon1":7770"#))
            .contains(&FigureError::SharesNotWhole { sum: 10_001 }.to_string())
    );
    assert!(
        refused(json.replace(r#""reality":6349"#, r#""reality":60000"#))
            .contains(&FigureError::ShareAboveWhole { points: 60_000 }.to_string())
    );
    assert!(
        refused(json.replace(r#""cycle":{"uplink":186"#, r#""cycle":{"uplink":187"#))
            .contains(&FigureError::SplitMismatch.to_string())
    );
    assert!(
        refused(json.replacen(r#""ams1":{"uplink":50"#, r#""ams1":{"uplink":51"#, 1))
            .contains(&FigureError::SplitMismatch.to_string())
    );
    // A row with no cycle traffic has no shares, and may not claim any:
    // with bill day 1, u2's only traffic (25 September) is before the cycle.
    let october = aggregate(
        &deployment_billed_on(1),
        &[lon1(u1, u2, u3), ams1(u1)],
        at("2026-10-08", 10 * HOUR),
    )
    .unwrap();
    let idle = serde_json::to_string(&october.users[u2]).unwrap();
    assert!(idle.contains(r#""cycle_shares":null"#), "{idle}");
    let shares = serde_json::to_string(row.cycle_shares().unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<CycleShares>(&shares).unwrap(),
        *row.cycle_shares().unwrap()
    );
    let claimed = idle.replace(
        r#""cycle_shares":null"#,
        &format!(r#""cycle_shares":{shares}"#),
    );
    assert!(serde_json::from_str::<UserUsage>(&claimed).is_err());
    // Every kind, with its message.
    let errors = [
        (
            FigureErrorKind::ShareAboveWhole,
            FigureError::ShareAboveWhole { points: 10_001 },
        ),
        (
            FigureErrorKind::SharesNotWhole,
            FigureError::SharesNotWhole { sum: 9_999 },
        ),
        (FigureErrorKind::SplitMismatch, FigureError::SplitMismatch),
        (
            FigureErrorKind::DerivedMismatch,
            FigureError::DerivedMismatch,
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        FigureErrorKind::ALL
    );
}

#[test]
fn activity_comes_from_the_latest_accounting_poll() {
    let ids = user_ids();
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let now = at("2026-10-08", 10 * HOUR);
    let tick = UnixTime::from_secs(now.as_secs() - 30);
    let statuses = BTreeMap::from([
        (
            node("lon1"),
            status(
                now,
                Some(tick),
                vec![
                    (email(u1, Inbound::Reality), tick),
                    (
                        email(u1, Inbound::Hy2),
                        UnixTime::from_secs(tick.as_secs() - 600),
                    ),
                    (
                        email(u2, Inbound::Hy2),
                        UnixTime::from_secs(tick.as_secs() - HOUR),
                    ),
                    (probe(Inbound::Reality), tick),
                ],
            ),
        ),
        (
            node("ams1"),
            status(
                now,
                None,
                vec![(
                    email(u2, Inbound::Reality),
                    UnixTime::from_secs(tick.as_secs() - 100),
                )],
            ),
        ),
    ]);
    let rows = activity(&users(), &statuses, now).unwrap();
    assert_eq!(rows[u1].active_now, ActiveNow::Active);
    assert_eq!(rows[u1].last_seen, Some(tick));
    assert_eq!(rows[u1].by_node[&node("lon1")].reality, Some(tick));
    assert_eq!(
        rows[u1].by_node[&node("lon1")].hy2,
        Some(UnixTime::from_secs(tick.as_secs() - 600))
    );
    // Growth at an older poll is not "now", and ams1 has no accounting
    // poll, so whether u2 and u3 are active there is unknown.
    assert_eq!(rows[u2].active_now, ActiveNow::Unknown);
    assert_eq!(
        rows[u2].last_seen,
        Some(UnixTime::from_secs(tick.as_secs() - 100))
    );
    assert_eq!(rows[u2].by_node.len(), 2);
    assert_eq!(rows[u3].active_now, ActiveNow::Unknown);
    assert_eq!(rows[u3].last_seen, None);
    assert!(rows[u3].by_node.is_empty());
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    let foreign = BTreeMap::from([(
        node("lon1"),
        status(now, Some(tick), vec![(email(&unknown, Inbound::Hy2), tick)]),
    )]);
    assert_eq!(
        activity(&users(), &foreign, now).unwrap_err(),
        UsageError::UnknownUser {
            node: node("lon1"),
            user: unknown
        }
    );
}

/// "Active now" is read only from fresh evidence. A user is active when
/// their counters grew at a node's latest accounting poll, that poll is at
/// most two accounting intervals older than the node's status (the stats
/// query works), and the status is at most `STATUS_FRESH_SECS` older than
/// the Mac's clock. A user is idle only when every node serving them has
/// such a poll showing no growth; anything less is unknown, never idle and
/// never active.
#[test]
fn active_now_needs_fresh_accounting_on_every_node_serving_the_user() {
    let ids = user_ids();
    let (u1, u2) = (&ids[0], &ids[1]);
    let now = at("2026-10-08", 10 * HOUR);
    let before = |secs: u64| UnixTime::from_secs(now.as_secs() - secs);
    let fresh = |node_now: UnixTime, grew: Vec<(StatsEmail, UnixTime)>| {
        status(
            node_now,
            Some(UnixTime::from_secs(node_now.as_secs() - 30)),
            grew,
        )
    };
    let tick = before(30);
    let both = |lon1: StatusV1, ams1: StatusV1| {
        BTreeMap::from([(node("lon1"), lon1), (node("ams1"), ams1)])
    };
    // Fresh everywhere: u1 grew on lon1, u2 grew nowhere.
    let rows = activity(
        &users(),
        &both(
            fresh(now, vec![(email(u1, Inbound::Reality), tick)]),
            fresh(now, Vec::new()),
        ),
        now,
    )
    .unwrap();
    assert_eq!(rows[u1].active_now, ActiveNow::Active);
    assert_eq!(rows[u2].active_now, ActiveNow::Idle);
    // The stats query has failed for three hours on lon1: its latest
    // successful poll is old, so growth recorded there is not "now".
    let stale_poll = before(3 * HOUR);
    let failing = status(
        now,
        Some(stale_poll),
        vec![(email(u1, Inbound::Reality), stale_poll)],
    );
    let rows = activity(
        &users(),
        &both(failing.clone(), fresh(now, Vec::new())),
        now,
    )
    .unwrap();
    assert_eq!(rows[u1].active_now, ActiveNow::Unknown);
    assert_eq!(rows[u1].last_seen, Some(stale_poll));
    assert_eq!(rows[u2].active_now, ActiveNow::Unknown);
    // Exactly two accounting intervals is still fresh; one second more is
    // not.
    let edge = |age: u64| {
        let polled = UnixTime::from_secs(now.as_secs() - age);
        let lon1 = status(
            now,
            Some(polled),
            vec![(email(u1, Inbound::Reality), polled)],
        );
        activity(&users(), &both(lon1, fresh(now, Vec::new())), now).unwrap()[u1].active_now
    };
    assert_eq!(edge(ACCOUNTING_FRESH_SECS), ActiveNow::Active);
    assert_eq!(edge(ACCOUNTING_FRESH_SECS + 1), ActiveNow::Unknown);
    // A status the Mac received long ago (the node stopped answering) is
    // not "now" either, however fresh it was then.
    let old = before(STATUS_FRESH_SECS + 1);
    let rows = activity(
        &users(),
        &both(
            fresh(
                old,
                vec![(
                    email(u1, Inbound::Reality),
                    UnixTime::from_secs(old.as_secs() - 30),
                )],
            ),
            fresh(now, Vec::new()),
        ),
        now,
    )
    .unwrap();
    assert_eq!(rows[u1].active_now, ActiveNow::Unknown);
    let recent = before(STATUS_FRESH_SECS);
    let rows = activity(
        &users(),
        &both(
            fresh(
                recent,
                vec![(
                    email(u1, Inbound::Reality),
                    UnixTime::from_secs(recent.as_secs() - 30),
                )],
            ),
            fresh(now, Vec::new()),
        ),
        now,
    )
    .unwrap();
    assert_eq!(rows[u1].active_now, ActiveNow::Active);
    // A node serving the user has no status at all: unknown.
    let only_lon1 = BTreeMap::from([(node("lon1"), fresh(now, Vec::new()))]);
    let rows = activity(&users(), &only_lon1, now).unwrap();
    assert_eq!(rows[u2].active_now, ActiveNow::Unknown);
    // A user served nowhere (suspended) is idle without any status.
    let mut users = users();
    users
        .get_mut(u2)
        .unwrap()
        .suspend(SuspendReason::Operator, at("2026-10-01", 0))
        .unwrap();
    let rows = activity(&users, &BTreeMap::new(), now).unwrap();
    assert_eq!(rows[u2].active_now, ActiveNow::Idle);
    assert_eq!(rows[u1].active_now, ActiveNow::Unknown);
    assert_eq!(
        serde_json::to_string(&ActiveNow::Unknown).unwrap(),
        "\"unknown\""
    );
}

#[test]
fn the_reality_caveat_marks_exactly_the_served_users() {
    let mut users = users();
    let mut rows = users.values_mut();
    let served = rows.next().unwrap();
    assert!(UsageAccuracy::of(served).reality_downlink_counted_at_close);
    let suspended = rows.next().unwrap();
    suspended
        .suspend(SuspendReason::Operator, at("2026-10-01", 0))
        .unwrap();
    assert!(!UsageAccuracy::of(suspended).reality_downlink_counted_at_close);
    let revoked = rows.next().unwrap();
    revoked.status = UserStatus::Revoked;
    assert!(!UsageAccuracy::of(revoked).reality_downlink_counted_at_close);
    revoked.status = UserStatus::Active;
    revoked.per_node.clear();
    assert!(!UsageAccuracy::of(revoked).reality_downlink_counted_at_close);
}

/// One bin entry in the property test: (bin index, user 0..3 or 3 for the
/// probe, REALITY or not, up, down).
type Entry = (usize, usize, bool, u64, u64);

fn entries(bins: usize) -> impl Strategy<Value = Vec<Entry>> {
    proptest::collection::vec(
        (
            0..bins,
            0_usize..4,
            any::<bool>(),
            1_u64..1_000_000,
            0_u64..1_000_000,
        ),
        0..40,
    )
}

/// Builds the bins of one reply from entries, summing repeats.
fn bins(
    first: UnixTime,
    width: u64,
    entries: &[Entry],
    ids: &[UserId],
) -> Vec<(UnixTime, Vec<(StatsEmail, Traffic)>)> {
    let mut by_bin: BTreeMap<usize, BTreeMap<StatsEmail, Traffic>> = BTreeMap::new();
    for &(index, who, reality, up, down) in entries {
        let inbound = if reality {
            Inbound::Reality
        } else {
            Inbound::Hy2
        };
        let email = if who == 3 {
            probe(inbound)
        } else {
            email(&ids[who], inbound)
        };
        let total = by_bin.entry(index).or_default().entry(email).or_default();
        total.uplink += up;
        total.downlink += down;
    }
    by_bin
        .into_iter()
        .map(|(index, traffic)| {
            (
                UnixTime::from_secs(first.as_secs() + index as u64 * width),
                traffic.into_iter().collect(),
            )
        })
        .collect()
}

fn sum(
    entries: &[(NodeId, UnixTime, StatsEmail, Traffic)],
    user: &UserId,
    from: UnixTime,
    to: UnixTime,
) -> Traffic {
    let mut total = Traffic::default();
    for (_, start, email, traffic) in entries {
        let mine = email.principal == Principal::User(OpaqueUserId::new(user.as_str()).unwrap());
        if mine && from <= *start && *start < to {
            total.uplink += traffic.uplink;
            total.downlink += traffic.downlink;
        }
    }
    total
}

proptest! {
    /// Against a brute-force sum over every recorded entry: each period of
    /// each user equals the entries that start in it, the cycle splits
    /// exactly by node and by protocol, and the shares add up.
    #[test]
    fn periods_equal_the_entries_that_start_in_them(
        day in 1_u8..=31,
        hours in 1_u64..=24,
        day_entries in entries(30),
        week_entries in entries(168),
        last_entries in entries(24),
        ams_entries in entries(168),
    ) {
        let ids = user_ids();
        let through = at("2026-10-08", hours * HOUR);
        let lon1 = NodeLedger::new(
            node("lon1"),
            continued(at("2026-09-01", 0), Vec::new()),
            vec![
                series(at("2026-09-01", 0), at("2026-10-01", 0), Resolution::Day, bins(at("2026-09-01", 0), DAY, &day_entries, &ids)),
                series(at("2026-10-01", 0), at("2026-10-08", 0), Resolution::Hour, bins(at("2026-10-01", 0), HOUR, &week_entries, &ids)),
                series(
                    at("2026-10-08", 0),
                    at("2026-10-09", 0),
                    Resolution::Hour,
                    bins(at("2026-10-08", 0), HOUR, &last_entries, &ids),
                ),
            ],
            LedgerEnd::Open,
        ).unwrap();
        let ams1 = NodeLedger::new(
            node("ams1"),
            continued(at("2026-09-01", 0), Vec::new()),
            vec![
                series(at("2026-09-01", 0), at("2026-10-01", 0), Resolution::Day, Vec::new()),
                series(at("2026-10-01", 0), at("2026-10-08", 0), Resolution::Hour, bins(at("2026-10-01", 0), HOUR, &ams_entries, &ids)),
                series(at("2026-10-08", 0), at("2026-10-09", 0), Resolution::Hour, Vec::new()),
            ],
            LedgerEnd::Open,
        ).unwrap();
        let mut recorded = Vec::new();
        for ledger in [&lon1, &ams1] {
            for reply in ledger.series() {
                for bin in reply.bins() {
                    for (email, traffic) in bin.traffic() {
                        recorded.push((ledger.node().clone(), UnixTime::from_secs(bin.start().as_secs()), email.clone(), *traffic));
                    }
                }
            }
        }
        let report = aggregate(&deployment_billed_on(day), &[lon1, ams1], through).unwrap();
        let periods = report.periods;
        for user in &ids {
            let row = &report.users[user];
            prop_assert_eq!(row.lifetime(), sum(&recorded, user, UnixTime::from_secs(0), through));
            prop_assert_eq!(row.cycle(), sum(&recorded, user, periods.cycle.starts_at(), through));
            prop_assert_eq!(row.month(), sum(&recorded, user, periods.utc_month_start.utc_start(), through));
            prop_assert_eq!(row.today(), sum(&recorded, user, periods.utc_day.utc_start(), through));
            let mut by_node = Traffic::default();
            for traffic in row.cycle_by_node().values() {
                by_node.uplink += traffic.uplink;
                by_node.downlink += traffic.downlink;
            }
            prop_assert_eq!(by_node, row.cycle());
            let protocols = row.cycle_by_protocol();
            prop_assert_eq!(
                traffic(protocols.reality.uplink + protocols.hy2.uplink, protocols.reality.downlink + protocols.hy2.downlink),
                row.cycle()
            );
            prop_assert_eq!(row.cycle_served_bytes(), row.cycle().uplink + row.cycle().downlink);
            match row.cycle_shares() {
                None => prop_assert_eq!(row.cycle_served_bytes(), 0),
                Some(shares) => {
                    prop_assert_eq!(shares.by_node().values().map(|share| u32::from(share.get())).sum::<u32>(), 10_000);
                    prop_assert_eq!(u32::from(shares.by_protocol().reality.get()) + u32::from(shares.by_protocol().hy2.get()), 10_000);
                }
            }
            // Every row decodes to itself: the figures are consistent.
            let json = serde_json::to_string(row).unwrap();
            prop_assert_eq!(&serde_json::from_str::<UserUsage>(&json).unwrap(), row);
        }
    }
}
