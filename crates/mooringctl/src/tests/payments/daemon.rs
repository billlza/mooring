// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull on the deployed daemon's tick: it asks while the Mac is
//! on no foreign network, records what it gets, and the status line shows
//! what was granted; on a foreign network it waits.

use mooring_daemon_core::payments::{OrderId, PackUse};
use mooring_daemon_core::usage::CollectedUsage;
use mooring_daemon_core::{ExpiryState, QuotaState};
use mooring_model::{NodeId, UnixTime, UserId};
use mooring_store::write_user_usage;

use super::super::deployed::{
    CARRIER, deployed, deployed_with, joined_to_the_declared_hotspot, published, shared, statuses,
    with_exit_on,
};
use super::super::portal::{collected, with_usage};
use super::super::support::{Harness, NOW};
use super::super::user::fixture;
use super::{FIRST, SECOND, connect, grant, ledger_on_disk, pack, page, refund_in_full};
use crate::daemon::Intervals;
use crate::payments::pull::Puller;

/// The deployed daemon asks the portal on a tick that leaves it room,
/// writes the ledger, and its status shows the paid expiry.
#[test]
fn the_daemon_pulls_and_its_status_shows_the_paid_time() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST)],
        false,
    ));
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
        let status = published(&control);
        let row = &status.parts().users[&UserId::parse(FIRST).unwrap()];
        assert_eq!(
            row.expiry,
            ExpiryState::Expires {
                at: UnixTime::from_secs(NOW + 30 * 86_400),
                days_left: 30
            }
        );
        String::from_utf8(log.clone()).unwrap()
    });
    assert_eq!(harness.portal.requests.borrow().len(), 1, "{log}");
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
    assert!(
        log.contains("mooringctl daemon: payment: order aaaaaaaaaaaaaaaaaaaa granted user fxuseraaab service from"),
        "{log}"
    );
}

/// On a foreign network (an own network no longer declared), the daemon
/// does not ask, and says why once.
#[test]
fn on_a_foreign_network_the_daemon_does_not_ask() {
    let mut harness = joined_to_the_declared_hotspot();
    // Withdraw the declaration: the hotspot is then foreign.
    std::fs::remove_file(
        harness
            .support_dir()
            .join(mooring_store::ALLOWED_NETWORKS_FILE),
    )
    .unwrap();
    for _ in 0..3 {
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
    }
    statuses(&harness);
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(harness.portal.requests.borrow().is_empty(), "{log}");
    assert_eq!(
        log.matches("payment pull: waiting while the Mac is on a network other than the M7 and the declared own networks")
            .count(),
        1,
        "{log}"
    );
    assert_eq!(ledger_on_disk(&harness), None);
}

/// The check made right before the payment pull's request reads the
/// network afresh: clear on the M7 with a declared own network, and not
/// once the declaration is withdrawn, configd cannot be read, or the
/// egress does not resolve.
#[test]
fn the_fresh_network_check_reads_the_network_again() {
    use mooring_macsys::{ConfigdFault, MacsysError};

    use crate::daemon::deployed::network_clear_now;

    let mut harness = joined_to_the_declared_hotspot();
    let support = harness.support_dir();
    let deployment = mooring_store::Store::new(&support)
        .load()
        .unwrap()
        .deployment;
    let exit = deployment.exit();
    assert!(network_clear_now(&harness.link, &support, exit));
    let declarations = support.join(mooring_store::ALLOWED_NETWORKS_FILE);
    let declared = std::fs::read(&declarations).unwrap();
    std::fs::remove_file(&declarations).unwrap();
    assert!(!network_clear_now(&harness.link, &support, exit));
    std::fs::write(&declarations, &declared).unwrap();
    assert!(network_clear_now(&harness.link, &support, exit));
    std::fs::write(&declarations, b"not json").unwrap();
    assert!(!network_clear_now(&harness.link, &support, exit));
    std::fs::write(&declarations, &declared).unwrap();
    harness.link.services = Err(MacsysError::Configd {
        fault: ConfigdFault::StoreUnavailable,
    });
    assert!(!network_clear_now(&harness.link, &support, exit));
    let only_m7 = deployed();
    let m7_support = only_m7.support_dir();
    let m7_deployment = mooring_store::Store::new(&m7_support)
        .load()
        .unwrap()
        .deployment;
    assert!(network_clear_now(
        &only_m7.link,
        &m7_support,
        m7_deployment.exit()
    ));
    let mut unplugged = deployed();
    unplugged.link.listed = Ok(Vec::new());
    assert!(!network_clear_now(
        &unplugged.link,
        &m7_support,
        m7_deployment.exit()
    ));
}

/// The fixture with `SECOND` revoked a day before the clock.
fn second_revoked() -> mooring_model::Deployment {
    fixture(|parts| {
        for user in &mut parts.users {
            if user.id.as_str() == SECOND {
                user.per_node.clear();
                user.status = mooring_model::UserStatus::Revoked {
                    since: UnixTime::from_secs(NOW - 86_400),
                };
            }
        }
    })
}

/// Once a user is removed (here at its request, as `user forget` does),
/// the daemon's next tick deletes its orders from the ledger, whatever the
/// pull is doing, and its log counts them without naming the user; the
/// other users' orders stay.
#[test]
fn the_daemon_deletes_a_removed_users_orders_from_the_ledger() {
    use mooring_model::Bookkeeping;
    use mooring_store::Store;

    let mut harness = deployed_with(second_revoked());
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
            grant(2, "bbbbbbbbbbbbbbbbbbbb", SECOND),
        ],
        false,
    ));
    let store = Store::new(harness.support_dir());
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
        let generation = store.load().unwrap().deployment.config_generation();
        store
            .record(
                generation,
                Bookkeeping::RevokedUserRemoved {
                    user: UserId::parse(SECOND).unwrap(),
                    at: UnixTime::from_secs(NOW),
                },
            )
            .unwrap();
        exit.tick(&control, log, false).unwrap();
        exit.tick(&control, log, false).unwrap();
        String::from_utf8(log.clone()).unwrap()
    });
    let ledger = ledger_on_disk(&harness).unwrap();
    let orders: Vec<String> = ledger.orders().keys().map(ToString::to_string).collect();
    assert_eq!(orders, ["aaaaaaaaaaaaaaaaaaaa"], "{log}");
    assert_eq!(ledger.cursor(), 2);
    let raw = std::fs::read_to_string(
        harness
            .support_dir()
            .join(mooring_store::PAYMENTS_DIRECTORY)
            .join(mooring_store::PAYMENT_LEDGER_FILE),
    )
    .unwrap();
    assert!(!raw.contains(SECOND), "{raw}");
    assert_eq!(
        log.matches("mooringctl daemon: payment ledger: deleted 1 order(s) of 1 removed user(s)")
            .count(),
        1,
        "{log}"
    );
}

/// The quota of user [`FIRST`] in [`with_a_quota`], without a pack.
const WITHOUT_PACK: u64 = 100_000_000_000;

/// A deployed daemon's harness in which user [`FIRST`] has a quota of
/// their own, so that the status shows what a pack adds to it.
fn with_a_quota() -> Harness {
    use mooring_model::{QuotaAction, UserQuota, WarnPercent};

    deployed_with(fixture(|parts| {
        let user = parts
            .users
            .iter_mut()
            .find(|candidate| candidate.id.as_str() == FIRST)
            .unwrap();
        user.policy.quota = Some(UserQuota {
            cycle_served_bytes: std::num::NonZeroU64::new(WITHOUT_PACK).unwrap(),
            warn_percent: WarnPercent::new(80).unwrap(),
            action: QuotaAction::Suspend,
        });
    }))
}

/// What the daemon collected by [`NOW`]: 70 GB served this cycle by user
/// [`FIRST`] on lon1, 20 GB of them in the five minutes that began half an
/// hour ago.
fn collected_with_detail() -> CollectedUsage {
    collected_with_detail_at(NOW)
}

/// [`collected_with_detail`], with each node's figures sampled at
/// `sampled`.
fn collected_with_detail_at(sampled: u64) -> CollectedUsage {
    use std::collections::BTreeMap;

    use mooring_agent_proto::{
        Inbound, OpaqueUserId, Principal, Resolution, SeriesRange, StatsEmail, Traffic, UsageBin,
        UsageSeriesV1,
    };

    let wire = mooring_agent_proto::UnixTime::from_secs;
    let user = UserId::parse(FIRST).unwrap();
    let lon = NodeId::parse("lon1").unwrap();
    let mut usage = collected(sampled, &user, 70_000_000_000);
    let mut history = usage.node(&lon).unwrap().clone();
    let email = StatsEmail {
        principal: Principal::User(OpaqueUserId::new(user.as_str()).unwrap()),
        inbound: Inbound::Reality,
    };
    let bin = UsageBin::new(
        wire(NOW - 1800),
        BTreeMap::from([(
            email,
            Traffic {
                uplink: 0,
                downlink: 20_000_000_000,
            },
        )]),
    )
    .unwrap();
    let range = SeriesRange::new(wire(NOW - 3600), wire(NOW), Resolution::FiveMin).unwrap();
    history
        .record_series(&lon, &UsageSeriesV1::new(range, vec![bin]).unwrap())
        .unwrap();
    usage.set_node(lon, history);
    usage
}

/// The log of a deployed daemon that pulled user [`FIRST`]'s traffic pack
/// and its refund in full, recorded at `refunded_at`, over four ticks; and
/// the quota the status then shows for the user.
fn pack_refunded_on_the_daemon(harness: &mut Harness, refunded_at: u64) -> (String, QuotaState) {
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(harness);
    connect(harness, 1, false, 1);
    let granted = pack(1, "aaaaaaaaaaaaaaaaaaaa", FIRST);
    harness.portal.ok(&page(
        true,
        0,
        vec![granted.clone(), refund_in_full(&granted, 2, refunded_at)],
        false,
    ));
    let (control, _retries) = shared();
    with_exit_on(harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
        let status = published(&control);
        let quota = status.parts().users[&UserId::parse(FIRST).unwrap()].quota;
        (String::from_utf8(log.clone()).unwrap(), quota)
    })
}

/// The use the ledger on disk records on the pack's refund.
fn recorded(harness: &Harness) -> Option<PackUse> {
    ledger_on_disk(harness).unwrap().orders()[&OrderId::parse("aaaaaaaaaaaaaaaaaaaa").unwrap()]
        .refunds[0]
        .pack_use
}

/// With the usage it collected reaching the refund's time, an hour ago,
/// the daemon records on its tick what the user had served this cycle by
/// then (design §9.6): the 70 GB served by now less the 20 GB served since
/// the refund. It logs the wait's end by the order. From then on the pack
/// counts only what the user had used of it: none, at 50 GB of 100.
#[test]
fn the_daemon_records_what_the_user_had_used_of_a_refunded_pack() {
    let mut harness = with_a_quota();
    with_usage(&harness, &collected_with_detail());
    let (log, quota) = pack_refunded_on_the_daemon(&mut harness, NOW - 3600);
    assert_eq!(
        recorded(&harness),
        Some(PackUse::Served {
            bytes: 50_000_000_000,
            learned_at: UnixTime::from_secs(NOW),
        }),
        "{log}"
    );
    for line in [
        "mooringctl daemon: payment: order aaaaaaaaaaaaaaaaaaaa refunded 800 so far, in full; it waits for the usage: its pack counts in full",
        "mooringctl daemon: payment: order aaaaaaaaaaaaaaaaaaaa's refund in full no longer waits for the usage; its pack counts from 2026-10-13 19:20:00 UTC on only what the user had used of it beyond the rest of their quota: 50000000000 bytes served this cycle by the refund's time",
    ] {
        assert_eq!(log.matches(line).count(), 1, "{line}\n{log}");
    }
    assert_eq!(
        quota,
        QuotaState::Within {
            used_bytes: 70_000_000_000,
            quota_bytes: WITHOUT_PACK
        },
        "{log}"
    );
}

/// With no usage collected, the refund goes on waiting on the daemon's
/// tick: nothing of the pack is taken back, and the user's quota holds all
/// of it. Usage that is only behind is no fault, and no line says one.
#[test]
fn without_the_usage_the_daemon_leaves_the_refund_waiting() {
    let mut harness = with_a_quota();
    let (log, quota) = pack_refunded_on_the_daemon(&mut harness, NOW);
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting), "{log}");
    assert!(!log.contains("no longer waits for the usage"), "{log}");
    assert!(!log.contains("cannot tell the use"), "{log}");
    assert_eq!(
        quota,
        QuotaState::UsageUnavailable {
            quota_bytes: WITHOUT_PACK + 50_000_000_000
        },
        "{log}"
    );
}

/// A usage store that cannot be read is a fault, not usage that is behind:
/// the daemon logs it once, by its kind and with no order or user, and the
/// refund goes on waiting.
#[test]
fn the_daemon_logs_a_fault_of_the_usage_once_and_the_refund_waits() {
    let mut harness = with_a_quota();
    write_user_usage(&harness.support_dir(), b"not a ledger").unwrap();
    let (log, _quota) = pack_refunded_on_the_daemon(&mut harness, NOW - 3600);
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting), "{log}");
    assert_eq!(
        log.matches("mooringctl daemon: payment ledger: the usage collected cannot tell the use at the refund(s) of traffic packs that wait for it (LedgerCorrupt); they wait on")
            .count(),
        1,
        "{log}"
    );
}

/// Records on disk user [`FIRST`]'s traffic pack and its refund in full,
/// recorded at `refunded_at`, as a daemon that ran before pulled them: the
/// refund waits for the usage.
fn waiting_refund_on_disk(harness: &mut Harness, refunded_at: u64) {
    connect(harness, 1, false, 1);
    let granted = pack(1, "aaaaaaaaaaaaaaaaaaaa", FIRST);
    harness.portal.ok(&page(
        true,
        0,
        vec![granted.clone(), refund_in_full(&granted, 2, refunded_at)],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    super::settle::tick(harness, &mut puller);
    assert_eq!(recorded(harness), Some(PackUse::Awaiting));
}

/// A refund that waits is settled whatever the pull's state: on a foreign
/// network the daemon makes no request, and still records, from the usage
/// it holds, what the user had used at a refund pulled earlier.
#[test]
fn a_waiting_refund_is_settled_while_the_pull_waits_on_a_foreign_network() {
    let mut harness = joined_to_the_declared_hotspot();
    waiting_refund_on_disk(&mut harness, NOW - 3600);
    with_usage(&harness, &collected_with_detail());
    // Withdraw the declaration: the hotspot is then foreign.
    std::fs::remove_file(
        harness
            .support_dir()
            .join(mooring_store::ALLOWED_NETWORKS_FILE),
    )
    .unwrap();
    for _ in 0..3 {
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
    }
    statuses(&harness);
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
        String::from_utf8(log.clone()).unwrap()
    });
    // The one request is the earlier daemon's.
    assert_eq!(harness.portal.requests.borrow().len(), 1, "{log}");
    assert_eq!(
        log.matches("payment pull: waiting while the Mac is on a network other than the M7 and the declared own networks")
            .count(),
        1,
        "{log}"
    );
    assert_eq!(
        recorded(&harness),
        Some(PackUse::Served {
            bytes: 50_000_000_000,
            learned_at: UnixTime::from_secs(NOW),
        }),
        "{log}"
    );
    assert_eq!(
        log.matches("refund in full no longer waits for the usage")
            .count(),
        1,
        "{log}"
    );
}

/// When the daemon applied the pack's refund, by the ledger on disk: the
/// time its tick began with.
fn refund_applied_at(harness: &Harness) -> u64 {
    ledger_on_disk(harness).unwrap().orders()[&OrderId::parse("aaaaaaaaaaaaaaaaaaaa").unwrap()]
        .refunds[0]
        .applied_at
        .as_secs()
}

/// The settle step dates its report by a clock read at the step, not by
/// the one its tick began with: what a tick collects is dated after the
/// tick began. Here the clock advances a second at each reading. A first
/// daemon, without usage, shows when the tick that pulls the refund
/// begins; a second, alike but for usage sampled a second after that,
/// records the use on that very tick, learned after the tick began.
#[test]
fn the_settle_step_reads_the_clock_again() {
    let mut calibrating = with_a_quota();
    calibrating.clock_step.set(1);
    pack_refunded_on_the_daemon(&mut calibrating, NOW - 3600);
    let began = refund_applied_at(&calibrating);
    assert_eq!(recorded(&calibrating), Some(PackUse::Awaiting));

    let mut harness = with_a_quota();
    harness.clock_step.set(1);
    with_usage(&harness, &collected_with_detail_at(began + 1));
    let (log, _quota) = pack_refunded_on_the_daemon(&mut harness, NOW - 3600);
    assert_eq!(refund_applied_at(&harness), began, "{log}");
    let Some(PackUse::Served { bytes, learned_at }) = recorded(&harness) else {
        panic!("the refund still waits: {log}");
    };
    assert_eq!(bytes, 50_000_000_000, "{log}");
    assert!(learned_at.as_secs() > began, "{log}");
    assert!(!log.contains("cannot tell the use"), "{log}");
}
