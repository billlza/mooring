// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull on the deployed daemon's tick: it asks while the Mac is
//! on no foreign network, records what it gets, and the status line shows
//! what was granted; on a foreign network it waits.

use mooring_daemon_core::ExpiryState;
use mooring_model::{UnixTime, UserId};

use super::super::deployed::{
    CARRIER, deployed, joined_to_the_declared_hotspot, published, shared, statuses, with_exit_on,
};
use super::super::support::NOW;
use super::{FIRST, connect, grant, ledger_on_disk, page};
use crate::daemon::Intervals;

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
