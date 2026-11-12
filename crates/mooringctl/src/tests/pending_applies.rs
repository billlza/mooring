// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of pending applies (design §13.6, §15.3): the
//! status carries since when each node has been behind the deployment's
//! generation, a restart keeps that date, a record that cannot be read is
//! said and replaced, and a write that fails is said and tried again.

use std::fs;

use mooring_daemon_core::pending_applies::{MAX_PENDING_APPLIES_BYTES, PendingApplies};
use mooring_model::node::NodeLifecycle;
use mooring_model::{ConfigGeneration, Deployment, NodeId, UnixTime};
use mooring_store::{PENDING_APPLIES_FILE, read_pending_applies};

use super::deployed::{CARRIER, deployed_with, published, shared, statuses, with_exit_on};
use super::support::NOW;
use super::user::fixture;
use crate::daemon::pending::Pending;
use crate::daemon::{Intervals, RunPaths};

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// The fixture at generation 2, ams1 having confirmed it and lon1 still
/// at generation 1.
fn lon1_behind() -> Deployment {
    fixture(|parts| {
        parts.config_generation = ConfigGeneration::new(2).unwrap();
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { applied, .. } = &mut node.lifecycle
                && node.id.as_str() == "ams1"
            {
                applied.config_generation = ConfigGeneration::new(2).unwrap();
            }
        }
    })
}

/// The record on disk in `run_dir`.
fn on_disk(run_dir: &std::path::Path) -> PendingApplies {
    let bytes = read_pending_applies(run_dir, MAX_PENDING_APPLIES_BYTES + 1)
        .unwrap()
        .unwrap();
    PendingApplies::decode(&bytes).unwrap()
}

/// The status shows since when lon1 has waited and ams1 waits for
/// nothing; the daemon started again an hour later shows the same date.
#[test]
fn the_status_shows_since_when_a_node_waits_and_a_restart_keeps_it() {
    let mut harness = deployed_with(lon1_behind());
    let run_dir = RunPaths::under(&harness.support_dir()).dir;
    for hour in [0, 1] {
        harness.now.set(NOW + hour * 3600);
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
        statuses(&harness);
        let (control, _retries) = shared();
        with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
            exit.tick(&control, log, false).unwrap();
            let status = published(&control);
            let nodes = &status.parts().nodes;
            assert_eq!(
                nodes[&node("lon1")].pending_apply_since,
                Some(UnixTime::from_secs(NOW))
            );
            assert_eq!(nodes[&node("ams1")].pending_apply_since, None);
        });
        assert_eq!(
            on_disk(&run_dir).since(),
            [(node("lon1"), UnixTime::from_secs(NOW))].into()
        );
    }
}

/// A record that cannot be read is said at the start and written again at
/// the first tick, with each wait dated from then.
#[test]
fn a_record_that_cannot_be_read_is_said_and_replaced() {
    let run = tempfile::tempdir().unwrap();
    fs::write(run.path().join(PENDING_APPLIES_FILE), b"not a record").unwrap();
    let (mut pending, note) = Pending::open(run.path());
    assert_eq!(
        note.as_deref(),
        Some(
            "pending applies: the record cannot be read (the record of pending applies is corrupt); each pending apply is dated from now, and the record is written again"
        )
    );
    assert_eq!(
        pending.track(&fixture(|_| {}), UnixTime::from_secs(NOW)),
        None
    );
    assert_eq!(on_disk(run.path()), PendingApplies::new());
}

/// A write that fails is said; the status still has the date, and the
/// write is tried again only a while later.
#[test]
fn a_write_that_fails_is_said_and_tried_again_later() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    let (mut pending, note) = Pending::open(&missing);
    assert_eq!(note, None);
    let at = UnixTime::from_secs(NOW);
    let said = pending.track(&lon1_behind(), at).unwrap();
    assert!(
        said.starts_with("pending applies: the record could not be written ("),
        "{said}"
    );
    assert!(
        said.ends_with("); the status shows it, and it is written again in 60 s"),
        "{said}"
    );
    assert_eq!(pending.since(), [(node("lon1"), at)].into());
    fs::create_dir(&missing).unwrap();
    assert_eq!(pending.track(&lon1_behind(), at), None);
    assert_eq!(read_pending_applies(&missing, 64).unwrap(), None);
}
