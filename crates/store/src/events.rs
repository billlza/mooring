// SPDX-License-Identifier: GPL-3.0-or-later

//! The event journals' day files (design §15.7), kept as `day_files` keeps
//! every kind of day file, under `events/` in the support directory:
//!
//! - `events/mac/<YYYY-MM-DD>.jsonl`, the Mac's own events, in the file of
//!   the UTC day of the event;
//! - `events/nodes/<node>/<YYYY-MM-DD>.jsonl`, each node's journal as the
//!   Mac read it, in the file of the UTC day of the read. A node's
//!   directory is named by its node id, which is lowercase letters and
//!   digits only, so it is never a path of its own; a directory there
//!   whose name is no node id is a stray.
//!
//! `daemon-core`'s `events` encodes and decodes the lines; the daemon
//! writes, the CLI reads, both through this crate. Every level of
//! `events/` is a private directory (mode 0700) and every day file mode
//! 0600. A day file is bounded at [`MAX_EVENTS_DAY_BYTES`] on both sides.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mooring_model::{CalendarDate, NodeId};

use crate::day_files::{DayFiles, DayLines, DayOps, Listed, Pruned};
use crate::durable::existing_private_dir;
use crate::error::{IoOp, StoreError};

/// The journals' directory, in the support directory.
pub const EVENTS_DIRECTORY: &str = "events";

/// The Mac's journal's directory, in [`EVENTS_DIRECTORY`].
pub const MAC_EVENTS_DIRECTORY: &str = "mac";

/// The directory of the nodes' journals, one directory per node, in
/// [`EVENTS_DIRECTORY`].
pub const NODE_EVENTS_DIRECTORY: &str = "nodes";

/// The largest day file read or written: a node's page of 4,096 events
/// is under 1 MiB.
pub const MAX_EVENTS_DAY_BYTES: usize = 4 * 1024 * 1024;

/// The operations the journals' errors name.
const OPS: DayOps = DayOps {
    create_dir: IoOp::CreateEventsDir,
    open: IoOp::OpenEventsDay,
    read: IoOp::ReadEventsDay,
    write: IoOp::WriteEventsDay,
    list: IoOp::ListEventsDays,
    remove: IoOp::RemoveEventsDay,
};

/// The error for a day file larger than the bound.
fn too_large(path: PathBuf) -> StoreError {
    StoreError::EventsDayTooLarge { path }
}

/// The Mac's journal's day files.
const MAC: DayFiles<'static> = DayFiles {
    dirs: &[EVENTS_DIRECTORY, MAC_EVENTS_DIRECTORY],
    ops: OPS,
    max_bytes: MAX_EVENTS_DAY_BYTES,
    too_large,
};

/// A node's journal's day files, under `dirs`.
const fn node_files<'a>(dirs: &'a [&'a str]) -> DayFiles<'a> {
    DayFiles {
        dirs,
        ops: OPS,
        max_bytes: MAX_EVENTS_DAY_BYTES,
        too_large,
    }
}

/// The levels of `node`'s journal's directory.
fn node_dirs(node: &NodeId) -> [&str; 3] {
    [EVENTS_DIRECTORY, NODE_EVENTS_DIRECTORY, node.as_str()]
}

/// `events/mac/<date>.jsonl` under `support_dir`.
#[must_use]
pub fn mac_events_path(support_dir: &Path, date: CalendarDate) -> PathBuf {
    MAC.path(support_dir, date)
}

/// Appends `lines` (whole lines) to the Mac's journal's file of `date`,
/// as `day_files` appends (the torn tail cut first, the bound kept, the
/// bytes flushed).
pub fn append_mac_events(
    support_dir: &Path,
    date: CalendarDate,
    lines: &[u8],
) -> Result<(), StoreError> {
    MAC.append(support_dir, date, lines)
}

/// The whole lines of the Mac's journal's file of `date`, or `None` when
/// there is none.
pub fn read_mac_events(
    support_dir: &Path,
    date: CalendarDate,
) -> Result<Option<DayLines>, StoreError> {
    MAC.read(support_dir, date)
}

/// The days of the Mac's journal, oldest first, and the strays beside
/// them.
pub fn list_mac_event_days(support_dir: &Path) -> Result<Listed, StoreError> {
    MAC.list(support_dir)
}

/// Removes the Mac's journal's day files of the days before `oldest`.
pub fn prune_mac_events_before(
    support_dir: &Path,
    oldest: CalendarDate,
) -> Result<Pruned, StoreError> {
    MAC.prune_before(support_dir, oldest)
}

/// `events/nodes/<node>/<date>.jsonl` under `support_dir`.
#[must_use]
pub fn node_events_path(support_dir: &Path, node: &NodeId, date: CalendarDate) -> PathBuf {
    node_files(&node_dirs(node)).path(support_dir, date)
}

/// Appends `lines` (whole lines) to `node`'s journal's file of `date`, as
/// `day_files` appends.
pub fn append_node_events(
    support_dir: &Path,
    node: &NodeId,
    date: CalendarDate,
    lines: &[u8],
) -> Result<(), StoreError> {
    node_files(&node_dirs(node)).append(support_dir, date, lines)
}

/// The whole lines of `node`'s journal's file of `date`, or `None` when
/// there is none.
pub fn read_node_events(
    support_dir: &Path,
    node: &NodeId,
    date: CalendarDate,
) -> Result<Option<DayLines>, StoreError> {
    node_files(&node_dirs(node)).read(support_dir, date)
}

/// The days of `node`'s journal, oldest first, and the strays beside
/// them.
pub fn list_node_event_days(support_dir: &Path, node: &NodeId) -> Result<Listed, StoreError> {
    node_files(&node_dirs(node)).list(support_dir)
}

/// Removes `node`'s journal's day files of the days before `oldest`.
pub fn prune_node_events_before(
    support_dir: &Path,
    node: &NodeId,
    oldest: CalendarDate,
) -> Result<Pruned, StoreError> {
    node_files(&node_dirs(node)).prune_before(support_dir, oldest)
}

/// The nodes that have a journal directory, and the strays beside them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventNodes {
    /// The nodes, in order.
    pub nodes: Vec<NodeId>,
    /// The entries of `events/nodes/` that are not a node's directory.
    pub strays: Vec<PathBuf>,
}

/// The nodes whose journals the Mac keeps: every directory in
/// `events/nodes/` named by a node id. None when there is no such
/// directory, and none is made; anything but a directory where `events/`
/// or `events/nodes/` belongs, a link included, is `DirNotDirectory`.
pub fn event_nodes(support_dir: &Path) -> Result<EventNodes, StoreError> {
    let Some(events) = existing_private_dir(support_dir, EVENTS_DIRECTORY, IoOp::ListEventsDays)?
    else {
        return Ok(EventNodes::default());
    };
    let Some(dir) = existing_private_dir(&events, NODE_EVENTS_DIRECTORY, IoOp::ListEventsDays)?
    else {
        return Ok(EventNodes::default());
    };
    let listing = |error: io::Error, path: &Path| StoreError::Io {
        op: IoOp::ListEventsDays,
        path: path.to_path_buf(),
        source: error,
    };
    let mut found = EventNodes::default();
    for entry in fs::read_dir(&dir).map_err(|error| listing(error, &dir))? {
        let entry = entry.map_err(|error| listing(error, &dir))?;
        let path = entry.path();
        let directory = entry
            .file_type()
            .map_err(|error| listing(error, &path))?
            .is_dir();
        let node = entry
            .file_name()
            .to_str()
            .and_then(|name| NodeId::parse(name).ok());
        match node {
            Some(node) if directory => found.nodes.push(node),
            _ => found.strays.push(path),
        }
    }
    found.nodes.sort_unstable();
    found.strays.sort_unstable();
    Ok(found)
}
