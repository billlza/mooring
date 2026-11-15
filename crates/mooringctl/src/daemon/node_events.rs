// SPDX-License-Identifier: GPL-3.0-or-later

//! Each node's event journal, read into the Mac's copy (design §15.7,
//! §11.1): on a tick that asks no node anything else, the node longest
//! due is asked `Events{since}` through the M7, as the usage collection
//! asks its requests (one request, bounded by the time to the next direct
//! probe), and what its page gives (`daemon-core`'s `events::accept`) is
//! appended to the copy's file of the read's UTC day through
//! `mooring-store`. Each node is read every interval, at once again while
//! its journal holds more than a page gave; the first read of a run waits
//! an interval after the daemon opened, as the usage collection does.
//!
//! The number asked from follows from the copy's newest line, read from
//! its file at a node's first read of the run, then from what the run
//! appended; an append that fails sends the next read back to the file.
//! The lines go to the file of the read's day, or of the copy's newest
//! day when the clock reads earlier, so the newest line is always in the
//! newest file. A node that cannot be read, a page that is refused or a
//! copy that cannot be read or written is logged once while it lasts and
//! once when it recovers; the node is read again an interval later.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_agent_proto::{LineRequest, Response};
use mooring_daemon_core::events::{Cursor, NodeLine, accept, decode_node_line, encode_node_line};
use mooring_model::iface::BsdName;
use mooring_model::node::{Node, NodeLifecycle};
use mooring_model::{CalendarDate, Deployment, NodeId};
use mooring_store::{
    DayLines, append_node_events, list_node_event_days, node_events_path, read_node_events,
};

use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::node::session::ops_session;

use super::chain;
use super::events::files;
use super::noted::Noted;

/// Where a node's copy stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Standing {
    /// The number to ask from next.
    cursor: Cursor,
    /// The newest day that has a file, if any.
    newest_day: Option<CalendarDate>,
}

/// The reader of the nodes' journals.
#[derive(Debug)]
pub(crate) struct NodeEvents {
    support: PathBuf,
    /// When the run's first read is due.
    first: Instant,
    /// When each node is next due; a node not listed is due.
    due: BTreeMap<NodeId, Instant>,
    /// Each node's copy as the run last read or appended it.
    copies: BTreeMap<NodeId, Standing>,
    /// Each node's failure, logged once while it lasts.
    failures: BTreeMap<NodeId, Noted>,
}

/// How a read ended, for the log.
enum Read {
    /// The copy took the page; the journal holds more when `more`.
    Took { more: bool },
    /// The read failed: what to log.
    Failed(String),
}

impl NodeEvents {
    /// A reader whose first read is due `interval` from now.
    pub(crate) fn open(support: &Path, interval: Duration) -> Self {
        Self {
            support: support.to_path_buf(),
            first: Instant::now() + interval,
            due: BTreeMap::new(),
            copies: BTreeMap::new(),
            failures: BTreeMap::new(),
        }
    }

    /// Reads the journal of the node longest due, if one is due: at most
    /// one request, through `egress`, ending within `budget`. Whether a
    /// node was asked. Only a clock that cannot be read or a log that
    /// cannot be written is an error.
    pub(crate) fn tick(
        &mut self,
        env: &Env<'_>,
        log: &mut dyn Write,
        deployment: &Deployment,
        egress: &BsdName,
        budget: Duration,
        interval: Duration,
    ) -> Result<bool, CommandError> {
        let started = Instant::now();
        if started < self.first {
            return Ok(false);
        }
        let serving = |id: &NodeId| deployment.nodes().get(id).is_some_and(reachable);
        self.due.retain(|id, _| serving(id));
        self.copies.retain(|id, _| serving(id));
        self.failures.retain(|id, _| serving(id));
        let Some(node) = deployment
            .nodes()
            .values()
            .filter(|node| reachable(node))
            .filter(|node| self.due.get(&node.id).is_none_or(|at| started >= *at))
            .min_by_key(|node| self.due.get(&node.id).copied())
        else {
            return Ok(false);
        };
        let copy = match self.copies.get(&node.id) {
            Some(copy) => *copy,
            None => match read_copy(&self.support, &node.id) {
                Ok(copy) => copy,
                Err(error) => {
                    self.due.insert(node.id.clone(), started + interval);
                    let now = (env.clock)()?;
                    return self
                        .failure(&node.id)
                        .holds(
                            log,
                            now,
                            &format!("{}: the copy of its event journal cannot be read", node.id),
                            chain(&error),
                        )
                        .map(|()| false);
                }
            },
        };
        let answer =
            ops_session(env, node, egress, Some(started + budget)).and_then(|mut session| {
                Ok(session.request(&LineRequest::Events {
                    since: copy.cursor.since(),
                })?)
            });
        let read_at = (env.clock)()?;
        let read = match answer {
            Ok(Response::Events(page)) => match accept(copy.cursor, &page, read_at) {
                Ok(accepted) => {
                    let today = CalendarDate::utc_of(read_at).map_err(|_| LocalError::Clock)?;
                    let day = copy.newest_day.map_or(today, |newest| newest.max(today));
                    match self.append(&node.id, day, &accepted.lines) {
                        Ok(()) => {
                            let newest_day = if accepted.lines.is_empty() {
                                copy.newest_day
                            } else {
                                Some(day)
                            };
                            self.copies.insert(
                                node.id.clone(),
                                Standing {
                                    cursor: accepted.next,
                                    newest_day,
                                },
                            );
                            Read::Took {
                                more: accepted.more,
                            }
                        }
                        Err(error) => {
                            // The file decides again where the copy stands.
                            self.copies.remove(&node.id);
                            Read::Failed(format!(
                                "its event journal was not written: {}",
                                chain(&error)
                            ))
                        }
                    }
                }
                Err(error) => Read::Failed(format!(
                    "its event journal's page was refused: {}",
                    chain(&error)
                )),
            },
            Ok(other) => Read::Failed(format!("the agent answered Events with {:?}", other.kind())),
            Err(error) => {
                Read::Failed(format!("its event journal was not read: {}", chain(&error)))
            }
        };
        let failure = self.failures.entry(node.id.clone()).or_default();
        match read {
            Read::Took { more } => {
                let next = if more { started } else { started + interval };
                self.due.insert(node.id.clone(), next);
                failure.ended(
                    log,
                    read_at,
                    Some(&format!("{}: its event journal is read again", node.id)),
                )?;
            }
            Read::Failed(text) => {
                self.due.insert(node.id.clone(), started + interval);
                failure.holds(log, read_at, &node.id.to_string(), text)?;
            }
        }
        Ok(true)
    }

    /// Appends `lines` to `node`'s copy, in the file of `day`. Nothing to
    /// append changes nothing.
    fn append(
        &self,
        node: &NodeId,
        day: CalendarDate,
        lines: &[NodeLine],
    ) -> Result<(), LocalError> {
        if lines.is_empty() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend(encode_node_line(line).map_err(LocalError::EventsEncode)?);
        }
        append_node_events(&self.support, node, day, &bytes).map_err(files)
    }

    /// `node`'s failure, logged once while it lasts.
    fn failure(&mut self, node: &NodeId) -> &mut Noted {
        self.failures.entry(node.clone()).or_default()
    }
}

/// Whether `node`'s agent is asked: adopted or applied, as the usage
/// collection's nodes.
fn reachable(node: &Node) -> bool {
    matches!(
        node.lifecycle,
        NodeLifecycle::Adopted { .. } | NodeLifecycle::Applied { .. }
    )
}

/// Where `node`'s copy stands by its files: after its newest whole line,
/// in the newest day file that holds one.
fn read_copy(support: &Path, node: &NodeId) -> Result<Standing, LocalError> {
    let days = list_node_event_days(support, node).map_err(files)?.days;
    for day in days.iter().rev() {
        let Some(DayLines { lines, .. }) = read_node_events(support, node, *day).map_err(files)?
        else {
            continue;
        };
        let Some((index, line)) = lines
            .split_inclusive(|&byte| byte == b'\n')
            .enumerate()
            .last()
        else {
            continue;
        };
        let refused = |source| LocalError::EventsLine {
            path: node_events_path(support, node, *day),
            line: index + 1,
            source,
        };
        let line = decode_node_line(line).map_err(refused)?;
        return Ok(Standing {
            cursor: Cursor::after(Some(&line)).map_err(refused)?,
            newest_day: days.last().copied(),
        });
    }
    Ok(Standing {
        cursor: Cursor::Fresh,
        newest_day: days.last().copied(),
    })
}
