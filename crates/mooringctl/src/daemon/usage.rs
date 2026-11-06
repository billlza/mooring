// SPDX-License-Identifier: GPL-3.0-or-later

//! Incremental, bounded accounting in the gap between carrier probes.
//! One SSH request per tick, through the pinned M7 interface, with an
//! explicit deadline. A node batch is durable before it becomes visible.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_agent_proto::{AgentError, LineRequest, Resolution, Response, SeriesRange, UsageMonth};
use mooring_daemon_core::error::{UsageError, UsageErrorKind};
use mooring_daemon_core::snapshot::{Ledgers, NodePoll};
use mooring_daemon_core::usage::{CollectedUsage, MAX_COLLECTED_USAGE_BYTES, NodeUsageHistory};
use mooring_model::iface::BsdName;
use mooring_model::node::{Node, NodeLifecycle};
use mooring_model::{Deployment, NodeId, UnixTime};
use mooring_store::{StoreError, read_user_usage, write_user_usage};

use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::node::{NodeError, session::ops_session};

const KEEP_ON_NODE: u64 = 48 * 3600;
const REQUEST_BUDGET: Duration = Duration::from_secs(15);
const PROBE_RESERVE: Duration = Duration::from_secs(2);

/// Give collection as much of the current gap as its bounded SSH window needs.
/// Cellular SSH can take longer than four seconds. Shorter probe cadences still
/// get their available window, keeping two seconds before the carrier probe and
/// deferring when less than one second remains for the request.
pub(crate) fn pull_budget(next_probe_in: Option<Duration>) -> Option<Duration> {
    let room = next_probe_in.map_or(REQUEST_BUDGET, |left| {
        left.saturating_sub(PROBE_RESERVE).min(REQUEST_BUDGET)
    });
    (room >= Duration::from_secs(1)).then_some(room)
}

/// Why `usage/users.json` could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CollectedReadError {
    /// The store could not read the file.
    #[error(transparent)]
    Store(StoreError),
    /// The file holds no collected usage document.
    #[error(transparent)]
    Decode(UsageError),
}

impl CollectedReadError {
    /// The usage view's reason for it.
    pub(crate) const fn kind(&self) -> UsageErrorKind {
        match self {
            Self::Store(_) => UsageErrorKind::StoreUnavailable,
            Self::Decode(error) => error.kind(),
        }
    }
}

/// The usage the daemon collected, in `support`'s `usage/users.json`, or
/// an empty history when there is none yet. The daemon's [`Collector`] is
/// its one writer and replaces it whole (the store's durable write), so a
/// reader in another process sees one complete document.
pub(crate) fn read_collected(support: &Path) -> Result<CollectedUsage, CollectedReadError> {
    match read_user_usage(support, MAX_COLLECTED_USAGE_BYTES + 1)
        .map_err(CollectedReadError::Store)?
    {
        Some(bytes) => CollectedUsage::decode(&bytes).map_err(CollectedReadError::Decode),
        None => Ok(CollectedUsage::default()),
    }
}

#[derive(Debug)]
enum StoreState {
    Ready(CollectedUsage),
    Unreadable {
        kind: UsageErrorKind,
    },
    Unwritten {
        candidate: CollectedUsage,
        retry_at: Instant,
    },
}

#[derive(Debug)]
enum Task {
    Status,
    Month(UsageMonth),
    Series { range: SeriesRange, recovered: bool },
}

#[derive(Debug)]
struct Batch {
    node: Node,
    history: NodeUsageHistory,
    tasks: VecDeque<Task>,
}

/// The daemon's one writer of usage/users.json.
#[derive(Debug)]
pub(crate) struct Collector {
    support: PathBuf,
    store: StoreState,
    pending: Option<Batch>,
    due: BTreeMap<NodeId, Instant>,
    first: Instant,
    maintenance_at: Instant,
    failure: Option<String>,
    store_failure: Option<String>,
    gaps: Vec<String>,
}

impl Collector {
    /// A bad existing document blocks this writer; it is retained for
    /// diagnosis and never replaced by an empty history.
    pub(crate) fn open(support: &Path, interval: Duration) -> Self {
        let (store, failure) = match read_collected(support) {
            Ok(history) => (StoreState::Ready(history), None),
            Err(error) => (
                StoreState::Unreadable { kind: error.kind() },
                Some(error.to_string()),
            ),
        };
        Self {
            support: support.to_path_buf(),
            store,
            pending: None,
            due: BTreeMap::new(),
            first: Instant::now() + interval,
            maintenance_at: Instant::now(),
            failure: None,
            store_failure: failure,
            gaps: Vec::new(),
        }
    }

    pub(crate) fn ledgers(&self) -> Ledgers<'_> {
        match &self.store {
            StoreState::Ready(history) => Ledgers::Collected(history),
            StoreState::Unreadable { kind } => Ledgers::Unavailable(*kind),
            StoreState::Unwritten { .. } => Ledgers::Unavailable(UsageErrorKind::StoreUnavailable),
        }
    }

    pub(crate) fn failure(&self) -> Option<&str> {
        self.store_failure.as_deref().or(self.failure.as_deref())
    }
    pub(crate) fn take_gaps(&mut self) -> Vec<String> {
        std::mem::take(&mut self.gaps)
    }

    /// Uses at most one bounded request. Failed batches are tried at the
    /// next interval; fresh persisted snapshots remain timestamped and the
    /// core refuses them once their three-minute freshness limit expires.
    pub(crate) fn tick(
        &mut self,
        env: &Env<'_>,
        deployment: &Deployment,
        egress: &BsdName,
        now: UnixTime,
        budget: Duration,
        interval: Duration,
    ) -> Option<(NodeId, NodePoll)> {
        let StoreState::Ready(history) = &mut self.store else {
            return None;
        };
        if Instant::now() < self.first {
            return None;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|batch| deployment.nodes().get(&batch.node.id) != Some(&batch.node))
        {
            self.pending = None;
        }
        if self.pending.is_none() {
            let node = deployment
                .nodes()
                .values()
                .filter(|node| {
                    matches!(
                        node.lifecycle,
                        NodeLifecycle::Adopted { .. } | NodeLifecycle::Applied { .. }
                    )
                })
                .filter(|node| {
                    self.due
                        .get(&node.id)
                        .is_none_or(|at| Instant::now() >= *at)
                })
                .min_by_key(|node| self.due.get(&node.id).copied());
            let node = node?;
            let saved = history.node(&node.id).cloned().unwrap_or_default();
            match batch(node.clone(), saved, now) {
                Ok(batch) => self.pending = Some(batch),
                Err(error) => {
                    self.failure = Some(error.to_string());
                    self.due.insert(node.id.clone(), Instant::now() + interval);
                    return None;
                }
            }
        }
        let mut batch = self.pending.take()?;
        let task = batch.tasks.pop_front()?;
        let request = match task {
            Task::Status => LineRequest::Status,
            Task::Month(month) => LineRequest::Usage { month },
            Task::Series { range, .. } => LineRequest::UsageSeries(range),
        };
        let mut result = ops_session(env, &batch.node, egress, Some(Instant::now() + budget))
            .and_then(|mut session| session.request(&request).map_err(CommandError::from));
        let fetched_at = match (env.clock)() {
            Ok(at) => at,
            Err(error) => {
                self.failure = Some(format!("usage pull clock failed: {error}"));
                self.due.insert(batch.node.id, Instant::now() + interval);
                return None;
            }
        };
        if let StoreState::Ready(history) = &self.store
            && let Ok(reply) = &mut result
            && let Err(error) = sanitize(history, deployment, &batch.node.id, fetched_at, reply)
        {
            result = Err(LocalError::CollectedUsage(error).into());
        }
        let polled = match accept(&mut batch, task, result, fetched_at, &mut self.gaps) {
            Ok(polled) => polled,
            Err(error) => {
                self.failure = Some(format!(
                    "{}: usage pull failed: {}",
                    batch.node.id,
                    super::chain(&error)
                ));
                self.due.insert(batch.node.id, Instant::now() + interval);
                return None;
            }
        };
        if batch.tasks.is_empty() {
            let StoreState::Ready(history) = &self.store else {
                return None;
            };
            let mut candidate = history.clone();
            let node = batch.node.id;
            match batch.history.validate_users(&node, deployment) {
                Ok(()) => {
                    candidate.set_node(node.clone(), batch.history);
                    self.failure = None;
                    self.persist(candidate, deployment, fetched_at, interval);
                }
                Err(error) => self.failure = Some(format!("{node}: {error}")),
            }
            self.due.insert(node, Instant::now() + interval);
        } else {
            self.pending = Some(batch);
        }
        polled
    }

    /// Local retention and persistence continue even with the M7 unplugged.
    pub(crate) fn maintain(&mut self, deployment: &Deployment, now: UnixTime, interval: Duration) {
        if Instant::now() < self.maintenance_at {
            return;
        }
        self.maintenance_at = Instant::now() + interval;
        let mut candidate = match &self.store {
            StoreState::Ready(history) => history.clone(),
            StoreState::Unwritten {
                candidate,
                retry_at,
            } if Instant::now() >= *retry_at => candidate.clone(),
            StoreState::Unreadable { .. } | StoreState::Unwritten { .. } => return,
        };
        for (id, node) in deployment.nodes() {
            if node.lifecycle == NodeLifecycle::Planned {
                candidate.observe_unserved(id.clone(), now);
            }
        }
        self.persist(candidate, deployment, now, interval);
        self.due
            .retain(|node, _| deployment.nodes().contains_key(node));
    }

    fn persist(
        &mut self,
        mut candidate: CollectedUsage,
        deployment: &Deployment,
        now: UnixTime,
        interval: Duration,
    ) {
        let encoded = candidate
            .prune(deployment, now)
            .and_then(|()| candidate.encode());
        let bytes = match encoded {
            Ok(bytes) => bytes,
            Err(error) => {
                self.store_failure = Some(error.to_string());
                self.store = StoreState::Unwritten {
                    candidate,
                    retry_at: Instant::now() + interval,
                };
                return;
            }
        };
        match write_user_usage(&self.support, &bytes) {
            Ok(()) => {
                self.store = StoreState::Ready(candidate);
                self.store_failure = None;
            }
            Err(error) => {
                self.store_failure = Some(format!("cannot persist collected usage: {error}"));
                self.store = StoreState::Unwritten {
                    candidate,
                    retry_at: Instant::now() + interval,
                };
            }
        }
    }
}

fn wire(at: u64) -> mooring_agent_proto::UnixTime {
    mooring_agent_proto::UnixTime::from_secs(at)
}

fn range(from: u64, to: u64) -> Result<SeriesRange, CommandError> {
    SeriesRange::new(wire(from), wire(to), Resolution::FiveMin).map_err(|_| {
        LocalError::CollectedUsage(UsageError::LedgerCorrupt {
            message: "invalid collection range".to_owned(),
        })
        .into()
    })
}

fn batch(node: Node, history: NodeUsageHistory, now: UnixTime) -> Result<Batch, CommandError> {
    let month = UsageMonth::containing(wire(now.as_secs())).map_err(|_| {
        LocalError::CollectedUsage(UsageError::LedgerCorrupt {
            message: "current month outside calendar".to_owned(),
        })
    })?;
    let mut tasks = VecDeque::from([Task::Status]);
    // The preceding month's authority is available for seven days only.
    if now.as_secs() - month.start().as_secs() < 7 * 86_400 && month.start().as_secs() > 0 {
        let prior = UsageMonth::containing(wire(month.start().as_secs() - 1)).map_err(|_| {
            LocalError::CollectedUsage(UsageError::LedgerCorrupt {
                message: "previous month outside calendar".to_owned(),
            })
        })?;
        tasks.push_back(Task::Month(prior));
    }
    let to = now.as_secs() / 300 * 300;
    let mut from = history
        .detail_through()
        .unwrap_or(to.saturating_sub(KEEP_ON_NODE));
    from = from.max(to.saturating_sub(KEEP_ON_NODE));
    while from < to {
        let end = to.min(from + Resolution::FiveMin.max_bins() * 300);
        tasks.push_back(Task::Series {
            range: range(from, end)?,
            recovered: false,
        });
        from = end;
    }
    tasks.push_back(Task::Month(month));
    Ok(Batch {
        node,
        history,
        tasks,
    })
}

fn accept(
    batch: &mut Batch,
    task: Task,
    result: Result<Response, CommandError>,
    now: UnixTime,
    gaps: &mut Vec<String>,
) -> Result<Option<(NodeId, NodePoll)>, CommandError> {
    let request = match task {
        Task::Status => mooring_agent_proto::RequestKind::Status,
        Task::Month(_) => mooring_agent_proto::RequestKind::Usage,
        Task::Series { .. } => mooring_agent_proto::RequestKind::UsageSeries,
    };
    match (task, result) {
        (Task::Status, Ok(Response::Status(status))) => Ok(Some((
            batch.node.id.clone(),
            NodePoll {
                polled_at: now,
                status: *status,
            },
        ))),
        (Task::Month(month), Ok(Response::Usage(sample))) if sample.month == month => {
            if sample.updated_at.as_secs() > now.as_secs() {
                return Err(LocalError::CollectedUsage(UsageError::LedgerCorrupt {
                    message: "monthly sample is in the future".to_owned(),
                })
                .into());
            }
            batch
                .history
                .record_month(&batch.node.id, *sample, now)
                .map_err(LocalError::CollectedUsage)?;
            Ok(None)
        }
        (
            Task::Month(month),
            Err(CommandError::Local(LocalError::Node(NodeError::Agent(
                AgentError::NoUsageRecorded { month: absent },
            )))),
        ) if month == absent => {
            gaps.push(format!("{}: monthly usage {month} is not recorded; retained history is not replaced with zeros", batch.node.id));
            Ok(None)
        }
        (Task::Series { range: wanted, .. }, Ok(Response::UsageSeries(series)))
            if series.range() == wanted =>
        {
            batch
                .history
                .record_series(&batch.node.id, &series)
                .map_err(LocalError::CollectedUsage)?;
            Ok(None)
        }
        (
            Task::Series {
                range: wanted,
                recovered,
            },
            Err(CommandError::Local(LocalError::Node(NodeError::Agent(
                AgentError::SeriesNotRecorded { recorded },
            )))),
        ) => {
            // The latest bin may not have closed on the node yet. Only
            // a missing prefix is a historical gap; a pending tail is
            // retried naturally from detail_through on the next cycle.
            if recorded.is_none_or(|held| held.from() > wanted.span().from()) {
                gaps.push(format!("{}: detailed usage {}..{} has a missing prefix; monthly reconciliation will preserve unknown splits", batch.node.id, wanted.span().from(), wanted.span().to()));
            }
            if !recovered
                && let Some(held) = recorded.filter(|held| held.resolution() == Resolution::FiveMin)
            {
                let from = wanted.span().from().as_secs().max(held.from().as_secs());
                let to = wanted.span().to().as_secs().min(held.to().as_secs());
                if from < to
                    && (from != wanted.span().from().as_secs()
                        || to != wanted.span().to().as_secs())
                {
                    batch.tasks.push_front(Task::Series {
                        range: range(from, to)?,
                        recovered: true,
                    });
                }
            }
            Ok(None)
        }
        (
            Task::Series {
                range: wanted,
                recovered,
            },
            Err(CommandError::Local(LocalError::Node(NodeError::Agent(
                AgentError::SeriesTooLarge { fitting_bins },
            )))),
        ) if fitting_bins > 0 && u64::from(fitting_bins) < wanted.span().bins() => {
            let split = wanted.span().from().as_secs() + u64::from(fitting_bins) * 300;
            batch.tasks.push_front(Task::Series {
                range: range(split, wanted.span().to().as_secs())?,
                recovered,
            });
            batch.tasks.push_front(Task::Series {
                range: range(wanted.span().from().as_secs(), split)?,
                recovered,
            });
            Ok(None)
        }
        (Task::Month(_), Ok(Response::Usage(_)))
        | (Task::Series { .. }, Ok(Response::UsageSeries(_))) => {
            Err(LocalError::CollectedUsage(UsageError::LedgerCorrupt {
                message: "node accounting reply does not echo the requested month or range"
                    .to_owned(),
            })
            .into())
        }
        (_, Err(error)) => Err(error),
        (_, Ok(reply)) => Err(NodeError::Unexpected {
            request,
            response: reply.kind(),
        }
        .into()),
    }
}

/// The data erased locally must not return in a still-retained node reply.
fn sanitize(
    history: &CollectedUsage,
    deployment: &Deployment,
    node: &NodeId,
    now: UnixTime,
    reply: &mut Response,
) -> Result<(), UsageError> {
    match reply {
        Response::Usage(month) => {
            history.retain_counter_users(node, &mut month.traffic, deployment, now)
        }
        Response::UsageSeries(series) => {
            let mut bins = Vec::new();
            for bin in series.bins() {
                let mut traffic = bin.traffic().clone();
                history.retain_counter_users(node, &mut traffic, deployment, now)?;
                if !traffic.is_empty() {
                    bins.push(
                        mooring_agent_proto::UsageBin::new(bin.start(), traffic).map_err(|_| {
                            UsageError::LedgerCorrupt {
                                message: "filtered usage bin is invalid".to_owned(),
                            }
                        })?,
                    );
                }
            }
            **series =
                mooring_agent_proto::UsageSeriesV1::new(series.range(), bins).map_err(|_| {
                    UsageError::LedgerCorrupt {
                        message: "filtered usage range is invalid".to_owned(),
                    }
                })?;
            Ok(())
        }
        _ => Ok(()),
    }
}
