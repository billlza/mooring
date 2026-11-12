// SPDX-License-Identifier: GPL-3.0-or-later

//! Incremental, bounded accounting in the gap between carrier probes.
//! One SSH request per tick, through the pinned M7 interface, with an
//! explicit deadline. A node batch is durable before it becomes visible.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_agent_proto::{AgentError, LineRequest, Resolution, Response, SeriesRange, UsageMonth};
use mooring_daemon_core::error::{UsageError, UsageErrorKind};
use mooring_daemon_core::payments::RunBegan;
use mooring_daemon_core::snapshot::{Ledgers, NodePoll};
use mooring_daemon_core::usage::{CollectedUsage, DownlinkCount, NodeUsageHistory, ServedBefore};
use mooring_model::iface::BsdName;
use mooring_model::node::{Node, NodeLifecycle};
use mooring_model::{Deployment, NodeId, UnixTime, UserId};
use mooring_store::write_user_usage;

use crate::app::Env;
use crate::collected_usage::{Told, behind, read_collected};
use crate::error::{CommandError, LocalError};
use crate::node::{NodeError, session::ops_session};
use crate::payments::pull::RefundReadings;

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

/// What one tick of the collection did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pulled {
    /// No node was asked anything.
    Nothing,
    /// A node was asked one request: with its `Status` poll, when the
    /// request was one and it succeeded.
    Asked(Option<Box<(NodeId, NodePoll)>>),
}

/// What the deployed daemon reads at `now` for the traffic packs refunded
/// in full (design §9.6): the usage collected, and each node's latest
/// status.
pub(crate) struct RefundView<'a> {
    /// The collection.
    pub(crate) collector: &'a Collector,
    /// The deployment the usage is read for.
    pub(crate) deployment: &'a Deployment,
    /// The instant the usage is read at.
    pub(crate) now: UnixTime,
    /// Each node's latest `Status` poll.
    pub(crate) polls: &'a BTreeMap<NodeId, NodePoll>,
}

impl RefundReadings for RefundView<'_> {
    fn served_before(&self, user: &UserId, at: UnixTime) -> Told<ServedBefore> {
        self.collector
            .served_before(self.deployment, self.now, user, at)
    }

    fn reality_downlink(&self, user: &UserId) -> Told<BTreeMap<NodeId, DownlinkCount>> {
        self.collector
            .reality_downlink(self.deployment, self.now, user)
    }

    fn xray_began(&self, node: &NodeId) -> Option<RunBegan> {
        self.polls
            .get(node)
            .and_then(|poll| RunBegan::of(&poll.status))
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

    /// What `user` had served in the billing cycle `now` is in before
    /// `at`, at most, by the usage collected
    /// ([`CollectedUsage::cycle_served_before`]). A refund in full of a
    /// traffic pack waits for it (design §9.6), and goes on waiting unless
    /// this is `Ok(Some)` ([`Self::told`]).
    pub(crate) fn served_before(
        &self,
        deployment: &Deployment,
        now: UnixTime,
        user: &UserId,
        at: UnixTime,
    ) -> Told<ServedBefore> {
        self.told(|history| history.cycle_served_before(deployment, now, user, at))
    }

    /// What each node has counted of `user`'s REALITY downlink in the
    /// billing cycle `now` is in, by the usage collected
    /// ([`CollectedUsage::cycle_reality_downlink`]). The use at a refund in
    /// full of a traffic pack takes it in while a download that was open
    /// at the refund may still be counted (design §9.6); it is told as
    /// [`Self::told`] says.
    pub(crate) fn reality_downlink(
        &self,
        deployment: &Deployment,
        now: UnixTime,
        user: &UserId,
    ) -> Told<BTreeMap<NodeId, DownlinkCount>> {
        self.told(|history| history.cycle_reality_downlink(deployment, now, user))
    }

    /// What `read` tells of the usage collected:
    ///
    /// - `Ok(None)` while the usage cannot tell yet: `read` tells nothing
    ///   (the report does not reach far enough, or it has no cycle figure
    ///   for the user), or the collection is behind ([`behind`]: a node
    ///   not collected lately, as while it cannot be reached), which the
    ///   status's usage view and [`Self::failure`] say.
    /// - `Err` with the kind of a fault, as [`Self::ledgers`] gives it: the
    ///   store cannot be read or its latest write failed, or the figures
    ///   contradict each other. It is never read as usage that is behind:
    ///   the caller logs it.
    fn told<T>(
        &self,
        read: impl FnOnce(&CollectedUsage) -> Result<Option<T>, UsageError>,
    ) -> Told<T> {
        let history = match &self.store {
            StoreState::Ready(history) => history,
            StoreState::Unreadable { kind } => return Err(*kind),
            StoreState::Unwritten { .. } => return Err(UsageErrorKind::StoreUnavailable),
        };
        match read(history) {
            Ok(told) => Ok(told),
            Err(error) if behind(error.kind()) => Ok(None),
            Err(error) => Err(error.kind()),
        }
    }

    pub(crate) fn failure(&self) -> Option<&str> {
        self.store_failure.as_deref().or(self.failure.as_deref())
    }
    pub(crate) fn take_gaps(&mut self) -> Vec<String> {
        std::mem::take(&mut self.gaps)
    }

    /// Uses at most one bounded request, and says whether it made one
    /// ([`Pulled`]), so that nothing else asks on the same tick. Failed
    /// batches are tried at the next interval; fresh persisted snapshots
    /// remain timestamped and the core refuses them once their three-minute
    /// freshness limit expires.
    pub(crate) fn tick(
        &mut self,
        env: &Env<'_>,
        deployment: &Deployment,
        egress: &BsdName,
        now: UnixTime,
        budget: Duration,
        interval: Duration,
    ) -> Pulled {
        let StoreState::Ready(history) = &mut self.store else {
            return Pulled::Nothing;
        };
        if Instant::now() < self.first {
            return Pulled::Nothing;
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
            let Some(node) = node else {
                return Pulled::Nothing;
            };
            let saved = history.node(&node.id).cloned().unwrap_or_default();
            match batch(node.clone(), saved, now) {
                Ok(batch) => self.pending = Some(batch),
                Err(error) => {
                    self.failure = Some(error.to_string());
                    self.due.insert(node.id.clone(), Instant::now() + interval);
                    return Pulled::Nothing;
                }
            }
        }
        let Some(mut batch) = self.pending.take() else {
            return Pulled::Nothing;
        };
        let Some(task) = batch.tasks.pop_front() else {
            return Pulled::Nothing;
        };
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
                return Pulled::Asked(None);
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
                return Pulled::Asked(None);
            }
        };
        if batch.tasks.is_empty() {
            let StoreState::Ready(history) = &self.store else {
                return Pulled::Asked(None);
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
        Pulled::Asked(polled.map(Box::new))
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
        // A batch that began before this sighting keeps it when `tick`
        // installs the batch (`set_node`), while the node held nothing.
        candidate.observe_unserved_nodes(deployment, now);
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
