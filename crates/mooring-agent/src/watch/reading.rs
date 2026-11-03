// SPDX-License-Identifier: GPL-3.0-or-later

//! The reading (design §11.3 step 4, §11.5): the host, the engine units,
//! the uplink's transfer and accounting, taken anew every
//! [`HOST_READING_SECS`], and the view's in between.

use std::collections::BTreeSet;

use mooring_agent_proto::{
    EngineHealth, EngineUser, NftCounter, StatsEmail, UnixTime, WatchConfig,
};

use super::nft::counter;
use super::status::{AccountingView, Failure, HostReading};
use super::transfer::{self, Transfer};
use super::{Fatal, HOST_READING_SECS, Watch, engines, host};
use crate::accounting::{self, Canary, Readings, XrayRun, stats};
use crate::host::Node;
use crate::paths::Paths;
use crate::store::errno;

/// The latest reading: taken every [`HOST_READING_SECS`], else the view's.
#[derive(Debug, Clone)]
pub(super) struct Reading {
    pub(super) host: HostReading,
    pub(super) engines: EngineHealth,
    pub(super) transfer: Transfer,
    pub(super) accounting: AccountingView,
}

/// One accounting poll of Xray's API.
enum XrayPoll {
    /// It read the counters, and Xray's Go heap.
    Read(Readings, u64),
    /// The API failed (`StatsQueryFailed`).
    Failed,
    /// Xray restarted during the poll, so the counters may be of either
    /// run: the poll is taken again at the next reading.
    Torn,
}

impl Watch {
    /// The reading, taken anew every [`HOST_READING_SECS`] (and at the
    /// first tick, or after the clock stepped back): the host, the engine
    /// units, the uplink's transfer, and accounting.
    pub(super) fn reading(
        &self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
        boot_id: &str,
        config: Option<&WatchConfig>,
    ) -> Result<Reading, Fatal> {
        if let Some(view) = &self.view
            && now
                .secs_since(view.host.at)
                .is_some_and(|age| age < HOST_READING_SECS)
        {
            return Ok(Reading {
                host: view.host,
                engines: view.engines,
                transfer: view.transfer.clone(),
                accounting: view.accounting.clone(),
            });
        }
        let host = host::read(paths, node, now)?;
        let xray = engines::read(node, EngineUser::Xray)?;
        let hy2 = engines::read(node, EngineUser::Hy2)?;
        let transfer = Transfer::next(
            self.view.as_ref().map(|view| &view.transfer),
            now,
            transfer::read(paths, boot_id)?,
        )?;
        let boot_secs = host.health.uptime_secs;
        let (accounting, go_heap) = self.account(
            paths,
            node,
            now,
            (boot_id, boot_secs),
            config.filter(|_| xray.active_since.is_some()).is_some(),
            config.map(|config| &config.emails),
        )?;
        Ok(Reading {
            host,
            engines: EngineHealth {
                xray: xray.state(boot_secs, go_heap),
                hy2: hy2.state(boot_secs, None),
            },
            transfer,
            accounting,
        })
    }

    /// Accounting at a reading: retention first, whatever else happens;
    /// then, with Xray running, a poll. `last_active` keeps only the
    /// `applied` configuration's emails (none without a generation).
    /// Returns the view and Xray's Go heap.
    fn account(
        &self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
        (boot_id, boot_secs): (&str, u64),
        running: bool,
        applied: Option<&BTreeSet<StatsEmail>>,
    ) -> Result<(AccountingView, Option<u64>), Fatal> {
        let failed = accounting::prune(paths, now).err().map(|error| Failure {
            errno: errno(&error),
        });
        let is_applied =
            |email: &StatsEmail| applied.is_some_and(|applied| applied.contains(email));
        let previous = self
            .view
            .as_ref()
            .map(|view| view.accounting.clone())
            .unwrap_or_default();
        let mut view = AccountingView {
            last_active: previous
                .last_active
                .into_iter()
                .filter(|(email, _)| is_applied(email))
                .collect(),
            failed,
            ..previous
        };
        if !running {
            // Nothing to ask: no generation, or Xray stopped (halted).
            view.query_failed = false;
            return Ok((view, None));
        }
        let (readings, go_heap) = match poll_xray(paths, node, boot_id, boot_secs)? {
            XrayPoll::Read(readings, go_heap) => (readings, go_heap),
            XrayPoll::Failed => {
                view.query_failed = true;
                return Ok((view, None));
            }
            XrayPoll::Torn => return Ok((view, None)),
        };
        view.query_failed = false;
        match accounting::load(paths)
            .and_then(|stored| accounting::poll(paths, stored, now, readings))
        {
            Ok(polled) => {
                view.at = Some(now);
                for email in polled.grew {
                    if is_applied(&email) {
                        view.last_active.insert(email, now);
                    }
                }
                match polled.canary {
                    Canary::Counted => view.canary_missing = false,
                    Canary::Missing => view.canary_missing = true,
                    Canary::Unknown => {}
                }
            }
            Err(error) => {
                view.failed = Some(Failure {
                    errno: errno(&error),
                });
            }
        }
        Ok((view, Some(go_heap)))
    }
}

/// Polls Xray's API: `statssys` around the counters and the probe-flow
/// counter, so that a restart between them shows.
fn poll_xray(
    paths: &Paths,
    node: &dyn Node,
    boot_id: &str,
    boot_secs: u64,
) -> Result<XrayPoll, Fatal> {
    let Ok(before) = stats::sys(paths, node) else {
        return Ok(XrayPoll::Failed);
    };
    let probe_flows = counter(node, NftCounter::ProbeFlows)?;
    let (Ok(counters), Ok(after)) = (stats::query(paths, node), stats::sys(paths, node)) else {
        return Ok(XrayPoll::Failed);
    };
    if after.uptime_secs < before.uptime_secs {
        return Ok(XrayPoll::Torn);
    }
    Ok(XrayPoll::Read(
        Readings {
            run: XrayRun {
                boot_id: boot_id.to_owned(),
                started_secs: boot_secs.saturating_sub(after.uptime_secs),
            },
            counters,
            probe_flows,
        },
        after.alloc_bytes,
    ))
}
