// SPDX-License-Identifier: GPL-3.0-or-later

//! Accounting (design §11.5): at every reading the watch polls Xray's
//! per-email counters and records what grew, per UTC month in
//! `/var/lib/mooring/usage/<YYYY-MM>.json` (`Usage{month}`) and in the
//! series (`UsageSeries`, [`series`]). Nothing else is recorded: no
//! destination and no address.
//!
//! Counters only grow within one run of Xray, so a poll adds each
//! counter's growth since the poll before in the same run, and after Xray
//! restarted, all a counter holds (what was counted between the last poll
//! and the restart is lost: at most one interval). A run is the boot and
//! the second since boot at which Xray's stats service started (`statssys`
//! `Uptime` against `/proc/uptime`), which no clock step moves. The first
//! poll the node ever makes is only a baseline.
//!
//! `usage/accounting.json` holds the latest poll, with what it added, and
//! the series. It is written before the month's file, which records the
//! poll it last took in, so a poll that a crash kept out of its month's
//! file is taken in at the next poll: every poll counts in its month
//! exactly once.
//!
//! Retention (F7): a month's file is removed [`MONTH_KEEP_SECS`] after its
//! month ends and never served after; the series keeps each bin
//! [`series::SERIES_KEEP_SECS`] after it ends; an email's `last_active` is
//! dropped once the applied configuration (`watch.json`'s emails) no longer
//! has it. A usage file
//! that cannot be read or written stops accounting and is reported
//! (`StateWrite`), and never affects the gate.

pub(crate) mod series;
pub(crate) mod stats;

use std::collections::BTreeMap;
use std::fs;
use std::io;

use mooring_agent_proto::{
    AgentError, IoOp, Principal, SeriesRange, StatsEmail, Traffic, UnixTime, UsageMonth,
    UsageSeriesV1, UsageV1,
};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::store::{io_error, malformed, read_json, remove, write_json};
use series::Series;

/// How long a month's file is kept after its month ends: 7 days (F7).
pub(crate) const MONTH_KEEP_SECS: u64 = 7 * 86_400;

/// The usage files are read by the `mooring` group (the viewer's
/// `Usage` and `UsageSeries`).
const MODE: u32 = 0o640;

/// How far two readings of one run's start may differ: each is rounded
/// down to a second.
const RUN_START_SLACK_SECS: u64 = 2;

/// The run of Xray a poll read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayRun {
    /// The kernel's boot id.
    pub(crate) boot_id: String,
    /// When its stats service started, in seconds since boot.
    pub(crate) started_secs: u64,
}

impl XrayRun {
    /// Whether this is the run `earlier` read.
    fn is(&self, earlier: &Self) -> bool {
        self.boot_id == earlier.boot_id
            && self.started_secs.abs_diff(earlier.started_secs) <= RUN_START_SLACK_SECS
    }
}

/// What one poll read, within one run of Xray.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Readings {
    pub(crate) run: XrayRun,
    /// Every accounting email's counters, at zero included.
    pub(crate) counters: BTreeMap<StatsEmail, Traffic>,
    /// The `probe_flows` counter (in-chain probe flows Xray opened).
    pub(crate) probe_flows: u64,
}

/// A poll, unique even across a lost `accounting.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PollId {
    at: UnixTime,
    seq: u64,
}

/// The latest poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    id: PollId,
    run: XrayRun,
    counters: BTreeMap<StatsEmail, Traffic>,
    probe_flows: u64,
    /// What it added to its month, the month of its last second.
    added: BTreeMap<StatsEmail, Traffic>,
}

/// `usage/accounting.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Accounting {
    poll: Poll,
    series: Series,
}

/// A month's file: its usage, and the latest poll it took in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonthFile {
    usage: UsageV1,
    poll: PollId,
}

/// What a poll shows about the accounting canary (design §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Canary {
    /// A probe counter exists, so Xray counts.
    Counted,
    /// An in-chain probe flow left Xray in this run since the poll before,
    /// so its counters were registered, and none exists: Xray is not
    /// counting (`AccountingCanaryMissing`).
    Missing,
    /// Neither: nothing new is known.
    Unknown,
}

/// What a poll found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Polled {
    /// The emails whose counters grew since the poll before, when the
    /// series continued, so that their growth is dated to this poll.
    pub(crate) grew: Vec<StatsEmail>,
    pub(crate) canary: Canary,
}

/// The stored accounting; `None` before the first poll.
pub(crate) fn load(paths: &Paths) -> Result<Option<Accounting>, AgentError> {
    read_json(&paths.accounting())
}

/// Records a poll at `now` that read `readings`, after `stored`: first
/// takes the stored poll into its month if a crash kept it out, then
/// writes the new poll and the series, then takes it into its month.
pub(crate) fn poll(
    paths: &Paths,
    stored: Option<Accounting>,
    now: UnixTime,
    readings: Readings,
) -> Result<Polled, AgentError> {
    if let Some(stored) = &stored {
        take_in(paths, &stored.poll)?;
    }
    let (previous, mut series) = match stored {
        Some(stored) => (Some(stored.poll), stored.series),
        None => (None, Series::default()),
    };
    let same_run = previous
        .as_ref()
        .filter(|previous| readings.run.is(&previous.run));
    let added = match (&previous, same_run) {
        (None, _) => BTreeMap::new(),
        (Some(_), Some(previous)) => growth(Some(&previous.counters), &readings.counters),
        (Some(_), None) => growth(None, &readings.counters),
    };
    let probe_counted = readings
        .counters
        .keys()
        .any(|email| email.principal == Principal::Probe);
    let canary = if probe_counted {
        Canary::Counted
    } else if same_run
        .is_some_and(|previous| flows_grew(previous.probe_flows, readings.probe_flows))
    {
        Canary::Missing
    } else {
        Canary::Unknown
    };
    let id = PollId {
        at: now,
        seq: previous.as_ref().map_or(1, |previous| previous.id.seq + 1),
    };
    let continued = series.record(
        id.seq,
        now,
        previous.as_ref().map(|previous| previous.id.seq),
        &added,
    );
    let poll = Poll {
        id,
        run: readings.run,
        counters: readings.counters,
        probe_flows: readings.probe_flows,
        added,
    };
    let grew = if continued {
        poll.added.keys().cloned().collect()
    } else {
        Vec::new()
    };
    let accounting = Accounting { poll, series };
    write_json(&paths.accounting(), &accounting, MODE)?;
    take_in(paths, &accounting.poll)?;
    Ok(Polled { grew, canary })
}

/// What each counter grew by since `before`, the counters of the poll
/// before in the same run, or, after a restart (`None`), all it holds. A
/// counter `before` lacks was registered since, from zero; one below its
/// reading in `before` was reset (only `statsquery -reset` does that, and
/// the agent never sends it), and counts from zero.
fn growth(
    before: Option<&BTreeMap<StatsEmail, Traffic>>,
    now: &BTreeMap<StatsEmail, Traffic>,
) -> BTreeMap<StatsEmail, Traffic> {
    let grown = |base: u64, value: u64| if value >= base { value - base } else { value };
    now.iter()
        .filter_map(|(email, counted)| {
            let base = before
                .and_then(|before| before.get(email))
                .copied()
                .unwrap_or_default();
            let added = Traffic {
                uplink: grown(base.uplink, counted.uplink),
                downlink: grown(base.downlink, counted.downlink),
            };
            (added.uplink > 0 || added.downlink > 0).then(|| (email.clone(), added))
        })
        .collect()
}

/// Whether the probe-flow counter shows a flow since `before`: grown, or,
/// after the ruleset was loaded again (which zeroes it), above zero.
const fn flows_grew(before: u64, now: u64) -> bool {
    if now >= before { now > before } else { now > 0 }
}

/// The month a poll's bytes count in: that of its last second.
fn month_of(at: UnixTime) -> Result<UsageMonth, AgentError> {
    UsageMonth::containing(UnixTime::from_secs(at.as_secs().saturating_sub(1)))
        .map_err(|_| malformed(IoOp::WriteState))
}

/// Takes `poll` into its month's file unless the file already took it in;
/// the poll's month gets a file even when the poll added nothing.
fn take_in(paths: &Paths, poll: &Poll) -> Result<(), AgentError> {
    let month = month_of(poll.id.at)?;
    let path = paths.usage_month(month);
    let file: Option<MonthFile> = read_json(&path)?;
    let mut usage = match file {
        // Taken in already, or nothing to add.
        Some(file) if file.poll == poll.id || poll.added.is_empty() => return Ok(()),
        Some(file) => file.usage,
        None => UsageV1 {
            month,
            updated_at: poll.id.at,
            traffic: BTreeMap::new(),
        },
    };
    for (email, bytes) in &poll.added {
        let total = usage.traffic.entry(email.clone()).or_default();
        total.uplink = total.uplink.saturating_add(bytes.uplink);
        total.downlink = total.downlink.saturating_add(bytes.downlink);
    }
    usage.updated_at = poll.id.at;
    write_json(
        &path,
        &MonthFile {
            usage,
            poll: poll.id,
        },
        MODE,
    )
}

/// Whether `month`'s retention has ended at `now`.
fn month_expired(month: UsageMonth, now: UnixTime) -> bool {
    month
        .next()
        .is_some_and(|next| now.as_secs() >= next.start().as_secs().saturating_add(MONTH_KEEP_SECS))
}

/// Ends what retention has ended at `now`: the month files past their
/// keep, the series' expired bins, and any temporary file a crash left in
/// the usage directory (only the watch writes there, and not while this
/// runs).
pub(crate) fn prune(paths: &Paths, now: UnixTime) -> Result<(), AgentError> {
    let entries = match fs::read_dir(paths.usage_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(IoOp::ReadState, &error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| io_error(IoOp::ReadState, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let leftover = name.starts_with('.') && name.ends_with(".tmp");
        let expired_month = name
            .strip_suffix(".json")
            .and_then(|month| month.parse::<UsageMonth>().ok())
            .is_some_and(|month| month_expired(month, now));
        if leftover || expired_month {
            remove(&entry.path())?;
        }
    }
    if let Some(mut accounting) = load(paths)?
        && accounting.series.prune(now)
    {
        write_json(&paths.accounting(), &accounting, MODE)?;
    }
    Ok(())
}

/// `Usage{month}` at `now`.
pub(crate) fn usage(
    paths: &Paths,
    now: UnixTime,
    month: UsageMonth,
) -> Result<UsageV1, AgentError> {
    if month_expired(month, now) {
        return Err(AgentError::NoUsageRecorded { month });
    }
    read_json::<MonthFile>(&paths.usage_month(month))?
        .map(|file| file.usage)
        .ok_or(AgentError::NoUsageRecorded { month })
}

/// `UsageSeries{range}` at `now`.
pub(crate) fn usage_series(
    paths: &Paths,
    now: UnixTime,
    range: SeriesRange,
) -> Result<UsageSeriesV1, AgentError> {
    match load(paths)? {
        Some(accounting) => accounting.series.answer(range, now),
        None => Err(AgentError::SeriesNotRecorded { recorded: None }),
    }
}
