// SPDX-License-Identifier: GPL-3.0-or-later

//! `router history` (design §15.6 rule 11, §15.7): the samples the daemon
//! recorded, one per poll of the M7, read from the day files
//! `mooring-store` keeps and printed as the document Mooring.app reads
//! (`--json`, one line) or as a summary: a header per day, the events the
//! samples show, and the hourly statistics.
//!
//! The command reads and never writes: a torn last line is reported as an
//! incomplete day, not cut (the daemon's next append does that). It reads
//! the days of its range one at a time; a line the decoder refuses ends it
//! with an error naming the file and the line, never the bytes. The range
//! is at most the days the daemon keeps; the default is yesterday and
//! today, UTC, by the Mac's clock.

use std::io::{self, Write};
use std::path::Path;

use mooring_daemon_core::radio_history::{
    HourBin, RadioEventKind, RadioHistory, RadioPoll, RadioSample, Stats, decode_line, hourly,
};
use mooring_model::error::ModelError;
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{RadioDay, radio_day_path, read_radio_day};

use crate::app::{Env, support_dir};
use crate::daemon::radio::RADIO_HISTORY_DAYS;
use crate::error::{CommandError, LocalError};
use crate::router::error::reason_phrase;
use crate::router::output::{Tenths, json_line, utc_stamp};

/// One day of the range as read.
struct Day {
    date: CalendarDate,
    samples: Vec<RadioSample>,
    /// Whether the file ended in a line without its newline.
    torn: bool,
}

fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

/// `router history [--since <date>] [--until <date>] [--json]`.
pub(crate) fn history(
    env: &Env<'_>,
    out: &mut dyn Write,
    since: Option<CalendarDate>,
    until: Option<CalendarDate>,
    json: bool,
) -> Result<(), CommandError> {
    let today = CalendarDate::utc_of((env.clock)()?).map_err(|_| LocalError::Clock)?;
    let (since, until) = range(today, since, until)?;
    let dir = support_dir(env)?;
    let days = read_days(&dir, since, until)?;
    let samples: Vec<RadioSample> = days
        .iter()
        .flat_map(|day| day.samples.iter().copied())
        .collect();
    let incomplete: Vec<CalendarDate> = days
        .iter()
        .filter(|day| day.torn)
        .map(|day| day.date)
        .collect();
    let history = RadioHistory::new(since, until, samples, incomplete);
    let text = if json {
        json_line(&history).map_err(|error| output(io::Error::other(error)))?
    } else {
        summary(&history, &days).map_err(|_| LocalError::Clock)?
    };
    out.write_all(text.as_bytes()).map_err(output)
}

/// The range asked for: `until` defaults to today and `since` to the day
/// before `until`; it must not run backwards nor cover more days than the
/// daemon keeps.
fn range(
    today: CalendarDate,
    since: Option<CalendarDate>,
    until: Option<CalendarDate>,
) -> Result<(CalendarDate, CalendarDate), LocalError> {
    let until = until.unwrap_or(today);
    let since = match since {
        Some(since) => since,
        None => CalendarDate::from_days_since_epoch(until.days_since_epoch().saturating_sub(1))
            .map_err(|_| LocalError::Clock)?,
    };
    if since > until {
        return Err(LocalError::HistoryRange { since, until });
    }
    let days = until.days_since_epoch() - since.days_since_epoch() + 1;
    if days > RADIO_HISTORY_DAYS {
        return Err(LocalError::HistoryRangeTooLong {
            days,
            max: RADIO_HISTORY_DAYS,
        });
    }
    Ok((since, until))
}

/// The days of the range, each read and decoded in turn; a day without a
/// file is empty.
fn read_days(
    dir: &Path,
    since: CalendarDate,
    until: CalendarDate,
) -> Result<Vec<Day>, CommandError> {
    let mut days = Vec::new();
    let mut date = since;
    loop {
        let day = match read_radio_day(dir, date)
            .map_err(|error| LocalError::HistoryFile(Box::new(error)))?
        {
            None => Day {
                date,
                samples: Vec::new(),
                torn: false,
            },
            Some(RadioDay { lines, torn }) => {
                let path = radio_day_path(dir, date);
                let mut samples = Vec::new();
                for (index, line) in lines.split_inclusive(|&byte| byte == b'\n').enumerate() {
                    samples.push(decode_line(line).map_err(|source| LocalError::HistoryLine {
                        path: path.clone(),
                        line: index + 1,
                        source,
                    })?);
                }
                Day {
                    date,
                    samples,
                    torn,
                }
            }
        };
        days.push(day);
        if date == until {
            break;
        }
        date = date.checked_add_days(1).map_err(|_| LocalError::Clock)?;
    }
    Ok(days)
}

/// How many of `samples` there are, and how many read a status.
fn counts(samples: &[RadioSample]) -> (usize, usize) {
    let read = samples
        .iter()
        .filter(|sample| matches!(sample.poll, RadioPoll::Read(_)))
        .count();
    (samples.len(), read)
}

/// The summary: one header line for the range, one per day, the events,
/// then the hourly table when there are samples. Every line ends in a
/// newline. `Err` only past the year 9999.
fn summary(history: &RadioHistory, days: &[Day]) -> Result<String, ModelError> {
    let (polls, read) = counts(history.samples());
    let mut text = format!(
        "radio history {} to {} UTC: {polls} polls, {read} read\n",
        history.since(),
        history.until()
    );
    for day in days {
        let (polls, read) = counts(&day.samples);
        if polls == 0 {
            text.push_str(&format!("{}: no samples", day.date));
        } else {
            text.push_str(&format!("{}: {polls} polls, {read} read", day.date));
        }
        if day.torn {
            text.push_str(
                "; the last line is incomplete (the daemon may be writing it, or stopped while writing it)",
            );
        }
        text.push('\n');
    }
    if history.events().is_empty() {
        text.push_str("events: none\n");
    } else {
        text.push_str("events:\n");
        for event in history.events() {
            text.push_str(&format!(
                "  {}  {}\n",
                utc_stamp(event.at)?,
                event_text(event.kind)
            ));
        }
    }
    let bins = hourly(history.samples());
    if !bins.is_empty() {
        text.push_str(
            "by hour (polls/read; LTE RSRP and SINR, NR RSRP and SINR as min/median/max; service types seen):\n",
        );
        for bin in &bins {
            text.push_str(&format!(
                "  {}  {}/{}  LTE RSRP {}, SINR {}; NR RSRP {}, SINR {}; {}\n",
                hour_stamp(bin.start)?,
                bin.polls,
                bin.read,
                stats_text(bin.lte_rsrp, "dBm"),
                stats_text(bin.lte_sinr, "dB"),
                stats_text(bin.nr_rsrp, "dBm"),
                stats_text(bin.nr_sinr, "dB"),
                services_text(bin),
            ));
        }
    }
    Ok(text)
}

/// `<yyyy-mm-dd> <hh>:00`, the hour `start` begins.
fn hour_stamp(start: UnixTime) -> Result<String, ModelError> {
    let date = CalendarDate::utc_of(start)?;
    Ok(format!("{date} {:02}:00", start.as_secs() % 86_400 / 3_600))
}

/// `min/median/max <unit>`, or "not reported".
fn stats_text<T: Into<i16> + Copy>(stats: Option<Stats<T>>, unit: &str) -> String {
    match stats {
        Some(stats) => format!(
            "{}/{}/{} {unit}",
            Tenths(stats.min.into()),
            Tenths(stats.median.into()),
            Tenths(stats.max.into())
        ),
        None => "not reported".to_owned(),
    }
}

/// The network service types a bin saw, in the M7's spellings, and how
/// many reads had none.
fn services_text(bin: &HourBin) -> String {
    if bin.read == 0 {
        return "no reads".to_owned();
    }
    if bin.services.is_empty() {
        return "no service".to_owned();
    }
    let names: Vec<&str> = bin.services.iter().map(|service| service.wire()).collect();
    let mut text = names.join(", ");
    if bin.no_service > 0 {
        text.push_str(&format!(" ({} without service)", bin.no_service));
    }
    text
}

/// An event, in the M7's own spellings.
fn event_text(kind: RadioEventKind) -> String {
    match kind {
        RadioEventKind::PollFailed { reason } => format!("poll failed: {}", reason_phrase(reason)),
        RadioEventKind::PollRecovered => "poll recovered".to_owned(),
        RadioEventKind::RouterRebooted => {
            "the M7 rebooted (uptime shorter than at the last read)".to_owned()
        }
        RadioEventKind::ServiceLost => "no service".to_owned(),
        RadioEventKind::ServiceRegained => "service regained".to_owned(),
        RadioEventKind::NetworkServiceChanged { from, to } => {
            format!("network service {} -> {}", from.wire(), to.wire())
        }
        RadioEventKind::DataServiceChanged { from, to } => {
            format!("data service {} -> {}", from.wire(), to.wire())
        }
        RadioEventKind::BandChanged { from, to } => format!("band {from} -> {to}"),
        RadioEventKind::PlmnChanged { from, to } => {
            format!("network {}-{} -> {}-{}", from.mcc, from.mnc, to.mcc, to.mnc)
        }
        RadioEventKind::SessionRestarted => {
            "data session restarted (shorter than at the last read)".to_owned()
        }
    }
}
