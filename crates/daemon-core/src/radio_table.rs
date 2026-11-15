// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history as tables (design §15.6 rule 13): what
//! `mooringctl router history --csv` prints, for tools that read columns,
//! such as the MATLAB package under `matlab/`. The samples table has one
//! row per poll of the M7 and the events table one row per change between
//! polls. Both are made from the samples of [`crate::radio_history`] and
//! hold nothing those do not (design §15.5).
//!
//! A table is its header line and its rows, each ended by a newline, with
//! the cells separated by commas. The header is the format's version: a
//! column is never renamed, moved or given another meaning under the same
//! header, and a reader refuses a header it does not know. No cell needs
//! quoting. Each is a whole number, a reading, a time or a name:
//! - a reading is in its unit with one decimal (`-104.5`);
//! - a time is the Mac's, as seconds since 1970 and as
//!   `2026-10-13T19:20:00Z`;
//! - a name is from a closed vocabulary, spelled as the JSON document
//!   spells it, or a band (`B3`, `n78`) or a network's codes (`234-30`).
//!
//! A value the sample does not hold is an empty cell: a reading the M7
//! did not report, and everything a failed poll or a read without service
//! could not give.

use mooring_model::{CalendarDate, ModelError, UnixTime};

use crate::radio_history::{
    RadioEvent, RadioEventKind, RadioPoll, RadioReading, RadioSample, SampledAttachment,
    SampledRadio,
};
use crate::router::{DataService, NetworkService, Plmn, RouterUnavailableReason, ThermalState};

/// The samples table's header: its columns, in order.
pub const SAMPLES_HEADER: &str = concat!(
    "at_unix,at_utc,outcome,failure,uptime_secs,temperature_c,thermal,service,",
    "network_service,data_service,band,ca_secondary_count,",
    "lte_rsrp_dbm,lte_rsrq_db,lte_sinr_db,lte_rssi_dbm,",
    "nr_rsrp_dbm,nr_rsrq_db,nr_sinr_db,plmn,session_secs"
);

/// The events table's header: its columns, in order.
pub const EVENTS_HEADER: &str = "at_unix,at_utc,event,reason,from,to";

/// How many columns the samples table has.
const SAMPLE_COLUMNS: usize = 21;

/// How many columns the events table has.
const EVENT_COLUMNS: usize = 6;

const SECS_PER_DAY: u64 = 86_400;

/// The samples table of `samples`, in their order: the header, then one
/// row per sample. `Err` only for a sample dated past the year 9999.
pub fn samples_table(samples: &[RadioSample]) -> Result<String, ModelError> {
    let mut table = String::from(SAMPLES_HEADER);
    table.push('\n');
    for sample in samples {
        push_row(&mut table, &sample_cells(sample)?);
    }
    Ok(table)
}

/// The events table of `events`, in their order: the header, then one row
/// per event. `Err` only for an event dated past the year 9999.
pub fn events_table(events: &[RadioEvent]) -> Result<String, ModelError> {
    let mut table = String::from(EVENTS_HEADER);
    table.push('\n');
    for event in events {
        push_row(&mut table, &event_cells(event)?);
    }
    Ok(table)
}

fn push_row(table: &mut String, cells: &[String]) {
    table.push_str(&cells.join(","));
    table.push('\n');
}

/// A sample's cells, in the header's order.
fn sample_cells(sample: &RadioSample) -> Result<[String; SAMPLE_COLUMNS], ModelError> {
    let (outcome, failure, reading): (_, _, Option<&RadioReading>) = match &sample.poll {
        RadioPoll::Read(reading) => ("read", "", Some(reading)),
        RadioPoll::Failed { reason } => ("failed", failure_name(*reason), None),
    };
    let (service, attached): (_, Option<&SampledAttachment>) = match reading.map(|read| &read.radio)
    {
        None => ("", None),
        Some(SampledRadio::NoService) => ("no_service", None),
        Some(SampledRadio::Attached(attached)) => ("attached", Some(attached)),
    };
    Ok([
        sample.at.as_secs().to_string(),
        utc(sample.at)?,
        outcome.to_owned(),
        failure.to_owned(),
        whole(reading.map(|read| read.uptime_secs)),
        whole(reading.map(|read| read.temperature_c.get())),
        reading
            .map_or("", |read| thermal_name(read.thermal))
            .to_owned(),
        service.to_owned(),
        attached
            .map_or("", |radio| network_service_name(radio.network_service))
            .to_owned(),
        attached
            .map_or("", |radio| data_service_name(radio.data_service))
            .to_owned(),
        attached.map_or_else(String::new, |radio| radio.band.to_string()),
        whole(attached.map(|radio| radio.ca_secondary_count)),
        reading_cell(attached.and_then(|radio| radio.lte.rsrp)),
        reading_cell(attached.and_then(|radio| radio.lte.rsrq)),
        reading_cell(attached.and_then(|radio| radio.lte.sinr)),
        reading_cell(attached.and_then(|radio| radio.lte.rssi)),
        reading_cell(attached.and_then(|radio| radio.nr.rsrp)),
        reading_cell(attached.and_then(|radio| radio.nr.rsrq)),
        reading_cell(attached.and_then(|radio| radio.nr.sinr)),
        attached.map_or_else(String::new, |radio| codes(radio.plmn)),
        whole(attached.map(|radio| radio.session_secs)),
    ])
}

/// An event's cells, in the header's order: its name, the reason of a
/// failed poll, and what a change went from and to.
fn event_cells(event: &RadioEvent) -> Result<[String; EVENT_COLUMNS], ModelError> {
    let none = String::new;
    let (name, reason, from, to) = match event.kind {
        RadioEventKind::PollFailed { reason } => {
            ("poll_failed", failure_name(reason), none(), none())
        }
        RadioEventKind::PollRecovered => ("poll_recovered", "", none(), none()),
        RadioEventKind::RouterRebooted => ("router_rebooted", "", none(), none()),
        RadioEventKind::ServiceLost => ("service_lost", "", none(), none()),
        RadioEventKind::ServiceRegained => ("service_regained", "", none(), none()),
        RadioEventKind::NetworkServiceChanged { from, to } => (
            "network_service_changed",
            "",
            network_service_name(from).to_owned(),
            network_service_name(to).to_owned(),
        ),
        RadioEventKind::DataServiceChanged { from, to } => (
            "data_service_changed",
            "",
            data_service_name(from).to_owned(),
            data_service_name(to).to_owned(),
        ),
        RadioEventKind::BandChanged { from, to } => {
            ("band_changed", "", from.to_string(), to.to_string())
        }
        RadioEventKind::PlmnChanged { from, to } => ("plmn_changed", "", codes(from), codes(to)),
        RadioEventKind::SessionRestarted => ("session_restarted", "", none(), none()),
    };
    Ok([
        event.at.as_secs().to_string(),
        utc(event.at)?,
        name.to_owned(),
        reason.to_owned(),
        from,
        to,
    ])
}

/// `time` as `<yyyy-mm-dd>T<hh>:<mm>:<ss>Z`. `Err` only past the year
/// 9999.
fn utc(time: UnixTime) -> Result<String, ModelError> {
    let date = CalendarDate::utc_of(time)?;
    let of_day = time.as_secs() % SECS_PER_DAY;
    Ok(format!(
        "{date}T{:02}:{:02}:{:02}Z",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    ))
}

/// A whole number, or the empty cell.
fn whole<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

/// A reading held in tenths of its unit, with its one decimal (`-1045` is
/// `-104.5`, `-5` is `-0.5`, `0` is `0.0`), or the empty cell.
fn reading_cell<T: Into<i16>>(reading: Option<T>) -> String {
    reading.map_or_else(String::new, |reading| {
        let tenths: i16 = reading.into();
        let sign = if tenths < 0 { "-" } else { "" };
        let magnitude = tenths.unsigned_abs();
        format!("{sign}{}.{}", magnitude / 10, magnitude % 10)
    })
}

/// A network's codes, as `<mcc>-<mnc>`.
fn codes(plmn: Plmn) -> String {
    format!("{}-{}", plmn.mcc, plmn.mnc)
}

/// The reason's name, as the JSON document spells it.
const fn failure_name(reason: RouterUnavailableReason) -> &'static str {
    match reason {
        RouterUnavailableReason::NotConfigured => "not_configured",
        RouterUnavailableReason::Unreachable => "unreachable",
        RouterUnavailableReason::AuthFailed => "auth_failed",
        RouterUnavailableReason::IdentityMismatch => "identity_mismatch",
        RouterUnavailableReason::Unsupported => "unsupported",
        RouterUnavailableReason::Malformed => "malformed",
        RouterUnavailableReason::LocalFailure => "local_failure",
    }
}

/// The network service type's name, as the JSON document spells it.
const fn network_service_name(service: NetworkService) -> &'static str {
    match service {
        NetworkService::Nr5g => "nr5g",
        NetworkService::Lte => "lte",
    }
}

/// The data service type's name, as the JSON document spells it.
const fn data_service_name(service: DataService) -> &'static str {
    match service {
        DataService::NrSub6 => "nr_sub6",
        DataService::Lte => "lte",
        DataService::LtePlus => "lte_plus",
    }
}

/// The thermal state's name, as the JSON document spells it.
const fn thermal_name(state: ThermalState) -> &'static str {
    match state {
        ThermalState::Normal => "normal",
    }
}
