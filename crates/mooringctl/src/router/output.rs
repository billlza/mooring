// SPDX-License-Identifier: GPL-3.0-or-later

//! What `router status` prints: a human summary, or one JSON line of the
//! `RouterReading` (`--json`). Enum values print as the M7 spells them, so
//! the operator can compare with its web interface. Text the M7 reports
//! (the firmware and web app versions, the network's and the SIM's names)
//! prints in double quotes, so nothing it holds can read as the summary's
//! own words, such as "not reported".

use std::fmt::{self, Write as _};

use mooring_daemon_core::router::netgear::NETGEAR_MODEL;
use mooring_daemon_core::router::{
    CarrierName, LteCarrier, LteCarriers, LteSignal, NrSignal, Radio, RadioState, RouterAdvisory,
    RouterReading, RouterStatus, WebAppVersion,
};
use mooring_model::date::CalendarDate;
use mooring_model::error::ModelError;
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;

const SECONDS_PER_DAY: u64 = 86_400;

/// A reading in tenths of its unit, shown with one decimal only when it
/// has one: `-1040` is `-104`, `-1045` is `-104.5`, `-5` is `-0.5`.
pub(crate) struct Tenths(pub(crate) i16);

impl fmt::Display for Tenths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let magnitude = self.0.unsigned_abs();
        let (whole, tenth) = (magnitude / 10, magnitude % 10);
        if tenth == 0 {
            write!(f, "{sign}{whole}")
        } else {
            write!(f, "{sign}{whole}.{tenth}")
        }
    }
}

/// A reading with its unit, or "not reported".
struct Reading(Option<i16>, &'static str);

impl fmt::Display for Reading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(tenths) => write!(f, "{} {}", Tenths(tenths), self.1),
            None => f.write_str("not reported"),
        }
    }
}

/// Text the M7 reported, in double quotes with `"` and `\` escaped by a
/// `\`, so its end is always where the text ends.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        for character in self.0.chars() {
            if matches!(character, '"' | '\\') {
                f.write_char('\\')?;
            }
            f.write_char(character)?;
        }
        f.write_char('"')
    }
}

/// Text the M7 may report as the empty string, which the status holds as
/// `None`: the text quoted, or `absent`, in the summary's own words.
fn reported(text: Option<&str>, absent: &str) -> String {
    text.map_or_else(|| absent.to_owned(), |text| Quoted(text).to_string())
}

/// A duration in seconds as `<days>d <hh>:<mm>:<ss>`.
struct Span(u64);

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (days, rest) = (self.0 / SECONDS_PER_DAY, self.0 % SECONDS_PER_DAY);
        write!(
            f,
            "{days}d {:02}:{:02}:{:02}",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        )
    }
}

const fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

fn carrier(carrier: LteCarrier) -> String {
    format!("B{} {}", carrier.band.get(), carrier.dl_bandwidth.wire())
}

fn carriers(carriers: Option<&LteCarriers>) -> String {
    match carriers {
        None => "none".to_owned(),
        Some(carriers) => {
            let mut text = format!("{} (primary)", carrier(carriers.primary()));
            for secondary in carriers.secondary() {
                text.push_str(", ");
                text.push_str(&carrier(*secondary));
            }
            match carriers.unassigned_slots() {
                0 => {}
                1 => text.push_str(", 1 unassigned slot"),
                slots => text.push_str(&format!(", {slots} unassigned slots")),
            }
            text
        }
    }
}

fn lte_line(lte: &LteSignal) -> String {
    format!(
        "LTE RSRP {}, RSRQ {}, SINR {}, RSSI {}",
        Reading(lte.rsrp.map(|value| value.tenths()), "dBm"),
        Reading(lte.rsrq.map(|value| value.tenths()), "dB"),
        Reading(lte.sinr.map(|value| value.tenths()), "dB"),
        Reading(lte.rssi.map(|value| value.tenths()), "dBm"),
    )
}

fn nr_line(nr: &NrSignal) -> String {
    format!(
        "NR RSRP {}, RSRQ {}, SINR {}",
        Reading(nr.rsrp.map(|value| value.tenths()), "dBm"),
        Reading(nr.rsrq.map(|value| value.tenths()), "dB"),
        Reading(nr.sinr.map(|value| value.tenths()), "dB"),
    )
}

fn radio_lines(lines: &mut Vec<String>, radio: &Radio, sim_spn: &str) {
    lines.push(format!(
        "radio connected: {}, {}, band {}; LTE carriers {}; secondary carriers {}; session {}",
        radio.network_service.wire(),
        radio.data_service.wire(),
        radio.band,
        carriers(radio.lte_carriers.as_ref()),
        radio.ca_secondary_count,
        Span(radio.session_secs),
    ));
    lines.push(format!(
        "network {} ({}-{}); SIM {sim_spn}",
        Quoted(radio.network.as_str()),
        radio.plmn.mcc,
        radio.plmn.mnc,
    ));
    lines.push(format!("{}; {}", lte_line(&radio.lte), nr_line(&radio.nr)));
}

/// `time` as `<yyyy-mm-dd> <hh>:<mm>:<ss> UTC`. `Err` only past the year
/// 9999.
pub(crate) fn utc_stamp(time: UnixTime) -> Result<String, ModelError> {
    let date = CalendarDate::utc_of(time)?;
    let of_day = time.as_secs() % SECONDS_PER_DAY;
    Ok(format!(
        "{date} {:02}:{:02}:{:02} UTC",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    ))
}

/// The human summary of `status`, read at `polled_at` on `interface` when
/// it is known (the daemon's status does not name it): one line per topic,
/// each ending in a newline. `Err` only if `polled_at` is past the year
/// 9999.
pub(crate) fn summary(
    interface: Option<&BsdName>,
    polled_at: UnixTime,
    status: &RouterStatus,
) -> Result<String, ModelError> {
    let polled = utc_stamp(polled_at)?;
    let parts = status.parts();
    // What the M7 reported as the empty string reads as not reported,
    // never as an empty name.
    let web_app = reported(
        parts.web_app.as_ref().map(WebAppVersion::as_str),
        "version not reported",
    );
    let sim_spn = reported(
        parts.sim_spn.as_ref().map(CarrierName::as_str),
        "name not reported",
    );
    let on = interface.map_or_else(String::new, |interface| {
        format!(" on {}", interface.as_str())
    });
    let mut lines = vec![
        format!("M7 {NETGEAR_MODEL}{on}, polled {polled}"),
        format!(
            "firmware {}, web app {web_app}; up {}; {} °C, thermal {}",
            Quoted(parts.firmware.as_str()),
            Span(parts.uptime_secs),
            parts.temperature_c.get(),
            parts.thermal.wire(),
        ),
    ];
    match &parts.radio {
        RadioState::Attached(radio) => radio_lines(&mut lines, radio, &sim_spn),
        RadioState::NoService => {
            lines.push(format!("radio no service; SIM {sim_spn}"));
        }
    }
    let battery = &parts.power.battery;
    lines.push(format!(
        "power {}; battery {} %, {}, {}, {}, {} °C",
        parts.power.state.wire(),
        battery.charge.get(),
        battery.state.wire(),
        if battery.charging {
            "charging"
        } else {
            "not charging"
        },
        battery.source.wire(),
        battery.temperature_c.get(),
    ));
    lines.push(format!(
        "counters received {} B, sent {} B",
        parts.counters.rx_bytes, parts.counters.tx_bytes
    ));
    let wifi = &parts.wifi;
    lines.push(format!(
        "Wi-Fi radio {} (main {}, guest {}, aux {}), {} clients",
        on_off(wifi.enabled),
        wifi.main.wire(),
        wifi.guest.wire(),
        wifi.aux.wire(),
        wifi.clients,
    ));
    let settings = &parts.settings;
    lines.push(format!(
        "offload Wi-Fi {}, Ethernet {}; UPnP {}; Analytics {}; Insight {}",
        on_off(settings.wifi_offload),
        on_off(settings.ethernet_offload),
        on_off(settings.upnp),
        on_off(settings.analytics),
        if settings.insight_active {
            "active"
        } else {
            "inactive"
        },
    ));
    let advisories = status.advisories();
    if !advisories.is_empty() {
        let names: Vec<&str> = advisories
            .iter()
            .map(|advisory| advisory_name(*advisory))
            .collect();
        lines.push(format!("the exit needs these off: {}", names.join(", ")));
    }
    lines.push(format!("unread SMS {}", parts.unread_sms));
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}

/// The setting an advisory names.
const fn advisory_name(advisory: RouterAdvisory) -> &'static str {
    match advisory {
        RouterAdvisory::WifiRadioOn => "Wi-Fi radio",
        RouterAdvisory::WifiOffloadOn => "Wi-Fi offload",
        RouterAdvisory::EthernetOffloadOn => "Ethernet offload",
        RouterAdvisory::UpnpOn => "UPnP",
        RouterAdvisory::InsightActive => "NETGEAR Insight",
    }
}

/// One line of JSON: the reading and a newline.
pub(crate) fn json_line(reading: &RouterReading) -> Result<String, serde_json::Error> {
    let mut line = serde_json::to_string(reading)?;
    line.push('\n');
    Ok(line)
}
