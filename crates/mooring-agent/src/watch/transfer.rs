// SPDX-License-Identifier: GPL-3.0-or-later

//! The uplink's transfer this UTC month (`StatusV1::transfer`, design
//! §11.3), which the provider bills: the interface's kernel counters,
//! counted as the deltas between the watch's readings and kept in its
//! view. The counters restart at every boot (the nightly reboot
//! included), so a reading in another boot, on another interface, or below
//! the one before is a reset, and counts from zero; what moved between
//! the last reading before a reset and the reset is not counted, so after
//! one the totals are a lower bound. A month counts from its first
//! reading.

use std::fs;

use mooring_agent_proto::{AgentError, IfName, IoOp, UnixTime, UplinkTransfer, UsageMonth};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::store::{io_error, malformed};

/// One reading of the uplink's counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counters {
    pub(crate) boot_id: String,
    pub(crate) interface: IfName,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
}

/// The month's transfer and the reading it was counted to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transfer {
    pub(crate) reported: UplinkTransfer,
    last: Counters,
}

impl Transfer {
    /// The transfer after `counters` were read at `now`, following
    /// `previous` (`None` for the watch's first reading).
    pub(crate) fn next(
        previous: Option<&Self>,
        now: UnixTime,
        counters: Counters,
    ) -> Result<Self, AgentError> {
        let month = UsageMonth::containing(now).map_err(|_| malformed(IoOp::ReadState))?;
        let fresh = UplinkTransfer {
            month,
            counted_from: now,
            rx_bytes: 0,
            tx_bytes: 0,
            counter_resets: 0,
        };
        let reported = match previous {
            Some(previous) if previous.reported.month == month => {
                let last = &previous.last;
                let reset = last.boot_id != counters.boot_id
                    || last.interface != counters.interface
                    || counters.rx_bytes < last.rx_bytes
                    || counters.tx_bytes < last.tx_bytes;
                let (rx, tx) = if reset {
                    (counters.rx_bytes, counters.tx_bytes)
                } else {
                    (
                        counters.rx_bytes - last.rx_bytes,
                        counters.tx_bytes - last.tx_bytes,
                    )
                };
                let was = previous.reported;
                UplinkTransfer {
                    rx_bytes: was.rx_bytes.saturating_add(rx),
                    tx_bytes: was.tx_bytes.saturating_add(tx),
                    counter_resets: was.counter_resets.saturating_add(u32::from(reset)),
                    ..was
                }
            }
            // The first reading, or the first of a month.
            Some(_) | None => fresh,
        };
        Ok(Self {
            reported,
            last: counters,
        })
    }
}

/// Reads the uplink's counters in boot `boot_id`.
pub(crate) fn read(paths: &Paths, boot_id: &str) -> Result<Counters, AgentError> {
    let interface = crate::hello::uplink(paths)?;
    let counter = |name: &str| -> Result<u64, AgentError> {
        fs::read_to_string(paths.net_statistic(&interface, name))
            .map_err(|error| io_error(IoOp::ReadState, &error))?
            .trim_end()
            .parse()
            .map_err(|_| malformed(IoOp::ReadState))
    };
    Ok(Counters {
        boot_id: boot_id.to_owned(),
        rx_bytes: counter("rx_bytes")?,
        tx_bytes: counter("tx_bytes")?,
        interface,
    })
}
