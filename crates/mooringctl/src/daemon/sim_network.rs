// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of the SIM's network (design §10.2, §15.3): every
//! tick sets the carrier check and the cycle rule in the state against the
//! ones the record was taken under, every poll that finds the M7 attached
//! sets what it reports against the record's baseline (`daemon-core`'s
//! [`SimNetworkRecord`]), and the status carries the result, which the
//! console shows as a notice when the M7 reports another network than the
//! baseline's. The record is written to `run/sim-network.json` whenever it
//! changes, so that a restart keeps the baseline and the time another
//! network was first seen.
//!
//! A record that cannot be read at the start is said and begun again, and
//! the status says so for as long as that record lasts
//! (`BaselineOrigin::RecordUnreadable`): it is never taken for a record
//! that found nothing changed. A write that fails is said, kept in memory
//! for the status, and tried again [`WRITE_RETRY`] later, or at once when
//! the record changes before then. Nothing is written while the file
//! holds the record.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mooring_daemon_core::router::RouterReading;
use mooring_daemon_core::sim_network::{
    BaselineOrigin, MAX_SIM_NETWORK_BYTES, RecordedUnder, SimNetwork, SimNetworkRecord,
    SimNetworkStatus,
};
use mooring_model::ExitSite;
use mooring_store::{read_sim_network, write_sim_network};

/// How long after a failed write the record is written again.
pub(crate) const WRITE_RETRY: Duration = Duration::from_secs(60);

/// Whether the file holds the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    /// It does: it was read from the file, or written to it.
    Current,
    /// It does not: the record was begun or changed, and the next tick
    /// writes it.
    Stale,
    /// It does not, and a write failed: the next is tried at this time.
    RetryAt(Instant),
}

/// The record, between ticks.
#[derive(Debug)]
pub(crate) struct NetworkWatch {
    run_dir: PathBuf,
    record: SimNetworkRecord,
    file: FileState,
}

impl NetworkWatch {
    /// The record in `run_dir`, or one begun under the carrier check and
    /// the cycle rule of `exit` when there is none or it cannot be read,
    /// and what to say about that.
    pub(crate) fn open(run_dir: &Path, exit: &ExitSite) -> (Self, Option<String>) {
        let read = match read_sim_network(run_dir, MAX_SIM_NETWORK_BYTES + 1) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => SimNetworkRecord::decode(&bytes)
                .map(Some)
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let begun = |origin| SimNetworkRecord::new(RecordedUnder::of(exit), origin);
        let (record, note) = match read {
            Ok(Some(record)) => (record, None),
            Ok(None) => (
                begun(BaselineOrigin::NoRecord),
                Some(
                    "sim network: no record yet; the next poll that finds the M7 attached gives the network the carrier check and the billing cycle are taken to go with, so a SIM changed before then is not noticed"
                        .to_owned(),
                ),
            ),
            Err(error) => (
                begun(BaselineOrigin::RecordUnreadable),
                Some(format!(
                    "sim network: the record cannot be read ({error}); it is begun again, so a SIM changed before now is not noticed, and the status says so"
                )),
            ),
        };
        // A record read is what the file holds; one begun is not there yet.
        let file = if note.is_none() {
            FileState::Current
        } else {
            FileState::Stale
        };
        (
            Self {
                run_dir: run_dir.to_path_buf(),
                record,
                file,
            },
            note,
        )
    }

    /// Sets the carrier check and the cycle rule of `exit` against the
    /// record's, and what `polled` reports, when it is a poll the record
    /// has not seen that found the M7 attached, against its baseline;
    /// writes the record when it changed, or when a write that failed is
    /// due again at `now`. Returns what to say.
    pub(crate) fn track(
        &mut self,
        exit: &ExitSite,
        polled: Option<&RouterReading>,
        now: Instant,
    ) -> Vec<String> {
        let poll = polled.and_then(|reading| match reading {
            RouterReading::Available { polled_at, status } => {
                SimNetwork::of(status).map(|network| (network, *polled_at))
            }
            RouterReading::Unavailable { .. } => None,
        });
        let next = self.record.observed(
            &RecordedUnder::of(exit),
            poll.as_ref().map(|(network, at)| (network, *at)),
        );
        let mut notes = Vec::new();
        if next != self.record {
            notes.extend(said(&self.record, &next));
            self.record = next;
            self.file = FileState::Stale;
        }
        let due = match self.file {
            FileState::Current => false,
            FileState::Stale => true,
            FileState::RetryAt(at) => now >= at,
        };
        if !due {
            return notes;
        }
        let written = self
            .record
            .encode()
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                write_sim_network(&self.run_dir, &bytes).map_err(|error| error.to_string())
            });
        match written {
            Ok(()) => self.file = FileState::Current,
            Err(error) => {
                self.file = FileState::RetryAt(now + WRITE_RETRY);
                notes.push(format!(
                    "sim network: the record could not be written ({error}); the status shows it, and it is written again in {} s",
                    WRITE_RETRY.as_secs()
                ));
            }
        }
        notes
    }

    /// What the status says of the SIM's network.
    pub(crate) fn status(&self) -> SimNetworkStatus {
        self.record.status().clone()
    }
}

/// A network as the log names it: the SIM's name, or that it has none,
/// and the network's codes as `router status` prints them.
pub(crate) fn shown(network: &SimNetwork) -> String {
    let plmn = &network.plmn;
    match &network.spn {
        Some(spn) => format!("{} ({}-{})", spn.as_str(), plmn.mcc, plmn.mnc),
        None => format!("a SIM without a name ({}-{})", plmn.mcc, plmn.mnc),
    }
}

/// The log's line for the record going from `before` to `after`; none
/// when only a time moved.
pub(crate) fn said(before: &SimNetworkRecord, after: &SimNetworkRecord) -> Option<String> {
    let taken = after.status().baseline.as_ref();
    if before.under() != after.under() {
        return Some(match taken {
            None => "sim network: the carrier check or the billing cycle changed; the next poll that finds the M7 attached gives the network they go with".to_owned(),
            Some(baseline) => format!(
                "sim network: the carrier check or the billing cycle changed; they are taken to go with {}, which the M7 reports",
                shown(baseline.network())
            ),
        });
    }
    let (Some(held), Some(taken)) = (before.status().baseline.as_ref(), taken) else {
        return taken.map(|baseline| {
            format!(
                "sim network: the M7 reports {}; the carrier check and the billing cycle are taken to go with it",
                shown(baseline.network())
            )
        });
    };
    let first = shown(taken.network());
    match (held.other(), taken.other()) {
        (None, Some(other)) => Some(format!(
            "sim network: the M7 reports {}, where it reported {first} under the recorded carrier check and billing cycle; if the SIM was changed, record both again (swap-day.md, section 2, steps 3 to 6)",
            shown(&other.network)
        )),
        (Some(was), Some(other)) if was.network != other.network => Some(format!(
            "sim network: the M7 now reports {}, and still not {first}",
            shown(&other.network)
        )),
        (Some(_), None) => Some(format!("sim network: the M7 reports {first} again")),
        (Some(_), Some(_)) | (None, None) => None,
    }
}
