// SPDX-License-Identifier: GPL-3.0-or-later

//! The node's abuse state (design §11.8), `/var/lib/mooring/watch/abuse.json`
//! (0640, group `mooring`): the users cut on the node, the records of what
//! the guard found and what was done, and the number the next record gets.
//!
//! It is one file, rewritten atomically by every change, so the cuts, the
//! records and their numbering never disagree after a crash, and a number
//! is never reused even once every record has expired. Its writers are the
//! watch and the ops role's `AbuseCut` and `AbuseClear`, each under
//! `gate.lock`; `AbuseRecords`, from the ops and viewer roles, reads it.
//! Records are kept [`ABUSE_RECORD_KEEP_SECS`] and at most
//! [`MAX_ABUSE_RECORDS_KEPT`] of them; a cut stays until it is lifted. A
//! record names an opaque user and aggregate figures only.

use std::collections::BTreeSet;

use mooring_agent_proto::{
    ABUSE_RECORD_KEEP_SECS, ABUSE_SUSPECTED_SECS, AbuseAction, AbuseCutEntry, AbuseCuts,
    AbuseFigures, AbuseFinding, AbuseGuardVersion, AbuseRecord, AbuseRecordsV1, AbuseSeq,
    AgentError, IoOp, MAX_ABUSE_RECORDS, MAX_ABUSE_RECORDS_KEPT, OpaqueUserId, UnixTime,
};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::store::{malformed, read_json, write_json};

/// The state file's format version.
const VERSION: u32 = 1;

/// The file is read by the `mooring` group, the viewer included.
const MODE: u32 = 0o640;

/// The node's abuse state, checked whenever it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbuseState {
    next: AbuseSeq,
    cuts: AbuseCuts,
    records: Vec<AbuseRecord>,
}

/// The file as written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    next_record: AbuseSeq,
    cuts: AbuseCuts,
    records: Vec<AbuseRecord>,
}

impl AbuseState {
    /// The state of a node that has recorded nothing.
    pub(crate) const fn empty() -> Self {
        Self {
            next: AbuseSeq::FIRST,
            cuts: AbuseCuts::EMPTY,
            records: Vec::new(),
        }
    }

    /// Reads the state; none recorded yet is [`AbuseState::empty`]. A file
    /// of another version, records not numbered consecutively below the
    /// next number, a cut made by a number not yet given, or more records
    /// than are kept, is `Io{ReadState}` with no error number: never read
    /// as no cut.
    pub(crate) fn read(paths: &Paths) -> Result<Self, AgentError> {
        let Some(file) = read_json::<StateFile>(&paths.abuse_state())? else {
            return Ok(Self::empty());
        };
        let consecutive = file
            .records
            .windows(2)
            .all(|pair| pair[0].seq.get().checked_add(1) == Some(pair[1].seq.get()));
        let below = file
            .records
            .last()
            .is_none_or(|last| last.seq < file.next_record)
            && file
                .cuts
                .entries()
                .iter()
                .all(|cut| cut.record < file.next_record);
        if file.version == VERSION
            && consecutive
            && below
            && file.records.len() <= MAX_ABUSE_RECORDS_KEPT
        {
            Ok(Self {
                next: file.next_record,
                cuts: file.cuts,
                records: file.records,
            })
        } else {
            Err(malformed(IoOp::ReadState))
        }
    }

    /// Writes the state atomically.
    pub(crate) fn write(&self, paths: &Paths) -> Result<(), AgentError> {
        write_json(
            &paths.abuse_state(),
            &StateFile {
                version: VERSION,
                next_record: self.next,
                cuts: self.cuts.clone(),
                records: self.records.clone(),
            },
            MODE,
        )
    }

    /// The users cut now.
    pub(crate) const fn cuts(&self) -> &AbuseCuts {
        &self.cuts
    }

    /// The records kept, oldest first.
    pub(crate) fn records(&self) -> &[AbuseRecord] {
        &self.records
    }

    /// Appends a record, numbered next, and returns its number.
    pub(crate) fn record(
        &mut self,
        at: UnixTime,
        user: &OpaqueUserId,
        action: AbuseAction,
        figures: Option<AbuseFigures>,
    ) -> AbuseSeq {
        let seq = self.next;
        self.records.push(AbuseRecord {
            seq,
            at,
            user: user.clone(),
            guard: AbuseGuardVersion::CURRENT,
            action,
            figures,
        });
        self.next = AbuseSeq::new(seq.get().saturating_add(1));
        seq
    }

    /// Cuts the user `entry` names: [`AgentError::AbuseCutsFull`] when the
    /// node holds [`mooring_agent_proto::MAX_ABUSE_CUTS`] users cut already. A user cut already
    /// keeps the cut made first.
    pub(crate) fn cut(&mut self, entry: AbuseCutEntry) -> Result<(), AgentError> {
        self.cuts = self
            .cuts
            .with(entry)
            .map_err(|_| AgentError::AbuseCutsFull)?;
        Ok(())
    }

    /// Lifts the user's cut, returning it; `None` when the user was not cut.
    pub(crate) fn clear(&mut self, user: &OpaqueUserId) -> Option<AbuseCutEntry> {
        let entry = self.cuts.get(user)?.clone();
        self.cuts = self.cuts.without(user);
        Some(entry)
    }

    /// Whether a record is due to be pruned at `now`: older than
    /// [`ABUSE_RECORD_KEEP_SECS`], or beyond [`MAX_ABUSE_RECORDS_KEPT`].
    pub(crate) fn prune_due(&self, now: UnixTime) -> bool {
        self.records.len() > MAX_ABUSE_RECORDS_KEPT
            || self
                .records
                .first()
                .is_some_and(|first| expired(now, first.at))
    }

    /// Drops the records older than [`ABUSE_RECORD_KEEP_SECS`] at `now`,
    /// then the oldest beyond [`MAX_ABUSE_RECORDS_KEPT`] (down to three
    /// quarters of it), from the oldest end only, so the rest stay
    /// numbered consecutively. The next number never goes back.
    pub(crate) fn prune(&mut self, now: UnixTime) {
        let first = self
            .records
            .iter()
            .position(|record| !expired(now, record.at))
            .unwrap_or(self.records.len());
        self.records.drain(..first);
        if self.records.len() > MAX_ABUSE_RECORDS_KEPT {
            let excess = self.records.len() - MAX_ABUSE_RECORDS_KEPT / 4 * 3;
            self.records.drain(..excess);
        }
    }

    /// `AbuseRecords{since}`: the cuts, and the records numbered `since`
    /// or later, at most [`MAX_ABUSE_RECORDS`] of them.
    pub(crate) fn page(&self, since: AbuseSeq) -> Result<AbuseRecordsV1, AgentError> {
        let records = self
            .records
            .iter()
            .filter(|record| record.seq >= since)
            .take(MAX_ABUSE_RECORDS)
            .cloned()
            .collect();
        AbuseRecordsV1::new(self.cuts.clone(), records, self.next)
            .map_err(|_| malformed(IoOp::ReadState))
    }

    /// Whether `user` has a record of `finding`, as an alert or a cut, at
    /// or after `since`.
    pub(crate) fn found_since(
        &self,
        user: &OpaqueUserId,
        finding: AbuseFinding,
        since: UnixTime,
    ) -> bool {
        self.records.iter().rev().any(|record| {
            record.at >= since
                && record.user == *user
                && match record.action {
                    AbuseAction::Cut { findings } | AbuseAction::Alerted { findings } => {
                        findings.contains(finding)
                    }
                    AbuseAction::OperatorCut | AbuseAction::Cleared => false,
                }
        })
    }

    /// How many users who are not cut have an alert record from the last
    /// [`ABUSE_SUSPECTED_SECS`] at `now`.
    pub(crate) fn suspected(&self, now: UnixTime) -> usize {
        let since = UnixTime::from_secs(now.as_secs().saturating_sub(ABUSE_SUSPECTED_SECS));
        self.records
            .iter()
            .filter(|record| record.at >= since && record.at <= now)
            .filter(|record| matches!(record.action, AbuseAction::Alerted { .. }))
            .filter(|record| self.cuts.get(&record.user).is_none())
            .map(|record| &record.user)
            .collect::<BTreeSet<_>>()
            .len()
    }
}

/// Whether a record made `at` is older than [`ABUSE_RECORD_KEEP_SECS`] at
/// `now`; one from after `now` (a clock that stepped back) is not.
fn expired(now: UnixTime, at: UnixTime) -> bool {
    now.secs_since(at)
        .is_some_and(|age| age > ABUSE_RECORD_KEEP_SECS)
}
