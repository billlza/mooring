// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's copy of the nodes' abuse records (design §11.8):
//! `abuse/records.json`, which `mooring-store` keeps. A node keeps its
//! records 30 days; the Mac keeps the copy it pulls for
//! [`MAC_ABUSE_RETENTION_SECS`] from each record's time, to show that each
//! case was handled and when. Merging a node's page adds the records the
//! copy lacks and refuses one that contradicts what it holds: a node never
//! reuses a number, so the same number with other content is a fault to
//! report, never one to settle by picking either.
//!
//! A record names an opaque user and aggregate figures only (no
//! destination, port or address), so the document is Level 0 apart from
//! that pseudonymous id (§12, §15.5).

use std::collections::BTreeMap;

use mooring_agent_proto::{AbuseRecord, AbuseRecordsV1, AbuseSeq, UnixTime};
use mooring_model::NodeId;
use mooring_model::kinds;
use serde::{Deserialize, Serialize};

/// The document's version.
pub const MAC_ABUSE_RECORDS_VERSION: u32 = 1;

/// How long the Mac keeps a record: 393 days, the shortest thirteen
/// calendar months, as for the journal (§15.7).
pub const MAC_ABUSE_RETENTION_SECS: u64 = 393 * 86_400;

/// The most records the Mac keeps per node; beyond it a merge is refused
/// rather than drop a record within its retention. A node's own bound is
/// 4,096 at any time, so 13 months of a busy node fit many times over.
pub const MAC_ABUSE_RECORDS_PER_NODE: usize = 65_536;

/// The most bytes of the document read: every node's records at their
/// longest fit.
pub const MAC_ABUSE_RECORDS_MAX_BYTES: usize = 64 << 20;

/// The Mac's copy, by node, each node's records in number order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDocument", into = "RawDocument")]
pub struct MacAbuseRecords {
    nodes: BTreeMap<NodeId, Vec<AbuseRecord>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    version: u32,
    nodes: BTreeMap<NodeId, Vec<AbuseRecord>>,
}

impl TryFrom<RawDocument> for MacAbuseRecords {
    type Error = AbuseRecordsError;

    fn try_from(raw: RawDocument) -> Result<Self, Self::Error> {
        if raw.version != MAC_ABUSE_RECORDS_VERSION {
            return Err(AbuseRecordsError::UnsupportedVersion { found: raw.version });
        }
        for (node, records) in &raw.nodes {
            if records.len() > MAC_ABUSE_RECORDS_PER_NODE {
                return Err(AbuseRecordsError::TooMany { node: node.clone() });
            }
            if !records.windows(2).all(|pair| pair[0].seq < pair[1].seq) {
                return Err(AbuseRecordsError::OutOfOrder { node: node.clone() });
            }
        }
        Ok(Self { nodes: raw.nodes })
    }
}

impl From<MacAbuseRecords> for RawDocument {
    fn from(records: MacAbuseRecords) -> Self {
        Self {
            version: MAC_ABUSE_RECORDS_VERSION,
            nodes: records.nodes,
        }
    }
}

impl MacAbuseRecords {
    /// Reads the document; no document is no record. The JSON's shape is
    /// checked first ([`AbuseRecordsError::Undecodable`], the decoder's
    /// message never kept), then the document's own rules.
    pub fn decode(bytes: Option<&[u8]>) -> Result<Self, AbuseRecordsError> {
        let Some(bytes) = bytes else {
            return Ok(Self::default());
        };
        let raw: RawDocument =
            serde_json::from_slice(bytes).map_err(|_| AbuseRecordsError::Undecodable)?;
        Self::try_from(raw)
    }

    /// The document as written: pretty JSON and a newline.
    pub fn encode(&self) -> Result<Vec<u8>, AbuseRecordsError> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| AbuseRecordsError::Unencodable)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// The records held for `node`, in number order.
    pub fn records(&self, node: &NodeId) -> &[AbuseRecord] {
        self.nodes.get(node).map_or(&[], Vec::as_slice)
    }

    /// The nodes with records, in id order.
    pub fn nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.nodes.keys()
    }

    /// Adds `page`'s records for `node` that the copy lacks, and returns
    /// how many were added. A record whose number the copy holds with other
    /// content is [`AbuseRecordsError::Conflict`], and nothing is added.
    pub fn merge(
        &mut self,
        node: &NodeId,
        page: &AbuseRecordsV1,
    ) -> Result<usize, AbuseRecordsError> {
        let held = self.nodes.get(node).map_or(&[][..], Vec::as_slice);
        let mut merged: BTreeMap<AbuseSeq, AbuseRecord> = held
            .iter()
            .map(|record| (record.seq, record.clone()))
            .collect();
        let mut added = 0;
        for record in page.records() {
            match merged.get(&record.seq) {
                Some(existing) if existing != record => {
                    return Err(AbuseRecordsError::Conflict {
                        node: node.clone(),
                        seq: record.seq.get(),
                    });
                }
                Some(_) => {}
                None => {
                    merged.insert(record.seq, record.clone());
                    added += 1;
                }
            }
        }
        if merged.len() > MAC_ABUSE_RECORDS_PER_NODE {
            return Err(AbuseRecordsError::TooMany { node: node.clone() });
        }
        if added > 0 {
            self.nodes
                .insert(node.clone(), merged.into_values().collect());
        }
        Ok(added)
    }

    /// Drops the records older than [`MAC_ABUSE_RETENTION_SECS`] at `now`
    /// (one dated after `now`, a clock that stepped back, stays) and the
    /// nodes left with none; returns how many were dropped.
    pub fn prune(&mut self, now: UnixTime) -> usize {
        let mut dropped = 0;
        for records in self.nodes.values_mut() {
            let before = records.len();
            records.retain(|record| {
                now.secs_since(record.at)
                    .is_none_or(|age| age <= MAC_ABUSE_RETENTION_SECS)
            });
            dropped += before - records.len();
        }
        self.nodes.retain(|_, records| !records.is_empty());
        dropped
    }
}

/// The Mac's copy of the abuse records cannot be read, merged or written.
/// No variant holds a byte of the document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AbuseRecordsError {
    /// The document is not one this build reads.
    #[error("the abuse records are not a document this build reads")]
    Undecodable,
    /// The document names another version.
    #[error(
        "the abuse records name version {found}; this build reads version {}",
        MAC_ABUSE_RECORDS_VERSION
    )]
    UnsupportedVersion {
        /// The version found.
        found: u32,
    },
    /// A node's records in the document read are not in number order, or
    /// repeat a number.
    #[error("the abuse records of node {node} are out of number order or repeat a number")]
    OutOfOrder {
        /// The node.
        node: NodeId,
    },
    /// A node's page gives a number the copy holds with other content.
    #[error("node {node} reports abuse record {seq} unlike the copy the Mac holds")]
    Conflict {
        /// The node.
        node: NodeId,
        /// The record's number.
        seq: u64,
    },
    /// A node's records are more than [`MAC_ABUSE_RECORDS_PER_NODE`]: in the
    /// document read, or after a merge, which is then refused.
    #[error(
        "the Mac keeps at most {} abuse records of node {node}",
        MAC_ABUSE_RECORDS_PER_NODE
    )]
    TooMany {
        /// The node.
        node: NodeId,
    },
    /// The document could not be written as JSON.
    #[error("the abuse records could not be written as JSON")]
    Unencodable,
}

impl AbuseRecordsError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> AbuseRecordsErrorKind {
        match self {
            Self::Undecodable => AbuseRecordsErrorKind::Undecodable,
            Self::UnsupportedVersion { .. } => AbuseRecordsErrorKind::UnsupportedVersion,
            Self::OutOfOrder { .. } => AbuseRecordsErrorKind::OutOfOrder,
            Self::Conflict { .. } => AbuseRecordsErrorKind::Conflict,
            Self::TooMany { .. } => AbuseRecordsErrorKind::TooMany,
            Self::Unencodable => AbuseRecordsErrorKind::Unencodable,
        }
    }
}

kinds! {
    /// The kind of an [`AbuseRecordsError`].
    pub enum AbuseRecordsErrorKind {
        /// See [`AbuseRecordsError::Undecodable`].
        Undecodable,
        /// See [`AbuseRecordsError::UnsupportedVersion`].
        UnsupportedVersion,
        /// See [`AbuseRecordsError::OutOfOrder`].
        OutOfOrder,
        /// See [`AbuseRecordsError::Conflict`].
        Conflict,
        /// See [`AbuseRecordsError::TooMany`].
        TooMany,
        /// See [`AbuseRecordsError::Unencodable`].
        Unencodable,
    }
}
