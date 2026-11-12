// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the usage the daemon collected, `usage/users.json`. The
//! daemon's collector (`daemon::usage`) starts from it, and `portal export`,
//! `user usage` and the apply job read it in their own processes.

use std::path::Path;

use mooring_daemon_core::error::{UsageError, UsageErrorKind};
use mooring_daemon_core::usage::{CollectedUsage, MAX_COLLECTED_USAGE_BYTES, UsageReport};
use mooring_model::{Deployment, UnixTime};
use mooring_store::{StoreError, read_user_usage};

/// Why `usage/users.json` could not be read.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CollectedReadError {
    /// The store could not read the file.
    #[error(transparent)]
    Store(StoreError),
    /// The file holds no collected usage document.
    #[error(transparent)]
    Decode(UsageError),
}

impl CollectedReadError {
    /// The usage view's reason for it.
    pub(crate) const fn kind(&self) -> UsageErrorKind {
        match self {
            Self::Store(_) => UsageErrorKind::StoreUnavailable,
            Self::Decode(error) => error.kind(),
        }
    }
}

/// Why the collected usage cannot be used at all. A fault is never read as
/// usage that is behind or as no usage: that would show every figure as
/// unknown or zero and hide it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UsageFault {
    /// `usage/users.json` cannot be read, or holds no collected usage
    /// document.
    #[error(transparent)]
    Read(CollectedReadError),
    /// The collected usage contradicts itself or the deployment.
    #[error(transparent)]
    Inconsistent(UsageError),
}

/// The usage the daemon collected, in `support`'s `usage/users.json`:
/// `None` when there is no such file. The daemon's [`Collector`] is its one
/// writer and replaces it whole (the store's durable write), so a reader in
/// another process sees one complete document; the read is the store's
/// bounded one of a regular file, which follows no link and changes no
/// mode.
///
/// [`Collector`]: crate::daemon::usage::Collector
pub(crate) fn read_collected_document(
    support: &Path,
) -> Result<Option<CollectedUsage>, CollectedReadError> {
    read_user_usage(support, MAX_COLLECTED_USAGE_BYTES + 1)
        .map_err(CollectedReadError::Store)?
        .map(|bytes| CollectedUsage::decode(&bytes).map_err(CollectedReadError::Decode))
        .transpose()
}

/// [`read_collected_document`], with an empty history when there is no
/// file yet: what the daemon starts from, and what `portal export`
/// aggregates (a serving node then has no ledger, so the report is behind).
pub(crate) fn read_collected(support: &Path) -> Result<CollectedUsage, CollectedReadError> {
    Ok(read_collected_document(support)?.unwrap_or_default())
}

/// What the daemon's collected usage gives at a time.
#[derive(Debug)]
pub(crate) enum Usage {
    /// The usage report.
    Report(UsageReport),
    /// No report, because the collection is behind: the daemon has not
    /// collected a serving node's usage yet (`MissingLedger`), or not within
    /// the report's freshness bound (`NotCoveredThrough`), as when it is
    /// stopped or a node cannot be reached.
    Behind(UsageError),
}

/// Whether `kind` says only that the collection is behind: the daemon has
/// not collected a serving node's usage yet (`MissingLedger`), or not within
/// the report's freshness bound (`NotCoveredThrough`), as when it is stopped
/// or a node cannot be reached. Every other kind is a fault.
pub(crate) const fn behind(kind: UsageErrorKind) -> bool {
    matches!(
        kind,
        UsageErrorKind::MissingLedger | UsageErrorKind::NotCoveredThrough
    )
}

/// The collected usage aggregated at `now`. A fault is never read as usage
/// that is behind: that would replace every user's figures with "unknown"
/// and hide it.
pub(crate) fn usage(
    support: &Path,
    deployment: &Deployment,
    now: UnixTime,
) -> Result<Usage, UsageFault> {
    match read_collected(support)
        .map_err(UsageFault::Read)?
        .aggregate(deployment, now)
    {
        Ok(report) => Ok(Usage::Report(report)),
        Err(error) if behind(error.kind()) => Ok(Usage::Behind(error)),
        Err(error) => Err(UsageFault::Inconsistent(error)),
    }
}
