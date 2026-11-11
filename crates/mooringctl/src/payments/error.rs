// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull's files could not be read or written.

use mooring_daemon_core::payments::{LedgerError, SettingsError};
use mooring_store::StoreError;

/// A payment file (the pull's settings or the ledger) could not be read or
/// written, or a change of the settings was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PaymentFileError {
    /// The store could not read or write the file.
    #[error("{file} cannot be read or written")]
    Store {
        /// The file, relative to the support directory.
        file: &'static str,
        /// Why.
        #[source]
        source: Box<StoreError>,
    },
    /// The settings file is not the pull's settings.
    #[error("payment-pull.json is not the payment pull's settings")]
    Settings(#[source] SettingsError),
    /// The ledger is not a payment ledger this build reads.
    #[error("payments/ledger.json is not a payment ledger this build reads")]
    Ledger(#[source] LedgerError),
    /// The pull is not connected, so there is nothing to change.
    #[error("the payment pull is not connected")]
    NotConnected,
}
