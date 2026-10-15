// SPDX-License-Identifier: GPL-3.0-or-later

//! The legacy login keychain as a [`SecretStore`] (design §12): the store
//! of this unsigned development slice, for the M7's admin password.
//!
//! Items are generic passwords under the service [`SERVICE`], one account
//! per [`SecretRef`] (its text, `router/admin`), labelled [`LABEL`]. No
//! data-protection keychain, access group or entitlement is used: those
//! need a signed build and arrive with M5, which moves the item (read
//! here, write there, delete here). macOS asks the user to allow access
//! when a rebuilt binary first reads the item; only the user can answer.
//!
//! An item is found by its service and account only, never by its label:
//! a `put` adds the item, and when one exists (`errSecDuplicateItem`)
//! updates that one's password and label, so an item made another way
//! (`security add-generic-password`, a rename in Keychain Access) is
//! replaced rather than reported missing.
//!
//! The pure parts, [`status_error`] and [`decode_item`], are tested; the
//! live keychain is never touched by tests.

use std::str;

use core_foundation::data::CFData;
use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef};
use mooring_store::{SecretOp, SecretStore, SecretStoreError};
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue,
    update_item,
};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
};
use zeroize::Zeroizing;

/// The keychain service of the development build.
pub(crate) const SERVICE: &str = "com.bill.mooring.dev";

/// The label shown in Keychain Access.
pub(crate) const LABEL: &str = "Mooring (development)";

/// `errSecItemNotFound` (`Security/SecBase.h`).
pub(crate) const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

/// `errSecDuplicateItem` (`Security/SecBase.h`).
pub(crate) const ERR_SEC_DUPLICATE_ITEM: i32 = -25_299;

/// The login keychain of the user running the command.
#[derive(Debug)]
pub(crate) struct LoginKeychain;

/// The store error for a Security framework `status`: a missing item is
/// `SecretMissing` (when reading or deleting); every other status is
/// `Keychain{op, status}`.
pub(crate) fn status_error(op: SecretOp, secret_ref: &SecretRef, status: i32) -> SecretStoreError {
    match op {
        SecretOp::Get | SecretOp::Delete if status == ERR_SEC_ITEM_NOT_FOUND => {
            SecretStoreError::SecretMissing {
                secret_ref: secret_ref.clone(),
            }
        }
        SecretOp::Get | SecretOp::Put | SecretOp::Delete => {
            SecretStoreError::Keychain { op, status }
        }
    }
}

/// The material of an item stored under `secret_ref`: UTF-8 text of the
/// reference's kind, or `ItemInvalid` (the text is never echoed).
pub(crate) fn decode_item(
    secret_ref: &SecretRef,
    bytes: &[u8],
) -> Result<SecretMaterial, SecretStoreError> {
    let invalid = || SecretStoreError::ItemInvalid {
        secret_ref: secret_ref.clone(),
    };
    let text = str::from_utf8(bytes).map_err(|_| invalid())?;
    SecretMaterial::decode(secret_ref.kind(), text).map_err(|_| invalid())
}

fn options(secret_ref: &SecretRef) -> PasswordOptions {
    PasswordOptions::new_generic_password(SERVICE, &secret_ref.to_string())
}

impl SecretStore for LoginKeychain {
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        let bytes = generic_password(options(secret_ref))
            .map(Zeroizing::new)
            .map_err(|error| status_error(SecretOp::Get, secret_ref, error.code()))?;
        decode_item(secret_ref, &bytes)
    }

    /// Adds the item; if it exists, updates the one found by service and
    /// account (whatever its label) to this password and [`LABEL`].
    fn put(&mut self, entry: SecretEntry) -> Result<(), SecretStoreError> {
        let (secret_ref, material) = entry.into_parts();
        let account = secret_ref.to_string();
        let text = material.encode();
        let put_error = |code: i32| status_error(SecretOp::Put, &secret_ref, code);
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(text.as_bytes()),
        });
        add.set_service(SERVICE)
            .set_account_name(&account)
            .set_label(LABEL);
        match add.add() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_DUPLICATE_ITEM => {
                let mut search = ItemSearchOptions::new();
                search
                    .class(ItemClass::generic_password())
                    .service(SERVICE)
                    .account(&account);
                let mut update = ItemUpdateOptions::new();
                update
                    .set_value(ItemUpdateValue::Data(CFData::from_buffer(text.as_bytes())))
                    .set_label(LABEL);
                update_item(&search, &update).map_err(|error| put_error(error.code()))
            }
            Err(error) => Err(put_error(error.code())),
        }
    }

    fn delete(&mut self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        delete_generic_password_options(options(secret_ref))
            .map_err(|error| status_error(SecretOp::Delete, secret_ref, error.code()))
    }
}
