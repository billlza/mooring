// SPDX-License-Identifier: GPL-3.0-or-later

//! The NETGEAR MR7450's JSON interface (M2a, 2026-10-13): its constants,
//! and the allowlist parser and redactor of its `model.json`.
//!
//! The MR7450 answers `GET /api/model.json?internalapi=1` (API 2.0).
//! Anonymous, the answer holds only the login fields; logged in, it holds
//! about 651 leaves, among them, in plaintext, the admin password, the
//! Wi-Fi passphrases, the IMEI, ICCID, IMSI and phone number, SMS bodies
//! and senders, cell identifiers, GPS, the clients' addresses, the WWAN
//! address and the session token (design §15.6). So the answer is only
//! ever read through one allowlist, [`NetgearLeaf`]:
//!
//! - one table of leaves (path, shape, which parse reads it);
//! - one streaming walk over the JSON, the only code that looks at keys,
//!   which follows the table's paths and checks each leaf's shape before
//!   the value is stored or written, and hands every other value on
//!   unread;
//! - the parsers, [`parse_netgear_session`] and
//!   [`parse_netgear_model_json`], which read only what the walk extracted
//!   and only by [`NetgearLeaf`] (the status parse never extracts the
//!   session token);
//! - the redactor, [`redact_netgear_model_json`], which keeps exactly the
//!   table's leaves that are not secret, when their shape passes, and
//!   writes every other value as a placeholder of its type.
//!
//! Every error names a leaf's path, never a byte of the answer.

mod allowlist;
mod build;
mod redact;
mod walk;

pub use allowlist::{NetgearLeaf, Segment};
pub use build::{NetgearSession, SecToken, parse_netgear_model_json, parse_netgear_session};
pub use redact::{RedactedModelJson, redact_netgear_model_json};

pub(crate) use allowlist::{LeafPath, carrier_list_path};

#[cfg(test)]
pub(crate) use allowlist::{LeafSet, LeafShape, LeafUse};
#[cfg(test)]
pub(crate) use build::NOT_REPORTED;
#[cfg(test)]
pub(crate) use walk::MAX_ARRAY_ELEMENTS;

/// The model the parser accepts (`general.model`).
pub const NETGEAR_MODEL: &str = "MR7450";

/// The API version the parser accepts (`general.apiVersion`).
pub const NETGEAR_API_VERSION: &str = "2.0";

/// The request target of the status document: the one JSON endpoint
/// chosen in M2a (`/model.json` is never requested).
pub const MODEL_JSON_TARGET: &str = "/api/model.json?internalapi=1";

/// The request target of the M7's session set-up, observed on 2026-10-14
/// (firmware NTGX75_10.04.43.01): a `GET` of [`MODEL_JSON_TARGET`] without
/// a session cookie is answered `302 Found` with a new `sessionId` cookie
/// and a `Location` of this target on the M7's own address; a `GET` of this
/// target with that cookie is answered `302 Found` with another `sessionId`
/// and a `Location` of [`MODEL_JSON_TARGET`], which then answers `200` with
/// the second cookie. Asking for the JSON again with the first cookie is
/// answered by the first redirect again, so this step is required. `op` and
/// `oq` are the JSON target's path and query, percent-encoded as the M7
/// wrote them.
pub const SESSION_SETUP_TARGET: &str = "/sess_cd_tmp?op=%2Fapi%2Fmodel%2Ejson&oq=internalapi%3D1";

/// The request target of the login form.
pub const LOGIN_TARGET: &str = "/Forms/config";

/// The login form's `err_redirect` field.
pub const LOGIN_ERR_REDIRECT: &str = "/index.html?loginfailed";

/// The login form's `ok_redirect` field.
pub const LOGIN_OK_REDIRECT: &str = "/index.html";

/// The login form's fields, in the web interface's order: the token, the
/// two redirects, the password.
pub const LOGIN_FIELDS: [&str; 4] = ["token", "err_redirect", "ok_redirect", "session.password"];

/// The role of an administrator's session (`session.userRole`), matched
/// exactly.
pub const ADMIN_ROLE: &str = "Admin";
