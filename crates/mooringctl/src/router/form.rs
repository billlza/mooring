// SPDX-License-Identifier: GPL-3.0-or-later

//! The login form's body (`application/x-www-form-urlencoded`, as the M7's
//! web interface posts it; M2a): `token`, `err_redirect`, `ok_redirect`,
//! `session.password`, in that order.

use std::fmt;

use mooring_daemon_core::router::netgear::{
    LOGIN_ERR_REDIRECT, LOGIN_FIELDS, LOGIN_OK_REDIRECT, SecToken,
};
use mooring_model::exact::{self, TextSink};
use mooring_model::secret::RouterAdminPassword;
use zeroize::{Zeroize, Zeroizing};

use crate::router::link::VerifiedIdentity;

/// Writes `value` as the WHATWG `application/x-www-form-urlencoded` byte
/// serializer does: ASCII letters, digits and `*-._` as they are, a space
/// as `+`, every other byte as `%XX` in upper case.
pub(crate) fn urlencode(value: &str, sink: &mut dyn TextSink) {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F",
    ];
    let mut literal = [0_u8; 4];
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"*-._".contains(&byte) {
            sink.put(char::from(byte).encode_utf8(&mut literal));
        } else if byte == b' ' {
            sink.put("+");
        } else {
            sink.put("%");
            sink.put(HEX[usize::from(byte >> 4)]);
            sink.put(HEX[usize::from(byte & 0x0f)]);
        }
    }
    // The stack copy may have held a password character.
    literal.zeroize();
}

/// The login form's body, holding the admin password: built only for a
/// [`VerifiedIdentity`], in an exactly sized zeroizing buffer, and never
/// shown in `Debug`.
pub(crate) struct LoginBody(Zeroizing<String>);

impl fmt::Debug for LoginBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LoginBody(<redacted>, {} bytes)", self.0.len())
    }
}

impl LoginBody {
    /// The body for logging in to the verified M7 with `token` (the
    /// anonymous answer's `session.secToken`) and `password`.
    pub(crate) fn new(
        _verified: &VerifiedIdentity,
        token: &SecToken,
        password: &RouterAdminPassword,
    ) -> Self {
        let [token_field, err_field, ok_field, password_field] = LOGIN_FIELDS;
        let fields = [
            (token_field, token.expose_str()),
            (err_field, LOGIN_ERR_REDIRECT),
            (ok_field, LOGIN_OK_REDIRECT),
            (password_field, password.expose_str()),
        ];
        Self(exact::text(|sink| {
            for (index, (name, value)) in fields.iter().enumerate() {
                if index > 0 {
                    sink.put("&");
                }
                urlencode(name, sink);
                sink.put("=");
                urlencode(value, sink);
            }
        }))
    }

    /// The body's text (ASCII), for the request only.
    pub(crate) fn expose_str(&self) -> &str {
        &self.0
    }

    /// The body's length in bytes (`Content-Length`).
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The buffer's capacity, for the test that it is exactly sized.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
