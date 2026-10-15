// SPDX-License-Identifier: GPL-3.0-or-later

//! The login form's encoding and body.

use mooring_daemon_core::router::netgear::parse_netgear_session;
use mooring_model::secret::RouterAdminPassword;

use super::support::{PASSWORD, TOKEN, anonymous};
use crate::router::form::{LoginBody, urlencode};
use crate::router::link::VerifiedIdentity;

/// The login body for [`PASSWORD`] and the anonymous answer's token.
pub(crate) fn login_body(verified: &VerifiedIdentity) -> LoginBody {
    let session = parse_netgear_session(&anonymous("Guest", 0, "MR7450")).unwrap();
    LoginBody::new(
        verified,
        session.token(),
        &RouterAdminPassword::parse(PASSWORD).unwrap(),
    )
}

/// The encoded form of [`PASSWORD`] (`p@ss w&rd=+%`).
pub(crate) const ENCODED_PASSWORD: &str = "p%40ss+w%26rd%3D%2B%25";

/// The encoded form of the test token (`tok-CANARY-7f3a;9b&=+ x`).
pub(crate) const ENCODED_TOKEN: &str = "tok-CANARY-7f3a%3B9b%26%3D%2B+x";

fn encoded(value: &str) -> String {
    let mut out = String::new();
    urlencode(value, &mut out);
    out
}

#[test]
fn form_encoding_matches_whatwg() {
    for (value, expected) in [
        ("abcXYZ019*-._", "abcXYZ019*-._"),
        (" ", "+"),
        ("a b", "a+b"),
        ("~", "%7E"),
        ("/", "%2F"),
        ("?", "%3F"),
        ("%", "%25"),
        ("+", "%2B"),
        ("&=", "%26%3D"),
        ("!'()", "%21%27%28%29"),
        ("\u{e9}", "%C3%A9"),
        ("\u{7f}", "%7F"),
        ("", ""),
        (PASSWORD, ENCODED_PASSWORD),
        (TOKEN, ENCODED_TOKEN),
    ] {
        assert_eq!(encoded(value), expected, "{value:?}");
    }
}

#[test]
fn the_login_body_is_exactly_sized() {
    let verified = super::http::verified(80);
    let body = login_body(&verified);
    let expected = format!(
        "token={ENCODED_TOKEN}&err_redirect=%2Findex.html%3Floginfailed&ok_redirect=%2Findex.html&session.password={ENCODED_PASSWORD}"
    );
    assert_eq!(body.expose_str(), expected);
    assert_eq!(body.len(), expected.len());
    assert_eq!(body.capacity(), body.len());
    let shown = format!("{body:?}");
    assert_eq!(
        shown,
        format!("LoginBody(<redacted>, {} bytes)", expected.len())
    );
}
