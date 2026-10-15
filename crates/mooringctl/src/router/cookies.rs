// SPDX-License-Identifier: GPL-3.0-or-later

//! The cookie jar of one command: in memory only, for one host and a few
//! seconds, so a cookie's attributes are ignored. A cookie value is a
//! session credential: zeroized, never in `Debug`, sent only in `Cookie`.

use std::fmt;

use mooring_model::exact::TextSink;
use zeroize::Zeroizing;

use crate::router::error::HttpFault;

/// The most cookies kept.
pub(crate) const MAX_COOKIES: usize = 16;

/// The longest cookie (name and value) accepted, in bytes.
pub(crate) const MAX_COOKIE_BYTES: usize = 4096;

/// One cookie: its name and value.
pub(crate) struct Cookie {
    name: String,
    value: Zeroizing<String>,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// RFC 9110 `tchar`.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// RFC 6265 `cookie-octet`.
fn is_cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

fn trim_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}

/// Parses a `Set-Cookie` value: `name=value`, the name a token and the
/// value cookie-octets, optionally in double quotes (kept as sent);
/// everything after the first `;` (the attributes) is ignored.
pub(crate) fn parse_set_cookie(header: &[u8]) -> Result<Cookie, HttpFault> {
    let pair = match header.iter().position(|&byte| byte == b';') {
        Some(end) => &header[..end],
        None => header,
    };
    let equals = pair
        .iter()
        .position(|&byte| byte == b'=')
        .ok_or(HttpFault::Cookie)?;
    let name = trim_whitespace(&pair[..equals]);
    let value = trim_whitespace(&pair[equals + 1..]);
    let inner = match value {
        [b'"', inner @ .., b'"'] => inner,
        other => other,
    };
    let valid = !name.is_empty()
        && name.iter().copied().all(is_token_byte)
        && inner.iter().copied().all(is_cookie_octet)
        && name.len() + value.len() <= MAX_COOKIE_BYTES;
    if !valid {
        return Err(HttpFault::Cookie);
    }
    // Both are ASCII by the checks above, so each byte is one char.
    let name: String = name.iter().copied().map(char::from).collect();
    let mut text = Zeroizing::new(String::with_capacity(value.len()));
    text.extend(value.iter().copied().map(char::from));
    Ok(Cookie { name, value: text })
}

/// The cookies the M7 set during one command.
#[derive(Default)]
pub(crate) struct CookieJar {
    cookies: Vec<Cookie>,
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.cookies.iter().map(|cookie| &cookie.name))
            .finish()
    }
}

impl CookieJar {
    /// Keeps `cookie`, replacing one of the same name; `TooManyCookies`
    /// past [`MAX_COOKIES`].
    pub(crate) fn store(&mut self, cookie: Cookie) -> Result<(), HttpFault> {
        if let Some(kept) = self
            .cookies
            .iter_mut()
            .find(|kept| kept.name == cookie.name)
        {
            *kept = cookie;
            return Ok(());
        }
        if self.cookies.len() == MAX_COOKIES {
            return Err(HttpFault::TooManyCookies);
        }
        self.cookies.push(cookie);
        Ok(())
    }

    /// Whether the jar holds no cookie.
    pub(crate) fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Writes the `Cookie` header's value: `a=1; b=2`, in the order the
    /// cookies were first set.
    pub(crate) fn write_header_value(&self, sink: &mut dyn TextSink) {
        for (index, cookie) in self.cookies.iter().enumerate() {
            if index > 0 {
                sink.put("; ");
            }
            sink.put(&cookie.name);
            sink.put("=");
            sink.put(&cookie.value);
        }
    }

    /// The cookie names, in order.
    #[cfg(test)]
    pub(crate) fn names(&self) -> Vec<&str> {
        self.cookies
            .iter()
            .map(|cookie| cookie.name.as_str())
            .collect()
    }
}
