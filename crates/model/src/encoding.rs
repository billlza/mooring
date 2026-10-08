// SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical text encodings shared by the key, digest and secret newtypes.
//!
//! Every decoder accepts exactly one spelling per byte string: the length is
//! fixed, padding is mandatory or forbidden by alphabet, and the base64
//! engines reject non-zero trailing bits, so decode-then-encode is the identity.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// Length of a 32-byte value in unpadded base64url.
pub(crate) const B64URL_32_LEN: usize = 43;
/// Length of a 32-byte value in padded standard base64.
pub(crate) const B64STD_32_LEN: usize = 44;

/// Decodes 32 bytes from 43 characters of unpadded base64url.
pub(crate) fn decode_b64url_32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != B64URL_32_LEN {
        return None;
    }
    let mut out = Zeroizing::new([0_u8; 32]);
    match URL_SAFE_NO_PAD.decode_slice(text, out.as_mut_slice()) {
        Ok(32) => Some(out),
        _ => None,
    }
}

/// Decodes 32 bytes from 44 characters of padded standard base64.
pub(crate) fn decode_b64std_32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != B64STD_32_LEN {
        return None;
    }
    let mut out = Zeroizing::new([0_u8; 32]);
    match STANDARD.decode_slice(text, out.as_mut_slice()) {
        Ok(32) => Some(out),
        _ => None,
    }
}

/// Encodes bytes as unpadded base64url.
pub(crate) fn encode_b64url(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))
}

/// Encodes bytes as padded standard base64.
pub(crate) fn encode_b64std(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(bytes))
}

/// Decodes exactly `N` bytes from `2 * N` lowercase hexadecimal characters.
pub(crate) fn decode_hex_lower<const N: usize>(text: &str) -> Option<[u8; N]> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !rest.is_empty() {
        return None;
    }
    let mut out = [0_u8; N];
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
    }
    Some(out)
}

/// Encodes bytes as lowercase hexadecimal.
pub(crate) fn encode_hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn hex_rejects_uppercase_and_wrong_length() {
        assert_eq!(decode_hex_lower::<2>("0a0b"), Some([0x0a, 0x0b]));
        assert_eq!(decode_hex_lower::<2>("0A0b"), None);
        assert_eq!(decode_hex_lower::<2>("0a0"), None);
        assert_eq!(decode_hex_lower::<2>("0a0b0c"), None);
        assert_eq!(decode_hex_lower::<2>("0g0b"), None);
    }

    #[test]
    fn base64_rejects_non_canonical_spellings() {
        let canonical = encode_b64url(&[0xff; 32]);
        assert!(decode_b64url_32(&canonical).is_some());
        // The last symbol of 32 bytes carries 4 data bits; setting a discarded
        // trailing bit must be rejected rather than silently ignored.
        let mut tweaked = canonical.to_string();
        tweaked.pop();
        tweaked.push('_');
        assert!(decode_b64url_32(&tweaked).is_none());
        // Padding is forbidden in base64url and mandatory in standard base64.
        assert!(decode_b64url_32(&format!("{}=", &canonical[..42])).is_none());
        let standard = encode_b64std(&[0x11; 32]);
        assert!(decode_b64std_32(&standard).is_some());
        assert!(decode_b64std_32(standard.trim_end_matches('=')).is_none());
        // The two alphabets are not interchangeable.
        assert!(decode_b64std_32(&encode_b64std(&[0xfb; 32]).replace('+', "-")).is_none());
    }

    proptest! {
        #[test]
        fn base64url_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let text = encode_b64url(&bytes);
            prop_assert_eq!(text.len(), B64URL_32_LEN);
            prop_assert_eq!(*decode_b64url_32(&text).unwrap(), bytes);
        }

        #[test]
        fn base64std_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let text = encode_b64std(&bytes);
            prop_assert_eq!(text.len(), B64STD_32_LEN);
            prop_assert_eq!(*decode_b64std_32(&text).unwrap(), bytes);
        }

        #[test]
        fn accepted_base64url_is_canonical(text in "[A-Za-z0-9_-]{43}") {
            if let Some(bytes) = decode_b64url_32(&text) {
                let again = encode_b64url(bytes.as_slice());
                prop_assert_eq!(again.as_str(), text.as_str());
            }
        }

        #[test]
        fn hex_round_trips(bytes in proptest::array::uniform8(any::<u8>())) {
            let text = encode_hex_lower(&bytes);
            prop_assert_eq!(decode_hex_lower::<8>(&text), Some(bytes));
        }
    }
}
