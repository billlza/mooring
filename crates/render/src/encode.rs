// SPDX-License-Identifier: GPL-3.0-or-later

//! Rendered files in zeroizing buffers of exactly the needed capacity,
//! through the model's exact renderer (`mooring_model::exact`) and the
//! export crate's JSON writer, so no reallocation ever leaves a copy of
//! secret material behind.

use mooring_model::exact::{self, TextSink};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::RenderError;

/// Runs `write` twice and returns its text in an exactly sized buffer.
pub(crate) fn text(write: impl Fn(&mut dyn TextSink)) -> Zeroizing<Vec<u8>> {
    let mut text = exact::text(write);
    // Moving the buffer out copies nothing; the empty string left behind
    // is what the outer wrapper zeroizes.
    Zeroizing::new(std::mem::take(&mut *text).into_bytes())
}

/// Pretty-printed JSON followed by one newline, in an exactly sized buffer.
pub(crate) fn json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, RenderError> {
    mooring_export::exact_json(value).map_err(RenderError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_buffers_are_exactly_sized() {
        let bytes = text(|sink| {
            sink.put("a = ");
            sink.show(&42);
            sink.put("\n");
        });
        assert_eq!(bytes.as_slice(), b"a = 42\n");
        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn json_buffers_are_exactly_sized_and_newline_terminated() {
        let bytes = json(&serde_json::json!({"a": [1, 2]})).unwrap();
        assert_eq!(bytes.as_slice(), b"{\n  \"a\": [\n    1,\n    2\n  ]\n}\n");
        assert_eq!(bytes.capacity(), bytes.len());
    }
}
