// SPDX-License-Identifier: GPL-3.0-or-later

//! Secret-bearing JSON documents, written through the model's exact-capacity
//! renderer; `mooring-render` uses the same function for its JSON configs.

use mooring_model::exact;
use serde::Serialize;
use zeroize::Zeroizing;

/// Pretty-printed JSON of `value` followed by one newline, in a zeroizing
/// buffer of exactly the needed capacity, so no reallocation leaves a copy
/// of the secrets it holds.
pub fn exact_json<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    exact::bytes(|out| {
        serde_json::to_writer_pretty(&mut *out, value)?;
        out.write_all(b"\n").map_err(serde_json::Error::io)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_is_pretty_newline_terminated_and_exactly_sized() {
        let bytes = exact_json(&serde_json::json!({"a": [1, 2]})).unwrap();
        assert_eq!(bytes.as_slice(), b"{\n  \"a\": [\n    1,\n    2\n  ]\n}\n");
        assert_eq!(bytes.capacity(), bytes.len());
    }
}
