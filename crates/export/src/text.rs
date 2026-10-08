// SPDX-License-Identifier: GPL-3.0-or-later

//! String quoting shared by the YAML emitter and the shape canonicaliser.
//! Output goes to the model's [`TextSink`]; secret-bearing documents are
//! rendered through `mooring_model::exact`, so no reallocation copies them.

use mooring_model::exact::TextSink;

/// Writes `text` as a JSON string that is also a valid YAML 1.2
/// double-quoted scalar.
///
/// `"` and `\` are escaped, and so is every character YAML or JSON readers
/// treat specially: C0 controls (including tab), DEL, C1 controls, the line
/// and paragraph separators, the byte-order mark and the two noncharacters
/// U+FFFE and U+FFFF. Everything else is written as is.
pub(crate) fn put_quoted(out: &mut dyn TextSink, text: &str) {
    out.put("\"");
    let mut start = 0;
    for (index, character) in text.char_indices() {
        let escape = match character {
            '"' => Some(Escape::Short("\\\"")),
            '\\' => Some(Escape::Short("\\\\")),
            '\n' => Some(Escape::Short("\\n")),
            '\r' => Some(Escape::Short("\\r")),
            '\t' => Some(Escape::Short("\\t")),
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}'
            | '\u{fffe}'
            | '\u{ffff}' => Some(Escape::Unicode(character)),
            _ => None,
        };
        if let Some(escape) = escape {
            out.put(&text[start..index]);
            match escape {
                Escape::Short(sequence) => out.put(sequence),
                Escape::Unicode(character) => out.put(&format!("\\u{:04x}", u32::from(character))),
            }
            start = index + character.len_utf8();
        }
    }
    out.put(&text[start..]);
    out.put("\"");
}

enum Escape {
    Short(&'static str),
    Unicode(char),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use saphyr::{LoadableYamlNode as _, Yaml};

    use super::*;

    fn quoted(text: &str) -> String {
        let mut out = String::new();
        put_quoted(&mut out, text);
        out
    }

    #[test]
    fn quoting_examples() {
        assert_eq!(quoted("lon1-reality"), "\"lon1-reality\"");
        assert_eq!(quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quoted("\n\t\u{7f}\u{85}"), "\"\\n\\t\\u007f\\u0085\"");
        assert_eq!(quoted("é✓"), "\"é✓\"");
    }

    #[test]
    fn exact_rendering_has_exact_capacity() {
        let text = mooring_model::exact::text(|out| {
            out.put("proxies:\n");
            put_quoted(out, "x\u{1}y");
        });
        assert_eq!(text.as_str(), "proxies:\n\"x\\u0001y\"");
        assert_eq!(text.capacity(), text.len());
    }

    proptest! {
        #[test]
        fn quoted_text_round_trips_through_json_and_yaml(text in any::<String>()) {
            let encoded = quoted(&text);
            let json: String = serde_json::from_str(&encoded).unwrap();
            prop_assert_eq!(&json, &text);
            let docs = Yaml::load_from_str(&format!("key: {encoded}\n")).unwrap();
            prop_assert_eq!(docs.len(), 1);
            prop_assert_eq!(docs[0]["key"].as_str(), Some(text.as_str()));
        }
    }
}
