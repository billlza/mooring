// SPDX-License-Identifier: GPL-3.0-or-later

//! Fixed strings in rendered configs as one-value types: a config struct
//! whose field is such a type can only ever carry that string, and reading a
//! golden back rejects any other spelling.

/// Declares a one-variant enum that serialises as exactly `$text`.
macro_rules! literal {
    ($(#[$meta:meta])* $name:ident = $text:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
        )]
        pub(crate) enum $name {
            #[doc = concat!("`", $text, "`.")]
            #[default]
            #[serde(rename = $text)]
            Value,
        }
    };
}

pub(crate) use literal;
