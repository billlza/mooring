// SPDX-License-Identifier: GPL-3.0-or-later

//! Declarative helpers shared by the wire types.

/// Declares a field-less enum together with `ALL`, every variant in
/// declaration order. The list is generated from the same tokens as the enum,
/// so it cannot fall out of step with it.
macro_rules! closed_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

/// Implements `Serialize` through `Display` and `Deserialize` through
/// `FromStr`, so a validated newtype travels as one JSON string and is
/// validated again on receipt.
macro_rules! string_serde {
    ($name:ty) => {
        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                text.parse().map_err(::serde::de::Error::custom)
            }
        }
    };
}

/// Declares a string newtype whose every value satisfies `$valid`. The only
/// constructors are `new` and `FromStr`, and deserialisation goes through
/// them, so an invalid value cannot be represented.
macro_rules! text_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, $error:ident, $valid:path
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates `text` and wraps it.
            pub fn new(text: impl Into<String>) -> Result<Self, $crate::ValueError> {
                let text = text.into();
                if $valid(&text) {
                    Ok(Self(text))
                } else {
                    Err($crate::ValueError::$error)
                }
            }

            /// The validated text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::ValueError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }

        $crate::macros::string_serde!($name);
    };
}

pub(crate) use closed_enum;
pub(crate) use string_serde;
pub(crate) use text_newtype;
