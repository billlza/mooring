// SPDX-License-Identifier: GPL-3.0-or-later

//! The `kinds!` macro, which declares a fieldless kind enum whose `ALL` list
//! is complete by construction. It is the one definition every Mooring crate
//! that depends on the model uses (design §14); `mooring-agent-proto`, which
//! has no internal dependencies, keeps its own `closed_enum!`.

/// Declares a fieldless kind enum together with `ALL`, `name()` and a
/// `Display` that writes the name.
///
/// `ALL` is generated from the same variant list as the enum, so it cannot
/// drift from the variants (design §14). The enum derives `Debug`, `Clone`,
/// `Copy`, `PartialEq`, `Eq`, `Hash`, `PartialOrd` and `Ord`.
#[macro_export]
macro_rules! kinds {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every kind, in declaration order.
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            /// The stable name of this kind: its variant identifier.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $( $name::$variant => stringify!($variant) ),+
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}
