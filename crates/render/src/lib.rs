// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure renderers for every engine config Mooring runs (design §8).
//!
//! - [`vps::bundle`] renders one node's managed files: `xray.json`,
//!   `hy2.json`, `wgexit.conf`, `nftables.conf`, `watch.json` and
//!   `viewer_authorized_keys`, with their digests and the bundle digest an
//!   `Apply` carries.
//! - [`vps::cloud_init`] renders a planned node's cloud-init user-data.
//! - [`mac::exit`] and [`mac::prober`] render the `mooring-exit` and
//!   `mooring-probe` configs the daemon sends to the engines on stdin.
//!
//! Nothing here performs I/O, reads a clock or draws randomness. Every
//! config is built as a closed type that also deserialises with unknown
//! fields rejected, so goldens read back into the same types. Fixed engine
//! strings are one-value types, and the outbound and binding types make the
//! designed invariants structural: Xray's `deny` is always the first
//! outbound, its exit is always bound to `wgexit`, a camouflage redirect
//! can only reach the REALITY target, and every Mac outbound and endpoint
//! is bound to an interface. `SPECIAL_V4` from the model is the one list
//! behind the Xray deny rules, the DoH `unexpectedIPs` and the Mac deny
//! rules.
//!
//! Rendered files are zeroized on drop and never `Debug`-printed;
//! `docs/engines.md` maps every engine key to the pinned upstream source.

#![deny(missing_docs)]

mod encode;
mod error;
mod literal;
mod reach;
mod rendered;
mod secret_text;
mod singbox;
mod system;
mod text_value;

pub mod mac;
pub mod vps;
pub mod wire;

#[cfg(test)]
mod tests;

pub use error::{
    CredentialHolder, CredentialKind, HostKeyRule, RenderError, RenderErrorKind, WireField,
};
pub use mac::{ExitConfig, ProbeEndpoint, ProberConfig};
pub use rendered::RenderedFile;
pub use vps::{CloudInitKeys, EngineCatalog, OpensshHostKey, UserData, VpsBundle};
pub use wire::{adoption_site, ssh_ed25519_key, ssh_ed25519_pub, target_facts};
