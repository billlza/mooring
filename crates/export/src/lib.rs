// SPDX-License-Identifier: GPL-3.0-or-later

//! CFM-importable client profiles (design §9).
//!
//! Pure: no I/O, no clock reads, no randomness; `now` is a parameter.
//!
//! - [`export_user`] writes one user's file, selected by the user's
//!   `ClientProfile`: sing-box JSON whose root holds only `outbounds`
//!   (default), or Clash YAML whose root holds only `proxies:`.
//! - [`check_certificate`] re-checks a node's stored Hysteria2 certificate
//!   against what CFM's pin verifier enforces; exports run it for every node.
//! - [`SingBoxOutbound`] is the one outbound value type; [`probe_outbounds`]
//!   builds the probe identity's outbounds that the Mac prober wraps.
//! - [`shapes`] enumerates every shape the emitter can produce; `cargo
//!   xtask acceptance` gates them against `contract/cfm-acceptance.toml`.
//!
//! Every emitted value domain is a subset of what both CFM importers accept;
//! `docs/cfm-contract.md` maps each field to its model type and CFM rule.

#![deny(missing_docs)]

mod cert;
mod clash;
mod error;
mod export;
mod json;
mod proxy;
mod shape;
mod singbox;
mod tag;
mod text;
mod tree;

pub use cert::{CERT_SKEW_MARGIN_SECS, certificate_pins, check_certificate};
pub use error::{ExportError, ExportErrorKind, NotApplied, TagRule};
pub use export::{ExportDocument, ExportFormat, ProbeOutbounds, export_user, probe_outbounds};
pub use json::exact_json;
pub use proxy::{ClientHello, Fingerprint, Protocol, line_name};
pub use shape::{ProxyShape, Shape, shapes};
pub use singbox::SingBoxOutbound;
pub use tag::OutboundTag;
