// SPDX-License-Identifier: GPL-3.0-or-later

//! Shape enumeration (design §9.3 item 2).
//!
//! A shape is what the emitter writes for one proxy once every variable
//! leaf is replaced by its type tag: the keys, their order, the constants
//! and the value domain of each leaf. It is the import contract with CFM.
//! [`shapes`] enumerates every shape the emitter can produce across
//! protocol × format × client line × capability set, from the same
//! templates the emitter renders. Each shape is hashed over a canonical
//! text of a one-proxy document, so every shape is also one importable file.

use std::collections::BTreeSet;

use mooring_model::exact::TextSink;
use mooring_model::{Capability, ClientLine, Sha256Digest};

use crate::export::ExportFormat;
use crate::proxy::{
    ClientHello, Hy2Slot, Protocol, RealitySlot, capabilities, client_lines, line_name,
};
use crate::tree::{LeafTag, Tree, put_canonical};
use crate::{clash, singbox};

/// The first line of every canonical shape text. Changing the
/// canonicalisation changes this version, so every hash changes with it.
const SHAPE_VERSION: &str = "mooring-export-shape/1";

/// The proxy variant a shape describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProxyShape {
    /// VLESS+REALITY+Vision with this ClientHello.
    VlessReality(ClientHello),
    /// Hysteria2.
    Hysteria2,
}

impl ProxyShape {
    /// The protocol.
    #[must_use]
    pub const fn protocol(self) -> Protocol {
        match self {
            Self::VlessReality(_) => Protocol::VlessReality,
            Self::Hysteria2 => Protocol::Hysteria2,
        }
    }

    fn item(self, format: ExportFormat) -> Tree<LeafTag> {
        match (format, self) {
            (ExportFormat::SingBoxJson, Self::VlessReality(hello)) => {
                singbox::reality_item(hello).map(&mut RealitySlot::leaf)
            }
            (ExportFormat::SingBoxJson, Self::Hysteria2) => {
                singbox::hysteria2_item().map(&mut Hy2Slot::leaf)
            }
            (ExportFormat::ClashYaml, Self::VlessReality(hello)) => {
                clash::reality_item(hello).map(&mut RealitySlot::leaf)
            }
            (ExportFormat::ClashYaml, Self::Hysteria2) => {
                clash::hysteria2_item().map(&mut Hy2Slot::leaf)
            }
        }
    }
}

/// One shape for one client line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    format: ExportFormat,
    proxy: ProxyShape,
    line: ClientLine,
    canonical: String,
    hash: Sha256Digest,
}

impl Shape {
    fn new(format: ExportFormat, proxy: ProxyShape, line: ClientLine) -> Self {
        let item = proxy.item(format);
        let document = match format {
            ExportFormat::SingBoxJson => singbox::document(vec![item]),
            ExportFormat::ClashYaml => clash::document(vec![item]),
        };
        let mut canonical = String::new();
        canonical.put(SHAPE_VERSION);
        canonical.put("\n");
        canonical.put(format.name());
        canonical.put("\n");
        put_canonical(&mut canonical, &document);
        let hash = Sha256Digest::of(canonical.as_bytes());
        Self {
            format,
            proxy,
            line,
            canonical,
            hash,
        }
    }

    /// The format.
    #[must_use]
    pub const fn format(&self) -> ExportFormat {
        self.format
    }

    /// The proxy variant.
    #[must_use]
    pub const fn proxy(&self) -> ProxyShape {
        self.proxy
    }

    /// The client line this shape is produced for.
    #[must_use]
    pub const fn line(&self) -> ClientLine {
        self.line
    }

    /// The canonical text the hash is taken over.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// SHA-256 of [`Self::canonical`].
    #[must_use]
    pub const fn hash(&self) -> Sha256Digest {
        self.hash
    }

    /// A stable, readable name: `<format>/<protocol>[/<hello>]`.
    #[must_use]
    pub fn name(&self) -> String {
        match self.proxy {
            ProxyShape::VlessReality(hello) => format!(
                "{}/{}/{}",
                self.format.name(),
                Protocol::VlessReality.name(),
                hello.name()
            ),
            ProxyShape::Hysteria2 => {
                format!("{}/{}", self.format.name(), Protocol::Hysteria2.name())
            }
        }
    }

    /// The stable name of [`Self::line`].
    #[must_use]
    pub const fn line_name(&self) -> &'static str {
        line_name(self.line)
    }
}

/// Every capability set: the subsets of every capability.
fn capability_sets() -> Vec<BTreeSet<Capability>> {
    let mut sets = vec![BTreeSet::new()];
    for cap in capabilities() {
        let with: Vec<_> = sets
            .iter()
            .map(|set| {
                let mut set = set.clone();
                set.insert(cap);
                set
            })
            .collect();
        sets.extend(with);
    }
    sets
}

/// Every shape the emitter can produce, once per `(hash, line)`, in client
/// line order. A capability set a line does not accept produces no export
/// (`CapabilityUnsupported`) and therefore no shape.
#[must_use]
pub fn shapes() -> Vec<Shape> {
    let mut shapes: Vec<Shape> = Vec::new();
    for line in client_lines() {
        for capabilities in capability_sets() {
            if !capabilities.iter().all(|cap| line.accepts(*cap)) {
                continue;
            }
            let hello = ClientHello::for_capabilities(&capabilities);
            for format in ExportFormat::ALL {
                for proxy in [ProxyShape::VlessReality(hello), ProxyShape::Hysteria2] {
                    let shape = Shape::new(format, proxy, line);
                    if !shapes
                        .iter()
                        .any(|known| known.line == line && known.hash == shape.hash)
                    {
                        shapes.push(shape);
                    }
                }
            }
        }
    }
    shapes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_sets_are_the_power_set() {
        let sets = capability_sets();
        assert_eq!(sets.len(), 1 << capabilities().count());
        let distinct: BTreeSet<_> = sets.iter().cloned().collect();
        assert_eq!(distinct.len(), sets.len());
    }

    #[test]
    fn the_enumeration_covers_every_line_format_and_protocol() {
        let all = shapes();
        // cfm04: 2 formats × 2 protocols; cfm05 adds the hybrid REALITY hello.
        assert_eq!(all.len(), 4 + 6);
        for line in client_lines() {
            for format in ExportFormat::ALL {
                for protocol in Protocol::ALL {
                    assert!(all.iter().any(|shape| shape.line() == line
                        && shape.format() == format
                        && shape.proxy().protocol() == protocol));
                }
            }
        }
        let hybrid = ProxyShape::VlessReality(ClientHello::ChromeX25519Mlkem768);
        assert!(
            all.iter()
                .all(|shape| shape.proxy() != hybrid || shape.line() == ClientLine::Cfm05)
        );
        let names: BTreeSet<_> = all.iter().map(|s| (s.line_name(), s.name())).collect();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn shapes_hash_their_canonical_text() {
        for shape in shapes() {
            assert_eq!(shape.hash(), Sha256Digest::of(shape.canonical().as_bytes()));
            // Three lines: version, format, and the tree without whitespace.
            let lines: Vec<_> = shape.canonical().split('\n').collect();
            assert_eq!(lines.len(), 3);
            assert_eq!(lines[0], SHAPE_VERSION);
            assert_eq!(lines[1], shape.format().name());
            assert!(!lines[2].contains(char::is_whitespace));
        }
    }

    #[test]
    fn lines_share_hashes_but_formats_and_hellos_do_not() {
        let all = shapes();
        let hash = |line, format, proxy| {
            all.iter()
                .find(|s| s.line() == line && s.format() == format && s.proxy() == proxy)
                .map(Shape::hash)
                .unwrap()
        };
        let classical = ProxyShape::VlessReality(ClientHello::Chrome);
        let hybrid = ProxyShape::VlessReality(ClientHello::ChromeX25519Mlkem768);
        for format in ExportFormat::ALL {
            assert_eq!(
                hash(ClientLine::Cfm04, format, classical),
                hash(ClientLine::Cfm05, format, classical)
            );
            assert_ne!(
                hash(ClientLine::Cfm05, format, classical),
                hash(ClientLine::Cfm05, format, hybrid)
            );
        }
        assert_ne!(
            hash(
                ClientLine::Cfm05,
                ExportFormat::SingBoxJson,
                ProxyShape::Hysteria2
            ),
            hash(
                ClientLine::Cfm05,
                ExportFormat::ClashYaml,
                ProxyShape::Hysteria2
            )
        );
    }
}
