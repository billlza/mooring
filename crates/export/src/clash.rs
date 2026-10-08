// SPDX-License-Identifier: GPL-3.0-or-later

//! The optional format: Clash YAML holding only `proxies:` (design §9.1).
//!
//! The YAML is written by hand, without a YAML library: block style, every
//! string scalar a JSON-encoded (YAML 1.2 double-quoted) string, booleans
//! as plain `true`/`false`, integers as plain decimals. Keys are fixed
//! identifiers written as plain scalars.

use mooring_model::exact::{self, TextSink};
use zeroize::Zeroizing;

use crate::proxy::{ClientHello, Hy2Slot, REALITY_PORT, RealitySlot};
use crate::text::put_quoted;
use crate::tree::{Literal, Scalar, Tree, put_literal};

/// The only root key.
const ROOT_KEY: &str = "proxies";
/// Indentation per nesting level.
const INDENT: usize = 2;

/// The VLESS+REALITY+Vision proxy (CFM `clash.rs` `convert_vless`).
pub(crate) fn reality_item(hello: ClientHello) -> Tree<RealitySlot> {
    let mut reality = vec![
        ("public-key", Tree::Leaf(RealitySlot::PublicKey)),
        ("short-id", Tree::Leaf(RealitySlot::ShortId)),
    ];
    if hello.offers_x25519mlkem768() {
        reality.push(("support-x25519mlkem768", Tree::Lit(Literal::Bool(true))));
    }
    Tree::Map(vec![
        ("name", Tree::Leaf(RealitySlot::Tag)),
        ("type", Tree::Lit(Literal::Str("vless"))),
        ("server", Tree::Leaf(RealitySlot::Server)),
        ("port", Tree::Lit(Literal::Int(REALITY_PORT.get()))),
        ("uuid", Tree::Leaf(RealitySlot::Uuid)),
        ("flow", Tree::Lit(Literal::Str("xtls-rprx-vision"))),
        ("packet-encoding", Tree::Lit(Literal::Str("xudp"))),
        ("tls", Tree::Lit(Literal::Bool(true))),
        ("servername", Tree::Leaf(RealitySlot::ServerName)),
        (
            "client-fingerprint",
            Tree::Lit(Literal::Str(hello.fingerprint().as_str())),
        ),
        ("reality-opts", Tree::Map(reality)),
    ])
}

/// The Hysteria2 proxy (CFM `clash.rs` `convert_hysteria2`). `fingerprint`
/// is the DER SHA-256 pin, which CFM maps to `certificate_sha256`.
pub(crate) fn hysteria2_item() -> Tree<Hy2Slot> {
    Tree::Map(vec![
        ("name", Tree::Leaf(Hy2Slot::Tag)),
        ("type", Tree::Lit(Literal::Str("hysteria2"))),
        ("server", Tree::Leaf(Hy2Slot::Server)),
        ("port", Tree::Leaf(Hy2Slot::Port)),
        ("ports", Tree::Leaf(Hy2Slot::PortsDash)),
        ("hop-interval", Tree::Leaf(Hy2Slot::HopSeconds)),
        ("password", Tree::Leaf(Hy2Slot::Password)),
        ("obfs", Tree::Lit(Literal::Str("salamander"))),
        ("obfs-password", Tree::Leaf(Hy2Slot::ObfsPassword)),
        ("sni", Tree::Leaf(Hy2Slot::Sni)),
        ("fingerprint", Tree::Leaf(Hy2Slot::DerPin)),
    ])
}

/// The document around `items`.
pub(crate) fn document<S>(items: Vec<Tree<S>>) -> Tree<S> {
    Tree::Map(vec![(ROOT_KEY, Tree::List(items))])
}

/// Renders a resolved document as block YAML into a zeroizing buffer of
/// exactly the needed capacity.
pub(crate) fn render(tree: &Tree<Scalar>) -> Zeroizing<Vec<u8>> {
    let mut text = exact::text(|out| put_document(out, tree));
    // Moving the buffer out copies nothing; the empty string left behind
    // is what the outer wrapper zeroizes.
    Zeroizing::new(std::mem::take(&mut *text).into_bytes())
}

fn put_document(out: &mut dyn TextSink, tree: &Tree<Scalar>) {
    match tree {
        Tree::Map(entries) if !entries.is_empty() => put_entries(out, entries, 0),
        other => {
            put_flow(out, other);
            out.put("\n");
        }
    }
}

fn put_indent(out: &mut dyn TextSink, indent: usize) {
    for _ in 0..indent {
        out.put(" ");
    }
}

fn put_entries(out: &mut dyn TextSink, entries: &[(&'static str, Tree<Scalar>)], indent: usize) {
    for (key, value) in entries {
        put_indent(out, indent);
        put_entry(out, key, value, indent);
    }
}

/// Writes `key: value` whose key starts at the current position, at nesting
/// `indent`.
fn put_entry(out: &mut dyn TextSink, key: &str, value: &Tree<Scalar>, indent: usize) {
    out.put(key);
    out.put(":");
    match value {
        Tree::Map(entries) if !entries.is_empty() => {
            out.put("\n");
            put_entries(out, entries, indent + INDENT);
        }
        Tree::List(items) if !items.is_empty() => {
            out.put("\n");
            put_items(out, items, indent + INDENT);
        }
        other => {
            out.put(" ");
            put_flow(out, other);
            out.put("\n");
        }
    }
}

fn put_items(out: &mut dyn TextSink, items: &[Tree<Scalar>], indent: usize) {
    for item in items {
        put_indent(out, indent);
        out.put("- ");
        match item {
            Tree::Map(entries) if !entries.is_empty() => {
                let mut rest = entries.iter();
                if let Some((key, value)) = rest.next() {
                    put_entry(out, key, value, indent + INDENT);
                }
                for (key, value) in rest {
                    put_indent(out, indent + INDENT);
                    put_entry(out, key, value, indent + INDENT);
                }
            }
            Tree::List(inner) if !inner.is_empty() => {
                out.put("\n");
                put_items(out, inner, indent + INDENT);
            }
            other => {
                put_flow(out, other);
                out.put("\n");
            }
        }
    }
}

/// Writes a scalar or an empty collection in flow style.
fn put_flow(out: &mut dyn TextSink, value: &Tree<Scalar>) {
    match value {
        Tree::Map(entries) => {
            out.put("{");
            for (position, (key, value)) in entries.iter().enumerate() {
                if position > 0 {
                    out.put(", ");
                }
                put_quoted(out, key);
                out.put(": ");
                put_flow(out, value);
            }
            out.put("}");
        }
        Tree::List(items) => {
            out.put("[");
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.put(", ");
                }
                put_flow(out, item);
            }
            out.put("]");
        }
        Tree::Lit(literal) => put_literal(out, *literal),
        Tree::Leaf(Scalar::Text(text)) => put_quoted(out, text),
        Tree::Leaf(Scalar::Int(value)) => out.put(&value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use saphyr::{LoadableYamlNode as _, Yaml};

    use super::*;

    fn text(value: &str) -> Tree<Scalar> {
        Tree::Leaf(Scalar::text(value))
    }

    fn rendered(tree: &Tree<Scalar>) -> String {
        String::from_utf8(render(tree).to_vec()).unwrap()
    }

    #[test]
    fn block_yaml_layout() {
        let tree = Tree::Map(vec![(
            ROOT_KEY,
            Tree::List(vec![
                Tree::Map(vec![
                    ("name", text("lon1-reality")),
                    ("port", Tree::Lit(Literal::Int(443))),
                    ("tls", Tree::Lit(Literal::Bool(true))),
                    (
                        "reality-opts",
                        Tree::Map(vec![("short-id", text("0123456789abcdef"))]),
                    ),
                    ("hop-interval", Tree::Leaf(Scalar::Int(30))),
                ]),
                Tree::Map(vec![("name", text("q\"uote"))]),
            ]),
        )]);
        assert_eq!(
            rendered(&tree),
            "proxies:\n  - name: \"lon1-reality\"\n    port: 443\n    tls: true\n    \
             reality-opts:\n      short-id: \"0123456789abcdef\"\n    hop-interval: 30\n  \
             - name: \"q\\\"uote\"\n"
        );
    }

    #[test]
    fn rendering_is_exactly_sized_and_valid_yaml() {
        let tree = Tree::Map(vec![
            (
                "proxies",
                Tree::List(vec![
                    Tree::List(vec![text("a"), Tree::Lit(Literal::Bool(false))]),
                    Tree::List(Vec::new()),
                    Tree::Map(Vec::new()),
                    text("plain"),
                ]),
            ),
            ("empty", Tree::Map(Vec::new())),
            ("none", Tree::List(Vec::new())),
            (
                "flow",
                Tree::Map(vec![(
                    "nested",
                    Tree::List(vec![Tree::Map(vec![("k", Tree::Lit(Literal::Str("v")))])]),
                )]),
            ),
        ]);
        let bytes = render(&tree);
        assert_eq!(bytes.capacity(), bytes.len());
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let docs = Yaml::load_from_str(&text).unwrap();
        assert_eq!(docs.len(), 1);
        let proxies = &docs[0]["proxies"];
        assert_eq!(proxies[0][0].as_str(), Some("a"));
        assert_eq!(proxies[0][1].as_bool(), Some(false));
        assert!(proxies[1].is_empty_collection());
        assert!(proxies[2].is_empty_collection());
        assert_eq!(proxies[3].as_str(), Some("plain"));
        assert!(docs[0]["empty"].is_empty_collection());
        assert!(docs[0]["none"].is_empty_collection());
        assert_eq!(docs[0]["flow"]["nested"][0]["k"].as_str(), Some("v"));
    }

    #[test]
    fn a_non_mapping_document_is_written_in_flow_style() {
        assert_eq!(rendered(&text("x")), "\"x\"\n");
        assert_eq!(rendered(&Tree::Map(Vec::new())), "{}\n");
    }
}
