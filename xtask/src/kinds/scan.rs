// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-file analysis on top of the tokenizer: `Kind` enums and their
//! variants, `A::B` path references, `A as B` aliases, out-of-line module
//! declarations, and which tokens are test-only code.
//!
//! An item is test-only when it, or an item containing it, carries an outer
//! `#[cfg(...)]` that requires `test` (`test`, `all(test, …)`, `any` of only
//! such predicates), or when an inner `#![cfg(test)]` applies to it.

use std::collections::BTreeMap;

use super::lexer::{Delim, LexError, Spanned, Token, tokenize};

/// A public enum named `Kind` or `<Something>Kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KindEnum {
    pub(crate) name: String,
    pub(crate) variants: Vec<String>,
    pub(crate) line: u32,
    pub(crate) in_test: bool,
}

/// `head::tail`, e.g. `Kind::Entropy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathRef {
    pub(crate) head: String,
    pub(crate) tail: String,
    pub(crate) in_test: bool,
}

/// `original as alias`, as in `use crate::error::Kind as ModelKind;`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Alias {
    pub(crate) original: String,
    pub(crate) alias: String,
}

/// `mod name;` with the inline modules that enclose it and its `#[path]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModDecl {
    pub(crate) inline_path: Vec<String>,
    pub(crate) name: String,
    pub(crate) path_attr: Option<String>,
    pub(crate) in_test: bool,
    pub(crate) line: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct FileScan {
    /// The file starts with `#![cfg(test)]`.
    pub(crate) file_is_test: bool,
    pub(crate) kind_enums: Vec<KindEnum>,
    pub(crate) paths: Vec<PathRef>,
    pub(crate) aliases: Vec<Alias>,
    pub(crate) mod_decls: Vec<ModDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ScanError {
    #[error(transparent)]
    Lex(#[from] LexError),
    #[error("line {line}: closing delimiter without a matching opening one")]
    UnmatchedClose { line: u32 },
    #[error("line {line}: delimiter is never closed")]
    Unclosed { line: u32 },
    #[error("line {line}: cannot read the variants of enum {name}")]
    MalformedEnum { name: String, line: u32 },
}

pub(crate) fn is_kind_name(name: &str) -> bool {
    name.ends_with("Kind")
}

pub(crate) fn scan(source: &str) -> Result<FileScan, ScanError> {
    let tokens = tokenize(source)?;
    let pairs = match_delimiters(&tokens)?;
    let attributes = scan_attributes(&tokens, &pairs);
    Items {
        tokens: &tokens,
        pairs: &pairs,
        attributes: &attributes,
    }
    .collect()
}

/// For every delimiter, the index of its partner; other entries hold their own index.
fn match_delimiters(tokens: &[Spanned]) -> Result<Vec<usize>, ScanError> {
    let mut pairs: Vec<usize> = (0..tokens.len()).collect();
    let mut open: Vec<(usize, Delim)> = Vec::new();
    for (index, spanned) in tokens.iter().enumerate() {
        match spanned.token {
            Token::Open(delim) => open.push((index, delim)),
            Token::Close(delim) => match open.pop() {
                Some((start, opened)) if opened == delim => {
                    pairs[start] = index;
                    pairs[index] = start;
                }
                _ => return Err(ScanError::UnmatchedClose { line: spanned.line }),
            },
            _ => {}
        }
    }
    match open.first() {
        Some(&(index, _)) => Err(ScanError::Unclosed {
            line: tokens[index].line,
        }),
        None => Ok(pairs),
    }
}

#[derive(Debug)]
struct AttributeScan {
    test_mask: Vec<bool>,
    file_is_test: bool,
    /// `#[path = "…"]`, keyed by the index of the item keyword after any visibility.
    path_attrs: BTreeMap<usize, String>,
}

fn token_at(tokens: &[Spanned], index: usize) -> Option<&Token> {
    tokens.get(index).map(|spanned| &spanned.token)
}

/// `#[…]` at `index`: the index of its closing bracket.
fn outer_attribute(tokens: &[Spanned], pairs: &[usize], index: usize) -> Option<usize> {
    match (token_at(tokens, index), token_at(tokens, index + 1)) {
        (Some(Token::Pound), Some(Token::Open(Delim::Bracket))) => Some(pairs[index + 1]),
        _ => None,
    }
}

/// `#![…]` at `index`: the index of its closing bracket.
fn inner_attribute(tokens: &[Spanned], pairs: &[usize], index: usize) -> Option<usize> {
    match (
        token_at(tokens, index),
        token_at(tokens, index + 1),
        token_at(tokens, index + 2),
    ) {
        (Some(Token::Pound), Some(Token::Bang), Some(Token::Open(Delim::Bracket))) => {
            Some(pairs[index + 2])
        }
        _ => None,
    }
}

fn mark(mask: &mut [bool], from: usize, to: usize) {
    for flag in mask.iter_mut().take(to).skip(from) {
        *flag = true;
    }
}

fn scan_attributes(tokens: &[Spanned], pairs: &[usize]) -> AttributeScan {
    let mut scan = AttributeScan {
        test_mask: vec![false; tokens.len()],
        file_is_test: false,
        path_attrs: BTreeMap::new(),
    };
    let mut open: Vec<usize> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if let Some(close) = inner_attribute(tokens, pairs, index) {
            if cfg_requires_test(&tokens[index + 3..close]) {
                match open.last() {
                    Some(&scope) => mark(&mut scan.test_mask, scope, pairs[scope] + 1),
                    None => scan.file_is_test = true,
                }
            }
            index = close + 1;
        } else if outer_attribute(tokens, pairs, index).is_some() {
            index = scan_outer_attributes(tokens, pairs, index, &mut scan);
        } else {
            match tokens[index].token {
                Token::Open(_) => open.push(index),
                Token::Close(_) => {
                    open.pop();
                }
                _ => {}
            }
            index += 1;
        }
    }
    scan
}

/// Handles the run of outer attributes starting at `start`; returns the index
/// of the item they decorate.
fn scan_outer_attributes(
    tokens: &[Spanned],
    pairs: &[usize],
    start: usize,
    scan: &mut AttributeScan,
) -> usize {
    let mut item = start;
    let mut cfg_test = false;
    let mut path = None;
    while let Some(close) = outer_attribute(tokens, pairs, item) {
        let body = &tokens[item + 2..close];
        cfg_test |= cfg_requires_test(body);
        if let Some(value) = path_attribute(body) {
            path = Some(value);
        }
        item = close + 1;
    }
    if cfg_test {
        mark(&mut scan.test_mask, start, item_end(tokens, pairs, item));
    }
    if let Some(value) = path {
        scan.path_attrs
            .insert(skip_visibility(tokens, pairs, item), value);
    }
    item
}

/// `pub`, `pub(crate)`, `pub(in path)`: the index of the token after it.
fn skip_visibility(tokens: &[Spanned], pairs: &[usize], index: usize) -> usize {
    if !tokens.get(index).is_some_and(|t| t.is_ident("pub")) {
        return index;
    }
    match token_at(tokens, index + 1) {
        Some(Token::Open(Delim::Paren)) => pairs[index + 1] + 1,
        _ => index + 1,
    }
}

const ITEM_KEYWORDS: &[&str] = &[
    "async",
    "const",
    "enum",
    "extern",
    "fn",
    "impl",
    "macro_rules",
    "mod",
    "static",
    "struct",
    "trait",
    "type",
    "union",
    "unsafe",
    "use",
];

/// The exclusive end of the item, statement, field, variant or arm starting at `start`.
///
/// Items end at a `;` or after their first top-level `{…}`. Other syntax
/// (fields, variants, match arms) also ends at a top-level `,`; for items a
/// comma may belong to generics (`fn f<A, B>()`), so it does not end them.
fn item_end(tokens: &[Spanned], pairs: &[usize], start: usize) -> usize {
    let keyword = skip_visibility(tokens, pairs, start);
    let is_item = tokens
        .get(keyword)
        .and_then(Spanned::ident)
        .is_some_and(|word| ITEM_KEYWORDS.contains(&word));
    let mut index = start;
    while let Some(token) = token_at(tokens, index) {
        match token {
            Token::Semi => return index + 1,
            Token::Comma if !is_item => return index,
            Token::Close(_) => return index,
            Token::Open(Delim::Brace) => return pairs[index] + 1,
            Token::Open(_) => index = pairs[index] + 1,
            _ => index += 1,
        }
    }
    tokens.len()
}

/// Whether `cfg(...)` (the tokens inside `#[` `]`) can only hold under `cfg(test)`.
fn cfg_requires_test(body: &[Spanned]) -> bool {
    match body {
        [cfg, open, inner @ .., close]
            if cfg.is_ident("cfg")
                && open.token == Token::Open(Delim::Paren)
                && close.token == Token::Close(Delim::Paren) =>
        {
            let mut parser = CfgParser {
                tokens: inner,
                pos: 0,
            };
            parser.predicate() == Some(true) && parser.pos == inner.len()
        }
        _ => false,
    }
}

/// Parses a cfg predicate and answers "does it require `test`?". `None`
/// means the predicate is not well-formed; rustc would reject such an
/// attribute, so it is treated as not test-only.
#[derive(Debug)]
struct CfgParser<'a> {
    tokens: &'a [Spanned],
    pos: usize,
}

impl CfgParser<'_> {
    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.pos).map(|spanned| &spanned.token);
        self.pos += 1;
        token
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|spanned| &spanned.token)
    }

    fn predicate(&mut self) -> Option<bool> {
        let Some(Token::Ident(name)) = self.next().cloned() else {
            return None;
        };
        match self.peek() {
            Some(Token::Open(Delim::Paren)) => {
                self.pos += 1;
                let children = self.list()?;
                Some(match name.as_str() {
                    "all" => children.iter().any(|&child| child),
                    "any" => !children.is_empty() && children.iter().all(|&child| child),
                    _ => false,
                })
            }
            Some(Token::Eq) => {
                self.pos += 1;
                matches!(self.next(), Some(Token::Str(_))).then_some(false)
            }
            _ => Some(name == "test"),
        }
    }

    /// Comma-separated predicates up to and including `)`.
    fn list(&mut self) -> Option<Vec<bool>> {
        let mut children = Vec::new();
        loop {
            if self.peek() == Some(&Token::Close(Delim::Paren)) {
                self.pos += 1;
                return Some(children);
            }
            children.push(self.predicate()?);
            match self.next() {
                Some(Token::Comma) => {}
                Some(Token::Close(Delim::Paren)) => return Some(children),
                _ => return None,
            }
        }
    }
}

/// `path = "…"` (the tokens inside `#[` `]`).
fn path_attribute(body: &[Spanned]) -> Option<String> {
    match body {
        [
            key,
            Spanned {
                token: Token::Eq, ..
            },
            Spanned {
                token: Token::Str(value),
                ..
            },
        ] if key.is_ident("path") => Some(value.clone()),
        _ => None,
    }
}

#[derive(Debug)]
struct Items<'a> {
    tokens: &'a [Spanned],
    pairs: &'a [usize],
    attributes: &'a AttributeScan,
}

impl Items<'_> {
    fn ident(&self, index: usize) -> Option<&str> {
        self.tokens.get(index).and_then(Spanned::ident)
    }

    fn in_test(&self, index: usize) -> bool {
        self.attributes.file_is_test || self.attributes.test_mask[index]
    }

    fn collect(&self) -> Result<FileScan, ScanError> {
        let mut scan = FileScan {
            file_is_test: self.attributes.file_is_test,
            ..FileScan::default()
        };
        // Inline modules enclosing the cursor: (name, index of the closing brace).
        let mut inline: Vec<(String, usize)> = Vec::new();
        for (index, spanned) in self.tokens.iter().enumerate() {
            while inline.last().is_some_and(|&(_, close)| close < index) {
                inline.pop();
            }
            match &spanned.token {
                Token::Ident(word) if word == "mod" => self.module(index, &mut inline, &mut scan),
                Token::Ident(word) if word == "enum" => self.kind_enum(index, &mut scan)?,
                Token::Ident(word) if word == "as" => {
                    if let (Some(original), Some(alias)) = (
                        index.checked_sub(1).and_then(|before| self.ident(before)),
                        self.ident(index + 1),
                    ) {
                        scan.aliases.push(Alias {
                            original: original.to_owned(),
                            alias: alias.to_owned(),
                        });
                    }
                }
                Token::PathSep => {
                    if let (Some(head), Some(tail)) = (
                        index.checked_sub(1).and_then(|before| self.ident(before)),
                        self.ident(index + 1),
                    ) {
                        scan.paths.push(PathRef {
                            head: head.to_owned(),
                            tail: tail.to_owned(),
                            in_test: self.in_test(index),
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(scan)
    }

    fn module(&self, index: usize, inline: &mut Vec<(String, usize)>, scan: &mut FileScan) {
        let Some(name) = self.ident(index + 1) else {
            return;
        };
        match token_at(self.tokens, index + 2) {
            Some(Token::Semi) => scan.mod_decls.push(ModDecl {
                inline_path: inline.iter().map(|(name, _)| name.clone()).collect(),
                name: name.to_owned(),
                path_attr: self.attributes.path_attrs.get(&index).cloned(),
                in_test: self.in_test(index),
                line: self.tokens[index].line,
            }),
            Some(Token::Open(Delim::Brace)) => {
                inline.push((name.to_owned(), self.pairs[index + 2]));
            }
            _ => {}
        }
    }

    /// `pub enum <Name>Kind … { Variant, … }`
    fn kind_enum(&self, index: usize, scan: &mut FileScan) -> Result<(), ScanError> {
        let is_pub = index
            .checked_sub(1)
            .and_then(|before| self.tokens.get(before))
            .is_some_and(|t| t.is_ident("pub"));
        let Some(name) = self.ident(index + 1).filter(|name| is_kind_name(name)) else {
            return Ok(());
        };
        if !is_pub {
            return Ok(());
        }
        let line = self.tokens[index].line;
        let malformed = || ScanError::MalformedEnum {
            name: name.to_owned(),
            line,
        };
        let mut body = index + 2;
        loop {
            match token_at(self.tokens, body) {
                Some(Token::Open(Delim::Brace)) => break,
                Some(Token::Open(_)) => body = self.pairs[body] + 1,
                Some(Token::Semi | Token::Close(_)) | None => return Err(malformed()),
                Some(_) => body += 1,
            }
        }
        let variants = self
            .variants(body + 1, self.pairs[body])
            .ok_or_else(malformed)?;
        scan.kind_enums.push(KindEnum {
            name: name.to_owned(),
            variants,
            line,
            in_test: self.in_test(index),
        });
        Ok(())
    }

    /// Variant names between `start` and the closing brace at `end`:
    /// attributes are skipped, payloads and discriminants ignored, and a
    /// trailing comma is allowed.
    fn variants(&self, start: usize, end: usize) -> Option<Vec<String>> {
        let mut variants = Vec::new();
        let mut index = start;
        while index < end {
            while let Some(close) = outer_attribute(self.tokens, self.pairs, index) {
                index = close + 1;
            }
            if index >= end {
                break;
            }
            variants.push(self.ident(index)?.to_owned());
            index += 1;
            while index < end && token_at(self.tokens, index) != Some(&Token::Comma) {
                index = match token_at(self.tokens, index) {
                    Some(Token::Open(_)) => self.pairs[index] + 1,
                    _ => index + 1,
                };
            }
            index += 1;
        }
        Some(variants)
    }
}

#[cfg(test)]
mod tests {
    use super::{Alias, KindEnum, ModDecl, PathRef, ScanError, scan};

    fn kind_enums(source: &str) -> Vec<KindEnum> {
        scan(source).unwrap().kind_enums
    }

    fn test_paths(source: &str) -> Vec<(String, String)> {
        scan(source)
            .unwrap()
            .paths
            .into_iter()
            .filter(|path| path.in_test)
            .map(|PathRef { head, tail, .. }| (head, tail))
            .collect()
    }

    fn pair(head: &str, tail: &str) -> (String, String) {
        (head.to_owned(), tail.to_owned())
    }

    #[test]
    fn extracts_variants_past_doc_comments_attributes_payloads_and_trailing_commas() {
        let source = r#"
            /// Error kinds.
            #[derive(Debug, Clone, Copy)]
            #[non_exhaustive]
            pub enum Kind {
                /// The OS RNG failed.
                #[doc = "with an attribute, too"]
                Entropy,
                CertBuild { reason: Vec<(u8, u8)> },
                /* block */ Tuple(u8, [u8; 2]),
                Discriminant = 1 << 2,
                #[cfg(feature = "lab")]
                Lab,
            }
        "#;
        assert_eq!(
            kind_enums(source),
            [KindEnum {
                name: "Kind".to_owned(),
                variants: ["Entropy", "CertBuild", "Tuple", "Discriminant", "Lab"]
                    .map(str::to_owned)
                    .to_vec(),
                line: 5,
                in_test: false,
            }]
        );
    }

    #[test]
    fn only_public_enums_named_kind_count() {
        let source = "
            pub enum StoreErrorKind { Lock }
            enum Kind { Private }
            pub(crate) enum Kind { Crate }
            pub enum Kinds { NotAKind }
            pub enum Kind<T> where T: Copy { Generic(T) }
            pub enum EmptyKind {}
        ";
        let found: Vec<_> = kind_enums(source)
            .into_iter()
            .map(|kind| (kind.name, kind.variants))
            .collect();
        assert_eq!(
            found,
            [
                ("StoreErrorKind".to_owned(), vec!["Lock".to_owned()]),
                ("Kind".to_owned(), vec!["Generic".to_owned()]),
                ("EmptyKind".to_owned(), vec![]),
            ]
        );
    }

    #[test]
    fn malformed_kind_enums_are_errors_not_empty() {
        assert!(matches!(
            scan("pub enum Kind;"),
            Err(ScanError::MalformedEnum { line: 1, .. })
        ));
        assert!(matches!(
            scan("pub enum Kind { 1 }"),
            Err(ScanError::MalformedEnum { line: 1, .. })
        ));
    }

    #[test]
    fn test_regions_come_from_cfg_test_items_only() {
        let source = r#"
            fn production() { let _ = Kind::Prod; }
            #[cfg(test)]
            mod tests {
                #[test]
                fn t() { assert_eq!(e.kind(), Kind::InMod); }
            }
            #[cfg(all(test, feature = "x"))]
            fn helper<A, B>() { Kind::InAll; }
            #[cfg(any(test, feature = "x"))]
            fn maybe() { Kind::InAny; }
            #[cfg(not(test))]
            fn not_test() { Kind::InNot; }
            #[cfg_attr(test, derive(Debug))]
            struct S { a: Kind::InCfgAttr }
            // Kind::InComment
            const C: &str = "Kind::InString";
        "#;
        assert_eq!(
            test_paths(source),
            [pair("Kind", "InMod"), pair("Kind", "InAll")]
        );
    }

    #[test]
    fn inner_cfg_test_marks_the_enclosing_module_or_the_file() {
        let module = "mod m { #![cfg(test)] fn f() { Kind::A; } } fn g() { Kind::B; }";
        assert_eq!(test_paths(module), [pair("Kind", "A")]);

        let file = scan("#![cfg(test)]\nuse x::Kind;\nfn f() { Kind::C; }").unwrap();
        assert!(file.file_is_test);
        assert!(file.paths.iter().all(|path| path.in_test));
    }

    #[test]
    fn test_only_kind_enums_are_flagged() {
        let enums = kind_enums("#[cfg(test)] mod t { pub enum Kind { Fixture } }");
        assert!(enums[0].in_test);
    }

    #[test]
    fn records_aliases_and_module_declarations() {
        let source = r#"
            pub use error::Kind as ModelKind;
            #[cfg(test)]
            mod tests;
            pub mod error;
            mod outer {
                #[path = "custom.rs"]
                pub(crate) mod inner;
            }
            #[cfg(test)]
            #[path = "t.rs"]
            mod more;
        "#;
        let file = scan(source).unwrap();
        assert!(file.aliases.contains(&Alias {
            original: "Kind".to_owned(),
            alias: "ModelKind".to_owned(),
        }));
        let decl = |inline: &[&str], name: &str, path: Option<&str>, in_test, line| ModDecl {
            inline_path: inline.iter().map(|s| (*s).to_owned()).collect(),
            name: name.to_owned(),
            path_attr: path.map(str::to_owned),
            in_test,
            line,
        };
        assert_eq!(
            file.mod_decls,
            [
                decl(&[], "tests", None, true, 4),
                decl(&[], "error", None, false, 5),
                decl(&["outer"], "inner", Some("custom.rs"), false, 8),
                decl(&[], "more", Some("t.rs"), true, 12),
            ]
        );
    }

    #[test]
    fn unbalanced_delimiters_are_errors() {
        assert_eq!(
            scan("fn f() { ]"),
            Err(ScanError::UnmatchedClose { line: 1 })
        );
        assert_eq!(scan("fn f() {\n"), Err(ScanError::Unclosed { line: 1 }));
    }
}
