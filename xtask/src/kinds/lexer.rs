// SPDX-License-Identifier: GPL-3.0-or-later

//! A small Rust tokenizer: just enough to find items, attributes and paths.
//!
//! Comments (including doc comments) produce no tokens, and literal contents
//! are opaque, so text such as `"Kind::A"` or `// Kind::A` can never count as
//! a reference.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delim {
    Paren,
    Bracket,
    Brace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// An identifier or keyword; a raw identifier keeps its `r#` prefix.
    Ident(String),
    /// The source text between the delimiters of a string literal (escapes unprocessed).
    Str(String),
    /// A numeric, character or byte literal.
    Literal,
    /// A lifetime or loop label.
    Lifetime,
    /// `::`
    PathSep,
    Pound,
    Bang,
    Comma,
    Semi,
    Eq,
    Open(Delim),
    Close(Delim),
    /// Any other punctuation character.
    Punct(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spanned {
    pub(crate) token: Token,
    pub(crate) line: u32,
}

impl Spanned {
    pub(crate) fn is_ident(&self, name: &str) -> bool {
        matches!(&self.token, Token::Ident(ident) if ident == name)
    }

    pub(crate) fn ident(&self) -> Option<&str> {
        match &self.token {
            Token::Ident(ident) => Some(ident),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unterminated {
    BlockComment,
    String,
    RawString,
    CharLiteral,
}

impl fmt::Display for Unterminated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BlockComment => "block comment",
            Self::String => "string literal",
            Self::RawString => "raw string literal",
            Self::CharLiteral => "character literal",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unterminated {what} starting on line {line}")]
pub(crate) struct LexError {
    pub(crate) what: Unterminated,
    pub(crate) line: u32,
}

pub(crate) fn tokenize(source: &str) -> Result<Vec<Spanned>, LexError> {
    let mut lexer = Lexer {
        chars: source.chars().collect(),
        pos: 0,
        line: 1,
        tokens: Vec::new(),
    };
    lexer.run()?;
    Ok(lexer.tokens)
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: u32,
    tokens: Vec<Spanned>,
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

impl Lexer {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    /// Consumes one character that must exist, or reports `what` as unterminated.
    fn expect_char(&mut self, what: Unterminated, line: u32) -> Result<char, LexError> {
        self.bump().ok_or(LexError { what, line })
    }

    fn push(&mut self, token: Token, line: u32) {
        self.tokens.push(Spanned { token, line });
    }

    fn run(&mut self) -> Result<(), LexError> {
        while let Some(c) = self.peek(0) {
            let line = self.line;
            match (c, self.peek(1)) {
                (c, _) if c.is_whitespace() => {
                    self.bump();
                }
                ('/', Some('/')) => self.skip_line_comment(),
                ('/', Some('*')) => self.skip_block_comment(line)?,
                ('"', _) => {
                    self.bump();
                    let text = self.quoted(line)?;
                    self.push(Token::Str(text), line);
                }
                ('\'', _) => self.quote_or_lifetime(line)?,
                (':', Some(':')) => {
                    self.pos += 2;
                    self.push(Token::PathSep, line);
                }
                (c, _) if c.is_ascii_digit() => self.number(line),
                (c, _) if is_ident_start(c) => self.word(line)?,
                (c, _) => {
                    self.bump();
                    self.push(punct(c), line);
                }
            }
        }
        Ok(())
    }

    fn skip_line_comment(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.pos += 1;
        }
    }

    fn skip_block_comment(&mut self, line: u32) -> Result<(), LexError> {
        self.pos += 2;
        let mut depth = 1_usize;
        while depth > 0 {
            match (self.peek(0), self.peek(1)) {
                (Some('/'), Some('*')) => {
                    self.pos += 2;
                    depth += 1;
                }
                (Some('*'), Some('/')) => {
                    self.pos += 2;
                    depth -= 1;
                }
                (Some(_), _) => {
                    self.bump();
                }
                (None, _) => {
                    return Err(LexError {
                        what: Unterminated::BlockComment,
                        line,
                    });
                }
            }
        }
        Ok(())
    }

    /// The body of a `"…"` literal; the opening quote is already consumed.
    fn quoted(&mut self, line: u32) -> Result<String, LexError> {
        let mut text = String::new();
        loop {
            match self.expect_char(Unterminated::String, line)? {
                '"' => return Ok(text),
                '\\' => {
                    text.push('\\');
                    text.push(self.expect_char(Unterminated::String, line)?);
                }
                c => text.push(c),
            }
        }
    }

    /// The length of a raw-string prefix (`r`, `br`, `cr`) at the cursor, if
    /// it is followed by `#…#"`.
    fn raw_string_prefix(&self) -> Option<usize> {
        let prefix = match (self.peek(0), self.peek(1)) {
            (Some('r'), _) => 1,
            (Some('b' | 'c'), Some('r')) => 2,
            _ => return None,
        };
        let mut offset = prefix;
        while self.peek(offset) == Some('#') {
            offset += 1;
        }
        (self.peek(offset) == Some('"')).then_some(prefix)
    }

    /// A raw string after its prefix: `#…#"body"#…#`.
    fn raw_string(&mut self, line: u32) -> Result<String, LexError> {
        let mut hashes = 0_usize;
        while self.peek(0) == Some('#') {
            self.pos += 1;
            hashes += 1;
        }
        self.expect_char(Unterminated::RawString, line)?;
        let mut text = String::new();
        loop {
            let c = self.expect_char(Unterminated::RawString, line)?;
            if c == '"' && (0..hashes).all(|offset| self.peek(offset) == Some('#')) {
                self.pos += hashes;
                return Ok(text);
            }
            text.push(c);
        }
    }

    /// `'x'`, `'\n'`, `'\u{1F600}'` are literals; `'a` and `'static` are lifetimes.
    fn quote_or_lifetime(&mut self, line: u32) -> Result<(), LexError> {
        match (self.peek(1), self.peek(2)) {
            (Some('\\'), _) => {
                self.pos += 2;
                self.expect_char(Unterminated::CharLiteral, line)?;
                while self.expect_char(Unterminated::CharLiteral, line)? != '\'' {}
                self.push(Token::Literal, line);
            }
            (Some(_), Some('\'')) => {
                for _ in 0..3 {
                    self.bump();
                }
                self.push(Token::Literal, line);
            }
            _ => {
                self.bump();
                while self.peek(0).is_some_and(is_ident_continue) {
                    self.pos += 1;
                }
                self.push(Token::Lifetime, line);
            }
        }
        Ok(())
    }

    fn number(&mut self, line: u32) {
        while let Some(c) = self.peek(0) {
            let fraction = c == '.' && self.peek(1).is_some_and(|next| next.is_ascii_digit());
            if !(c.is_ascii_alphanumeric() || c == '_' || fraction) {
                break;
            }
            self.pos += 1;
        }
        self.push(Token::Literal, line);
    }

    /// An identifier, a raw identifier, or a prefixed literal (`b"…"`, `r#"…"#`, `b'x'`, `c"…"`).
    fn word(&mut self, line: u32) -> Result<(), LexError> {
        if let Some(prefix) = self.raw_string_prefix() {
            self.pos += prefix;
            let text = self.raw_string(line)?;
            self.push(Token::Str(text), line);
            return Ok(());
        }
        match (self.peek(0), self.peek(1)) {
            (Some('b' | 'c'), Some('"')) => {
                self.pos += 2;
                let text = self.quoted(line)?;
                self.push(Token::Str(text), line);
                return Ok(());
            }
            (Some('b'), Some('\'')) => {
                self.pos += 1;
                return self.quote_or_lifetime(line);
            }
            _ => {}
        }
        let mut name = String::new();
        if self.peek(0) == Some('r')
            && self.peek(1) == Some('#')
            && self.peek(2).is_some_and(is_ident_start)
        {
            name.push_str("r#");
            self.pos += 2;
        }
        while let Some(c) = self.peek(0).filter(|c| is_ident_continue(*c)) {
            name.push(c);
            self.pos += 1;
        }
        self.push(Token::Ident(name), line);
        Ok(())
    }
}

fn punct(c: char) -> Token {
    match c {
        '#' => Token::Pound,
        '!' => Token::Bang,
        ',' => Token::Comma,
        ';' => Token::Semi,
        '=' => Token::Eq,
        '(' => Token::Open(Delim::Paren),
        '[' => Token::Open(Delim::Bracket),
        '{' => Token::Open(Delim::Brace),
        ')' => Token::Close(Delim::Paren),
        ']' => Token::Close(Delim::Bracket),
        '}' => Token::Close(Delim::Brace),
        other => Token::Punct(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{Delim, LexError, Token, Unterminated, tokenize};

    fn tokens(source: &str) -> Vec<Token> {
        tokenize(source)
            .unwrap()
            .into_iter()
            .map(|spanned| spanned.token)
            .collect()
    }

    fn ident(name: &str) -> Token {
        Token::Ident(name.to_owned())
    }

    #[test]
    fn comments_including_doc_and_nested_block_comments_produce_no_tokens() {
        let source =
            "/// Kind::A\n//! Kind::B\n/* outer /* Kind::C */ still comment */ x // Kind::D";
        assert_eq!(tokens(source), [ident("x")]);
    }

    #[test]
    fn literal_contents_are_opaque() {
        let source = r####"a "Kind::A \" Kind::B" r#"Kind::"C""# b"Kind::D" br##"x"## c"e" 'x' '\'' b'\\' '\u{1F600}'"####;
        assert_eq!(
            tokens(source),
            [
                ident("a"),
                Token::Str(r#"Kind::A \" Kind::B"#.to_owned()),
                Token::Str(r#"Kind::"C""#.to_owned()),
                Token::Str("Kind::D".to_owned()),
                Token::Str("x".to_owned()),
                Token::Str("e".to_owned()),
                Token::Literal,
                Token::Literal,
                Token::Literal,
                Token::Literal,
            ]
        );
    }

    #[test]
    fn distinguishes_lifetimes_raw_identifiers_and_paths() {
        assert_eq!(
            tokens("fn f<'a>(x: &'a r#type) -> Kind::A { 'outer: loop {} }"),
            [
                ident("fn"),
                ident("f"),
                Token::Punct('<'),
                Token::Lifetime,
                Token::Punct('>'),
                Token::Open(Delim::Paren),
                ident("x"),
                Token::Punct(':'),
                Token::Punct('&'),
                Token::Lifetime,
                ident("r#type"),
                Token::Close(Delim::Paren),
                Token::Punct('-'),
                Token::Punct('>'),
                ident("Kind"),
                Token::PathSep,
                ident("A"),
                Token::Open(Delim::Brace),
                Token::Lifetime,
                Token::Punct(':'),
                ident("loop"),
                Token::Open(Delim::Brace),
                Token::Close(Delim::Brace),
                Token::Close(Delim::Brace),
            ]
        );
    }

    #[test]
    fn numbers_stop_at_ranges_and_method_calls() {
        assert_eq!(
            tokens("1.5 0..10 2.max"),
            [
                Token::Literal,
                Token::Literal,
                Token::Punct('.'),
                Token::Punct('.'),
                Token::Literal,
                Token::Literal,
                Token::Punct('.'),
                ident("max"),
            ]
        );
    }

    #[test]
    fn tracks_lines_across_multiline_literals_and_comments() {
        let spanned = tokenize("a\n/* x\n y */ \"p\nq\"\nb").unwrap();
        let lines: Vec<_> = spanned.iter().map(|s| s.line).collect();
        assert_eq!(lines, [1, 3, 5]);
    }

    #[test]
    fn reports_unterminated_constructs() {
        let cases = [
            ("x /* open", Unterminated::BlockComment, 1),
            ("x\n\"open", Unterminated::String, 2),
            ("r#\"open\"", Unterminated::RawString, 1),
            ("'\\", Unterminated::CharLiteral, 1),
        ];
        for (source, what, line) in cases {
            assert_eq!(tokenize(source), Err(LexError { what, line }), "{source}");
        }
    }
}
