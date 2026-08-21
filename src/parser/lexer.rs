use crate::ast::{HexToken, SourceLocation};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Keywords
    Rule,
    Meta,
    Strings,
    Condition,
    And,
    Or,
    Not,
    Of,
    Them,
    Any,
    All,
    None,
    True,
    False,
    Ascii,
    Wide,
    Nocase,

    // Identifiers
    Ident(String),
    StringIdent(String),      // $id
    StringCountIdent(String), // #id
    StringOffsetIdent(String),// @id

    // Literals
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    HexPattern(Vec<HexToken>),
    RegexPattern {
        pattern: String,
        nocase: bool,
    },

    // Operators & Punctuation
    OpenBrace,     // {
    CloseBrace,    // }
    OpenParen,     // (
    CloseParen,    // )
    Colon,         // :
    Equals,        // =
    Comma,         // ,
    Dot,           // .
    Eq,            // ==
    Neq,           // !=
    Lt,            // <
    Lte,           // <=
    Gt,            // >
    Gte,           // >=
    Plus,          // +
    Minus,         // -
    Star,          // *
    Slash,         // /

    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Rule => write!(f, "'rule'"),
            TokenKind::Meta => write!(f, "'meta'"),
            TokenKind::Strings => write!(f, "'strings'"),
            TokenKind::Condition => write!(f, "'condition'"),
            TokenKind::And => write!(f, "'and'"),
            TokenKind::Or => write!(f, "'or'"),
            TokenKind::Not => write!(f, "'not'"),
            TokenKind::Of => write!(f, "'of'"),
            TokenKind::Them => write!(f, "'them'"),
            TokenKind::Any => write!(f, "'any'"),
            TokenKind::All => write!(f, "'all'"),
            TokenKind::None => write!(f, "'none'"),
            TokenKind::True => write!(f, "'true'"),
            TokenKind::False => write!(f, "'false'"),
            TokenKind::Ascii => write!(f, "'ascii'"),
            TokenKind::Wide => write!(f, "'wide'"),
            TokenKind::Nocase => write!(f, "'nocase'"),
            TokenKind::Ident(s) => write!(f, "identifier '{}'", s),
            TokenKind::StringIdent(s) => write!(f, "string identifier '{}'", s),
            TokenKind::StringCountIdent(s) => write!(f, "count identifier '{}'", s),
            TokenKind::StringOffsetIdent(s) => write!(f, "offset identifier '{}'", s),
            TokenKind::StringLit(s) => write!(f, "\"{}\"", s),
            TokenKind::IntLit(i) => write!(f, "{}", i),
            TokenKind::FloatLit(fl) => write!(f, "{}", fl),
            TokenKind::HexPattern(_) => write!(f, "hex pattern {{ ... }}"),
            TokenKind::RegexPattern { pattern, nocase } => {
                write!(f, "/{}/{}", pattern, if *nocase { "i" } else { "" })
            }
            TokenKind::OpenBrace => write!(f, "'{{'"),
            TokenKind::CloseBrace => write!(f, "'}}'"),
            TokenKind::OpenParen => write!(f, "'('"),
            TokenKind::CloseParen => write!(f, "')'"),
            TokenKind::Colon => write!(f, "':'"),
            TokenKind::Equals => write!(f, "'='"),
            TokenKind::Comma => write!(f, "','"),
            TokenKind::Dot => write!(f, "'.'"),
            TokenKind::Eq => write!(f, "'=='"),
            TokenKind::Neq => write!(f, "'!='"),
            TokenKind::Lt => write!(f, "'<'"),
            TokenKind::Lte => write!(f, "'<='"),
            TokenKind::Gt => write!(f, "'>'"),
            TokenKind::Gte => write!(f, "'>='"),
            TokenKind::Plus => write!(f, "'+'"),
            TokenKind::Minus => write!(f, "'-'"),
            TokenKind::Star => write!(f, "'*'"),
            TokenKind::Slash => write!(f, "'/'"),
            TokenKind::Eof => write!(f, "<EOF>"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub location: SourceLocation,
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("Lexer error at {location}: {message}")]
pub struct LexError {
    pub location: SourceLocation,
    pub message: String,
}

pub struct Lexer {
    chars: Vec<(usize, char)>,
    cursor: usize,
    line: usize,
    column: usize,
    prev_token_kind: Option<TokenKind>,
}

impl Lexer {
    pub fn new(input: &str) -> Self {
        let chars: Vec<(usize, char)> = input.char_indices().collect();
        Self {
            chars,
            cursor: 0,
            line: 1,
            column: 1,
            prev_token_kind: None,
        }
    }

    fn current_loc(&self) -> SourceLocation {
        SourceLocation {
            line: self.line,
            column: self.column,
        }
    }

    fn peek(&self) -> Option<char> {
        if self.cursor < self.chars.len() {
            Some(self.chars[self.cursor].1)
        } else {
            None
        }
    }

    fn peek_ahead(&self, n: usize) -> Option<char> {
        if self.cursor + n < self.chars.len() {
            Some(self.chars[self.cursor + n].1)
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<char> {
        if self.cursor < self.chars.len() {
            let ch = self.chars[self.cursor].1;
            self.cursor += 1;
            if ch == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            Some(ch)
        } else {
            None
        }
    }

    fn skip_whitespace_and_comments(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r' | '\n') => {
                    self.advance();
                }
                Some('/') => {
                    if self.peek_ahead(1) == Some('/') {
                        // Single-line comment
                        self.advance(); // /
                        self.advance(); // /
                        while let Some(ch) = self.peek() {
                            if ch == '\n' {
                                break;
                            }
                            self.advance();
                        }
                    } else if self.peek_ahead(1) == Some('*') {
                        // Multi-line comment
                        let start_loc = self.current_loc();
                        self.advance(); // /
                        self.advance(); // *
                        let mut closed = false;
                        while let Some(ch) = self.peek() {
                            if ch == '*' && self.peek_ahead(1) == Some('/') {
                                self.advance(); // *
                                self.advance(); // /
                                closed = true;
                                break;
                            }
                            self.advance();
                        }
                        if !closed {
                            return Err(LexError {
                                location: start_loc,
                                message: "Unterminated multi-line comment".to_string(),
                            });
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    pub fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_whitespace_and_comments()?;
        let loc = self.current_loc();

        let ch = match self.peek() {
            Some(c) => c,
            None => {
                return Ok(Token {
                    kind: TokenKind::Eof,
                    location: loc,
                })
            }
        };

        // Hex pattern: if previous token was '=' and next is '{'
        if ch == '{' && matches!(self.prev_token_kind, Some(TokenKind::Equals)) {
            let hex_token = self.lex_hex_pattern()?;
            self.prev_token_kind = Some(hex_token.kind.clone());
            return Ok(hex_token);
        }

        // Regex pattern: if '/' occurs after '=', '(', ',', or boolean keywords
        if ch == '/' && self.is_regex_context() {
            let regex_token = self.lex_regex()?;
            self.prev_token_kind = Some(regex_token.kind.clone());
            return Ok(regex_token);
        }

        let token_kind = match ch {
            '{' => {
                self.advance();
                TokenKind::OpenBrace
            }
            '}' => {
                self.advance();
                TokenKind::CloseBrace
            }
            '(' => {
                self.advance();
                TokenKind::OpenParen
            }
            ')' => {
                self.advance();
                TokenKind::CloseParen
            }
            ':' => {
                self.advance();
                TokenKind::Colon
            }
            ',' => {
                self.advance();
                TokenKind::Comma
            }
            '.' => {
                self.advance();
                TokenKind::Dot
            }
            '+' => {
                self.advance();
                TokenKind::Plus
            }
            '-' => {
                self.advance();
                TokenKind::Minus
            }
            '*' => {
                self.advance();
                TokenKind::Star
            }
            '/' => {
                self.advance();
                TokenKind::Slash
            }
            '=' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    TokenKind::Eq
                } else {
                    TokenKind::Equals
                }
            }
            '!' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    TokenKind::Neq
                } else {
                    return Err(LexError {
                        location: loc,
                        message: "Unexpected '!'. Did you mean '!=' or 'not'?".to_string(),
                    });
                }
            }
            '<' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    TokenKind::Lte
                } else {
                    TokenKind::Lt
                }
            }
            '>' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    TokenKind::Gte
                } else {
                    TokenKind::Gt
                }
            }
            '"' => self.lex_string_literal()?,
            '$' => self.lex_prefixed_ident(TokenKind::StringIdent)?,
            '#' => self.lex_prefixed_ident(TokenKind::StringCountIdent)?,
            '@' => self.lex_prefixed_ident(TokenKind::StringOffsetIdent)?,
            '0'..='9' => self.lex_number()?,
            'a'..='z' | 'A'..='Z' | '_' => self.lex_ident_or_keyword()?,
            _ => {
                return Err(LexError {
                    location: loc,
                    message: format!("Unexpected character: '{}'", ch),
                });
            }
        };

        self.prev_token_kind = Some(token_kind.clone());
        Ok(Token {
            kind: token_kind,
            location: loc,
        })
    }

    fn is_regex_context(&self) -> bool {
        match &self.prev_token_kind {
            Some(
                TokenKind::Equals
                | TokenKind::OpenParen
                | TokenKind::Comma
                | TokenKind::And
                | TokenKind::Or
                | TokenKind::Not,
            ) => true,
            _ => false,
        }
    }

    fn lex_prefixed_ident<F>(&mut self, constructor: F) -> Result<TokenKind, LexError>
    where
        F: FnOnce(String) -> TokenKind,
    {
        let prefix = self.advance().unwrap();
        let mut name = String::new();
        name.push(prefix);

        if self.peek() == Some('*') {
            name.push(self.advance().unwrap());
            return Ok(constructor(name));
        }

        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '*' {
                name.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        if name.len() == 1 {
            return Err(LexError {
                location: self.current_loc(),
                message: format!("Identifier expected after '{}'", prefix),
            });
        }

        Ok(constructor(name))
    }

    fn lex_ident_or_keyword(&mut self) -> Result<TokenKind, LexError> {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                s.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        let kind = match s.as_str() {
            "rule" => TokenKind::Rule,
            "meta" => TokenKind::Meta,
            "strings" => TokenKind::Strings,
            "condition" => TokenKind::Condition,
            "and" => TokenKind::And,
            "or" => TokenKind::Or,
            "not" => TokenKind::Not,
            "of" => TokenKind::Of,
            "them" => TokenKind::Them,
            "any" => TokenKind::Any,
            "all" => TokenKind::All,
            "none" => TokenKind::None,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "ascii" => TokenKind::Ascii,
            "wide" => TokenKind::Wide,
            "nocase" => TokenKind::Nocase,
            _ => TokenKind::Ident(s),
        };

        Ok(kind)
    }

    fn lex_number(&mut self) -> Result<TokenKind, LexError> {
        let loc = self.current_loc();
        let mut s = String::new();

        // Check for hex: 0x...
        if self.peek() == Some('0') && (self.peek_ahead(1) == Some('x') || self.peek_ahead(1) == Some('X')) {
            s.push(self.advance().unwrap()); // 0
            s.push(self.advance().unwrap()); // x
            while let Some(ch) = self.peek() {
                if ch.is_ascii_hexdigit() {
                    s.push(self.advance().unwrap());
                } else {
                    break;
                }
            }
            let val = i64::from_str_radix(&s[2..], 16).map_err(|e| LexError {
                location: loc,
                message: format!("Invalid hex integer literal: {}", e),
            })?;
            return Ok(TokenKind::IntLit(val));
        }

        let mut is_float = false;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                s.push(self.advance().unwrap());
            } else if ch == '.' && !is_float && self.peek_ahead(1).map_or(false, |c| c.is_ascii_digit()) {
                is_float = true;
                s.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        // Check for KB, MB, GB suffixes for integer sizes
        let mut multiplier: i64 = 1;
        if !is_float {
            if let Some(ch) = self.peek() {
                if ch == 'K' && self.peek_ahead(1) == Some('B') {
                    self.advance();
                    self.advance();
                    multiplier = 1024;
                } else if ch == 'M' && self.peek_ahead(1) == Some('B') {
                    self.advance();
                    self.advance();
                    multiplier = 1024 * 1024;
                } else if ch == 'G' && self.peek_ahead(1) == Some('B') {
                    self.advance();
                    self.advance();
                    multiplier = 1024 * 1024 * 1024;
                }
            }
        }

        if is_float {
            let val = s.parse::<f64>().map_err(|e| LexError {
                location: loc,
                message: format!("Invalid float literal: {}", e),
            })?;
            Ok(TokenKind::FloatLit(val))
        } else {
            let val = s.parse::<i64>().map_err(|e| LexError {
                location: loc,
                message: format!("Invalid integer literal: {}", e),
            })?;
            Ok(TokenKind::IntLit(val * multiplier))
        }
    }

    fn lex_string_literal(&mut self) -> Result<TokenKind, LexError> {
        let loc = self.current_loc();
        self.advance(); // consume opening "
        let mut s = String::new();

        while let Some(ch) = self.peek() {
            if ch == '"' {
                self.advance();
                return Ok(TokenKind::StringLit(s));
            } else if ch == '\\' {
                self.advance();
                match self.advance() {
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some('x') => {
                        let mut hex_str = String::new();
                        for _ in 0..2 {
                            if let Some(h) = self.advance() {
                                if h.is_ascii_hexdigit() {
                                    hex_str.push(h);
                                } else {
                                    return Err(LexError {
                                        location: self.current_loc(),
                                        message: "Invalid hex escape in string".to_string(),
                                    });
                                }
                            }
                        }
                        let byte_val = u8::from_str_radix(&hex_str, 16).map_err(|e| LexError {
                            location: self.current_loc(),
                            message: format!("Invalid hex escape: {}", e),
                        })?;
                        s.push(byte_val as char);
                    }
                    Some(other) => s.push(other),
                    None => {
                        return Err(LexError {
                            location: loc,
                            message: "Unterminated escape sequence in string literal".to_string(),
                        })
                    }
                }
            } else {
                s.push(self.advance().unwrap());
            }
        }

        Err(LexError {
            location: loc,
            message: "Unterminated string literal".to_string(),
        })
    }

    fn lex_hex_pattern(&mut self) -> Result<Token, LexError> {
        let loc = self.current_loc();
        self.advance(); // consume '{'
        let mut tokens = Vec::new();

        loop {
            self.skip_whitespace_and_comments()?;
            let ch = match self.peek() {
                Some(c) => c,
                None => {
                    return Err(LexError {
                        location: loc,
                        message: "Unterminated hex byte pattern, missing '}'".to_string(),
                    })
                }
            };

            if ch == '}' {
                self.advance();
                break;
            }

            // Read high nibble char
            let high_char = self.advance().unwrap();
            self.skip_whitespace_and_comments()?;
            let low_char = match self.advance() {
                Some(c) => c,
                None => {
                    return Err(LexError {
                        location: self.current_loc(),
                        message: "Incomplete hex byte, expected second nibble".to_string(),
                    })
                }
            };

            let token = match (high_char, low_char) {
                ('?', '?') => HexToken::Wildcard,
                ('?', low) if low.is_ascii_hexdigit() => {
                    let val = low.to_digit(16).unwrap() as u8;
                    HexToken::LowNibble(val)
                }
                (high, '?') if high.is_ascii_hexdigit() => {
                    let val = high.to_digit(16).unwrap() as u8;
                    HexToken::HighNibble(val)
                }
                (high, low) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                    let high_val = high.to_digit(16).unwrap() as u8;
                    let low_val = low.to_digit(16).unwrap() as u8;
                    HexToken::Exact((high_val << 4) | low_val)
                }
                _ => {
                    return Err(LexError {
                        location: self.current_loc(),
                        message: format!("Invalid hex byte: '{}{}'", high_char, low_char),
                    })
                }
            };
            tokens.push(token);
        }

        Ok(Token {
            kind: TokenKind::HexPattern(tokens),
            location: loc,
        })
    }

    fn lex_regex(&mut self) -> Result<Token, LexError> {
        let loc = self.current_loc();
        self.advance(); // consume opening '/'
        let mut pattern = String::new();
        let mut escaped = false;

        loop {
            let ch = match self.advance() {
                Some(c) => c,
                None => {
                    return Err(LexError {
                        location: loc,
                        message: "Unterminated regular expression, missing closing '/'".to_string(),
                    })
                }
            };

            if escaped {
                pattern.push(ch);
                escaped = false;
            } else if ch == '\\' {
                pattern.push('\\');
                escaped = true;
            } else if ch == '/' {
                break;
            } else {
                pattern.push(ch);
            }
        }

        // Check flags: 'i' for nocase
        let mut nocase = false;
        if self.peek() == Some('i') {
            self.advance();
            nocase = true;
        }

        Ok(Token {
            kind: TokenKind::RegexPattern { pattern, nocase },
            location: loc,
        })
    }

    pub fn tokenize_all(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = tok.kind == TokenKind::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }
}
