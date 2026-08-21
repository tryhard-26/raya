use crate::ast::*;
use crate::parser::lexer::{LexError, Lexer, Token, TokenKind};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("Parse error at {location}: {message}")]
pub struct ParseError {
    pub location: SourceLocation,
    pub message: String,
}

impl From<LexError> for ParseError {
    fn from(err: LexError) -> Self {
        ParseError {
            location: err.location,
            message: err.message,
        }
    }
}

pub struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    pub fn from_source(source: &str) -> Result<Self, ParseError> {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize_all()?;
        Ok(Self::new(tokens))
    }

    fn current(&self) -> &Token {
        if self.cursor < self.tokens.len() {
            &self.tokens[self.cursor]
        } else {
            &self.tokens[self.tokens.len() - 1]
        }
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.current().kind
    }

    fn current_loc(&self) -> SourceLocation {
        self.current().location
    }

    fn advance(&mut self) -> &Token {
        let prev = self.cursor;
        if self.cursor < self.tokens.len() - 1 {
            self.cursor += 1;
        }
        &self.tokens[prev]
    }

    fn check(&self, kind: &TokenKind) -> bool {
        match (self.peek_kind(), kind) {
            (TokenKind::Ident(a), TokenKind::Ident(b)) => a == b,
            (TokenKind::StringIdent(a), TokenKind::StringIdent(b)) => a == b,
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        }
    }

    fn match_token(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: TokenKind, msg: &str) -> Result<Token, ParseError> {
        if self.check(&kind) {
            Ok(self.advance().clone())
        } else {
            Err(ParseError {
                location: self.current_loc(),
                message: format!("Expected {}, found {}: {}", kind, self.peek_kind(), msg),
            })
        }
    }

    pub fn parse_rules(&mut self) -> Result<Vec<Rule>, ParseError> {
        let mut rules = Vec::new();
        while !self.check(&TokenKind::Eof) {
            rules.push(self.parse_rule()?);
        }
        Ok(rules)
    }

    pub fn parse_rule(&mut self) -> Result<Rule, ParseError> {
        let start_tok = self.expect(TokenKind::Rule, "rule definition must start with 'rule'")?;
        let loc = start_tok.location;

        let name = match self.advance().kind.clone() {
            TokenKind::Ident(s) => s,
            other => {
                return Err(ParseError {
                    location: self.current_loc(),
                    message: format!("Expected rule name identifier, found {}", other),
                })
            }
        };

        // Optional tags: rule name : tag1 tag2 {
        let mut tags = Vec::new();
        if self.match_token(&TokenKind::Colon) {
            while let TokenKind::Ident(tag) = self.peek_kind() {
                tags.push(tag.clone());
                self.advance();
            }
        }

        self.expect(TokenKind::OpenBrace, "expected '{' after rule header")?;

        let mut meta = HashMap::new();
        let mut strings = Vec::new();
        let mut condition: Option<Expr> = None;

        while !self.check(&TokenKind::CloseBrace) && !self.check(&TokenKind::Eof) {
            match self.peek_kind() {
                TokenKind::Meta => {
                    self.advance();
                    self.expect(TokenKind::Colon, "expected ':' after 'meta'")?;
                    while self.is_ident_token() {
                        let key = self.parse_ident_name()?;
                        self.expect(TokenKind::Equals, "expected '=' in meta entry")?;
                        let val = self.parse_meta_value()?;
                        meta.insert(key, val);
                    }
                }
                TokenKind::Strings => {
                    self.advance();
                    self.expect(TokenKind::Colon, "expected ':' after 'strings'")?;
                    while matches!(self.peek_kind(), TokenKind::StringIdent(_)) {
                        let str_def = self.parse_string_definition()?;
                        strings.push(str_def);
                    }
                }
                TokenKind::Condition => {
                    self.advance();
                    self.expect(TokenKind::Colon, "expected ':' after 'condition'")?;
                    condition = Some(self.parse_expression()?);
                }
                other => {
                    return Err(ParseError {
                        location: self.current_loc(),
                        message: format!("Unexpected token in rule body: {}", other),
                    })
                }
            }
        }

        self.expect(TokenKind::CloseBrace, "expected '}' closing rule body")?;

        let cond = condition.ok_or_else(|| ParseError {
            location: loc,
            message: format!("Rule '{}' is missing required 'condition:' section", name),
        })?;

        Ok(Rule {
            name,
            tags,
            meta,
            strings,
            condition: cond,
            location: loc,
        })
    }

    fn is_ident_token(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Ident(_))
    }

    fn parse_ident_name(&mut self) -> Result<String, ParseError> {
        match self.advance().kind.clone() {
            TokenKind::Ident(s) => Ok(s),
            other => Err(ParseError {
                location: self.current_loc(),
                message: format!("Expected identifier, found {}", other),
            }),
        }
    }

    fn parse_meta_value(&mut self) -> Result<MetaValue, ParseError> {
        let tok = self.advance().clone();
        match tok.kind {
            TokenKind::StringLit(s) => Ok(MetaValue::String(s)),
            TokenKind::IntLit(i) => Ok(MetaValue::Integer(i)),
            TokenKind::FloatLit(fl) => Ok(MetaValue::Float(fl)),
            TokenKind::True => Ok(MetaValue::Boolean(true)),
            TokenKind::False => Ok(MetaValue::Boolean(false)),
            other => Err(ParseError {
                location: tok.location,
                message: format!("Expected meta value (string, int, float, bool), found {}", other),
            }),
        }
    }

    fn parse_string_definition(&mut self) -> Result<StringDefinition, ParseError> {
        let id_tok = self.advance().clone();
        let id = match id_tok.kind {
            TokenKind::StringIdent(s) => s,
            other => {
                return Err(ParseError {
                    location: id_tok.location,
                    message: format!("Expected string identifier (e.g. $a), found {}", other),
                })
            }
        };

        self.expect(TokenKind::Equals, "expected '=' after string identifier")?;

        let val_tok = self.advance().clone();
        let pattern = match val_tok.kind {
            TokenKind::StringLit(s) => {
                let mut ascii = false;
                let mut wide = false;
                let mut nocase = false;

                while matches!(
                    self.peek_kind(),
                    TokenKind::Ascii | TokenKind::Wide | TokenKind::Nocase
                ) {
                    match self.advance().kind {
                        TokenKind::Ascii => ascii = true,
                        TokenKind::Wide => wide = true,
                        TokenKind::Nocase => nocase = true,
                        _ => unreachable!(),
                    }
                }

                // If neither ascii nor wide is explicitly specified, default to ascii
                if !ascii && !wide {
                    ascii = true;
                }

                StringPattern::Literal {
                    bytes: s.into_bytes(),
                    ascii,
                    wide,
                    nocase,
                }
            }
            TokenKind::HexPattern(tokens) => StringPattern::Hex { tokens },
            TokenKind::RegexPattern { pattern, nocase } => StringPattern::Regex { pattern, nocase },
            other => {
                return Err(ParseError {
                    location: val_tok.location,
                    message: format!(
                        "Expected string literal, hex pattern, or regex, found {}",
                        other
                    ),
                })
            }
        };

        Ok(StringDefinition { id, pattern })
    }

    pub fn parse_expression(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_or()
    }

    fn parse_expr_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_expr_and()?;
        while self.match_token(&TokenKind::Or) {
            let right = self.parse_expr_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_expr_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_expr_comparison()?;
        while self.match_token(&TokenKind::And) {
            let right = self.parse_expr_comparison()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_expr_comparison(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_expr_additive()?;
        loop {
            let op = if self.match_token(&TokenKind::Eq) {
                BinaryOperator::Eq
            } else if self.match_token(&TokenKind::Neq) {
                BinaryOperator::Neq
            } else if self.match_token(&TokenKind::Lt) {
                BinaryOperator::Lt
            } else if self.match_token(&TokenKind::Lte) {
                BinaryOperator::Lte
            } else if self.match_token(&TokenKind::Gt) {
                BinaryOperator::Gt
            } else if self.match_token(&TokenKind::Gte) {
                BinaryOperator::Gte
            } else {
                break;
            };

            let right = self.parse_expr_additive()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_expr_additive(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_expr_multiplicative()?;
        loop {
            let op = if self.match_token(&TokenKind::Plus) {
                BinaryOperator::Add
            } else if self.match_token(&TokenKind::Minus) {
                BinaryOperator::Sub
            } else {
                break;
            };

            let right = self.parse_expr_multiplicative()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_expr_multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_expr_unary()?;
        loop {
            let op = if self.match_token(&TokenKind::Star) {
                BinaryOperator::Mul
            } else if self.match_token(&TokenKind::Slash) {
                BinaryOperator::Div
            } else {
                break;
            };

            let right = self.parse_expr_unary()?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_expr_unary(&mut self) -> Result<Expr, ParseError> {
        if self.match_token(&TokenKind::Not) {
            let expr = self.parse_expr_unary()?;
            return Ok(Expr::Not(Box::new(expr)));
        }
        if self.match_token(&TokenKind::Minus) {
            let expr = self.parse_expr_unary()?;
            return Ok(Expr::Binary {
                left: Box::new(Expr::Integer(0)),
                op: BinaryOperator::Sub,
                right: Box::new(expr),
            });
        }
        self.parse_expr_primary()
    }

    fn parse_expr_primary(&mut self) -> Result<Expr, ParseError> {
        let tok = self.current().clone();
        match tok.kind {
            TokenKind::True => {
                self.advance();
                Ok(Expr::Boolean(true))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Boolean(false))
            }
            TokenKind::IntLit(i) => {
                self.advance();
                // Check if this integer is followed by "of" -> CountOf
                if self.match_token(&TokenKind::Of) {
                    let set = self.parse_set_selector()?;
                    Ok(Expr::CountOf {
                        count: Box::new(Expr::Integer(i)),
                        set,
                    })
                } else {
                    Ok(Expr::Integer(i))
                }
            }
            TokenKind::FloatLit(fl) => {
                self.advance();
                Ok(Expr::Float(fl))
            }
            TokenKind::StringLit(s) => {
                self.advance();
                Ok(Expr::StringLit(s))
            }
            TokenKind::StringIdent(s) => {
                self.advance();
                Ok(Expr::StringRef(s))
            }
            TokenKind::StringCountIdent(s) => {
                self.advance();
                Ok(Expr::StringCount(s))
            }
            TokenKind::StringOffsetIdent(s) => {
                self.advance();
                Ok(Expr::StringOffset(s))
            }
            TokenKind::Any => {
                self.advance();
                self.expect(TokenKind::Of, "expected 'of' after 'any'")?;
                let set = self.parse_set_selector()?;
                Ok(Expr::AnyOf(set))
            }
            TokenKind::All => {
                self.advance();
                self.expect(TokenKind::Of, "expected 'of' after 'all'")?;
                let set = self.parse_set_selector()?;
                Ok(Expr::AllOf(set))
            }
            TokenKind::None => {
                self.advance();
                self.expect(TokenKind::Of, "expected 'of' after 'none'")?;
                let set = self.parse_set_selector()?;
                Ok(Expr::NoneOf(set))
            }
            TokenKind::OpenParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.expect(TokenKind::CloseParen, "expected ')' closing parenthesis")?;
                // If followed by 'of', it's (expr) of <set>
                if self.match_token(&TokenKind::Of) {
                    let set = self.parse_set_selector()?;
                    Ok(Expr::CountOf {
                        count: Box::new(expr),
                        set,
                    })
                } else {
                    Ok(expr)
                }
            }
            TokenKind::Ident(ref name) => {
                let id = name.clone();
                self.advance();
                self.parse_identifier_suffix(id)
            }
            _ => Err(ParseError {
                location: tok.location,
                message: format!("Unexpected token in expression: {}", tok.kind),
            }),
        }
    }

    fn parse_identifier_suffix(&mut self, id: String) -> Result<Expr, ParseError> {
        // Check for module/function or property access: id.prop or id.func(args)
        if self.match_token(&TokenKind::Dot) {
            let prop_name = self.parse_ident_name()?;

            // Check if function call: id.prop(...)
            if self.match_token(&TokenKind::OpenParen) {
                let mut args = Vec::new();
                if !self.check(&TokenKind::CloseParen) {
                    loop {
                        args.push(self.parse_expression()?);
                        if !self.match_token(&TokenKind::Comma) {
                            break;
                        }
                    }
                }
                self.expect(TokenKind::CloseParen, "expected ')' closing argument list")?;

                // Check for chaining: pe.section(".text").entropy
                let call = Expr::FunctionCall {
                    module: id,
                    function: prop_name,
                    args,
                };

                if self.match_token(&TokenKind::Dot) {
                    let sub_prop = self.parse_ident_name()?;
                    // Also check for sub-sub property or method call like .entropy
                    Ok(Expr::MemberAccess {
                        object: Box::new(call),
                        property: sub_prop,
                        sub_property: None,
                    })
                } else {
                    Ok(call)
                }
            } else {
                // Property access: pe.is_dll or pe.number_of_sections
                let mut sub_prop = None;
                if self.match_token(&TokenKind::Dot) {
                    sub_prop = Some(self.parse_ident_name()?);
                }

                Ok(Expr::MemberAccess {
                    object: Box::new(Expr::Variable(id)),
                    property: prop_name,
                    sub_property: sub_prop,
                })
            }
        } else if self.match_token(&TokenKind::OpenParen) {
            // Function call without module prefix: func(args)
            let mut args = Vec::new();
            if !self.check(&TokenKind::CloseParen) {
                loop {
                    args.push(self.parse_expression()?);
                    if !self.match_token(&TokenKind::Comma) {
                        break;
                    }
                }
            }
            self.expect(TokenKind::CloseParen, "expected ')' closing argument list")?;
            Ok(Expr::FunctionCall {
                module: String::new(),
                function: id,
                args,
            })
        } else {
            Ok(Expr::Variable(id))
        }
    }

    fn parse_set_selector(&mut self) -> Result<SetSelector, ParseError> {
        if self.match_token(&TokenKind::Them) {
            return Ok(SetSelector::Them);
        }

        if self.match_token(&TokenKind::OpenParen) {
            let mut list = Vec::new();
            if self.check(&TokenKind::CloseParen) {
                self.advance();
                return Ok(SetSelector::List(list));
            }

            while let TokenKind::StringIdent(ref s) = self.peek_kind() {
                let name = s.clone();
                self.advance();
                if name.ends_with('*') {
                    self.expect(TokenKind::CloseParen, "expected ')' closing wildcard selector")?;
                    return Ok(SetSelector::Wildcard(name));
                }
                list.push(name);
                if !self.match_token(&TokenKind::Comma) {
                    break;
                }
            }

            self.expect(TokenKind::CloseParen, "expected ')' closing set selector")?;
            Ok(SetSelector::List(list))
        } else if let TokenKind::StringIdent(ref s) = self.peek_kind() {
            let name = s.clone();
            self.advance();
            if name.ends_with('*') {
                Ok(SetSelector::Wildcard(name))
            } else {
                Ok(SetSelector::List(vec![name]))
            }
        } else {
            Err(ParseError {
                location: self.current_loc(),
                message: format!(
                    "Expected 'them', '($*)', or list of string identifiers, found {}",
                    self.peek_kind()
                ),
            })
        }
    }
}
