use crate::error::{FilterError, FilterErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Ident(String),
    Macro(String),
    String(String),
    Number(String),
    Bool(bool),
    Null,
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
    NotLike,
    AnyEq,
    AnyNe,
    AnyGt,
    AnyGte,
    AnyLt,
    AnyLte,
    AnyLike,
    AnyNotLike,
    And,
    Or,
    LParen,
    RParen,
    Comma,
    Eof,
}

pub(crate) struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    _input: &'a str,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            _input: input,
        }
    }

    pub(crate) fn tokenize(mut self) -> Result<Vec<Token>, FilterError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_ws();
            let Some(ch) = self.peek() else {
                tokens.push(Token::Eof);
                return Ok(tokens);
            };
            let token = match ch {
                '(' => {
                    self.bump();
                    Token::LParen
                }
                ')' => {
                    self.bump();
                    Token::RParen
                }
                ',' => {
                    self.bump();
                    Token::Comma
                }
                '=' => {
                    self.bump();
                    Token::Eq
                }
                '!' => {
                    let position = self.pos;
                    self.bump();
                    match self.peek() {
                        Some('=') => {
                            self.bump();
                            Token::Ne
                        }
                        Some('~') => {
                            self.bump();
                            Token::NotLike
                        }
                        _ => {
                            return Err(FilterError::at(
                                FilterErrorKind::UnexpectedCharacter,
                                position,
                                "unexpected character '!'",
                            ))
                        }
                    }
                }
                '>' => {
                    self.bump();
                    if self.peek() == Some('=') {
                        self.bump();
                        Token::Gte
                    } else {
                        Token::Gt
                    }
                }
                '<' => {
                    self.bump();
                    if self.peek() == Some('=') {
                        self.bump();
                        Token::Lte
                    } else {
                        Token::Lt
                    }
                }
                '~' => {
                    self.bump();
                    Token::Like
                }
                '?' => self.lex_any_operator()?,
                '&' => {
                    let position = self.pos;
                    self.bump();
                    if self.peek() == Some('&') {
                        self.bump();
                        Token::And
                    } else {
                        return Err(FilterError::at(
                            FilterErrorKind::UnexpectedCharacter,
                            position,
                            "unexpected character '&'",
                        ));
                    }
                }
                '|' => {
                    let position = self.pos;
                    self.bump();
                    if self.peek() == Some('|') {
                        self.bump();
                        Token::Or
                    } else {
                        return Err(FilterError::at(
                            FilterErrorKind::UnexpectedCharacter,
                            position,
                            "unexpected character '|'",
                        ));
                    }
                }
                '\'' | '"' => Token::String(self.lex_string(ch)?),
                '@' => Token::Macro(self.lex_macro()?),
                c if c.is_ascii_digit() || c == '-' => Token::Number(self.lex_number()?),
                c if is_ident_start(c) => self.lex_ident_or_keyword()?,
                other => {
                    return Err(FilterError::at(
                        FilterErrorKind::UnexpectedCharacter,
                        self.pos,
                        format!("unexpected character '{other}'"),
                    ))
                }
            };
            tokens.push(token);
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.bump();
        }
    }

    fn lex_any_operator(&mut self) -> Result<Token, FilterError> {
        let position = self.pos;
        self.bump();
        match self.peek() {
            Some('=') => {
                self.bump();
                Ok(Token::AnyEq)
            }
            Some('!') => {
                self.bump();
                match self.peek() {
                    Some('=') => {
                        self.bump();
                        Ok(Token::AnyNe)
                    }
                    Some('~') => {
                        self.bump();
                        Ok(Token::AnyNotLike)
                    }
                    _ => Err(FilterError::at(
                        FilterErrorKind::UnexpectedCharacter,
                        position,
                        "unexpected character after '?!'",
                    )),
                }
            }
            Some('>') => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    Ok(Token::AnyGte)
                } else {
                    Ok(Token::AnyGt)
                }
            }
            Some('<') => {
                self.bump();
                if self.peek() == Some('=') {
                    self.bump();
                    Ok(Token::AnyLte)
                } else {
                    Ok(Token::AnyLt)
                }
            }
            Some('~') => {
                self.bump();
                Ok(Token::AnyLike)
            }
            _ => Err(FilterError::at(
                FilterErrorKind::UnexpectedCharacter,
                position,
                "unexpected character '?'",
            )),
        }
    }

    fn lex_string(&mut self, quote: char) -> Result<String, FilterError> {
        let start = self.pos;
        self.bump(); // opening quote
        let mut out = String::new();
        while let Some(ch) = self.bump() {
            match ch {
                c if c == quote => return Ok(out),
                '\\' => {
                    let escaped = self.bump().ok_or_else(|| {
                        FilterError::at(
                            FilterErrorKind::UnterminatedString,
                            start,
                            "unterminated string literal",
                        )
                    })?;
                    if escaped == quote || escaped == '\\' {
                        out.push(escaped);
                    } else {
                        out.push('\\');
                        out.push(escaped);
                    }
                }
                other => out.push(other),
            }
        }
        Err(FilterError::at(
            FilterErrorKind::UnterminatedString,
            start,
            "unterminated string literal",
        ))
    }

    fn lex_macro(&mut self) -> Result<String, FilterError> {
        let start = self.pos;
        self.bump(); // @

        let mut name = String::from("@");
        match self.peek() {
            Some(c) if is_ident_start(c) => {}
            _ => {
                return Err(FilterError::at(
                    FilterErrorKind::UnexpectedCharacter,
                    start,
                    "expected macro name after '@'",
                ))
            }
        }

        let mut previous_was_dot = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                self.bump();
                previous_was_dot = false;
            } else if c == '.' {
                if previous_was_dot {
                    return Err(FilterError::at(
                        FilterErrorKind::UnexpectedCharacter,
                        self.pos,
                        "empty segment in '@' identifier",
                    ));
                }

                name.push(c);
                self.bump();
                previous_was_dot = true;
            } else if c == ':' {
                if previous_was_dot {
                    return Err(FilterError::at(
                        FilterErrorKind::UnexpectedCharacter,
                        self.pos.saturating_sub(1),
                        "trailing '.' in '@' identifier",
                    ));
                }
                name.push(c);
                self.bump();

                match self.peek() {
                    Some(c) if is_ident_start(c) => {}
                    _ => {
                        return Err(FilterError::at(
                            FilterErrorKind::UnexpectedCharacter,
                            self.pos,
                            "expected modifier after ':'",
                        ))
                    }
                }

                while let Some(c) = self.peek() {
                    if is_ident_part_continue(c) {
                        name.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }

                break;
            } else {
                break;
            }
        }

        if previous_was_dot {
            return Err(FilterError::at(
                FilterErrorKind::UnexpectedCharacter,
                self.pos.saturating_sub(1),
                "trailing '.' in '@' identifier",
            ));
        }

        Ok(name)
    }

    fn lex_number(&mut self) -> Result<String, FilterError> {
        let start = self.pos;
        let mut out = String::new();
        if self.peek() == Some('-') {
            out.push('-');
            self.bump();
        }
        let mut integer_digits = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                integer_digits += 1;
                out.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if integer_digits == 0 {
            return Err(FilterError::at(
                FilterErrorKind::InvalidNumber,
                start,
                "invalid number literal",
            ));
        }
        if self.peek() == Some('.') {
            out.push('.');
            self.bump();
            let mut fraction_digits = 0;
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    fraction_digits += 1;
                    out.push(c);
                    self.bump();
                } else {
                    break;
                }
            }
            if fraction_digits == 0 {
                return Err(FilterError::at(
                    FilterErrorKind::InvalidNumber,
                    start,
                    "invalid number literal",
                ));
            }
        }
        Ok(out)
    }

    fn lex_ident_or_keyword(&mut self) -> Result<Token, FilterError> {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if is_ident_continue(c) {
                out.push(c);
                self.bump();
            } else if c == ':' {
                out.push(c);
                self.bump();

                match self.peek() {
                    Some(c) if is_ident_start(c) => {}
                    _ => {
                        return Err(FilterError::at(
                            FilterErrorKind::UnexpectedCharacter,
                            self.pos,
                            "expected modifier after ':'",
                        ))
                    }
                }

                while let Some(c) = self.peek() {
                    if is_ident_part_continue(c) {
                        out.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }

                break;
            } else {
                break;
            }
        }
        Ok(match out.as_str() {
            "true" => Token::Bool(true),
            "false" => Token::Bool(false),
            "null" => Token::Null,
            _ => Token::Ident(out),
        })
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

fn is_ident_part_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
