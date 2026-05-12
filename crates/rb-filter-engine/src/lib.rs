//! Rusty Base filter engine.
//!
//! This crate is the first hardened Rust core planned for Rusty Base: a typed,
//! bounded parser/compiler for PocketBase-style filter and access-rule strings.
//! It intentionally starts small: parse a safe subset, count expressions, and
//! emit parameterized SQL fragments.

use std::fmt;

const DEFAULT_EXPR_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOutput {
    pub sql: String,
    pub params: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Number(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    message: String,
}

impl FilterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FilterError {}

pub fn compile_filter(input: &str) -> Result<String, String> {
    compile_filter_with_params(input)
        .map(|out| out.sql)
        .map_err(|err| err.to_string())
}

pub fn compile_filter_with_params(input: &str) -> Result<CompileOutput, FilterError> {
    compile_filter_with_limit(input, DEFAULT_EXPR_LIMIT)
}

pub fn compile_filter_with_limit(
    input: &str,
    max_expressions: usize,
) -> Result<CompileOutput, FilterError> {
    let tokens = Lexer::new(input).tokenize()?;
    let mut parser = Parser::new(tokens, max_expressions);
    let ast = parser.parse()?;
    let mut compiler = SqlCompiler::default();
    let sql = compiler.compile(&ast)?;
    Ok(CompileOutput {
        sql,
        params: compiler.params,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
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
    And,
    Or,
    LParen,
    RParen,
    Eof,
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    _input: &'a str,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            _input: input,
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, FilterError> {
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
                '=' => {
                    self.bump();
                    Token::Eq
                }
                '!' => {
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
                        _ => return Err(FilterError::new("unexpected character '!'")),
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
                '&' => {
                    self.bump();
                    if self.peek() == Some('&') {
                        self.bump();
                        Token::And
                    } else {
                        return Err(FilterError::new("unexpected character '&'"));
                    }
                }
                '|' => {
                    self.bump();
                    if self.peek() == Some('|') {
                        self.bump();
                        Token::Or
                    } else {
                        return Err(FilterError::new("unexpected character '|'"));
                    }
                }
                '\'' => Token::String(self.lex_string()?),
                c if c.is_ascii_digit() || c == '-' => Token::Number(self.lex_number()?),
                c if is_ident_start(c) => self.lex_ident_or_keyword(),
                other => return Err(FilterError::new(format!("unexpected character '{other}'"))),
            };
            tokens.push(token);
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.bump();
        }
    }

    fn lex_string(&mut self) -> Result<String, FilterError> {
        self.bump(); // opening quote
        let mut out = String::new();
        while let Some(ch) = self.bump() {
            match ch {
                '\'' => return Ok(out),
                '\\' => {
                    let escaped = self
                        .bump()
                        .ok_or_else(|| FilterError::new("unterminated string literal"))?;
                    out.push(escaped);
                }
                other => out.push(other),
            }
        }
        Err(FilterError::new("unterminated string literal"))
    }

    fn lex_number(&mut self) -> Result<String, FilterError> {
        let mut out = String::new();
        if self.peek() == Some('-') {
            out.push('-');
            self.bump();
        }
        let mut has_digit = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                has_digit = true;
                out.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if self.peek() == Some('.') {
            out.push('.');
            self.bump();
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    has_digit = true;
                    out.push(c);
                    self.bump();
                } else {
                    break;
                }
            }
        }
        if !has_digit {
            return Err(FilterError::new("invalid number literal"));
        }
        Ok(out)
    }

    fn lex_ident_or_keyword(&mut self) -> Token {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if is_ident_continue(c) {
                out.push(c);
                self.bump();
            } else {
                break;
            }
        }
        match out.as_str() {
            "true" => Token::Bool(true),
            "false" => Token::Bool(false),
            "null" => Token::Null,
            _ => Token::Ident(out),
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Binary {
        left: Box<Expr>,
        op: LogicOp,
        right: Box<Expr>,
    },
    Group(Box<Expr>),
    Compare {
        field: String,
        op: CompareOp,
        value: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogicOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
    NotLike,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    max_expressions: usize,
    expression_count: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>, max_expressions: usize) -> Self {
        Self {
            tokens,
            pos: 0,
            max_expressions,
            expression_count: 0,
        }
    }

    fn parse(&mut self) -> Result<Expr, FilterError> {
        let expr = self.parse_or()?;
        if !matches!(self.peek(), Token::Eof) {
            return Err(FilterError::new(format!(
                "unexpected token after expression: {:?}",
                self.peek()
            )));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: LogicOp::Or,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_primary()?;
        while matches!(self.peek(), Token::And) {
            self.bump();
            let right = self.parse_primary()?;
            left = Expr::Binary {
                left: Box::new(left),
                op: LogicOp::And,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        if matches!(self.peek(), Token::LParen) {
            self.bump();
            let expr = self.parse_or()?;
            self.expect_rparen()?;
            return Ok(Expr::Group(Box::new(expr)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Expr, FilterError> {
        self.expression_count += 1;
        if self.expression_count > self.max_expressions {
            return Err(FilterError::new("expression limit exceeded"));
        }

        let field = match self.bump() {
            Token::Ident(value) => value,
            other => {
                return Err(FilterError::new(format!(
                    "expected identifier, found {other:?}"
                )))
            }
        };
        let op = match self.bump() {
            Token::Eq => CompareOp::Eq,
            Token::Ne => CompareOp::Ne,
            Token::Gt => CompareOp::Gt,
            Token::Gte => CompareOp::Gte,
            Token::Lt => CompareOp::Lt,
            Token::Lte => CompareOp::Lte,
            Token::Like => CompareOp::Like,
            Token::NotLike => CompareOp::NotLike,
            other => {
                return Err(FilterError::new(format!(
                    "expected operator, found {other:?}"
                )))
            }
        };
        let value = match self.bump() {
            Token::String(value) => Value::String(value),
            Token::Number(value) => Value::Number(value),
            Token::Bool(value) => Value::Bool(value),
            Token::Null => Value::Null,
            other => return Err(FilterError::new(format!("expected value, found {other:?}"))),
        };
        Ok(Expr::Compare { field, op, value })
    }

    fn expect_rparen(&mut self) -> Result<(), FilterError> {
        match self.bump() {
            Token::RParen => Ok(()),
            other => Err(FilterError::new(format!("expected ')', found {other:?}"))),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn bump(&mut self) -> Token {
        let token = self.peek().clone();
        self.pos += 1;
        token
    }
}

#[derive(Default)]
struct SqlCompiler {
    params: Vec<Value>,
}

impl SqlCompiler {
    fn compile(&mut self, expr: &Expr) -> Result<String, FilterError> {
        match expr {
            Expr::Binary { left, op, right } => {
                let left = self.compile(left)?;
                let right = self.compile(right)?;
                let op = match op {
                    LogicOp::And => "AND",
                    LogicOp::Or => "OR",
                };
                Ok(format!("{left} {op} {right}"))
            }
            Expr::Group(inner) => Ok(format!("({})", self.compile(inner)?)),
            Expr::Compare { field, op, value } => self.compile_compare(field, *op, value),
        }
    }

    fn compile_compare(
        &mut self,
        field: &str,
        op: CompareOp,
        value: &Value,
    ) -> Result<String, FilterError> {
        if !is_safe_identifier_path(field) {
            return Err(FilterError::new(format!("unsafe identifier '{field}'")));
        }

        match (op, value) {
            (CompareOp::Eq, Value::Null) => Ok(format!("{field} IS NULL")),
            (CompareOp::Ne, Value::Null) => Ok(format!("{field} IS NOT NULL")),
            (CompareOp::Eq, Value::Bool(true)) => Ok(format!("{field} = TRUE")),
            (CompareOp::Eq, Value::Bool(false)) => Ok(format!("{field} = FALSE")),
            (CompareOp::Ne, Value::Bool(true)) => Ok(format!("{field} != TRUE")),
            (CompareOp::Ne, Value::Bool(false)) => Ok(format!("{field} != FALSE")),
            (CompareOp::Like, _) => {
                self.params.push(wrap_like(value));
                Ok(format!("{field} LIKE ? ESCAPE '\\'"))
            }
            (CompareOp::NotLike, _) => {
                self.params.push(wrap_like(value));
                Ok(format!("{field} NOT LIKE ? ESCAPE '\\'"))
            }
            (_, Value::Null) => Err(FilterError::new("null can only be used with = or !=")),
            (_, Value::Bool(_)) => {
                self.params.push(value.clone());
                Ok(format!("{field} {} ?", compare_op_sql(op)))
            }
            _ => {
                self.params.push(value.clone());
                Ok(format!("{field} {} ?", compare_op_sql(op)))
            }
        }
    }
}

fn compare_op_sql(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "=",
        CompareOp::Ne => "!=",
        CompareOp::Gt => ">",
        CompareOp::Gte => ">=",
        CompareOp::Lt => "<",
        CompareOp::Lte => "<=",
        CompareOp::Like => "LIKE",
        CompareOp::NotLike => "NOT LIKE",
    }
}

fn wrap_like(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(format!("%{}%", escape_like(value))),
        other => other.clone(),
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn is_safe_identifier_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_ident_continue))
}
