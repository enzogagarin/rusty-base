//! Rusty Base filter engine.
//!
//! This crate is the first hardened Rust core planned for Rusty Base: a typed,
//! bounded parser/compiler for PocketBase-style filter and access-rule strings.
//! It intentionally starts small: parse a safe subset, count expressions, and
//! emit parameterized SQL fragments.

use std::{collections::HashMap, fmt};

const DEFAULT_EXPR_LIMIT: usize = 64;
const DEFAULT_INPUT_BYTES: usize = 16 * 1024;
const DEFAULT_DEPTH_LIMIT: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterSettings {
    pub max_expressions: usize,
    pub max_input_bytes: usize,
    pub max_depth: usize,
}

impl Default for FilterSettings {
    fn default() -> Self {
        Self {
            max_expressions: DEFAULT_EXPR_LIMIT,
            max_input_bytes: DEFAULT_INPUT_BYTES,
            max_depth: DEFAULT_DEPTH_LIMIT,
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Number,
    Bool,
    DateTime,
    Array,
    Relation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: String,
    pub kind: FieldKind,
}

impl FieldSchema {
    pub fn new(name: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterSchema {
    fields: HashMap<String, FieldKind>,
}

impl FilterSchema {
    pub fn new(fields: impl IntoIterator<Item = FieldSchema>) -> Self {
        Self {
            fields: fields
                .into_iter()
                .map(|field| (field.name, field.kind))
                .collect(),
        }
    }

    pub fn field_kind(&self, field: &str) -> Option<FieldKind> {
        self.fields.get(field).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterErrorKind {
    Syntax,
    UnexpectedCharacter,
    UnexpectedToken,
    UnterminatedString,
    InvalidNumber,
    InputLengthLimitExceeded,
    DepthLimitExceeded,
    ExpressionLimitExceeded,
    UnknownField,
    InvalidOperator,
    InvalidLiteral,
    UnsafeIdentifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    kind: FilterErrorKind,
    message: String,
    position: Option<usize>,
}

impl FilterError {
    fn new(message: impl Into<String>) -> Self {
        Self::with_kind(FilterErrorKind::Syntax, message)
    }

    fn with_kind(kind: FilterErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            position: None,
        }
    }

    fn at(kind: FilterErrorKind, position: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            position: Some(position),
        }
    }

    pub fn kind(&self) -> FilterErrorKind {
        self.kind
    }

    pub fn position(&self) -> Option<usize> {
        self.position
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(position) => write!(f, "{} at byte {}", self.message, position),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for FilterError {}

pub fn compile_filter(input: &str) -> Result<String, String> {
    compile_filter_with_params(input)
        .map(|out| out.sql)
        .map_err(|err| err.to_string())
}

pub fn compile_filter_with_params(input: &str) -> Result<CompileOutput, FilterError> {
    compile_filter_with_settings(input, FilterSettings::default())
}

pub fn compile_filter_with_limit(
    input: &str,
    max_expressions: usize,
) -> Result<CompileOutput, FilterError> {
    compile_filter_with_settings(
        input,
        FilterSettings {
            max_expressions,
            ..FilterSettings::default()
        },
    )
}

pub fn compile_filter_with_settings(
    input: &str,
    settings: FilterSettings,
) -> Result<CompileOutput, FilterError> {
    if input.len() > settings.max_input_bytes {
        return Err(FilterError::with_kind(
            FilterErrorKind::InputLengthLimitExceeded,
            "input length limit exceeded",
        ));
    }
    let tokens = Lexer::new(input).tokenize()?;
    let mut parser = Parser::new(tokens, settings);
    let ast = parser.parse()?;
    let mut compiler = SqlCompiler::default();
    let sql = compiler.compile(&ast)?;
    Ok(CompileOutput {
        sql,
        params: compiler.params,
    })
}

pub fn compile_filter_with_schema(
    input: &str,
    schema: &FilterSchema,
) -> Result<CompileOutput, FilterError> {
    compile_filter_with_schema_and_settings(input, schema, FilterSettings::default())
}

pub fn compile_filter_with_schema_and_settings(
    input: &str,
    schema: &FilterSchema,
    settings: FilterSettings,
) -> Result<CompileOutput, FilterError> {
    if input.len() > settings.max_input_bytes {
        return Err(FilterError::with_kind(
            FilterErrorKind::InputLengthLimitExceeded,
            "input length limit exceeded",
        ));
    }
    let tokens = Lexer::new(input).tokenize()?;
    let mut parser = Parser::new(tokens, settings);
    let ast = parser.parse()?;
    let mut compiler = SqlCompiler::with_schema(schema);
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
                '\'' => Token::String(self.lex_string()?),
                c if c.is_ascii_digit() || c == '-' => Token::Number(self.lex_number()?),
                c if is_ident_start(c) => self.lex_ident_or_keyword(),
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

    fn lex_string(&mut self) -> Result<String, FilterError> {
        let start = self.pos;
        self.bump(); // opening quote
        let mut out = String::new();
        while let Some(ch) = self.bump() {
            match ch {
                '\'' => return Ok(out),
                '\\' => {
                    let escaped = self.bump().ok_or_else(|| {
                        FilterError::at(
                            FilterErrorKind::UnterminatedString,
                            start,
                            "unterminated string literal",
                        )
                    })?;
                    out.push(escaped);
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
    AnyEq,
    AnyNe,
    AnyGt,
    AnyGte,
    AnyLt,
    AnyLte,
    AnyLike,
    AnyNotLike,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    settings: FilterSettings,
    expression_count: usize,
    depth: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>, settings: FilterSettings) -> Self {
        Self {
            tokens,
            pos: 0,
            settings,
            expression_count: 0,
            depth: 0,
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
            self.depth += 1;
            if self.depth > self.settings.max_depth {
                return Err(FilterError::with_kind(
                    FilterErrorKind::DepthLimitExceeded,
                    "depth limit exceeded",
                ));
            }
            self.bump();
            let expr = self.parse_or()?;
            self.expect_rparen()?;
            self.depth -= 1;
            return Ok(Expr::Group(Box::new(expr)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Expr, FilterError> {
        self.expression_count += 1;
        if self.expression_count > self.settings.max_expressions {
            return Err(FilterError::with_kind(
                FilterErrorKind::ExpressionLimitExceeded,
                "expression limit exceeded",
            ));
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
            Token::AnyEq => CompareOp::AnyEq,
            Token::AnyNe => CompareOp::AnyNe,
            Token::AnyGt => CompareOp::AnyGt,
            Token::AnyGte => CompareOp::AnyGte,
            Token::AnyLt => CompareOp::AnyLt,
            Token::AnyLte => CompareOp::AnyLte,
            Token::AnyLike => CompareOp::AnyLike,
            Token::AnyNotLike => CompareOp::AnyNotLike,
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
struct SqlCompiler<'a> {
    params: Vec<Value>,
    schema: Option<&'a FilterSchema>,
}

impl<'a> SqlCompiler<'a> {
    fn with_schema(schema: &'a FilterSchema) -> Self {
        Self {
            params: Vec::new(),
            schema: Some(schema),
        }
    }

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
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe identifier '{field}'"),
            ));
        }
        if let Some(schema) = self.schema {
            let kind = schema.field_kind(field).ok_or_else(|| {
                FilterError::with_kind(
                    FilterErrorKind::UnknownField,
                    format!("unknown field '{field}'"),
                )
            })?;
            validate_field_operation(field, kind, op, value)?;
        }

        if is_any_match_op(op) {
            return self.compile_any_match(field, op, value);
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

    fn compile_any_match(
        &mut self,
        field: &str,
        op: CompareOp,
        value: &Value,
    ) -> Result<String, FilterError> {
        let inner_op = any_match_sql_op(op)?;
        let escape_clause = match op {
            CompareOp::AnyLike | CompareOp::AnyNotLike => {
                self.params.push(wrap_like(value));
                " ESCAPE '\\'"
            }
            _ => {
                self.params.push(value.clone());
                ""
            }
        };
        Ok(format!(
            "EXISTS (SELECT 1 FROM json_each({field}) WHERE json_each.value {inner_op} ?{escape_clause})"
        ))
    }
}

fn validate_field_operation(
    field: &str,
    kind: FieldKind,
    op: CompareOp,
    value: &Value,
) -> Result<(), FilterError> {
    if is_any_match_op(op) {
        return if kind == FieldKind::Array {
            validate_array_literal(field, value)
        } else {
            Err(FilterError::new(format!(
                "any-match operator {} is only allowed on array fields",
                op_symbol(op)
            )))
        };
    }

    match kind {
        FieldKind::Text => {
            validate_operator_allowed(
                kind,
                op,
                &[
                    CompareOp::Eq,
                    CompareOp::Ne,
                    CompareOp::Like,
                    CompareOp::NotLike,
                ],
            )?;
            match value {
                Value::String(_) | Value::Null => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected string"))),
            }
        }
        FieldKind::Relation => {
            validate_operator_allowed(kind, op, &[CompareOp::Eq, CompareOp::Ne])?;
            match value {
                Value::String(_) | Value::Null => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected string"))),
            }
        }
        FieldKind::DateTime => {
            validate_operator_allowed(
                kind,
                op,
                &[
                    CompareOp::Eq,
                    CompareOp::Ne,
                    CompareOp::Gt,
                    CompareOp::Gte,
                    CompareOp::Lt,
                    CompareOp::Lte,
                ],
            )?;
            match value {
                Value::String(_) | Value::Null => Ok(()),
                _ => Err(FilterError::new(format!(
                    "field '{field}' expected datetime string"
                ))),
            }
        }
        FieldKind::Number => {
            validate_operator_allowed(
                kind,
                op,
                &[
                    CompareOp::Eq,
                    CompareOp::Ne,
                    CompareOp::Gt,
                    CompareOp::Gte,
                    CompareOp::Lt,
                    CompareOp::Lte,
                ],
            )?;
            match value {
                Value::Number(_) | Value::Null => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected number"))),
            }
        }
        FieldKind::Bool => {
            validate_operator_allowed(kind, op, &[CompareOp::Eq, CompareOp::Ne])?;
            match value {
                Value::Bool(_) | Value::Null => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected bool"))),
            }
        }
        FieldKind::Array => Err(FilterError::new(format!(
            "operator {} is not allowed on array field '{field}'; use any-match operators",
            op_symbol(op)
        ))),
    }
}

fn validate_array_literal(_field: &str, _value: &Value) -> Result<(), FilterError> {
    Ok(())
}

fn validate_operator_allowed(
    kind: FieldKind,
    op: CompareOp,
    allowed: &[CompareOp],
) -> Result<(), FilterError> {
    if allowed.contains(&op) {
        Ok(())
    } else {
        Err(FilterError::with_kind(
            FilterErrorKind::InvalidOperator,
            format!(
                "operator {} is not allowed on {:?} fields",
                op_symbol(op),
                kind
            ),
        ))
    }
}

fn op_symbol(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "=",
        CompareOp::Ne => "!=",
        CompareOp::Gt => ">",
        CompareOp::Gte => ">=",
        CompareOp::Lt => "<",
        CompareOp::Lte => "<=",
        CompareOp::Like => "~",
        CompareOp::NotLike => "!~",
        CompareOp::AnyEq => "?=",
        CompareOp::AnyNe => "?!=",
        CompareOp::AnyGt => "?>",
        CompareOp::AnyGte => "?>=",
        CompareOp::AnyLt => "?<",
        CompareOp::AnyLte => "?<=",
        CompareOp::AnyLike => "?~",
        CompareOp::AnyNotLike => "?!~",
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
        CompareOp::AnyEq => "=",
        CompareOp::AnyNe => "!=",
        CompareOp::AnyGt => ">",
        CompareOp::AnyGte => ">=",
        CompareOp::AnyLt => "<",
        CompareOp::AnyLte => "<=",
        CompareOp::AnyLike => "LIKE",
        CompareOp::AnyNotLike => "NOT LIKE",
    }
}

fn is_any_match_op(op: CompareOp) -> bool {
    matches!(
        op,
        CompareOp::AnyEq
            | CompareOp::AnyNe
            | CompareOp::AnyGt
            | CompareOp::AnyGte
            | CompareOp::AnyLt
            | CompareOp::AnyLte
            | CompareOp::AnyLike
            | CompareOp::AnyNotLike
    )
}

fn any_match_sql_op(op: CompareOp) -> Result<&'static str, FilterError> {
    match op {
        CompareOp::AnyEq => Ok("="),
        CompareOp::AnyNe => Ok("!="),
        CompareOp::AnyGt => Ok(">"),
        CompareOp::AnyGte => Ok(">="),
        CompareOp::AnyLt => Ok("<"),
        CompareOp::AnyLte => Ok("<="),
        CompareOp::AnyLike => Ok("LIKE"),
        CompareOp::AnyNotLike => Ok("NOT LIKE"),
        _ => Err(FilterError::new("not an any-match operator")),
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
