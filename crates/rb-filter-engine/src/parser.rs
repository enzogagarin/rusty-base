use crate::{
    ast::{CompareOp, Expr, FilterAst, LogicOp, Operand, Value},
    error::{FilterError, FilterErrorKind},
    lexer::{Lexer, Token},
};

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

pub fn parse_filter(input: &str) -> Result<FilterAst, FilterError> {
    parse_filter_with_settings(input, FilterSettings::default())
}

pub fn parse_filter_with_settings(
    input: &str,
    settings: FilterSettings,
) -> Result<FilterAst, FilterError> {
    if input.len() > settings.max_input_bytes {
        return Err(FilterError::with_kind(
            FilterErrorKind::InputLengthLimitExceeded,
            "input length limit exceeded",
        ));
    }

    let tokens = Lexer::new(input).tokenize()?;
    let mut parser = Parser::new(tokens, settings);
    Ok(FilterAst {
        expr: parser.parse()?,
    })
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

        let left = self.parse_operand()?;
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
        let right = self.parse_operand()?;
        Ok(Expr::Compare { left, op, right })
    }

    fn parse_operand(&mut self) -> Result<Operand, FilterError> {
        match self.bump() {
            Token::Ident(value) if matches!(self.peek(), Token::LParen) => {
                self.parse_function_operand(value)
            }
            Token::Ident(value) => Ok(Operand::Field(value)),
            Token::Macro(value) => Ok(Operand::Macro(value)),
            Token::String(value) => Ok(Operand::Value(Value::String(value))),
            Token::Number(value) => Ok(Operand::Value(Value::Number(value))),
            Token::Bool(value) => Ok(Operand::Value(Value::Bool(value))),
            Token::Null => Ok(Operand::Value(Value::Null)),
            other => Err(FilterError::new(format!(
                "expected operand, found {other:?}"
            ))),
        }
    }

    fn parse_function_operand(&mut self, name: String) -> Result<Operand, FilterError> {
        self.expect_lparen()?;

        let mut args = Vec::new();
        if matches!(self.peek(), Token::RParen) {
            self.bump();
            return Ok(Operand::Function { name, args });
        }

        loop {
            args.push(self.parse_operand()?);
            match self.bump() {
                Token::Comma => {}
                Token::RParen => break,
                other => {
                    return Err(FilterError::new(format!(
                        "expected ',' or ')' in function call, found {other:?}"
                    )))
                }
            }
        }

        Ok(Operand::Function { name, args })
    }

    fn expect_lparen(&mut self) -> Result<(), FilterError> {
        match self.bump() {
            Token::LParen => Ok(()),
            other => Err(FilterError::new(format!("expected '(', found {other:?}"))),
        }
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
