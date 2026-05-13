use std::fmt;

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
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self::with_kind(FilterErrorKind::Syntax, message)
    }

    pub fn with_kind(kind: FilterErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            position: None,
        }
    }

    pub(crate) fn at(kind: FilterErrorKind, position: usize, message: impl Into<String>) -> Self {
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
