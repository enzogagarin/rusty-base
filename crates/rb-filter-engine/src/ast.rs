use crate::schema::{FieldKind, RelationTraversal, ResolvedField};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterAst {
    pub(crate) expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    String(String),
    Number(String),
    Bool(bool),
    Null,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPlan {
    pub predicate: PlannedExpr,
    pub relations: Vec<RelationTraversal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelationSqlOptions {
    pub root_alias: Option<String>,
}

impl RelationSqlOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root_alias(root_alias: impl Into<String>) -> Self {
        Self {
            root_alias: Some(root_alias.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedExpr {
    Binary {
        left: Box<PlannedExpr>,
        op: PlanLogicOp,
        right: Box<PlannedExpr>,
    },
    Group(Box<PlannedExpr>),
    Compare {
        left: PlannedOperand,
        op: PlanCompareOp,
        right: PlannedOperand,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedOperand {
    Field(PlannedField),
    Function {
        name: String,
        args: Vec<PlannedOperand>,
        kind: FieldKind,
    },
    Value(Value),
    EachValues {
        name: String,
        values: Vec<Value>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedField {
    pub name: String,
    pub resolved: ResolvedField,
}

impl PlannedField {
    pub fn relation(&self) -> Option<&RelationTraversal> {
        self.resolved.relation.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanLogicOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanCompareOp {
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

impl PlanCompareOp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Like => "~",
            Self::NotLike => "!~",
            Self::AnyEq => "?=",
            Self::AnyNe => "?!=",
            Self::AnyGt => "?>",
            Self::AnyGte => "?>=",
            Self::AnyLt => "?<",
            Self::AnyLte => "?<=",
            Self::AnyLike => "?~",
            Self::AnyNotLike => "?!~",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    Binary {
        left: Box<Expr>,
        op: LogicOp,
        right: Box<Expr>,
    },
    Group(Box<Expr>),
    Compare {
        left: Operand,
        op: CompareOp,
        right: Operand,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Operand {
    Field(String),
    Function { name: String, args: Vec<Operand> },
    Macro(String),
    Value(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogicOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldModifier {
    Lower,
    Length,
    Each,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestModifier {
    Isset,
    Changed,
    Each,
    Lower,
    Length,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompareOp {
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

impl From<LogicOp> for PlanLogicOp {
    fn from(value: LogicOp) -> Self {
        match value {
            LogicOp::And => Self::And,
            LogicOp::Or => Self::Or,
        }
    }
}

impl From<CompareOp> for PlanCompareOp {
    fn from(value: CompareOp) -> Self {
        match value {
            CompareOp::Eq => Self::Eq,
            CompareOp::Ne => Self::Ne,
            CompareOp::Gt => Self::Gt,
            CompareOp::Gte => Self::Gte,
            CompareOp::Lt => Self::Lt,
            CompareOp::Lte => Self::Lte,
            CompareOp::Like => Self::Like,
            CompareOp::NotLike => Self::NotLike,
            CompareOp::AnyEq => Self::AnyEq,
            CompareOp::AnyNe => Self::AnyNe,
            CompareOp::AnyGt => Self::AnyGt,
            CompareOp::AnyGte => Self::AnyGte,
            CompareOp::AnyLt => Self::AnyLt,
            CompareOp::AnyLte => Self::AnyLte,
            CompareOp::AnyLike => Self::AnyLike,
            CompareOp::AnyNotLike => Self::AnyNotLike,
        }
    }
}
