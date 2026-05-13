use std::collections::HashMap;

use crate::{
    compiler::sqlite::{quote_identifier_path, sqlite_json_path},
    error::{FilterError, FilterErrorKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Number,
    Bool,
    DateTime,
    Array,
    Json,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedField {
    pub sql: String,
    pub kind: Option<FieldKind>,
    pub relation: Option<RelationTraversal>,
    pub each: bool,
}

impl ResolvedField {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            kind: None,
            relation: None,
            each: false,
        }
    }

    pub fn with_kind(sql: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            sql: sql.into(),
            kind: Some(kind),
            relation: None,
            each: false,
        }
    }

    pub fn with_relation(mut self, relation: RelationTraversal) -> Self {
        self.relation = Some(relation);
        self
    }
}

pub trait FieldResolver {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError>;
}

impl FieldResolver for FilterSchema {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        if let Some(kind) = self.field_kind(field) {
            return Ok(ResolvedField::with_kind(
                quote_identifier_path(field)?,
                kind,
            ));
        }

        if let Some(resolved) = self.resolve_json_path(field)? {
            return Ok(resolved);
        }

        Err(FilterError::with_kind(
            FilterErrorKind::UnknownField,
            format!("unknown field '{field}'"),
        ))
    }
}

impl FilterSchema {
    fn resolve_json_path(&self, field: &str) -> Result<Option<ResolvedField>, FilterError> {
        let Some((root, nested_path)) = field.split_once('.') else {
            return Ok(None);
        };

        if self.field_kind(root) != Some(FieldKind::Json) {
            return Ok(None);
        }

        let root_sql = quote_identifier_path(root)?;
        let json_path = sqlite_json_path(nested_path)?;

        Ok(Some(ResolvedField::new(format!(
            "json_extract({root_sql}, '{json_path}')"
        ))))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationMultiplicity {
    Single,
    Multiple,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationStep {
    pub source_collection: String,
    pub source_field: String,
    pub target_collection: String,
    pub target_field: String,
    pub multiplicity: RelationMultiplicity,
}

impl RelationStep {
    pub fn new(
        source_collection: impl Into<String>,
        source_field: impl Into<String>,
        target_collection: impl Into<String>,
        target_field: impl Into<String>,
        multiplicity: RelationMultiplicity,
    ) -> Self {
        Self {
            source_collection: source_collection.into(),
            source_field: source_field.into(),
            target_collection: target_collection.into(),
            target_field: target_field.into(),
            multiplicity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationTraversal {
    pub field_path: String,
    pub steps: Vec<RelationStep>,
    pub leaf_field: String,
}

impl RelationTraversal {
    pub fn new(
        field_path: impl Into<String>,
        steps: impl IntoIterator<Item = RelationStep>,
        leaf_field: impl Into<String>,
    ) -> Self {
        Self {
            field_path: field_path.into(),
            steps: steps.into_iter().collect(),
            leaf_field: leaf_field.into(),
        }
    }
}
