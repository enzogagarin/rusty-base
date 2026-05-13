//! Rusty Base filter engine.
//!
//! This crate is the first hardened Rust core planned for Rusty Base: a typed,
//! bounded parser/compiler for PocketBase-style filter and access-rule strings.
//! It intentionally starts small: parse a safe subset, count expressions, and
//! emit parameterized SQL fragments.

mod ast;
pub mod compiler;
mod error;
mod lexer;
mod parser;
mod schema;

pub use ast::{
    FilterAst, FilterPlan, PlanCompareOp, PlanLogicOp, PlannedExpr, PlannedField, PlannedOperand,
    RelationSqlOptions, Value,
};
pub use compiler::sqlite::{
    compile_ast, compile_ast_with_context, compile_ast_with_named_params,
    compile_ast_with_named_params_and_context, compile_ast_with_resolver,
    compile_ast_with_resolver_and_context, compile_ast_with_resolver_and_named_params,
    compile_ast_with_resolver_and_named_params_and_context, compile_ast_with_schema,
    compile_ast_with_schema_and_context, compile_ast_with_schema_and_named_params,
    compile_ast_with_schema_and_named_params_and_context, compile_filter,
    compile_filter_with_context, compile_filter_with_limit, compile_filter_with_named_params,
    compile_filter_with_named_params_and_context, compile_filter_with_params,
    compile_filter_with_resolver, compile_filter_with_resolver_and_context,
    compile_filter_with_resolver_and_named_params,
    compile_filter_with_resolver_and_named_params_and_context,
    compile_filter_with_resolver_and_settings, compile_filter_with_schema,
    compile_filter_with_schema_and_context, compile_filter_with_schema_and_named_params,
    compile_filter_with_schema_and_named_params_and_context,
    compile_filter_with_schema_and_settings, compile_filter_with_settings, plan_ast,
    plan_ast_with_context, plan_ast_with_resolver, plan_ast_with_resolver_and_context,
    plan_ast_with_schema, plan_ast_with_schema_and_context, plan_filter, plan_filter_with_context,
    plan_filter_with_resolver, plan_filter_with_resolver_and_context,
    plan_filter_with_resolver_and_settings, plan_filter_with_schema,
    plan_filter_with_schema_and_context, plan_filter_with_schema_and_settings,
    plan_filter_with_settings, render_plan_sql, render_plan_sql_with_named_params,
    render_plan_sql_with_named_params_and_options, render_plan_sql_with_options, CompileOutput,
    FilterContext, FilterDateTime, NamedCompileOutput, NamedParam, RequestContext,
};
pub use error::{FilterError, FilterErrorKind};
pub use parser::{parse_filter, parse_filter_with_settings, FilterSettings};
pub use schema::{
    FieldKind, FieldResolver, FieldSchema, FilterSchema, RelationMultiplicity, RelationStep,
    RelationTraversal, ResolvedField,
};
