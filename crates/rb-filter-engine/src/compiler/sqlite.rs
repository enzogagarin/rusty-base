use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ast::{
        CompareOp, Expr, FieldModifier, FilterAst, FilterPlan, LogicOp, Operand, PlanCompareOp,
        PlanLogicOp, PlannedExpr, PlannedField, PlannedOperand, RelationSqlOptions,
        RequestModifier, Value,
    },
    error::{FilterError, FilterErrorKind},
    parser::{parse_filter, parse_filter_with_settings, FilterSettings},
    schema::{
        FieldKind, FieldResolver, FilterSchema, RelationMultiplicity, RelationStep,
        RelationTraversal, ResolvedField,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOutput {
    pub sql: String,
    pub params: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedCompileOutput {
    pub sql: String,
    pub params: Vec<NamedParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedParam {
    pub name: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterContext {
    pub now: FilterDateTime,
    pub request: RequestContext,
}

impl FilterContext {
    pub fn new(now: FilterDateTime) -> Self {
        Self {
            now,
            request: RequestContext::default(),
        }
    }

    pub fn with_request(mut self, request: RequestContext) -> Self {
        self.request = request;
        self
    }

    pub fn with_request_context(mut self, context: impl Into<String>) -> Self {
        self.request.context = context.into();
        self
    }

    pub fn with_request_method(mut self, method: impl Into<String>) -> Self {
        self.request.method = method.into();
        self
    }

    pub fn with_auth_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.request.auth.insert(field.into(), value);
        self
    }

    pub fn with_query_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.request.query.insert(field.into(), value);
        self
    }

    pub fn with_header_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.request
            .headers
            .insert(normalize_header_key(field), value);
        self
    }

    pub fn with_body_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.request.body.insert(field.into(), value);
        self
    }

    pub fn with_body_length(mut self, field: impl Into<String>, length: usize) -> Self {
        self.request.body_lengths.insert(field.into(), length);
        self
    }

    pub fn with_body_each_values(
        mut self,
        field: impl Into<String>,
        values: impl IntoIterator<Item = Value>,
    ) -> Self {
        self.request
            .body_each_values
            .insert(field.into(), values.into_iter().collect());
        self
    }

    pub fn with_body_changed(mut self, field: impl Into<String>, changed: bool) -> Self {
        self.request.body_changes.insert(field.into(), changed);
        self
    }
}

impl Default for FilterContext {
    fn default() -> Self {
        Self {
            now: FilterDateTime::now_utc(),
            request: RequestContext::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    pub context: String,
    pub method: String,
    pub auth: HashMap<String, Value>,
    pub query: HashMap<String, Value>,
    pub headers: HashMap<String, Value>,
    pub body: HashMap<String, Value>,
    pub body_lengths: HashMap<String, usize>,
    pub body_each_values: HashMap<String, Vec<Value>>,
    pub body_changes: HashMap<String, bool>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn with_auth_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.auth.insert(field.into(), value);
        self
    }

    pub fn with_query_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.query.insert(field.into(), value);
        self
    }

    pub fn with_header_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.headers.insert(normalize_header_key(field), value);
        self
    }

    pub fn with_body_value(mut self, field: impl Into<String>, value: Value) -> Self {
        self.body.insert(field.into(), value);
        self
    }

    pub fn with_body_length(mut self, field: impl Into<String>, length: usize) -> Self {
        self.body_lengths.insert(field.into(), length);
        self
    }

    pub fn with_body_each_values(
        mut self,
        field: impl Into<String>,
        values: impl IntoIterator<Item = Value>,
    ) -> Self {
        self.body_each_values
            .insert(field.into(), values.into_iter().collect());
        self
    }

    pub fn with_body_changed(mut self, field: impl Into<String>, changed: bool) -> Self {
        self.body_changes.insert(field.into(), changed);
        self
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            context: "default".to_string(),
            method: String::new(),
            auth: HashMap::new(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: HashMap::new(),
            body_lengths: HashMap::new(),
            body_each_values: HashMap::new(),
            body_changes: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterDateTime {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    millisecond: u16,
}

impl FilterDateTime {
    pub fn utc(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        millisecond: u16,
    ) -> Result<Self, FilterError> {
        if !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || millisecond > 999
        {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                "invalid UTC datetime components",
            ));
        }

        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            millisecond,
        })
    }

    fn now_utc() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix_parts(duration.as_secs() as i64, duration.subsec_millis() as u16)
    }

    fn from_unix_parts(seconds: i64, millisecond: u16) -> Self {
        let days = seconds.div_euclid(86_400);
        let seconds_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);

        Self {
            year,
            month,
            day,
            hour: (seconds_of_day / 3_600) as u8,
            minute: ((seconds_of_day % 3_600) / 60) as u8,
            second: (seconds_of_day % 60) as u8,
            millisecond,
        }
    }

    fn date_at(self, hour: u8, minute: u8, second: u8, millisecond: u16) -> Self {
        Self {
            hour,
            minute,
            second,
            millisecond,
            ..self
        }
    }

    fn add_days(self, days: i64) -> Self {
        let total_days = days_from_civil(self.year, self.month, self.day) + days;
        let (year, month, day) = civil_from_days(total_days);
        Self {
            year,
            month,
            day,
            ..self
        }
    }

    fn month_start(self) -> Self {
        Self {
            day: 1,
            ..self.date_at(0, 0, 0, 0)
        }
    }

    fn month_end(self) -> Self {
        Self {
            day: days_in_month(self.year, self.month),
            ..self.date_at(23, 59, 59, 999)
        }
    }

    fn year_start(self) -> Self {
        Self {
            month: 1,
            day: 1,
            ..self.date_at(0, 0, 0, 0)
        }
    }

    fn year_end(self) -> Self {
        Self {
            month: 12,
            day: 31,
            ..self.date_at(23, 59, 59, 999)
        }
    }

    fn weekday(self) -> u8 {
        let days = days_from_civil(self.year, self.month, self.day);
        (days + 4).rem_euclid(7) as u8
    }

    fn to_pocketbase_string(self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millisecond
        )
    }
}
pub fn compile_filter(input: &str) -> Result<String, String> {
    compile_filter_with_params(input)
        .map(|out| out.sql)
        .map_err(|err| err.to_string())
}

pub fn compile_filter_with_params(input: &str) -> Result<CompileOutput, FilterError> {
    compile_filter_with_settings(input, FilterSettings::default())
}

pub fn compile_ast(ast: &FilterAst) -> Result<CompileOutput, FilterError> {
    compile_ast_with_context(ast, FilterContext::default())
}

pub fn compile_ast_with_context(
    ast: &FilterAst,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    let mut compiler = SqlCompiler::with_context(context);
    let sql = compiler.compile(&ast.expr)?;
    Ok(CompileOutput {
        sql,
        params: compiler.params.into_positional(),
    })
}

pub fn compile_ast_with_named_params(ast: &FilterAst) -> Result<NamedCompileOutput, FilterError> {
    compile_ast_with_named_params_and_context(ast, FilterContext::default())
}

pub fn compile_ast_with_named_params_and_context(
    ast: &FilterAst,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    let mut compiler = SqlCompiler::with_named_context(context);
    let sql = compiler.compile(&ast.expr)?;
    Ok(NamedCompileOutput {
        sql,
        params: compiler.params.into_named(),
    })
}

pub fn compile_ast_with_resolver(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
) -> Result<CompileOutput, FilterError> {
    compile_ast_with_resolver_and_context(ast, resolver, FilterContext::default())
}

pub fn compile_ast_with_resolver_and_context(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    let mut compiler = SqlCompiler::with_resolver_and_context(resolver, context);
    let sql = compiler.compile(&ast.expr)?;
    Ok(CompileOutput {
        sql,
        params: compiler.params.into_positional(),
    })
}

pub fn compile_ast_with_resolver_and_named_params(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
) -> Result<NamedCompileOutput, FilterError> {
    compile_ast_with_resolver_and_named_params_and_context(ast, resolver, FilterContext::default())
}

pub fn compile_ast_with_resolver_and_named_params_and_context(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    let mut compiler = SqlCompiler::with_resolver_and_named_context(resolver, context);
    let sql = compiler.compile(&ast.expr)?;
    Ok(NamedCompileOutput {
        sql,
        params: compiler.params.into_named(),
    })
}

pub fn compile_ast_with_schema(
    ast: &FilterAst,
    schema: &FilterSchema,
) -> Result<CompileOutput, FilterError> {
    compile_ast_with_resolver(ast, schema)
}

pub fn compile_ast_with_schema_and_context(
    ast: &FilterAst,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    compile_ast_with_resolver_and_context(ast, schema, context)
}

pub fn compile_ast_with_schema_and_named_params(
    ast: &FilterAst,
    schema: &FilterSchema,
) -> Result<NamedCompileOutput, FilterError> {
    compile_ast_with_resolver_and_named_params(ast, schema)
}

pub fn compile_ast_with_schema_and_named_params_and_context(
    ast: &FilterAst,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    compile_ast_with_resolver_and_named_params_and_context(ast, schema, context)
}

pub fn plan_ast(ast: &FilterAst) -> Result<FilterPlan, FilterError> {
    plan_ast_with_context(ast, FilterContext::default())
}

pub fn plan_ast_with_context(
    ast: &FilterAst,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    let mut planner = FilterPlanner::with_context(context);
    let predicate = planner.plan(&ast.expr)?;
    Ok(FilterPlan {
        predicate,
        relations: planner.relations,
    })
}

pub fn plan_ast_with_resolver(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
) -> Result<FilterPlan, FilterError> {
    plan_ast_with_resolver_and_context(ast, resolver, FilterContext::default())
}

pub fn plan_ast_with_resolver_and_context(
    ast: &FilterAst,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    let mut planner = FilterPlanner::with_resolver_and_context(resolver, context);
    let predicate = planner.plan(&ast.expr)?;
    Ok(FilterPlan {
        predicate,
        relations: planner.relations,
    })
}

pub fn plan_ast_with_schema(
    ast: &FilterAst,
    schema: &FilterSchema,
) -> Result<FilterPlan, FilterError> {
    plan_ast_with_resolver(ast, schema)
}

pub fn plan_ast_with_schema_and_context(
    ast: &FilterAst,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    plan_ast_with_resolver_and_context(ast, schema, context)
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
    let ast = parse_filter_with_settings(input, settings)?;
    compile_ast(&ast)
}

pub fn compile_filter_with_named_params(input: &str) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_named_params(&ast)
}

pub fn compile_filter_with_named_params_and_context(
    input: &str,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_named_params_and_context(&ast, context)
}

pub fn plan_filter(input: &str) -> Result<FilterPlan, FilterError> {
    plan_filter_with_settings(input, FilterSettings::default())
}

pub fn plan_filter_with_settings(
    input: &str,
    settings: FilterSettings,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter_with_settings(input, settings)?;
    plan_ast(&ast)
}

pub fn plan_filter_with_context(
    input: &str,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter(input)?;
    plan_ast_with_context(&ast, context)
}

pub fn compile_filter_with_context(
    input: &str,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_context(&ast, context)
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
    let ast = parse_filter_with_settings(input, settings)?;
    compile_ast_with_schema(&ast, schema)
}

pub fn compile_filter_with_schema_and_context(
    input: &str,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_schema_and_context(&ast, schema, context)
}

pub fn compile_filter_with_schema_and_named_params(
    input: &str,
    schema: &FilterSchema,
) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_schema_and_named_params(&ast, schema)
}

pub fn compile_filter_with_schema_and_named_params_and_context(
    input: &str,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_schema_and_named_params_and_context(&ast, schema, context)
}

pub fn plan_filter_with_schema(
    input: &str,
    schema: &FilterSchema,
) -> Result<FilterPlan, FilterError> {
    plan_filter_with_schema_and_settings(input, schema, FilterSettings::default())
}

pub fn plan_filter_with_schema_and_settings(
    input: &str,
    schema: &FilterSchema,
    settings: FilterSettings,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter_with_settings(input, settings)?;
    plan_ast_with_schema(&ast, schema)
}

pub fn plan_filter_with_schema_and_context(
    input: &str,
    schema: &FilterSchema,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter(input)?;
    plan_ast_with_schema_and_context(&ast, schema, context)
}

pub fn compile_filter_with_resolver(
    input: &str,
    resolver: &dyn FieldResolver,
) -> Result<CompileOutput, FilterError> {
    compile_filter_with_resolver_and_settings(input, resolver, FilterSettings::default())
}

pub fn compile_filter_with_resolver_and_settings(
    input: &str,
    resolver: &dyn FieldResolver,
    settings: FilterSettings,
) -> Result<CompileOutput, FilterError> {
    let ast = parse_filter_with_settings(input, settings)?;
    compile_ast_with_resolver(&ast, resolver)
}

pub fn compile_filter_with_resolver_and_context(
    input: &str,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<CompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_resolver_and_context(&ast, resolver, context)
}

pub fn compile_filter_with_resolver_and_named_params(
    input: &str,
    resolver: &dyn FieldResolver,
) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_resolver_and_named_params(&ast, resolver)
}

pub fn compile_filter_with_resolver_and_named_params_and_context(
    input: &str,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<NamedCompileOutput, FilterError> {
    let ast = parse_filter(input)?;
    compile_ast_with_resolver_and_named_params_and_context(&ast, resolver, context)
}

pub fn plan_filter_with_resolver(
    input: &str,
    resolver: &dyn FieldResolver,
) -> Result<FilterPlan, FilterError> {
    plan_filter_with_resolver_and_settings(input, resolver, FilterSettings::default())
}

pub fn plan_filter_with_resolver_and_settings(
    input: &str,
    resolver: &dyn FieldResolver,
    settings: FilterSettings,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter_with_settings(input, settings)?;
    plan_ast_with_resolver(&ast, resolver)
}

pub fn plan_filter_with_resolver_and_context(
    input: &str,
    resolver: &dyn FieldResolver,
    context: FilterContext,
) -> Result<FilterPlan, FilterError> {
    let ast = parse_filter(input)?;
    plan_ast_with_resolver_and_context(&ast, resolver, context)
}

pub fn render_plan_sql(plan: &FilterPlan) -> Result<CompileOutput, FilterError> {
    render_plan_sql_with_options(plan, RelationSqlOptions::default())
}

pub fn render_plan_sql_with_options(
    plan: &FilterPlan,
    options: RelationSqlOptions,
) -> Result<CompileOutput, FilterError> {
    let mut renderer = PlanSqlRenderer::new(&plan.relations, options);
    let sql = renderer.render_expr(&plan.predicate)?;
    Ok(CompileOutput {
        sql,
        params: renderer.params.into_positional(),
    })
}

pub fn render_plan_sql_with_named_params(
    plan: &FilterPlan,
) -> Result<NamedCompileOutput, FilterError> {
    render_plan_sql_with_named_params_and_options(plan, RelationSqlOptions::default())
}

pub fn render_plan_sql_with_named_params_and_options(
    plan: &FilterPlan,
    options: RelationSqlOptions,
) -> Result<NamedCompileOutput, FilterError> {
    let mut renderer = PlanSqlRenderer::new_named(&plan.relations, options);
    let sql = renderer.render_expr(&plan.predicate)?;
    Ok(NamedCompileOutput {
        sql,
        params: renderer.params.into_named(),
    })
}
struct FilterPlanner<'a> {
    field_resolver: Option<&'a dyn FieldResolver>,
    context: FilterContext,
    relations: Vec<RelationTraversal>,
}

impl<'a> FilterPlanner<'a> {
    fn with_context(context: FilterContext) -> Self {
        Self {
            field_resolver: None,
            context,
            relations: Vec::new(),
        }
    }

    fn with_resolver_and_context(
        field_resolver: &'a dyn FieldResolver,
        context: FilterContext,
    ) -> Self {
        Self {
            field_resolver: Some(field_resolver),
            context,
            relations: Vec::new(),
        }
    }

    fn plan(&mut self, expr: &Expr) -> Result<PlannedExpr, FilterError> {
        match expr {
            Expr::Binary { left, op, right } => Ok(PlannedExpr::Binary {
                left: Box::new(self.plan(left)?),
                op: (*op).into(),
                right: Box::new(self.plan(right)?),
            }),
            Expr::Group(inner) => Ok(PlannedExpr::Group(Box::new(self.plan(inner)?))),
            Expr::Compare { left, op, right } => {
                let left = self.plan_operand(left)?;
                let right = self.plan_operand(right)?;
                let resolved_left = planned_operand_to_resolved(&left);
                let resolved_right = planned_operand_to_resolved(&right);
                validate_plan_compare_operands(&resolved_left, *op, &resolved_right)?;

                Ok(PlannedExpr::Compare {
                    left,
                    op: (*op).into(),
                    right,
                })
            }
        }
    }

    fn plan_operand(&mut self, operand: &Operand) -> Result<PlannedOperand, FilterError> {
        match operand {
            Operand::Field(field) => self.plan_field_operand(field),
            Operand::Function { name, args } => self.plan_function_operand(name, args),
            Operand::Macro(name) => {
                if let Some(each) = self.resolve_request_each_operand(name)? {
                    return Ok(each);
                }
                Ok(PlannedOperand::Value(resolve_macro(name, &self.context)?))
            }
            Operand::Value(value) => Ok(PlannedOperand::Value(value.clone())),
        }
    }

    fn resolve_request_each_operand(
        &self,
        name: &str,
    ) -> Result<Option<PlannedOperand>, FilterError> {
        let (base_name, modifier) = split_request_modifier(name)?;
        if modifier != Some(RequestModifier::Each) {
            return Ok(None);
        }

        let Some(field) = base_name.strip_prefix("@request.body.") else {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                "request modifier ':each' is only supported for @request.body.*",
            ));
        };
        if !is_safe_identifier_path(field) {
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe request identifier '{name}'"),
            ));
        }

        let values = self
            .context
            .request
            .body_each_values
            .get(field)
            .cloned()
            .or_else(|| {
                self.context
                    .request
                    .body
                    .get(field)
                    .cloned()
                    .map(|value| vec![value])
            })
            .unwrap_or_default();

        Ok(Some(PlannedOperand::EachValues {
            name: name.to_string(),
            values,
        }))
    }

    fn plan_field_operand(&mut self, field: &str) -> Result<PlannedOperand, FilterError> {
        let (field_name, modifier) = split_field_modifier(field)?;
        if !is_safe_identifier_path(field_name) {
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe identifier '{field}'"),
            ));
        }

        let resolved = apply_field_modifier(field, self.resolve_field(field_name)?, modifier)?;
        self.collect_relation(&resolved);

        Ok(PlannedOperand::Field(PlannedField {
            name: field.to_string(),
            resolved,
        }))
    }

    fn plan_function_operand(
        &mut self,
        name: &str,
        args: &[Operand],
    ) -> Result<PlannedOperand, FilterError> {
        let planned_args = args
            .iter()
            .map(|arg| self.plan_operand(arg))
            .collect::<Result<Vec<_>, _>>()?;
        let resolved_args = planned_args
            .iter()
            .map(planned_operand_to_resolved)
            .collect::<Vec<_>>();

        let kind = match name {
            "strftime" => validate_strftime_args(&resolved_args)?,
            "geoDistance" => validate_geo_distance_args(&resolved_args)?,
            _ => {
                return Err(FilterError::with_kind(
                    FilterErrorKind::InvalidOperator,
                    format!("unknown function '{name}'"),
                ))
            }
        };

        Ok(PlannedOperand::Function {
            name: name.to_string(),
            args: planned_args,
            kind,
        })
    }

    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match self.field_resolver {
            Some(resolver) => {
                let resolved = resolver.resolve_field(field)?;
                if resolved.sql.trim().is_empty() {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::UnsafeIdentifier,
                        format!("field '{field}' resolved to empty SQL"),
                    ));
                }
                Ok(resolved)
            }
            None => Ok(ResolvedField::new(field)),
        }
    }

    fn collect_relation(&mut self, resolved: &ResolvedField) {
        if let Some(relation) = &resolved.relation {
            if !self.relations.contains(relation) {
                self.relations.push(relation.clone());
            }
        }
    }
}

#[derive(Debug, Clone)]
enum SqlParams {
    Positional(Vec<Value>),
    Named {
        params: Vec<NamedParam>,
        names_by_value: HashMap<Value, String>,
    },
}

impl SqlParams {
    fn positional() -> Self {
        Self::Positional(Vec::new())
    }

    fn named() -> Self {
        Self::Named {
            params: Vec::new(),
            names_by_value: HashMap::new(),
        }
    }

    fn bind(&mut self, value: Value) -> String {
        match self {
            Self::Positional(params) => {
                params.push(value);
                "?".to_string()
            }
            Self::Named {
                params,
                names_by_value,
            } => {
                if let Some(name) = names_by_value.get(&value) {
                    return format!(":{name}");
                }

                let name = format!("p{}", params.len());
                names_by_value.insert(value.clone(), name.clone());
                params.push(NamedParam {
                    name: name.clone(),
                    value,
                });
                format!(":{name}")
            }
        }
    }

    fn into_positional(self) -> Vec<Value> {
        match self {
            Self::Positional(params) => params,
            Self::Named { params, .. } => params.into_iter().map(|param| param.value).collect(),
        }
    }

    fn into_named(self) -> Vec<NamedParam> {
        match self {
            Self::Named { params, .. } => params,
            Self::Positional(params) => params
                .into_iter()
                .enumerate()
                .map(|(index, value)| NamedParam {
                    name: format!("p{index}"),
                    value,
                })
                .collect(),
        }
    }
}

struct SqlCompiler<'a> {
    params: SqlParams,
    field_resolver: Option<&'a dyn FieldResolver>,
    context: FilterContext,
}

impl Default for SqlCompiler<'_> {
    fn default() -> Self {
        Self::with_context(FilterContext::default())
    }
}

impl<'a> SqlCompiler<'a> {
    fn with_context(context: FilterContext) -> Self {
        Self {
            params: SqlParams::positional(),
            field_resolver: None,
            context,
        }
    }

    fn with_named_context(context: FilterContext) -> Self {
        Self {
            params: SqlParams::named(),
            field_resolver: None,
            context,
        }
    }

    fn with_resolver_and_context(
        field_resolver: &'a dyn FieldResolver,
        context: FilterContext,
    ) -> Self {
        Self {
            params: SqlParams::positional(),
            field_resolver: Some(field_resolver),
            context,
        }
    }

    fn with_resolver_and_named_context(
        field_resolver: &'a dyn FieldResolver,
        context: FilterContext,
    ) -> Self {
        Self {
            params: SqlParams::named(),
            field_resolver: Some(field_resolver),
            context,
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
            Expr::Compare { left, op, right } => self.compile_compare(left, *op, right),
        }
    }

    fn compile_compare(
        &mut self,
        left: &Operand,
        op: CompareOp,
        right: &Operand,
    ) -> Result<String, FilterError> {
        let left = self.resolve_operand(left)?;
        let right = self.resolve_operand(right)?;

        if left.is_each_match() {
            return self.compile_each_match(&left, op, &right);
        }
        if right.is_each_match() {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier is only supported on the left side of a comparison",
            ));
        }

        validate_compare_operands(&left, op, &right)?;

        if is_any_match_op(op) {
            return self.compile_any_match(&left, op, &right);
        }

        if matches!(op, CompareOp::Eq | CompareOp::Ne)
            && (left.is_null_value() || right.is_null_value())
        {
            return Ok(self.compile_null_equality(&left, op, &right));
        }

        match op {
            CompareOp::Like | CompareOp::NotLike => self.compile_like(&left, op, &right),
            _ if left.is_null_value() || right.is_null_value() => {
                Err(FilterError::new("null can only be used with = or !="))
            }
            _ => {
                let left_sql = self.render_operand(&left);
                let right_sql = self.render_operand(&right);
                Ok(format!("{left_sql} {} {right_sql}", compare_op_sql(op)))
            }
        }
    }

    fn resolve_operand(&self, operand: &Operand) -> Result<ResolvedOperand, FilterError> {
        match operand {
            Operand::Field(field) => {
                let (field_name, modifier) = split_field_modifier(field)?;
                if !is_safe_identifier_path(field_name) {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::UnsafeIdentifier,
                        format!("unsafe identifier '{field}'"),
                    ));
                }

                Ok(ResolvedOperand::Field {
                    name: field.clone(),
                    resolved: apply_field_modifier(
                        field,
                        self.resolve_field(field_name)?,
                        modifier,
                    )?,
                })
            }
            Operand::Function { name, args } => self.resolve_function(name, args),
            Operand::Macro(name) => {
                if let Some(each) = self.resolve_request_each_operand(name)? {
                    return Ok(each);
                }
                Ok(ResolvedOperand::Value(resolve_macro(name, &self.context)?))
            }
            Operand::Value(value) => Ok(ResolvedOperand::Value(value.clone())),
        }
    }

    fn resolve_request_each_operand(
        &self,
        name: &str,
    ) -> Result<Option<ResolvedOperand>, FilterError> {
        let (base_name, modifier) = split_request_modifier(name)?;
        if modifier != Some(RequestModifier::Each) {
            return Ok(None);
        }

        let Some(field) = base_name.strip_prefix("@request.body.") else {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                format!("request modifier ':each' is only supported for @request.body.*"),
            ));
        };
        if !is_safe_identifier_path(field) {
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe request identifier '{name}'"),
            ));
        }

        let values = self
            .context
            .request
            .body_each_values
            .get(field)
            .cloned()
            .or_else(|| {
                self.context
                    .request
                    .body
                    .get(field)
                    .cloned()
                    .map(|value| vec![value])
            })
            .unwrap_or_default();

        Ok(Some(ResolvedOperand::EachValues {
            name: name.to_string(),
            values,
        }))
    }

    fn resolve_function(
        &self,
        name: &str,
        args: &[Operand],
    ) -> Result<ResolvedOperand, FilterError> {
        let resolved_args = args
            .iter()
            .map(|arg| self.resolve_operand(arg))
            .collect::<Result<Vec<_>, _>>()?;

        let kind = match name {
            "strftime" => validate_strftime_args(&resolved_args)?,
            "geoDistance" => validate_geo_distance_args(&resolved_args)?,
            _ => {
                return Err(FilterError::with_kind(
                    FilterErrorKind::InvalidOperator,
                    format!("unknown function '{name}'"),
                ))
            }
        };

        Ok(ResolvedOperand::Function {
            name: name.to_string(),
            args: resolved_args,
            kind,
        })
    }

    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match self.field_resolver {
            Some(resolver) => {
                let resolved = resolver.resolve_field(field)?;
                if resolved.sql.trim().is_empty() {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::UnsafeIdentifier,
                        format!("field '{field}' resolved to empty SQL"),
                    ));
                }
                Ok(resolved)
            }
            None => Ok(ResolvedField::new(field)),
        }
    }

    fn compile_null_equality(
        &mut self,
        left: &ResolvedOperand,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> String {
        let operator = if matches!(op, CompareOp::Ne) {
            "IS NOT"
        } else {
            "IS"
        };

        match (left.is_null_value(), right.is_null_value()) {
            (true, true) => format!("NULL {operator} NULL"),
            (false, true) => {
                let left_sql = self.render_operand(left);
                format!("{left_sql} {operator} NULL")
            }
            (true, false) => {
                let right_sql = self.render_operand(right);
                format!("{right_sql} {operator} NULL")
            }
            (false, false) => unreachable!("null equality requires at least one null operand"),
        }
    }

    fn compile_like(
        &mut self,
        left: &ResolvedOperand,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        let left_sql = self.render_operand(left);
        let right_sql = self.render_like_pattern_operand(right);
        let sql_op = match op {
            CompareOp::Like => "LIKE",
            CompareOp::NotLike => "NOT LIKE",
            _ => return Err(FilterError::new("not a like operator")),
        };
        Ok(format!("{left_sql} {sql_op} {right_sql} ESCAPE '\\'"))
    }

    fn compile_each_match(
        &mut self,
        left: &ResolvedOperand,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        if is_any_match_op(op) {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier cannot be combined with any-match operators",
            ));
        }

        match left {
            ResolvedOperand::Field { .. } => {
                validate_compare_operands(left, op, right)?;
                self.compile_each_field_match(left, op, right)
            }
            ResolvedOperand::EachValues { values, .. } => {
                self.compile_each_value_match(values, op, right)
            }
            ResolvedOperand::Function { .. } | ResolvedOperand::Value(_) => {
                unreachable!("compile_each_match should only be called for operands marked as each")
            }
        }
    }

    fn compile_each_field_match(
        &mut self,
        left: &ResolvedOperand,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        let ResolvedOperand::Field { resolved, .. } = left else {
            unreachable!("field each match requires a field operand");
        };
        let item_sql = self.render_each_item_condition("json_each.value", op, right)?;
        Ok(format!(
            "NOT EXISTS (SELECT 1 FROM json_each({}) WHERE NOT ({item_sql}))",
            resolved.sql
        ))
    }

    fn compile_each_value_match(
        &mut self,
        values: &[Value],
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        if values.is_empty() {
            return Ok("TRUE".to_string());
        }

        let mut parts = Vec::with_capacity(values.len());
        for value in values {
            let left_sql = self.render_operand(&ResolvedOperand::Value(value.clone()));
            parts.push(self.render_each_item_condition(&left_sql, op, right)?);
        }
        Ok(parts.join(" AND "))
    }

    fn render_each_item_condition(
        &mut self,
        item_sql: &str,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        if matches!(op, CompareOp::Eq | CompareOp::Ne) && right.is_null_value() {
            let operator = if matches!(op, CompareOp::Ne) {
                "IS NOT"
            } else {
                "IS"
            };
            return Ok(format!("{item_sql} {operator} NULL"));
        }
        if right.is_null_value() {
            return Err(FilterError::new("null can only be used with = or !="));
        }

        match op {
            CompareOp::Like | CompareOp::NotLike => {
                let right_sql = self.render_like_pattern_operand(right);
                let sql_op = compare_op_sql(op);
                Ok(format!("{item_sql} {sql_op} {right_sql} ESCAPE '\\'"))
            }
            CompareOp::Eq
            | CompareOp::Ne
            | CompareOp::Gt
            | CompareOp::Gte
            | CompareOp::Lt
            | CompareOp::Lte => {
                let right_sql = self.render_operand(right);
                Ok(format!("{item_sql} {} {right_sql}", compare_op_sql(op)))
            }
            _ => Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier cannot be combined with any-match operators",
            )),
        }
    }

    fn render_operand(&mut self, operand: &ResolvedOperand) -> String {
        match operand {
            ResolvedOperand::Field { resolved, .. } => resolved.sql.clone(),
            ResolvedOperand::Function { name, args, .. } => self.render_function(name, args),
            ResolvedOperand::Value(Value::String(value)) => {
                self.params.bind(Value::String(value.clone()))
            }
            ResolvedOperand::Value(Value::Number(value)) => {
                self.params.bind(Value::Number(value.clone()))
            }
            ResolvedOperand::Value(Value::Bool(true)) => "TRUE".to_string(),
            ResolvedOperand::Value(Value::Bool(false)) => "FALSE".to_string(),
            ResolvedOperand::Value(Value::Null) => "NULL".to_string(),
            ResolvedOperand::EachValues { .. } => {
                unreachable!(":each request values must be rendered by compile_each_match")
            }
        }
    }

    fn render_like_pattern_operand(&mut self, operand: &ResolvedOperand) -> String {
        match operand {
            ResolvedOperand::Field { resolved, .. } => format!("('%' || {} || '%')", resolved.sql),
            ResolvedOperand::Function { name, args, .. } => {
                format!("('%' || {} || '%')", self.render_function(name, args))
            }
            ResolvedOperand::Value(value) => self.params.bind(wrap_like(value)),
            ResolvedOperand::EachValues { .. } => {
                unreachable!(":each request values must be rendered by compile_each_match")
            }
        }
    }

    fn render_function(&mut self, name: &str, args: &[ResolvedOperand]) -> String {
        match name {
            "strftime" => {
                let rendered_args = args
                    .iter()
                    .map(|arg| self.render_operand(arg))
                    .collect::<Vec<_>>();
                format!("strftime({})", rendered_args.join(","))
            }
            "geoDistance" => {
                let lat_a = self.render_operand(&args[1]);
                let lat_b = self.render_operand(&args[3]);
                let lon_b = self.render_operand(&args[2]);
                let lon_a = self.render_operand(&args[0]);
                let lat_a_repeat = self.render_operand(&args[1]);
                let lat_b_repeat = self.render_operand(&args[3]);

                format!(
                    "(6371 * acos(cos(radians({lat_a})) * cos(radians({lat_b})) * cos(radians({lon_b}) - radians({lon_a})) + sin(radians({lat_a_repeat})) * sin(radians({lat_b_repeat}))))"
                )
            }
            _ => unreachable!("unsupported functions are rejected during resolution"),
        }
    }

    fn compile_any_match(
        &mut self,
        left: &ResolvedOperand,
        op: CompareOp,
        right: &ResolvedOperand,
    ) -> Result<String, FilterError> {
        let field_sql = match left {
            ResolvedOperand::Field { resolved, .. } => resolved.sql.clone(),
            ResolvedOperand::Function { .. }
            | ResolvedOperand::Value(_)
            | ResolvedOperand::EachValues { .. } => {
                return Err(FilterError::with_kind(
                    FilterErrorKind::InvalidOperator,
                    "any-match operators require a field on the left side",
                ))
            }
        };

        let inner_op = any_match_sql_op(op)?;
        let (right_sql, escape_clause) = match op {
            CompareOp::AnyLike | CompareOp::AnyNotLike => {
                (self.render_like_pattern_operand(right), " ESCAPE '\\'")
            }
            _ => (self.render_operand(right), ""),
        };
        Ok(format!(
            "EXISTS (SELECT 1 FROM json_each({field_sql}) WHERE json_each.value {inner_op} {right_sql}{escape_clause})"
        ))
    }
}

struct PlanSqlRenderer<'a> {
    params: SqlParams,
    relations: &'a [RelationTraversal],
    options: RelationSqlOptions,
}

struct RelationRenderContext<'a> {
    relation: &'a RelationTraversal,
    relation_index: usize,
}

impl<'a> PlanSqlRenderer<'a> {
    fn new(relations: &'a [RelationTraversal], options: RelationSqlOptions) -> Self {
        Self {
            params: SqlParams::positional(),
            relations,
            options,
        }
    }

    fn new_named(relations: &'a [RelationTraversal], options: RelationSqlOptions) -> Self {
        Self {
            params: SqlParams::named(),
            relations,
            options,
        }
    }

    fn render_expr(&mut self, expr: &PlannedExpr) -> Result<String, FilterError> {
        match expr {
            PlannedExpr::Binary { left, op, right } => {
                let left = self.render_expr(left)?;
                let right = self.render_expr(right)?;
                let op = match op {
                    PlanLogicOp::And => "AND",
                    PlanLogicOp::Or => "OR",
                };
                Ok(format!("{left} {op} {right}"))
            }
            PlannedExpr::Group(inner) => Ok(format!("({})", self.render_expr(inner)?)),
            PlannedExpr::Compare { left, op, right } => self.render_compare(left, *op, right),
        }
    }

    fn render_compare(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
    ) -> Result<String, FilterError> {
        let Some(relation) = self.comparison_relation(left, right)? else {
            return self.render_plain_compare(left, op, right, None);
        };

        let relation_index = self.relation_index_for_chain(relation)?;
        let context = RelationRenderContext {
            relation,
            relation_index,
        };
        let inner_op = if relation_has_multiple_step(relation) && is_plan_any_match_op(op) {
            plan_any_match_inner_op(op)?
        } else {
            op
        };
        let inner_sql = self.render_plain_compare(left, inner_op, right, Some(&context))?;

        if relation_has_multiple_step(relation) && !is_plan_any_match_op(op) {
            self.render_relation_for_all(&context, inner_sql)
        } else {
            self.render_relation_exists(&context, inner_sql)
        }
    }

    fn comparison_relation<'b>(
        &self,
        left: &'b PlannedOperand,
        right: &'b PlannedOperand,
    ) -> Result<Option<&'b RelationTraversal>, FilterError> {
        let mut relations = Vec::new();
        collect_planned_operand_relations(left, &mut relations);
        collect_planned_operand_relations(right, &mut relations);

        let Some(relation) = relations.first().copied() else {
            return Ok(None);
        };

        if relations
            .iter()
            .any(|candidate| !same_relation_steps(relation, candidate))
        {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "relation SQL rendering currently supports one relation chain per comparison",
            ));
        }

        validate_relation_chain(relation)?;
        Ok(Some(relation))
    }

    fn render_plain_compare(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        if planned_operand_is_each_match(left) {
            return self.render_each_match(left, op, right, relation_context);
        }
        if planned_operand_is_each_match(right) {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier is only supported on the left side of a comparison",
            ));
        }

        if is_plan_any_match_op(op) {
            return self.render_any_match(left, op, right, relation_context);
        }

        if matches!(op, PlanCompareOp::Eq | PlanCompareOp::Ne)
            && (planned_operand_is_null_value(left) || planned_operand_is_null_value(right))
        {
            return self.render_null_equality(left, op, right, relation_context);
        }

        match op {
            PlanCompareOp::Like | PlanCompareOp::NotLike => {
                self.render_like(left, op, right, relation_context)
            }
            _ if planned_operand_is_null_value(left) || planned_operand_is_null_value(right) => {
                Err(FilterError::new("null can only be used with = or !="))
            }
            _ => {
                let left_sql = self.render_operand(left, relation_context)?;
                let right_sql = self.render_operand(right, relation_context)?;
                Ok(format!(
                    "{left_sql} {} {right_sql}",
                    plan_compare_op_sql(op)
                ))
            }
        }
    }

    fn render_null_equality(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        let operator = if matches!(op, PlanCompareOp::Ne) {
            "IS NOT"
        } else {
            "IS"
        };

        match (
            planned_operand_is_null_value(left),
            planned_operand_is_null_value(right),
        ) {
            (true, true) => Ok(format!("NULL {operator} NULL")),
            (false, true) => {
                let left_sql = self.render_operand(left, relation_context)?;
                Ok(format!("{left_sql} {operator} NULL"))
            }
            (true, false) => {
                let right_sql = self.render_operand(right, relation_context)?;
                Ok(format!("{right_sql} {operator} NULL"))
            }
            (false, false) => unreachable!("null equality requires at least one null operand"),
        }
    }

    fn render_like(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        let left_sql = self.render_operand(left, relation_context)?;
        let right_sql = self.render_like_pattern_operand(right, relation_context)?;
        let sql_op = match op {
            PlanCompareOp::Like => "LIKE",
            PlanCompareOp::NotLike => "NOT LIKE",
            _ => return Err(FilterError::new("not a like operator")),
        };
        Ok(format!("{left_sql} {sql_op} {right_sql} ESCAPE '\\'"))
    }

    fn render_each_match(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        if is_plan_any_match_op(op) {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier cannot be combined with any-match operators",
            ));
        }

        match left {
            PlannedOperand::Field(_) => {
                let field_sql = self.render_operand(left, relation_context)?;
                let item_sql = self.render_each_item_condition(
                    "json_each.value",
                    op,
                    right,
                    relation_context,
                )?;
                Ok(format!(
                    "NOT EXISTS (SELECT 1 FROM json_each({field_sql}) WHERE NOT ({item_sql}))"
                ))
            }
            PlannedOperand::EachValues { values, .. } => {
                self.render_each_value_match(values, op, right, relation_context)
            }
            PlannedOperand::Function { .. } | PlannedOperand::Value(_) => {
                Err(FilterError::with_kind(
                    FilterErrorKind::InvalidOperator,
                    "':each' modifier requires a field on the left side",
                ))
            }
        }
    }

    fn render_each_value_match(
        &mut self,
        values: &[Value],
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        if values.is_empty() {
            return Ok("TRUE".to_string());
        }

        let mut parts = Vec::with_capacity(values.len());
        for value in values {
            let left_sql =
                self.render_operand(&PlannedOperand::Value(value.clone()), relation_context)?;
            parts.push(self.render_each_item_condition(&left_sql, op, right, relation_context)?);
        }
        Ok(parts.join(" AND "))
    }

    fn render_each_item_condition(
        &mut self,
        item_sql: &str,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        if matches!(op, PlanCompareOp::Eq | PlanCompareOp::Ne)
            && planned_operand_is_null_value(right)
        {
            let operator = if matches!(op, PlanCompareOp::Ne) {
                "IS NOT"
            } else {
                "IS"
            };
            return Ok(format!("{item_sql} {operator} NULL"));
        }
        if planned_operand_is_null_value(right) {
            return Err(FilterError::new("null can only be used with = or !="));
        }

        match op {
            PlanCompareOp::Like | PlanCompareOp::NotLike => {
                let right_sql = self.render_like_pattern_operand(right, relation_context)?;
                Ok(format!(
                    "{item_sql} {} {right_sql} ESCAPE '\\'",
                    plan_compare_op_sql(op)
                ))
            }
            PlanCompareOp::Eq
            | PlanCompareOp::Ne
            | PlanCompareOp::Gt
            | PlanCompareOp::Gte
            | PlanCompareOp::Lt
            | PlanCompareOp::Lte => {
                let right_sql = self.render_operand(right, relation_context)?;
                Ok(format!(
                    "{item_sql} {} {right_sql}",
                    plan_compare_op_sql(op)
                ))
            }
            _ => Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "':each' modifier cannot be combined with any-match operators",
            )),
        }
    }

    fn render_any_match(
        &mut self,
        left: &PlannedOperand,
        op: PlanCompareOp,
        right: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        let PlannedOperand::Field(_) = left else {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "any-match operators require a field on the left side",
            ));
        };
        let field_sql = self.render_operand(left, relation_context)?;
        let inner_op = plan_any_match_sql_op(op)?;
        let (right_sql, escape_clause) = match op {
            PlanCompareOp::AnyLike | PlanCompareOp::AnyNotLike => (
                self.render_like_pattern_operand(right, relation_context)?,
                " ESCAPE '\\'",
            ),
            _ => (self.render_operand(right, relation_context)?, ""),
        };

        Ok(format!(
            "EXISTS (SELECT 1 FROM json_each({field_sql}) WHERE json_each.value {inner_op} {right_sql}{escape_clause})"
        ))
    }

    fn render_operand(
        &mut self,
        operand: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        match operand {
            PlannedOperand::Field(field) => self.render_field(field, relation_context),
            PlannedOperand::Function { name, args, .. } => {
                self.render_function(name, args, relation_context)
            }
            PlannedOperand::Value(Value::String(value)) => {
                Ok(self.params.bind(Value::String(value.clone())))
            }
            PlannedOperand::Value(Value::Number(value)) => {
                Ok(self.params.bind(Value::Number(value.clone())))
            }
            PlannedOperand::Value(Value::Bool(true)) => Ok("TRUE".to_string()),
            PlannedOperand::Value(Value::Bool(false)) => Ok("FALSE".to_string()),
            PlannedOperand::Value(Value::Null) => Ok("NULL".to_string()),
            PlannedOperand::EachValues { .. } => {
                unreachable!(":each request values must be rendered by render_each_match")
            }
        }
    }

    fn render_field(
        &self,
        field: &PlannedField,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        let Some(field_relation) = field.relation() else {
            return Ok(field.resolved.sql.clone());
        };

        let Some(context) = relation_context else {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                format!(
                    "relation field '{}' cannot be rendered outside its relation subquery",
                    field.name
                ),
            ));
        };

        if !same_relation_steps(context.relation, field_relation) {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "relation SQL rendering currently supports one relation chain per comparison",
            ));
        }

        self.relation_leaf_sql(context, field_relation)
    }

    fn render_like_pattern_operand(
        &mut self,
        operand: &PlannedOperand,
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        match operand {
            PlannedOperand::Field(_) | PlannedOperand::Function { .. } => {
                let rendered = self.render_operand(operand, relation_context)?;
                Ok(format!("('%' || {rendered} || '%')"))
            }
            PlannedOperand::Value(value) => Ok(self.params.bind(wrap_like(value))),
            PlannedOperand::EachValues { .. } => {
                unreachable!(":each request values must be rendered by render_each_match")
            }
        }
    }

    fn render_function(
        &mut self,
        name: &str,
        args: &[PlannedOperand],
        relation_context: Option<&RelationRenderContext<'_>>,
    ) -> Result<String, FilterError> {
        match name {
            "strftime" => {
                let rendered_args = args
                    .iter()
                    .map(|arg| self.render_operand(arg, relation_context))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("strftime({})", rendered_args.join(",")))
            }
            "geoDistance" => {
                if args.len() != 4 {
                    return Err(FilterError::new(format!(
                        "[geoDistance] expected 4 arguments, got {}",
                        args.len()
                    )));
                }

                let lat_a = self.render_operand(&args[1], relation_context)?;
                let lat_b = self.render_operand(&args[3], relation_context)?;
                let lon_b = self.render_operand(&args[2], relation_context)?;
                let lon_a = self.render_operand(&args[0], relation_context)?;
                let lat_a_repeat = self.render_operand(&args[1], relation_context)?;
                let lat_b_repeat = self.render_operand(&args[3], relation_context)?;

                Ok(format!(
                    "(6371 * acos(cos(radians({lat_a})) * cos(radians({lat_b})) * cos(radians({lon_b}) - radians({lon_a})) + sin(radians({lat_a_repeat})) * sin(radians({lat_b_repeat}))))"
                ))
            }
            _ => Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                format!("unknown function '{name}'"),
            )),
        }
    }

    fn render_relation_exists(
        &self,
        context: &RelationRenderContext<'_>,
        inner_sql: String,
    ) -> Result<String, FilterError> {
        validate_relation_chain(context.relation)?;

        let from_clause = context
            .relation
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                let target_table = quote_safe_identifier_part(&step.target_collection)?;
                let alias = self.relation_alias_sql(context.relation_index, index);
                Ok(format!("{target_table} AS {alias}"))
            })
            .collect::<Result<Vec<_>, FilterError>>()?
            .join(", ");

        let mut conditions = self.relation_link_conditions(context)?;
        conditions.push(inner_sql);

        Ok(format!(
            "EXISTS (SELECT 1 FROM {from_clause} WHERE {})",
            conditions.join(" AND ")
        ))
    }

    fn render_relation_for_all(
        &self,
        context: &RelationRenderContext<'_>,
        inner_sql: String,
    ) -> Result<String, FilterError> {
        validate_relation_chain(context.relation)?;

        let from_clause = context
            .relation
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                let target_table = quote_safe_identifier_part(&step.target_collection)?;
                let alias = self.relation_alias_sql(context.relation_index, index);
                Ok(format!("{target_table} AS {alias}"))
            })
            .collect::<Result<Vec<_>, FilterError>>()?
            .join(", ");

        let mut conditions = self.relation_link_conditions(context)?;
        conditions.push(format!("NOT ({inner_sql})"));

        Ok(format!(
            "NOT EXISTS (SELECT 1 FROM {from_clause} WHERE {})",
            conditions.join(" AND ")
        ))
    }

    fn relation_link_conditions(
        &self,
        context: &RelationRenderContext<'_>,
    ) -> Result<Vec<String>, FilterError> {
        context
            .relation
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| {
                let source_alias = if index == 0 {
                    self.root_alias_sql(step)?
                } else {
                    self.relation_alias_sql(context.relation_index, index - 1)
                };
                let target_alias = self.relation_alias_sql(context.relation_index, index);
                let source_field = quote_safe_identifier_part(&step.source_field)?;
                let target_field = quote_safe_identifier_part(&step.target_field)?;

                match step.multiplicity {
                    RelationMultiplicity::Single => Ok(format!(
                        "{target_alias}.{target_field} = {source_alias}.{source_field}"
                    )),
                    RelationMultiplicity::Multiple => {
                        let array_alias =
                            self.relation_array_alias_sql(context.relation_index, index);
                        let value_field = quote_identifier_part("value");

                        Ok(format!(
                            "EXISTS (SELECT 1 FROM json_each({source_alias}.{source_field}) AS {array_alias} WHERE {array_alias}.{value_field} = {target_alias}.{target_field})"
                        ))
                    }
                }
            })
            .collect()
    }

    fn relation_leaf_sql(
        &self,
        context: &RelationRenderContext<'_>,
        relation: &RelationTraversal,
    ) -> Result<String, FilterError> {
        validate_relation_chain(context.relation)?;

        let last_step_index = relation.steps.len() - 1;
        let alias = self.relation_alias_sql(context.relation_index, last_step_index);
        let leaf_field = quote_safe_identifier_part(&relation.leaf_field)?;
        Ok(format!("{alias}.{leaf_field}"))
    }

    fn root_alias_sql(&self, step: &RelationStep) -> Result<String, FilterError> {
        let alias = self
            .options
            .root_alias
            .as_deref()
            .unwrap_or(&step.source_collection);
        quote_safe_identifier_part(alias)
    }

    fn relation_alias_sql(&self, relation_index: usize, step_index: usize) -> String {
        quote_identifier_part(&format!("__rb_rel_{relation_index}_{step_index}"))
    }

    fn relation_array_alias_sql(&self, relation_index: usize, step_index: usize) -> String {
        quote_identifier_part(&format!("__rb_rel_{relation_index}_{step_index}_each"))
    }

    fn relation_index_for_chain(&self, relation: &RelationTraversal) -> Result<usize, FilterError> {
        self.relations
            .iter()
            .position(|candidate| same_relation_steps(candidate, relation))
            .ok_or_else(|| {
                FilterError::with_kind(
                    FilterErrorKind::InvalidOperator,
                    format!(
                        "relation '{}' is missing from the filter plan",
                        relation.field_path
                    ),
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedOperand {
    Field {
        name: String,
        resolved: ResolvedField,
    },
    Function {
        name: String,
        args: Vec<ResolvedOperand>,
        kind: FieldKind,
    },
    Value(Value),
    EachValues {
        name: String,
        values: Vec<Value>,
    },
}

impl ResolvedOperand {
    fn as_value(&self) -> Option<&Value> {
        match self {
            ResolvedOperand::Value(value) => Some(value),
            ResolvedOperand::Field { .. }
            | ResolvedOperand::Function { .. }
            | ResolvedOperand::EachValues { .. } => None,
        }
    }

    fn is_null_value(&self) -> bool {
        matches!(self, ResolvedOperand::Value(Value::Null))
    }

    fn is_each_match(&self) -> bool {
        match self {
            ResolvedOperand::Field { resolved, .. } => resolved.each,
            ResolvedOperand::EachValues { .. } => true,
            ResolvedOperand::Function { .. } | ResolvedOperand::Value(_) => false,
        }
    }

    fn kind(&self) -> Option<FieldKind> {
        match self {
            ResolvedOperand::Field { resolved, .. } => resolved.kind,
            ResolvedOperand::Function { kind, .. } => Some(*kind),
            ResolvedOperand::Value(_) | ResolvedOperand::EachValues { .. } => None,
        }
    }

    fn name_for_errors(&self) -> &str {
        match self {
            ResolvedOperand::Field { name, .. } => name,
            ResolvedOperand::Function { name, .. } => name,
            ResolvedOperand::Value(_) => "literal",
            ResolvedOperand::EachValues { name, .. } => name,
        }
    }
}

fn planned_operand_to_resolved(operand: &PlannedOperand) -> ResolvedOperand {
    match operand {
        PlannedOperand::Field(field) => ResolvedOperand::Field {
            name: field.name.clone(),
            resolved: field.resolved.clone(),
        },
        PlannedOperand::Function { name, args, kind } => ResolvedOperand::Function {
            name: name.clone(),
            args: args.iter().map(planned_operand_to_resolved).collect(),
            kind: *kind,
        },
        PlannedOperand::Value(value) => ResolvedOperand::Value(value.clone()),
        PlannedOperand::EachValues { name, values } => ResolvedOperand::EachValues {
            name: name.clone(),
            values: values.clone(),
        },
    }
}

fn validate_compare_operands(
    left: &ResolvedOperand,
    op: CompareOp,
    right: &ResolvedOperand,
) -> Result<(), FilterError> {
    validate_compare_operands_with_options(left, op, right, false)
}

fn validate_plan_compare_operands(
    left: &ResolvedOperand,
    op: CompareOp,
    right: &ResolvedOperand,
) -> Result<(), FilterError> {
    validate_compare_operands_with_options(left, op, right, true)
}

fn validate_compare_operands_with_options(
    left: &ResolvedOperand,
    op: CompareOp,
    right: &ResolvedOperand,
    allow_relation_any_match: bool,
) -> Result<(), FilterError> {
    let left_relation_any_match = allow_relation_any_match
        && is_any_match_op(op)
        && resolved_operand_has_multiple_relation(left);
    match left {
        ResolvedOperand::Field { .. } | ResolvedOperand::Function { .. } => {
            if let Some(kind) = left.kind() {
                let validation_op = if left_relation_any_match {
                    compare_any_match_inner_op(op)?
                } else {
                    op
                };
                validate_field_operation(
                    left.name_for_errors(),
                    kind,
                    validation_op,
                    right.as_value(),
                )?;
            };
        }
        ResolvedOperand::Value(_) | ResolvedOperand::EachValues { .. } if is_any_match_op(op) => {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                "any-match operators require a field on the left side",
            ))
        }
        ResolvedOperand::Value(_) | ResolvedOperand::EachValues { .. } => {}
    }

    if is_any_match_op(op) {
        return Ok(());
    }

    if let ResolvedOperand::Field { .. } | ResolvedOperand::Function { .. } = right {
        if let Some(kind) = right.kind() {
            validate_field_operation(right.name_for_errors(), kind, op, left.as_value())?;
        };
    }

    Ok(())
}

fn resolved_operand_has_multiple_relation(operand: &ResolvedOperand) -> bool {
    match operand {
        ResolvedOperand::Field { resolved, .. } => resolved
            .relation
            .as_ref()
            .is_some_and(relation_has_multiple_step),
        ResolvedOperand::Function { args, .. } => {
            args.iter().any(resolved_operand_has_multiple_relation)
        }
        ResolvedOperand::Value(_) | ResolvedOperand::EachValues { .. } => false,
    }
}

fn validate_strftime_args(args: &[ResolvedOperand]) -> Result<FieldKind, FilterError> {
    if args.is_empty() {
        return Err(FilterError::new("[strftime] expected at least 1 argument"));
    }
    if args.len() > 10 {
        return Err(FilterError::new("[strftime] too many arguments"));
    }
    if !matches!(args.first(), Some(ResolvedOperand::Value(Value::String(_)))) {
        return Err(FilterError::new(
            "[strftime] expects the first argument to be a format string",
        ));
    }

    for (index, arg) in args.iter().enumerate().skip(2) {
        if !matches!(arg, ResolvedOperand::Value(Value::String(_))) {
            return Err(FilterError::new(format!(
                "[strftime] modifier argument {index} must be a string"
            )));
        }
    }

    Ok(FieldKind::Text)
}

fn validate_geo_distance_args(args: &[ResolvedOperand]) -> Result<FieldKind, FilterError> {
    if args.len() != 4 {
        return Err(FilterError::new(format!(
            "[geoDistance] expected 4 arguments, got {}",
            args.len()
        )));
    }

    for (index, arg) in args.iter().enumerate() {
        match arg {
            ResolvedOperand::Value(Value::Number(_)) => {}
            ResolvedOperand::Field { resolved, .. }
                if resolved.kind.is_none() || resolved.kind == Some(FieldKind::Number) => {}
            ResolvedOperand::Function { kind, .. } if *kind == FieldKind::Number => {}
            _ => {
                return Err(FilterError::new(format!(
                    "[geoDistance] argument {index} must be a number or numeric field"
                )))
            }
        }
    }

    Ok(FieldKind::Number)
}

fn resolve_macro(name: &str, context: &FilterContext) -> Result<Value, FilterError> {
    let now = context.now;
    let value = match name {
        "@now" => Value::String(now.to_pocketbase_string()),
        "@yesterday" => Value::String(now.add_days(-1).to_pocketbase_string()),
        "@tomorrow" => Value::String(now.add_days(1).to_pocketbase_string()),
        "@second" => Value::Number(now.second.to_string()),
        "@minute" => Value::Number(now.minute.to_string()),
        "@hour" => Value::Number(now.hour.to_string()),
        "@day" => Value::Number(now.day.to_string()),
        "@month" => Value::Number(now.month.to_string()),
        "@weekday" => Value::Number(now.weekday().to_string()),
        "@year" => Value::Number(now.year.to_string()),
        "@todayStart" => Value::String(now.date_at(0, 0, 0, 0).to_pocketbase_string()),
        "@todayEnd" => Value::String(now.date_at(23, 59, 59, 999).to_pocketbase_string()),
        "@monthStart" => Value::String(now.month_start().to_pocketbase_string()),
        "@monthEnd" => Value::String(now.month_end().to_pocketbase_string()),
        "@yearStart" => Value::String(now.year_start().to_pocketbase_string()),
        "@yearEnd" => Value::String(now.year_end().to_pocketbase_string()),
        _ if name.starts_with("@request") => return resolve_request_identifier(name, context),
        _ => {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                format!("unknown macro '{name}'"),
            ))
        }
    };

    Ok(value)
}

fn resolve_request_identifier(name: &str, context: &FilterContext) -> Result<Value, FilterError> {
    let request = &context.request;
    let (base_name, modifier) = split_request_modifier(name)?;

    if base_name == "@request.context" {
        reject_request_modifier(name, modifier)?;
        return Ok(Value::String(request.context.clone()));
    }

    if base_name == "@request.method" {
        reject_request_modifier(name, modifier)?;
        return Ok(Value::String(request.method.clone()));
    }

    if let Some(field) = base_name.strip_prefix("@request.auth.") {
        return request_map_value(name, field, &request.auth, modifier);
    }

    if let Some(field) = base_name.strip_prefix("@request.query.") {
        return request_map_value(name, field, &request.query, modifier);
    }

    if let Some(field) = base_name.strip_prefix("@request.headers.") {
        return request_map_value(
            name,
            &normalize_header_key(field),
            &request.headers,
            modifier,
        );
    }

    if let Some(field) = base_name.strip_prefix("@request.body.") {
        return request_body_value(
            name,
            field,
            &request.body,
            &request.body_lengths,
            &request.body_changes,
            modifier,
        );
    }

    Err(FilterError::with_kind(
        FilterErrorKind::InvalidLiteral,
        format!("unknown request identifier '{name}'"),
    ))
}

fn split_request_modifier(name: &str) -> Result<(&str, Option<RequestModifier>), FilterError> {
    let Some((base, modifier)) = name.rsplit_once(':') else {
        return Ok((name, None));
    };

    let modifier = match modifier {
        "isset" => RequestModifier::Isset,
        "changed" => RequestModifier::Changed,
        "each" => RequestModifier::Each,
        "lower" => RequestModifier::Lower,
        "length" => RequestModifier::Length,
        _ => {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                format!("unsupported request modifier ':{modifier}'"),
            ))
        }
    };

    Ok((base, Some(modifier)))
}

fn reject_request_modifier(
    name: &str,
    modifier: Option<RequestModifier>,
) -> Result<(), FilterError> {
    if let Some(modifier) = modifier {
        return Err(FilterError::with_kind(
            FilterErrorKind::InvalidLiteral,
            format!(
                "unsupported request modifier ':{}' for '{name}'",
                request_modifier_name(modifier)
            ),
        ));
    }

    Ok(())
}

fn request_map_value(
    name: &str,
    field: &str,
    values: &HashMap<String, Value>,
    modifier: Option<RequestModifier>,
) -> Result<Value, FilterError> {
    if !is_safe_identifier_path(field) {
        return Err(FilterError::with_kind(
            FilterErrorKind::UnsafeIdentifier,
            format!("unsafe request identifier '{name}'"),
        ));
    }

    match modifier {
        Some(RequestModifier::Isset) => return Ok(Value::Bool(values.contains_key(field))),
        Some(RequestModifier::Lower) => return Ok(lower_request_value(values.get(field))),
        Some(RequestModifier::Changed)
        | Some(RequestModifier::Each)
        | Some(RequestModifier::Length) => {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                format!(
                    "request modifier ':{}' is only supported for @request.body.*",
                    request_modifier_name(modifier.unwrap())
                ),
            ))
        }
        None => {}
    };

    Ok(values
        .get(field)
        .cloned()
        .unwrap_or_else(|| Value::String(String::new())))
}

fn request_body_value(
    name: &str,
    field: &str,
    values: &HashMap<String, Value>,
    lengths: &HashMap<String, usize>,
    changes: &HashMap<String, bool>,
    modifier: Option<RequestModifier>,
) -> Result<Value, FilterError> {
    if !is_safe_identifier_path(field) {
        return Err(FilterError::with_kind(
            FilterErrorKind::UnsafeIdentifier,
            format!("unsafe request identifier '{name}'"),
        ));
    }

    match modifier {
        Some(RequestModifier::Isset) => Ok(Value::Bool(values.contains_key(field))),
        Some(RequestModifier::Changed) => Ok(Value::Bool(
            values.contains_key(field) && changes.get(field).copied().unwrap_or(false),
        )),
        Some(RequestModifier::Each) => Err(FilterError::with_kind(
            FilterErrorKind::InvalidLiteral,
            "request modifier ':each' must be used as the left operand of a comparison",
        )),
        Some(RequestModifier::Lower) => Ok(lower_request_value(values.get(field))),
        Some(RequestModifier::Length) => Ok(Value::Number(
            lengths.get(field).copied().unwrap_or_default().to_string(),
        )),
        None => Ok(values
            .get(field)
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()))),
    }
}

fn lower_request_value(value: Option<&Value>) -> Value {
    Value::String(request_value_to_string(value).to_ascii_lowercase())
}

fn request_value_to_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Null) | None => String::new(),
    }
}

fn request_modifier_name(modifier: RequestModifier) -> &'static str {
    match modifier {
        RequestModifier::Isset => "isset",
        RequestModifier::Changed => "changed",
        RequestModifier::Each => "each",
        RequestModifier::Lower => "lower",
        RequestModifier::Length => "length",
    }
}

fn normalize_header_key(field: impl Into<String>) -> String {
    field.into().to_ascii_lowercase().replace('-', "_")
}

fn split_field_modifier(field: &str) -> Result<(&str, Option<FieldModifier>), FilterError> {
    let Some((base, modifier)) = field.rsplit_once(':') else {
        return Ok((field, None));
    };

    let modifier = match modifier {
        "lower" => FieldModifier::Lower,
        "length" => FieldModifier::Length,
        "each" => FieldModifier::Each,
        _ => {
            return Err(FilterError::with_kind(
                FilterErrorKind::InvalidLiteral,
                format!("unsupported field modifier ':{modifier}'"),
            ))
        }
    };

    Ok((base, Some(modifier)))
}

fn apply_field_modifier(
    field: &str,
    mut resolved: ResolvedField,
    modifier: Option<FieldModifier>,
) -> Result<ResolvedField, FilterError> {
    let Some(modifier) = modifier else {
        return Ok(resolved);
    };

    if resolved.relation.is_some() {
        return Err(FilterError::with_kind(
            FilterErrorKind::InvalidOperator,
            format!(
                "field modifier ':{}' is not supported on relation field '{field}' yet",
                field_modifier_name(modifier),
            ),
        ));
    }

    match modifier {
        FieldModifier::Lower => {
            if let Some(kind) = resolved.kind {
                if kind != FieldKind::Text {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::InvalidOperator,
                        "field modifier ':lower' is only allowed on text fields",
                    ));
                }
            }
            resolved.sql = format!("LOWER({})", resolved.sql);
            resolved.kind = Some(FieldKind::Text);
        }
        FieldModifier::Length => {
            if let Some(kind) = resolved.kind {
                if !matches!(
                    kind,
                    FieldKind::Array | FieldKind::Relation | FieldKind::Json
                ) {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::InvalidOperator,
                        "field modifier ':length' is only allowed on array-like fields",
                    ));
                }
            }
            resolved.sql = format!("COALESCE(json_array_length({}), 0)", resolved.sql);
            resolved.kind = Some(FieldKind::Number);
        }
        FieldModifier::Each => {
            if let Some(kind) = resolved.kind {
                if !matches!(
                    kind,
                    FieldKind::Array | FieldKind::Relation | FieldKind::Json
                ) {
                    return Err(FilterError::with_kind(
                        FilterErrorKind::InvalidOperator,
                        "field modifier ':each' is only allowed on array-like fields",
                    ));
                }
            }
            resolved.kind = Some(FieldKind::Text);
            resolved.each = true;
        }
    }

    Ok(resolved)
}

fn field_modifier_name(modifier: FieldModifier) -> &'static str {
    match modifier {
        FieldModifier::Lower => "lower",
        FieldModifier::Length => "length",
        FieldModifier::Each => "each",
    }
}

fn validate_field_operation(
    field: &str,
    kind: FieldKind,
    op: CompareOp,
    value: Option<&Value>,
) -> Result<(), FilterError> {
    if is_any_match_op(op) {
        return if matches!(kind, FieldKind::Array | FieldKind::Json) {
            if let Some(value) = value {
                validate_array_literal(field, value)?;
            }
            Ok(())
        } else {
            Err(FilterError::with_kind(
                FilterErrorKind::InvalidOperator,
                format!(
                    "any-match operator {} is only allowed on array fields",
                    op_symbol(op)
                ),
            ))
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
                Some(Value::String(_) | Value::Null) | None => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected string"))),
            }
        }
        FieldKind::Relation => {
            validate_operator_allowed(kind, op, &[CompareOp::Eq, CompareOp::Ne])?;
            match value {
                Some(Value::String(_) | Value::Null) | None => Ok(()),
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
                Some(Value::String(_) | Value::Null) | None => Ok(()),
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
                Some(Value::Number(_) | Value::Null) | None => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected number"))),
            }
        }
        FieldKind::Bool => {
            validate_operator_allowed(kind, op, &[CompareOp::Eq, CompareOp::Ne])?;
            match value {
                Some(Value::Bool(_) | Value::Null) | None => Ok(()),
                _ => Err(FilterError::new(format!("field '{field}' expected bool"))),
            }
        }
        FieldKind::Array => Err(FilterError::new(format!(
            "operator {} is not allowed on array field '{field}'; use any-match operators",
            op_symbol(op)
        ))),
        FieldKind::Json => Ok(()),
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

fn compare_any_match_inner_op(op: CompareOp) -> Result<CompareOp, FilterError> {
    match op {
        CompareOp::AnyEq => Ok(CompareOp::Eq),
        CompareOp::AnyNe => Ok(CompareOp::Ne),
        CompareOp::AnyGt => Ok(CompareOp::Gt),
        CompareOp::AnyGte => Ok(CompareOp::Gte),
        CompareOp::AnyLt => Ok(CompareOp::Lt),
        CompareOp::AnyLte => Ok(CompareOp::Lte),
        CompareOp::AnyLike => Ok(CompareOp::Like),
        CompareOp::AnyNotLike => Ok(CompareOp::NotLike),
        _ => Err(FilterError::new("not an any-match operator")),
    }
}

fn planned_operand_is_null_value(operand: &PlannedOperand) -> bool {
    matches!(operand, PlannedOperand::Value(Value::Null))
}

fn planned_operand_is_each_match(operand: &PlannedOperand) -> bool {
    match operand {
        PlannedOperand::Field(PlannedField {
            resolved: ResolvedField { each: true, .. },
            ..
        })
        | PlannedOperand::EachValues { .. } => true,
        PlannedOperand::Field(_) | PlannedOperand::Function { .. } | PlannedOperand::Value(_) => {
            false
        }
    }
}

fn is_plan_any_match_op(op: PlanCompareOp) -> bool {
    matches!(
        op,
        PlanCompareOp::AnyEq
            | PlanCompareOp::AnyNe
            | PlanCompareOp::AnyGt
            | PlanCompareOp::AnyGte
            | PlanCompareOp::AnyLt
            | PlanCompareOp::AnyLte
            | PlanCompareOp::AnyLike
            | PlanCompareOp::AnyNotLike
    )
}

fn plan_any_match_sql_op(op: PlanCompareOp) -> Result<&'static str, FilterError> {
    match op {
        PlanCompareOp::AnyEq => Ok("="),
        PlanCompareOp::AnyNe => Ok("!="),
        PlanCompareOp::AnyGt => Ok(">"),
        PlanCompareOp::AnyGte => Ok(">="),
        PlanCompareOp::AnyLt => Ok("<"),
        PlanCompareOp::AnyLte => Ok("<="),
        PlanCompareOp::AnyLike => Ok("LIKE"),
        PlanCompareOp::AnyNotLike => Ok("NOT LIKE"),
        _ => Err(FilterError::new("not an any-match operator")),
    }
}

fn plan_any_match_inner_op(op: PlanCompareOp) -> Result<PlanCompareOp, FilterError> {
    match op {
        PlanCompareOp::AnyEq => Ok(PlanCompareOp::Eq),
        PlanCompareOp::AnyNe => Ok(PlanCompareOp::Ne),
        PlanCompareOp::AnyGt => Ok(PlanCompareOp::Gt),
        PlanCompareOp::AnyGte => Ok(PlanCompareOp::Gte),
        PlanCompareOp::AnyLt => Ok(PlanCompareOp::Lt),
        PlanCompareOp::AnyLte => Ok(PlanCompareOp::Lte),
        PlanCompareOp::AnyLike => Ok(PlanCompareOp::Like),
        PlanCompareOp::AnyNotLike => Ok(PlanCompareOp::NotLike),
        _ => Err(FilterError::new("not an any-match operator")),
    }
}

fn plan_compare_op_sql(op: PlanCompareOp) -> &'static str {
    match op {
        PlanCompareOp::Eq => "=",
        PlanCompareOp::Ne => "!=",
        PlanCompareOp::Gt => ">",
        PlanCompareOp::Gte => ">=",
        PlanCompareOp::Lt => "<",
        PlanCompareOp::Lte => "<=",
        PlanCompareOp::Like => "LIKE",
        PlanCompareOp::NotLike => "NOT LIKE",
        PlanCompareOp::AnyEq => "=",
        PlanCompareOp::AnyNe => "!=",
        PlanCompareOp::AnyGt => ">",
        PlanCompareOp::AnyGte => ">=",
        PlanCompareOp::AnyLt => "<",
        PlanCompareOp::AnyLte => "<=",
        PlanCompareOp::AnyLike => "LIKE",
        PlanCompareOp::AnyNotLike => "NOT LIKE",
    }
}

fn collect_planned_operand_relations<'a>(
    operand: &'a PlannedOperand,
    relations: &mut Vec<&'a RelationTraversal>,
) {
    match operand {
        PlannedOperand::Field(field) => {
            if let Some(relation) = field.relation() {
                if !relations
                    .iter()
                    .any(|existing| same_relation_steps(existing, relation))
                {
                    relations.push(relation);
                }
            }
        }
        PlannedOperand::Function { args, .. } => {
            for arg in args {
                collect_planned_operand_relations(arg, relations);
            }
        }
        PlannedOperand::Value(_) | PlannedOperand::EachValues { .. } => {}
    }
}

fn same_relation_steps(left: &RelationTraversal, right: &RelationTraversal) -> bool {
    left.steps == right.steps
}

fn relation_has_multiple_step(relation: &RelationTraversal) -> bool {
    relation
        .steps
        .iter()
        .any(|step| step.multiplicity == RelationMultiplicity::Multiple)
}

fn validate_relation_chain(relation: &RelationTraversal) -> Result<(), FilterError> {
    if relation.steps.is_empty() {
        return Err(FilterError::with_kind(
            FilterErrorKind::InvalidOperator,
            format!("relation '{}' has no traversal steps", relation.field_path),
        ));
    }

    Ok(())
}

fn wrap_like(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(normalize_like_pattern(value)),
        other => other.clone(),
    }
}

fn normalize_like_pattern(value: &str) -> String {
    if contains_unescaped_char(value, '%') {
        value.to_string()
    } else {
        format!("%{}%", escape_unescaped_chars(value, &['\\', '%', '_']))
    }
}

fn contains_unescaped_char(value: &str, target: char) -> bool {
    let mut previous = None;

    for ch in value.chars() {
        if ch == target && previous != Some('\\') {
            return true;
        }

        previous = if ch == '\\' && previous == Some('\\') {
            None
        } else {
            Some(ch)
        };
    }

    false
}

fn escape_unescaped_chars(value: &str, escape_chars: &[char]) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let mut result = Vec::with_capacity(chars.len());
    let mut matched = false;

    for index in (0..chars.len()).rev() {
        let ch = chars[index];

        if matched {
            if ch != '\\' {
                result.push('\\');
            }
            matched = false;
        } else if escape_chars.contains(&ch) {
            matched = true;
        }

        result.push(ch);

        if index == 0 && matched {
            result.push('\\');
        }
    }

    result.reverse();
    result.into_iter().collect()
}

fn is_safe_identifier_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_ident_continue))
}

pub(crate) fn quote_identifier_path(value: &str) -> Result<String, FilterError> {
    if !is_safe_identifier_path(value) {
        return Err(FilterError::with_kind(
            FilterErrorKind::UnsafeIdentifier,
            format!("unsafe identifier '{value}'"),
        ));
    }

    Ok(value
        .split('.')
        .map(quote_identifier_part)
        .collect::<Vec<_>>()
        .join("."))
}

fn quote_safe_identifier_part(value: &str) -> Result<String, FilterError> {
    if !is_safe_identifier_part(value) {
        return Err(FilterError::with_kind(
            FilterErrorKind::UnsafeIdentifier,
            format!("unsafe identifier '{value}'"),
        ));
    }

    Ok(quote_identifier_part(value))
}

fn is_safe_identifier_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn quote_identifier_part(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub(crate) fn sqlite_json_path(value: &str) -> Result<String, FilterError> {
    let mut path = String::from("$");

    for part in value.split('.') {
        if part.is_empty() {
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe JSON path '{value}'"),
            ));
        }

        if part.chars().all(|ch| ch.is_ascii_digit()) {
            path.push('[');
            path.push_str(part);
            path.push(']');
        } else if is_json_key_part(part) {
            path.push('.');
            path.push_str(part);
        } else {
            return Err(FilterError::with_kind(
                FilterErrorKind::UnsafeIdentifier,
                format!("unsafe JSON path '{value}'"),
            ));
        }
    }

    Ok(path)
}

fn is_json_key_part(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if is_ident_start(ch))
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i32::from(month);
    let day = i32::from(day);
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    i64::from(era * 146_097 + day_of_era - 719_468)
}

fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };

    year += i64::from(month <= 2);

    (year as i32, month as u8, day as u8)
}
