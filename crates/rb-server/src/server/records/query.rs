use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    pub page: u64,
    pub per_page: u64,
    pub filter: Option<String>,
    pub sort: Option<String>,
    pub skip_total: bool,
    pub expand: Vec<String>,
    pub fields: Vec<String>,
    pub context: FilterContext,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 30,
            filter: None,
            sort: None,
            skip_total: false,
            expand: Vec::new(),
            fields: Vec::new(),
            context: FilterContext::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordList {
    pub page: u64,
    pub per_page: u64,
    pub total_items: i64,
    pub total_pages: i64,
    pub items: Vec<JsonValue>,
}

pub(crate) struct RecordResolver<'a> {
    collection: &'a CollectionConfig,
}

impl<'a> RecordResolver<'a> {
    pub(crate) fn new(collection: &'a CollectionConfig) -> Self {
        Self { collection }
    }

    pub(crate) fn custom_field(&self, field: &str) -> Option<&CollectionField> {
        self.collection
            .fields
            .iter()
            .find(|candidate| candidate.name == field)
    }

    pub(crate) fn custom_field_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        self.custom_field(field).map(|field| field.kind)
    }

    pub(crate) fn json_root_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        let (root, _) = field.split_once('.')?;
        self.custom_field_kind(root)
            .filter(|kind| is_json_path_field_kind(*kind))
    }
}

impl FieldResolver for RecordResolver<'_> {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "id" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier("id"),
                    FieldKind::Text,
                ));
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier(field),
                    FieldKind::DateTime,
                ));
            }
            _ => {}
        }

        if let Some(custom_field) = self.custom_field(field) {
            return Ok(ResolvedField::with_kind(
                json_data_extract(field),
                filter_field_kind(custom_field),
            ));
        }

        if self.json_root_kind(field).is_some() {
            return Ok(ResolvedField::new(json_data_extract(field)));
        }

        Err(FilterError::with_kind(
            rb_filter_engine::FilterErrorKind::UnknownField,
            format!("unknown field '{field}'"),
        ))
    }
}

pub(crate) struct ViewRecordResolver<'a> {
    collection: &'a CollectionConfig,
}

impl<'a> ViewRecordResolver<'a> {
    pub(crate) fn new(collection: &'a CollectionConfig) -> Self {
        Self { collection }
    }

    pub(crate) fn custom_field(&self, field: &str) -> Option<&CollectionField> {
        self.collection
            .fields
            .iter()
            .find(|candidate| candidate.name == field)
    }
}

impl FieldResolver for ViewRecordResolver<'_> {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "id" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier("id"),
                    FieldKind::Text,
                ));
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier(field),
                    FieldKind::DateTime,
                ));
            }
            _ => {}
        }

        if let Some(custom_field) = self.custom_field(field) {
            return Ok(ResolvedField::with_kind(
                quote_identifier(field),
                filter_field_kind(custom_field),
            ));
        }

        Err(FilterError::with_kind(
            rb_filter_engine::FilterErrorKind::UnknownField,
            format!("unknown field '{field}'"),
        ))
    }
}

pub(crate) struct IncomingRecordResolver<'a> {
    collection: &'a CollectionConfig,
}

impl<'a> IncomingRecordResolver<'a> {
    pub(crate) fn new(collection: &'a CollectionConfig) -> Self {
        Self { collection }
    }

    pub(crate) fn custom_field(&self, field: &str) -> Option<&CollectionField> {
        self.collection
            .fields
            .iter()
            .find(|candidate| candidate.name == field)
    }

    pub(crate) fn custom_field_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        self.custom_field(field).map(|field| field.kind)
    }

    pub(crate) fn json_root_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        let (root, _) = field.split_once('.')?;
        self.custom_field_kind(root)
            .filter(|kind| is_json_path_field_kind(*kind))
    }
}

impl FieldResolver for IncomingRecordResolver<'_> {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "id" => {
                return Ok(ResolvedField::with_kind(
                    incoming_json_extract("id"),
                    FieldKind::Text,
                ));
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    incoming_json_extract(field),
                    FieldKind::DateTime,
                ));
            }
            _ => {}
        }

        if let Some(custom_field) = self.custom_field(field) {
            return Ok(ResolvedField::with_kind(
                incoming_json_extract(field),
                filter_field_kind(custom_field),
            ));
        }

        if self.json_root_kind(field).is_some() {
            return Ok(ResolvedField::new(incoming_json_extract(field)));
        }

        Err(FilterError::with_kind(
            rb_filter_engine::FilterErrorKind::UnknownField,
            format!("unknown field '{field}'"),
        ))
    }
}

pub(crate) fn filter_field_kind(field: &CollectionField) -> FieldKind {
    if field.kind == CollectionFieldKind::Select && field.max_select.unwrap_or(1) > 1 {
        FieldKind::Array
    } else {
        FieldKind::from(field.kind)
    }
}

pub(crate) fn is_json_path_field_kind(kind: CollectionFieldKind) -> bool {
    matches!(
        kind,
        CollectionFieldKind::Json | CollectionFieldKind::GeoPoint
    )
}

pub(crate) struct CompiledPredicate {
    pub(crate) sql: Option<String>,
    pub(crate) params: Vec<SqlValue>,
}

pub(crate) fn compile_list_predicate(
    collection: &CollectionConfig,
    resolver: &impl FieldResolver,
    options: &ListOptions,
) -> Result<CompiledPredicate, ServerError> {
    let mut sql = Vec::new();
    let mut params = Vec::new();

    if !is_superuser_context(&options.context) {
        if let Some(rule) = collection
            .list_rule
            .as_deref()
            .filter(|rule| !rule.trim().is_empty())
        {
            push_compiled_predicate(rule, resolver, &options.context, &mut sql, &mut params)?;
        }
    }

    if let Some(filter) = options
        .filter
        .as_deref()
        .filter(|filter| !filter.trim().is_empty())
    {
        push_compiled_predicate(filter, resolver, &options.context, &mut sql, &mut params)?;
    }

    Ok(CompiledPredicate {
        sql: if sql.is_empty() {
            None
        } else {
            Some(sql.join(" AND "))
        },
        params,
    })
}

pub(crate) fn push_compiled_predicate(
    filter: &str,
    resolver: &impl FieldResolver,
    context: &FilterContext,
    sql: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) -> Result<(), ServerError> {
    let compiled = compile_filter_with_resolver_and_context(filter, resolver, context.clone())?;
    sql.push(format!("({})", compiled.sql));
    params.extend(filter_params_to_sqlite(compiled.params)?);
    Ok(())
}

pub(crate) fn filter_params_to_sqlite(
    params: Vec<FilterValue>,
) -> Result<Vec<SqlValue>, ServerError> {
    params.into_iter().map(filter_value_to_sqlite).collect()
}

pub(crate) fn filter_value_to_sqlite(value: FilterValue) -> Result<SqlValue, ServerError> {
    Ok(match value {
        FilterValue::String(value) => SqlValue::Text(value),
        FilterValue::Number(value) => {
            if let Ok(value) = value.parse::<i64>() {
                SqlValue::Integer(value)
            } else if let Ok(value) = value.parse::<f64>() {
                SqlValue::Real(value)
            } else {
                return Err(ServerError::BadRequest(format!(
                    "invalid numeric value '{value}'"
                )));
            }
        }
        FilterValue::Bool(value) => SqlValue::Integer(if value { 1 } else { 0 }),
        FilterValue::Null => SqlValue::Null,
    })
}

pub(crate) fn record_sort_sql(
    resolver: &impl FieldResolver,
    sort: Option<&str>,
) -> Result<String, ServerError> {
    let Some(sort) = sort.map(str::trim).filter(|sort| !sort.is_empty()) else {
        return Ok(r#""created" DESC, "id" ASC"#.to_string());
    };

    let mut parts = Vec::new();
    for raw_field in sort
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
    {
        let (direction, field) = if let Some(field) = raw_field.strip_prefix('-') {
            ("DESC", field.trim())
        } else if let Some(field) = raw_field.strip_prefix('+') {
            ("ASC", field.trim())
        } else {
            ("ASC", raw_field)
        };
        let expression = if field == "@random" {
            "RANDOM()".to_string()
        } else if field == "@rowid" {
            "rowid".to_string()
        } else {
            resolver.resolve_field(field)?.sql
        };
        parts.push(format!("{expression} {direction}"));
    }

    if parts.is_empty() {
        Ok(r#""created" DESC, "id" ASC"#.to_string())
    } else {
        Ok(parts.join(", "))
    }
}

pub(crate) fn view_record_sort_sql(
    resolver: &impl FieldResolver,
    sort: Option<&str>,
) -> Result<String, ServerError> {
    if sort.map(str::trim).is_none_or(str::is_empty) {
        Ok(format!("{} ASC", quote_identifier("id")))
    } else {
        record_sort_sql(resolver, sort)
    }
}

pub(crate) fn list_options_from_query(
    query: &HashMap<String, String>,
    context: FilterContext,
) -> Result<ListOptions, ServerError> {
    let page = parse_u64_query(query, "page")?.unwrap_or(1).max(1);
    let per_page = parse_u64_query(query, "perPage")?
        .unwrap_or(30)
        .clamp(1, 500);

    Ok(ListOptions {
        page,
        per_page,
        filter: query.get("filter").cloned(),
        sort: query.get("sort").cloned(),
        skip_total: truthy_query_value(query, "skipTotal"),
        expand: expand_options_from_query(query)?,
        fields: field_options_from_query(query)?,
        context,
    })
}

pub(crate) fn parse_u64_query(
    query: &HashMap<String, String>,
    name: &str,
) -> Result<Option<u64>, ServerError> {
    query
        .get(name)
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                ServerError::BadRequest(format!("query parameter '{name}' must be a number"))
            })
        })
        .transpose()
}

pub(crate) fn truthy_query_value(query: &HashMap<String, String>, name: &str) -> bool {
    query.get(name).is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "t" | "true"
        )
    })
}

pub(crate) fn request_context(
    request: &HttpRequest,
    query: &HashMap<String, String>,
) -> FilterContext {
    let mut context = FilterContext::default().with_request_method(request.method.clone());

    for (name, value) in query {
        context = context.with_query_value(name.clone(), FilterValue::String(value.clone()));
    }

    for (name, value) in &request.headers {
        context = context.with_header_value(name.clone(), FilterValue::String(value.clone()));
    }

    if let Some(auth_id) = request.headers.get("x-rb-auth-id") {
        context = context.with_auth_value("id", FilterValue::String(auth_id.clone()));
    }

    context
}
