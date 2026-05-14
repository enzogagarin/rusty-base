use super::*;
use super::{auth::*, collections::*, files::*, http::*, storage::*, validation::*};

mod cascade;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordValueMutationKind {
    Append,
    Prepend,
    Delete,
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
                ))
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier(field),
                    FieldKind::DateTime,
                ))
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
                ))
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    quote_identifier(field),
                    FieldKind::DateTime,
                ))
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
                ))
            }
            "created" | "updated" => {
                return Ok(ResolvedField::with_kind(
                    incoming_json_extract(field),
                    FieldKind::DateTime,
                ))
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

pub(crate) fn field_options_from_query(
    query: &HashMap<String, String>,
) -> Result<Vec<String>, ServerError> {
    let Some(fields) = query.get("fields") else {
        return Ok(Vec::new());
    };

    let mut projections = Vec::new();
    for path in fields
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_field_projection_path(path)?;
        if !projections.iter().any(|existing| existing == path) {
            projections.push(path.to_string());
        }
    }

    Ok(projections)
}

pub(crate) fn validate_field_projection_path(path: &str) -> Result<(), ServerError> {
    if path
        .split('.')
        .any(|part| part != "*" && !is_safe_identifier_part(part))
    {
        return Err(ServerError::BadRequest(format!(
            "invalid fields path '{path}'"
        )));
    }

    Ok(())
}

pub(crate) fn expand_options_from_query(
    query: &HashMap<String, String>,
) -> Result<Vec<String>, ServerError> {
    let Some(expand) = query.get("expand") else {
        return Ok(Vec::new());
    };

    let mut expands = Vec::new();
    for path in expand
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_expand_path(path)?;
        if !expands.iter().any(|existing| existing == path) {
            expands.push(path.to_string());
        }
    }

    Ok(expands)
}

pub(crate) fn validate_expand_path(path: &str) -> Result<(), ServerError> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.len() > 6 {
        return Err(ServerError::BadRequest(format!(
            "expand path '{path}' exceeds the 6-level limit"
        )));
    }
    if parts.iter().any(|part| !is_safe_identifier_part(part)) {
        return Err(ServerError::BadRequest(format!(
            "invalid expand path '{path}'"
        )));
    }

    Ok(())
}

pub(crate) fn group_expand_paths(expands: &[String]) -> HashMap<String, Vec<String>> {
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for expand in expands {
        let (field, nested) = expand.split_once('.').unwrap_or((expand, ""));
        let nested_expands = grouped.entry(field.to_string()).or_default();
        if !nested.is_empty() && !nested_expands.iter().any(|existing| existing == nested) {
            nested_expands.push(nested.to_string());
        }
    }

    grouped
}

pub(crate) fn project_record_responses(
    records: &mut [JsonValue],
    fields: &[String],
) -> Result<(), ServerError> {
    for record in records {
        project_record_response(record, fields)?;
    }

    Ok(())
}

pub(crate) fn project_record_response(
    record: &mut JsonValue,
    fields: &[String],
) -> Result<(), ServerError> {
    project_json_response(record, fields)
}

pub(crate) fn project_json_response(
    value: &mut JsonValue,
    fields: &[String],
) -> Result<(), ServerError> {
    if fields.is_empty() {
        return Ok(());
    }

    let source = value.clone();
    let mut projected = Map::new();
    let expand_projection_parents = expand_projection_parents(fields);

    for field in fields {
        let parts = field.split('.').collect::<Vec<_>>();
        project_field_path(
            &source,
            &mut projected,
            &parts,
            &[],
            &expand_projection_parents,
        );
    }

    *value = JsonValue::Object(projected);
    Ok(())
}

pub(crate) fn expand_projection_parents(fields: &[String]) -> HashSet<Vec<String>> {
    let mut parents = HashSet::new();
    for field in fields {
        let mut parent = Vec::new();
        for part in field.split('.') {
            if part == "expand" {
                parents.insert(parent.clone());
            }
            parent.push(part.to_string());
        }
    }

    parents
}

pub(crate) fn project_field_path(
    source: &JsonValue,
    target: &mut Map<String, JsonValue>,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) {
    let Some((head, tail)) = parts.split_first() else {
        return;
    };
    let Some(source_object) = source.as_object() else {
        return;
    };

    if *head == "*" {
        for (key, value) in source_object {
            if key == "expand" && expand_projection_parents.contains(current_path) {
                continue;
            }

            let child_path = child_projection_path(current_path, key);
            let projected = if tail.is_empty() {
                Some(copy_wildcard_value(
                    value,
                    &child_path,
                    expand_projection_parents,
                ))
            } else {
                project_value_path(value, tail, &child_path, expand_projection_parents)
            };
            if let Some(projected) = projected {
                merge_projected_value(target, key, projected);
            }
        }
        return;
    }

    let Some(value) = source_object.get(*head) else {
        return;
    };
    let child_path = child_projection_path(current_path, head);
    let projected = if tail.is_empty() {
        Some(value.clone())
    } else {
        project_value_path(value, tail, &child_path, expand_projection_parents)
    };
    if let Some(projected) = projected {
        merge_projected_value(target, head, projected);
    }
}

pub(crate) fn project_value_path(
    source: &JsonValue,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> Option<JsonValue> {
    if parts.is_empty() {
        return Some(source.clone());
    }

    if source.is_object() {
        let mut projected = Map::new();
        project_field_path(
            source,
            &mut projected,
            parts,
            current_path,
            expand_projection_parents,
        );
        return (!projected.is_empty()).then_some(JsonValue::Object(projected));
    }

    if let Some(array) = source.as_array() {
        return Some(JsonValue::Array(
            array
                .iter()
                .filter_map(|value| {
                    project_value_path(value, parts, current_path, expand_projection_parents)
                })
                .collect(),
        ));
    }

    None
}

pub(crate) fn copy_wildcard_value(
    source: &JsonValue,
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> JsonValue {
    match source {
        JsonValue::Object(object) => {
            let mut copied = Map::new();
            for (key, value) in object {
                if key == "expand" && expand_projection_parents.contains(current_path) {
                    continue;
                }

                copied.insert(
                    key.clone(),
                    copy_wildcard_value(
                        value,
                        &child_projection_path(current_path, key),
                        expand_projection_parents,
                    ),
                );
            }
            JsonValue::Object(copied)
        }
        JsonValue::Array(array) => JsonValue::Array(
            array
                .iter()
                .map(|value| copy_wildcard_value(value, current_path, expand_projection_parents))
                .collect(),
        ),
        _ => source.clone(),
    }
}

pub(crate) fn child_projection_path(current_path: &[String], child: &str) -> Vec<String> {
    let mut path = current_path.to_vec();
    path.push(child.to_string());
    path
}

pub(crate) fn merge_projected_value(
    target: &mut Map<String, JsonValue>,
    key: &str,
    value: JsonValue,
) {
    if let Some(existing) = target.get_mut(key) {
        merge_json(existing, value);
    } else {
        target.insert(key.to_string(), value);
    }
}

pub(crate) fn merge_json(existing: &mut JsonValue, incoming: JsonValue) {
    match (existing, incoming) {
        (JsonValue::Object(existing), JsonValue::Object(incoming)) => {
            for (key, value) in incoming {
                merge_projected_value(existing, &key, value);
            }
        }
        (JsonValue::Array(existing), JsonValue::Array(incoming)) => {
            for (index, value) in incoming.into_iter().enumerate() {
                if let Some(existing) = existing.get_mut(index) {
                    merge_json(existing, value);
                } else {
                    existing.push(value);
                }
            }
        }
        (existing, incoming) => {
            *existing = incoming;
        }
    }
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

pub(crate) fn context_with_body_values(context: FilterContext, body: &JsonValue) -> FilterContext {
    context_with_body_values_and_changes(context, body, None)
}

pub(crate) fn context_with_body_values_and_changes(
    mut context: FilterContext,
    body: &JsonValue,
    existing: Option<&JsonValue>,
) -> FilterContext {
    let Some(object) = body.as_object() else {
        return context;
    };
    let existing_object = existing.and_then(JsonValue::as_object);

    for (name, value) in object {
        context = context.with_body_value(name.clone(), json_to_filter_value(value));
        if let Some(array) = value.as_array() {
            context = context.with_body_length(name.clone(), array.len());
            context = context.with_body_each_values(
                name.clone(),
                array.iter().map(json_to_filter_value).collect::<Vec<_>>(),
            );
        }
        if let Some(existing_object) = existing_object {
            context =
                context.with_body_changed(name.clone(), existing_object.get(name) != Some(value));
        }
    }

    context
}

pub(crate) fn is_superuser_context(context: &FilterContext) -> bool {
    matches!(
        context.request.auth.get("collectionName"),
        Some(FilterValue::String(collection)) if collection == SUPERUSERS_COLLECTION
    )
}

pub(crate) fn json_to_filter_value(value: &JsonValue) -> FilterValue {
    match value {
        JsonValue::String(value) => FilterValue::String(value.clone()),
        JsonValue::Number(value) => FilterValue::Number(value.to_string()),
        JsonValue::Bool(value) => FilterValue::Bool(*value),
        JsonValue::Null => FilterValue::Null,
        JsonValue::Array(_) | JsonValue::Object(_) => FilterValue::String(value.to_string()),
    }
}

pub(crate) fn row_to_record(
    collection_name: &str,
    collection_id: &str,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<JsonValue> {
    let id = row.get::<_, String>(0)?;
    let data = row.get::<_, String>(1)?;
    let created = row.get::<_, String>(2)?;
    let updated = row.get::<_, String>(3)?;
    let data = serde_json::from_str::<JsonValue>(&data).unwrap_or(JsonValue::Object(Map::new()));

    Ok(record_from_parts(
        collection_name,
        collection_id,
        id,
        data,
        created,
        updated,
    ))
}

pub(crate) fn statement_column_names(stmt: &rusqlite::Statement<'_>) -> Vec<String> {
    stmt.column_names()
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(crate) fn view_row_to_record(
    collection_name: &str,
    collection_id: &str,
    column_names: &[String],
    row: &rusqlite::Row<'_>,
) -> Result<JsonValue, ServerError> {
    let mut record = Map::new();
    for (index, name) in column_names.iter().enumerate() {
        let value = row.get::<_, SqlValue>(index)?;
        record.insert(name.clone(), sql_value_to_json(value));
    }

    let id = record
        .get("id")
        .and_then(view_record_id)
        .ok_or_else(|| ServerError::BadRequest("viewQuery must return an id column".to_string()))?;
    record.insert("id".to_string(), JsonValue::String(id));
    record.insert(
        "collectionId".to_string(),
        JsonValue::String(collection_id.to_string()),
    );
    record.insert(
        "collectionName".to_string(),
        JsonValue::String(collection_name.to_string()),
    );
    record
        .entry("created".to_string())
        .or_insert_with(|| JsonValue::String(String::new()));
    record
        .entry("updated".to_string())
        .or_insert_with(|| JsonValue::String(String::new()));
    Ok(JsonValue::Object(record))
}

pub(crate) fn view_record_id(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(value) if !value.is_empty() => Some(value.clone()),
        JsonValue::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct ViewQueryLimits {
    timeout: Duration,
    progress_ops: i32,
    max_progress_callbacks: u64,
}

const DEFAULT_VIEW_QUERY_LIMITS: ViewQueryLimits = ViewQueryLimits {
    timeout: Duration::from_secs(2),
    progress_ops: 10_000,
    max_progress_callbacks: 20_000,
};

fn with_view_query_authorizer<T>(
    conn: &Connection,
    work: impl FnOnce() -> Result<T, ServerError>,
) -> Result<T, ServerError> {
    with_view_query_guard(conn, DEFAULT_VIEW_QUERY_LIMITS, work)
}

fn with_view_query_guard<T>(
    conn: &Connection,
    limits: ViewQueryLimits,
    work: impl FnOnce() -> Result<T, ServerError>,
) -> Result<T, ServerError> {
    conn.authorizer(Some(view_query_authorizer));
    let started = Instant::now();
    let mut progress_callbacks = 0_u64;
    conn.progress_handler(
        limits.progress_ops,
        Some(move || {
            progress_callbacks = progress_callbacks.saturating_add(1);
            started.elapsed() >= limits.timeout
                || progress_callbacks > limits.max_progress_callbacks
        }),
    );
    let result = work().map_err(map_view_query_authorizer_error);
    conn.progress_handler(0, None::<fn() -> bool>);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    result
}

fn view_query_authorizer(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. } => {
            if is_denied_view_query_table(table_name) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }
        AuthAction::Function { function_name } => {
            if is_denied_view_query_function(function_name) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }
        _ => Authorization::Deny,
    }
}

fn is_denied_view_query_function(function_name: &str) -> bool {
    matches!(
        function_name.to_ascii_lowercase().as_str(),
        "load_extension" | "readfile" | "writefile" | "fts3_tokenizer"
    )
}

fn map_view_query_authorizer_error(err: ServerError) -> ServerError {
    match err {
        ServerError::Storage(err)
            if err.sqlite_error_code() == Some(ErrorCode::OperationInterrupted) =>
        {
            ServerError::BadRequest("viewQuery exceeded execution limits".to_string())
        }
        ServerError::Storage(err)
            if err.sqlite_error_code() == Some(ErrorCode::AuthorizationForStatementDenied)
                || err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("not authorized") =>
        {
            ServerError::BadRequest("viewQuery attempted a denied SQLite operation".to_string())
        }
        ServerError::Storage(err) => {
            ServerError::BadRequest(format!("viewQuery execution failed: {err}"))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_query_authorizer_allows_record_table_reads() {
        let context = AuthContext {
            action: AuthAction::Read {
                table_name: "_rb_records_posts",
                column_name: "data",
            },
            database_name: Some("main"),
            accessor: None,
        };

        assert_eq!(view_query_authorizer(context), Authorization::Allow);
    }

    #[test]
    fn view_query_authorizer_denies_internal_reads_and_writes() {
        let internal_read = AuthContext {
            action: AuthAction::Read {
                table_name: "_rb_auth_tokens",
                column_name: "token",
            },
            database_name: Some("main"),
            accessor: None,
        };
        let write = AuthContext {
            action: AuthAction::Insert {
                table_name: "_rb_records_posts",
            },
            database_name: Some("main"),
            accessor: None,
        };
        let unsafe_function = AuthContext {
            action: AuthAction::Function {
                function_name: "load_extension",
            },
            database_name: Some("main"),
            accessor: None,
        };

        assert_eq!(view_query_authorizer(internal_read), Authorization::Deny);
        assert_eq!(view_query_authorizer(write), Authorization::Deny);
        assert_eq!(view_query_authorizer(unsafe_function), Authorization::Deny);
    }

    #[test]
    fn view_query_progress_guard_interrupts_expensive_queries() {
        let conn = Connection::open_in_memory().unwrap();
        let limits = ViewQueryLimits {
            timeout: Duration::from_secs(60),
            progress_ops: 1,
            max_progress_callbacks: 0,
        };

        let err = with_view_query_guard(&conn, limits, || {
            conn.query_row(
                r#"
                WITH RECURSIVE numbers(value) AS (
                    SELECT 1
                    UNION ALL
                    SELECT value + 1 FROM numbers WHERE value < 1000
                )
                SELECT sum(value) FROM numbers
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )?;
            Ok(())
        })
        .unwrap_err();

        assert_eq!(err.to_string(), "viewQuery exceeded execution limits");
        let value: i64 = conn.query_row("SELECT 1", [], |row| row.get(0)).unwrap();
        assert_eq!(value, 1);
    }
}

pub(crate) fn sql_value_to_json(value: SqlValue) -> JsonValue {
    match value {
        SqlValue::Null => JsonValue::Null,
        SqlValue::Integer(value) => json!(value),
        SqlValue::Real(value) => serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        SqlValue::Text(value) => JsonValue::String(value),
        SqlValue::Blob(value) => JsonValue::String(URL_SAFE_NO_PAD.encode(value)),
    }
}

pub(crate) fn record_from_parts(
    collection_name: &str,
    collection_id: &str,
    id: String,
    data: JsonValue,
    created: String,
    updated: String,
) -> JsonValue {
    let mut record = match data {
        JsonValue::Object(map) => map,
        _ => Map::new(),
    };

    record.remove("passwordHash");
    record.insert("id".to_string(), JsonValue::String(id));
    record.insert(
        "collectionId".to_string(),
        JsonValue::String(collection_id.to_string()),
    );
    record.insert(
        "collectionName".to_string(),
        JsonValue::String(collection_name.to_string()),
    );
    record.insert("created".to_string(), JsonValue::String(created));
    record.insert("updated".to_string(), JsonValue::String(updated));
    JsonValue::Object(record)
}

pub(crate) fn non_empty_rule(rule: Option<&str>) -> Option<&str> {
    rule.filter(|rule| !rule.trim().is_empty())
}

pub(crate) fn forbidden(action: &str, collection_name: &str) -> ServerError {
    ServerError::Forbidden(format!(
        "{action} rule denied access to collection '{collection_name}'"
    ))
}

pub(crate) fn read_only_view_collection(collection_name: &str) -> ServerError {
    ServerError::BadRequest(format!("view collection '{collection_name}' is read-only"))
}

pub(crate) fn prepare_record_value_modifiers(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    existing: Option<&JsonValue>,
) -> Result<(), ServerError> {
    let mut mutations: HashMap<String, RecordValueMutation> = HashMap::new();
    let keys = object.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        let Some((field_name, kind)) = parse_record_value_mutation_key(collection, &key) else {
            continue;
        };
        let value = object.remove(&key).unwrap_or(JsonValue::Null);
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            RecordValueMutationKind::Append => mutation.append_values.push((key, value)),
            RecordValueMutationKind::Prepend => mutation.prepend_values.push((key, value)),
            RecordValueMutationKind::Delete => mutation.delete_values.push((key, value)),
        }
    }

    for (field_name, mutation) in mutations {
        let field = collection_field(collection, &field_name).ok_or_else(|| {
            validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_unknown_field",
                format!("Unknown field for collection '{}'.", collection.name),
            )
        })?;
        let existing_value = existing
            .and_then(JsonValue::as_object)
            .and_then(|object| object.get(&field_name));
        let base_value = object.get(&field_name).or(existing_value);
        let final_value = match field.kind {
            CollectionFieldKind::Number => {
                apply_number_value_modifier(field, base_value, &mutation)?
            }
            CollectionFieldKind::Select | CollectionFieldKind::Relation => {
                apply_string_list_value_modifier(field, base_value, &mutation)?
            }
            _ => continue,
        };
        object.insert(field_name, final_value);
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RecordValueMutation {
    pub(crate) append_values: Vec<(String, JsonValue)>,
    pub(crate) prepend_values: Vec<(String, JsonValue)>,
    pub(crate) delete_values: Vec<(String, JsonValue)>,
}

pub(crate) fn apply_number_value_modifier(
    field: &CollectionField,
    base_value: Option<&JsonValue>,
    mutation: &RecordValueMutation,
) -> Result<JsonValue, ServerError> {
    if !mutation.prepend_values.is_empty() {
        return Err(invalid_record_value_modifier(
            field,
            &mutation.prepend_values[0].0,
            "Number fields do not support prepend modifiers.",
        ));
    }

    let mut number = match base_value {
        Some(value) if !is_empty_record_value(value) => value.as_f64().ok_or_else(|| {
            invalid_record_value_modifier(
                field,
                &field.name,
                "Number modifiers require an existing numeric value.",
            )
        })?,
        _ => 0.0,
    };

    for (key, value) in &mutation.append_values {
        number += modifier_number(field, key, value)?;
    }
    for (key, value) in &mutation.delete_values {
        number -= modifier_number(field, key, value)?;
    }

    let Some(number) = serde_json::Number::from_f64(number) else {
        return Err(invalid_record_value_modifier(
            field,
            &field.name,
            "Number modifier result must be finite.",
        ));
    };
    Ok(JsonValue::Number(number))
}

pub(crate) fn apply_string_list_value_modifier(
    field: &CollectionField,
    base_value: Option<&JsonValue>,
    mutation: &RecordValueMutation,
) -> Result<JsonValue, ServerError> {
    let max_select = field.max_select.unwrap_or(1).max(1);
    let mut values = match base_value {
        Some(value) if !is_empty_record_value(value) => {
            modifier_string_values(field, &field.name, value)?
        }
        _ => Vec::new(),
    };

    if !mutation.delete_values.is_empty() {
        let mut delete_values = Vec::new();
        for (key, value) in &mutation.delete_values {
            delete_values.extend(modifier_string_values(field, key, value)?);
        }
        let delete_values = delete_values.into_iter().collect::<HashSet<_>>();
        values.retain(|value| !delete_values.contains(value));
    }

    if !mutation.prepend_values.is_empty() {
        let mut prepended = Vec::new();
        for (key, value) in &mutation.prepend_values {
            prepended.extend(modifier_string_values(field, key, value)?);
        }
        prepended.extend(values);
        values = prepended;
    }

    for (key, value) in &mutation.append_values {
        values.extend(modifier_string_values(field, key, value)?);
    }

    dedupe_strings(&mut values);
    Ok(string_list_field_value(&values, max_select))
}

pub(crate) fn modifier_number(
    field: &CollectionField,
    key: &str,
    value: &JsonValue,
) -> Result<f64, ServerError> {
    value.as_f64().ok_or_else(|| {
        invalid_record_value_modifier(field, key, "Number modifiers require numeric values.")
    })
}

pub(crate) fn modifier_string_values(
    field: &CollectionField,
    key: &str,
    value: &JsonValue,
) -> Result<Vec<String>, ServerError> {
    match value {
        JsonValue::String(value) if value.trim().is_empty() => Ok(Vec::new()),
        JsonValue::String(value) => Ok(vec![value.clone()]),
        JsonValue::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    invalid_record_value_modifier(
                        field,
                        key,
                        "Select and relation modifiers require string values.",
                    )
                })
            })
            .filter(|result| {
                result
                    .as_ref()
                    .map_or(true, |value| !value.trim().is_empty())
            })
            .collect(),
        JsonValue::Null => Ok(Vec::new()),
        _ => Err(invalid_record_value_modifier(
            field,
            key,
            "Select and relation modifiers require a string or string array.",
        )),
    }
}

pub(crate) fn invalid_record_value_modifier(
    field: &CollectionField,
    key: &str,
    message: impl Into<String>,
) -> ServerError {
    validation_error(
        "Failed to validate record.",
        key,
        "validation_invalid_modifier",
        format!("Field '{}': {}", field.name, message.into()),
    )
}

pub(crate) fn parse_record_value_mutation_key(
    collection: &CollectionConfig,
    key: &str,
) -> Option<(String, RecordValueMutationKind)> {
    if let Some(field) = key.strip_prefix('+').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Prepend)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Prepend));
    }
    if let Some(field) = key.strip_suffix('+').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Append)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Append));
    }
    if let Some(field) = key.strip_suffix('-').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Delete)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Delete));
    }
    None
}

pub(crate) fn record_value_modifier_field<'a>(
    collection: &'a CollectionConfig,
    name: &str,
    kind: RecordValueMutationKind,
) -> Option<&'a CollectionField> {
    collection_field(collection, name).filter(|field| match (field.kind, kind) {
        (
            CollectionFieldKind::Number,
            RecordValueMutationKind::Append | RecordValueMutationKind::Delete,
        ) => true,
        (
            CollectionFieldKind::Select | CollectionFieldKind::Relation,
            RecordValueMutationKind::Append
            | RecordValueMutationKind::Prepend
            | RecordValueMutationKind::Delete,
        ) => field.max_select.unwrap_or(1) > 1,
        _ => false,
    })
}

pub(crate) fn collection_field<'a>(
    collection: &'a CollectionConfig,
    name: &str,
) -> Option<&'a CollectionField> {
    collection.fields.iter().find(|field| field.name == name)
}

pub(crate) fn string_list_field_value(values: &[String], max_select: u64) -> JsonValue {
    if max_select <= 1 {
        JsonValue::String(values.first().cloned().unwrap_or_default())
    } else {
        JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect())
    }
}

impl Store {
    pub fn create_record(
        &self,
        collection_name: &str,
        data: JsonValue,
    ) -> Result<JsonValue, ServerError> {
        self.create_record_with_context(collection_name, data, FilterContext::default())
    }

    pub fn create_record_with_context(
        &self,
        collection_name: &str,
        data: JsonValue,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        self.create_record_with_uploads(collection_name, data, Vec::new(), context)
    }

    pub(crate) fn create_record_with_uploads(
        &self,
        collection_name: &str,
        mut data: JsonValue,
        uploads: Vec<FileUpload>,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type == CollectionType::View {
            return Err(read_only_view_collection(&collection.name));
        }
        let collection_name = collection.name.as_str();
        let object = data_object_mut(&mut data)?;
        let file_changes = prepare_file_changes(&collection, object, uploads, None)?;
        prepare_record_value_modifiers(&collection, object, None)?;
        validate_record_fields(&collection, object)?;
        prepare_auth_password(&collection, object, true)?;
        let now = now_timestamp();
        apply_autodate_fields(&collection, object, true, &now);
        validate_record_field_options(&collection, object)?;
        self.validate_record_relations_exist(&collection, object)?;

        let id = object
            .remove("id")
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(generate_id);
        validate_record_id(&id)?;

        object.remove("created");
        object.remove("updated");
        object.remove("collectionId");
        object.remove("collectionName");

        let mut rule_data = data.clone();
        if let Some(object) = rule_data.as_object_mut() {
            object.insert("id".to_string(), JsonValue::String(id.clone()));
        }
        let is_superuser = is_superuser_context(&context);
        let context = context_with_body_values(context, &data);
        if !is_superuser {
            self.enforce_incoming_record_rule(
                &collection,
                collection.create_rule.as_deref(),
                &rule_data,
                context,
                "create",
            )?;
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data_json = serde_json::to_string(&data)?;
        let conn = self.connection()?;
        conn.execute(
            &format!(
                "INSERT INTO {table_sql} (id, data, created, updated) VALUES (?1, ?2, ?3, ?3)"
            ),
            params![id, data_json, now],
        )?;
        store_file_uploads(&conn, collection_name, &id, &file_changes.store_files)?;
        drop(conn);

        self.read_record(collection_name, &id)
    }

    pub fn get_record(
        &self,
        collection_name: &str,
        id: &str,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        validate_record_id(id)?;
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type == CollectionType::View {
            return self.get_view_record(&collection, id, context);
        }
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        let resolver = RecordResolver::new(&collection);
        let mut params = vec![SqlValue::Text(id.to_string())];
        let mut where_parts = vec!["id = ?".to_string()];

        if !is_superuser_context(&context) {
            if let Some(rule) = collection
                .view_rule
                .as_deref()
                .filter(|rule| !rule.trim().is_empty())
            {
                let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
                where_parts.push(format!("({})", compiled.sql));
                params.extend(filter_params_to_sqlite(compiled.params)?);
            }
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let sql = format!(
            "SELECT id, data, created, updated FROM {table_sql} WHERE {} LIMIT 1",
            where_parts.join(" AND ")
        );
        let conn = self.connection()?;
        conn.query_row(&sql, params_from_iter(params.iter()), |row| {
            row_to_record(collection_name, &collection_id, row)
        })
        .optional()?
        .ok_or_else(|| ServerError::NotFound(format!("record '{id}' not found")))
    }

    pub fn list_records(
        &self,
        collection_name: &str,
        options: ListOptions,
    ) -> Result<RecordList, ServerError> {
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type == CollectionType::View {
            return self.list_view_records(&collection, options);
        }
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        let resolver = RecordResolver::new(&collection);
        let predicate = compile_list_predicate(&collection, &resolver, &options)?;
        let order_sql = record_sort_sql(&resolver, options.sort.as_deref())?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let where_sql = predicate
            .sql
            .as_ref()
            .map(|sql| format!(" WHERE {sql}"))
            .unwrap_or_default();
        let offset = options.page.saturating_sub(1) * options.per_page;

        let (total_items, mut items) = {
            let conn = self.connection()?;
            let total_items = if options.skip_total {
                -1
            } else {
                let count_sql = format!("SELECT COUNT(*) FROM {table_sql}{where_sql}");
                conn.query_row(
                    &count_sql,
                    params_from_iter(predicate.params.iter()),
                    |row| row.get::<_, i64>(0),
                )?
            };

            let list_sql = format!(
                "SELECT id, data, created, updated FROM {table_sql}{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?"
            );
            let mut list_params = predicate.params;
            list_params.push(SqlValue::Integer(options.per_page as i64));
            list_params.push(SqlValue::Integer(offset as i64));

            let mut stmt = conn.prepare(&list_sql)?;
            let rows = stmt.query_map(params_from_iter(list_params.iter()), |row| {
                row_to_record(collection_name, &collection_id, row)
            })?;
            let items = rows.collect::<Result<Vec<_>, _>>()?;
            (total_items, items)
        };

        if !options.expand.is_empty() {
            self.expand_records(&collection, &mut items, &options.expand, &options.context)?;
        }
        if !options.fields.is_empty() {
            project_record_responses(&mut items, &options.fields)?;
        }

        let total_pages = if options.skip_total {
            -1
        } else if total_items == 0 {
            0
        } else {
            let per_page = options.per_page as i64;
            (total_items + per_page - 1) / per_page
        };

        Ok(RecordList {
            page: options.page,
            per_page: options.per_page,
            total_items,
            total_pages,
            items,
        })
    }

    pub(crate) fn get_view_record(
        &self,
        collection: &CollectionConfig,
        id: &str,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(collection);
        let resolver = ViewRecordResolver::new(collection);
        let mut params = vec![SqlValue::Text(id.to_string())];
        let mut where_parts = vec![format!("{} = ?", quote_identifier("id"))];

        if !is_superuser_context(&context) {
            if let Some(rule) = collection
                .view_rule
                .as_deref()
                .filter(|rule| !rule.trim().is_empty())
            {
                let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
                where_parts.push(format!("({})", compiled.sql));
                params.extend(filter_params_to_sqlite(compiled.params)?);
            }
        }

        let view_sql = view_query_sql(collection)?;
        let sql = format!(
            "SELECT * FROM ({view_sql}) AS {} WHERE {} LIMIT 1",
            quote_identifier("_rb_view"),
            where_parts.join(" AND ")
        );
        let conn = self.connection()?;
        with_view_query_authorizer(&conn, || {
            let mut stmt = conn.prepare(&sql)?;
            let column_names = statement_column_names(&stmt);
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            if let Some(row) = rows.next()? {
                view_row_to_record(collection_name, &collection_id, &column_names, row)
            } else {
                Err(ServerError::NotFound(format!("record '{id}' not found")))
            }
        })
    }

    pub(crate) fn list_view_records(
        &self,
        collection: &CollectionConfig,
        options: ListOptions,
    ) -> Result<RecordList, ServerError> {
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(collection);
        let resolver = ViewRecordResolver::new(collection);
        let predicate = compile_list_predicate(collection, &resolver, &options)?;
        let order_sql = view_record_sort_sql(&resolver, options.sort.as_deref())?;
        let view_sql = view_query_sql(collection)?;
        let view_table_sql = format!("({view_sql}) AS {}", quote_identifier("_rb_view"));
        let where_sql = predicate
            .sql
            .as_ref()
            .map(|sql| format!(" WHERE {sql}"))
            .unwrap_or_default();
        let offset = options.page.saturating_sub(1) * options.per_page;

        let (total_items, mut items) = {
            let conn = self.connection()?;
            with_view_query_authorizer(&conn, || {
                let total_items = if options.skip_total {
                    -1
                } else {
                    let count_sql = format!("SELECT COUNT(*) FROM {view_table_sql}{where_sql}");
                    conn.query_row(
                        &count_sql,
                        params_from_iter(predicate.params.iter()),
                        |row| row.get::<_, i64>(0),
                    )?
                };

                let list_sql = format!(
                "SELECT * FROM {view_table_sql}{where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?"
            );
                let mut list_params = predicate.params;
                list_params.push(SqlValue::Integer(options.per_page as i64));
                list_params.push(SqlValue::Integer(offset as i64));

                let mut stmt = conn.prepare(&list_sql)?;
                let column_names = statement_column_names(&stmt);
                let mut rows = stmt.query(params_from_iter(list_params.iter()))?;
                let mut items = Vec::new();
                while let Some(row) = rows.next()? {
                    items.push(view_row_to_record(
                        collection_name,
                        &collection_id,
                        &column_names,
                        row,
                    )?);
                }
                Ok((total_items, items))
            })?
        };

        if !options.expand.is_empty() {
            self.expand_records(collection, &mut items, &options.expand, &options.context)?;
        }
        if !options.fields.is_empty() {
            project_record_responses(&mut items, &options.fields)?;
        }

        let total_pages = if options.skip_total {
            -1
        } else if total_items == 0 {
            0
        } else {
            let per_page = options.per_page as i64;
            (total_items + per_page - 1) / per_page
        };

        Ok(RecordList {
            page: options.page,
            per_page: options.per_page,
            total_items,
            total_pages,
            items,
        })
    }

    pub fn expand_record_response(
        &self,
        collection_name: &str,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let collection = self.get_collection(collection_name)?;
        self.expand_record_with_collection(&collection, record, expands, context)
    }

    pub fn update_record(
        &self,
        collection_name: &str,
        id: &str,
        patch: JsonValue,
    ) -> Result<JsonValue, ServerError> {
        self.update_record_with_context(collection_name, id, patch, FilterContext::default())
    }

    pub fn update_record_with_context(
        &self,
        collection_name: &str,
        id: &str,
        patch: JsonValue,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        self.update_record_with_uploads(collection_name, id, patch, Vec::new(), context)
    }

    pub(crate) fn update_record_with_uploads(
        &self,
        collection_name: &str,
        id: &str,
        patch: JsonValue,
        uploads: Vec<FileUpload>,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        validate_record_id(id)?;
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type == CollectionType::View {
            return Err(read_only_view_collection(&collection.name));
        }
        let collection_name = collection.name.as_str();
        let mut patch = patch;
        let mut existing = self.read_record(collection_name, id)?;
        let stored_files = {
            let patch_object = data_object_mut(&mut patch)?;
            prepare_file_changes(&collection, patch_object, uploads, Some(&existing))?
        };
        {
            let patch_object = data_object_mut(&mut patch)?;
            prepare_record_value_modifiers(&collection, patch_object, Some(&existing))?;
            validate_record_fields(&collection, patch_object)?;
            prepare_auth_password(&collection, patch_object, false)?;
        }

        let is_superuser = is_superuser_context(&context);
        let context = context_with_body_values_and_changes(context, &patch, Some(&existing));
        if !is_superuser {
            self.enforce_existing_record_rule(
                collection_name,
                &collection,
                collection.update_rule.as_deref(),
                id,
                context,
                "update",
            )?;
        }

        let existing_object = existing.as_object_mut().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        let patch_object = data_object(&patch)?;

        existing_object.remove("id");
        existing_object.remove("created");
        existing_object.remove("updated");
        existing_object.remove("collectionId");
        existing_object.remove("collectionName");

        for (key, value) in patch_object {
            if !is_system_record_key(key) {
                existing_object.insert(key.clone(), value.clone());
            }
        }
        let now = now_timestamp();
        apply_autodate_fields(&collection, existing_object, false, &now);
        validate_record_field_options(&collection, existing_object)?;
        self.validate_record_relations_exist(&collection, existing_object)?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data_json = serde_json::to_string(&existing)?;
        let conn = self.connection()?;
        delete_file_names(&conn, collection_name, id, &stored_files.delete_files)?;
        let affected = conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![data_json, now, id],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!("record '{id}' not found")));
        }
        store_file_uploads(&conn, collection_name, id, &stored_files.store_files)?;
        drop(conn);

        self.read_record(collection_name, id)
    }

    pub(crate) fn expand_records(
        &self,
        collection: &CollectionConfig,
        records: &mut [JsonValue],
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        for record in records {
            self.expand_record_with_collection(collection, record, expands, context)?;
        }
        Ok(())
    }

    pub(crate) fn expand_record_with_collection(
        &self,
        collection: &CollectionConfig,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let grouped = group_expand_paths(expands);
        let record_object = record.as_object().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        let mut requested = Vec::new();

        for (field_name, nested_expands) in grouped {
            let field = collection
                .fields
                .iter()
                .find(|field| field.name == field_name)
                .ok_or_else(|| {
                    ServerError::BadRequest(format!(
                        "expand field '{field_name}' does not exist on collection '{}'",
                        collection.name
                    ))
                })?;
            if field.kind != CollectionFieldKind::Relation {
                return Err(ServerError::BadRequest(format!(
                    "expand field '{field_name}' is not a relation field"
                )));
            }

            let target_collection = field.collection.clone().ok_or_else(|| {
                ServerError::BadRequest(format!(
                    "relation field '{field_name}' does not declare a target collection"
                ))
            })?;

            if let Some(value) = record_object.get(&field_name).cloned() {
                requested.push((field_name, target_collection, nested_expands, value));
            }
        }

        let mut expanded = Map::new();
        for (field_name, target_collection, nested_expands, value) in requested {
            if let Some(expanded_value) =
                self.expand_relation_value(&target_collection, &value, &nested_expands, context)?
            {
                expanded.insert(field_name, expanded_value);
            }
        }

        if !expanded.is_empty() {
            let record_object = record.as_object_mut().ok_or_else(|| {
                ServerError::BadRequest("record response must be a JSON object".to_string())
            })?;
            record_object.insert("expand".to_string(), JsonValue::Object(expanded));
        }

        Ok(())
    }

    pub(crate) fn expand_relation_value(
        &self,
        target_collection: &str,
        value: &JsonValue,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<JsonValue>, ServerError> {
        if let Some(id) = value.as_str() {
            return Ok(self
                .expanded_related_record(target_collection, id, nested_expands, context)?
                .map(JsonValue::Object));
        }

        let Some(ids) = value.as_array() else {
            return Ok(None);
        };

        let mut records = Vec::new();
        for id in ids.iter().filter_map(JsonValue::as_str) {
            if let Some(record) =
                self.expanded_related_record(target_collection, id, nested_expands, context)?
            {
                records.push(JsonValue::Object(record));
            }
        }

        Ok(Some(JsonValue::Array(records)))
    }

    pub(crate) fn expanded_related_record(
        &self,
        target_collection: &str,
        id: &str,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<Map<String, JsonValue>>, ServerError> {
        let mut record = match self.get_record(target_collection, id, context.clone()) {
            Ok(record) => record,
            Err(ServerError::Forbidden(_) | ServerError::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        };

        if !nested_expands.is_empty() {
            let target = self.get_collection(target_collection)?;
            self.expand_record_with_collection(&target, &mut record, nested_expands, context)?;
        }

        let record = record.as_object().cloned().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        Ok(Some(record))
    }

    pub(crate) fn read_record(
        &self,
        collection_name: &str,
        id: &str,
    ) -> Result<JsonValue, ServerError> {
        validate_record_id(id)?;

        let collection = self.get_collection(collection_name)?;
        let conn = self.connection()?;
        read_record_with_connection(&conn, &collection, id)
    }

    pub(crate) fn record_exists(
        &self,
        collection_identifier: &str,
        id: &str,
    ) -> Result<bool, ServerError> {
        validate_record_id(id)?;
        let collection = self.get_collection(collection_identifier)?;
        if collection.collection_type == CollectionType::View {
            return Ok(self
                .get_view_record(&collection, id, FilterContext::default())
                .is_ok());
        }
        let table_sql = quote_identifier(&record_table_name(&collection.name)?);
        let conn = self.connection()?;
        let count = conn.query_row(
            &format!("SELECT COUNT(*) FROM {table_sql} WHERE id = ?1"),
            params![id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count > 0)
    }

    pub(crate) fn validate_record_relations_exist(
        &self,
        collection: &CollectionConfig,
        object: &Map<String, JsonValue>,
    ) -> Result<(), ServerError> {
        for field in &collection.fields {
            if field.kind != CollectionFieldKind::Relation {
                continue;
            }
            let Some(target_collection) = field
                .collection
                .as_deref()
                .map(str::trim)
                .filter(|target| !target.is_empty())
            else {
                continue;
            };
            let Some(value) = object.get(&field.name) else {
                continue;
            };
            if is_empty_record_value(value) {
                continue;
            }

            let ids = relation_field_ids(field, value)?;
            for id in ids {
                match self.record_exists(target_collection, id) {
                    Ok(true) => {}
                    Ok(false) | Err(ServerError::NotFound(_)) => {
                        return Err(invalid_relation_target_value(field));
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(())
    }

    pub(crate) fn enforce_incoming_record_rule(
        &self,
        collection: &CollectionConfig,
        rule: Option<&str>,
        record: &JsonValue,
        context: FilterContext,
        action: &str,
    ) -> Result<(), ServerError> {
        let Some(rule) = non_empty_rule(rule) else {
            return Ok(());
        };

        let resolver = IncomingRecordResolver::new(collection);
        let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
        let sql = format!(
            r#"WITH "__rb_input"("data") AS (SELECT ?) SELECT 1 FROM "__rb_input" WHERE ({}) LIMIT 1"#,
            compiled.sql
        );
        let mut params = vec![SqlValue::Text(serde_json::to_string(record)?)];
        params.extend(filter_params_to_sqlite(compiled.params)?);

        let conn = self.connection()?;
        let allowed = conn
            .query_row(&sql, params_from_iter(params.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .is_some();

        if allowed {
            Ok(())
        } else {
            Err(forbidden(action, &collection.name))
        }
    }

    pub(crate) fn enforce_existing_record_rule(
        &self,
        collection_name: &str,
        collection: &CollectionConfig,
        rule: Option<&str>,
        id: &str,
        context: FilterContext,
        action: &str,
    ) -> Result<(), ServerError> {
        let conn = self.connection()?;
        if self.existing_record_rule_allows_with_connection(
            &conn,
            collection_name,
            collection,
            rule,
            id,
            context,
        )? {
            Ok(())
        } else {
            Err(forbidden(action, collection_name))
        }
    }

    pub(crate) fn existing_record_rule_allows(
        &self,
        collection_name: &str,
        collection: &CollectionConfig,
        rule: Option<&str>,
        id: &str,
        context: FilterContext,
    ) -> Result<bool, ServerError> {
        let conn = self.connection()?;
        self.existing_record_rule_allows_with_connection(
            &conn,
            collection_name,
            collection,
            rule,
            id,
            context,
        )
    }

    pub(crate) fn existing_record_rule_allows_with_connection(
        &self,
        conn: &Connection,
        collection_name: &str,
        collection: &CollectionConfig,
        rule: Option<&str>,
        id: &str,
        context: FilterContext,
    ) -> Result<bool, ServerError> {
        if is_superuser_context(&context) {
            return Ok(true);
        }

        let Some(rule) = non_empty_rule(rule) else {
            return Ok(true);
        };

        let resolver = RecordResolver::new(collection);
        let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let sql = format!(
            "SELECT 1 FROM {table_sql} WHERE id = ? AND ({}) LIMIT 1",
            compiled.sql
        );
        let mut params = vec![SqlValue::Text(id.to_string())];
        params.extend(filter_params_to_sqlite(compiled.params)?);

        let allowed = conn
            .query_row(&sql, params_from_iter(params.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .is_some();

        Ok(allowed)
    }
}

pub(crate) fn read_record_with_connection(
    conn: &Connection,
    collection: &CollectionConfig,
    id: &str,
) -> Result<JsonValue, ServerError> {
    validate_record_id(id)?;
    let collection_name = collection.name.as_str();
    let collection_id = record_collection_id(collection);
    let table_sql = quote_identifier(&record_table_name(collection_name)?);
    conn.query_row(
        &format!("SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 LIMIT 1"),
        params![id],
        |row| row_to_record(collection_name, &collection_id, row),
    )
    .optional()?
    .ok_or_else(|| ServerError::NotFound(format!("record '{id}' not found")))
}
