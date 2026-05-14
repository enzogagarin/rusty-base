use super::*;

pub(crate) fn statement_column_names(stmt: &rusqlite::Statement<'_>) -> Vec<String> {
    stmt.column_names()
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(crate) fn validate_view_column_names(column_names: &[String]) -> Result<(), ServerError> {
    let mut seen = HashSet::new();
    for name in column_names {
        if !is_safe_identifier_part(name) {
            return Err(ServerError::BadRequest(format!(
                "viewQuery returned invalid column name '{name}'"
            )));
        }
        if is_reserved_view_column_name(name) {
            return Err(ServerError::BadRequest(format!(
                "viewQuery cannot return reserved column '{name}'"
            )));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(ServerError::BadRequest(format!(
                "viewQuery returned duplicate column '{name}'"
            )));
        }
    }

    Ok(())
}

pub(crate) fn is_reserved_view_column_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "collectionid" | "collectionname" | "expand"
    )
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

pub(crate) fn read_only_view_collection(collection_name: &str) -> ServerError {
    ServerError::BadRequest(format!("view collection '{collection_name}' is read-only"))
}

impl Store {
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
            validate_view_column_names(&column_names)?;
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
                validate_view_column_names(&column_names)?;
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
