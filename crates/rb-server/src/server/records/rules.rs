use super::*;

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

pub(crate) fn non_empty_rule(rule: Option<&str>) -> Option<&str> {
    rule.filter(|rule| !rule.trim().is_empty())
}

pub(crate) fn forbidden(action: &str, collection_name: &str) -> ServerError {
    ServerError::Forbidden(format!(
        "{action} rule denied access to collection '{collection_name}'"
    ))
}

impl Store {
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
