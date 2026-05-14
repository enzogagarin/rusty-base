use super::*;
use super::{auth::*, collections::*, files::*, http::*, storage::*, validation::*};

mod cascade;
mod expand;
mod mutation;
mod projection;
mod query;
mod rules;
mod view;

pub(crate) use expand::*;
pub(crate) use mutation::*;
pub(crate) use projection::*;
pub(crate) use query::*;
pub use query::{ListOptions, RecordList};
pub(crate) use rules::*;
pub(crate) use view::*;

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
