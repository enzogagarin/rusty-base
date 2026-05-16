use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionImportRequest {
    pub collections: Vec<CollectionConfig>,
    #[serde(default)]
    pub delete_missing: bool,
}

impl CollectionImportRequest {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        if value.is_array() {
            return Ok(Self {
                collections: serde_json::from_value(value)?,
                delete_missing: false,
            });
        }

        Ok(serde_json::from_value(value)?)
    }
}

pub(crate) fn collection_export_payload(collections: Vec<CollectionConfig>) -> JsonValue {
    json!({
        "collections": collections
            .into_iter()
            .map(collection_export_value)
            .collect::<Vec<_>>()
    })
}

pub(crate) fn collection_export_value(collection: CollectionConfig) -> JsonValue {
    let id = collection_id_value(&collection).unwrap_or_else(|| collection.name.clone());
    let is_view_collection = collection.collection_type == CollectionType::View;
    let view_query = collection.view_query;
    let mut value = json!({
        "id": id,
        "name": collection.name,
        "type": collection.collection_type,
        "schema": collection.fields
            .into_iter()
            .map(collection_field_export_value)
            .collect::<Vec<_>>(),
        "indexes": collection.indexes,
        "listRule": collection.list_rule,
        "viewRule": collection.view_rule,
        "createRule": collection.create_rule,
        "updateRule": collection.update_rule,
        "deleteRule": collection.delete_rule
    });
    let object = value.as_object_mut().expect("export value must be object");
    if is_view_collection || !view_query.is_empty() {
        object.insert("viewQuery".to_string(), json!(view_query));
    }
    insert_optional_json(object, "authRule", collection.auth_rule);
    insert_optional_json(object, "manageRule", collection.manage_rule);
    insert_optional_json(object, "passwordAuth", collection.password_auth);
    insert_optional_json(object, "authToken", collection.auth_token);
    insert_optional_json(
        object,
        "passwordResetToken",
        collection.password_reset_token,
    );
    insert_optional_json(object, "emailChangeToken", collection.email_change_token);
    insert_optional_json(object, "verificationToken", collection.verification_token);
    insert_optional_json(object, "fileToken", collection.file_token);
    insert_optional_json(
        object,
        "verificationTemplate",
        collection.verification_template,
    );
    insert_optional_json(
        object,
        "passwordResetTemplate",
        collection.password_reset_template,
    );
    insert_optional_json(
        object,
        "emailChangeTemplate",
        collection.email_change_template,
    );
    insert_optional_json(object, "oauth2", collection.oauth2);
    insert_optional_json(object, "mfa", collection.mfa);
    insert_optional_json(object, "otp", collection.otp);
    value
}

pub(crate) fn insert_optional_json<T: Serialize>(
    object: &mut Map<String, JsonValue>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

pub(crate) fn collection_field_export_value(field: CollectionField) -> JsonValue {
    let mut value = Map::new();
    if let Some(id) = field.id {
        value.insert("id".to_string(), JsonValue::String(id));
    }
    value.insert("name".to_string(), JsonValue::String(field.name));
    value.insert("type".to_string(), json!(field.kind));
    if let Some(collection) = field.collection {
        value.insert("collection".to_string(), JsonValue::String(collection));
    }
    if let Some(min_select) = field.min_select {
        value.insert("minSelect".to_string(), json!(min_select));
    }
    if let Some(max_select) = field.max_select {
        value.insert("maxSelect".to_string(), json!(max_select));
    }
    if let Some(max_size) = field.max_size {
        value.insert("maxSize".to_string(), json!(max_size));
    }
    if let Some(min) = field.min {
        value.insert("min".to_string(), json!(min));
    }
    if let Some(max) = field.max {
        value.insert("max".to_string(), json!(max));
    }
    if let Some(pattern) = field.pattern {
        value.insert("pattern".to_string(), JsonValue::String(pattern));
    }
    if let Some(autogenerate_pattern) = field.autogenerate_pattern {
        value.insert(
            "autogeneratePattern".to_string(),
            JsonValue::String(autogenerate_pattern),
        );
    }
    if !field.mime_types.is_empty() {
        value.insert("mimeTypes".to_string(), json!(field.mime_types));
    }
    if !field.thumbs.is_empty() {
        value.insert("thumbs".to_string(), json!(field.thumbs));
    }
    if !field.values.is_empty() {
        value.insert("values".to_string(), json!(field.values));
    }
    if !field.only_domains.is_empty() {
        value.insert("onlyDomains".to_string(), json!(field.only_domains));
    }
    if !field.except_domains.is_empty() {
        value.insert("exceptDomains".to_string(), json!(field.except_domains));
    }
    if field.on_create {
        value.insert("onCreate".to_string(), JsonValue::Bool(true));
    }
    if field.on_update {
        value.insert("onUpdate".to_string(), JsonValue::Bool(true));
    }
    value.insert("required".to_string(), JsonValue::Bool(field.required));
    value.insert("system".to_string(), JsonValue::Bool(field.system));
    value.insert("hidden".to_string(), JsonValue::Bool(field.hidden));
    value.insert(
        "presentable".to_string(),
        JsonValue::Bool(field.presentable),
    );
    value.insert("primaryKey".to_string(), JsonValue::Bool(field.primary_key));
    if field.protected {
        value.insert("protected".to_string(), JsonValue::Bool(true));
    }
    if field.cascade_delete {
        value.insert("cascadeDelete".to_string(), JsonValue::Bool(true));
    }

    JsonValue::Object(value)
}

pub(crate) fn existing_collections_tx(
    tx: &rusqlite::Transaction<'_>,
) -> Result<HashMap<String, CollectionConfig>, ServerError> {
    let mut stmt = tx.prepare(r#"SELECT name, schema_json FROM "_rb_collections""#)?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut collections = HashMap::new();

    for row in rows {
        let (name, schema_json) = row?;
        collections.insert(name, serde_json::from_str(&schema_json)?);
    }

    Ok(collections)
}

pub(crate) fn merge_imported_collection(
    current: &CollectionConfig,
    mut imported: CollectionConfig,
    delete_missing: bool,
) -> CollectionConfig {
    if imported
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .is_none()
    {
        imported.id = current.id.clone();
    }
    preserve_collection_field_ids(&current.fields, &mut imported.fields);

    if delete_missing {
        return imported;
    }

    let mut imported_fields = HashMap::new();
    for field in &imported.fields {
        imported_fields.insert(field.name.clone(), ());
    }

    for field in &current.fields {
        if !imported_fields.contains_key(&field.name) {
            imported.fields.push(field.clone());
        }
    }

    imported
}

pub(crate) fn prune_record_fields_tx(
    tx: &rusqlite::Transaction<'_>,
    collection_name: &str,
    fields: &[CollectionField],
) -> Result<(), ServerError> {
    let table_sql = quote_identifier(&record_table_name(collection_name)?);
    let updates = {
        let mut stmt = tx.prepare(&format!("SELECT id, data FROM {table_sql}"))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut updates = Vec::new();

        for row in rows {
            let (id, data) = row?;
            let mut data = serde_json::from_str::<JsonValue>(&data)?;
            let Some(object) = data.as_object_mut() else {
                continue;
            };

            let original_len = object.len();
            object.retain(|key, _| {
                is_system_record_key(key) || fields.iter().any(|field| field.name == *key)
            });

            if object.len() != original_len {
                updates.push((id, serde_json::to_string(&data)?));
            }
        }

        updates
    };

    let now = now_timestamp();
    for (id, data) in updates {
        tx.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![data, &now, id],
        )?;
    }

    Ok(())
}

impl Store {
    pub fn import_collections(&self, request: CollectionImportRequest) -> Result<(), ServerError> {
        let mut incoming_names = HashMap::new();
        let mut incoming_ids = HashMap::new();
        for collection in &request.collections {
            validate_collection_name(&collection.name)?;
            if incoming_names.insert(collection.name.clone(), ()).is_some() {
                return Err(ServerError::BadRequest(format!(
                    "duplicate collection '{}'",
                    collection.name
                )));
            }
            if let Some(id) = collection
                .id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
            {
                validate_collection_id(id)?;
                if incoming_ids.insert(id.to_string(), ()).is_some() {
                    return Err(ServerError::BadRequest(format!(
                        "duplicate collection id '{id}'"
                    )));
                }
            }
        }

        let now = now_timestamp();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let existing = existing_collections_tx(&tx)?;

        if request.delete_missing {
            for name in existing.keys() {
                if incoming_names.contains_key(name) {
                    continue;
                }

                let table_sql = quote_identifier(&record_table_name(name)?);
                tx.execute(&format!("DROP TABLE IF EXISTS {table_sql}"), [])?;
                tx.execute(
                    r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
                    params![name],
                )?;
                tx.execute(
                    r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
                    params![name],
                )?;
                tx.execute(
                    r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
                    params![name],
                )?;
                tx.execute(
                    r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
                    params![name],
                )?;
                tx.execute(
                    r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
                    params![name],
                )?;
                tx.execute(
                    r#"DELETE FROM "_rb_collections" WHERE name = ?1"#,
                    params![name],
                )?;
            }
        }

        for imported in request.collections {
            let mut collection = if let Some(current) = existing.get(&imported.name) {
                merge_imported_collection(current, imported, request.delete_missing)
            } else {
                imported
            };
            normalize_collection(&mut collection);
            validate_collection(&collection)?;
            let existing_name = existing
                .get(&collection.name)
                .map(|existing| existing.name.as_str());
            ensure_collection_identifier_available_tx(&tx, &collection.name, existing_name)?;
            if let Some(id) = collection.id.as_deref() {
                ensure_collection_identifier_available_tx(&tx, id, existing_name)?;
            }
            if let Some(current) = existing.get(&collection.name) {
                if collection_owns_record_table(current) {
                    drop_safe_collection_indexes(&tx, current)?;
                }
            }

            let table_sql = quote_identifier(&record_table_name(&collection.name)?);
            if collection_owns_record_table(&collection) {
                tx.execute(
                    &format!(
                        r#"
                        CREATE TABLE IF NOT EXISTS {table_sql} (
                            id TEXT PRIMARY KEY NOT NULL,
                            data TEXT NOT NULL,
                            created TEXT NOT NULL,
                            updated TEXT NOT NULL
                        )
                        "#
                    ),
                    [],
                )?;
            } else {
                tx.execute(&format!("DROP TABLE IF EXISTS {table_sql}"), [])?;
            }

            if let Some(current) = existing.get(&collection.name) {
                if current.collection_type == CollectionType::Auth
                    && collection.collection_type != CollectionType::Auth
                {
                    tx.execute(
                        r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
                        params![&collection.name],
                    )?;
                    tx.execute(
                        r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
                        params![&collection.name],
                    )?;
                    tx.execute(
                        r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
                        params![&collection.name],
                    )?;
                    tx.execute(
                        r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
                        params![&collection.name],
                    )?;
                }
                if request.delete_missing {
                    prune_record_fields_tx(&tx, &collection.name, &collection.fields)?;
                }
            }

            let schema_json = serde_json::to_string(&collection)?;
            let affected = tx.execute(
                r#"
                UPDATE "_rb_collections"
                SET schema_json = ?2, updated = ?3
                WHERE name = ?1
                "#,
                params![&collection.name, schema_json, &now],
            )?;
            if affected == 0 {
                tx.execute(
                    r#"
                    INSERT INTO "_rb_collections" (name, schema_json, created, updated)
                    VALUES (?1, ?2, ?3, ?3)
                    "#,
                    params![&collection.name, schema_json, &now],
                )?;
            }
            if collection_owns_record_table(&collection) {
                apply_safe_collection_indexes(&tx, &collection)?;
            }
        }

        tx.commit()?;
        Ok(())
    }
}
