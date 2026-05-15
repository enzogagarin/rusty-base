use super::profile::{oauth2_meta_payload, OAuth2Profile};
use super::provider::ensure_oauth2_provider_configured;
use super::*;
use crate::server::storage::*;

pub(crate) fn insert_oauth2_auth_record_tx(
    conn: &Connection,
    collection: &CollectionConfig,
    collection_name: &str,
    profile: &OAuth2Profile,
    create_data: &JsonValue,
) -> Result<String, ServerError> {
    let mut data = create_data.clone();
    let object = data.as_object_mut().ok_or_else(|| {
        validation_error(
            AUTH_FORM_VALIDATION_MESSAGE,
            "createData",
            "validation_invalid_body",
            "OAuth2 createData must be a JSON object.",
        )
    })?;
    object.remove("id");
    object.remove("created");
    object.remove("updated");
    object.remove("collectionId");
    object.remove("collectionName");
    object.remove("password");
    object.remove("passwordConfirm");
    object.remove("passwordHash");

    insert_profile_field(object, collection, "email", profile.email.as_deref());
    insert_profile_field(object, collection, "username", profile.username.as_deref());
    insert_profile_field(object, collection, "name", profile.name.as_deref());
    if collection_has_field(collection, "verified") {
        object.insert("verified".to_string(), JsonValue::Bool(true));
    }
    if collection_has_field(collection, "emailVisibility") {
        object.insert("emailVisibility".to_string(), JsonValue::Bool(false));
    }

    validate_record_fields(collection, object)?;
    let id = generate_id();
    let resolver = RecordResolver::new(collection);
    if let Some(rule) = non_empty_rule(collection.create_rule.as_deref()) {
        let context = context_with_body_values(FilterContext::default(), &data);
        let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
        let params = filter_params_to_sqlite(compiled.params)?;
        let allowed = conn.query_row(
            &format!("SELECT CASE WHEN ({}) THEN 1 ELSE 0 END", compiled.sql),
            params_from_iter(params.iter()),
            |row| row.get::<_, i64>(0),
        )? != 0;
        if !allowed {
            return Err(forbidden("create", &collection.name));
        }
    }

    let now = now_timestamp();
    let table_sql = quote_identifier(&record_table_name(collection_name)?);
    conn.execute(
        &format!("INSERT INTO {table_sql} (id, data, created, updated) VALUES (?1, ?2, ?3, ?3)"),
        params![&id, serde_json::to_string(&data)?, now],
    )?;
    Ok(id)
}

pub(crate) fn insert_profile_field(
    object: &mut Map<String, JsonValue>,
    collection: &CollectionConfig,
    field: &str,
    value: Option<&str>,
) {
    if object.contains_key(field) || !collection_has_field(collection, field) {
        return;
    }
    if let Some(value) = value {
        object.insert(field.to_string(), JsonValue::String(value.to_string()));
    }
}

pub(crate) fn collection_has_field(collection: &CollectionConfig, field: &str) -> bool {
    collection
        .fields
        .iter()
        .any(|candidate| candidate.name == field)
}

pub(crate) fn upsert_external_auth_account(
    conn: &Connection,
    collection_name: &str,
    provider: &str,
    provider_id: &str,
    record_id: &str,
    data: &JsonValue,
) -> Result<(), ServerError> {
    let now = now_timestamp();
    conn.execute(
        r#"
        INSERT INTO "_rb_auth_external_accounts"
            (collection_name, provider, provider_id, record_id, data, created, updated)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
        ON CONFLICT(collection_name, provider, provider_id)
        DO UPDATE SET record_id = excluded.record_id, data = excluded.data, updated = excluded.updated
        "#,
        params![
            collection_name,
            provider,
            provider_id,
            record_id,
            serde_json::to_string(data)?,
            now
        ],
    )?;
    Ok(())
}

impl Store {
    pub(crate) fn auth_with_oauth2_profile(
        &self,
        collection_name: &str,
        provider: &str,
        profile: OAuth2Profile,
        create_data: &JsonValue,
    ) -> Result<(AuthResponse, JsonValue), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        ensure_oauth2_provider_configured(&collection, provider)?;
        let conn = self.connection()?;
        let linked_record_id = conn
            .query_row(
                r#"
                SELECT record_id
                FROM "_rb_auth_external_accounts"
                WHERE collection_name = ?1 AND provider = ?2 AND provider_id = ?3
                LIMIT 1
                "#,
                params![collection_name, provider, &profile.provider_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let (record_id, is_new) = if let Some(record_id) = linked_record_id {
            (record_id, false)
        } else if let Some(email) = profile.email.as_deref() {
            let table_sql = quote_identifier(&record_table_name(collection_name)?);
            let record_id = conn
                .query_row(
                    &format!(
                        "SELECT id FROM {table_sql} WHERE json_extract(data, '$.email') = ?1 LIMIT 1"
                    ),
                    params![email],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(record_id) = record_id {
                (record_id, false)
            } else {
                (
                    insert_oauth2_auth_record_tx(
                        &conn,
                        &collection,
                        collection_name,
                        &profile,
                        create_data,
                    )?,
                    true,
                )
            }
        } else {
            (
                insert_oauth2_auth_record_tx(
                    &conn,
                    &collection,
                    collection_name,
                    &profile,
                    create_data,
                )?,
                true,
            )
        };

        let meta = oauth2_meta_payload(provider, &profile, is_new);
        upsert_external_auth_account(
            &conn,
            collection_name,
            provider,
            &profile.provider_id,
            &record_id,
            &meta,
        )?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let row = conn
            .query_row(
                &format!(
                    "SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 LIMIT 1"
                ),
                params![&record_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(invalid_credentials)?;

        let (id, data, created, updated) = row;
        let data = serde_json::from_str::<JsonValue>(&data)?;
        let (token, expires) = insert_auth_token(
            &conn,
            collection_name,
            &id,
            auth_token_ttl_millis(&collection),
        )?;

        Ok((
            AuthResponse {
                token,
                expires,
                record: record_from_parts(
                    collection_name,
                    &collection_id,
                    id,
                    data,
                    created,
                    updated,
                ),
            },
            meta,
        ))
    }
}
