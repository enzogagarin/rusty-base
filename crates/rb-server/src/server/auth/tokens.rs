use super::*;
use crate::server::{collections::*, records::*, storage::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenDurationConfig {
    #[serde(default)]
    pub duration: u64,
}

impl TokenDurationConfig {
    pub(crate) fn seconds(duration: u64) -> Self {
        Self { duration }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires: String,
    pub record: JsonValue,
}

pub(crate) fn auth_response_payload(
    store: &Store,
    collection_name: &str,
    mut response: AuthResponse,
    expands: &[String],
    fields: &[String],
    context: FilterContext,
) -> Result<JsonValue, ServerError> {
    let context = context_with_auth_record_values(context, &response.record);
    store.expand_record_response(collection_name, &mut response.record, expands, &context)?;
    let collection = store.get_collection(collection_name)?;
    sanitize_record_response(&collection, &mut response.record, &context)?;

    let mut payload = json!(response);
    project_json_response(&mut payload, fields)?;
    Ok(payload)
}

pub(crate) fn auth_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.auth_token, AUTH_TOKEN_TTL_MILLIS)
}

pub(crate) fn file_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.file_token, FILE_TOKEN_TTL_MILLIS)
}

pub(crate) fn duration_config_millis(
    config: Option<TokenDurationConfig>,
    default_millis: u128,
) -> u128 {
    config
        .map(|config| u128::from(config.duration) * 1000)
        .filter(|duration| *duration > 0)
        .unwrap_or(default_millis)
}

pub(crate) fn bearer_token(request: &HttpRequest) -> Option<&str> {
    let value = request.headers.get("authorization")?.trim();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .or_else(|| {
            if value.is_empty() || value.contains(char::is_whitespace) {
                None
            } else {
                Some(value)
            }
        })
}

pub(crate) fn context_with_auth_record_values(
    mut context: FilterContext,
    record: &JsonValue,
) -> FilterContext {
    let Some(object) = record.as_object() else {
        return context;
    };

    for (name, value) in object {
        context = context.with_auth_value(name.clone(), json_to_filter_value(value));
    }

    context
}

pub(crate) fn invalid_credentials() -> ServerError {
    ServerError::BadRequest("Failed to authenticate.".to_string())
}

pub(crate) fn ensure_auth_token_columns(conn: &Connection) -> Result<(), ServerError> {
    let mut stmt = conn.prepare(r#"PRAGMA table_info("_rb_auth_tokens")"#)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let columns = rows.collect::<Result<Vec<_>, _>>()?;
    let has_expires = columns.iter().any(|name| name == "expires");
    let has_renewable = columns.iter().any(|name| name == "renewable");

    if !has_expires {
        conn.execute(
            r#"ALTER TABLE "_rb_auth_tokens" ADD COLUMN expires TEXT NOT NULL DEFAULT '0'"#,
            [],
        )?;
        conn.execute(
            r#"
            UPDATE "_rb_auth_tokens"
            SET expires = CAST(CAST(created AS INTEGER) + CAST(?1 AS INTEGER) AS TEXT)
            WHERE expires = '0'
            "#,
            params![AUTH_TOKEN_TTL_MILLIS.to_string()],
        )?;
    }
    if !has_renewable {
        conn.execute(
            r#"ALTER TABLE "_rb_auth_tokens" ADD COLUMN renewable INTEGER NOT NULL DEFAULT 1"#,
            [],
        )?;
    }

    Ok(())
}

pub(crate) fn insert_auth_token(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    ttl_millis: u128,
) -> Result<(String, String), ServerError> {
    insert_auth_token_with_renewable(conn, collection_name, record_id, ttl_millis, true)
}

pub(crate) fn insert_auth_token_with_renewable(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    ttl_millis: u128,
    renewable: bool,
) -> Result<(String, String), ServerError> {
    let token = generate_token();
    let now = now_millis();
    let expires = (now + ttl_millis).to_string();
    conn.execute(
        r#"
        INSERT INTO "_rb_auth_tokens"
            (token, collection_name, record_id, created, expires, renewable)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            &token,
            collection_name,
            record_id,
            now.to_string(),
            &expires,
            if renewable { 1 } else { 0 }
        ],
    )?;

    Ok((token, expires))
}

impl Store {
    pub fn auth_refresh(
        &self,
        collection_name: &str,
        token: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        let (token_collection_name, record_id, renewable) = self.valid_auth_token_subject(token)?;
        if token_collection_name != collection_name {
            return Err(ServerError::Forbidden("invalid auth token".to_string()));
        }
        if !renewable {
            return Err(ServerError::Forbidden(
                "impersonate auth tokens cannot be refreshed".to_string(),
            ));
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
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
            .ok_or_else(|| ServerError::Forbidden("auth record not found".to_string()))?;

        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE token = ?1"#,
            params![token],
        )?;
        let (new_token, expires) = insert_auth_token(
            &conn,
            collection_name,
            &record_id,
            auth_token_ttl_millis(&collection),
        )?;
        drop(conn);

        let (id, data, created, updated) = row;
        Ok(AuthResponse {
            token: new_token,
            expires,
            record: record_from_parts(
                collection_name,
                &collection_id,
                id,
                serde_json::from_str::<JsonValue>(&data)?,
                created,
                updated,
            ),
        })
    }
}

impl Store {
    pub fn revoke_auth_token(&self, collection_name: &str, token: &str) -> Result<(), ServerError> {
        let (token_collection_name, _) = self.valid_token_subject(token)?;
        if token_collection_name != collection_name {
            return Err(ServerError::Forbidden("invalid auth token".to_string()));
        }

        let conn = self.connection()?;
        let affected = conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE token = ?1"#,
            params![token],
        )?;
        if affected == 0 {
            return Err(ServerError::Forbidden("invalid auth token".to_string()));
        }

        Ok(())
    }
}

impl Store {
    pub fn context_for_token(
        &self,
        token: &str,
        context: FilterContext,
    ) -> Result<FilterContext, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(token)?;
        let record = self.read_record(&collection_name, &record_id)?;
        Ok(context_with_auth_record_values(context, &record))
    }
}

impl Store {
    pub fn expire_token(&self, token: &str) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute(
            r#"UPDATE "_rb_auth_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", token],
        )?;
        Ok(())
    }

    pub(crate) fn valid_token_subject(&self, token: &str) -> Result<(String, String), ServerError> {
        let (collection_name, record_id, _) = self.valid_auth_token_subject(token)?;
        Ok((collection_name, record_id))
    }

    pub(crate) fn valid_auth_token_subject(
        &self,
        token: &str,
    ) -> Result<(String, String, bool), ServerError> {
        let conn = self.connection()?;
        let token_row = conn
            .query_row(
                r#"
                SELECT collection_name, record_id, expires, renewable
                FROM "_rb_auth_tokens"
                WHERE token = ?1
                "#,
                params![token],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| ServerError::Forbidden("invalid auth token".to_string()))?;
        let (collection_name, record_id, expires, renewable) = token_row;
        let expires = expires
            .parse::<u128>()
            .map_err(|_| ServerError::Forbidden("invalid auth token".to_string()))?;
        if expires <= now_millis() {
            return Err(ServerError::Forbidden("expired auth token".to_string()));
        }

        Ok((collection_name, record_id, renewable != 0))
    }

    pub(crate) fn valid_subject_token(
        &self,
        table_name: &str,
        token: &str,
        label: &str,
    ) -> Result<(String, String), ServerError> {
        let table_sql = quote_identifier(table_name);
        let conn = self.connection()?;
        let token_row = conn
            .query_row(
                &format!(
                    r#"
                    SELECT collection_name, record_id, expires
                    FROM {table_sql}
                    WHERE token = ?1
                    "#
                ),
                params![token],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| ServerError::Forbidden(format!("invalid {label} token")))?;
        let (collection_name, record_id, expires) = token_row;
        let expires = expires
            .parse::<u128>()
            .map_err(|_| ServerError::Forbidden(format!("invalid {label} token")))?;
        if expires <= now_millis() {
            return Err(ServerError::Forbidden(format!("expired {label} token")));
        }

        Ok((collection_name, record_id))
    }
}
