use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::{OsRng, RngCore};
use rb_filter_engine::{
    compile_filter_with_resolver_and_context, FieldKind, FieldResolver, FilterContext, FilterError,
    ResolvedField, Value as FilterValue,
};
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use std::{
    collections::HashMap,
    fmt, io,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const AUTH_TOKEN_TTL_MILLIS: u128 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug)]
pub enum ServerError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Storage(rusqlite::Error),
    Json(serde_json::Error),
    Filter(FilterError),
    Io(io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(message) => write!(f, "{message}"),
            Self::Forbidden(message) => write!(f, "{message}"),
            Self::NotFound(message) => write!(f, "{message}"),
            Self::Storage(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Filter(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<rusqlite::Error> for ServerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

impl From<serde_json::Error> for ServerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<FilterError> for ServerError {
    fn from(value: FilterError) -> Self {
        Self::Filter(value)
    }
}

impl From<io::Error> for ServerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionConfig {
    pub name: String,
    #[serde(default, rename = "type")]
    pub collection_type: CollectionType,
    #[serde(default)]
    pub fields: Vec<CollectionField>,
    #[serde(default)]
    pub list_rule: Option<String>,
    #[serde(default)]
    pub view_rule: Option<String>,
    #[serde(default)]
    pub create_rule: Option<String>,
    #[serde(default)]
    pub update_rule: Option<String>,
    #[serde(default)]
    pub delete_rule: Option<String>,
}

impl CollectionConfig {
    pub fn new(name: impl Into<String>, fields: impl IntoIterator<Item = CollectionField>) -> Self {
        Self {
            name: name.into(),
            collection_type: CollectionType::Base,
            fields: fields.into_iter().collect(),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
        }
    }

    pub fn auth(
        name: impl Into<String>,
        fields: impl IntoIterator<Item = CollectionField>,
    ) -> Self {
        Self {
            collection_type: CollectionType::Auth,
            ..Self::new(name, fields)
        }
    }

    pub fn with_type(mut self, collection_type: CollectionType) -> Self {
        self.collection_type = collection_type;
        self
    }

    pub fn with_list_rule(mut self, rule: impl Into<String>) -> Self {
        self.list_rule = Some(rule.into());
        self
    }

    pub fn with_view_rule(mut self, rule: impl Into<String>) -> Self {
        self.view_rule = Some(rule.into());
        self
    }

    pub fn with_create_rule(mut self, rule: impl Into<String>) -> Self {
        self.create_rule = Some(rule.into());
        self
    }

    pub fn with_update_rule(mut self, rule: impl Into<String>) -> Self {
        self.update_rule = Some(rule.into());
        self
    }

    pub fn with_delete_rule(mut self, rule: impl Into<String>) -> Self {
        self.delete_rule = Some(rule.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CollectionType {
    #[default]
    Base,
    Auth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionField {
    pub name: String,
    pub kind: CollectionFieldKind,
}

impl CollectionField {
    pub fn new(name: impl Into<String>, kind: CollectionFieldKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionFieldKind {
    Text,
    Number,
    Bool,
    #[serde(rename = "datetime")]
    DateTime,
    Array,
    Json,
    Relation,
}

impl From<CollectionFieldKind> for FieldKind {
    fn from(value: CollectionFieldKind) -> Self {
        match value {
            CollectionFieldKind::Text => Self::Text,
            CollectionFieldKind::Number => Self::Number,
            CollectionFieldKind::Bool => Self::Bool,
            CollectionFieldKind::DateTime => Self::DateTime,
            CollectionFieldKind::Array => Self::Array,
            CollectionFieldKind::Json => Self::Json,
            CollectionFieldKind::Relation => Self::Relation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    pub page: u64,
    pub per_page: u64,
    pub filter: Option<String>,
    pub context: FilterContext,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 30,
            filter: None,
            context: FilterContext::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordList {
    pub page: u64,
    pub per_page: u64,
    pub total_items: u64,
    pub total_pages: u64,
    pub items: Vec<JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires: String,
    pub record: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuthWithPasswordRequest {
    identity: String,
    password: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, ServerError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, ServerError> {
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS "_rb_collections" (
                name TEXT PRIMARY KEY NOT NULL,
                schema_json TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS "_rb_auth_tokens" (
                token TEXT PRIMARY KEY NOT NULL,
                collection_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                created TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            "#,
        )?;
        ensure_auth_token_expires_column(&conn)?;
        Ok(())
    }

    pub fn create_collection(
        &self,
        collection: CollectionConfig,
    ) -> Result<CollectionConfig, ServerError> {
        validate_collection(&collection)?;

        let now = now_timestamp();
        let schema_json = serde_json::to_string(&collection)?;
        let table = record_table_name(&collection.name)?;
        let table_sql = quote_identifier(&table);
        let conn = self.connection()?;

        conn.execute(
            r#"
            INSERT INTO "_rb_collections" (name, schema_json, created, updated)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![&collection.name, schema_json, now],
        )?;
        conn.execute(
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

        Ok(collection)
    }

    pub fn get_collection(&self, name: &str) -> Result<CollectionConfig, ServerError> {
        validate_collection_name(name)?;
        let conn = self.connection()?;
        let schema_json = conn
            .query_row(
                r#"SELECT schema_json FROM "_rb_collections" WHERE name = ?1"#,
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| ServerError::NotFound(format!("collection '{name}' not found")))?;

        Ok(serde_json::from_str(&schema_json)?)
    }

    pub fn list_collections(&self) -> Result<Vec<CollectionConfig>, ServerError> {
        let conn = self.connection()?;
        let mut stmt =
            conn.prepare(r#"SELECT schema_json FROM "_rb_collections" ORDER BY name ASC"#)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

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
        mut data: JsonValue,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        let collection = self.get_collection(collection_name)?;
        let object = data_object_mut(&mut data)?;
        validate_record_fields(&collection, object)?;
        prepare_auth_password(&collection, object, true)?;

        let id = object
            .remove("id")
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(generate_id);
        validate_record_id(&id)?;

        object.remove("created");
        object.remove("updated");
        object.remove("collectionName");

        let mut rule_data = data.clone();
        if let Some(object) = rule_data.as_object_mut() {
            object.insert("id".to_string(), JsonValue::String(id.clone()));
        }
        let context = context_with_body_values(context, &data);
        self.enforce_incoming_record_rule(
            &collection,
            collection.create_rule.as_deref(),
            &rule_data,
            context,
            "create",
        )?;

        let now = now_timestamp();
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data_json = serde_json::to_string(&data)?;
        let conn = self.connection()?;
        conn.execute(
            &format!(
                "INSERT INTO {table_sql} (id, data, created, updated) VALUES (?1, ?2, ?3, ?3)"
            ),
            params![id, data_json, now],
        )?;
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
        let resolver = RecordResolver::new(&collection);
        let mut params = vec![SqlValue::Text(id.to_string())];
        let mut where_parts = vec!["id = ?".to_string()];

        if let Some(rule) = collection
            .view_rule
            .as_deref()
            .filter(|rule| !rule.trim().is_empty())
        {
            let compiled = compile_filter_with_resolver_and_context(rule, &resolver, context)?;
            where_parts.push(format!("({})", compiled.sql));
            params.extend(filter_params_to_sqlite(compiled.params)?);
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let sql = format!(
            "SELECT id, data, created, updated FROM {table_sql} WHERE {} LIMIT 1",
            where_parts.join(" AND ")
        );
        let conn = self.connection()?;
        conn.query_row(&sql, params_from_iter(params.iter()), |row| {
            row_to_record(collection_name, row)
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
        let resolver = RecordResolver::new(&collection);
        let predicate = compile_list_predicate(&collection, &resolver, &options)?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let where_sql = predicate
            .sql
            .as_ref()
            .map(|sql| format!(" WHERE {sql}"))
            .unwrap_or_default();
        let offset = options.page.saturating_sub(1) * options.per_page;

        let conn = self.connection()?;
        let count_sql = format!("SELECT COUNT(*) FROM {table_sql}{where_sql}");
        let total_items: u64 = conn.query_row(
            &count_sql,
            params_from_iter(predicate.params.iter()),
            |row| row.get::<_, u64>(0),
        )?;

        let list_sql = format!(
            "SELECT id, data, created, updated FROM {table_sql}{where_sql} ORDER BY created DESC, id ASC LIMIT ? OFFSET ?"
        );
        let mut list_params = predicate.params;
        list_params.push(SqlValue::Integer(options.per_page as i64));
        list_params.push(SqlValue::Integer(offset as i64));

        let mut stmt = conn.prepare(&list_sql)?;
        let rows = stmt.query_map(params_from_iter(list_params.iter()), |row| {
            row_to_record(collection_name, row)
        })?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        let total_pages = if total_items == 0 {
            0
        } else {
            total_items.div_ceil(options.per_page)
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
        validate_record_id(id)?;
        let collection = self.get_collection(collection_name)?;
        let mut patch = patch;
        {
            let patch_object = data_object_mut(&mut patch)?;
            validate_record_fields(&collection, patch_object)?;
            prepare_auth_password(&collection, patch_object, false)?;
        }

        let mut existing = self.read_record(collection_name, id)?;
        let context = context_with_body_values(context, &patch);
        self.enforce_existing_record_rule(
            collection_name,
            &collection,
            collection.update_rule.as_deref(),
            id,
            context,
            "update",
        )?;

        let existing_object = existing.as_object_mut().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        let patch_object = data_object(&patch)?;

        existing_object.remove("id");
        existing_object.remove("created");
        existing_object.remove("updated");
        existing_object.remove("collectionName");

        for (key, value) in patch_object {
            if !is_system_record_key(key) {
                existing_object.insert(key.clone(), value.clone());
            }
        }

        let now = now_timestamp();
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data_json = serde_json::to_string(&existing)?;
        let conn = self.connection()?;
        let affected = conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![data_json, now, id],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!("record '{id}' not found")));
        }
        drop(conn);

        self.read_record(collection_name, id)
    }

    pub fn delete_record(&self, collection_name: &str, id: &str) -> Result<(), ServerError> {
        self.delete_record_with_context(collection_name, id, FilterContext::default())
    }

    pub fn delete_record_with_context(
        &self,
        collection_name: &str,
        id: &str,
        context: FilterContext,
    ) -> Result<(), ServerError> {
        validate_record_id(id)?;
        let collection = self.get_collection(collection_name)?;
        self.read_record(collection_name, id)?;
        self.enforce_existing_record_rule(
            collection_name,
            &collection,
            collection.delete_rule.as_deref(),
            id,
            context,
            "delete",
        )?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let affected = conn.execute(
            &format!("DELETE FROM {table_sql} WHERE id = ?1"),
            params![id],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!("record '{id}' not found")));
        }

        Ok(())
    }

    pub fn auth_with_password(
        &self,
        collection_name: &str,
        identity: &str,
        password: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type != CollectionType::Auth {
            return Err(ServerError::BadRequest(format!(
                "collection '{collection_name}' is not an auth collection"
            )));
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let row = conn
            .query_row(
                &format!(
                    "SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 OR json_extract(data, '$.email') = ?1 OR json_extract(data, '$.username') = ?1 LIMIT 1"
                ),
                params![identity],
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
        let password_hash = data
            .as_object()
            .and_then(|object| object.get("passwordHash"))
            .and_then(JsonValue::as_str)
            .ok_or_else(invalid_credentials)?;
        verify_password(password, password_hash)?;

        let (token, expires) = insert_auth_token(&conn, collection_name, &id)?;
        drop(conn);

        Ok(AuthResponse {
            token,
            expires,
            record: record_from_parts(collection_name, id, data, created, updated),
        })
    }

    pub fn auth_refresh(
        &self,
        collection_name: &str,
        token: &str,
    ) -> Result<AuthResponse, ServerError> {
        let (token_collection_name, record_id) = self.valid_token_subject(token)?;
        if token_collection_name != collection_name {
            return Err(ServerError::Forbidden("invalid auth token".to_string()));
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
        let (new_token, expires) = insert_auth_token(&conn, collection_name, &record_id)?;
        drop(conn);

        let (id, data, created, updated) = row;
        Ok(AuthResponse {
            token: new_token,
            expires,
            record: record_from_parts(
                &collection_name,
                id,
                serde_json::from_str::<JsonValue>(&data)?,
                created,
                updated,
            ),
        })
    }

    pub fn context_for_token(
        &self,
        token: &str,
        context: FilterContext,
    ) -> Result<FilterContext, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(token)?;
        let record = self.read_record(&collection_name, &record_id)?;
        Ok(context_with_auth_record_values(context, &record))
    }

    pub fn expire_token(&self, token: &str) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute(
            r#"UPDATE "_rb_auth_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", token],
        )?;
        Ok(())
    }

    fn valid_token_subject(&self, token: &str) -> Result<(String, String), ServerError> {
        let conn = self.connection()?;
        let token_row = conn
            .query_row(
                r#"
                SELECT collection_name, record_id, expires
                FROM "_rb_auth_tokens"
                WHERE token = ?1
                "#,
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
            .ok_or_else(|| ServerError::Forbidden("invalid auth token".to_string()))?;
        let (collection_name, record_id, expires) = token_row;
        let expires = expires
            .parse::<u128>()
            .map_err(|_| ServerError::Forbidden("invalid auth token".to_string()))?;
        if expires <= now_millis() {
            return Err(ServerError::Forbidden("expired auth token".to_string()));
        }

        Ok((collection_name, record_id))
    }

    fn read_record(&self, collection_name: &str, id: &str) -> Result<JsonValue, ServerError> {
        validate_record_id(id)?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        conn.query_row(
            &format!("SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 LIMIT 1"),
            params![id],
            |row| row_to_record(collection_name, row),
        )
        .optional()?
        .ok_or_else(|| ServerError::NotFound(format!("record '{id}' not found")))
    }

    fn enforce_incoming_record_rule(
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

    fn enforce_existing_record_rule(
        &self,
        collection_name: &str,
        collection: &CollectionConfig,
        rule: Option<&str>,
        id: &str,
        context: FilterContext,
        action: &str,
    ) -> Result<(), ServerError> {
        let Some(rule) = non_empty_rule(rule) else {
            return Ok(());
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
            Err(forbidden(action, collection_name))
        }
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, ServerError> {
        self.conn
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))
    }
}

#[derive(Clone)]
pub struct RustyBaseApp {
    store: Arc<Store>,
}

impl RustyBaseApp {
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn handle(&self, request: HttpRequest) -> HttpResponse {
        match self.handle_result(request) {
            Ok(response) => response,
            Err(err) => error_response(err),
        }
    }

    fn handle_result(&self, request: HttpRequest) -> Result<HttpResponse, ServerError> {
        let (path, query) = split_path_query(&request.path);
        let segments = path_segments(&path);
        let segments = segments.iter().map(String::as_str).collect::<Vec<_>>();

        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["api", "health"]) => Ok(HttpResponse::json(
                200,
                json!({"code": 200, "message": "API is healthy."}),
            )),
            ("GET", ["api", "collections"]) => {
                let collections = self.store.list_collections()?;
                Ok(HttpResponse::json(200, json!({"items": collections})))
            }
            ("POST", ["api", "collections"]) => {
                let collection: CollectionConfig = serde_json::from_slice(&request.body)?;
                let collection = self.store.create_collection(collection)?;
                Ok(HttpResponse::json(200, json!(collection)))
            }
            ("POST", ["api", "collections", collection, "auth-with-password"]) => {
                let auth: AuthWithPasswordRequest = serde_json::from_slice(&request.body)?;
                let response =
                    self.store
                        .auth_with_password(collection, &auth.identity, &auth.password)?;
                Ok(HttpResponse::json(200, json!(response)))
            }
            ("POST", ["api", "collections", collection, "auth-refresh"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let response = self.store.auth_refresh(collection, token)?;
                Ok(HttpResponse::json(200, json!(response)))
            }
            ("GET", ["api", "collections", collection, "records"]) => {
                let options =
                    list_options_from_query(&query, self.request_context(&request, &query)?)?;
                let list = self.store.list_records(collection, options)?;
                Ok(HttpResponse::json(200, json!(list)))
            }
            ("POST", ["api", "collections", collection, "records"]) => {
                let data: JsonValue = serde_json::from_slice(&request.body)?;
                let record = self.store.create_record_with_context(
                    collection,
                    data,
                    self.request_context(&request, &query)?,
                )?;
                Ok(HttpResponse::json(200, record))
            }
            ("GET", ["api", "collections", collection, "records", id]) => {
                let record = self.store.get_record(
                    collection,
                    id,
                    self.request_context(&request, &query)?,
                )?;
                Ok(HttpResponse::json(200, record))
            }
            ("PATCH", ["api", "collections", collection, "records", id]) => {
                let patch: JsonValue = serde_json::from_slice(&request.body)?;
                let record = self.store.update_record_with_context(
                    collection,
                    id,
                    patch,
                    self.request_context(&request, &query)?,
                )?;
                Ok(HttpResponse::json(200, record))
            }
            ("DELETE", ["api", "collections", collection, "records", id]) => {
                self.store.delete_record_with_context(
                    collection,
                    id,
                    self.request_context(&request, &query)?,
                )?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            _ => Err(ServerError::NotFound(format!(
                "route '{} {}' not found",
                request.method, request.path
            ))),
        }
    }

    fn request_context(
        &self,
        request: &HttpRequest,
        query: &HashMap<String, String>,
    ) -> Result<FilterContext, ServerError> {
        let context = request_context(request, query);
        let Some(token) = bearer_token(request) else {
            return Ok(context);
        };

        self.store.context_for_token(token, context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn json(
        method: impl Into<String>,
        path: impl Into<String>,
        body: impl Serialize,
    ) -> Result<Self, ServerError> {
        let mut request = Self::new(method, path);
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        request.body = serde_json::to_vec(&body)?;
        Ok(request)
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers
            .insert(normalize_http_header_name(&name), value.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: JsonValue,
}

impl HttpResponse {
    pub fn json(status: u16, body: JsonValue) -> Self {
        Self { status, body }
    }

    pub fn to_http_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let body = if self.status == 204 {
            Vec::new()
        } else {
            serde_json::to_vec(&self.body).unwrap_or_else(|_| b"{}".to_vec())
        };
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            status_text,
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body)
        .collect()
    }
}

pub fn serve(addr: &str, db_path: impl AsRef<Path>) -> Result<(), ServerError> {
    let app = RustyBaseApp::new(Store::open(db_path)?);
    let listener = TcpListener::bind(addr)?;

    for stream in listener.incoming() {
        let app = app.clone();
        let stream = stream?;
        std::thread::spawn(move || {
            let _ = handle_stream(app, stream);
        });
    }

    Ok(())
}

fn handle_stream(app: RustyBaseApp, mut stream: TcpStream) -> Result<(), ServerError> {
    let request = parse_http_request(&mut stream)?;
    let response = app.handle(request);
    stream.write_all(&response.to_http_bytes())?;
    Ok(())
}

fn parse_http_request(stream: &mut TcpStream) -> Result<HttpRequest, ServerError> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| ServerError::BadRequest("missing HTTP method".to_string()))?;
    let path = request_parts
        .next()
        .ok_or_else(|| ServerError::BadRequest("missing HTTP path".to_string()))?;

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = normalize_http_header_name(name);
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().map_err(|_| {
                    ServerError::BadRequest("invalid Content-Length header".to_string())
                })?;
            }
            headers.insert(name, value);
        }
    }

    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body,
    })
}

struct RecordResolver<'a> {
    collection: &'a CollectionConfig,
}

impl<'a> RecordResolver<'a> {
    fn new(collection: &'a CollectionConfig) -> Self {
        Self { collection }
    }

    fn custom_field_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        self.collection
            .fields
            .iter()
            .find(|candidate| candidate.name == field)
            .map(|field| field.kind)
    }

    fn json_root_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        let (root, _) = field.split_once('.')?;
        self.custom_field_kind(root)
            .filter(|kind| *kind == CollectionFieldKind::Json)
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

        if let Some(kind) = self.custom_field_kind(field) {
            return Ok(ResolvedField::with_kind(
                json_data_extract(field),
                FieldKind::from(kind),
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

struct IncomingRecordResolver<'a> {
    collection: &'a CollectionConfig,
}

impl<'a> IncomingRecordResolver<'a> {
    fn new(collection: &'a CollectionConfig) -> Self {
        Self { collection }
    }

    fn custom_field_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        self.collection
            .fields
            .iter()
            .find(|candidate| candidate.name == field)
            .map(|field| field.kind)
    }

    fn json_root_kind(&self, field: &str) -> Option<CollectionFieldKind> {
        let (root, _) = field.split_once('.')?;
        self.custom_field_kind(root)
            .filter(|kind| *kind == CollectionFieldKind::Json)
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

        if let Some(kind) = self.custom_field_kind(field) {
            return Ok(ResolvedField::with_kind(
                incoming_json_extract(field),
                FieldKind::from(kind),
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

struct CompiledPredicate {
    sql: Option<String>,
    params: Vec<SqlValue>,
}

fn compile_list_predicate(
    collection: &CollectionConfig,
    resolver: &RecordResolver<'_>,
    options: &ListOptions,
) -> Result<CompiledPredicate, ServerError> {
    let mut sql = Vec::new();
    let mut params = Vec::new();

    if let Some(rule) = collection
        .list_rule
        .as_deref()
        .filter(|rule| !rule.trim().is_empty())
    {
        push_compiled_predicate(rule, resolver, &options.context, &mut sql, &mut params)?;
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

fn push_compiled_predicate(
    filter: &str,
    resolver: &RecordResolver<'_>,
    context: &FilterContext,
    sql: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) -> Result<(), ServerError> {
    let compiled = compile_filter_with_resolver_and_context(filter, resolver, context.clone())?;
    sql.push(format!("({})", compiled.sql));
    params.extend(filter_params_to_sqlite(compiled.params)?);
    Ok(())
}

fn filter_params_to_sqlite(params: Vec<FilterValue>) -> Result<Vec<SqlValue>, ServerError> {
    params.into_iter().map(filter_value_to_sqlite).collect()
}

fn filter_value_to_sqlite(value: FilterValue) -> Result<SqlValue, ServerError> {
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

fn list_options_from_query(
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
        context,
    })
}

fn parse_u64_query(
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

fn request_context(request: &HttpRequest, query: &HashMap<String, String>) -> FilterContext {
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

fn bearer_token(request: &HttpRequest) -> Option<&str> {
    let value = request.headers.get("authorization")?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .filter(|token| !token.trim().is_empty())
}

fn context_with_body_values(mut context: FilterContext, body: &JsonValue) -> FilterContext {
    let Some(object) = body.as_object() else {
        return context;
    };

    for (name, value) in object {
        context = context.with_body_value(name.clone(), json_to_filter_value(value));
    }

    context
}

fn context_with_auth_record_values(
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

fn json_to_filter_value(value: &JsonValue) -> FilterValue {
    match value {
        JsonValue::String(value) => FilterValue::String(value.clone()),
        JsonValue::Number(value) => FilterValue::Number(value.to_string()),
        JsonValue::Bool(value) => FilterValue::Bool(*value),
        JsonValue::Null => FilterValue::Null,
        JsonValue::Array(_) | JsonValue::Object(_) => FilterValue::String(value.to_string()),
    }
}

fn row_to_record(collection_name: &str, row: &rusqlite::Row<'_>) -> rusqlite::Result<JsonValue> {
    let id = row.get::<_, String>(0)?;
    let data = row.get::<_, String>(1)?;
    let created = row.get::<_, String>(2)?;
    let updated = row.get::<_, String>(3)?;
    let data = serde_json::from_str::<JsonValue>(&data).unwrap_or(JsonValue::Object(Map::new()));

    Ok(record_from_parts(
        collection_name,
        id,
        data,
        created,
        updated,
    ))
}

fn record_from_parts(
    collection_name: &str,
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
        "collectionName".to_string(),
        JsonValue::String(collection_name.to_string()),
    );
    record.insert("created".to_string(), JsonValue::String(created));
    record.insert("updated".to_string(), JsonValue::String(updated));
    JsonValue::Object(record)
}

fn non_empty_rule(rule: Option<&str>) -> Option<&str> {
    rule.filter(|rule| !rule.trim().is_empty())
}

fn forbidden(action: &str, collection_name: &str) -> ServerError {
    ServerError::Forbidden(format!(
        "{action} rule denied access to collection '{collection_name}'"
    ))
}

fn invalid_credentials() -> ServerError {
    ServerError::Forbidden("invalid auth credentials".to_string())
}

fn ensure_auth_token_expires_column(conn: &Connection) -> Result<(), ServerError> {
    let mut stmt = conn.prepare(r#"PRAGMA table_info("_rb_auth_tokens")"#)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let has_expires = rows
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "expires");

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

    Ok(())
}

fn insert_auth_token(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
) -> Result<(String, String), ServerError> {
    let token = generate_token();
    let now = now_millis();
    let expires = (now + AUTH_TOKEN_TTL_MILLIS).to_string();
    conn.execute(
        r#"
        INSERT INTO "_rb_auth_tokens" (token, collection_name, record_id, created, expires)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            &token,
            collection_name,
            record_id,
            now.to_string(),
            &expires
        ],
    )?;

    Ok((token, expires))
}

fn validate_collection(collection: &CollectionConfig) -> Result<(), ServerError> {
    validate_collection_name(&collection.name)?;
    let mut seen = HashMap::new();

    if collection.collection_type == CollectionType::Auth
        && collection
            .fields
            .iter()
            .all(|field| field.name != "email" && field.name != "username")
    {
        return Err(ServerError::BadRequest(
            "auth collections need an email or username field".to_string(),
        ));
    }

    for field in &collection.fields {
        validate_field_name(&field.name)?;
        if is_system_record_key(&field.name) {
            return Err(ServerError::BadRequest(format!(
                "field '{}' is reserved",
                field.name
            )));
        }
        if seen.insert(field.name.clone(), ()).is_some() {
            return Err(ServerError::BadRequest(format!(
                "duplicate field '{}'",
                field.name
            )));
        }
    }

    Ok(())
}

fn validate_collection_name(name: &str) -> Result<(), ServerError> {
    if is_safe_identifier_part(name) {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe collection name '{name}'"
        )))
    }
}

fn validate_record_id(id: &str) -> Result<(), ServerError> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!("unsafe record id '{id}'")))
    }
}

fn validate_field_name(name: &str) -> Result<(), ServerError> {
    if is_safe_identifier_path(name) {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe field name '{name}'"
        )))
    }
}

fn validate_record_fields(
    collection: &CollectionConfig,
    object: &Map<String, JsonValue>,
) -> Result<(), ServerError> {
    for key in object.keys() {
        if is_system_record_key(key) {
            continue;
        }

        if collection.collection_type == CollectionType::Auth
            && matches!(key.as_str(), "password" | "passwordConfirm")
        {
            continue;
        }

        if collection.fields.iter().all(|field| field.name != *key) {
            return Err(ServerError::BadRequest(format!(
                "unknown field '{key}' for collection '{}'",
                collection.name
            )));
        }
    }

    Ok(())
}

fn prepare_auth_password(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    require_password: bool,
) -> Result<(), ServerError> {
    if collection.collection_type != CollectionType::Auth {
        return Ok(());
    }

    object.remove("passwordHash");
    let password = take_string_field(object, "password")?;
    let password_confirm = take_string_field(object, "passwordConfirm")?;

    let Some(password) = password else {
        return if require_password {
            Err(ServerError::BadRequest("password is required".to_string()))
        } else {
            Ok(())
        };
    };

    if password.len() < 8 {
        return Err(ServerError::BadRequest(
            "password must be at least 8 characters".to_string(),
        ));
    }

    if password_confirm
        .as_deref()
        .is_some_and(|confirm| confirm != password)
    {
        return Err(ServerError::BadRequest(
            "passwordConfirm does not match password".to_string(),
        ));
    }

    object.insert(
        "passwordHash".to_string(),
        JsonValue::String(hash_password(&password)?),
    );
    Ok(())
}

fn take_string_field(
    object: &mut Map<String, JsonValue>,
    field: &str,
) -> Result<Option<String>, ServerError> {
    object
        .remove(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| ServerError::BadRequest(format!("field '{field}' must be a string")))
        })
        .transpose()
}

fn data_object(value: &JsonValue) -> Result<&Map<String, JsonValue>, ServerError> {
    value
        .as_object()
        .ok_or_else(|| ServerError::BadRequest("record body must be a JSON object".to_string()))
}

fn data_object_mut(value: &mut JsonValue) -> Result<&mut Map<String, JsonValue>, ServerError> {
    value
        .as_object_mut()
        .ok_or_else(|| ServerError::BadRequest("record body must be a JSON object".to_string()))
}

fn is_system_record_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "created" | "updated" | "collectionName" | "passwordHash"
    )
}

fn record_table_name(collection_name: &str) -> Result<String, ServerError> {
    validate_collection_name(collection_name)?;
    Ok(format!("_rb_records_{collection_name}"))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn is_safe_identifier_part(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_safe_identifier_path(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(is_safe_identifier_part)
}

fn json_data_extract(field: &str) -> String {
    format!(
        "json_extract({}, '{}')",
        quote_identifier("data"),
        json_path(field)
    )
}

fn incoming_json_extract(field: &str) -> String {
    format!(
        "json_extract({}.{}, '{}')",
        quote_identifier("__rb_input"),
        quote_identifier("data"),
        json_path(field)
    )
}

fn json_path(field: &str) -> String {
    let mut path = String::from("$");
    for part in field.split('.') {
        path.push('.');
        path.push_str(part);
    }
    path
}

fn generate_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("rb{:x}{:x}", nanos, counter)
        .chars()
        .take(32)
        .collect()
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("rb_{}", hex_encode(&bytes))
}

fn hash_password(password: &str) -> Result<String, ServerError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| ServerError::BadRequest(format!("failed to hash password: {err}")))
}

fn verify_password(password: &str, password_hash: &str) -> Result<(), ServerError> {
    let password_hash = PasswordHash::new(password_hash).map_err(|_| invalid_credentials())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &password_hash)
        .map_err(|_| invalid_credentials())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now_timestamp() -> String {
    now_millis().to_string()
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn split_path_query(path: &str) -> (String, HashMap<String, String>) {
    let Some((path, query)) = path.split_once('?') else {
        return (path.to_string(), HashMap::new());
    };

    (path.to_string(), parse_query(query))
}

fn path_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn normalize_http_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn error_response(err: ServerError) -> HttpResponse {
    let status = match err {
        ServerError::BadRequest(_) | ServerError::Json(_) | ServerError::Filter(_) => 400,
        ServerError::Forbidden(_) => 403,
        ServerError::NotFound(_) => 404,
        ServerError::Storage(_) | ServerError::Io(_) => 500,
    };

    HttpResponse::json(
        status,
        json!({
            "code": status,
            "message": err.to_string(),
        }),
    )
}
