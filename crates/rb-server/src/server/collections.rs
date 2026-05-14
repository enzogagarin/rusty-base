use super::*;
use super::{auth::*, files::*, records::*, settings::*, storage::*, validation::*};

mod import_export;
mod indexes;
mod schema;

pub(crate) use import_export::collection_export_payload;
pub use import_export::CollectionImportRequest;
use indexes::*;
pub(crate) use schema::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default, rename = "type")]
    pub collection_type: CollectionType,
    #[serde(default, alias = "schema")]
    pub fields: Vec<CollectionField>,
    #[serde(default)]
    pub indexes: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub view_query: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_auth: Option<AuthPasswordConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<TokenDurationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_reset_token: Option<TokenDurationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_change_token: Option<TokenDurationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<TokenDurationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_token: Option<TokenDurationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuth2Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<MfaConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<OtpConfig>,
}

impl CollectionConfig {
    pub fn new(name: impl Into<String>, fields: impl IntoIterator<Item = CollectionField>) -> Self {
        Self {
            id: None,
            name: name.into(),
            collection_type: CollectionType::Base,
            fields: fields.into_iter().collect(),
            indexes: Vec::new(),
            view_query: String::new(),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
            auth_rule: None,
            manage_rule: None,
            password_auth: None,
            auth_token: None,
            password_reset_token: None,
            email_change_token: None,
            verification_token: None,
            file_token: None,
            oauth2: None,
            mfa: None,
            otp: None,
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
    View,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(alias = "kind", rename = "type")]
    pub kind: CollectionFieldKind,
    #[serde(
        default,
        alias = "collectionId",
        alias = "targetCollection",
        skip_serializing_if = "Option::is_none"
    )]
    pub collection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_select: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_select: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autogenerate_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mime_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thumbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except_domains: Vec<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub presentable: bool,
    #[serde(default)]
    pub primary_key: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub cascade_delete: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub on_create: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub on_update: bool,
}

impl CollectionField {
    pub fn new(name: impl Into<String>, kind: CollectionFieldKind) -> Self {
        Self {
            id: None,
            name: name.into(),
            kind,
            collection: None,
            min_select: None,
            max_select: None,
            max_size: None,
            min: None,
            max: None,
            pattern: None,
            autogenerate_pattern: None,
            mime_types: Vec::new(),
            thumbs: Vec::new(),
            values: Vec::new(),
            only_domains: Vec::new(),
            except_domains: Vec::new(),
            required: false,
            system: false,
            hidden: false,
            presentable: false,
            primary_key: false,
            protected: false,
            cascade_delete: false,
            on_create: false,
            on_update: false,
        }
    }

    pub fn relation(name: impl Into<String>, collection: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            kind: CollectionFieldKind::Relation,
            collection: Some(collection.into()),
            min_select: None,
            max_select: None,
            max_size: None,
            min: None,
            max: None,
            pattern: None,
            autogenerate_pattern: None,
            mime_types: Vec::new(),
            thumbs: Vec::new(),
            values: Vec::new(),
            only_domains: Vec::new(),
            except_domains: Vec::new(),
            required: false,
            system: false,
            hidden: false,
            presentable: false,
            primary_key: false,
            protected: false,
            cascade_delete: false,
            on_create: false,
            on_update: false,
        }
    }

    pub fn with_max_select(mut self, max_select: u64) -> Self {
        self.max_select = Some(max_select);
        self
    }

    pub fn with_min_select(mut self, min_select: u64) -> Self {
        self.min_select = Some(min_select);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionFieldKind {
    Text,
    Email,
    Url,
    Editor,
    File,
    Number,
    Bool,
    #[serde(rename = "date", alias = "datetime")]
    DateTime,
    Array,
    Json,
    Relation,
    Select,
    #[serde(rename = "geoPoint", alias = "geopoint")]
    GeoPoint,
    #[serde(rename = "autodate")]
    AutoDate,
}

impl From<CollectionFieldKind> for FieldKind {
    fn from(value: CollectionFieldKind) -> Self {
        match value {
            CollectionFieldKind::Text => Self::Text,
            CollectionFieldKind::Email => Self::Text,
            CollectionFieldKind::Url => Self::Text,
            CollectionFieldKind::Editor => Self::Text,
            CollectionFieldKind::File => Self::Text,
            CollectionFieldKind::Number => Self::Number,
            CollectionFieldKind::Bool => Self::Bool,
            CollectionFieldKind::DateTime => Self::DateTime,
            CollectionFieldKind::Array => Self::Array,
            CollectionFieldKind::Json => Self::Json,
            CollectionFieldKind::Relation => Self::Relation,
            CollectionFieldKind::Select => Self::Text,
            CollectionFieldKind::GeoPoint => Self::Json,
            CollectionFieldKind::AutoDate => Self::DateTime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionListOptions {
    pub page: u64,
    pub per_page: u64,
    pub filter: Option<String>,
    pub sort: Option<String>,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<CollectionField>>,
    #[serde(default)]
    pub indexes: Option<Vec<String>>,
    #[serde(default)]
    pub view_query: Option<String>,
    #[serde(default, rename = "type")]
    pub collection_type: Option<CollectionType>,
    #[serde(default)]
    pub list_rule: Option<Option<String>>,
    #[serde(default)]
    pub view_rule: Option<Option<String>>,
    #[serde(default)]
    pub create_rule: Option<Option<String>>,
    #[serde(default)]
    pub update_rule: Option<Option<String>>,
    #[serde(default)]
    pub delete_rule: Option<Option<String>>,
    #[serde(default)]
    pub auth_rule: Option<Option<String>>,
    #[serde(default)]
    pub manage_rule: Option<Option<String>>,
    #[serde(default)]
    pub password_auth: Option<AuthPasswordConfig>,
    #[serde(default)]
    pub auth_token: Option<TokenDurationConfig>,
    #[serde(default)]
    pub password_reset_token: Option<TokenDurationConfig>,
    #[serde(default)]
    pub email_change_token: Option<TokenDurationConfig>,
    #[serde(default)]
    pub verification_token: Option<TokenDurationConfig>,
    #[serde(default)]
    pub file_token: Option<TokenDurationConfig>,
    #[serde(default)]
    pub oauth2: Option<OAuth2Config>,
    #[serde(default)]
    pub mfa: Option<MfaConfig>,
    #[serde(default)]
    pub otp: Option<OtpConfig>,
}

pub(crate) struct CollectionResolver;

impl FieldResolver for CollectionResolver {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "id" => Ok(ResolvedField::with_kind(
                collection_id_sql(),
                FieldKind::Text,
            )),
            "name" => Ok(ResolvedField::with_kind(
                quote_identifier("name"),
                FieldKind::Text,
            )),
            "created" | "updated" => Ok(ResolvedField::with_kind(
                quote_identifier(field),
                FieldKind::DateTime,
            )),
            "type" => Ok(ResolvedField::with_kind(
                collection_type_sql(),
                FieldKind::Text,
            )),
            "system" => Ok(ResolvedField::with_kind(
                collection_system_sql(),
                FieldKind::Bool,
            )),
            _ => Err(FilterError::with_kind(
                rb_filter_engine::FilterErrorKind::UnknownField,
                format!("unknown collection field '{field}'"),
            )),
        }
    }
}

pub(crate) fn collection_list_options_from_query(
    query: &HashMap<String, String>,
) -> Result<CollectionListOptions, ServerError> {
    let page = parse_u64_query(query, "page")?.unwrap_or(1).max(1);
    let per_page = parse_u64_query(query, "perPage")?
        .unwrap_or(30)
        .clamp(1, 500);

    Ok(CollectionListOptions {
        page,
        per_page,
        filter: query.get("filter").cloned(),
        sort: query.get("sort").cloned(),
        fields: field_options_from_query(query)?,
    })
}

pub(crate) fn collection_sort_sql(sort: Option<&str>) -> Result<String, ServerError> {
    let Some(sort) = sort.map(str::trim).filter(|sort| !sort.is_empty()) else {
        return Ok(r#""name" ASC"#.to_string());
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
        let expression = match field {
            "@random" => "RANDOM()".to_string(),
            "id" | "name" => quote_identifier("name"),
            "created" | "updated" => quote_identifier(field),
            "type" => collection_type_sql(),
            "system" => collection_system_sql(),
            _ => {
                return Err(ServerError::BadRequest(format!(
                    "invalid collection sort field '{field}'"
                )))
            }
        };
        parts.push(format!("{expression} {direction}"));
    }

    if parts.is_empty() {
        Ok(r#""name" ASC"#.to_string())
    } else {
        Ok(parts.join(", "))
    }
}

pub(crate) fn collection_type_sql() -> String {
    r#"json_extract("schema_json", '$.type')"#.to_string()
}

pub(crate) fn collection_system_sql() -> String {
    r#"CASE WHEN "name" LIKE '\_%' ESCAPE '\' THEN TRUE ELSE FALSE END"#.to_string()
}

pub(crate) fn collection_id_value(collection: &CollectionConfig) -> Option<String> {
    collection
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

pub(crate) fn record_collection_id(collection: &CollectionConfig) -> String {
    collection_id_value(collection).unwrap_or_else(|| collection.name.clone())
}

pub(crate) fn collection_id_sql() -> String {
    r#"COALESCE(NULLIF(json_extract("schema_json", '$.id'), ''), "name")"#.to_string()
}

pub(crate) fn get_collection_with_connection(
    conn: &Connection,
    name: &str,
) -> Result<CollectionConfig, ServerError> {
    validate_collection_identifier(name)?;
    let schema_json = conn
        .query_row(
            &format!(
                r#"
                SELECT schema_json
                FROM "_rb_collections"
                WHERE name = ?1 OR {} = ?1
                LIMIT 1
                "#,
                collection_id_sql()
            ),
            params![name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| ServerError::NotFound(format!("collection '{name}' not found")))?;

    Ok(serde_json::from_str(&schema_json)?)
}

pub(crate) fn list_collections_with_connection(
    conn: &Connection,
) -> Result<Vec<CollectionConfig>, ServerError> {
    let mut stmt =
        conn.prepare(r#"SELECT schema_json FROM "_rb_collections" ORDER BY name ASC"#)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

pub(crate) fn collection_owns_record_table(collection: &CollectionConfig) -> bool {
    collection.collection_type != CollectionType::View
}

pub(crate) fn view_query_sql(collection: &CollectionConfig) -> Result<String, ServerError> {
    validate_view_query(&collection.view_query)?;
    Ok(collection.view_query.trim().to_string())
}

pub(crate) fn ensure_collection_identifier_available(
    conn: &Connection,
    identifier: &str,
    excluding_name: Option<&str>,
) -> Result<(), ServerError> {
    let owner = conn
        .query_row(
            &format!(
                r#"
                SELECT name
                FROM "_rb_collections"
                WHERE name = ?1 OR {} = ?1
                LIMIT 1
                "#,
                collection_id_sql()
            ),
            params![identifier],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    ensure_collection_identifier_owner_available(identifier, owner, excluding_name)
}

pub(crate) fn ensure_collection_identifier_available_tx(
    tx: &rusqlite::Transaction<'_>,
    identifier: &str,
    excluding_name: Option<&str>,
) -> Result<(), ServerError> {
    let owner = tx
        .query_row(
            &format!(
                r#"
                SELECT name
                FROM "_rb_collections"
                WHERE name = ?1 OR {} = ?1
                LIMIT 1
                "#,
                collection_id_sql()
            ),
            params![identifier],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    ensure_collection_identifier_owner_available(identifier, owner, excluding_name)
}

pub(crate) fn ensure_collection_identifier_owner_available(
    identifier: &str,
    owner: Option<String>,
    excluding_name: Option<&str>,
) -> Result<(), ServerError> {
    if owner
        .as_deref()
        .is_some_and(|owner| Some(owner) != excluding_name)
    {
        return Err(ServerError::BadRequest(format!(
            "collection identifier '{identifier}' already exists"
        )));
    }

    Ok(())
}

impl Store {
    pub fn create_collection(
        &self,
        mut collection: CollectionConfig,
    ) -> Result<CollectionConfig, ServerError> {
        normalize_collection(&mut collection);
        validate_collection(&collection)?;

        let now = now_timestamp();
        let schema_json = serde_json::to_string(&collection)?;
        let table = record_table_name(&collection.name)?;
        let table_sql = quote_identifier(&table);
        let conn = self.connection()?;
        ensure_collection_identifier_available(&conn, &collection.name, None)?;
        if let Some(id) = collection.id.as_deref() {
            ensure_collection_identifier_available(&conn, id, None)?;
        }

        conn.execute(
            r#"
            INSERT INTO "_rb_collections" (name, schema_json, created, updated)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![&collection.name, schema_json, now],
        )?;
        if collection_owns_record_table(&collection) {
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
            apply_safe_collection_indexes(&conn, &collection)?;
        }

        Ok(collection)
    }

    pub fn get_collection(&self, name: &str) -> Result<CollectionConfig, ServerError> {
        let conn = self.connection()?;
        get_collection_with_connection(&conn, name)
    }

    pub fn get_collection_response(
        &self,
        identifier: &str,
        fields: &[String],
    ) -> Result<JsonValue, ServerError> {
        validate_collection_identifier(identifier)?;
        let conn = self.connection()?;
        let (name, schema_json, created, updated) = conn
            .query_row(
                &format!(
                    r#"
                    SELECT name, schema_json, created, updated
                    FROM "_rb_collections"
                    WHERE name = ?1 OR {} = ?1
                    LIMIT 1
                    "#,
                    collection_id_sql()
                ),
                params![identifier],
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
            .ok_or_else(|| ServerError::NotFound(format!("collection '{identifier}' not found")))?;
        let mut payload = collection_row_to_value(name, schema_json, created, updated)?;
        project_json_response(&mut payload, fields)?;
        Ok(payload)
    }

    pub fn list_collections(&self) -> Result<Vec<CollectionConfig>, ServerError> {
        let conn = self.connection()?;
        list_collections_with_connection(&conn)
    }

    pub fn list_collection_page(
        &self,
        options: CollectionListOptions,
    ) -> Result<JsonValue, ServerError> {
        let resolver = CollectionResolver;
        let mut where_sql = String::new();
        let mut params = Vec::new();
        if let Some(filter) = options
            .filter
            .as_deref()
            .filter(|filter| !filter.trim().is_empty())
        {
            let compiled = compile_filter_with_resolver_and_context(
                filter,
                &resolver,
                FilterContext::default(),
            )?;
            where_sql = format!(" WHERE ({})", compiled.sql);
            params.extend(filter_params_to_sqlite(compiled.params)?);
        }

        let order_sql = collection_sort_sql(options.sort.as_deref())?;
        let offset = options.page.saturating_sub(1) * options.per_page;
        let (total_items, items) = {
            let conn = self.connection()?;
            let total_items: u64 = conn.query_row(
                &format!(r#"SELECT COUNT(*) FROM "_rb_collections"{where_sql}"#),
                params_from_iter(params.iter()),
                |row| row.get::<_, u64>(0),
            )?;

            let mut list_params = params;
            list_params.push(SqlValue::Integer(options.per_page as i64));
            list_params.push(SqlValue::Integer(offset as i64));
            let sql = format!(
                r#"
                SELECT name, schema_json, created, updated
                FROM "_rb_collections"
                {where_sql}
                ORDER BY {order_sql}
                LIMIT ? OFFSET ?
                "#
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(list_params.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let rows = rows.collect::<Result<Vec<_>, _>>()?;
            let items = rows
                .into_iter()
                .map(|(name, schema_json, created, updated)| {
                    collection_row_to_value(name, schema_json, created, updated)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (total_items, items)
        };

        let total_pages = if total_items == 0 {
            0
        } else {
            total_items.div_ceil(options.per_page)
        };

        let mut payload = json!(RecordList {
            page: options.page,
            per_page: options.per_page,
            total_items: total_items.min(i64::MAX as u64) as i64,
            total_pages: total_pages.min(i64::MAX as u64) as i64,
            items,
        });
        project_json_response(&mut payload, &options.fields)?;
        Ok(payload)
    }

    pub fn update_collection(
        &self,
        identifier: &str,
        patch: CollectionPatch,
    ) -> Result<CollectionConfig, ServerError> {
        validate_collection_identifier(identifier)?;
        let mut collection = self.get_collection(identifier)?;
        let old_collection = collection.clone();
        let old_name = collection.name.clone();
        apply_collection_patch(&mut collection, patch);
        normalize_collection(&mut collection);
        validate_collection(&collection)?;

        let new_name = collection.name.clone();
        let old_table = record_table_name(&old_name)?;
        let new_table = record_table_name(&new_name)?;
        let schema_json = serde_json::to_string(&collection)?;
        let now = now_timestamp();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if collection_owns_record_table(&old_collection) {
            drop_safe_collection_indexes(&tx, &old_collection)?;
        }

        if old_name != new_name {
            ensure_collection_identifier_available_tx(&tx, &new_name, Some(&old_name))?;

            if collection_owns_record_table(&old_collection)
                && collection_owns_record_table(&collection)
            {
                let old_table_sql = quote_identifier(&old_table);
                let new_table_sql = quote_identifier(&new_table);
                tx.execute(
                    &format!("ALTER TABLE {old_table_sql} RENAME TO {new_table_sql}"),
                    [],
                )?;
            }
            tx.execute(
                r#"UPDATE "_rb_auth_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_action_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_external_accounts" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_file_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_files" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
        }
        if collection_owns_record_table(&old_collection)
            && !collection_owns_record_table(&collection)
        {
            let old_table_sql = quote_identifier(&old_table);
            tx.execute(&format!("DROP TABLE IF EXISTS {old_table_sql}"), [])?;
        }
        if !collection_owns_record_table(&old_collection)
            && collection_owns_record_table(&collection)
        {
            let new_table_sql = quote_identifier(&new_table);
            tx.execute(
                &format!(
                    r#"
                    CREATE TABLE IF NOT EXISTS {new_table_sql} (
                        id TEXT PRIMARY KEY NOT NULL,
                        data TEXT NOT NULL,
                        created TEXT NOT NULL,
                        updated TEXT NOT NULL
                    )
                    "#
                ),
                [],
            )?;
        }

        let affected = tx.execute(
            r#"
            UPDATE "_rb_collections"
            SET name = ?1, schema_json = ?2, updated = ?3
            WHERE name = ?4
            "#,
            params![&new_name, schema_json, now, &old_name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{old_name}' not found"
            )));
        }
        if collection_owns_record_table(&collection) {
            apply_safe_collection_indexes(&tx, &collection)?;
        }
        tx.commit()?;

        Ok(collection)
    }

    pub fn delete_collection(&self, identifier: &str) -> Result<(), ServerError> {
        validate_collection_identifier(identifier)?;
        let collection = self.get_collection(identifier)?;
        let name = collection.name;

        let table_sql = quote_identifier(&record_table_name(&name)?);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(&format!("DROP TABLE IF EXISTS {table_sql}"), [])?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        let affected = tx.execute(
            r#"DELETE FROM "_rb_collections" WHERE name = ?1"#,
            params![&name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{name}' not found"
            )));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn truncate_collection(&self, identifier: &str) -> Result<(), ServerError> {
        validate_collection_identifier(identifier)?;
        let collection = self.get_collection(identifier)?;
        let name = collection.name;

        let table_sql = quote_identifier(&record_table_name(&name)?);
        let conn = self.connection()?;
        conn.execute(&format!("DELETE FROM {table_sql}"), [])?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        Ok(())
    }
}
