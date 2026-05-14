use super::*;
use super::{auth::*, files::*, records::*, settings::*, storage::*, validation::*};

mod indexes;

use indexes::*;

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

pub(crate) fn collection_row_to_value(
    name: String,
    schema_json: String,
    created: String,
    updated: String,
) -> Result<JsonValue, ServerError> {
    let collection = serde_json::from_str::<CollectionConfig>(&schema_json)?;
    let id = collection_id_value(&collection).unwrap_or_else(|| name.clone());
    let mut value = json!(collection);
    let object = value.as_object_mut().ok_or_else(|| {
        ServerError::BadRequest("collection response must be a JSON object".to_string())
    })?;
    let index_warnings = collection_index_warnings(&collection)?;
    if !index_warnings.is_empty() {
        object.insert(
            "indexWarnings".to_string(),
            JsonValue::Array(index_warnings),
        );
    }
    object.insert("id".to_string(), JsonValue::String(id));
    object.insert("name".to_string(), JsonValue::String(name.clone()));
    object.insert("created".to_string(), JsonValue::String(created));
    object.insert("updated".to_string(), JsonValue::String(updated));
    object.insert("system".to_string(), JsonValue::Bool(name.starts_with('_')));
    decorate_collection_response_fields(object);
    Ok(value)
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

pub(crate) fn decorate_collection_response_fields(object: &mut Map<String, JsonValue>) {
    let mut fields = object
        .remove("fields")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|field| !is_response_only_collection_field_value(field))
        .collect::<Vec<_>>();

    let mut decorated = Vec::with_capacity(fields.len() + 3);
    decorated.push(scaffold_id_field());
    decorated.append(&mut fields);
    decorated.push(scaffold_created_field());
    decorated.push(scaffold_updated_field());
    object.insert("fields".to_string(), JsonValue::Array(decorated));
}

pub(crate) fn is_response_only_collection_field_value(field: &JsonValue) -> bool {
    serde_json::from_value::<CollectionField>(field.clone())
        .is_ok_and(|field| is_response_only_collection_field(&field))
}

pub(crate) fn is_response_only_collection_field(field: &CollectionField) -> bool {
    match field.name.as_str() {
        "id" => {
            field.id.as_deref() == Some("text3208210256")
                && field.kind == CollectionFieldKind::Text
                && field.required
                && field.system
                && !field.hidden
                && !field.presentable
                && field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.min == Some(15)
                && field.max == Some(15)
                && field.pattern.as_deref() == Some("^[a-z0-9]+$")
                && field.autogenerate_pattern.as_deref() == Some("[a-z0-9]{15}")
        }
        "created" => {
            field.id.as_deref() == Some("autodate2990389176")
                && field.kind == CollectionFieldKind::AutoDate
                && !field.required
                && !field.system
                && !field.hidden
                && !field.presentable
                && !field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.on_create
                && !field.on_update
        }
        "updated" => {
            field.id.as_deref() == Some("autodate3332085495")
                && field.kind == CollectionFieldKind::AutoDate
                && !field.required
                && !field.system
                && !field.hidden
                && !field.presentable
                && !field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.on_create
                && field.on_update
        }
        _ => false,
    }
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

pub(crate) fn apply_collection_patch(collection: &mut CollectionConfig, patch: CollectionPatch) {
    if let Some(name) = patch.name {
        collection.name = name;
    }
    if let Some(collection_type) = patch.collection_type {
        collection.collection_type = collection_type;
    }
    if let Some(mut fields) = patch.fields {
        preserve_collection_field_ids(&collection.fields, &mut fields);
        collection.fields = fields;
    }
    if let Some(indexes) = patch.indexes {
        collection.indexes = indexes;
    }
    if let Some(view_query) = patch.view_query {
        collection.view_query = view_query;
    }
    if let Some(rule) = patch.list_rule {
        collection.list_rule = rule;
    }
    if let Some(rule) = patch.view_rule {
        collection.view_rule = rule;
    }
    if let Some(rule) = patch.create_rule {
        collection.create_rule = rule;
    }
    if let Some(rule) = patch.update_rule {
        collection.update_rule = rule;
    }
    if let Some(rule) = patch.delete_rule {
        collection.delete_rule = rule;
    }
    if let Some(rule) = patch.auth_rule {
        collection.auth_rule = rule;
    }
    if let Some(rule) = patch.manage_rule {
        collection.manage_rule = rule;
    }
    if let Some(password_auth) = patch.password_auth {
        collection.password_auth = Some(password_auth);
    }
    if let Some(auth_token) = patch.auth_token {
        collection.auth_token = Some(auth_token);
    }
    if let Some(password_reset_token) = patch.password_reset_token {
        collection.password_reset_token = Some(password_reset_token);
    }
    if let Some(email_change_token) = patch.email_change_token {
        collection.email_change_token = Some(email_change_token);
    }
    if let Some(verification_token) = patch.verification_token {
        collection.verification_token = Some(verification_token);
    }
    if let Some(file_token) = patch.file_token {
        collection.file_token = Some(file_token);
    }
    if let Some(oauth2) = patch.oauth2 {
        collection.oauth2 = Some(oauth2);
    }
    if let Some(mfa) = patch.mfa {
        collection.mfa = Some(mfa);
    }
    if let Some(otp) = patch.otp {
        collection.otp = Some(otp);
    }
}

pub(crate) fn normalize_collection(collection: &mut CollectionConfig) {
    collection
        .fields
        .retain(|field| !is_response_only_collection_field(field));
    normalize_collection_id(collection);
    normalize_collection_indexes(&mut collection.indexes);
    collection.view_query = collection.view_query.trim().to_string();
    normalize_collection_fields(&mut collection.fields);

    if collection.collection_type != CollectionType::View {
        collection.view_query.clear();
    }

    if collection.collection_type != CollectionType::Auth {
        collection.auth_rule = None;
        collection.manage_rule = None;
        collection.password_auth = None;
        collection.auth_token = None;
        collection.password_reset_token = None;
        collection.email_change_token = None;
        collection.verification_token = None;
        collection.file_token = None;
        collection.oauth2 = None;
        collection.mfa = None;
        collection.otp = None;
        return;
    }

    let default_identity_fields = default_auth_identity_fields(collection);
    let password_auth = collection
        .password_auth
        .get_or_insert_with(Default::default);
    if password_auth.identity_fields.is_empty() {
        password_auth.identity_fields = default_identity_fields.clone();
    }
    dedupe_strings(&mut password_auth.identity_fields);

    collection.auth_rule.get_or_insert_with(String::new);
    collection
        .auth_token
        .get_or_insert_with(|| TokenDurationConfig::seconds((AUTH_TOKEN_TTL_MILLIS / 1000) as u64));
    collection.password_reset_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((PASSWORD_RESET_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection.email_change_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((EMAIL_CHANGE_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection.verification_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((VERIFICATION_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection
        .file_token
        .get_or_insert_with(|| TokenDurationConfig::seconds((FILE_TOKEN_TTL_MILLIS / 1000) as u64));
    collection.oauth2.get_or_insert_with(Default::default);
    collection.mfa.get_or_insert_with(Default::default);

    let otp_missing = collection.otp.is_none();
    let otp = collection.otp.get_or_insert_with(Default::default);
    if otp.duration == 0 {
        otp.duration = (OTP_TOKEN_TTL_MILLIS / 1000) as u64;
    }
    if otp.length == 0 {
        otp.length = 8;
    }
    if otp_missing && !otp.enabled {
        otp.enabled = default_identity_fields.iter().any(|field| field == "email");
    }
}

pub(crate) fn normalize_collection_fields(fields: &mut [CollectionField]) {
    for field in fields {
        field.id = field
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .or_else(|| Some(generate_field_id(field.kind)));

        if matches!(
            field.kind,
            CollectionFieldKind::Text | CollectionFieldKind::Email
        ) {
            field.min.get_or_insert(0);
            field.max.get_or_insert(0);
            field.pattern.get_or_insert_with(String::new);
            field.autogenerate_pattern.get_or_insert_with(String::new);
        }
    }
}

pub(crate) fn preserve_collection_field_ids(
    current: &[CollectionField],
    incoming: &mut [CollectionField],
) {
    for field in incoming {
        if field
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .is_some()
        {
            continue;
        }

        if let Some(existing) = current.iter().find(|existing| existing.name == field.name) {
            field.id = existing.id.clone();
        }
    }
}

pub(crate) fn normalize_collection_id(collection: &mut CollectionConfig) {
    collection.id = collection
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| Some(generate_collection_id()));
}

pub(crate) fn normalize_collection_indexes(indexes: &mut Vec<String>) {
    for index in indexes.iter_mut() {
        *index = index.trim().to_string();
    }
    indexes.retain(|index| !index.is_empty());
    dedupe_strings(indexes);
}

pub(crate) fn collection_scaffolds() -> JsonValue {
    json!({
        "base": scaffold_collection("base", base_scaffold_fields(), json!({})),
        "auth": scaffold_collection(
            "auth",
            auth_scaffold_fields(vec![
                scaffold_id_field(),
                json!({
                    "id": "password901924565",
                    "name": "password",
                    "type": "password",
                    "required": true,
                    "system": true,
                    "hidden": true,
                    "min": 8,
                    "max": 0,
                    "pattern": "",
                    "cost": 0
                }),
                json!({
                    "id": "text2504183744",
                    "name": "tokenKey",
                    "type": "text",
                    "required": true,
                    "system": true,
                    "hidden": true,
                    "primaryKey": false,
                    "min": 30,
                    "max": 60,
                    "pattern": "",
                    "autogeneratePattern": "[a-zA-Z0-9]{50}",
                    "presentable": false
                }),
                json!({
                    "id": "email3885137012",
                    "name": "email",
                    "type": "email",
                    "required": true,
                    "system": true,
                    "hidden": false,
                    "onlyDomains": null,
                    "exceptDomains": null,
                    "presentable": false
                }),
                scaffold_bool_field("bool1547992806", "emailVisibility", true),
                scaffold_bool_field("bool256245529", "verified", true)
            ]),
            json!({
                "authRule": "",
                "manageRule": null,
                "passwordAuth": {
                    "enabled": true,
                    "identityFields": ["email"]
                },
                "authToken": { "duration": 604800 },
                "passwordResetToken": { "duration": 1800 },
                "emailChangeToken": { "duration": 1800 },
                "verificationToken": { "duration": 259200 },
                "fileToken": { "duration": 180 },
                "oauth2": {
                    "enabled": false,
                    "mappedFields": {
                        "id": "",
                        "name": "",
                        "username": "",
                        "avatarURL": ""
                    },
                    "providers": []
                },
                "mfa": {
                    "enabled": false,
                    "duration": 1800,
                    "rule": ""
                },
                "otp": {
                    "enabled": true,
                    "duration": 180,
                    "length": 8
                }
            })
        ),
        "view": scaffold_collection("view", Vec::new(), json!({ "viewQuery": "" }))
    })
}

pub(crate) fn base_scaffold_fields() -> Vec<JsonValue> {
    vec![
        scaffold_id_field(),
        scaffold_created_field(),
        scaffold_updated_field(),
    ]
}

pub(crate) fn auth_scaffold_fields(mut fields: Vec<JsonValue>) -> Vec<JsonValue> {
    fields.push(scaffold_created_field());
    fields.push(scaffold_updated_field());
    fields
}

pub(crate) fn scaffold_collection(
    collection_type: &str,
    fields: Vec<JsonValue>,
    extra: JsonValue,
) -> JsonValue {
    let mut collection = Map::new();
    collection.insert("id".to_string(), JsonValue::String(String::new()));
    collection.insert("name".to_string(), JsonValue::String(String::new()));
    collection.insert(
        "type".to_string(),
        JsonValue::String(collection_type.to_string()),
    );
    collection.insert("fields".to_string(), JsonValue::Array(fields));
    collection.insert("indexes".to_string(), JsonValue::Array(Vec::new()));
    collection.insert("listRule".to_string(), JsonValue::Null);
    collection.insert("viewRule".to_string(), JsonValue::Null);
    collection.insert("createRule".to_string(), JsonValue::Null);
    collection.insert("updateRule".to_string(), JsonValue::Null);
    collection.insert("deleteRule".to_string(), JsonValue::Null);
    collection.insert("created".to_string(), JsonValue::String(String::new()));
    collection.insert("updated".to_string(), JsonValue::String(String::new()));
    collection.insert("system".to_string(), JsonValue::Bool(false));

    if let JsonValue::Object(extra) = extra {
        collection.extend(extra);
    }

    JsonValue::Object(collection)
}

pub(crate) fn scaffold_id_field() -> JsonValue {
    json!({
        "id": "text3208210256",
        "name": "id",
        "type": "text",
        "required": true,
        "system": true,
        "hidden": false,
        "primaryKey": true,
        "min": 15,
        "max": 15,
        "pattern": "^[a-z0-9]+$",
        "autogeneratePattern": "[a-z0-9]{15}",
        "presentable": false
    })
}

pub(crate) fn scaffold_created_field() -> JsonValue {
    scaffold_autodate_field("autodate2990389176", "created", true, false)
}

pub(crate) fn scaffold_updated_field() -> JsonValue {
    scaffold_autodate_field("autodate3332085495", "updated", true, true)
}

pub(crate) fn scaffold_autodate_field(
    id: &str,
    name: &str,
    on_create: bool,
    on_update: bool,
) -> JsonValue {
    json!({
        "id": id,
        "name": name,
        "type": "autodate",
        "required": false,
        "system": false,
        "hidden": false,
        "presentable": false,
        "onCreate": on_create,
        "onUpdate": on_update
    })
}

pub(crate) fn scaffold_bool_field(id: &str, name: &str, system: bool) -> JsonValue {
    json!({
        "id": id,
        "name": name,
        "type": "bool",
        "required": false,
        "system": system,
        "hidden": false,
        "presentable": false
    })
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
