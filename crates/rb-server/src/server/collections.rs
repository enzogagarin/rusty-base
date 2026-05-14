use super::*;
use super::{auth::*, files::*, records::*, settings::*, storage::*, validation::*};

mod crud;
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
