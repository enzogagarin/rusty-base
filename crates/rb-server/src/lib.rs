use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use rb_filter_engine::{
    compile_filter_with_resolver_and_context, FieldKind, FieldResolver, FilterContext, FilterError,
    ResolvedField, Value as FilterValue,
};
use ring::digest;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    io::{BufRead, BufReader, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const AUTH_TOKEN_TTL_MILLIS: u128 = 7 * 24 * 60 * 60 * 1000;
const FILE_TOKEN_TTL_MILLIS: u128 = 2 * 60 * 1000;
const VERIFICATION_TOKEN_TTL_MILLIS: u128 = 3 * 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TOKEN_TTL_MILLIS: u128 = 30 * 60 * 1000;
const EMAIL_CHANGE_TOKEN_TTL_MILLIS: u128 = 30 * 60 * 1000;
const OTP_TOKEN_TTL_MILLIS: u128 = 3 * 60 * 1000;
const AUTH_FORM_VALIDATION_MESSAGE: &str = "An error occurred while validating the submitted data.";
const SUPERUSERS_COLLECTION: &str = "_superusers";
const MAX_THUMB_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_THUMB_SOURCE_PIXELS: u64 = 16_000_000;
const MAX_THUMB_EDGE: u32 = 2048;
const REALTIME_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub enum ServerError {
    BadRequest(String),
    BadRequestData { message: String, data: JsonValue },
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
            Self::BadRequestData { message, .. } => write!(f, "{message}"),
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
    #[serde(default, alias = "schema")]
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
            name: name.into(),
            collection_type: CollectionType::Base,
            fields: fields.into_iter().collect(),
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPasswordConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub identity_fields: Vec<String>,
}

impl Default for AuthPasswordConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            identity_fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenDurationConfig {
    #[serde(default)]
    pub duration: u64,
}

impl TokenDurationConfig {
    fn seconds(duration: u64) -> Self {
        Self { duration }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mapped_fields: OAuth2MappedFields,
    #[serde(default)]
    pub providers: Vec<OAuth2ProviderConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2MappedFields {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, alias = "avatarUrl", rename = "avatarURL")]
    pub avatar_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2ProviderConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_info_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub duration: u64,
    #[serde(default)]
    pub rule: String,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration: 1800,
            rule: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub duration: u64,
    #[serde(default)]
    pub length: u64,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration: (OTP_TOKEN_TTL_MILLIS / 1000) as u64,
            length: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionField {
    pub name: String,
    #[serde(alias = "type")]
    pub kind: CollectionFieldKind,
    #[serde(
        default,
        alias = "collectionId",
        alias = "targetCollection",
        skip_serializing_if = "Option::is_none"
    )]
    pub collection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_select: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mime_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thumbs: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected: bool,
}

impl CollectionField {
    pub fn new(name: impl Into<String>, kind: CollectionFieldKind) -> Self {
        Self {
            name: name.into(),
            kind,
            collection: None,
            max_select: None,
            max_size: None,
            mime_types: Vec::new(),
            thumbs: Vec::new(),
            protected: false,
        }
    }

    pub fn relation(name: impl Into<String>, collection: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: CollectionFieldKind::Relation,
            collection: Some(collection.into()),
            max_select: None,
            max_size: None,
            mime_types: Vec::new(),
            thumbs: Vec::new(),
            protected: false,
        }
    }

    pub fn with_max_select(mut self, max_select: u64) -> Self {
        self.max_select = Some(max_select);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectionFieldKind {
    Text,
    Email,
    File,
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
            CollectionFieldKind::Email => Self::Text,
            CollectionFieldKind::File => Self::Text,
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
    pub sort: Option<String>,
    pub skip_total: bool,
    pub expand: Vec<String>,
    pub fields: Vec<String>,
    pub context: FilterContext,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 30,
            filter: None,
            sort: None,
            skip_total: false,
            expand: Vec::new(),
            fields: Vec::new(),
            context: FilterContext::default(),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordList {
    pub page: u64,
    pub per_page: u64,
    pub total_items: i64,
    pub total_pages: i64,
    pub items: Vec<JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires: String,
    pub record: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OAuth2Profile {
    provider_id: String,
    name: Option<String>,
    username: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    raw_user: JsonValue,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expiry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileUpload {
    field_name: String,
    original_name: String,
    content_type: String,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredFileInput {
    field_name: String,
    filename: String,
    content_type: String,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredFile {
    content_type: String,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMutationKind {
    Set,
    Append,
    Prepend,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThumbMode {
    CropCenter,
    CropTop,
    CropBottom,
    Fit,
    ResizeWidth,
    ResizeHeight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThumbSpec {
    width: u32,
    height: u32,
    mode: ThumbMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ReferencedFile {
    protected: bool,
    thumbs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FileFieldMutation {
    explicit_set: Option<JsonValue>,
    set_uploads: Vec<FileUpload>,
    append_uploads: Vec<FileUpload>,
    prepend_uploads: Vec<FileUpload>,
    delete_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PreparedFileChanges {
    store_files: Vec<StoredFileInput>,
    delete_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeEvent {
    pub event: String,
    pub data: JsonValue,
}

pub struct RealtimeConnection {
    pub client_id: String,
    receiver: mpsc::Receiver<RealtimeEvent>,
}

impl RealtimeConnection {
    pub fn recv_timeout(&self, timeout: Duration) -> Result<RealtimeEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RealtimeSubscription {
    collection: String,
    record_id: Option<String>,
}

impl RealtimeSubscription {
    fn topic(&self) -> String {
        match &self.record_id {
            Some(record_id) => format!("{}/{record_id}", self.collection),
            None => format!("{}/*", self.collection),
        }
    }
}

#[derive(Debug, Clone)]
struct RealtimeClient {
    sender: mpsc::Sender<RealtimeEvent>,
    subscriptions: Vec<RealtimeSubscription>,
    context: FilterContext,
}

#[derive(Debug, Clone)]
struct RealtimeClientSnapshot {
    client_id: String,
    sender: mpsc::Sender<RealtimeEvent>,
    subscriptions: Vec<RealtimeSubscription>,
    context: FilterContext,
}

#[derive(Debug, Clone)]
struct RealtimeDelivery {
    client_id: String,
    sender: mpsc::Sender<RealtimeEvent>,
    event: RealtimeEvent,
}

#[derive(Debug, Default)]
struct RealtimeBroker {
    clients: Mutex<HashMap<String, RealtimeClient>>,
}

impl RealtimeBroker {
    fn connect(&self) -> Result<RealtimeConnection, ServerError> {
        let client_id = generate_id();
        let (sender, receiver) = mpsc::channel();
        let connection = RealtimeConnection {
            client_id: client_id.clone(),
            receiver,
        };
        let client = RealtimeClient {
            sender: sender.clone(),
            subscriptions: Vec::new(),
            context: FilterContext::default(),
        };

        self.clients
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))?
            .insert(client_id.clone(), client);
        let _ = sender.send(RealtimeEvent {
            event: "PB_CONNECT".to_string(),
            data: json!({ "clientId": client_id }),
        });

        Ok(connection)
    }

    fn set_subscriptions(
        &self,
        client_id: &str,
        subscriptions: Vec<RealtimeSubscription>,
        context: FilterContext,
    ) -> Result<(), ServerError> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))?;
        let client = clients
            .get_mut(client_id)
            .ok_or_else(|| ServerError::NotFound("Missing or invalid client id.".to_string()))?;

        client.subscriptions = subscriptions;
        client.context = context;
        Ok(())
    }

    fn snapshots(&self) -> Vec<RealtimeClientSnapshot> {
        let Ok(clients) = self.clients.lock() else {
            return Vec::new();
        };

        clients
            .iter()
            .map(|(client_id, client)| RealtimeClientSnapshot {
                client_id: client_id.clone(),
                sender: client.sender.clone(),
                subscriptions: client.subscriptions.clone(),
                context: client.context.clone(),
            })
            .collect()
    }

    fn remove_client(&self, client_id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(client_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuthWithPasswordRequest {
    identity: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthWithOtpRequest {
    otp_id: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq)]
struct AuthWithOAuth2Request {
    provider: String,
    code: String,
    code_verifier: String,
    redirect_url: String,
    create_data: JsonValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ImpersonateRequest {
    duration: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealtimeSubscribeRequest {
    client_id: String,
    #[serde(default)]
    subscriptions: Vec<String>,
}

impl RealtimeSubscribeRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Something went wrong while processing your request.",
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        let client_id = required_form_string(
            object,
            "clientId",
            "Something went wrong while processing your request.",
        )?;
        let subscriptions = object
            .get("subscriptions")
            .and_then(JsonValue::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            client_id,
            subscriptions,
        })
    }
}

impl AuthWithPasswordRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Failed to authenticate.",
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            identity: required_form_string(object, "identity", "Failed to authenticate.")?,
            password: required_form_string(object, "password", "Failed to authenticate.")?,
        })
    }
}

impl AuthWithOtpRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Failed to authenticate.",
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            otp_id: required_form_string(object, "otpId", "Failed to authenticate.")?,
            password: required_form_string(object, "password", "Failed to authenticate.")?,
        })
    }
}

impl AuthWithOAuth2Request {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            provider: required_form_string(object, "provider", AUTH_FORM_VALIDATION_MESSAGE)?,
            code: required_form_string(object, "code", AUTH_FORM_VALIDATION_MESSAGE)?,
            code_verifier: required_form_string(
                object,
                "codeVerifier",
                AUTH_FORM_VALIDATION_MESSAGE,
            )?,
            redirect_url: required_form_string(
                object,
                "redirectUrl",
                AUTH_FORM_VALIDATION_MESSAGE,
            )?,
            create_data: object
                .get("createData")
                .cloned()
                .unwrap_or_else(|| JsonValue::Object(Map::new())),
        })
    }
}

impl ImpersonateRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            duration: optional_form_u64(object, "duration", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthEmailRequest {
    email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthNewEmailRequest {
    new_email: String,
}

impl AuthNewEmailRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            new_email: required_form_string(object, "newEmail", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl AuthEmailRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            email: required_form_string(object, "email", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthTokenRequest {
    token: String,
}

impl AuthTokenRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            token: required_form_string(object, "token", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfirmPasswordResetRequest {
    token: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfirmEmailChangeRequest {
    token: String,
    password: String,
}

impl ConfirmEmailChangeRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            token: required_form_string(object, "token", AUTH_FORM_VALIDATION_MESSAGE)?,
            password: required_form_string(object, "password", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl ConfirmPasswordResetRequest {
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            token: required_form_string(object, "token", AUTH_FORM_VALIDATION_MESSAGE)?,
            password: required_form_string(object, "password", AUTH_FORM_VALIDATION_MESSAGE)?,
            password_confirm: required_form_string(
                object,
                "passwordConfirm",
                AUTH_FORM_VALIDATION_MESSAGE,
            )?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthActionKind {
    Verification,
    PasswordReset,
    EmailChange,
    Otp,
}

impl AuthActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::PasswordReset => "passwordReset",
            Self::EmailChange => "emailChange",
            Self::Otp => "otp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<CollectionField>>,
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
    fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        if value.is_array() {
            return Ok(Self {
                collections: serde_json::from_value(value)?,
                delete_missing: false,
            });
        }

        Ok(serde_json::from_value(value)?)
    }
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
                expires TEXT NOT NULL,
                renewable INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS "_rb_auth_action_tokens" (
                token TEXT PRIMARY KEY NOT NULL,
                kind TEXT NOT NULL,
                collection_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                data TEXT NOT NULL,
                created TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS "_rb_auth_external_accounts" (
                collection_name TEXT NOT NULL,
                provider TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                data TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL,
                PRIMARY KEY (collection_name, provider, provider_id)
            );
            CREATE TABLE IF NOT EXISTS "_rb_file_tokens" (
                token TEXT PRIMARY KEY NOT NULL,
                collection_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                created TEXT NOT NULL,
                expires TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS "_rb_files" (
                collection_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                field_name TEXT NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                data BLOB NOT NULL,
                created TEXT NOT NULL,
                PRIMARY KEY (collection_name, record_id, filename)
            );
            "#,
        )?;
        ensure_auth_token_columns(&conn)?;
        Ok(())
    }

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
        name: &str,
        patch: CollectionPatch,
    ) -> Result<CollectionConfig, ServerError> {
        validate_collection_name(name)?;
        let mut collection = self.get_collection(name)?;
        apply_collection_patch(&mut collection, patch);
        normalize_collection(&mut collection);
        validate_collection(&collection)?;

        let old_name = name;
        let new_name = collection.name.clone();
        let old_table = record_table_name(old_name)?;
        let new_table = record_table_name(&new_name)?;
        let schema_json = serde_json::to_string(&collection)?;
        let now = now_timestamp();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;

        if old_name != new_name {
            let name_taken = tx
                .query_row(
                    r#"SELECT 1 FROM "_rb_collections" WHERE name = ?1 LIMIT 1"#,
                    params![&new_name],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some();
            if name_taken {
                return Err(ServerError::BadRequest(format!(
                    "collection '{new_name}' already exists"
                )));
            }

            let old_table_sql = quote_identifier(&old_table);
            let new_table_sql = quote_identifier(&new_table);
            tx.execute(
                &format!("ALTER TABLE {old_table_sql} RENAME TO {new_table_sql}"),
                [],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_action_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_external_accounts" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_file_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_files" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, old_name],
            )?;
        }

        let affected = tx.execute(
            r#"
            UPDATE "_rb_collections"
            SET name = ?1, schema_json = ?2, updated = ?3
            WHERE name = ?4
            "#,
            params![&new_name, schema_json, now, old_name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{old_name}' not found"
            )));
        }
        tx.commit()?;

        Ok(collection)
    }

    pub fn import_collections(
        &self,
        mut request: CollectionImportRequest,
    ) -> Result<(), ServerError> {
        for collection in &mut request.collections {
            normalize_collection(collection);
        }

        let mut incoming_names = HashMap::new();
        for collection in &request.collections {
            validate_collection(collection)?;
            if incoming_names.insert(collection.name.clone(), ()).is_some() {
                return Err(ServerError::BadRequest(format!(
                    "duplicate collection '{}'",
                    collection.name
                )));
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
            let collection = if let Some(current) = existing.get(&imported.name) {
                merge_imported_collection(current, imported, request.delete_missing)
            } else {
                imported
            };
            validate_collection(&collection)?;

            let table_sql = quote_identifier(&record_table_name(&collection.name)?);
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
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_collection(&self, name: &str) -> Result<(), ServerError> {
        validate_collection_name(name)?;
        self.get_collection(name)?;

        let table_sql = quote_identifier(&record_table_name(name)?);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
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
        let affected = tx.execute(
            r#"DELETE FROM "_rb_collections" WHERE name = ?1"#,
            params![name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{name}' not found"
            )));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn truncate_collection(&self, name: &str) -> Result<(), ServerError> {
        validate_collection_name(name)?;
        self.get_collection(name)?;

        let table_sql = quote_identifier(&record_table_name(name)?);
        let conn = self.connection()?;
        conn.execute(&format!("DELETE FROM {table_sql}"), [])?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
            params![name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
            params![name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
            params![name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
            params![name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
            params![name],
        )?;
        Ok(())
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
        data: JsonValue,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        self.create_record_with_uploads(collection_name, data, Vec::new(), context)
    }

    fn create_record_with_uploads(
        &self,
        collection_name: &str,
        mut data: JsonValue,
        uploads: Vec<FileUpload>,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        let collection = self.get_collection(collection_name)?;
        let object = data_object_mut(&mut data)?;
        let file_changes = prepare_file_changes(&collection, object, uploads, None)?;
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
                row_to_record(collection_name, row)
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

    pub fn expand_record_response(
        &self,
        collection_name: &str,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let collection = self.get_collection(collection_name)?;
        self.expand_record_with_collection(&collection, record, expands, context)
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

    fn update_record_with_uploads(
        &self,
        collection_name: &str,
        id: &str,
        patch: JsonValue,
        uploads: Vec<FileUpload>,
        context: FilterContext,
    ) -> Result<JsonValue, ServerError> {
        validate_record_id(id)?;
        let collection = self.get_collection(collection_name)?;
        let mut patch = patch;
        let mut existing = self.read_record(collection_name, id)?;
        let stored_files = {
            let patch_object = data_object_mut(&mut patch)?;
            prepare_file_changes(&collection, patch_object, uploads, Some(&existing))?
        };
        {
            let patch_object = data_object_mut(&mut patch)?;
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
        if !is_superuser_context(&context) {
            self.enforce_existing_record_rule(
                collection_name,
                &collection,
                collection.delete_rule.as_deref(),
                id,
                context,
                "delete",
            )?;
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let affected = conn.execute(
            &format!("DELETE FROM {table_sql} WHERE id = ?1"),
            params![id],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!("record '{id}' not found")));
        }
        conn.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, id],
        )?;
        if collection.collection_type == CollectionType::Auth {
            conn.execute(
                r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
        }

        Ok(())
    }

    pub fn auth_with_password(
        &self,
        collection_name: &str,
        identity: &str,
        password: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let password_config = auth_password_config(&collection);
        if !password_config.enabled {
            return Err(invalid_credentials());
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let mut predicates = vec!["id = ?1".to_string()];
        for field in password_config.identity_fields {
            predicates.push(format!("json_extract(data, '$.{field}') = ?1"));
        }
        let conn = self.connection()?;
        let row = conn
            .query_row(
                &format!(
                    "SELECT id, data, created, updated FROM {table_sql} WHERE {} LIMIT 1",
                    predicates.join(" OR ")
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

        let (token, expires) = insert_auth_token(
            &conn,
            collection_name,
            &id,
            auth_token_ttl_millis(&collection),
        )?;
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
        let collection = self.auth_collection(collection_name)?;
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
                &collection_name,
                id,
                serde_json::from_str::<JsonValue>(&data)?,
                created,
                updated,
            ),
        })
    }

    pub fn impersonate_auth_record(
        &self,
        collection_name: &str,
        record_id: &str,
        duration_seconds: Option<u64>,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        validate_record_id(record_id)?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let row = conn
            .query_row(
                &format!(
                    "SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 LIMIT 1"
                ),
                params![record_id],
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
            .ok_or_else(|| ServerError::NotFound(format!("record '{record_id}' not found")))?;

        let ttl_millis = duration_seconds
            .filter(|duration| *duration > 0)
            .map(|duration| u128::from(duration) * 1000)
            .unwrap_or_else(|| auth_token_ttl_millis(&collection));
        let (token, expires) =
            insert_auth_token_with_renewable(&conn, collection_name, record_id, ttl_millis, false)?;
        drop(conn);

        let (id, data, created, updated) = row;
        Ok(AuthResponse {
            token,
            expires,
            record: record_from_parts(
                collection_name,
                id,
                serde_json::from_str::<JsonValue>(&data)?,
                created,
                updated,
            ),
        })
    }

    pub fn request_otp(&self, collection_name: &str, email: &str) -> Result<String, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let otp = auth_otp_config(&collection);
        if !otp.enabled
            || !default_auth_identity_fields(&collection)
                .iter()
                .any(|field| field == "email")
        {
            return Err(ServerError::BadRequest(format!(
                "OTP auth is not enabled for collection '{collection_name}'"
            )));
        }
        let email = validate_form_email("email", email, AUTH_FORM_VALIDATION_MESSAGE)?;
        let otp_id = generate_id();
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let record_id = conn
            .query_row(
                &format!(
                    "SELECT id FROM {table_sql} WHERE json_extract(data, '$.email') = ?1 LIMIT 1"
                ),
                params![&email],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let Some(record_id) = record_id else {
            return Ok(otp_id);
        };

        delete_auth_action_tokens(&conn, &collection.name, &record_id, AuthActionKind::Otp)?;
        let password = generate_otp_password(otp.length);
        let created = now_timestamp();
        let expires = (now_millis() + u128::from(otp.duration) * 1000).to_string();
        conn.execute(
            r#"
            INSERT INTO "_rb_auth_action_tokens"
                (token, kind, collection_name, record_id, data, created, expires)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                &otp_id,
                AuthActionKind::Otp.as_str(),
                &collection.name,
                &record_id,
                json!({ "email": email, "password": password }).to_string(),
                created,
                expires
            ],
        )?;

        Ok(otp_id)
    }

    pub fn auth_with_otp(
        &self,
        collection_name: &str,
        otp_id: &str,
        password: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let conn = self.connection()?;
        let (record_id, token_data) =
            match auth_action_subject_data(&conn, collection_name, AuthActionKind::Otp, otp_id) {
                Ok(data) => data,
                Err(ServerError::BadRequest(_)) => return Err(invalid_credentials()),
                Err(err) => return Err(err),
            };
        let expected_password = token_data
            .get("password")
            .and_then(JsonValue::as_str)
            .ok_or_else(invalid_credentials)?;
        if password != expected_password {
            return Err(invalid_credentials());
        }

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

        let (id, data, created, _) = row;
        let mut data = serde_json::from_str::<JsonValue>(&data)?;
        let object = data_object_mut(&mut data)?;
        object.insert("verified".to_string(), JsonValue::Bool(true));
        let updated = now_timestamp();
        conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![serde_json::to_string(&data)?, &updated, &record_id],
        )?;
        delete_auth_action_tokens(
            &conn,
            collection.name.as_str(),
            &record_id,
            AuthActionKind::Otp,
        )?;
        let (token, expires) = insert_auth_token(
            &conn,
            collection_name,
            &record_id,
            auth_token_ttl_millis(&collection),
        )?;

        Ok(AuthResponse {
            token,
            expires,
            record: record_from_parts(collection_name, id, data, created, updated),
        })
    }

    fn auth_with_oauth2_profile(
        &self,
        collection_name: &str,
        provider: &str,
        profile: OAuth2Profile,
        create_data: &JsonValue,
    ) -> Result<(AuthResponse, JsonValue), ServerError> {
        let collection = self.auth_collection(collection_name)?;
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
                record: record_from_parts(collection_name, id, data, created, updated),
            },
            meta,
        ))
    }

    pub fn request_verification(
        &self,
        collection_name: &str,
        email: &str,
    ) -> Result<(), ServerError> {
        self.request_auth_action_token(collection_name, email, AuthActionKind::Verification)?;
        Ok(())
    }

    pub fn confirm_verification(
        &self,
        collection_name: &str,
        token: &str,
    ) -> Result<(), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let conn = self.connection()?;
        let record_id =
            auth_action_subject(&conn, collection_name, AuthActionKind::Verification, token)?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data = conn
            .query_row(
                &format!("SELECT data FROM {table_sql} WHERE id = ?1 LIMIT 1"),
                params![&record_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid_auth_action_token(AuthActionKind::Verification))?;
        let mut data = serde_json::from_str::<JsonValue>(&data)?;
        let object = data_object_mut(&mut data)?;
        object.insert("verified".to_string(), JsonValue::Bool(true));

        let now = now_timestamp();
        conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![serde_json::to_string(&data)?, now, &record_id],
        )?;
        delete_auth_action_tokens(
            &conn,
            collection.name.as_str(),
            &record_id,
            AuthActionKind::Verification,
        )?;
        Ok(())
    }

    pub fn request_password_reset(
        &self,
        collection_name: &str,
        email: &str,
    ) -> Result<(), ServerError> {
        self.request_auth_action_token(collection_name, email, AuthActionKind::PasswordReset)?;
        Ok(())
    }

    pub fn confirm_password_reset(
        &self,
        collection_name: &str,
        token: &str,
        password: &str,
        password_confirm: &str,
    ) -> Result<(), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let mut password_data = json!({
            "password": password,
            "passwordConfirm": password_confirm,
        });
        let password_object = data_object_mut(&mut password_data)?;
        prepare_auth_password_with_message(
            &collection,
            password_object,
            true,
            AUTH_FORM_VALIDATION_MESSAGE,
        )?;
        let password_hash = password_object
            .remove("passwordHash")
            .ok_or_else(|| ServerError::BadRequest("missing password hash".to_string()))?;

        let conn = self.connection()?;
        let record_id =
            auth_action_subject(&conn, collection_name, AuthActionKind::PasswordReset, token)?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data = conn
            .query_row(
                &format!("SELECT data FROM {table_sql} WHERE id = ?1 LIMIT 1"),
                params![&record_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid_auth_action_token(AuthActionKind::PasswordReset))?;
        let mut data = serde_json::from_str::<JsonValue>(&data)?;
        let object = data_object_mut(&mut data)?;
        object.insert("passwordHash".to_string(), password_hash);

        let now = now_timestamp();
        conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![serde_json::to_string(&data)?, now, &record_id],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, &record_id],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, &record_id],
        )?;
        delete_auth_action_tokens(
            &conn,
            collection.name.as_str(),
            &record_id,
            AuthActionKind::PasswordReset,
        )?;
        Ok(())
    }

    pub fn request_email_change(
        &self,
        collection_name: &str,
        auth_token: &str,
        new_email: &str,
    ) -> Result<(), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let (token_collection_name, record_id) = self.valid_token_subject(auth_token)?;
        if token_collection_name != collection_name {
            return Err(ServerError::Forbidden("invalid auth token".to_string()));
        }

        let conn = self.connection()?;
        let new_email = self.ensure_auth_email_available_tx(
            &conn,
            collection_name,
            new_email,
            Some(&record_id),
        )?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let exists = conn
            .query_row(
                &format!("SELECT 1 FROM {table_sql} WHERE id = ?1 LIMIT 1"),
                params![&record_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(ServerError::Forbidden("auth record not found".to_string()));
        }

        delete_auth_action_tokens(
            &conn,
            &collection.name,
            &record_id,
            AuthActionKind::EmailChange,
        )?;
        let token = generate_token();
        let created = now_timestamp();
        let expires = (now_millis()
            + auth_action_ttl_millis(&collection, AuthActionKind::EmailChange))
        .to_string();
        conn.execute(
            r#"
            INSERT INTO "_rb_auth_action_tokens"
                (token, kind, collection_name, record_id, data, created, expires)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                &token,
                AuthActionKind::EmailChange.as_str(),
                &collection.name,
                &record_id,
                json!({ "newEmail": new_email }).to_string(),
                created,
                expires
            ],
        )?;

        Ok(())
    }

    pub fn confirm_email_change(
        &self,
        collection_name: &str,
        token: &str,
        password: &str,
    ) -> Result<(), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let conn = self.connection()?;
        let (record_id, token_data) =
            auth_action_subject_data(&conn, collection_name, AuthActionKind::EmailChange, token)?;
        let new_email = token_data
            .get("newEmail")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_auth_action_token(AuthActionKind::EmailChange))?
            .to_string();
        let new_email = self.ensure_auth_email_available_tx(
            &conn,
            collection_name,
            &new_email,
            Some(&record_id),
        )?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let data = conn
            .query_row(
                &format!("SELECT data FROM {table_sql} WHERE id = ?1 LIMIT 1"),
                params![&record_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid_auth_action_token(AuthActionKind::EmailChange))?;
        let mut data = serde_json::from_str::<JsonValue>(&data)?;
        let object = data_object_mut(&mut data)?;
        let password_hash = object
            .get("passwordHash")
            .and_then(JsonValue::as_str)
            .ok_or_else(invalid_credentials)?;
        verify_password(password, password_hash)?;
        object.insert("email".to_string(), JsonValue::String(new_email));
        object.insert("verified".to_string(), JsonValue::Bool(true));

        let now = now_timestamp();
        conn.execute(
            &format!("UPDATE {table_sql} SET data = ?1, updated = ?2 WHERE id = ?3"),
            params![serde_json::to_string(&data)?, now, &record_id],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, &record_id],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, &record_id],
        )?;
        delete_auth_action_tokens(
            &conn,
            collection.name.as_str(),
            &record_id,
            AuthActionKind::EmailChange,
        )?;

        Ok(())
    }

    #[doc(hidden)]
    pub fn latest_auth_action_token(
        &self,
        collection_name: &str,
        record_id: &str,
        kind: &str,
    ) -> Result<Option<String>, ServerError> {
        validate_collection_name(collection_name)?;
        validate_record_id(record_id)?;
        validate_auth_action_kind(kind)?;

        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT token
            FROM "_rb_auth_action_tokens"
            WHERE collection_name = ?1 AND record_id = ?2 AND kind = ?3
            ORDER BY CAST(created AS INTEGER) DESC
            LIMIT 1
            "#,
            params![collection_name, record_id, kind],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(ServerError::Storage)
    }

    #[doc(hidden)]
    pub fn latest_auth_action_data(
        &self,
        collection_name: &str,
        record_id: &str,
        kind: &str,
    ) -> Result<Option<JsonValue>, ServerError> {
        validate_collection_name(collection_name)?;
        validate_record_id(record_id)?;
        validate_auth_action_kind(kind)?;

        let conn = self.connection()?;
        let data = conn
            .query_row(
                r#"
                SELECT data
                FROM "_rb_auth_action_tokens"
                WHERE collection_name = ?1 AND record_id = ?2 AND kind = ?3
                ORDER BY CAST(created AS INTEGER) DESC
                LIMIT 1
                "#,
                params![collection_name, record_id, kind],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        data.map(|value| serde_json::from_str::<JsonValue>(&value).map_err(ServerError::Json))
            .transpose()
    }

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

    fn request_auth_action_token(
        &self,
        collection_name: &str,
        email: &str,
        kind: AuthActionKind,
    ) -> Result<Option<String>, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let record_id = conn
            .query_row(
                &format!(
                    "SELECT id FROM {table_sql} WHERE json_extract(data, '$.email') = ?1 LIMIT 1"
                ),
                params![email],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let Some(record_id) = record_id else {
            return Ok(None);
        };

        delete_auth_action_tokens(&conn, &collection.name, &record_id, kind)?;
        let token = generate_token();
        let created = now_timestamp();
        let expires = (now_millis() + auth_action_ttl_millis(&collection, kind)).to_string();
        conn.execute(
            r#"
            INSERT INTO "_rb_auth_action_tokens"
                (token, kind, collection_name, record_id, data, created, expires)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                &token,
                kind.as_str(),
                &collection.name,
                &record_id,
                json!({ "email": email }).to_string(),
                created,
                expires
            ],
        )?;

        Ok(Some(token))
    }

    fn ensure_auth_email_available_tx(
        &self,
        conn: &Connection,
        collection_name: &str,
        email: &str,
        except_record_id: Option<&str>,
    ) -> Result<String, ServerError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "newEmail",
                "validation_required",
                "Field 'newEmail' is required.",
            ));
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let taken = if let Some(record_id) = except_record_id {
            conn.query_row(
                &format!(
                    "SELECT 1 FROM {table_sql} WHERE json_extract(data, '$.email') = ?1 AND id <> ?2 LIMIT 1"
                ),
                params![email, record_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        } else {
            conn.query_row(
                &format!(
                    "SELECT 1 FROM {table_sql} WHERE json_extract(data, '$.email') = ?1 LIMIT 1"
                ),
                params![email],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        };

        if taken {
            return Err(validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "newEmail",
                "validation_not_unique",
                "The email is already in use.",
            ));
        }

        Ok(email.to_string())
    }

    fn auth_collection(&self, collection_name: &str) -> Result<CollectionConfig, ServerError> {
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type != CollectionType::Auth {
            return Err(ServerError::BadRequest(format!(
                "collection '{collection_name}' is not an auth collection"
            )));
        }

        Ok(collection)
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

    pub fn superuser_auth_is_required(&self) -> Result<bool, ServerError> {
        match self.get_collection(SUPERUSERS_COLLECTION) {
            Ok(_) => {}
            Err(ServerError::NotFound(_)) => return Ok(false),
            Err(err) => return Err(err),
        }

        let table_sql = quote_identifier(&record_table_name(SUPERUSERS_COLLECTION)?);
        let conn = self.connection()?;
        let count = conn.query_row(&format!("SELECT COUNT(*) FROM {table_sql}"), [], |row| {
            row.get::<_, u64>(0)
        })?;

        Ok(count > 0)
    }

    pub fn is_superuser_token(&self, token: &str) -> Result<bool, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(token)?;
        if collection_name != SUPERUSERS_COLLECTION {
            return Ok(false);
        }

        self.read_record(SUPERUSERS_COLLECTION, &record_id)?;
        Ok(true)
    }

    pub fn create_file_token(&self, auth_token: &str) -> Result<String, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(auth_token)?;
        let collection = self.auth_collection(&collection_name)?;
        let token = generate_token();
        let now = now_millis();
        let expires = (now + file_token_ttl_millis(&collection)).to_string();
        let conn = self.connection()?;
        conn.execute(
            r#"
            INSERT INTO "_rb_file_tokens" (token, collection_name, record_id, created, expires)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                &token,
                &collection_name,
                &record_id,
                now.to_string(),
                &expires
            ],
        )?;

        Ok(token)
    }

    pub fn context_for_file_token(
        &self,
        token: &str,
        context: FilterContext,
    ) -> Result<FilterContext, ServerError> {
        let (collection_name, record_id) = self.valid_file_token_subject(token)?;
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

    fn get_file(
        &self,
        collection_name: &str,
        record_id: &str,
        filename: &str,
    ) -> Result<StoredFile, ServerError> {
        validate_collection_name(collection_name)?;
        validate_record_id(record_id)?;
        validate_file_name(filename)?;

        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT content_type, data
            FROM "_rb_files"
            WHERE collection_name = ?1 AND record_id = ?2 AND filename = ?3
            LIMIT 1
            "#,
            params![collection_name, record_id, filename],
            |row| {
                Ok(StoredFile {
                    content_type: row.get::<_, String>(0)?,
                    data: row.get::<_, Vec<u8>>(1)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| ServerError::NotFound(format!("file '{filename}' not found")))
    }

    fn expand_records(
        &self,
        collection: &CollectionConfig,
        records: &mut [JsonValue],
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        for record in records {
            self.expand_record_with_collection(collection, record, expands, context)?;
        }
        Ok(())
    }

    fn expand_record_with_collection(
        &self,
        collection: &CollectionConfig,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let grouped = group_expand_paths(expands);
        let record_object = record.as_object().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        let mut requested = Vec::new();

        for (field_name, nested_expands) in grouped {
            let field = collection
                .fields
                .iter()
                .find(|field| field.name == field_name)
                .ok_or_else(|| {
                    ServerError::BadRequest(format!(
                        "expand field '{field_name}' does not exist on collection '{}'",
                        collection.name
                    ))
                })?;
            if field.kind != CollectionFieldKind::Relation {
                return Err(ServerError::BadRequest(format!(
                    "expand field '{field_name}' is not a relation field"
                )));
            }

            let target_collection = field.collection.clone().ok_or_else(|| {
                ServerError::BadRequest(format!(
                    "relation field '{field_name}' does not declare a target collection"
                ))
            })?;

            if let Some(value) = record_object.get(&field_name).cloned() {
                requested.push((field_name, target_collection, nested_expands, value));
            }
        }

        let mut expanded = Map::new();
        for (field_name, target_collection, nested_expands, value) in requested {
            if let Some(expanded_value) =
                self.expand_relation_value(&target_collection, &value, &nested_expands, context)?
            {
                expanded.insert(field_name, expanded_value);
            }
        }

        if !expanded.is_empty() {
            let record_object = record.as_object_mut().ok_or_else(|| {
                ServerError::BadRequest("record response must be a JSON object".to_string())
            })?;
            record_object.insert("expand".to_string(), JsonValue::Object(expanded));
        }

        Ok(())
    }

    fn expand_relation_value(
        &self,
        target_collection: &str,
        value: &JsonValue,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<JsonValue>, ServerError> {
        if let Some(id) = value.as_str() {
            return Ok(self
                .expanded_related_record(target_collection, id, nested_expands, context)?
                .map(JsonValue::Object));
        }

        let Some(ids) = value.as_array() else {
            return Ok(None);
        };

        let mut records = Vec::new();
        for id in ids.iter().filter_map(JsonValue::as_str) {
            if let Some(record) =
                self.expanded_related_record(target_collection, id, nested_expands, context)?
            {
                records.push(JsonValue::Object(record));
            }
        }

        Ok(Some(JsonValue::Array(records)))
    }

    fn expanded_related_record(
        &self,
        target_collection: &str,
        id: &str,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<Map<String, JsonValue>>, ServerError> {
        let mut record = match self.get_record(target_collection, id, context.clone()) {
            Ok(record) => record,
            Err(ServerError::Forbidden(_) | ServerError::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        };

        if !nested_expands.is_empty() {
            let target = self.get_collection(target_collection)?;
            self.expand_record_with_collection(&target, &mut record, nested_expands, context)?;
        }

        let record = record.as_object().cloned().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        Ok(Some(record))
    }

    fn valid_token_subject(&self, token: &str) -> Result<(String, String), ServerError> {
        let (collection_name, record_id, _) = self.valid_auth_token_subject(token)?;
        Ok((collection_name, record_id))
    }

    fn valid_auth_token_subject(&self, token: &str) -> Result<(String, String, bool), ServerError> {
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

    fn valid_file_token_subject(&self, token: &str) -> Result<(String, String), ServerError> {
        self.valid_subject_token("_rb_file_tokens", token, "file")
    }

    fn valid_subject_token(
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
        if self.existing_record_rule_allows(collection_name, collection, rule, id, context)? {
            Ok(())
        } else {
            Err(forbidden(action, collection_name))
        }
    }

    fn existing_record_rule_allows(
        &self,
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

        let conn = self.connection()?;
        let allowed = conn
            .query_row(&sql, params_from_iter(params.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .optional()?
            .is_some();

        Ok(allowed)
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
    realtime: Arc<RealtimeBroker>,
}

impl RustyBaseApp {
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            realtime: Arc::new(RealtimeBroker::default()),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn realtime_connect(&self) -> Result<RealtimeConnection, ServerError> {
        self.realtime.connect()
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
            ("GET", ["api", "realtime"]) => {
                let connection = self.realtime_connect()?;
                Ok(HttpResponse::event_stream(vec![RealtimeEvent {
                    event: "PB_CONNECT".to_string(),
                    data: json!({ "clientId": connection.client_id }),
                }]))
            }
            ("POST", ["api", "realtime"]) => {
                let subscribe =
                    RealtimeSubscribeRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let subscriptions = realtime_subscriptions(&subscribe.subscriptions)?;
                for subscription in &subscriptions {
                    self.store.get_collection(&subscription.collection)?;
                }
                let context = self.request_context(&request, &query)?;
                self.realtime
                    .set_subscriptions(&subscribe.client_id, subscriptions, context)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "files", "token"]) => {
                let auth_token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let token = self.store.create_file_token(auth_token)?;
                Ok(HttpResponse::json(200, json!({ "token": token })))
            }
            ("GET", ["api", "files", collection, record_id, filename]) => {
                let collection_config = self.store.get_collection(collection)?;
                let record = self.store.read_record(collection, record_id)?;
                let Some(referenced_file) = referenced_file(&collection_config, &record, filename)?
                else {
                    return Err(ServerError::NotFound(format!(
                        "file '{filename}' not found"
                    )));
                };
                if referenced_file.protected {
                    let context = self.file_request_context(&request, &query)?;
                    let record = self.store.get_record(collection, record_id, context)?;
                    if !record_references_file(&collection_config, &record, filename)? {
                        return Err(ServerError::NotFound(format!(
                            "file '{filename}' not found"
                        )));
                    }
                }
                let mut file = self.store.get_file(collection, record_id, filename)?;
                if let Some(thumb) = query.get("thumb").filter(|thumb| !thumb.trim().is_empty()) {
                    file = thumbnail_file(file, thumb, &referenced_file.thumbs);
                }
                let mut response = HttpResponse::bytes(200, file.content_type, file.data);
                if truthy_query_value(&query, "download") {
                    response = response.with_header(
                        "Content-Disposition",
                        content_disposition_attachment(filename),
                    );
                }
                Ok(response)
            }
            ("GET", ["api", "collections"]) => {
                self.require_superuser_admin(&request)?;
                let list = self
                    .store
                    .list_collection_page(collection_list_options_from_query(&query)?)?;
                Ok(HttpResponse::json(200, list))
            }
            ("POST", ["api", "collections"]) => {
                self.require_superuser_admin(&request)?;
                let collection: CollectionConfig = serde_json::from_slice(&request.body)?;
                let collection = self.store.create_collection(collection)?;
                Ok(HttpResponse::json(200, json!(collection)))
            }
            ("PUT", ["api", "collections", "import"]) => {
                self.require_superuser_admin(&request)?;
                let request =
                    CollectionImportRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store.import_collections(request)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", "meta", "scaffolds"]) => {
                self.require_superuser_admin(&request)?;
                Ok(HttpResponse::json(200, collection_scaffolds()))
            }
            ("GET", ["api", "collections", "meta", "export"]) => {
                self.require_superuser_admin(&request)?;
                let collections = self.store.list_collections()?;
                Ok(HttpResponse::json(
                    200,
                    collection_export_payload(collections),
                ))
            }
            ("GET", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                let collection = self.store.get_collection(collection)?;
                Ok(HttpResponse::json(200, json!(collection)))
            }
            ("PATCH", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                let patch: CollectionPatch = serde_json::from_slice(&request.body)?;
                let collection = self.store.update_collection(collection, patch)?;
                Ok(HttpResponse::json(200, json!(collection)))
            }
            ("DELETE", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                self.store.delete_collection(collection)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("DELETE", ["api", "collections", collection, "truncate"]) => {
                self.require_superuser_admin(&request)?;
                self.store.truncate_collection(collection)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", collection, "auth-methods"]) => {
                let collection = self.store.get_collection(collection)?;
                let mut payload = auth_methods_payload(&collection)?;
                let fields = field_options_from_query(&query)?;
                project_json_response(&mut payload, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "request-verification"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_verification(collection, &request.email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-verification"]) => {
                let request = AuthTokenRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .confirm_verification(collection, &request.token)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "request-password-reset"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_password_reset(collection, &request.email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-password-reset"]) => {
                let request =
                    ConfirmPasswordResetRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store.confirm_password_reset(
                    collection,
                    &request.token,
                    &request.password,
                    &request.password_confirm,
                )?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "request-email-change"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let request =
                    AuthNewEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_email_change(collection, token, &request.new_email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-email-change"]) => {
                let request =
                    ConfirmEmailChangeRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .confirm_email_change(collection, &request.token, &request.password)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "auth-with-password"]) => {
                let auth =
                    AuthWithPasswordRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let response =
                    self.store
                        .auth_with_password(collection, &auth.identity, &auth.password)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "request-otp"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let otp_id = self.store.request_otp(collection, &request.email)?;
                Ok(HttpResponse::json(200, json!({ "otpId": otp_id })))
            }
            ("POST", ["api", "collections", collection, "auth-with-otp"]) => {
                let auth = AuthWithOtpRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let response =
                    self.store
                        .auth_with_otp(collection, &auth.otp_id, &auth.password)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-with-oauth2"]) => {
                let auth =
                    AuthWithOAuth2Request::from_json(serde_json::from_slice(&request.body)?)?;
                let profile = if let Some(profile) = oauth2_profile_from_code(&auth.code)? {
                    profile
                } else {
                    let collection_config = self.store.auth_collection(collection)?;
                    let provider_config =
                        oauth2_provider_configured(&collection_config, &auth.provider)?;
                    exchange_oauth2_code(&collection_config, provider_config, &auth)?
                };
                let (response, meta) = self.store.auth_with_oauth2_profile(
                    collection,
                    &auth.provider,
                    profile,
                    &auth.create_data,
                )?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = oauth2_auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    meta,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-refresh"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let response = self.store.auth_refresh(collection, token)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "impersonate", id]) => {
                self.require_superuser_token(&request)?;
                let body = json_body_or_empty(&request.body)?;
                let impersonate = ImpersonateRequest::from_json(body)?;
                let response =
                    self.store
                        .impersonate_auth_record(collection, id, impersonate.duration)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-logout"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                self.store.revoke_auth_token(collection, token)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", collection, "records"]) => {
                self.require_superuser_record_access(collection, &request)?;
                let options =
                    list_options_from_query(&query, self.request_context(&request, &query)?)?;
                let list = self.store.list_records(collection, options)?;
                Ok(HttpResponse::json(200, json!(list)))
            }
            ("POST", ["api", "collections", collection, "records"]) => {
                self.require_superuser_record_access(collection, &request)?;
                let collection_config = self.store.get_collection(collection)?;
                let (data, uploads) = record_payload_from_request(&request, &collection_config)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.create_record_with_uploads(
                    collection,
                    data,
                    uploads,
                    context.clone(),
                )?;
                let realtime_record = record.clone();
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                self.publish_realtime_record_event(collection, "create", &realtime_record);
                Ok(HttpResponse::json(200, record))
            }
            ("GET", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.get_record(collection, id, context.clone())?;
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                Ok(HttpResponse::json(200, record))
            }
            ("PATCH", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let collection_config = self.store.get_collection(collection)?;
                let (patch, uploads) = record_payload_from_request(&request, &collection_config)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.update_record_with_uploads(
                    collection,
                    id,
                    patch,
                    uploads,
                    context.clone(),
                )?;
                let realtime_record = record.clone();
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                self.publish_realtime_record_event(collection, "update", &realtime_record);
                Ok(HttpResponse::json(200, record))
            }
            ("DELETE", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let realtime_record = self.store.read_record(collection, id).ok();
                let realtime_deliveries = realtime_record
                    .as_ref()
                    .map(|record| self.realtime_deliveries(collection, "delete", record))
                    .unwrap_or_default();
                self.store.delete_record_with_context(
                    collection,
                    id,
                    self.request_context(&request, &query)?,
                )?;
                self.send_realtime_deliveries(realtime_deliveries);
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            _ => Err(ServerError::NotFound(format!(
                "route '{} {}' not found",
                request.method, request.path
            ))),
        }
    }

    fn require_superuser_admin(&self, request: &HttpRequest) -> Result<(), ServerError> {
        if !self.store.superuser_auth_is_required()? {
            return Ok(());
        }

        self.require_superuser_token(request)
    }

    fn require_superuser_token(&self, request: &HttpRequest) -> Result<(), ServerError> {
        let token = bearer_token(request)
            .ok_or_else(|| ServerError::Forbidden("missing superuser auth token".to_string()))?;
        if self.store.is_superuser_token(token)? {
            Ok(())
        } else {
            Err(ServerError::Forbidden(
                "superuser auth token is required".to_string(),
            ))
        }
    }

    fn require_superuser_record_access(
        &self,
        collection: &str,
        request: &HttpRequest,
    ) -> Result<(), ServerError> {
        if collection == SUPERUSERS_COLLECTION {
            self.require_superuser_admin(request)?;
        }

        Ok(())
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

    fn file_request_context(
        &self,
        request: &HttpRequest,
        query: &HashMap<String, String>,
    ) -> Result<FilterContext, ServerError> {
        let context = request_context(request, query);
        if let Some(token) = query.get("token").filter(|token| !token.trim().is_empty()) {
            return self.store.context_for_file_token(token, context);
        }

        self.request_context(request, query)
    }

    fn publish_realtime_record_event(&self, collection: &str, action: &str, record: &JsonValue) {
        let deliveries = self.realtime_deliveries(collection, action, record);
        self.send_realtime_deliveries(deliveries);
    }

    fn realtime_deliveries(
        &self,
        collection_name: &str,
        action: &str,
        record: &JsonValue,
    ) -> Vec<RealtimeDelivery> {
        let Some(record_id) = record.get("id").and_then(JsonValue::as_str) else {
            return Vec::new();
        };
        let Ok(collection) = self.store.get_collection(collection_name) else {
            return Vec::new();
        };

        let payload = json!({
            "action": action,
            "record": record,
        });
        let mut deliveries = Vec::new();
        for client in self.realtime.snapshots() {
            for subscription in client
                .subscriptions
                .iter()
                .filter(|subscription| subscription.collection == collection_name)
                .filter(|subscription| {
                    subscription
                        .record_id
                        .as_deref()
                        .map_or(true, |subscribed_id| subscribed_id == record_id)
                })
            {
                if !self.realtime_subscription_allows(
                    &collection,
                    subscription,
                    record_id,
                    &client.context,
                ) {
                    continue;
                }

                deliveries.push(RealtimeDelivery {
                    client_id: client.client_id.clone(),
                    sender: client.sender.clone(),
                    event: RealtimeEvent {
                        event: subscription.topic(),
                        data: payload.clone(),
                    },
                });
            }
        }

        deliveries
    }

    fn realtime_subscription_allows(
        &self,
        collection: &CollectionConfig,
        subscription: &RealtimeSubscription,
        record_id: &str,
        context: &FilterContext,
    ) -> bool {
        let rule = if subscription.record_id.is_some() {
            collection.view_rule.as_deref()
        } else {
            collection.list_rule.as_deref()
        };

        self.store
            .existing_record_rule_allows(
                &collection.name,
                collection,
                rule,
                record_id,
                context.clone(),
            )
            .unwrap_or(false)
    }

    fn send_realtime_deliveries(&self, deliveries: Vec<RealtimeDelivery>) {
        for delivery in deliveries {
            if delivery.sender.send(delivery.event).is_err() {
                self.realtime.remove_client(&delivery.client_id);
            }
        }
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
    pub content_type: String,
    pub headers: HashMap<String, String>,
    pub raw_body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body: JsonValue) -> Self {
        Self {
            status,
            body,
            content_type: "application/json".to_string(),
            headers: HashMap::new(),
            raw_body: Vec::new(),
        }
    }

    pub fn bytes(status: u16, content_type: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            body: JsonValue::Null,
            content_type: content_type.into(),
            headers: HashMap::new(),
            raw_body: body,
        }
    }

    pub fn event_stream(events: Vec<RealtimeEvent>) -> Self {
        let body = events.iter().flat_map(sse_event_bytes).collect::<Vec<u8>>();
        Self::bytes(200, "text/event-stream", body)
            .with_header("Cache-Control", "no-cache")
            .with_header("X-Accel-Buffering", "no")
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers
            .insert(normalize_http_header_name(&name), value.into());
        self
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
        } else if self.content_type == "application/json" && self.raw_body.is_empty() {
            serde_json::to_vec(&self.body).unwrap_or_else(|_| b"{}".to_vec())
        } else {
            self.raw_body.clone()
        };
        let mut headers = self
            .headers
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "content-type" | "content-length" | "connection"
                )
            })
            .collect::<Vec<_>>();
        headers.sort_by(|(left, _), (right, _)| left.cmp(right));
        let mut extra_headers = String::new();
        for (name, value) in headers {
            extra_headers.push_str(name);
            extra_headers.push_str(": ");
            extra_headers.push_str(&sanitize_http_header_value(value));
            extra_headers.push_str("\r\n");
        }
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            status_text,
            self.content_type,
            extra_headers,
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
    let (path, _) = split_path_query(&request.path);
    let segments = path_segments(&path);
    let segments = segments.iter().map(String::as_str).collect::<Vec<_>>();
    if request.method == "GET" && segments.as_slice() == ["api", "realtime"] {
        return handle_realtime_stream(app, stream);
    }

    let response = app.handle(request);
    stream.write_all(&response.to_http_bytes())?;
    Ok(())
}

fn handle_realtime_stream(app: RustyBaseApp, mut stream: TcpStream) -> Result<(), ServerError> {
    let connection = app.realtime_connect()?;
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\n",
    )?;

    loop {
        match connection.recv_timeout(REALTIME_IDLE_TIMEOUT) {
            Ok(event) => {
                stream.write_all(&sse_event_bytes(&event))?;
                stream.flush()?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let event = RealtimeEvent {
                    event: "PB_DISCONNECT".to_string(),
                    data: json!({}),
                };
                stream.write_all(&sse_event_bytes(&event))?;
                stream.flush()?;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    app.realtime.remove_client(&connection.client_id);
    Ok(())
}

fn json_body_or_empty(body: &[u8]) -> Result<JsonValue, ServerError> {
    if body.is_empty() {
        Ok(JsonValue::Object(Map::new()))
    } else {
        serde_json::from_slice(body).map_err(ServerError::Json)
    }
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

struct CollectionResolver;

impl FieldResolver for CollectionResolver {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "id" | "name" => Ok(ResolvedField::with_kind(
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

    if !is_superuser_context(&options.context) {
        if let Some(rule) = collection
            .list_rule
            .as_deref()
            .filter(|rule| !rule.trim().is_empty())
        {
            push_compiled_predicate(rule, resolver, &options.context, &mut sql, &mut params)?;
        }
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

fn collection_list_options_from_query(
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

fn collection_sort_sql(sort: Option<&str>) -> Result<String, ServerError> {
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

fn record_sort_sql(
    resolver: &RecordResolver<'_>,
    sort: Option<&str>,
) -> Result<String, ServerError> {
    let Some(sort) = sort.map(str::trim).filter(|sort| !sort.is_empty()) else {
        return Ok(r#""created" DESC, "id" ASC"#.to_string());
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
        let expression = if field == "@random" {
            "RANDOM()".to_string()
        } else if field == "@rowid" {
            "rowid".to_string()
        } else {
            resolver.resolve_field(field)?.sql
        };
        parts.push(format!("{expression} {direction}"));
    }

    if parts.is_empty() {
        Ok(r#""created" DESC, "id" ASC"#.to_string())
    } else {
        Ok(parts.join(", "))
    }
}

fn collection_type_sql() -> String {
    r#"json_extract("schema_json", '$.type')"#.to_string()
}

fn collection_system_sql() -> String {
    r#"CASE WHEN "name" LIKE '\_%' ESCAPE '\' THEN TRUE ELSE FALSE END"#.to_string()
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
        sort: query.get("sort").cloned(),
        skip_total: truthy_query_value(query, "skipTotal"),
        expand: expand_options_from_query(query)?,
        fields: field_options_from_query(query)?,
        context,
    })
}

fn field_options_from_query(query: &HashMap<String, String>) -> Result<Vec<String>, ServerError> {
    let Some(fields) = query.get("fields") else {
        return Ok(Vec::new());
    };

    let mut projections = Vec::new();
    for path in fields
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_field_projection_path(path)?;
        if !projections.iter().any(|existing| existing == path) {
            projections.push(path.to_string());
        }
    }

    Ok(projections)
}

fn realtime_subscriptions(values: &[String]) -> Result<Vec<RealtimeSubscription>, ServerError> {
    let mut subscriptions = Vec::new();
    for value in values {
        let topic = value
            .split_once('?')
            .map_or(value.as_str(), |(topic, _)| topic);
        let topic = topic.trim().trim_matches('/');
        if topic.is_empty() {
            continue;
        }
        let Some((collection, target)) = topic.split_once('/') else {
            return Err(ServerError::BadRequest(format!(
                "invalid realtime subscription '{value}'"
            )));
        };
        validate_collection_name(collection)?;
        let record_id = if target == "*" {
            None
        } else {
            validate_record_id(target)?;
            Some(target.to_string())
        };
        subscriptions.push(RealtimeSubscription {
            collection: collection.to_string(),
            record_id,
        });
    }
    dedupe_realtime_subscriptions(&mut subscriptions);

    Ok(subscriptions)
}

fn dedupe_realtime_subscriptions(subscriptions: &mut Vec<RealtimeSubscription>) {
    let mut seen = HashSet::new();
    subscriptions.retain(|subscription| seen.insert(subscription.topic()));
}

fn validate_field_projection_path(path: &str) -> Result<(), ServerError> {
    if path
        .split('.')
        .any(|part| part != "*" && !is_safe_identifier_part(part))
    {
        return Err(ServerError::BadRequest(format!(
            "invalid fields path '{path}'"
        )));
    }

    Ok(())
}

fn expand_options_from_query(query: &HashMap<String, String>) -> Result<Vec<String>, ServerError> {
    let Some(expand) = query.get("expand") else {
        return Ok(Vec::new());
    };

    let mut expands = Vec::new();
    for path in expand
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_expand_path(path)?;
        if !expands.iter().any(|existing| existing == path) {
            expands.push(path.to_string());
        }
    }

    Ok(expands)
}

fn validate_expand_path(path: &str) -> Result<(), ServerError> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.len() > 6 {
        return Err(ServerError::BadRequest(format!(
            "expand path '{path}' exceeds the 6-level limit"
        )));
    }
    if parts.iter().any(|part| !is_safe_identifier_part(part)) {
        return Err(ServerError::BadRequest(format!(
            "invalid expand path '{path}'"
        )));
    }

    Ok(())
}

fn group_expand_paths(expands: &[String]) -> HashMap<String, Vec<String>> {
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for expand in expands {
        let (field, nested) = expand.split_once('.').unwrap_or((expand, ""));
        let nested_expands = grouped.entry(field.to_string()).or_default();
        if !nested.is_empty() && !nested_expands.iter().any(|existing| existing == nested) {
            nested_expands.push(nested.to_string());
        }
    }

    grouped
}

fn project_record_responses(
    records: &mut [JsonValue],
    fields: &[String],
) -> Result<(), ServerError> {
    for record in records {
        project_record_response(record, fields)?;
    }

    Ok(())
}

fn auth_response_payload(
    store: &Store,
    collection_name: &str,
    mut response: AuthResponse,
    expands: &[String],
    fields: &[String],
    context: FilterContext,
) -> Result<JsonValue, ServerError> {
    let context = context_with_auth_record_values(context, &response.record);
    store.expand_record_response(collection_name, &mut response.record, expands, &context)?;

    let mut payload = json!(response);
    project_json_response(&mut payload, fields)?;
    Ok(payload)
}

fn oauth2_auth_response_payload(
    store: &Store,
    collection_name: &str,
    mut response: AuthResponse,
    meta: JsonValue,
    expands: &[String],
    fields: &[String],
    context: FilterContext,
) -> Result<JsonValue, ServerError> {
    let context = context_with_auth_record_values(context, &response.record);
    store.expand_record_response(collection_name, &mut response.record, expands, &context)?;

    let mut payload = json!(response);
    if let Some(object) = payload.as_object_mut() {
        object.insert("meta".to_string(), meta);
    }
    project_json_response(&mut payload, fields)?;
    Ok(payload)
}

fn auth_methods_payload(collection: &CollectionConfig) -> Result<JsonValue, ServerError> {
    if collection.collection_type != CollectionType::Auth {
        return Err(ServerError::BadRequest(format!(
            "collection '{}' is not an auth collection",
            collection.name
        )));
    }

    let password = auth_password_config(collection);
    let identity_fields = password.identity_fields.clone();
    let email_password = password.enabled && identity_fields.iter().any(|field| field == "email");
    let username_password =
        password.enabled && identity_fields.iter().any(|field| field == "username");
    let has_email_field = default_auth_identity_fields(collection)
        .iter()
        .any(|field| field == "email");
    let oauth2 = collection.oauth2.clone().unwrap_or_default();
    let oauth2_providers = if oauth2.enabled {
        oauth2
            .providers
            .iter()
            .filter(|provider| !provider.name.trim().is_empty())
            .map(oauth2_auth_method_provider)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mfa = collection.mfa.clone().unwrap_or_default();
    let otp = auth_otp_config(collection);

    Ok(json!({
        "password": {
            "enabled": password.enabled,
            "identityFields": identity_fields,
        },
        "oauth2": {
            "enabled": oauth2.enabled && !oauth2_providers.is_empty(),
            "providers": oauth2_providers.clone(),
        },
        "authProviders": oauth2_providers,
        "emailPassword": email_password,
        "usernamePassword": username_password,
        "mfa": {
            "enabled": mfa.enabled,
            "duration": if mfa.enabled { mfa.duration } else { 0 },
        },
        "otp": {
            "enabled": otp.enabled && has_email_field,
            "duration": if otp.enabled && has_email_field { otp.duration } else { 0 },
        }
    }))
}

fn auth_password_config(collection: &CollectionConfig) -> AuthPasswordConfig {
    let mut config = collection.password_auth.clone().unwrap_or_default();
    if config.identity_fields.is_empty() {
        config.identity_fields = default_auth_identity_fields(collection);
    }
    dedupe_strings(&mut config.identity_fields);
    config
}

fn default_auth_identity_fields(collection: &CollectionConfig) -> Vec<String> {
    collection
        .fields
        .iter()
        .filter(|field| field.name == "email" || field.name == "username")
        .map(|field| field.name.clone())
        .collect()
}

fn auth_otp_config(collection: &CollectionConfig) -> OtpConfig {
    let mut config = collection.otp.clone().unwrap_or_else(|| OtpConfig {
        enabled: default_auth_identity_fields(collection)
            .iter()
            .any(|field| field == "email"),
        ..Default::default()
    });
    if config.duration == 0 {
        config.duration = (OTP_TOKEN_TTL_MILLIS / 1000) as u64;
    }
    if config.length == 0 {
        config.length = 8;
    }
    config
}

fn auth_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.auth_token, AUTH_TOKEN_TTL_MILLIS)
}

fn file_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.file_token, FILE_TOKEN_TTL_MILLIS)
}

fn auth_action_ttl_millis(collection: &CollectionConfig, kind: AuthActionKind) -> u128 {
    match kind {
        AuthActionKind::Verification => {
            duration_config_millis(collection.verification_token, VERIFICATION_TOKEN_TTL_MILLIS)
        }
        AuthActionKind::PasswordReset => duration_config_millis(
            collection.password_reset_token,
            PASSWORD_RESET_TOKEN_TTL_MILLIS,
        ),
        AuthActionKind::EmailChange => {
            duration_config_millis(collection.email_change_token, EMAIL_CHANGE_TOKEN_TTL_MILLIS)
        }
        AuthActionKind::Otp => u128::from(auth_otp_config(collection).duration) * 1000,
    }
}

fn duration_config_millis(config: Option<TokenDurationConfig>, default_millis: u128) -> u128 {
    config
        .map(|config| u128::from(config.duration) * 1000)
        .filter(|duration| *duration > 0)
        .unwrap_or(default_millis)
}

fn oauth2_auth_method_provider(provider: &OAuth2ProviderConfig) -> JsonValue {
    let state = generate_oauth2_state();
    let code_verifier = generate_oauth2_code_verifier();
    let code_challenge = oauth2_code_challenge(&code_verifier);

    json!({
        "name": provider.name,
        "displayName": if provider.display_name.is_empty() {
            provider.name.clone()
        } else {
            provider.display_name.clone()
        },
        "state": state,
        "authURL": oauth2_auth_url(provider, &state, &code_challenge),
        "codeVerifier": code_verifier,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": "S256"
    })
}

fn generate_oauth2_state() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_oauth2_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn oauth2_code_challenge(code_verifier: &str) -> String {
    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

fn oauth2_auth_url(provider: &OAuth2ProviderConfig, state: &str, code_challenge: &str) -> String {
    let Some(auth_url) = oauth2_authorize_url(provider) else {
        return String::new();
    };
    if provider.client_id.trim().is_empty() {
        return String::new();
    }

    let scopes = oauth2_provider_scopes(provider);
    let mut params = vec![
        ("client_id", provider.client_id.trim().to_string()),
        ("code_challenge", code_challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("response_type", "code".to_string()),
    ];
    if !scopes.is_empty() {
        params.push(("scope", scopes.join(" ")));
    }
    params.push(("state", state.to_string()));
    params.push(("redirect_uri", String::new()));

    append_query_params(&auth_url, &params)
}

fn oauth2_authorize_url(provider: &OAuth2ProviderConfig) -> Option<String> {
    let auth_url = provider.auth_url.trim();
    if !auth_url.is_empty() {
        return Some(auth_url.to_string());
    }

    match oauth2_provider_key(&provider.name).as_str() {
        "github" => Some("https://github.com/login/oauth/authorize".to_string()),
        "google" => Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
        _ => None,
    }
}

fn oauth2_provider_scopes(provider: &OAuth2ProviderConfig) -> Vec<String> {
    if !provider.scopes.is_empty() {
        return provider
            .scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .map(str::to_string)
            .collect();
    }

    match oauth2_provider_key(&provider.name).as_str() {
        "github" => vec!["read:user".to_string(), "user:email".to_string()],
        "google" => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn append_query_params(base_url: &str, params: &[(&str, String)]) -> String {
    let mut url = base_url.to_string();
    let separator = if url.contains('?') {
        if url.ends_with('?') || url.ends_with('&') {
            ""
        } else {
            "&"
        }
    } else {
        "?"
    };
    url.push_str(separator);
    for (index, (name, value)) in params.iter().enumerate() {
        if index > 0 {
            url.push('&');
        }
        url.push_str(&percent_encode_query_component(name));
        url.push('=');
        url.push_str(&percent_encode_query_component(value));
    }
    url
}

fn ensure_oauth2_provider_configured(
    collection: &CollectionConfig,
    provider: &str,
) -> Result<(), ServerError> {
    oauth2_provider_configured(collection, provider).map(|_| ())
}

fn oauth2_provider_configured<'a>(
    collection: &'a CollectionConfig,
    provider: &str,
) -> Result<&'a OAuth2ProviderConfig, ServerError> {
    let Some(oauth2) = collection.oauth2.as_ref() else {
        return Err(ServerError::BadRequest(format!(
            "OAuth2 auth is not enabled for collection '{}'",
            collection.name
        )));
    };
    if !oauth2.enabled {
        return Err(ServerError::BadRequest(format!(
            "OAuth2 auth is not enabled for collection '{}'",
            collection.name
        )));
    }

    oauth2
        .providers
        .iter()
        .find(|candidate| candidate.name == provider)
        .ok_or_else(|| {
            ServerError::BadRequest(format!("OAuth2 provider '{provider}' is not configured"))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OAuth2ExchangeEndpoints {
    token_url: String,
    user_info_url: String,
    email_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuth2TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

fn exchange_oauth2_code(
    collection: &CollectionConfig,
    provider: &OAuth2ProviderConfig,
    request: &AuthWithOAuth2Request,
) -> Result<OAuth2Profile, ServerError> {
    let endpoints = oauth2_exchange_endpoints(provider).ok_or_else(|| {
        ServerError::BadRequest(format!(
            "OAuth2 provider callback exchange is not configured for provider '{}'",
            provider.name
        ))
    })?;
    if provider.client_id.trim().is_empty() {
        return Err(ServerError::BadRequest(format!(
            "OAuth2 provider '{}' is missing a clientId",
            provider.name
        )));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("RustyBase OAuth2")
        .build()
        .map_err(|err| oauth2_provider_request_error("client", err))?;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", request.code.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("redirect_uri", request.redirect_url.as_str()),
        ("code_verifier", request.code_verifier.as_str()),
    ];
    if !provider.client_secret.trim().is_empty() {
        form.push(("client_secret", provider.client_secret.as_str()));
    }

    let token_json = client
        .post(&endpoints.token_url)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .map_err(|err| oauth2_provider_request_error("token", err))
        .and_then(|response| oauth2_provider_json_response(response, "token"))?;
    let token = serde_json::from_value::<OAuth2TokenResponse>(token_json).map_err(|_| {
        ServerError::BadRequest("OAuth2 provider token response is invalid".to_string())
    })?;
    if token.access_token.trim().is_empty() {
        return Err(ServerError::BadRequest(
            "OAuth2 provider token response is missing access_token".to_string(),
        ));
    }

    let user_json = client
        .get(&endpoints.user_info_url)
        .header("Accept", "application/json")
        .bearer_auth(&token.access_token)
        .send()
        .map_err(|err| oauth2_provider_request_error("user info", err))
        .and_then(|response| oauth2_provider_json_response(response, "user info"))?;
    let fallback_email = if oauth2_provider_key(&provider.name) == "github"
        && oauth2_profile_value(&user_json, "", &["email"]).is_none()
    {
        if let Some(email_url) = endpoints.email_url.as_deref() {
            oauth2_primary_email(&client, email_url, &token.access_token)?
        } else {
            None
        }
    } else {
        None
    };

    oauth2_profile_from_user_info(collection, provider, user_json, fallback_email, token)
}

fn oauth2_exchange_endpoints(provider: &OAuth2ProviderConfig) -> Option<OAuth2ExchangeEndpoints> {
    let token_url = provider.token_url.trim();
    let user_info_url = provider.user_info_url.trim();
    if !token_url.is_empty() && !user_info_url.is_empty() {
        return Some(OAuth2ExchangeEndpoints {
            token_url: token_url.to_string(),
            user_info_url: user_info_url.to_string(),
            email_url: None,
        });
    }

    match oauth2_provider_key(&provider.name).as_str() {
        "github" => Some(OAuth2ExchangeEndpoints {
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            email_url: Some("https://api.github.com/user/emails".to_string()),
        }),
        "google" => Some(OAuth2ExchangeEndpoints {
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
            email_url: None,
        }),
        _ => None,
    }
}

fn oauth2_provider_key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn oauth2_provider_request_error(label: &str, err: reqwest::Error) -> ServerError {
    ServerError::BadRequest(format!("OAuth2 provider {label} request failed: {err}"))
}

fn oauth2_provider_json_response(
    response: reqwest::blocking::Response,
    label: &str,
) -> Result<JsonValue, ServerError> {
    let status = response.status();
    let body = response
        .text()
        .map_err(|err| oauth2_provider_request_error(label, err))?;
    if !status.is_success() {
        return Err(ServerError::BadRequest(format!(
            "OAuth2 provider {label} request failed with status {}",
            status.as_u16()
        )));
    }

    serde_json::from_str(&body).map_err(|_| {
        ServerError::BadRequest(format!("OAuth2 provider {label} response must be JSON"))
    })
}

fn oauth2_primary_email(
    client: &reqwest::blocking::Client,
    email_url: &str,
    access_token: &str,
) -> Result<Option<String>, ServerError> {
    let value = client
        .get(email_url)
        .header("Accept", "application/json")
        .bearer_auth(access_token)
        .send()
        .map_err(|err| oauth2_provider_request_error("email", err))
        .and_then(|response| oauth2_provider_json_response(response, "email"))?;
    let Some(emails) = value.as_array() else {
        return Ok(None);
    };

    let primary_verified = emails.iter().find_map(|email| {
        let object = email.as_object()?;
        let is_primary = object
            .get("primary")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let is_verified = object
            .get("verified")
            .and_then(JsonValue::as_bool)
            .unwrap_or(true);
        if is_primary && is_verified {
            object
                .get("email")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        } else {
            None
        }
    });
    if primary_verified.is_some() {
        return Ok(primary_verified);
    }

    Ok(emails.iter().find_map(|email| {
        let object = email.as_object()?;
        let is_verified = object
            .get("verified")
            .and_then(JsonValue::as_bool)
            .unwrap_or(true);
        if is_verified {
            object
                .get("email")
                .and_then(JsonValue::as_str)
                .map(str::to_string)
        } else {
            None
        }
    }))
}

fn oauth2_profile_from_user_info(
    collection: &CollectionConfig,
    provider: &OAuth2ProviderConfig,
    user_info: JsonValue,
    fallback_email: Option<String>,
    token: OAuth2TokenResponse,
) -> Result<OAuth2Profile, ServerError> {
    let mapped_fields = collection
        .oauth2
        .as_ref()
        .map(|oauth2| oauth2.mapped_fields.clone())
        .unwrap_or_default();
    let provider_id = oauth2_profile_value(&user_info, &mapped_fields.id, &["id", "sub"])
        .ok_or_else(|| {
            ServerError::BadRequest(format!(
                "OAuth2 provider '{}' user info response is missing an id",
                provider.name
            ))
        })?;

    let email = oauth2_profile_value(&user_info, "", &["email"]).or(fallback_email);
    Ok(OAuth2Profile {
        provider_id,
        name: oauth2_profile_value(
            &user_info,
            &mapped_fields.name,
            &["name", "display_name", "login"],
        ),
        username: oauth2_profile_value(
            &user_info,
            &mapped_fields.username,
            &["username", "login", "preferred_username", "email"],
        ),
        email,
        avatar_url: oauth2_profile_value(
            &user_info,
            &mapped_fields.avatar_url,
            &["avatarURL", "avatarUrl", "avatar_url", "picture"],
        ),
        raw_user: user_info,
        access_token: Some(token.access_token),
        refresh_token: token.refresh_token,
        expiry: token.expires_in.map(|value| value.to_string()),
    })
}

fn oauth2_profile_value(value: &JsonValue, mapped_path: &str, defaults: &[&str]) -> Option<String> {
    let mapped_path = mapped_path.trim();
    if !mapped_path.is_empty() {
        return json_scalar_at_path(value, mapped_path);
    }

    defaults
        .iter()
        .find_map(|path| json_scalar_at_path(value, path))
}

fn json_scalar_at_path(value: &JsonValue, path: &str) -> Option<String> {
    let mut current = value;
    for segment in path.split('.').map(str::trim) {
        if segment.is_empty() {
            return None;
        }
        current = current.as_object()?.get(segment)?;
    }

    match current {
        JsonValue::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        JsonValue::Number(value) => Some(value.to_string()),
        JsonValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn oauth2_profile_from_code(code: &str) -> Result<Option<OAuth2Profile>, ServerError> {
    let code = code.trim();
    let Some(payload) = code
        .strip_prefix("rb_profile:")
        .or_else(|| code.strip_prefix("profile:"))
        .or_else(|| code.starts_with('{').then_some(code))
    else {
        return Ok(None);
    };

    let value = serde_json::from_str::<JsonValue>(payload).map_err(|_| {
        validation_error(
            AUTH_FORM_VALIDATION_MESSAGE,
            "code",
            "validation_invalid_oauth2_profile",
            "OAuth2 provider profile payload must be a JSON object.",
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        validation_error(
            AUTH_FORM_VALIDATION_MESSAGE,
            "code",
            "validation_invalid_oauth2_profile",
            "OAuth2 provider profile payload must be a JSON object.",
        )
    })?;
    let provider_id = object
        .get("id")
        .or_else(|| object.get("providerId"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "code",
                "validation_required",
                "OAuth2 provider profile id is required.",
            )
        })?
        .to_string();

    Ok(Some(OAuth2Profile {
        provider_id,
        name: optional_json_string(object, "name"),
        username: optional_json_string(object, "username"),
        email: optional_json_string(object, "email"),
        avatar_url: optional_json_string(object, "avatarURL")
            .or_else(|| optional_json_string(object, "avatarUrl")),
        raw_user: object
            .get("rawUser")
            .cloned()
            .unwrap_or_else(|| value.clone()),
        access_token: optional_json_string(object, "accessToken"),
        refresh_token: optional_json_string(object, "refreshToken"),
        expiry: optional_json_string(object, "expiry"),
    }))
}

fn optional_json_string(object: &Map<String, JsonValue>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn insert_oauth2_auth_record_tx(
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

fn insert_profile_field(
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

fn collection_has_field(collection: &CollectionConfig, field: &str) -> bool {
    collection
        .fields
        .iter()
        .any(|candidate| candidate.name == field)
}

fn oauth2_meta_payload(provider: &str, profile: &OAuth2Profile, is_new: bool) -> JsonValue {
    json!({
        "provider": provider,
        "id": profile.provider_id,
        "name": profile.name,
        "username": profile.username,
        "email": profile.email,
        "isNew": is_new,
        "avatarURL": profile.avatar_url,
        "rawUser": profile.raw_user,
        "accessToken": profile.access_token,
        "refreshToken": profile.refresh_token,
        "expiry": profile.expiry,
    })
}

fn upsert_external_auth_account(
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

fn record_payload_from_request(
    request: &HttpRequest,
    collection: &CollectionConfig,
) -> Result<(JsonValue, Vec<FileUpload>), ServerError> {
    let Some(boundary) = multipart_boundary(request) else {
        return Ok((serde_json::from_slice(&request.body)?, Vec::new()));
    };

    multipart_record_payload(&request.body, &boundary, collection)
}

fn multipart_boundary(request: &HttpRequest) -> Option<String> {
    let content_type = request.headers.get("content-type")?;
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("multipart/form-data"))
    {
        return None;
    }

    for part in parts {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("boundary") {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }

    None
}

fn multipart_record_payload(
    body: &[u8],
    boundary: &str,
    collection: &CollectionConfig,
) -> Result<(JsonValue, Vec<FileUpload>), ServerError> {
    let mut object = Map::new();
    let mut uploads = Vec::new();
    let file_fields = collection
        .fields
        .iter()
        .filter(|field| field.kind == CollectionFieldKind::File)
        .map(|field| field.name.as_str())
        .collect::<HashSet<_>>();

    for part in parse_multipart_parts(body, boundary)? {
        let Some(name) = part.name else {
            continue;
        };

        if let Some(filename) = part.filename {
            uploads.push(FileUpload {
                field_name: name,
                original_name: filename,
                content_type: part
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                data: part.data,
            });
            continue;
        }

        let value = String::from_utf8(part.data).map_err(|_| {
            ServerError::BadRequest("multipart form field must be valid UTF-8".to_string())
        })?;
        if file_fields.contains(name.as_str()) && value.is_empty() {
            continue;
        }
        let value = multipart_text_value(collection, &name, value)?;
        insert_form_value(&mut object, name, value);
    }

    Ok((JsonValue::Object(object), uploads))
}

fn multipart_text_value(
    collection: &CollectionConfig,
    name: &str,
    value: String,
) -> Result<JsonValue, ServerError> {
    let Some(field) = collection.fields.iter().find(|field| field.name == name) else {
        return Ok(JsonValue::String(value));
    };

    match field.kind {
        CollectionFieldKind::Bool => match value.as_str() {
            "true" => Ok(JsonValue::Bool(true)),
            "false" => Ok(JsonValue::Bool(false)),
            _ => Err(validation_error(
                "Failed to validate record.",
                name,
                "validation_invalid_bool",
                format!("Field '{name}' must be a boolean."),
            )),
        },
        CollectionFieldKind::Number => value
            .parse::<serde_json::Number>()
            .map(JsonValue::Number)
            .map_err(|_| {
                validation_error(
                    "Failed to validate record.",
                    name,
                    "validation_invalid_number",
                    format!("Field '{name}' must be a number."),
                )
            }),
        CollectionFieldKind::Array | CollectionFieldKind::Json => serde_json::from_str(&value)
            .map_err(|_| {
                validation_error(
                    "Failed to validate record.",
                    name,
                    "validation_invalid_json",
                    format!("Field '{name}' must be valid JSON."),
                )
            }),
        _ => Ok(JsonValue::String(value)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MultipartPart {
    name: Option<String>,
    filename: Option<String>,
    content_type: Option<String>,
    data: Vec<u8>,
}

fn parse_multipart_parts(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, ServerError> {
    if boundary.is_empty() {
        return Err(ServerError::BadRequest(
            "multipart boundary is required".to_string(),
        ));
    }

    let marker = format!("--{boundary}").into_bytes();
    let mut cursor = find_subslice(body, &marker)
        .ok_or_else(|| ServerError::BadRequest("multipart boundary not found".to_string()))?;
    let mut parts = Vec::new();

    loop {
        if !body[cursor..].starts_with(&marker) {
            return Err(ServerError::BadRequest(
                "invalid multipart boundary".to_string(),
            ));
        }
        cursor += marker.len();

        if body[cursor..].starts_with(b"--") {
            break;
        }
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        }

        let header_len = find_subslice(&body[cursor..], b"\r\n\r\n")
            .ok_or_else(|| ServerError::BadRequest("multipart headers not closed".to_string()))?;
        let header_bytes = &body[cursor..cursor + header_len];
        cursor += header_len + 4;

        let next_boundary = find_subslice(&body[cursor..], &boundary_separator(&marker))
            .ok_or_else(|| ServerError::BadRequest("multipart part not closed".to_string()))?;
        let data = body[cursor..cursor + next_boundary].to_vec();
        cursor += next_boundary + 2;

        parts.push(parse_multipart_part(header_bytes, data)?);
    }

    Ok(parts)
}

fn boundary_separator(marker: &[u8]) -> Vec<u8> {
    let mut separator = Vec::with_capacity(marker.len() + 2);
    separator.extend_from_slice(b"\r\n");
    separator.extend_from_slice(marker);
    separator
}

fn parse_multipart_part(headers: &[u8], data: Vec<u8>) -> Result<MultipartPart, ServerError> {
    let headers = std::str::from_utf8(headers)
        .map_err(|_| ServerError::BadRequest("multipart headers must be UTF-8".to_string()))?;
    let mut name = None;
    let mut filename = None;
    let mut content_type = None;

    for line in headers.split("\r\n") {
        let Some((header_name, value)) = line.split_once(':') else {
            continue;
        };
        if header_name.eq_ignore_ascii_case("content-disposition") {
            name = quoted_header_param(value, "name");
            filename = quoted_header_param(value, "filename");
        } else if header_name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().to_string());
        }
    }

    Ok(MultipartPart {
        name,
        filename,
        content_type,
        data,
    })
}

fn quoted_header_param(value: &str, param: &str) -> Option<String> {
    for part in value.split(';').map(str::trim) {
        let Some((name, raw_value)) = part.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(param) {
            return Some(raw_value.trim().trim_matches('"').to_string());
        }
    }

    None
}

fn insert_form_value(object: &mut Map<String, JsonValue>, name: String, value: JsonValue) {
    if let Some(existing) = object.get_mut(&name) {
        match existing {
            JsonValue::Array(values) => values.push(value),
            other => {
                let first = std::mem::take(other);
                *other = JsonValue::Array(vec![first, value]);
            }
        }
    } else {
        object.insert(name, value);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn project_record_response(record: &mut JsonValue, fields: &[String]) -> Result<(), ServerError> {
    project_json_response(record, fields)
}

fn project_json_response(value: &mut JsonValue, fields: &[String]) -> Result<(), ServerError> {
    if fields.is_empty() {
        return Ok(());
    }

    let source = value.clone();
    let mut projected = Map::new();
    let expand_projection_parents = expand_projection_parents(fields);

    for field in fields {
        let parts = field.split('.').collect::<Vec<_>>();
        project_field_path(
            &source,
            &mut projected,
            &parts,
            &[],
            &expand_projection_parents,
        );
    }

    *value = JsonValue::Object(projected);
    Ok(())
}

fn expand_projection_parents(fields: &[String]) -> HashSet<Vec<String>> {
    let mut parents = HashSet::new();
    for field in fields {
        let mut parent = Vec::new();
        for part in field.split('.') {
            if part == "expand" {
                parents.insert(parent.clone());
            }
            parent.push(part.to_string());
        }
    }

    parents
}

fn project_field_path(
    source: &JsonValue,
    target: &mut Map<String, JsonValue>,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) {
    let Some((head, tail)) = parts.split_first() else {
        return;
    };
    let Some(source_object) = source.as_object() else {
        return;
    };

    if *head == "*" {
        for (key, value) in source_object {
            if key == "expand" && expand_projection_parents.contains(current_path) {
                continue;
            }

            let child_path = child_projection_path(current_path, key);
            let projected = if tail.is_empty() {
                Some(copy_wildcard_value(
                    value,
                    &child_path,
                    expand_projection_parents,
                ))
            } else {
                project_value_path(value, tail, &child_path, expand_projection_parents)
            };
            if let Some(projected) = projected {
                merge_projected_value(target, key, projected);
            }
        }
        return;
    }

    let Some(value) = source_object.get(*head) else {
        return;
    };
    let child_path = child_projection_path(current_path, head);
    let projected = if tail.is_empty() {
        Some(value.clone())
    } else {
        project_value_path(value, tail, &child_path, expand_projection_parents)
    };
    if let Some(projected) = projected {
        merge_projected_value(target, head, projected);
    }
}

fn project_value_path(
    source: &JsonValue,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> Option<JsonValue> {
    if parts.is_empty() {
        return Some(source.clone());
    }

    if source.is_object() {
        let mut projected = Map::new();
        project_field_path(
            source,
            &mut projected,
            parts,
            current_path,
            expand_projection_parents,
        );
        return (!projected.is_empty()).then_some(JsonValue::Object(projected));
    }

    if let Some(array) = source.as_array() {
        return Some(JsonValue::Array(
            array
                .iter()
                .filter_map(|value| {
                    project_value_path(value, parts, current_path, expand_projection_parents)
                })
                .collect(),
        ));
    }

    None
}

fn copy_wildcard_value(
    source: &JsonValue,
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> JsonValue {
    match source {
        JsonValue::Object(object) => {
            let mut copied = Map::new();
            for (key, value) in object {
                if key == "expand" && expand_projection_parents.contains(current_path) {
                    continue;
                }

                copied.insert(
                    key.clone(),
                    copy_wildcard_value(
                        value,
                        &child_projection_path(current_path, key),
                        expand_projection_parents,
                    ),
                );
            }
            JsonValue::Object(copied)
        }
        JsonValue::Array(array) => JsonValue::Array(
            array
                .iter()
                .map(|value| copy_wildcard_value(value, current_path, expand_projection_parents))
                .collect(),
        ),
        _ => source.clone(),
    }
}

fn child_projection_path(current_path: &[String], child: &str) -> Vec<String> {
    let mut path = current_path.to_vec();
    path.push(child.to_string());
    path
}

fn merge_projected_value(target: &mut Map<String, JsonValue>, key: &str, value: JsonValue) {
    if let Some(existing) = target.get_mut(key) {
        merge_json(existing, value);
    } else {
        target.insert(key.to_string(), value);
    }
}

fn merge_json(existing: &mut JsonValue, incoming: JsonValue) {
    match (existing, incoming) {
        (JsonValue::Object(existing), JsonValue::Object(incoming)) => {
            for (key, value) in incoming {
                merge_projected_value(existing, &key, value);
            }
        }
        (JsonValue::Array(existing), JsonValue::Array(incoming)) => {
            for (index, value) in incoming.into_iter().enumerate() {
                if let Some(existing) = existing.get_mut(index) {
                    merge_json(existing, value);
                } else {
                    existing.push(value);
                }
            }
        }
        (existing, incoming) => {
            *existing = incoming;
        }
    }
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

fn truthy_query_value(query: &HashMap<String, String>, name: &str) -> bool {
    query.get(name).is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "t" | "true"
        )
    })
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

fn context_with_body_values(context: FilterContext, body: &JsonValue) -> FilterContext {
    context_with_body_values_and_changes(context, body, None)
}

fn context_with_body_values_and_changes(
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

fn is_superuser_context(context: &FilterContext) -> bool {
    matches!(
        context.request.auth.get("collectionName"),
        Some(FilterValue::String(collection)) if collection == SUPERUSERS_COLLECTION
    )
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

fn collection_row_to_value(
    name: String,
    schema_json: String,
    created: String,
    updated: String,
) -> Result<JsonValue, ServerError> {
    let collection = serde_json::from_str::<CollectionConfig>(&schema_json)?;
    let mut value = json!(collection);
    let object = value.as_object_mut().ok_or_else(|| {
        ServerError::BadRequest("collection response must be a JSON object".to_string())
    })?;
    object.insert("id".to_string(), JsonValue::String(name.clone()));
    object.insert("name".to_string(), JsonValue::String(name.clone()));
    object.insert("created".to_string(), JsonValue::String(created));
    object.insert("updated".to_string(), JsonValue::String(updated));
    object.insert("system".to_string(), JsonValue::Bool(name.starts_with('_')));
    Ok(value)
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
    ServerError::BadRequest("Failed to authenticate.".to_string())
}

fn validation_error(
    message: impl Into<String>,
    field: impl Into<String>,
    code: impl Into<String>,
    field_message: impl Into<String>,
) -> ServerError {
    let mut data = Map::new();
    data.insert(
        field.into(),
        json!({
            "code": code.into(),
            "message": field_message.into(),
        }),
    );
    ServerError::BadRequestData {
        message: message.into(),
        data: JsonValue::Object(data),
    }
}

fn ensure_auth_token_columns(conn: &Connection) -> Result<(), ServerError> {
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

fn insert_auth_token(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    ttl_millis: u128,
) -> Result<(String, String), ServerError> {
    insert_auth_token_with_renewable(conn, collection_name, record_id, ttl_millis, true)
}

fn insert_auth_token_with_renewable(
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

fn auth_action_subject(
    conn: &Connection,
    collection_name: &str,
    kind: AuthActionKind,
    token: &str,
) -> Result<String, ServerError> {
    let (record_id, _) = auth_action_subject_data(conn, collection_name, kind, token)?;
    Ok(record_id)
}

fn auth_action_subject_data(
    conn: &Connection,
    collection_name: &str,
    kind: AuthActionKind,
    token: &str,
) -> Result<(String, JsonValue), ServerError> {
    let row = conn
        .query_row(
            r#"
            SELECT record_id, data, expires
            FROM "_rb_auth_action_tokens"
            WHERE token = ?1 AND kind = ?2 AND collection_name = ?3
            LIMIT 1
            "#,
            params![token, kind.as_str(), collection_name],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid_auth_action_token(kind))?;
    let (record_id, data, expires) = row;
    let expires = expires
        .parse::<u128>()
        .map_err(|_| invalid_auth_action_token(kind))?;
    if expires <= now_millis() {
        conn.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE token = ?1"#,
            params![token],
        )?;
        return Err(invalid_auth_action_token(kind));
    }
    let data =
        serde_json::from_str::<JsonValue>(&data).map_err(|_| invalid_auth_action_token(kind))?;

    Ok((record_id, data))
}

fn delete_auth_action_tokens(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    kind: AuthActionKind,
) -> Result<(), ServerError> {
    conn.execute(
        r#"
        DELETE FROM "_rb_auth_action_tokens"
        WHERE collection_name = ?1 AND record_id = ?2 AND kind = ?3
        "#,
        params![collection_name, record_id, kind.as_str()],
    )?;
    Ok(())
}

fn validate_auth_action_kind(kind: &str) -> Result<(), ServerError> {
    match kind {
        "verification" | "passwordReset" | "emailChange" | "otp" => Ok(()),
        _ => Err(ServerError::BadRequest(format!(
            "unknown auth action token kind '{kind}'"
        ))),
    }
}

fn invalid_auth_action_token(kind: AuthActionKind) -> ServerError {
    ServerError::BadRequest(format!("invalid or expired {} token", kind.as_str()))
}

fn apply_collection_patch(collection: &mut CollectionConfig, patch: CollectionPatch) {
    if let Some(name) = patch.name {
        collection.name = name;
    }
    if let Some(fields) = patch.fields {
        collection.fields = fields;
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

fn normalize_collection(collection: &mut CollectionConfig) {
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

    collection.auth_rule.get_or_insert_with(|| String::new());
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

fn collection_scaffolds() -> JsonValue {
    json!({
        "base": scaffold_collection("base", vec![scaffold_id_field()], json!({})),
        "auth": scaffold_collection(
            "auth",
            vec![
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
            ],
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

fn scaffold_collection(
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

fn scaffold_id_field() -> JsonValue {
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

fn scaffold_bool_field(id: &str, name: &str, system: bool) -> JsonValue {
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

fn collection_export_payload(collections: Vec<CollectionConfig>) -> JsonValue {
    json!({
        "collections": collections
            .into_iter()
            .map(collection_export_value)
            .collect::<Vec<_>>()
    })
}

fn collection_export_value(collection: CollectionConfig) -> JsonValue {
    let mut value = json!({
        "name": collection.name,
        "type": collection.collection_type,
        "schema": collection.fields
            .into_iter()
            .map(collection_field_export_value)
            .collect::<Vec<_>>(),
        "listRule": collection.list_rule,
        "viewRule": collection.view_rule,
        "createRule": collection.create_rule,
        "updateRule": collection.update_rule,
        "deleteRule": collection.delete_rule
    });
    let object = value.as_object_mut().expect("export value must be object");
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

fn insert_optional_json<T: Serialize>(
    object: &mut Map<String, JsonValue>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

fn collection_field_export_value(field: CollectionField) -> JsonValue {
    let mut value = Map::new();
    value.insert("name".to_string(), JsonValue::String(field.name));
    value.insert("type".to_string(), json!(field.kind));
    if let Some(collection) = field.collection {
        value.insert("collection".to_string(), JsonValue::String(collection));
    }
    if let Some(max_select) = field.max_select {
        value.insert("maxSelect".to_string(), json!(max_select));
    }
    if let Some(max_size) = field.max_size {
        value.insert("maxSize".to_string(), json!(max_size));
    }
    if !field.mime_types.is_empty() {
        value.insert("mimeTypes".to_string(), json!(field.mime_types));
    }
    if !field.thumbs.is_empty() {
        value.insert("thumbs".to_string(), json!(field.thumbs));
    }
    if field.protected {
        value.insert("protected".to_string(), JsonValue::Bool(true));
    }

    JsonValue::Object(value)
}

fn existing_collections_tx(
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

fn merge_imported_collection(
    current: &CollectionConfig,
    mut imported: CollectionConfig,
    delete_missing: bool,
) -> CollectionConfig {
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

fn prune_record_fields_tx(
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
        if let Some(target) = &field.collection {
            validate_collection_name(target)?;
            if field.kind != CollectionFieldKind::Relation {
                return Err(ServerError::BadRequest(format!(
                    "field '{}' declares a target collection but is not a relation",
                    field.name
                )));
            }
        }
        if field.kind != CollectionFieldKind::File
            && (field.protected
                || field.max_size.is_some()
                || !field.mime_types.is_empty()
                || !field.thumbs.is_empty())
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares file options but is not a file field",
                field.name
            )));
        }
        if field.kind == CollectionFieldKind::File {
            for thumb in &field.thumbs {
                if parse_thumb_spec(thumb).is_none() {
                    return Err(ServerError::BadRequest(format!(
                        "field '{}' has invalid thumb size '{}'",
                        field.name, thumb
                    )));
                }
            }
        }
    }

    validate_auth_options(collection)?;

    Ok(())
}

fn validate_auth_options(collection: &CollectionConfig) -> Result<(), ServerError> {
    if collection.collection_type != CollectionType::Auth {
        return Ok(());
    }

    let field_names = collection
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<HashSet<_>>();
    let password_auth = auth_password_config(collection);
    for field in &password_auth.identity_fields {
        if !field_names.contains(field.as_str()) {
            return Err(ServerError::BadRequest(format!(
                "password auth identity field '{field}' does not exist"
            )));
        }
    }

    for (name, value) in [
        (
            "authToken",
            collection.auth_token.map(|config| config.duration),
        ),
        (
            "passwordResetToken",
            collection
                .password_reset_token
                .map(|config| config.duration),
        ),
        (
            "emailChangeToken",
            collection.email_change_token.map(|config| config.duration),
        ),
        (
            "verificationToken",
            collection.verification_token.map(|config| config.duration),
        ),
        (
            "fileToken",
            collection.file_token.map(|config| config.duration),
        ),
    ] {
        if value.is_some_and(|duration| duration == 0) {
            return Err(ServerError::BadRequest(format!(
                "{name} duration must be greater than zero"
            )));
        }
    }

    if let Some(otp) = &collection.otp {
        if otp.enabled && !field_names.contains("email") {
            return Err(ServerError::BadRequest(
                "OTP auth requires an email identity field".to_string(),
            ));
        }
        if otp.duration == 0 {
            return Err(ServerError::BadRequest(
                "otp duration must be greater than zero".to_string(),
            ));
        }
        if !(4..=12).contains(&otp.length) {
            return Err(ServerError::BadRequest(
                "otp length must be between 4 and 12".to_string(),
            ));
        }
    }

    if let Some(oauth2) = &collection.oauth2 {
        if collection.name == SUPERUSERS_COLLECTION && oauth2.enabled {
            return Err(ServerError::BadRequest(
                "superusers collection does not support OAuth2 auth".to_string(),
            ));
        }
        for provider in &oauth2.providers {
            if provider.name.trim().is_empty() {
                return Err(ServerError::BadRequest(
                    "OAuth2 provider name is required".to_string(),
                ));
            }
            let has_token_url = !provider.token_url.trim().is_empty();
            let has_user_info_url = !provider.user_info_url.trim().is_empty();
            if has_token_url != has_user_info_url {
                return Err(ServerError::BadRequest(format!(
                    "OAuth2 provider '{}' requires both tokenUrl and userInfoUrl",
                    provider.name
                )));
            }
            for (field, url) in [
                ("authUrl", provider.auth_url.as_str()),
                ("tokenUrl", provider.token_url.as_str()),
                ("userInfoUrl", provider.user_info_url.as_str()),
            ] {
                let url = url.trim();
                if !url.is_empty() && !is_http_url(url) {
                    return Err(ServerError::BadRequest(format!(
                        "OAuth2 provider '{}' has invalid {field}",
                        provider.name
                    )));
                }
            }
        }
    }

    Ok(())
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
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

fn prepare_file_changes(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    uploads: Vec<FileUpload>,
    existing: Option<&JsonValue>,
) -> Result<PreparedFileChanges, ServerError> {
    let mut mutations: HashMap<String, FileFieldMutation> = HashMap::new();
    let keys = object.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        let Some((field_name, kind)) = parse_file_mutation_key(collection, &key) else {
            continue;
        };
        let value = object.remove(&key).unwrap_or(JsonValue::Null);
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            FileMutationKind::Set => {
                mutation.explicit_set = Some(value);
            }
            FileMutationKind::Delete => {
                mutation.delete_names.extend(file_names_from_value(&value)?);
            }
            FileMutationKind::Append | FileMutationKind::Prepend => {
                if !is_empty_file_value(&value) {
                    return Err(validation_error(
                        "Failed to validate record.",
                        key,
                        "validation_invalid_file_modifier",
                        "File append/prepend modifiers require uploaded file parts.",
                    ));
                }
            }
        }
    }

    for upload in uploads {
        let raw_field_name = upload.field_name.clone();
        let Some((field_name, kind)) = parse_file_mutation_key(collection, &raw_field_name) else {
            return Err(validation_error(
                "Failed to validate record.",
                raw_field_name,
                "validation_unknown_field",
                format!("Unknown field for collection '{}'.", collection.name),
            ));
        };
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            FileMutationKind::Set => mutation.set_uploads.push(upload),
            FileMutationKind::Append => mutation.append_uploads.push(upload),
            FileMutationKind::Prepend => mutation.prepend_uploads.push(upload),
            FileMutationKind::Delete => {
                return Err(validation_error(
                    "Failed to validate record.",
                    raw_field_name,
                    "validation_invalid_file_modifier",
                    "File delete modifiers require filename values.",
                ))
            }
        }
    }

    let mut changes = PreparedFileChanges::default();
    for (field_name, mutation) in mutations {
        let field = collection
            .fields
            .iter()
            .find(|field| field.name == field_name)
            .ok_or_else(|| {
                validation_error(
                    "Failed to validate record.",
                    &field_name,
                    "validation_unknown_field",
                    format!("Unknown field for collection '{}'.", collection.name),
                )
            })?;
        if field.kind != CollectionFieldKind::File {
            return Err(validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_invalid_file_field",
                "Uploaded files are only allowed on file fields.",
            ));
        }

        let max_select = field.max_select.unwrap_or(1).max(1);
        let existing_names = existing
            .and_then(JsonValue::as_object)
            .and_then(|object| object.get(&field_name))
            .map(file_names_from_value)
            .transpose()?
            .unwrap_or_default();

        let mut final_names = if let Some(value) = mutation.explicit_set {
            file_names_from_value(&value)?
        } else {
            existing_names.clone()
        };

        if !mutation.delete_names.is_empty() {
            let delete_names = mutation
                .delete_names
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            final_names.retain(|name| !delete_names.contains(name));
            changes.delete_files.extend(
                existing_names
                    .iter()
                    .filter(|name| delete_names.contains(*name))
                    .cloned(),
            );
        }

        if !mutation.set_uploads.is_empty() {
            changes.delete_files.extend(existing_names.iter().cloned());
            final_names.clear();
            let uploaded = prepare_uploaded_files(field, mutation.set_uploads, &mut changes)?;
            final_names.extend(uploaded);
        }

        if !mutation.prepend_uploads.is_empty() {
            let uploaded = prepare_uploaded_files(field, mutation.prepend_uploads, &mut changes)?;
            let mut combined = uploaded;
            combined.extend(final_names);
            final_names = combined;
        }

        if !mutation.append_uploads.is_empty() {
            let uploaded = prepare_uploaded_files(field, mutation.append_uploads, &mut changes)?;
            final_names.extend(uploaded);
        }

        if final_names.len() as u64 > max_select {
            return Err(validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_max_select",
                format!("Field '{field_name}' accepts at most {max_select} file(s)."),
            ));
        }

        changes.delete_files.extend(
            existing_names
                .iter()
                .filter(|name| !final_names.contains(*name))
                .cloned(),
        );
        dedupe_strings(&mut changes.delete_files);
        object.insert(
            field_name.clone(),
            file_field_value(&final_names, max_select),
        );
    }

    Ok(changes)
}

fn prepare_uploaded_files(
    field: &CollectionField,
    uploads: Vec<FileUpload>,
    changes: &mut PreparedFileChanges,
) -> Result<Vec<String>, ServerError> {
    let mut filenames = Vec::new();
    for upload in uploads {
        if field
            .max_size
            .is_some_and(|max_size| max_size > 0 && upload.data.len() as u64 > max_size)
        {
            return Err(validation_error(
                "Failed to validate record.",
                &field.name,
                "validation_max_size",
                format!("Field '{}' file exceeds the maximum size.", field.name),
            ));
        }

        let content_type = normalize_content_type(&upload.content_type);
        if !field.mime_types.is_empty() && !mime_type_allowed(&field.mime_types, &content_type) {
            return Err(validation_error(
                "Failed to validate record.",
                &field.name,
                "validation_mime_type",
                format!("Field '{}' does not allow this file type.", field.name),
            ));
        }

        let filename = stored_file_name(&upload.original_name);
        validate_file_name(&filename)?;
        filenames.push(filename.clone());
        changes.store_files.push(StoredFileInput {
            field_name: field.name.clone(),
            filename,
            content_type,
            data: upload.data,
        });
    }

    Ok(filenames)
}

fn parse_file_mutation_key(
    collection: &CollectionConfig,
    key: &str,
) -> Option<(String, FileMutationKind)> {
    if let Some(field) = key
        .strip_prefix('+')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Prepend));
    }
    if let Some(field) = key
        .strip_suffix('+')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Append));
    }
    if let Some(field) = key
        .strip_suffix('-')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Delete));
    }
    file_field(collection, key).map(|field| (field.name.clone(), FileMutationKind::Set))
}

fn file_field<'a>(collection: &'a CollectionConfig, name: &str) -> Option<&'a CollectionField> {
    collection
        .fields
        .iter()
        .find(|field| field.name == name && field.kind == CollectionFieldKind::File)
}

fn file_names_from_value(value: &JsonValue) -> Result<Vec<String>, ServerError> {
    match value {
        JsonValue::String(value) if value.trim().is_empty() => Ok(Vec::new()),
        JsonValue::String(value) => Ok(vec![value.clone()]),
        JsonValue::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    ServerError::BadRequest("file names must be strings".to_string())
                })
            })
            .filter(|result| result.as_ref().map_or(true, |name| !name.trim().is_empty()))
            .collect(),
        JsonValue::Null => Ok(Vec::new()),
        _ => Err(ServerError::BadRequest(
            "file field value must be a string or string array".to_string(),
        )),
    }
}

fn is_empty_file_value(value: &JsonValue) -> bool {
    match value {
        JsonValue::String(value) => value.is_empty(),
        JsonValue::Array(values) => values.is_empty(),
        JsonValue::Null => true,
        _ => false,
    }
}

fn file_field_value(names: &[String], max_select: u64) -> JsonValue {
    if max_select <= 1 {
        JsonValue::String(names.first().cloned().unwrap_or_default())
    } else {
        JsonValue::Array(names.iter().cloned().map(JsonValue::String).collect())
    }
}

fn thumbnail_file(file: StoredFile, spec: &str, allowed_thumbs: &[String]) -> StoredFile {
    let spec = spec.trim();
    if !allowed_thumbs.iter().any(|thumb| thumb == spec) {
        return file;
    }

    render_thumbnail(&file, spec).unwrap_or(file)
}

fn render_thumbnail(file: &StoredFile, spec: &str) -> Option<StoredFile> {
    if file.data.len() > MAX_THUMB_SOURCE_BYTES {
        return None;
    }

    let spec = parse_thumb_spec(spec)?;
    let format = image::guess_format(&file.data).ok()?;
    if !matches!(
        format,
        image::ImageFormat::Png
            | image::ImageFormat::Jpeg
            | image::ImageFormat::Gif
            | image::ImageFormat::WebP
    ) {
        return None;
    }

    let reader = image::ImageReader::with_format(Cursor::new(file.data.as_slice()), format);
    let (source_width, source_height) = reader.into_dimensions().ok()?;
    if source_width == 0 || source_height == 0 {
        return None;
    }
    if u64::from(source_width) * u64::from(source_height) > MAX_THUMB_SOURCE_PIXELS {
        return None;
    }

    let decoded = image::load_from_memory_with_format(&file.data, format).ok()?;
    let thumbnail = render_thumbnail_image(decoded, spec, source_width, source_height)?;
    let mut output = Cursor::new(Vec::new());
    thumbnail
        .write_to(&mut output, image::ImageFormat::Png)
        .ok()?;

    Some(StoredFile {
        content_type: "image/png".to_string(),
        data: output.into_inner(),
    })
}

fn parse_thumb_spec(value: &str) -> Option<ThumbSpec> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let (size, suffix) = match value.chars().last()? {
        't' | 'b' | 'f' => (&value[..value.len() - 1], value.chars().last()),
        _ => (value, None),
    };
    let (width, height) = size.split_once('x')?;
    let width = width.parse::<u32>().ok()?;
    let height = height.parse::<u32>().ok()?;
    if (width == 0 && height == 0) || width > MAX_THUMB_EDGE || height > MAX_THUMB_EDGE {
        return None;
    }

    let mode = match (width, height, suffix) {
        (0, _, None | Some('f')) => ThumbMode::ResizeHeight,
        (_, 0, None | Some('f')) => ThumbMode::ResizeWidth,
        (0, _, Some('t') | Some('b')) | (_, 0, Some('t') | Some('b')) => return None,
        (_, _, Some('f')) => ThumbMode::Fit,
        (_, _, Some('t')) => ThumbMode::CropTop,
        (_, _, Some('b')) => ThumbMode::CropBottom,
        (_, _, None) => ThumbMode::CropCenter,
        _ => return None,
    };

    Some(ThumbSpec {
        width,
        height,
        mode,
    })
}

fn render_thumbnail_image(
    image: image::DynamicImage,
    spec: ThumbSpec,
    source_width: u32,
    source_height: u32,
) -> Option<image::DynamicImage> {
    match spec.mode {
        ThumbMode::ResizeWidth => {
            let height = scaled_dimension(source_height, spec.width, source_width)?;
            resize_image(image, spec.width, height)
        }
        ThumbMode::ResizeHeight => {
            let width = scaled_dimension(source_width, spec.height, source_height)?;
            resize_image(image, width, spec.height)
        }
        ThumbMode::Fit => {
            let scale = (spec.width as f64 / source_width as f64)
                .min(spec.height as f64 / source_height as f64);
            let width = bounded_dimension((source_width as f64 * scale).round())?;
            let height = bounded_dimension((source_height as f64 * scale).round())?;
            resize_image(image, width, height)
        }
        ThumbMode::CropCenter | ThumbMode::CropTop | ThumbMode::CropBottom => {
            let scale = (spec.width as f64 / source_width as f64)
                .max(spec.height as f64 / source_height as f64);
            let resize_width =
                bounded_dimension((source_width as f64 * scale).ceil())?.max(spec.width);
            let resize_height =
                bounded_dimension((source_height as f64 * scale).ceil())?.max(spec.height);
            let resized = resize_image(image, resize_width, resize_height)?;
            let x = resize_width.saturating_sub(spec.width) / 2;
            let y = match spec.mode {
                ThumbMode::CropTop => 0,
                ThumbMode::CropBottom => resize_height.saturating_sub(spec.height),
                _ => resize_height.saturating_sub(spec.height) / 2,
            };

            Some(resized.crop_imm(x, y, spec.width, spec.height))
        }
    }
}

fn resize_image(
    image: image::DynamicImage,
    width: u32,
    height: u32,
) -> Option<image::DynamicImage> {
    if width == 0 || height == 0 {
        return None;
    }
    if u64::from(width) * u64::from(height) > MAX_THUMB_SOURCE_PIXELS {
        return None;
    }

    Some(image.resize_exact(width, height, image::imageops::FilterType::Lanczos3))
}

fn scaled_dimension(source_side: u32, target_side: u32, source_target_side: u32) -> Option<u32> {
    bounded_dimension(source_side as f64 * target_side as f64 / source_target_side as f64)
}

fn bounded_dimension(value: f64) -> Option<u32> {
    if !value.is_finite() {
        return None;
    }

    let value = value.round().max(1.0);
    if value > f64::from(MAX_THUMB_EDGE) {
        return None;
    }

    Some(value as u32)
}

fn record_references_file(
    collection: &CollectionConfig,
    record: &JsonValue,
    filename: &str,
) -> Result<bool, ServerError> {
    Ok(referenced_file(collection, record, filename)?.is_some())
}

fn referenced_file(
    collection: &CollectionConfig,
    record: &JsonValue,
    filename: &str,
) -> Result<Option<ReferencedFile>, ServerError> {
    let Some(object) = record.as_object() else {
        return Ok(None);
    };

    let mut referenced = ReferencedFile::default();
    let mut found = false;
    for field in collection
        .fields
        .iter()
        .filter(|field| field.kind == CollectionFieldKind::File)
    {
        let Some(value) = object.get(&field.name) else {
            continue;
        };
        if file_names_from_value(value)?
            .iter()
            .any(|name| name == filename)
        {
            found = true;
            referenced.protected |= field.protected;
            referenced.thumbs.extend(field.thumbs.iter().cloned());
        }
    }

    dedupe_strings(&mut referenced.thumbs);
    Ok(found.then_some(referenced))
}

fn store_file_uploads(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    files: &[StoredFileInput],
) -> Result<(), ServerError> {
    let now = now_timestamp();
    for file in files {
        conn.execute(
            r#"
            INSERT OR REPLACE INTO "_rb_files"
                (collection_name, record_id, field_name, filename, content_type, data, created)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                collection_name,
                record_id,
                &file.field_name,
                &file.filename,
                &file.content_type,
                &file.data,
                &now
            ],
        )?;
    }

    Ok(())
}

fn delete_file_names(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    filenames: &[String],
) -> Result<(), ServerError> {
    for filename in filenames {
        conn.execute(
            r#"
            DELETE FROM "_rb_files"
            WHERE collection_name = ?1 AND record_id = ?2 AND filename = ?3
            "#,
            params![collection_name, record_id, filename],
        )?;
    }

    Ok(())
}

fn dedupe_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn stored_file_name(original: &str) -> String {
    let basename = original
        .rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("file");
    let sanitized = sanitize_file_name(basename);
    let suffix = generate_file_suffix();

    if let Some((stem, ext)) = sanitized.rsplit_once('.') {
        if !stem.is_empty() && !ext.is_empty() {
            return format!("{stem}_{suffix}.{ext}");
        }
    }

    format!("{sanitized}_{suffix}")
}

fn sanitize_file_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_string();

    if sanitized.is_empty() {
        "file".to_string()
    } else {
        sanitized
    }
}

fn normalize_content_type(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "application/octet-stream".to_string()
    } else {
        value.to_string()
    }
}

fn mime_type_allowed(allowed: &[String], content_type: &str) -> bool {
    let content_type = content_type_base(content_type);
    allowed
        .iter()
        .map(|value| content_type_base(value))
        .filter(|value| !value.is_empty())
        .any(|allowed| {
            allowed == content_type
                || allowed
                    .strip_suffix("/*")
                    .is_some_and(|prefix| content_type.starts_with(&format!("{prefix}/")))
        })
}

fn content_type_base(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn validate_file_name(name: &str) -> Result<(), ServerError> {
    if !name.is_empty()
        && name.len() <= 255
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe file name '{name}'"
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
            return Err(validation_error(
                "Failed to validate record.",
                key,
                "validation_unknown_field",
                format!("Unknown field for collection '{}'.", collection.name),
            ));
        }
    }

    Ok(())
}

fn prepare_auth_password(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    require_password: bool,
) -> Result<(), ServerError> {
    prepare_auth_password_with_message(
        collection,
        object,
        require_password,
        "Failed to validate record.",
    )
}

fn prepare_auth_password_with_message(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    require_password: bool,
    message: &'static str,
) -> Result<(), ServerError> {
    if collection.collection_type != CollectionType::Auth {
        return Ok(());
    }

    object.remove("passwordHash");
    let password = take_string_field(object, "password")?;
    let password_confirm = take_string_field(object, "passwordConfirm")?;

    let Some(password) = password else {
        return if require_password {
            Err(validation_error(
                message,
                "password",
                "validation_required",
                "Password is required.",
            ))
        } else {
            Ok(())
        };
    };

    if password.len() < 8 {
        return Err(validation_error(
            message,
            "password",
            "validation_min_text_constraint",
            "Password must be at least 8 characters.",
        ));
    }

    if password_confirm
        .as_deref()
        .is_some_and(|confirm| confirm != password)
    {
        return Err(validation_error(
            message,
            "passwordConfirm",
            "validation_values_mismatch",
            "Password confirmation does not match.",
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
            value.as_str().map(str::to_string).ok_or_else(|| {
                validation_error(
                    "Failed to validate record.",
                    field,
                    "validation_invalid_string",
                    format!("Field '{field}' must be a string."),
                )
            })
        })
        .transpose()
}

fn required_form_string(
    object: &Map<String, JsonValue>,
    field: &str,
    message: &str,
) -> Result<String, ServerError> {
    let Some(value) = object.get(field) else {
        return Err(validation_error(
            message,
            field,
            "validation_required",
            format!("Field '{field}' is required."),
        ));
    };

    let Some(value) = value.as_str() else {
        return Err(validation_error(
            message,
            field,
            "validation_invalid_string",
            format!("Field '{field}' must be a string."),
        ));
    };

    if value.trim().is_empty() {
        return Err(validation_error(
            message,
            field,
            "validation_required",
            format!("Field '{field}' is required."),
        ));
    }

    Ok(value.to_string())
}

fn optional_form_u64(
    object: &Map<String, JsonValue>,
    field: &str,
    message: &str,
) -> Result<Option<u64>, ServerError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if let Some(value) = value.as_u64() {
        return Ok(Some(value));
    }

    Err(validation_error(
        message,
        field,
        "validation_invalid_number",
        format!("Field '{field}' must be a non-negative number."),
    ))
}

fn validate_form_email(field: &str, value: &str, message: &str) -> Result<String, ServerError> {
    let value = value.trim();
    if is_plausible_email(value) {
        Ok(value.to_string())
    } else {
        Err(validation_error(
            message,
            field,
            "validation_is_email",
            "Must be a valid email address.",
        ))
    }
}

fn is_plausible_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };

    !local.is_empty()
        && !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.contains('.')
        && !value.chars().any(char::is_whitespace)
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

fn generate_otp_password(length: u64) -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let length = length.clamp(4, 12) as usize;
    let modulus = 10_u64.pow(length as u32);
    let value = u64::from_le_bytes(bytes) % modulus;
    format!("{value:0length$}")
}

fn generate_file_suffix() -> String {
    let mut bytes = [0u8; 5];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
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

fn percent_encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
            }
        }
    }
    out
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

fn sse_event_bytes(event: &RealtimeEvent) -> Vec<u8> {
    let data = serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string());
    format!(
        "event: {}\ndata: {data}\n\n",
        sanitize_sse_event(&event.event)
    )
    .into_bytes()
}

fn sanitize_sse_event(event: &str) -> String {
    event
        .chars()
        .filter(|ch| *ch != '\r' && *ch != '\n')
        .collect()
}

fn sanitize_http_header_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect()
}

fn content_disposition_attachment(filename: &str) -> String {
    format!(
        "attachment; filename=\"{}\"",
        filename
            .chars()
            .map(|ch| {
                if ch == '"' || ch == '\\' || ch == '\r' || ch == '\n' {
                    '_'
                } else {
                    ch
                }
            })
            .collect::<String>()
    )
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_true() -> bool {
    true
}

fn error_response(err: ServerError) -> HttpResponse {
    let status = match &err {
        ServerError::BadRequest(_)
        | ServerError::BadRequestData { .. }
        | ServerError::Json(_)
        | ServerError::Filter(_) => 400,
        ServerError::Forbidden(_) => 403,
        ServerError::NotFound(_) => 404,
        ServerError::Storage(_) | ServerError::Io(_) => 500,
    };
    let data = match &err {
        ServerError::BadRequestData { data, .. } => data.clone(),
        _ => json!({}),
    };

    HttpResponse::json(
        status,
        json!({
            "code": status,
            "message": err.to_string(),
            "data": data,
        }),
    )
}
