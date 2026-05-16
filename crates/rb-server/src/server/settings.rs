use super::*;
use super::{storage::*, validation::*};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    #[serde(default)]
    pub meta: AppMetaSettings,
    #[serde(default)]
    pub logs: LogSettings,
    #[serde(default)]
    pub batch: BatchSettings,
    #[serde(default)]
    pub smtp: SmtpSettings,
    #[serde(default)]
    pub s3: S3Settings,
    #[serde(default)]
    pub backups: BackupSettings,
    #[serde(default)]
    pub rate_limits: RateLimitSettings,
    #[serde(default)]
    pub trusted_proxy: TrustedProxySettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppMetaSettings {
    #[serde(default = "default_app_name")]
    pub app_name: String,
    #[serde(default, alias = "appUrl", rename = "appURL")]
    pub app_url: String,
    #[serde(default)]
    pub sender_name: String,
    #[serde(default)]
    pub sender_address: String,
    #[serde(default)]
    pub hide_controls: bool,
}

impl Default for AppMetaSettings {
    fn default() -> Self {
        Self {
            app_name: default_app_name(),
            app_url: String::new(),
            sender_name: String::new(),
            sender_address: String::new(),
            hide_controls: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSettings {
    #[serde(default = "default_log_max_days")]
    pub max_days: u64,
    #[serde(default)]
    pub min_level: i64,
    #[serde(default = "default_true")]
    pub log_ip: bool,
    #[serde(default)]
    pub log_auth_id: bool,
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            max_days: default_log_max_days(),
            min_level: 0,
            log_ip: true,
            log_auth_id: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_batch_max_requests")]
    pub max_requests: u64,
    #[serde(default = "default_batch_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub max_body_size: u64,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: DEFAULT_BATCH_MAX_REQUESTS,
            timeout: DEFAULT_BATCH_TIMEOUT_SECONDS,
            max_body_size: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_smtp_port")]
    pub port: u64,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default)]
    pub auth_method: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub local_name: String,
}

impl Default for SmtpSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_smtp_port(),
            host: String::new(),
            username: String::new(),
            password: String::new(),
            auth_method: String::new(),
            tls: true,
            local_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct S3Settings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,
    #[serde(default)]
    pub force_path_style: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSettings {
    #[serde(default)]
    pub cron: String,
    #[serde(default = "default_backup_cron_max_keep")]
    pub cron_max_keep: u64,
    #[serde(default)]
    pub s3: S3Settings,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            cron: String::new(),
            cron_max_keep: default_backup_cron_max_keep(),
            s3: S3Settings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rate_limit_rules")]
    pub rules: Vec<RateLimitRule>,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: default_rate_limit_rules(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitRule {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub duration: u64,
    #[serde(default)]
    pub max_requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrustedProxySettings {
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub use_leftmost_ip: bool,
}

pub(crate) fn settings_response_payload(settings: AppSettings) -> Result<JsonValue, ServerError> {
    let mut value = serde_json::to_value(settings)?;
    redact_settings_secrets(&mut value);
    Ok(value)
}

pub(crate) fn redact_settings_secrets(value: &mut JsonValue) {
    redact_object_string(value, &["smtp", "password"]);
    redact_object_string(value, &["s3", "secret"]);
    redact_object_string(value, &["backups", "s3", "secret"]);
}

pub(crate) fn redact_object_string(value: &mut JsonValue, path: &[&str]) {
    let Some((head, tail)) = path.split_first() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if tail.is_empty() {
        if object
            .get(*head)
            .and_then(JsonValue::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            object.insert(
                (*head).to_string(),
                JsonValue::String(SETTINGS_SECRET_REDACTION.to_string()),
            );
        }
        return;
    }

    if let Some(child) = object.get_mut(*head) {
        redact_object_string(child, tail);
    }
}

pub(crate) fn merge_settings_patch(
    target: &mut JsonValue,
    patch: &JsonValue,
    path: &mut Vec<String>,
) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            path.push(key.clone());
            if is_redacted_settings_secret(path, value) {
                path.pop();
                continue;
            }

            if let Some(existing) = target.get_mut(key) {
                merge_settings_patch(existing, value, path);
            } else {
                target.insert(key.clone(), value.clone());
            }
            path.pop();
        }
    } else {
        *target = patch.clone();
    }
}

pub(crate) fn is_redacted_settings_secret(path: &[String], value: &JsonValue) -> bool {
    value.as_str() == Some(SETTINGS_SECRET_REDACTION)
        && path
            .last()
            .is_some_and(|field| matches!(field.as_str(), "password" | "secret"))
}

pub(crate) fn validate_app_settings(settings: &AppSettings) -> Result<(), ServerError> {
    if settings.meta.app_name.trim().is_empty() {
        return Err(settings_required("meta.appName"));
    }
    if settings.batch.max_requests == 0 {
        return Err(settings_invalid_number(
            "batch.maxRequests",
            "Batch maxRequests must be greater than zero.",
        ));
    }
    if settings.batch.timeout == 0 {
        return Err(settings_invalid_number(
            "batch.timeout",
            "Batch timeout must be greater than zero.",
        ));
    }
    if settings.smtp.enabled {
        if settings.smtp.host.trim().is_empty() {
            return Err(settings_required("smtp.host"));
        }
        if settings.smtp.port == 0 {
            return Err(settings_invalid_number(
                "smtp.port",
                "SMTP port must be greater than zero.",
            ));
        }
    }

    validate_s3_settings("s3", &settings.s3)?;
    validate_s3_settings("backups.s3", &settings.backups.s3)?;
    for (index, rule) in settings.rate_limits.rules.iter().enumerate() {
        if rule.label.trim().is_empty() {
            return Err(settings_required(format!("rateLimits.rules.{index}.label")));
        }
        if rule.duration == 0 {
            return Err(settings_invalid_number(
                format!("rateLimits.rules.{index}.duration"),
                "Rate limit duration must be greater than zero.",
            ));
        }
        if rule.max_requests == 0 {
            return Err(settings_invalid_number(
                format!("rateLimits.rules.{index}.maxRequests"),
                "Rate limit maxRequests must be greater than zero.",
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_s3_settings(field: &str, settings: &S3Settings) -> Result<(), ServerError> {
    if !settings.enabled {
        return Ok(());
    }

    for (name, value) in [
        ("bucket", settings.bucket.as_str()),
        ("region", settings.region.as_str()),
        ("endpoint", settings.endpoint.as_str()),
        ("accessKey", settings.access_key.as_str()),
        ("secret", settings.secret.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(settings_required(format!("{field}.{name}")));
        }
    }

    Ok(())
}

pub(crate) fn settings_required(field: impl Into<String>) -> ServerError {
    validation_error(
        SETTINGS_FORM_VALIDATION_MESSAGE,
        field,
        "validation_required",
        "Missing required value.",
    )
}

pub(crate) fn settings_invalid_number(
    field: impl Into<String>,
    message: impl Into<String>,
) -> ServerError {
    validation_error(
        SETTINGS_FORM_VALIDATION_MESSAGE,
        field,
        "validation_invalid_number",
        message,
    )
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn default_app_name() -> String {
    "Rusty Base".to_string()
}

pub(crate) fn default_log_max_days() -> u64 {
    7
}

pub(crate) fn default_batch_max_requests() -> u64 {
    DEFAULT_BATCH_MAX_REQUESTS
}

pub(crate) fn default_batch_timeout() -> u64 {
    DEFAULT_BATCH_TIMEOUT_SECONDS
}

pub(crate) fn default_smtp_port() -> u64 {
    587
}

pub(crate) fn default_backup_cron_max_keep() -> u64 {
    3
}

pub(crate) fn default_rate_limit_rules() -> Vec<RateLimitRule> {
    vec![
        RateLimitRule {
            label: "*:auth".to_string(),
            audience: String::new(),
            duration: 3,
            max_requests: 2,
        },
        RateLimitRule {
            label: "*:create".to_string(),
            audience: String::new(),
            duration: 5,
            max_requests: 20,
        },
        RateLimitRule {
            label: "/api/batch".to_string(),
            audience: String::new(),
            duration: 1,
            max_requests: 3,
        },
        RateLimitRule {
            label: "/api/".to_string(),
            audience: String::new(),
            duration: 10,
            max_requests: 300,
        },
    ]
}

pub(crate) fn default_true() -> bool {
    true
}

impl Store {
    pub fn get_settings(&self) -> Result<AppSettings, ServerError> {
        let conn = self.connection()?;
        app_settings_from_conn(&conn)
    }

    pub fn update_settings(&self, patch: JsonValue) -> Result<AppSettings, ServerError> {
        if !patch.is_object() {
            return Err(validation_error(
                SETTINGS_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            ));
        }

        let mut value = serde_json::to_value(self.get_settings()?)?;
        merge_settings_patch(&mut value, &patch, &mut Vec::new());
        let settings: AppSettings = serde_json::from_value(value)?;
        validate_app_settings(&settings)?;

        let now = now_timestamp();
        let settings_json = serde_json::to_string(&settings)?;
        let conn = self.connection()?;
        conn.execute(
            r#"
            INSERT INTO "_rb_settings" (key, value, updated)
            VALUES ('app', ?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated
            "#,
            params![settings_json, now],
        )?;

        Ok(settings)
    }
}

pub(crate) fn app_settings_from_conn(conn: &Connection) -> Result<AppSettings, ServerError> {
    let value = conn
        .query_row(
            r#"SELECT value FROM "_rb_settings" WHERE key = 'app' LIMIT 1"#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    let settings = match value {
        Some(value) => serde_json::from_str(&value)?,
        None => AppSettings::default(),
    };
    validate_app_settings(&settings)?;
    Ok(settings)
}
