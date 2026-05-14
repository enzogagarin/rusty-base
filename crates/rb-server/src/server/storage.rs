use super::*;
use super::{auth::*, collections::*, validation::*};

pub struct Store {
    pub(crate) conn: Mutex<Connection>,
}

pub(crate) fn data_object(value: &JsonValue) -> Result<&Map<String, JsonValue>, ServerError> {
    value
        .as_object()
        .ok_or_else(|| ServerError::BadRequest("record body must be a JSON object".to_string()))
}

pub(crate) fn data_object_mut(
    value: &mut JsonValue,
) -> Result<&mut Map<String, JsonValue>, ServerError> {
    value
        .as_object_mut()
        .ok_or_else(|| ServerError::BadRequest("record body must be a JSON object".to_string()))
}

pub(crate) fn is_system_record_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "created" | "updated" | "collectionId" | "collectionName" | "passwordHash"
    )
}

pub(crate) fn record_table_name(collection_name: &str) -> Result<String, ServerError> {
    validate_collection_name(collection_name)?;
    Ok(format!("_rb_records_{collection_name}"))
}

pub(crate) fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub(crate) fn is_safe_identifier_part(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub(crate) fn is_safe_identifier_path(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(is_safe_identifier_part)
}

pub(crate) fn json_data_extract(field: &str) -> String {
    format!(
        "json_extract({}, '{}')",
        quote_identifier("data"),
        json_path(field)
    )
}

pub(crate) fn incoming_json_extract(field: &str) -> String {
    format!(
        "json_extract({}.{}, '{}')",
        quote_identifier("__rb_input"),
        quote_identifier("data"),
        json_path(field)
    )
}

pub(crate) fn json_path(field: &str) -> String {
    let mut path = String::from("$");
    for part in field.split('.') {
        path.push('.');
        path.push_str(part);
    }
    path
}

pub(crate) fn generate_id() -> String {
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

pub(crate) fn generate_collection_id() -> String {
    format!("_rbc_{}", generate_id())
}

pub(crate) fn generate_field_id(kind: CollectionFieldKind) -> String {
    format!("{}{}", field_kind_id_prefix(kind), generate_id())
}

pub(crate) fn field_kind_id_prefix(kind: CollectionFieldKind) -> &'static str {
    match kind {
        CollectionFieldKind::Text => "text",
        CollectionFieldKind::Email => "email",
        CollectionFieldKind::Url => "url",
        CollectionFieldKind::Editor => "editor",
        CollectionFieldKind::File => "file",
        CollectionFieldKind::Number => "number",
        CollectionFieldKind::Bool => "bool",
        CollectionFieldKind::DateTime => "date",
        CollectionFieldKind::Array => "array",
        CollectionFieldKind::Json => "json",
        CollectionFieldKind::Relation => "relation",
        CollectionFieldKind::Select => "select",
        CollectionFieldKind::GeoPoint => "geoPoint",
        CollectionFieldKind::AutoDate => "autodate",
    }
}

pub(crate) fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("rb_{}", hex_encode(&bytes))
}

pub(crate) fn generate_otp_password(length: u64) -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let length = length.clamp(4, 12) as usize;
    let modulus = 10_u64.pow(length as u32);
    let value = u64::from_le_bytes(bytes) % modulus;
    format!("{value:0length$}")
}

pub(crate) fn generate_file_suffix() -> String {
    let mut bytes = [0u8; 5];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

pub(crate) fn hash_password(password: &str) -> Result<String, ServerError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| ServerError::BadRequest(format!("failed to hash password: {err}")))
}

pub(crate) fn verify_password(password: &str, password_hash: &str) -> Result<(), ServerError> {
    let password_hash = PasswordHash::new(password_hash).map_err(|_| invalid_credentials())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &password_hash)
        .map_err(|_| invalid_credentials())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn now_timestamp() -> String {
    timestamp_from_millis(now_millis())
}

pub(crate) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) fn timestamp_from_millis(millis: u128) -> String {
    let total_seconds = millis / 1000;
    let millisecond = (millis % 1000) as u32;
    let days = (total_seconds / 86_400) as i64;
    let seconds_of_day = (total_seconds % 86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millisecond:03}Z")
}

pub(crate) fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let days = days_since_unix_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ServerError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, ServerError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    pub(crate) fn from_connection(conn: Connection) -> Result<Self, ServerError> {
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    pub(crate) fn initialize(&self) -> Result<(), ServerError> {
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
            CREATE TABLE IF NOT EXISTS "_rb_settings" (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated TEXT NOT NULL
            );
            "#,
        )?;
        ensure_auth_token_columns(&conn)?;
        Ok(())
    }

    pub(crate) fn begin_batch_transaction(&self) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub(crate) fn commit_batch_transaction(&self) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub(crate) fn rollback_batch_transaction(&self) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    pub(crate) fn with_savepoint<T>(
        &self,
        name: &str,
        work: impl FnOnce(&Connection) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        let savepoint = quote_identifier(name);
        let begin = format!("SAVEPOINT {savepoint}");
        let release = format!("RELEASE SAVEPOINT {savepoint}");
        let rollback = format!("ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint}");
        let conn = self.connection()?;

        conn.execute_batch(&begin)?;

        match work(&conn) {
            Ok(value) => match conn.execute_batch(&release) {
                Ok(()) => Ok(value),
                Err(err) => {
                    let _ = conn.execute_batch(&rollback);
                    Err(ServerError::Storage(err))
                }
            },
            Err(err) => {
                let _ = conn.execute_batch(&rollback);
                Err(err)
            }
        }
    }

    pub(crate) fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, ServerError> {
        self.conn
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))
    }
}
