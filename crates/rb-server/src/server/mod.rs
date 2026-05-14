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
use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization},
    params, params_from_iter,
    types::Value as SqlValue,
    Connection, ErrorCode, OptionalExtension,
};
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

pub(crate) mod app;
pub(crate) mod auth;
pub(crate) mod collections;
pub(crate) mod files;
pub(crate) mod http;
pub(crate) mod realtime;
pub(crate) mod records;
pub(crate) mod settings;
pub(crate) mod storage;
pub(crate) mod validation;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const AUTH_TOKEN_TTL_MILLIS: u128 = 7 * 24 * 60 * 60 * 1000;
const FILE_TOKEN_TTL_MILLIS: u128 = 2 * 60 * 1000;
const VERIFICATION_TOKEN_TTL_MILLIS: u128 = 3 * 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TOKEN_TTL_MILLIS: u128 = 30 * 60 * 1000;
const EMAIL_CHANGE_TOKEN_TTL_MILLIS: u128 = 30 * 60 * 1000;
const OTP_TOKEN_TTL_MILLIS: u128 = 3 * 60 * 1000;
const AUTH_FORM_VALIDATION_MESSAGE: &str = "An error occurred while validating the submitted data.";
const SETTINGS_FORM_VALIDATION_MESSAGE: &str = "An error occurred while submitting the form.";
const SUPERUSERS_COLLECTION: &str = "_superusers";
const MAX_THUMB_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_THUMB_SOURCE_PIXELS: u64 = 16_000_000;
const MAX_THUMB_EDGE: u32 = 2048;
const DEFAULT_JSON_MAX_SIZE_BYTES: u64 = 1024 * 1024;
const DEFAULT_EDITOR_MAX_SIZE_BYTES: u64 = 5 * 1024 * 1024;
const REALTIME_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_BATCH_MAX_REQUESTS: u64 = 50;
const DEFAULT_BATCH_TIMEOUT_SECONDS: u64 = 3;
const SETTINGS_SECRET_REDACTION: &str = "******";

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
