use super::*;
use crate::server::{collections::*, files::*, records::*, settings::*, storage::*};

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct AuthWithPasswordRequest {
    pub(crate) identity: String,
    pub(crate) password: String,
}

impl AuthWithPasswordRequest {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
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

pub(crate) fn auth_password_config(collection: &CollectionConfig) -> AuthPasswordConfig {
    let mut config = collection.password_auth.clone().unwrap_or_default();
    if config.identity_fields.is_empty() {
        config.identity_fields = default_auth_identity_fields(collection);
    }
    dedupe_strings(&mut config.identity_fields);
    config
}

pub(crate) fn default_auth_identity_fields(collection: &CollectionConfig) -> Vec<String> {
    collection
        .fields
        .iter()
        .filter(|field| field.name == "email" || field.name == "username")
        .map(|field| field.name.clone())
        .collect()
}

pub(crate) fn prepare_auth_password(
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

pub(crate) fn prepare_auth_password_with_message(
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

pub(crate) fn apply_auth_record_create_defaults(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    verified: bool,
) {
    if collection.collection_type != CollectionType::Auth {
        return;
    }

    insert_auth_bool_default(collection, object, "verified", verified);
    insert_auth_bool_default(collection, object, "emailVisibility", false);
}

fn insert_auth_bool_default(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    field: &str,
    value: bool,
) {
    if object.contains_key(field) || !auth_collection_has_field(collection, field) {
        return;
    }

    object.insert(field.to_string(), JsonValue::Bool(value));
}

pub(crate) fn auth_collection_has_field(collection: &CollectionConfig, field: &str) -> bool {
    collection
        .fields
        .iter()
        .any(|candidate| candidate.name == field)
}

pub(crate) fn take_string_field(
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

pub(crate) fn required_form_string(
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

pub(crate) fn optional_form_u64(
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

pub(crate) fn validate_form_email(
    field: &str,
    value: &str,
    message: &str,
) -> Result<String, ServerError> {
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

pub(crate) fn is_plausible_email(value: &str) -> bool {
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

impl Store {
    pub fn auth_with_password(
        &self,
        collection_name: &str,
        identity: &str,
        password: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
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
            record: record_from_parts(collection_name, &collection_id, id, data, created, updated),
        })
    }
}
