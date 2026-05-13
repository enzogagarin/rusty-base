use super::*;
use super::{auth::*, collections::*, files::*, storage::*};

pub(crate) fn validation_error(
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

pub(crate) fn validate_collection(collection: &CollectionConfig) -> Result<(), ServerError> {
    validate_collection_name(&collection.name)?;
    if let Some(id) = collection.id.as_deref() {
        validate_collection_id(id)?;
    }
    if collection.collection_type == CollectionType::View {
        validate_view_query(&collection.view_query)?;
    }
    for index in &collection.indexes {
        validate_collection_index(index)?;
    }
    let mut seen = HashMap::new();
    let mut seen_ids = HashMap::new();

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
        if let Some(id) = field.id.as_deref() {
            validate_field_id(id)?;
            if seen_ids.insert(id.to_string(), ()).is_some() {
                return Err(ServerError::BadRequest(format!(
                    "duplicate field id '{id}'"
                )));
            }
        }
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
        if field.kind != CollectionFieldKind::Relation && field.min_select.is_some() {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares minSelect but is not a relation field",
                field.name
            )));
        }
        if field.kind != CollectionFieldKind::Relation && field.cascade_delete {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares cascadeDelete but is not a relation field",
                field.name
            )));
        }
        if field.kind == CollectionFieldKind::Relation {
            let max_select = field.max_select.unwrap_or(1).max(1);
            if field
                .min_select
                .is_some_and(|min_select| min_select > max_select)
            {
                return Err(ServerError::BadRequest(format!(
                    "field '{}' minSelect cannot be greater than maxSelect",
                    field.name
                )));
            }
        }
        if field.kind != CollectionFieldKind::File
            && (field.protected || !field.mime_types.is_empty() || !field.thumbs.is_empty())
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares file options but is not a file field",
                field.name
            )));
        }
        if !matches!(
            field.kind,
            CollectionFieldKind::File | CollectionFieldKind::Json | CollectionFieldKind::Editor
        ) && field.max_size.is_some()
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares maxSize but is not a file, json, or editor field",
                field.name
            )));
        }
        if !matches!(
            field.kind,
            CollectionFieldKind::Email | CollectionFieldKind::Url
        ) && (!field.only_domains.is_empty() || !field.except_domains.is_empty())
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares domain options but is not an email or url field",
                field.name
            )));
        }
        for domain in field.only_domains.iter().chain(&field.except_domains) {
            validate_domain_option(&field.name, domain)?;
        }
        if field.kind != CollectionFieldKind::AutoDate && (field.on_create || field.on_update) {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares autodate options but is not an autodate field",
                field.name
            )));
        }
        if field.kind == CollectionFieldKind::AutoDate && !field.on_create && !field.on_update {
            return Err(ServerError::BadRequest(format!(
                "field '{}' autodate must run on create or update",
                field.name
            )));
        }
        if field.kind != CollectionFieldKind::Select && !field.values.is_empty() {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares select values but is not a select field",
                field.name
            )));
        }
        if field.kind == CollectionFieldKind::Select {
            validate_select_field_settings(field)?;
        }
        let is_text_like = matches!(
            field.kind,
            CollectionFieldKind::Text | CollectionFieldKind::Email
        );
        if !matches!(
            field.kind,
            CollectionFieldKind::Text | CollectionFieldKind::Email | CollectionFieldKind::Number
        ) && (field.min.is_some() || field.max.is_some())
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares min/max options but is not a text-like or number field",
                field.name
            )));
        }
        if !is_text_like
            && (field.pattern.is_some()
                || field.autogenerate_pattern.is_some()
                || field.primary_key)
        {
            return Err(ServerError::BadRequest(format!(
                "field '{}' declares text options but is not a text-like field",
                field.name
            )));
        }
        if let (Some(min), Some(max)) = (field.min, field.max) {
            let invalid_range = if field.kind == CollectionFieldKind::Number {
                min > max
            } else {
                max > 0 && min > max
            };
            if invalid_range {
                return Err(ServerError::BadRequest(format!(
                    "field '{}' min cannot be greater than max",
                    field.name
                )));
            }
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

pub(crate) fn validate_select_field_settings(field: &CollectionField) -> Result<(), ServerError> {
    if field.values.is_empty() {
        return Err(ServerError::BadRequest(format!(
            "field '{}' select values must not be empty",
            field.name
        )));
    }

    let mut seen = HashSet::new();
    for value in &field.values {
        if value.trim().is_empty() {
            return Err(ServerError::BadRequest(format!(
                "field '{}' select values must not contain empty options",
                field.name
            )));
        }
        if !seen.insert(value) {
            return Err(ServerError::BadRequest(format!(
                "field '{}' select values must be unique",
                field.name
            )));
        }
    }

    Ok(())
}

pub(crate) fn validate_domain_option(field_name: &str, domain: &str) -> Result<(), ServerError> {
    let domain = domain.trim();
    if domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || domain.chars().any(char::is_whitespace)
    {
        return Err(ServerError::BadRequest(format!(
            "field '{field_name}' has invalid domain option '{domain}'"
        )));
    }

    Ok(())
}

pub(crate) fn validate_auth_options(collection: &CollectionConfig) -> Result<(), ServerError> {
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

pub(crate) fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

pub(crate) fn validate_collection_name(name: &str) -> Result<(), ServerError> {
    if is_safe_identifier_part(name) {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe collection name '{name}'"
        )))
    }
}

pub(crate) fn validate_collection_identifier(identifier: &str) -> Result<(), ServerError> {
    validate_collection_name(identifier).or_else(|_| validate_collection_id(identifier))
}

pub(crate) fn validate_collection_id(id: &str) -> Result<(), ServerError> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe collection id '{id}'"
        )))
    }
}

pub(crate) fn validate_collection_index(index: &str) -> Result<(), ServerError> {
    if !index.is_empty() && index.len() <= 2048 && !index.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(ServerError::BadRequest(
            "collection indexes must be non-empty strings without control characters".to_string(),
        ))
    }
}

pub(crate) fn validate_view_query(query: &str) -> Result<(), ServerError> {
    let query = query.trim();
    let lowered = query.to_ascii_lowercase();
    if !query.is_empty()
        && query.len() <= 8192
        && lowered.starts_with("select ")
        && !query.contains(';')
        && !query
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(
            "viewQuery must be a single SELECT query".to_string(),
        ))
    }
}

pub(crate) fn validate_field_id(id: &str) -> Result<(), ServerError> {
    if !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!("unsafe field id '{id}'")))
    }
}

pub(crate) fn validate_record_id(id: &str) -> Result<(), ServerError> {
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

pub(crate) fn validate_field_name(name: &str) -> Result<(), ServerError> {
    if is_safe_identifier_path(name) {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe field name '{name}'"
        )))
    }
}

pub(crate) fn validate_record_fields(
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

pub(crate) fn validate_record_field_options(
    collection: &CollectionConfig,
    object: &Map<String, JsonValue>,
) -> Result<(), ServerError> {
    for field in &collection.fields {
        let value = object.get(&field.name);
        if field.required && value.is_none_or(|value| is_empty_field_value(field, value)) {
            return Err(validation_error(
                "Failed to validate record.",
                &field.name,
                "validation_required",
                format!("Field '{}' is required.", field.name),
            ));
        }
        if relation_min_select(field) > 0
            && value.is_none_or(|value| is_empty_field_value(field, value))
        {
            return Err(min_relation_select_error(field));
        }

        let Some(value) = value else {
            continue;
        };
        if is_empty_field_value(field, value) {
            continue;
        }

        match field.kind {
            CollectionFieldKind::Text | CollectionFieldKind::Email => {
                validate_text_field_value(field, value)?;
            }
            CollectionFieldKind::Url => {
                validate_url_field_value(field, value)?;
            }
            CollectionFieldKind::Editor => {
                validate_editor_field_value(field, value)?;
            }
            CollectionFieldKind::Number => {
                validate_number_field_value(field, value)?;
            }
            CollectionFieldKind::Bool => {
                if !value.is_boolean() {
                    return Err(validation_error(
                        "Failed to validate record.",
                        &field.name,
                        "validation_invalid_bool",
                        format!("Field '{}' must be a boolean.", field.name),
                    ));
                }
            }
            CollectionFieldKind::DateTime => {
                validate_datetime_field_value(field, value)?;
            }
            CollectionFieldKind::AutoDate => {
                validate_datetime_field_value(field, value)?;
            }
            CollectionFieldKind::Array => {
                if !value.is_array() {
                    return Err(validation_error(
                        "Failed to validate record.",
                        &field.name,
                        "validation_invalid_array",
                        format!("Field '{}' must be an array.", field.name),
                    ));
                }
            }
            CollectionFieldKind::Relation => validate_relation_field_value(field, value)?,
            CollectionFieldKind::Select => validate_select_field_value(field, value)?,
            CollectionFieldKind::Json => validate_json_field_value(field, value)?,
            CollectionFieldKind::GeoPoint => validate_geo_point_field_value(field, value)?,
            CollectionFieldKind::File => {}
        }
    }

    Ok(())
}

pub(crate) fn apply_autodate_fields(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    is_create: bool,
    now: &str,
) {
    for field in &collection.fields {
        if field.kind != CollectionFieldKind::AutoDate {
            continue;
        }
        if (is_create && field.on_create) || (!is_create && field.on_update) {
            object.insert(field.name.clone(), JsonValue::String(now.to_string()));
        }
    }
}

pub(crate) fn validate_json_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let max_size = json_field_max_size(field);
    let size = serde_json::to_vec(value)?.len() as u64;
    if size > max_size {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_size",
            format!("Field '{}' must be at most {} bytes.", field.name, max_size),
        ));
    }

    Ok(())
}

pub(crate) fn json_field_max_size(field: &CollectionField) -> u64 {
    field
        .max_size
        .filter(|max_size| *max_size > 0)
        .unwrap_or(DEFAULT_JSON_MAX_SIZE_BYTES)
}

pub(crate) fn validate_geo_point_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(object) = value.as_object() else {
        return Err(invalid_geo_point_field_value(field));
    };
    let Some(lon) = object.get("lon").and_then(JsonValue::as_f64) else {
        return Err(invalid_geo_point_field_value(field));
    };
    let Some(lat) = object.get("lat").and_then(JsonValue::as_f64) else {
        return Err(invalid_geo_point_field_value(field));
    };

    if !(-180.0..=180.0).contains(&lon) || !(-90.0..=90.0).contains(&lat) {
        return Err(invalid_geo_point_field_value(field));
    }

    Ok(())
}

pub(crate) fn invalid_geo_point_field_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_geo_point",
        format!(
            "Field '{}' must be an object with numeric lon/lat coordinates.",
            field.name
        ),
    )
}

pub(crate) fn validate_datetime_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(datetime) = value.as_str() else {
        return Err(invalid_datetime_field_value(field));
    };
    if !is_pocketbase_datetime(datetime) {
        return Err(invalid_datetime_field_value(field));
    }

    Ok(())
}

pub(crate) fn invalid_datetime_field_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_datetime",
        format!(
            "Field '{}' must be a datetime string in YYYY-MM-DD HH:MM:SS.mmmZ format.",
            field.name
        ),
    )
}

pub(crate) fn is_pocketbase_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }

    let Some(year) = parse_fixed_digits(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = parse_fixed_digits(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = parse_fixed_digits(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = parse_fixed_digits(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = parse_fixed_digits(bytes, 14, 2) else {
        return false;
    };
    let Some(second) = parse_fixed_digits(bytes, 17, 2) else {
        return false;
    };
    if parse_fixed_digits(bytes, 20, 3).is_none() {
        return false;
    }

    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

pub(crate) fn parse_fixed_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let mut value = 0u32;
    for byte in bytes.get(start..start + len)? {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

pub(crate) fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[allow(clippy::manual_is_multiple_of)]
pub(crate) fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub(crate) fn validate_number_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(number) = value.as_f64() else {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_invalid_number",
            format!("Field '{}' must be a number.", field.name),
        ));
    };

    if field.min.is_some_and(|min| number < min as f64) {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_min_number_constraint",
            format!(
                "Field '{}' must be greater than or equal to {}.",
                field.name,
                field.min.unwrap_or_default()
            ),
        ));
    }
    if field.max.is_some_and(|max| number > max as f64) {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_number_constraint",
            format!(
                "Field '{}' must be less than or equal to {}.",
                field.name,
                field.max.unwrap_or_default()
            ),
        ));
    }

    Ok(())
}

pub(crate) fn validate_select_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let max_select = field.max_select.unwrap_or(1).max(1);
    if max_select <= 1 {
        let Some(option) = value.as_str() else {
            return Err(invalid_select_field_value(field));
        };
        if !field.values.iter().any(|value| value == option) {
            return Err(invalid_select_field_value(field));
        }
        return Ok(());
    }

    let JsonValue::Array(options) = value else {
        return Err(invalid_select_field_value(field));
    };
    if options.len() as u64 > max_select {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_select",
            format!(
                "Field '{}' accepts at most {} selected value(s).",
                field.name, max_select
            ),
        ));
    }

    for option in options {
        let Some(option) = option.as_str() else {
            return Err(invalid_select_field_value(field));
        };
        if !field.values.iter().any(|value| value == option) {
            return Err(invalid_select_field_value(field));
        }
    }

    Ok(())
}

pub(crate) fn invalid_select_field_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_select",
        format!(
            "Field '{}' must be one of the configured select values.",
            field.name
        ),
    )
}

pub(crate) fn validate_text_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(text) = value.as_str() else {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_invalid_string",
            format!("Field '{}' must be a string.", field.name),
        ));
    };

    if field
        .min
        .is_some_and(|min| text.chars().count() < min as usize)
    {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_min_text_constraint",
            format!(
                "Field '{}' must be at least {} characters.",
                field.name,
                field.min.unwrap_or_default()
            ),
        ));
    }
    if field
        .max
        .is_some_and(|max| max > 0 && text.chars().count() > max as usize)
    {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_text_constraint",
            format!(
                "Field '{}' must be at most {} characters.",
                field.name,
                field.max.unwrap_or_default()
            ),
        ));
    }
    if field
        .pattern
        .as_deref()
        .filter(|pattern| !pattern.is_empty())
        .is_some_and(|pattern| !text_matches_pattern(text, pattern))
    {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_pattern_constraint",
            format!(
                "Field '{}' does not match the required pattern.",
                field.name
            ),
        ));
    }
    if field.kind == CollectionFieldKind::Email && !is_plausible_email(text) {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_is_email",
            "Must be a valid email address.",
        ));
    }
    if field.kind == CollectionFieldKind::Email {
        let domain = text
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or_default();
        validate_domain_constraints(field, domain)?;
    }

    Ok(())
}

pub(crate) fn validate_url_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(url) = value.as_str() else {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_invalid_string",
            format!("Field '{}' must be a string.", field.name),
        ));
    };
    if !is_plausible_url(url) {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_is_url",
            "Must be a valid URL.",
        ));
    }
    let Some(host) = url_host(url) else {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_is_url",
            "Must be a valid URL.",
        ));
    };
    validate_domain_constraints(field, &host)
}

pub(crate) fn validate_editor_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(text) = value.as_str() else {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_invalid_string",
            format!("Field '{}' must be a string.", field.name),
        ));
    };

    let max_size = editor_field_max_size(field);
    if text.len() as u64 > max_size {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_size",
            format!("Field '{}' must be at most {} bytes.", field.name, max_size),
        ));
    }

    Ok(())
}

pub(crate) fn editor_field_max_size(field: &CollectionField) -> u64 {
    field
        .max_size
        .filter(|max_size| *max_size > 0)
        .unwrap_or(DEFAULT_EDITOR_MAX_SIZE_BYTES)
}

pub(crate) fn validate_domain_constraints(
    field: &CollectionField,
    domain: &str,
) -> Result<(), ServerError> {
    if !field.only_domains.is_empty()
        && !field
            .only_domains
            .iter()
            .any(|allowed| domain_matches(domain, allowed))
    {
        return Err(domain_constraint_error(field));
    }
    if field
        .except_domains
        .iter()
        .any(|blocked| domain_matches(domain, blocked))
    {
        return Err(domain_constraint_error(field));
    }

    Ok(())
}

pub(crate) fn domain_constraint_error(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_domain_constraint",
        format!("Field '{}' is not allowed for this domain.", field.name),
    )
}

pub(crate) fn domain_matches(domain: &str, configured: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let configured = configured.trim().trim_end_matches('.').to_ascii_lowercase();
    domain == configured || domain.ends_with(&format!(".{configured}"))
}

pub(crate) fn is_plausible_url(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !is_url_scheme(scheme) || rest.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }

    url_host(value).is_some()
}

pub(crate) fn is_url_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

pub(crate) fn url_host(value: &str) -> Option<String> {
    let (_, rest) = value.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_port.starts_with('[') {
        let (host, _) = host_port.split_once(']')?;
        return Some(host.trim_start_matches('[').to_ascii_lowercase());
    }

    let host = if let Some((host, port)) = host_port.rsplit_once(':') {
        if port.is_empty() || !port.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        host
    } else {
        host_port
    }
    .trim_end_matches('.');
    if host.is_empty() {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

pub(crate) fn validate_relation_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    relation_field_ids(field, value)?;
    Ok(())
}

pub(crate) fn relation_field_ids<'a>(
    field: &CollectionField,
    value: &'a JsonValue,
) -> Result<Vec<&'a str>, ServerError> {
    let max_select = field.max_select.unwrap_or(1).max(1);
    let min_select = relation_min_select(field);
    let ids = match value {
        JsonValue::String(id) => vec![id.as_str()],
        JsonValue::Array(values) => {
            if values.len() as u64 > max_select {
                return Err(validation_error(
                    "Failed to validate record.",
                    &field.name,
                    "validation_max_select",
                    format!(
                        "Field '{}' accepts at most {} relation(s).",
                        field.name, max_select
                    ),
                ));
            }

            let mut ids = Vec::with_capacity(values.len());
            for value in values {
                let Some(id) = value.as_str() else {
                    return Err(invalid_relation_field_value(field));
                };
                ids.push(id);
            }
            ids
        }
        _ => return Err(invalid_relation_field_value(field)),
    };

    if ids.len() as u64 > max_select {
        return Err(validation_error(
            "Failed to validate record.",
            &field.name,
            "validation_max_select",
            format!(
                "Field '{}' accepts at most {} relation(s).",
                field.name, max_select
            ),
        ));
    }
    if (ids.len() as u64) < min_select {
        return Err(min_relation_select_error(field));
    }

    for id in &ids {
        if validate_record_id(id).is_err() {
            return Err(invalid_relation_field_value(field));
        }
    }

    Ok(ids)
}

pub(crate) fn relation_value_contains(value: &JsonValue, id: &str) -> bool {
    match value {
        JsonValue::String(value) => value == id,
        JsonValue::Array(values) => values
            .iter()
            .any(|value| value.as_str().is_some_and(|value| value == id)),
        _ => false,
    }
}

pub(crate) fn relation_min_select(field: &CollectionField) -> u64 {
    field.min_select.unwrap_or(0)
}

pub(crate) fn min_relation_select_error(field: &CollectionField) -> ServerError {
    let min_select = relation_min_select(field);
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_min_select",
        format!(
            "Field '{}' requires at least {} relation(s).",
            field.name, min_select
        ),
    )
}

pub(crate) fn invalid_relation_field_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_relation",
        format!(
            "Field '{}' must be a relation id or relation id array.",
            field.name
        ),
    )
}

pub(crate) fn invalid_relation_target_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_relation",
        format!("Field '{}' references a missing record.", field.name),
    )
}

pub(crate) fn is_empty_field_value(field: &CollectionField, value: &JsonValue) -> bool {
    if field.kind == CollectionFieldKind::Json {
        return match value {
            JsonValue::Null => true,
            JsonValue::String(value) => value.is_empty(),
            JsonValue::Array(values) => values.is_empty(),
            JsonValue::Object(values) => values.is_empty(),
            _ => false,
        };
    }

    is_empty_record_value(value)
}

pub(crate) fn is_empty_record_value(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => true,
        JsonValue::String(value) => value.is_empty(),
        JsonValue::Array(values) => values.is_empty(),
        _ => false,
    }
}

pub(crate) fn text_matches_pattern(value: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    if let Some(inner) = pattern
        .strip_prefix("^[")
        .and_then(|rest| rest.split_once(']'))
    {
        let (class, suffix) = inner;
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !ascii_class_matches(class, first) {
            return false;
        }

        return match suffix {
            ".+" | ".+$" => chars.next().is_some(),
            ".*" | ".*$" => true,
            "+" | "+$" => value.chars().all(|ch| ascii_class_matches(class, ch)),
            "*" | "*$" => value.chars().all(|ch| ascii_class_matches(class, ch)),
            "$" | "" => value.chars().count() == 1,
            _ => false,
        };
    }

    let anchored_start = pattern.strip_prefix('^');
    let anchored = anchored_start.unwrap_or(pattern);
    let anchored_end = anchored.strip_suffix('$');
    let literal = anchored_end.unwrap_or(anchored);
    if literal_contains_regex_meta(literal) {
        return false;
    }

    match (anchored_start.is_some(), anchored_end.is_some()) {
        (true, true) => value == literal,
        (true, false) => value.starts_with(literal),
        (false, true) => value.ends_with(literal),
        (false, false) => value.contains(literal),
    }
}

pub(crate) fn ascii_class_matches(class: &str, ch: char) -> bool {
    if !ch.is_ascii() {
        return false;
    }
    let chars = class.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if index + 2 < chars.len() && chars[index + 1] == '-' {
            if chars[index] <= ch && ch <= chars[index + 2] {
                return true;
            }
            index += 3;
        } else {
            if chars[index] == ch {
                return true;
            }
            index += 1;
        }
    }

    false
}

pub(crate) fn literal_contains_regex_meta(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '[' | ']' | '(' | ')' | '{' | '}' | '+' | '*' | '?' | '|' | '\\' | '.'
        )
    })
}
