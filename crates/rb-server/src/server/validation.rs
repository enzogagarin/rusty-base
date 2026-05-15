use super::auth::is_plausible_email;
use super::collections::*;
use super::storage::is_system_record_key;
use super::*;

mod collection;
mod datetime;
mod pattern;
mod view;

pub(crate) use collection::*;
pub(crate) use datetime::*;
pub(crate) use pattern::*;
pub(crate) use view::*;

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
