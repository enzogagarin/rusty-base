use super::super::{
    auth::auth_password_config,
    collections::{CollectionConfig, CollectionField, CollectionFieldKind, CollectionType},
    files::parse_thumb_spec,
    storage::{is_safe_identifier_part, is_safe_identifier_path, is_system_record_key},
    ServerError, SUPERUSERS_COLLECTION,
};
use super::view::validate_view_query;
use std::collections::{HashMap, HashSet};

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
