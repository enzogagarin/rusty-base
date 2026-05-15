use super::provider::OAuth2TokenResponse;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OAuth2Profile {
    pub(crate) provider_id: String,
    pub(crate) name: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) raw_user: JsonValue,
    pub(crate) access_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) expiry: Option<String>,
}

pub(crate) fn oauth2_profile_from_user_info(
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

pub(crate) fn oauth2_profile_value(
    value: &JsonValue,
    mapped_path: &str,
    defaults: &[&str],
) -> Option<String> {
    let mapped_path = mapped_path.trim();
    if !mapped_path.is_empty() {
        return json_scalar_at_path(value, mapped_path);
    }

    defaults
        .iter()
        .find_map(|path| json_scalar_at_path(value, path))
}

pub(crate) fn json_scalar_at_path(value: &JsonValue, path: &str) -> Option<String> {
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

pub(crate) fn oauth2_profile_from_code(code: &str) -> Result<Option<OAuth2Profile>, ServerError> {
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

pub(crate) fn optional_json_string(object: &Map<String, JsonValue>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn oauth2_meta_payload(
    provider: &str,
    profile: &OAuth2Profile,
    is_new: bool,
) -> JsonValue {
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
