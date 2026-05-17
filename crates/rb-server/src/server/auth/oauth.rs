use super::*;
use crate::server::{collections::*, records::*, storage::Store};

mod accounts;
mod profile;
mod provider;

pub(crate) use profile::*;
pub(crate) use provider::*;

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuthWithOAuth2Request {
    pub(crate) provider: String,
    pub(crate) code: String,
    pub(crate) code_verifier: String,
    pub(crate) redirect_url: String,
    pub(crate) create_data: JsonValue,
}

impl AuthWithOAuth2Request {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
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

pub(crate) fn oauth2_auth_response_payload(
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
    let collection = store.get_collection(collection_name)?;
    sanitize_record_response(&collection, &mut response.record, &context)?;

    let mut payload = json!(response);
    if let Some(object) = payload.as_object_mut() {
        object.insert("meta".to_string(), meta);
    }
    project_json_response(&mut payload, fields)?;
    Ok(payload)
}

pub(crate) fn auth_methods_payload(
    collection: &CollectionConfig,
) -> Result<JsonValue, ServerError> {
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
