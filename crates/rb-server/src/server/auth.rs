use super::*;
use super::{
    collections::*, files::*, http::*, records::*, settings::*, storage::*, validation::*,
};

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
    pub(crate) fn seconds(duration: u64) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires: String,
    pub record: JsonValue,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct AuthWithPasswordRequest {
    pub(crate) identity: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthWithOtpRequest {
    pub(crate) otp_id: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuthWithOAuth2Request {
    pub(crate) provider: String,
    pub(crate) code: String,
    pub(crate) code_verifier: String,
    pub(crate) redirect_url: String,
    pub(crate) create_data: JsonValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImpersonateRequest {
    pub(crate) duration: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchRequestBody {
    pub(crate) requests: Vec<BatchRequestInput>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchRequestInput {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: JsonValue,
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

impl AuthWithOtpRequest {
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
            otp_id: required_form_string(object, "otpId", "Failed to authenticate.")?,
            password: required_form_string(object, "password", "Failed to authenticate.")?,
        })
    }
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

impl ImpersonateRequest {
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
            duration: optional_form_u64(object, "duration", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl BatchRequestBody {
    pub(crate) fn from_json(value: JsonValue, max_requests: usize) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Something went wrong while processing your request.",
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;
        let Some(requests) = object.get("requests").and_then(JsonValue::as_array) else {
            return Err(validation_error(
                "Something went wrong while processing your request.",
                "requests",
                "validation_required",
                "Field 'requests' is required.",
            ));
        };
        if requests.len() > max_requests {
            return Err(validation_error(
                "Something went wrong while processing your request.",
                "requests",
                "validation_max_items",
                format!("Batch requests cannot contain more than {max_requests} items."),
            ));
        }

        Ok(Self {
            requests: requests
                .iter()
                .cloned()
                .map(BatchRequestInput::from_json)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl BatchRequestInput {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Something went wrong while processing your request.",
                "requests",
                "validation_invalid_body",
                "Batch request must be a JSON object.",
            )
        })?;

        let method = required_form_string(
            object,
            "method",
            "Something went wrong while processing your request.",
        )?
        .to_ascii_uppercase();
        let url = required_form_string(
            object,
            "url",
            "Something went wrong while processing your request.",
        )?;
        let headers = batch_request_headers(object.get("headers"))?;
        let body = object.get("body").cloned().unwrap_or(JsonValue::Null);

        Ok(Self {
            method,
            url,
            headers,
            body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthEmailRequest {
    pub(crate) email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthNewEmailRequest {
    pub(crate) new_email: String,
}

impl AuthNewEmailRequest {
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
            new_email: required_form_string(object, "newEmail", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl AuthEmailRequest {
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
            email: required_form_string(object, "email", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthTokenRequest {
    pub(crate) token: String,
}

impl AuthTokenRequest {
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
            token: required_form_string(object, "token", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmPasswordResetRequest {
    pub(crate) token: String,
    pub(crate) password: String,
    pub(crate) password_confirm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmEmailChangeRequest {
    pub(crate) token: String,
    pub(crate) password: String,
}

impl ConfirmEmailChangeRequest {
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
            token: required_form_string(object, "token", AUTH_FORM_VALIDATION_MESSAGE)?,
            password: required_form_string(object, "password", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl ConfirmPasswordResetRequest {
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
pub(crate) enum AuthActionKind {
    Verification,
    PasswordReset,
    EmailChange,
    Otp,
}

impl AuthActionKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Verification => "verification",
            Self::PasswordReset => "passwordReset",
            Self::EmailChange => "emailChange",
            Self::Otp => "otp",
        }
    }
}

pub(crate) fn auth_response_payload(
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

pub(crate) fn auth_otp_config(collection: &CollectionConfig) -> OtpConfig {
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

pub(crate) fn auth_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.auth_token, AUTH_TOKEN_TTL_MILLIS)
}

pub(crate) fn file_token_ttl_millis(collection: &CollectionConfig) -> u128 {
    duration_config_millis(collection.file_token, FILE_TOKEN_TTL_MILLIS)
}

pub(crate) fn auth_action_ttl_millis(collection: &CollectionConfig, kind: AuthActionKind) -> u128 {
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

pub(crate) fn duration_config_millis(
    config: Option<TokenDurationConfig>,
    default_millis: u128,
) -> u128 {
    config
        .map(|config| u128::from(config.duration) * 1000)
        .filter(|duration| *duration > 0)
        .unwrap_or(default_millis)
}

pub(crate) fn oauth2_auth_method_provider(provider: &OAuth2ProviderConfig) -> JsonValue {
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

pub(crate) fn generate_oauth2_state() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn generate_oauth2_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn oauth2_code_challenge(code_verifier: &str) -> String {
    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

pub(crate) fn oauth2_auth_url(
    provider: &OAuth2ProviderConfig,
    state: &str,
    code_challenge: &str,
) -> String {
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

pub(crate) fn oauth2_authorize_url(provider: &OAuth2ProviderConfig) -> Option<String> {
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

pub(crate) fn oauth2_provider_scopes(provider: &OAuth2ProviderConfig) -> Vec<String> {
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

pub(crate) fn append_query_params(base_url: &str, params: &[(&str, String)]) -> String {
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

pub(crate) fn ensure_oauth2_provider_configured(
    collection: &CollectionConfig,
    provider: &str,
) -> Result<(), ServerError> {
    oauth2_provider_configured(collection, provider).map(|_| ())
}

pub(crate) fn oauth2_provider_configured<'a>(
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
pub(crate) struct OAuth2ExchangeEndpoints {
    pub(crate) token_url: String,
    pub(crate) user_info_url: String,
    pub(crate) email_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OAuth2TokenResponse {
    #[serde(default)]
    pub(crate) access_token: String,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
    #[serde(default)]
    pub(crate) expires_in: Option<i64>,
}

pub(crate) fn exchange_oauth2_code(
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

pub(crate) fn oauth2_exchange_endpoints(
    provider: &OAuth2ProviderConfig,
) -> Option<OAuth2ExchangeEndpoints> {
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

pub(crate) fn oauth2_provider_key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

pub(crate) fn oauth2_provider_request_error(label: &str, err: reqwest::Error) -> ServerError {
    ServerError::BadRequest(format!("OAuth2 provider {label} request failed: {err}"))
}

pub(crate) fn oauth2_provider_json_response(
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

pub(crate) fn oauth2_primary_email(
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

pub(crate) fn insert_oauth2_auth_record_tx(
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
    object.remove("collectionId");
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

pub(crate) fn insert_profile_field(
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

pub(crate) fn collection_has_field(collection: &CollectionConfig, field: &str) -> bool {
    collection
        .fields
        .iter()
        .any(|candidate| candidate.name == field)
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

pub(crate) fn upsert_external_auth_account(
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

pub(crate) fn bearer_token(request: &HttpRequest) -> Option<&str> {
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

pub(crate) fn context_with_auth_record_values(
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

pub(crate) fn invalid_credentials() -> ServerError {
    ServerError::BadRequest("Failed to authenticate.".to_string())
}

pub(crate) fn ensure_auth_token_columns(conn: &Connection) -> Result<(), ServerError> {
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

pub(crate) fn insert_auth_token(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    ttl_millis: u128,
) -> Result<(String, String), ServerError> {
    insert_auth_token_with_renewable(conn, collection_name, record_id, ttl_millis, true)
}

pub(crate) fn insert_auth_token_with_renewable(
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

pub(crate) fn auth_action_subject(
    conn: &Connection,
    collection_name: &str,
    kind: AuthActionKind,
    token: &str,
) -> Result<String, ServerError> {
    let (record_id, _) = auth_action_subject_data(conn, collection_name, kind, token)?;
    Ok(record_id)
}

pub(crate) fn auth_action_subject_data(
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

pub(crate) fn delete_auth_action_tokens(
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

pub(crate) fn validate_auth_action_kind(kind: &str) -> Result<(), ServerError> {
    match kind {
        "verification" | "passwordReset" | "emailChange" | "otp" => Ok(()),
        _ => Err(ServerError::BadRequest(format!(
            "unknown auth action token kind '{kind}'"
        ))),
    }
}

pub(crate) fn invalid_auth_action_token(kind: AuthActionKind) -> ServerError {
    ServerError::BadRequest(format!("invalid or expired {} token", kind.as_str()))
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

    pub fn auth_refresh(
        &self,
        collection_name: &str,
        token: &str,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
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
                collection_name,
                &collection_id,
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
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
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
                &collection_id,
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
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
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
            record: record_from_parts(collection_name, &collection_id, id, data, created, updated),
        })
    }

    pub(crate) fn auth_with_oauth2_profile(
        &self,
        collection_name: &str,
        provider: &str,
        profile: OAuth2Profile,
        create_data: &JsonValue,
    ) -> Result<(AuthResponse, JsonValue), ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
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
                record: record_from_parts(
                    collection_name,
                    &collection_id,
                    id,
                    data,
                    created,
                    updated,
                ),
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
            ORDER BY created DESC
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
                ORDER BY created DESC
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

    pub(crate) fn request_auth_action_token(
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

    pub(crate) fn ensure_auth_email_available_tx(
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

    pub(crate) fn auth_collection(
        &self,
        collection_name: &str,
    ) -> Result<CollectionConfig, ServerError> {
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

    pub fn expire_token(&self, token: &str) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute(
            r#"UPDATE "_rb_auth_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", token],
        )?;
        Ok(())
    }

    pub(crate) fn valid_token_subject(&self, token: &str) -> Result<(String, String), ServerError> {
        let (collection_name, record_id, _) = self.valid_auth_token_subject(token)?;
        Ok((collection_name, record_id))
    }

    pub(crate) fn valid_auth_token_subject(
        &self,
        token: &str,
    ) -> Result<(String, String, bool), ServerError> {
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

    pub(crate) fn valid_subject_token(
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
}
