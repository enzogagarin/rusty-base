use super::*;
use crate::server::{collections::*, records::*, storage::*};

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

impl Store {
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
}
