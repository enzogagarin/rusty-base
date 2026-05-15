use super::profile::{oauth2_profile_from_user_info, oauth2_profile_value, OAuth2Profile};
use super::*;
use crate::server::http::percent_encode_query_component;

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
