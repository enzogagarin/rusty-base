use super::*;
use super::{http::*, validation::*};

mod action_tokens;
mod impersonation;
mod oauth;
mod otp;
mod password;
mod superusers;
mod tokens;

pub use action_tokens::AuthMailTemplate;
pub use oauth::{OAuth2Config, OAuth2MappedFields, OAuth2ProviderConfig};
pub use otp::{MfaConfig, OtpConfig};
pub use password::AuthPasswordConfig;
pub use tokens::{AuthResponse, TokenDurationConfig};

pub(crate) use action_tokens::*;
pub(crate) use impersonation::*;
pub(crate) use oauth::*;
pub(crate) use otp::*;
pub(crate) use password::*;
pub(crate) use tokens::*;

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
