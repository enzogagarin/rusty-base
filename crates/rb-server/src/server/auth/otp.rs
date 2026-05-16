use super::*;
use crate::server::mail::AuthActionMail;
use crate::server::{collections::*, records::*, storage::*};

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthWithOtpRequest {
    pub(crate) otp_id: String,
    pub(crate) password: String,
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

impl Store {
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
        let token_data = json!({
            "email": email.clone(),
            "otpId": otp_id.clone(),
            "password": password.clone()
        });
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
                token_data.to_string(),
                created,
                expires
            ],
        )?;
        self.queue_auth_action_mail_tx(
            &conn,
            AuthActionMail {
                kind: AuthActionKind::Otp,
                collection_name: collection.name.clone(),
                record_id,
                recipient: email.to_string(),
                token: password,
                data: token_data,
                template: auth_mail_template_for_kind(&collection, AuthActionKind::Otp),
            },
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
}
