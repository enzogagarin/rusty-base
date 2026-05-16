use super::*;
use crate::server::{collections::*, mail::*, storage::*};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthMailTemplate {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub html: String,
}

pub(crate) fn default_auth_mail_template(kind: AuthActionKind) -> AuthMailTemplate {
    match kind {
        AuthActionKind::Verification => AuthMailTemplate {
            subject: "Verify your {APP_NAME} email".to_string(),
            body: "Use this token to verify your email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n".to_string(),
            html: String::new(),
        },
        AuthActionKind::PasswordReset => AuthMailTemplate {
            subject: "Reset your {APP_NAME} password".to_string(),
            body: "Use this token to reset your password.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n".to_string(),
            html: String::new(),
        },
        AuthActionKind::EmailChange => AuthMailTemplate {
            subject: "Confirm your {APP_NAME} email change".to_string(),
            body: "Use this token to confirm your new email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n".to_string(),
            html: String::new(),
        },
        AuthActionKind::Otp => AuthMailTemplate {
            subject: "Your {APP_NAME} one-time password".to_string(),
            body: "Use this one-time password to sign in.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n".to_string(),
            html: String::new(),
        },
    }
}

pub(crate) fn auth_mail_template_for_kind(
    collection: &CollectionConfig,
    kind: AuthActionKind,
) -> AuthMailTemplate {
    match kind {
        AuthActionKind::Verification => collection.verification_template.clone(),
        AuthActionKind::PasswordReset => collection.password_reset_template.clone(),
        AuthActionKind::EmailChange => collection.email_change_template.clone(),
        AuthActionKind::Otp => collection.otp_template.clone(),
    }
    .unwrap_or_else(|| default_auth_mail_template(kind))
}

impl Store {
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
        let token_data = json!({ "newEmail": new_email });
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
                token_data.to_string(),
                created,
                expires
            ],
        )?;
        self.queue_auth_action_mail_tx(
            &conn,
            AuthActionMail {
                kind: AuthActionKind::EmailChange,
                collection_name: collection.name.clone(),
                record_id,
                recipient: new_email,
                token,
                data: token_data,
                template: auth_mail_template_for_kind(&collection, AuthActionKind::EmailChange),
            },
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
}

impl Store {
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
        let token_data = json!({ "email": email });
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
                token_data.to_string(),
                created,
                expires
            ],
        )?;
        self.queue_auth_action_mail_tx(
            &conn,
            AuthActionMail {
                kind,
                collection_name: collection.name.clone(),
                record_id,
                recipient: email.to_string(),
                token: token.clone(),
                data: token_data,
                template: auth_mail_template_for_kind(&collection, kind),
            },
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
}
