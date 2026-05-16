use super::*;
use super::{auth::*, settings::*, storage::*, validation::*};

pub(crate) struct AuthActionMail {
    pub(crate) kind: AuthActionKind,
    pub(crate) collection_name: String,
    pub(crate) record_id: String,
    pub(crate) recipient: String,
    pub(crate) token: String,
    pub(crate) data: JsonValue,
}

impl Store {
    pub(crate) fn queue_auth_action_mail_tx(
        &self,
        conn: &Connection,
        message: AuthActionMail,
    ) -> Result<(), ServerError> {
        let settings = app_settings_from_conn(conn)?;
        let meta = settings.meta;
        let app_name = if meta.app_name.trim().is_empty() {
            default_app_name()
        } else {
            meta.app_name.trim().to_string()
        };
        let action_path = auth_action_path(&message.collection_name, message.kind);
        let action_url = action_url(meta.app_url.trim(), &action_path);
        let subject = auth_action_subject_line(&app_name, message.kind);
        let sender_name = meta.sender_name.trim().to_string();
        let sender_address = meta.sender_address.trim().to_string();
        let created = now_timestamp();
        let id = generate_id();

        let mut data = data_object(&message.data)?.clone();
        data.insert("appName".to_string(), JsonValue::String(app_name.clone()));
        data.insert(
            "collectionName".to_string(),
            JsonValue::String(message.collection_name.clone()),
        );
        data.insert(
            "recordId".to_string(),
            JsonValue::String(message.record_id.clone()),
        );
        data.insert(
            "recipient".to_string(),
            JsonValue::String(message.recipient.clone()),
        );
        data.insert(
            "token".to_string(),
            JsonValue::String(message.token.clone()),
        );
        data.insert(
            "actionPath".to_string(),
            JsonValue::String(action_path.clone()),
        );
        data.insert(
            "actionUrl".to_string(),
            JsonValue::String(action_url.clone()),
        );

        let text = auth_action_text_body(&app_name, message.kind, &action_url, &message.token);
        let html = auth_action_html_body(&app_name, message.kind, &action_url, &message.token);
        conn.execute(
            r#"
            INSERT INTO "_rb_mail_outbox"
                (id, kind, collection_name, record_id, recipient, sender_name, sender_address, subject, text, html, data, created)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                id,
                message.kind.as_str(),
                message.collection_name,
                message.record_id,
                message.recipient,
                sender_name,
                sender_address,
                subject,
                text,
                html,
                JsonValue::Object(data).to_string(),
                created
            ],
        )?;
        Ok(())
    }

    pub fn list_mail_outbox(&self) -> Result<JsonValue, ServerError> {
        let conn = self.connection()?;
        let total_items =
            conn.query_row(r#"SELECT COUNT(*) FROM "_rb_mail_outbox""#, [], |row| {
                row.get::<_, u64>(0)
            })?;
        let mut statement = conn.prepare(
            r#"
            SELECT id, kind, collection_name, record_id, recipient, sender_name, sender_address,
                   subject, text, html, data, created
            FROM "_rb_mail_outbox"
            ORDER BY created DESC, id DESC
            "#,
        )?;
        let items = statement
            .query_map([], mail_outbox_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "page": 1,
            "perPage": items.len(),
            "totalItems": total_items,
            "totalPages": if total_items == 0 { 0 } else { 1 },
            "items": items
        }))
    }

    pub fn clear_mail_outbox(&self) -> Result<(), ServerError> {
        let conn = self.connection()?;
        conn.execute(r#"DELETE FROM "_rb_mail_outbox""#, [])?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn latest_mail_outbox(
        &self,
        collection_name: &str,
        record_id: &str,
        kind: &str,
    ) -> Result<Option<JsonValue>, ServerError> {
        validate_collection_name(collection_name)?;
        validate_record_id(record_id)?;
        validate_auth_action_kind(kind)?;

        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT id, kind, collection_name, record_id, recipient, sender_name, sender_address,
                   subject, text, html, data, created
            FROM "_rb_mail_outbox"
            WHERE collection_name = ?1 AND record_id = ?2 AND kind = ?3
            ORDER BY created DESC, id DESC
            LIMIT 1
            "#,
            params![collection_name, record_id, kind],
            mail_outbox_row,
        )
        .optional()
        .map_err(ServerError::Storage)
    }
}

fn mail_outbox_row(row: &rusqlite::Row<'_>) -> Result<JsonValue, rusqlite::Error> {
    let data = row.get::<_, String>(10)?;
    let data = serde_json::from_str::<JsonValue>(&data).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(err))
    })?;
    Ok(json!({
        "id": row.get::<_, String>(0)?,
        "kind": row.get::<_, String>(1)?,
        "collectionName": row.get::<_, String>(2)?,
        "recordId": row.get::<_, String>(3)?,
        "recipient": row.get::<_, String>(4)?,
        "senderName": row.get::<_, String>(5)?,
        "senderAddress": row.get::<_, String>(6)?,
        "subject": row.get::<_, String>(7)?,
        "text": row.get::<_, String>(8)?,
        "html": row.get::<_, String>(9)?,
        "data": data,
        "created": row.get::<_, String>(11)?
    }))
}

fn auth_action_path(collection_name: &str, kind: AuthActionKind) -> String {
    let action = match kind {
        AuthActionKind::Verification => "confirm-verification",
        AuthActionKind::PasswordReset => "confirm-password-reset",
        AuthActionKind::EmailChange => "confirm-email-change",
        AuthActionKind::Otp => "auth-with-otp",
    };
    format!("/api/collections/{collection_name}/{action}")
}

fn action_url(app_url: &str, path: &str) -> String {
    if app_url.is_empty() {
        return path.to_string();
    }
    format!("{}{}", app_url.trim_end_matches('/'), path)
}

fn auth_action_subject_line(app_name: &str, kind: AuthActionKind) -> String {
    match kind {
        AuthActionKind::Verification => format!("Verify your {app_name} email"),
        AuthActionKind::PasswordReset => format!("Reset your {app_name} password"),
        AuthActionKind::EmailChange => format!("Confirm your {app_name} email change"),
        AuthActionKind::Otp => format!("Your {app_name} one-time password"),
    }
}

fn auth_action_text_body(
    app_name: &str,
    kind: AuthActionKind,
    action_url: &str,
    token: &str,
) -> String {
    let lead = match kind {
        AuthActionKind::Verification => "Use this token to verify your email address.",
        AuthActionKind::PasswordReset => "Use this token to reset your password.",
        AuthActionKind::EmailChange => "Use this token to confirm your new email address.",
        AuthActionKind::Otp => "Use this one-time password to sign in.",
    };
    format!("{app_name}\n\n{lead}\n\nEndpoint: {action_url}\nToken: {token}\n")
}

fn auth_action_html_body(
    app_name: &str,
    kind: AuthActionKind,
    action_url: &str,
    token: &str,
) -> String {
    let lead = match kind {
        AuthActionKind::Verification => "Use this token to verify your email address.",
        AuthActionKind::PasswordReset => "Use this token to reset your password.",
        AuthActionKind::EmailChange => "Use this token to confirm your new email address.",
        AuthActionKind::Otp => "Use this one-time password to sign in.",
    };
    format!(
        "<p><strong>{}</strong></p><p>{}</p><p>Endpoint: <code>{}</code></p><p>Token: <code>{}</code></p>",
        html_escape(app_name),
        html_escape(lead),
        html_escape(action_url),
        html_escape(token)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
