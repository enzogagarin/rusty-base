use super::*;
use super::{auth::*, settings::*, storage::*, validation::*};
use std::net::ToSocketAddrs;

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
        let meta = settings.meta.clone();
        let smtp = settings.smtp.clone();
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
        if smtp.enabled {
            send_smtp_mail(
                &smtp,
                &sender_name,
                &sender_address,
                &message.recipient,
                &subject,
                &text,
                &html,
            )?;
        }
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

fn send_smtp_mail(
    smtp: &SmtpSettings,
    sender_name: &str,
    sender_address: &str,
    recipient: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Result<(), ServerError> {
    if smtp.tls {
        return Err(ServerError::BadRequest(
            "SMTP TLS delivery is not implemented yet; use a local non-TLS relay or disable SMTP."
                .to_string(),
        ));
    }

    let sender_address = smtp_sender_address(smtp, sender_address)?;
    let recipient = recipient.trim();
    if recipient.is_empty() {
        return Err(ServerError::BadRequest(
            "SMTP recipient address is required.".to_string(),
        ));
    }

    let address = format!("{}:{}", smtp.host.trim(), smtp.port);
    let mut addresses = address
        .to_socket_addrs()
        .map_err(|err| ServerError::BadRequest(format!("SMTP address failed: {err}")))?;
    let address = addresses
        .next()
        .ok_or_else(|| ServerError::BadRequest("SMTP address did not resolve.".to_string()))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    smtp_expect(&mut reader, &[220])?;
    let local_name = if smtp.local_name.trim().is_empty() {
        "localhost"
    } else {
        smtp.local_name.trim()
    };
    smtp_command(
        &mut stream,
        &mut reader,
        &format!("EHLO {local_name}"),
        &[250],
    )?;
    smtp_auth(smtp, &mut stream, &mut reader)?;
    smtp_command(
        &mut stream,
        &mut reader,
        &format!("MAIL FROM:<{}>", smtp_path_address(&sender_address)),
        &[250],
    )?;
    smtp_command(
        &mut stream,
        &mut reader,
        &format!("RCPT TO:<{}>", smtp_path_address(recipient)),
        &[250, 251],
    )?;
    smtp_command(&mut stream, &mut reader, "DATA", &[354])?;
    let raw = smtp_message(sender_name, &sender_address, recipient, subject, text, html);
    stream.write_all(smtp_dot_stuffed(&raw).as_bytes())?;
    stream.write_all(b"\r\n.\r\n")?;
    smtp_expect(&mut reader, &[250])?;
    smtp_command(&mut stream, &mut reader, "QUIT", &[221]).ok();
    Ok(())
}

fn smtp_auth(
    smtp: &SmtpSettings,
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
) -> Result<(), ServerError> {
    if smtp.username.trim().is_empty() && smtp.password.is_empty() {
        return Ok(());
    }
    let method = smtp.auth_method.trim().to_ascii_lowercase();
    if method == "login" {
        smtp_command(stream, reader, "AUTH LOGIN", &[334])?;
        smtp_command(
            stream,
            reader,
            &base64::engine::general_purpose::STANDARD.encode(smtp.username.trim()),
            &[334],
        )?;
        smtp_command(
            stream,
            reader,
            &base64::engine::general_purpose::STANDARD.encode(smtp.password.as_str()),
            &[235],
        )?;
        return Ok(());
    }

    let payload = format!("\0{}\0{}", smtp.username.trim(), smtp.password);
    smtp_command(
        stream,
        reader,
        &format!(
            "AUTH PLAIN {}",
            base64::engine::general_purpose::STANDARD.encode(payload)
        ),
        &[235],
    )?;
    Ok(())
}

fn smtp_sender_address(
    smtp: &SmtpSettings,
    configured_sender: &str,
) -> Result<String, ServerError> {
    let sender = configured_sender.trim();
    if !sender.is_empty() {
        return Ok(sender.to_string());
    }
    let username = smtp.username.trim();
    if !username.is_empty() && username.contains('@') {
        return Ok(username.to_string());
    }
    Err(ServerError::BadRequest(
        "SMTP sender address is required.".to_string(),
    ))
}

fn smtp_command(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    command: &str,
    expected: &[u16],
) -> Result<String, ServerError> {
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\r\n")?;
    smtp_expect(reader, expected)
}

fn smtp_expect(reader: &mut BufReader<TcpStream>, expected: &[u16]) -> Result<String, ServerError> {
    let mut response = String::new();
    let code = loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Err(ServerError::BadRequest(
                "SMTP server closed the connection.".to_string(),
            ));
        }
        let line_code = line
            .get(0..3)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| ServerError::BadRequest(format!("Invalid SMTP response: {line}")))?;
        let more = line.as_bytes().get(3).is_some_and(|value| *value == b'-');
        response.push_str(&line);
        if !more {
            break line_code;
        }
    };
    if !expected.contains(&code) {
        return Err(ServerError::BadRequest(format!(
            "SMTP delivery failed with response: {}",
            response.trim()
        )));
    }
    Ok(response)
}

fn smtp_message(
    sender_name: &str,
    sender_address: &str,
    recipient: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> String {
    let boundary = format!("rb-{}", generate_id());
    format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n--{}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n--{}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{}\r\n--{}--\r\n",
        smtp_from_header(sender_name, sender_address),
        smtp_header_value(recipient),
        smtp_header_value(subject),
        boundary,
        boundary,
        text,
        boundary,
        html,
        boundary
    )
}

fn smtp_dot_stuffed(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .split('\n')
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn smtp_from_header(sender_name: &str, sender_address: &str) -> String {
    let sender_name = smtp_header_value(sender_name);
    let sender_address = smtp_header_value(sender_address);
    if sender_name.is_empty() {
        sender_address
    } else {
        format!(
            "\"{}\" <{}>",
            sender_name.replace('"', "\\\""),
            sender_address
        )
    }
}

fn smtp_header_value(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn smtp_path_address(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .replace(['\r', '\n'], "")
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
