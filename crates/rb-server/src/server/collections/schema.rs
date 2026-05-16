use super::*;

pub(crate) fn collection_row_to_value(
    name: String,
    schema_json: String,
    created: String,
    updated: String,
) -> Result<JsonValue, ServerError> {
    let collection = serde_json::from_str::<CollectionConfig>(&schema_json)?;
    let id = collection_id_value(&collection).unwrap_or_else(|| name.clone());
    let mut value = json!(collection);
    let object = value.as_object_mut().ok_or_else(|| {
        ServerError::BadRequest("collection response must be a JSON object".to_string())
    })?;
    let index_warnings = collection_index_warnings(&collection)?;
    if !index_warnings.is_empty() {
        object.insert(
            "indexWarnings".to_string(),
            JsonValue::Array(index_warnings),
        );
    }
    object.insert("id".to_string(), JsonValue::String(id));
    object.insert("name".to_string(), JsonValue::String(name.clone()));
    object.insert("created".to_string(), JsonValue::String(created));
    object.insert("updated".to_string(), JsonValue::String(updated));
    object.insert("system".to_string(), JsonValue::Bool(name.starts_with('_')));
    decorate_collection_response_fields(object);
    Ok(value)
}

pub(crate) fn decorate_collection_response_fields(object: &mut Map<String, JsonValue>) {
    let mut fields = object
        .remove("fields")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|field| !is_response_only_collection_field_value(field))
        .collect::<Vec<_>>();

    let mut decorated = Vec::with_capacity(fields.len() + 3);
    decorated.push(scaffold_id_field());
    decorated.append(&mut fields);
    decorated.push(scaffold_created_field());
    decorated.push(scaffold_updated_field());
    object.insert("fields".to_string(), JsonValue::Array(decorated));
}

pub(crate) fn is_response_only_collection_field_value(field: &JsonValue) -> bool {
    serde_json::from_value::<CollectionField>(field.clone())
        .is_ok_and(|field| is_response_only_collection_field(&field))
}

pub(crate) fn is_response_only_collection_field(field: &CollectionField) -> bool {
    match field.name.as_str() {
        "id" => {
            field.id.as_deref() == Some("text3208210256")
                && field.kind == CollectionFieldKind::Text
                && field.required
                && field.system
                && !field.hidden
                && !field.presentable
                && field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.min == Some(15)
                && field.max == Some(15)
                && field.pattern.as_deref() == Some("^[a-z0-9]+$")
                && field.autogenerate_pattern.as_deref() == Some("[a-z0-9]{15}")
        }
        "created" => {
            field.id.as_deref() == Some("autodate2990389176")
                && field.kind == CollectionFieldKind::AutoDate
                && !field.required
                && !field.system
                && !field.hidden
                && !field.presentable
                && !field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.on_create
                && !field.on_update
        }
        "updated" => {
            field.id.as_deref() == Some("autodate3332085495")
                && field.kind == CollectionFieldKind::AutoDate
                && !field.required
                && !field.system
                && !field.hidden
                && !field.presentable
                && !field.primary_key
                && !field.protected
                && !field.cascade_delete
                && field.on_create
                && field.on_update
        }
        _ => false,
    }
}

pub(crate) fn apply_collection_patch(collection: &mut CollectionConfig, patch: CollectionPatch) {
    if let Some(name) = patch.name {
        collection.name = name;
    }
    if let Some(collection_type) = patch.collection_type {
        collection.collection_type = collection_type;
    }
    if let Some(mut fields) = patch.fields {
        preserve_collection_field_ids(&collection.fields, &mut fields);
        collection.fields = fields;
    }
    if let Some(indexes) = patch.indexes {
        collection.indexes = indexes;
    }
    if let Some(view_query) = patch.view_query {
        collection.view_query = view_query;
    }
    if let Some(rule) = patch.list_rule {
        collection.list_rule = rule;
    }
    if let Some(rule) = patch.view_rule {
        collection.view_rule = rule;
    }
    if let Some(rule) = patch.create_rule {
        collection.create_rule = rule;
    }
    if let Some(rule) = patch.update_rule {
        collection.update_rule = rule;
    }
    if let Some(rule) = patch.delete_rule {
        collection.delete_rule = rule;
    }
    if let Some(rule) = patch.auth_rule {
        collection.auth_rule = rule;
    }
    if let Some(rule) = patch.manage_rule {
        collection.manage_rule = rule;
    }
    if let Some(password_auth) = patch.password_auth {
        collection.password_auth = Some(password_auth);
    }
    if let Some(auth_token) = patch.auth_token {
        collection.auth_token = Some(auth_token);
    }
    if let Some(password_reset_token) = patch.password_reset_token {
        collection.password_reset_token = Some(password_reset_token);
    }
    if let Some(email_change_token) = patch.email_change_token {
        collection.email_change_token = Some(email_change_token);
    }
    if let Some(verification_token) = patch.verification_token {
        collection.verification_token = Some(verification_token);
    }
    if let Some(file_token) = patch.file_token {
        collection.file_token = Some(file_token);
    }
    if let Some(template) = patch.verification_template {
        collection.verification_template = Some(template);
    }
    if let Some(template) = patch.password_reset_template {
        collection.password_reset_template = Some(template);
    }
    if let Some(template) = patch.email_change_template {
        collection.email_change_template = Some(template);
    }
    if let Some(template) = patch.otp_template {
        collection.otp_template = Some(template);
    }
    if let Some(oauth2) = patch.oauth2 {
        collection.oauth2 = Some(oauth2);
    }
    if let Some(mfa) = patch.mfa {
        collection.mfa = Some(mfa);
    }
    if let Some(otp) = patch.otp {
        collection.otp = Some(otp);
    }
}

pub(crate) fn normalize_collection(collection: &mut CollectionConfig) {
    collection
        .fields
        .retain(|field| !is_response_only_collection_field(field));
    normalize_collection_id(collection);
    normalize_collection_indexes(&mut collection.indexes);
    collection.view_query = collection.view_query.trim().to_string();
    normalize_collection_fields(&mut collection.fields);

    if collection.collection_type != CollectionType::View {
        collection.view_query.clear();
    }

    if collection.collection_type != CollectionType::Auth {
        collection.auth_rule = None;
        collection.manage_rule = None;
        collection.password_auth = None;
        collection.auth_token = None;
        collection.password_reset_token = None;
        collection.email_change_token = None;
        collection.verification_token = None;
        collection.file_token = None;
        collection.verification_template = None;
        collection.password_reset_template = None;
        collection.email_change_template = None;
        collection.otp_template = None;
        collection.oauth2 = None;
        collection.mfa = None;
        collection.otp = None;
        return;
    }

    let default_identity_fields = default_auth_identity_fields(collection);
    let password_auth = collection
        .password_auth
        .get_or_insert_with(Default::default);
    if password_auth.identity_fields.is_empty() {
        password_auth.identity_fields = default_identity_fields.clone();
    }
    dedupe_strings(&mut password_auth.identity_fields);

    collection.auth_rule.get_or_insert_with(String::new);
    collection
        .auth_token
        .get_or_insert_with(|| TokenDurationConfig::seconds((AUTH_TOKEN_TTL_MILLIS / 1000) as u64));
    collection.password_reset_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((PASSWORD_RESET_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection.email_change_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((EMAIL_CHANGE_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection.verification_token.get_or_insert_with(|| {
        TokenDurationConfig::seconds((VERIFICATION_TOKEN_TTL_MILLIS / 1000) as u64)
    });
    collection
        .file_token
        .get_or_insert_with(|| TokenDurationConfig::seconds((FILE_TOKEN_TTL_MILLIS / 1000) as u64));
    collection
        .verification_template
        .get_or_insert_with(|| default_auth_mail_template(AuthActionKind::Verification));
    collection
        .password_reset_template
        .get_or_insert_with(|| default_auth_mail_template(AuthActionKind::PasswordReset));
    collection
        .email_change_template
        .get_or_insert_with(|| default_auth_mail_template(AuthActionKind::EmailChange));
    collection
        .otp_template
        .get_or_insert_with(|| default_auth_mail_template(AuthActionKind::Otp));
    collection.oauth2.get_or_insert_with(Default::default);
    collection.mfa.get_or_insert_with(Default::default);

    let otp_missing = collection.otp.is_none();
    let otp = collection.otp.get_or_insert_with(Default::default);
    if otp.duration == 0 {
        otp.duration = (OTP_TOKEN_TTL_MILLIS / 1000) as u64;
    }
    if otp.length == 0 {
        otp.length = 8;
    }
    if otp_missing && !otp.enabled {
        otp.enabled = default_identity_fields.iter().any(|field| field == "email");
    }
}

pub(crate) fn normalize_collection_fields(fields: &mut [CollectionField]) {
    for field in fields {
        field.id = field
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .or_else(|| Some(generate_field_id(field.kind)));

        if matches!(
            field.kind,
            CollectionFieldKind::Text | CollectionFieldKind::Email
        ) {
            field.min.get_or_insert(0);
            field.max.get_or_insert(0);
            field.pattern.get_or_insert_with(String::new);
            field.autogenerate_pattern.get_or_insert_with(String::new);
        }
    }
}

pub(crate) fn preserve_collection_field_ids(
    current: &[CollectionField],
    incoming: &mut [CollectionField],
) {
    for field in incoming {
        if field
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .is_some()
        {
            continue;
        }

        if let Some(existing) = current.iter().find(|existing| existing.name == field.name) {
            field.id = existing.id.clone();
        }
    }
}

pub(crate) fn normalize_collection_id(collection: &mut CollectionConfig) {
    collection.id = collection
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| Some(generate_collection_id()));
}

pub(crate) fn normalize_collection_indexes(indexes: &mut Vec<String>) {
    for index in indexes.iter_mut() {
        *index = index.trim().to_string();
    }
    indexes.retain(|index| !index.is_empty());
    dedupe_strings(indexes);
}

pub(crate) fn collection_scaffolds() -> JsonValue {
    json!({
        "base": scaffold_collection("base", base_scaffold_fields(), json!({})),
        "auth": scaffold_collection(
            "auth",
            auth_scaffold_fields(vec![
                scaffold_id_field(),
                json!({
                    "id": "password901924565",
                    "name": "password",
                    "type": "password",
                    "required": true,
                    "system": true,
                    "hidden": true,
                    "min": 8,
                    "max": 0,
                    "pattern": "",
                    "cost": 0
                }),
                json!({
                    "id": "text2504183744",
                    "name": "tokenKey",
                    "type": "text",
                    "required": true,
                    "system": true,
                    "hidden": true,
                    "primaryKey": false,
                    "min": 30,
                    "max": 60,
                    "pattern": "",
                    "autogeneratePattern": "[a-zA-Z0-9]{50}",
                    "presentable": false
                }),
                json!({
                    "id": "email3885137012",
                    "name": "email",
                    "type": "email",
                    "required": true,
                    "system": true,
                    "hidden": false,
                    "onlyDomains": null,
                    "exceptDomains": null,
                    "presentable": false
                }),
                scaffold_bool_field("bool1547992806", "emailVisibility", true),
                scaffold_bool_field("bool256245529", "verified", true)
            ]),
            json!({
                "authRule": "",
                "manageRule": null,
                "passwordAuth": {
                    "enabled": true,
                    "identityFields": ["email"]
                },
                "authToken": { "duration": 604800 },
                "passwordResetToken": { "duration": 1800 },
                "emailChangeToken": { "duration": 1800 },
                "verificationToken": { "duration": 259200 },
                "fileToken": { "duration": 180 },
                "verificationTemplate": {
                    "subject": "Verify your {APP_NAME} email",
                    "body": "Use this token to verify your email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n",
                    "html": ""
                },
                "passwordResetTemplate": {
                    "subject": "Reset your {APP_NAME} password",
                    "body": "Use this token to reset your password.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n",
                    "html": ""
                },
                "emailChangeTemplate": {
                    "subject": "Confirm your {APP_NAME} email change",
                    "body": "Use this token to confirm your new email address.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n",
                    "html": ""
                },
                "otpTemplate": {
                    "subject": "Your {APP_NAME} one-time password",
                    "body": "Use this one-time password to sign in.\n\nEndpoint: {ACTION_URL}\nToken: {TOKEN}\n",
                    "html": ""
                },
                "oauth2": {
                    "enabled": false,
                    "mappedFields": {
                        "id": "",
                        "name": "",
                        "username": "",
                        "avatarURL": ""
                    },
                    "providers": []
                },
                "mfa": {
                    "enabled": false,
                    "duration": 1800,
                    "rule": ""
                },
                "otp": {
                    "enabled": true,
                    "duration": 180,
                    "length": 8
                }
            })
        ),
        "view": scaffold_collection("view", Vec::new(), json!({ "viewQuery": "" }))
    })
}

pub(crate) fn base_scaffold_fields() -> Vec<JsonValue> {
    vec![
        scaffold_id_field(),
        scaffold_created_field(),
        scaffold_updated_field(),
    ]
}

pub(crate) fn auth_scaffold_fields(mut fields: Vec<JsonValue>) -> Vec<JsonValue> {
    fields.push(scaffold_created_field());
    fields.push(scaffold_updated_field());
    fields
}

pub(crate) fn scaffold_collection(
    collection_type: &str,
    fields: Vec<JsonValue>,
    extra: JsonValue,
) -> JsonValue {
    let mut collection = Map::new();
    collection.insert("id".to_string(), JsonValue::String(String::new()));
    collection.insert("name".to_string(), JsonValue::String(String::new()));
    collection.insert(
        "type".to_string(),
        JsonValue::String(collection_type.to_string()),
    );
    collection.insert("fields".to_string(), JsonValue::Array(fields));
    collection.insert("indexes".to_string(), JsonValue::Array(Vec::new()));
    collection.insert("listRule".to_string(), JsonValue::Null);
    collection.insert("viewRule".to_string(), JsonValue::Null);
    collection.insert("createRule".to_string(), JsonValue::Null);
    collection.insert("updateRule".to_string(), JsonValue::Null);
    collection.insert("deleteRule".to_string(), JsonValue::Null);
    collection.insert("created".to_string(), JsonValue::String(String::new()));
    collection.insert("updated".to_string(), JsonValue::String(String::new()));
    collection.insert("system".to_string(), JsonValue::Bool(false));

    if let JsonValue::Object(extra) = extra {
        collection.extend(extra);
    }

    JsonValue::Object(collection)
}

pub(crate) fn scaffold_id_field() -> JsonValue {
    json!({
        "id": "text3208210256",
        "name": "id",
        "type": "text",
        "required": true,
        "system": true,
        "hidden": false,
        "primaryKey": true,
        "min": 15,
        "max": 15,
        "pattern": "^[a-z0-9]+$",
        "autogeneratePattern": "[a-z0-9]{15}",
        "presentable": false
    })
}

pub(crate) fn scaffold_created_field() -> JsonValue {
    scaffold_autodate_field("autodate2990389176", "created", true, false)
}

pub(crate) fn scaffold_updated_field() -> JsonValue {
    scaffold_autodate_field("autodate3332085495", "updated", true, true)
}

pub(crate) fn scaffold_autodate_field(
    id: &str,
    name: &str,
    on_create: bool,
    on_update: bool,
) -> JsonValue {
    json!({
        "id": id,
        "name": name,
        "type": "autodate",
        "required": false,
        "system": false,
        "hidden": false,
        "presentable": false,
        "onCreate": on_create,
        "onUpdate": on_update
    })
}

pub(crate) fn scaffold_bool_field(id: &str, name: &str, system: bool) -> JsonValue {
    json!({
        "id": id,
        "name": name,
        "type": "bool",
        "required": false,
        "system": system,
        "hidden": false,
        "presentable": false
    })
}
