use super::*;

pub(crate) fn sanitize_record_responses(
    collection: &CollectionConfig,
    records: &mut [JsonValue],
    context: &FilterContext,
) -> Result<(), ServerError> {
    for record in records {
        sanitize_record_response(collection, record, context)?;
    }
    Ok(())
}

pub(crate) fn sanitize_record_response(
    collection: &CollectionConfig,
    record: &mut JsonValue,
    context: &FilterContext,
) -> Result<(), ServerError> {
    if is_superuser_context(context) {
        return Ok(());
    }

    let hidden_fields = collection
        .fields
        .iter()
        .filter(|field| field.hidden)
        .map(|field| field.name.clone())
        .collect::<Vec<_>>();
    let hide_auth_email = should_hide_auth_record_email(collection, record, context);
    if hidden_fields.is_empty() && !hide_auth_email {
        return Ok(());
    }

    let object = record.as_object_mut().ok_or_else(|| {
        ServerError::BadRequest("record response must be a JSON object".to_string())
    })?;
    for field in hidden_fields {
        object.remove(&field);
        if let Some(expand) = object.get_mut("expand").and_then(JsonValue::as_object_mut) {
            expand.remove(&field);
        }
    }
    if hide_auth_email {
        object.remove("email");
    }

    Ok(())
}

pub(crate) fn should_hide_auth_record_email(
    collection: &CollectionConfig,
    record: &JsonValue,
    context: &FilterContext,
) -> bool {
    if collection.collection_type != CollectionType::Auth
        || !collection_field_exists(collection, "email")
        || !collection_field_exists(collection, "emailVisibility")
    {
        return false;
    }

    let Some(object) = record.as_object() else {
        return false;
    };
    if !object.contains_key("email") {
        return false;
    }
    if object
        .get("emailVisibility")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
    {
        return false;
    }

    !request_auth_matches_record(collection, object, context)
}

pub(crate) fn request_auth_matches_record(
    collection: &CollectionConfig,
    record: &Map<String, JsonValue>,
    context: &FilterContext,
) -> bool {
    let Some(record_id) = record.get("id").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(FilterValue::String(auth_id)) = context.request.auth.get("id") else {
        return false;
    };
    if auth_id != record_id {
        return false;
    }

    matches!(
        context.request.auth.get("collectionName"),
        Some(FilterValue::String(collection_name)) if collection_name == &collection.name
    )
}

fn collection_field_exists(collection: &CollectionConfig, name: &str) -> bool {
    collection.fields.iter().any(|field| field.name == name)
}
