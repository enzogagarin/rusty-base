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
    if hidden_fields.is_empty() {
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

    Ok(())
}
