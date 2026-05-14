use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordValueMutationKind {
    Append,
    Prepend,
    Delete,
}

pub(crate) fn prepare_record_value_modifiers(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    existing: Option<&JsonValue>,
) -> Result<(), ServerError> {
    let mut mutations: HashMap<String, RecordValueMutation> = HashMap::new();
    let keys = object.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        let Some((field_name, kind)) = parse_record_value_mutation_key(collection, &key) else {
            continue;
        };
        let value = object.remove(&key).unwrap_or(JsonValue::Null);
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            RecordValueMutationKind::Append => mutation.append_values.push((key, value)),
            RecordValueMutationKind::Prepend => mutation.prepend_values.push((key, value)),
            RecordValueMutationKind::Delete => mutation.delete_values.push((key, value)),
        }
    }

    for (field_name, mutation) in mutations {
        let field = collection_field(collection, &field_name).ok_or_else(|| {
            validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_unknown_field",
                format!("Unknown field for collection '{}'.", collection.name),
            )
        })?;
        let existing_value = existing
            .and_then(JsonValue::as_object)
            .and_then(|object| object.get(&field_name));
        let base_value = object.get(&field_name).or(existing_value);
        let final_value = match field.kind {
            CollectionFieldKind::Number => {
                apply_number_value_modifier(field, base_value, &mutation)?
            }
            CollectionFieldKind::Select | CollectionFieldKind::Relation => {
                apply_string_list_value_modifier(field, base_value, &mutation)?
            }
            _ => continue,
        };
        object.insert(field_name, final_value);
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RecordValueMutation {
    pub(crate) append_values: Vec<(String, JsonValue)>,
    pub(crate) prepend_values: Vec<(String, JsonValue)>,
    pub(crate) delete_values: Vec<(String, JsonValue)>,
}

pub(crate) fn apply_number_value_modifier(
    field: &CollectionField,
    base_value: Option<&JsonValue>,
    mutation: &RecordValueMutation,
) -> Result<JsonValue, ServerError> {
    if !mutation.prepend_values.is_empty() {
        return Err(invalid_record_value_modifier(
            field,
            &mutation.prepend_values[0].0,
            "Number fields do not support prepend modifiers.",
        ));
    }

    let mut number = match base_value {
        Some(value) if !is_empty_record_value(value) => value.as_f64().ok_or_else(|| {
            invalid_record_value_modifier(
                field,
                &field.name,
                "Number modifiers require an existing numeric value.",
            )
        })?,
        _ => 0.0,
    };

    for (key, value) in &mutation.append_values {
        number += modifier_number(field, key, value)?;
    }
    for (key, value) in &mutation.delete_values {
        number -= modifier_number(field, key, value)?;
    }

    let Some(number) = serde_json::Number::from_f64(number) else {
        return Err(invalid_record_value_modifier(
            field,
            &field.name,
            "Number modifier result must be finite.",
        ));
    };
    Ok(JsonValue::Number(number))
}

pub(crate) fn apply_string_list_value_modifier(
    field: &CollectionField,
    base_value: Option<&JsonValue>,
    mutation: &RecordValueMutation,
) -> Result<JsonValue, ServerError> {
    let max_select = field.max_select.unwrap_or(1).max(1);
    let mut values = match base_value {
        Some(value) if !is_empty_record_value(value) => {
            modifier_string_values(field, &field.name, value)?
        }
        _ => Vec::new(),
    };

    if !mutation.delete_values.is_empty() {
        let mut delete_values = Vec::new();
        for (key, value) in &mutation.delete_values {
            delete_values.extend(modifier_string_values(field, key, value)?);
        }
        let delete_values = delete_values.into_iter().collect::<HashSet<_>>();
        values.retain(|value| !delete_values.contains(value));
    }

    if !mutation.prepend_values.is_empty() {
        let mut prepended = Vec::new();
        for (key, value) in &mutation.prepend_values {
            prepended.extend(modifier_string_values(field, key, value)?);
        }
        prepended.extend(values);
        values = prepended;
    }

    for (key, value) in &mutation.append_values {
        values.extend(modifier_string_values(field, key, value)?);
    }

    dedupe_strings(&mut values);
    Ok(string_list_field_value(&values, max_select))
}

pub(crate) fn modifier_number(
    field: &CollectionField,
    key: &str,
    value: &JsonValue,
) -> Result<f64, ServerError> {
    value.as_f64().ok_or_else(|| {
        invalid_record_value_modifier(field, key, "Number modifiers require numeric values.")
    })
}

pub(crate) fn modifier_string_values(
    field: &CollectionField,
    key: &str,
    value: &JsonValue,
) -> Result<Vec<String>, ServerError> {
    match value {
        JsonValue::String(value) if value.trim().is_empty() => Ok(Vec::new()),
        JsonValue::String(value) => Ok(vec![value.clone()]),
        JsonValue::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    invalid_record_value_modifier(
                        field,
                        key,
                        "Select and relation modifiers require string values.",
                    )
                })
            })
            .filter(|result| {
                result
                    .as_ref()
                    .map_or(true, |value| !value.trim().is_empty())
            })
            .collect(),
        JsonValue::Null => Ok(Vec::new()),
        _ => Err(invalid_record_value_modifier(
            field,
            key,
            "Select and relation modifiers require a string or string array.",
        )),
    }
}

pub(crate) fn invalid_record_value_modifier(
    field: &CollectionField,
    key: &str,
    message: impl Into<String>,
) -> ServerError {
    validation_error(
        "Failed to validate record.",
        key,
        "validation_invalid_modifier",
        format!("Field '{}': {}", field.name, message.into()),
    )
}

pub(crate) fn parse_record_value_mutation_key(
    collection: &CollectionConfig,
    key: &str,
) -> Option<(String, RecordValueMutationKind)> {
    if let Some(field) = key.strip_prefix('+').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Prepend)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Prepend));
    }
    if let Some(field) = key.strip_suffix('+').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Append)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Append));
    }
    if let Some(field) = key.strip_suffix('-').and_then(|name| {
        record_value_modifier_field(collection, name, RecordValueMutationKind::Delete)
    }) {
        return Some((field.name.clone(), RecordValueMutationKind::Delete));
    }
    None
}

pub(crate) fn record_value_modifier_field<'a>(
    collection: &'a CollectionConfig,
    name: &str,
    kind: RecordValueMutationKind,
) -> Option<&'a CollectionField> {
    collection_field(collection, name).filter(|field| match (field.kind, kind) {
        (
            CollectionFieldKind::Number,
            RecordValueMutationKind::Append | RecordValueMutationKind::Delete,
        ) => true,
        (
            CollectionFieldKind::Select | CollectionFieldKind::Relation,
            RecordValueMutationKind::Append
            | RecordValueMutationKind::Prepend
            | RecordValueMutationKind::Delete,
        ) => field.max_select.unwrap_or(1) > 1,
        _ => false,
    })
}

pub(crate) fn collection_field<'a>(
    collection: &'a CollectionConfig,
    name: &str,
) -> Option<&'a CollectionField> {
    collection.fields.iter().find(|field| field.name == name)
}

pub(crate) fn string_list_field_value(values: &[String], max_select: u64) -> JsonValue {
    if max_select <= 1 {
        JsonValue::String(values.first().cloned().unwrap_or_default())
    } else {
        JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect())
    }
}
