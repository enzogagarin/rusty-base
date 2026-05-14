use super::*;

pub(crate) fn field_options_from_query(
    query: &HashMap<String, String>,
) -> Result<Vec<String>, ServerError> {
    let Some(fields) = query.get("fields") else {
        return Ok(Vec::new());
    };

    let mut projections = Vec::new();
    for path in fields
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_field_projection_path(path)?;
        if !projections.iter().any(|existing| existing == path) {
            projections.push(path.to_string());
        }
    }

    Ok(projections)
}

pub(crate) fn validate_field_projection_path(path: &str) -> Result<(), ServerError> {
    if path
        .split('.')
        .any(|part| part != "*" && !is_safe_identifier_part(part))
    {
        return Err(ServerError::BadRequest(format!(
            "invalid fields path '{path}'"
        )));
    }

    Ok(())
}

pub(crate) fn project_record_responses(
    records: &mut [JsonValue],
    fields: &[String],
) -> Result<(), ServerError> {
    for record in records {
        project_record_response(record, fields)?;
    }

    Ok(())
}

pub(crate) fn project_record_response(
    record: &mut JsonValue,
    fields: &[String],
) -> Result<(), ServerError> {
    project_json_response(record, fields)
}

pub(crate) fn project_json_response(
    value: &mut JsonValue,
    fields: &[String],
) -> Result<(), ServerError> {
    if fields.is_empty() {
        return Ok(());
    }

    let source = value.clone();
    let mut projected = Map::new();
    let expand_projection_parents = expand_projection_parents(fields);

    for field in fields {
        let parts = field.split('.').collect::<Vec<_>>();
        project_field_path(
            &source,
            &mut projected,
            &parts,
            &[],
            &expand_projection_parents,
        );
    }

    *value = JsonValue::Object(projected);
    Ok(())
}

pub(crate) fn expand_projection_parents(fields: &[String]) -> HashSet<Vec<String>> {
    let mut parents = HashSet::new();
    for field in fields {
        let mut parent = Vec::new();
        for part in field.split('.') {
            if part == "expand" {
                parents.insert(parent.clone());
            }
            parent.push(part.to_string());
        }
    }

    parents
}

pub(crate) fn project_field_path(
    source: &JsonValue,
    target: &mut Map<String, JsonValue>,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) {
    let Some((head, tail)) = parts.split_first() else {
        return;
    };
    let Some(source_object) = source.as_object() else {
        return;
    };

    if *head == "*" {
        for (key, value) in source_object {
            if key == "expand" && expand_projection_parents.contains(current_path) {
                continue;
            }

            let child_path = child_projection_path(current_path, key);
            let projected = if tail.is_empty() {
                Some(copy_wildcard_value(
                    value,
                    &child_path,
                    expand_projection_parents,
                ))
            } else {
                project_value_path(value, tail, &child_path, expand_projection_parents)
            };
            if let Some(projected) = projected {
                merge_projected_value(target, key, projected);
            }
        }
        return;
    }

    let Some(value) = source_object.get(*head) else {
        return;
    };
    let child_path = child_projection_path(current_path, head);
    let projected = if tail.is_empty() {
        Some(value.clone())
    } else {
        project_value_path(value, tail, &child_path, expand_projection_parents)
    };
    if let Some(projected) = projected {
        merge_projected_value(target, head, projected);
    }
}

pub(crate) fn project_value_path(
    source: &JsonValue,
    parts: &[&str],
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> Option<JsonValue> {
    if parts.is_empty() {
        return Some(source.clone());
    }

    if source.is_object() {
        let mut projected = Map::new();
        project_field_path(
            source,
            &mut projected,
            parts,
            current_path,
            expand_projection_parents,
        );
        return (!projected.is_empty()).then_some(JsonValue::Object(projected));
    }

    if let Some(array) = source.as_array() {
        return Some(JsonValue::Array(
            array
                .iter()
                .filter_map(|value| {
                    project_value_path(value, parts, current_path, expand_projection_parents)
                })
                .collect(),
        ));
    }

    None
}

pub(crate) fn copy_wildcard_value(
    source: &JsonValue,
    current_path: &[String],
    expand_projection_parents: &HashSet<Vec<String>>,
) -> JsonValue {
    match source {
        JsonValue::Object(object) => {
            let mut copied = Map::new();
            for (key, value) in object {
                if key == "expand" && expand_projection_parents.contains(current_path) {
                    continue;
                }

                copied.insert(
                    key.clone(),
                    copy_wildcard_value(
                        value,
                        &child_projection_path(current_path, key),
                        expand_projection_parents,
                    ),
                );
            }
            JsonValue::Object(copied)
        }
        JsonValue::Array(array) => JsonValue::Array(
            array
                .iter()
                .map(|value| copy_wildcard_value(value, current_path, expand_projection_parents))
                .collect(),
        ),
        _ => source.clone(),
    }
}

pub(crate) fn child_projection_path(current_path: &[String], child: &str) -> Vec<String> {
    let mut path = current_path.to_vec();
    path.push(child.to_string());
    path
}

pub(crate) fn merge_projected_value(
    target: &mut Map<String, JsonValue>,
    key: &str,
    value: JsonValue,
) {
    if let Some(existing) = target.get_mut(key) {
        merge_json(existing, value);
    } else {
        target.insert(key.to_string(), value);
    }
}

pub(crate) fn merge_json(existing: &mut JsonValue, incoming: JsonValue) {
    match (existing, incoming) {
        (JsonValue::Object(existing), JsonValue::Object(incoming)) => {
            for (key, value) in incoming {
                merge_projected_value(existing, &key, value);
            }
        }
        (JsonValue::Array(existing), JsonValue::Array(incoming)) => {
            for (index, value) in incoming.into_iter().enumerate() {
                if let Some(existing) = existing.get_mut(index) {
                    merge_json(existing, value);
                } else {
                    existing.push(value);
                }
            }
        }
        (existing, incoming) => {
            *existing = incoming;
        }
    }
}
