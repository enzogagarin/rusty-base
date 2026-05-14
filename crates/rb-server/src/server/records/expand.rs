use super::*;

pub(crate) fn expand_options_from_query(
    query: &HashMap<String, String>,
) -> Result<Vec<String>, ServerError> {
    let Some(expand) = query.get("expand") else {
        return Ok(Vec::new());
    };

    let mut expands = Vec::new();
    for path in expand
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        validate_expand_path(path)?;
        if !expands.iter().any(|existing| existing == path) {
            expands.push(path.to_string());
        }
    }

    Ok(expands)
}

pub(crate) fn validate_expand_path(path: &str) -> Result<(), ServerError> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.len() > 6 {
        return Err(ServerError::BadRequest(format!(
            "expand path '{path}' exceeds the 6-level limit"
        )));
    }
    if parts.iter().any(|part| !is_safe_identifier_part(part)) {
        return Err(ServerError::BadRequest(format!(
            "invalid expand path '{path}'"
        )));
    }

    Ok(())
}

pub(crate) fn group_expand_paths(expands: &[String]) -> HashMap<String, Vec<String>> {
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for expand in expands {
        let (field, nested) = expand.split_once('.').unwrap_or((expand, ""));
        let nested_expands = grouped.entry(field.to_string()).or_default();
        if !nested.is_empty() && !nested_expands.iter().any(|existing| existing == nested) {
            nested_expands.push(nested.to_string());
        }
    }

    grouped
}

impl Store {
    pub fn expand_record_response(
        &self,
        collection_name: &str,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let collection = self.get_collection(collection_name)?;
        self.expand_record_with_collection(&collection, record, expands, context)
    }

    pub(crate) fn expand_records(
        &self,
        collection: &CollectionConfig,
        records: &mut [JsonValue],
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        for record in records {
            self.expand_record_with_collection(collection, record, expands, context)?;
        }
        Ok(())
    }

    pub(crate) fn expand_record_with_collection(
        &self,
        collection: &CollectionConfig,
        record: &mut JsonValue,
        expands: &[String],
        context: &FilterContext,
    ) -> Result<(), ServerError> {
        if expands.is_empty() {
            return Ok(());
        }

        let grouped = group_expand_paths(expands);
        let record_object = record.as_object().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        let mut requested = Vec::new();

        for (field_name, nested_expands) in grouped {
            let field = collection
                .fields
                .iter()
                .find(|field| field.name == field_name)
                .ok_or_else(|| {
                    ServerError::BadRequest(format!(
                        "expand field '{field_name}' does not exist on collection '{}'",
                        collection.name
                    ))
                })?;
            if field.kind != CollectionFieldKind::Relation {
                return Err(ServerError::BadRequest(format!(
                    "expand field '{field_name}' is not a relation field"
                )));
            }

            let target_collection = field.collection.clone().ok_or_else(|| {
                ServerError::BadRequest(format!(
                    "relation field '{field_name}' does not declare a target collection"
                ))
            })?;

            if let Some(value) = record_object.get(&field_name).cloned() {
                requested.push((field_name, target_collection, nested_expands, value));
            }
        }

        let mut expanded = Map::new();
        for (field_name, target_collection, nested_expands, value) in requested {
            if let Some(expanded_value) =
                self.expand_relation_value(&target_collection, &value, &nested_expands, context)?
            {
                expanded.insert(field_name, expanded_value);
            }
        }

        if !expanded.is_empty() {
            let record_object = record.as_object_mut().ok_or_else(|| {
                ServerError::BadRequest("record response must be a JSON object".to_string())
            })?;
            record_object.insert("expand".to_string(), JsonValue::Object(expanded));
        }

        Ok(())
    }

    pub(crate) fn expand_relation_value(
        &self,
        target_collection: &str,
        value: &JsonValue,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<JsonValue>, ServerError> {
        if let Some(id) = value.as_str() {
            return Ok(self
                .expanded_related_record(target_collection, id, nested_expands, context)?
                .map(JsonValue::Object));
        }

        let Some(ids) = value.as_array() else {
            return Ok(None);
        };

        let mut records = Vec::new();
        for id in ids.iter().filter_map(JsonValue::as_str) {
            if let Some(record) =
                self.expanded_related_record(target_collection, id, nested_expands, context)?
            {
                records.push(JsonValue::Object(record));
            }
        }

        Ok(Some(JsonValue::Array(records)))
    }

    pub(crate) fn expanded_related_record(
        &self,
        target_collection: &str,
        id: &str,
        nested_expands: &[String],
        context: &FilterContext,
    ) -> Result<Option<Map<String, JsonValue>>, ServerError> {
        let mut record = match self.get_record(target_collection, id, context.clone()) {
            Ok(record) => record,
            Err(ServerError::Forbidden(_) | ServerError::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        };

        if !nested_expands.is_empty() {
            let target = self.get_collection(target_collection)?;
            self.expand_record_with_collection(&target, &mut record, nested_expands, context)?;
        }

        let record = record.as_object().cloned().ok_or_else(|| {
            ServerError::BadRequest("record response must be a JSON object".to_string())
        })?;
        Ok(Some(record))
    }
}
