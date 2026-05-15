use super::*;
use super::{auth::*, collections::*, records::*, storage::*, validation::*};

mod multipart;
mod thumbnails;

pub(crate) use multipart::*;
pub(crate) use thumbnails::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredFileInput {
    pub(crate) field_name: String,
    pub(crate) filename: String,
    pub(crate) content_type: String,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredFile {
    pub(crate) content_type: String,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileMutationKind {
    Set,
    Append,
    Prepend,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ReferencedFile {
    pub(crate) protected: bool,
    pub(crate) thumbs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FileFieldMutation {
    pub(crate) explicit_set: Option<JsonValue>,
    pub(crate) set_uploads: Vec<FileUpload>,
    pub(crate) append_uploads: Vec<FileUpload>,
    pub(crate) prepend_uploads: Vec<FileUpload>,
    pub(crate) delete_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PreparedFileChanges {
    pub(crate) store_files: Vec<StoredFileInput>,
    pub(crate) delete_files: Vec<String>,
}

pub(crate) fn prepare_file_changes(
    collection: &CollectionConfig,
    object: &mut Map<String, JsonValue>,
    uploads: Vec<FileUpload>,
    existing: Option<&JsonValue>,
) -> Result<PreparedFileChanges, ServerError> {
    let mut mutations: HashMap<String, FileFieldMutation> = HashMap::new();
    let keys = object.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        let Some((field_name, kind)) = parse_file_mutation_key(collection, &key) else {
            continue;
        };
        let value = object.remove(&key).unwrap_or(JsonValue::Null);
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            FileMutationKind::Set => {
                mutation.explicit_set = Some(value);
            }
            FileMutationKind::Delete => {
                mutation.delete_names.extend(file_names_from_value(&value)?);
            }
            FileMutationKind::Append | FileMutationKind::Prepend => {
                if !is_empty_file_value(&value) {
                    return Err(validation_error(
                        "Failed to validate record.",
                        key,
                        "validation_invalid_file_modifier",
                        "File append/prepend modifiers require uploaded file parts.",
                    ));
                }
            }
        }
    }

    for upload in uploads {
        let raw_field_name = upload.field_name.clone();
        let Some((field_name, kind)) = parse_file_mutation_key(collection, &raw_field_name) else {
            return Err(validation_error(
                "Failed to validate record.",
                raw_field_name,
                "validation_unknown_field",
                format!("Unknown field for collection '{}'.", collection.name),
            ));
        };
        let mutation = mutations.entry(field_name).or_default();
        match kind {
            FileMutationKind::Set => mutation.set_uploads.push(upload),
            FileMutationKind::Append => mutation.append_uploads.push(upload),
            FileMutationKind::Prepend => mutation.prepend_uploads.push(upload),
            FileMutationKind::Delete => {
                return Err(validation_error(
                    "Failed to validate record.",
                    raw_field_name,
                    "validation_invalid_file_modifier",
                    "File delete modifiers require filename values.",
                ))
            }
        }
    }

    let mut changes = PreparedFileChanges::default();
    for (field_name, mutation) in mutations {
        let field = collection
            .fields
            .iter()
            .find(|field| field.name == field_name)
            .ok_or_else(|| {
                validation_error(
                    "Failed to validate record.",
                    &field_name,
                    "validation_unknown_field",
                    format!("Unknown field for collection '{}'.", collection.name),
                )
            })?;
        if field.kind != CollectionFieldKind::File {
            return Err(validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_invalid_file_field",
                "Uploaded files are only allowed on file fields.",
            ));
        }

        let max_select = field.max_select.unwrap_or(1).max(1);
        let existing_names = existing
            .and_then(JsonValue::as_object)
            .and_then(|object| object.get(&field_name))
            .map(file_names_from_value)
            .transpose()?
            .unwrap_or_default();

        let mut final_names = if let Some(value) = mutation.explicit_set {
            file_names_from_value(&value)?
        } else {
            existing_names.clone()
        };

        if !mutation.delete_names.is_empty() {
            let delete_names = mutation
                .delete_names
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            final_names.retain(|name| !delete_names.contains(name));
            changes.delete_files.extend(
                existing_names
                    .iter()
                    .filter(|name| delete_names.contains(*name))
                    .cloned(),
            );
        }

        if !mutation.set_uploads.is_empty() {
            changes.delete_files.extend(existing_names.iter().cloned());
            final_names.clear();
            let uploaded = prepare_uploaded_files(field, mutation.set_uploads, &mut changes)?;
            final_names.extend(uploaded);
        }

        if !mutation.prepend_uploads.is_empty() {
            let uploaded = prepare_uploaded_files(field, mutation.prepend_uploads, &mut changes)?;
            let mut combined = uploaded;
            combined.extend(final_names);
            final_names = combined;
        }

        if !mutation.append_uploads.is_empty() {
            let uploaded = prepare_uploaded_files(field, mutation.append_uploads, &mut changes)?;
            final_names.extend(uploaded);
        }

        if final_names.len() as u64 > max_select {
            return Err(validation_error(
                "Failed to validate record.",
                &field_name,
                "validation_max_select",
                format!("Field '{field_name}' accepts at most {max_select} file(s)."),
            ));
        }

        changes.delete_files.extend(
            existing_names
                .iter()
                .filter(|name| !final_names.contains(*name))
                .cloned(),
        );
        dedupe_strings(&mut changes.delete_files);
        object.insert(
            field_name.clone(),
            file_field_value(&final_names, max_select),
        );
    }

    Ok(changes)
}

pub(crate) fn prepare_uploaded_files(
    field: &CollectionField,
    uploads: Vec<FileUpload>,
    changes: &mut PreparedFileChanges,
) -> Result<Vec<String>, ServerError> {
    let mut filenames = Vec::new();
    for upload in uploads {
        if field
            .max_size
            .is_some_and(|max_size| max_size > 0 && upload.data.len() as u64 > max_size)
        {
            return Err(validation_error(
                "Failed to validate record.",
                &field.name,
                "validation_max_size",
                format!("Field '{}' file exceeds the maximum size.", field.name),
            ));
        }

        let content_type = normalize_content_type(&upload.content_type);
        if !field.mime_types.is_empty() && !mime_type_allowed(&field.mime_types, &content_type) {
            return Err(validation_error(
                "Failed to validate record.",
                &field.name,
                "validation_mime_type",
                format!("Field '{}' does not allow this file type.", field.name),
            ));
        }

        let filename = stored_file_name(&upload.original_name);
        validate_file_name(&filename)?;
        filenames.push(filename.clone());
        changes.store_files.push(StoredFileInput {
            field_name: field.name.clone(),
            filename,
            content_type,
            data: upload.data,
        });
    }

    Ok(filenames)
}

pub(crate) fn parse_file_mutation_key(
    collection: &CollectionConfig,
    key: &str,
) -> Option<(String, FileMutationKind)> {
    if let Some(field) = key
        .strip_prefix('+')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Prepend));
    }
    if let Some(field) = key
        .strip_suffix('+')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Append));
    }
    if let Some(field) = key
        .strip_suffix('-')
        .and_then(|name| file_field(collection, name))
    {
        return Some((field.name.clone(), FileMutationKind::Delete));
    }
    file_field(collection, key).map(|field| (field.name.clone(), FileMutationKind::Set))
}

pub(crate) fn file_field<'a>(
    collection: &'a CollectionConfig,
    name: &str,
) -> Option<&'a CollectionField> {
    collection
        .fields
        .iter()
        .find(|field| field.name == name && field.kind == CollectionFieldKind::File)
}

pub(crate) fn file_names_from_value(value: &JsonValue) -> Result<Vec<String>, ServerError> {
    match value {
        JsonValue::String(value) if value.trim().is_empty() => Ok(Vec::new()),
        JsonValue::String(value) => Ok(vec![value.clone()]),
        JsonValue::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    ServerError::BadRequest("file names must be strings".to_string())
                })
            })
            .filter(|result| result.as_ref().map_or(true, |name| !name.trim().is_empty()))
            .collect(),
        JsonValue::Null => Ok(Vec::new()),
        _ => Err(ServerError::BadRequest(
            "file field value must be a string or string array".to_string(),
        )),
    }
}

pub(crate) fn is_empty_file_value(value: &JsonValue) -> bool {
    match value {
        JsonValue::String(value) => value.is_empty(),
        JsonValue::Array(values) => values.is_empty(),
        JsonValue::Null => true,
        _ => false,
    }
}

pub(crate) fn file_field_value(names: &[String], max_select: u64) -> JsonValue {
    string_list_field_value(names, max_select)
}

pub(crate) fn record_references_file(
    collection: &CollectionConfig,
    record: &JsonValue,
    filename: &str,
) -> Result<bool, ServerError> {
    Ok(referenced_file(collection, record, filename)?.is_some())
}

pub(crate) fn referenced_file(
    collection: &CollectionConfig,
    record: &JsonValue,
    filename: &str,
) -> Result<Option<ReferencedFile>, ServerError> {
    let Some(object) = record.as_object() else {
        return Ok(None);
    };

    let mut referenced = ReferencedFile::default();
    let mut found = false;
    for field in collection
        .fields
        .iter()
        .filter(|field| field.kind == CollectionFieldKind::File)
    {
        let Some(value) = object.get(&field.name) else {
            continue;
        };
        if file_names_from_value(value)?
            .iter()
            .any(|name| name == filename)
        {
            found = true;
            referenced.protected |= field.protected;
            referenced.thumbs.extend(field.thumbs.iter().cloned());
        }
    }

    dedupe_strings(&mut referenced.thumbs);
    Ok(found.then_some(referenced))
}

pub(crate) fn store_file_uploads(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    files: &[StoredFileInput],
) -> Result<(), ServerError> {
    let now = now_timestamp();
    for file in files {
        conn.execute(
            r#"
            INSERT OR REPLACE INTO "_rb_files"
                (collection_name, record_id, field_name, filename, content_type, data, created)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                collection_name,
                record_id,
                &file.field_name,
                &file.filename,
                &file.content_type,
                &file.data,
                &now
            ],
        )?;
    }

    Ok(())
}

pub(crate) fn delete_file_names(
    conn: &Connection,
    collection_name: &str,
    record_id: &str,
    filenames: &[String],
) -> Result<(), ServerError> {
    for filename in filenames {
        conn.execute(
            r#"
            DELETE FROM "_rb_files"
            WHERE collection_name = ?1 AND record_id = ?2 AND filename = ?3
            "#,
            params![collection_name, record_id, filename],
        )?;
    }

    Ok(())
}

pub(crate) fn dedupe_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

pub(crate) fn stored_file_name(original: &str) -> String {
    let basename = original
        .rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("file");
    let sanitized = sanitize_file_name(basename);
    let suffix = generate_file_suffix();

    if let Some((stem, ext)) = sanitized.rsplit_once('.') {
        if !stem.is_empty() && !ext.is_empty() {
            return format!("{stem}_{suffix}.{ext}");
        }
    }

    format!("{sanitized}_{suffix}")
}

pub(crate) fn sanitize_file_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_string();

    if sanitized.is_empty() {
        "file".to_string()
    } else {
        sanitized
    }
}

pub(crate) fn normalize_content_type(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "application/octet-stream".to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn mime_type_allowed(allowed: &[String], content_type: &str) -> bool {
    let content_type = content_type_base(content_type);
    allowed
        .iter()
        .map(|value| content_type_base(value))
        .filter(|value| !value.is_empty())
        .any(|allowed| {
            allowed == content_type
                || allowed
                    .strip_suffix("/*")
                    .is_some_and(|prefix| content_type.starts_with(&format!("{prefix}/")))
        })
}

pub(crate) fn content_type_base(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

pub(crate) fn validate_file_name(name: &str) -> Result<(), ServerError> {
    if !name.is_empty()
        && name.len() <= 255
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsafe file name '{name}'"
        )))
    }
}

impl Store {
    pub fn create_file_token(&self, auth_token: &str) -> Result<String, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(auth_token)?;
        let collection = self.auth_collection(&collection_name)?;
        let token = generate_token();
        let now = now_millis();
        let expires = (now + file_token_ttl_millis(&collection)).to_string();
        let conn = self.connection()?;
        conn.execute(
            r#"
            INSERT INTO "_rb_file_tokens" (token, collection_name, record_id, created, expires)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                &token,
                &collection_name,
                &record_id,
                now.to_string(),
                &expires
            ],
        )?;

        Ok(token)
    }

    pub fn context_for_file_token(
        &self,
        token: &str,
        context: FilterContext,
    ) -> Result<FilterContext, ServerError> {
        let (collection_name, record_id) = self.valid_file_token_subject(token)?;
        let record = self.read_record(&collection_name, &record_id)?;
        Ok(context_with_auth_record_values(context, &record))
    }

    pub(crate) fn get_file(
        &self,
        collection_name: &str,
        record_id: &str,
        filename: &str,
    ) -> Result<StoredFile, ServerError> {
        validate_collection_name(collection_name)?;
        validate_record_id(record_id)?;
        validate_file_name(filename)?;

        let conn = self.connection()?;
        conn.query_row(
            r#"
            SELECT content_type, data
            FROM "_rb_files"
            WHERE collection_name = ?1 AND record_id = ?2 AND filename = ?3
            LIMIT 1
            "#,
            params![collection_name, record_id, filename],
            |row| {
                Ok(StoredFile {
                    content_type: row.get::<_, String>(0)?,
                    data: row.get::<_, Vec<u8>>(1)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| ServerError::NotFound(format!("file '{filename}' not found")))
    }

    pub(crate) fn valid_file_token_subject(
        &self,
        token: &str,
    ) -> Result<(String, String), ServerError> {
        self.valid_subject_token("_rb_file_tokens", token, "file")
    }
}
