use super::super::{collections::*, http::HttpRequest, validation::validation_error, ServerError};
use serde_json::{Map, Value as JsonValue};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileUpload {
    pub(crate) field_name: String,
    pub(crate) original_name: String,
    pub(crate) content_type: String,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn record_payload_from_request(
    request: &HttpRequest,
    collection: &CollectionConfig,
) -> Result<(JsonValue, Vec<FileUpload>), ServerError> {
    let Some(boundary) = multipart_boundary(request) else {
        return Ok((serde_json::from_slice(&request.body)?, Vec::new()));
    };

    multipart_record_payload(&request.body, &boundary, collection)
}

pub(crate) fn multipart_boundary(request: &HttpRequest) -> Option<String> {
    let content_type = request.headers.get("content-type")?;
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("multipart/form-data"))
    {
        return None;
    }

    for part in parts {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("boundary") {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }

    None
}

pub(crate) fn multipart_record_payload(
    body: &[u8],
    boundary: &str,
    collection: &CollectionConfig,
) -> Result<(JsonValue, Vec<FileUpload>), ServerError> {
    let mut object = Map::new();
    let mut uploads = Vec::new();
    let file_fields = collection
        .fields
        .iter()
        .filter(|field| field.kind == CollectionFieldKind::File)
        .map(|field| field.name.as_str())
        .collect::<HashSet<_>>();

    for part in parse_multipart_parts(body, boundary)? {
        let Some(name) = part.name else {
            continue;
        };

        if let Some(filename) = part.filename {
            uploads.push(FileUpload {
                field_name: name,
                original_name: filename,
                content_type: part
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                data: part.data,
            });
            continue;
        }

        let value = String::from_utf8(part.data).map_err(|_| {
            ServerError::BadRequest("multipart form field must be valid UTF-8".to_string())
        })?;
        if file_fields.contains(name.as_str()) && value.is_empty() {
            continue;
        }
        let value = multipart_text_value(collection, &name, value)?;
        insert_form_value(&mut object, name, value);
    }

    Ok((JsonValue::Object(object), uploads))
}

pub(crate) fn multipart_text_value(
    collection: &CollectionConfig,
    name: &str,
    value: String,
) -> Result<JsonValue, ServerError> {
    let Some(field) = collection.fields.iter().find(|field| field.name == name) else {
        return Ok(JsonValue::String(value));
    };

    match field.kind {
        CollectionFieldKind::Bool => match value.as_str() {
            "true" => Ok(JsonValue::Bool(true)),
            "false" => Ok(JsonValue::Bool(false)),
            _ => Err(validation_error(
                "Failed to validate record.",
                name,
                "validation_invalid_bool",
                format!("Field '{name}' must be a boolean."),
            )),
        },
        CollectionFieldKind::Number => value
            .parse::<serde_json::Number>()
            .map(JsonValue::Number)
            .map_err(|_| {
                validation_error(
                    "Failed to validate record.",
                    name,
                    "validation_invalid_number",
                    format!("Field '{name}' must be a number."),
                )
            }),
        CollectionFieldKind::Select if field.max_select.unwrap_or(1) > 1 => {
            serde_json::from_str(&value).map_err(|_| {
                validation_error(
                    "Failed to validate record.",
                    name,
                    "validation_invalid_select",
                    format!("Field '{name}' must be a select value array."),
                )
            })
        }
        CollectionFieldKind::Array | CollectionFieldKind::Json | CollectionFieldKind::GeoPoint => {
            serde_json::from_str(&value).map_err(|_| {
                validation_error(
                    "Failed to validate record.",
                    name,
                    "validation_invalid_json",
                    format!("Field '{name}' must be valid JSON."),
                )
            })
        }
        CollectionFieldKind::AutoDate => Ok(JsonValue::String(value)),
        _ => Ok(JsonValue::String(value)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MultipartPart {
    pub(crate) name: Option<String>,
    pub(crate) filename: Option<String>,
    pub(crate) content_type: Option<String>,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn parse_multipart_parts(
    body: &[u8],
    boundary: &str,
) -> Result<Vec<MultipartPart>, ServerError> {
    if boundary.is_empty() {
        return Err(ServerError::BadRequest(
            "multipart boundary is required".to_string(),
        ));
    }

    let marker = format!("--{boundary}").into_bytes();
    let mut cursor = find_subslice(body, &marker)
        .ok_or_else(|| ServerError::BadRequest("multipart boundary not found".to_string()))?;
    let mut parts = Vec::new();

    loop {
        if !body[cursor..].starts_with(&marker) {
            return Err(ServerError::BadRequest(
                "invalid multipart boundary".to_string(),
            ));
        }
        cursor += marker.len();

        if body[cursor..].starts_with(b"--") {
            break;
        }
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        }

        let header_len = find_subslice(&body[cursor..], b"\r\n\r\n")
            .ok_or_else(|| ServerError::BadRequest("multipart headers not closed".to_string()))?;
        let header_bytes = &body[cursor..cursor + header_len];
        cursor += header_len + 4;

        let next_boundary = find_subslice(&body[cursor..], &boundary_separator(&marker))
            .ok_or_else(|| ServerError::BadRequest("multipart part not closed".to_string()))?;
        let data = body[cursor..cursor + next_boundary].to_vec();
        cursor += next_boundary + 2;

        parts.push(parse_multipart_part(header_bytes, data)?);
    }

    Ok(parts)
}

pub(crate) fn boundary_separator(marker: &[u8]) -> Vec<u8> {
    let mut separator = Vec::with_capacity(marker.len() + 2);
    separator.extend_from_slice(b"\r\n");
    separator.extend_from_slice(marker);
    separator
}

pub(crate) fn parse_multipart_part(
    headers: &[u8],
    data: Vec<u8>,
) -> Result<MultipartPart, ServerError> {
    let headers = std::str::from_utf8(headers)
        .map_err(|_| ServerError::BadRequest("multipart headers must be UTF-8".to_string()))?;
    let mut name = None;
    let mut filename = None;
    let mut content_type = None;

    for line in headers.split("\r\n") {
        let Some((header_name, value)) = line.split_once(':') else {
            continue;
        };
        if header_name.eq_ignore_ascii_case("content-disposition") {
            name = quoted_header_param(value, "name");
            filename = quoted_header_param(value, "filename");
        } else if header_name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().to_string());
        }
    }

    Ok(MultipartPart {
        name,
        filename,
        content_type,
        data,
    })
}

pub(crate) fn quoted_header_param(value: &str, param: &str) -> Option<String> {
    for part in value.split(';').map(str::trim) {
        let Some((name, raw_value)) = part.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(param) {
            return Some(raw_value.trim().trim_matches('"').to_string());
        }
    }

    None
}

pub(crate) fn insert_form_value(
    object: &mut Map<String, JsonValue>,
    name: String,
    value: JsonValue,
) {
    if let Some(existing) = object.get_mut(&name) {
        match existing {
            JsonValue::Array(values) => values.push(value),
            other => {
                let first = std::mem::take(other);
                *other = JsonValue::Array(vec![first, value]);
            }
        }
    } else {
        object.insert(name, value);
    }
}

pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
