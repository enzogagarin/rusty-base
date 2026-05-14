use super::*;
use crate::server::{collections::*, records::*, storage::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImpersonateRequest {
    pub(crate) duration: Option<u64>,
}

impl ImpersonateRequest {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                AUTH_FORM_VALIDATION_MESSAGE,
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        Ok(Self {
            duration: optional_form_u64(object, "duration", AUTH_FORM_VALIDATION_MESSAGE)?,
        })
    }
}

impl Store {
    pub fn impersonate_auth_record(
        &self,
        collection_name: &str,
        record_id: &str,
        duration_seconds: Option<u64>,
    ) -> Result<AuthResponse, ServerError> {
        let collection = self.auth_collection(collection_name)?;
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        validate_record_id(record_id)?;

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let conn = self.connection()?;
        let row = conn
            .query_row(
                &format!(
                    "SELECT id, data, created, updated FROM {table_sql} WHERE id = ?1 LIMIT 1"
                ),
                params![record_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| ServerError::NotFound(format!("record '{record_id}' not found")))?;

        let ttl_millis = duration_seconds
            .filter(|duration| *duration > 0)
            .map(|duration| u128::from(duration) * 1000)
            .unwrap_or_else(|| auth_token_ttl_millis(&collection));
        let (token, expires) =
            insert_auth_token_with_renewable(&conn, collection_name, record_id, ttl_millis, false)?;
        drop(conn);

        let (id, data, created, updated) = row;
        Ok(AuthResponse {
            token,
            expires,
            record: record_from_parts(
                collection_name,
                &collection_id,
                id,
                serde_json::from_str::<JsonValue>(&data)?,
                created,
                updated,
            ),
        })
    }
}
