use super::*;
use crate::server::{collections::*, storage::*};

impl Store {
    pub(crate) fn auth_collection(
        &self,
        collection_name: &str,
    ) -> Result<CollectionConfig, ServerError> {
        let collection = self.get_collection(collection_name)?;
        if collection.collection_type != CollectionType::Auth {
            return Err(ServerError::BadRequest(format!(
                "collection '{collection_name}' is not an auth collection"
            )));
        }

        Ok(collection)
    }
}

impl Store {
    pub fn superuser_auth_is_required(&self) -> Result<bool, ServerError> {
        match self.get_collection(SUPERUSERS_COLLECTION) {
            Ok(_) => {}
            Err(ServerError::NotFound(_)) => return Ok(false),
            Err(err) => return Err(err),
        }

        let table_sql = quote_identifier(&record_table_name(SUPERUSERS_COLLECTION)?);
        let conn = self.connection()?;
        let count = conn.query_row(&format!("SELECT COUNT(*) FROM {table_sql}"), [], |row| {
            row.get::<_, u64>(0)
        })?;

        Ok(count > 0)
    }

    pub fn is_superuser_token(&self, token: &str) -> Result<bool, ServerError> {
        let (collection_name, record_id) = self.valid_token_subject(token)?;
        if collection_name != SUPERUSERS_COLLECTION {
            return Ok(false);
        }

        self.read_record(SUPERUSERS_COLLECTION, &record_id)?;
        Ok(true)
    }
}
