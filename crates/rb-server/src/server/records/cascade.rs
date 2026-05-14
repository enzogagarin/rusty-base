use super::*;

pub(crate) struct CascadeDeleteTarget {
    pub(crate) collection_name: String,
    pub(crate) record_id: String,
}

impl Store {
    pub fn delete_record(&self, collection_name: &str, id: &str) -> Result<(), ServerError> {
        self.delete_record_with_context(collection_name, id, FilterContext::default())
    }

    pub fn delete_record_with_context(
        &self,
        collection_name: &str,
        id: &str,
        context: FilterContext,
    ) -> Result<(), ServerError> {
        self.with_savepoint("rb_delete_record_cascade", |conn| {
            self.delete_record_internal(
                conn,
                collection_name,
                id,
                &context,
                &mut HashSet::new(),
                true,
            )
        })
    }

    pub(crate) fn delete_record_internal(
        &self,
        conn: &Connection,
        collection_identifier: &str,
        id: &str,
        context: &FilterContext,
        visited: &mut HashSet<(String, String)>,
        enforce_rule: bool,
    ) -> Result<(), ServerError> {
        validate_record_id(id)?;
        let collection = get_collection_with_connection(conn, collection_identifier)?;
        if collection.collection_type == CollectionType::View {
            return Err(read_only_view_collection(&collection.name));
        }
        let collection_name = collection.name.as_str();
        let collection_id = record_collection_id(&collection);
        let record_key = (collection_name.to_string(), id.to_string());
        if !visited.insert(record_key) {
            return Ok(());
        }

        read_record_with_connection(conn, &collection, id)?;
        if enforce_rule && !is_superuser_context(context) {
            let allowed = self.existing_record_rule_allows_with_connection(
                conn,
                collection_name,
                &collection,
                collection.delete_rule.as_deref(),
                id,
                context.clone(),
            )?;
            if !allowed {
                return Err(forbidden("delete", collection_name));
            }
        }

        let table_sql = quote_identifier(&record_table_name(collection_name)?);
        let affected = conn.execute(
            &format!("DELETE FROM {table_sql} WHERE id = ?1"),
            params![id],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!("record '{id}' not found")));
        }
        conn.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1 AND record_id = ?2"#,
            params![collection_name, id],
        )?;
        if collection.collection_type == CollectionType::Auth {
            conn.execute(
                r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
            conn.execute(
                r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1 AND record_id = ?2"#,
                params![collection_name, id],
            )?;
        }

        let cascade_targets =
            self.cascade_delete_targets_with_connection(conn, collection_name, &collection_id, id)?;
        for target in cascade_targets {
            self.delete_record_internal(
                conn,
                &target.collection_name,
                &target.record_id,
                context,
                visited,
                false,
            )?;
        }

        Ok(())
    }

    pub(crate) fn cascade_delete_targets_with_connection(
        &self,
        conn: &Connection,
        source_collection_name: &str,
        source_collection_id: &str,
        source_record_id: &str,
    ) -> Result<Vec<CascadeDeleteTarget>, ServerError> {
        let collections = list_collections_with_connection(conn)?;
        let mut targets = Vec::new();
        let mut seen = HashSet::new();

        for collection in collections {
            let fields = collection
                .fields
                .iter()
                .filter(|field| {
                    field.kind == CollectionFieldKind::Relation
                        && field.cascade_delete
                        && field.collection.as_deref().is_some_and(|target| {
                            target == source_collection_name || target == source_collection_id
                        })
                })
                .collect::<Vec<_>>();
            if fields.is_empty() {
                continue;
            }

            let table_sql = quote_identifier(&record_table_name(&collection.name)?);
            let mut stmt = conn.prepare(&format!("SELECT id, data FROM {table_sql}"))?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;

            for row in rows {
                let (record_id, data) = row?;
                let data = serde_json::from_str::<JsonValue>(&data)?;
                let Some(object) = data.as_object() else {
                    continue;
                };
                let references_source = fields.iter().any(|field| {
                    object
                        .get(&field.name)
                        .is_some_and(|value| relation_value_contains(value, source_record_id))
                });
                if references_source && seen.insert((collection.name.clone(), record_id.clone())) {
                    targets.push(CascadeDeleteTarget {
                        collection_name: collection.name.clone(),
                        record_id,
                    });
                }
            }
        }

        Ok(targets)
    }
}
