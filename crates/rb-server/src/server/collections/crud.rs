use super::*;

impl Store {
    pub fn create_collection(
        &self,
        mut collection: CollectionConfig,
    ) -> Result<CollectionConfig, ServerError> {
        normalize_collection(&mut collection);
        validate_collection(&collection)?;

        let now = now_timestamp();
        let schema_json = serde_json::to_string(&collection)?;
        let table = record_table_name(&collection.name)?;
        let table_sql = quote_identifier(&table);
        let conn = self.connection()?;
        ensure_collection_identifier_available(&conn, &collection.name, None)?;
        if let Some(id) = collection.id.as_deref() {
            ensure_collection_identifier_available(&conn, id, None)?;
        }

        conn.execute(
            r#"
            INSERT INTO "_rb_collections" (name, schema_json, created, updated)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![&collection.name, schema_json, now],
        )?;
        if collection_owns_record_table(&collection) {
            conn.execute(
                &format!(
                    r#"
                    CREATE TABLE IF NOT EXISTS {table_sql} (
                        id TEXT PRIMARY KEY NOT NULL,
                        data TEXT NOT NULL,
                        created TEXT NOT NULL,
                        updated TEXT NOT NULL
                    )
                    "#
                ),
                [],
            )?;
            apply_safe_collection_indexes(&conn, &collection)?;
        }

        Ok(collection)
    }

    pub fn get_collection(&self, name: &str) -> Result<CollectionConfig, ServerError> {
        let conn = self.connection()?;
        get_collection_with_connection(&conn, name)
    }

    pub fn get_collection_response(
        &self,
        identifier: &str,
        fields: &[String],
    ) -> Result<JsonValue, ServerError> {
        validate_collection_identifier(identifier)?;
        let conn = self.connection()?;
        let (name, schema_json, created, updated) = conn
            .query_row(
                &format!(
                    r#"
                    SELECT name, schema_json, created, updated
                    FROM "_rb_collections"
                    WHERE name = ?1 OR {} = ?1
                    LIMIT 1
                    "#,
                    collection_id_sql()
                ),
                params![identifier],
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
            .ok_or_else(|| ServerError::NotFound(format!("collection '{identifier}' not found")))?;
        let mut payload = collection_row_to_value(name, schema_json, created, updated)?;
        project_json_response(&mut payload, fields)?;
        Ok(payload)
    }

    pub fn list_collections(&self) -> Result<Vec<CollectionConfig>, ServerError> {
        let conn = self.connection()?;
        list_collections_with_connection(&conn)
    }

    pub fn list_collection_page(
        &self,
        options: CollectionListOptions,
    ) -> Result<JsonValue, ServerError> {
        let resolver = CollectionResolver;
        let mut where_sql = String::new();
        let mut params = Vec::new();
        if let Some(filter) = options
            .filter
            .as_deref()
            .filter(|filter| !filter.trim().is_empty())
        {
            let compiled = compile_filter_with_resolver_and_context(
                filter,
                &resolver,
                FilterContext::default(),
            )?;
            where_sql = format!(" WHERE ({})", compiled.sql);
            params.extend(filter_params_to_sqlite(compiled.params)?);
        }

        let order_sql = collection_sort_sql(options.sort.as_deref())?;
        let offset = options.page.saturating_sub(1) * options.per_page;
        let (total_items, items) = {
            let conn = self.connection()?;
            let total_items: u64 = conn.query_row(
                &format!(r#"SELECT COUNT(*) FROM "_rb_collections"{where_sql}"#),
                params_from_iter(params.iter()),
                |row| row.get::<_, u64>(0),
            )?;

            let mut list_params = params;
            list_params.push(SqlValue::Integer(options.per_page as i64));
            list_params.push(SqlValue::Integer(offset as i64));
            let sql = format!(
                r#"
                SELECT name, schema_json, created, updated
                FROM "_rb_collections"
                {where_sql}
                ORDER BY {order_sql}
                LIMIT ? OFFSET ?
                "#
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(list_params.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let rows = rows.collect::<Result<Vec<_>, _>>()?;
            let items = rows
                .into_iter()
                .map(|(name, schema_json, created, updated)| {
                    collection_row_to_value(name, schema_json, created, updated)
                })
                .collect::<Result<Vec<_>, _>>()?;
            (total_items, items)
        };

        let total_pages = if total_items == 0 {
            0
        } else {
            total_items.div_ceil(options.per_page)
        };

        let mut payload = json!(RecordList {
            page: options.page,
            per_page: options.per_page,
            total_items: total_items.min(i64::MAX as u64) as i64,
            total_pages: total_pages.min(i64::MAX as u64) as i64,
            items,
        });
        project_json_response(&mut payload, &options.fields)?;
        Ok(payload)
    }

    pub fn update_collection(
        &self,
        identifier: &str,
        patch: CollectionPatch,
    ) -> Result<CollectionConfig, ServerError> {
        validate_collection_identifier(identifier)?;
        let mut collection = self.get_collection(identifier)?;
        let old_collection = collection.clone();
        let old_name = collection.name.clone();
        apply_collection_patch(&mut collection, patch);
        normalize_collection(&mut collection);
        validate_collection(&collection)?;

        let new_name = collection.name.clone();
        let old_table = record_table_name(&old_name)?;
        let new_table = record_table_name(&new_name)?;
        let schema_json = serde_json::to_string(&collection)?;
        let now = now_timestamp();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if collection_owns_record_table(&old_collection) {
            drop_safe_collection_indexes(&tx, &old_collection)?;
        }

        if old_name != new_name {
            ensure_collection_identifier_available_tx(&tx, &new_name, Some(&old_name))?;

            if collection_owns_record_table(&old_collection)
                && collection_owns_record_table(&collection)
            {
                let old_table_sql = quote_identifier(&old_table);
                let new_table_sql = quote_identifier(&new_table);
                tx.execute(
                    &format!("ALTER TABLE {old_table_sql} RENAME TO {new_table_sql}"),
                    [],
                )?;
            }
            tx.execute(
                r#"UPDATE "_rb_auth_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_action_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_auth_external_accounts" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_file_tokens" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
            tx.execute(
                r#"UPDATE "_rb_files" SET collection_name = ?1 WHERE collection_name = ?2"#,
                params![&new_name, &old_name],
            )?;
        }
        if collection_owns_record_table(&old_collection)
            && !collection_owns_record_table(&collection)
        {
            let old_table_sql = quote_identifier(&old_table);
            tx.execute(&format!("DROP TABLE IF EXISTS {old_table_sql}"), [])?;
        }
        if !collection_owns_record_table(&old_collection)
            && collection_owns_record_table(&collection)
        {
            let new_table_sql = quote_identifier(&new_table);
            tx.execute(
                &format!(
                    r#"
                    CREATE TABLE IF NOT EXISTS {new_table_sql} (
                        id TEXT PRIMARY KEY NOT NULL,
                        data TEXT NOT NULL,
                        created TEXT NOT NULL,
                        updated TEXT NOT NULL
                    )
                    "#
                ),
                [],
            )?;
        }

        let affected = tx.execute(
            r#"
            UPDATE "_rb_collections"
            SET name = ?1, schema_json = ?2, updated = ?3
            WHERE name = ?4
            "#,
            params![&new_name, schema_json, now, &old_name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{old_name}' not found"
            )));
        }
        if collection_owns_record_table(&collection) {
            apply_safe_collection_indexes(&tx, &collection)?;
        }
        tx.commit()?;

        Ok(collection)
    }

    pub fn delete_collection(&self, identifier: &str) -> Result<(), ServerError> {
        validate_collection_identifier(identifier)?;
        let collection = self.get_collection(identifier)?;
        let name = collection.name;

        let table_sql = quote_identifier(&record_table_name(&name)?);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(&format!("DROP TABLE IF EXISTS {table_sql}"), [])?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        tx.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        let affected = tx.execute(
            r#"DELETE FROM "_rb_collections" WHERE name = ?1"#,
            params![&name],
        )?;
        if affected == 0 {
            return Err(ServerError::NotFound(format!(
                "collection '{name}' not found"
            )));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn truncate_collection(&self, identifier: &str) -> Result<(), ServerError> {
        validate_collection_identifier(identifier)?;
        let collection = self.get_collection(identifier)?;
        let name = collection.name;

        let table_sql = quote_identifier(&record_table_name(&name)?);
        let conn = self.connection()?;
        conn.execute(&format!("DELETE FROM {table_sql}"), [])?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_action_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_auth_external_accounts" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_file_tokens" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        conn.execute(
            r#"DELETE FROM "_rb_files" WHERE collection_name = ?1"#,
            params![&name],
        )?;
        Ok(())
    }
}
