use rb_filter_engine::{
    compile_filter_with_resolver, compile_filter_with_schema, plan_filter_with_schema, FieldKind,
    FieldResolver, FieldSchema, FilterError, FilterErrorKind, FilterSchema, ResolvedField, Value,
};

fn schema() -> FilterSchema {
    FilterSchema::new([
        FieldSchema::new("name", FieldKind::Text),
        FieldSchema::new("nickname", FieldKind::Text),
        FieldSchema::new("age", FieldKind::Number),
        FieldSchema::new("verified", FieldKind::Bool),
        FieldSchema::new("deleted_at", FieldKind::DateTime),
        FieldSchema::new("tags", FieldKind::Array),
        FieldSchema::new("profile", FieldKind::Json),
        FieldSchema::new("author.id", FieldKind::Relation),
        FieldSchema::new("office.lon", FieldKind::Number),
        FieldSchema::new("office.lat", FieldKind::Number),
    ])
}

#[test]
fn compiles_known_fields_with_type_compatible_operators() {
    let out = compile_filter_with_schema("name ~ 'burak' && age >= 30", &schema()).unwrap();
    assert_eq!(out.sql, "\"name\" LIKE ? ESCAPE '\\' AND \"age\" >= ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("%burak%".to_string()),
            Value::Number("30".to_string())
        ]
    );
}

#[test]
fn rejects_unknown_fields() {
    let err = compile_filter_with_schema("password = 'secret'", &schema()).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn rejects_like_on_number_fields() {
    let err = compile_filter_with_schema("age ~ '3'", &schema()).unwrap_err();
    assert!(err.to_string().contains("operator ~ is not allowed"));
}

#[test]
fn rejects_numeric_comparison_on_text_fields() {
    let err = compile_filter_with_schema("name >= 10", &schema()).unwrap_err();
    assert!(err.to_string().contains("operator >= is not allowed"));
}

#[test]
fn rejects_string_literal_for_number_fields() {
    let err = compile_filter_with_schema("age = 'old'", &schema()).unwrap_err();
    assert!(err.to_string().contains("expected number"));
}

#[test]
fn rejects_any_match_on_non_array_fields() {
    let err = compile_filter_with_schema("name ?= 'burak'", &schema()).unwrap_err();
    assert!(err.to_string().contains("any-match operator"));
}

#[test]
fn accepts_any_match_on_array_fields() {
    let out = compile_filter_with_schema("tags ?= 'rust'", &schema()).unwrap();
    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM json_each(\"tags\") WHERE json_each.value = ?)"
    );
}

#[test]
fn accepts_relation_identifier_fields() {
    let out = compile_filter_with_schema("author.id = 'abc123'", &schema()).unwrap();
    assert_eq!(out.sql, "\"author\".\"id\" = ?");
}

#[test]
fn compiles_json_path_fields_from_schema_root() {
    let out = compile_filter_with_schema("profile.name = 'Burak'", &schema()).unwrap();
    assert_eq!(out.sql, "json_extract(\"profile\", '$.name') = ?");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn compiles_nested_json_path_fields() {
    let out = compile_filter_with_schema("profile.address.city ~ 'Istanbul'", &schema()).unwrap();
    assert_eq!(
        out.sql,
        "json_extract(\"profile\", '$.address.city') LIKE ? ESCAPE '\\'"
    );
    assert_eq!(out.params, vec![Value::String("%Istanbul%".to_string())]);
}

#[test]
fn compiles_json_array_index_paths() {
    let out = compile_filter_with_schema("profile.items.0.name = 'rust'", &schema()).unwrap();
    assert_eq!(out.sql, "json_extract(\"profile\", '$.items[0].name') = ?");
    assert_eq!(out.params, vec![Value::String("rust".to_string())]);
}

#[test]
fn compiles_any_match_on_json_path_arrays() {
    let out = compile_filter_with_schema("profile.tags ?= 'rust'", &schema()).unwrap();
    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM json_each(json_extract(\"profile\", '$.tags')) WHERE json_each.value = ?)"
    );
    assert_eq!(out.params, vec![Value::String("rust".to_string())]);
}

#[test]
fn rejects_nested_paths_on_non_json_schema_roots() {
    let err = compile_filter_with_schema("name.first = 'Burak'", &schema()).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn plans_json_path_fields_without_relation_metadata() {
    let plan = plan_filter_with_schema("profile.name = 'Burak'", &schema()).unwrap();
    assert!(plan.relations.is_empty());
}

#[test]
fn compiles_schema_resolved_field_to_field_comparisons() {
    let out = compile_filter_with_schema("name = nickname", &schema()).unwrap();
    assert_eq!(out.sql, "\"name\" = \"nickname\"");
    assert_eq!(out.params, vec![]);
}

#[test]
fn compiles_schema_resolved_literal_to_field_comparisons() {
    let out = compile_filter_with_schema("'Burak' = name", &schema()).unwrap();
    assert_eq!(out.sql, "? = \"name\"");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn compiles_schema_resolved_like_with_field_pattern_operand() {
    let out = compile_filter_with_schema("name ~ nickname", &schema()).unwrap();
    assert_eq!(
        out.sql,
        "\"name\" LIKE ('%' || \"nickname\" || '%') ESCAPE '\\'"
    );
    assert_eq!(out.params, vec![]);
}

#[test]
fn compiles_schema_resolved_strftime_function_operand() {
    let out = compile_filter_with_schema("strftime('%Y', deleted_at) = '2026'", &schema()).unwrap();
    assert_eq!(out.sql, "strftime(?,\"deleted_at\") = ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("%Y".to_string()),
            Value::String("2026".to_string())
        ]
    );
}

#[test]
fn compiles_schema_resolved_geo_distance_function_operand() {
    let out =
        compile_filter_with_schema("geoDistance(office.lon, office.lat, 1, 2) < 200", &schema())
            .unwrap();
    assert_eq!(
        out.sql,
        "(6371 * acos(cos(radians(\"office\".\"lat\")) * cos(radians(?)) * cos(radians(?) - radians(\"office\".\"lon\")) + sin(radians(\"office\".\"lat\")) * sin(radians(?)))) < ?"
    );
    assert_eq!(
        out.params,
        vec![
            Value::Number("2".to_string()),
            Value::Number("1".to_string()),
            Value::Number("2".to_string()),
            Value::Number("200".to_string())
        ]
    );
}

#[test]
fn custom_resolver_controls_sql_identifier_rendering() {
    struct Resolver;

    impl FieldResolver for Resolver {
        fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
            match field {
                "name" => Ok(ResolvedField::with_kind("[[name]]", FieldKind::Text)),
                _ => Err(FilterError::with_kind(
                    FilterErrorKind::UnknownField,
                    format!("unknown field '{field}'"),
                )),
            }
        }
    }

    let out = compile_filter_with_resolver("name = 'Burak'", &Resolver).unwrap();
    assert_eq!(out.sql, "[[name]] = ?");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}
