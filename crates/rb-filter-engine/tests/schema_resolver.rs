use rb_filter_engine::{compile_filter_with_schema, FieldKind, FieldSchema, FilterSchema, Value};

fn schema() -> FilterSchema {
    FilterSchema::new([
        FieldSchema::new("name", FieldKind::Text),
        FieldSchema::new("age", FieldKind::Number),
        FieldSchema::new("verified", FieldKind::Bool),
        FieldSchema::new("deleted_at", FieldKind::DateTime),
        FieldSchema::new("tags", FieldKind::Array),
        FieldSchema::new("author.id", FieldKind::Relation),
    ])
}

#[test]
fn compiles_known_fields_with_type_compatible_operators() {
    let out = compile_filter_with_schema("name ~ 'burak' && age >= 30", &schema()).unwrap();
    assert_eq!(out.sql, "name LIKE ? ESCAPE '\\' AND age >= ?");
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
        "EXISTS (SELECT 1 FROM json_each(tags) WHERE json_each.value = ?)"
    );
}

#[test]
fn accepts_relation_identifier_fields() {
    let out = compile_filter_with_schema("author.id = 'abc123'", &schema()).unwrap();
    assert_eq!(out.sql, "author.id = ?");
}
