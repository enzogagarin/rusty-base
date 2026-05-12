use rb_filter_engine::{compile_filter, compile_filter_with_params, Value};

#[test]
fn compiles_equality_with_bound_parameter() {
    let out = compile_filter_with_params("name = 'Burak'").unwrap();
    assert_eq!(out.sql, "name = ?");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn compiles_boolean_precedence_with_parentheses() {
    let out = compile_filter_with_params("id = null || (status = true && score >= 10)").unwrap();
    assert_eq!(out.sql, "id IS NULL OR (status = TRUE AND score >= ?)");
    assert_eq!(out.params, vec![Value::Number("10".to_string())]);
}

#[test]
fn compiles_like_with_escape_clause() {
    let out = compile_filter_with_params("title ~ 'rust_%'").unwrap();
    assert_eq!(out.sql, "title LIKE ? ESCAPE '\\'");
    assert_eq!(out.params, vec![Value::String("%rust\\_\\%%".to_string())]);
}

#[test]
fn compiles_not_like_with_escape_clause() {
    let out = compile_filter_with_params("title !~ 'draft'").unwrap();
    assert_eq!(out.sql, "title NOT LIKE ? ESCAPE '\\'");
    assert_eq!(out.params, vec![Value::String("%draft%".to_string())]);
}

#[test]
fn compiles_any_match_equality_for_sqlite_json_arrays() {
    let out = compile_filter_with_params("tags ?= 'rust'").unwrap();
    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM json_each(tags) WHERE json_each.value = ?)"
    );
    assert_eq!(out.params, vec![Value::String("rust".to_string())]);
}

#[test]
fn compiles_any_match_like_for_sqlite_json_arrays() {
    let out = compile_filter_with_params("tags ?~ 'rust'").unwrap();
    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM json_each(tags) WHERE json_each.value LIKE ? ESCAPE '\\')"
    );
    assert_eq!(out.params, vec![Value::String("%rust%".to_string())]);
}

#[test]
fn rejects_too_many_expressions() {
    let input = (0..65)
        .map(|i| format!("f{i} = {i}"))
        .collect::<Vec<_>>()
        .join(" && ");
    let err = compile_filter(&input).unwrap_err();
    assert!(err.contains("expression limit"));
}

#[test]
fn rejects_unclosed_string() {
    let err = compile_filter("name = 'oops").unwrap_err();
    assert!(err.contains("unterminated string"));
}

#[test]
fn rejects_invalid_identifier() {
    let err = compile_filter("../secret = true").unwrap_err();
    assert!(err.contains("unexpected character"));
}
