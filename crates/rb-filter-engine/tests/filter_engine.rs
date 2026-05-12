use rb_filter_engine::{
    compile_filter, compile_filter_with_params, compile_filter_with_settings, FilterErrorKind,
    FilterSettings, Value,
};

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

#[test]
fn exposes_structured_error_kind_and_byte_position() {
    let err = compile_filter_with_params("name = 'Burak' && !").unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::UnexpectedCharacter);
    assert_eq!(err.position(), Some(18));
    assert!(err.to_string().contains("byte 18"));
}

#[test]
fn exposes_unterminated_string_position() {
    let err = compile_filter_with_params("name = 'oops").unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::UnterminatedString);
    assert_eq!(err.position(), Some(7));
}

#[test]
fn rejects_number_literals_without_fraction_digits() {
    let err = compile_filter_with_params("score = 1.").unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::InvalidNumber);
    assert_eq!(err.position(), Some(8));
}

#[test]
fn rejects_bare_minus_as_number_literal() {
    let err = compile_filter_with_params("score = -").unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::InvalidNumber);
    assert_eq!(err.position(), Some(8));
}

#[test]
fn accepts_negative_decimal_number_literal() {
    let out = compile_filter_with_params("score = -1.25").unwrap();
    assert_eq!(out.sql, "score = ?");
    assert_eq!(out.params, vec![Value::Number("-1.25".to_string())]);
}

#[test]
fn exposes_limit_error_without_position() {
    let err = compile_filter_with_settings(
        "name = 'Burak'",
        FilterSettings {
            max_input_bytes: 5,
            ..FilterSettings::default()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::InputLengthLimitExceeded);
    assert_eq!(err.position(), None);
}

#[test]
fn rejects_input_that_exceeds_configured_length() {
    let err = compile_filter_with_settings(
        "name = 'Burak'",
        FilterSettings {
            max_input_bytes: 5,
            ..FilterSettings::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("input length limit"));
}

#[test]
fn rejects_parentheses_that_exceed_configured_depth() {
    let err = compile_filter_with_settings(
        "(((name = 'Burak')))",
        FilterSettings {
            max_depth: 2,
            ..FilterSettings::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("depth limit"));
}
