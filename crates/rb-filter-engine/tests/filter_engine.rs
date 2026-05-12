use rb_filter_engine::compile_filter;

#[test]
fn compiles_equality_with_bound_parameter() {
    let sql = compile_filter("name = 'Burak'").unwrap();
    assert_eq!(sql, "name = ?");
}

#[test]
fn compiles_boolean_precedence_with_parentheses() {
    let sql = compile_filter("id = null || (status = true && score >= 10)").unwrap();
    assert_eq!(sql, "id IS NULL OR (status = TRUE AND score >= ?)");
}

#[test]
fn compiles_like_with_escape_clause() {
    let sql = compile_filter("title ~ 'rust'").unwrap();
    assert_eq!(sql, "title LIKE ? ESCAPE '\\'");
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
