use rb_filter_engine::{
    compile_ast, compile_filter, compile_filter_with_context, compile_filter_with_named_params,
    compile_filter_with_named_params_and_context, compile_filter_with_params,
    compile_filter_with_settings, parse_filter, FilterContext, FilterDateTime, FilterErrorKind,
    FilterSettings, NamedParam, Value,
};

#[test]
fn compiles_equality_with_bound_parameter() {
    let out = compile_filter_with_params("name = 'Burak'").unwrap();
    assert_eq!(out.sql, "name = ?");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn parses_and_compiles_as_separate_steps() {
    let ast = parse_filter("name = 'Burak' && score >= 10").unwrap();
    let out = compile_ast(&ast).unwrap();
    assert_eq!(out.sql, "name = ? AND score >= ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("Burak".to_string()),
            Value::Number("10".to_string())
        ]
    );
}

#[test]
fn compiles_field_to_field_comparisons() {
    let out = compile_filter_with_params("name = nickname").unwrap();
    assert_eq!(out.sql, "name = nickname");
    assert_eq!(out.params, vec![]);
}

#[test]
fn compiles_literal_to_field_comparisons() {
    let out = compile_filter_with_params("'Burak' = name").unwrap();
    assert_eq!(out.sql, "? = name");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn compiles_like_with_field_pattern_operand() {
    let out = compile_filter_with_params("title ~ summary").unwrap();
    assert_eq!(out.sql, "title LIKE ('%' || summary || '%') ESCAPE '\\'");
    assert_eq!(out.params, vec![]);
}

#[test]
fn compiles_like_with_literal_left_operand() {
    let out = compile_filter_with_params("'rusty base' ~ title").unwrap();
    assert_eq!(out.sql, "? LIKE ('%' || title || '%') ESCAPE '\\'");
    assert_eq!(out.params, vec![Value::String("rusty base".to_string())]);
}

#[test]
fn compiles_strftime_function_operand() {
    let out = compile_filter_with_params("strftime('%Y', created) = '2026'").unwrap();
    assert_eq!(out.sql, "strftime(?,created) = ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("%Y".to_string()),
            Value::String("2026".to_string())
        ]
    );
}

#[test]
fn compiles_geo_distance_function_operand() {
    let out =
        compile_filter_with_params("geoDistance(office.lon, office.lat, 1, 2) < 200").unwrap();
    assert_eq!(
        out.sql,
        "(6371 * acos(cos(radians(office.lat)) * cos(radians(?)) * cos(radians(?) - radians(office.lon)) + sin(radians(office.lat)) * sin(radians(?)))) < ?"
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
fn compiles_geo_distance_with_named_params_reusing_repeated_arguments() {
    let out = compile_filter_with_named_params("geoDistance(office.lon, office.lat, 1, 2) < 200")
        .unwrap();
    assert_eq!(
        out.sql,
        "(6371 * acos(cos(radians(office.lat)) * cos(radians(:p0)) * cos(radians(:p1) - radians(office.lon)) + sin(radians(office.lat)) * sin(radians(:p0)))) < :p2"
    );
    assert_eq!(
        out.params,
        vec![
            NamedParam {
                name: "p0".to_string(),
                value: Value::Number("2".to_string()),
            },
            NamedParam {
                name: "p1".to_string(),
                value: Value::Number("1".to_string()),
            },
            NamedParam {
                name: "p2".to_string(),
                value: Value::Number("200".to_string()),
            },
        ]
    );
}

#[test]
fn compiles_datetime_macros_with_fixed_context() {
    let context = fixed_context();
    let out =
        compile_filter_with_context("created >= @todayStart && created <= @todayEnd", context)
            .unwrap();
    assert_eq!(out.sql, "created >= ? AND created <= ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("2026-05-12 00:00:00.000Z".to_string()),
            Value::String("2026-05-12 23:59:59.999Z".to_string())
        ]
    );
}

#[test]
fn compiles_numeric_macros_with_fixed_context() {
    let out =
        compile_filter_with_context("year = @year && weekday = @weekday", fixed_context()).unwrap();
    assert_eq!(out.sql, "year = ? AND weekday = ?");
    assert_eq!(
        out.params,
        vec![
            Value::Number("2026".to_string()),
            Value::Number("2".to_string())
        ]
    );
}

#[test]
fn compiles_request_auth_context_identifiers() {
    let context = fixed_context()
        .with_auth_value("id", Value::String("user_123".to_string()))
        .with_auth_value("role", Value::String("staff".to_string()));

    let out = compile_filter_with_context(
        "owner = @request.auth.id && role = @request.auth.role",
        context,
    )
    .unwrap();

    assert_eq!(out.sql, "owner = ? AND role = ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("user_123".to_string()),
            Value::String("staff".to_string())
        ]
    );
}

#[test]
fn compiles_request_query_method_header_and_body_identifiers() {
    let context = fixed_context()
        .with_request_context("realtime")
        .with_request_method("GET")
        .with_query_value("page", Value::String("1".to_string()))
        .with_header_value("X-Token", Value::String("secret".to_string()))
        .with_body_value("title", Value::String("Rusty Base".to_string()));

    let out = compile_filter_with_context(
        "ctx = @request.context && method = @request.method && page = @request.query.page && token = @request.headers.x_token && title = @request.body.title",
        context,
    )
    .unwrap();

    assert_eq!(
        out.sql,
        "ctx = ? AND method = ? AND page = ? AND token = ? AND title = ?"
    );
    assert_eq!(
        out.params,
        vec![
            Value::String("realtime".to_string()),
            Value::String("GET".to_string()),
            Value::String("1".to_string()),
            Value::String("secret".to_string()),
            Value::String("Rusty Base".to_string())
        ]
    );
}

#[test]
fn treats_missing_request_values_as_empty_strings() {
    let out = compile_filter_with_context("owner = @request.auth.id", fixed_context()).unwrap();
    assert_eq!(out.sql, "owner = ?");
    assert_eq!(out.params, vec![Value::String(String::new())]);
}

#[test]
fn compiles_request_isset_modifier() {
    let context = fixed_context()
        .with_body_value("title", Value::String("Rusty Base".to_string()))
        .with_header_value("X-Token", Value::String("secret".to_string()));

    let out = compile_filter_with_context(
        "@request.body.title:isset = true && @request.body.role:isset = false && @request.headers.x_token:isset = true",
        context,
    )
    .unwrap();

    assert_eq!(out.sql, "TRUE = TRUE AND FALSE = FALSE AND TRUE = TRUE");
    assert_eq!(out.params, Vec::<Value>::new());
}

#[test]
fn compiles_request_lower_and_length_modifiers() {
    let context = fixed_context()
        .with_body_value("title", Value::String("Rusty Base".to_string()))
        .with_body_length("tags", 2);

    let out = compile_filter_with_context(
        "@request.body.title:lower = 'rusty base' && @request.body.tags:length >= 2",
        context,
    )
    .unwrap();

    assert_eq!(out.sql, "? = ? AND ? >= ?");
    assert_eq!(
        out.params,
        vec![
            Value::String("rusty base".to_string()),
            Value::String("rusty base".to_string()),
            Value::Number("2".to_string()),
            Value::Number("2".to_string())
        ]
    );
}

#[test]
fn reuses_named_params_for_repeated_request_values() {
    let context = fixed_context().with_auth_value("id", Value::String("user_123".to_string()));
    let out = compile_filter_with_named_params_and_context(
        "owner = @request.auth.id || editor = @request.auth.id",
        context,
    )
    .unwrap();

    assert_eq!(out.sql, "owner = :p0 OR editor = :p0");
    assert_eq!(
        out.params,
        vec![NamedParam {
            name: "p0".to_string(),
            value: Value::String("user_123".to_string()),
        }]
    );
}

fn fixed_context() -> FilterContext {
    FilterContext::new(FilterDateTime::utc(2026, 5, 12, 16, 30, 45, 123).unwrap())
}

#[test]
fn compiles_double_quoted_string_literals() {
    let out = compile_filter_with_params(r#"name = "Burak""#).unwrap();
    assert_eq!(out.sql, "name = ?");
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn compiles_escaped_double_quoted_string_literals() {
    let out = compile_filter_with_params(r#"title = "say \"hello\"""#).unwrap();
    assert_eq!(out.sql, "title = ?");
    assert_eq!(out.params, vec![Value::String("say \"hello\"".to_string())]);
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
    assert_eq!(out.params, vec![Value::String("rust_%".to_string())]);
}

#[test]
fn compiles_like_without_explicit_percent_as_contains_match() {
    let out = compile_filter_with_params("title ~ 'rust_draft'").unwrap();
    assert_eq!(out.sql, "title LIKE ? ESCAPE '\\'");
    assert_eq!(
        out.params,
        vec![Value::String("%rust\\_draft%".to_string())]
    );
}

#[test]
fn compiles_like_with_escaped_percent_as_literal_contains_match() {
    let out = compile_filter_with_params(r"title ~ 'rust\%'").unwrap();
    assert_eq!(out.sql, "title LIKE ? ESCAPE '\\'");
    assert_eq!(out.params, vec![Value::String("%rust\\%%".to_string())]);
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
    let out = compile_filter_with_params("tags ?~ 'rust_%'").unwrap();
    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM json_each(tags) WHERE json_each.value LIKE ? ESCAPE '\\')"
    );
    assert_eq!(out.params, vec![Value::String("rust_%".to_string())]);
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
fn rejects_unknown_request_identifier_scope() {
    let err = compile_filter_with_params("@request.cookies.token = 'abc'").unwrap_err();
    assert_eq!(err.kind(), FilterErrorKind::InvalidLiteral);
    assert!(err.to_string().contains("unknown request identifier"));
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
fn exposes_unterminated_double_quoted_string_position() {
    let err = compile_filter_with_params(r#"name = "oops"#).unwrap_err();
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
