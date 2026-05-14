use rb_filter_engine::{
    compile_filter_with_schema, compile_filter_with_schema_and_context, FieldKind, FieldSchema,
    FilterContext, FilterDateTime, FilterSchema, Value,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::{fs, path::Path};

struct CompatibilityFixture {
    name: &'static str,
    filter: &'static str,
    expected_sql: &'static str,
    expected_params: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PocketBaseFixtureFile {
    name: String,
    #[serde(default = "default_fixture_context")]
    context: String,
    schema: Vec<PocketBaseFixtureField>,
    cases: Vec<PocketBaseFixtureCase>,
}

#[derive(Debug, Deserialize)]
struct PocketBaseFixtureField {
    name: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PocketBaseFixtureCase {
    name: String,
    filter: String,
    expected_sql: Option<String>,
    #[serde(default)]
    expected_params: Vec<PocketBaseFixtureParam>,
    expected_behavior: String,
    pocket_base_note: String,
}

#[derive(Debug, Deserialize)]
struct PocketBaseFixtureParam {
    #[serde(rename = "type")]
    param_type: String,
    #[serde(default)]
    value: JsonValue,
}

fn schema() -> FilterSchema {
    FilterSchema::new([
        FieldSchema::new("id", FieldKind::Text),
        FieldSchema::new("name", FieldKind::Text),
        FieldSchema::new("nickname", FieldKind::Text),
        FieldSchema::new("owner", FieldKind::Text),
        FieldSchema::new("status", FieldKind::Bool),
        FieldSchema::new("score", FieldKind::Number),
        FieldSchema::new("created", FieldKind::DateTime),
        FieldSchema::new("tags", FieldKind::Array),
        FieldSchema::new("profile", FieldKind::Json),
        FieldSchema::new("office.lon", FieldKind::Number),
        FieldSchema::new("office.lat", FieldKind::Number),
    ])
}

#[test]
fn pocketbase_json_fixture_set_matches_expected_behavior() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pocketbase");
    let mut paths = fs::read_dir(&fixtures_dir)
        .unwrap_or_else(|err| panic!("failed to read {fixtures_dir:?}: {err}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();

    assert!(!paths.is_empty(), "expected PocketBase fixture json files");

    for path in paths {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read fixture {path:?}: {err}"));
        let file = serde_json::from_str::<PocketBaseFixtureFile>(&text)
            .unwrap_or_else(|err| panic!("failed to parse fixture {path:?}: {err}"));
        let schema = pocketbase_fixture_schema(&file.schema);
        let context = pocketbase_fixture_context(&file.context);

        for case in file.cases {
            assert!(
                !case.pocket_base_note.trim().is_empty(),
                "{} / {} is missing a PocketBase behavior note",
                file.name,
                case.name
            );

            match case.expected_behavior.as_str() {
                "allowed" => {
                    let out = compile_filter_with_schema_and_context(
                        &case.filter,
                        &schema,
                        context.clone(),
                    )
                    .unwrap_or_else(|err| {
                        panic!("{} / {} should compile: {err}", file.name, case.name)
                    });
                    let expected_sql = case.expected_sql.as_deref().unwrap_or_else(|| {
                        panic!("{} / {} is missing expectedSql", file.name, case.name)
                    });
                    assert_eq!(out.sql, expected_sql, "{} / {}", file.name, case.name);
                    assert_eq!(
                        out.params,
                        pocketbase_fixture_params(&case.expected_params),
                        "{} / {}",
                        file.name,
                        case.name
                    );
                }
                "denied" => {
                    let result = compile_filter_with_schema_and_context(
                        &case.filter,
                        &schema,
                        context.clone(),
                    );
                    assert!(
                        result.is_err(),
                        "{} / {} should be denied",
                        file.name,
                        case.name
                    );
                }
                other => panic!(
                    "{} / {} has unknown expectedBehavior '{other}'",
                    file.name, case.name
                ),
            }
        }
    }
}

#[test]
fn pocketbase_safe_subset_golden_fixtures_compile() {
    let fixtures = vec![
        CompatibilityFixture {
            name: "basic equality",
            filter: "name = 'Burak'",
            expected_sql: "\"name\" = ?",
            expected_params: vec![Value::String("Burak".to_string())],
        },
        CompatibilityFixture {
            name: "double quoted text",
            filter: r#"name = "Burak""#,
            expected_sql: "\"name\" = ?",
            expected_params: vec![Value::String("Burak".to_string())],
        },
        CompatibilityFixture {
            name: "field to field equality",
            filter: "name = nickname",
            expected_sql: "\"name\" = \"nickname\"",
            expected_params: vec![],
        },
        CompatibilityFixture {
            name: "literal to field equality",
            filter: "'Burak' = name",
            expected_sql: "? = \"name\"",
            expected_params: vec![Value::String("Burak".to_string())],
        },
        CompatibilityFixture {
            name: "field to field contains",
            filter: "name ~ nickname",
            expected_sql: "\"name\" LIKE ('%' || \"nickname\" || '%') ESCAPE '\\'",
            expected_params: vec![],
        },
        CompatibilityFixture {
            name: "boolean grouping",
            filter: "id = null || (status = true && score >= 10)",
            expected_sql: "\"id\" IS NULL OR (\"status\" = TRUE AND \"score\" >= ?)",
            expected_params: vec![Value::Number("10".to_string())],
        },
        CompatibilityFixture {
            name: "contains text",
            filter: "name ~ 'rust_%'",
            expected_sql: "\"name\" LIKE ? ESCAPE '\\'",
            expected_params: vec![Value::String("rust_%".to_string())],
        },
        CompatibilityFixture {
            name: "contains text without explicit wildcard",
            filter: "name ~ 'rust_base'",
            expected_sql: "\"name\" LIKE ? ESCAPE '\\'",
            expected_params: vec![Value::String("%rust\\_base%".to_string())],
        },
        CompatibilityFixture {
            name: "datetime comparison",
            filter: r#"created >= "2026-01-01 00:00:00.000Z""#,
            expected_sql: "\"created\" >= ?",
            expected_params: vec![Value::String("2026-01-01 00:00:00.000Z".to_string())],
        },
        CompatibilityFixture {
            name: "array any-match",
            filter: "tags ?= 'rust'",
            expected_sql: "EXISTS (SELECT 1 FROM json_each(\"tags\") WHERE json_each.value = ?)",
            expected_params: vec![Value::String("rust".to_string())],
        },
        CompatibilityFixture {
            name: "json nested field equality",
            filter: "profile.name = 'Burak'",
            expected_sql: "json_extract(\"profile\", '$.name') = ?",
            expected_params: vec![Value::String("Burak".to_string())],
        },
        CompatibilityFixture {
            name: "json nested array any-match",
            filter: "profile.tags ?= 'rust'",
            expected_sql: "EXISTS (SELECT 1 FROM json_each(json_extract(\"profile\", '$.tags')) WHERE json_each.value = ?)",
            expected_params: vec![Value::String("rust".to_string())],
        },
        CompatibilityFixture {
            name: "strftime function",
            filter: "strftime('%Y', created) = '2026'",
            expected_sql: "strftime(?,\"created\") = ?",
            expected_params: vec![
                Value::String("%Y".to_string()),
                Value::String("2026".to_string()),
            ],
        },
        CompatibilityFixture {
            name: "geoDistance function",
            filter: "geoDistance(office.lon, office.lat, 1, 2) < 200",
            expected_sql: "(6371 * acos(cos(radians(\"office\".\"lat\")) * cos(radians(?)) * cos(radians(?) - radians(\"office\".\"lon\")) + sin(radians(\"office\".\"lat\")) * sin(radians(?)))) < ?",
            expected_params: vec![
                Value::Number("2".to_string()),
                Value::Number("1".to_string()),
                Value::Number("2".to_string()),
                Value::Number("200".to_string()),
            ],
        },
    ];

    for fixture in fixtures {
        let out = compile_filter_with_schema(fixture.filter, &schema())
            .unwrap_or_else(|err| panic!("{} failed: {err}", fixture.name));

        assert_eq!(out.sql, fixture.expected_sql, "{}", fixture.name);
        assert_eq!(out.params, fixture.expected_params, "{}", fixture.name);
    }
}

#[test]
fn pocketbase_macro_fixtures_compile_with_fixed_context() {
    let fixtures = vec![
        CompatibilityFixture {
            name: "@now",
            filter: "created >= @now",
            expected_sql: "\"created\" >= ?",
            expected_params: vec![Value::String("2026-05-12 16:30:45.123Z".to_string())],
        },
        CompatibilityFixture {
            name: "@todayStart",
            filter: "created >= @todayStart",
            expected_sql: "\"created\" >= ?",
            expected_params: vec![Value::String("2026-05-12 00:00:00.000Z".to_string())],
        },
        CompatibilityFixture {
            name: "@monthEnd",
            filter: "created <= @monthEnd",
            expected_sql: "\"created\" <= ?",
            expected_params: vec![Value::String("2026-05-31 23:59:59.999Z".to_string())],
        },
        CompatibilityFixture {
            name: "@year",
            filter: "score = @year",
            expected_sql: "\"score\" = ?",
            expected_params: vec![Value::Number("2026".to_string())],
        },
    ];

    for fixture in fixtures {
        let out =
            compile_filter_with_schema_and_context(fixture.filter, &schema(), fixed_context())
                .unwrap_or_else(|err| panic!("{} failed: {err}", fixture.name));

        assert_eq!(out.sql, fixture.expected_sql, "{}", fixture.name);
        assert_eq!(out.params, fixture.expected_params, "{}", fixture.name);
    }
}

#[test]
fn pocketbase_request_fixtures_compile_with_fixed_context() {
    let context = fixed_context()
        .with_auth_value("id", Value::String("user_123".to_string()))
        .with_auth_value("role", Value::String("staff".to_string()))
        .with_query_value("name", Value::String("Burak".to_string()))
        .with_body_value("title", Value::String("Rusty Base".to_string()));
    let fixtures = vec![
        CompatibilityFixture {
            name: "request auth ownership",
            filter: "owner = @request.auth.id",
            expected_sql: "\"owner\" = ?",
            expected_params: vec![Value::String("user_123".to_string())],
        },
        CompatibilityFixture {
            name: "request auth field",
            filter: "nickname = @request.auth.role",
            expected_sql: "\"nickname\" = ?",
            expected_params: vec![Value::String("staff".to_string())],
        },
        CompatibilityFixture {
            name: "request query field",
            filter: "name = @request.query.name",
            expected_sql: "\"name\" = ?",
            expected_params: vec![Value::String("Burak".to_string())],
        },
        CompatibilityFixture {
            name: "request auth presence",
            filter: r#"@request.auth.id != """#,
            expected_sql: "? != ?",
            expected_params: vec![
                Value::String("user_123".to_string()),
                Value::String(String::new()),
            ],
        },
        CompatibilityFixture {
            name: "request body isset modifier",
            filter: "@request.body.title:isset = true",
            expected_sql: "TRUE = TRUE",
            expected_params: vec![],
        },
    ];

    for fixture in fixtures {
        let out =
            compile_filter_with_schema_and_context(fixture.filter, &schema(), context.clone())
                .unwrap_or_else(|err| panic!("{} failed: {err}", fixture.name));

        assert_eq!(out.sql, fixture.expected_sql, "{}", fixture.name);
        assert_eq!(out.params, fixture.expected_params, "{}", fixture.name);
    }
}

fn fixed_context() -> FilterContext {
    FilterContext::new(FilterDateTime::utc(2026, 5, 12, 16, 30, 45, 123).unwrap())
}

fn default_fixture_context() -> String {
    "none".to_string()
}

fn pocketbase_fixture_schema(fields: &[PocketBaseFixtureField]) -> FilterSchema {
    FilterSchema::new(
        fields
            .iter()
            .map(|field| FieldSchema::new(field.name.clone(), pocketbase_fixture_kind(field))),
    )
}

fn pocketbase_fixture_kind(field: &PocketBaseFixtureField) -> FieldKind {
    match field.kind.as_str() {
        "array" => FieldKind::Array,
        "bool" => FieldKind::Bool,
        "datetime" => FieldKind::DateTime,
        "json" => FieldKind::Json,
        "number" => FieldKind::Number,
        "relation" => FieldKind::Relation,
        "text" => FieldKind::Text,
        other => panic!(
            "unknown fixture field kind '{}' for '{}'",
            other, field.name
        ),
    }
}

fn pocketbase_fixture_context(name: &str) -> FilterContext {
    match name {
        "none" => fixed_context(),
        "fixed_request" => fixed_context()
            .with_auth_value("id", Value::String("user_123".to_string()))
            .with_auth_value("role", Value::String("staff".to_string()))
            .with_query_value("name", Value::String("Burak".to_string()))
            .with_body_value("title", Value::String("Rusty Base".to_string())),
        other => panic!("unknown PocketBase fixture context '{other}'"),
    }
}

fn pocketbase_fixture_params(params: &[PocketBaseFixtureParam]) -> Vec<Value> {
    params
        .iter()
        .map(|param| match param.param_type.as_str() {
            "bool" => Value::Bool(
                param
                    .value
                    .as_bool()
                    .unwrap_or_else(|| panic!("fixture bool param must be bool: {param:?}")),
            ),
            "null" => Value::Null,
            "number" => Value::Number(
                param
                    .value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| param.value.as_i64().map(|value| value.to_string()))
                    .or_else(|| param.value.as_u64().map(|value| value.to_string()))
                    .or_else(|| param.value.as_f64().map(|value| value.to_string()))
                    .unwrap_or_else(|| {
                        panic!("fixture number param must be string or number: {param:?}")
                    }),
            ),
            "string" => Value::String(
                param
                    .value
                    .as_str()
                    .unwrap_or_else(|| panic!("fixture string param must be string: {param:?}"))
                    .to_string(),
            ),
            other => panic!("unknown fixture param type '{other}'"),
        })
        .collect()
}
