use rb_filter_engine::{
    compile_filter_with_resolver, plan_filter_with_resolver, render_plan_sql,
    render_plan_sql_with_named_params, render_plan_sql_with_options, FieldKind, FieldResolver,
    FilterError, FilterErrorKind, NamedParam, RelationMultiplicity, RelationSqlOptions,
    RelationStep, RelationTraversal, ResolvedField, Value,
};

struct Resolver;

impl FieldResolver for Resolver {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "published" => Ok(ResolvedField::with_kind(
                "\"posts\".\"published\"",
                FieldKind::Bool,
            )),
            "author.name" => Ok(ResolvedField::with_kind(
                "\"author_records\".\"name\"",
                FieldKind::Text,
            )
            .with_relation(author_relation("author.name", "name"))),
            "author.nickname" => Ok(ResolvedField::with_kind(
                "\"author_records\".\"nickname\"",
                FieldKind::Text,
            )
            .with_relation(author_relation("author.nickname", "nickname"))),
            "author.created" => Ok(ResolvedField::with_kind(
                "\"author_records\".\"created\"",
                FieldKind::DateTime,
            )
            .with_relation(author_relation("author.created", "created"))),
            "org.owner.name" => Ok(ResolvedField::with_kind(
                "\"owner_records\".\"name\"",
                FieldKind::Text,
            )
            .with_relation(owner_relation("org.owner.name", "name"))),
            "collaborators.name" => Ok(ResolvedField::with_kind(
                "\"collaborator_records\".\"name\"",
                FieldKind::Text,
            )
            .with_relation(collaborators_relation("collaborators.name", "name"))),
            "collaborators.created" => Ok(ResolvedField::with_kind(
                "\"collaborator_records\".\"created\"",
                FieldKind::DateTime,
            )
            .with_relation(collaborators_relation("collaborators.created", "created"))),
            "team.members.name" => Ok(ResolvedField::with_kind(
                "\"member_records\".\"name\"",
                FieldKind::Text,
            )
            .with_relation(team_members_relation("team.members.name", "name"))),
            _ => Err(FilterError::with_kind(
                FilterErrorKind::UnknownField,
                format!("unknown field '{field}'"),
            )),
        }
    }
}

fn author_relation(field_path: &str, leaf_field: &str) -> RelationTraversal {
    RelationTraversal::new(
        field_path,
        [RelationStep::new(
            "posts",
            "author",
            "users",
            "id",
            RelationMultiplicity::Single,
        )],
        leaf_field,
    )
}

fn owner_relation(field_path: &str, leaf_field: &str) -> RelationTraversal {
    RelationTraversal::new(
        field_path,
        [
            RelationStep::new("posts", "org", "orgs", "id", RelationMultiplicity::Single),
            RelationStep::new("orgs", "owner", "users", "id", RelationMultiplicity::Single),
        ],
        leaf_field,
    )
}

fn collaborators_relation(field_path: &str, leaf_field: &str) -> RelationTraversal {
    RelationTraversal::new(
        field_path,
        [RelationStep::new(
            "posts",
            "collaborators",
            "users",
            "id",
            RelationMultiplicity::Multiple,
        )],
        leaf_field,
    )
}

fn team_members_relation(field_path: &str, leaf_field: &str) -> RelationTraversal {
    RelationTraversal::new(
        field_path,
        [
            RelationStep::new("posts", "team", "teams", "id", RelationMultiplicity::Single),
            RelationStep::new(
                "teams",
                "members",
                "users",
                "id",
                RelationMultiplicity::Multiple,
            ),
        ],
        leaf_field,
    )
}

#[test]
fn renders_single_value_relation_comparison_as_exists() {
    let plan = plan_filter_with_resolver(r#"author.name ~ "burak" && published = true"#, &Resolver)
        .unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"author\" AND \"__rb_rel_0_0\".\"name\" LIKE ? ESCAPE '\\') AND \"posts\".\"published\" = TRUE"
    );
    assert_eq!(out.params, vec![Value::String("%burak%".to_string())]);
}

#[test]
fn renders_single_value_relation_with_custom_root_alias() {
    let plan = plan_filter_with_resolver(r#"author.name = "Burak""#, &Resolver).unwrap();
    let out =
        render_plan_sql_with_options(&plan, RelationSqlOptions::with_root_alias("p")).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"p\".\"author\" AND \"__rb_rel_0_0\".\"name\" = ?)"
    );
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn renders_relation_plan_with_named_params_reusing_literals() {
    let plan = plan_filter_with_resolver(
        r#"author.name = "Burak" || author.nickname = "Burak""#,
        &Resolver,
    )
    .unwrap();
    let out = render_plan_sql_with_named_params(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"author\" AND \"__rb_rel_0_0\".\"name\" = :p0) OR EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"author\" AND \"__rb_rel_0_0\".\"nickname\" = :p0)"
    );
    assert_eq!(
        out.params,
        vec![NamedParam {
            name: "p0".to_string(),
            value: Value::String("Burak".to_string()),
        }]
    );
}

#[test]
fn renders_function_operands_inside_single_value_relation_exists() {
    let plan =
        plan_filter_with_resolver("strftime('%Y', author.created) = '2026'", &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"author\" AND strftime(?,\"__rb_rel_0_0\".\"created\") = ?)"
    );
    assert_eq!(
        out.params,
        vec![
            Value::String("%Y".to_string()),
            Value::String("2026".to_string())
        ]
    );
}

#[test]
fn renders_multiple_leaf_fields_from_same_single_value_relation() {
    let plan = plan_filter_with_resolver("author.name = author.nickname", &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"author\" AND \"__rb_rel_0_0\".\"name\" = \"__rb_rel_0_0\".\"nickname\")"
    );
    assert_eq!(out.params, vec![]);
}

#[test]
fn renders_nested_single_value_relation_chain() {
    let plan = plan_filter_with_resolver(r#"org.owner.name = "Burak""#, &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"orgs\" AS \"__rb_rel_0_0\", \"users\" AS \"__rb_rel_0_1\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"org\" AND \"__rb_rel_0_1\".\"id\" = \"__rb_rel_0_0\".\"owner\" AND \"__rb_rel_0_1\".\"name\" = ?)"
    );
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn renders_multi_value_relation_any_match_as_exists() {
    let plan = plan_filter_with_resolver(r#"collaborators.name ?= "Burak""#, &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE EXISTS (SELECT 1 FROM json_each(\"posts\".\"collaborators\") AS \"__rb_rel_0_0_each\" WHERE \"__rb_rel_0_0_each\".\"value\" = \"__rb_rel_0_0\".\"id\") AND \"__rb_rel_0_0\".\"name\" = ?)"
    );
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn direct_sql_compiler_does_not_render_relation_any_match() {
    let err =
        compile_filter_with_resolver(r#"collaborators.name ?= "Burak""#, &Resolver).unwrap_err();

    assert_eq!(err.kind(), FilterErrorKind::InvalidOperator);
    assert!(err.to_string().contains("any-match operator"));
}

#[test]
fn renders_multi_value_relation_like_any_match_as_exists() {
    let plan = plan_filter_with_resolver(r#"collaborators.name ?~ "burak""#, &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE EXISTS (SELECT 1 FROM json_each(\"posts\".\"collaborators\") AS \"__rb_rel_0_0_each\" WHERE \"__rb_rel_0_0_each\".\"value\" = \"__rb_rel_0_0\".\"id\") AND \"__rb_rel_0_0\".\"name\" LIKE ? ESCAPE '\\')"
    );
    assert_eq!(out.params, vec![Value::String("%burak%".to_string())]);
}

#[test]
fn renders_function_any_match_inside_multi_value_relation_exists() {
    let plan =
        plan_filter_with_resolver("strftime('%Y', collaborators.created) ?= '2026'", &Resolver)
            .unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE EXISTS (SELECT 1 FROM json_each(\"posts\".\"collaborators\") AS \"__rb_rel_0_0_each\" WHERE \"__rb_rel_0_0_each\".\"value\" = \"__rb_rel_0_0\".\"id\") AND strftime(?,\"__rb_rel_0_0\".\"created\") = ?)"
    );
    assert_eq!(
        out.params,
        vec![
            Value::String("%Y".to_string()),
            Value::String("2026".to_string())
        ]
    );
}

#[test]
fn renders_nested_multi_value_relation_any_match() {
    let plan = plan_filter_with_resolver(r#"team.members.name ?= "Burak""#, &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "EXISTS (SELECT 1 FROM \"teams\" AS \"__rb_rel_0_0\", \"users\" AS \"__rb_rel_0_1\" WHERE \"__rb_rel_0_0\".\"id\" = \"posts\".\"team\" AND EXISTS (SELECT 1 FROM json_each(\"__rb_rel_0_0\".\"members\") AS \"__rb_rel_0_1_each\" WHERE \"__rb_rel_0_1_each\".\"value\" = \"__rb_rel_0_1\".\"id\") AND \"__rb_rel_0_1\".\"name\" = ?)"
    );
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}

#[test]
fn renders_multi_value_relation_default_match_all_as_not_exists() {
    let plan = plan_filter_with_resolver(r#"collaborators.name = "Burak""#, &Resolver).unwrap();
    let out = render_plan_sql(&plan).unwrap();

    assert_eq!(
        out.sql,
        "NOT EXISTS (SELECT 1 FROM \"users\" AS \"__rb_rel_0_0\" WHERE EXISTS (SELECT 1 FROM json_each(\"posts\".\"collaborators\") AS \"__rb_rel_0_0_each\" WHERE \"__rb_rel_0_0_each\".\"value\" = \"__rb_rel_0_0\".\"id\") AND NOT (\"__rb_rel_0_0\".\"name\" = ?))"
    );
    assert_eq!(out.params, vec![Value::String("Burak".to_string())]);
}
