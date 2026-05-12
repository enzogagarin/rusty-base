use rb_filter_engine::{
    plan_filter_with_resolver, plan_filter_with_resolver_and_context, FieldKind, FieldResolver,
    FilterContext, FilterDateTime, FilterError, FilterErrorKind, PlanCompareOp, PlanLogicOp,
    PlannedExpr, PlannedOperand, RelationMultiplicity, RelationStep, RelationTraversal,
    ResolvedField, Value,
};

struct Resolver;

impl FieldResolver for Resolver {
    fn resolve_field(&self, field: &str) -> Result<ResolvedField, FilterError> {
        match field {
            "published" => Ok(ResolvedField::with_kind("posts.published", FieldKind::Bool)),
            "author.name" => Ok(
                ResolvedField::with_kind("author_records.name", FieldKind::Text)
                    .with_relation(author_relation("author.name", "name")),
            ),
            "author.created" => Ok(ResolvedField::with_kind(
                "author_records.created",
                FieldKind::DateTime,
            )
            .with_relation(author_relation("author.created", "created"))),
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

#[test]
fn plans_relation_metadata_without_changing_predicate_shape() {
    let relation = author_relation("author.name", "name");
    let plan = plan_filter_with_resolver(r#"author.name ~ "burak" && published = true"#, &Resolver)
        .unwrap();

    assert_eq!(plan.relations, vec![relation.clone()]);

    let PlannedExpr::Binary {
        left: first,
        op,
        right: second,
    } = plan.predicate
    else {
        panic!("expected binary predicate");
    };
    assert_eq!(op, PlanLogicOp::And);

    let PlannedExpr::Compare {
        left: relation_left,
        op,
        right: relation_right,
    } = *first
    else {
        panic!("expected relation comparison");
    };
    assert_eq!(op, PlanCompareOp::Like);
    assert_eq!(op.symbol(), "~");

    let PlannedOperand::Field(field) = relation_left else {
        panic!("expected left field");
    };
    assert_eq!(field.name, "author.name");
    assert_eq!(field.resolved.sql, "author_records.name");
    assert_eq!(field.relation(), Some(&relation));

    let PlannedOperand::Value(Value::String(value)) = relation_right else {
        panic!("expected right string");
    };
    assert_eq!(value, "burak");

    let PlannedExpr::Compare {
        left: root_left,
        op,
        right: root_right,
    } = *second
    else {
        panic!("expected root comparison");
    };
    assert_eq!(op, PlanCompareOp::Eq);
    assert!(matches!(root_left, PlannedOperand::Field(_)));
    assert_eq!(root_right, PlannedOperand::Value(Value::Bool(true)));
}

#[test]
fn deduplicates_repeated_relation_traversals() {
    let plan =
        plan_filter_with_resolver("author.name = 'Burak' || author.name = 'Enzo'", &Resolver)
            .unwrap();

    assert_eq!(plan.relations, vec![author_relation("author.name", "name")]);
}

#[test]
fn plans_function_operands_with_relation_fields() {
    let plan =
        plan_filter_with_resolver("strftime('%Y', author.created) = '2026'", &Resolver).unwrap();

    assert_eq!(
        plan.relations,
        vec![author_relation("author.created", "created")]
    );
    let relation = plan.relations.first().cloned();

    let PlannedExpr::Compare { left, op, right } = plan.predicate else {
        panic!("expected comparison");
    };
    assert_eq!(op, PlanCompareOp::Eq);

    let PlannedOperand::Function { name, args, kind } = left else {
        panic!("expected function operand");
    };
    assert_eq!(name, "strftime");
    assert_eq!(kind, FieldKind::Text);
    assert_eq!(args.len(), 2);
    assert_eq!(
        args[0],
        PlannedOperand::Value(Value::String("%Y".to_string()))
    );

    let PlannedOperand::Field(field) = &args[1] else {
        panic!("expected relation field argument");
    };
    assert_eq!(field.relation().cloned(), relation);
    assert_eq!(
        right,
        PlannedOperand::Value(Value::String("2026".to_string()))
    );
}

#[test]
fn plans_macros_with_relation_fields() {
    let context = FilterContext::new(FilterDateTime::utc(2026, 5, 12, 16, 30, 45, 123).unwrap());
    let plan =
        plan_filter_with_resolver_and_context("author.created >= @todayStart", &Resolver, context)
            .unwrap();

    assert_eq!(
        plan.relations,
        vec![author_relation("author.created", "created")]
    );

    let PlannedExpr::Compare { left, op, right } = plan.predicate else {
        panic!("expected comparison");
    };
    assert_eq!(op, PlanCompareOp::Gte);
    assert!(matches!(left, PlannedOperand::Field(_)));
    assert_eq!(
        right,
        PlannedOperand::Value(Value::String("2026-05-12 00:00:00.000Z".to_string()))
    );
}
