use rb_filter_engine::{
    compile_filter_with_schema_and_context, FieldKind, FieldSchema, FilterContext, FilterDateTime,
    FilterSchema, Value,
};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const ITERATIONS: usize = 20_000;

fn main() {
    let schema = schema();
    let context = context();
    let cases = [
        ("basic equality", "name = 'Burak'"),
        (
            "request ownership",
            "owner = @request.auth.id && published = true",
        ),
        (
            "json and array",
            "profile.tags ?= 'rust' && profile.name ~ 'Ada'",
        ),
        (
            "function operands",
            "geoDistance(office.lon, office.lat, 29.0, 41.0) < 10",
        ),
    ];

    println!("rb-filter-engine compile benchmark");
    println!("iterations: {ITERATIONS}");
    for (name, filter) in cases {
        let elapsed = bench_filter(filter, &schema, &context);
        print_result(name, elapsed);
    }

    let wide_or = wide_or_filter(32);
    let elapsed = bench_filter(&wide_or, &schema, &context);
    print_result("wide OR chain", elapsed);
}

fn bench_filter(filter: &str, schema: &FilterSchema, context: &FilterContext) -> Duration {
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let output = compile_filter_with_schema_and_context(filter, schema, context.clone())
            .unwrap_or_else(|err| panic!("benchmark filter failed: {filter}: {err}"));
        black_box(output);
    }
    start.elapsed()
}

fn print_result(name: &str, elapsed: Duration) {
    let nanos = elapsed.as_nanos() / ITERATIONS as u128;
    println!("{name:<20} {nanos:>10} ns/iter");
}

fn schema() -> FilterSchema {
    FilterSchema::new([
        FieldSchema::new("id", FieldKind::Text),
        FieldSchema::new("name", FieldKind::Text),
        FieldSchema::new("owner", FieldKind::Text),
        FieldSchema::new("published", FieldKind::Bool),
        FieldSchema::new("score", FieldKind::Number),
        FieldSchema::new("created", FieldKind::DateTime),
        FieldSchema::new("tags", FieldKind::Array),
        FieldSchema::new("profile", FieldKind::Json),
        FieldSchema::new("office.lon", FieldKind::Number),
        FieldSchema::new("office.lat", FieldKind::Number),
    ])
}

fn context() -> FilterContext {
    FilterContext::new(FilterDateTime::utc(2026, 5, 12, 16, 30, 45, 123).unwrap())
        .with_auth_value("id", Value::String("user_123".to_string()))
}

fn wide_or_filter(width: usize) -> String {
    (0..width)
        .map(|index| format!("name = 'user_{index}'"))
        .collect::<Vec<_>>()
        .join(" || ")
}
