use rb_filter_engine::{
    compile_filter_with_params, compile_filter_with_schema_and_context,
    compile_filter_with_schema_and_settings, compile_filter_with_settings,
    parse_filter_with_settings, plan_filter_with_schema_and_settings, FieldKind, FieldSchema,
    FilterContext, FilterDateTime, FilterErrorKind, FilterSchema, FilterSettings, Value,
};
use std::{fs, path::PathBuf};

#[test]
fn parser_never_panics_on_generated_ascii_inputs() {
    let mut seed = 0x5EED_u64;

    for _ in 0..256 {
        let len = (next_u64(&mut seed) % 96) as usize;
        let input = generated_ascii(&mut seed, len);

        assert_no_compile_panic(&input);
    }
}

#[test]
fn filter_pipeline_never_panics_on_seed_corpus_inputs() {
    let schema = fuzz_schema();

    for input in seed_corpus_inputs() {
        assert_filter_pipeline_no_panic(&input, &schema);
    }
}

#[test]
fn filter_pipeline_never_panics_on_mutated_seed_corpus_inputs() {
    let corpus = seed_corpus_inputs();
    let schema = fuzz_schema();
    let mut seed = 0x00C0_FFEE_5EED_u64;

    for _ in 0..256 {
        let base = &corpus[(next_u64(&mut seed) as usize) % corpus.len()];
        let input = mutate_input(base, &mut seed);

        assert_filter_pipeline_no_panic(&input, &schema);
    }
}

#[test]
fn parser_never_panics_on_generated_unicodeish_inputs() {
    let alphabet = [
        'a',
        'Z',
        '_',
        '.',
        '\'',
        '"',
        '=',
        '!',
        '~',
        '?',
        '&',
        '|',
        '(',
        ')',
        '<',
        '>',
        '@',
        '\\',
        '\n',
        '\t',
        '\u{0000}',
        '\u{00A0}',
        '\u{2028}',
        '\u{2603}',
        '\u{1F680}',
    ];
    let mut seed = 0x0BAD_5EED_u64;

    for _ in 0..128 {
        let len = (next_u64(&mut seed) % 80) as usize;
        let input = (0..len)
            .map(|_| {
                let index = (next_u64(&mut seed) as usize) % alphabet.len();
                alphabet[index]
            })
            .collect::<String>();

        assert_no_compile_panic(&input);
    }
}

#[test]
fn deeply_nested_inputs_hit_depth_limit_without_panicking() {
    let input = format!("{}name = 'Burak'{}", "(".repeat(24), ")".repeat(24));
    let err = compile_filter_with_settings(
        &input,
        FilterSettings {
            max_depth: 8,
            ..FilterSettings::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.kind(), FilterErrorKind::DepthLimitExceeded);
}

#[test]
fn default_settings_remain_bounded_for_untrusted_filters() {
    let settings = FilterSettings::default();

    assert!(settings.max_expressions <= 128);
    assert!(settings.max_input_bytes <= 16 * 1024);
    assert!(settings.max_depth <= 32);
}

fn assert_no_compile_panic(input: &str) {
    let result = std::panic::catch_unwind(|| compile_filter_with_params(input));
    assert!(result.is_ok(), "parser panicked for input: {input:?}");
}

fn assert_filter_pipeline_no_panic(input: &str, schema: &FilterSchema) {
    let settings = fuzz_settings();

    let parsed = std::panic::catch_unwind(|| parse_filter_with_settings(input, settings));
    assert!(parsed.is_ok(), "parser panicked for input: {input:?}");

    let compiled = std::panic::catch_unwind(|| compile_filter_with_settings(input, settings));
    assert!(compiled.is_ok(), "compiler panicked for input: {input:?}");

    let schema_compiled = std::panic::catch_unwind(|| {
        compile_filter_with_schema_and_settings(input, schema, settings)
    });
    assert!(
        schema_compiled.is_ok(),
        "schema compiler panicked for input: {input:?}"
    );

    let planned =
        std::panic::catch_unwind(|| plan_filter_with_schema_and_settings(input, schema, settings));
    assert!(
        planned.is_ok(),
        "schema planner panicked for input: {input:?}"
    );

    let context_compiled = std::panic::catch_unwind(|| {
        compile_filter_with_schema_and_context(input, schema, fuzz_context())
    });
    assert!(
        context_compiled.is_ok(),
        "context compiler panicked for input: {input:?}"
    );
}

fn seed_corpus_inputs() -> Vec<String> {
    let mut inputs = inline_seed_corpus()
        .iter()
        .map(|input| (*input).to_string())
        .collect::<Vec<_>>();
    let mut file_inputs = file_seed_corpus();
    assert!(
        !file_inputs.is_empty(),
        "filter fuzz seed corpus must contain at least one input"
    );
    inputs.append(&mut file_inputs);
    inputs
}

fn inline_seed_corpus() -> &'static [&'static str] {
    &[
        "",
        "(",
        ")",
        "((((((((name = 'Burak'))))))))",
        "name = 'unterminated",
        "name = 'escaped \\' quote'",
        "name = \"unterminated",
        "name = \"escaped \\\" quote\"",
        "name = @request.auth.id && tags ?= 'rust'",
        "profile.tags ?= 'rust' && created >= @todayStart",
        "name = '\u{2603}'",
        "name = '\u{2028}\u{2029}'",
        "name = 'null\u{0000}byte'",
        "score = -",
        "score = 1.",
        "@request.body.items:each ?= 'x'",
        "geoDistance(office.lon, office.lat, 29.0, 41.0) < 10",
        "name = @request.cookies.session",
        "tags ?= 'rust' && && name = 'bad'",
        "((((((((((((((((((((name = 'too deep'))))))))))))))))))))",
    ]
}

fn file_seed_corpus() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/fuzz/filter_engine_seed_corpus.txt");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fuzz seed corpus {path:?}: {err}"));

    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(line.to_string())
            }
        })
        .collect()
}

fn fuzz_settings() -> FilterSettings {
    FilterSettings {
        max_expressions: 32,
        max_input_bytes: 512,
        max_depth: 12,
    }
}

fn fuzz_schema() -> FilterSchema {
    FilterSchema::new([
        FieldSchema::new("id", FieldKind::Text),
        FieldSchema::new("name", FieldKind::Text),
        FieldSchema::new("nickname", FieldKind::Text),
        FieldSchema::new("owner", FieldKind::Text),
        FieldSchema::new("published", FieldKind::Bool),
        FieldSchema::new("verified", FieldKind::Bool),
        FieldSchema::new("score", FieldKind::Number),
        FieldSchema::new("created", FieldKind::DateTime),
        FieldSchema::new("updated", FieldKind::DateTime),
        FieldSchema::new("tags", FieldKind::Array),
        FieldSchema::new("profile", FieldKind::Json),
        FieldSchema::new("author.id", FieldKind::Relation),
        FieldSchema::new("office.lon", FieldKind::Number),
        FieldSchema::new("office.lat", FieldKind::Number),
    ])
}

fn fuzz_context() -> FilterContext {
    FilterContext::new(FilterDateTime::utc(2026, 5, 12, 16, 30, 45, 123).unwrap())
        .with_auth_value("id", Value::String("user_123".to_string()))
        .with_query_value("search", Value::String("rust".to_string()))
        .with_body_value("title", Value::String("Draft".to_string()))
        .with_header_value("x-custom", Value::String("yes".to_string()))
}

fn next_u64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

fn generated_ascii(seed: &mut u64, len: usize) -> String {
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'-=!~?&|() <>,@\\\n\t";

    (0..len)
        .map(|_| {
            let index = (next_u64(seed) as usize) % ALPHABET.len();
            ALPHABET[index] as char
        })
        .collect()
}

fn mutate_input(input: &str, seed: &mut u64) -> String {
    let mut bytes = input.as_bytes().to_vec();
    let mutations = 1 + (next_u64(seed) % 8) as usize;

    for _ in 0..mutations {
        match next_u64(seed) % 4 {
            0 => {
                let index = mutation_index(seed, bytes.len() + 1);
                bytes.insert(index, mutation_byte(seed));
            }
            1 if !bytes.is_empty() => {
                let index = mutation_index(seed, bytes.len());
                bytes.remove(index);
            }
            2 if !bytes.is_empty() => {
                let index = mutation_index(seed, bytes.len());
                bytes[index] = mutation_byte(seed);
            }
            _ if !bytes.is_empty() => {
                let index = mutation_index(seed, bytes.len());
                let byte = bytes[index];
                bytes.insert(index, byte);
            }
            _ => bytes.push(mutation_byte(seed)),
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn mutation_index(seed: &mut u64, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        (next_u64(seed) as usize) % len
    }
}

fn mutation_byte(seed: &mut u64) -> u8 {
    const BYTES: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'\"-=!~?&|() <>,@\\/\n\t[]{}:$#\x00\xff";
    BYTES[(next_u64(seed) as usize) % BYTES.len()]
}
