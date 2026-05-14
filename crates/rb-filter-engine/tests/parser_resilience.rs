use rb_filter_engine::{
    compile_filter_with_params, compile_filter_with_settings, FilterErrorKind, FilterSettings,
};

#[test]
fn parser_never_panics_on_generated_ascii_inputs() {
    let mut seed = 0x5EED_u64;

    for _ in 0..512 {
        let len = (next_u64(&mut seed) % 96) as usize;
        let input = generated_ascii(&mut seed, len);

        let result = std::panic::catch_unwind(|| compile_filter_with_params(&input));
        assert!(result.is_ok(), "parser panicked for input: {input:?}");
    }
}

#[test]
fn parser_never_panics_on_seed_corpus_inputs() {
    let inputs = [
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
    ];

    for input in inputs {
        assert_no_compile_panic(input);
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

    for _ in 0..256 {
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
