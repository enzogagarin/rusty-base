use rb_filter_engine::{compile_filter_with_params, FilterSettings};

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
fn default_settings_remain_bounded_for_untrusted_filters() {
    let settings = FilterSettings::default();

    assert!(settings.max_expressions <= 128);
    assert!(settings.max_input_bytes <= 16 * 1024);
    assert!(settings.max_depth <= 32);
}

fn next_u64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

fn generated_ascii(seed: &mut u64, len: usize) -> String {
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'-=!~?&|() <>\\\n\t";

    (0..len)
        .map(|_| {
            let index = (next_u64(seed) as usize) % ALPHABET.len();
            ALPHABET[index] as char
        })
        .collect()
}
