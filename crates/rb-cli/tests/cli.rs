use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

fn rusty_base() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rusty-base"))
}

#[test]
fn compiles_filter_with_schema_file() {
    let schema_path = write_temp_schema(r#"{"fields":[{"name":"age","kind":"number"}]}"#);

    let output = rusty_base()
        .args([
            "compile-filter",
            "--schema",
            schema_path.to_str().unwrap(),
            "age >= 30",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "sql: \"age\" >= ?\nparams: [number:30]\n");
}

#[test]
fn compiles_json_path_filter_with_schema_file() {
    let schema_path = write_temp_schema(r#"{"fields":[{"name":"profile","kind":"json"}]}"#);

    let output = rusty_base()
        .args([
            "compile-filter",
            "--schema",
            schema_path.to_str().unwrap(),
            "profile.name = 'Burak'",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "sql: json_extract(\"profile\", '$.name') = ?\nparams: [string:Burak]\n"
    );
}

#[test]
fn rejects_filter_that_violates_schema_file() {
    let schema_path = write_temp_schema(r#"{"fields":[{"name":"age","kind":"number"}]}"#);

    let output = rusty_base()
        .args([
            "compile-filter",
            "--schema",
            schema_path.to_str().unwrap(),
            "age ~ '3'",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(stderr(&output).contains("operator ~ is not allowed"));
}

#[test]
fn rejects_unknown_schema_field_kind() {
    let schema_path = write_temp_schema(r#"{"fields":[{"name":"age","kind":"integer"}]}"#);

    let output = rusty_base()
        .args([
            "compile-filter",
            "--schema",
            schema_path.to_str().unwrap(),
            "age >= 30",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown field kind 'integer'"));
}

fn write_temp_schema(contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rusty-base-schema-{}-{}.json",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&path, contents).unwrap();
    path
}

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = UNIQUE_SUFFIX.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{counter}")
}

static UNIQUE_SUFFIX: AtomicUsize = AtomicUsize::new(0);

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
