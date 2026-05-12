use rb_filter_engine::{
    compile_filter_with_params, compile_filter_with_schema, CompileOutput, FieldKind, FieldSchema,
    FilterSchema, Value,
};
use serde::Deserialize;
use std::{env, fs, path::Path, process};

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [cmd] if cmd == "--help" || cmd == "help" => {
            print_help();
            Ok(())
        }
        [cmd, filter] if cmd == "compile-filter" => {
            let out = compile_filter_with_params(filter).map_err(|err| err.to_string())?;
            print_compile_output(&out);
            Ok(())
        }
        [cmd, schema_flag, schema_path, filter]
            if cmd == "compile-filter" && schema_flag == "--schema" =>
        {
            let schema = load_schema(schema_path)?;
            let out = compile_filter_with_schema(filter, &schema).map_err(|err| err.to_string())?;
            print_compile_output(&out);
            Ok(())
        }
        [] => {
            print_help();
            Ok(())
        }
        _ => Err(usage().to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct SchemaFile {
    fields: Vec<SchemaField>,
}

#[derive(Debug, Deserialize)]
struct SchemaField {
    name: String,
    kind: String,
}

fn load_schema(path: impl AsRef<Path>) -> Result<FilterSchema, String> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read schema '{}': {err}", path.display()))?;
    let schema: SchemaFile = serde_json::from_str(&contents)
        .map_err(|err| format!("failed to parse schema '{}': {err}", path.display()))?;

    let fields = schema
        .fields
        .into_iter()
        .map(|field| {
            let kind = parse_field_kind(&field.kind)?;
            Ok(FieldSchema::new(field.name, kind))
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(FilterSchema::new(fields))
}

fn parse_field_kind(kind: &str) -> Result<FieldKind, String> {
    match kind {
        "text" => Ok(FieldKind::Text),
        "number" => Ok(FieldKind::Number),
        "bool" => Ok(FieldKind::Bool),
        "datetime" => Ok(FieldKind::DateTime),
        "array" => Ok(FieldKind::Array),
        "relation" => Ok(FieldKind::Relation),
        other => Err(format!(
            "unknown field kind '{other}' (expected text, number, bool, datetime, array, or relation)"
        )),
    }
}

fn print_help() {
    println!("Rusty Base CLI");
    println!();
    println!("Usage:");
    println!("  rusty-base compile-filter \"name = 'Burak' && age >= 30\"");
    println!("  rusty-base compile-filter --schema schema.json \"age >= 30\"");
}

fn usage() -> &'static str {
    "usage: rusty-base compile-filter [--schema schema.json] \"name = 'Burak' && age >= 30\""
}

fn print_compile_output(out: &CompileOutput) {
    println!("sql: {}", out.sql);
    println!(
        "params: [{}]",
        out.params
            .iter()
            .map(format_value)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn format_value(value: &Value) -> String {
    match value {
        Value::String(value) => format!("string:{value}"),
        Value::Number(value) => format!("number:{value}"),
        Value::Bool(value) => format!("bool:{value}"),
        Value::Null => "null".to_string(),
    }
}
