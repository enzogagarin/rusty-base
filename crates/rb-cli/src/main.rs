use rb_filter_engine::{compile_filter_with_params, CompileOutput, Value};
use std::{env, process};

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
        [] => {
            print_help();
            Ok(())
        }
        _ => Err("usage: rusty-base compile-filter \"name = 'Burak' && age >= 30\"".to_string()),
    }
}

fn print_help() {
    println!("Rusty Base CLI");
    println!();
    println!("Usage:");
    println!("  rusty-base compile-filter \"name = 'Burak' && age >= 30\"");
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
