use rb_server::{serve, ServerError};
use std::{env, process};

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), ServerError> {
    match args.as_slice() {
        [] => {
            print_help();
            Ok(())
        }
        [cmd] if cmd == "--help" || cmd == "help" => {
            print_help();
            Ok(())
        }
        [cmd, db_path] if cmd == "serve" => serve("127.0.0.1:8090", db_path),
        [cmd, db_path, addr] if cmd == "serve" => serve(addr, db_path),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!("Rusty Base server");
    println!();
    println!("Usage:");
    println!("  rb-server serve ./rusty-base.db");
    println!("  rb-server serve ./rusty-base.db 127.0.0.1:8090");
}
