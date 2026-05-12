# Rusty Base

**Rusty Base is a security-hardened Rust core experiment inspired by PocketBase's best idea: a backend should be small, self-hostable, and pleasant to extend.**

PocketBase is already a strong Go project. Rusty Base is not a blind rewrite. The goal is narrower and more serious: keep the product philosophy, then move only the high-risk/high-throughput engines into Rust.

## Why this exists

PocketBase proves that many teams do not need a distributed backend circus to ship useful software. One binary, SQLite, auth, files, realtime, and an admin UI is a brutally effective package.

The trade-off is that some subsystems become critical pressure points:

- access-rule and filter parsing decides who can see what;
- realtime fanout becomes expensive with many connected clients;
- image/file processing touches untrusted user input;
- SQLite transaction discipline defines the ceiling of the system;
- extension runtimes need capability boundaries if the backend is exposed to teams or customers.

Rusty Base explores those exact pressure points in Rust.

## Current status

This repository currently contains the first safe step:

- `crates/rb-filter-engine`: a typed, bounded filter/access-rule parser and SQL compiler prototype.

It is intentionally small and tested. It does **not** pretend to be PocketBase-compatible yet. Compatibility will be earned with golden tests, not marketing copy.

## Design principles

- **No big-bang rewrite.** Replace core engines one by one.
- **Security before cleverness.** Parsers, auth, file handling, and plugin execution must be bounded and fuzzable.
- **PocketBase ergonomics matter.** Self-hostable, simple, boring deployment remains the north star.
- **SQLite stays until evidence says otherwise.** Rust does not magically remove SQLite's single-writer model.
- **Tests first.** Every engine starts with behavior tests and compatibility fixtures.

## Planned Rust core engines

### 1. Filter/access-rule engine

Access rules are the security heart of a backend like this.

Target capabilities:

- parse PocketBase-style filter strings into a typed AST;
- enforce expression limits and recursion limits;
- compile only to parameterized SQL;
- expose normalized query plans for caching;
- fuzz malformed input aggressively;
- run golden compatibility tests against PocketBase-style rules.

Current crate: `rb-filter-engine`.

### 2. Media/file engine

File uploads and thumbnails process attacker-controlled bytes.

Target capabilities:

- image dimension and decoded-byte limits;
- safe thumbnail generation;
- metadata stripping;
- content-type verification by magic bytes;
- predictable worker/backpressure limits;
- optional WebP/AVIF output.

### 3. Realtime engine

Realtime starts simple, then suddenly becomes a fanout and backpressure problem.

Target capabilities:

- topic index for collection/record/wildcard subscriptions;
- bounded per-client queues;
- slow-client eviction policy;
- auth-state invalidation;
- optional Redis/NATS bridge for multi-instance deployments.

### 4. SQLite/storage guard layer

SQLite is good. The guard rails around it can be better.

Target capabilities:

- typed transaction state machine;
- prepared statement cache;
- query-cost and timeout policy;
- WAL checkpoint control;
- backup/restore integrity checks.

### 5. Capability-based extension runtime

Long-term direction: optional WASM/V8-style sandbox for extensions.

Target capabilities:

- declared permissions for DB, filesystem, HTTP, and environment access;
- CPU and memory limits;
- deterministic hook execution where possible;
- auditable extension manifests.

## Repository layout

```text
.
├── Cargo.toml
├── crates
│   └── rb-filter-engine
│       ├── Cargo.toml
│       ├── src/lib.rs
│       └── tests/filter_engine.rs
├── docs
│   └── ARCHITECTURE.md
└── README.md
```

## Quick start

```bash
cargo test
cargo fmt --check
cargo check --workspace
```

Example:

```rust
use rb_filter_engine::compile_filter_with_params;

let out = compile_filter_with_params("name = 'Burak' && score >= 10")?;
assert_eq!(out.sql, "name = ? AND score >= ?");
assert_eq!(out.params.len(), 2);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What works today

The first filter engine prototype supports:

- identifiers: `name`, `author.id`, `_verified`;
- string, number, boolean, and null literals;
- comparison operators: `=`, `!=`, `>`, `>=`, `<`, `<=`;
- contains-like operators: `~`, `!~`;
- PocketBase-style any-match operators for SQLite JSON arrays: `?=`, `?!=`, `?>`, `?>=`, `?<`, `?<=`, `?~`, `?!~`;
- logical operators: `&&`, `||`;
- parentheses;
- expression count limits;
- parameterized SQL output.

Example:

```text
id = null || (status = true && score >= 10)
```

compiles to:

```sql
id IS NULL OR (status = TRUE AND score >= ?)
```

## What does not work yet

Not implemented yet:

- full PocketBase `fexpr` grammar compatibility;
- `?=` / `?~` style any-match operators;
- relation expansion query planning;
- field resolver integration with collection schema;
- Go FFI bindings;
- fuzz harness;
- benchmark suite.

Those gaps are deliberate. This repo will grow through verified steps, not hand-wavy rewrites.

## Relationship to PocketBase

Rusty Base is inspired by PocketBase, but it is not affiliated with the PocketBase project.

The technical bet is this:

> Keep the single-binary, self-hosted backend experience. Move the security-sensitive and high-concurrency engines to Rust only where that materially improves correctness, control, or throughput.

## License

MIT
