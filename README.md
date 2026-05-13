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

This repository currently contains the first safe steps:

- `crates/rb-filter-engine`: a typed, bounded filter/access-rule parser and SQL compiler prototype.
- `crates/rb-server`: a minimal PocketBase-style HTTP/SQLite slice with
  collection metadata, record CRUD, and list/view filtering through
  `rb-filter-engine`.

It is intentionally small and tested. It does **not** pretend to be fully
PocketBase-compatible yet. Compatibility will be earned with golden tests, not
marketing copy.

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
│   ├── rb-cli
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── rb-filter-engine
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs
│   │   └── tests/filter_engine.rs
│   └── rb-server
│       ├── Cargo.toml
│       ├── src/lib.rs
│       ├── src/main.rs
│       └── tests/server_slice.rs
├── docs
│   ├── ARCHITECTURE.md
│   ├── FILTER_COMPATIBILITY.md
│   ├── RELATION_QUERY_PLAN.md
│   └── ROADMAP.md
└── README.md
```

## Quick start

```bash
cargo test
cargo fmt --check
cargo check --workspace
```

Run the current CLI smoke path:

```bash
cargo run -p rb-cli -- compile-filter "name = 'Burak' && age >= 30"
```

Expected output:

```text
sql: name = ? AND age >= ?
params: [string:Burak, number:30]
```

Build a local executable:

```bash
cargo build --release -p rb-cli
./target/release/rusty-base compile-filter "tags ?= 'rust'"
```

Run schema-aware validation from the CLI:

```bash
cat > schema.json <<'JSON'
{
  "fields": [
    { "name": "name", "kind": "text" },
    { "name": "age", "kind": "number" },
    { "name": "verified", "kind": "bool" },
    { "name": "tags", "kind": "array" },
    { "name": "profile", "kind": "json" }
  ]
}
JSON

cargo run -p rb-cli -- compile-filter --schema schema.json "age >= 30 && tags ?= 'rust'"
```

Schema-aware compilation resolves fields as quoted SQL identifiers:

```text
sql: "age" >= ? AND EXISTS (SELECT 1 FROM json_each("tags") WHERE json_each.value = ?)
params: [number:30, string:rust]
```

Supported schema field kinds: `text`, `number`, `bool`, `datetime`, `array`,
`json`, `relation`.

Run the current HTTP/SQLite slice:

```bash
cargo run -p rb-server -- serve ./rusty-base.db 127.0.0.1:8090
```

Create a collection and records with PocketBase-style paths:

```bash
curl -s http://127.0.0.1:8090/api/health

curl -s http://127.0.0.1:8090/api/collections \
  -H 'content-type: application/json' \
  -d '{"name":"users","type":"auth","fields":[{"name":"email","kind":"text"},{"name":"name","kind":"text"}]}'

curl -s http://127.0.0.1:8090/api/collections/users/records \
  -H 'content-type: application/json' \
  -d '{"email":"burak@example.com","name":"Burak","password":"correct horse","passwordConfirm":"correct horse"}'

TOKEN=$(curl -s http://127.0.0.1:8090/api/collections/users/auth-with-password \
  -H 'content-type: application/json' \
  -d '{"identity":"burak@example.com","password":"correct horse"}' \
  | jq -r '.token')

TOKEN=$(curl -s http://127.0.0.1:8090/api/collections/users/auth-refresh \
  -H "authorization: Bearer $TOKEN" \
  | jq -r '.token')

curl -s -X POST http://127.0.0.1:8090/api/collections/users/auth-logout \
  -H "authorization: Bearer $TOKEN"

curl -s http://127.0.0.1:8090/api/collections \
  -H 'content-type: application/json' \
  -d '{"name":"posts","fields":[{"name":"title","kind":"text"},{"name":"published","kind":"bool"},{"name":"owner","kind":"text"}],"listRule":"owner = @request.auth.id"}'

curl -s http://127.0.0.1:8090/api/collections/posts/records \
  -H 'content-type: application/json' \
  -d '{"title":"Rusty Base","published":true,"owner":"user_1"}'

curl -s 'http://127.0.0.1:8090/api/collections/posts/records?filter=published%20%3D%20true' \
  -H "authorization: Bearer $TOKEN"
```

`auth-logout` is a Rusty Base server-side token revocation extension. PocketBase
itself treats auth tokens as stateless and client logout usually means clearing
the local auth store.

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
- single-quoted and double-quoted string, number, boolean, and null literals;
- field-literal, field-field, and literal-field comparisons;
- function operands for `strftime(...)` and `geoDistance(...)`;
- PocketBase-style time macros such as `@now`, `@todayStart`, and `@year`;
- request-context identifiers for rule filters, including `@request.auth.*`,
  `@request.query.*`, `@request.headers.*`, `@request.body.*`,
  `@request.context`, and `@request.method`;
- `@request.*:isset` checks for rule filters, for example
  `@request.body.role:isset = false`;
- `@request.body.*:changed` checks for update rules, for example
  `@request.body.role:changed = false`;
- `:lower`, `:length`, and `:each` modifiers for bounded rule/filter
  expressions, including `@request.body.title:lower`, `tags:length`, and
  `tags:each`;
- comparison operators: `=`, `!=`, `>`, `>=`, `<`, `<=`;
- contains-like operators: `~`, `!~`;
- PocketBase-style any-match operators for SQLite JSON arrays: `?=`, `?!=`, `?>`, `?>=`, `?<`, `?<=`, `?~`, `?!~`;
- schema-aware JSON paths, for example `profile.name = "Burak"` compiles to
  SQLite `json_extract(...)`;
- logical operators: `&&`, `||`;
- parentheses;
- expression count limits;
- configurable input length and parentheses depth limits;
- optional schema-aware field/type/operator validation;
- a first relation-aware `FilterPlan` layer for resolver-provided traversal
  metadata;
- relation-plan SQL rendering for single-value and multi-value relation chains;
- parameterized SQL output.
- optional named-parameter SQL output for callers that want repeated values to
  share placeholders.

See `docs/FILTER_COMPATIBILITY.md` for the current PocketBase filter
compatibility matrix.

The first server slice supports:

- SQLite-backed collection metadata;
- per-collection record tables with JSON record data;
- `GET/POST /api/collections`;
- `GET /api/collections/meta/scaffolds` for PocketBase-style collection type
  scaffolds;
- `GET /api/collections/meta/export` as a Rusty Base import-ready metadata
  export helper;
- `PUT /api/collections/import` for bulk collection metadata import, accepting
  both `fields`/`kind` and PocketBase-style `schema`/`type` field input;
- `GET/PATCH /api/collections/:collection`, including safe metadata updates
  and record table renames;
- `DELETE /api/collections/:collection` and
  `DELETE /api/collections/:collection/truncate`;
- `GET/POST /api/collections/:collection/records`;
- `GET/PATCH/DELETE /api/collections/:collection/records/:id`;
- PocketBase-like list response shape with `page`, `perPage`, `totalItems`,
  `totalPages`, and `items`;
- first `?expand=relation,nested.relation` support for relation record
  responses;
- first `?fields=...` response projection support for records and expanded
  relations, including `*` and nested paths such as `expand.author.name`;
- `GET /api/collections/:collection/auth-methods` with the current
  password-auth method summary and response `fields` projection;
- `auth-with-password` and `auth-refresh` response `expand`/`fields` support,
  including response-level paths such as `record.expand.profile.bio`;
- verification and password-reset request/confirm auth flows backed by opaque
  action tokens;
- relation expand respects target collection view rules and omits hidden related
  records from the `expand` payload;
- PocketBase-like error response shape with `code`, `message`, and `data`;
- field-level validation `data` for the first auth and record form failures;
- list/view/create/update/delete rule predicates and client filter predicates
  compiled through
  `rb-filter-engine`;
- auth collections with Argon2 password hashing;
- PocketBase-style `email` collection field input, mapped to text-compatible
  filtering for now;
- `auth-with-password` login with opaque bearer tokens and expiration metadata;
- `auth-refresh` token rotation for authenticated auth records;
- `auth-logout` public bearer-token revocation;
- password-reset confirmation invalidates existing auth tokens for the record;
- bearer-token expiration checks before `@request.auth.*` is populated;
- `Authorization: Bearer ...` request context population for `@request.auth.*`;
- a temporary `x-rb-auth-id` compatibility header for tests and early manual
  experiments.

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
- full PocketBase modifier compatibility for uploaded files and relation-edge
  cases;
- cross-collection identifiers such as `@collection.*`;
- full PocketBase auth provider/settings parity beyond the current
  password/verification/reset token flow;
- exact PocketBase admin API/export compatibility;
- complete relation `expand` edge-case parity and relation permission fixtures;
- files, realtime, and admin UI;
- Go FFI bindings;
- `cargo-fuzz` corpus and CI fuzz target;
- benchmark suite.

Those gaps are deliberate. This repo will grow through verified steps, not hand-wavy rewrites.

## Relationship to PocketBase

Rusty Base is inspired by PocketBase, but it is not affiliated with the PocketBase project.

The technical bet is this:

> Keep the single-binary, self-hosted backend experience. Move the security-sensitive and high-concurrency engines to Rust only where that materially improves correctness, control, or throughput.

## License

MIT
