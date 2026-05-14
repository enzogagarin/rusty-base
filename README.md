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
- `fixtures/pocketbase`: JSON compatibility fixtures that record input filters,
  expected SQL, expected params, server API behavior, and PocketBase notes.

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
│   │   ├── src/ast.rs
│   │   ├── src/compiler/sqlite.rs
│   │   ├── src/error.rs
│   │   ├── src/lexer.rs
│   │   ├── src/lib.rs
│   │   ├── src/parser.rs
│   │   ├── src/schema.rs
│   │   └── tests/filter_engine.rs
│   └── rb-server
│       ├── Cargo.toml
│       ├── src/lib.rs
│       ├── src/server
│       │   ├── admin
│       │   │   └── index.html
│       │   ├── admin.rs
│       │   ├── app.rs
│       │   ├── auth
│       │   │   ├── action_tokens.rs
│       │   │   ├── impersonation.rs
│       │   │   ├── oauth.rs
│       │   │   ├── otp.rs
│       │   │   ├── password.rs
│       │   │   ├── superusers.rs
│       │   │   └── tokens.rs
│       │   ├── auth.rs
│       │   ├── collections.rs
│       │   ├── files.rs
│       │   ├── http.rs
│       │   ├── realtime.rs
│       │   ├── records.rs
│       │   ├── settings.rs
│       │   ├── storage.rs
│       │   └── validation.rs
│       ├── src/main.rs
│       └── tests/server_slice.rs
├── docs
│   ├── ARCHITECTURE.md
│   ├── FILTER_COMPATIBILITY.md
│   ├── INDEX_PLAN.md
│   ├── RELATION_QUERY_PLAN.md
│   └── ROADMAP.md
├── fixtures
│   └── pocketbase
│       ├── filter_denied.json
│       ├── filter_request_context.json
│       └── filter_safe_subset.json
└── README.md
```

## Quick start

Rusty Base currently requires Rust 1.88 or newer. The locked dependency graph
uses `image 0.25.x`, whose current transitive stack includes crates that require
Cargo/Rust support newer than 1.84. Local development is pinned with
`rust-toolchain.toml` to match CI.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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

Run the local filter-engine benchmark smoke:

```bash
cargo run -p rb-filter-engine --example bench_filter --release
```

Run the local server benchmark smoke:

```bash
cargo run -p rb-server --example bench_server --release
```

Run the PocketBase-style blog demo script:

```bash
./examples/blog.sh
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

Supported schema field kinds: `text`, `select`, `number`, `bool`, `datetime`,
`array`, `json`, `relation`.

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

USER_ID=$(curl -s http://127.0.0.1:8090/api/collections/users/records \
  -H 'content-type: application/json' \
  -d '{"email":"burak@example.com","name":"Burak","password":"correct horse","passwordConfirm":"correct horse"}' \
  | jq -r '.id')

TOKEN=$(curl -s http://127.0.0.1:8090/api/collections/users/auth-with-password \
  -H 'content-type: application/json' \
  -d '{"identity":"burak@example.com","password":"correct horse"}' \
  | jq -r '.token')

TOKEN=$(curl -s http://127.0.0.1:8090/api/collections/users/auth-refresh \
  -H "authorization: Bearer $TOKEN" \
  | jq -r '.token')

curl -s http://127.0.0.1:8090/api/collections \
  -H 'content-type: application/json' \
  -d '{"name":"posts","fields":[{"name":"title","kind":"text"},{"name":"published","kind":"bool"},{"name":"owner","kind":"text"}],"listRule":"owner = @request.auth.id"}'

curl -s http://127.0.0.1:8090/api/collections/posts/records \
  -H 'content-type: application/json' \
  -d "{\"title\":\"Rusty Base\",\"published\":true,\"owner\":\"$USER_ID\"}"

curl -s 'http://127.0.0.1:8090/api/collections/posts/records?filter=published%20%3D%20true' \
  -H "authorization: Bearer $TOKEN"

curl -s -X POST http://127.0.0.1:8090/api/collections/users/auth-logout \
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

- embedded admin UI shell at `GET /admin` and PocketBase-style `GET /_/`;
- SQLite-backed collection metadata;
- per-collection record tables with JSON record data;
- PocketBase-style UTC `created`/`updated` timestamps for collection and
  record responses;
- `GET/POST /api/collections`, with collection list pagination, filtering,
  sorting, and response `fields` projection;
- persisted collection IDs with collection metadata lookup/update/truncate/delete
  by either ID or name, plus `fields` projection on create/view/update
  responses;
- record list/view/create/update/delete routes resolve collection IDs or names
  and return PocketBase-style `collectionId` plus `collectionName`;
- persisted collection field IDs with PocketBase-style `type` field metadata
  output while still accepting legacy Rusty Base `kind` input;
- collection responses include PocketBase-style response-only `id`, `created`,
  and `updated` system field metadata, with `created`/`updated` represented as
  `autodate` fields for admin UI style flows;
- first common/text/select/url/editor/autodate field option metadata parity for
  `required`, `hidden`, `system`, `presentable`, `primaryKey`, `min`, `max`,
  `pattern`, `autogeneratePattern`, `values`, relation `minSelect`,
  `maxSelect`/`cascadeDelete`, domain allow/deny lists, `onCreate`/`onUpdate`,
  and JSON/editor `maxSize`;
- record create/update enforcement for `required`, text `min`/`max`/common
  regex-like `pattern` constraints, email shape, basic bool/number/array
  shapes, URL shape/domain options, PocketBase-style datetime format, geoPoint
  lon/lat shape, number `min`/`max`, select `values`/`maxSelect`, JSON
  required/`maxSize`, editor `maxSize`, custom autodate stamping, relation
  `minSelect`/`maxSelect`, and relation target existence, evaluated against
  the final record state on updates;
- PocketBase-style record value modifiers for number add/subtract and
  multi-select/relation append, prepend, and remove operations;
- relation `cascadeDelete` support for deleting dependent records atomically
  when their referenced target record is deleted;
- `GET /api/collections/meta/scaffolds` for PocketBase-style collection type
  scaffolds;
- `GET /api/collections/meta/export` as a Rusty Base import-ready metadata
  export helper;
- `PUT /api/collections/import` for bulk collection metadata import, accepting
  both `fields`/`kind` and PocketBase-style `schema`/`type` field input;
- collection `indexes` metadata is persisted, patched, imported, exported, and
  planned into safe SQLite expression indexes for simple scalar fields without
  executing raw PocketBase index SQL; unsupported metadata-only indexes are
  surfaced through collection `indexWarnings`;
- first read-only `view` collection MVP with persisted `viewQuery`, list/view
  records backed by a single SELECT query, filter/sort support through the Rust
  filter engine, rejected record mutations, an internal-table denylist, and a
  SQLite authorizer plus progress/column guard for bounded view query execution;
- `GET/PATCH /api/collections/:collection`, including safe metadata updates
  and record table renames;
- `DELETE /api/collections/:collection` and
  `DELETE /api/collections/:collection/truncate`;
- first `_superusers` bootstrap and bearer-token guard for collection metadata
  management after a superuser exists;
- `GET/PATCH /api/settings` for superuser-managed PocketBase-style app
  settings, including persisted meta/logs/batch/smtp/s3/backups/rate limit and
  trusted proxy sections with secret redaction;
- `GET/POST /api/collections/:collectionIdOrName/records`;
- `GET/PATCH/DELETE /api/collections/:collectionIdOrName/records/:id`;
- JSON `POST /api/batch` for transactional record create/update/upsert/delete
  request batches, honoring the persisted batch `enabled`, `maxRequests`, and
  `maxBodySize` settings;
- `GET /api/realtime` SSE connect and `POST /api/realtime` subscriptions for
  first record create/update/delete events;
- PocketBase-style `file` collection field input, multipart record
  create/update uploads, and `GET /api/files/:collection/:record/:filename`
  downloads backed by the first SQLite file store;
- `POST /api/files/token` and protected `file` fields, with short-lived file
  tokens populating `@request.auth.*` for protected downloads;
- `download=1` file responses with `Content-Disposition: attachment`;
- first `thumb` image thumbnail generation for PNG/JPEG/GIF/WebP inputs,
  gated by configured file-field `thumbs`, including crop, top/bottom crop,
  fit, width-only, and height-only formats;
- first file-field `maxSize` and `mimeTypes` upload validation;
- PocketBase-style uploaded-file modifiers for replace, append, prepend,
  delete-by-name, and zero-value clearing on file fields;
- PocketBase-style number, select, and relation record value modifiers;
- PocketBase-like list response shape with `page`, `perPage`, `totalItems`,
  `totalPages`, and `items`;
- record list `skipTotal` support to skip count queries and return `-1`
  counters;
- record list `sort` support for system fields, collection fields, nested JSON
  paths, `@random`, and `@rowid`;
- first `?expand=relation,nested.relation` support for relation record
  responses;
- first `?fields=...` response projection support for records and expanded
  relations, including `*` and nested paths such as `expand.author.name`;
- server compatibility fixtures for admin bootstrap, auth action tokens, auth
  context, batch requests, import/export, settings, view collections, relation
  expand, realtime, and protected file access under
  `fixtures/pocketbase/server`;
- `GET /api/collections/:collection/auth-methods` with password, OTP, MFA,
  OAuth2 provider auth URLs, PKCE verifier/challenge data, and legacy SDK
  compatibility fields plus response `fields` projection;
- persisted auth collection options for password identities, token durations,
  OTP, MFA, and OAuth2 provider metadata across create/update/import/export;
- `auth-with-password`, `auth-with-otp`, and `auth-refresh` response
  `expand`/`fields` support, including response-level paths such as
  `record.expand.profile.bio`;
- `auth-with-oauth2` request validation, provider profile account-linking, and
  the first remote token/userinfo callback exchange path;
- superuser-only `impersonate` endpoint for auth records, including custom
  duration and nonrenewable impersonation tokens;
- `request-otp` and `auth-with-otp` backed by short-lived one-time auth action
  tokens;
- verification, password-reset, and email-change request/confirm auth flows
  backed by opaque action tokens;
- relation expand respects target collection view rules and omits hidden related
  records from the `expand` payload;
- PocketBase-like error response shape with `code`, `message`, and `data`;
- field-level validation `data` for the first auth and record form failures;
- list/view/create/update/delete rule predicates and client filter predicates
  compiled through
  `rb-filter-engine`;
- `_superusers` auth tokens bypass record access rules and protect subsequent
  `_superusers` record management;
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
- full PocketBase modifier compatibility for relation-edge cases;
- full file field option parity, S3/local filesystem adapters, large-file
  streaming, and deeper protected-file compatibility beyond the current
  SQLite-backed file MVP;
- cross-collection identifiers such as `@collection.*`;
- full PocketBase auth provider/settings parity beyond the current persisted
  settings surface, password/verification/reset token flow, and first OAuth2
  path;
- exact PocketBase admin API/export compatibility;
- complete relation `expand` edge-case parity and relation permission fixtures;
- complete realtime parity, including subscription options, SDK edge cases, and
  production keepalive behavior;
- complete admin UI beyond the current embedded shell;
- Go FFI bindings;
- full `cargo-fuzz` corpus and CI fuzz target;
- full Criterion benchmark suite beyond the current lightweight benchmark
  examples.

Those gaps are deliberate. This repo will grow through verified steps, not hand-wavy rewrites.

## Relationship to PocketBase

Rusty Base is inspired by PocketBase, but it is not affiliated with the PocketBase project.

The technical bet is this:

> Keep the single-binary, self-hosted backend experience. Move the security-sensitive and high-concurrency engines to Rust only where that materially improves correctness, control, or throughput.

## License

MIT
