# Rusty Base Architecture

Rusty Base is structured as a set of Rust engines, not a full PocketBase clone.

## North star

The project should preserve the operational shape that makes PocketBase attractive:

- one deployable backend;
- SQLite-first local persistence;
- simple auth/files/realtime primitives;
- extension points for product logic;
- self-hosted by default.

The Rust work targets subsystems where memory safety, explicit resource limits, typed state machines, and fuzzability are worth the integration cost.

## Engine boundaries

### rb-filter-engine

Responsibility:

- tokenize and parse user-facing filter/access-rule strings;
- build a typed AST;
- enforce expression limits;
- compile to parameterized SQL fragments;
- produce query plans for relation-aware access checks;
- render a narrow relation-aware SQL predicate for single-value and multi-value
  relation chains.

Module layout:

- `lexer.rs`: tokenization and bounded lexical errors;
- `parser.rs`: parser limits and AST construction;
- `ast.rs`: public AST/plan shapes and private parser operands;
- `schema.rs`: field schemas, relation traversal metadata, and resolver API;
- `error.rs`: structured filter error kinds and display;
- `compiler/sqlite.rs`: SQLite SQL compilation, planning, request macros, and
  relation-aware SQL rendering.

Non-responsibility:

- it does not execute SQL;
- it does not know HTTP;
- it does not own database connections;
- it does not decide business permissions by itself.

Expected integration shape:

```text
request context + collection schema + filter string
        ↓
rb-filter-engine
        ↓
typed query plan + parameterized SQL
        ↓
storage/query layer
```

### rb-server

Responsibility:

- provide the first PocketBase-style HTTP shell;
- store collection metadata in SQLite;
- store record data in per-collection SQLite tables;
- store the first uploaded file blobs in SQLite for the current MVP and serve
  them through `/api/files/:collection/:record/:filename`;
- support the first PocketBase-style file field mutations for replace, append,
  prepend, delete-by-name, and clearing;
- issue short-lived protected file tokens that populate `@request.auth.*` for
  protected file downloads;
- expose file download attachment headers for `download=1` requests;
- generate the first bounded image thumbnails for `thumb` requests against
  PNG/JPEG/GIF/WebP uploads;
- validate first file-field upload options (`maxSize`, `mimeTypes`, configured
  `thumbs`);
- keep an in-process realtime broker for SSE clients and publish first record
  create/update/delete events through collection or record subscriptions;
- support auth collections with Argon2 password hashes and expiring bearer
  tokens;
- support a first `_superusers` bootstrap flow, superuser-protected collection
  metadata management, and superuser rule bypass for record access;
- expose a first public auth-methods summary for auth collections, including
  password, OTP, MFA, OAuth2, and legacy SDK compatibility fields;
- persist normalized auth collection options for password identity fields,
  token durations, OTP, MFA, and OAuth2 provider metadata;
- store short-lived opaque auth action tokens for verification, password reset,
  email change, and OTP flows;
- rotate valid auth tokens through `auth-refresh`;
- revoke valid bearer tokens through `auth-logout`;
- return PocketBase-like API error bodies with `code`, `message`, and `data`;
- include field-level validation `data` for initial auth and record form errors;
- update collection metadata and rename record tables transactionally;
- list collection metadata with PocketBase-style pagination, sorting, filtering,
  and response projection;
- expose collection type scaffolds for admin UI style flows;
- import collection metadata in bulk with optional deletion of missing
  collections and fields;
- export import-ready collection metadata through a Rusty Base helper route;
- expand first-level and nested relation records into the PocketBase-style
  `expand` response object;
- project record, auth, and expanded relation responses with first-pass
  `fields` query support;
- omit expanded relation records that fail the target collection `viewRule`;
- translate collection schemas into `rb-filter-engine` field resolvers;
- apply list/view/create/update/delete filters with request context.

Non-responsibility:

- it is not a complete PocketBase API surface yet;
- its server-side `auth-logout` route is a Rusty Base extension rather than a
  PocketBase-compatible route;
- it does not implement a broad OAuth provider matrix, a full admin API/admin
  UI, admin UI OAuth setting flows, or full auth settings yet;
- it does not own full file field option parity, S3/local filesystem adapters,
  complete realtime parity, admin UI, protected-file edge parity, or migration
  compatibility yet.

Current integration shape:

```text
HTTP request + SQLite store + collection schema
        ↓
rb-server
        ↓
rb-filter-engine for filter/rule predicates
        ↓
parameterized SQLite query
```

### rb-media-engine, planned

Responsibility:

- safe image inspection;
- thumbnail generation;
- upload validation;
- metadata stripping;
- worker limits.

### rb-realtime-engine, planned

Responsibility:

- subscription registry;
- topic index;
- backpressure;
- per-client queue policy;
- distributed fanout adapters.

### rb-storage-guard, planned

Responsibility:

- SQLite connection policy;
- transaction scheduling;
- prepared statement cache;
- WAL/checkpoint policy;
- backup/restore integrity guardrails.

## Compatibility strategy

Compatibility must be proven with tests:

1. collect PocketBase-style filter fixtures;
2. record expected SQL behavior and access decisions;
3. run the same fixtures against Rusty Base;
4. add fuzz and property tests for malformed input.

No compatibility claim should be made before this exists.

## Security posture

Every engine should have:

- hard input limits;
- no string-concatenated user values in SQL;
- parser recursion/expression limits;
- explicit error messages for invalid input;
- fuzz targets before public use;
- benchmarks for pathological cases.

## First milestone

The first milestone is a hardened filter compiler that supports a useful subset:

- equality and inequality;
- numeric comparisons;
- boolean/null handling;
- LIKE/NOT LIKE with escaping;
- PocketBase-style any-match operators over SQLite JSON arrays;
- first relation-aware SQL rendering for single-value and multi-value relation
  chains;
- schema-aware JSON field path extraction;
- `&&`, `||`, and parentheses;
- expression, input length, and parentheses depth limits;
- schema-aware field/type/operator validation;
- bound parameters, including optional named-parameter output.

That is implemented in `crates/rb-filter-engine`.

The workspace also includes:

- `crates/rb-cli`, a small executable smoke runner that exposes the current
  filter engine from the command line.
- `crates/rb-server`, a first HTTP/SQLite slice with collection metadata,
  record CRUD, and list/view filtering.

```bash
cargo run -p rb-cli -- compile-filter "name = 'Burak' && age >= 30"
cargo run -p rb-server -- serve ./rusty-base.db 127.0.0.1:8090
```
