# Rusty Base Roadmap

This roadmap tracks the path from the current filter-engine prototype to a
working Rust-powered PocketBase-style backend.

## Current Baseline

- Local repository: `https://github.com/enzogagarin/rusty-base`
- Main branch head: `c427081d740b1adfa0368e949fd459f24b08ddf8`
- Implemented crates:
  - `rb-filter-engine`: bounded filter/access-rule parser and SQL compiler
  - `rb-cli`: smoke CLI for filter compilation
- Verified locally:
  - `cargo fmt --check`
  - `cargo check --workspace`
  - `cargo test`

## Phase 1: Compatibility-Grade Filter Engine

Goal: make `rb-filter-engine` a trustworthy replacement candidate for
PocketBase's filter/access-rule compiler.

Deliverables:

- Add a golden compatibility fixture format.
- Capture PocketBase-style filter examples and expected behavior.
- Support double-quoted strings.
- Support operand-vs-operand expressions, not only `field op literal`.
- Introduce a `FieldResolver` abstraction so identifiers are resolved and
  quoted by the integration layer instead of emitted raw.
- Preserve parameterized SQL output.
- Document known compatibility gaps.
- Add property tests and fuzz targets for parser resilience.
- Add microbenchmarks for normal and pathological filters.

Exit criteria:

- A compatibility matrix exists.
- Golden tests cover operators, literals, grouping, null handling, LIKE,
  any-match operators, macros, and failure cases.
- Public compilation APIs can require schema/resolver validation for untrusted
  filters.

## Phase 2: PocketBase Integration Proof

Goal: prove that the Rust filter engine can power PocketBase-style rules from a
host application.

Deliverables:

- Add an FFI boundary crate or C ABI wrapper for the filter engine.
- Define stable request/response structs for:
  - filter input
  - schema/resolver metadata
  - SQL fragment
  - bound parameters
  - structured errors
- Build a minimal Go integration spike that calls the Rust engine.
- Compare outputs against PocketBase's current `tools/search` behavior.

Exit criteria:

- A Go test can compile a real PocketBase-style rule through Rust.
- Errors and parameters round-trip cleanly across the boundary.
- Integration overhead is measured.

## Phase 3: Rust-Powered PocketBase Slice

Goal: run a small PocketBase-like backend where at least one production-facing
path is powered by Rust.

Deliverables:

- Add a minimal HTTP app shell.
- Keep SQLite as the storage backend.
- Implement collection metadata and record CRUD for a narrow subset.
- Use `rb-filter-engine` for list/view access rules.
- Add basic auth context needed for rule evaluation.
- Add integration tests around record visibility and denied access.

Exit criteria:

- A demo binary can serve a collection.
- List/view rules are enforced through Rust.
- SQLite writes and reads work end to end.

## Phase 4: High-Risk Rust Engines

Goal: add Rust engines where safety, boundedness, or concurrency materially
improves the PocketBase model.

Candidate engines:

- `rb-realtime-engine`
  - topic index
  - bounded per-client queues
  - slow-client eviction
  - auth-state invalidation
- `rb-media-engine`
  - magic-byte content detection
  - image dimension and decoded-byte limits
  - thumbnail generation
  - metadata stripping
- `rb-storage-guard`
  - transaction state machine
  - SQLite connection policy
  - query timeout/cost guardrails
  - WAL checkpoint and backup checks

Exit criteria:

- Each engine has isolated tests, fuzz/property tests where relevant, and
  benchmarks before public integration.

## Phase 5: Developer Experience

Goal: keep the PocketBase promise: one small backend that is pleasant to run and
extend.

Deliverables:

- Single-binary build path.
- Clear CLI commands.
- Local admin/developer workflow.
- Migration story.
- Example app.
- Release artifacts for common platforms.

Exit criteria:

- A user can clone, run one command, create a collection, write a rule, and use
  CRUD APIs without understanding the internal engine split.

## Completed In First Continuation

- Added filter compatibility fixtures under `crates/rb-filter-engine/tests`.
- Added double-quoted string support.
- Split parsing from SQL rendering with public `FilterAst` APIs.
- Introduced a first `FieldResolver` trait.
- Made schema-aware compilation render quoted SQL identifier paths.
- Added the first compatibility matrix in `docs/FILTER_COMPATIBILITY.md`.
- Added the first operand-vs-operand parser/compiler path for field-field and
  literal-field comparisons.
- Aligned LIKE literal handling with PocketBase-style explicit `%` wildcard
  preservation.
- Promoted macro compatibility fixtures to passing tests with a fixed context.
- Added initial relation query-plan notes in `docs/RELATION_QUERY_PLAN.md`.
- Added first function operand support for `strftime(...)` and `geoDistance(...)`.
- Added PocketBase-style time macro support through `FilterContext`.
- Added the first explicit `FilterPlan` API with `PlannedExpr` and
  `PlannedOperand` types.
- Let resolvers attach relation traversal metadata through `ResolvedField`.
- Added relation-plan tests for predicate shape, deduplication, function
  operands, and fixed-context macros.
- Added schema-declared JSON field support with nested SQLite `json_extract(...)`
  rendering and JSON path compatibility fixtures.
- Added the first relation SQL renderer for single-value relation chains using
  correlated `EXISTS` predicates.
- Added multi-value relation traversal rendering with any-match `?` operators
  and default match-all predicates.
- Added named-parameter SQL output APIs so repeated values can share the same
  placeholder while existing positional output remains unchanged.
- Added the first request-context identifier support for rule filters:
  `@request.auth.*`, `@request.query.*`, `@request.headers.*`,
  `@request.body.*`, `@request.context`, and `@request.method`.
- Added `rb-server`, the first minimal HTTP/SQLite slice with collection
  metadata, record CRUD, PocketBase-style record routes, and list/view filters
  powered by `rb-filter-engine`.
- Added create/update/delete rule enforcement in `rb-server`, including
  incoming-record create checks and existing-record update/delete checks.
- Added a first auth MVP in `rb-server`: auth collections, Argon2 password
  hashing, `auth-with-password`, opaque bearer tokens, and real
  `@request.auth.*` population from authenticated records.
- Added token expiration metadata, bearer-token expiry checks, and
  `auth-refresh` rotation scoped to the requested auth collection.
- Added the first request field modifier: `@request.*:isset` compiles to
  boolean presence checks and is enforced by server create rules.
- Added `:lower` and `:length` modifier support for field expressions and
  request-body rule checks.
- Added public auth token revocation with
  `POST /api/collections/:collection/auth-logout` as a Rusty Base extension.
- Aligned the first API error response shape with PocketBase-style `code`,
  `message`, and `data` fields and changed failed password authentication to a
  generic 400 response.
- Added field-level validation `data` details for initial auth form and record
  form failures.
- Added `@request.body.*:changed` support for update rules by comparing
  submitted body fields with the existing record values.
- Added initial `:each` support for existing array-like fields and submitted
  `@request.body.*` arrays.
- Added `GET/PATCH /api/collections/:collection` for collection metadata
  updates, field list changes, rule changes, and safe record table renames.
- Added collection delete and truncate endpoints.
- Added `PUT /api/collections/import` for bulk collection metadata import,
  including `deleteMissing` handling for missing collections and JSON-backed
  record fields.
- Added collection metadata scaffolds and a Rusty Base import-ready metadata
  export helper.
- Added first relation `expand` support in `rb-server` responses, including
  single, multi, and nested relation expansion.
- Added first `fields` response projection support for records and expanded
  relation payloads.
- Added auth response `expand` and response-level `fields` projection support
  for `auth-with-password` and `auth-refresh`.
- Added relation expand coverage for target collection `viewRule` filtering so
  hidden related records are omitted from the `expand` payload.
- Added `GET /api/collections/:collection/auth-methods` with the current
  password-auth summary and response `fields` projection.
- Added PocketBase-style `email` collection field input, currently mapped to
  text-compatible filter behavior.
- Added verification request/confirm and password-reset request/confirm auth
  flows backed by short-lived opaque action tokens.
- Added password-reset token confirmation that updates the auth record password
  hash and invalidates existing auth tokens for the record.
- Added the first file-field MVP: PocketBase-style `file` fields,
  multipart record create/update uploads, SQLite-backed file blob storage,
  filename sanitization/suffixing, and `/api/files/:collection/:record/:file`
  downloads.
- Added PocketBase-style uploaded-file field modifiers for replace, append
  (`field+`), prepend (`+field`), delete-by-name (`field-`), and zero-value
  clearing.
- Added `/api/files/token` and protected `file` field support so protected
  downloads can satisfy target record `viewRule` checks through short-lived file
  tokens.
- Added `download=1` attachment headers for file responses.
- Added first real `thumb` generation for PNG/JPEG/GIF/WebP files with bounded
  source bytes/pixels and PocketBase-style size modes (`WxH`, `WxHt`, `WxHb`,
  `WxHf`, `0xH`, `Wx0`).
- Added file-field option validation for `maxSize`, `mimeTypes`, and configured
  `thumbs` so thumbnail requests only generate declared sizes.
- Added the first realtime MVP: `GET /api/realtime` SSE connect,
  `POST /api/realtime` subscriptions, and record create/update/delete event
  delivery filtered through collection `listRule` or record `viewRule`.

## Next Sprint

1. Add auth route coverage beyond password/refresh/reset: email change, OTP,
   and OAuth placeholders where useful.
2. Expand compatibility fixtures around placeholder-like wildcard cases.
3. Add a Go/PocketBase comparison harness for the filter compatibility fixtures.
4. Add relation compatibility fixtures copied from PocketBase-style access-rule
   examples.
5. Add file option parity and uploaded/protected-file compatibility fixtures
   around edge cases.
