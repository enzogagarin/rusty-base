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
- Added `GET /api/collections/:collection/auth-methods` with password, OTP,
  MFA, OAuth2, legacy SDK compatibility fields, and response `fields`
  projection.
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
- Added PocketBase-style record value modifiers for number add/subtract and
  multi-select/relation append, prepend, and remove operations.
- Added the first realtime MVP: `GET /api/realtime` SSE connect,
  `POST /api/realtime` subscriptions, and record create/update/delete event
  delivery filtered through collection `listRule` or record `viewRule`.
- Added PocketBase-style email change request/confirm auth flow, including
  current-password confirmation and stale auth/file token invalidation.
- Added PocketBase-style `request-otp` and `auth-with-otp` MVP backed by
  short-lived one-time action tokens.
- Added persisted auth collection options for password identities, token
  durations, OTP, MFA, and OAuth2 provider metadata.
- Added the first `auth-with-oauth2` provider profile account-linking path,
  including external account persistence, existing-record matching by email, and
  auth response `meta` output.
- Added remote OAuth2 code exchange through configured token/userinfo endpoints,
  with initial GitHub and Google endpoint presets sharing the same account-link
  core.
- Added PocketBase-style OAuth2 `auth-methods` output with generated state,
  PKCE code verifier/challenge data, provider auth URLs, preset GitHub/Google
  scopes, and custom provider scopes.
- Added the first `_superusers` bootstrap/guard path: collection metadata routes
  require a superuser token after bootstrap, `_superusers` records are protected
  after the first superuser exists, and superuser auth bypasses record rules.
- Added PocketBase-style paginated collection list output with collection
  metadata filtering, sorting, and response `fields` projection.
- Added superuser-only `GET/PATCH /api/settings` with persisted
  PocketBase-style meta/logs/batch/smtp/s3/backups/rate limit/trusted proxy
  sections, secret redaction, and batch `enabled`/`maxRequests`/`maxBodySize`
  enforcement.
- Added persisted collection IDs, collection metadata lookup/update/truncate/
  delete by ID or name, collection `id` filtering/sorting, and `fields`
  projection on collection create/view/update responses.
- Added record route lookup by collection ID or name and PocketBase-style
  `collectionId` metadata on record/auth responses.
- Added persisted collection field IDs, PocketBase-style `type` field metadata
  responses, export/import field ID preservation, and backwards-compatible
  `kind` input parsing.
- Added first common/text/select/url/editor/autodate field option metadata
  parity for
  `required`, `hidden`, `system`, `presentable`, `primaryKey`, `min`, `max`,
  `pattern`, `autogeneratePattern`, `values`, relation `minSelect`,
  `maxSelect`/`cascadeDelete`, domain allow/deny lists, `onCreate`/`onUpdate`,
  and JSON/editor `maxSize`, including import/export preservation.
- Added record create/update enforcement for `required`, text `min`/`max`/
  common regex-like `pattern` constraints, email shape, basic bool/number/array
  shapes, URL shape/domain options, PocketBase-style datetime format, geoPoint
  lon/lat shape, number `min`/`max`, select `values`/`maxSelect`, JSON
  required/`maxSize`, editor `maxSize`, custom autodate stamping, relation
  `minSelect`/`maxSelect`, and relation target existence against the final
  record state.
- Added PocketBase-style UTC `created`/`updated` timestamps for collection and
  record responses.
- Added first `url` and `editor` field parity, including PocketBase `date`
  type output, legacy `datetime` input compatibility, URL domain restrictions,
  and editor `maxSize` validation.
- Added first `geoPoint` field parity with lon/lat validation and nested
  `location.lat`/`location.lon` filter support.
- Added PocketBase-style response-only collection system fields (`id`,
  `created`, `updated`) for admin UI compatibility, represented as text and
  autodate metadata without persisting them into user schemas.
- Added collection `indexes` metadata persistence across create/patch/import/
  export responses for admin UI compatibility, while deferring safe SQLite index
  execution to a storage-specific pass.
- Added relation `minSelect` metadata and create/update validation, including
  missing and too-few relation checks.
- Added relation `cascadeDelete` metadata and recursive dependent-record
  cleanup when a referenced target record is deleted.
- Added a first read-only `view` collection MVP with persisted `viewQuery`,
  SELECT-backed list/view records, filter/sort support through `rb-filter-engine`,
  and mutation endpoints rejected as read-only.
- Split the former 10k+ line `rb-server/src/lib.rs` MVP monolith into focused
  `server/*` modules, kept `lib.rs` as the public re-export layer, raised the
  declared workspace Rust minimum to 1.88 for the locked `image 0.25.x`
  dependency graph, and cleaned the workspace so fmt/check/clippy/test pass.
- Pinned CI to Rust 1.88.0, documented the exact fmt/clippy/test checks, and
  cleaned the README smoke curl flow so auth examples keep a valid bearer token
  until logout.
- Split auth internals into password, token, action-token, OAuth2, OTP,
  superuser, and impersonation modules while preserving the existing public
  `rb-server` re-export surface.
- Hardened the first `viewQuery` validation pass with an internal-table denylist
  for auth tokens, auth action tokens, settings, and stored files, and documented
  that a future SQLite authorizer hook is still needed for table-level execution
  safety.

## Next Sprint

1. Expand remaining field-type parity beyond the currently supported
   bool/number/text/email/url/editor/date/autodate/geoPoint/select/json/
   relation/file subset.
2. Harden view collection compatibility around field inference, relation expand
   edge cases, and SQLite-authorizer-backed query execution safety.
3. Design safe SQLite index execution for JSON-backed record tables instead of
   running raw PocketBase index SQL strings directly.
4. Expand OAuth2 provider presets and harden callback validation around
   redirect URLs and provider-specific response edge cases.
5. Expand compatibility fixtures around placeholder-like wildcard cases.
6. Add a Go/PocketBase comparison harness for the filter compatibility fixtures.
7. Add relation compatibility fixtures copied from PocketBase-style access-rule
   examples.
8. Add file option parity and uploaded/protected-file compatibility fixtures
   around edge cases.
