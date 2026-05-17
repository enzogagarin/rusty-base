# PocketBase Compatibility Plan

This document defines how Rusty Base compares itself with PocketBase without
turning compatibility into guesswork.

## Target

- PocketBase source: `https://github.com/pocketbase/pocketbase`
- Target version: `v0.38.1`
- Last reviewed commit: `a286d28`
- Rusty Base audit head: `f913570`

The target should be bumped intentionally. When it changes, add fixtures for
new behavior before updating claims in `README.md` or `docs/ROADMAP.md`.

## Compatibility Principles

- Fixtures are the source of truth.
- Exact parity and intentional divergence should be recorded separately.
- Rusty Base-only extensions must not be counted as PocketBase compatibility.
- A missing fixture means "unknown", not "compatible".
- Security-sensitive differences must be explicit even if the public API shape
  appears similar.

## Current Fixture Coverage

Filter fixtures live under `fixtures/pocketbase/*.json` and are loaded by
`crates/rb-filter-engine/tests/compatibility_fixtures.rs`.

Current filter fixture groups:

- safe subset filters;
- denied filters;
- request-context filters.

Server behavior fixtures live under `fixtures/pocketbase/server/*.json` and are
loaded by `crates/rb-server/tests/pocketbase_server_fixtures.rs`.

Current server fixture groups:

- admin bootstrap;
- auth action tokens;
- auth context;
- batch;
- import/export;
- protected files;
- realtime;
- relation expand;
- settings;
- view collections.

## Known Strict-Parity Gaps

These should become comparison-harness scenarios before they are implemented:

- full PocketBase `fexpr` grammar, comments, placeholders, and wildcard edge
  cases;
- `@collection.*` cross-collection identifiers;
- broader relation and back-relation rule examples;
- relation-edge modifier behavior for nested fields;
- complete field type and field option parity;
- exact collection import/export/admin API response parity;
- unique and compound index execution semantics;
- OAuth2 provider matrix and callback edge cases;
- multipart batch requests with file uploads;
- realtime reconnect, auth-change, and SDK edge cases;
- protected-file behavior for view collections and hidden relation paths.

## Intentional Rusty Base Differences

These differences may remain, but each needs fixture coverage and user-facing
documentation:

- Rusty Base currently uses revocable opaque auth tokens, while PocketBase uses
  stateless JWT-style record tokens.
- Rusty Base exposes `POST /api/collections/:collection/auth-logout` as a
  server-side token revocation extension.
- Rusty Base stores current record fields in JSON-backed `_rb_records_*` tables
  instead of PocketBase's physical per-field columns.
- Rusty Base does not execute raw PocketBase collection index SQL. It preserves
  metadata and executes only Rust-planned safe SQLite indexes.
- Rusty Base file storage is currently SQLite-backed for the MVP rather than
  PocketBase-style local/S3 filesystem storage.
- Rusty Base view collection execution is guarded by an explicit SQLite
  authorizer and progress handler.

## Harness Shape

The first harness should be a local developer script, not a CI requirement.

Inputs:

- pinned PocketBase binary path or source checkout;
- Rusty Base server binary built from the current workspace;
- fixture directory;
- temporary data directories for both servers.

Flow:

1. Start PocketBase on a random local port with a temporary `pb_data` path.
2. Start Rusty Base on a random local port with a temporary SQLite database.
3. Bootstrap comparable superuser/admin state.
4. Apply fixture setup operations.
5. Execute fixture HTTP operations against both servers when both support the
   route.
6. Normalize volatile fields such as IDs, timestamps, tokens, and file suffixes.
7. Write an outcome object that records exact match, accepted difference,
   Rusty-only extension, or unsupported behavior.

The output should be JSON so it can later feed CI, docs, and a compatibility
matrix.

## Initial Harness Milestones

1. Add a script that verifies a PocketBase binary version and can start/stop it
   from a temporary data directory. Started in
   `scripts/pocketbase_compare.mjs`.
2. Add a Rusty Base server start helper that reuses the same random-port and
   cleanup code. Started in `scripts/pocketbase_compare.mjs`.
3. Port one server fixture category with low setup cost. Started with the
   settings access checks from `fixtures/pocketbase/server/settings.json`.
4. Port one filter fixture category to direct PocketBase comparison.
5. Add normalization helpers for timestamps, generated IDs, tokens, and
   response ordering.
6. Promote the harness to CI only after it can run without network access and
   without mutating repository state.

## Verification Commands

Current local compatibility checks:

```bash
node scripts/check_admin_js.mjs
cargo test --workspace
node scripts/admin_smoke.mjs
node scripts/admin_browser_smoke.mjs
```

Current harness smoke command:

```bash
node scripts/pocketbase_compare.mjs --pocketbase ./pocketbase
node scripts/pocketbase_compare.mjs --pocketbase ./pocketbase --fixture settings-access
```
