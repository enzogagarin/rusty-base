# Index Plan

Rusty Base currently preserves PocketBase-style collection `indexes` metadata,
but it does not execute raw index SQL.

That is intentional. PocketBase index strings target PocketBase's storage
layout, while Rusty Base records currently live in JSON-backed SQLite tables
named `_rb_records_*`. Running raw SQL from imported metadata would mix product
compatibility with storage execution and make future migrations brittle.

## Current Behavior

- Collection `indexes` are normalized, deduplicated, persisted, patched,
  imported, and exported.
- Raw index SQL is metadata-only.
- A server integration test asserts that persisted index metadata does not
  create a SQLite index.

## Safe Execution Direction

The first executable index pass should compile a small Rust-owned plan instead
of running imported SQL directly:

- map known collection fields to safe SQLite expressions;
- quote all generated identifiers internally;
- use JSON expression indexes for scalar record fields, for example
  `json_extract(data, '$.title')`;
- skip relation arrays, file arrays, and nested JSON indexes until they have
  dedicated compatibility fixtures;
- make execution idempotent by checking SQLite metadata before applying a plan.

## Not Yet

- No raw PocketBase index SQL execution.
- No automatic generated-column migration yet.
- No unique-index behavior until record validation and conflict reporting match
  the server API shape.
