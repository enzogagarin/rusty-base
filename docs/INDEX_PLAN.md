# Index Plan

Rusty Base preserves PocketBase-style collection `indexes` metadata and executes
only the small subset it can safely plan itself.

That is intentional. PocketBase index strings target PocketBase's storage
layout, while Rusty Base records currently live in JSON-backed SQLite tables
named `_rb_records_*`. Running raw SQL from imported metadata would mix product
compatibility with storage execution and make future migrations brittle.

## Current Behavior

- Collection `indexes` are normalized, deduplicated, persisted, patched,
  imported, and exported.
- Raw index SQL is never executed directly.
- Simple non-unique single-field indexes such as
  `CREATE INDEX idx_posts_title ON posts (title)` are parsed as metadata and
  compiled into Rust-owned SQLite expression indexes on `_rb_records_posts`.
- Generated SQLite indexes use internal names like `_rb_idx_posts_*` instead of
  the imported raw index name.
- Unsupported indexes remain metadata-only but are visible in collection
  responses through `indexWarnings`.
- A server integration test asserts that the raw index name is not created and
  that the safe internal index is removed when metadata is patched away.

## Safe Execution Direction

Index execution should continue through Rust-owned plans:

- map known collection fields to safe SQLite expressions;
- quote all generated identifiers internally;
- use JSON expression indexes for scalar record fields, for example
  `json_extract(data, '$.title')`;
- skip relation arrays, file arrays, unique indexes, compound indexes, and
  nested JSON indexes until they have dedicated compatibility fixtures;
- keep execution idempotent with `CREATE INDEX IF NOT EXISTS`.

## Not Yet

- No raw PocketBase index SQL execution.
- No automatic generated-column migration yet.
- No unique-index behavior until record validation and conflict reporting match
  the server API shape.
- No compound indexes yet.
