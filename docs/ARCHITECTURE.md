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

The workspace also includes `crates/rb-cli`, a small executable smoke runner that exposes the current engine from the command line:

```bash
cargo run -p rb-cli -- compile-filter "name = 'Burak' && age >= 30"
```
