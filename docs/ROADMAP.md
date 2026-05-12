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

## Next Sprint

1. Expand compatibility fixtures around placeholder-like wildcard cases.
2. Add single-value relation SQL rendering on top of `FilterPlan`.
3. Add named-parameter rendering so repeated function arguments do not need
   duplicated positional values.
4. Add multi-value relation traversal and any-match SQL rendering.
5. Add a Go/PocketBase comparison harness for the filter compatibility fixtures.
