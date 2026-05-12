# Filter Compatibility Matrix

This document tracks how `rb-filter-engine` compares with PocketBase's current
filter/access-rule syntax.

Status legend:

- `supported`: implemented and covered by tests.
- `partial`: implemented for a safe subset, with known semantic differences.
- `planned`: intentionally not implemented yet.

## Syntax

| Capability | Status | Notes |
| --- | --- | --- |
| Single-quoted strings | supported | Escapes are handled with `\`. |
| Double-quoted strings | supported | Added for PocketBase-style filter compatibility. |
| Numbers | supported | Integers and decimal literals; exponent notation is not implemented. |
| Booleans | supported | `true` and `false`. |
| Null | supported | Limited to `=` and `!=`. |
| `&&`, `||` | supported | `&&` binds tighter than `||`. |
| Parentheses | supported | Bounded by `FilterSettings::max_depth`. |
| Operand-vs-operand expressions | partial | Field, literal, boolean, number, null, and supported function operands can appear in comparisons. |
| Function operands | partial | `strftime(...)` and `geoDistance(...)` are implemented for the current SQL renderer. |
| Identifier macros | supported | Time macros such as `@now`, `@todayStart`, `@monthEnd`, and numeric macros such as `@year` are resolved from `FilterContext`. |
| Request context identifiers | partial | `@request.auth.*`, `@request.query.*`, `@request.headers.*`, `@request.body.*`, `@request.context`, and `@request.method` resolve from `FilterContext::request`. Request field modifiers are still planned. |
| Cross-collection identifiers | planned | `@collection.*` joins are not implemented yet. |

## Operators

| Operator | Status | Notes |
| --- | --- | --- |
| `=`, `!=` | supported | Parameterized output; special handling for `null` and booleans. |
| `>`, `>=`, `<`, `<=` | supported | Schema-aware validation limits usage to compatible field kinds. |
| `~`, `!~` | partial | Uses `LIKE`/`NOT LIKE` with escaping. Field pattern operands and explicit `%` wildcard preservation are supported; full placeholder parity is still being expanded. |
| `?=`, `?!=`, `?>`, `?>=`, `?<`, `?<=`, `?~`, `?!~` | partial | Implemented for SQLite JSON arrays via `json_each`; relation multi-match SQL rendering supports resolver-provided traversal metadata. |

## Field Resolution

| Capability | Status | Notes |
| --- | --- | --- |
| Schema-aware field validation | supported | Unknown fields are rejected. |
| Resolver abstraction | supported | `FieldResolver` can map filter identifiers to SQL fragments and field kinds. |
| Quoted schema identifiers | supported | `FilterSchema` resolves fields as quoted SQL identifier paths. |
| Relation expansion planning | partial | `FilterPlan` can carry relation traversal metadata and render single-value and multi-value relation chains as correlated SQL. Multi-value `?` operators use any-match semantics; non-`?` multi-value relation comparisons use a match-all `NOT EXISTS` shape. See `docs/RELATION_QUERY_PLAN.md`. |
| JSON path extraction | partial | Schema fields with kind `json` can resolve nested paths such as `profile.name` to SQLite `json_extract(...)`; object keys and numeric array indexes are covered. |

## Functions

| Function | Status | Notes |
| --- | --- | --- |
| `strftime(format, value, ...)` | partial | Supports a string format, an optional time value, and string modifiers. |
| `geoDistance(lonA, latA, lonB, latB)` | partial | Supports number literals and numeric fields. Named-parameter rendering reuses repeated argument placeholders. |

## Macros

| Macro group | Status | Notes |
| --- | --- | --- |
| Date/time values | supported | `@now`, `@yesterday`, `@tomorrow`, `@todayStart`, `@todayEnd`, `@monthStart`, `@monthEnd`, `@yearStart`, `@yearEnd`. |
| Date/time parts | supported | `@second`, `@minute`, `@hour`, `@day`, `@month`, `@weekday`, `@year`. |

## Request Context

| Identifier group | Status | Notes |
| --- | --- | --- |
| `@request.context` | supported | Defaults to `default` unless the caller sets another context. |
| `@request.method` | supported | Resolved as a string from `FilterContext::request.method`. |
| `@request.auth.*` | partial | Scalar values can be supplied through `FilterContext`; missing values resolve to an empty string for PocketBase-style unauthenticated checks such as `@request.auth.id != ""`. |
| `@request.query.*` | partial | Scalar query values can be supplied through `FilterContext`; missing values resolve to an empty string. |
| `@request.headers.*` | partial | Header keys are normalized to lowercase and `-` is replaced with `_`. |
| `@request.body.*` | partial | Scalar body values are supported; uploaded files and request modifiers are not implemented yet. |

## Safety

| Capability | Status | Notes |
| --- | --- | --- |
| Input byte limit | supported | Configurable through `FilterSettings`. |
| Expression count limit | supported | Configurable through `FilterSettings`. |
| Parentheses depth limit | supported | Configurable through `FilterSettings`. |
| Parameterized values | supported | User values are emitted as bound parameters. |
| Named parameters | supported | Named output APIs can reuse the same placeholder for repeated values, including repeated function arguments. Positional output remains the default. |
| Parser resilience smoke test | supported | Deterministic generated-input test exists. |
| Fuzz target | planned | `cargo-fuzz` target is still needed. |
| Benchmarks | planned | Normal and pathological filter benches are still needed. |
