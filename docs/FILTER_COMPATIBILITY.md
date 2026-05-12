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

## Operators

| Operator | Status | Notes |
| --- | --- | --- |
| `=`, `!=` | supported | Parameterized output; special handling for `null` and booleans. |
| `>`, `>=`, `<`, `<=` | supported | Schema-aware validation limits usage to compatible field kinds. |
| `~`, `!~` | partial | Uses `LIKE`/`NOT LIKE` with escaping. Field pattern operands and explicit `%` wildcard preservation are supported; full placeholder parity is still being expanded. |
| `?=`, `?!=`, `?>`, `?>=`, `?<`, `?<=`, `?~`, `?!~` | partial | Implemented for SQLite JSON arrays via `json_each`; relation multi-match SQL rendering is not implemented. |

## Field Resolution

| Capability | Status | Notes |
| --- | --- | --- |
| Schema-aware field validation | supported | Unknown fields are rejected. |
| Resolver abstraction | supported | `FieldResolver` can map filter identifiers to SQL fragments and field kinds. |
| Quoted schema identifiers | supported | `FilterSchema` resolves fields as quoted SQL identifier paths. |
| Relation expansion planning | partial | `FilterPlan` can carry relation traversal metadata and render single-value relation chains as correlated `EXISTS` SQL. Multi-value relation SQL is still planned. See `docs/RELATION_QUERY_PLAN.md`. |
| JSON path extraction | partial | Schema fields with kind `json` can resolve nested paths such as `profile.name` to SQLite `json_extract(...)`; object keys and numeric array indexes are covered. |

## Functions

| Function | Status | Notes |
| --- | --- | --- |
| `strftime(format, value, ...)` | partial | Supports a string format, an optional time value, and string modifiers. |
| `geoDistance(lonA, latA, lonB, latB)` | partial | Supports number literals and numeric fields. Relation multi-match behavior is not implemented. |

## Macros

| Macro group | Status | Notes |
| --- | --- | --- |
| Date/time values | supported | `@now`, `@yesterday`, `@tomorrow`, `@todayStart`, `@todayEnd`, `@monthStart`, `@monthEnd`, `@yearStart`, `@yearEnd`. |
| Date/time parts | supported | `@second`, `@minute`, `@hour`, `@day`, `@month`, `@weekday`, `@year`. |

## Safety

| Capability | Status | Notes |
| --- | --- | --- |
| Input byte limit | supported | Configurable through `FilterSettings`. |
| Expression count limit | supported | Configurable through `FilterSettings`. |
| Parentheses depth limit | supported | Configurable through `FilterSettings`. |
| Parameterized values | supported | User values are emitted as bound parameters. |
| Parser resilience smoke test | supported | Deterministic generated-input test exists. |
| Fuzz target | planned | `cargo-fuzz` target is still needed. |
| Benchmarks | planned | Normal and pathological filter benches are still needed. |
