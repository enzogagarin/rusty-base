# Relation Query Plan Notes

PocketBase filter compatibility cannot stop at SQL fragment rendering. Relation
fields need a query-planning layer that can describe joins, subqueries, and
multi-match constraints before SQL is emitted.

## Problem

The current `rb-filter-engine` output is a single parameterized SQL fragment.
That is enough for plain collection fields and SQLite JSON arrays, but not for
PocketBase-style relation filters such as:

```text
author.name = "Burak"
posts.tags ?= "rust"
orgs.office.lon > 10
```

Those expressions may require:

- resolving a filter identifier through collection metadata;
- joining related record tables;
- producing subqueries for multi-value relations;
- applying access rules for expanded relation records;
- keeping bound parameters separate from SQL structure.

## Proposed Shape

Add a lowering step between AST parsing and SQL rendering:

```text
FilterAst
  -> ResolvedFilterPlan
  -> SqlRenderOutput
```

`ResolvedFilterPlan` should contain:

- the root predicate expression;
- field operands resolved to typed field references;
- required joins or subqueries;
- parameter values;
- relation traversal metadata;
- warnings for compatibility fallbacks.

## Resolver Responsibilities

A future relation-aware resolver should answer:

- Does this identifier exist?
- Is it a root field, JSON path, relation field, or request-context field?
- What field kind does it have?
- Does it require joining another table?
- If relation traversal is multi-value, what multi-match query shape is needed?
- Which SQL alias owns the rendered identifier?

The existing `FieldResolver` trait is intentionally small. It is a first safe
step, not the final relation-planning API.

## Current Implementation

`rb-filter-engine` now exposes a first explicit plan layer:

- `plan_filter(...)` and `plan_ast(...)` lower parsed filters into `FilterPlan`.
- `PlannedExpr` preserves the predicate shape without emitting SQL.
- `ResolvedField` can carry optional `RelationTraversal` metadata.
- Relation traversals are deduplicated in `FilterPlan::relations`.
- Existing SQL compilation and CLI behavior remain unchanged.

This is deliberately not a join renderer yet. The host application or a future
renderer still owns alias selection, access-rule composition, and the final SQL
shape for single-value and multi-value relations.

## Non-Goals For The Current Filter Engine

- Owning database connections.
- Executing access checks.
- Loading collection schemas from storage.
- Deciding HTTP authorization policy.

The engine should stay a parser, validator, and planner. The host application
should provide schema and request context, then execute the final query.

## Implementation Order

1. Keep plain field resolution stable with `FieldResolver`. Done.
2. Add explicit plan structs without changing the CLI behavior. Done.
3. Add JSON-path field support.
4. Add single-value relation SQL rendering.
5. Add multi-value relation traversal and any-match SQL rendering.
6. Add compatibility fixtures copied from PocketBase relation-rule examples.
