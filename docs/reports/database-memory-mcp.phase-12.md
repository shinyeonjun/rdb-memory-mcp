# Database Memory MCP Phase 12 Report

## Status

Complete. Added MCP typed tools level 1 for SQLite-backed graph metadata:

- `index_database`
- `list_databases`
- `list_tables`
- `describe_table`
- `find_table`
- `find_column`
- `impact_analysis`
- `trace_relationships`
- `schema_diff`

`graph_stats` (Phase 11) was left in place. `cargo test` passes, and a manual end-to-end JSON-RPC smoke test of 6 of the 10 tools against the real compiled binary succeeds.

## Changed Files

- `crates/database-memory-core/src/graph_store.rs`: added `GraphStore::list_snapshots`.
- `crates/database-memory-mcp/src/lib.rs`: request/result types and MCP tool methods for all Phase 12 tools; reuses core SQLite introspection, graph builder, impact analysis, relationship tracing, and schema diff functions; small MCP-local copies of the CLI's table/column lookup and describe-table helpers; in-process tests.
- `docs/reports/database-memory-mcp.phase-12.md`

## Verification Command And Result

Codex's sandbox could not run `cargo` at all (`spawnSync cargo ENOENT` via its Node fallback; normal shell blocked by the missing sandbox helper) and left this phase unverified. Verifying outside the sandbox with network access:

```powershell
cargo test
```

First run found a real test bug: `mcp_lists_finds_and_describes_graph_metadata` panicked with `index out of bounds: the len is 0 but the index is 0` at the assertion on `description.foreign_keys.outbound[0]`. Root cause: the test built its fixture with `snapshot("sample", true, false)` (`include_orders: true, include_fk: false`) but then asserted an outbound foreign key exists. Fixed by correcting the fixture call to `snapshot("sample", true, true)` (include the FK) — a one-line test fix, no production code changed.

After the fix:

```text
running 6 tests (database-memory-cli)   ... 6 passed
running 21 tests (database-memory-core) ... 21 passed
running 4 tests (database-memory-mcp)   ... 4 passed
  test tests::graph_stats_missing_cache_returns_zero ... ok
  test tests::graph_stats_counts_indexed_snapshots ... ok
  test tests::mcp_lists_finds_and_describes_graph_metadata ... ok
  test tests::mcp_runs_impact_trace_and_schema_diff ... ok

cargo build: zero warnings across all four crates (including database-memory-mcp bin)
```

Manual end-to-end smoke test: launched `target/debug/database-memory-mcp.exe`, sent a real JSON-RPC `initialize` handshake, then sequential `tools/call` requests (waiting for each response before sending the next, matching real MCP client behavior) against a real SQLite fixture (2 tables, 1 FK, 1 index):

- `tools/list`: all 10 tools registered with correct JSON schemas.
- `index_database`: indexed 2 tables, 5 columns, 3 constraints, 1 index.
- `list_databases`: returned the `sqlite:sample` snapshot.
- `list_tables`: returned `["orders", "users"]`.
- `describe_table` (orders): correct columns, PK, outbound FK to `users`, index.
- `impact_analysis` (users, both, depth 3): correct grouped BFS result reaching columns/tables/constraints/indexes.
- `find_column` ("user"): correctly found `orders.user_id`.

(An earlier attempt that fired all `tools/call` requests without waiting for responses showed them resolve out of order — `index_database` completing last, so the dependent read-tools saw an empty/missing cache. That is expected concurrent-request behavior for an async stdio server, not a product bug; real MCP clients send one request at a time and wait for the response.)

## Deviations From The Plan

- Did not move the CLI's private `describe_table`/`find_table`/`find_column` helpers into `database-memory-core`. For Phase 12, small MCP-local copies were the smaller patch and avoid broad CLI/core refactoring.
- Tool outputs follow the Phase 11 pattern: MCP methods return JSON as text content. Error responses are JSON objects with an `error` field.
- `list_databases` returns an empty snapshot list for a missing cache path without creating the cache.
- `impact_analysis` resolves either an explicit `object_key`, a table name, or a table-plus-column name. Column-only resolution is supported only when the column name is unambiguous.
- No config profiles, new adapters, row-data access, arbitrary SQL, or graph query escape hatch were added.

## Remaining Risks

- `schema_diff` compares the two snapshot keys requested by alias. The current `index_database` behavior still overwrites `sqlite:<alias>`; historical multi-snapshot capture remains a later product concern unless users/indexing code insert distinct snapshot keys.
- Column-only object resolution assumes the current SQLite key shape (`main/main`) when constructing a key after ambiguity checks. Table-plus-column and explicit object keys avoid that assumption.
- Concurrent tool calls that depend on each other (e.g. `index_database` then an immediate read tool) must be sequenced by the calling client, awaiting each response — this is standard MCP client behavior but worth noting since it surfaced during ad hoc testing.

## Recommended Next Phase

Proceed to Phase 13: config and connection profiles.
