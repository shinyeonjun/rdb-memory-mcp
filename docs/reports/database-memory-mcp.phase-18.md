# Database Memory MCP Phase 18 Report

## Status

Complete. Added a constrained, read-only graph query escape hatch over the persisted metadata graph. The query accepts a small JSON-shaped request: snapshot key or alias at the MCP layer, optional node label/key/name filters, optional edge type, optional top-level payload array length filter, optional bounded traversal, and a required result limit capped server-side at 500.

The core implementation only reads existing graph nodes and edges from `GraphStore`. It does not construct or execute caller-provided SQL and does not read user table rows.

## Changed Files

- `crates/database-memory-core/src/lib.rs`: exports the new graph query module.
- `crates/database-memory-core/src/graph_store.rs`: adds `nodes_for_snapshot` for safe snapshot-scoped graph node reads.
- `crates/database-memory-core/src/impact_analysis.rs`: derives serde traits for the existing `Direction` enum so the query struct remains JSON-serializable.
- `crates/database-memory-core/src/graph_query.rs`: new constrained query implementation and tests.
- `crates/database-memory-mcp/src/lib.rs`: exposes the new `query_graph` MCP tool and adds a small MCP wiring test.
- `docs/reports/database-memory-mcp.phase-18.md`: this report.

## Verification Command And Result

Formatting:

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe fmt --check
```

Result: passed after running `cargo fmt` once.

Targeted Phase 18 core tests:

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-core graph_query
```

Result: passed, 5 tests:

```text
graph_query_filters_nodes_by_label ... ok
graph_query_filters_nodes_by_name_substring ... ok
graph_query_runs_bounded_traversal ... ok
graph_query_caps_oversized_limit ... ok
graph_query_filters_payload_array_length ... ok
```

Full core crate check:

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-core
```

Result: passed, 36 tests plus doc-tests with 0 tests.

MCP crate check attempted:

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-mcp
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-phase18-mcp -p database-memory-mcp
C:/Users/plosind/.cargo/bin/cargo.exe test --jobs 1 --target-dir target-codex-phase18-mcp-j1 -p database-memory-mcp
C:/Users/plosind/.cargo/bin/cargo.exe check --target-dir target-codex-phase18-check -p database-memory-mcp
```

Result: all MCP compile attempts failed with the known transient Windows file-lock error (`os error 32`) while removing generated `.rcgu.o` files, including fresh target directories and `--jobs 1`. The temporary target directories created for these retries were removed afterward. No MCP test assertion failure or Rust type error was reached before the lock failures.

Normal shell and `apply_patch` were unavailable because `codex-windows-sandbox-setup.exe` is missing, so file reads/writes and cargo invocations used the Node fallback.

## Deviations From The Plan

- Added MCP `query_graph`; skipped CLI wiring because the plan calls CLI optional/nice-to-have and the manual CLI parser would add more surface than the phase needs.
- Used a constrained JSON query struct, not SQL, Cypher, or a general expression evaluator.
- Added one intentionally tiny payload filter, `payload_array_min_len`, to support practical ad hoc metadata questions such as finding `Index` nodes whose stored `columns` array has more than N entries. It only checks a top-level JSON array length using `serde_json`.
- Enforced `GRAPH_QUERY_MAX_LIMIT = 500` by capping the requested limit and applying it across returned node/edge/traversal result items. Traversal depth is also capped at `GRAPH_QUERY_MAX_DEPTH = 8`.

Independently re-verified outside the sandbox (where Codex's repeated MCP compile attempts hit the file-lock issue): `cargo test` (54 tests across all crates including `tests::mcp_runs_query_graph` in `database-memory-mcp`, all passing after 1 transient Windows file-lock retry) and `cargo build` (zero warnings after 1 retry). Manual code review of `graph_query.rs` confirms: no raw SQL is built from caller input anywhere (all filtering happens in Rust over already-materialized `GraphNodeRecord`/`GraphEdgeRecord` values fetched via existing parameterized `GraphStore` methods); `limit` is hard-capped via `.min(GRAPH_QUERY_MAX_LIMIT)` (500) before any results are collected; traversal `max_depth` is hard-capped via `.min(GRAPH_QUERY_MAX_DEPTH)` (8) — an oversized request cannot force unbounded scanning or return size.

## Remaining Risks

- Broad node filters may scan all graph nodes for a snapshot before applying the return cap. The returned result is capped; Phase 22 performance work is the right place to optimize large-cache scans if needed.
- The query grammar is deliberately small. It covers common label/name/key/edge/traversal and simple payload-array cases, not arbitrary nested predicates.

## Recommended Next Phase

Proceed to Phase 19: DDL/migration snapshot source.
