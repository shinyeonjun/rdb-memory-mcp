# Database Memory MCP Phase 3 Report

## Status

Complete. Local graph store schema was added and `cargo test` passes.

## Changed Files

- `crates/database-memory-core/Cargo.toml`
- `crates/database-memory-core/src/lib.rs`
- `crates/database-memory-core/src/graph_store.rs`
- `Cargo.lock`
- `docs/plans/database-memory-mcp.md`
- `docs/reports/database-memory-mcp.phase-3.md`

## Verification Command And Result

Command:

```powershell
cargo test
```

Result:

```text
running 4 tests
test tests::product_boundary_stays_rdb_first ... ok
test tests::stable_object_key_formats_and_parses ... ok
test graph_store::graph_store_tests::graph_store_inserts_and_finds_node ... ok
test graph_store::graph_store_tests::graph_store_inserts_and_finds_edge ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Doc-tests database_memory_core: ok. 0 passed; 0 failed
```

## Deviations From The Plan

- Codex's sandboxed exec environment had no network access (crates.io unreachable) and no working shell/PATH to `cargo`, so it could not compile or run tests itself and reported the code unverified.
- First verification attempt outside the sandbox found 4 real `rustc E0597` borrow-checker errors ("`stmt` does not live long enough") in `nodes_by_label`, `edges_from`, `edges_to`, and `edges_by_type` — each returned `collect_nodes(stmt.query_map(...)?)`/`collect_edges(...)` as a tail expression, dropping `stmt` while still borrowed. Sent back to Codex for a targeted fix: bind the `query_map` result to a local `rows` variable before passing it to `collect_nodes`/`collect_edges`. Re-verified and all tests pass.
- Windows Defender (or similar) intermittently locks the `target/debug/incremental` cache during compilation, causing a transient `os error 32` ("failed to move dependency graph ... process cannot access the file"). Retrying, or setting `CARGO_INCREMENTAL=0`, works around it reliably; this is an environment quirk, not a code issue.
- `rusqlite` was added with the `bundled` feature (vendors SQLite via `libsqlite3-sys`), so no system SQLite install is required. `Cargo.lock` now includes `rusqlite`, `libsqlite3-sys`, and their transitive deps.
- Snapshot-to-graph builder (Phase 4) was intentionally not implemented; no adapters, CLI commands, or MCP code were added.

## Remaining Risks

- The graph store's insert/query methods have not yet been exercised with real `SchemaSnapshot` data — only synthetic node/edge fixtures in the two `graph_store` tests. Phase 4's builder tests should catch any schema/mapping mismatches.
- Local builds on this machine intermittently hit the Defender file-lock issue above; if CI or another machine sees the same, prefer `CARGO_INCREMENTAL=0` or excluding `target/` from real-time scanning rather than treating it as a flaky test.

## Recommended Next Phase

Proceed to Phase 4: Snapshot To Graph Builder — convert a `SchemaSnapshot` into graph nodes and edges via `GraphStore`, with tests for table, column, PK, FK, and index edges.
