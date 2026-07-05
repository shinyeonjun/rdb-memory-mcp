# Database Memory MCP Phase 4 Report

## Status

Complete. Added a deterministic `SchemaSnapshot` to `GraphStore` builder and `cargo test` passes.

## Changed Files

- `crates/database-memory-core/src/lib.rs`
- `crates/database-memory-core/src/graph_builder.rs`
- `docs/reports/database-memory-mcp.phase-4.md`

## Verification Command And Result

Command:

```powershell
cargo test
```

Result:

```text
running 8 tests
test tests::product_boundary_stays_rdb_first ... ok
test tests::stable_object_key_formats_and_parses ... ok
test graph_store::graph_store_tests::graph_store_inserts_and_finds_node ... ok
test graph_store::graph_store_tests::graph_store_inserts_and_finds_edge ... ok
test graph_builder::graph_builder_tests::graph_builder_writes_table_and_column_edges ... ok
test graph_builder::graph_builder_tests::graph_builder_writes_primary_key_edges ... ok
test graph_builder::graph_builder_tests::graph_builder_writes_foreign_key_edges ... ok
test graph_builder::graph_builder_tests::graph_builder_writes_index_edges ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo build` (non-test) also finishes clean with zero warnings.

## Deviations From The Plan

- Codex could not run `cargo test` itself in its sandbox (no network, no working shell/cargo path) and reported the builder unverified. Verified outside the sandbox with network access instead.
- First verification pass found a real `unused_imports` warning for `ObjectKind` in `graph_builder.rs` — it's only used by the `#[cfg(test)]` submodule via `use super::*`, not by the non-test builder code. Fixed by gating the import with `#[cfg(test)] use crate::ObjectKind;` so it's only compiled in when tests need it. No behavior changed.
- Did not implement Phase 5 adapters, Phase 6+ CLI/MCP wiring, or any row-data reading.
- View, trigger, and routine dependency edges were left out for this phase; the implemented builder covers the required Level 1 tables, columns, constraints, and indexes.
- Payload JSON is intentionally minimal so Phase 4 does not add dependencies or broaden storage behavior.

## Remaining Risks

- The FK edge orientation is source column -> foreign key -> referenced column. If later query APIs expect the opposite direction, change the builder and tests together before exposing MCP tools.
- Rebuilding a snapshot deletes the previous snapshot before inserting the new graph because `GraphStore` does not expose a transaction API yet.
- `ObjectKey` still does not escape colons inside identifiers, as noted in Phase 2.

## Recommended Next Phase

Proceed to Phase 5: SQLite Introspection Adapter Level 1, producing `SchemaSnapshot` values from SQLite metadata only.
