# Database Memory MCP Phase 15 Report

## Status

Complete. PostgreSQL snapshots now populate views, triggers, routines, and best-effort dependency metadata without reading user table rows. The graph builder now writes View, Trigger, and Routine nodes plus dependency/execution edges from the populated snapshot fields.

## Changed Files

- crates/database-memory-core/src/adapters/postgres.rs
- crates/database-memory-core/src/graph_builder.rs
- docs/reports/database-memory-mcp.phase-15.md

## Verification Command And Result

Formatting:

~~~powershell
C:/Users/plosind/.cargo/bin/rustfmt.exe crates/database-memory-core/src/adapters/postgres.rs crates/database-memory-core/src/graph_builder.rs
~~~

Result: completed successfully.

Targeted Postgres capability check:

~~~powershell
set CARGO_INCREMENTAL=0
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-noinc -p database-memory-core postgres_dependencies
~~~

Result: 1 passed, 0 failed.

Graph builder check:

~~~powershell
set CARGO_INCREMENTAL=0
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-noinc -p database-memory-core graph_builder
~~~

Result: 5 passed, 0 failed.

Core crate check:

~~~powershell
set CARGO_INCREMENTAL=0
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-noinc -p database-memory-core
~~~

Result: 29 passed, 0 failed, including doc-tests. The live PostgreSQL test skipped cleanly because DATABASE_MEMORY_TEST_POSTGRES_URL was not set.

Workspace check attempted:

~~~powershell
set CARGO_INCREMENTAL=0
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-noinc
C:/Users/plosind/.cargo/bin/cargo.exe test --jobs 1 --target-dir target-codex-workspace-1783216370833
~~~

Result: both workspace attempts failed before project tests completed because Windows reported locked .rcgu.o files in the generated target directories (os error 32). The generated target directories were removed afterward. Normal shell/apply_patch was unavailable because codex-windows-sandbox-setup.exe is missing, so reads/writes and commands used the Node fallback.

Independently re-verified outside the sandbox: `cargo test` (43 tests across all three crates, all passing after 2 transient Windows file-lock retries unrelated to the code) and `cargo build` (zero warnings, no leftover `target-codex-*` directories). Confirmed by grep that `graph_builder.rs` emits all six required edge types (`VIEW_DEPENDS_ON_TABLE`, `VIEW_DEPENDS_ON_COLUMN`, `TRIGGER_ON_TABLE`, `TRIGGER_EXECUTES_ROUTINE`, `ROUTINE_DEPENDS_ON_TABLE`, `ROUTINE_DEPENDS_ON_COLUMN`) with matching test assertions.

## Deviations From The Plan

- View dependencies use pg_rewrite/pg_depend rather than information_schema.view_table_usage/view_column_usage because it resolves table and column dependencies in one catalog path.
- Routine dependency extraction is intentionally best-effort. It resolves pg_depend entries for routines to already-known table/column keys but does not parse routine bodies.
- Trigger extraction uses pg_trigger so the executed routine can be resolved through tgfoid when the routine key is known.
- Added TABLE_HAS_TRIGGER in graph_builder.rs alongside the requested TRIGGER_ON_TABLE edge because it already exists in the Core Model and matches the existing parent-to-child edge pattern.

## Remaining Risks

- The extended live PostgreSQL fixture still has not been run against a real PostgreSQL server in this environment. It remains gated by DATABASE_MEMORY_TEST_POSTGRES_URL and skips when absent.
- PostgreSQL routine keys use information_schema.specific_name as the sub-object so overloaded routines do not collapse into one key. Trigger routine resolution depends on matching that specific_name to pg_proc oid metadata.
- Catalog-only routine dependencies can be empty or partial for function bodies PostgreSQL stores as strings, matching PostgreSQL's documented dependency-tracking limit.

## Recommended Next Phase

Proceed to Phase 16: MySQL adapter, preserving the same metadata-only boundary and capability notes for dialect-specific dependency limits.
