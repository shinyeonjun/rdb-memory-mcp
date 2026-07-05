# Database Memory MCP Phase 19 Report

## Status

Complete. Added a SQLite-only DDL/migration snapshot source. It discovers a single SQL file or top-level `.sql` files in a directory, applies them in lexicographic filename order to a fresh in-memory SQLite database, then reuses the existing SQLite introspection path to produce a `SchemaSnapshot`.

The DDL source is indexable as `ddl-sqlite:<alias>` through both CLI `index --source ddl-sqlite` and MCP `index_database`. It does not touch real database files and does not read row data. For meaningful live-vs-DDL diffs, DDL snapshot object keys intentionally use the same `sqlite:<alias>:...` object-key namespace as the live SQLite adapter while the stored snapshot key remains `ddl-sqlite:<alias>`.

## Changed Files

- `crates/database-memory-core/src/lib.rs`: exports the new DDL module.
- `crates/database-memory-core/src/adapters/sqlite.rs`: factors SQLite snapshot construction so DDL can introspect an already-open in-memory connection.
- `crates/database-memory-core/src/ddl/mod.rs`: new DDL module root.
- `crates/database-memory-core/src/ddl/sqlite.rs`: new SQLite DDL file/directory source plus tests.
- `crates/database-memory-cli/src/main.rs`: supports `index --source ddl-sqlite --path <sql-file-or-dir> --alias <name>`.
- `crates/database-memory-mcp/src/lib.rs`: supports MCP `index_database` with `source: "ddl-sqlite"`.
- `docs/reports/database-memory-mcp.phase-19.md`: this report.

## Verification Command And Result

Normal PowerShell and `apply_patch` were unavailable because `codex-windows-sandbox-setup.exe` is missing, so edits and commands used the Node fallback.

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe fmt --check
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-core ddl_source
C:/Users/plosind/.cargo/bin/cargo.exe test
```

Results:

```text
cargo fmt --check: passed
cargo test -p database-memory-core ddl_source: 2 passed
cargo test: 57 passed across database-memory-cli, database-memory-core, and database-memory-mcp
```

Independently re-verified outside the sandbox: `cargo test` (57 tests across all three crates, all passing on the first attempt — no file-lock retry needed this time) and `cargo build` (zero warnings). Manually reviewed `ddl/sqlite.rs`: DDL is only ever applied to `Connection::open_in_memory()`, never to a real file, so this cannot touch or read any production database. Confirmed the object-key design choice works as intended — `sqlite_ddl_snapshot_diffs_cleanly_against_live_sqlite_snapshot` proves a DDL-derived snapshot and a live-introspected snapshot of the identical schema produce zero added/removed/changed nodes or edges via the existing `schema_diff`, because DDL-derived `ObjectKey`s deliberately reuse `source_kind = "sqlite"` (matching the live adapter) even though the outer `SchemaSnapshot.source_kind` and stored snapshot key use `ddl-sqlite`. Without this, every node would show as both added and removed on every diff.

## Deviations From The Plan

- Scoped to SQLite DDL only, matching the requested Phase 19 reduction and existing adapter rollout order.
- Used throwaway in-memory SQLite execution through `rusqlite` instead of adding `sqlparser`; this reuses the existing introspection logic and avoids a new dependency.
- Directory discovery is non-recursive and applies only top-level `.sql` files in lexicographic filename order.
- Added MCP indexing support in addition to CLI because it is the same existing source switch.

## Remaining Risks

- Migration-tool features such as placeholders, includes, down migrations, and dialect-conditional blocks are not interpreted.
- DDL-vs-live diffs are clean only when the DDL snapshot uses the same alias as the live SQLite snapshot.
- SQLite adapter capability limits still apply: views, triggers, routines, and deeper dependencies remain unsupported.

## Recommended Next Phase

If DDL workflow depth is the priority, add a small Phase 19b for PostgreSQL DDL snapshots. Otherwise proceed to Phase 20 per the plan.
