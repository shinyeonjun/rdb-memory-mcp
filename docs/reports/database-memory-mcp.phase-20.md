# Database Memory MCP Phase 20 Report

## Status

Complete. Added a SQL Server Level 1 adapter using the pure-Rust async 'tiberius' client behind a synchronous public function. `cargo test` passes (60 tests across all crates, including the env-gated SQL Server test skipping cleanly with no server available). The adapter builds the existing 'SchemaSnapshot' model with 'source_kind = "sqlserver"' and Level 1 capabilities: schemas, base tables, columns, primary keys, foreign keys, unique constraints, and indexes are supported; views, triggers, routines, and cross-object dependencies are marked unsupported.

The adapter queries only SQL Server metadata/catalog state:

- 'DB_NAME()'
- 'sys.tables'
- 'sys.schemas'
- 'sys.columns'
- 'sys.types'
- 'sys.default_constraints'
- 'sys.key_constraints'
- 'sys.foreign_keys'
- 'sys.foreign_key_columns'
- 'sys.indexes'
- 'sys.index_columns'

No adapter query selects from user tables.

## Changed Files

- 'crates/database-memory-core/Cargo.toml': adds 'tiberius', 'tokio', and 'tokio-util' dependencies for the SQL Server adapter.
- 'crates/database-memory-core/src/adapters/mod.rs': exports the SQL Server adapter module.
- 'crates/database-memory-core/src/adapters/sqlserver.rs': new SQL Server metadata adapter, Level 1 capability unit test, and env-gated live integration test.
- 'crates/database-memory-cli/src/main.rs': supports 'database-memory index --source sqlserver --connection-string <ado-connection-string> --alias <name>' and adds a parse test.
- 'crates/database-memory-mcp/src/lib.rs': supports MCP 'index_database' with 'source: "sqlserver"' and 'connection_string'.
- 'docs/reports/database-memory-mcp.phase-20.md': this report.

## Verification Command And Result

Normal PowerShell and 'apply_patch' were unavailable because 'codex-windows-sandbox-setup.exe' is missing, so edits and commands used the Node filesystem/process fallback.

Formatting:

~~~powershell
C:/Users/plosind/.cargo/bin/rustfmt.exe --edition 2021 crates/database-memory-core/src/adapters/sqlserver.rs crates/database-memory-cli/src/main.rs crates/database-memory-mcp/src/lib.rs
C:/Users/plosind/.cargo/bin/rustfmt.exe --edition 2021 --check crates/database-memory-core/src/adapters/sqlserver.rs crates/database-memory-cli/src/main.rs crates/database-memory-mcp/src/lib.rs
~~~

Result: passed.

Compile/test attempt:

~~~powershell
C:/Users/plosind/.cargo/bin/cargo.exe check -p database-memory-core --target-dir target-codex-phase20-check
~~~

Result: failed before Rust compilation because this sandbox could not reach crates.io to resolve registry metadata:

~~~text
error: failed to get 'mysql' as a dependency of package 'database-memory-core'
Caused by: unable to update registry 'crates-io'
Caused by: download of config.json failed
Caused by: [7] Could not connect to server
~~~

No live SQL Server test was run; no SQL Server instance or Docker is available in this environment.

Verified independently outside the sandbox with network access (`tiberius` pulls in ~34 packages including `rustls`, `ring`, `tokio-rustls`):

```powershell
cargo test
cargo build
```

Results: `cargo test` passed on the first attempt (60 tests across all three crates, including `adapters::sqlserver::sqlserver_adapter_tests::sqlserver_adapter_live_introspection_is_env_gated` and `sqlserver_capabilities_are_level_1_metadata_only`); `cargo build` needed one retry for the same known Windows file-lock issue, then finished with zero warnings. No code fixes were needed — the implementation compiled and passed on the first real compile.

Manual code review of `adapters/sqlserver.rs` confirms every query targets `sys.*` catalog views or `DB_NAME()` — no query anywhere selects from a user-defined table; the only other SQL (`client.simple_query` in a `run_batch` helper) is confined to the gated live test's own disposable schema setup/teardown. Also reviewed the sync/async bridging: `introspect_sqlserver` checks `tokio::runtime::Handle::try_current()` and, if already inside a Tokio runtime (as it would be when called from the `tokio::main`-based MCP server), spawns a separate OS thread to host its own current-thread runtime — correctly avoiding a "cannot start a runtime from within a runtime" panic while keeping the adapter's public function signature synchronous like the other three adapters.

Live SQL Server testing is gated by:

~~~text
DATABASE_MEMORY_TEST_SQLSERVER_URL
~~~

Expected connection string style is Tiberius ADO.NET format, for example:

~~~text
server=tcp:localhost,1433;user=sa;password=Password123;database=app;TrustServerCertificate=true
~~~

When 'DATABASE_MEMORY_TEST_SQLSERVER_URL' is absent, the live test prints a skip message and returns early.

## Deviations From The Plan

- Added 'tokio-util' directly because Tiberius/Tokio integration requires 'compat_write()' for Tokio TCP streams.
- Used Tiberius ADO.NET connection strings rather than URL-style strings because 'Config::from_ado_string' is the native Tiberius parser for SQL Server connection-string parameters.
- The synchronous adapter wrapper starts the short-lived current-thread Tokio runtime as planned, with one small guard: if the function is called from an already-entered Tokio runtime, it runs that blocking wrapper on a worker thread to avoid nested-runtime panics. Public callers remain synchronous.
- SQL Server views, triggers, routines, and dependency depth were intentionally left unsupported for Level 1.

## Remaining Risks

- The live SQL Server integration test has not been run against a real SQL Server instance (none available in this environment) — verified by code review and successful compilation only.
- Catalog type conversions are based on Tiberius support for SQL Server catalog scalar types such as 'sysname', 'nvarchar', 'int', and 'bit'; these compiled correctly but have not been exercised against a live server.
- Cross-database foreign keys are represented as constraints but only resolve referenced object keys when the referenced table is present in the current database snapshot.

## Recommended Next Phase

Proceed to Phase 21: Oracle adapter, keeping the same metadata-only boundary and env-gated live test convention.
