# Database Memory MCP Phase 16 Report

## Status

Complete. Added MySQL/MariaDB Level 1 metadata introspection and wired `--source mysql` / MCP `source: "mysql"` indexing through the existing snapshot-to-graph path. `cargo test` passes (46 tests across all crates, including the env-gated MySQL test skipping cleanly with no server available).

The adapter reads only `SELECT DATABASE()` and `INFORMATION_SCHEMA` metadata:

- `INFORMATION_SCHEMA.TABLES`
- `INFORMATION_SCHEMA.COLUMNS`
- `INFORMATION_SCHEMA.KEY_COLUMN_USAGE`
- `INFORMATION_SCHEMA.TABLE_CONSTRAINTS`
- `INFORMATION_SCHEMA.STATISTICS`

No user table rows are selected. MySQL/MariaDB database/catalog names are mapped to both the common `database` and `schema` fields for this Level 1 adapter, so the connection string must select a database/schema.

## Changed Files

- `crates/database-memory-core/Cargo.toml`: adds the synchronous `mysql` crate dependency.
- `crates/database-memory-core/src/adapters/mod.rs`: exports the MySQL adapter module.
- `crates/database-memory-core/src/adapters/mysql.rs`: new synchronous MySQL/MariaDB metadata adapter, Level 1 capabilities test, and env-gated live integration test.
- `crates/database-memory-cli/src/main.rs`: supports `database-memory index --source mysql --connection-string <url> --alias <name>` and adds a parse test.
- `crates/database-memory-mcp/src/lib.rs`: supports MCP `index_database` with `source: "mysql"` and `connection_string`.
- `docs/reports/database-memory-mcp.phase-16.md`: this report.

## Verification Command And Result

Formatting:

~~~powershell
C:/Users/plosind/.cargo/bin/rustfmt.exe crates/database-memory-core/src/adapters/mysql.rs crates/database-memory-cli/src/main.rs crates/database-memory-mcp/src/lib.rs
~~~

Result: completed successfully.

Targeted test attempted:

~~~powershell
C:/Users/plosind/.cargo/bin/cargo.exe test --target-dir target-codex-mysql-phase16 -p database-memory-core mysql_adapter_tests
~~~

Result: failed before compilation because this sandbox could not reach crates.io to resolve the new `mysql` dependency:

~~~text
error: failed to get `mysql` as a dependency of package `database-memory-core`
Caused by: download of config.json failed
Caused by: [7] Could not connect to server (Failed to connect to index.crates.io port 443)
~~~

The temporary `target-codex-mysql-phase16` directory was removed afterward.

Verified independently outside the sandbox with network access (`mysql` crate pulls in ~76 transitive packages, including `icu_*`/`regex`/`url` via `mysql_common`):

```powershell
cargo test
cargo build
```

3 transient Windows file-lock errors (`os error 32`, the same known incremental-cache/antivirus race seen in earlier phases, worse here due to the much larger dependency count compiling in parallel) required 3 retries; the 4th attempt compiled and ran cleanly:

```text
running 11 tests (database-memory-cli)   ... 11 passed
  test tests::parses_mysql_index_command ... ok
running 31 tests (database-memory-core)  ... 31 passed
  test adapters::mysql::mysql_adapter_tests::mysql_adapter_live_introspection_is_env_gated ... ok
  test adapters::mysql::mysql_adapter_tests::mysql_capabilities_are_level_1_metadata_only ... ok
running 4 tests (database-memory-mcp)    ... 4 passed

cargo build: zero warnings across all four crates
```

46 tests total, all passing. No code fixes were needed. Manual review of `adapters/mysql.rs` confirms every catalog query targets `INFORMATION_SCHEMA.*` (`SELECT DATABASE()`, `TABLES`, `COLUMNS`, `KEY_COLUMN_USAGE`, `TABLE_CONSTRAINTS`, `STATISTICS`); the only other SQL in the file is inside the gated live test's own disposable-table setup/teardown, not the adapter itself.

Live MySQL/MariaDB testing is gated by:

~~~text
DATABASE_MEMORY_TEST_MYSQL_URL
~~~

When the env var is absent, the live test prints a skip message and returns early. When set, it creates disposable tables in the selected database, runs metadata introspection, asserts table/column/PK/FK/index extraction, and drops the tables. There is no MySQL/MariaDB server or Docker available in this environment, so the live path was not executed here.

## Deviations From The Plan

- Used the synchronous `mysql` crate and kept `database-memory-core` synchronous, matching the existing PostgreSQL adapter pattern.
- Required the MySQL connection URL to select a database/schema. `SELECT DATABASE()` returning null is treated as an adapter error.
- Mapped MySQL/MariaDB database/catalog to the common `schema` field and used the same name for the common `database` field. This avoids server-wide scans and keeps stable keys scoped to the selected database.
- Left views, triggers, routines, and dependencies unsupported for MySQL Level 1, as requested.
- Did not update `Cargo.lock` by hand because dependency resolution could not run in this sandbox.

## Remaining Risks

- The live MySQL/MariaDB integration test has not been run against a real server (none available in this environment). It should be run once with `DATABASE_MEMORY_TEST_MYSQL_URL=mysql://user:pass@host:3306/database` before relying on it in CI.
- Cross-database foreign keys are listed as constraints, but referenced table/column keys are resolved only when the referenced table is in the selected database snapshot.

## Recommended Next Phase

Proceed to Phase 17 after networked `cargo test` passes: capability-aware responses that make unsupported MySQL Level 2+ metadata explicit to MCP/CLI callers.
