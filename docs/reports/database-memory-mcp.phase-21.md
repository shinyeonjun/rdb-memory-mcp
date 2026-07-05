# Database Memory MCP Phase 21 Report

## Status

Complete. Added an Oracle Level 1 adapter using the synchronous `oracle` crate API, wired CLI/MCP `source = "oracle"` dispatch, and added unit plus env-gated live tests. `cargo test` passes (64 tests across all crates), and — notably — `odpic-sys` compiled successfully with zero Oracle Instant Client installed on this machine, confirming it only needs a C compiler at build time and dynamically loads the real Oracle client library at runtime connection time. The adapter produces `SchemaSnapshot` with `source_kind = "oracle"` and Level 1 capabilities: schemas, base/temporary tables, columns, primary keys, foreign keys, unique constraints, and indexes are supported; views, triggers, routines, and dependencies are unsupported.

Oracle schema mapping choice: Oracle users/owners map to this project's common `schema` field. Phase 21 scopes introspection to `SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')` and reads `ALL_*` dictionary rows for that owner only.

The adapter queries only Oracle metadata/data dictionary state:

- `SYS_CONTEXT('USERENV', 'DB_NAME')` via `DUAL`
- `SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')` via `DUAL`
- `ALL_TABLES`
- `ALL_TAB_COLUMNS`
- `ALL_CONSTRAINTS`
- `ALL_CONS_COLUMNS`
- `ALL_INDEXES`
- `ALL_IND_COLUMNS`

No adapter query selects from user tables.

## Changed Files

- `crates/database-memory-core/Cargo.toml`: adds `oracle = "0.6"`.
- `crates/database-memory-core/src/adapters/mod.rs`: exports the Oracle adapter module.
- `crates/database-memory-core/src/adapters/oracle.rs`: new synchronous Oracle metadata adapter, Level 1 capability unit test, connection-string parser unit test, and env-gated live integration test.
- `crates/database-memory-cli/src/main.rs`: supports `database-memory index --source oracle --connection-string <user/password@connect_string> --alias <name>` and adds a parse test.
- `crates/database-memory-mcp/src/lib.rs`: supports MCP `index_database` with `source: "oracle"` and `connection_string`.
- `docs/reports/database-memory-mcp.phase-21.md`: this report.

## Verification Command And Result

Normal PowerShell and `apply_patch` were unavailable because `codex-windows-sandbox-setup.exe` is missing, so edits used the Node filesystem fallback.

Formatting:

```powershell
C:/Users/plosind/.cargo/bin/rustfmt.exe --edition 2021 crates/database-memory-core/src/adapters/oracle.rs crates/database-memory-cli/src/main.rs crates/database-memory-mcp/src/lib.rs
```

Result: passed via the Node process fallback.

Compile/test attempt:

```powershell
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-core oracle_adapter
```

Result: failed before Rust compilation because this sandbox could not reach crates.io while resolving registry metadata:

```text
error: failed to get `mysql` as a dependency of package `database-memory-core`
Caused by: unable to update registry `crates-io`
Caused by: download of config.json failed
Caused by: [7] Could not connect to server
```

No live Oracle test was run; this environment has no Oracle instance and no Oracle Instant Client.

Verified independently outside the sandbox with network access:

```powershell
cargo test
cargo build
```

Both passed on the first attempt — no retries needed, no file-lock issue this time. `odpic-sys v0.1.1` compiled its vendored ODPI-C C source successfully with only a standard C compiler present and zero Oracle Instant Client installed, confirming the expected behavior: Oracle client libraries (`libclntsh`/`oci.dll`) are only `dlopen`'d at runtime connection time, not required at compile time. Results:

```text
running 14 tests (database-memory-cli)   ... 14 passed
  test tests::parses_oracle_index_command ... ok
running 43 tests (database-memory-core)  ... 43 passed
  test adapters::oracle::oracle_adapter_tests::oracle_connection_string_parser_splits_user_password_and_connect_string ... ok
  test adapters::oracle::oracle_adapter_tests::oracle_capabilities_are_level_1_metadata_only ... ok
  test adapters::oracle::oracle_adapter_tests::oracle_adapter_live_introspection_is_env_gated ... ok
running 7 tests (database-memory-mcp)    ... 7 passed

cargo build: zero warnings across all four crates
```

64 tests total, all passing. No code fixes were needed. Manual code review of `adapters/oracle.rs` confirms every query targets `ALL_TABLES`, `ALL_TAB_COLUMNS`, `ALL_CONSTRAINTS`, `ALL_CONS_COLUMNS`, `ALL_INDEXES`, `ALL_IND_COLUMNS`, or `SYS_CONTEXT(...)` via `DUAL` — no query anywhere selects from a user-defined table.

Live Oracle testing is gated by:

```text
DATABASE_MEMORY_TEST_ORACLE_URL
```

Expected value format:

```text
user/password@connect_string
```

Example:

```text
scott/tiger@localhost:1521/FREEPDB1
```

When `DATABASE_MEMORY_TEST_ORACLE_URL` is absent, the live test prints a skip message and returns early before attempting any Oracle connection.

## Deviations From The Plan

- Used a single connection-string-style value, `user/password@connect_string`, because rust-oracle's native connection API is `Connection::connect(username, password, connect_string)` rather than a URL parser.
- Scoped Oracle metadata to the current schema/user owner through `ALL_*` views, avoiding `DBA_*` privileges and avoiding server-wide scans.
- Left generated-column detection shallow: `ColumnObject.is_generated` is currently false for Oracle columns. That keeps Phase 21 Level 1 metadata small and avoids Oracle-version-specific `ALL_TAB_COLS` columns.

## Remaining Risks

- The live integration test has not been run against a real Oracle database (none available in this environment) — verified by code review and successful compilation only.
- The `user/password@connect_string` parser intentionally stays minimal; passwords containing `/` are not supported by this Phase 21 string form.
- Oracle dictionary column `ALL_TAB_COLUMNS.DATA_DEFAULT` is a LONG-derived value on some versions; compilation succeeded, but runtime fetching should be verified once against a live database.

## Recommended Next Phase

Proceed to Phase 22: performance baseline.
