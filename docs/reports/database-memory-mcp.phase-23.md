# Database Memory MCP Phase 23 Report

## Status

Complete. Phase 23 security hardening is implemented with no row-data access added. The project still has no arbitrary SQL MCP or CLI tool, query_graph remains a constrained JSON metadata query over the local graph cache, and future row sampling is marked behind a default-off unsafe-row-sampling Cargo feature that currently gates no code.

## Changed Files

- crates/database-memory-core/Cargo.toml: adds default-off unsafe-row-sampling feature.
- crates/database-memory-core/src/lib.rs: exports redact, adds the row-sampling feature marker const, and adds the lightweight source-scan security test.
- crates/database-memory-core/src/redact.rs: new connection-string and connection-error redaction helper plus tests for postgres/mysql URL strings, SQL Server ADO strings, and Oracle user/password@connect_string.
- crates/database-memory-core/src/adapters/postgres.rs: redacts connection failures before they become adapter display errors.
- crates/database-memory-core/src/adapters/mysql.rs: redacts pool/connect failures before they become adapter display errors.
- crates/database-memory-core/src/adapters/sqlserver.rs: redacts ADO parse, TCP connect, socket option, and TDS connect failures.
- crates/database-memory-core/src/adapters/oracle.rs: redacts Oracle connection failures.
- crates/database-memory-cli/src/main.rs: redacts connection adapter errors before CLI output.
- crates/database-memory-mcp/src/lib.rs: redacts connection adapter errors before MCP JSON error output.
- docs/reports/database-memory-mcp.phase-23.md: this report.

## Verification Command And Result

Normal PowerShell and apply_patch were unavailable because codex-windows-sandbox-setup.exe is missing, so reads, writes, formatting, and tests used the Node filesystem/process fallback.

Formatting:

~~~powershell
cargo fmt --check
~~~

Result: passed.

Focused tests:

~~~powershell
cargo test -p database-memory-core redact
cargo test -p database-memory-core adapter_sources_do_not_contain_obvious_row_selects
cargo test -p database-memory-core unsafe_row_sampling_feature_is_named_guardrail_only
~~~

Result: passed. Redaction tests: 4 passed. Source-scan test: 1 passed. Feature marker test: 1 passed.

Full workspace test:

~~~powershell
cargo test
~~~

Initial result: hit the known transient Windows file-lock error, os error 32, while removing generated object files for database-memory-cli and database-memory-mcp.

Retry command:

~~~powershell
cargo test --jobs 1
~~~

Retry result: passed. Totals: database-memory-cli 14 passed, database-memory-core 54 passed, database-memory-mcp 7 passed, doc-tests 0. Total: 75 tests passed across the workspace.

## Metadata-Only Query Audit Findings

SQLite production adapter audit, crates/database-memory-core/src/adapters/sqlite.rs:

- Lines 225-228: SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'. This reads SQLite schema catalog rows only.
- Line 243: PRAGMA table_info(<quoted table name>). This returns column metadata for a table, not table rows.
- Lines 285-288: PRAGMA foreign_key_list(<quoted table name>). This returns FK metadata only.
- Line 372: PRAGMA index_list(<quoted table name>). This returns index metadata only.
- Line 413: PRAGMA index_info(<quoted index name>). This returns index-column metadata only.
- Finding: no SQLite production adapter query selects from a user-defined table or reads row data.

PostgreSQL production adapter audit, crates/database-memory-core/src/adapters/postgres.rs:

- Line 56: SELECT current_database(), database identity only.
- Lines 371-397: information_schema.schemata and information_schema.tables.
- Lines 427-435: information_schema.columns.
- Lines 471-488: pg_catalog.pg_constraint, pg_class, pg_namespace, pg_attribute, and unnest(conkey/confkey) for key metadata.
- Lines 551-565: pg_catalog.pg_index, pg_class, pg_namespace, and pg_attribute for index metadata.
- Lines 609-614: information_schema.views for view definitions.
- Lines 638-652: pg_rewrite, pg_depend, pg_class, pg_namespace, and pg_attribute for view dependency metadata.
- Lines 691-700: information_schema.routines joined to pg_namespace/pg_proc for routine metadata.
- Lines 729-739: pg_proc, pg_depend, pg_class, pg_namespace, and pg_attribute for routine dependencies.
- Lines 779-795: pg_trigger, pg_class, pg_namespace, and pg_proc for trigger metadata.
- Finding: no PostgreSQL production adapter query selects from a user-defined table or reads row data. The test fixture view definition around line 951 contains a SELECT over disposable test tables inside CREATE VIEW; that is test setup DDL, not production adapter introspection, and it does not execute as a row-read query in the adapter.

MySQL production adapter audit, crates/database-memory-core/src/adapters/mysql.rs:

- Line 238: SELECT DATABASE(), database identity only.
- Lines 252-255: INFORMATION_SCHEMA.TABLES for base table metadata.
- Lines 280-284: INFORMATION_SCHEMA.COLUMNS for column metadata.
- Lines 346-354: INFORMATION_SCHEMA.KEY_COLUMN_USAGE joined to INFORMATION_SCHEMA.TABLE_CONSTRAINTS for key/FK metadata.
- Lines 445-446: INFORMATION_SCHEMA.STATISTICS for index metadata.
- Finding: no MySQL production adapter query selects from a user-defined table or reads row data.

SQL Server production adapter audit, crates/database-memory-core/src/adapters/sqlserver.rs:

- Line 338: SELECT DB_NAME() AS database_name, database identity only.
- Lines 353-357: sys.tables and sys.schemas for table/schema metadata.
- Lines 410-424: sys.columns, sys.tables, sys.schemas, sys.types, and sys.default_constraints for column metadata.
- Lines 459-477: sys.key_constraints, sys.index_columns, and sys.columns for PK/UQ metadata.
- Lines 511-532: sys.foreign_keys, sys.foreign_key_columns, sys.tables, sys.schemas, and sys.columns for FK metadata.
- Lines 578-596: sys.indexes, sys.index_columns, sys.tables, sys.schemas, and sys.columns for index metadata.
- Finding: no SQL Server production adapter query selects from a user-defined table or reads row data.

Oracle production adapter audit, crates/database-memory-core/src/adapters/oracle.rs:

- Lines 289 and 294: SYS_CONTEXT(...) FROM DUAL, database/current-schema identity only.
- Lines 308-310: ALL_TABLES for table metadata.
- Lines 350-352: ALL_TAB_COLUMNS for column metadata.
- Lines 404-419: ALL_CONSTRAINTS and ALL_CONS_COLUMNS for PK/UQ/FK metadata.
- Lines 488-500: ALL_INDEXES, ALL_IND_COLUMNS, and ALL_CONSTRAINTS for index metadata.
- Finding: no Oracle production adapter query selects from a user-defined table or reads row data. DUAL is Oracle's system one-row relation, not user table data.

Graph query audit, crates/database-memory-core/src/graph_query.rs:

- Line 75: query_graph accepts a typed GraphQuery struct, not SQL.
- Lines 76 and 107: result limit and traversal depth are hard-capped with GRAPH_QUERY_MAX_LIMIT and GRAPH_QUERY_MAX_DEPTH.
- Lines 143-146: node filtering reads GraphStore::nodes_by_label or GraphStore::nodes_for_snapshot, i.e. indexed metadata graph records.
- Lines 200-201 and 217: traversal reads graph edges/nodes from GraphStore, not a live database.
- Finding: no SQL string is present in graph_query.rs; it remains a constrained JSON filter over stored graph metadata.

The new source-scan test in crates/database-memory-core/src/lib.rs lines 387-418 checks production adapter sources for obvious row-select patterns such as SELECT *, FROM users, FROM orders, and confirms graph_query.rs contains no SELECT token. This is intentionally lightweight, not a SQL parser.

## No Arbitrary SQL MCP/CLI Tool Audit

- MCP exposes only typed tools at crates/database-memory-mcp/src/lib.rs lines 245-301: index_database, list_databases, list_tables, describe_table, find_table, find_column, impact_analysis, trace_relationships, schema_diff, query_graph, and graph_stats.
- MCP query_graph is described at line 296 as a constrained read-only JSON query over indexed graph metadata and dispatches to query_graph_for_request, not to a live DB SQL executor.
- MCP index_database accepts source, path, connection_string, alias, and cache_path; no raw SQL request field is executed.
- CLI command parsing accepts index, describe-table, find-table, and find-column; the index flags include --source, --path, --connection-string, --alias, --cache-path, and --config-path, not raw SQL.
- Config still rejects unknown TOML fields via #[serde(deny_unknown_fields)] at crates/database-memory-core/src/config.rs line 16, with tests at lines 152 and 162 proving query and sql fields are rejected.

Finding: there is no arbitrary SQL MCP tool or CLI command.

## Connection Redaction

- crates/database-memory-core/src/redact.rs masks URL-style credentials, ADO-style password=.../pwd=..., and Oracle user/password@connect_string strings.
- Adapter connection failures are redacted before becoming display strings in postgres lines 43-46, mysql lines 48-52, sqlserver lines 89-113, and oracle lines 47-52.
- CLI errors are redacted before user output in crates/database-memory-cli/src/main.rs lines 62-87.
- MCP JSON error output is redacted before serialization in crates/database-memory-mcp/src/lib.rs lines 328-353.

## Unsafe Row Sampling Gate

- crates/database-memory-core/Cargo.toml line 11 defines default-off unsafe-row-sampling = [].
- crates/database-memory-core/src/lib.rs line 21 defines UNSAFE_ROW_SAMPLING_FEATURE with a doc comment stating future row-data sampling must be guarded by this feature.
- No row-sampling code was added and the feature currently gates nothing by design.

Independently re-verified outside the sandbox: `cargo test` (75 tests across all crates, all passing on the first attempt, no file-lock retry needed this time) and `cargo build` (zero warnings). Manually reviewed `redact.rs` and confirmed via grep that `redact_connection_string`/`redact_error_with_connection_string` are applied at the exact connection-error origination points in all four network adapters (postgres, mysql, sqlserver, oracle — sqlite correctly has no connection string to redact) and again at the CLI and MCP call sites (defense in depth). Redaction test coverage (URL-style, ADO-style, Oracle `user/password@` style) matches the connection string formats each adapter actually documents/accepts.

## Deviations From The Plan

None. Phase 23 stayed within security hardening. No Phase 24 packaging, Phase 25 docs, arbitrary SQL execution, or row-data sampling was added.

## Remaining Risks

- The source-scan test is a guardrail, not a SQL parser. It catches obvious row-select regressions but cannot prove every possible future string construction is safe.
- Adapter metadata fields can contain database object definitions such as view, routine, trigger, index predicate, and default expressions. Those are schema metadata, but they may contain literals authored into DDL.
- Redaction focuses on common connection-string credential shapes. Exotic vendor-specific key names may need to be added if a future adapter introduces them.

## Recommended Next Phase

Proceed to Phase 24: packaging, keeping the default product boundary metadata-only and leaving any future row sampling behind explicit unsafe-row-sampling opt-in work.
