# Database Memory Trust Foundation

This pass strengthens the existing RDB metadata engine without adding row-data access or a general SQL tool.

## Implemented

- Transactional snapshot replacement with rollback to the previous valid graph on failure.
- Source-aware snapshot selection for CLI and MCP, explicit alias ambiguity errors, and stable-key selection for duplicate table names across schemas.
- Structured table/column matches and richer table evidence: object keys, schema/database identity, column defaults/generated state, constraints, FK endpoints, and index definitions.
- Server-side MCP pagination and bounded impact, relationship, and query-graph traversal with clamp/truncation metadata.
- Alias-independent schema comparison: connection alias changes no longer appear as full schema deletion/recreation.
- SQLite `table_xinfo` support for generated columns, removal of fabricated partial-index predicate text, and explicit adapter limitation warnings.
- SQLite DDL authorizer that rejects external database attachment and extension loading.
- CLI `find-column --format json` now returns type, nullability, ordinal position, default, and generated state.
- CLI inventory now supports deterministic offset pagination and reports the next page explicitly for large schemas.
- Bulk inventory now builds table descriptions from one normalized snapshot pass instead of issuing per-table graph queries.
- MCP schema comparison now bounds every returned change list, impact seeds, and the shared impact-node budget while preserving exact category counts and explicit truncation metadata.
- Stable object keys preserve the original format for ordinary identifiers and switch to a backward-compatible escaped `v2:` form for quoted identifiers containing `:` or `%`.

## Large-Schema Check

A generated SQLite DDL snapshot with 1,001 tables, 2,002 columns, and 2,002 constraints was read as two pages. The pages contained 1,001 unique stable table keys with no overlap or omission. The 1,000-table first page improved from about 39.5 seconds to about 1.95 seconds on the same local release build.

## Verification

- `cargo check --locked --workspace --all-targets`
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
- `cargo test --locked --workspace`
- Backend Visual Map RDB smoke: CLI contract, quoted identifier identity, SQLite DDL indexing, bulk inventory, stable describe, impact, and trace passed.
- Database Memory: 97 workspace tests and Clippy with warnings denied passed.
- Backend Visual Map checks: TypeScript typecheck, Knip, 73 Vitest tests, 167 Rust tests (plus one ignored manual scale test), and Clippy with warnings denied passed.

On 2026-07-21, the live PostgreSQL 16, MySQL 8.4, SQL Server 2022, and Oracle Database Free 23.26.2 adapter tests passed against disposable local Docker databases. The Backend Visual Map product smoke indexed all four sources and verified non-empty table and column inventory; the empty-database negative path also failed as intended. Oracle was exercised through Oracle Instant Client 19.30 and continues to require Oracle Client 11.2 or later at runtime.
