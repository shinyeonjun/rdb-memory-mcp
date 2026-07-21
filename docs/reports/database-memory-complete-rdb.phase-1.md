# Complete RDB Memory Phase 1 Report

Date: 2026-07-22
Status: Complete
Scope: requirements, source audit, support boundary, and baseline verification

## Decision

The final product scope is all relational databases. Support is delivered through
three explicit tiers rather than an unverifiable universal claim:

1. A vendor-neutral canonical metadata and relationship contract.
2. Certified native adapters for SQLite, PostgreSQL, MySQL, MariaDB, SQL Server,
   and Oracle.
3. A generic ODBC adapter for additional RDB products, with certification only
   when the driver and product/version pass the same completeness gates.

An authoritative indexing attempt has exactly two outcomes: `complete` or
`failed`. Partial, unknown, silently omitted, and permission-filtered metadata
cannot be published as complete.

## Existing Product Evidence

- The workspace already contains SQLite, SQLite DDL, PostgreSQL, MySQL,
  SQL Server, and Oracle source adapters.
- The existing graph store provides atomic snapshot replacement, stable object
  keys, bounded traversal, impact analysis, and schema diff.
- CLI and MCP transports exist, but their discovery surface is mainly table and
  column oriented.
- Live network tests are environment gated. A default green test run does not
  prove behavior against a real server.

## Confirmed Gaps

- No persisted completeness proof or discovered/emitted reconciliation existed.
- PostgreSQL dependency coverage was partial.
- MySQL, SQL Server, and Oracle exposed only Level 1 table/column/key/index
  metadata.
- The common model omitted materialized views, sequences, routine parameters,
  types/domains/enums, synonyms, partitions, exclusion constraints, and generic
  vendor extension facts.
- Existing adapters can silently skip rows when identity mapping fails.
- The public contract can describe only a subset of modeled object kinds.

## Safety Boundary

- Metadata only; application rows, sampling, profiling, DML, and migrations are
  out of scope.
- Credentials and connection strings must never be persisted or returned.
- Missing metadata privilege is an actionable failed analysis.
- A failed replacement must leave the last complete graph untouched.

## Baseline And Current Verification

Baseline before Phase 2 foundation work:

- `cargo test --workspace`: 97 passed.

Verification after strict structural validation and the initial completeness
contract were added:

- `cargo test --workspace`: 107 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Certified graph persistence rejects a tampered count proof before opening the
  replacement transaction.
- Invalid structural references are rejected before the previous snapshot is
  deleted.

## Artifacts

- `docs/research/database-memory-complete-rdb.md`
- `docs/plans/database-memory-complete-rdb.md`
- `crates/database-memory-core/src/snapshot_validation.rs`
- `crates/database-memory-core/src/certification.rs`

## Phase Gate

Phase 1 is complete. Phase 2 may proceed. Native adapters remain legacy and
non-authoritative until the full v2 model, certification evidence, and adapter
specific count probes are implemented and verified.
