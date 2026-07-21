# Complete RDB Memory Phase 4 Report

Date: 2026-07-22
Status: Complete
Scope: certified PostgreSQL 14, 15, 16, 17, and 18 catalog adapter

## Delivered Adapter

- Replaced the partial PostgreSQL collector with a `CatalogIntrospector`
  implementation that reads one metadata-only, read-only, repeatable-read
  transaction and returns only a certified `complete` or structured `failed`
  outcome. The public compatibility Facade can no longer bypass v2 analysis.
- Separated the vendor catalog Reader from `PostgresSnapshotMapper`, which is
  the PostgreSQL-to-canonical Anti-Corruption Layer. The common Assembler and
  Specifications own normalization, structural validation, reconciliation,
  and certification.
- Added an explicit catalog-version Strategy for every certified major. A new
  PostgreSQL major fails until its strategy and live contract are added. The
  strategy normalizes real catalog changes such as PostgreSQL 17 replacing the
  legacy `-1` statistics target with `NULL`.

## Complete Metadata

- Emits schemas, principals, tables, foreign and partitioned tables,
  partitions, ordinary and materialized views, view output columns, sequences,
  composite types, domains, enums and enum values, ranges/multiranges, routines,
  overload-safe parameters, triggers, policies, extensions, and event triggers.
- Preserves PK, unique, FK, check, and exclusion constraints; ordered key and
  included columns; expression/partial indexes; access methods, operator
  classes, collations, sort/null ordering, validity state, generated/default and
  identity expressions, ownership, RLS, partition bounds, and direct catalog
  dependency evidence.
- Keeps nested-view dependencies direct and models sequence usage,
  inheritance/partition relationships, type use, routine calls, trigger target
  and routine links, and vendor dependency edges without flattening reachability.
- Uses routine identity arguments in stable keys, so overloads cannot collide.
  Functions and procedures retain distinct canonical kinds and properties.

## Trust And Failure Semantics

- Reconciles raw and emitted counts for every modeled object and relationship
  category. Missing parents, keys, columns, types, dependencies, duplicate
  identities, oversized definitions, or count loss fail before certification.
- Records server version, selected Strategy, exact database/schema scope,
  current and session principals, transaction mode, schema privilege probes,
  transport state, and capability evidence in the completeness proof.
- A requested schema without `USAGE` returns `permission_denied` and no
  snapshot. The same restricted role completes after the exact privilege is
  granted, proving both sides of the gate.
- PostgreSQL does not persist complete dependencies for string-bodied SQL,
  PL/pgSQL, and other opaque routine bodies. Such routines and their triggers
  return `unsupported_metadata`; they are never presented as complete with
  guessed or missing edges. SQL-standard parsed bodies are catalog-certified.
- Remote TCP endpoints require `sslmode=require` and use the operating system's
  certificate trust through native TLS. Loopback/local plaintext is explicit in
  the proof. Connection strings and credentials are redacted from all failures.

## Version Matrix

- PostgreSQL 14: rich live catalog contract passed.
- PostgreSQL 15: rich live catalog contract passed.
- PostgreSQL 16: rich live catalog, privilege, and opaque-routine contracts
  passed.
- PostgreSQL 17: rich live contract passed with nullable statistics-target
  semantics.
- PostgreSQL 18: rich live contract passed with the PostgreSQL 18 Strategy.

The rich schema includes composite constraints, identity and generated columns,
enum/domain/composite types, a sequence, partitioning, expression/partial/include
indexes, nested views, a materialized view, RLS, overloads, and a SQL-standard
procedure. Docker health checks and tests run against real servers, not mocks.

## Verification

- `cargo test --workspace` with the PostgreSQL 16 live URL: 141 tests passed.
- The rich catalog contract passed independently against PostgreSQL 14 through
  18.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

## Deferred Cross-Cutting Gate

The adapter uses verified native TLS and rejects remote plaintext fallback. A
private-CA TLS server fixture and runtime certificate-rotation cases belong to
the Phase 10 security/release matrix; they are not claimed as live evidence in
this phase.

## Phase Gate

PostgreSQL 14 through 18 are certified native adapters under contract v2.
Phase 5 must bring MySQL and MariaDB through the same independent Reader,
version Strategy, canonical Mapper, privilege probe, reconciliation, and live
server matrix before either product may be called complete.
