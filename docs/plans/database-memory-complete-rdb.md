# Complete RDB Memory Implementation Plan

Status: In Progress
Scale: Large
Owner decision: all relational databases are the final support scope

## Goal

Deliver a production-grade, read-only RDB knowledge graph engine. For a certified
database and declared scope, indexing either commits a graph proven complete or
fails without replacing the last complete snapshot. The graph must support exact
object lookup, generic search, relationship tracing, impact analysis, and schema
diff for Backend Visual Map's later integration layer.

## Current Facts

- SQLite, SQLite DDL, PostgreSQL, MySQL, SQL Server, and Oracle sources exist.
- The graph store, traversal, impact, diff, CLI, MCP, redaction, and atomic
  replacement foundations exist.
- The baseline workspace has 97 passing tests.
- PostgreSQL dependencies are partial; MySQL, SQL Server, and Oracle are Level 1.
- No persisted completeness proof exists.
- Live network tests skip successfully when environment variables are absent.
- Public discovery is centered on tables and columns.

## Required Behavior

### Functional Requirements

- RDB-F001: Index catalogs/databases, schemas, relations, columns, constraints,
  indexes, views/materialized views, sequences, routines and parameters,
  triggers, types/domains/enums, synonyms/aliases, and partitions when the DB
  exposes them.
- RDB-F002: Preserve PK, FK, unique, check, exclusion, generated/default,
  identity, relation ownership, partition, inheritance, view, trigger, routine,
  type, sequence, and generic dependency relationships.
- RDB-F003: Preserve ordered composite columns and vendor metadata needed to
  explain a relation without reading user rows.
- RDB-F004: Use stable collision-safe identities across schemas, overloads,
  quoted identifiers, reserved delimiters, and snapshots.
- RDB-F005: Search and describe every object kind, not only tables and columns.
- RDB-F006: Trace inbound/outbound relationships and impact from any object.
- RDB-F007: Diff complete snapshots without conflating alias-only changes.
- RDB-F008: Provide bounded inventory pages and generic graph queries.
- RDB-F009: Support SQLite, PostgreSQL, MySQL, MariaDB, SQL Server, and Oracle
  with native certified adapters.
- RDB-F010: Provide a generic ODBC path for additional relational databases and
  native extension hooks for vendor-complete facts.

### Completeness Requirements

- RDB-C001: An authoritative result is exactly `complete` or `failed`.
- RDB-C002: A complete snapshot records scope, product/version, adapter/contract
  version, privilege/capability checks, discovered counts, emitted counts, and
  zero unresolved mappings.
- RDB-C003: No adapter may silently drop a discovered object or relationship.
- RDB-C004: Required metadata hidden by permissions fails indexing with a
  redacted actionable error.
- RDB-C005: Unsupported required metadata fails indexing; warnings cannot make a
  snapshot complete.
- RDB-C006: Failed indexing never replaces the last complete generation.
- RDB-C007: Empty search/traversal results are authoritative only for a complete
  snapshot.

### Security And Privacy Requirements

- RDB-S001: Never read or persist application table rows.
- RDB-S002: Never persist or echo credentials and connection strings.
- RDB-S003: SQLite sources are read-only; DDL ingestion denies attachment,
  extension loading, and filesystem/network escape.
- RDB-S004: Definitions and diagnostic output are size-bounded and redacted.
- RDB-S005: Cache paths and aliases cannot escape the caller-selected boundary.
- RDB-S006: Network adapters use read-only/session-safe settings where supported.

### Reliability And Performance Requirements

- RDB-R001: Snapshot replacement and cache migration are atomic and recoverable.
- RDB-R002: Output and traversal work are bounded before materialization.
- RDB-R003: Deterministic ordering produces stable snapshots and diffs.
- RDB-R004: 100k objects are a normal supported workload; 1M objects have a
  measured release ceiling and no unbounded response.
- RDB-R005: Cancellation/timeout failure preserves the previous snapshot.
- RDB-R006: Every certified adapter is tested against a live server in release CI.

### Interface Requirements

- RDB-I001: CLI and MCP expose the same versioned JSON contract.
- RDB-I002: `contract` reports exact built-in adapters, certified versions,
  generic ODBC availability, limits, and metadata-only policy.
- RDB-I003: Index output includes completeness proof and stable snapshot key.
- RDB-I004: Errors use stable machine-readable codes plus redacted messages.
- RDB-I005: Existing v1 caches remain readable and are identified as legacy,
  non-authoritative snapshots until re-indexed.

## Non-Goals

- Reading, sampling, profiling, changing, or copying application row data.
- Executing migrations or application DML.
- Code graph extraction or Code-to-DB linking; Backend Map owns that layer.
- Claiming an untested database/version as certified.
- Replacing vendor catalogs with SQL text guessing when exact metadata exists.

## Architecture

```text
Connection/DDL source
        |
        v
Vendor adapter or generic ODBC adapter
        |
        v
Canonical snapshot assembler
  - strict identity/reference validation
  - discovered/emitted reconciliation
  - privilege/capability proof
        |
        v
Complete snapshot transaction
        |
        +--> SQLite graph cache
        +--> CLI/MCP JSON contract
        +--> search/trace/impact/diff
```

Boundaries:

- Adapters collect vendor facts and report source counts; they do not write the
  graph store.
- The assembler maps facts and rejects any unresolved identity/reference.
- The validator proves structural and declared-scope completeness.
- The graph builder persists only validated complete snapshots.
- CLI/MCP are read-only transport layers over the same core API.

Design patterns used at these boundaries:

- **Ports and Adapters:** `CatalogIntrospector` is the core input port; every
  native or ODBC implementation is replaceable infrastructure.
- **Strategy:** product/version-specific catalog discovery is selected per RDB
  without branching inside the canonical graph model.
- **Anti-Corruption Layer:** `CanonicalSchemaSnapshot` isolates vendor catalog
  names and shapes from the product contract while retaining exact properties.
- **Assembler + Specification:** `CanonicalSnapshotAssembler` normalizes facts;
  structural and completeness validators decide whether they are certifiable.
- **Repository + Unit of Work:** `GraphStore` owns persistence and atomic
  replacement; adapters never write graph state.
- **Result Object:** `AnalysisOutcome` exposes only `complete` or `failed` with
  stable failure codes. Partial authority is not representable.

Patterns are introduced only at ownership boundaries. Adapter-specific query
helpers remain plain functions where an additional abstraction would not reduce
coupling or test cost.

## Implementation Phases

### Phase 1: Requirements And Current-State Audit

Status: Complete (2026-07-22)

Goal:

- Establish the final contract and prove the current gaps.

Deliverables:

- Research decision record.
- Requirement IDs and traceable implementation plan.
- Baseline test and adapter capability evidence.

Verification:

```powershell
cargo test --workspace
```

Rollback:

- Documentation-only; remove the new research and plan files.

### Phase 2: Canonical Contract V2 And Structural Validation

Status: Complete (2026-07-22)

Goal:

- Make silent data loss structurally impossible before expanding adapters.

Deliverables:

- Additive v2 common object/relationship model and extension representation.
- Complete/failed status and proof schema.
- Strict duplicate, parent, reference, cardinality, and identity validation.
- Versioned serialization and v1 cache migration.
- Graph persistence refuses non-complete v2 snapshots.

Verification:

```powershell
cargo test --workspace snapshot graph_builder graph_store
cargo clippy --workspace --all-targets -- -D warnings
```

Rollback:

- Keep the v1 reader and disable v2 writing behind the contract version gate.

### Phase 3: SQLite And DDL Completeness

Status: Complete

Goal:

- Produce the first fully complete certified adapter.

Deliverables:

- CHECK/UNIQUE constraints and expressions.
- Generated expressions, partial/expression indexes, trigger dependencies.
- Complete object/edge count reconciliation.
- Multi-file DDL determinism and strict unsupported-statement failures.

Verification:

```powershell
cargo test --workspace sqlite ddl
```

Rollback:

- Retain old v1 indexing for legacy cache inspection only.

### Phase 4: PostgreSQL Completeness

Status: Complete (2026-07-22)

Goal:

- Certify supported PostgreSQL major versions with full modeled metadata.

Deliverables:

- Checks/exclusions, materialized views, sequences, identity/generated details,
  partitions/inheritance, types/domains/enums, routines/parameters/overloads,
  triggers, and catalog dependency edges.
- Scope and privilege probes with count reconciliation.
- Explicit failure for dependency facts PostgreSQL cannot prove from catalogs;
  optional definition parsing may supplement but never override catalog truth.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d postgres
cargo test --workspace postgres_adapter_live_introspection_is_env_gated -- --nocapture
```

Rollback:

- Disable PostgreSQL v2 certification while preserving v1 cache reading.

### Phase 5: MySQL And MariaDB Completeness

Status: Complete (2026-07-22)

Goal:

- Certify MySQL and MariaDB independently.

Deliverables:

- Views, view dependencies, triggers, routines/parameters, events, checks,
  generated expressions, partitions, index expressions/order, and privileges.
- Product/version detection and dialect-specific catalog paths.
- Separate certification records for MySQL and MariaDB majors.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d mysql mysql80 mysql97 mariadb1011 mariadb114 mariadb118 mariadb123
cargo test -p database-memory-core adapters::mysql -- --nocapture
```

Rollback:

- Remove certification for the failing product/version; retain cache migration.

### Phase 6: SQL Server Completeness

Status: In Progress

Goal:

- Certify SQL Server and supported Azure SQL variants.

Deliverables:

- Views/materialized equivalents, computed/identity details, checks, sequences,
  synonyms, routines/parameters, triggers, types, partitions, included indexes,
  and `sys.sql_expression_dependencies` edges.
- `VIEW DEFINITION` and scope proof.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d sqlserver
cargo test --workspace sqlserver_adapter_live_introspection_is_env_gated -- --nocapture
```

Rollback:

- Disable SQL Server v2 certification.

### Phase 7: Oracle Completeness

Goal:

- Certify supported Oracle major versions and selected schema scopes.

Deliverables:

- Views/materialized views, virtual/identity columns, checks, sequences,
  synonyms, packages/routines/parameters/overloads, triggers, types, partitions,
  function indexes, and dependency edges.
- Explicit USER/ALL/DBA scope and privilege proof.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d oracle
cargo test --workspace oracle_adapter_live_introspection_is_env_gated -- --nocapture
```

Rollback:

- Disable Oracle v2 certification.

### Phase 8: Generic ODBC And Additional RDB Certification

Goal:

- Make the support boundary open-ended without false universal claims.

Deliverables:

- ODBC catalog-function adapter for common RDB metadata.
- Driver capability negotiation and strict completeness reconciliation.
- Native extension hook and certification fixtures for additional products,
  beginning with DB2 and one PostgreSQL-compatible distributed RDB.

Verification:

```powershell
cargo test --workspace odbc -- --nocapture
```

Rollback:

- Ship native adapters only and report generic ODBC unavailable in `contract`.

### Phase 9: Complete CLI And MCP Contract

Goal:

- Expose the complete graph safely to Backend Map and other read clients.

Deliverables:

- Generic list/find/describe for all object kinds.
- Complete proof, support ledger, structured errors, bounded pagination.
- CLI/MCP contract parity and compatibility tests.
- Remove table-only assumptions from public inventory and traversal entrypoints.

Verification:

```powershell
cargo test --workspace
```

Rollback:

- Keep v1 commands as compatibility aliases over the v2 core.

### Phase 10: Scale, Security, Packaging, And Release Audit

Goal:

- Prove production readiness requirement by requirement.

Deliverables:

- 10k/50k/100k/1M scale matrix.
- Threat model and security regression suite.
- Live adapter CI matrix and generated support ledger.
- Windows/Linux packaging and checksum verification.
- Requirement traceability report with no unproven item.

Verification:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Rollback:

- Do not publish; preserve the last certified release and caches.

## Test Plan

- Unit: identifiers, typed metadata, generic extensions, strict validation,
  redaction, bounded graph algorithms.
- Contract: JSON schema, CLI/MCP parity, v1 migration, stable errors.
- Golden: one exhaustive schema per RDB feature family.
- Live: every native adapter against real server containers.
- Differential: compare adapter counts to independent vendor catalog count
  queries under the same principal and scope.
- Failure: permissions, timeout, disconnect, malformed metadata, duplicate keys,
  unresolved references, corrupt cache, interrupted migration.
- Scale: deterministic generated schemas and measured runtime/memory ceilings.
- Security: source scan and runtime assertions proving metadata-only behavior.

## Requirement Traceability

| Requirement group | Primary evidence |
|---|---|
| RDB-F001..F004 | adapter golden/live tests plus snapshot validator |
| RDB-F005..F008 | core, CLI, and MCP contract tests |
| RDB-F009..F010 | generated support ledger and live certification matrix |
| RDB-C001..C007 | completeness proof tests and failure atomicity tests |
| RDB-S001..S006 | security tests, redaction tests, metadata query audit |
| RDB-R001..R006 | store recovery, bounded algorithms, scale and CI evidence |
| RDB-I001..I005 | versioned JSON fixtures and migration tests |

## Risks And Assumptions

- Absolute database-wide completeness requires sufficient metadata privileges;
  insufficient privileges are a failed analysis, not a partial success.
- Some engines do not record dynamic routine dependencies. Those versions cannot
  be certified for dependency-complete analysis without an additional proven
  source.
- ODBC availability depends on installed drivers. Driver presence does not equal
  certification.
- Vendor catalog changes require versioned fixtures and support ledger updates.
- Contract v2 is additive where possible, but Backend Map integration will need a
  deliberate adapter update after DB Memory is certified.

## Implementation And Review Workflow

For every phase:

1. Implement the phase against this plan.
2. Run focused tests, then the full workspace gates.
3. Write `docs/reports/database-memory-complete-rdb.phase-N.md`.
4. Review the diff against requirement IDs before starting the next phase.
