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

- Native complete strategies exist for SQLite/DDL, PostgreSQL 14-18, MySQL
  8.0/8.4/9.7, MariaDB 10.11/11.4/11.8/12.3, SQL Server 2017-2025 Database
  Engine, Oracle AI Database 26ai Free 23.26.2.0.0, and YugabyteDB YSQL
  15.12-YB-2025.2.3.2-b0.
- The optional ODBC path performs runtime capability negotiation and has a
  certified SQL Server bridge. Other products fail closed. DB2 is explicitly
  deferred because the owner declined the required IBM license/EULA decision.
- Every new interface index stores a verified contract-v2 completeness proof;
  failed analysis preserves the previous complete generation.
- Generic CLI and MCP discovery covers all 26 canonical object kinds with
  bounded database-side pagination and structured errors.
- The default workspace has 207 passing tests; the ODBC-enabled workspace has
  209. The release-profile workspace also has 207 passing tests. Live network
  cases remain environment-gated and fail closed when a
  product/version or evidence requirement is not certified.
- Certified graph persistence reconciles both semantic relationship counts and
  the physical traversal projection inside the replacement transaction.
- MCP local-file access is restricted to canonicalized startup-time allowed
  roots; CLI path selection remains under the trusted local operator.

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

Completed:

- Native version strategies and live certification for SQL Server 2017, 2019,
  2022, and 2025.
- Fail-closed metadata visibility, transport, dynamic SQL, encrypted module,
  catalog stability, and selected-schema scope gates.
- Table types as canonical user-defined types, including their columns,
  constraints, indexes, and table-valued routine parameter relationships.
- Independent raw-catalog reconciliation for emitted objects and
  relationships, including extension objects and external references.
- XML schema collections/namespaces, typed XML column and routine parameter
  relationships, and schema-scoped extended properties with `sql_variant`
  type, display value, and raw value preservation.
- Cross-schema foreign-key scope rejection/acceptance and live bounded-timeout
  proof across the four-version matrix.
- A shared cooperative `CancellationToken` at the introspection port. Every
  native adapter checks cancellation at lifecycle boundaries, SQLite interrupts
  VM work through its progress handler, and SQL Server races its async discovery
  future against cancellation. Cancelled work emits no snapshot.

Remaining before Phase 6 completion:

- Live certification for selected Azure SQL Database and Azure SQL Managed
  Instance variants; unsupported engine editions continue to fail closed.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d sqlserver2017 sqlserver2019 sqlserver sqlserver2025
cargo test -p database-memory-core sqlserver --no-fail-fast -- --nocapture
```

Rollback:

- Disable SQL Server v2 certification.

### Phase 7: Oracle Completeness

Status: Complete (2026-07-22)

Goal:

- Certify supported Oracle major versions and selected schema scopes.

Certification boundary:

- Accept only server versions represented by a live-tested catalog strategy;
  unsupported versions fail before any snapshot is emitted.
- Treat one connected PDB or non-CDB as the catalog boundary. Root-container
  `CDB_*` discovery is not silently folded into this phase.
- With no schema selection, certify the session user's complete owned schema
  from `USER_*` views. Explicit selected-schema scopes require complete `DBA_*`
  visibility and reject a missing, Oracle-maintained, or partially visible
  owner.
- Use `*_OBJECTS` as the independent inventory ledger. Every selected logical
  object must map to the canonical graph or an explicit Oracle extension; no
  iterator filtering may silently discard an unresolved parent or reference.
- Exclude only documented implementation artifacts such as Oracle-maintained
  objects and recycle-bin entries. System-generated names for real constraints,
  indexes, identity sequences, and other logical objects remain represented.
- Reject remote database-link targets, unresolved cross-scope references,
  invalid catalog objects, truncated definitions, and dependencies that cannot
  be proven complete.

Deliverables:

- Views/materialized views, virtual/identity columns, checks, sequences,
  synonyms, packages/routines/parameters/overloads, triggers, types, partitions,
  function indexes, and dependency edges.
- Explicit USER/ALL/DBA scope and privilege proof.
- Bounded Oracle call timeout, metadata-only connection policy, redacted
  failures, stable double-read, and exact raw-catalog count reconciliation.
- Compatibility facade that returns a legacy `SchemaSnapshot` only after the v2
  complete contract is certified.

Implementation increments:

1. Replace the Level 1 facade with a closed `AnalysisOutcome` adapter, version
   strategy, bounded call timeout, USER/DBA scope policy, raw inventory ledger,
   stable read, and independent counts.
2. Map tables, columns (including hidden/virtual/identity semantics), every
   constraint state, indexes and function expressions, views/view columns, and
   materialized views.
3. Map sequences, synonyms, object/collection types and attributes, table
   partitions/subpartitions, packages, overloaded routines and parameters, and
   all trigger target kinds.
4. Reconcile `*_DEPENDENCIES`, synonym/type/sequence/materialization/partition
   relationships, remote references, invalid objects, and dynamic PL/SQL proof.
5. Live-certify each accepted Oracle strategy with owner-only, privileged
   multi-schema, denied-visibility, cross-schema, timeout, mutation, and residue
   tests. Add a strategy only when its live matrix passes.

Success criteria:

- A rich Oracle fixture emits every independently inventoried object and every
  supported relationship with matching discovered/emitted counts.
- Any unsupported version, insufficient privilege, catalog mutation, timeout,
  remote link, unresolved reference, invalid object, or opaque dependency path
  returns one redacted `failed` outcome and no snapshot.
- The adapter never queries application table rows and leaves no test users,
  schema objects, jobs, links, or other residue after live tests.

Verification:

```powershell
docker compose -f dev/docker-compose.db-test.yml up -d oracle
$env:DATABASE_MEMORY_TEST_ORACLE_URL='system/oracle@127.0.0.1:11521/FREEPDB1'
cargo test -p database-memory-core oracle --no-fail-fast -- --nocapture
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Rollback:

- Disable Oracle v2 certification.

### Phase 8: Generic ODBC And Additional RDB Certification

Status: In Progress (ODBC capability negotiation and the SQL Server bridge are
complete; YugabyteDB YSQL 2025.2.3.2 is complete; DB2 is deferred)

Goal:

- Make the support boundary open-ended without false universal claims.

Deliverables:

- ODBC catalog-function adapter for common RDB metadata.
- Driver capability negotiation and strict completeness reconciliation.
- Native extension hook and certification fixtures for additional products,
  beginning with DB2 and one PostgreSQL-compatible distributed RDB.

Completed slices:

- Generic ODBC support reports exact driver-declared versus runtime-call-verified
  capabilities and fails closed for an unprovable common contract.
- The SQL Server ODBC strategy delegates authoritative discovery to the native
  certified SQL Server adapter after runtime metadata-call verification.
- YugabyteDB YSQL `15.12-YB-2025.2.3.2-b0` (container image
  `yugabytedb/yugabyte:2025.2.3.2-b1`) has its own product Strategy. It preserves
  tablet/hash-key facts, range split clauses, database/table colocation,
  tablegroups, tablespaces, and placement options without treating
  PostgreSQL-wire compatibility as PostgreSQL certification.

Deferred boundary:

- DB2 certification has not started because available runtime/container paths
  require a separate IBM license/EULA decision. The owner declined accepting
  that responsibility. No DB2 driver, image, or license terms are accepted by
  this project until the owner explicitly changes that decision.

Verification:

```powershell
cargo test --workspace odbc -- --nocapture
$env:DATABASE_MEMORY_TEST_YUGABYTE_URL='postgresql://yugabyte@127.0.0.1:15443/yugabyte?sslmode=disable'
cargo test -p database-memory-core yugabytedb -- --nocapture --test-threads=1
```

Rollback:

- Ship native adapters only and report generic ODBC unavailable in `contract`.

### Phase 9: Complete CLI And MCP Contract

Status: Complete (2026-07-22)

Goal:

- Expose the complete graph safely to Backend Map and other read clients.

Deliverables:

- Generic list/find/describe for all object kinds.
- Complete proof, support ledger, structured errors, bounded pagination.
- CLI/MCP contract parity and compatibility tests.
- Remove table-only assumptions from public inventory and traversal entrypoints.

Completed:

- Added one shared contract-v2 application service over the certified adapter
  and graph-store ports. CLI and MCP no longer downgrade complete canonical
  snapshots to legacy `SchemaSnapshot` payloads while indexing.
- Added generic bounded list/find/describe operations for all 26 canonical
  object kinds, snapshot authority/proof reads, structured errors, and a
  generated runtime support ledger.
- Preserved v1 table commands and cache reads as compatibility surfaces while
  marking old snapshots `legacy_non_authoritative`.
- Added CLI/MCP parity tests over one certified cache and fail-closed generation
  replacement tests.
- Bounded SQLite DDL loading, application, and catalog extraction with a real
  deadline/cancellation path and a 64 MiB total input limit.

Verification:

```powershell
cargo test --workspace
```

Rollback:

- Keep v1 commands as compatibility aliases over the v2 core.

### Phase 10: Scale, Security, Packaging, And Release Audit

Status: Complete (2026-07-22)

Goal:

- Prove production readiness requirement by requirement.

Deliverables:

- 10k/50k/100k/1M scale matrix.
- Threat model and security regression suite.
- Live adapter CI matrix and generated support ledger.
- Windows/Linux packaging and checksum verification.
- Requirement traceability report with no unproven item.

Completed:

- Added deterministic 10k/50k/100k/1M release-process scale gates and committed
  Windows X64 evidence. The 1M case remains bounded and is documented as a
  heavyweight ceiling rather than a normal interactive target.
- Added repository threat modeling, read-only source guards, DML/DDL regression
  guards, RustSec auditing, and a reviewed dependency exception ledger.
- Reconciled certified semantic relationship counts against actual graph nodes
  and traversal edges in the same transaction. This exposed and fixed missing
  CHECK-constraint column edges.
- Added a fail-closed MCP filesystem policy with explicit allowed roots and a
  safer environment-variable credential path for CLI profiles.
- Added Windows/Linux quality, release, packaging, checksum, and live adapter
  workflows with pinned actions and Rust 1.96.1.
- Rebuilt and extracted the Windows package, then revalidated its contract,
  support ledger, manifest hashes, and platform checksum.

Verification:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Rollback:

- Do not publish; preserve the last certified release and caches.

### Phase 11: Final Support Ledger And Release Candidate

Status: Complete (publication remains owner-gated)

Goal:

- Stabilize `main`, collect hosted workflow receipts, and freeze the exact
  release support boundary before Backend Map integration begins.

Deliverables:

- Green Windows/Linux hosted quality and packaging runs for the merged commit.
- Green open-source live adapter matrix for every claimed version.
- Proprietary SQL Server/Oracle/ODBC matrix receipt when an owner-controlled,
  licensed self-hosted runner and secrets are available.
- Final machine-readable support ledger review and release-candidate decision.

Completed:

- Prepared the `0.2.0` candidate at behavioral revision
  `a2e8596e81fb2b70c368e4ccca2c4372a1c35f9b`.
- Collected a green four-job hosted CI receipt and a green 13-job open-source
  live matrix receipt for that exact revision.
- Re-read the release binary contract and verified contract v2,
  `metadata_only = true`, `row_data_access = false`, and authoritative outcomes
  limited to `complete` and `failed`.
- Kept the licensed SQL Server, Oracle, and ODBC hosted job owner-gated instead
  of pretending it ran. Prior local live evidence remains documented; a fresh
  hosted receipt requires an owner-controlled licensed Windows runner.
- Froze DB2 as unsupported under the owner's no-EULA decision. It is neither a
  release claim nor a hidden partial implementation.
- Recorded the final decision and exact workflow receipts in
  `docs/reports/database-memory-complete-rdb.phase-11.md`.

Release rule:

- No tag is published while a required workflow is failing or while a claimed
  product/version lacks matching live evidence. DB2 remains explicitly deferred
  under the owner's no-EULA decision and is not a release blocker or claim.

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
| RDB-R001..R005 | store recovery, projection reconciliation, bounded algorithms, and committed scale evidence |
| RDB-R006 | live adapter workflow plus Phase 11 hosted/self-hosted release receipts |
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
