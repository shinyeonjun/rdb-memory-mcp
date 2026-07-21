# Complete RDB Memory Research

Status: Accepted baseline
Scale: Large
Date: 2026-07-22

## Problem

Database Memory must produce a trustworthy, read-only graph of a relational
database. Indexing is successful only when every object and relationship in the
declared analysis scope is represented. Partial metadata must not be returned as
an authoritative graph.

The finished component is the database half of Backend Visual Map. Code-to-DB
linking belongs to the integration layer; Database Memory owns DB-to-DB facts.

## Current Repository Facts

- The workspace contains three Rust crates: core, CLI, and MCP.
- The local graph store is SQLite with snapshot-scoped node and edge tables.
- Current sources are SQLite, SQLite DDL, PostgreSQL, MySQL, SQL Server, and
  Oracle.
- The current model represents database, schema, table, column, PK, FK, unique,
  check, index, view, trigger, and routine objects.
- PostgreSQL extracts views, triggers, routines, and part of catalog dependency
  metadata.
- MySQL, SQL Server, and Oracle intentionally stop at tables, columns, keys, and
  indexes.
- SQLite reports explicit limitations for check/unique constraints, index
  expressions, generated expressions, and trigger dependencies.
- Adapter assembly uses `filter_map` in several places. Missing parents or
  references can therefore be dropped without making indexing fail.
- Live adapter tests are environment-gated. A green default `cargo test` run does
  not prove any network RDB adapter against a real server.
- The CLI and MCP surface are table-centric even though the graph contains more
  object kinds.
- There is no completeness proof, privilege proof, source count reconciliation,
  or supported-version certification in the persisted snapshot.

## External Metadata Facts

### PostgreSQL

PostgreSQL exposes a portable subset through `information_schema` and richer
facts through `pg_catalog`. `pg_class` spans tables, indexes, sequences, and
views; `pg_depend` stores object dependencies; partition metadata has dedicated
catalogs. Information schema rows are privilege-filtered, so row visibility
cannot by itself prove whole-database coverage.

Sources:

- https://www.postgresql.org/docs/current/catalogs-overview.html
- https://www.postgresql.org/docs/current/catalog-pg-depend.html
- https://www.postgresql.org/docs/current/infoschema-tables.html

### MySQL and MariaDB

MySQL exposes views, triggers, routines, parameters, check constraints,
partitions, and view dependencies in `INFORMATION_SCHEMA`. Visible rows and some
definitions depend on privileges. MariaDB is protocol-compatible in many areas
but has catalog differences and requires its own certification.

Sources:

- https://dev.mysql.com/doc/refman/9.1/en/information-schema-general-table-reference.html
- https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html
- https://dev.mysql.com/doc/refman/8.0/en/stored-routines-metadata.html

### SQL Server

SQL Server exposes schema objects through `sys.*` catalog views and dependencies
through `sys.sql_expression_dependencies`. Complete dependency visibility
requires `VIEW DEFINITION`; some dynamic and temporary objects are not tracked by
that catalog.

Sources:

- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-sql-expression-dependencies-transact-sql
- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/catalog-views-transact-sql

### Oracle

Oracle exposes accessible objects through `ALL_*`, owned objects through
`USER_*`, and database-wide objects through `DBA_*`. Routines, dependencies,
views, triggers, identity columns, partitions, materialized views, types, and
synonyms have separate dictionary views. Scope and privileges must therefore be
part of the completeness proof.

`ALL_*` is not a completeness boundary for an arbitrary schema: it contains
only objects accessible through the current session's direct grants and enabled
roles. The native adapter therefore uses `USER_*` for the session user's full
owned schema and requires successful `DBA_*` catalog probes for any explicit
multi-schema scope. A root-container `CDB_*` scan is a separate future scope;
the initial certified contract is one connected PDB or non-CDB only.

`ALL_OBJECTS`/`USER_OBJECTS` is the independent inventory ledger. Specialized
views map the logical graph, while every in-scope inventory row must either map
to a canonical object or to an explicit Oracle extension object. Dictionary
objects marked as Oracle-maintained and recycle-bin artifacts are outside the
application-schema policy; generated logical constraints and indexes remain in
scope. Catalog reads are repeated and must be byte-for-byte stable before a
snapshot can be certified.

Oracle exposes static dependencies through `*_DEPENDENCIES`, but remote database
links and dynamic SQL cannot be assumed to be represented there. Remote links
fail closed. PL/SQL dependency certification requires catalog-tracked static
dependencies plus a proof that no untracked dynamic statement exists; objects
without that proof are not downgraded to partial success.

Sources:

- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/about-static-data-dictionary-views.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_OBJECTS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_TAB_COLS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_CONSTRAINTS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_DEPENDENCIES.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_VIEWS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_MVIEWS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_TRIGGERS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_PROCEDURES.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_ARGUMENTS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_SEQUENCES.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_SYNONYMS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_TYPES.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/ALL_TAB_PARTITIONS.html
- https://docs.oracle.com/en/database/oracle/oracle-database/26/refrn/cdb_-views.html

### Generic RDB Coverage

ODBC catalog functions provide a common floor for catalogs, schemas, tables,
columns, indexes, primary keys, foreign keys, privileges, procedures, and
procedure parameters. They do not provide every vendor extension or dependency,
so ODBC can discover and certify the common contract while native enrichers are
required for a vendor-complete graph.

Source:

- https://learn.microsoft.com/en-us/sql/odbc/reference/develop-app/catalog-functions-in-odbc

## Decision: Meaning Of All RDB

Context:

- The owner selected every relational database as the final product scope.
- The set of RDB products and vendor extensions is open-ended.
- Claiming support without executable evidence conflicts with the product trust
  requirement.

Options:

- A: Name a fixed set of vendors and reject every other RDB.
- B: Treat all RDBs as equivalent through information schema only.
- C: Use a common RDB contract, a generic ODBC discovery path, native vendor
  enrichers, and a certification ledger.

Decision:

- Choose C.
- A database/version is shown as supported only after its contract suite passes.
- Unknown products may be inspected through ODBC, but they are not marked
  complete unless capability and reconciliation checks pass.

Consequences:

- Support is extensible without weakening truth semantics.
- Native adapters remain necessary for vendor-specific dependencies.
- Release artifacts need a generated support ledger rather than prose claims.

## Decision: Completeness Contract

Context:

- A full metadata query can still return only objects visible to the current
  principal.
- Existing adapters can silently discard rows that do not map to known parents.
- An empty relationship result cannot distinguish absence from failed analysis.

Decision:

- Indexing has only two authoritative outcomes: `complete` or `failed`.
- A complete snapshot carries a machine-verifiable proof containing:
  - requested catalog/schema scope,
  - server product and version,
  - principal and metadata capability checks without credentials,
  - discovered and emitted counts by object kind,
  - discovered and emitted counts by relationship kind,
  - zero unresolved mappings,
  - zero unsupported required capabilities,
  - adapter and contract versions.
- Partial work may exist transiently during indexing but is never committed over
  the last complete snapshot.
- A failure identifies the exact category and source identity that could not be
  represented.

Consequences:

- Permission and catalog gaps become hard failures, not warnings.
- Existing limitation warnings remain readable for old snapshots but cannot
  qualify a new snapshot as complete.

## Decision: Canonical Graph Model

Context:

- The existing typed model is useful for common RDB facts.
- No finite common enum can anticipate every vendor object.
- Backend consumers need stable identities and generic traversal.

Decision:

- Preserve typed common objects for database, schema, relation, column,
  constraint, index, routine, parameter, trigger, sequence, and type.
- Add generic extension objects and generic typed relationships for vendor facts
  that do not fit the common contract.
- Stable identity includes source kind, connection alias, catalog/database,
  schema, object kind, object name, and overload/sub-object identity.
- Every relationship stores direction, type, provenance, and adapter evidence.
- Definitions are metadata; user table rows are never read or persisted.

Consequences:

- Existing consumers can migrate additively.
- Vendor support does not require changing the graph store schema for every new
  object kind.

## Decision: Security Boundary

- Read metadata only; never execute user DML or select application rows.
- Open SQLite sources read-only.
- Keep credentials in process environment/input only and redact all errors.
- Persist no connection string, password, token, routine secret, or row sample.
- DDL ingestion remains isolated and denies attachment and extension loading.
- Require explicit metadata privileges and report the minimum missing privilege.
- Bound output, traversal depth, query complexity, and stored definition sizes.

## Decision: Compatibility And Migration

- Existing v1 caches remain readable.
- New complete snapshots use a versioned v2 contract and an atomic cache
  migration.
- A v1 or partial snapshot can be inspected for diagnostics but is never labeled
  complete.
- The last complete generation survives failed re-indexing.

## Verification Strategy

- Pure contract tests validate identities, references, counts, serialization,
  migration, and failure atomicity.
- Golden metadata fixtures cover every common object and edge.
- Live Docker tests are mandatory for PostgreSQL, MySQL, MariaDB, and SQL Server.
- SQLite and DDL tests run locally on every build.
- Oracle uses an official/free container in the release matrix and a native
  client smoke on Windows packaging.
- Generic ODBC tests run against at least PostgreSQL, SQL Server, SQLite, and one
  non-native engine to prove driver portability.
- Each supported database major version has a generated certification record.
- Scale tests cover 10k, 50k, 100k, and 1M graph objects with bounded memory,
  atomic indexing, search, impact, and relationship traversal.
- Security tests prove no row reads, credential persistence, path escape, DDL
  attachment, unbounded output, or stale partial replacement.

## Current Verdict

The repository is a strong metadata graph prototype and already has useful
atomic storage, stable keys, traversal, impact, diff, CLI, MCP, and redaction.
It is not yet a complete RDB memory under the new contract. The highest-risk
gaps are silent row loss, no completeness proof, an underspecified object model,
partial network adapters, table-only public discovery, and skipped live tests.
