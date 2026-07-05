# Database Memory MCP Implementation Plan

Status: Complete (Phases 1-25 implemented)
Scale: Large

## Goal

Build `database-memory-mcp`: a production-grade RDB schema graph memory MCP server.

The finished product indexes relational database structure into a persistent local graph, then lets AI agents answer project-tracking questions such as:

- What depends on this table or column?
- What is the blast radius of changing or dropping this object?
- Which tables are relationship hubs?
- What changed between two schema snapshots?
- Which schema objects are isolated, risky, or undocumented by relationships?

This is not a SQLite-only prototype. SQLite is the first adapter used to prove the common RDB model.

## Current Facts

- The workspace currently has no source code.
- There is no existing `openwiki/`, `docs/`, package manifest, or implementation to preserve.
- Product direction approved in interview:
  - RDB-wide target.
  - Rust implementation.
  - Live read-only introspection first.
  - No user table data reads by default.
  - Support order: SQLite, PostgreSQL, MySQL/MariaDB, SQL Server, Oracle.

## Proposed Behavior

- Run as a local CLI and MCP stdio server.
- Connect to supported RDBs in metadata-only mode.
- Convert DB-specific catalog results into a common `SchemaSnapshot`.
- Persist snapshots and a graph in local SQLite.
- Expose typed MCP tools for indexing, describing, relationship tracing, impact analysis, diffing, and graph stats.
- Later support migration/DDL files as another snapshot source.

## Success Criteria

- A user can index an SQLite database file and ask `describe_table` and `impact_analysis`.
- The same graph engine works unchanged after adding PostgreSQL and MySQL adapters.
- No default tool reads user table rows.
- Every non-trivial phase leaves one runnable check.
- Phase reports are written to `docs/reports/database-memory-mcp.phase-N.md`.
- Public naming stays RDB/database-first, not SQLite-first.

## Non-Goals

- Running migrations.
- Deploying database changes.
- Auto-fixing indexes or schema design.
- Acting as a live SQL query assistant.
- Reading or sampling user table rows by default.
- Building a UI before the MCP/CLI contract is stable.
- Supporting every database dialect in the first release.

## Architecture

```text
DB / DDL Source
    |
    v
Source Adapter
    - sqlite
    - postgres
    - mysql
    - later: sqlserver, oracle, ddl
    |
    v
SchemaSnapshot
    - database
    - schemas
    - tables
    - columns
    - constraints
    - indexes
    - views
    - triggers
    - routines
    - adapter capabilities
    |
    v
Graph Builder
    - stable node keys
    - stable edge keys
    - dependency normalization
    |
    v
Graph Store
    - local SQLite
    - snapshots
    - nodes
    - edges
    - indexes
    |
    v
Analysis Engine
    - describe
    - search
    - BFS impact
    - relationship paths
    - diff
    - hub/orphan detection
    |
    v
Interfaces
    - CLI
    - MCP stdio tools
```

## Core Model

Node labels:

- `Database`
- `Schema`
- `Table`
- `Column`
- `PrimaryKey`
- `ForeignKey`
- `UniqueConstraint`
- `CheckConstraint`
- `Index`
- `View`
- `Trigger`
- `Routine`

Edge types:

- `DATABASE_HAS_SCHEMA`
- `SCHEMA_HAS_TABLE`
- `TABLE_HAS_COLUMN`
- `TABLE_HAS_INDEX`
- `TABLE_HAS_TRIGGER`
- `TABLE_HAS_CONSTRAINT`
- `TABLE_HAS_VIEW`
- `COLUMN_IN_PRIMARY_KEY`
- `COLUMN_IN_UNIQUE`
- `COLUMN_IN_INDEX`
- `FK_FROM_COLUMN`
- `FK_TO_COLUMN`
- `VIEW_DEPENDS_ON_TABLE`
- `VIEW_DEPENDS_ON_COLUMN`
- `TRIGGER_ON_TABLE`
- `TRIGGER_EXECUTES_ROUTINE`
- `ROUTINE_DEPENDS_ON_TABLE`
- `ROUTINE_DEPENDS_ON_COLUMN`

Stable object key format:

```text
<source-kind>:<connection-alias>:<database>:<schema>:<object-kind>:<object-name>[:<sub-object>]
```

Example:

```text
sqlite:app-db:main:main:table:orders
sqlite:app-db:main:main:column:orders:id
postgres:prod:app:public:table:users
```

## Initial MCP Tools

- `index_database`: introspect a configured database and persist a new snapshot.
- `list_databases`: list indexed connection aliases and snapshots.
- `list_schemas`: list schemas for one snapshot.
- `list_tables`: list tables, optionally filtered by schema/name.
- `describe_table`: return columns, keys, indexes, inbound/outbound FKs, views, triggers.
- `find_table`: fuzzy/name search for tables.
- `find_column`: fuzzy/name search for columns.
- `trace_relationships`: follow graph edges from an object with max depth and direction.
- `impact_analysis`: BFS from table/column and return blast radius grouped by object type.
- `schema_diff`: compare two snapshots.
- `graph_stats`: counts, hubs, isolated objects, adapter capability notes.

## Implementation Phases

### Phase 1: Rust Workspace Skeleton — Implemented

See `docs/reports/database-memory-mcp.phase-1.md`.

Goal:

- Create the minimal Rust project shape.

Deliverables:

- `Cargo.toml`
- `crates/database-memory-core`
- `crates/database-memory-cli`
- Basic `cargo test` pass.

Verification:

```powershell
cargo test
```

Rollback:

- Delete the Rust workspace files.

### Phase 2: Core Domain Types — Implemented

See `docs/reports/database-memory-mcp.phase-2.md`.

Goal:

- Define `SchemaSnapshot`, object structs, identifiers, and adapter capabilities.

Deliverables:

- Core model structs.
- Serialization support.
- One small unit test for stable object keys.

Verification:

```powershell
cargo test -p database-memory-core
```

Rollback:

- Revert core model files.

### Phase 3: Local Graph Store Schema — Implemented

See `docs/reports/database-memory-mcp.phase-3.md`.

Goal:

- Persist snapshots, nodes, and edges in local SQLite.

Deliverables:

- `GraphStore`
- SQLite migrations or explicit bootstrap SQL.
- Indexes for node and edge lookup.

Verification:

```powershell
cargo test -p database-memory-core graph_store
```

Rollback:

- Drop local graph DB file and revert store module.

### Phase 4: Snapshot To Graph Builder — Implemented

See `docs/reports/database-memory-mcp.phase-4.md`.

Goal:

- Convert a `SchemaSnapshot` into graph nodes and edges.

Deliverables:

- Deterministic graph builder.
- Tests for table, column, PK, FK, and index edges.

Verification:

```powershell
cargo test -p database-memory-core graph_builder
```

Rollback:

- Revert builder module only.

### Phase 5: SQLite Introspection Adapter Level 1 — Implemented

See `docs/reports/database-memory-mcp.phase-5.md`.

Goal:

- Read SQLite tables, columns, PKs, FKs, and indexes from a database file.

Deliverables:

- `sqlite` adapter.
- Uses SQLite metadata/PRAGMA only.
- Fixture SQLite database for tests.

Verification:

```powershell
cargo test -p database-memory-core sqlite_adapter
```

Rollback:

- Remove adapter module and test fixture.

### Phase 6: CLI Index Command — Implemented

See `docs/reports/database-memory-mcp.phase-6.md`.

Goal:

- Let a user index a SQLite DB file from the command line.

Deliverables:

- `database-memory index --source sqlite --path <db> --alias <name>`
- Local cache path selection.
- Human-readable summary.

Verification:

```powershell
cargo run -p database-memory-cli -- index --source sqlite --path .\fixtures\sample.sqlite --alias sample
```

Rollback:

- Remove CLI command while keeping core code.

### Phase 7: Describe And Search CLI Commands — Implemented

See `docs/reports/database-memory-mcp.phase-7.md`.

Goal:

- Prove the stored graph is usable without MCP.

Deliverables:

- `describe-table`
- `find-table`
- `find-column`
- Output as text and JSON.

Verification:

```powershell
cargo run -p database-memory-cli -- describe-table sample orders
cargo run -p database-memory-cli -- find-column sample user_id
```

Rollback:

- Remove CLI command handlers.

### Phase 8: Impact Analysis Engine — Implemented

See `docs/reports/database-memory-mcp.phase-8.md`.

Goal:

- Implement bounded BFS over table/column dependency edges.

Deliverables:

- `impact_analysis(object_key, direction, max_depth)`
- Grouped output by object type and distance.
- Cycle-safe traversal.

Verification:

```powershell
cargo test -p database-memory-core impact_analysis
```

Rollback:

- Revert analysis module.

### Phase 9: Relationship Trace Engine — Implemented

See `docs/reports/database-memory-mcp.phase-9.md`.

Goal:

- Return specific paths, not just impacted object sets.

Deliverables:

- Path tracing with max depth.
- Direction control: inbound, outbound, both.
- Tests for FK chains and cycles.

Verification:

```powershell
cargo test -p database-memory-core relationship_trace
```

Rollback:

- Revert path tracing module.

### Phase 10: Snapshot Diff Engine — Implemented

See `docs/reports/database-memory-mcp.phase-10.md`.

Goal:

- Compare two indexed schema snapshots.

Deliverables:

- Added/removed/changed nodes.
- Added/removed edges.
- Impact analysis seeded from changed nodes.

Verification:

```powershell
cargo test -p database-memory-core schema_diff
```

Rollback:

- Revert diff module.

### Phase 11: MCP Server Skeleton — Implemented

See `docs/reports/database-memory-mcp.phase-11.md`.

Goal:

- Expose a minimal MCP stdio server.

Deliverables:

- MCP server crate or module.
- Tool registration.
- `graph_stats` or `list_databases` working first.

Verification:

```powershell
cargo test
```

Rollback:

- Disable MCP binary target; keep CLI.

### Phase 12: MCP Typed Tools Level 1 — Implemented

See `docs/reports/database-memory-mcp.phase-12.md`.

Goal:

- Expose the useful SQLite-backed graph tools through MCP.

Deliverables:

- `index_database`
- `list_databases`
- `list_tables`
- `describe_table`
- `find_table`
- `find_column`
- `impact_analysis`
- `trace_relationships`
- `schema_diff`
- `graph_stats`

Verification:

```powershell
cargo test
```

Rollback:

- Remove individual tool registrations.

### Phase 13: Config And Connection Profiles — Implemented

See `docs/reports/database-memory-mcp.phase-13.md`.

Goal:

- Avoid passing long connection details repeatedly.

Deliverables:

- Config file for aliases.
- Environment variable support for secrets.
- Validation that default mode is metadata-only.

Verification:

```powershell
cargo test -p database-memory-core config
```

Rollback:

- CLI continues accepting direct flags.

### Phase 14: PostgreSQL Adapter Level 1 — Implemented

See `docs/reports/database-memory-mcp.phase-14.md`.

Goal:

- Add production RDB support without changing graph/analysis code.

Deliverables:

- PostgreSQL adapter for schemas, tables, columns, PKs, FKs, unique constraints, indexes.
- Integration test gated by env var or container availability.
- Capability notes for dependency depth.

Verification:

```powershell
cargo test -p database-memory-core postgres_adapter
```

Rollback:

- Feature-gate or remove Postgres adapter.

### Phase 15: PostgreSQL Dependency Depth — Implemented

See `docs/reports/database-memory-mcp.phase-15.md`.

Goal:

- Add view/trigger/routine dependency metadata where reliable.

Deliverables:

- View nodes.
- Trigger nodes.
- Routine nodes.
- `pg_depend`-based edges where available.
- Capability warnings for function-body dependencies that catalogs cannot fully infer.

Verification:

```powershell
cargo test -p database-memory-core postgres_dependencies
```

Rollback:

- Disable Level 2/3 dependency extraction for Postgres.

### Phase 16: MySQL/MariaDB Adapter Level 1 — Implemented

See `docs/reports/database-memory-mcp.phase-16.md`.

Goal:

- Prove the common model across a third RDB family.

Deliverables:

- MySQL/MariaDB adapter for schemas, tables, columns, keys, constraints, indexes.
- Integration tests gated by env var or container availability.

Verification:

```powershell
cargo test -p database-memory-core mysql_adapter
```

Rollback:

- Feature-gate or remove MySQL adapter.

### Phase 17: Capability-Aware Responses — Implemented

See `docs/reports/database-memory-mcp.phase-17.md`.

Goal:

- Make incomplete metadata explicit instead of pretending all DBs expose the same facts.

Deliverables:

- Adapter capability matrix.
- Response warnings.
- Tests that unsupported relationship types are reported.

Verification:

```powershell
cargo test -p database-memory-core capabilities
```

Rollback:

- Keep capability data internal until response format is stable.

### Phase 18: Graph Query Tool — Implemented

See `docs/reports/database-memory-mcp.phase-18.md`.

Goal:

- Add a flexible query escape hatch after typed tools are stable.

Deliverables:

- Minimal graph query grammar or constrained JSON query.
- Read-only execution.
- Query limits.

Verification:

```powershell
cargo test -p database-memory-core graph_query
```

Rollback:

- Remove `query_graph`; typed tools remain.

### Phase 19: DDL/Migration Snapshot Source — Implemented (SQLite only)

See `docs/reports/database-memory-mcp.phase-19.md`. Scope reduced to SQLite DDL, matching the adapter rollout order; Postgres/MySQL DDL sources were not implemented.

Goal:

- Analyze proposed schema changes before they are applied.

Deliverables:

- Migration file discovery.
- Dialect-scoped parser/importer.
- Produces the same `SchemaSnapshot` model.
- Diff from live/current snapshot.

Verification:

```powershell
cargo test -p database-memory-core ddl_source
```

Rollback:

- Keep live introspection only.

### Phase 20: SQL Server Adapter — Implemented

See `docs/reports/database-memory-mcp.phase-20.md`.

Goal:

- Extend RDB support to SQL Server.

Deliverables:

- Metadata adapter.
- Capability notes.
- Integration test gate.

Verification:

```powershell
cargo test -p database-memory-core sqlserver_adapter
```

Rollback:

- Feature-gate adapter.

### Phase 21: Oracle Adapter — Implemented

See `docs/reports/database-memory-mcp.phase-21.md`.

Goal:

- Extend RDB support to Oracle.

Deliverables:

- Metadata adapter.
- Capability notes.
- Integration test gate.

Verification:

```powershell
cargo test -p database-memory-core oracle_adapter
```

Rollback:

- Feature-gate adapter.

### Phase 22: Performance Baseline — Implemented

See `docs/reports/database-memory-mcp.phase-22.md`.

Goal:

- Keep graph operations fast enough for agent use.

Deliverables:

- Synthetic schema generator.
- Benchmarks for indexing, search, impact analysis, and diff.
- Performance budget documented.

Verification:

```powershell
cargo test --release
```

Rollback:

- Remove benchmark harness; keep functional tests.

### Phase 23: Security Hardening — Implemented

See `docs/reports/database-memory-mcp.phase-23.md`.

Goal:

- Make the read-only boundary enforceable and visible.

Deliverables:

- No arbitrary SQL MCP tool.
- Metadata-only query audit.
- Connection redaction in logs/errors.
- Explicit unsafe feature gate for any future row sampling.

Verification:

```powershell
cargo test
```

Rollback:

- Disable affected adapter/tool until fixed.

### Phase 24: Packaging — Implemented

See `docs/reports/database-memory-mcp.phase-24.md`.

Goal:

- Make local installation boring.

Deliverables:

- Release binary build.
- Install instructions for Codex/Claude-compatible MCP config.
- Windows/macOS/Linux notes.

Verification:

```powershell
cargo build --release
```

Rollback:

- Keep source install path documented.

### Phase 25: Documentation And Examples — Implemented (Final Phase)

See `docs/reports/database-memory-mcp.phase-25.md`.

Goal:

- Make the product understandable without source reading.

Deliverables:

- README.
- Example SQLite DB.
- Example MCP config.
- Example questions and outputs.
- Adapter capability table.

Verification:

```powershell
cargo test
```

Rollback:

- Revert docs/examples only.

## Test Plan

Baseline checks:

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

Adapter checks:

```powershell
cargo test -p database-memory-core sqlite_adapter
cargo test -p database-memory-core postgres_adapter
cargo test -p database-memory-core mysql_adapter
```

Manual smoke checks:

```powershell
cargo run -p database-memory-cli -- index --source sqlite --path .\fixtures\sample.sqlite --alias sample
cargo run -p database-memory-cli -- describe-table sample orders
cargo run -p database-memory-cli -- impact-analysis sample orders
```

## Risks And Assumptions

- SQL dialects expose different metadata depth; capability-aware output is required.
- PostgreSQL can track many object dependencies, but function-body dependencies may be incomplete when only catalog metadata is used.
- DDL/migration parsing is valuable but should wait until live introspection proves the graph model.
- `query_graph` is intentionally delayed because typed tools are safer and easier for agents.
- SQLite is the first adapter only; naming must never imply a SQLite-only product.
- No row data is read by default.

## Phase Report Requirement

After each implementation phase, write:

```text
docs/reports/database-memory-mcp.phase-N.md
```

Each report must include:

- Status: Complete, Partial, or Blocked.
- Changed files.
- Verification command and result.
- Deviations from this plan.
- Remaining risks.
- Recommended next phase.

## Codex/Claude Prompt

```text
Read docs/research/database-memory-mcp.md and docs/plans/database-memory-mcp.md.
Implement Phase 1 only with the smallest safe patch.
Do not implement later phases early.
Keep the product RDB-first, not SQLite-first.
Run the smallest relevant checks.
Write docs/reports/database-memory-mcp.phase-1.md with changed files, verification, deviations, risks, and next phase.
```
