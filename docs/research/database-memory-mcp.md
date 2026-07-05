# Database Memory MCP Research

Status: Proposed
Scale: Large
Date: 2026-07-05

## Summary

`database-memory-mcp` should be an RDB schema graph memory server, not a live SQL query assistant and not a deployment tool.

Finished target:

- Connect to relational databases in read-only/introspection mode.
- Normalize schema metadata into one common graph model.
- Persist that graph locally.
- Answer structure, dependency, diff, and impact questions through MCP.
- Avoid reading user table data by default.

## Sources

- MCP tools specification: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP overview: https://modelcontextprotocol.io/specification/2025-11-25/basic
- Official MCP Rust SDK: https://github.com/modelcontextprotocol/rust-sdk
- `rusqlite` docs: https://docs.rs/rusqlite/
- `sqlx` repository: https://github.com/transact-rs/sqlx
- PostgreSQL information schema: https://www.postgresql.org/docs/current/information-schema.html
- PostgreSQL `key_column_usage`: https://www.postgresql.org/docs/current/infoschema-key-column-usage.html
- PostgreSQL `pg_depend`: https://www.postgresql.org/docs/current/catalog-pg-depend.html
- PostgreSQL dependency tracking limits: https://www.postgresql.org/docs/current/ddl-depend.html
- MySQL `INFORMATION_SCHEMA`: https://dev.mysql.com/doc/en/information-schema.html
- MySQL `KEY_COLUMN_USAGE`: https://dev.mysql.com/doc/refman/9.6/en/information-schema-key-column-usage-table.html
- SQLite PRAGMA docs: https://sqlite.org/pragma.html
- codebase-memory-mcp repository: https://github.com/DeusData/codebase-memory-mcp

## Decision: Product Boundary

Context:

- Existing DB MCP servers often focus on live database access, query execution, schema discovery, or performance diagnostics.
- The target here is closer to `codebase-memory-mcp`: pre-index structure once, then answer structural questions cheaply.
- The user explicitly wants RDB as the target, not a SQLite-only prototype.

Options:

- A: Live SQL query MCP.
  - Pros: immediately useful for ad hoc querying.
  - Cons: crowded category, higher data/security risk, weaker differentiation.
- B: RDB schema graph memory MCP.
  - Pros: clear gap, safer, fits impact analysis and project tracking.
  - Cons: less useful for questions that need row-level data.
- C: Combined query + schema memory MCP.
  - Pros: broad surface.
  - Cons: scope creep and unclear trust boundary.

Decision:

- Choose B.

Consequences:

- The server must not execute arbitrary user data queries in default mode.
- Product language should be "read-only RDB schema memory", not "database assistant".
- Future row sampling can be a separate opt-in extension if there is proven demand.

## Decision: Implementation Language

Context:

- `codebase-memory-mcp` is written in C and optimized as a static, high-performance code intelligence binary.
- The DB version needs adapters, normalized metadata structs, graph storage, diffing, MCP JSON handling, and strong error boundaries.
- Official Rust MCP SDK exists, and Rust has mature SQLite and SQL access crates.

Options:

- A: C.
  - Pros: matches codebase-memory-mcp philosophy, small binaries, direct SQLite fit.
  - Cons: more manual memory/error handling, slower iteration for adapter-heavy product.
- B: Rust.
  - Pros: good typed domain modeling, safe graph algorithms, `serde`, `rusqlite`, `sqlx`, MCP SDK path.
  - Cons: more compile-time friction and async/runtime choices.
- C: Go.
  - Pros: fast delivery, easy CLI/server code.
  - Cons: weaker type modeling than Rust for graph/domain invariants.

Decision:

- Choose Rust.

Consequences:

- Start with a Rust workspace and small crates/modules, not a large framework.
- Use `rusqlite` for the local graph store.
- Use direct DB-specific connectors or `sqlx` only where it reduces adapter code.

## Decision: First Input Source

Context:

- RDB products expose metadata through catalog views or PRAGMA commands.
- Parsing SQL DDL first would create dialect complexity before the graph model is proven.
- Migration/DDL parsing is still needed later for "future change impact" from repository files.

Options:

- A: Live read-only introspection first.
  - Pros: stable, precise, immediately useful.
  - Cons: cannot analyze unapplied migrations.
- B: DDL/migration parsing first.
  - Pros: strong code-review workflow.
  - Cons: dialect parsing complexity arrives too early.
- C: Both from day one.
  - Pros: complete.
  - Cons: too much surface before core graph is validated.

Decision:

- Final target is both. First implementation is live read-only introspection.

Consequences:

- Phase 1 must define a source-agnostic `SchemaSnapshot`.
- Later DDL/migration import should produce the same `SchemaSnapshot`.

## Decision: Database Support Order

Context:

- SQLite is easiest to test locally and supports schema metadata through PRAGMA.
- PostgreSQL proves real production RDB usefulness and has rich system catalogs.
- MySQL/MariaDB proves the model is not Postgres-specific.
- SQL Server and Oracle require more dialect and catalog investment.

Options:

- A: SQLite -> PostgreSQL -> MySQL/MariaDB -> SQL Server -> Oracle.
- B: PostgreSQL -> MySQL/MariaDB -> SQLite -> SQL Server -> Oracle.
- C: PostgreSQL only, deeply.

Decision:

- Choose A.

Consequences:

- SQLite is the first adapter, not the product identity.
- All public docs and type names must say RDB or database, not SQLite.

## Decision: Metadata Depth

Context:

- Basic graph value comes from tables, columns, PKs, FKs, and indexes.
- Mature impact analysis also needs views, triggers, routines, constraints, and dependency metadata.
- PostgreSQL tracks some dependencies in `pg_depend`, but its own docs note limits for function bodies defined as strings.

Options:

- A: Basic schema only.
  - Pros: fast first release.
  - Cons: shallow blast radius.
- B: Layered metadata depth.
  - Pros: useful early, extensible to serious cases.
  - Cons: requires capability flags per adapter.

Decision:

- Choose B.

Metadata levels:

- Level 1: schemas, tables, columns, PKs, FKs, unique constraints, indexes.
- Level 2: views and view dependencies.
- Level 3: triggers, routines, checks, generated columns, partial/expression indexes where available.
- Level 4: migration/DDL-derived future graph.

Consequences:

- Adapter outputs must include capability metadata.
- Query results must say when a database cannot expose a relationship reliably.

## Decision: Local Graph Store

Context:

- The server needs persistent indexed metadata and cheap graph traversal.
- SQLite is boring, embedded, portable, and already fits the codebase-memory pattern.
- A graph database dependency would make installation heavier.

Options:

- A: SQLite local graph store.
  - Pros: simple, portable, no server dependency.
  - Cons: traversal logic is application-owned.
- B: Neo4j/Memgraph backend.
  - Pros: graph-native queries.
  - Cons: heavy dependency, deployment cost.
- C: In-memory only.
  - Pros: simplest.
  - Cons: no memory across sessions.

Decision:

- Choose SQLite local graph store.

Consequences:

- Store normalized nodes/edges plus snapshots.
- Add indexes for `node_key`, `label`, `edge_from`, `edge_to`, and `edge_type`.
- Keep Cypher-like syntax optional; typed tools come first.

## Decision: MCP Surface

Context:

- MCP tools expose callable functions with schemas.
- Agents work best with narrow, named tools before a free-form query language.
- Cypher-like querying is powerful but can wait.

Options:

- A: Only `query_graph`.
  - Pros: small tool list.
  - Cons: hard for agents to use reliably.
- B: Typed tools first, query language later.
  - Pros: safer, clearer UX, easier tests.
  - Cons: more tool definitions.

Decision:

- Choose B.

Initial tool set:

- `index_database`
- `list_databases`
- `list_schemas`
- `list_tables`
- `describe_table`
- `find_table`
- `find_column`
- `trace_relationships`
- `impact_analysis`
- `schema_diff`
- `graph_stats`

Later tool set:

- `query_graph`
- `explain_path`
- `detect_hubs`
- `detect_orphans`
- `export_graph`
- `import_snapshot`

## Decision: Security And Privacy

Context:

- DB access is high trust even when read-only.
- Product value does not require reading user table rows.

Options:

- A: Metadata only.
  - Pros: safer default and clean position.
  - Cons: cannot answer data quality questions.
- B: Allow sample rows/counts.
  - Pros: richer context.
  - Cons: privacy and permission risk.

Decision:

- Choose A.

Consequences:

- Default adapters query catalogs only.
- Config should reject arbitrary SQL tools.
- Later sample mode must be explicit, visibly unsafe, and disabled by default.

## Decision: Rollout Shape

Context:

- This is a new architecture and product, not a small feature.
- The user wants the final target defined, but implementation should happen through safe patches.

Decision:

- Use many small phases with phase reports.
- Each phase must leave one runnable check.
- Avoid speculative abstractions, but keep the source -> snapshot -> graph boundary from day one because that is the product spine.

## Open Assumptions

- The first implementation will run as a local MCP stdio server.
- No hosted service, deployment automation, auth proxy, or UI is required before the core CLI/MCP is useful.
- SQLite adapter can use local database files only in early phases.
- PostgreSQL/MySQL adapters can require explicit connection strings with read-only credentials.
- The project may later add DDL/migration parsing, but not before live introspection and graph impact are stable.
