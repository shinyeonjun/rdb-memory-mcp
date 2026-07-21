# Complete RDB Memory Phase 3 Report

Date: 2026-07-22
Status: Complete
Scope: certified SQLite file and SQLite DDL adapters

## Delivered Adapter

- Replaced the former Level 1 SQLite collector with one catalog pipeline shared
  by the compatibility snapshot API, the certified API, and SQLite DDL input.
- Added a read-only SQLite path Strategy behind `CatalogIntrospector`; the
  adapter opens existing files with `SQLITE_OPEN_READ_ONLY`, enables
  `query_only`, applies a bounded busy/progress timeout, and reads metadata
  inside one transaction.
- Split responsibilities between the SQLite catalog reader, SQLite SQL AST
  parser, vendor-to-canonical mapper, dependency probes, and the common
  certification Assembler. The public SQLite module is now a thin Facade.
- Added first-class `ViewColumn`, `Virtual`, and `Shadow` object semantics so
  persisted SQLite relations are not disguised as ordinary tables or columns.

## Complete Metadata

- Emits named and unnamed PRIMARY KEY, FOREIGN KEY, UNIQUE, and CHECK
  constraints. PK/FK/UQ facts are cross-checked between parsed DDL and PRAGMA
  catalogs; inconsistent or unresolved metadata fails the analysis.
- Preserves generated expressions and storage mode, collations, STRICT and
  WITHOUT ROWID flags, FK actions/deferral, expression and partial indexes,
  index ordering/collation, and auxiliary index columns.
- Uses SQLite's prepare-time authorizer for semantic expression, view, and
  trigger dependencies. Statements are prepared as `EXPLAIN` and never
  stepped, so application rows are not read.
- Keeps nested view relations direct: a view points to the lower view and its
  output columns, while transitive base-table reachability remains graph
  traversal rather than a fabricated direct edge.
- Proves SQLite's absence of persisted routines and all other unsupported
  vendor object categories as explicit zero-count evidence.

## Trust And Failure Semantics

- Reconciles every canonical object and relationship category with evidence
  derived from `database_list`, `table_list`, `table_xinfo`, `index_list`,
  `index_xinfo`, `foreign_key_list`, parsed `sqlite_schema`, and authorizer
  dependency probes.
- Complete snapshots have no limitations and report all required capabilities
  as supported. Any parser, mapping, dependency, count, or certification loss
  returns `failed`; no partial authoritative state is constructed.
- Missing files report a connection-stage failure. Interrupted discovery
  reports a retryable timeout instead of a generic catalog error.
- Snapshot definitions are bounded, system-owned `sqlite_*` objects are
  excluded consistently from inventory and evidence, and stable keys preserve
  reserved identifier characters.

## DDL Safety And Determinism

- Applies `.sql` files in deterministic filename order to an isolated in-memory
  SQLite database and then runs the same complete catalog mapper.
- Parses every top-level statement before execution. Schema DDL and transaction
  wrappers are accepted; row SELECT/INSERT/UPDATE/DELETE, CTAS, ATTACH/DETACH,
  VACUUM/ANALYZE/REINDEX, unsafe PRAGMAs, temporary objects, EXPLAIN, and virtual
  table modules fail explicitly.
- The SQLite authorizer remains a defense-in-depth boundary against attachment,
  extension loading, temporary objects, virtual-table modules, and unknown
  actions.

## Verification

- `cargo test --workspace`: passed.
- `cargo test -p database-memory-core sqlite -- --nocapture`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Tests cover rich composite constraints, generated/check/index expressions,
  trigger writes, view columns, nested views, virtual/shadow tables, stable
  identifiers, graph reachability, DDL ordering/rejection, missing files, and a
  sentinel proving application row values never enter serialized output.

## Phase Gate

SQLite files and SQLite DDL are the first certified complete adapters. Phase 4
must implement PostgreSQL through the same port and certification contract;
the existing partial PostgreSQL path remains non-authoritative until then.
