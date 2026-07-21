# Complete RDB Memory Phase 5 Report

Date: 2026-07-22
Status: Complete
Scope: certified MySQL 8.0, 8.4, and 9.7 plus MariaDB 10.11, 11.4,
11.8, and 12.3 catalog adapters

## Delivered Adapters

- Replaced the partial MySQL collector with a native `CatalogIntrospector` that
  performs one metadata-only, repeatable-read transaction with a consistent
  snapshot. The existing public functions remain a thin compatibility Facade
  and cannot bypass contract-v2 certification.
- Kept MySQL and MariaDB as distinct product Strategies. An explicit
  `MysqlFamilyVersion` selects only the seven live-certified version lines;
  unknown products and version lines fail before metadata is declared complete.
- Separated the vendor catalog Reader (`RawMysqlFamilyCatalog`) from the
  MySQL-family-to-canonical Mapper. The shared Assembler and Specifications own
  canonical validation, discovered/emitted reconciliation, and certification.
- Added Rustls transport through the native MySQL driver. Remote TCP endpoints
  require TLS, cleartext authentication and `LOCAL INFILE` are disabled, and
  every diagnostic passes through bounded credential redaction.

## Complete Metadata

- Emits the selected database/schema, current principal and active roles,
  tables, columns, views, routines and overload-safe parameters, triggers,
  events, partitions/subpartitions, and MariaDB sequences.
- Preserves PK, unique, FK, and check constraints with ordered columns and FK
  update/delete rules. Index metadata retains key order, prefix lengths,
  expressions, descending keys, visibility or ignored state, and uniqueness.
- Preserves defaults, generated expressions, identity/auto-increment facts,
  collation and character sets, engines, row formats, view security and
  algorithms, routine attributes, trigger timing/events, event schedules, and
  vendor partition/sequence properties as canonical annotations.
- MySQL view dependencies come from `INFORMATION_SCHEMA` usage catalogs.
  MariaDB does not expose an equivalent authoritative table-dependency view, so
  the adapter parses `SHOW CREATE VIEW` with the `sqlparser` AST. Nested
  relations are preserved and CTE aliases are excluded without regex or token
  substring guessing.

## Trust And Failure Semantics

- `SHOW GRANTS` is parsed as a scoped privilege proof, including active roles.
  A complete snapshot requires effective schema-wide `SELECT`, `SHOW VIEW`,
  `EXECUTE`, `EVENT`, and `TRIGGER` visibility. Object-only grants or incomplete
  metadata visibility return `permission_denied` and no replacement snapshot.
- The catalog is signed before and after collection from deterministic ordered
  metadata. Concurrent DDL, disappearing objects, hidden definitions, malformed
  ordinals, dangling references, duplicate identities, oversized definitions,
  or raw/emitted count drift fail certification.
- MySQL and MariaDB do not expose a complete dependency catalog for stored
  routine, trigger, and event bodies. If such an opaque body exists, analysis
  returns `unsupported_metadata`; the adapter never guesses edges or labels a
  snapshot complete with missing dependencies. Routine and trigger objects are
  mapped only when all required dependency evidence is authoritative.
- Only catalog and definition metadata is queried. Application table rows are
  neither selected nor persisted. Product-specific query timeouts and a
  read-only transaction boundary constrain collection work.

## Version Matrix

- MySQL 8.0: empty and rich live catalog contracts passed.
- MySQL 8.4 LTS: rich catalog, privilege, role, trigger/event failure, and
  transport contracts passed.
- MySQL 9.7 LTS: empty and rich live catalog contracts passed.
- MariaDB 10.11 LTS: empty and rich live catalog contracts passed.
- MariaDB 11.4 LTS: rich catalog, privilege, role, trigger/event failure, and
  AST view-dependency contracts passed.
- MariaDB 11.8 LTS: empty and rich live catalog contracts passed.
- MariaDB 12.3: empty and rich live catalog contracts passed, including current
  sequence and system-period catalog shapes.

The rich fixture covers composite PK/FK/unique/check constraints, generated
columns, prefix and descending indexes, nested views, partitions, and MariaDB
sequences. All tests run against real Docker servers. Live tests that mutate the
shared fixture database are serialized with a test-only lock so one product
contract cannot observe another test's temporary procedural object.

## Verification

- `cargo test -p database-memory-core adapters::mysql -- --nocapture` with all
  seven regular URLs and both admin URLs: 14 passed, 0 failed.
- `cargo test --workspace --all-targets` with PostgreSQL 16 and the full
  MySQL/MariaDB matrix: CLI 10, core 132, MCP 11; 153 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Post-test residue checks found zero `dm_%` fixture objects and accounts on all
  seven MySQL-family servers.

## Design Pattern Review

- Ports and Adapters keeps the core independent from the MySQL client and
  catalog dialects.
- Strategy isolates product/version catalog differences instead of scattering
  version branches through the canonical model.
- The Reader plus Anti-Corruption Mapper prevents vendor row shapes from leaking
  into graph contracts.
- Specifications and the closed Result Object make incomplete authority
  unrepresentable as a successful snapshot.
- The compatibility Facade preserves callers while routing every analysis
  through the certified path.

No extra repository or factory hierarchy was introduced inside the adapter;
plain query and mapping functions remain where another interface would not
reduce coupling or improve independent testing.

## Deferred Cross-Cutting Gate

Private-CA TLS fixtures, certificate rotation, interruption recovery under
large live catalogs, and release-CI matrix generation remain Phase 10 work.
They are not claimed as evidence in this phase.

## Phase Gate

The seven listed MySQL/MariaDB version lines have certified native Strategies
under contract v2, with explicit closed failures for metadata the products
cannot prove. Phase 6 must bring SQL Server through the same Reader, Strategy,
Mapper, Specification, privilege, reconciliation, and live-server gates before
its existing Level-1 adapter can be called complete.
