# Complete RDB Phase 8 YugabyteDB Certification Report

Date: 2026-07-22

Status: Complete for the exact YugabyteDB YSQL release described below. Phase 8
as a whole remains in progress because DB2 certification is intentionally
deferred.

## Certified Scope

- Product: YugabyteDB YSQL
- Server identity: `15.12-YB-2025.2.3.2-b0`
- Test image: `yugabytedb/yugabyte:2025.2.3.2-b1`
- API boundary: PostgreSQL wire protocol and YSQL `pg_catalog`; YCQL is not in
  this RDB adapter's scope.
- Authority: metadata-only, one read-only repeatable-read transaction, exactly
  `complete` or `failed`, and no application table rows.

The PostgreSQL and YugabyteDB entrypoints reject one another's product identity.
A compatible wire protocol is never treated as product certification. Any other
YugabyteDB release fails until a separate live Strategy passes the same matrix.

## Distributed Metadata

The shared PostgreSQL catalog reader remains the common implementation for YSQL
semantics. A product-specific YugabyteDB Strategy additionally reads and maps:

- `yb_table_properties`: tablet count, hash-key column count, colocation,
  tablegroup OID, and colocation ID for every scoped physical relation/index.
- `yb_get_range_split_clause`: exact range split clauses when applicable.
- `yb_is_database_colocated`: database-level colocation state.
- `pg_yb_tablegroup`: tablegroup identity, ownership, ACL, options, and
  tablespace association.
- `pg_tablespace`: tablespace identity, ownership, ACL, placement options, and
  comments.

Tablespaces and tablegroups are explicit canonical extension objects. Physical
relations link to their effective tablespace and, when colocated, to their
tablegroup. Primary-key indexes and sequences that have no independent YB
storage are retained with `yugabytedb_storage_backed=false`; absence is not
silently interpreted as an unknown value.

## Closed Failure Rules

Certification returns no snapshot when:

- the product identity or exact release does not match the Strategy;
- a YugabyteDB metadata relation/function is missing or unreadable;
- a physical relation lacks its one expected property row;
- tablet, hash-key, colocation, tablegroup, or tablespace fields are internally
  inconsistent;
- a referenced tablegroup/tablespace is absent;
- raw and emitted object/relationship counts differ; or
- an opaque routine body prevents catalog-proven dependencies.

## Live Verification

Passed against the pinned local image:

- empty/default database identity and capability proof;
- rich schema with enum/composite/domain, sequence, PK/FK/unique/check,
  expression/partial/include indexes, hash and range presplitting, view,
  materialized view, and SQL-standard routine;
- colocated database with tablegroup membership;
- custom placement tablespace linked to its table;
- opaque PL/pgSQL routine fail-closed behavior; and
- PostgreSQL/YugabyteDB cross-product rejection.

Regression evidence:

- PostgreSQL 14, 15, 16, 17, and 18 rich catalog contracts passed.
- Default workspace: CLI 10, core 171, MCP 11; 192 passed, 0 failed.
- ODBC-enabled workspace: CLI 10, core 173, MCP 11; 194 passed, 0 failed.
- Default and ODBC-enabled workspace Clippy passed with `-D warnings`.
- Docker Compose configuration validation passed.

## Legal Boundary

YugabyteDB core is used through its Apache-2.0 distribution. DB2 was not pulled,
installed, or tested because doing so would require a separate IBM license/EULA
decision that the owner explicitly declined. This report makes no DB2 support
claim.

## Primary Product References

- <https://docs.yugabyte.com/stable/additional-features/colocation/>
- <https://docs.yugabyte.com/stable/api/ysql/the-sql-language/statements/ddl_create_index/>
- <https://docs.yugabyte.com/stable/api/ysql/the-sql-language/statements/ddl_alter_tablespace/>
