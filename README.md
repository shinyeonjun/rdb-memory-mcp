# Database Memory MCP

[![Release](https://img.shields.io/github/v/release/shinyeonjun/rdb-memory-mcp?display_name=tag)](https://github.com/shinyeonjun/rdb-memory-mcp/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Database Memory MCP is a metadata-only RDB schema graph CLI and MCP server. It indexes relational database metadata into a local graph so people and agents can answer schema structure, dependency, diff, and impact questions without exposing table rows.

```text
Database catalog or DDL -> schema graph cache -> CLI / MCP typed queries
```

It is not a live SQL query tool, row-data assistant, deployment tool, or migration runner. Default adapters read catalogs, schema objects, PRAGMA metadata, or DDL-derived metadata; they do not read user table rows.

## Quick start

Download a tagged Windows zip from [Releases](https://github.com/shinyeonjun/rdb-memory-mcp/releases), or build from source with Rust. Then index the included sample DDL and inspect its impact graph:

~~~powershell
database-memory index --source ddl-sqlite --path examples/sample-schema.sql --alias shop --cache-path examples/shop-cache.sqlite
database-memory impact-analysis ddl-sqlite:shop --object-key sqlite:shop:main:main:table:orders --max-depth 3 --limit 50 --format json --cache-path examples/shop-cache.sqlite
~~~

For installation and MCP client configuration, see [docs/install.md](docs/install.md).

## Features

- Index only certified-complete database metadata into a local graph cache; failed analysis never replaces the last complete generation.
- List, find, and describe every canonical object kind, including views, routines, triggers, sequences, types, policies, packages, and extensions. Partition details remain metadata on their owning objects.
- Inspect the exact adapter/server identity, selected scope, discovered-versus-emitted counts, and capability evidence for each complete snapshot.
- Describe tables with columns, keys, inbound/outbound foreign keys, indexes, and capability warnings.
- Find tables and columns by name.
- Analyze impact from a table, column, or graph object key.
- Trace relationship paths through schema graph edges.
- Diff two indexed schema snapshots without treating connection-alias changes as schema changes.
- Use query_graph as a constrained, read-only graph query escape hatch after typed tools are not enough.

## Trust And Scale Behavior

- Snapshot replacement is transactional. A failed re-index keeps the last valid snapshot intact.
- New indexing has exactly two outcomes: `complete` with a verified proof, or `failed` with a structured, redacted error. There is no authoritative partial or unknown state.
- Old v1 caches remain readable but are explicitly reported as `legacy_non_authoritative`; re-index them before relying on completeness.
- Bare aliases work across database types when unique. Ambiguous aliases and duplicate table names return explicit errors with stable-key candidates.
- Generic object results include database, schema, kind, and stable object keys. Object pages clamp at 500; object relationship pages clamp at 200; graph traversals clamp depth to 8 and results to 200. Every bounded response reports clamping or truncation.
- MCP schema diffs default to 100 results and clamp at 200. Each change list, impact seed list, and the shared impact-node budget are bounded; exact category counts and `truncated` remain in the response.
- Bounded traversals merge inbound and outbound evidence before truncation and keep dependencies, constraints, and indexes ahead of broad ownership lists such as table columns.
- Ordinary stable keys keep the original colon-delimited form. Keys containing `:` or `%` inside an identifier use a backward-compatible `v2:` escaped form, so quoted database identifiers do not collide or misparse.
- Missing privileges, unsupported versions, opaque dependencies, catalog mutation, unresolved references, and adapter gaps fail closed instead of being represented as invented metadata.
- SQLite DDL is evaluated in an isolated in-memory database. Row statements, external attachment, virtual tables, and extension loading are denied. Input is deadline-bound and capped at 64 MiB total.

For the full product boundary and design history, see [docs/plans/database-memory-mcp.md](docs/plans/database-memory-mcp.md).

## Release Binaries

Tagged releases build a Windows zip:

~~~text
rdb-memory-mcp-windows-amd64.zip
  database-memory.exe
  database-memory-mcp.exe
  README.md
  LICENSE
~~~

The CLI exposes the same versioned metadata-only contract as MCP. The generic v2 surface is `contract`, `index`, `list-snapshots`, `describe-snapshot`, `list-objects`, `find-objects`, and `describe-object`. The table-specific commands remain compatibility aliases.

~~~powershell
database-memory contract --format json
database-memory list-snapshots --format json --cache-path examples/shop-cache.sqlite
database-memory list-objects ddl-sqlite:shop --kind table --format json --cache-path examples/shop-cache.sqlite
database-memory find-objects ddl-sqlite:shop customer --kind column --format json --cache-path examples/shop-cache.sqlite
database-memory describe-object ddl-sqlite:shop sqlite:shop:main:main:table:orders --format json --cache-path examples/shop-cache.sqlite
database-memory inventory ddl-sqlite:shop --limit 100 --format json --cache-path examples/shop-cache.sqlite
database-memory inventory ddl-sqlite:shop --offset 100 --limit 100 --format json --cache-path examples/shop-cache.sqlite
database-memory impact-analysis ddl-sqlite:shop --object-key sqlite:shop:main:main:table:orders --max-depth 3 --limit 50 --format json --cache-path examples/shop-cache.sqlite
database-memory trace-relationships ddl-sqlite:shop sqlite:shop:main:main:table:orders --max-depth 4 --limit 20 --format json --cache-path examples/shop-cache.sqlite
~~~

The contract reports `metadata_only: true`, `row_data_access: false`, exact certified versions/scopes, ODBC build availability, bounded limits, and the intentionally deferred DB2 boundary.
Inventory responses use stable table-key ordering and report `offset`, `has_more`, and `next_offset`, so callers can continue without treating the first page as the complete schema.

## MCP Client Config

Use the built MCP stdio server binary. Full platform notes and alternate client shapes are in [docs/install.md](docs/install.md).

~~~json
{
  "mcpServers": {
    "database-memory": {
      "command": "/absolute/path/to/target/release/database-memory-mcp",
      "args": []
    }
  }
}
~~~

On Windows, point command at database-memory-mcp.exe.

## Try The Example Schema

The example schema is a small shop database in [examples/sample-schema.sql](examples/sample-schema.sql). It has customers, products, orders, order items, foreign keys, unique constraints, and indexes.

Index it directly from DDL:

~~~powershell
database-memory index --source ddl-sqlite --path examples/sample-schema.sql --alias shop --cache-path examples/shop-cache.sqlite
~~~

The complete index output includes the stable snapshot key, total object and relationship counts, adapter/server identity, selected scope, and the full completeness proof. A concise text run starts like this:

~~~text
snapshot indexed: ddl-sqlite:shop
status: complete
objects indexed: <verified total>
relationships indexed: <verified total>
cache path: examples/shop-cache.sqlite
~~~

DDL imports use the snapshot key ddl-sqlite:<alias>. The graph object keys still use sqlite:<alias>:... because the DDL source applies the SQL to an in-memory SQLite database and reuses SQLite metadata introspection. The DDL authorizer rejects external database attachment and extension loading.

Describe a table:

~~~powershell
database-memory describe-table ddl-sqlite:shop orders --cache-path examples/shop-cache.sqlite
~~~

Captured output:

~~~text
table: orders
columns:
  id INTEGER nullable: no
  customer_id INTEGER nullable: no
  status TEXT nullable: no
  created_at TEXT nullable: no
primary key: id
foreign keys:
  outbound:
    fk_orders_0: orders(customer_id) -> customers(id)
  inbound:
    fk_order_items_1: order_items(order_id) -> orders(id)
indexes:
  idx_orders_customer_id: customer_id unique: no primary: no
~~~

Find tables and columns:

~~~powershell
database-memory find-table ddl-sqlite:shop order --cache-path examples/shop-cache.sqlite
~~~

~~~text
order_items
orders
~~~

~~~powershell
database-memory find-column ddl-sqlite:shop customer --cache-path examples/shop-cache.sqlite
~~~

~~~text
orders.customer_id
~~~

Use `--format json` when the caller needs stable column/table keys, database and schema identity, type, nullability, default value, ordinal position, or generated-column state.

You can also materialize the schema yourself with SQLite, then index the resulting database file with --source sqlite.

~~~powershell
sqlite3 examples/shop.sqlite ".read examples/sample-schema.sql"
database-memory index --source sqlite --path examples/shop.sqlite --alias shop --cache-path examples/shop-cache.sqlite
~~~

## Example MCP Questions

After indexing the example schema, an agent can ask:

- What is impacted if orders.customer_id changes?
- Trace relationships outward from orders.customer_id.
- Find tables related to orders.
- Show me schema graph nodes whose names contain customer.

The MCP client may call impact_analysis like this:

~~~json
{
  "alias": "ddl-sqlite:shop",
  "table": "orders",
  "column": "customer_id",
  "direction": "outbound",
  "max_depth": 2,
  "cache_path": "examples/shop-cache.sqlite"
}
~~~

Representative decoded tool text (bounded-response metadata and edge endpoints are abbreviated below):

~~~json
{
  "direction": "outbound",
  "max_depth": 2,
  "object_key": "sqlite:shop:main:main:column:orders:customer_id",
  "snapshot_key": "ddl-sqlite:shop",
  "groups": [
    {
      "depth": 2,
      "label": "Column",
      "nodes": [
        {
          "depth": 2,
          "display_name": "id",
          "edge_type_used": "FK_TO_COLUMN",
          "label": "Column",
          "node_key": "sqlite:shop:main:main:column:customers:id"
        }
      ]
    },
    {
      "depth": 1,
      "label": "ForeignKey",
      "nodes": [
        {
          "depth": 1,
          "display_name": "fk_orders_0",
          "edge_type_used": "FK_FROM_COLUMN",
          "label": "ForeignKey",
          "node_key": "sqlite:shop:main:main:foreign_key:orders:fk_orders_0"
        }
      ]
    },
    {
      "depth": 1,
      "label": "Index",
      "nodes": [
        {
          "depth": 1,
          "display_name": "idx_orders_customer_id",
          "edge_type_used": "COLUMN_IN_INDEX",
          "label": "Index",
          "node_key": "sqlite:shop:main:main:index:orders:idx_orders_customer_id"
        }
      ]
    }
  ],
  "capability_warnings": []
}
~~~

For relationship tracing from the same column, call trace_relationships with:

~~~json
{
  "alias": "ddl-sqlite:shop",
  "start_object_key": "sqlite:shop:main:main:column:orders:customer_id",
  "direction": "outbound",
  "max_depth": 2,
  "cache_path": "examples/shop-cache.sqlite"
}
~~~

The captured result includes paths from the column to idx_orders_customer_id, to fk_orders_0, and through that FK to customers.id.

## Certified Support Boundary

Every accepted source is metadata-only and must pass exact product/version detection, scope and privilege proof, stable catalog reads, canonical validation, and independent discovered-versus-emitted reconciliation. `database-memory contract --format json` is the machine-readable source of truth.

| Source | Certified versions | Scope and boundary |
| --- | --- | --- |
| `sqlite` | Bundled runtime used by this binary | Read-only `main` catalog/schema. |
| `ddl-sqlite` | SQLite-compatible schema DDL | Isolated `main` catalog/schema; no row statements or external resources. |
| `postgres` | PostgreSQL 14, 15, 16, 17, 18 | One connected database and selected schemas. Compatible products are rejected. |
| `yugabytedb` | YSQL `15.12-YB-2025.2.3.2-b0` | One connected database and selected schemas. Tablet, split, colocation, tablegroup, tablespace, and placement metadata are preserved. YCQL and other releases are rejected. |
| `mysql` | MySQL 8.0, 8.4, 9.7 | One selected database. MariaDB identity is rejected at this entrypoint. |
| `mariadb` | MariaDB 10.11, 11.4, 11.8, 12.3 | One selected database. MySQL identity is rejected at this entrypoint. |
| `sqlserver` | SQL Server 2017, 2019, 2022, 2025 Database Engine | One connected database and selected schemas. Azure variants are not claimed yet. |
| `oracle` | Oracle AI Database 26ai Free `23.26.2.0.0` | One connected PDB/non-CDB and selected owner schemas; Oracle Client 11.2+ is required. |
| `odbc` | Runtime-negotiated SQL Server bridge for the native-certified versions | Optional `odbc` build feature plus a matching 64-bit driver. Other products fail closed until a product strategy is live-certified. |
| `db2` | Not supported | Deliberately deferred because implementation/testing requires a separate IBM license/EULA decision the owner declined. |
