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

- Index a database schema or SQLite DDL file into a local graph cache.
- Describe tables with columns, keys, inbound/outbound foreign keys, indexes, and capability warnings.
- Find tables and columns by name.
- Analyze impact from a table, column, or graph object key.
- Trace relationship paths through schema graph edges.
- Diff two indexed schema snapshots without treating connection-alias changes as schema changes.
- Use query_graph as a constrained, read-only graph query escape hatch after typed tools are not enough.

## Trust And Scale Behavior

- Snapshot replacement is transactional. A failed re-index keeps the last valid snapshot intact.
- Bare aliases work across database types when unique. Ambiguous aliases and duplicate table names return explicit errors with stable-key candidates.
- MCP table and column results include database, schema, and stable object keys. List/search tools and the CLI inventory contract are paged; graph traversals clamp depth to 8 and results to 200 and report whether output was truncated.
- MCP schema diffs default to 100 results and clamp at 200. Each change list, impact seed list, and the shared impact-node budget are bounded; exact category counts and `truncated` remain in the response.
- Bounded traversals merge inbound and outbound evidence before truncation and keep dependencies, constraints, and indexes ahead of broad ownership lists such as table columns.
- Ordinary stable keys keep the original colon-delimited form. Keys containing `:` or `%` inside an identifier use a backward-compatible `v2:` escaped form, so quoted database identifiers do not collide or misparse.
- Adapter limitations are returned with capability warnings instead of being represented as invented metadata.
- SQLite DDL is evaluated in an in-memory database. External database attachment is denied while DDL is being applied.

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

The CLI exposes a versioned metadata-only JSON contract. Machine-readable output is available for `contract`, `index`, `describe-table`, `inventory`, `find-table`, `find-column`, `impact-analysis`, and `trace-relationships`.

~~~powershell
database-memory contract --format json
database-memory inventory ddl-sqlite:shop --limit 100 --format json --cache-path examples/shop-cache.sqlite
database-memory inventory ddl-sqlite:shop --offset 100 --limit 100 --format json --cache-path examples/shop-cache.sqlite
database-memory impact-analysis ddl-sqlite:shop --object-key sqlite:shop:main:main:table:orders --max-depth 3 --limit 50 --format json --cache-path examples/shop-cache.sqlite
database-memory trace-relationships ddl-sqlite:shop sqlite:shop:main:main:table:orders --max-depth 4 --limit 20 --format json --cache-path examples/shop-cache.sqlite
~~~

The contract reports `metadata_only: true` and `row_data_access: false`; traversal and inventory limits are bounded by the binary contract.
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

Captured output from the release CLI:

~~~text
snapshot indexed: ddl-sqlite:shop
tables indexed: 4
columns indexed: 17
constraints indexed: 7
indexes indexed: 5
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
capability warnings:
  view dependency metadata is not tracked by the ddl-sqlite adapter.
  trigger dependency metadata is not tracked by the ddl-sqlite adapter.
  routine dependency metadata is not tracked by the ddl-sqlite adapter.
  cross-object dependency metadata is not tracked by the ddl-sqlite adapter.
  SQLite CHECK and UNIQUE constraints are not emitted as constraint nodes.
  SQLite partial-index predicates and expression-index expressions are not extracted.
  SQLite generated columns are identified, but generation expressions are not extracted.
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
  "capability_warnings": [
    "view dependency metadata is not tracked by the ddl-sqlite adapter.",
    "trigger dependency metadata is not tracked by the ddl-sqlite adapter.",
    "routine dependency metadata is not tracked by the ddl-sqlite adapter.",
    "cross-object dependency metadata is not tracked by the ddl-sqlite adapter.",
    "SQLite CHECK and UNIQUE constraints are not emitted as constraint nodes.",
    "SQLite partial-index predicates and expression-index expressions are not extracted.",
    "SQLite generated columns are identified, but generation expressions are not extracted."
  ]
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

## Adapter Capabilities

All adapters are metadata-only by default. Level 1 targets schemas/tables/columns plus primary keys, foreign keys, unique constraints, and indexes; adapter-specific gaps are listed below and returned at runtime.

| Source | Input | Needs live connection? | Level 1 | Level 2+ metadata |
| --- | --- | --- | --- | --- |
| sqlite | --path <db-file> | Local database file only | Partial: tables, generated-column identity, PK/FK, indexes, views, and triggers | View-to-table/column dependencies are resolved at prepare time. Trigger-body dependencies, CHECK/UNIQUE constraint nodes, partial/expression index definitions, and routines are not fully extracted. |
| ddl-sqlite | --path <sql-file-or-dir> | No | Same SQLite metadata after authorized in-memory DDL application | Same SQLite limitations; external database attachment and extension loading are denied. |
| postgres | --connection-string <url> | Yes | Supported | Furthest along: views, triggers, and routines are supported; cross-object dependencies are partial/best-effort through PostgreSQL catalogs. |
| yugabytedb | --connection-string <YSQL-url> | Yes | Core certified for YSQL 2025.2.3.2 | The complete core outcome includes tablet/hash-key counts, range split clauses, colocation, tablegroups, tablespaces, and placement metadata. The legacy CLI/MCP cache path remains schema-only until the Phase 9 v2 contract wiring; other releases and YCQL are not claimed. |
| mysql | --connection-string <url> | Yes | Supported | Views, triggers, routines, and dependency metadata are unsupported at Level 1. |
| sqlserver | --connection-string <ado-connection-string> | Yes | Supported | Views, triggers, routines, and dependency metadata are unsupported at Level 1. |
| oracle | --connection-string <user/password@connect_string> | Yes; Oracle Client 11.2+ is required at runtime | Supported for the current schema | Views, triggers, routines, and dependency metadata are unsupported at Level 1. |
