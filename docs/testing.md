# Testing

The repository has two executable test tiers. A passing command must never mean
that a required external database was silently skipped.

## Unit And Contract Tests

Run the deterministic workspace suite with no database services or connection
environment variables:

```powershell
cargo test --locked --workspace
```

This tier includes pure unit tests and local contract tests for the canonical
model, certification, graph persistence, CLI, and MCP surfaces. Live database
tests appear as `ignored` in the result and are not counted as passing tests.

The optional ODBC build has its own deterministic contract run:

```powershell
cargo test --locked --workspace --features database-memory-core/odbc
```

## Live Adapter Certification

Live tests are marked with a reasoned Rust `ignore` attribute. Select them with
`--ignored` only after configuring the environment variable named by the test.
For example:

```powershell
$env:DATABASE_MEMORY_TEST_POSTGRES_URL = "postgresql://user:password@127.0.0.1:5432/database?sslmode=disable"
cargo test --locked -p database-memory-core postgres_adapter_live_introspection_is_env_gated -- --ignored --nocapture
```

An explicitly selected live test fails immediately when its required variable
is absent. Do not run an unfiltered `cargo test -- --ignored` unless every live
database and administrative connection is configured.

The authoritative full matrix is
[`.github/workflows/live-adapters.yml`](../.github/workflows/live-adapters.yml).
It provisions disposable PostgreSQL, YugabyteDB, MySQL, and MariaDB services;
creates the extra YugabyteDB colocated database; and supplies separate
administrative MySQL-family connections for privilege fixtures. SQL Server,
Oracle, and ODBC certification runs only through the explicitly requested
licensed self-hosted job.

The live environment families are:

- `DATABASE_MEMORY_TEST_POSTGRES_URL`
- `DATABASE_MEMORY_TEST_YUGABYTE_URL` and
  `DATABASE_MEMORY_TEST_YUGABYTE_COLOCATED_URL`
- `DATABASE_MEMORY_TEST_MYSQL80_URL`,
  `DATABASE_MEMORY_TEST_MYSQL84_URL`, and
  `DATABASE_MEMORY_TEST_MYSQL97_URL`
- `DATABASE_MEMORY_TEST_MARIADB1011_URL`,
  `DATABASE_MEMORY_TEST_MARIADB114_URL`,
  `DATABASE_MEMORY_TEST_MARIADB118_URL`, and
  `DATABASE_MEMORY_TEST_MARIADB123_URL`
- `DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL` and
  `DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL`
- `DATABASE_MEMORY_TEST_SQLSERVER2017_URL` through
  `DATABASE_MEMORY_TEST_SQLSERVER2025_URL`
- `DATABASE_MEMORY_TEST_ORACLE_URL`
- `DATABASE_MEMORY_TEST_ODBC_SQLSERVER_URL`

Live fixtures create and remove disposable schema objects. Never point their
administrative variables at a production database.
