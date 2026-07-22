# Test Tier Separation Plan

Status: Complete (2026-07-22)
Scale: Medium
Branch: `refactor/test-tiers`

## Goal

Make test results truthful before restructuring the large vendor adapters. A
default workspace test run must execute only deterministic unit and contract
tests. Tests that require a live database must be visibly ignored by default,
must run only through the live certification path, and must fail immediately
when their declared connection input is missing.

## Baseline Facts

- `cargo test --locked --workspace` reports 207 passing tests with no live test
  environment variables configured.
- 27 of those tests are live PostgreSQL, YugabyteDB, MySQL/MariaDB, SQL Server,
  or Oracle tests that currently return successfully when their environment is
  absent. The ODBC feature adds one more test with the same behavior.
- Unit, contract, and live tests share adapter modules because the live fixtures
  need private adapter details. Moving them to integration-test crates now would
  force production visibility changes before the adapter boundaries are split.
- `.github/workflows/live-adapters.yml` already owns live database startup, but
  invokes the mixed test modules without an explicit live-only selector.

## Success Criteria

- Default CI reports live database tests as ignored instead of passed.
- Every ignored live test fails with a named missing-environment error when it
  is deliberately selected without its required connection input.
- Live adapter CI runs ignored tests explicitly and supplies every input needed
  by the selected fixture.
- PostgreSQL/YugabyteDB cross-product rejection tests run against the opposite
  product instead of silently skipping.
- MySQL/MariaDB privilege tests receive disposable administrative connections.
- YugabyteDB colocation coverage receives a disposable colocated database.
- Public Rust APIs, JSON contracts, stable keys, cache schema, certification
  behavior, and vendor SQL remain unchanged.

## In Scope

- Live-test attributes and test-only environment validation.
- GitHub Actions live certification commands and disposable database setup.
- Docker Compose settings used only by the live test matrix.
- Contributor documentation for unit/contract and live test commands.

## Out Of Scope

- Splitting Oracle, SQL Server, MySQL/MariaDB, or ODBC production modules.
- Generalizing vendor catalog SQL or changing adapter strategies.
- Changing supported database/version claims.
- Moving private live fixtures into public integration-test APIs.
- Product behavior, persistence, CLI, MCP, or frontend integration changes.

## Implementation

1. Mark every network-backed adapter test with a reasoned Rust `ignore`
   attribute.
2. Replace successful early returns with explicit required-environment checks.
3. Reuse small test-only case collectors for MySQL/MariaDB and SQL Server
   matrices so an empty selected matrix is a failure.
4. Run ignored tests explicitly in the live workflow, including cross-product
   identity checks.
5. Supply disposable MySQL/MariaDB administrative URLs and a YugabyteDB
   colocated database in live CI.
6. Document the two test tiers and their commands.

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --features database-memory-core/odbc
cargo test --locked -p database-memory-core postgres_adapter_live_introspection_is_env_gated -- --ignored
docker compose -f dev/docker-compose.db-test.yml config
```

The deliberately selected live test in the fifth command must fail because the
required environment variable is absent. That failure is the contract check,
not a release failure. Full network certification remains the responsibility of
`.github/workflows/live-adapters.yml` on its provisioned databases.

## Verification Results

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed.
- ODBC-enabled workspace clippy with `-D warnings`: passed.
- Default workspace: 180 passed, 27 explicitly ignored live tests.
- ODBC-enabled workspace: 181 passed, 28 explicitly ignored live tests.
- Deliberately selected PostgreSQL live test without its environment: failed
  immediately with the required variable name.
- Live workflow filters select all 28 ignored tests across their routed jobs.
- Docker Compose configuration: valid.
- Isolated MySQL 8.4 live run: all six catalog and privilege tests passed; the
  disposable container was removed afterward.
- Independent reviewer: no actionable findings and no files edited.

The full GitHub-hosted live matrix and proprietary self-hosted SQL
Server/Oracle/ODBC jobs were not available in this local run. `actionlint` was
also unavailable; workflow commands, filters, YAML structure, and Compose input
were checked separately.

## Roles

Implementer prompt:

> Apply only the test-tier boundary described here. Preserve production and
> public contracts, make skipped live coverage visible, and prove deterministic
> tests remain green.

Reviewer prompt:

> Review the patch without editing it. Verify that every environment-backed
> test is ignored by default, every explicitly selected live path fails closed
> on missing input, the workflow supplies or deliberately routes every required
> input, and no production contract changed.
