# Complete RDB Phase 11 Release Candidate Report

Date: 2026-07-22

Status: Complete for the owner-authorized boundary. Publication remains an
explicit owner decision.

## Decision

Database Memory `0.2.0` is approved as the database-core candidate for Backend
Map integration. The certified behavioral revision is
`a2e8596e81fb2b70c368e4ccca2c4372a1c35f9b`. This report is a documentation-only
descendant of that revision and does not alter the tested runtime.

No tag or GitHub release was created. A later publication must preserve the
support boundary below and must not represent an unexecuted licensed workflow
as green.

## Hosted Receipts

| Gate | Revision | Result | Receipt |
| --- | --- | --- | --- |
| Candidate CI | `a2e8596` | 4 succeeded, 0 failed | [run 29899329950](https://github.com/shinyeonjun/rdb-memory-mcp/actions/runs/29899329950) |
| Open-source live matrix | `a2e8596` | 13 succeeded, 1 licensed job skipped, 0 failed | [run 29899329149](https://github.com/shinyeonjun/rdb-memory-mcp/actions/runs/29899329149) |
| Merged pre-version CI | `0aab82b` | 4 succeeded, 0 failed | [run 29898347052](https://github.com/shinyeonjun/rdb-memory-mcp/actions/runs/29898347052) |

The first merged live run correctly exposed a YugabyteDB test-fixture race:
parallel DDL invalidated the shared YSQL catalog and returned SQLSTATE `40001`.
The adapter itself had completed its independent contract. The live harness was
made serial for YugabyteDB, then the full matrix passed twice, including the
`0.2.0` candidate. The failed discovery receipt is
[run 29896727473](https://github.com/shinyeonjun/rdb-memory-mcp/actions/runs/29896727473).

## Live Matrix

| Product | Exact tested lines | Candidate result |
| --- | --- | --- |
| PostgreSQL | 14, 15, 16, 17, 18 | All passed |
| YugabyteDB YSQL | `15.12-YB-2025.2.3.2-b0` | Passed |
| MySQL | 8.0, 8.4, 9.7 | All passed |
| MariaDB | 10.11, 11.4, 11.8, 12.3 | All passed |

SQLite file and SQLite DDL sources do not need a server matrix. They passed the
same candidate's deterministic adapter, contract, workspace, release, and
packaging gates.

## Contract Freeze

The `database-memory contract --format json` command was executed from the
release build after the version change and reported:

- product version `0.2.0`;
- interface contract version 2 and complete snapshot contract version 2;
- `metadata_only: true` and `row_data_access: false`;
- authoritative outcomes exactly `complete` and `failed`;
- explicit support entries for SQLite, SQLite DDL, PostgreSQL, YugabyteDB,
  MySQL, MariaDB, SQL Server, Oracle, ODBC, and deferred DB2;
- exact product/version strategies instead of wire-compatible inference.

The default workspace passed 207 tests locally. Candidate CI additionally
passed Windows and Ubuntu default/ODBC formatting, Clippy, tests, RustSec,
release-mode tests, the 10k scale gate, Linux packaging, extraction, contract,
manifest, and checksum verification.

## Licensed Boundary

SQL Server, Oracle, and the SQL Server ODBC bridge retain their implemented
fail-closed strategies and previously recorded disposable local live evidence.
The candidate workflow did not execute those products because the owner chose
not to provision licensed self-hosted infrastructure or accept new vendor
license responsibility. Therefore:

- this report does not claim a fresh hosted proprietary receipt;
- the manual `include_proprietary=true` workflow remains the publication gate
  whenever policy requires a current hosted proprietary run;
- Azure SQL variants are not claimed;
- generic ODBC is not universal RDB support and accepts only a runtime-verified
  SQL Server bridge for native-certified versions;
- DB2 remains unsupported and fails closed under the owner's no-EULA decision.

These are explicit product boundaries, not partial or unknown analysis states.
For every accepted source, an authoritative indexing attempt still ends only as
`complete` or `failed` and never replaces the last complete snapshot on failure.

## Handoff

Backend Map integration may now depend on contract v2 and the `0.2.0` candidate
without importing vendor-specific adapter internals. Future database expansion
must add a product/version Strategy, exhaustive metadata reconciliation, and a
matching live receipt before it enters the support ledger.
