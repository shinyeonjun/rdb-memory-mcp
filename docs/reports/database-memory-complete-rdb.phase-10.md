# Complete RDB Phase 10 Production Readiness Report

Date: 2026-07-22

Status: Complete. Hosted workflow receipts remain the Phase 11 release gate.

## Outcome

Phase 10 closes the local production-readiness work for scale, security,
projection integrity, packaging, and automation. It does not broaden the
certified database list. Unsupported versions/products still fail closed, DB2
remains owner-deferred, and no release may be tagged until the merged commit's
hosted/live workflow gates pass.

## Scale Evidence

Release-mode measurements were collected in separate processes on Windows X64
with Rust 1.96.1. The exact machine-readable record is
`docs/reports/evidence/database-memory-scale-windows-x64.json`.

| Target | Actual objects | Graph edges | Index | Page | Search | Impact | Cache | Peak working set |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10k | 10,009 | 13,342 | 1.361 s | 6 ms | 6 ms | 4 ms | 36.2 MB | 54.6 MB |
| 50k | 50,005 | 66,670 | 5.953 s | 21 ms | 28 ms | 4 ms | 179.8 MB | 247.8 MB |
| 100k | 100,009 | 133,342 | 12.135 s | 41 ms | 52 ms | 5 ms | 359.9 MB | 487.0 MB |
| 1M | 1,000,009 | 1,333,342 | 126.013 s | 477 ms | 561 ms | 27 ms | 3.65 GB | 4.79 GB |

The 100k case is the normal large-workload target. The 1M case is a measured
offline ceiling and should have at least 8 GB of free RAM and 8 GB of free disk.
Every response stayed bounded; the impact query reported truncation instead of
materializing the full high-degree graph.

## Security And Reliability

- `cargo audit` reports zero vulnerabilities. The only warning is the
  documented unmaintained `paste 1.0.15` build macro through Oracle 0.6.3.
- SQL Server and MySQL were moved from vulnerable/outdated Rustls paths to the
  platform-native TLS stack.
- Regression tests lock each adapter's read-only session guard and reject
  production adapter source containing DML or schema-changing DDL literals.
- CLI profiles can receive secrets through
  `DATABASE_MEMORY_<ALIAS>_CONNECTION_STRING`, avoiding shell arguments.
- MCP source/cache paths are canonicalized against startup-time allowed roots.
  Both source and cache rejection are tested through actual MCP tool methods.
- Certified graph writes verify physical node/edge counts before commit. The
  new invariant found a real omission: CHECK constraints were counted but their
  column edges were absent. `COLUMN_IN_CHECK` now preserves that impact path.
- The repository threat model and dependency exception ledger are under
  `docs/security/`.

## Packaging And Automation

- Rust is pinned to 1.96.1.
- CI covers Windows and Ubuntu, default and ODBC builds, formatting, Clippy,
  debug/release tests, RustSec, a 10k scale gate, and Linux packaging.
- The live matrix covers PostgreSQL 14-18, YugabyteDB, MySQL 8.0/8.4/9.7, and
  MariaDB 10.11/11.4/11.8/12.3. Licensed SQL Server, Oracle, and ODBC runs are
  manual on an owner-controlled Windows runner.
- Release jobs build Windows and Linux archives, verify tag/version parity,
  extract each archive, rerun the contract, verify every manifest hash, and
  publish only after both platforms pass.
- Local Windows packaging passed after extraction and contract/hash/checksum
  verification. Linux execution is intentionally verified by the hosted job.

## Requirement Traceability

| Requirements | Evidence | Disposition |
| --- | --- | --- |
| RDB-F001..F004 | native adapter fixtures/live tests, canonical validation, stable-key tests | Covered for support-ledger versions |
| RDB-F005..F008 | generic v2 list/find/describe, bounded graph/impact/trace/diff tests | Covered |
| RDB-F009 | generated support ledger and product/version strategies | Covered exactly; no compatible-product inference |
| RDB-F010 | ODBC capability probe and SQL Server bridge tests | Covered as fail-closed extension path, not universal certification |
| RDB-C001..C007 | certification reconciliation, projection verification, rollback and failed-generation tests | Covered |
| RDB-S001..S004/S006 | row-leak fixtures, DDL authorizer, redaction, read-only/query source guards | Covered |
| RDB-S005 | `McpPathPolicy`, allowed-root and tool-level denial tests; CLI remains operator-controlled | Covered |
| RDB-R001..R005 | graph transaction tests, deterministic ordering, cancellation, bounded algorithms, committed scale evidence | Covered |
| RDB-R006 | `.github/workflows/live-adapters.yml` and previous live certification reports | Implemented; merged-run receipts are Phase 11's release gate |
| RDB-I001..I005 | CLI/MCP parity, contract-v2 tests, structured errors, v1 authority labeling | Covered |

## Verification

- Default debug workspace: 207 passed, 0 failed.
- ODBC debug workspace: 209 passed, 0 failed.
- Default release workspace: 207 passed, 0 failed.
- Default and ODBC Clippy: passed with `-D warnings`.
- Formatting, diff whitespace, actionlint: passed.
- RustSec: 0 vulnerabilities, 1 documented maintenance warning.
- Scale audit: all four targets passed their time, memory, cache, and bounded
  response budgets.
- Windows package: archive extraction, contract, support ledger, manifest, and
  SHA-256 verification passed.

## Honest Boundary

This report proves the implementation and local Windows evidence. It does not
pretend that a workflow definition is the same thing as a hosted receipt.
Phase 11 must collect green Windows/Linux and open-source live runs after merge.
The proprietary matrix additionally requires infrastructure and licenses the
owner controls; absent that receipt, no new proprietary release claim is added.
