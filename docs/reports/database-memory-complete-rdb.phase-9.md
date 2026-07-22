# Complete RDB Phase 9 CLI And MCP Contract Report

Date: 2026-07-22

Status: Complete

## Outcome

CLI and MCP now expose the same contract-v2 application service. New indexing
persists only a verified `CertifiedSchemaSnapshot`; no interface can silently
discard canonical extension metadata or completeness evidence by converting the
result back to the legacy schema model.

The authoritative interface has only two analysis outcomes:

- `complete`: a transactional graph generation plus adapter/server identity,
  exact scope, capability evidence, and discovered-versus-emitted counts.
- `failed`: a bounded, redacted, structured failure. The previous complete
  generation remains untouched.

## Public Contract

- Generic `list_objects`, `find_objects`, and `describe_object` cover all 26
  canonical object kinds.
- `list_snapshots` and `describe_snapshot` expose authority and the complete
  proof. Legacy v1 snapshots remain readable but are always labeled
  `legacy_non_authoritative`.
- Object pages are filtered and bounded inside SQLite before materialization.
  Object pages clamp at 500 and per-direction relationship pages at 200, with
  explicit clamping and truncation metadata.
- `contract` / `get_contract` report exact native product versions, selected
  scope rules, optional ODBC availability, metadata-only policy, and the
  owner-deferred DB2 boundary.
- Existing table-specific CLI and MCP tools remain compatibility aliases over
  the same graph cache.

## Reliability And Security

- Source dispatch validates mutually exclusive path/connection inputs, exact
  product selection for MySQL versus MariaDB, bounded scopes, and deadlines.
- MCP errors are machine-readable `{status,error}` JSON. CLI JSON failures use
  the same shape. Nested adapter failures retain stable code/stage/remediation
  fields without connection secrets.
- SQLite DDL execution now applies deadline and cancellation checks during file
  loading, validation, VM execution, and catalog extraction. DDL input is
  capped at 64 MiB total and remains isolated from row statements,
  attachment, virtual tables, and extensions.
- Certified snapshot replacement remains transactional. Failed analysis and
  failed persistence cannot destroy the last complete generation.

## Compatibility

- Contract v1 command names and table inventory fields remain present.
- Certified payloads are readable by the old table inventory and describe
  commands.
- Existing v1 cache payloads remain readable but cannot be mistaken for a
  complete v2 snapshot.

## Verification

- CLI/MCP parity integration: identical snapshot detail, object page, and
  object detail values from one certified DDL cache.
- Default workspace test suite: 201 passed, 0 failed.
- ODBC-enabled workspace test suite: 203 passed, 0 failed.
- Default and ODBC-enabled workspace Clippy passed with `-D warnings`.
- Formatting and whitespace validation passed.

Phase 10 must now prove scale ceilings, threat-model controls, packaging, and
release traceability. No additional database product is claimed by this phase.
