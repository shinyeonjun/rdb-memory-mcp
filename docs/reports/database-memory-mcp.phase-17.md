# Database Memory MCP Phase 17 Report

## Status

Complete. Capability-aware responses now expose already-stored adapter capability limits from the persisted snapshot payload. MCP responses for `describe_table`, `impact_analysis`, and `trace_relationships` include `capability_warnings`; CLI `describe-table` includes the same warnings in JSON and a short text section.

## Changed Files

- `crates/database-memory-core/src/lib.rs`: added shared `capability_warnings` formatting for Unsupported, Partial, and Unknown capability support.
- `crates/database-memory-core/src/graph_store.rs`: added `GraphStore::get_snapshot_capabilities`, reading capabilities from existing `graph_snapshots.payload_json` without adding duplicated storage.
- `crates/database-memory-mcp/src/lib.rs`: added capability warnings to `describe_table`, `impact_analysis`, and `trace_relationships` responses plus sqlite/mysql/postgres warning tests.
- `crates/database-memory-cli/src/main.rs`: added capability warnings to `describe-table --format json` and text output.
- `docs/reports/database-memory-mcp.phase-17.md`: this report.

## Verification Command And Result

Formatting:

~~~powershell
C:/Users/plosind/.cargo/bin/cargo.exe fmt --check
~~~

Result: passed after running `cargo fmt` once.

Targeted tests:

~~~powershell
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-mcp
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-core graph_store
C:/Users/plosind/.cargo/bin/cargo.exe test -p database-memory-cli
~~~

Results:

- MCP: 6 passed, including sqlite warnings, mysql unsupported warnings, and postgres no unsupported view/trigger/routine warning.
- Core graph_store: first attempt hit the known Windows file-lock error (os error 32), second attempt passed: 3 passed.
- CLI: 11 passed.

Workspace check:

~~~powershell
C:/Users/plosind/.cargo/bin/cargo.exe test
~~~

Result: first attempt hit the known Windows file-lock error (os error 32), second attempt passed:

~~~text
running 11 tests (database-memory-cli)  ... 11 passed
running 31 tests (database-memory-core) ... 31 passed
running 6 tests (database-memory-mcp)   ... 6 passed
~~~

48 tests total passed across the workspace, plus doc-tests with 0 tests.

Independently re-verified outside the sandbox: `cargo test` (48 tests across all crates, all passing after 1 transient Windows file-lock retry) and `cargo build` (zero warnings after 1 retry for the same reason). Codex's self-reported results matched exactly — no fixes were needed.

## Deviations From The Plan

- No new graph storage column/table was added. Capabilities are retrieved from the existing snapshot `payload_json` using serde, which keeps storage single-sourced.
- PostgreSQL responses still warn that cross-object dependency metadata is partially tracked, because `dependencies` is `Partial`. They do not warn that view, trigger, or routine support is unsupported.
- CLI text output got only a small `capability warnings:` section; no broader renderer redesign.

## Remaining Risks

- Older caches whose snapshot payloads predate `capabilities` will return a payload error when a capability-aware response is requested. Existing Phase 17 snapshots are fine because `SchemaSnapshot` already stores capabilities.
- Capability warnings are intentionally broad per snapshot, not filtered to only the specific object type being described or traced.

## Recommended Next Phase

Proceed to Phase 18 only if needed: a read-only `graph_query` tool over already-indexed graph metadata. Do not add DDL parsing, SQL Server/Oracle adapters, or row-data access until the typed capability-aware surfaces are accepted.
