# Database Memory Paged Inventory

Status: Implemented and locally verified

## Goal

Let desktop consumers read schemas larger than one inventory response without presenting a partial page as the complete database.

## Success Criteria

- `database-memory inventory` accepts `--offset` and keeps the existing stable table-key ordering.
- JSON reports `offset`, `has_more`, and `next_offset` alongside the existing total and limit fields.
- Existing calls without `--offset` remain compatible and return the first page.
- Empty and out-of-range pages terminate safely without repeating data.
- Backend Visual Map verifies page identity, merges every accepted page in Rust, and records an explicit gap if paging stops early.
- The desktop bootstrap remains bounded while full Rust-side search and exact totals cover the merged inventory.

## Scope

In scope: additive CLI pagination, page contract tests, desktop page ingestion, bounded DB bootstrap, and bundled engine refresh.

Out of scope: row data, arbitrary SQL, schema mutation, and replacing the existing metadata graph.

## Affected Areas

- `crates/database-memory-cli/src/args.rs`
- `crates/database-memory-cli/src/main.rs`
- `crates/database-memory-cli/src/metadata.rs`
- Backend Visual Map DB inventory and bootstrap adapters

## Implementation Steps

1. Add and test the additive CLI page fields and `--offset` parsing.
2. Fetch and validate pages in the desktop Rust layer, preserving partial results as explicit unknown coverage on failure.
3. Bound DB data crossing into React while retaining exact summary counts and Rust-side search.
4. Rebuild the bundled engine and run both repositories' full checks.

## Test Commands

```powershell
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
npm run typecheck
npm test -- --run
cargo test --locked
```

## Verification Result

- Database Memory: format, Clippy with warnings denied, and all 84 workspace tests passed.
- Backend Visual Map: typecheck, dead-code scan, 68 frontend tests, 164 Rust tests, Clippy with warnings denied, and production frontend build passed.
- The bundled development engine passed the metadata-only contract and SQLite DDL product smoke.
- A 1,001-table generated schema returned two pages with 1,001 unique stable keys; the 1,000-table page completed in about 1.95 seconds after the bulk-path fix.

## Codex Implementer Prompt

```text
Read docs/plans/database-memory-paged-inventory.md. Implement one step at a time with additive JSON compatibility, deterministic ordering, explicit partial coverage, and no row-data access.
```

## Codex Reviewer Prompt

```text
Review the paged-inventory diff only. Check duplicate or skipped pages, snapshot identity drift, output bounds, partial-result honesty, and compatibility for callers that omit --offset.
```
