# Database Memory Product Contract

Status: Locally verified; owner review, clean commit and release tag pending

## Goal

Expose the existing metadata-only graph as a stable, versioned JSON CLI contract that Backend Visual Map can consume without opening the engine cache or reading database rows.

## Success Criteria

- `database-memory contract --format json` identifies the binary version, contract version, metadata-only boundary, and supported commands.
- table description preserves columns, PK, inbound/outbound FK, unique/check constraints, indexes, and adapter capability warnings when the adapter can provide them.
- bounded impact and relationship-trace commands return stable object keys, edge types, depth, direction, snapshot key, and capability warnings.
- no row-sampling Cargo feature exists in the product build; adding one requires a new reviewed contract boundary.
- JSON fixtures and CLI tests lock the contract shape without storing connection strings or row data.

## Scope

In scope: `database-memory-cli`, shared core serialization helpers where necessary, contract tests, release documentation, and a product-safe feature guard.

Out of scope: arbitrary SQL, row sampling, changing database schemas, editor/UI work, or direct cache coupling from the desktop app.

## Affected Areas

- `crates/database-memory-cli/src/args.rs`
- `crates/database-memory-cli/src/main.rs`
- `crates/database-memory-cli/src/metadata.rs`
- focused shared code in `database-memory-core` only when it removes duplicate graph-contract logic
- CLI contract fixtures and release notes

The existing local change in `crates/database-memory-core/src/adapters/postgres.rs` must be preserved.

## Implementation Steps

1. Add contract/version JSON and validate output stability.
2. Complete table metadata JSON without breaking the existing v0.1 command shape.
3. Add bounded impact and trace JSON commands using the existing core graph algorithms.
4. Keep row sampling absent from the build and maintain sanitized contract fixtures.
5. Build the release binary and update Backend Visual Map only after the contract tests pass.

## Test Commands

```powershell
cargo test -p database-memory-cli
cargo test --workspace
cargo build --release -p database-memory-cli
target/release/database-memory.exe contract --format json
```

## Codex Implementer Prompt

```text
Read AGENTS.md and docs/plans/database-memory-product-contract.md. Implement the requested step only. Preserve the existing postgres.rs user modification, keep the CLI metadata-only, reuse current graph algorithms, add focused contract tests, and report exact verification results.
```

## Codex Reviewer Prompt

```text
You did not write this code. Review only the current database-memory product-contract diff. Do not edit. Check JSON compatibility, bounded traversal, row-data safety, feature guards, secret handling, and whether simpler existing core helpers should replace duplication. Findings first.
```
