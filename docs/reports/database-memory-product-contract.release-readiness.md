# Database Memory Product Contract Release Readiness

Status: Complete locally; owner approved v0.1.1 publication  
Date: 2026-07-11

## Contract

- engine version: 0.1.1
- CLI contract version: 1
- metadata only: true
- row data access: false
- bounded inventory, impact analysis and relationship trace JSON commands: verified
- stable object keys, source-qualified snapshots, constraints, indexes and capability warnings: verified

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p database-memory-cli
powershell -File scripts/package-release.ps1
```

Results:

- CLI tests: 8 passed
- core tests: 59 passed
- MCP tests: 7 passed
- release build: passed
- SQLite DDL product contract: passed
- PostgreSQL 16 live metadata index: passed
- MySQL 8.4 live metadata index: passed

## Local Release Candidate

- archive: `dist/rdb-memory-mcp-windows-amd64.zip`
- archive SHA-256: `77a46aef313a8c908d179865f9d9e431cee7e5b995528aa0d9537aa91b9d7e3c`
- CLI SHA-256: `3863f093de49c71266f24c0dc05b25735cac6f608a1bd07340b69ecbce4c768a`
- contents: `database-memory.exe`, `database-memory-mcp.exe`, `README.md`, `LICENSE`

The release workflow now pins the Rust toolchain and checkout action, runs format/clippy/locked tests, verifies the metadata-only contract through the package script and publishes with the GitHub CLI instead of an unpinned release action.

## Publication

The product-contract implementation and preserved PostgreSQL changes were verified together. The owner approved MIT publication as `v0.1.1`; the release commit, tag and published asset digests are checked after this report's local evidence.
