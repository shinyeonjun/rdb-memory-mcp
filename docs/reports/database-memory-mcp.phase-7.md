# Database Memory MCP Phase 7 Report

## Status

Complete. Phase 7 CLI handlers (`describe-table`, `find-table`, `find-column`) work against the persisted graph cache, `cargo test` passes, and manual smoke tests of all three commands (text and JSON output) succeed.

## Changed Files

- `crates/database-memory-core/Cargo.toml`
- `crates/database-memory-core/src/graph_builder.rs`
- `crates/database-memory-cli/Cargo.toml`
- `crates/database-memory-cli/src/main.rs`
- `docs/reports/database-memory-mcp.phase-7.md`

## Verification Command And Result

Commands:

```powershell
cargo test
cargo run -p database-memory-cli -- index --source sqlite --path sample.sqlite --alias sample
cargo run -p database-memory-cli -- describe-table sample orders
cargo run -p database-memory-cli -- describe-table sample orders --format json
cargo run -p database-memory-cli -- find-table sample ord
cargo run -p database-memory-cli -- find-column sample user
```

Results:

```text
running 6 tests (database-memory-cli)
test tests::rejects_missing_required_index_flag ... ok
test tests::parses_describe_table_json_format ... ok
test tests::parses_index_command_with_default_cache_path ... ok
test tests::rejects_unsupported_source_before_opening_path ... ok
test tests::find_commands_search_cached_graph ... ok
test tests::describe_table_uses_cached_graph_metadata ... ok
test result: ok. 6 passed; 0 failed

running 10 tests (database-memory-core)
test result: ok. 10 passed; 0 failed
```

`describe-table sample orders` (text):
```text
table: orders
columns:
  id INTEGER nullable: no
  user_id INTEGER nullable: no
  total_cents INTEGER nullable: no
primary key: id
foreign keys:
  outbound:
    fk_orders_0: orders(user_id) -> users(id)
  inbound:
    (none)
indexes:
  idx_orders_user_id: user_id unique: no primary: no
```

`describe-table sample orders --format json` produced well-formed pretty JSON with `table`, `columns`, `primary_key`, `foreign_keys.{outbound,inbound}`, and `indexes`. `find-table sample ord` printed `orders`; `find-column sample user` printed `orders.user_id`.

## Deviations From The Plan

- Codex's sandbox could not run `cargo` (`codex-windows-sandbox-setup.exe not found`) and left verification unrun. Verifying outside the sandbox uncovered two real problems that needed fixing before this phase could be marked complete:
  1. **File corruption from the Node-based write fallback**: in `crates/database-memory-core/src/graph_builder.rs`, the hand-rolled `edge_payload`/`json_string` JSON-escaping helper came out with its backslash escapes stripped (e.g. `'\\'` became the invalid `'\'`, and `'\n'`/`'\r'`/`'\t'` became raw embedded control characters), which failed to compile. Fixed by deleting the hand-rolled escaper entirely and reusing `serde_json` (already a new dependency this phase) via a small `EdgePayload` struct — smaller and correct instead of restoring broken manual escaping.
  2. **Ownership bug** in `crates/database-memory-cli/src/main.rs`'s test fixture: `orders_id` was moved into a `column(...)` call and then reused in `columns: vec![orders_id]` for a primary-key constraint (`error[E0382]: use of moved value`). Fixed by cloning at the first use site, matching the same pattern already used elsewhere in the same fixture.
  - Both fixes were verified by a subsequent clean `cargo test` and `cargo build` (zero warnings) after each change.
- Added `serde_json` to both core and CLI crates — the standard minimal dependency needed for cached metadata payloads and JSON output.
- Updated `graph_builder.rs` to store full serialized metadata objects in graph node payloads. The prior Phase 6 payload only had key/name/kind, which was not enough to describe column type/nullability, constraints, or indexes without re-introspection. **Breaking change**: existing Phase 6 caches must be re-indexed; the CLI returns a clear re-run-index error (`old_cache_error`) if it sees old minimal node payloads.
- Did not implement Phase 8 impact analysis, Phase 9 relationship trace, Phase 10 diff, MCP tools, config profiles, or any user table row reads.

## Remaining Risks

- The new commands assume the current implemented snapshot key shape, `sqlite:<alias>`, until multi-source indexing exists.
- Manual parser still supports only `--flag value`, matching the Phase 6 style.
- This is the second phase in a row (after Phase 6) where Codex's sandboxed exec environment either hung, lost file-write access, or produced silently-corrupted output when falling back to its Node-based filesystem tool. Every phase's generated code must continue to be compiled and smoke-tested outside the sandbox before being marked complete — this phase's two bugs would not have been caught by trusting the sandbox's self-report alone.

## Recommended Next Phase

Proceed to Phase 8: bounded impact analysis over the stored graph.
