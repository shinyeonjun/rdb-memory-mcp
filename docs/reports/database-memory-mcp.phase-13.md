# Database Memory MCP Phase 13 Report

## Status

Complete. Added config and connection profiles for named SQLite aliases, with CLI profile resolution for `index`, `describe-table`, `find-table`, and `find-column`. `cargo test` passes and a manual CLI smoke test confirms alias-based `--path`/`--source` resolution works end-to-end. This phase did not add PostgreSQL/MySQL adapters, arbitrary SQL, row reads, or MCP alias resolution.

## Changed Files

- `crates/database-memory-core/Cargo.toml`: added the minimal `toml` dependency.
- `crates/database-memory-core/src/lib.rs`: exports the new config module.
- `crates/database-memory-core/src/config.rs`: TOML profile parsing (`deny_unknown_fields` so a `query`/`sql` field fails to parse), optional config loading, env-var path override convention, and config tests.
- `crates/database-memory-cli/src/main.rs`: adds `--config-path` and resolves `--alias` against config profiles while keeping explicit flags higher priority.
- `docs/reports/database-memory-mcp.phase-13.md`: this report.

## Verification Command And Result

Codex's sandbox could not reach crates.io to resolve the new `toml` dependency and left this unverified. Verifying outside the sandbox with network access:

```powershell
cargo test
cargo build
```

Results:

```text
running 10 tests (database-memory-cli)   ... 10 passed
  test tests::describe_table_uses_config_cache_path_default ... ok
  test tests::cli_flags_override_config_profile_values ... ok
  test tests::parses_index_command_from_config_profile ... ok
  test tests::invalid_config_file_falls_back_to_explicit_flags ... ok
  (plus 6 pre-existing tests)

running 25 tests (database-memory-core)  ... 25 passed
  test config::config_tests::config_missing_file_returns_none ... ok
  test config::config_tests::config_rejects_query_fields_so_default_stays_metadata_only ... ok
  test config::config_tests::config_parses_valid_toml_profiles ... ok
  test config::config_tests::config_path_env_var_overrides_profile_path ... ok
  (plus 21 pre-existing tests)

running 4 tests (database-memory-mcp)    ... 4 passed

cargo build: zero warnings across all four crates
```

39 tests total, all passing. No fixes were needed to the implementation itself.

Manual smoke test: wrote a `.database-memory/config.toml` with an `[sample]` profile (`source = "sqlite"`, `path = "<fixture>.sqlite"`, no explicit `cache_path`), then ran `database-memory index --alias sample` with **no** `--source`/`--path` flags. The CLI correctly resolved both from the config profile and indexed successfully (1 table, 2 columns, 1 constraint), confirming the config-resolution wiring works end-to-end, not just in unit tests.

## Deviations From The Plan

- Used a flat top-level TOML alias map instead of a nested settings framework:

```toml
[app]
source = "sqlite"
path = "db/app.sqlite"
cache_path = ".database-memory/app.sqlite"
```

- The env-var convention is `DATABASE_MEMORY_<ALIAS>_PATH`, with non-alphanumeric alias characters converted to `_` and letters uppercased.
- Invalid config files are ignored by the CLI so explicit flags still work and missing profile values still fall back to the existing required-flag errors.
- `ConnectionProfile` uses `#[serde(deny_unknown_fields)]`, so any config field (like `query` or `sql`) that isn't `source`/`path`/`cache_path` fails to parse — verified by a dedicated test and manually reviewed to confirm the config schema has no code path toward row-data access.
- MCP tools still require explicit `cache_path`; no MCP config/profile behavior was added in Phase 13.

## Remaining Risks

- Config profile resolution is CLI-only for now; MCP tool calls still need an explicit `cache_path` per call. Extending profile resolution to MCP tools is a natural follow-up if a real client needs it.
- `Cargo.lock` now includes `toml` and its transitive deps (`toml_edit`, `winnow`, `indexmap`, etc.) after the networked verification run.

## Recommended Next Phase

Proceed to Phase 14: PostgreSQL adapter level 1, keeping the same metadata-only boundary and reusing the Phase 13 profile shape for future connection strings when that adapter exists.
