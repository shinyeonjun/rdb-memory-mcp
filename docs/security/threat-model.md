# Database Memory Threat Model

## Overview

Database Memory is a local, read-only database metadata analysis engine. Its
runtime surfaces are the `database-memory` CLI, the `database-memory-mcp` stdio
server, native/ODBC database adapters, the SQLite DDL ingestion path, and the
local SQLite graph cache. It is not a general SQL client, migration tool, data
browser, hosted multi-tenant service, or authorization layer.

The primary security objective is stronger than ordinary read-only UX: no
successful or failed analysis may read, return, log, or persist application row
values. A new authoritative snapshot may be published only when product,
version, scope, privilege visibility, catalog stability, object counts,
relationship counts, canonical integrity, and graph projection integrity are
all proven. Otherwise the result is `failed` and the prior complete generation
remains intact.

## Threat Model, Trust Boundaries, and Assumptions

### Assets

- Database credentials, TLS client material, and connection endpoints.
- Integrity and availability of the connected production database.
- Application rows, including secrets and regulated or personal data.
- Schema definitions, routine/trigger bodies, object names, and topology, which
  may themselves be confidential source and infrastructure information.
- Completeness proofs, support claims, stable object identity, and cached graph
  generations used to make change-impact decisions.
- Local files reachable by source/cache paths and the host account running MCP.
- Release binaries, manifests, checksums, CI credentials, and GitHub releases.

### Actors and input ownership

- The local operator is trusted to choose a database, source path, requested
  scope, cache location, and least-privilege metadata account.
- A database server and all returned metadata are untrusted inputs. Object
  names, definitions, comments, catalog values, error messages, and version
  banners may be malformed or adversarial.
- SQLite files and DDL files are untrusted inputs, even when selected by the
  operator. DDL can attempt row access, attachment, extension loading, virtual
  tables, excessive allocation, or long-running execution.
- MCP callers, including an LLM influenced by repository content, are
  semi-trusted. Tool arguments must be treated as untrusted even though MCP is
  local stdio rather than a network listener.
- Database drivers, ODBC drivers, native TLS, Oracle Client, the Rust toolchain,
  dependencies, CI actions, and container images are supply-chain trust roots.
- Repository maintainers and the tag-publishing GitHub token are trusted release
  principals. Pull-request code is not trusted with release permissions.

### Trust boundaries

1. CLI/MCP arguments cross into the shared v2 application contract.
2. Connection secrets cross into native client libraries and a remote server.
3. Remote catalog rows cross from a database into product-specific mapping.
4. SQLite/DDL bytes cross into parsers and an isolated in-memory SQLite engine.
5. Discovered metadata crosses certification and canonical validation before it
   can enter the graph projection transaction.
6. Certified metadata crosses into a local SQLite cache and later read APIs.
7. MCP responses cross into an agent host that may log or relay tool payloads.
8. Source, dependencies, CI actions, and tags cross into release artifacts.

### Security invariants

- Live database sessions are metadata-only and read-only. Server adapters must
  retain their engine-specific read-only transaction or access-mode guard.
- Production adapter query literals contain no DML or schema-changing DDL.
- SQLite database files open read-only. DDL executes only after AST validation,
  under an authorizer, in memory, with size, deadline, and cancellation bounds.
- Connection strings are secret inputs, are redacted from structured failures,
  and are never part of snapshot identity or persisted payloads.
- Compatible-looking products, unsupported versions, insufficient visibility,
  unstable catalogs, opaque dependencies, unresolved references, count loss,
  and malformed metadata fail closed.
- Completeness counts and the actual graph projection are reconciled inside the
  same replacement transaction. Projection mismatch rolls back.
- Cache reads are bounded and corrupt/future/incompatible caches are rejected or
  explicitly labeled `legacy_non_authoritative`.
- Release jobs have read-only repository permission until the final publish job;
  actions and Rust are pinned, both host packages are tested, archives are
  extracted, contracts and file hashes are reverified, and SHA-256 files are
  published.

### Assumptions and exclusions

- The operator must provision a metadata-capable, least-privilege account and
  protect the host account. Database Memory cannot reduce privileges granted by
  the server account or protect a fully compromised host.
- The local cache is not encrypted. Filesystem access to it grants access to the
  analyzed schema and definitions, but not application rows.
- MCP stdio authentication and transcript retention belong to the MCP host.
  Database Memory does not expose a listening socket or implement user auth.
- Availability of a vendor driver is not certification. Native drivers and ODBC
  strategies are trusted native-code boundaries and must match the support
  ledger.
- Deliberately executing user business queries, editing schemas, migrations,
  row browsing, and write operations are out of scope and must not be added to
  this product surface.

## Attack Surface, Mitigations, and Attacker Stories

| Surface and attacker story | Existing controls | Residual risk and required operation |
|---|---|---|
| A malicious server returns crafted identifiers or definitions to cause query injection, key collision, or false dependencies. | Parameter binding/engine quoting, typed catalog rows, product/version strategies, stable escaped keys, duplicate/dangling-reference validation, count reconciliation, two stable reads. | Parser/driver defects remain possible. New vendor versions require fixtures and live certification before support is claimed. |
| An overprivileged credential or implementation regression writes to production. | PostgreSQL/MySQL/Oracle read-only transactions, SQL Server read-only client intent, ODBC access-mode set-and-verify, SQLite read-only flags, centralized source regression tests. | Server-side read-only roles remain the strongest control. Operators should not provide write-capable accounts. |
| A DDL file tries to read rows, attach a database, load native code, create a virtual table, exhaust memory, or run indefinitely. | Statement allowlist, SQLite authorizer, isolated in-memory connection, 64 MiB aggregate input cap, progress handler, cancellation, deadline, no partial persistence. | Parsing and local file reads are still CPU/I/O work; run untrusted repositories with normal OS isolation. |
| Secrets leak through errors, aliases, cache payloads, command history, process arguments, or MCP logs. | Structured redaction, secret-shaped alias rejection, no connection string persistence, profile-scoped environment-variable input, row-leak regression fixtures. | `--connection-string` can be visible in shell history/process inspection and MCP hosts may log requests. Use the documented environment-variable path for CLI operation and sanitize host logs. |
| A caller supplies arbitrary paths to read a local SQLite schema or overwrite a cache. | CLI remains an operator interface. MCP canonicalizes existing ancestors/symlinks and rejects source/cache paths outside its startup-time allowed roots; cache format validation and transactional writes still apply inside that boundary. | The MCP process retains the host account's authority inside configured roots. Keep `DATABASE_MEMORY_MCP_ALLOWED_ROOTS` narrow and protect those directories with OS permissions. |
| A huge schema, high-degree graph, or repeated request causes denial of service. | Adapter deadlines/cancellation, bounded DDL, SQL-side pagination, clamped relationship/traversal/diff budgets, 10k/50k/100k/1M scale audit. | Full indexing is intentionally proportional to schema size. Hosts need capacity appropriate to the support matrix and should serialize expensive indexing. |
| A failed or malicious re-index replaces trusted evidence with partial data. | `complete`/`failed` closed outcome, certified payload verification, graph count reconciliation in the replacement transaction, rollback tests. | Cache media failure after a committed transaction is an operational backup concern; re-index from the authoritative database. |
| A forged or corrupt cache is reported as authoritative. | Cache schema version checks, certified payload verification, stable-key and endpoint validation, explicit legacy authority status. | The cache is not cryptographically signed. Protect it with filesystem permissions and regenerate after suspected tampering. |
| A compromised dependency, CI action, tag, or artifact reaches users. | Locked dependencies, RustSec audit, pinned checkout/upload/download action commits, pinned Rust toolchain, least-privilege jobs, tag/version check, two-OS tests, archive extraction and contract/hash verification. | Vendor clients and one tracked unmaintained transitive build macro remain supply-chain dependencies; review the exception ledger on every release. |

### Severity calibration

- Critical: any reachable path that executes writes against a connected database,
  returns application rows, leaks credentials into normal output/cache, or lets
  untrusted pull-request code publish a release.
- High: a false `complete` result caused by omitted metadata, product/version
  confusion, count loss, or generation replacement after a failed analysis; a
  practical arbitrary local-file read through a semi-trusted MCP caller.
- Medium: unbounded resource consumption, cache tampering that requires local
  filesystem access, or schema-definition disclosure without credentials/rows.
- Low: malformed input that fails closed with no secret disclosure, inaccurate
  non-authoritative legacy output labeling, or local-only denial of one request.

The model is reviewed whenever an adapter, object kind, public operation,
credential path, cache format, CI action, packaging target, or support claim
changes.
