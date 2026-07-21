# Complete RDB Memory Phase 2 Report

Date: 2026-07-22
Status: Complete
Scope: canonical contract v2, strict validation, authority, and persistence

## Delivered Contract

- Added a flattened, additive `CanonicalSchemaSnapshot` that keeps legacy v1
  schema fields readable while adding canonical metadata objects, annotations,
  and relationships.
- Added stable object kinds for materialized views, sequences, routine
  parameters, user-defined types, domains, enum values, synonyms, exclusion
  constraints, events, packages, principals, policies, and vendor extensions.
- Added exact metadata properties and standard/vendor relationship types without
  coupling the core to a single vendor catalog.
- Added deterministic normalization for top-level objects, dependencies,
  events, capabilities, annotations, and generic relationships. Ordered
  composite key/index columns remain in source order.

## Trust And Completeness

- Added structural validation for duplicate identities, source/scope mismatch,
  parent kinds, dangling references, column ownership and ordinals, FK
  cardinality, duplicate relationship facts, semantic endpoint kinds, and
  bounded metadata definitions/properties.
- Added contract v2 certification with server, adapter, exact scope, capability
  probes, and per-category object and relationship reconciliation.
- Every discovered count requires bounded catalog evidence, including a proven
  zero. There is no production helper that can certify by simply recounting the
  emitted graph.
- Certified capability state rejects partial, unsupported, unknown, and retained
  adapter limitations. An engine that proves a feature is absent may report a
  supported zero; an adapter that did not inspect it may not.
- Added a closed `AnalysisOutcome` result object. Valid construction exposes
  only a verified `complete` snapshot or a structured `failed` result with a
  stable code, stage, remediation, retryability, bounded text, and credential
  redaction.

## Architecture And Patterns

- `CatalogIntrospector`: Ports and Adapters input port and per-RDB Strategy.
- `CanonicalSchemaSnapshot`: Anti-Corruption Layer for vendor catalog shapes.
- `CanonicalSnapshotAssembler`: Assembler that owns normalization and
  certification.
- Validators: Specification objects for structural and completeness policy.
- `GraphStore`: Repository and transactional Unit of Work.
- `DatabaseAnalysisService`: application service sequencing request validation,
  discovery, assembly, and exact outcome production.

Adapters cannot write graph state through this workflow. The assembler cannot
hide mapping loss because source and emitted counts are independently supplied
and reconciled.

## Cache Compatibility And Atomicity

- Existing v1 payloads remain readable and are explicitly classified as
  `legacy_non_authoritative`.
- Certified v2 payloads are revalidated when read and before every write.
- The low-level snapshot insert API cannot bypass v2 certification, including
  malformed or null contract-version markers.
- Graph cache schema version 2 migrations run inside an immediate transaction.
  Future unknown cache versions are rejected rather than modified.
- Failed structural or certification checks occur before replacement, preserving
  the previous graph generation.

## Verification

- `cargo test --workspace`: passed after the v2 foundation changes.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- Focused contract, canonical validation, graph builder, graph store, and
  application service tests passed.
- Legacy JSON reads through both canonical and legacy snapshot structures.
- Stable object keys round-trip every v2 object kind.

## Phase Gate

Phase 2 is complete. No existing native adapter is certified yet. Phase 3 must
make SQLite and SQLite DDL emit complete canonical facts and independent
catalog evidence before either may write authoritative v2 snapshots.
