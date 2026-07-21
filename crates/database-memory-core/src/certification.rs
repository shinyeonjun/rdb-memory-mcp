use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::canonical::{normalize_canonical_snapshot, CanonicalSchemaSnapshot};
use crate::canonical_validation::validate_canonical_schema_snapshot;
use crate::snapshot_validation::SnapshotValidationIssue;
use crate::{CapabilitySupport, ConstraintKind, ObjectKind};

pub const COMPLETE_CONTRACT_VERSION: u32 = 2;
pub const MAX_PROOF_TEXT_BYTES: usize = 16_384;
pub const MAX_SCOPE_VALUE_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedSchemaSnapshot {
    pub contract_version: u32,
    #[serde(flatten)]
    pub snapshot: CanonicalSchemaSnapshot,
    pub completeness: CompletenessProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletenessProof {
    pub status: CompletionStatus,
    pub adapter: AdapterIdentity,
    pub server: ServerIdentity,
    pub scope: IntrospectionScope,
    pub object_counts: Vec<CountReconciliation>,
    pub relationship_counts: Vec<RelationshipCountReconciliation>,
    pub capability_checks: Vec<CapabilityCheck>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionStatus {
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdapterIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub product: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntrospectionScope {
    pub catalogs: Vec<String>,
    pub schemas: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CountReconciliation {
    pub category: ObjectCategory,
    pub discovered: u64,
    pub emitted: u64,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationshipCountReconciliation {
    pub category: RelationshipCategory,
    pub discovered: u64,
    pub emitted: u64,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryCounts {
    pub objects: BTreeMap<ObjectCategory, DiscoveredCount>,
    pub relationships: BTreeMap<RelationshipCategory, DiscoveredCount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredCount {
    pub count: u64,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectCategory {
    Database,
    Schema,
    Table,
    Column,
    PrimaryKey,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Index,
    View,
    ViewColumn,
    Trigger,
    Routine,
    MaterializedView,
    Sequence,
    RoutineParameter,
    UserDefinedType,
    Domain,
    EnumValue,
    Synonym,
    ExclusionConstraint,
    Event,
    Package,
    Principal,
    Policy,
    Extension,
}

impl ObjectCategory {
    pub const ALL: [Self; 26] = [
        Self::Database,
        Self::Schema,
        Self::Table,
        Self::Column,
        Self::PrimaryKey,
        Self::ForeignKey,
        Self::UniqueConstraint,
        Self::CheckConstraint,
        Self::Index,
        Self::View,
        Self::ViewColumn,
        Self::Trigger,
        Self::Routine,
        Self::MaterializedView,
        Self::Sequence,
        Self::RoutineParameter,
        Self::UserDefinedType,
        Self::Domain,
        Self::EnumValue,
        Self::Synonym,
        Self::ExclusionConstraint,
        Self::Event,
        Self::Package,
        Self::Principal,
        Self::Policy,
        Self::Extension,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipCategory {
    DatabaseHasSchema,
    SchemaHasTable,
    TableHasColumn,
    TableHasConstraint,
    ConstraintColumn,
    ForeignKeyColumnPair,
    TableHasIndex,
    IndexColumn,
    SchemaHasView,
    ViewDependency,
    TriggerTarget,
    TriggerRoutine,
    SchemaHasRoutine,
    RoutineDependency,
    MetadataParent,
    MetadataRelationship,
}

impl RelationshipCategory {
    pub const ALL: [Self; 16] = [
        Self::DatabaseHasSchema,
        Self::SchemaHasTable,
        Self::TableHasColumn,
        Self::TableHasConstraint,
        Self::ConstraintColumn,
        Self::ForeignKeyColumnPair,
        Self::TableHasIndex,
        Self::IndexColumn,
        Self::SchemaHasView,
        Self::ViewDependency,
        Self::TriggerTarget,
        Self::TriggerRoutine,
        Self::SchemaHasRoutine,
        Self::RoutineDependency,
        Self::MetadataParent,
        Self::MetadataRelationship,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub name: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificationError {
    pub issues: Vec<CertificationIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificationIssue {
    pub code: String,
    pub subject: String,
    pub message: String,
}

impl fmt::Display for CertificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "schema snapshot certification failed with {} issue(s)",
            self.issues.len()
        )?;
        if let Some(issue) = self.issues.first() {
            write!(f, ": {} [{}]", issue.message, issue.subject)?;
        }
        Ok(())
    }
}

impl Error for CertificationError {}

pub fn certify_schema_snapshot(
    mut snapshot: CanonicalSchemaSnapshot,
    adapter: AdapterIdentity,
    server: ServerIdentity,
    mut scope: IntrospectionScope,
    discovered_counts: DiscoveryCounts,
    mut capability_checks: Vec<CapabilityCheck>,
) -> Result<CertifiedSchemaSnapshot, CertificationError> {
    normalize_canonical_snapshot(&mut snapshot);
    capability_checks.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.evidence.cmp(&right.evidence))
    });
    let mut issues = validate_canonical_schema_snapshot(&snapshot)
        .err()
        .into_iter()
        .flat_map(|error| error.issues)
        .map(certification_issue_from_validation)
        .collect::<Vec<_>>();

    require_non_empty(&mut issues, "adapter.name", &adapter.name);
    require_non_empty(&mut issues, "adapter.version", &adapter.version);
    require_non_empty(&mut issues, "server.product", &server.product);
    require_non_empty(&mut issues, "server.version", &server.version);
    normalize_scope(&mut scope);
    if scope.catalogs.is_empty() {
        issue(
            &mut issues,
            "scope_missing",
            "scope.catalogs",
            "at least one catalog/database must be declared",
        );
    }
    if scope.schemas.is_empty() {
        issue(
            &mut issues,
            "scope_missing",
            "scope.schemas",
            "at least one schema must be declared",
        );
    }
    if capability_checks.is_empty() {
        issue(
            &mut issues,
            "capability_proof_missing",
            "capability_checks",
            "at least one metadata capability check is required",
        );
    }
    for check in &capability_checks {
        require_non_empty(&mut issues, "capability.name", &check.name);
        require_non_empty(&mut issues, "capability.evidence", &check.evidence);
    }

    let emitted_counts = emitted_object_counts(&snapshot);
    let mut object_counts = Vec::with_capacity(ObjectCategory::ALL.len());
    for category in ObjectCategory::ALL {
        let emitted = emitted_counts.get(&category).copied().unwrap_or(0);
        match discovered_counts.objects.get(&category) {
            Some(discovery) => {
                let discovered = discovery.count;
                require_discovery_evidence(
                    &mut issues,
                    &format!("object_counts.{category:?}"),
                    &discovery.evidence,
                );
                if discovered != emitted {
                    issue(
                        &mut issues,
                        "object_count_mismatch",
                        &format!("object_counts.{category:?}"),
                        &format!("discovered {discovered} object(s), emitted {emitted}"),
                    );
                }
                object_counts.push(CountReconciliation {
                    category,
                    discovered,
                    emitted,
                    evidence: discovery.evidence.clone(),
                });
            }
            None => issue(
                &mut issues,
                "discovered_count_missing",
                &format!("object_counts.{category:?}"),
                "adapter did not report a discovered count for this category",
            ),
        }
    }

    let emitted_relationships = emitted_relationship_counts(&snapshot);
    let mut relationship_counts = Vec::with_capacity(RelationshipCategory::ALL.len());
    for category in RelationshipCategory::ALL {
        let emitted = emitted_relationships.get(&category).copied().unwrap_or(0);
        match discovered_counts.relationships.get(&category) {
            Some(discovery) => {
                let discovered = discovery.count;
                require_discovery_evidence(
                    &mut issues,
                    &format!("relationship_counts.{category:?}"),
                    &discovery.evidence,
                );
                if discovered != emitted {
                    issue(
                        &mut issues,
                        "relationship_count_mismatch",
                        &format!("relationship_counts.{category:?}"),
                        &format!("discovered {discovered} relation(s), emitted {emitted}"),
                    );
                }
                relationship_counts.push(RelationshipCountReconciliation {
                    category,
                    discovered,
                    emitted,
                    evidence: discovery.evidence.clone(),
                });
            }
            None => issue(
                &mut issues,
                "discovered_relationship_count_missing",
                &format!("relationship_counts.{category:?}"),
                "adapter did not report a discovered count for this relationship category",
            ),
        }
    }

    if !issues.is_empty() {
        return Err(CertificationError { issues });
    }

    let certified = CertifiedSchemaSnapshot {
        contract_version: COMPLETE_CONTRACT_VERSION,
        snapshot,
        completeness: CompletenessProof {
            status: CompletionStatus::Complete,
            adapter,
            server,
            scope,
            object_counts,
            relationship_counts,
            capability_checks,
        },
    };
    verify_certified_schema_snapshot(&certified)?;
    Ok(certified)
}

pub fn verify_certified_schema_snapshot(
    certified: &CertifiedSchemaSnapshot,
) -> Result<(), CertificationError> {
    let mut issues = validate_canonical_schema_snapshot(&certified.snapshot)
        .err()
        .into_iter()
        .flat_map(|error| error.issues)
        .map(certification_issue_from_validation)
        .collect::<Vec<_>>();

    if certified.contract_version != COMPLETE_CONTRACT_VERSION {
        issue(
            &mut issues,
            "unsupported_contract_version",
            "contract_version",
            &format!(
                "expected contract version {COMPLETE_CONTRACT_VERSION}, got {}",
                certified.contract_version
            ),
        );
    }

    let mut normalized = certified.snapshot.clone();
    normalize_canonical_snapshot(&mut normalized);
    if normalized != certified.snapshot {
        issue(
            &mut issues,
            "snapshot_not_canonical",
            "snapshot",
            "certified snapshot collections must use deterministic canonical ordering",
        );
    }

    let proof = &certified.completeness;
    require_non_empty(&mut issues, "adapter.name", &proof.adapter.name);
    require_non_empty(&mut issues, "adapter.version", &proof.adapter.version);
    require_non_empty(&mut issues, "server.product", &proof.server.product);
    require_non_empty(&mut issues, "server.version", &proof.server.version);
    validate_scope(&mut issues, &proof.scope);
    validate_capabilities(&mut issues, certified);
    validate_capability_checks(&mut issues, &proof.capability_checks);
    let mut sorted_checks = proof.capability_checks.clone();
    sorted_checks.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.evidence.cmp(&right.evidence))
    });
    if sorted_checks != proof.capability_checks {
        issue(
            &mut issues,
            "capability_checks_not_canonical",
            "capability_checks",
            "capability checks must use deterministic ordering",
        );
    }
    validate_count_reconciliation(&mut issues, certified);

    if issues.is_empty() {
        Ok(())
    } else {
        Err(CertificationError { issues })
    }
}

pub fn emitted_object_counts(snapshot: &CanonicalSchemaSnapshot) -> BTreeMap<ObjectCategory, u64> {
    let schema = &snapshot.schema;
    let mut counts = ObjectCategory::ALL
        .into_iter()
        .map(|category| (category, 0))
        .collect::<BTreeMap<_, _>>();
    counts.insert(ObjectCategory::Database, 1);
    counts.insert(ObjectCategory::Schema, schema.schemas.len() as u64);
    counts.insert(ObjectCategory::Table, schema.tables.len() as u64);
    counts.insert(ObjectCategory::Column, schema.columns.len() as u64);
    counts.insert(ObjectCategory::Index, schema.indexes.len() as u64);
    counts.insert(ObjectCategory::View, schema.views.len() as u64);
    counts.insert(ObjectCategory::Trigger, schema.triggers.len() as u64);
    counts.insert(ObjectCategory::Routine, schema.routines.len() as u64);
    for constraint in &schema.constraints {
        let category = match constraint.kind {
            ConstraintKind::PrimaryKey => ObjectCategory::PrimaryKey,
            ConstraintKind::ForeignKey => ObjectCategory::ForeignKey,
            ConstraintKind::Unique => ObjectCategory::UniqueConstraint,
            ConstraintKind::Check => ObjectCategory::CheckConstraint,
        };
        *counts.entry(category).or_default() += 1;
    }
    for object in &snapshot.metadata.objects {
        *counts
            .entry(object_category_from_kind(object.key.object_kind))
            .or_default() += 1;
    }
    counts
}

pub fn emitted_relationship_counts(
    snapshot: &CanonicalSchemaSnapshot,
) -> BTreeMap<RelationshipCategory, u64> {
    let schema = &snapshot.schema;
    let mut counts = RelationshipCategory::ALL
        .into_iter()
        .map(|category| (category, 0))
        .collect::<BTreeMap<_, _>>();
    counts.insert(
        RelationshipCategory::DatabaseHasSchema,
        schema.schemas.len() as u64,
    );
    counts.insert(
        RelationshipCategory::SchemaHasTable,
        schema.tables.len() as u64,
    );
    counts.insert(
        RelationshipCategory::TableHasColumn,
        schema.columns.len() as u64,
    );
    counts.insert(
        RelationshipCategory::TableHasConstraint,
        schema.constraints.len() as u64,
    );
    counts.insert(
        RelationshipCategory::TableHasIndex,
        schema.indexes.len() as u64,
    );
    counts.insert(
        RelationshipCategory::IndexColumn,
        schema
            .indexes
            .iter()
            .map(|index| index.columns.len() as u64)
            .sum(),
    );
    counts.insert(
        RelationshipCategory::SchemaHasView,
        schema.views.len() as u64,
    );
    counts.insert(
        RelationshipCategory::ViewDependency,
        schema
            .views
            .iter()
            .map(|view| view.depends_on.len() as u64)
            .sum(),
    );
    counts.insert(
        RelationshipCategory::TriggerTarget,
        schema.triggers.len() as u64,
    );
    counts.insert(
        RelationshipCategory::TriggerRoutine,
        schema
            .triggers
            .iter()
            .filter(|trigger| trigger.executes_routine_key.is_some())
            .count() as u64,
    );
    counts.insert(
        RelationshipCategory::SchemaHasRoutine,
        schema.routines.len() as u64,
    );
    counts.insert(
        RelationshipCategory::RoutineDependency,
        schema
            .routines
            .iter()
            .map(|routine| routine.depends_on.len() as u64)
            .sum(),
    );
    let mut constraint_columns = 0_u64;
    let mut foreign_key_pairs = 0_u64;
    for constraint in &schema.constraints {
        match constraint.kind {
            ConstraintKind::ForeignKey => foreign_key_pairs += constraint.columns.len() as u64,
            _ => constraint_columns += constraint.columns.len() as u64,
        }
    }
    counts.insert(RelationshipCategory::ConstraintColumn, constraint_columns);
    counts.insert(
        RelationshipCategory::ForeignKeyColumnPair,
        foreign_key_pairs,
    );
    counts.insert(
        RelationshipCategory::MetadataParent,
        snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| object.parent_key.is_some())
            .count() as u64,
    );
    counts.insert(
        RelationshipCategory::MetadataRelationship,
        snapshot.metadata.relationships.len() as u64,
    );
    counts
}

#[cfg(test)]
pub fn fixture_discovery_counts(snapshot: &CanonicalSchemaSnapshot) -> DiscoveryCounts {
    DiscoveryCounts {
        objects: emitted_object_counts(snapshot)
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: "test fixture canonical object inventory".to_owned(),
                    },
                )
            })
            .collect(),
        relationships: emitted_relationship_counts(snapshot)
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: "test fixture canonical relationship inventory".to_owned(),
                    },
                )
            })
            .collect(),
    }
}

fn object_category_from_kind(kind: ObjectKind) -> ObjectCategory {
    match kind {
        ObjectKind::Database => ObjectCategory::Database,
        ObjectKind::Schema => ObjectCategory::Schema,
        ObjectKind::Table => ObjectCategory::Table,
        ObjectKind::Column => ObjectCategory::Column,
        ObjectKind::PrimaryKey => ObjectCategory::PrimaryKey,
        ObjectKind::ForeignKey => ObjectCategory::ForeignKey,
        ObjectKind::UniqueConstraint => ObjectCategory::UniqueConstraint,
        ObjectKind::CheckConstraint => ObjectCategory::CheckConstraint,
        ObjectKind::Index => ObjectCategory::Index,
        ObjectKind::View => ObjectCategory::View,
        ObjectKind::ViewColumn => ObjectCategory::ViewColumn,
        ObjectKind::Trigger => ObjectCategory::Trigger,
        ObjectKind::Routine => ObjectCategory::Routine,
        ObjectKind::MaterializedView => ObjectCategory::MaterializedView,
        ObjectKind::Sequence => ObjectCategory::Sequence,
        ObjectKind::RoutineParameter => ObjectCategory::RoutineParameter,
        ObjectKind::UserDefinedType => ObjectCategory::UserDefinedType,
        ObjectKind::Domain => ObjectCategory::Domain,
        ObjectKind::EnumValue => ObjectCategory::EnumValue,
        ObjectKind::Synonym => ObjectCategory::Synonym,
        ObjectKind::ExclusionConstraint => ObjectCategory::ExclusionConstraint,
        ObjectKind::Event => ObjectCategory::Event,
        ObjectKind::Package => ObjectCategory::Package,
        ObjectKind::Principal => ObjectCategory::Principal,
        ObjectKind::Policy => ObjectCategory::Policy,
        ObjectKind::Extension => ObjectCategory::Extension,
    }
}

fn normalize_scope(scope: &mut IntrospectionScope) {
    scope.catalogs.sort();
    scope.catalogs.dedup();
    scope.schemas.sort();
    scope.schemas.dedup();
}

fn validate_scope(issues: &mut Vec<CertificationIssue>, scope: &IntrospectionScope) {
    if scope.catalogs.is_empty() {
        issue(
            issues,
            "scope_missing",
            "scope.catalogs",
            "at least one catalog/database must be declared",
        );
    }
    if scope.schemas.is_empty() {
        issue(
            issues,
            "scope_missing",
            "scope.schemas",
            "at least one schema must be declared",
        );
    }
    validate_canonical_scope_values(issues, "scope.catalogs", &scope.catalogs);
    validate_canonical_scope_values(issues, "scope.schemas", &scope.schemas);
}

fn validate_canonical_scope_values(
    issues: &mut Vec<CertificationIssue>,
    subject: &str,
    values: &[String],
) {
    if values.iter().any(|value| {
        value.trim().is_empty()
            || value.len() > MAX_SCOPE_VALUE_BYTES
            || value.chars().any(char::is_control)
    }) {
        issue(
            issues,
            "scope_value_missing",
            subject,
            "scope values must be bounded, non-empty, and contain no controls",
        );
    }
    let mut canonical = values.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical != values {
        issue(
            issues,
            "scope_not_canonical",
            subject,
            "scope values must be sorted and unique",
        );
    }
}

fn validate_capabilities(
    issues: &mut Vec<CertificationIssue>,
    certified: &CertifiedSchemaSnapshot,
) {
    let capabilities = &certified.snapshot.schema.capabilities;
    if capabilities.source_kind != certified.snapshot.schema.source_kind {
        issue(
            issues,
            "capability_source_mismatch",
            "capabilities.source_kind",
            "capability source must match snapshot source",
        );
    }
    if !capabilities.metadata_only {
        issue(
            issues,
            "metadata_only_required",
            "capabilities.metadata_only",
            "certified indexing must be metadata-only",
        );
    }
    for (name, supported) in [
        ("schemas", capabilities.schemas),
        ("tables", capabilities.tables),
        ("columns", capabilities.columns),
        ("constraints", capabilities.constraints),
        ("indexes", capabilities.indexes),
    ] {
        if !supported {
            issue(
                issues,
                "required_capability_missing",
                &format!("capabilities.{name}"),
                "certified adapters must prove this metadata category",
            );
        }
    }
    for (name, support) in [
        ("views", capabilities.views),
        ("triggers", capabilities.triggers),
        ("routines", capabilities.routines),
        ("dependencies", capabilities.dependencies),
    ] {
        if support != CapabilitySupport::Supported {
            issue(
                issues,
                "required_capability_incomplete",
                &format!("capabilities.{name}"),
                "certified adapters must support or prove absence of this metadata category",
            );
        }
    }
    if !capabilities.limitations.is_empty() {
        issue(
            issues,
            "adapter_limitations_present",
            "capabilities.limitations",
            "a certified complete snapshot cannot retain unmodeled metadata limitations",
        );
    }
}

fn validate_capability_checks(issues: &mut Vec<CertificationIssue>, checks: &[CapabilityCheck]) {
    if checks.is_empty() {
        issue(
            issues,
            "capability_proof_missing",
            "capability_checks",
            "at least one metadata capability check is required",
        );
    }
    let mut names = BTreeSet::new();
    for check in checks {
        require_non_empty(issues, "capability.name", &check.name);
        require_non_empty(issues, "capability.evidence", &check.evidence);
        if !check.name.trim().is_empty() && !names.insert(check.name.as_str()) {
            issue(
                issues,
                "duplicate_capability_check",
                &format!("capability_checks.{}", check.name),
                "capability check names must be unique",
            );
        }
    }
}

fn validate_count_reconciliation(
    issues: &mut Vec<CertificationIssue>,
    certified: &CertifiedSchemaSnapshot,
) {
    let emitted_counts = emitted_object_counts(&certified.snapshot);
    let mut seen = BTreeSet::new();
    for count in &certified.completeness.object_counts {
        require_discovery_evidence(
            issues,
            &format!("object_counts.{:?}", count.category),
            &count.evidence,
        );
        if !seen.insert(count.category) {
            issue(
                issues,
                "duplicate_object_count",
                &format!("object_counts.{:?}", count.category),
                "each object category must have exactly one reconciliation",
            );
            continue;
        }
        let actual = emitted_counts.get(&count.category).copied().unwrap_or(0);
        if count.discovered != count.emitted || count.emitted != actual {
            issue(
                issues,
                "object_count_mismatch",
                &format!("object_counts.{:?}", count.category),
                &format!(
                    "discovered {}, declared emitted {}, actual emitted {}",
                    count.discovered, count.emitted, actual
                ),
            );
        }
    }
    for category in ObjectCategory::ALL {
        if !seen.contains(&category) {
            issue(
                issues,
                "object_count_missing",
                &format!("object_counts.{category:?}"),
                "every object category requires a reconciliation",
            );
        }
    }

    let emitted_relationships = emitted_relationship_counts(&certified.snapshot);
    let mut seen_relationships = BTreeSet::new();
    for count in &certified.completeness.relationship_counts {
        require_discovery_evidence(
            issues,
            &format!("relationship_counts.{:?}", count.category),
            &count.evidence,
        );
        if !seen_relationships.insert(count.category) {
            issue(
                issues,
                "duplicate_relationship_count",
                &format!("relationship_counts.{:?}", count.category),
                "each relationship category must have exactly one reconciliation",
            );
            continue;
        }
        let actual = emitted_relationships
            .get(&count.category)
            .copied()
            .unwrap_or(0);
        if count.discovered != count.emitted || count.emitted != actual {
            issue(
                issues,
                "relationship_count_mismatch",
                &format!("relationship_counts.{:?}", count.category),
                &format!(
                    "discovered {}, declared emitted {}, actual emitted {}",
                    count.discovered, count.emitted, actual
                ),
            );
        }
    }
    for category in RelationshipCategory::ALL {
        if !seen_relationships.contains(&category) {
            issue(
                issues,
                "relationship_count_missing",
                &format!("relationship_counts.{category:?}"),
                "every relationship category requires a reconciliation",
            );
        }
    }
}

fn require_discovery_evidence(issues: &mut Vec<CertificationIssue>, subject: &str, evidence: &str) {
    if evidence.trim().is_empty()
        || evidence.len() > MAX_PROOF_TEXT_BYTES
        || evidence.chars().any(char::is_control)
    {
        issue(
            issues,
            "discovery_evidence_missing",
            subject,
            "discovered counts require bounded non-control catalog evidence",
        );
    }
}

fn require_non_empty(issues: &mut Vec<CertificationIssue>, subject: &str, value: &str) {
    if value.trim().is_empty()
        || value.len() > MAX_PROOF_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        issue(
            issues,
            "proof_value_missing",
            subject,
            "certification proof value must be bounded, non-empty, and contain no controls",
        );
    }
}

fn certification_issue_from_validation(issue: SnapshotValidationIssue) -> CertificationIssue {
    CertificationIssue {
        code: issue.code,
        subject: issue.object_key,
        message: issue.message,
    }
}

fn issue(issues: &mut Vec<CertificationIssue>, code: &str, subject: &str, message: &str) {
    issues.push(CertificationIssue {
        code: code.to_owned(),
        subject: subject.to_owned(),
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalSchemaSnapshot;
    use crate::{
        AdapterCapabilities, CapabilitySupport, ColumnObject, DatabaseObject, ObjectKey,
        ObjectKind, SchemaObject, SchemaSnapshot, TableKind, TableObject,
    };

    #[test]
    fn complete_snapshot_requires_every_discovered_count_to_match() {
        let snapshot = snapshot();
        let mut counts = fixture_discovery_counts(&snapshot);
        counts
            .objects
            .get_mut(&ObjectCategory::Column)
            .unwrap()
            .count = 2;

        let error = certify_schema_snapshot(
            snapshot,
            adapter(),
            server(),
            scope(),
            counts,
            capability_checks(),
        )
        .unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "object_count_mismatch"));
    }

    #[test]
    fn certified_snapshot_is_versioned_flattened_and_deterministic() {
        let snapshot = snapshot();
        let certified = certify_schema_snapshot(
            snapshot.clone(),
            adapter(),
            server(),
            IntrospectionScope {
                catalogs: vec!["main".to_owned(), "main".to_owned()],
                schemas: vec!["main".to_owned(), "main".to_owned()],
            },
            fixture_discovery_counts(&snapshot),
            capability_checks(),
        )
        .unwrap();
        let value = serde_json::to_value(&certified).unwrap();

        assert_eq!(value["contract_version"], COMPLETE_CONTRACT_VERSION);
        assert_eq!(value["source_kind"], "sqlite");
        assert_eq!(value["completeness"]["status"], "complete");
        assert_eq!(certified.completeness.scope.catalogs, vec!["main"]);
        assert_eq!(certified.completeness.scope.schemas, vec!["main"]);
        let legacy_reader: SchemaSnapshot = serde_json::from_value(value).unwrap();
        assert_eq!(legacy_reader.database.name, "main");
    }

    #[test]
    fn certification_requires_capability_evidence() {
        let snapshot = snapshot();
        let error = certify_schema_snapshot(
            snapshot.clone(),
            adapter(),
            server(),
            scope(),
            fixture_discovery_counts(&snapshot),
            vec![],
        )
        .unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "capability_proof_missing"));
    }

    #[test]
    fn verification_rejects_tampered_certification_payload() {
        let snapshot = snapshot();
        let mut certified = certify_schema_snapshot(
            snapshot.clone(),
            adapter(),
            server(),
            scope(),
            fixture_discovery_counts(&snapshot),
            capability_checks(),
        )
        .unwrap();
        certified.completeness.object_counts[0].emitted += 1;

        let error = verify_certified_schema_snapshot(&certified).unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "object_count_mismatch"));
    }

    #[test]
    fn verification_rejects_noncanonical_collection_order() {
        let snapshot = snapshot();
        let mut certified = certify_schema_snapshot(
            snapshot.clone(),
            adapter(),
            server(),
            scope(),
            fixture_discovery_counts(&snapshot),
            capability_checks(),
        )
        .unwrap();
        certified.snapshot.schema.capabilities.notes = vec!["z".to_owned(), "a".to_owned()];

        let error = verify_certified_schema_snapshot(&certified).unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "snapshot_not_canonical"));
    }

    #[test]
    fn complete_snapshot_rejects_adapter_metadata_gaps() {
        let mut snapshot = snapshot();
        snapshot.schema.capabilities.dependencies = CapabilitySupport::Partial;
        snapshot
            .schema
            .capabilities
            .limitations
            .push("trigger bodies are not analyzed".to_owned());

        let error = certify_schema_snapshot(
            snapshot.clone(),
            adapter(),
            server(),
            scope(),
            fixture_discovery_counts(&snapshot),
            capability_checks(),
        )
        .unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "required_capability_incomplete"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "adapter_limitations_present"));
    }

    #[test]
    fn complete_snapshot_reconciles_relationships_independently() {
        let snapshot = snapshot();
        let mut counts = fixture_discovery_counts(&snapshot);
        counts
            .relationships
            .get_mut(&RelationshipCategory::TableHasColumn)
            .unwrap()
            .count = 0;

        let error = certify_schema_snapshot(
            snapshot,
            adapter(),
            server(),
            scope(),
            counts,
            capability_checks(),
        )
        .unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "relationship_count_mismatch"));
    }

    #[test]
    fn discovered_counts_require_catalog_evidence_even_when_zero() {
        let snapshot = snapshot();
        let mut counts = fixture_discovery_counts(&snapshot);
        counts
            .objects
            .get_mut(&ObjectCategory::MaterializedView)
            .unwrap()
            .evidence
            .clear();

        let error = certify_schema_snapshot(
            snapshot,
            adapter(),
            server(),
            scope(),
            counts,
            capability_checks(),
        )
        .unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "discovery_evidence_missing"));
    }

    fn snapshot() -> CanonicalSchemaSnapshot {
        let database_key = key(ObjectKind::Database, "main", None);
        let schema_key = key(ObjectKind::Schema, "main", None);
        let table_key = key(ObjectKind::Table, "users", None);
        CanonicalSchemaSnapshot::from(SchemaSnapshot {
            source_kind: "sqlite".to_owned(),
            connection_alias: "sample".to_owned(),
            database: DatabaseObject {
                key: database_key.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: schema_key.clone(),
                database_key,
                name: "main".to_owned(),
            }],
            tables: vec![TableObject {
                key: table_key.clone(),
                schema_key,
                name: "users".to_owned(),
                kind: TableKind::BaseTable,
            }],
            columns: vec![ColumnObject {
                key: key(ObjectKind::Column, "users", Some("id")),
                table_key,
                name: "id".to_owned(),
                ordinal_position: 1,
                data_type: "integer".to_owned(),
                is_nullable: false,
                default_value: None,
                is_generated: false,
            }],
            constraints: vec![],
            indexes: vec![],
            views: vec![],
            triggers: vec![],
            routines: vec![],
            capabilities: AdapterCapabilities {
                source_kind: "sqlite".to_owned(),
                metadata_only: true,
                schemas: true,
                tables: true,
                columns: true,
                constraints: true,
                indexes: true,
                views: CapabilitySupport::Supported,
                triggers: CapabilitySupport::Supported,
                routines: CapabilitySupport::Supported,
                dependencies: CapabilitySupport::Supported,
                limitations: vec![],
                notes: vec![],
            },
        })
    }

    fn adapter() -> AdapterIdentity {
        AdapterIdentity {
            name: "sqlite".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    fn server() -> ServerIdentity {
        ServerIdentity {
            product: "SQLite".to_owned(),
            version: "3".to_owned(),
        }
    }

    fn scope() -> IntrospectionScope {
        IntrospectionScope {
            catalogs: vec!["main".to_owned()],
            schemas: vec!["main".to_owned()],
        }
    }

    fn capability_checks() -> Vec<CapabilityCheck> {
        vec![CapabilityCheck {
            name: "metadata_visibility".to_owned(),
            evidence: "sqlite_schema and PRAGMA reads completed".to_owned(),
        }]
    }

    fn key(kind: ObjectKind, object_name: &str, sub_object: Option<&str>) -> ObjectKey {
        ObjectKey::new(
            "sqlite",
            "sample",
            "main",
            "main",
            kind,
            object_name,
            sub_object.map(str::to_owned),
        )
    }
}
