use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::{
    CanonicalSchemaSnapshot, MetadataRelationshipKind, MetadataValue, ObjectAnnotation,
};
use crate::snapshot_validation::{
    validate_schema_snapshot, SnapshotValidationError, SnapshotValidationIssue,
};
use crate::{ObjectKey, ObjectKind};

pub const MAX_DEFINITION_BYTES: usize = 1_048_576;
pub const MAX_PROPERTIES_PER_ITEM: usize = 256;
pub const MAX_PROPERTY_KEY_BYTES: usize = 256;
pub const MAX_PROPERTY_STRING_BYTES: usize = 65_536;
pub const MAX_PROPERTY_LIST_ITEMS: usize = 4_096;

pub fn validate_canonical_schema_snapshot(
    snapshot: &CanonicalSchemaSnapshot,
) -> Result<(), SnapshotValidationError> {
    let mut issues = validate_schema_snapshot(&snapshot.schema)
        .err()
        .map(|error| error.issues)
        .unwrap_or_default();
    let mut keys = base_object_keys(snapshot);

    for object in &snapshot.metadata.objects {
        let stable_key = object.key.to_string();
        if keys
            .insert(stable_key.clone(), object.key.clone())
            .is_some()
        {
            push_issue(
                &mut issues,
                "duplicate_object_key",
                &stable_key,
                "stable object key is duplicated",
            );
        }
        validate_extension_identity(&mut issues, snapshot, object);
        validate_definition(&mut issues, &stable_key, object.definition.as_deref());
        validate_properties(&mut issues, &stable_key, &object.properties);
    }

    for object in &snapshot.metadata.objects {
        let stable_key = object.key.to_string();
        match &object.parent_key {
            Some(parent) => {
                require_key(&mut issues, &keys, parent, &stable_key);
                require_same_scope(&mut issues, &object.key, parent, &stable_key);
                require_metadata_parent_kind(
                    &mut issues,
                    &keys,
                    object.key.object_kind,
                    parent,
                    &stable_key,
                );
            }
            None => push_issue(
                &mut issues,
                "metadata_parent_missing",
                &stable_key,
                "canonical metadata objects require an explicit parent",
            ),
        }
    }

    validate_annotations(&mut issues, &keys, &snapshot.metadata.annotations);
    validate_relationships(snapshot, &mut issues, &keys);

    if issues.is_empty() {
        Ok(())
    } else {
        Err(SnapshotValidationError { issues })
    }
}

fn base_object_keys(snapshot: &CanonicalSchemaSnapshot) -> BTreeMap<String, ObjectKey> {
    let schema = &snapshot.schema;
    let mut keys = BTreeMap::new();
    register(&mut keys, &schema.database.key);
    for key in schema
        .schemas
        .iter()
        .map(|object| &object.key)
        .chain(schema.tables.iter().map(|object| &object.key))
        .chain(schema.columns.iter().map(|object| &object.key))
        .chain(schema.constraints.iter().map(|object| &object.key))
        .chain(schema.indexes.iter().map(|object| &object.key))
        .chain(schema.views.iter().map(|object| &object.key))
        .chain(schema.triggers.iter().map(|object| &object.key))
        .chain(schema.routines.iter().map(|object| &object.key))
    {
        register(&mut keys, key);
    }
    keys
}

fn register(keys: &mut BTreeMap<String, ObjectKey>, key: &ObjectKey) {
    keys.entry(key.to_string()).or_insert_with(|| key.clone());
}

fn validate_extension_identity(
    issues: &mut Vec<SnapshotValidationIssue>,
    snapshot: &CanonicalSchemaSnapshot,
    object: &crate::canonical::MetadataObject,
) {
    let stable_key = object.key.to_string();
    if !is_canonical_metadata_kind(object.key.object_kind) {
        push_issue(
            issues,
            "metadata_object_kind_invalid",
            &stable_key,
            "typed legacy objects must stay in the canonical schema collections",
        );
    }
    if object.key.source_kind != snapshot.schema.database.key.source_kind
        || object.key.connection_alias != snapshot.schema.connection_alias
    {
        push_issue(
            issues,
            "metadata_source_mismatch",
            &stable_key,
            "metadata object source and alias must match the snapshot",
        );
    }
    if object.key.database != snapshot.schema.database.key.database {
        push_issue(
            issues,
            "metadata_database_mismatch",
            &stable_key,
            "metadata object database must match the snapshot database",
        );
    }
    if object.name.trim().is_empty() {
        push_issue(
            issues,
            "metadata_name_missing",
            &stable_key,
            "metadata object name must not be empty",
        );
    }
    match object.key.object_kind {
        ObjectKind::Extension => match object.extension_kind.as_deref() {
            Some(name) if valid_extension_name(name) => {}
            _ => push_issue(
                issues,
                "extension_kind_invalid",
                &stable_key,
                "vendor extension objects require a bounded non-control extension kind",
            ),
        },
        _ if object.extension_kind.is_some() => push_issue(
            issues,
            "extension_kind_unexpected",
            &stable_key,
            "standard metadata objects must not declare an extension kind",
        ),
        _ => {}
    }
}

fn is_canonical_metadata_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::PrimaryKey
            | ObjectKind::UniqueConstraint
            | ObjectKind::CheckConstraint
            | ObjectKind::Index
            | ObjectKind::Routine
            | ObjectKind::MaterializedView
            | ObjectKind::ViewColumn
            | ObjectKind::Sequence
            | ObjectKind::RoutineParameter
            | ObjectKind::UserDefinedType
            | ObjectKind::Domain
            | ObjectKind::EnumValue
            | ObjectKind::Synonym
            | ObjectKind::ExclusionConstraint
            | ObjectKind::Event
            | ObjectKind::Package
            | ObjectKind::Principal
            | ObjectKind::Policy
            | ObjectKind::Trigger
            | ObjectKind::Extension
    )
}

fn validate_annotations(
    issues: &mut Vec<SnapshotValidationIssue>,
    keys: &BTreeMap<String, ObjectKey>,
    annotations: &[ObjectAnnotation],
) {
    let mut annotated = BTreeSet::new();
    for annotation in annotations {
        let stable_key = annotation.object_key.to_string();
        require_key(issues, keys, &annotation.object_key, &stable_key);
        if !annotated.insert(stable_key.clone()) {
            push_issue(
                issues,
                "duplicate_object_annotation",
                &stable_key,
                "an object may have only one canonical annotation",
            );
        }
        if annotation.definition.is_none() && annotation.properties.is_empty() {
            push_issue(
                issues,
                "empty_object_annotation",
                &stable_key,
                "annotation must contain a definition or properties",
            );
        }
        validate_definition(issues, &stable_key, annotation.definition.as_deref());
        validate_properties(issues, &stable_key, &annotation.properties);
    }
}

fn validate_relationships(
    snapshot: &CanonicalSchemaSnapshot,
    issues: &mut Vec<SnapshotValidationIssue>,
    keys: &BTreeMap<String, ObjectKey>,
) {
    let mut relationships = BTreeSet::new();
    for relationship in &snapshot.metadata.relationships {
        let from = relationship.from_key.to_string();
        let to = relationship.to_key.to_string();
        let subject = format!("{}:{from}->{to}", relationship.kind.graph_edge_type());
        require_key(issues, keys, &relationship.from_key, &subject);
        require_key(issues, keys, &relationship.to_key, &subject);
        validate_relationship_endpoint_kinds(issues, keys, relationship, &subject);
        if relationship.ordinal == Some(0) {
            push_issue(
                issues,
                "relationship_ordinal_invalid",
                &subject,
                "relationship ordinal must be at least 1",
            );
        }
        if let MetadataRelationshipKind::Extension(name) = &relationship.kind {
            if !valid_extension_name(name) {
                push_issue(
                    issues,
                    "extension_relationship_invalid",
                    &subject,
                    "vendor relationship names must be bounded and contain no controls",
                );
            }
        }
        let identity = (relationship.kind.clone(), from, to, relationship.ordinal);
        if !relationships.insert(identity) {
            push_issue(
                issues,
                "duplicate_metadata_relationship",
                &subject,
                "canonical metadata relationship is duplicated",
            );
        }
        validate_properties(issues, &subject, &relationship.properties);
    }
}

fn require_metadata_parent_kind(
    issues: &mut Vec<SnapshotValidationIssue>,
    keys: &BTreeMap<String, ObjectKey>,
    child_kind: ObjectKind,
    parent: &ObjectKey,
    subject: &str,
) {
    let expected: &[ObjectKind] = match child_kind {
        ObjectKind::ViewColumn => &[ObjectKind::View, ObjectKind::MaterializedView],
        ObjectKind::MaterializedView
        | ObjectKind::Sequence
        | ObjectKind::UserDefinedType
        | ObjectKind::Domain
        | ObjectKind::Synonym
        | ObjectKind::Package => &[ObjectKind::Schema],
        ObjectKind::PrimaryKey | ObjectKind::UniqueConstraint => &[ObjectKind::MaterializedView],
        ObjectKind::Routine => &[ObjectKind::Package],
        ObjectKind::CheckConstraint => &[ObjectKind::Domain, ObjectKind::MaterializedView],
        ObjectKind::Index => &[ObjectKind::MaterializedView],
        ObjectKind::Event => &[ObjectKind::Database, ObjectKind::Schema],
        ObjectKind::RoutineParameter => &[ObjectKind::Routine],
        ObjectKind::EnumValue => &[ObjectKind::UserDefinedType],
        ObjectKind::ExclusionConstraint => &[ObjectKind::Table],
        ObjectKind::Principal => &[ObjectKind::Database, ObjectKind::Schema],
        ObjectKind::Policy => &[ObjectKind::Schema, ObjectKind::Table, ObjectKind::View],
        ObjectKind::Trigger => &[
            ObjectKind::Database,
            ObjectKind::Schema,
            ObjectKind::Table,
            ObjectKind::View,
            ObjectKind::MaterializedView,
        ],
        ObjectKind::Extension => return,
        _ => return,
    };
    if let Some(actual) = keys.get(&parent.to_string()) {
        if !expected.contains(&actual.object_kind) {
            push_issue(
                issues,
                "metadata_parent_kind_mismatch",
                subject,
                &format!(
                    "metadata parent has kind {}, expected {}",
                    actual.object_kind,
                    expected
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" or ")
                ),
            );
        }
    }
}

fn validate_relationship_endpoint_kinds(
    issues: &mut Vec<SnapshotValidationIssue>,
    keys: &BTreeMap<String, ObjectKey>,
    relationship: &crate::canonical::MetadataRelationship,
    subject: &str,
) {
    let Some(from) = keys.get(&relationship.from_key.to_string()) else {
        return;
    };
    let Some(to) = keys.get(&relationship.to_key.to_string()) else {
        return;
    };
    let valid = match &relationship.kind {
        MetadataRelationshipKind::DependsOn | MetadataRelationshipKind::Extension(_) => true,
        MetadataRelationshipKind::UsesType => {
            matches!(
                from.object_kind,
                ObjectKind::Column
                    | ObjectKind::ViewColumn
                    | ObjectKind::Routine
                    | ObjectKind::RoutineParameter
                    | ObjectKind::Sequence
            ) && matches!(
                to.object_kind,
                ObjectKind::UserDefinedType | ObjectKind::Domain
            )
        }
        MetadataRelationshipKind::UsesSequence => {
            from.object_kind == ObjectKind::Column && to.object_kind == ObjectKind::Sequence
        }
        MetadataRelationshipKind::PartitionOf => {
            from.object_kind == ObjectKind::Table && to.object_kind == ObjectKind::Table
        }
        MetadataRelationshipKind::InheritsFrom => {
            (from.object_kind == ObjectKind::Table && to.object_kind == ObjectKind::Table)
                || (from.object_kind == ObjectKind::UserDefinedType
                    && to.object_kind == ObjectKind::UserDefinedType)
        }
        MetadataRelationshipKind::SynonymFor => from.object_kind == ObjectKind::Synonym,
        MetadataRelationshipKind::HasParameter => {
            matches!(from.object_kind, ObjectKind::Routine | ObjectKind::Package)
                && to.object_kind == ObjectKind::RoutineParameter
        }
        MetadataRelationshipKind::ReturnsType => {
            from.object_kind == ObjectKind::Routine
                && matches!(
                    to.object_kind,
                    ObjectKind::UserDefinedType | ObjectKind::Domain
                )
        }
        MetadataRelationshipKind::OwnedBy => to.object_kind == ObjectKind::Principal,
        MetadataRelationshipKind::Materializes => {
            from.object_kind == ObjectKind::MaterializedView
                && matches!(to.object_kind, ObjectKind::Table | ObjectKind::View)
        }
        MetadataRelationshipKind::Invokes => {
            matches!(
                from.object_kind,
                ObjectKind::Routine | ObjectKind::Trigger | ObjectKind::Event
            ) && to.object_kind == ObjectKind::Routine
        }
        MetadataRelationshipKind::IncludesColumn => {
            from.object_kind == ObjectKind::Index
                && matches!(to.object_kind, ObjectKind::Column | ObjectKind::ViewColumn)
        }
        MetadataRelationshipKind::ExcludesWith => {
            from.object_kind == ObjectKind::ExclusionConstraint
                && to.object_kind == ObjectKind::Column
        }
    };
    if !valid {
        push_issue(
            issues,
            "metadata_relationship_kind_mismatch",
            subject,
            "relationship endpoint object kinds do not match the canonical relation",
        );
    }
}

fn require_key(
    issues: &mut Vec<SnapshotValidationIssue>,
    keys: &BTreeMap<String, ObjectKey>,
    target: &ObjectKey,
    subject: &str,
) {
    if !keys.contains_key(&target.to_string()) {
        push_issue(
            issues,
            "relationship_target_missing",
            subject,
            &format!("relationship target {target} is not present in the snapshot"),
        );
    }
}

fn require_same_scope(
    issues: &mut Vec<SnapshotValidationIssue>,
    child: &ObjectKey,
    parent: &ObjectKey,
    subject: &str,
) {
    if child.source_kind != parent.source_kind
        || child.connection_alias != parent.connection_alias
        || child.database != parent.database
    {
        push_issue(
            issues,
            "metadata_parent_scope_mismatch",
            subject,
            "metadata object and parent must belong to the same source and database",
        );
    }
}

fn validate_definition(
    issues: &mut Vec<SnapshotValidationIssue>,
    subject: &str,
    definition: Option<&str>,
) {
    if let Some(definition) = definition {
        if definition.len() > MAX_DEFINITION_BYTES {
            push_issue(
                issues,
                "definition_too_large",
                subject,
                "metadata definition exceeds the canonical size limit",
            );
        }
    }
}

fn validate_properties(
    issues: &mut Vec<SnapshotValidationIssue>,
    subject: &str,
    properties: &BTreeMap<String, MetadataValue>,
) {
    if properties.len() > MAX_PROPERTIES_PER_ITEM {
        push_issue(
            issues,
            "too_many_properties",
            subject,
            "metadata item exceeds the canonical property count limit",
        );
    }
    for (name, value) in properties {
        if name.trim().is_empty()
            || name.len() > MAX_PROPERTY_KEY_BYTES
            || name.chars().any(char::is_control)
        {
            push_issue(
                issues,
                "property_name_invalid",
                subject,
                "metadata property names must be bounded and contain no controls",
            );
        }
        match value {
            MetadataValue::String(value) if value.len() > MAX_PROPERTY_STRING_BYTES => push_issue(
                issues,
                "property_value_too_large",
                subject,
                "metadata string property exceeds the canonical size limit",
            ),
            MetadataValue::StringList(values)
                if values.len() > MAX_PROPERTY_LIST_ITEMS
                    || values
                        .iter()
                        .any(|value| value.len() > MAX_PROPERTY_STRING_BYTES) =>
            {
                push_issue(
                    issues,
                    "property_value_too_large",
                    subject,
                    "metadata list property exceeds the canonical size limit",
                );
            }
            _ => {}
        }
    }
}

fn valid_extension_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_PROPERTY_KEY_BYTES
        && !value.chars().any(char::is_control)
}

fn push_issue(
    issues: &mut Vec<SnapshotValidationIssue>,
    code: &str,
    object_key: &str,
    message: &str,
) {
    issues.push(SnapshotValidationIssue {
        code: code.to_owned(),
        object_key: object_key.to_owned(),
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{
        CanonicalMetadata, MetadataObject, MetadataRelationship, MetadataRelationshipKind,
    };
    use crate::{
        AdapterCapabilities, CapabilitySupport, DatabaseObject, SchemaObject, SchemaSnapshot,
    };

    #[test]
    fn validates_new_objects_annotations_and_relationships() {
        let mut snapshot = canonical_snapshot();
        let schema_key = key(ObjectKind::Schema, "main", None);
        let sequence_key = key(ObjectKind::Sequence, "users_id_seq", None);
        snapshot.metadata.objects.push(MetadataObject {
            key: sequence_key.clone(),
            parent_key: Some(schema_key),
            name: "users_id_seq".to_owned(),
            extension_kind: None,
            definition: None,
            properties: BTreeMap::from([("increment".to_owned(), MetadataValue::Integer(1))]),
        });
        snapshot.metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::DependsOn,
            from_key: sequence_key.clone(),
            to_key: snapshot.schema.database.key.clone(),
            ordinal: None,
            properties: BTreeMap::new(),
        });
        snapshot.metadata.annotations.push(ObjectAnnotation {
            object_key: sequence_key,
            definition: None,
            properties: BTreeMap::from([("cache".to_owned(), MetadataValue::Unsigned(1))]),
        });

        assert!(validate_canonical_schema_snapshot(&snapshot).is_ok());
    }

    #[test]
    fn accepts_materialized_view_check_constraints() {
        let mut snapshot = canonical_snapshot();
        let schema_key = key(ObjectKind::Schema, "main", None);
        let materialized_view_key = key(ObjectKind::MaterializedView, "account_rollup", None);
        snapshot.metadata.objects.extend([
            MetadataObject {
                key: materialized_view_key.clone(),
                parent_key: Some(schema_key),
                name: "account_rollup".to_owned(),
                extension_kind: None,
                definition: Some("SELECT id FROM accounts".to_owned()),
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: key(
                    ObjectKind::PrimaryKey,
                    "account_rollup",
                    Some("PK_ACCOUNT_ROLLUP"),
                ),
                parent_key: Some(materialized_view_key.clone()),
                name: "PK_ACCOUNT_ROLLUP".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: key(
                    ObjectKind::CheckConstraint,
                    "account_rollup",
                    Some("SYS_C000001"),
                ),
                parent_key: Some(materialized_view_key),
                name: "SYS_C000001".to_owned(),
                extension_kind: None,
                definition: Some("id IS NOT NULL".to_owned()),
                properties: BTreeMap::new(),
            },
        ]);

        assert!(validate_canonical_schema_snapshot(&snapshot).is_ok());
    }

    #[test]
    fn accepts_packaged_routines_and_parameters() {
        let mut snapshot = canonical_snapshot();
        let schema_key = key(ObjectKind::Schema, "main", None);
        let package_key = key(ObjectKind::Package, "account_api", None);
        let routine_key = key(ObjectKind::Routine, "account_api", Some("find(number)"));
        let parameter_key = key(
            ObjectKind::RoutineParameter,
            "account_api",
            Some("find(number)#1:id"),
        );
        snapshot.metadata.objects.extend([
            MetadataObject {
                key: package_key.clone(),
                parent_key: Some(schema_key),
                name: "account_api".to_owned(),
                extension_kind: None,
                definition: Some("PACKAGE account_api AS END".to_owned()),
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: routine_key.clone(),
                parent_key: Some(package_key),
                name: "find".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: parameter_key.clone(),
                parent_key: Some(routine_key.clone()),
                name: "id".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
        ]);
        snapshot.metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::HasParameter,
            from_key: routine_key,
            to_key: parameter_key,
            ordinal: Some(1),
            properties: BTreeMap::new(),
        });

        assert!(validate_canonical_schema_snapshot(&snapshot).is_ok());
    }

    #[test]
    fn rejects_dangling_and_duplicate_metadata() {
        let mut snapshot = canonical_snapshot();
        let extension_key = key(ObjectKind::Extension, "warehouse", None);
        let object = MetadataObject {
            key: extension_key,
            parent_key: Some(key(ObjectKind::Schema, "missing", None)),
            name: "warehouse".to_owned(),
            extension_kind: None,
            definition: None,
            properties: BTreeMap::new(),
        };
        snapshot.metadata.objects = vec![object.clone(), object];

        let error = validate_canonical_schema_snapshot(&snapshot).unwrap_err();
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "duplicate_object_key"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "relationship_target_missing"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "extension_kind_invalid"));
    }

    #[test]
    fn rejects_semantically_invalid_parent_and_relationship_kinds() {
        let mut snapshot = canonical_snapshot();
        let sequence_key = key(ObjectKind::Sequence, "users_id_seq", None);
        snapshot.metadata.objects.push(MetadataObject {
            key: sequence_key.clone(),
            parent_key: Some(snapshot.schema.database.key.clone()),
            name: "users_id_seq".to_owned(),
            extension_kind: None,
            definition: None,
            properties: BTreeMap::new(),
        });
        snapshot.metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::UsesSequence,
            from_key: sequence_key.clone(),
            to_key: snapshot.schema.database.key.clone(),
            ordinal: None,
            properties: BTreeMap::new(),
        });

        let error = validate_canonical_schema_snapshot(&snapshot).unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "metadata_parent_kind_mismatch"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "metadata_relationship_kind_mismatch"));
    }

    #[test]
    fn accepts_schema_policy_trigger_and_sequence_type_relationships() {
        let mut snapshot = canonical_snapshot();
        let database_key = snapshot.schema.database.key.clone();
        let schema_key = key(ObjectKind::Schema, "main", None);
        let table_key = key(ObjectKind::Table, "accounts", None);
        let type_key = key(ObjectKind::UserDefinedType, "account_number", None);
        let sequence_key = key(ObjectKind::Sequence, "account_numbers", None);
        let policy_key = key(ObjectKind::Policy, "tenant_policy", None);
        let trigger_key = key(ObjectKind::Trigger, "audit_ddl", None);
        snapshot.schema.tables.push(crate::TableObject {
            key: table_key,
            schema_key: schema_key.clone(),
            name: "accounts".to_owned(),
            kind: crate::TableKind::BaseTable,
        });
        snapshot.metadata.objects.extend([
            MetadataObject {
                key: type_key.clone(),
                parent_key: Some(schema_key.clone()),
                name: "account_number".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: sequence_key.clone(),
                parent_key: Some(schema_key.clone()),
                name: "account_numbers".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: policy_key,
                parent_key: Some(schema_key),
                name: "tenant_policy".to_owned(),
                extension_kind: None,
                definition: None,
                properties: BTreeMap::new(),
            },
            MetadataObject {
                key: trigger_key,
                parent_key: Some(database_key),
                name: "audit_ddl".to_owned(),
                extension_kind: None,
                definition: Some(
                    "CREATE TRIGGER audit_ddl ON DATABASE FOR CREATE_TABLE AS RETURN".to_owned(),
                ),
                properties: BTreeMap::new(),
            },
        ]);
        snapshot.metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::UsesType,
            from_key: sequence_key,
            to_key: type_key,
            ordinal: None,
            properties: BTreeMap::new(),
        });

        assert!(validate_canonical_schema_snapshot(&snapshot).is_ok());
    }

    fn canonical_snapshot() -> CanonicalSchemaSnapshot {
        let database_key = key(ObjectKind::Database, "main", None);
        CanonicalSchemaSnapshot {
            schema: SchemaSnapshot {
                source_kind: "sqlite".to_owned(),
                connection_alias: "sample".to_owned(),
                database: DatabaseObject {
                    key: database_key.clone(),
                    name: "main".to_owned(),
                },
                schemas: vec![SchemaObject {
                    key: key(ObjectKind::Schema, "main", None),
                    database_key,
                    name: "main".to_owned(),
                }],
                tables: vec![],
                columns: vec![],
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
            },
            metadata: CanonicalMetadata::default(),
        }
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
