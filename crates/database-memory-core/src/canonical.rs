use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ObjectKey, SchemaSnapshot};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalSchemaSnapshot {
    #[serde(flatten)]
    pub schema: SchemaSnapshot,
    #[serde(default, skip_serializing_if = "CanonicalMetadata::is_empty")]
    pub metadata: CanonicalMetadata,
}

impl From<SchemaSnapshot> for CanonicalSchemaSnapshot {
    fn from(schema: SchemaSnapshot) -> Self {
        Self {
            schema,
            metadata: CanonicalMetadata::default(),
        }
    }
}

pub fn normalize_canonical_snapshot(snapshot: &mut CanonicalSchemaSnapshot) {
    let schema = &mut snapshot.schema;
    schema.schemas.sort_by_key(|object| object.key.to_string());
    schema.tables.sort_by_key(|object| object.key.to_string());
    schema.columns.sort_by_key(|object| object.key.to_string());
    schema
        .constraints
        .sort_by_key(|object| object.key.to_string());
    schema.indexes.sort_by_key(|object| object.key.to_string());
    schema.views.sort_by_key(|object| object.key.to_string());
    schema.triggers.sort_by_key(|object| object.key.to_string());
    schema.routines.sort_by_key(|object| object.key.to_string());
    for view in &mut schema.views {
        view.depends_on.sort_by_key(ObjectKey::to_string);
        view.depends_on.dedup();
    }
    for trigger in &mut schema.triggers {
        trigger.events.sort();
        trigger.events.dedup();
    }
    for routine in &mut schema.routines {
        routine.depends_on.sort_by_key(ObjectKey::to_string);
        routine.depends_on.dedup();
    }
    schema.capabilities.notes.sort();
    schema.capabilities.notes.dedup();
    schema.capabilities.limitations.sort();
    schema.capabilities.limitations.dedup();

    snapshot
        .metadata
        .objects
        .sort_by_key(|object| object.key.to_string());
    snapshot
        .metadata
        .annotations
        .sort_by_key(|annotation| annotation.object_key.to_string());
    snapshot.metadata.relationships.sort_by_key(|relationship| {
        (
            relationship.kind.clone(),
            relationship.from_key.to_string(),
            relationship.to_key.to_string(),
            relationship.ordinal,
        )
    });
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<MetadataObject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<ObjectAnnotation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<MetadataRelationship>,
}

impl CanonicalMetadata {
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.annotations.is_empty() && self.relationships.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataObject {
    pub key: ObjectKey,
    pub parent_key: Option<ObjectKey>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, MetadataValue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectAnnotation {
    pub object_key: ObjectKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, MetadataValue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataRelationship {
    pub kind: MetadataRelationshipKind,
    pub from_key: ObjectKey,
    pub to_key: ObjectKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, MetadataValue>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "extension_name", rename_all = "snake_case")]
pub enum MetadataRelationshipKind {
    DependsOn,
    UsesType,
    UsesSequence,
    PartitionOf,
    InheritsFrom,
    SynonymFor,
    HasParameter,
    ReturnsType,
    OwnedBy,
    Materializes,
    Invokes,
    IncludesColumn,
    ExcludesWith,
    Extension(String),
}

impl MetadataRelationshipKind {
    pub fn graph_edge_type(&self) -> String {
        match self {
            Self::DependsOn => "DEPENDS_ON".to_owned(),
            Self::UsesType => "USES_TYPE".to_owned(),
            Self::UsesSequence => "USES_SEQUENCE".to_owned(),
            Self::PartitionOf => "PARTITION_OF".to_owned(),
            Self::InheritsFrom => "INHERITS_FROM".to_owned(),
            Self::SynonymFor => "SYNONYM_FOR".to_owned(),
            Self::HasParameter => "HAS_PARAMETER".to_owned(),
            Self::ReturnsType => "RETURNS_TYPE".to_owned(),
            Self::OwnedBy => "OWNED_BY".to_owned(),
            Self::Materializes => "MATERIALIZES".to_owned(),
            Self::Invokes => "INVOKES".to_owned(),
            Self::IncludesColumn => "INCLUDES_COLUMN".to_owned(),
            Self::ExcludesWith => "EXCLUDES_WITH".to_owned(),
            Self::Extension(name) => format!("EXTENSION:{}", name),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum MetadataValue {
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
    StringList(Vec<String>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterCapabilities, CapabilitySupport, DatabaseObject, ObjectKind, SchemaObject};

    #[test]
    fn empty_canonical_metadata_keeps_legacy_payload_shape() {
        let canonical = CanonicalSchemaSnapshot::from(snapshot());
        let value = serde_json::to_value(canonical).unwrap();

        assert_eq!(value["source_kind"], "sqlite");
        assert!(value.get("metadata").is_none());
    }

    #[test]
    fn legacy_v1_snapshot_deserializes_as_empty_canonical_metadata() {
        let legacy = serde_json::to_value(snapshot()).unwrap();

        let canonical: CanonicalSchemaSnapshot = serde_json::from_value(legacy).unwrap();

        assert_eq!(canonical.schema.source_kind, "sqlite");
        assert!(canonical.metadata.is_empty());
    }

    #[test]
    fn relationship_edge_names_are_stable_and_extension_aware() {
        assert_eq!(
            MetadataRelationshipKind::PartitionOf.graph_edge_type(),
            "PARTITION_OF"
        );
        assert_eq!(
            MetadataRelationshipKind::Extension("policy_applies_to".to_owned()).graph_edge_type(),
            "EXTENSION:policy_applies_to"
        );
    }

    #[test]
    fn normalization_is_deterministic_and_preserves_ordered_column_contracts() {
        let mut canonical = CanonicalSchemaSnapshot::from(snapshot());
        canonical.schema.capabilities.notes = vec!["z".to_owned(), "a".to_owned()];

        normalize_canonical_snapshot(&mut canonical);

        assert_eq!(canonical.schema.capabilities.notes, vec!["a", "z"]);
        let once = serde_json::to_string(&canonical).unwrap();
        normalize_canonical_snapshot(&mut canonical);
        assert_eq!(serde_json::to_string(&canonical).unwrap(), once);
    }

    fn snapshot() -> SchemaSnapshot {
        let database_key = key(ObjectKind::Database, "main", None);
        SchemaSnapshot {
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
