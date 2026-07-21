use std::collections::BTreeMap;

use crate::canonical::{CanonicalMetadata, MetadataObject, ObjectAnnotation};
use crate::certification::{verify_certified_schema_snapshot, CertifiedSchemaSnapshot};
use crate::graph_store::{
    GraphEdgeRecord, GraphNodeRecord, GraphSnapshotRecord, GraphStore, GraphStoreResult,
};
use crate::snapshot_validation::validate_schema_snapshot;
#[cfg(test)]
use crate::ObjectKind;
use crate::{ConstraintKind, ConstraintObject, ObjectKey, SchemaSnapshot};

pub fn insert_schema_snapshot_graph(
    store: &GraphStore,
    snapshot_key: &str,
    captured_at_unix_ms: i64,
    snapshot: &SchemaSnapshot,
) -> GraphStoreResult<()> {
    validate_schema_snapshot(snapshot)?;
    store.with_transaction(|store| {
        insert_schema_snapshot_graph_inner(
            store,
            snapshot_key,
            captured_at_unix_ms,
            snapshot,
            snapshot,
            None,
        )
    })
}

pub fn insert_certified_schema_snapshot_graph(
    store: &GraphStore,
    snapshot_key: &str,
    captured_at_unix_ms: i64,
    certified: &CertifiedSchemaSnapshot,
) -> GraphStoreResult<()> {
    verify_certified_schema_snapshot(certified)?;
    store.with_transaction(|store| {
        insert_schema_snapshot_graph_inner(
            store,
            snapshot_key,
            captured_at_unix_ms,
            &certified.snapshot.schema,
            certified,
            Some(&certified.snapshot.metadata),
        )
    })
}

fn insert_schema_snapshot_graph_inner<T: serde::Serialize>(
    store: &GraphStore,
    snapshot_key: &str,
    captured_at_unix_ms: i64,
    snapshot: &SchemaSnapshot,
    snapshot_payload: &T,
    metadata: Option<&CanonicalMetadata>,
) -> GraphStoreResult<()> {
    let annotations = metadata
        .map(|metadata| {
            metadata
                .annotations
                .iter()
                .map(|annotation| (annotation.object_key.to_string(), annotation))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    store.delete_snapshot(snapshot_key)?;
    store.insert_snapshot(&GraphSnapshotRecord {
        snapshot_key: snapshot_key.to_owned(),
        source: Some(format!(
            "{}:{}",
            snapshot.source_kind, snapshot.connection_alias
        )),
        captured_at_unix_ms,
        payload_json: payload_json(snapshot_payload),
    })?;

    insert_node(
        store,
        snapshot_key,
        &snapshot.database.key,
        "Database",
        &snapshot.database.name,
        &snapshot.database,
        annotation_for(&annotations, &snapshot.database.key),
    )?;

    for schema in sorted_by_key(&snapshot.schemas, |schema| &schema.key) {
        insert_node(
            store,
            snapshot_key,
            &schema.key,
            "Schema",
            &schema.name,
            schema,
            annotation_for(&annotations, &schema.key),
        )?;
    }
    for table in sorted_by_key(&snapshot.tables, |table| &table.key) {
        insert_node(
            store,
            snapshot_key,
            &table.key,
            "Table",
            &table.name,
            table,
            annotation_for(&annotations, &table.key),
        )?;
    }
    for column in sorted_by_key(&snapshot.columns, |column| &column.key) {
        insert_node(
            store,
            snapshot_key,
            &column.key,
            "Column",
            &column.name,
            column,
            annotation_for(&annotations, &column.key),
        )?;
    }
    for constraint in sorted_by_key(&snapshot.constraints, |constraint| &constraint.key) {
        insert_node(
            store,
            snapshot_key,
            &constraint.key,
            constraint_label(constraint),
            &constraint.name,
            constraint,
            annotation_for(&annotations, &constraint.key),
        )?;
    }
    for index in sorted_by_key(&snapshot.indexes, |index| &index.key) {
        insert_node(
            store,
            snapshot_key,
            &index.key,
            "Index",
            &index.name,
            index,
            annotation_for(&annotations, &index.key),
        )?;
    }
    for view in sorted_by_key(&snapshot.views, |view| &view.key) {
        insert_node(
            store,
            snapshot_key,
            &view.key,
            "View",
            &view.name,
            view,
            annotation_for(&annotations, &view.key),
        )?;
    }
    for trigger in sorted_by_key(&snapshot.triggers, |trigger| &trigger.key) {
        insert_node(
            store,
            snapshot_key,
            &trigger.key,
            "Trigger",
            &trigger.name,
            trigger,
            annotation_for(&annotations, &trigger.key),
        )?;
    }
    for routine in sorted_by_key(&snapshot.routines, |routine| &routine.key) {
        insert_node(
            store,
            snapshot_key,
            &routine.key,
            "Routine",
            &routine.name,
            routine,
            annotation_for(&annotations, &routine.key),
        )?;
    }

    if let Some(metadata) = metadata {
        for object in sorted_metadata_objects(&metadata.objects) {
            insert_node(
                store,
                snapshot_key,
                &object.key,
                metadata_object_label(object),
                &object.name,
                object,
                annotation_for(&annotations, &object.key),
            )?;
        }
    }

    for schema in sorted_by_key(&snapshot.schemas, |schema| &schema.key) {
        insert_edge(
            store,
            snapshot_key,
            "DATABASE_HAS_SCHEMA",
            &schema.database_key,
            &schema.key,
        )?;
    }
    for table in sorted_by_key(&snapshot.tables, |table| &table.key) {
        insert_edge(
            store,
            snapshot_key,
            "SCHEMA_HAS_TABLE",
            &table.schema_key,
            &table.key,
        )?;
    }
    for column in sorted_by_key(&snapshot.columns, |column| &column.key) {
        insert_edge(
            store,
            snapshot_key,
            "TABLE_HAS_COLUMN",
            &column.table_key,
            &column.key,
        )?;
    }
    for constraint in sorted_by_key(&snapshot.constraints, |constraint| &constraint.key) {
        insert_constraint_edges(store, snapshot_key, constraint)?;
    }
    for index in sorted_by_key(&snapshot.indexes, |index| &index.key) {
        insert_edge(
            store,
            snapshot_key,
            "TABLE_HAS_INDEX",
            &index.table_key,
            &index.key,
        )?;
        for column_key in sorted_keys(&index.columns) {
            insert_edge(
                store,
                snapshot_key,
                "COLUMN_IN_INDEX",
                column_key,
                &index.key,
            )?;
        }
    }
    for view in sorted_by_key(&snapshot.views, |view| &view.key) {
        insert_edge(
            store,
            snapshot_key,
            "SCHEMA_HAS_VIEW",
            &view.schema_key,
            &view.key,
        )?;
        for dependency in sorted_keys(&view.depends_on) {
            match dependency.object_kind {
                crate::ObjectKind::Table => insert_edge(
                    store,
                    snapshot_key,
                    "VIEW_DEPENDS_ON_TABLE",
                    &view.key,
                    dependency,
                )?,
                crate::ObjectKind::Column => insert_edge(
                    store,
                    snapshot_key,
                    "VIEW_DEPENDS_ON_COLUMN",
                    &view.key,
                    dependency,
                )?,
                crate::ObjectKind::View => insert_edge(
                    store,
                    snapshot_key,
                    "VIEW_DEPENDS_ON_VIEW",
                    &view.key,
                    dependency,
                )?,
                _ => {}
            }
        }
    }
    for trigger in sorted_by_key(&snapshot.triggers, |trigger| &trigger.key) {
        let (owner_edge, target_edge) = if trigger.table_key.object_kind == crate::ObjectKind::View
        {
            ("VIEW_HAS_TRIGGER", "TRIGGER_ON_VIEW")
        } else {
            ("TABLE_HAS_TRIGGER", "TRIGGER_ON_TABLE")
        };
        insert_edge(
            store,
            snapshot_key,
            owner_edge,
            &trigger.table_key,
            &trigger.key,
        )?;
        insert_edge(
            store,
            snapshot_key,
            target_edge,
            &trigger.key,
            &trigger.table_key,
        )?;
        if let Some(routine_key) = &trigger.executes_routine_key {
            insert_edge(
                store,
                snapshot_key,
                "TRIGGER_EXECUTES_ROUTINE",
                &trigger.key,
                routine_key,
            )?;
        }
    }
    for routine in sorted_by_key(&snapshot.routines, |routine| &routine.key) {
        insert_edge(
            store,
            snapshot_key,
            "SCHEMA_HAS_ROUTINE",
            &routine.schema_key,
            &routine.key,
        )?;
        for dependency in sorted_keys(&routine.depends_on) {
            match dependency.object_kind {
                crate::ObjectKind::Table => insert_edge(
                    store,
                    snapshot_key,
                    "ROUTINE_DEPENDS_ON_TABLE",
                    &routine.key,
                    dependency,
                )?,
                crate::ObjectKind::Column => insert_edge(
                    store,
                    snapshot_key,
                    "ROUTINE_DEPENDS_ON_COLUMN",
                    &routine.key,
                    dependency,
                )?,
                _ => {}
            }
        }
    }

    if let Some(metadata) = metadata {
        for object in sorted_metadata_objects(&metadata.objects) {
            if let Some(parent_key) = &object.parent_key {
                insert_edge(
                    store,
                    snapshot_key,
                    "METADATA_PARENT",
                    parent_key,
                    &object.key,
                )?;
            }
        }
        let mut relationships = metadata.relationships.iter().collect::<Vec<_>>();
        relationships.sort_by_key(|relationship| {
            (
                relationship.kind.graph_edge_type(),
                relationship.from_key.to_string(),
                relationship.to_key.to_string(),
                relationship.ordinal,
            )
        });
        for relationship in relationships {
            insert_metadata_relationship(store, snapshot_key, relationship)?;
        }
    }

    Ok(())
}

fn insert_constraint_edges(
    store: &GraphStore,
    snapshot_key: &str,
    constraint: &ConstraintObject,
) -> GraphStoreResult<()> {
    insert_edge(
        store,
        snapshot_key,
        "TABLE_HAS_CONSTRAINT",
        &constraint.table_key,
        &constraint.key,
    )?;

    match constraint.kind {
        ConstraintKind::PrimaryKey => {
            for column_key in sorted_keys(&constraint.columns) {
                insert_edge(
                    store,
                    snapshot_key,
                    "COLUMN_IN_PRIMARY_KEY",
                    column_key,
                    &constraint.key,
                )?;
            }
        }
        ConstraintKind::ForeignKey => {
            for column_key in sorted_keys(&constraint.columns) {
                insert_edge(
                    store,
                    snapshot_key,
                    "FK_FROM_COLUMN",
                    column_key,
                    &constraint.key,
                )?;
            }
            for column_key in sorted_keys(&constraint.referenced_columns) {
                insert_edge(
                    store,
                    snapshot_key,
                    "FK_TO_COLUMN",
                    &constraint.key,
                    column_key,
                )?;
            }
        }
        ConstraintKind::Unique => {
            for column_key in sorted_keys(&constraint.columns) {
                insert_edge(
                    store,
                    snapshot_key,
                    "COLUMN_IN_UNIQUE",
                    column_key,
                    &constraint.key,
                )?;
            }
        }
        ConstraintKind::Check => {}
    }

    Ok(())
}

fn insert_node<T: serde::Serialize>(
    store: &GraphStore,
    snapshot_key: &str,
    key: &ObjectKey,
    label: &str,
    display_name: &str,
    payload: &T,
    annotation: Option<&ObjectAnnotation>,
) -> GraphStoreResult<()> {
    store.insert_node(&GraphNodeRecord {
        snapshot_key: snapshot_key.to_owned(),
        node_key: key.to_string(),
        label: label.to_owned(),
        display_name: Some(display_name.to_owned()),
        payload_json: node_payload_json(payload, annotation),
    })
}

fn insert_metadata_relationship(
    store: &GraphStore,
    snapshot_key: &str,
    relationship: &crate::canonical::MetadataRelationship,
) -> GraphStoreResult<()> {
    let edge_type = relationship.kind.graph_edge_type();
    let from = relationship.from_key.to_string();
    let to = relationship.to_key.to_string();
    let ordinal = relationship
        .ordinal
        .map(|value| value.to_string())
        .unwrap_or_default();
    store.insert_edge(&GraphEdgeRecord {
        snapshot_key: snapshot_key.to_owned(),
        edge_key: format!("{edge_type}:{from}->{to}:{ordinal}"),
        edge_from: from,
        edge_to: to,
        edge_type,
        payload_json: payload_json(relationship),
    })
}

fn insert_edge(
    store: &GraphStore,
    snapshot_key: &str,
    edge_type: &str,
    edge_from: &ObjectKey,
    edge_to: &ObjectKey,
) -> GraphStoreResult<()> {
    let from = edge_from.to_string();
    let to = edge_to.to_string();
    store.insert_edge(&GraphEdgeRecord {
        snapshot_key: snapshot_key.to_owned(),
        edge_key: format!("{edge_type}:{from}->{to}"),
        edge_from: from,
        edge_to: to,
        edge_type: edge_type.to_owned(),
        payload_json: edge_payload(edge_type),
    })
}

fn constraint_label(constraint: &ConstraintObject) -> &'static str {
    match constraint.kind {
        ConstraintKind::PrimaryKey => "PrimaryKey",
        ConstraintKind::ForeignKey => "ForeignKey",
        ConstraintKind::Unique => "UniqueConstraint",
        ConstraintKind::Check => "CheckConstraint",
    }
}

fn sorted_by_key<T, F>(items: &[T], key: F) -> Vec<&T>
where
    F: Fn(&T) -> &ObjectKey,
{
    let mut refs = items.iter().collect::<Vec<_>>();
    refs.sort_by_key(|item| key(*item).to_string());
    refs
}

fn sorted_keys(keys: &[ObjectKey]) -> Vec<&ObjectKey> {
    let mut refs = keys.iter().collect::<Vec<_>>();
    refs.sort_by_key(|key| key.to_string());
    refs
}

fn sorted_metadata_objects(objects: &[MetadataObject]) -> Vec<&MetadataObject> {
    let mut refs = objects.iter().collect::<Vec<_>>();
    refs.sort_by_key(|object| object.key.to_string());
    refs
}

fn annotation_for<'a>(
    annotations: &'a BTreeMap<String, &'a ObjectAnnotation>,
    key: &ObjectKey,
) -> Option<&'a ObjectAnnotation> {
    annotations.get(&key.to_string()).copied()
}

fn metadata_object_label(object: &MetadataObject) -> &'static str {
    match object.key.object_kind {
        crate::ObjectKind::MaterializedView => "MaterializedView",
        crate::ObjectKind::ViewColumn => "ViewColumn",
        crate::ObjectKind::Sequence => "Sequence",
        crate::ObjectKind::RoutineParameter => "RoutineParameter",
        crate::ObjectKind::UserDefinedType => "UserDefinedType",
        crate::ObjectKind::Domain => "Domain",
        crate::ObjectKind::EnumValue => "EnumValue",
        crate::ObjectKind::Synonym => "Synonym",
        crate::ObjectKind::ExclusionConstraint => "ExclusionConstraint",
        crate::ObjectKind::Event => "Event",
        crate::ObjectKind::Package => "Package",
        crate::ObjectKind::Principal => "Principal",
        crate::ObjectKind::Policy => "Policy",
        crate::ObjectKind::Extension => "Extension",
        _ => "MetadataObject",
    }
}

fn payload_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("schema metadata should serialize to JSON")
}

fn node_payload_json<T: serde::Serialize>(
    value: &T,
    annotation: Option<&ObjectAnnotation>,
) -> String {
    let mut value = serde_json::to_value(value).expect("schema metadata should serialize to JSON");
    if let (Some(annotation), Some(object)) = (annotation, value.as_object_mut()) {
        object.insert(
            "canonical_annotation".to_owned(),
            serde_json::to_value(annotation).expect("annotation metadata should serialize to JSON"),
        );
    }
    serde_json::to_string(&value).expect("schema metadata should serialize to JSON")
}

#[derive(serde::Serialize)]
struct EdgePayload<'a> {
    edge_type: &'a str,
}

fn edge_payload(edge_type: &str) -> String {
    serde_json::to_string(&EdgePayload { edge_type }).expect("edge type should serialize to JSON")
}

#[cfg(test)]
mod graph_builder_tests {
    use super::*;
    use crate::canonical::{
        CanonicalSchemaSnapshot, MetadataObject, MetadataRelationship, MetadataRelationshipKind,
        MetadataValue, ObjectAnnotation,
    };
    use crate::certification::{
        certify_schema_snapshot, fixture_discovery_counts, AdapterIdentity, CapabilityCheck,
        IntrospectionScope, ServerIdentity, COMPLETE_CONTRACT_VERSION,
    };
    use crate::graph_store::{GraphStore, SnapshotAuthority, SnapshotContractStatus};
    use crate::{
        AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintObject, DatabaseObject,
        IndexObject, RoutineKind, RoutineObject, SchemaObject, TableKind, TableObject,
        TriggerObject, ViewObject,
    };

    const SNAPSHOT: &str = "snapshot-1";

    #[test]
    fn graph_builder_writes_table_and_column_edges() {
        let store = built_store();
        let schema = key(ObjectKind::Schema, "main", None);
        let orders = key(ObjectKind::Table, "orders", None);
        let orders_id = key(ObjectKind::Column, "orders", Some("id"));

        assert_eq!(
            store
                .get_node(SNAPSHOT, &orders.to_string())
                .unwrap()
                .unwrap()
                .label,
            "Table"
        );
        assert_edge(&store, "SCHEMA_HAS_TABLE", &schema, &orders);
        assert_edge(&store, "TABLE_HAS_COLUMN", &orders, &orders_id);
    }

    #[test]
    fn graph_builder_writes_schema_ownership_for_views_and_routines() {
        let store = built_store();
        let schema = key(ObjectKind::Schema, "main", None);
        let view = key(ObjectKind::View, "order_users", None);
        let routine = key(ObjectKind::Routine, "orders_touch", None);

        assert_edge(&store, "SCHEMA_HAS_VIEW", &schema, &view);
        assert_edge(&store, "SCHEMA_HAS_ROUTINE", &schema, &routine);
    }

    #[test]
    fn graph_builder_writes_primary_key_edges() {
        let store = built_store();
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let users_pk = key(ObjectKind::PrimaryKey, "users", Some("pk_users"));

        assert_eq!(
            store
                .get_node(SNAPSHOT, &users_pk.to_string())
                .unwrap()
                .unwrap()
                .label,
            "PrimaryKey"
        );
        assert_edge(&store, "COLUMN_IN_PRIMARY_KEY", &users_id, &users_pk);
    }

    #[test]
    fn graph_builder_writes_foreign_key_edges() {
        let store = built_store();
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let fk = key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user"));

        assert_edge(
            &store,
            "TABLE_HAS_CONSTRAINT",
            &key(ObjectKind::Table, "orders", None),
            &fk,
        );
        assert_edge(&store, "FK_FROM_COLUMN", &orders_user_id, &fk);
        assert_edge(&store, "FK_TO_COLUMN", &fk, &users_id);
    }

    #[test]
    fn graph_builder_writes_index_edges() {
        let store = built_store();
        let orders = key(ObjectKind::Table, "orders", None);
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));
        let index = key(ObjectKind::Index, "orders", Some("idx_orders_user_id"));

        assert_eq!(
            store
                .get_node(SNAPSHOT, &index.to_string())
                .unwrap()
                .unwrap()
                .label,
            "Index"
        );
        assert_edge(&store, "TABLE_HAS_INDEX", &orders, &index);
        assert_edge(&store, "COLUMN_IN_INDEX", &orders_user_id, &index);
    }

    #[test]
    fn graph_builder_writes_view_trigger_and_routine_edges() {
        let store = built_store();
        let orders = key(ObjectKind::Table, "orders", None);
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));
        let view = key(ObjectKind::View, "order_users", None);
        let trigger = key(ObjectKind::Trigger, "orders", Some("trg_orders_touch"));
        let routine = key(ObjectKind::Routine, "orders_touch", None);

        assert_eq!(
            store
                .get_node(SNAPSHOT, &view.to_string())
                .unwrap()
                .unwrap()
                .label,
            "View"
        );
        assert_eq!(
            store
                .get_node(SNAPSHOT, &trigger.to_string())
                .unwrap()
                .unwrap()
                .label,
            "Trigger"
        );
        assert_eq!(
            store
                .get_node(SNAPSHOT, &routine.to_string())
                .unwrap()
                .unwrap()
                .label,
            "Routine"
        );
        assert_edge(&store, "VIEW_DEPENDS_ON_TABLE", &view, &orders);
        assert_edge(&store, "VIEW_DEPENDS_ON_COLUMN", &view, &orders_user_id);
        assert_edge(&store, "TRIGGER_ON_TABLE", &trigger, &orders);
        assert_edge(&store, "TRIGGER_EXECUTES_ROUTINE", &trigger, &routine);
        assert_edge(&store, "ROUTINE_DEPENDS_ON_TABLE", &routine, &orders);
        assert_edge(
            &store,
            "ROUTINE_DEPENDS_ON_COLUMN",
            &routine,
            &orders_user_id,
        );
    }

    #[test]
    fn graph_builder_keeps_previous_snapshot_when_replacement_fails() {
        let store = built_store();
        let before = store
            .get_node(
                SNAPSHOT,
                &key(ObjectKind::Column, "users", Some("id")).to_string(),
            )
            .unwrap()
            .unwrap();
        let mut invalid = snapshot();
        invalid.columns[0].table_key = key(ObjectKind::Table, "missing", None);

        assert!(insert_schema_snapshot_graph(&store, SNAPSHOT, 1, &invalid).is_err());
        assert_eq!(
            store.get_node(SNAPSHOT, &before.node_key).unwrap().unwrap(),
            before
        );
    }

    #[test]
    fn graph_builder_persists_verified_complete_contract() {
        let store = GraphStore::in_memory().unwrap();
        let snapshot = snapshot();
        let certified = certified(snapshot);

        insert_certified_schema_snapshot_graph(&store, SNAPSHOT, 7, &certified).unwrap();

        let payload = store.get_snapshot(SNAPSHOT).unwrap().unwrap().payload_json;
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            value["contract_version"],
            serde_json::json!(COMPLETE_CONTRACT_VERSION)
        );
        assert_eq!(value["completeness"]["status"], "complete");
        assert_eq!(
            store
                .get_snapshot_contract_status(SNAPSHOT)
                .unwrap()
                .unwrap(),
            SnapshotContractStatus {
                authority: SnapshotAuthority::Complete,
                contract_version: Some(COMPLETE_CONTRACT_VERSION),
            }
        );
        assert!(store.get_certified_snapshot(SNAPSHOT).unwrap().is_some());
    }

    #[test]
    fn graph_builder_keeps_complete_snapshot_when_certification_is_tampered() {
        let store = GraphStore::in_memory().unwrap();
        let snapshot = snapshot();
        let certified = certified(snapshot.clone());
        insert_certified_schema_snapshot_graph(&store, SNAPSHOT, 7, &certified).unwrap();
        let before = store.get_snapshot(SNAPSHOT).unwrap().unwrap();
        let mut tampered = certified;
        tampered.completeness.object_counts[0].discovered += 1;

        assert!(insert_certified_schema_snapshot_graph(&store, SNAPSHOT, 8, &tampered).is_err());
        assert_eq!(store.get_snapshot(SNAPSHOT).unwrap().unwrap(), before);
    }

    #[test]
    fn graph_builder_persists_canonical_objects_annotations_and_relationships() {
        let store = GraphStore::in_memory().unwrap();
        let mut base = snapshot();
        base.capabilities.views = CapabilitySupport::Supported;
        base.capabilities.triggers = CapabilitySupport::Supported;
        base.capabilities.routines = CapabilitySupport::Supported;
        base.capabilities.dependencies = CapabilitySupport::Supported;
        let column = key(ObjectKind::Column, "orders", Some("id"));
        let sequence = key(ObjectKind::Sequence, "orders_id_seq", None);
        let mut canonical = CanonicalSchemaSnapshot::from(base);
        canonical.metadata.objects.push(MetadataObject {
            key: sequence.clone(),
            parent_key: Some(key(ObjectKind::Schema, "main", None)),
            name: "orders_id_seq".to_owned(),
            extension_kind: None,
            definition: None,
            properties: BTreeMap::from([("increment".to_owned(), MetadataValue::Integer(1))]),
        });
        canonical.metadata.annotations.push(ObjectAnnotation {
            object_key: column.clone(),
            definition: None,
            properties: BTreeMap::from([("identity".to_owned(), MetadataValue::Boolean(true))]),
        });
        canonical.metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::UsesSequence,
            from_key: column.clone(),
            to_key: sequence.clone(),
            ordinal: None,
            properties: BTreeMap::new(),
        });
        let certified = certify_canonical(canonical);

        insert_certified_schema_snapshot_graph(&store, SNAPSHOT, 9, &certified).unwrap();

        let sequence_node = store
            .get_node(SNAPSHOT, &sequence.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(sequence_node.label, "Sequence");
        let column_payload: serde_json::Value = serde_json::from_str(
            &store
                .get_node(SNAPSHOT, &column.to_string())
                .unwrap()
                .unwrap()
                .payload_json,
        )
        .unwrap();
        assert_eq!(
            column_payload["canonical_annotation"]["properties"]["identity"]["value"],
            true
        );
        assert_edge(
            &store,
            "METADATA_PARENT",
            &key(ObjectKind::Schema, "main", None),
            &sequence,
        );
        assert_edge(&store, "USES_SEQUENCE", &column, &sequence);
    }

    fn built_store() -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot()).unwrap();
        store
    }

    fn certified(mut snapshot: SchemaSnapshot) -> CertifiedSchemaSnapshot {
        snapshot.capabilities.views = CapabilitySupport::Supported;
        snapshot.capabilities.triggers = CapabilitySupport::Supported;
        snapshot.capabilities.routines = CapabilitySupport::Supported;
        snapshot.capabilities.dependencies = CapabilitySupport::Supported;
        certify_canonical(CanonicalSchemaSnapshot::from(snapshot))
    }

    fn certify_canonical(snapshot: CanonicalSchemaSnapshot) -> CertifiedSchemaSnapshot {
        let counts = fixture_discovery_counts(&snapshot);
        certify_schema_snapshot(
            snapshot,
            AdapterIdentity {
                name: "sqlite".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            ServerIdentity {
                product: "SQLite".to_owned(),
                version: "3".to_owned(),
            },
            IntrospectionScope {
                catalogs: vec!["main".to_owned()],
                schemas: vec!["main".to_owned()],
            },
            counts,
            vec![CapabilityCheck {
                name: "metadata_visibility".to_owned(),
                evidence: "catalog reads completed".to_owned(),
            }],
        )
        .unwrap()
    }

    fn snapshot() -> SchemaSnapshot {
        let database = key(ObjectKind::Database, "main", None);
        let schema = key(ObjectKind::Schema, "main", None);
        let users = key(ObjectKind::Table, "users", None);
        let orders = key(ObjectKind::Table, "orders", None);
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let orders_id = key(ObjectKind::Column, "orders", Some("id"));
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));

        SchemaSnapshot {
            source_kind: "sqlite".to_owned(),
            connection_alias: "app-db".to_owned(),
            database: DatabaseObject {
                key: database.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: schema.clone(),
                database_key: database,
                name: "main".to_owned(),
            }],
            tables: vec![
                TableObject {
                    key: users.clone(),
                    schema_key: schema.clone(),
                    name: "users".to_owned(),
                    kind: TableKind::BaseTable,
                },
                TableObject {
                    key: orders.clone(),
                    schema_key: schema,
                    name: "orders".to_owned(),
                    kind: TableKind::BaseTable,
                },
            ],
            columns: vec![
                column(users_id.clone(), users.clone(), "id", 1),
                column(orders_id, orders.clone(), "id", 1),
                column(orders_user_id.clone(), orders.clone(), "user_id", 2),
            ],
            constraints: vec![
                ConstraintObject {
                    key: key(ObjectKind::PrimaryKey, "users", Some("pk_users")),
                    table_key: users.clone(),
                    name: "pk_users".to_owned(),
                    kind: ConstraintKind::PrimaryKey,
                    columns: vec![users_id.clone()],
                    referenced_table_key: None,
                    referenced_columns: vec![],
                    expression: None,
                },
                ConstraintObject {
                    key: key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
                    table_key: orders.clone(),
                    name: "fk_orders_user".to_owned(),
                    kind: ConstraintKind::ForeignKey,
                    columns: vec![orders_user_id.clone()],
                    referenced_table_key: Some(users),
                    referenced_columns: vec![users_id],
                    expression: None,
                },
            ],
            indexes: vec![IndexObject {
                key: key(ObjectKind::Index, "orders", Some("idx_orders_user_id")),
                table_key: orders.clone(),
                name: "idx_orders_user_id".to_owned(),
                columns: vec![orders_user_id.clone()],
                is_unique: false,
                is_primary: false,
                predicate: None,
                expression: None,
            }],
            views: vec![ViewObject {
                key: key(ObjectKind::View, "order_users", None),
                schema_key: key(ObjectKind::Schema, "main", None),
                name: "order_users".to_owned(),
                definition: Some("select orders.user_id from orders".to_owned()),
                depends_on: vec![orders.clone(), orders_user_id.clone()],
            }],
            triggers: vec![TriggerObject {
                key: key(ObjectKind::Trigger, "orders", Some("trg_orders_touch")),
                table_key: orders.clone(),
                name: "trg_orders_touch".to_owned(),
                timing: Some("BEFORE".to_owned()),
                events: vec!["INSERT".to_owned()],
                definition: Some("CREATE TRIGGER trg_orders_touch".to_owned()),
                executes_routine_key: Some(key(ObjectKind::Routine, "orders_touch", None)),
            }],
            routines: vec![RoutineObject {
                key: key(ObjectKind::Routine, "orders_touch", None),
                schema_key: key(ObjectKind::Schema, "main", None),
                name: "orders_touch".to_owned(),
                kind: RoutineKind::Function,
                definition: Some("return new".to_owned()),
                depends_on: vec![orders, orders_user_id],
            }],
            capabilities: AdapterCapabilities {
                source_kind: "sqlite".to_owned(),
                metadata_only: true,
                schemas: true,
                tables: true,
                columns: true,
                constraints: true,
                indexes: true,
                views: CapabilitySupport::Unsupported,
                triggers: CapabilitySupport::Unsupported,
                routines: CapabilitySupport::Unsupported,
                dependencies: CapabilitySupport::Unsupported,
                limitations: vec![],
                notes: vec![],
            },
        }
    }

    fn column(
        key: ObjectKey,
        table_key: ObjectKey,
        name: &str,
        ordinal_position: u32,
    ) -> ColumnObject {
        ColumnObject {
            key,
            table_key,
            name: name.to_owned(),
            ordinal_position,
            data_type: "integer".to_owned(),
            is_nullable: false,
            default_value: None,
            is_generated: false,
        }
    }

    fn key(kind: ObjectKind, object_name: &str, sub_object: Option<&str>) -> ObjectKey {
        ObjectKey::new(
            "sqlite",
            "app-db",
            "main",
            "main",
            kind,
            object_name,
            sub_object.map(str::to_owned),
        )
    }

    fn assert_edge(store: &GraphStore, edge_type: &str, from: &ObjectKey, to: &ObjectKey) {
        let edges = store.edges_by_type(SNAPSHOT, edge_type).unwrap();
        assert!(
            edges.iter().any(|edge| {
                edge.edge_from == from.to_string() && edge.edge_to == to.to_string()
            }),
            "missing {edge_type} edge from {from} to {to}"
        );
    }
}
