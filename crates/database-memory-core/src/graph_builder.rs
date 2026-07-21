use crate::graph_store::{
    GraphEdgeRecord, GraphNodeRecord, GraphSnapshotRecord, GraphStore, GraphStoreResult,
};
#[cfg(test)]
use crate::ObjectKind;
use crate::{ConstraintKind, ConstraintObject, ObjectKey, SchemaSnapshot};

pub fn insert_schema_snapshot_graph(
    store: &GraphStore,
    snapshot_key: &str,
    captured_at_unix_ms: i64,
    snapshot: &SchemaSnapshot,
) -> GraphStoreResult<()> {
    store.with_transaction(|store| {
        insert_schema_snapshot_graph_inner(store, snapshot_key, captured_at_unix_ms, snapshot)
    })
}

fn insert_schema_snapshot_graph_inner(
    store: &GraphStore,
    snapshot_key: &str,
    captured_at_unix_ms: i64,
    snapshot: &SchemaSnapshot,
) -> GraphStoreResult<()> {
    store.delete_snapshot(snapshot_key)?;
    store.insert_snapshot(&GraphSnapshotRecord {
        snapshot_key: snapshot_key.to_owned(),
        source: Some(format!(
            "{}:{}",
            snapshot.source_kind, snapshot.connection_alias
        )),
        captured_at_unix_ms,
        payload_json: payload_json(snapshot),
    })?;

    insert_node(
        store,
        snapshot_key,
        &snapshot.database.key,
        "Database",
        &snapshot.database.name,
        &snapshot.database,
    )?;

    for schema in sorted_by_key(&snapshot.schemas, |schema| &schema.key) {
        insert_node(
            store,
            snapshot_key,
            &schema.key,
            "Schema",
            &schema.name,
            schema,
        )?;
    }
    for table in sorted_by_key(&snapshot.tables, |table| &table.key) {
        insert_node(store, snapshot_key, &table.key, "Table", &table.name, table)?;
    }
    for column in sorted_by_key(&snapshot.columns, |column| &column.key) {
        insert_node(
            store,
            snapshot_key,
            &column.key,
            "Column",
            &column.name,
            column,
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
        )?;
    }
    for index in sorted_by_key(&snapshot.indexes, |index| &index.key) {
        insert_node(store, snapshot_key, &index.key, "Index", &index.name, index)?;
    }
    for view in sorted_by_key(&snapshot.views, |view| &view.key) {
        insert_node(store, snapshot_key, &view.key, "View", &view.name, view)?;
    }
    for trigger in sorted_by_key(&snapshot.triggers, |trigger| &trigger.key) {
        insert_node(
            store,
            snapshot_key,
            &trigger.key,
            "Trigger",
            &trigger.name,
            trigger,
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
        )?;
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
) -> GraphStoreResult<()> {
    store.insert_node(&GraphNodeRecord {
        snapshot_key: snapshot_key.to_owned(),
        node_key: key.to_string(),
        label: label.to_owned(),
        display_name: Some(display_name.to_owned()),
        payload_json: payload_json(payload),
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

fn payload_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("schema metadata should serialize to JSON")
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
    use crate::graph_store::GraphStore;
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

    fn built_store() -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot()).unwrap();
        store
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
