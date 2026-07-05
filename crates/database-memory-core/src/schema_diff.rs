use std::collections::{BTreeMap, BTreeSet};

use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphStore, GraphStoreResult};
use crate::impact_analysis::{impact_analysis, Direction, ImpactAnalysisResult};

pub const DEFAULT_SCHEMA_DIFF_IMPACT_MAX_DEPTH: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDiff {
    pub from_snapshot_key: String,
    pub to_snapshot_key: String,
    pub added_nodes: Vec<GraphNodeRecord>,
    pub removed_nodes: Vec<GraphNodeRecord>,
    pub changed_nodes: Vec<ChangedGraphNode>,
    pub added_edges: Vec<GraphEdgeRecord>,
    pub removed_edges: Vec<GraphEdgeRecord>,
    pub impacted: Vec<SchemaDiffImpact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedGraphNode {
    pub from: GraphNodeRecord,
    pub to: GraphNodeRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDiffImpact {
    pub seed_node_key: String,
    pub snapshot_key: String,
    pub impact: ImpactAnalysisResult,
}

pub fn schema_diff(
    store: &GraphStore,
    from_snapshot_key: &str,
    to_snapshot_key: &str,
) -> GraphStoreResult<SchemaDiff> {
    schema_diff_with_impact_depth(
        store,
        from_snapshot_key,
        to_snapshot_key,
        DEFAULT_SCHEMA_DIFF_IMPACT_MAX_DEPTH,
    )
}

pub fn schema_diff_with_impact_depth(
    store: &GraphStore,
    from_snapshot_key: &str,
    to_snapshot_key: &str,
    impact_max_depth: u32,
) -> GraphStoreResult<SchemaDiff> {
    let from_nodes = snapshot_nodes(store, from_snapshot_key)?;
    let to_nodes = snapshot_nodes(store, to_snapshot_key)?;
    let from_edges = snapshot_edges(store, from_snapshot_key)?;
    let to_edges = snapshot_edges(store, to_snapshot_key)?;

    let added_nodes = to_nodes
        .iter()
        .filter(|(node_key, _)| !from_nodes.contains_key(*node_key))
        .map(|(_, node)| node.clone())
        .collect::<Vec<_>>();
    let removed_nodes = from_nodes
        .iter()
        .filter(|(node_key, _)| !to_nodes.contains_key(*node_key))
        .map(|(_, node)| node.clone())
        .collect::<Vec<_>>();
    let changed_nodes = to_nodes
        .iter()
        .filter_map(|(node_key, to)| {
            let from = from_nodes.get(node_key)?;
            (from.payload_json != to.payload_json).then(|| ChangedGraphNode {
                from: from.clone(),
                to: to.clone(),
            })
        })
        .collect::<Vec<_>>();

    let added_edges = to_edges
        .iter()
        .filter(|(edge_key, _)| !from_edges.contains_key(*edge_key))
        .map(|(_, edge)| edge.clone())
        .collect::<Vec<_>>();
    let removed_edges = from_edges
        .iter()
        .filter(|(edge_key, _)| !to_edges.contains_key(*edge_key))
        .map(|(_, edge)| edge.clone())
        .collect::<Vec<_>>();

    let impacted = changed_impacts(
        store,
        from_snapshot_key,
        to_snapshot_key,
        impact_max_depth,
        &added_nodes,
        &removed_nodes,
        &changed_nodes,
    )?;

    Ok(SchemaDiff {
        from_snapshot_key: from_snapshot_key.to_owned(),
        to_snapshot_key: to_snapshot_key.to_owned(),
        added_nodes,
        removed_nodes,
        changed_nodes,
        added_edges,
        removed_edges,
        impacted,
    })
}

fn changed_impacts(
    store: &GraphStore,
    from_snapshot_key: &str,
    to_snapshot_key: &str,
    impact_max_depth: u32,
    added_nodes: &[GraphNodeRecord],
    removed_nodes: &[GraphNodeRecord],
    changed_nodes: &[ChangedGraphNode],
) -> GraphStoreResult<Vec<SchemaDiffImpact>> {
    let mut seeds = BTreeSet::<(String, String)>::new();

    for node in added_nodes {
        seeds.insert((to_snapshot_key.to_owned(), node.node_key.clone()));
    }
    for node in removed_nodes {
        seeds.insert((from_snapshot_key.to_owned(), node.node_key.clone()));
    }
    for node in changed_nodes {
        seeds.insert((to_snapshot_key.to_owned(), node.to.node_key.clone()));
    }

    seeds
        .into_iter()
        .map(|(snapshot_key, seed_node_key)| {
            let impact = impact_analysis(
                store,
                &snapshot_key,
                &seed_node_key,
                Direction::Both,
                impact_max_depth,
            )?;
            Ok(SchemaDiffImpact {
                seed_node_key,
                snapshot_key,
                impact,
            })
        })
        .collect()
}

fn snapshot_nodes(
    store: &GraphStore,
    snapshot_key: &str,
) -> GraphStoreResult<BTreeMap<String, GraphNodeRecord>> {
    let mut nodes = BTreeMap::new();
    for label in NODE_LABELS {
        for node in store.nodes_by_label(snapshot_key, label)? {
            nodes.insert(node.node_key.clone(), node);
        }
    }
    Ok(nodes)
}

fn snapshot_edges(
    store: &GraphStore,
    snapshot_key: &str,
) -> GraphStoreResult<BTreeMap<String, GraphEdgeRecord>> {
    let mut edges = BTreeMap::new();
    for edge_type in EDGE_TYPES {
        for edge in store.edges_by_type(snapshot_key, edge_type)? {
            edges.insert(edge.edge_key.clone(), edge);
        }
    }
    Ok(edges)
}

const NODE_LABELS: &[&str] = &[
    "Database",
    "Schema",
    "Table",
    "Column",
    "PrimaryKey",
    "ForeignKey",
    "UniqueConstraint",
    "CheckConstraint",
    "Index",
    "View",
    "Trigger",
    "Routine",
];

const EDGE_TYPES: &[&str] = &[
    "DATABASE_HAS_SCHEMA",
    "SCHEMA_HAS_TABLE",
    "TABLE_HAS_COLUMN",
    "TABLE_HAS_INDEX",
    "TABLE_HAS_TRIGGER",
    "TABLE_HAS_CONSTRAINT",
    "TABLE_HAS_VIEW",
    "COLUMN_IN_PRIMARY_KEY",
    "COLUMN_IN_UNIQUE",
    "COLUMN_IN_INDEX",
    "FK_FROM_COLUMN",
    "FK_TO_COLUMN",
    "VIEW_DEPENDS_ON_TABLE",
    "VIEW_DEPENDS_ON_COLUMN",
    "TRIGGER_ON_TABLE",
    "TRIGGER_EXECUTES_ROUTINE",
    "ROUTINE_DEPENDS_ON_TABLE",
    "ROUTINE_DEPENDS_ON_COLUMN",
];

#[cfg(test)]
mod schema_diff_tests {
    use super::*;
    use crate::graph_builder::insert_schema_snapshot_graph;
    use crate::{
        AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
        DatabaseObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
        TableObject,
    };

    const FROM: &str = "snapshot-from";
    const TO: &str = "snapshot-to";

    #[test]
    fn schema_diff_reports_added_table_and_column_nodes() {
        let store = store_with_snapshots(
            snapshot(false, false, "integer", false),
            snapshot(true, false, "integer", false),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();

        assert!(has_node(
            &diff.added_nodes,
            &key(ObjectKind::Table, "orders", None)
        ));
        assert!(has_node(
            &diff.added_nodes,
            &key(ObjectKind::Column, "orders", Some("id"))
        ));
        assert!(has_edge(
            &diff.added_edges,
            "SCHEMA_HAS_TABLE",
            &key(ObjectKind::Schema, "main", None),
            &key(ObjectKind::Table, "orders", None),
        ));
        assert!(diff.impacted.iter().any(|impact| {
            impact.seed_node_key == key(ObjectKind::Table, "orders", None).to_string()
        }));
    }

    #[test]
    fn schema_diff_reports_removed_column_nodes() {
        let store = store_with_snapshots(
            snapshot(false, true, "integer", false),
            snapshot(false, false, "integer", false),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();

        assert!(has_node(
            &diff.removed_nodes,
            &key(ObjectKind::Column, "users", Some("email"))
        ));
        assert!(has_edge(
            &diff.removed_edges,
            "TABLE_HAS_COLUMN",
            &key(ObjectKind::Table, "users", None),
            &key(ObjectKind::Column, "users", Some("email")),
        ));
        assert!(diff.impacted.iter().any(|impact| {
            impact.snapshot_key == FROM
                && impact.seed_node_key
                    == key(ObjectKind::Column, "users", Some("email")).to_string()
        }));
    }

    #[test]
    fn schema_diff_reports_changed_node_payload() {
        let store = store_with_snapshots(
            snapshot(false, false, "integer", false),
            snapshot(false, false, "bigint", false),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();

        assert_eq!(diff.changed_nodes.len(), 1);
        assert_eq!(
            diff.changed_nodes[0].to.node_key,
            key(ObjectKind::Column, "users", Some("id")).to_string()
        );
        assert_ne!(
            diff.changed_nodes[0].from.payload_json,
            diff.changed_nodes[0].to.payload_json
        );
    }

    #[test]
    fn schema_diff_reports_added_and_removed_fk_edges() {
        let store = store_with_snapshots(
            snapshot(true, false, "integer", false),
            snapshot(true, false, "integer", true),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();

        assert!(has_edge(
            &diff.added_edges,
            "FK_FROM_COLUMN",
            &key(ObjectKind::Column, "orders", Some("user_id")),
            &key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
        ));
        assert!(has_edge(
            &diff.added_edges,
            "FK_TO_COLUMN",
            &key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
            &key(ObjectKind::Column, "users", Some("id")),
        ));

        let reverse = schema_diff(&store, TO, FROM).unwrap();
        assert!(has_edge(
            &reverse.removed_edges,
            "FK_TO_COLUMN",
            &key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
            &key(ObjectKind::Column, "users", Some("id")),
        ));
    }

    fn store_with_snapshots(from: SchemaSnapshot, to: SchemaSnapshot) -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, FROM, 0, &from).unwrap();
        insert_schema_snapshot_graph(&store, TO, 1, &to).unwrap();
        store
    }

    fn snapshot(
        include_orders: bool,
        include_user_email: bool,
        user_id_type: &str,
        include_fk: bool,
    ) -> SchemaSnapshot {
        let database = key(ObjectKind::Database, "main", None);
        let schema = key(ObjectKind::Schema, "main", None);
        let users = key(ObjectKind::Table, "users", None);
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let users_email = key(ObjectKind::Column, "users", Some("email"));
        let orders = key(ObjectKind::Table, "orders", None);
        let orders_id = key(ObjectKind::Column, "orders", Some("id"));
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));

        let mut tables = vec![TableObject {
            key: users.clone(),
            schema_key: schema.clone(),
            name: "users".to_owned(),
            kind: TableKind::BaseTable,
        }];
        let mut columns = vec![column(
            users_id.clone(),
            users.clone(),
            "id",
            1,
            user_id_type,
        )];
        let mut constraints = Vec::new();

        if include_user_email {
            columns.push(column(users_email, users.clone(), "email", 2, "text"));
        }

        if include_orders {
            tables.push(TableObject {
                key: orders.clone(),
                schema_key: schema.clone(),
                name: "orders".to_owned(),
                kind: TableKind::BaseTable,
            });
            columns.push(column(orders_id, orders.clone(), "id", 1, "integer"));
            columns.push(column(
                orders_user_id.clone(),
                orders.clone(),
                "user_id",
                2,
                "integer",
            ));
        }

        if include_fk {
            constraints.push(ConstraintObject {
                key: key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
                table_key: orders,
                name: "fk_orders_user".to_owned(),
                kind: ConstraintKind::ForeignKey,
                columns: vec![orders_user_id],
                referenced_table_key: Some(users.clone()),
                referenced_columns: vec![users_id],
                expression: None,
            });
        }

        SchemaSnapshot {
            source_kind: "sqlite".to_owned(),
            connection_alias: "app-db".to_owned(),
            database: DatabaseObject {
                key: database.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: schema,
                database_key: database,
                name: "main".to_owned(),
            }],
            tables,
            columns,
            constraints,
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
                views: CapabilitySupport::Unsupported,
                triggers: CapabilitySupport::Unsupported,
                routines: CapabilitySupport::Unsupported,
                dependencies: CapabilitySupport::Unsupported,
                notes: vec![],
            },
        }
    }

    fn column(
        key: ObjectKey,
        table_key: ObjectKey,
        name: &str,
        ordinal_position: u32,
        data_type: &str,
    ) -> ColumnObject {
        ColumnObject {
            key,
            table_key,
            name: name.to_owned(),
            ordinal_position,
            data_type: data_type.to_owned(),
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

    fn has_node(nodes: &[GraphNodeRecord], key: &ObjectKey) -> bool {
        nodes.iter().any(|node| node.node_key == key.to_string())
    }

    fn has_edge(
        edges: &[GraphEdgeRecord],
        edge_type: &str,
        from: &ObjectKey,
        to: &ObjectKey,
    ) -> bool {
        let from = from.to_string();
        let to = to.to_string();
        edges
            .iter()
            .any(|edge| edge.edge_type == edge_type && edge.edge_from == from && edge.edge_to == to)
    }
}
