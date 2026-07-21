use std::collections::{BTreeMap, BTreeSet};

use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphStore, GraphStoreResult};
use crate::impact_analysis::{impact_analysis_bounded, Direction, ImpactAnalysisResult};
use crate::ObjectKey;
use serde_json::Value;

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
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDiffCounts {
    pub added_nodes: usize,
    pub removed_nodes: usize,
    pub changed_nodes: usize,
    pub added_edges: usize,
    pub removed_edges: usize,
    pub impacted_seeds: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedSchemaDiff {
    pub diff: SchemaDiff,
    pub counts: SchemaDiffCounts,
    pub result_limit: usize,
    pub truncated: bool,
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
    Ok(build_schema_diff(
        store,
        from_snapshot_key,
        to_snapshot_key,
        impact_max_depth,
        usize::MAX,
    )?
    .diff)
}

pub fn schema_diff_bounded(
    store: &GraphStore,
    from_snapshot_key: &str,
    to_snapshot_key: &str,
    result_limit: usize,
) -> GraphStoreResult<BoundedSchemaDiff> {
    build_schema_diff(
        store,
        from_snapshot_key,
        to_snapshot_key,
        DEFAULT_SCHEMA_DIFF_IMPACT_MAX_DEPTH,
        result_limit,
    )
}

fn build_schema_diff(
    store: &GraphStore,
    from_snapshot_key: &str,
    to_snapshot_key: &str,
    impact_max_depth: u32,
    result_limit: usize,
) -> GraphStoreResult<BoundedSchemaDiff> {
    let from_nodes = snapshot_nodes(store, from_snapshot_key)?;
    let to_nodes = snapshot_nodes(store, to_snapshot_key)?;
    let from_edges = snapshot_edges(store, from_snapshot_key)?;
    let to_edges = snapshot_edges(store, to_snapshot_key)?;

    let mut added_nodes = to_nodes
        .iter()
        .filter(|(node_key, _)| !from_nodes.contains_key(*node_key))
        .map(|(_, node)| node.clone())
        .collect::<Vec<_>>();
    let mut removed_nodes = from_nodes
        .iter()
        .filter(|(node_key, _)| !to_nodes.contains_key(*node_key))
        .map(|(_, node)| node.clone())
        .collect::<Vec<_>>();
    let mut changed_nodes = Vec::new();
    for (node_key, to) in &to_nodes {
        let Some(from) = from_nodes.get(node_key) else {
            continue;
        };
        if from.label != to.label
            || from.display_name != to.display_name
            || comparable_payload(&from.payload_json)? != comparable_payload(&to.payload_json)?
        {
            changed_nodes.push(ChangedGraphNode {
                from: from.clone(),
                to: to.clone(),
            });
        }
    }

    let mut added_edges = to_edges
        .iter()
        .filter(|(edge_key, _)| !from_edges.contains_key(*edge_key))
        .map(|(_, edge)| edge.clone())
        .collect::<Vec<_>>();
    let mut removed_edges = from_edges
        .iter()
        .filter(|(edge_key, _)| !to_edges.contains_key(*edge_key))
        .map(|(_, edge)| edge.clone())
        .collect::<Vec<_>>();

    let seeds = changed_impact_seeds(
        from_snapshot_key,
        to_snapshot_key,
        &added_nodes,
        &removed_nodes,
        &changed_nodes,
    );
    let counts = SchemaDiffCounts {
        added_nodes: added_nodes.len(),
        removed_nodes: removed_nodes.len(),
        changed_nodes: changed_nodes.len(),
        added_edges: added_edges.len(),
        removed_edges: removed_edges.len(),
        impacted_seeds: seeds.len(),
    };
    let (impacted, impact_truncated) =
        changed_impacts(store, impact_max_depth, seeds, result_limit)?;
    let truncated = impact_truncated
        || added_nodes.len() > result_limit
        || removed_nodes.len() > result_limit
        || changed_nodes.len() > result_limit
        || added_edges.len() > result_limit
        || removed_edges.len() > result_limit;
    added_nodes.truncate(result_limit);
    removed_nodes.truncate(result_limit);
    changed_nodes.truncate(result_limit);
    added_edges.truncate(result_limit);
    removed_edges.truncate(result_limit);

    Ok(BoundedSchemaDiff {
        diff: SchemaDiff {
            from_snapshot_key: from_snapshot_key.to_owned(),
            to_snapshot_key: to_snapshot_key.to_owned(),
            added_nodes,
            removed_nodes,
            changed_nodes,
            added_edges,
            removed_edges,
            impacted,
        },
        counts,
        result_limit,
        truncated,
    })
}

fn changed_impact_seeds(
    from_snapshot_key: &str,
    to_snapshot_key: &str,
    added_nodes: &[GraphNodeRecord],
    removed_nodes: &[GraphNodeRecord],
    changed_nodes: &[ChangedGraphNode],
) -> BTreeSet<(String, String)> {
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
}

fn changed_impacts(
    store: &GraphStore,
    impact_max_depth: u32,
    seeds: BTreeSet<(String, String)>,
    result_limit: usize,
) -> GraphStoreResult<(Vec<SchemaDiffImpact>, bool)> {
    let mut remaining_results = result_limit;
    let mut truncated = seeds.len() > result_limit;
    let mut impacts = Vec::new();

    for (snapshot_key, seed_node_key) in seeds.into_iter().take(result_limit) {
        let bounded = impact_analysis_bounded(
            store,
            &snapshot_key,
            &seed_node_key,
            Direction::Both,
            impact_max_depth,
            remaining_results,
        )?;
        let result_count = bounded
            .result
            .groups
            .iter()
            .map(|group| group.nodes.len())
            .sum::<usize>();
        if remaining_results != usize::MAX {
            remaining_results = remaining_results.saturating_sub(result_count);
        }
        truncated |= bounded.truncated;
        impacts.push(SchemaDiffImpact {
            seed_node_key,
            snapshot_key,
            impact: bounded.result,
            truncated: bounded.truncated,
        });
    }

    Ok((impacts, truncated))
}

fn snapshot_nodes(
    store: &GraphStore,
    snapshot_key: &str,
) -> GraphStoreResult<BTreeMap<String, GraphNodeRecord>> {
    let mut nodes = BTreeMap::new();
    for node in store.nodes_for_snapshot(snapshot_key)? {
        nodes.insert(comparable_object_key(&node.node_key), node);
    }
    Ok(nodes)
}

fn snapshot_edges(
    store: &GraphStore,
    snapshot_key: &str,
) -> GraphStoreResult<BTreeMap<String, GraphEdgeRecord>> {
    let mut edges = BTreeMap::new();
    for edge in store.edges_for_snapshot(snapshot_key)? {
        edges.insert(comparable_edge_key(&edge), edge);
    }
    Ok(edges)
}

fn comparable_object_key(raw_key: &str) -> String {
    let Ok(mut key) = raw_key.parse::<ObjectKey>() else {
        return raw_key.to_owned();
    };
    key.connection_alias = "_".to_owned();
    key.to_string()
}

fn comparable_edge_key(edge: &GraphEdgeRecord) -> String {
    format!(
        "{}:{}->{}",
        edge.edge_type,
        comparable_object_key(&edge.edge_from),
        comparable_object_key(&edge.edge_to)
    )
}

fn comparable_payload(payload_json: &str) -> GraphStoreResult<Value> {
    let mut payload = serde_json::from_str(payload_json)?;
    remove_connection_aliases(&mut payload);
    Ok(payload)
}

fn remove_connection_aliases(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("connection_alias");
            for value in fields.values_mut() {
                remove_connection_aliases(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_connection_aliases(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod schema_diff_tests {
    use super::*;
    use crate::graph_builder::insert_schema_snapshot_graph;
    use crate::{
        AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
        DatabaseObject, ObjectKey, ObjectKind, RoutineKind, RoutineObject, SchemaObject,
        SchemaSnapshot, TableKind, TableObject, TriggerObject, ViewObject,
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
    fn bounded_schema_diff_caps_changes_seeds_and_total_impact_nodes() {
        let store = store_with_snapshots(
            snapshot(false, false, "integer", false),
            snapshot(true, true, "bigint", true),
        );

        let bounded = schema_diff_bounded(&store, FROM, TO, 1).unwrap();
        let impact_nodes = bounded
            .diff
            .impacted
            .iter()
            .flat_map(|impact| &impact.impact.groups)
            .map(|group| group.nodes.len())
            .sum::<usize>();

        assert!(bounded.truncated);
        assert_eq!(bounded.result_limit, 1);
        assert!(bounded.counts.added_nodes > bounded.diff.added_nodes.len());
        assert!(bounded.counts.added_edges > bounded.diff.added_edges.len());
        assert!(bounded.counts.impacted_seeds > bounded.diff.impacted.len());
        assert!(bounded.diff.changed_nodes.len() <= 1);
        assert!(bounded.diff.added_nodes.len() <= 1);
        assert!(bounded.diff.added_edges.len() <= 1);
        assert!(bounded.diff.impacted.len() <= 1);
        assert!(impact_nodes <= 1);
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

    #[test]
    fn schema_diff_includes_every_view_routine_and_trigger_relationship() {
        let store = store_with_snapshots(
            snapshot_with_dependency_objects(false),
            snapshot_with_dependency_objects(true),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();
        let schema = key(ObjectKind::Schema, "main", None);
        let users = key(ObjectKind::Table, "users", None);
        let base_view = key(ObjectKind::View, "active_users", None);
        let nested_view = key(ObjectKind::View, "active_user_ids", None);
        let routine = key(ObjectKind::Routine, "refresh_users", None);
        let trigger = key(
            ObjectKind::Trigger,
            "active_users",
            Some("refresh_active_users"),
        );

        assert!(has_edge(
            &diff.added_edges,
            "SCHEMA_HAS_VIEW",
            &schema,
            &base_view,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "SCHEMA_HAS_ROUTINE",
            &schema,
            &routine,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "VIEW_DEPENDS_ON_TABLE",
            &base_view,
            &users,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "VIEW_DEPENDS_ON_VIEW",
            &nested_view,
            &base_view,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "VIEW_HAS_TRIGGER",
            &base_view,
            &trigger,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "TRIGGER_ON_VIEW",
            &trigger,
            &base_view,
        ));
        assert!(has_edge(
            &diff.added_edges,
            "TRIGGER_EXECUTES_ROUTINE",
            &trigger,
            &routine,
        ));
    }

    #[test]
    fn schema_diff_ignores_connection_alias_only_changes() {
        let store = store_with_snapshots(
            snapshot_with_alias("before", true, true, "integer", true),
            snapshot_with_alias("after", true, true, "integer", true),
        );

        let diff = schema_diff(&store, FROM, TO).unwrap();

        assert!(diff.added_nodes.is_empty());
        assert!(diff.removed_nodes.is_empty());
        assert!(diff.changed_nodes.is_empty());
        assert!(diff.added_edges.is_empty());
        assert!(diff.removed_edges.is_empty());
        assert!(diff.impacted.is_empty());
    }

    #[test]
    fn comparable_keys_do_not_collapse_reserved_identifier_boundaries() {
        let table_with_delimiter = ObjectKey::new(
            "postgres",
            "before",
            "app",
            "public",
            ObjectKind::Table,
            "orders:archive",
            None,
        );
        let sub_object = ObjectKey::new(
            "postgres",
            "after",
            "app",
            "public",
            ObjectKind::Table,
            "orders",
            Some("archive".to_owned()),
        );

        assert_ne!(
            comparable_object_key(&table_with_delimiter.to_string()),
            comparable_object_key(&sub_object.to_string())
        );
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
        snapshot_with_alias(
            "app-db",
            include_orders,
            include_user_email,
            user_id_type,
            include_fk,
        )
    }

    fn snapshot_with_alias(
        alias: &str,
        include_orders: bool,
        include_user_email: bool,
        user_id_type: &str,
        include_fk: bool,
    ) -> SchemaSnapshot {
        let database = key_for(alias, ObjectKind::Database, "main", None);
        let schema = key_for(alias, ObjectKind::Schema, "main", None);
        let users = key_for(alias, ObjectKind::Table, "users", None);
        let users_id = key_for(alias, ObjectKind::Column, "users", Some("id"));
        let users_email = key_for(alias, ObjectKind::Column, "users", Some("email"));
        let orders = key_for(alias, ObjectKind::Table, "orders", None);
        let orders_id = key_for(alias, ObjectKind::Column, "orders", Some("id"));
        let orders_user_id = key_for(alias, ObjectKind::Column, "orders", Some("user_id"));

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
                key: key_for(
                    alias,
                    ObjectKind::ForeignKey,
                    "orders",
                    Some("fk_orders_user"),
                ),
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
            connection_alias: alias.to_owned(),
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
                limitations: vec![],
                notes: vec![],
            },
        }
    }

    fn snapshot_with_dependency_objects(include: bool) -> SchemaSnapshot {
        let mut snapshot = snapshot(false, false, "integer", false);
        if !include {
            return snapshot;
        }

        let schema = key(ObjectKind::Schema, "main", None);
        let users = key(ObjectKind::Table, "users", None);
        let base_view = key(ObjectKind::View, "active_users", None);
        let nested_view = key(ObjectKind::View, "active_user_ids", None);
        let routine = key(ObjectKind::Routine, "refresh_users", None);
        snapshot.views = vec![
            ViewObject {
                key: base_view.clone(),
                schema_key: schema.clone(),
                name: "active_users".to_owned(),
                definition: None,
                depends_on: vec![users.clone()],
            },
            ViewObject {
                key: nested_view,
                schema_key: schema.clone(),
                name: "active_user_ids".to_owned(),
                definition: None,
                depends_on: vec![base_view.clone()],
            },
        ];
        snapshot.routines = vec![RoutineObject {
            key: routine.clone(),
            schema_key: schema,
            name: "refresh_users".to_owned(),
            kind: RoutineKind::Function,
            definition: None,
            depends_on: vec![users],
        }];
        snapshot.triggers = vec![TriggerObject {
            key: key(
                ObjectKind::Trigger,
                "active_users",
                Some("refresh_active_users"),
            ),
            table_key: base_view,
            name: "refresh_active_users".to_owned(),
            timing: Some("AFTER".to_owned()),
            events: vec!["UPDATE".to_owned()],
            definition: None,
            executes_routine_key: Some(routine),
        }];
        snapshot.capabilities.views = CapabilitySupport::Supported;
        snapshot.capabilities.triggers = CapabilitySupport::Supported;
        snapshot.capabilities.routines = CapabilitySupport::Supported;
        snapshot.capabilities.dependencies = CapabilitySupport::Supported;
        snapshot
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
        key_for("app-db", kind, object_name, sub_object)
    }

    fn key_for(
        alias: &str,
        kind: ObjectKind,
        object_name: &str,
        sub_object: Option<&str>,
    ) -> ObjectKey {
        ObjectKey::new(
            "sqlite",
            alias,
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
