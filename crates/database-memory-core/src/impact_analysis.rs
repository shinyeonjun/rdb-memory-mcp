use std::collections::{BTreeMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::graph_store::{GraphEdgeRecord, GraphStore, GraphStoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactAnalysisResult {
    pub snapshot_key: String,
    pub object_key: String,
    pub direction: Direction,
    pub max_depth: u32,
    pub groups: Vec<ImpactAnalysisGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactAnalysisGroup {
    pub label: String,
    pub depth: u32,
    pub nodes: Vec<ImpactAnalysisNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactAnalysisNode {
    pub node_key: String,
    pub label: String,
    pub display_name: Option<String>,
    pub depth: u32,
    pub edge_type_used: String,
}

pub fn impact_analysis(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: &str,
    direction: Direction,
    max_depth: u32,
) -> GraphStoreResult<ImpactAnalysisResult> {
    let mut visited = HashSet::from([object_key.to_owned()]);
    let mut queue = VecDeque::from([(object_key.to_owned(), 0)]);
    let mut nodes = Vec::new();

    if store.get_node(snapshot_key, object_key)?.is_none() {
        return Ok(result(
            snapshot_key,
            object_key,
            direction,
            max_depth,
            nodes,
        ));
    }

    while let Some((node_key, depth)) = queue.pop_front() {
        if depth == max_depth {
            continue;
        }

        for (edge, next_key) in next_edges(store, snapshot_key, &node_key, direction)? {
            if !visited.insert(next_key.clone()) {
                continue;
            }

            if let Some(node) = store.get_node(snapshot_key, &next_key)? {
                let next_depth = depth + 1;
                queue.push_back((next_key.clone(), next_depth));
                nodes.push(ImpactAnalysisNode {
                    node_key: next_key,
                    label: node.label,
                    display_name: node.display_name,
                    depth: next_depth,
                    edge_type_used: edge.edge_type,
                });
            }
        }
    }

    Ok(result(
        snapshot_key,
        object_key,
        direction,
        max_depth,
        nodes,
    ))
}

pub(crate) fn next_edges(
    store: &GraphStore,
    snapshot_key: &str,
    node_key: &str,
    direction: Direction,
) -> GraphStoreResult<Vec<(GraphEdgeRecord, String)>> {
    let mut edges = Vec::new();

    if matches!(direction, Direction::Outbound | Direction::Both) {
        edges.extend(
            store
                .edges_from(snapshot_key, node_key)?
                .into_iter()
                .map(|edge| {
                    let next = edge.edge_to.clone();
                    (edge, next)
                }),
        );
    }
    if matches!(direction, Direction::Inbound | Direction::Both) {
        edges.extend(
            store
                .edges_to(snapshot_key, node_key)?
                .into_iter()
                .map(|edge| {
                    let next = edge.edge_from.clone();
                    (edge, next)
                }),
        );
    }

    Ok(edges)
}

fn result(
    snapshot_key: &str,
    object_key: &str,
    direction: Direction,
    max_depth: u32,
    nodes: Vec<ImpactAnalysisNode>,
) -> ImpactAnalysisResult {
    let mut grouped = BTreeMap::<(String, u32), Vec<ImpactAnalysisNode>>::new();
    for node in nodes {
        grouped
            .entry((node.label.clone(), node.depth))
            .or_default()
            .push(node);
    }

    ImpactAnalysisResult {
        snapshot_key: snapshot_key.to_owned(),
        object_key: object_key.to_owned(),
        direction,
        max_depth,
        groups: grouped
            .into_iter()
            .map(|((label, depth), mut nodes)| {
                nodes.sort_by(|left, right| left.node_key.cmp(&right.node_key));
                ImpactAnalysisGroup {
                    label,
                    depth,
                    nodes,
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod impact_analysis_tests {
    use super::*;
    use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphSnapshotRecord};

    const SNAPSHOT: &str = "snapshot-1";

    #[test]
    fn impact_analysis_fk_chain_reaches_related_tables_and_columns() {
        let store = seeded_store();
        let users = key("table", "users");
        let result = impact_analysis(&store, SNAPSHOT, &users, Direction::Both, 3).unwrap();
        let reached = reached_keys(&result);

        assert!(reached.contains(&key("column", "users:id")));
        assert!(reached.contains(&key("foreign_key", "orders:fk_orders_user")));
        assert!(reached.contains(&key("column", "orders:user_id")));
        assert!(reached.contains(&key("table", "orders")));
        assert_eq!(depth_of(&result, &key("table", "orders")), Some(3));
    }

    #[test]
    fn impact_analysis_cycle_safe_no_duplicate_visits() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Table");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "B_TO_A", "B", "A", "B_TO_A");

        let result = impact_analysis(&store, SNAPSHOT, "A", Direction::Outbound, 10).unwrap();
        let reached = reached_keys(&result);

        assert_eq!(reached, vec!["B".to_owned()]);
    }

    #[test]
    fn impact_analysis_max_depth_excludes_farther_nodes() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Column");
        node(&store, "C", "Index");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "B_TO_C", "B", "C", "B_TO_C");

        let result = impact_analysis(&store, SNAPSHOT, "A", Direction::Outbound, 1).unwrap();
        let reached = reached_keys(&result);

        assert_eq!(reached, vec!["B".to_owned()]);
    }

    fn seeded_store() -> GraphStore {
        let store = empty_store();
        let users = key("table", "users");
        let users_id = key("column", "users:id");
        let orders = key("table", "orders");
        let orders_user_id = key("column", "orders:user_id");
        let fk = key("foreign_key", "orders:fk_orders_user");

        node(&store, &users, "Table");
        node(&store, &users_id, "Column");
        node(&store, &orders, "Table");
        node(&store, &orders_user_id, "Column");
        node(&store, &fk, "ForeignKey");

        edge(&store, "users_id", &users, &users_id, "TABLE_HAS_COLUMN");
        edge(
            &store,
            "orders_user_id",
            &orders,
            &orders_user_id,
            "TABLE_HAS_COLUMN",
        );
        edge(&store, "orders_fk", &orders, &fk, "TABLE_HAS_CONSTRAINT");
        edge(
            &store,
            "fk_from_orders_user",
            &orders_user_id,
            &fk,
            "FK_FROM_COLUMN",
        );
        edge(&store, "fk_to_users_id", &fk, &users_id, "FK_TO_COLUMN");

        store
    }

    fn empty_store() -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        store
            .insert_snapshot(&GraphSnapshotRecord {
                snapshot_key: SNAPSHOT.to_owned(),
                source: None,
                captured_at_unix_ms: 0,
                payload_json: "{}".to_owned(),
            })
            .unwrap();
        store
    }

    fn node(store: &GraphStore, node_key: &str, label: &str) {
        store
            .insert_node(&GraphNodeRecord {
                snapshot_key: SNAPSHOT.to_owned(),
                node_key: node_key.to_owned(),
                label: label.to_owned(),
                display_name: Some(node_key.to_owned()),
                payload_json: "{}".to_owned(),
            })
            .unwrap();
    }

    fn edge(store: &GraphStore, edge_key: &str, edge_from: &str, edge_to: &str, edge_type: &str) {
        store
            .insert_edge(&GraphEdgeRecord {
                snapshot_key: SNAPSHOT.to_owned(),
                edge_key: edge_key.to_owned(),
                edge_from: edge_from.to_owned(),
                edge_to: edge_to.to_owned(),
                edge_type: edge_type.to_owned(),
                payload_json: "{}".to_owned(),
            })
            .unwrap();
    }

    fn key(kind: &str, name: &str) -> String {
        format!("sqlite:sample:main:main:{kind}:{name}")
    }

    fn reached_keys(result: &ImpactAnalysisResult) -> Vec<String> {
        let mut keys = result
            .groups
            .iter()
            .flat_map(|group| group.nodes.iter().map(|node| node.node_key.clone()))
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    fn depth_of(result: &ImpactAnalysisResult, node_key: &str) -> Option<u32> {
        result
            .groups
            .iter()
            .flat_map(|group| group.nodes.iter())
            .find(|node| node.node_key == node_key)
            .map(|node| node.depth)
    }
}
