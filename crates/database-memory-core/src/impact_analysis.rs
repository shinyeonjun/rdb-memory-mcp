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
    pub edge_from: String,
    pub edge_to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedImpactAnalysisResult {
    pub result: ImpactAnalysisResult,
    pub truncated: bool,
}

pub fn impact_analysis(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: &str,
    direction: Direction,
    max_depth: u32,
) -> GraphStoreResult<ImpactAnalysisResult> {
    Ok(impact_analysis_bounded(
        store,
        snapshot_key,
        object_key,
        direction,
        max_depth,
        usize::MAX,
    )?
    .result)
}

pub fn impact_analysis_bounded(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: &str,
    direction: Direction,
    max_depth: u32,
    max_results: usize,
) -> GraphStoreResult<BoundedImpactAnalysisResult> {
    let mut visited = HashSet::from([object_key.to_owned()]);
    let mut queue = VecDeque::from([(object_key.to_owned(), 0)]);
    let mut nodes = Vec::new();
    let mut truncated = false;
    let mut remaining_budget = max_results;

    if store.get_node(snapshot_key, object_key)?.is_none() {
        return Ok(BoundedImpactAnalysisResult {
            result: result(snapshot_key, object_key, direction, max_depth, nodes),
            truncated,
        });
    }

    'traversal: while let Some((node_key, depth)) = queue.pop_front() {
        if depth == max_depth {
            continue;
        }

        let (edges, has_more_edges) =
            next_edges_bounded(store, snapshot_key, &node_key, direction, remaining_budget)?;
        if max_results != usize::MAX {
            remaining_budget -= edges.len();
        }
        truncated |= has_more_edges;

        for (edge, next_key) in edges {
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
                    edge_from: edge.edge_from,
                    edge_to: edge.edge_to,
                });
            }
        }

        if has_more_edges {
            break 'traversal;
        }
    }

    Ok(BoundedImpactAnalysisResult {
        result: result(snapshot_key, object_key, direction, max_depth, nodes),
        truncated,
    })
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

pub(crate) fn next_edges_bounded(
    store: &GraphStore,
    snapshot_key: &str,
    node_key: &str,
    direction: Direction,
    max_edges: usize,
) -> GraphStoreResult<(Vec<(GraphEdgeRecord, String)>, bool)> {
    if max_edges == usize::MAX {
        return Ok((next_edges(store, snapshot_key, node_key, direction)?, false));
    }

    let mut edges = Vec::new();
    if matches!(direction, Direction::Outbound | Direction::Both) {
        let mut outbound =
            store.edges_from_limited(snapshot_key, node_key, max_edges.saturating_add(1))?;
        if outbound.len() > max_edges {
            outbound.truncate(max_edges);
            edges.extend(outbound.into_iter().map(|edge| {
                let next = edge.edge_to.clone();
                (edge, next)
            }));
            return Ok((edges, true));
        }
        edges.extend(outbound.into_iter().map(|edge| {
            let next = edge.edge_to.clone();
            (edge, next)
        }));
    }

    if matches!(direction, Direction::Inbound | Direction::Both) {
        let remaining = max_edges - edges.len();
        let mut inbound =
            store.edges_to_limited(snapshot_key, node_key, remaining.saturating_add(1))?;
        let has_more = inbound.len() > remaining;
        inbound.truncate(remaining);
        edges.extend(inbound.into_iter().map(|edge| {
            let next = edge.edge_from.clone();
            (edge, next)
        }));
        return Ok((edges, has_more));
    }

    Ok((edges, false))
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

    #[test]
    fn bounded_impact_analysis_stops_and_reports_truncation() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Column");
        node(&store, "C", "Index");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "A_TO_C", "A", "C", "A_TO_C");

        let bounded =
            impact_analysis_bounded(&store, SNAPSHOT, "A", Direction::Outbound, 2, 1).unwrap();

        assert!(bounded.truncated);
        assert_eq!(reached_keys(&bounded.result), vec!["B".to_owned()]);
    }

    #[test]
    fn impact_analysis_preserves_stored_endpoints_for_every_direction() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Table");
        node(&store, "C", "Table");
        edge(&store, "B_TO_A", "B", "A", "INBOUND_EDGE");
        edge(&store, "A_TO_C", "A", "C", "OUTBOUND_EDGE");

        let inbound = impact_analysis(&store, SNAPSHOT, "A", Direction::Inbound, 1).unwrap();
        assert_endpoints(&inbound, "B", "B", "A");

        let outbound = impact_analysis(&store, SNAPSHOT, "A", Direction::Outbound, 1).unwrap();
        assert_endpoints(&outbound, "C", "A", "C");

        let both = impact_analysis(&store, SNAPSHOT, "A", Direction::Both, 1).unwrap();
        assert_endpoints(&both, "B", "B", "A");
        assert_endpoints(&both, "C", "A", "C");
    }

    #[test]
    fn bounded_edge_fetch_caps_high_degree_work_at_limit_plus_one() {
        let store = empty_store();
        node(&store, "A", "Table");
        for index in 0..512 {
            let next = format!("N{index:03}");
            node(&store, &next, "Column");
            edge(&store, &format!("EDGE_{index:03}"), "A", &next, "A_TO_N");
        }

        let (edges, has_more) =
            next_edges_bounded(&store, SNAPSHOT, "A", Direction::Outbound, 2).unwrap();
        assert!(has_more);
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].1, "N000");
        assert_eq!(edges[1].1, "N001");

        let bounded =
            impact_analysis_bounded(&store, SNAPSHOT, "A", Direction::Outbound, 1, 2).unwrap();
        assert!(bounded.truncated);
        assert_eq!(reached_keys(&bounded.result), vec!["N000", "N001"]);
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

    fn assert_endpoints(
        result: &ImpactAnalysisResult,
        node_key: &str,
        edge_from: &str,
        edge_to: &str,
    ) {
        let node = result
            .groups
            .iter()
            .flat_map(|group| &group.nodes)
            .find(|node| node.node_key == node_key)
            .unwrap();
        assert_eq!(node.edge_from, edge_from);
        assert_eq!(node.edge_to, edge_to);
    }
}
