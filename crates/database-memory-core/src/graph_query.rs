use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphStore, GraphStoreResult};
use crate::impact_analysis::{merge_bounded_edges, next_edges_bounded, Direction};

pub const GRAPH_QUERY_MAX_LIMIT: usize = 500;
pub const GRAPH_QUERY_MAX_DEPTH: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQuery {
    pub snapshot_key: String,
    pub node_label: Option<String>,
    pub node_key_contains: Option<String>,
    pub name_contains: Option<String>,
    pub edge_type: Option<String>,
    pub payload_array_min_len: Option<PayloadArrayMinLen>,
    pub traversal: Option<GraphQueryTraversal>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadArrayMinLen {
    pub field: String,
    pub min_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQueryTraversal {
    pub start_node_key: String,
    pub direction: Direction,
    pub max_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphQueryResult {
    pub snapshot_key: String,
    pub limit_requested: usize,
    pub limit_applied: usize,
    pub limit_clamped: bool,
    pub max_depth_requested: Option<u32>,
    pub max_depth_applied: Option<u32>,
    pub max_depth_clamped: bool,
    pub result_count: usize,
    pub truncated: bool,
    pub nodes: Vec<GraphQueryNode>,
    pub edges: Vec<GraphQueryEdge>,
    pub traversal: Vec<GraphQueryTraversalHit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphQueryNode {
    pub node_key: String,
    pub label: String,
    pub display_name: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphQueryEdge {
    pub edge_key: String,
    pub edge_from: String,
    pub edge_to: String,
    pub edge_type: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphQueryTraversalHit {
    pub node_key: String,
    pub label: String,
    pub display_name: Option<String>,
    pub depth: u32,
    pub edge_key: String,
    pub edge_type: String,
}

pub fn query_graph(store: &GraphStore, query: &GraphQuery) -> GraphStoreResult<GraphQueryResult> {
    let limit_applied = query.limit.min(GRAPH_QUERY_MAX_LIMIT);
    let mut remaining = limit_applied;
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut traversal = Vec::new();
    let mut truncated = false;

    if wants_nodes(query) {
        let matches = matching_nodes(store, query)?;
        truncated |= matches.len() > remaining;
        nodes.extend(matches.into_iter().take(remaining).map(query_node));
        remaining -= nodes.len();
    }

    if query.traversal.is_none() {
        if let Some(edge_type) = &query.edge_type {
            let mut matches = store.edges_by_type_limited(
                &query.snapshot_key,
                edge_type,
                remaining.saturating_add(1),
            )?;
            truncated |= matches.len() > remaining;
            matches.truncate(remaining);
            edges.extend(matches.into_iter().map(query_edge));
            remaining -= edges.len();
        }
    }

    let max_depth_requested = query
        .traversal
        .as_ref()
        .map(|traversal| traversal.max_depth);
    let max_depth_applied = query
        .traversal
        .as_ref()
        .map(|traversal| traversal.max_depth.min(GRAPH_QUERY_MAX_DEPTH));
    if let Some(traversal_query) = &query.traversal {
        let bounded = bounded_traversal(
            store,
            query,
            traversal_query,
            max_depth_applied.unwrap_or(0),
            remaining,
        )?;
        traversal = bounded.hits;
        truncated |= bounded.truncated;
    }
    let result_count = nodes.len() + edges.len() + traversal.len();

    Ok(GraphQueryResult {
        snapshot_key: query.snapshot_key.clone(),
        limit_requested: query.limit,
        limit_applied,
        limit_clamped: query.limit != limit_applied,
        max_depth_requested,
        max_depth_applied,
        max_depth_clamped: max_depth_requested != max_depth_applied,
        result_count,
        truncated,
        nodes,
        edges,
        traversal,
    })
}

fn wants_nodes(query: &GraphQuery) -> bool {
    query.node_label.is_some()
        || query.node_key_contains.is_some()
        || query.name_contains.is_some()
        || query.payload_array_min_len.is_some()
        || (query.edge_type.is_none() && query.traversal.is_none())
}

fn matching_nodes(
    store: &GraphStore,
    query: &GraphQuery,
) -> GraphStoreResult<Vec<GraphNodeRecord>> {
    let nodes = if let Some(label) = &query.node_label {
        store.nodes_by_label(&query.snapshot_key, label)?
    } else {
        store.nodes_for_snapshot(&query.snapshot_key)?
    };
    Ok(nodes
        .into_iter()
        .filter(|node| node_matches(node, query))
        .collect())
}

fn node_matches(node: &GraphNodeRecord, query: &GraphQuery) -> bool {
    query
        .node_key_contains
        .as_ref()
        .map(|needle| contains_ignore_case(&node.node_key, needle))
        .unwrap_or(true)
        && query
            .name_contains
            .as_ref()
            .map(|needle| {
                node.display_name
                    .as_ref()
                    .map(|name| contains_ignore_case(name, needle))
                    .unwrap_or(false)
            })
            .unwrap_or(true)
        && query
            .payload_array_min_len
            .as_ref()
            .map(|filter| payload_array_len_at_least(&node.payload_json, filter))
            .unwrap_or(true)
}

struct BoundedTraversal {
    hits: Vec<GraphQueryTraversalHit>,
    truncated: bool,
}

fn bounded_traversal(
    store: &GraphStore,
    query: &GraphQuery,
    traversal: &GraphQueryTraversal,
    max_depth: u32,
    limit: usize,
) -> GraphStoreResult<BoundedTraversal> {
    let mut hits = Vec::new();
    let mut truncated = false;
    if max_depth == 0
        || store
            .get_node(&query.snapshot_key, &traversal.start_node_key)?
            .is_none()
    {
        return Ok(BoundedTraversal { hits, truncated });
    }

    let mut visited = HashSet::from([traversal.start_node_key.clone()]);
    let mut queue = VecDeque::from([(traversal.start_node_key.clone(), 0)]);
    while let Some((node_key, depth)) = queue.pop_front() {
        if depth == max_depth {
            continue;
        }
        if hits.len() == limit {
            truncated = true;
            break;
        }

        let (edges, has_more_edges) = next_query_edges_bounded(
            store,
            &query.snapshot_key,
            &node_key,
            traversal.direction,
            query.edge_type.as_deref(),
            limit - hits.len(),
        )?;
        truncated |= has_more_edges;
        for (edge, next_key) in edges {
            if !visited.insert(next_key.clone()) {
                continue;
            }
            if let Some(node) = store.get_node(&query.snapshot_key, &next_key)? {
                let next_depth = depth + 1;
                hits.push(GraphQueryTraversalHit {
                    node_key: next_key.clone(),
                    label: node.label,
                    display_name: node.display_name,
                    depth: next_depth,
                    edge_key: edge.edge_key,
                    edge_type: edge.edge_type,
                });
                if next_depth < max_depth {
                    queue.push_back((next_key, next_depth));
                }
            }
        }
        if has_more_edges {
            break;
        }
    }
    Ok(BoundedTraversal { hits, truncated })
}

fn next_query_edges_bounded(
    store: &GraphStore,
    snapshot_key: &str,
    node_key: &str,
    direction: Direction,
    edge_type: Option<&str>,
    max_edges: usize,
) -> GraphStoreResult<(Vec<(GraphEdgeRecord, String)>, bool)> {
    let Some(edge_type) = edge_type else {
        return next_edges_bounded(store, snapshot_key, node_key, direction, max_edges);
    };

    let mut edges = Vec::new();
    let fetch_limit = max_edges.saturating_add(1);
    let mut source_truncated = false;
    if matches!(direction, Direction::Outbound | Direction::Both) {
        let outbound =
            store.edges_from_by_type_limited(snapshot_key, node_key, edge_type, fetch_limit)?;
        source_truncated |= outbound.len() > max_edges;
        edges.extend(outbound.into_iter().map(|edge| {
            let next = edge.edge_to.clone();
            (edge, next)
        }));
    }

    if matches!(direction, Direction::Inbound | Direction::Both) {
        let inbound =
            store.edges_to_by_type_limited(snapshot_key, node_key, edge_type, fetch_limit)?;
        source_truncated |= inbound.len() > max_edges;
        edges.extend(inbound.into_iter().map(|edge| {
            let next = edge.edge_from.clone();
            (edge, next)
        }));
    }

    Ok(merge_bounded_edges(edges, max_edges, source_truncated))
}

fn contains_ignore_case(value: &str, needle: &str) -> bool {
    value.to_lowercase().contains(&needle.to_lowercase())
}

fn payload_array_len_at_least(payload_json: &str, filter: &PayloadArrayMinLen) -> bool {
    serde_json::from_str::<Value>(payload_json)
        .ok()
        .and_then(|payload| {
            payload
                .get(&filter.field)
                .and_then(Value::as_array)
                .map(|items| items.len() >= filter.min_len)
        })
        .unwrap_or(false)
}

fn query_node(node: GraphNodeRecord) -> GraphQueryNode {
    GraphQueryNode {
        node_key: node.node_key,
        label: node.label,
        display_name: node.display_name,
        payload: serde_json::from_str(&node.payload_json).unwrap_or(Value::Null),
    }
}

fn query_edge(edge: GraphEdgeRecord) -> GraphQueryEdge {
    GraphQueryEdge {
        edge_key: edge.edge_key,
        edge_from: edge.edge_from,
        edge_to: edge.edge_to,
        edge_type: edge.edge_type,
        payload: serde_json::from_str(&edge.payload_json).unwrap_or(Value::Null),
    }
}

#[cfg(test)]
mod graph_query_tests {
    use super::*;
    use crate::graph_store::{GraphEdgeRecord, GraphSnapshotRecord};

    const SNAPSHOT: &str = "snapshot-1";

    #[test]
    fn graph_query_filters_nodes_by_label() {
        let store = seeded_store();
        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: Some("Index".to_owned()),
                node_key_contains: None,
                name_contains: None,
                edge_type: None,
                payload_array_min_len: None,
                traversal: None,
                limit: 10,
            },
        )
        .unwrap();

        assert_eq!(result.nodes.len(), 2);
        assert!(result.nodes.iter().all(|node| node.label == "Index"));
    }

    #[test]
    fn graph_query_filters_nodes_by_name_substring() {
        let store = seeded_store();
        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: Some("Table".to_owned()),
                node_key_contains: None,
                name_contains: Some("ord".to_owned()),
                edge_type: None,
                payload_array_min_len: None,
                traversal: None,
                limit: 10,
            },
        )
        .unwrap();

        assert_eq!(result.nodes[0].display_name.as_deref(), Some("orders"));
    }

    #[test]
    fn graph_query_runs_bounded_traversal() {
        let store = seeded_store();
        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: None,
                node_key_contains: None,
                name_contains: None,
                edge_type: None,
                payload_array_min_len: None,
                traversal: Some(GraphQueryTraversal {
                    start_node_key: "table:orders".to_owned(),
                    direction: Direction::Outbound,
                    max_depth: 1,
                }),
                limit: 10,
            },
        )
        .unwrap();

        assert_eq!(
            result
                .traversal
                .iter()
                .map(|hit| hit.node_key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "index:orders.user_id",
                "column:orders.id",
                "column:orders.user_id"
            ]
        );
    }

    #[test]
    fn graph_query_caps_oversized_limit() {
        let store = seeded_store();
        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: None,
                node_key_contains: None,
                name_contains: None,
                edge_type: None,
                payload_array_min_len: None,
                traversal: None,
                limit: GRAPH_QUERY_MAX_LIMIT + 100,
            },
        )
        .unwrap();

        assert_eq!(result.limit_applied, GRAPH_QUERY_MAX_LIMIT);
        assert!(result.limit_clamped);
        assert!(result.nodes.len() < GRAPH_QUERY_MAX_LIMIT);
    }

    #[test]
    fn graph_query_filters_edges_before_bounding_high_degree_traversal() {
        let store = seeded_store();
        node(&store, "table:root", "Table", "root", "{}");
        for index in 0..256 {
            let key = format!("column:noise.{index:03}");
            node(&store, &key, "Column", &key, "{}");
            edge(
                &store,
                &format!("noise-{index:03}"),
                "table:root",
                &key,
                "NOISE",
            );
        }
        for index in 0..3 {
            let key = format!("column:wanted.{index:03}");
            node(&store, &key, "Column", &key, "{}");
            edge(
                &store,
                &format!("wanted-{index:03}"),
                "table:root",
                &key,
                "WANTED",
            );
        }

        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: None,
                node_key_contains: None,
                name_contains: None,
                edge_type: Some("WANTED".to_owned()),
                payload_array_min_len: None,
                traversal: Some(GraphQueryTraversal {
                    start_node_key: "table:root".to_owned(),
                    direction: Direction::Outbound,
                    max_depth: 1,
                }),
                limit: 2,
            },
        )
        .unwrap();

        assert_eq!(result.traversal.len(), 2);
        assert!(result.traversal.iter().all(|hit| hit.edge_type == "WANTED"));
        assert!(result.truncated);
        assert_eq!(result.result_count, 2);
    }

    #[test]
    fn filtered_both_direction_traversal_does_not_starve_inbound_edges() {
        let store = seeded_store();
        node(&store, "table:root", "Table", "root", "{}");
        node(&store, "table:caller", "Table", "caller", "{}");
        edge(&store, "a-inbound", "table:caller", "table:root", "RELATED");
        for index in 0..3 {
            let key = format!("table:outbound:{index}");
            node(&store, &key, "Table", &key, "{}");
            edge(
                &store,
                &format!("z-outbound-{index}"),
                "table:root",
                &key,
                "RELATED",
            );
        }

        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: None,
                node_key_contains: None,
                name_contains: None,
                edge_type: Some("RELATED".to_owned()),
                payload_array_min_len: None,
                traversal: Some(GraphQueryTraversal {
                    start_node_key: "table:root".to_owned(),
                    direction: Direction::Both,
                    max_depth: 1,
                }),
                limit: 2,
            },
        )
        .unwrap();

        assert!(result.truncated);
        assert_eq!(result.result_count, 2);
        assert_eq!(result.traversal[0].node_key, "table:caller");
        assert!(result
            .traversal
            .iter()
            .any(|hit| hit.node_key.starts_with("table:outbound:")));
    }

    #[test]
    fn graph_query_filters_payload_array_length() {
        let store = seeded_store();
        let result = query_graph(
            &store,
            &GraphQuery {
                snapshot_key: SNAPSHOT.to_owned(),
                node_label: Some("Index".to_owned()),
                node_key_contains: None,
                name_contains: None,
                edge_type: None,
                payload_array_min_len: Some(PayloadArrayMinLen {
                    field: "columns".to_owned(),
                    min_len: 3,
                }),
                traversal: None,
                limit: 10,
            },
        )
        .unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].display_name.as_deref(), Some("idx_big"));
    }

    fn seeded_store() -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        store
            .insert_snapshot(&GraphSnapshotRecord {
                snapshot_key: SNAPSHOT.to_owned(),
                source: None,
                captured_at_unix_ms: 0,
                payload_json: "{}".to_owned(),
            })
            .unwrap();
        node(&store, "table:orders", "Table", "orders", "{}");
        node(&store, "table:users", "Table", "users", "{}");
        node(&store, "column:orders.id", "Column", "id", "{}");
        node(&store, "column:orders.user_id", "Column", "user_id", "{}");
        node(
            &store,
            "index:orders.user_id",
            "Index",
            "idx_orders_user_id",
            r#"{"columns":["user_id"]}"#,
        );
        node(
            &store,
            "index:orders.big",
            "Index",
            "idx_big",
            r#"{"columns":["a","b","c"]}"#,
        );
        edge(
            &store,
            "orders-id",
            "table:orders",
            "column:orders.id",
            "TABLE_HAS_COLUMN",
        );
        edge(
            &store,
            "orders-user-id",
            "table:orders",
            "column:orders.user_id",
            "TABLE_HAS_COLUMN",
        );
        edge(
            &store,
            "orders-index",
            "table:orders",
            "index:orders.user_id",
            "TABLE_HAS_INDEX",
        );
        store
    }

    fn node(
        store: &GraphStore,
        node_key: &str,
        label: &str,
        display_name: &str,
        payload_json: &str,
    ) {
        store
            .insert_node(&GraphNodeRecord {
                snapshot_key: SNAPSHOT.to_owned(),
                node_key: node_key.to_owned(),
                label: label.to_owned(),
                display_name: Some(display_name.to_owned()),
                payload_json: payload_json.to_owned(),
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
}
