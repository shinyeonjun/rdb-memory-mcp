use std::collections::{HashSet, VecDeque};

use crate::graph_store::{GraphStore, GraphStoreResult};
use crate::impact_analysis::{next_edges_bounded, Direction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPath {
    pub hops: Vec<GraphPathHop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPathHop {
    pub node_key: String,
    pub label: String,
    pub edge_type_used: Option<String>,
    pub edge_from: Option<String>,
    pub edge_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedRelationshipTraceResult {
    pub paths: Vec<GraphPath>,
    pub truncated: bool,
}

pub fn trace_relationships(
    store: &GraphStore,
    snapshot_key: &str,
    start_key: &str,
    direction: Direction,
    max_depth: u32,
) -> GraphStoreResult<Vec<GraphPath>> {
    Ok(trace_relationships_bounded(
        store,
        snapshot_key,
        start_key,
        direction,
        max_depth,
        usize::MAX,
    )?
    .paths)
}

pub fn trace_relationships_bounded(
    store: &GraphStore,
    snapshot_key: &str,
    start_key: &str,
    direction: Direction,
    max_depth: u32,
    max_paths: usize,
) -> GraphStoreResult<BoundedRelationshipTraceResult> {
    let Some(start_node) = store.get_node(snapshot_key, start_key)? else {
        return Ok(BoundedRelationshipTraceResult {
            paths: Vec::new(),
            truncated: false,
        });
    };
    if max_depth == 0 {
        return Ok(BoundedRelationshipTraceResult {
            paths: Vec::new(),
            truncated: false,
        });
    }

    let start_hop = GraphPathHop {
        node_key: start_key.to_owned(),
        label: start_node.label,
        edge_type_used: None,
        edge_from: None,
        edge_to: None,
    };
    let mut queue = VecDeque::from([(vec![start_hop], HashSet::from([start_key.to_owned()]))]);
    let mut paths = Vec::new();
    let mut truncated = false;
    let mut remaining_budget = max_paths;

    'traversal: while let Some((hops, visited)) = queue.pop_front() {
        let depth = (hops.len() - 1) as u32;
        if depth == max_depth {
            continue;
        }

        let current_key = &hops.last().unwrap().node_key;
        let (edges, has_more_edges) = next_edges_bounded(
            store,
            snapshot_key,
            current_key,
            direction,
            remaining_budget,
        )?;
        if max_paths != usize::MAX {
            remaining_budget -= edges.len();
        }
        truncated |= has_more_edges;

        for (edge, next_key) in edges {
            if visited.contains(&next_key) {
                continue;
            }

            if let Some(node) = store.get_node(snapshot_key, &next_key)? {
                let mut next_hops = hops.clone();
                next_hops.push(GraphPathHop {
                    node_key: next_key.clone(),
                    label: node.label,
                    edge_type_used: Some(edge.edge_type),
                    edge_from: Some(edge.edge_from),
                    edge_to: Some(edge.edge_to),
                });
                paths.push(GraphPath {
                    hops: next_hops.clone(),
                });

                if depth + 1 < max_depth {
                    let mut next_visited = visited.clone();
                    next_visited.insert(next_key);
                    queue.push_back((next_hops, next_visited));
                }
            }
        }

        if has_more_edges {
            break 'traversal;
        }
    }

    Ok(BoundedRelationshipTraceResult { paths, truncated })
}

#[cfg(test)]
mod relationship_trace_tests {
    use super::*;
    use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphSnapshotRecord};

    const SNAPSHOT: &str = "snapshot-1";

    #[test]
    fn relationship_trace_fk_chain_returns_exact_ordered_path() {
        let store = empty_store();
        let orders_user_id = key("column", "orders:user_id");
        let fk = key("foreign_key", "orders:fk_orders_user");
        let users_id = key("column", "users:id");

        node(&store, &orders_user_id, "Column");
        node(&store, &fk, "ForeignKey");
        node(&store, &users_id, "Column");
        edge(
            &store,
            "fk_from_orders_user",
            &orders_user_id,
            &fk,
            "FK_FROM_COLUMN",
        );
        edge(&store, "fk_to_users_id", &fk, &users_id, "FK_TO_COLUMN");

        let paths =
            trace_relationships(&store, SNAPSHOT, &orders_user_id, Direction::Outbound, 2).unwrap();

        assert!(paths.iter().any(|path| {
            path.hops
                == vec![
                    hop(&orders_user_id, "Column", None, None, None),
                    hop(
                        &fk,
                        "ForeignKey",
                        Some("FK_FROM_COLUMN"),
                        Some(&orders_user_id),
                        Some(&fk),
                    ),
                    hop(
                        &users_id,
                        "Column",
                        Some("FK_TO_COLUMN"),
                        Some(&fk),
                        Some(&users_id),
                    ),
                ]
        }));
    }

    #[test]
    fn relationship_trace_cycle_safe_no_path_revisits_node() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Table");
        node(&store, "C", "Table");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "B_TO_C", "B", "C", "B_TO_C");
        edge(&store, "C_TO_A", "C", "A", "C_TO_A");

        let paths = trace_relationships(&store, SNAPSHOT, "A", Direction::Outbound, 10).unwrap();

        assert_eq!(paths.len(), 2);
        for path in paths {
            let mut seen = HashSet::new();
            for hop in path.hops {
                assert!(seen.insert(hop.node_key));
            }
        }
    }

    #[test]
    fn relationship_trace_max_depth_bounds_paths() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Column");
        node(&store, "C", "Index");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "B_TO_C", "B", "C", "B_TO_C");

        let paths = trace_relationships(&store, SNAPSHOT, "A", Direction::Outbound, 1).unwrap();

        assert_eq!(
            paths,
            vec![GraphPath {
                hops: vec![
                    hop("A", "Table", None, None, None),
                    hop("B", "Column", Some("A_TO_B"), Some("A"), Some("B"))
                ]
            }]
        );
    }

    #[test]
    fn bounded_relationship_trace_stops_and_reports_truncation() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Column");
        node(&store, "C", "Index");
        edge(&store, "A_TO_B", "A", "B", "A_TO_B");
        edge(&store, "A_TO_C", "A", "C", "A_TO_C");

        let bounded =
            trace_relationships_bounded(&store, SNAPSHOT, "A", Direction::Outbound, 2, 1).unwrap();

        assert!(bounded.truncated);
        assert_eq!(bounded.paths.len(), 1);
        assert_eq!(bounded.paths[0].hops.last().unwrap().node_key, "B");
    }

    #[test]
    fn relationship_trace_preserves_stored_endpoints_for_every_direction() {
        let store = empty_store();
        node(&store, "A", "Table");
        node(&store, "B", "Table");
        node(&store, "C", "Table");
        edge(&store, "B_TO_A", "B", "A", "INBOUND_EDGE");
        edge(&store, "A_TO_C", "A", "C", "OUTBOUND_EDGE");

        let inbound = trace_relationships(&store, SNAPSHOT, "A", Direction::Inbound, 1).unwrap();
        assert_last_hop_endpoints(&inbound, "B", "B", "A");

        let outbound = trace_relationships(&store, SNAPSHOT, "A", Direction::Outbound, 1).unwrap();
        assert_last_hop_endpoints(&outbound, "C", "A", "C");

        let both = trace_relationships(&store, SNAPSHOT, "A", Direction::Both, 1).unwrap();
        assert_last_hop_endpoints(&both, "B", "B", "A");
        assert_last_hop_endpoints(&both, "C", "A", "C");
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

    fn hop(
        node_key: &str,
        label: &str,
        edge_type_used: Option<&str>,
        edge_from: Option<&str>,
        edge_to: Option<&str>,
    ) -> GraphPathHop {
        GraphPathHop {
            node_key: node_key.to_owned(),
            label: label.to_owned(),
            edge_type_used: edge_type_used.map(str::to_owned),
            edge_from: edge_from.map(str::to_owned),
            edge_to: edge_to.map(str::to_owned),
        }
    }

    fn assert_last_hop_endpoints(
        paths: &[GraphPath],
        node_key: &str,
        edge_from: &str,
        edge_to: &str,
    ) {
        let hop = paths
            .iter()
            .filter_map(|path| path.hops.last())
            .find(|hop| hop.node_key == node_key)
            .unwrap();
        assert_eq!(hop.edge_from.as_deref(), Some(edge_from));
        assert_eq!(hop.edge_to.as_deref(), Some(edge_to));
    }
}
