use std::collections::{HashSet, VecDeque};

use crate::graph_store::{GraphStore, GraphStoreResult};
use crate::impact_analysis::{next_edges, Direction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPath {
    pub hops: Vec<GraphPathHop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPathHop {
    pub node_key: String,
    pub label: String,
    pub edge_type_used: Option<String>,
}

pub fn trace_relationships(
    store: &GraphStore,
    snapshot_key: &str,
    start_key: &str,
    direction: Direction,
    max_depth: u32,
) -> GraphStoreResult<Vec<GraphPath>> {
    let Some(start_node) = store.get_node(snapshot_key, start_key)? else {
        return Ok(Vec::new());
    };
    if max_depth == 0 {
        return Ok(Vec::new());
    }

    let start_hop = GraphPathHop {
        node_key: start_key.to_owned(),
        label: start_node.label,
        edge_type_used: None,
    };
    let mut queue = VecDeque::from([(vec![start_hop], HashSet::from([start_key.to_owned()]))]);
    let mut paths = Vec::new();

    while let Some((hops, visited)) = queue.pop_front() {
        let depth = (hops.len() - 1) as u32;
        if depth == max_depth {
            continue;
        }

        let current_key = &hops.last().unwrap().node_key;
        for (edge, next_key) in next_edges(store, snapshot_key, current_key, direction)? {
            if visited.contains(&next_key) {
                continue;
            }

            if let Some(node) = store.get_node(snapshot_key, &next_key)? {
                let mut next_hops = hops.clone();
                next_hops.push(GraphPathHop {
                    node_key: next_key.clone(),
                    label: node.label,
                    edge_type_used: Some(edge.edge_type),
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
    }

    Ok(paths)
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
                    hop(&orders_user_id, "Column", None),
                    hop(&fk, "ForeignKey", Some("FK_FROM_COLUMN")),
                    hop(&users_id, "Column", Some("FK_TO_COLUMN")),
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
                hops: vec![hop("A", "Table", None), hop("B", "Column", Some("A_TO_B"))]
            }]
        );
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

    fn hop(node_key: &str, label: &str, edge_type_used: Option<&str>) -> GraphPathHop {
        GraphPathHop {
            node_key: node_key.to_owned(),
            label: label.to_owned(),
            edge_type_used: edge_type_used.map(str::to_owned),
        }
    }
}
