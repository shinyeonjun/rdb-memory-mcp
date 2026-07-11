use std::error::Error;
use std::fmt;
use std::path::Path;

use crate::AdapterCapabilities;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

pub type GraphStoreResult<T> = Result<T, GraphStoreError>;

#[derive(Debug)]
pub enum GraphStoreError {
    Storage(rusqlite::Error),
    Payload(serde_json::Error),
}

impl fmt::Display for GraphStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "graph store storage error: {err}"),
            Self::Payload(err) => write!(f, "graph store payload error: {err}"),
        }
    }
}

impl Error for GraphStoreError {}

impl From<rusqlite::Error> for GraphStoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(err)
    }
}

impl From<serde_json::Error> for GraphStoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::Payload(err)
    }
}

#[derive(Deserialize)]
struct SnapshotCapabilitiesPayload {
    capabilities: AdapterCapabilities,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphSnapshotRecord {
    pub snapshot_key: String,
    pub source: Option<String>,
    pub captured_at_unix_ms: i64,
    pub payload_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNodeRecord {
    pub snapshot_key: String,
    pub node_key: String,
    pub label: String,
    pub display_name: Option<String>,
    pub payload_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphEdgeRecord {
    pub snapshot_key: String,
    pub edge_key: String,
    pub edge_from: String,
    pub edge_to: String,
    pub edge_type: String,
    pub payload_json: String,
}

pub struct GraphStore {
    conn: Connection,
}

impl GraphStore {
    pub fn open(path: impl AsRef<Path>) -> GraphStoreResult<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> GraphStoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> GraphStoreResult<Self> {
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> GraphStoreResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS graph_snapshots (
                snapshot_key TEXT PRIMARY KEY,
                source TEXT,
                captured_at_unix_ms INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                snapshot_key TEXT NOT NULL,
                node_key TEXT NOT NULL,
                label TEXT NOT NULL,
                display_name TEXT,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (snapshot_key, node_key),
                FOREIGN KEY (snapshot_key)
                    REFERENCES graph_snapshots(snapshot_key)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                snapshot_key TEXT NOT NULL,
                edge_key TEXT NOT NULL,
                edge_from TEXT NOT NULL,
                edge_to TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (snapshot_key, edge_key),
                FOREIGN KEY (snapshot_key, edge_from)
                    REFERENCES graph_nodes(snapshot_key, node_key)
                    ON DELETE CASCADE,
                FOREIGN KEY (snapshot_key, edge_to)
                    REFERENCES graph_nodes(snapshot_key, node_key)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_graph_nodes_key
                ON graph_nodes (node_key);
            CREATE INDEX IF NOT EXISTS idx_graph_nodes_label
                ON graph_nodes (label);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_key
                ON graph_edges (edge_key);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_from
                ON graph_edges (edge_from);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_to
                ON graph_edges (edge_to);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_type
                ON graph_edges (edge_type);
            ",
        )?;
        Ok(())
    }

    pub fn insert_snapshot(&self, snapshot: &GraphSnapshotRecord) -> GraphStoreResult<()> {
        self.conn.execute(
            "
            INSERT INTO graph_snapshots (
                snapshot_key, source, captured_at_unix_ms, payload_json
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(snapshot_key) DO UPDATE SET
                source = excluded.source,
                captured_at_unix_ms = excluded.captured_at_unix_ms,
                payload_json = excluded.payload_json
            ",
            params![
                &snapshot.snapshot_key,
                snapshot.source.as_deref(),
                snapshot.captured_at_unix_ms,
                &snapshot.payload_json
            ],
        )?;
        Ok(())
    }

    pub fn get_snapshot(
        &self,
        snapshot_key: &str,
    ) -> GraphStoreResult<Option<GraphSnapshotRecord>> {
        self.conn
            .query_row(
                "
                SELECT snapshot_key, source, captured_at_unix_ms, payload_json
                FROM graph_snapshots
                WHERE snapshot_key = ?1
                ",
                params![snapshot_key],
                |row| {
                    Ok(GraphSnapshotRecord {
                        snapshot_key: row.get(0)?,
                        source: row.get(1)?,
                        captured_at_unix_ms: row.get(2)?,
                        payload_json: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(GraphStoreError::from)
    }

    pub fn get_snapshot_capabilities(
        &self,
        snapshot_key: &str,
    ) -> GraphStoreResult<Option<AdapterCapabilities>> {
        let payload_json = self
            .conn
            .query_row(
                "
                SELECT payload_json
                FROM graph_snapshots
                WHERE snapshot_key = ?1
                ",
                params![snapshot_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        payload_json
            .map(|payload_json| {
                serde_json::from_str::<SnapshotCapabilitiesPayload>(&payload_json)
                    .map(|payload| payload.capabilities)
            })
            .transpose()
            .map_err(GraphStoreError::from)
    }

    pub fn snapshot_count(&self) -> GraphStoreResult<u64> {
        let count = self
            .conn
            .query_row("SELECT COUNT(*) FROM graph_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(count as u64)
    }

    pub fn list_snapshots(&self) -> GraphStoreResult<Vec<GraphSnapshotRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, source, captured_at_unix_ms, payload_json
            FROM graph_snapshots
            ORDER BY snapshot_key
            ",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(GraphSnapshotRecord {
                snapshot_key: row.get(0)?,
                source: row.get(1)?,
                captured_at_unix_ms: row.get(2)?,
                payload_json: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(GraphStoreError::from)
    }

    pub fn delete_snapshot(&self, snapshot_key: &str) -> GraphStoreResult<()> {
        self.conn.execute(
            "DELETE FROM graph_snapshots WHERE snapshot_key = ?1",
            params![snapshot_key],
        )?;
        Ok(())
    }

    pub fn insert_node(&self, node: &GraphNodeRecord) -> GraphStoreResult<()> {
        self.conn.execute(
            "
            INSERT INTO graph_nodes (
                snapshot_key, node_key, label, display_name, payload_json
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(snapshot_key, node_key) DO UPDATE SET
                label = excluded.label,
                display_name = excluded.display_name,
                payload_json = excluded.payload_json
            ",
            params![
                &node.snapshot_key,
                &node.node_key,
                &node.label,
                node.display_name.as_deref(),
                &node.payload_json
            ],
        )?;
        Ok(())
    }

    pub fn get_node(
        &self,
        snapshot_key: &str,
        node_key: &str,
    ) -> GraphStoreResult<Option<GraphNodeRecord>> {
        self.conn
            .query_row(
                "
                SELECT snapshot_key, node_key, label, display_name, payload_json
                FROM graph_nodes
                WHERE snapshot_key = ?1 AND node_key = ?2
                ",
                params![snapshot_key, node_key],
                map_node,
            )
            .optional()
            .map_err(GraphStoreError::from)
    }

    pub fn nodes_by_label(
        &self,
        snapshot_key: &str,
        label: &str,
    ) -> GraphStoreResult<Vec<GraphNodeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, node_key, label, display_name, payload_json
            FROM graph_nodes
            WHERE snapshot_key = ?1 AND label = ?2
            ORDER BY node_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key, label], map_node)?;
        collect_nodes(rows)
    }

    pub fn nodes_for_snapshot(&self, snapshot_key: &str) -> GraphStoreResult<Vec<GraphNodeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, node_key, label, display_name, payload_json
            FROM graph_nodes
            WHERE snapshot_key = ?1
            ORDER BY node_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key], map_node)?;
        collect_nodes(rows)
    }

    pub fn delete_node(&self, snapshot_key: &str, node_key: &str) -> GraphStoreResult<()> {
        self.conn.execute(
            "DELETE FROM graph_nodes WHERE snapshot_key = ?1 AND node_key = ?2",
            params![snapshot_key, node_key],
        )?;
        Ok(())
    }

    pub fn insert_edge(&self, edge: &GraphEdgeRecord) -> GraphStoreResult<()> {
        self.conn.execute(
            "
            INSERT INTO graph_edges (
                snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(snapshot_key, edge_key) DO UPDATE SET
                edge_from = excluded.edge_from,
                edge_to = excluded.edge_to,
                edge_type = excluded.edge_type,
                payload_json = excluded.payload_json
            ",
            params![
                &edge.snapshot_key,
                &edge.edge_key,
                &edge.edge_from,
                &edge.edge_to,
                &edge.edge_type,
                &edge.payload_json
            ],
        )?;
        Ok(())
    }

    pub fn get_edge(
        &self,
        snapshot_key: &str,
        edge_key: &str,
    ) -> GraphStoreResult<Option<GraphEdgeRecord>> {
        self.conn
            .query_row(
                "
                SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
                FROM graph_edges
                WHERE snapshot_key = ?1 AND edge_key = ?2
                ",
                params![snapshot_key, edge_key],
                map_edge,
            )
            .optional()
            .map_err(GraphStoreError::from)
    }

    pub fn edges_from(
        &self,
        snapshot_key: &str,
        edge_from: &str,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_from = ?2
            ORDER BY edge_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key, edge_from], map_edge)?;
        collect_edges(rows)
    }

    pub fn edges_from_limited(
        &self,
        snapshot_key: &str,
        edge_from: &str,
        limit: usize,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_from = ?2
            ORDER BY edge_key
            LIMIT ?3
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_from, sqlite_limit(limit)],
            map_edge,
        )?;
        collect_edges(rows)
    }

    pub fn edges_to(
        &self,
        snapshot_key: &str,
        edge_to: &str,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_to = ?2
            ORDER BY edge_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key, edge_to], map_edge)?;
        collect_edges(rows)
    }

    pub fn edges_to_limited(
        &self,
        snapshot_key: &str,
        edge_to: &str,
        limit: usize,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_to = ?2
            ORDER BY edge_key
            LIMIT ?3
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_to, sqlite_limit(limit)],
            map_edge,
        )?;
        collect_edges(rows)
    }

    pub fn edges_by_type(
        &self,
        snapshot_key: &str,
        edge_type: &str,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_type = ?2
            ORDER BY edge_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key, edge_type], map_edge)?;
        collect_edges(rows)
    }

    pub fn delete_edge(&self, snapshot_key: &str, edge_key: &str) -> GraphStoreResult<()> {
        self.conn.execute(
            "DELETE FROM graph_edges WHERE snapshot_key = ?1 AND edge_key = ?2",
            params![snapshot_key, edge_key],
        )?;
        Ok(())
    }
}

fn map_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<GraphNodeRecord> {
    Ok(GraphNodeRecord {
        snapshot_key: row.get(0)?,
        node_key: row.get(1)?,
        label: row.get(2)?,
        display_name: row.get(3)?,
        payload_json: row.get(4)?,
    })
}

fn map_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<GraphEdgeRecord> {
    Ok(GraphEdgeRecord {
        snapshot_key: row.get(0)?,
        edge_key: row.get(1)?,
        edge_from: row.get(2)?,
        edge_to: row.get(3)?,
        edge_type: row.get(4)?,
        payload_json: row.get(5)?,
    })
}

fn collect_nodes(
    rows: impl Iterator<Item = rusqlite::Result<GraphNodeRecord>>,
) -> GraphStoreResult<Vec<GraphNodeRecord>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(GraphStoreError::from)
}

fn collect_edges(
    rows: impl Iterator<Item = rusqlite::Result<GraphEdgeRecord>>,
) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(GraphStoreError::from)
}

fn sqlite_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod graph_store_tests {
    use super::*;

    #[test]
    fn graph_store_inserts_and_finds_node() {
        let store = seeded_store();
        let node = GraphNodeRecord {
            snapshot_key: "snapshot-1".to_string(),
            node_key: "table:public.users".to_string(),
            label: "table".to_string(),
            display_name: Some("users".to_string()),
            payload_json: r#"{"schema":"public","name":"users"}"#.to_string(),
        };

        store.insert_node(&node).unwrap();

        assert_eq!(
            store.get_node("snapshot-1", "table:public.users").unwrap(),
            Some(node.clone())
        );
        assert_eq!(
            store.nodes_by_label("snapshot-1", "table").unwrap(),
            vec![node]
        );
    }

    #[test]
    fn graph_store_counts_snapshots() {
        let store = seeded_store();

        assert_eq!(store.snapshot_count().unwrap(), 1);
        assert_eq!(
            store.list_snapshots().unwrap()[0].snapshot_key,
            "snapshot-1"
        );
    }

    #[test]
    fn graph_store_inserts_and_finds_edge() {
        let store = seeded_store();
        store
            .insert_node(&GraphNodeRecord {
                snapshot_key: "snapshot-1".to_string(),
                node_key: "table:public.orders".to_string(),
                label: "table".to_string(),
                display_name: Some("orders".to_string()),
                payload_json: "{}".to_string(),
            })
            .unwrap();
        store
            .insert_node(&GraphNodeRecord {
                snapshot_key: "snapshot-1".to_string(),
                node_key: "table:public.users".to_string(),
                label: "table".to_string(),
                display_name: Some("users".to_string()),
                payload_json: "{}".to_string(),
            })
            .unwrap();
        let edge = GraphEdgeRecord {
            snapshot_key: "snapshot-1".to_string(),
            edge_key: "fk:orders.user_id:users.id".to_string(),
            edge_from: "table:public.orders".to_string(),
            edge_to: "table:public.users".to_string(),
            edge_type: "foreign_key".to_string(),
            payload_json: r#"{"columns":["user_id"]}"#.to_string(),
        };

        store.insert_edge(&edge).unwrap();

        assert_eq!(
            store
                .get_edge("snapshot-1", "fk:orders.user_id:users.id")
                .unwrap(),
            Some(edge.clone())
        );
        assert_eq!(
            store
                .edges_from("snapshot-1", "table:public.orders")
                .unwrap(),
            vec![edge.clone()]
        );
        assert_eq!(
            store.edges_to("snapshot-1", "table:public.users").unwrap(),
            vec![edge.clone()]
        );
        assert_eq!(
            store.edges_by_type("snapshot-1", "foreign_key").unwrap(),
            vec![edge]
        );
    }

    fn seeded_store() -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        store
            .insert_snapshot(&GraphSnapshotRecord {
                snapshot_key: "snapshot-1".to_string(),
                source: Some("test".to_string()),
                captured_at_unix_ms: 0,
                payload_json: "{}".to_string(),
            })
            .unwrap();
        store
    }
}
