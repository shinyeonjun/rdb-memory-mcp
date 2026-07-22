use std::error::Error;
use std::fmt;
use std::path::Path;

use crate::certification::{
    verify_certified_schema_snapshot, CertificationError, CertifiedSchemaSnapshot,
};
use crate::snapshot_validation::SnapshotValidationError;
use crate::AdapterCapabilities;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

pub type GraphStoreResult<T> = Result<T, GraphStoreError>;
pub const GRAPH_STORE_SCHEMA_VERSION: i64 = 2;

#[derive(Debug)]
pub enum GraphStoreError {
    Storage(rusqlite::Error),
    Payload(serde_json::Error),
    InvalidSnapshot(SnapshotValidationError),
    InvalidCertification(CertificationError),
    UnsupportedSchemaVersion(i64),
}

impl fmt::Display for GraphStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "graph store storage error: {err}"),
            Self::Payload(err) => write!(f, "graph store payload error: {err}"),
            Self::InvalidSnapshot(err) => write!(f, "graph store rejected invalid snapshot: {err}"),
            Self::InvalidCertification(err) => {
                write!(f, "graph store rejected uncertified snapshot: {err}")
            }
            Self::UnsupportedSchemaVersion(version) => write!(
                f,
                "graph store schema version {version} is newer than supported version {GRAPH_STORE_SCHEMA_VERSION}"
            ),
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

impl From<SnapshotValidationError> for GraphStoreError {
    fn from(err: SnapshotValidationError) -> Self {
        Self::InvalidSnapshot(err)
    }
}

impl From<CertificationError> for GraphStoreError {
    fn from(err: CertificationError) -> Self {
        Self::InvalidCertification(err)
    }
}

#[derive(Deserialize)]
struct SnapshotCapabilitiesPayload {
    capabilities: AdapterCapabilities,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotAuthority {
    Complete,
    LegacyNonAuthoritative,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotContractStatus {
    pub authority: SnapshotAuthority,
    pub contract_version: Option<u32>,
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
        let version = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        if version > GRAPH_STORE_SCHEMA_VERSION {
            return Err(GraphStoreError::UnsupportedSchemaVersion(version));
        }
        self.conn.execute_batch("PRAGMA foreign_keys = ON")?;
        let migration = self.conn.execute_batch(
            "
            BEGIN IMMEDIATE;

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
            CREATE INDEX IF NOT EXISTS idx_graph_edges_from_type_key
                ON graph_edges (snapshot_key, edge_from, edge_type, edge_key);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_to_type_key
                ON graph_edges (snapshot_key, edge_to, edge_type, edge_key);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_type_key
                ON graph_edges (snapshot_key, edge_type, edge_key);

            PRAGMA user_version = 2;
            COMMIT;
            ",
        );
        match migration {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error.into())
            }
        }
    }

    pub fn schema_version(&self) -> GraphStoreResult<i64> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map_err(GraphStoreError::from)
    }

    pub fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&Self) -> GraphStoreResult<T>,
    ) -> GraphStoreResult<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match operation(self) {
            Ok(value) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(error) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(error.into())
                }
            },
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn insert_snapshot(&self, snapshot: &GraphSnapshotRecord) -> GraphStoreResult<()> {
        validate_persisted_snapshot_payload(&snapshot.payload_json)?;
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

    pub fn get_snapshot_contract_status(
        &self,
        snapshot_key: &str,
    ) -> GraphStoreResult<Option<SnapshotContractStatus>> {
        let Some(snapshot) = self.get_snapshot(snapshot_key)? else {
            return Ok(None);
        };
        match snapshot_contract_version(&snapshot.payload_json)? {
            None => Ok(Some(SnapshotContractStatus {
                authority: SnapshotAuthority::LegacyNonAuthoritative,
                contract_version: None,
            })),
            Some(contract_version) => {
                let certified =
                    serde_json::from_str::<CertifiedSchemaSnapshot>(&snapshot.payload_json)?;
                verify_certified_schema_snapshot(&certified)?;
                Ok(Some(SnapshotContractStatus {
                    authority: SnapshotAuthority::Complete,
                    contract_version: Some(contract_version),
                }))
            }
        }
    }

    pub fn get_certified_snapshot(
        &self,
        snapshot_key: &str,
    ) -> GraphStoreResult<Option<CertifiedSchemaSnapshot>> {
        let Some(snapshot) = self.get_snapshot(snapshot_key)? else {
            return Ok(None);
        };
        if snapshot_contract_version(&snapshot.payload_json)?.is_none() {
            return Ok(None);
        }
        let certified = serde_json::from_str::<CertifiedSchemaSnapshot>(&snapshot.payload_json)?;
        verify_certified_schema_snapshot(&certified)?;
        Ok(Some(certified))
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

    pub fn node_count_for_snapshot(&self, snapshot_key: &str) -> GraphStoreResult<u64> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM graph_nodes WHERE snapshot_key = ?1",
            params![snapshot_key],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as u64)
    }

    pub fn find_nodes_page(
        &self,
        snapshot_key: &str,
        label: Option<&str>,
        query: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> GraphStoreResult<(u64, Vec<GraphNodeRecord>)> {
        let normalized_query = query.map(str::trim).filter(|query| !query.is_empty());
        match (label, normalized_query) {
            (None, None) => {
                let total = self.conn.query_row(
                    "SELECT COUNT(*) FROM graph_nodes WHERE snapshot_key = ?1",
                    params![snapshot_key],
                    |row| row.get::<_, i64>(0),
                )?;
                let mut stmt = self.conn.prepare(
                    "SELECT snapshot_key, node_key, label, display_name, payload_json
                     FROM graph_nodes
                     WHERE snapshot_key = ?1
                     ORDER BY label, node_key
                     LIMIT ?2 OFFSET ?3",
                )?;
                let rows = stmt.query_map(
                    params![snapshot_key, sqlite_limit(limit), sqlite_offset(offset)],
                    map_node,
                )?;
                Ok((total as u64, collect_nodes(rows)?))
            }
            (Some(label), None) => {
                let total = self.conn.query_row(
                    "SELECT COUNT(*) FROM graph_nodes
                     WHERE snapshot_key = ?1 AND label = ?2",
                    params![snapshot_key, label],
                    |row| row.get::<_, i64>(0),
                )?;
                let mut stmt = self.conn.prepare(
                    "SELECT snapshot_key, node_key, label, display_name, payload_json
                     FROM graph_nodes
                     WHERE snapshot_key = ?1 AND label = ?2
                     ORDER BY node_key
                     LIMIT ?3 OFFSET ?4",
                )?;
                let rows = stmt.query_map(
                    params![
                        snapshot_key,
                        label,
                        sqlite_limit(limit),
                        sqlite_offset(offset)
                    ],
                    map_node,
                )?;
                Ok((total as u64, collect_nodes(rows)?))
            }
            (None, Some(query)) => {
                let total = self.conn.query_row(
                    "SELECT COUNT(*) FROM graph_nodes
                     WHERE snapshot_key = ?1
                       AND (instr(lower(node_key), lower(?2)) > 0
                            OR instr(lower(COALESCE(display_name, '')), lower(?2)) > 0)",
                    params![snapshot_key, query],
                    |row| row.get::<_, i64>(0),
                )?;
                let mut stmt = self.conn.prepare(
                    "SELECT snapshot_key, node_key, label, display_name, payload_json
                     FROM graph_nodes
                     WHERE snapshot_key = ?1
                       AND (instr(lower(node_key), lower(?2)) > 0
                            OR instr(lower(COALESCE(display_name, '')), lower(?2)) > 0)
                     ORDER BY label, node_key
                     LIMIT ?3 OFFSET ?4",
                )?;
                let rows = stmt.query_map(
                    params![
                        snapshot_key,
                        query,
                        sqlite_limit(limit),
                        sqlite_offset(offset)
                    ],
                    map_node,
                )?;
                Ok((total as u64, collect_nodes(rows)?))
            }
            (Some(label), Some(query)) => {
                let total = self.conn.query_row(
                    "SELECT COUNT(*) FROM graph_nodes
                     WHERE snapshot_key = ?1 AND label = ?2
                       AND (instr(lower(node_key), lower(?3)) > 0
                            OR instr(lower(COALESCE(display_name, '')), lower(?3)) > 0)",
                    params![snapshot_key, label, query],
                    |row| row.get::<_, i64>(0),
                )?;
                let mut stmt = self.conn.prepare(
                    "SELECT snapshot_key, node_key, label, display_name, payload_json
                     FROM graph_nodes
                     WHERE snapshot_key = ?1 AND label = ?2
                       AND (instr(lower(node_key), lower(?3)) > 0
                            OR instr(lower(COALESCE(display_name, '')), lower(?3)) > 0)
                     ORDER BY node_key
                     LIMIT ?4 OFFSET ?5",
                )?;
                let rows = stmt.query_map(
                    params![
                        snapshot_key,
                        label,
                        query,
                        sqlite_limit(limit),
                        sqlite_offset(offset)
                    ],
                    map_node,
                )?;
                Ok((total as u64, collect_nodes(rows)?))
            }
        }
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

    pub fn edges_for_snapshot(&self, snapshot_key: &str) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1
            ORDER BY edge_key
            ",
        )?;
        let rows = stmt.query_map(params![snapshot_key], map_edge)?;
        collect_edges(rows)
    }

    pub fn edge_count_for_snapshot(&self, snapshot_key: &str) -> GraphStoreResult<u64> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM graph_edges WHERE snapshot_key = ?1",
            params![snapshot_key],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as u64)
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
            ORDER BY
                CASE
                    WHEN edge_type IN (
                        'DATABASE_HAS_SCHEMA',
                        'SCHEMA_HAS_TABLE',
                        'SCHEMA_HAS_VIEW',
                        'SCHEMA_HAS_ROUTINE',
                        'TABLE_HAS_COLUMN'
                    ) THEN 2
                    WHEN edge_type = 'TABLE_HAS_INDEX' THEN 1
                    ELSE 0
                END,
                edge_key
            LIMIT ?3
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_from, sqlite_limit(limit)],
            map_edge,
        )?;
        collect_edges(rows)
    }

    pub fn edges_from_by_type_limited(
        &self,
        snapshot_key: &str,
        edge_from: &str,
        edge_type: &str,
        limit: usize,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_from = ?2 AND edge_type = ?3
            ORDER BY edge_key
            LIMIT ?4
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_from, edge_type, sqlite_limit(limit)],
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
            ORDER BY
                CASE
                    WHEN edge_type IN (
                        'DATABASE_HAS_SCHEMA',
                        'SCHEMA_HAS_TABLE',
                        'SCHEMA_HAS_VIEW',
                        'SCHEMA_HAS_ROUTINE',
                        'TABLE_HAS_COLUMN'
                    ) THEN 2
                    WHEN edge_type = 'TABLE_HAS_INDEX' THEN 1
                    ELSE 0
                END,
                edge_key
            LIMIT ?3
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_to, sqlite_limit(limit)],
            map_edge,
        )?;
        collect_edges(rows)
    }

    pub fn edges_to_by_type_limited(
        &self,
        snapshot_key: &str,
        edge_to: &str,
        edge_type: &str,
        limit: usize,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_to = ?2 AND edge_type = ?3
            ORDER BY edge_key
            LIMIT ?4
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_to, edge_type, sqlite_limit(limit)],
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

    pub fn edges_by_type_limited(
        &self,
        snapshot_key: &str,
        edge_type: &str,
        limit: usize,
    ) -> GraphStoreResult<Vec<GraphEdgeRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT snapshot_key, edge_key, edge_from, edge_to, edge_type, payload_json
            FROM graph_edges
            WHERE snapshot_key = ?1 AND edge_type = ?2
            ORDER BY edge_key
            LIMIT ?3
            ",
        )?;
        let rows = stmt.query_map(
            params![snapshot_key, edge_type, sqlite_limit(limit)],
            map_edge,
        )?;
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

fn validate_persisted_snapshot_payload(payload_json: &str) -> GraphStoreResult<()> {
    if snapshot_contract_version(payload_json)?.is_some() {
        let certified = serde_json::from_str::<CertifiedSchemaSnapshot>(payload_json)?;
        verify_certified_schema_snapshot(&certified)?;
    }
    Ok(())
}

fn snapshot_contract_version(payload_json: &str) -> GraphStoreResult<Option<u32>> {
    let value = serde_json::from_str::<serde_json::Value>(payload_json)?;
    let object = serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(value)?;
    object
        .get("contract_version")
        .cloned()
        .map(serde_json::from_value::<u32>)
        .transpose()
        .map_err(GraphStoreError::from)
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

fn sqlite_offset(offset: usize) -> i64 {
    i64::try_from(offset).unwrap_or(i64::MAX)
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

        assert_eq!(store.schema_version().unwrap(), GRAPH_STORE_SCHEMA_VERSION);
        assert_eq!(store.snapshot_count().unwrap(), 1);
        assert_eq!(
            store.list_snapshots().unwrap()[0].snapshot_key,
            "snapshot-1"
        );
        assert_eq!(
            store
                .get_snapshot_contract_status("snapshot-1")
                .unwrap()
                .unwrap(),
            SnapshotContractStatus {
                authority: SnapshotAuthority::LegacyNonAuthoritative,
                contract_version: None,
            }
        );
        assert!(store
            .get_certified_snapshot("snapshot-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn graph_store_rejects_unknown_future_cache_versions() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 99").unwrap();

        let error = match GraphStore::from_connection(conn) {
            Ok(_) => panic!("future graph cache version was accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            GraphStoreError::UnsupportedSchemaVersion(99)
        ));
    }

    #[test]
    fn low_level_store_cannot_bypass_v2_certification() {
        let store = seeded_store();
        let before = store.get_snapshot("snapshot-1").unwrap().unwrap();

        let error = store
            .insert_snapshot(&GraphSnapshotRecord {
                snapshot_key: "snapshot-1".to_owned(),
                source: Some("tampered".to_owned()),
                captured_at_unix_ms: 99,
                payload_json: r#"{"contract_version":2}"#.to_owned(),
            })
            .unwrap_err();

        assert!(matches!(error, GraphStoreError::Payload(_)));
        assert_eq!(store.get_snapshot("snapshot-1").unwrap().unwrap(), before);

        let null_version_error = store
            .insert_snapshot(&GraphSnapshotRecord {
                snapshot_key: "snapshot-1".to_owned(),
                source: Some("tampered".to_owned()),
                captured_at_unix_ms: 100,
                payload_json: r#"{"contract_version":null}"#.to_owned(),
            })
            .unwrap_err();
        assert!(matches!(null_version_error, GraphStoreError::Payload(_)));
        assert_eq!(store.get_snapshot("snapshot-1").unwrap().unwrap(), before);
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
