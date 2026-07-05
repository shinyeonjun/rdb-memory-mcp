use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GraphStatsRequest {
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphStatsResult {
    pub cache_path: String,
    pub cache_exists: bool,
    pub indexed_snapshots: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IndexDatabaseRequest {
    pub source: String,
    pub path: Option<String>,
    pub connection_string: Option<String>,
    pub alias: String,
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexDatabaseResult {
    pub snapshot_key: String,
    pub tables_indexed: usize,
    pub columns_indexed: usize,
    pub constraints_indexed: usize,
    pub indexes_indexed: usize,
    pub cache_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDatabasesRequest {
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListDatabasesResult {
    pub cache_path: String,
    pub snapshots: Vec<SnapshotSummary>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub snapshot_key: String,
    pub source: Option<String>,
    pub alias: String,
    pub captured_at_unix_ms: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListTablesRequest {
    pub alias: String,
    pub cache_path: Option<String>,
    pub name_filter: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTablesResult {
    pub snapshot_key: String,
    pub tables: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeTableRequest {
    pub alias: String,
    pub table_name: String,
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableDescription {
    pub table: String,
    pub columns: Vec<ColumnDescription>,
    pub primary_key: Vec<String>,
    pub foreign_keys: ForeignKeysDescription,
    pub indexes: Vec<IndexDescription>,
    pub capability_warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnDescription {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignKeysDescription {
    pub outbound: Vec<ForeignKeyDescription>,
    pub inbound: Vec<ForeignKeyDescription>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignKeyDescription {
    pub name: String,
    pub table: String,
    pub columns: Vec<String>,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexDescription {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub primary: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindTableRequest {
    pub alias: String,
    pub query: String,
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindTableResult {
    pub snapshot_key: String,
    pub tables: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindColumnRequest {
    pub alias: String,
    pub query: String,
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindColumnResult {
    pub snapshot_key: String,
    pub columns: Vec<ColumnMatch>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnMatch {
    pub table: String,
    pub column: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImpactAnalysisRequest {
    pub alias: String,
    pub object_key: Option<String>,
    #[serde(default, alias = "table_name")]
    pub table: Option<String>,
    #[serde(default, alias = "column_name")]
    pub column: Option<String>,
    pub direction: String,
    pub max_depth: Option<u32>,
    pub cache_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceRelationshipsRequest {
    pub alias: String,
    #[serde(alias = "start_key")]
    pub start_object_key: String,
    pub direction: String,
    pub max_depth: Option<u32>,
    pub cache_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SchemaDiffRequest {
    pub cache_path: Option<String>,
    pub from_alias: String,
    pub to_alias: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryGraphRequest {
    pub cache_path: Option<String>,
    pub alias: Option<String>,
    pub snapshot_key: Option<String>,
    pub node_label: Option<String>,
    pub node_key_contains: Option<String>,
    pub name_contains: Option<String>,
    pub edge_type: Option<String>,
    pub payload_array_min_len: Option<QueryPayloadArrayMinLen>,
    pub traversal: Option<QueryGraphTraversalRequest>,
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryPayloadArrayMinLen {
    pub field: String,
    pub min_len: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryGraphTraversalRequest {
    pub start_node_key: String,
    pub direction: String,
    pub max_depth: u32,
}
