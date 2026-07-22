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
    #[serde(default)]
    pub requested_catalogs: Vec<String>,
    #[serde(default)]
    pub requested_schemas: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub cache_path: Option<String>,
}

pub type IndexDatabaseResult = database_memory_core::interface_contract::IndexResult;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDatabasesRequest {
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListDatabasesResult {
    pub cache_path: String,
    pub snapshots: Vec<SnapshotSummary>,
}

pub type SnapshotSummary = database_memory_core::interface_contract::SnapshotSummary;

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GetContractRequest {}

pub type GetContractResult = database_memory_core::interface_contract::ProductContract;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListSnapshotsRequest {
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSnapshotsResult {
    pub contract_version: u32,
    pub cache_path: String,
    pub snapshots: Vec<SnapshotSummary>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeSnapshotRequest {
    #[serde(alias = "alias")]
    pub snapshot: String,
    pub cache_path: Option<String>,
}

pub type DescribeSnapshotResult = database_memory_core::interface_contract::SnapshotDetail;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListObjectsRequest {
    #[serde(alias = "alias")]
    pub snapshot: String,
    pub kind: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub cache_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindObjectsRequest {
    #[serde(alias = "alias")]
    pub snapshot: String,
    pub query: String,
    pub kind: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub cache_path: Option<String>,
}

pub type ObjectsResult = database_memory_core::interface_contract::ObjectPage;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeObjectRequest {
    #[serde(alias = "alias")]
    pub snapshot: String,
    pub object_key: String,
    pub relationship_limit: Option<usize>,
    pub cache_path: Option<String>,
}

pub type DescribeObjectResult = database_memory_core::interface_contract::ObjectDetail;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListTablesRequest {
    pub alias: String,
    pub cache_path: Option<String>,
    pub name_filter: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTablesResult {
    pub snapshot_key: String,
    pub tables: Vec<String>,
    pub table_matches: Vec<TableMatch>,
    pub page: PageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableMatch {
    pub object_key: String,
    pub database: String,
    pub schema: String,
    pub table: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageMetadata {
    pub total: usize,
    pub offset: usize,
    pub limit_requested: usize,
    pub limit_applied: usize,
    pub limit_clamped: bool,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DescribeTableRequest {
    pub alias: String,
    pub table_name: String,
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableDescription {
    pub snapshot_key: String,
    pub object_key: String,
    pub database: String,
    pub schema: String,
    pub table: String,
    pub columns: Vec<ColumnDescription>,
    pub primary_key: Vec<String>,
    pub primary_key_keys: Vec<String>,
    pub constraints: Vec<ConstraintDescription>,
    pub foreign_keys: ForeignKeysDescription,
    pub indexes: Vec<IndexDescription>,
    pub capability_warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnDescription {
    pub object_key: String,
    pub name: String,
    pub ordinal_position: u32,
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
    pub default_value: Option<String>,
    pub generated: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintDescription {
    pub object_key: String,
    pub name: String,
    pub kind: String,
    pub column_keys: Vec<String>,
    pub columns: Vec<String>,
    pub referenced_table_key: Option<String>,
    pub referenced_column_keys: Vec<String>,
    pub expression: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignKeysDescription {
    pub outbound: Vec<ForeignKeyDescription>,
    pub inbound: Vec<ForeignKeyDescription>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForeignKeyDescription {
    pub object_key: String,
    pub name: String,
    pub table_key: String,
    pub table: String,
    pub column_keys: Vec<String>,
    pub columns: Vec<String>,
    pub referenced_table_key: Option<String>,
    pub referenced_table: String,
    pub referenced_column_keys: Vec<String>,
    pub referenced_columns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexDescription {
    pub object_key: String,
    pub name: String,
    pub column_keys: Vec<String>,
    pub columns: Vec<String>,
    pub unique: bool,
    pub primary: bool,
    pub predicate: Option<String>,
    pub expression: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindTableRequest {
    pub alias: String,
    pub query: String,
    pub cache_path: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindTableResult {
    pub snapshot_key: String,
    pub tables: Vec<String>,
    pub table_matches: Vec<TableMatch>,
    pub page: PageMetadata,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindColumnRequest {
    pub alias: String,
    pub query: String,
    pub cache_path: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindColumnResult {
    pub snapshot_key: String,
    pub columns: Vec<ColumnMatch>,
    pub page: PageMetadata,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnMatch {
    pub object_key: String,
    pub table_key: String,
    pub database: String,
    pub schema: String,
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
    #[serde(default, alias = "limit")]
    pub result_limit: Option<usize>,
    pub cache_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceRelationshipsRequest {
    pub alias: String,
    #[serde(alias = "start_key")]
    pub start_object_key: String,
    pub direction: String,
    pub max_depth: Option<u32>,
    #[serde(default, alias = "limit")]
    pub result_limit: Option<usize>,
    pub cache_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SchemaDiffRequest {
    pub cache_path: Option<String>,
    pub from_alias: String,
    pub to_alias: String,
    #[serde(default, alias = "limit")]
    pub result_limit: Option<usize>,
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
