mod tools;
mod types;

#[cfg(test)]
mod tools_tests;

pub use tools::graph_stats_for_cache_path;
pub use types::*;

use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use tools::{
    describe_object_for_request, describe_snapshot_for_request, describe_table_for_request,
    find_column_for_request, find_objects_for_request, find_table_for_request,
    get_contract_for_request, graph_stats_for_cache_path as graph_stats,
    impact_analysis_for_request, index_database_for_request, list_databases_for_request,
    list_objects_for_request, list_snapshots_for_request, list_tables_for_request,
    query_graph_for_request, schema_diff_for_request, tool_json, trace_relationships_for_request,
};

#[derive(Debug, Clone, Default)]
pub struct DatabaseMemoryMcp;

#[tool_router(server_handler)]
impl DatabaseMemoryMcp {
    pub fn new() -> Self {
        Self
    }

    #[tool(description = "Return the exact metadata-only product contract and support ledger")]
    pub fn get_contract(
        &self,
        Parameters(request): Parameters<GetContractRequest>,
    ) -> Result<String, String> {
        tool_json::<_, String>(Ok(get_contract_for_request(request)))
    }

    #[tool(description = "Index database schema metadata into the local graph cache")]
    pub fn index_database(
        &self,
        Parameters(request): Parameters<IndexDatabaseRequest>,
    ) -> Result<String, String> {
        tool_json(index_database_for_request(request))
    }

    #[tool(description = "List indexed database snapshots in a graph cache")]
    pub fn list_databases(
        &self,
        Parameters(request): Parameters<ListDatabasesRequest>,
    ) -> Result<String, String> {
        tool_json(list_databases_for_request(request))
    }

    #[tool(description = "List snapshots with complete or legacy-non-authoritative status")]
    pub fn list_snapshots(
        &self,
        Parameters(request): Parameters<ListSnapshotsRequest>,
    ) -> Result<String, String> {
        tool_json(list_snapshots_for_request(request))
    }

    #[tool(
        description = "Describe one snapshot and return its completeness proof when authoritative"
    )]
    pub fn describe_snapshot(
        &self,
        Parameters(request): Parameters<DescribeSnapshotRequest>,
    ) -> Result<String, String> {
        tool_json(describe_snapshot_for_request(request))
    }

    #[tool(description = "List any canonical database object kind with bounded pagination")]
    pub fn list_objects(
        &self,
        Parameters(request): Parameters<ListObjectsRequest>,
    ) -> Result<String, String> {
        tool_json(list_objects_for_request(request))
    }

    #[tool(description = "Find any canonical database object kind by stable identity or name")]
    pub fn find_objects(
        &self,
        Parameters(request): Parameters<FindObjectsRequest>,
    ) -> Result<String, String> {
        tool_json(find_objects_for_request(request))
    }

    #[tool(
        description = "Describe one canonical object and its bounded incoming/outgoing relationships"
    )]
    pub fn describe_object(
        &self,
        Parameters(request): Parameters<DescribeObjectRequest>,
    ) -> Result<String, String> {
        tool_json(describe_object_for_request(request))
    }

    #[tool(description = "List table names for an indexed database alias")]
    pub fn list_tables(
        &self,
        Parameters(request): Parameters<ListTablesRequest>,
    ) -> Result<String, String> {
        tool_json(list_tables_for_request(request))
    }

    #[tool(description = "Describe one indexed table from graph metadata")]
    pub fn describe_table(
        &self,
        Parameters(request): Parameters<DescribeTableRequest>,
    ) -> Result<String, String> {
        tool_json(describe_table_for_request(request))
    }

    #[tool(description = "Find indexed tables by substring")]
    pub fn find_table(
        &self,
        Parameters(request): Parameters<FindTableRequest>,
    ) -> Result<String, String> {
        tool_json(find_table_for_request(request))
    }

    #[tool(description = "Find indexed columns by substring")]
    pub fn find_column(
        &self,
        Parameters(request): Parameters<FindColumnRequest>,
    ) -> Result<String, String> {
        tool_json(find_column_for_request(request))
    }

    #[tool(description = "Analyze graph impact from an indexed table, column, or object key")]
    pub fn impact_analysis(
        &self,
        Parameters(request): Parameters<ImpactAnalysisRequest>,
    ) -> Result<String, String> {
        tool_json(impact_analysis_for_request(request))
    }

    #[tool(description = "Trace relationship paths from an indexed object key")]
    pub fn trace_relationships(
        &self,
        Parameters(request): Parameters<TraceRelationshipsRequest>,
    ) -> Result<String, String> {
        tool_json(trace_relationships_for_request(request))
    }

    #[tool(description = "Diff two indexed schema snapshots")]
    pub fn schema_diff(
        &self,
        Parameters(request): Parameters<SchemaDiffRequest>,
    ) -> Result<String, String> {
        tool_json(schema_diff_for_request(request))
    }

    #[tool(description = "Run a constrained read-only JSON query over indexed graph metadata")]
    pub fn query_graph(
        &self,
        Parameters(request): Parameters<QueryGraphRequest>,
    ) -> Result<String, String> {
        tool_json(query_graph_for_request(request))
    }

    #[tool(description = "Return basic stats for a database-memory graph cache")]
    pub fn graph_stats(
        &self,
        Parameters(request): Parameters<GraphStatsRequest>,
    ) -> Result<String, String> {
        let cache_path = request
            .cache_path
            .as_deref()
            .unwrap_or(".database-memory/graph.sqlite");
        tool_json::<_, String>(Ok(graph_stats(cache_path)))
    }
}
