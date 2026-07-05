use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use database_memory_core::graph_builder::insert_schema_snapshot_graph;
use database_memory_core::graph_query::{
    query_graph as run_query_graph, GraphQuery, GraphQueryResult, GraphQueryTraversal,
    PayloadArrayMinLen,
};
use database_memory_core::graph_store::{GraphNodeRecord, GraphStore};
use database_memory_core::impact_analysis::{
    impact_analysis as run_impact_analysis, Direction, ImpactAnalysisResult,
};
use database_memory_core::relationship_trace::{
    trace_relationships as run_trace_relationships, GraphPath,
};
use database_memory_core::schema_diff::{schema_diff as run_schema_diff, SchemaDiff};
use database_memory_core::{
    capability_warnings, introspect_schema_source, ColumnObject, ConstraintKind, ConstraintObject,
    IndexObject, ObjectKey,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::types::*;

const DEFAULT_CACHE_PATH: &str = ".database-memory/graph.sqlite";
pub(crate) fn index_database_for_request(
    request: IndexDatabaseRequest,
) -> Result<IndexDatabaseResult, String> {
    let cache_path = cache_path(request.cache_path);
    ensure_parent_dir(&cache_path).map_err(|err| err.to_string())?;
    let source_path = request.path.as_deref().map(Path::new);
    let snapshot = introspect_schema_source(
        &request.source,
        source_path,
        request.connection_string.as_deref(),
        &request.alias,
    )?;
    let store = GraphStore::open(&cache_path).map_err(|err| err.to_string())?;
    let snapshot_key = format!("{}:{}", request.source, request.alias);
    insert_schema_snapshot_graph(&store, &snapshot_key, now_unix_ms(), &snapshot)
        .map_err(|err| err.to_string())?;

    Ok(IndexDatabaseResult {
        snapshot_key,
        tables_indexed: snapshot.tables.len(),
        columns_indexed: snapshot.columns.len(),
        constraints_indexed: snapshot.constraints.len(),
        indexes_indexed: snapshot.indexes.len(),
        cache_path: cache_path.display().to_string(),
    })
}

pub(crate) fn list_databases_for_request(
    request: ListDatabasesRequest,
) -> Result<ListDatabasesResult, String> {
    let cache_path = cache_path(request.cache_path);
    if !cache_path.exists() {
        return Ok(ListDatabasesResult {
            cache_path: cache_path.display().to_string(),
            snapshots: vec![],
        });
    }

    let store = GraphStore::open(&cache_path).map_err(|err| err.to_string())?;
    let snapshots = store
        .list_snapshots()
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|snapshot| SnapshotSummary {
            alias: alias_from_snapshot_key(&snapshot.snapshot_key),
            snapshot_key: snapshot.snapshot_key,
            source: snapshot.source,
            captured_at_unix_ms: snapshot.captured_at_unix_ms,
        })
        .collect();

    Ok(ListDatabasesResult {
        cache_path: cache_path.display().to_string(),
        snapshots,
    })
}

pub(crate) fn list_tables_for_request(
    request: ListTablesRequest,
) -> Result<ListTablesResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    let tables = list_table_names(&store, &snapshot_key, request.name_filter.as_deref())?;
    Ok(ListTablesResult {
        snapshot_key,
        tables,
    })
}

pub(crate) fn describe_table_for_request(
    request: DescribeTableRequest,
) -> Result<TableDescription, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    describe_table(&store, &snapshot_key, &request.table_name)
}

pub(crate) fn find_table_for_request(request: FindTableRequest) -> Result<FindTableResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    let tables = list_table_names(&store, &snapshot_key, Some(&request.query))?;
    Ok(FindTableResult {
        snapshot_key,
        tables,
    })
}

pub(crate) fn find_column_for_request(
    request: FindColumnRequest,
) -> Result<FindColumnResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    Ok(FindColumnResult {
        snapshot_key: snapshot_key.clone(),
        columns: find_columns(&store, &snapshot_key, &request.query)?,
    })
}

pub(crate) fn impact_analysis_for_request(request: ImpactAnalysisRequest) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    let direction = parse_direction(&request.direction)?;
    let object_key = resolve_object_key(
        &store,
        &snapshot_key,
        request.object_key.as_deref(),
        request.table.as_deref(),
        request.column.as_deref(),
    )?;
    let result = run_impact_analysis(
        &store,
        &snapshot_key,
        &object_key,
        direction,
        request.max_depth.unwrap_or(3),
    )
    .map_err(|err| err.to_string())?;
    let mut value = impact_json(&result);
    value["capability_warnings"] = json!(snapshot_capability_warnings(&store, &snapshot_key)?);
    Ok(value)
}

pub(crate) fn trace_relationships_for_request(
    request: TraceRelationshipsRequest,
) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = snapshot_key(&request.alias);
    require_snapshot(&store, &snapshot_key)?;
    let direction = parse_direction(&request.direction)?;
    let paths = run_trace_relationships(
        &store,
        &snapshot_key,
        &request.start_object_key,
        direction,
        request.max_depth.unwrap_or(3),
    )
    .map_err(|err| err.to_string())?;
    Ok(json!({
        "snapshot_key": snapshot_key,
        "start_object_key": request.start_object_key,
        "direction": direction_name(direction),
        "max_depth": request.max_depth.unwrap_or(3),
        "paths": graph_paths_json(&paths),
        "capability_warnings": snapshot_capability_warnings(&store, &snapshot_key)?,
    }))
}

pub(crate) fn schema_diff_for_request(request: SchemaDiffRequest) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let from_snapshot_key = snapshot_key(&request.from_alias);
    let to_snapshot_key = snapshot_key(&request.to_alias);
    require_snapshot(&store, &from_snapshot_key)?;
    require_snapshot(&store, &to_snapshot_key)?;
    let diff = run_schema_diff(&store, &from_snapshot_key, &to_snapshot_key)
        .map_err(|err| err.to_string())?;
    Ok(schema_diff_json(&diff))
}

pub(crate) fn query_graph_for_request(
    request: QueryGraphRequest,
) -> Result<GraphQueryResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = request
        .snapshot_key
        .clone()
        .or_else(|| request.alias.as_deref().map(snapshot_key))
        .ok_or("pass snapshot_key or alias")?;
    require_snapshot(&store, &snapshot_key)?;
    let traversal = request
        .traversal
        .map(|traversal| {
            Ok::<_, String>(GraphQueryTraversal {
                start_node_key: traversal.start_node_key,
                direction: parse_direction(&traversal.direction)?,
                max_depth: traversal.max_depth,
            })
        })
        .transpose()?;
    run_query_graph(
        &store,
        &GraphQuery {
            snapshot_key,
            node_label: request.node_label,
            node_key_contains: request.node_key_contains,
            name_contains: request.name_contains,
            edge_type: request.edge_type,
            payload_array_min_len: request
                .payload_array_min_len
                .map(|filter| PayloadArrayMinLen {
                    field: filter.field,
                    min_len: filter.min_len,
                }),
            traversal,
            limit: request.limit,
        },
    )
    .map_err(|err| err.to_string())
}

pub fn graph_stats_for_cache_path(cache_path: impl AsRef<Path>) -> GraphStatsResult {
    let path = cache_path.as_ref();
    let cache_path = path.display().to_string();

    if !path.exists() {
        return GraphStatsResult {
            cache_path,
            cache_exists: false,
            indexed_snapshots: 0,
            error: None,
        };
    }

    match GraphStore::open(path).and_then(|store| store.snapshot_count()) {
        Ok(indexed_snapshots) => GraphStatsResult {
            cache_path,
            cache_exists: true,
            indexed_snapshots,
            error: None,
        },
        Err(err) => GraphStatsResult {
            cache_path,
            cache_exists: true,
            indexed_snapshots: 0,
            error: Some(err.to_string()),
        },
    }
}

fn describe_table(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<TableDescription, String> {
    let table = find_table_node(store, snapshot_key, table_name)?;
    let columns = table_columns(store, snapshot_key, &table.node_key)?;
    let constraints = table_constraints(store, snapshot_key, &table.node_key)?;
    let primary_key = constraints
        .iter()
        .find(|constraint| constraint.kind == ConstraintKind::PrimaryKey)
        .map(|constraint| names_from_keys(&constraint.columns))
        .unwrap_or_default();
    let mut outbound = constraints
        .iter()
        .filter(|constraint| constraint.kind == ConstraintKind::ForeignKey)
        .map(foreign_key_description)
        .collect::<Vec<_>>();
    outbound.sort_by(|left, right| left.name.cmp(&right.name));

    let mut inbound_keys = BTreeSet::new();
    for column in &columns {
        for edge in store
            .edges_to(snapshot_key, &column.key.to_string())
            .map_err(|err| err.to_string())?
        {
            if edge.edge_type == "FK_TO_COLUMN" {
                inbound_keys.insert(edge.edge_from);
            }
        }
    }
    let mut inbound = Vec::new();
    for key in inbound_keys {
        let node = required_node(store, snapshot_key, &key)?;
        inbound.push(foreign_key_description(&foreign_key_from_node(&node)?));
    }
    inbound.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(TableDescription {
        table: table_name.to_owned(),
        columns: columns
            .into_iter()
            .map(|column| ColumnDescription {
                name: column.name,
                data_type: column.data_type,
                nullable: column.is_nullable,
            })
            .collect(),
        primary_key,
        foreign_keys: ForeignKeysDescription { outbound, inbound },
        indexes: table_indexes(store, snapshot_key, &table.node_key)?
            .into_iter()
            .map(|index| IndexDescription {
                name: index.name,
                columns: names_from_keys(&index.columns),
                unique: index.is_unique,
                primary: index.is_primary,
            })
            .collect(),
        capability_warnings: snapshot_capability_warnings(store, snapshot_key)?,
    })
}

fn list_table_names(
    store: &GraphStore,
    snapshot_key: &str,
    filter: Option<&str>,
) -> Result<Vec<String>, String> {
    let needle = filter.map(str::to_lowercase);
    let mut tables = Vec::new();
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        let name = object_key(&node)?.object_name;
        if needle
            .as_ref()
            .map(|needle| name.to_lowercase().contains(needle))
            .unwrap_or(true)
        {
            tables.push(name);
        }
    }
    tables.sort();
    Ok(tables)
}

fn find_columns(
    store: &GraphStore,
    snapshot_key: &str,
    query: &str,
) -> Result<Vec<ColumnMatch>, String> {
    let needle = query.to_lowercase();
    let mut columns = Vec::new();
    for node in store
        .nodes_by_label(snapshot_key, "Column")
        .map_err(|err| err.to_string())?
    {
        let key = object_key(&node)?;
        let column = key
            .sub_object
            .clone()
            .unwrap_or_else(|| key.object_name.clone());
        if column.to_lowercase().contains(&needle) {
            columns.push(ColumnMatch {
                table: key.object_name,
                column,
            });
        }
    }
    columns.sort_by(|left, right| {
        left.table
            .cmp(&right.table)
            .then_with(|| left.column.cmp(&right.column))
    });
    Ok(columns)
}

fn find_table_node(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<GraphNodeRecord, String> {
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        if object_key(&node)?.object_name == table_name {
            return Ok(node);
        }
    }
    Err(format!(
        "table '{table_name}' not found in snapshot '{snapshot_key}'"
    ))
}

fn table_columns(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<ColumnObject>, String> {
    let mut columns = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_COLUMN" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            columns.push(column_from_node(&node)?);
        }
    }
    columns.sort_by_key(|column| column.ordinal_position);
    Ok(columns)
}

fn table_constraints(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<ConstraintObject>, String> {
    let mut constraints = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_CONSTRAINT" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            constraints.push(constraint_from_node(&node)?);
        }
    }
    Ok(constraints)
}

fn table_indexes(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<IndexObject>, String> {
    let mut indexes = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_INDEX" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            indexes.push(index_from_node(&node)?);
        }
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

fn resolve_object_key(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: Option<&str>,
    table: Option<&str>,
    column: Option<&str>,
) -> Result<String, String> {
    if let Some(object_key) = object_key {
        return Ok(object_key.to_owned());
    }

    match (table, column) {
        (Some(table), Some(column)) => {
            let table_name = table;
            let table = find_table_node(store, snapshot_key, table_name)?;
            for column_object in table_columns(store, snapshot_key, &table.node_key)? {
                if column_object.name == column {
                    return Ok(column_object.key.to_string());
                }
            }
            Err(format!(
                "column '{column}' not found on table '{table_name}'"
            ))
        }
        (Some(table), None) => Ok(find_table_node(store, snapshot_key, table)?.node_key),
        (None, Some(column)) => {
            let matches = find_columns(store, snapshot_key, column)?
                .into_iter()
                .filter(|item| item.column == column)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [item] => Ok(ObjectKey::new(
                    "sqlite",
                    alias_from_snapshot_key(snapshot_key),
                    "main",
                    "main",
                    database_memory_core::ObjectKind::Column,
                    item.table.clone(),
                    Some(item.column.clone()),
                )
                .to_string()),
                [] => Err(format!(
                    "column '{column}' not found in snapshot '{snapshot_key}'"
                )),
                _ => Err(format!(
                    "column '{column}' is ambiguous; pass table and column together"
                )),
            }
        }
        (None, None) => Err("pass object_key, table, or table plus column".to_owned()),
    }
}

fn required_node(
    store: &GraphStore,
    snapshot_key: &str,
    node_key: &str,
) -> Result<GraphNodeRecord, String> {
    store
        .get_node(snapshot_key, node_key)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("graph node '{node_key}' not found"))
}

fn object_key(node: &GraphNodeRecord) -> Result<ObjectKey, String> {
    node.node_key
        .parse()
        .map_err(|err| format!("invalid graph node key '{}': {err}", node.node_key))
}

fn column_from_node(node: &GraphNodeRecord) -> Result<ColumnObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn constraint_from_node(node: &GraphNodeRecord) -> Result<ConstraintObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn foreign_key_from_node(node: &GraphNodeRecord) -> Result<ConstraintObject, String> {
    let constraint = constraint_from_node(node)?;
    if constraint.kind == ConstraintKind::ForeignKey {
        Ok(constraint)
    } else {
        Err(format!(
            "graph node '{}' is not a foreign key",
            node.node_key
        ))
    }
}

fn index_from_node(node: &GraphNodeRecord) -> Result<IndexObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn old_cache_error(node: &GraphNodeRecord) -> String {
    format!(
        "graph node '{}' is missing metadata payload; re-run index for this alias",
        node.node_key
    )
}

fn foreign_key_description(constraint: &ConstraintObject) -> ForeignKeyDescription {
    ForeignKeyDescription {
        name: constraint.name.clone(),
        table: constraint.table_key.object_name.clone(),
        columns: names_from_keys(&constraint.columns),
        referenced_table: constraint
            .referenced_table_key
            .as_ref()
            .map(|key| key.object_name.clone())
            .unwrap_or_default(),
        referenced_columns: names_from_keys(&constraint.referenced_columns),
    }
}

fn names_from_keys(keys: &[ObjectKey]) -> Vec<String> {
    keys.iter()
        .map(|key| {
            key.sub_object
                .clone()
                .unwrap_or_else(|| key.object_name.clone())
        })
        .collect()
}

fn open_existing_store(cache_path: &Path) -> Result<GraphStore, String> {
    if !cache_path.exists() {
        return Err(format!(
            "cache path '{}' not found; run index first",
            cache_path.display()
        ));
    }
    GraphStore::open(cache_path).map_err(|err| err.to_string())
}

fn require_snapshot(store: &GraphStore, snapshot_key: &str) -> Result<(), String> {
    store
        .get_snapshot(snapshot_key)
        .map_err(|err| err.to_string())?
        .map(|_| ())
        .ok_or_else(|| format!("snapshot '{snapshot_key}' not found in cache; run index first"))
}

fn snapshot_capability_warnings(
    store: &GraphStore,
    snapshot_key: &str,
) -> Result<Vec<String>, String> {
    store
        .get_snapshot_capabilities(snapshot_key)
        .map_err(|err| err.to_string())?
        .map(|capabilities| capability_warnings(&capabilities))
        .ok_or_else(|| format!("snapshot '{snapshot_key}' not found in cache; run index first"))
}

fn cache_path(cache_path: Option<String>) -> PathBuf {
    cache_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_PATH))
}

fn snapshot_key(alias: &str) -> String {
    if alias.contains(':') {
        alias.to_owned()
    } else {
        format!("sqlite:{alias}")
    }
}

fn alias_from_snapshot_key(snapshot_key: &str) -> String {
    snapshot_key
        .split_once(':')
        .map(|(_, alias)| alias.to_owned())
        .unwrap_or_else(|| snapshot_key.to_owned())
}

fn parse_direction(direction: &str) -> Result<Direction, String> {
    match direction {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        "both" => Ok(Direction::Both),
        _ => Err(format!(
            "unknown direction '{direction}'; expected inbound, outbound, or both"
        )),
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
        Direction::Both => "both",
    }
}

fn node_json(node: &GraphNodeRecord) -> Value {
    json!({
        "snapshot_key": &node.snapshot_key,
        "node_key": &node.node_key,
        "label": &node.label,
        "display_name": &node.display_name,
        "payload": serde_json::from_str::<Value>(&node.payload_json).unwrap_or(Value::Null),
    })
}

fn edge_json(edge: &database_memory_core::graph_store::GraphEdgeRecord) -> Value {
    json!({
        "snapshot_key": &edge.snapshot_key,
        "edge_key": &edge.edge_key,
        "edge_from": &edge.edge_from,
        "edge_to": &edge.edge_to,
        "edge_type": &edge.edge_type,
        "payload": serde_json::from_str::<Value>(&edge.payload_json).unwrap_or(Value::Null),
    })
}

fn impact_json(result: &ImpactAnalysisResult) -> Value {
    json!({
        "snapshot_key": &result.snapshot_key,
        "object_key": &result.object_key,
        "direction": direction_name(result.direction),
        "max_depth": result.max_depth,
        "groups": result.groups.iter().map(|group| json!({
            "label": &group.label,
            "depth": group.depth,
            "nodes": group.nodes.iter().map(|node| json!({
                "node_key": &node.node_key,
                "label": &node.label,
                "display_name": &node.display_name,
                "depth": node.depth,
                "edge_type_used": &node.edge_type_used,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn graph_paths_json(paths: &[GraphPath]) -> Vec<Value> {
    paths
        .iter()
        .map(|path| {
            json!({
                "hops": path.hops.iter().map(|hop| json!({
                    "node_key": &hop.node_key,
                    "label": &hop.label,
                    "edge_type_used": &hop.edge_type_used,
                })).collect::<Vec<_>>()
            })
        })
        .collect()
}

fn schema_diff_json(diff: &SchemaDiff) -> Value {
    json!({
        "from_snapshot_key": &diff.from_snapshot_key,
        "to_snapshot_key": &diff.to_snapshot_key,
        "added_nodes": diff.added_nodes.iter().map(node_json).collect::<Vec<_>>(),
        "removed_nodes": diff.removed_nodes.iter().map(node_json).collect::<Vec<_>>(),
        "changed_nodes": diff.changed_nodes.iter().map(|changed| json!({
            "from": node_json(&changed.from),
            "to": node_json(&changed.to),
        })).collect::<Vec<_>>(),
        "added_edges": diff.added_edges.iter().map(edge_json).collect::<Vec<_>>(),
        "removed_edges": diff.removed_edges.iter().map(edge_json).collect::<Vec<_>>(),
        "impacted": diff.impacted.iter().map(|impact| json!({
            "seed_node_key": &impact.seed_node_key,
            "snapshot_key": &impact.snapshot_key,
            "impact": impact_json(&impact.impact),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn tool_json<T: Serialize>(result: Result<T, String>) -> String {
    let value = match result {
        Ok(value) => serde_json::to_value(value).expect("tool result should serialize"),
        Err(error) => json!({ "error": error }),
    };
    serde_json::to_string(&value).expect("tool result should serialize")
}

fn ensure_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
