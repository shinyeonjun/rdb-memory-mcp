use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use database_memory_core::graph_query::{
    query_graph as run_query_graph, GraphQuery, GraphQueryResult, GraphQueryTraversal,
    PayloadArrayMinLen,
};
use database_memory_core::graph_store::{GraphNodeRecord, GraphStore};
use database_memory_core::impact_analysis::{
    impact_analysis_bounded as run_impact_analysis, Direction, ImpactAnalysisResult,
};
use database_memory_core::interface_contract::{
    describe_object as describe_generic_object, describe_snapshot, index_complete_source,
    list_objects as list_generic_objects, list_snapshot_summaries, product_contract,
    CompleteIndexRequest, InterfaceError, InterfaceStage, DEFAULT_TIMEOUT_MS,
    INTERFACE_CONTRACT_VERSION,
};
use database_memory_core::relationship_trace::{
    trace_relationships_bounded as run_trace_relationships, GraphPath,
};
use database_memory_core::schema_diff::{
    schema_diff_bounded as run_schema_diff, BoundedSchemaDiff,
};
use database_memory_core::{
    capability_warnings, ColumnObject, ConstraintKind, ConstraintObject, IndexObject, ObjectKey,
    ObjectKind,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::types::*;

const DEFAULT_CACHE_PATH: &str = ".database-memory/graph.sqlite";
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const DEFAULT_TRAVERSAL_DEPTH: u32 = 3;
const MAX_TRAVERSAL_DEPTH: u32 = 8;
const DEFAULT_RESULT_LIMIT: usize = 100;
const MAX_RESULT_LIMIT: usize = 200;

struct Page<T> {
    items: Vec<T>,
    metadata: PageMetadata,
}

pub(crate) fn index_database_for_request(
    request: IndexDatabaseRequest,
) -> Result<IndexDatabaseResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    ensure_parent_dir(&cache_path)
        .map_err(|error| InterfaceError::storage("could not create cache directory", error))?;
    let mut complete = CompleteIndexRequest::new(
        request.source,
        request.path.map(PathBuf::from),
        request.connection_string,
        request.alias,
    );
    complete.requested_catalogs = request.requested_catalogs;
    complete.requested_schemas = request.requested_schemas;
    complete.timeout_ms = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let store = GraphStore::open(&cache_path)
        .map_err(|error| InterfaceError::storage("could not open graph cache", error))?;
    index_complete_source(
        &store,
        &complete,
        now_unix_ms(),
        cache_path.display().to_string(),
    )
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
    let snapshots = list_snapshot_summaries(&store).map_err(|error| error.to_string())?;

    Ok(ListDatabasesResult {
        cache_path: cache_path.display().to_string(),
        snapshots,
    })
}

pub(crate) fn get_contract_for_request(_: GetContractRequest) -> GetContractResult {
    product_contract()
}

pub(crate) fn list_snapshots_for_request(
    request: ListSnapshotsRequest,
) -> Result<ListSnapshotsResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    if !cache_path.exists() {
        return Ok(ListSnapshotsResult {
            contract_version: INTERFACE_CONTRACT_VERSION,
            cache_path: cache_path.display().to_string(),
            snapshots: Vec::new(),
        });
    }
    let store = GraphStore::open(&cache_path)
        .map_err(|error| InterfaceError::storage("could not open graph cache", error))?;
    Ok(ListSnapshotsResult {
        contract_version: INTERFACE_CONTRACT_VERSION,
        cache_path: cache_path.display().to_string(),
        snapshots: list_snapshot_summaries(&store)?,
    })
}

pub(crate) fn describe_snapshot_for_request(
    request: DescribeSnapshotRequest,
) -> Result<DescribeSnapshotResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_contract_store(&cache_path)?;
    describe_snapshot(&store, &request.snapshot)
}

pub(crate) fn list_objects_for_request(
    request: ListObjectsRequest,
) -> Result<ObjectsResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_contract_store(&cache_path)?;
    list_generic_objects(
        &store,
        &request.snapshot,
        parse_object_kind(request.kind.as_deref())?,
        None,
        request.offset.unwrap_or(0),
        request.limit,
    )
}

pub(crate) fn find_objects_for_request(
    request: FindObjectsRequest,
) -> Result<ObjectsResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_contract_store(&cache_path)?;
    list_generic_objects(
        &store,
        &request.snapshot,
        parse_object_kind(request.kind.as_deref())?,
        Some(&request.query),
        request.offset.unwrap_or(0),
        request.limit,
    )
}

pub(crate) fn describe_object_for_request(
    request: DescribeObjectRequest,
) -> Result<DescribeObjectResult, InterfaceError> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_contract_store(&cache_path)?;
    describe_generic_object(
        &store,
        &request.snapshot,
        &request.object_key,
        request.relationship_limit,
    )
}

fn parse_object_kind(kind: Option<&str>) -> Result<Option<ObjectKind>, InterfaceError> {
    kind.map(|kind| {
        kind.parse().map_err(|_| {
            InterfaceError::invalid_request(
                InterfaceStage::ObjectLookup,
                format!("unknown object kind '{kind}'"),
                "use an object kind listed by get_contract",
            )
        })
    })
    .transpose()
}

fn open_existing_contract_store(cache_path: &Path) -> Result<GraphStore, InterfaceError> {
    if !cache_path.exists() {
        return Err(InterfaceError::invalid_request(
            InterfaceStage::SnapshotLookup,
            format!("cache path '{}' was not found", cache_path.display()),
            "run index_database first or provide an existing cache_path",
        ));
    }
    GraphStore::open(cache_path)
        .map_err(|error| InterfaceError::storage("could not open graph cache", error))
}

pub(crate) fn list_tables_for_request(
    request: ListTablesRequest,
) -> Result<ListTablesResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    let page = paginate(
        find_tables(&store, &snapshot_key, request.name_filter.as_deref())?,
        request.offset,
        request.limit,
    )?;
    let tables = page.items.iter().map(|item| item.table.clone()).collect();
    Ok(ListTablesResult {
        snapshot_key,
        tables,
        table_matches: page.items,
        page: page.metadata,
    })
}

pub(crate) fn describe_table_for_request(
    request: DescribeTableRequest,
) -> Result<TableDescription, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    describe_table(&store, &snapshot_key, &request.table_name)
}

pub(crate) fn find_table_for_request(request: FindTableRequest) -> Result<FindTableResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    let page = paginate(
        find_tables(&store, &snapshot_key, Some(&request.query))?,
        request.offset,
        request.limit,
    )?;
    let tables = page.items.iter().map(|item| item.table.clone()).collect();
    Ok(FindTableResult {
        snapshot_key,
        tables,
        table_matches: page.items,
        page: page.metadata,
    })
}

pub(crate) fn find_column_for_request(
    request: FindColumnRequest,
) -> Result<FindColumnResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    let page = paginate(
        find_columns(&store, &snapshot_key, &request.query)?,
        request.offset,
        request.limit,
    )?;
    Ok(FindColumnResult {
        snapshot_key: snapshot_key.clone(),
        columns: page.items,
        page: page.metadata,
    })
}

pub(crate) fn impact_analysis_for_request(request: ImpactAnalysisRequest) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    let direction = parse_direction(&request.direction)?;
    let object_key = resolve_object_key(
        &store,
        &snapshot_key,
        request.object_key.as_deref(),
        request.table.as_deref(),
        request.column.as_deref(),
    )?;
    let max_depth_requested = request.max_depth.unwrap_or(DEFAULT_TRAVERSAL_DEPTH);
    let max_depth_applied = max_depth_requested.min(MAX_TRAVERSAL_DEPTH);
    let result_limit_requested = request.result_limit.unwrap_or(DEFAULT_RESULT_LIMIT);
    let result_limit_applied = result_limit_requested.min(MAX_RESULT_LIMIT);
    let bounded = run_impact_analysis(
        &store,
        &snapshot_key,
        &object_key,
        direction,
        max_depth_applied,
        result_limit_applied,
    )
    .map_err(|err| err.to_string())?;
    let result_count = bounded
        .result
        .groups
        .iter()
        .map(|group| group.nodes.len())
        .sum::<usize>();
    let mut value = impact_json(&bounded.result);
    value["max_depth_requested"] = json!(max_depth_requested);
    value["max_depth_applied"] = json!(max_depth_applied);
    value["max_depth_clamped"] = json!(max_depth_requested != max_depth_applied);
    value["result_limit_requested"] = json!(result_limit_requested);
    value["result_limit_applied"] = json!(result_limit_applied);
    value["result_limit_clamped"] = json!(result_limit_requested != result_limit_applied);
    value["result_count"] = json!(result_count);
    value["truncated"] = json!(bounded.truncated);
    value["capability_warnings"] = json!(snapshot_capability_warnings(&store, &snapshot_key)?);
    Ok(value)
}

pub(crate) fn trace_relationships_for_request(
    request: TraceRelationshipsRequest,
) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = resolve_snapshot_key(&store, &request.alias)?;
    require_snapshot(&store, &snapshot_key)?;
    let direction = parse_direction(&request.direction)?;
    required_node(&store, &snapshot_key, &request.start_object_key)?;
    let max_depth_requested = request.max_depth.unwrap_or(DEFAULT_TRAVERSAL_DEPTH);
    let max_depth_applied = max_depth_requested.min(MAX_TRAVERSAL_DEPTH);
    let result_limit_requested = request.result_limit.unwrap_or(DEFAULT_RESULT_LIMIT);
    let result_limit_applied = result_limit_requested.min(MAX_RESULT_LIMIT);
    let bounded = run_trace_relationships(
        &store,
        &snapshot_key,
        &request.start_object_key,
        direction,
        max_depth_applied,
        result_limit_applied,
    )
    .map_err(|err| err.to_string())?;
    Ok(json!({
        "snapshot_key": snapshot_key,
        "start_object_key": request.start_object_key,
        "direction": direction_name(direction),
        "max_depth": max_depth_applied,
        "max_depth_requested": max_depth_requested,
        "max_depth_applied": max_depth_applied,
        "max_depth_clamped": max_depth_requested != max_depth_applied,
        "result_limit_requested": result_limit_requested,
        "result_limit_applied": result_limit_applied,
        "result_limit_clamped": result_limit_requested != result_limit_applied,
        "result_count": bounded.paths.len(),
        "truncated": bounded.truncated,
        "paths": graph_paths_json(&bounded.paths),
        "capability_warnings": snapshot_capability_warnings(&store, &snapshot_key)?,
    }))
}

pub(crate) fn schema_diff_for_request(request: SchemaDiffRequest) -> Result<Value, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let from_snapshot_key = resolve_snapshot_key(&store, &request.from_alias)?;
    let to_snapshot_key = resolve_snapshot_key(&store, &request.to_alias)?;
    require_snapshot(&store, &from_snapshot_key)?;
    require_snapshot(&store, &to_snapshot_key)?;
    let result_limit_requested = request.result_limit.unwrap_or(DEFAULT_RESULT_LIMIT);
    if result_limit_requested == 0 {
        return Err("result_limit must be greater than zero".to_owned());
    }
    let result_limit_applied = result_limit_requested.min(MAX_RESULT_LIMIT);
    let diff = run_schema_diff(
        &store,
        &from_snapshot_key,
        &to_snapshot_key,
        result_limit_applied,
    )
    .map_err(|err| err.to_string())?;
    Ok(schema_diff_json(
        &diff,
        result_limit_requested,
        result_limit_applied,
    ))
}

pub(crate) fn query_graph_for_request(
    request: QueryGraphRequest,
) -> Result<GraphQueryResult, String> {
    let cache_path = cache_path(request.cache_path);
    let store = open_existing_store(&cache_path)?;
    let snapshot_key = match (request.snapshot_key.clone(), request.alias.as_deref()) {
        (Some(snapshot_key), _) => snapshot_key,
        (None, Some(alias)) => resolve_snapshot_key(&store, alias)?,
        (None, None) => return Err("pass snapshot_key or alias".to_owned()),
    };
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
    if let Some(traversal) = &traversal {
        required_node(&store, &snapshot_key, &traversal.start_node_key)?;
    }
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
    let table_identity = object_key(&table)?;
    let columns = table_columns(store, snapshot_key, &table.node_key)?;
    let constraints = table_constraints(store, snapshot_key, &table.node_key)?;
    let primary_key_columns = constraints
        .iter()
        .find(|constraint| constraint.kind == ConstraintKind::PrimaryKey)
        .map(|constraint| constraint.columns.as_slice())
        .unwrap_or_default();
    let primary_key = names_from_keys(primary_key_columns);
    let primary_key_keys = string_keys(primary_key_columns);
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
        snapshot_key: snapshot_key.to_owned(),
        object_key: table.node_key.clone(),
        database: table_identity.database,
        schema: table_identity.schema,
        table: table_identity.object_name,
        columns: columns
            .into_iter()
            .map(|column| ColumnDescription {
                object_key: column.key.to_string(),
                name: column.name,
                ordinal_position: column.ordinal_position,
                data_type: column.data_type,
                nullable: column.is_nullable,
                default_value: column.default_value,
                generated: column.is_generated,
            })
            .collect(),
        primary_key,
        primary_key_keys,
        constraints: constraints.iter().map(constraint_description).collect(),
        foreign_keys: ForeignKeysDescription { outbound, inbound },
        indexes: table_indexes(store, snapshot_key, &table.node_key)?
            .into_iter()
            .map(|index| IndexDescription {
                object_key: index.key.to_string(),
                name: index.name,
                column_keys: string_keys(&index.columns),
                columns: names_from_keys(&index.columns),
                unique: index.is_unique,
                primary: index.is_primary,
                predicate: index.predicate,
                expression: index.expression,
            })
            .collect(),
        capability_warnings: snapshot_capability_warnings(store, snapshot_key)?,
    })
}

fn find_tables(
    store: &GraphStore,
    snapshot_key: &str,
    filter: Option<&str>,
) -> Result<Vec<TableMatch>, String> {
    let needle = filter.map(str::to_lowercase);
    let mut tables = Vec::new();
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        let key = object_key(&node)?;
        if needle
            .as_ref()
            .map(|needle| key.object_name.to_lowercase().contains(needle))
            .unwrap_or(true)
        {
            tables.push(TableMatch {
                object_key: node.node_key,
                database: key.database,
                schema: key.schema,
                table: key.object_name,
            });
        }
    }
    tables.sort_by(|left, right| {
        left.database
            .cmp(&right.database)
            .then_with(|| left.schema.cmp(&right.schema))
            .then_with(|| left.table.cmp(&right.table))
            .then_with(|| left.object_key.cmp(&right.object_key))
    });
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
            let table_key = ObjectKey::new(
                key.source_kind.clone(),
                key.connection_alias.clone(),
                key.database.clone(),
                key.schema.clone(),
                ObjectKind::Table,
                key.object_name.clone(),
                None,
            )
            .to_string();
            columns.push(ColumnMatch {
                object_key: node.node_key,
                table_key,
                database: key.database,
                schema: key.schema,
                table: key.object_name,
                column,
            });
        }
    }
    columns.sort_by(|left, right| {
        left.database
            .cmp(&right.database)
            .then_with(|| left.schema.cmp(&right.schema))
            .then_with(|| left.table.cmp(&right.table))
            .then_with(|| left.column.cmp(&right.column))
            .then_with(|| left.object_key.cmp(&right.object_key))
    });
    Ok(columns)
}

fn find_table_node(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<GraphNodeRecord, String> {
    if let Some(node) = store
        .get_node(snapshot_key, table_name)
        .map_err(|err| err.to_string())?
    {
        if node.label == "Table" {
            return Ok(node);
        }
        return Err(format!("graph node '{table_name}' is not a table"));
    }

    let mut matches = store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter_map(|node| match object_key(&node) {
            Ok(key) if key.object_name == table_name => Some(Ok(node)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    matches.sort_by(|left, right| left.node_key.cmp(&right.node_key));

    match matches.len() {
        0 => Err(format!(
            "table '{table_name}' not found in snapshot '{snapshot_key}'"
        )),
        1 => Ok(matches.remove(0)),
        _ => Err(format!(
            "table '{table_name}' is ambiguous in snapshot '{snapshot_key}'; pass one object key: {}",
            matches
                .iter()
                .map(|node| node.node_key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
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
        required_node(store, snapshot_key, object_key)?;
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
                [item] => Ok(item.object_key.clone()),
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
        object_key: constraint.key.to_string(),
        name: constraint.name.clone(),
        table_key: constraint.table_key.to_string(),
        table: constraint.table_key.object_name.clone(),
        column_keys: string_keys(&constraint.columns),
        columns: names_from_keys(&constraint.columns),
        referenced_table_key: constraint
            .referenced_table_key
            .as_ref()
            .map(ToString::to_string),
        referenced_table: constraint
            .referenced_table_key
            .as_ref()
            .map(|key| key.object_name.clone())
            .unwrap_or_default(),
        referenced_column_keys: string_keys(&constraint.referenced_columns),
        referenced_columns: names_from_keys(&constraint.referenced_columns),
    }
}

fn constraint_description(constraint: &ConstraintObject) -> ConstraintDescription {
    ConstraintDescription {
        object_key: constraint.key.to_string(),
        name: constraint.name.clone(),
        kind: constraint_kind_name(constraint.kind).to_owned(),
        column_keys: string_keys(&constraint.columns),
        columns: names_from_keys(&constraint.columns),
        referenced_table_key: constraint
            .referenced_table_key
            .as_ref()
            .map(ToString::to_string),
        referenced_column_keys: string_keys(&constraint.referenced_columns),
        expression: constraint.expression.clone(),
    }
}

fn constraint_kind_name(kind: ConstraintKind) -> &'static str {
    match kind {
        ConstraintKind::PrimaryKey => "primary_key",
        ConstraintKind::ForeignKey => "foreign_key",
        ConstraintKind::Unique => "unique",
        ConstraintKind::Check => "check",
    }
}

fn string_keys(keys: &[ObjectKey]) -> Vec<String> {
    keys.iter().map(ToString::to_string).collect()
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

fn paginate<T>(
    items: Vec<T>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Page<T>, String> {
    let offset = offset.unwrap_or(0);
    let limit_requested = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit_requested == 0 {
        return Err("limit must be greater than zero".to_owned());
    }
    let limit_applied = limit_requested.min(MAX_PAGE_LIMIT);
    let total = items.len();
    let has_more = offset.saturating_add(limit_applied) < total;
    let items = items.into_iter().skip(offset).take(limit_applied).collect();

    Ok(Page {
        items,
        metadata: PageMetadata {
            total,
            offset,
            limit_requested,
            limit_applied,
            limit_clamped: limit_requested != limit_applied,
            has_more,
        },
    })
}

fn resolve_snapshot_key(store: &GraphStore, selector: &str) -> Result<String, String> {
    if store
        .get_snapshot(selector)
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Ok(selector.to_owned());
    }

    let matches = store
        .list_snapshots()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|snapshot| alias_from_snapshot_key(&snapshot.snapshot_key) == selector)
        .map(|snapshot| snapshot.snapshot_key)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [snapshot_key] => Ok(snapshot_key.clone()),
        [] => Err(format!("database snapshot '{selector}' not found")),
        _ => Err(format!(
            "database alias '{selector}' is ambiguous; pass one snapshot key: {}",
            matches.join(", ")
        )),
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
                "edge_from": &node.edge_from,
                "edge_to": &node.edge_to,
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
                    "edge_from": &hop.edge_from,
                    "edge_to": &hop.edge_to,
                })).collect::<Vec<_>>()
            })
        })
        .collect()
}

fn schema_diff_json(
    bounded: &BoundedSchemaDiff,
    result_limit_requested: usize,
    result_limit_applied: usize,
) -> Value {
    let diff = &bounded.diff;
    json!({
        "from_snapshot_key": &diff.from_snapshot_key,
        "to_snapshot_key": &diff.to_snapshot_key,
        "counts": {
            "added_nodes": bounded.counts.added_nodes,
            "removed_nodes": bounded.counts.removed_nodes,
            "changed_nodes": bounded.counts.changed_nodes,
            "added_edges": bounded.counts.added_edges,
            "removed_edges": bounded.counts.removed_edges,
            "impacted_seeds": bounded.counts.impacted_seeds,
        },
        "result_limit_requested": result_limit_requested,
        "result_limit_applied": result_limit_applied,
        "result_limit_clamped": result_limit_requested != result_limit_applied,
        "truncated": bounded.truncated,
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
            "truncated": impact.truncated,
            "impact": impact_json(&impact.impact),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn tool_json<T, E>(result: Result<T, E>) -> Result<String, String>
where
    T: Serialize,
    E: Serialize + fmt::Display,
{
    match result {
        Ok(value) => serde_json::to_string(&value).map_err(|error| error.to_string()),
        Err(error) => Err(serde_json::to_string(&json!({
            "status": "failed",
            "error": error,
        }))
        .unwrap_or_else(|_| error.to_string())),
    }
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
