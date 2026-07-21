use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use database_memory_core::graph_builder::insert_schema_snapshot_graph;
use database_memory_core::graph_query::GraphQueryResult;
use database_memory_core::graph_store::{GraphSnapshotRecord, GraphStore};
use database_memory_core::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};
use rmcp::handler::server::wrapper::Parameters;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::*;
const SNAPSHOT: &str = "sqlite:sample";

#[test]
fn graph_stats_counts_indexed_snapshots() {
    let path = temp_cache_path();
    let store = GraphStore::open(&path).unwrap();
    store
        .insert_snapshot(&GraphSnapshotRecord {
            snapshot_key: "sqlite:sample".to_owned(),
            source: Some("sqlite:sample".to_owned()),
            captured_at_unix_ms: 0,
            payload_json: "{}".to_owned(),
        })
        .unwrap();
    drop(store);

    let stats = graph_stats_for_cache_path(&path);
    assert!(stats.cache_exists);
    assert_eq!(stats.indexed_snapshots, 1);
    assert_eq!(stats.error, None);

    let server = DatabaseMemoryMcp::new();
    let body = server
        .graph_stats(Parameters(GraphStatsRequest {
            cache_path: Some(path.display().to_string()),
        }))
        .unwrap();
    let tool_stats: GraphStatsResult = serde_json::from_str(&body).unwrap();
    assert_eq!(tool_stats.indexed_snapshots, 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn graph_stats_missing_cache_returns_zero() {
    let path = temp_cache_path();
    let stats = graph_stats_for_cache_path(&path);

    assert!(!stats.cache_exists);
    assert_eq!(stats.indexed_snapshots, 0);
    assert_eq!(stats.error, None);
}

#[test]
fn mcp_lists_finds_and_describes_graph_metadata() {
    let path = temp_cache_path();
    write_snapshot(&path, SNAPSHOT, &snapshot("sample", true, true));
    let server = DatabaseMemoryMcp::new();

    let databases: ListDatabasesResult =
        parse_tool(server.list_databases(Parameters(ListDatabasesRequest {
            cache_path: Some(path.display().to_string()),
        })));
    assert_eq!(databases.snapshots[0].alias, "sample");

    let tables: ListTablesResult = parse_tool(server.list_tables(Parameters(ListTablesRequest {
        alias: "sample".to_owned(),
        cache_path: Some(path.display().to_string()),
        name_filter: Some("ord".to_owned()),
        offset: None,
        limit: None,
    })));
    assert_eq!(tables.tables, vec!["orders"]);

    let description: TableDescription =
        parse_tool(server.describe_table(Parameters(DescribeTableRequest {
            alias: "sample".to_owned(),
            table_name: "orders".to_owned(),
            cache_path: Some(path.display().to_string()),
        })));
    assert_eq!(description.primary_key, vec!["id"]);
    assert_eq!(
        description.object_key,
        key("sample", ObjectKind::Table, "orders", None).to_string()
    );
    assert_eq!(description.schema, "main");
    assert!(description
        .columns
        .iter()
        .all(|column| column.object_key.starts_with("sqlite:sample:")));
    assert!(description
        .constraints
        .iter()
        .any(|constraint| constraint.kind == "foreign_key"));
    assert_eq!(
        description.foreign_keys.outbound[0].referenced_table,
        "users"
    );
    assert_eq!(description.indexes[0].name, "idx_orders_user_id");
    assert!(description
        .capability_warnings
        .iter()
        .any(|warning| warning.contains("view dependency metadata is not tracked")));

    let columns: FindColumnResult = parse_tool(server.find_column(Parameters(FindColumnRequest {
        alias: "sample".to_owned(),
        query: "USER".to_owned(),
        cache_path: Some(path.display().to_string()),
        offset: None,
        limit: None,
    })));
    assert_eq!(columns.columns[0].table, "orders");
    assert_eq!(columns.columns[0].column, "user_id");

    let _ = std::fs::remove_file(path);
}

#[test]
fn mcp_runs_impact_trace_and_schema_diff() {
    let path = temp_cache_path();
    write_snapshot(&path, "sqlite:from", &snapshot("from", false, false));
    write_snapshot(&path, "sqlite:to", &snapshot("to", true, true));
    let server = DatabaseMemoryMcp::new();

    let impact: Value = parse_tool(server.impact_analysis(Parameters(ImpactAnalysisRequest {
        alias: "to".to_owned(),
        object_key: None,
        table: Some("orders".to_owned()),
        column: Some("user_id".to_owned()),
        direction: "outbound".to_owned(),
        max_depth: Some(2),
        result_limit: None,
        cache_path: Some(path.display().to_string()),
    })));
    assert_eq!(
        impact["object_key"].as_str().unwrap(),
        key("to", ObjectKind::Column, "orders", Some("user_id")).to_string()
    );
    assert!(impact["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|group| { group["label"].as_str() == Some("ForeignKey") }));
    assert!(json_string_array(&impact["capability_warnings"])
        .iter()
        .any(|warning| warning.contains("routine dependency metadata is not tracked")));

    let trace: Value = parse_tool(server.trace_relationships(Parameters(
        TraceRelationshipsRequest {
            alias: "to".to_owned(),
            start_object_key: key("to", ObjectKind::Column, "orders", Some("user_id")).to_string(),
            direction: "outbound".to_owned(),
            max_depth: Some(2),
            result_limit: None,
            cache_path: Some(path.display().to_string()),
        },
    )));
    assert!(!trace["paths"].as_array().unwrap().is_empty());
    assert!(json_string_array(&trace["capability_warnings"])
        .iter()
        .any(|warning| warning.contains("trigger dependency metadata is not tracked")));

    let diff: Value = parse_tool(server.schema_diff(Parameters(SchemaDiffRequest {
        cache_path: Some(path.display().to_string()),
        from_alias: "from".to_owned(),
        to_alias: "to".to_owned(),
        result_limit: None,
    })));
    let added_user_id = key("to", ObjectKind::Column, "orders", Some("user_id")).to_string();
    assert!(diff["added_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|node| { node["node_key"].as_str() == Some(added_user_id.as_str()) }));
    assert!(diff["removed_nodes"].as_array().unwrap().is_empty());
    assert!(diff["changed_nodes"].as_array().unwrap().is_empty());
    assert_eq!(diff["result_limit_applied"], 100);
    assert_eq!(diff["truncated"], false);

    let limited: Value = parse_tool(server.schema_diff(Parameters(SchemaDiffRequest {
        cache_path: Some(path.display().to_string()),
        from_alias: "from".to_owned(),
        to_alias: "to".to_owned(),
        result_limit: Some(1),
    })));
    let limited_impact_nodes = limited["impacted"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|impact| impact["impact"]["groups"].as_array().unwrap())
        .map(|group| group["nodes"].as_array().unwrap().len())
        .sum::<usize>();
    assert_eq!(limited["result_limit_applied"], 1);
    assert_eq!(limited["truncated"], true);
    assert!(limited["counts"]["added_nodes"].as_u64().unwrap() > 1);
    assert!(limited["added_nodes"].as_array().unwrap().len() <= 1);
    assert!(limited["added_edges"].as_array().unwrap().len() <= 1);
    assert!(limited["impacted"].as_array().unwrap().len() <= 1);
    assert!(limited_impact_nodes <= 1);

    let clamped: Value = parse_tool(server.schema_diff(Parameters(SchemaDiffRequest {
        cache_path: Some(path.display().to_string()),
        from_alias: "from".to_owned(),
        to_alias: "to".to_owned(),
        result_limit: Some(999),
    })));
    assert_eq!(clamped["result_limit_applied"], 200);
    assert_eq!(clamped["result_limit_clamped"], true);

    let zero_limit = server
        .schema_diff(Parameters(SchemaDiffRequest {
            cache_path: Some(path.display().to_string()),
            from_alias: "from".to_owned(),
            to_alias: "to".to_owned(),
            result_limit: Some(0),
        }))
        .unwrap_err();
    assert!(zero_limit.contains("result_limit must be greater than zero"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn mcp_runs_query_graph() {
    let path = temp_cache_path();
    write_snapshot(&path, SNAPSHOT, &snapshot("sample", true, true));
    let server = DatabaseMemoryMcp::new();

    let result: GraphQueryResult = parse_tool(server.query_graph(Parameters(QueryGraphRequest {
        cache_path: Some(path.display().to_string()),
        alias: Some("sample".to_owned()),
        snapshot_key: None,
        node_label: Some("Index".to_owned()),
        node_key_contains: None,
        name_contains: Some("user".to_owned()),
        edge_type: None,
        payload_array_min_len: None,
        traversal: None,
        limit: 10,
    })));

    assert_eq!(result.nodes.len(), 1);
    assert_eq!(
        result.nodes[0].display_name.as_deref(),
        Some("idx_orders_user_id")
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn mysql_tool_response_reports_unsupported_relationship_capabilities() {
    let path = temp_cache_path();
    write_snapshot(
        &path,
        "mysql:my",
        &snapshot_with_capabilities("my", unsupported_capabilities("mysql")),
    );
    let server = DatabaseMemoryMcp::new();

    let description: TableDescription =
        parse_tool(server.describe_table(Parameters(DescribeTableRequest {
            alias: "mysql:my".to_owned(),
            table_name: "orders".to_owned(),
            cache_path: Some(path.display().to_string()),
        })));

    assert!(description
        .capability_warnings
        .iter()
        .any(|warning| warning.contains("view dependency metadata is not tracked")));
    assert!(description
        .capability_warnings
        .iter()
        .any(|warning| warning.contains("trigger dependency metadata is not tracked")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn postgres_tool_response_does_not_warn_view_trigger_routine_support() {
    let path = temp_cache_path();
    write_snapshot(
        &path,
        "postgres:pg",
        &snapshot_with_capabilities("pg", postgres_capabilities()),
    );
    let server = DatabaseMemoryMcp::new();

    let impact: Value = parse_tool(server.impact_analysis(Parameters(ImpactAnalysisRequest {
        alias: "postgres:pg".to_owned(),
        object_key: None,
        table: Some("orders".to_owned()),
        column: Some("user_id".to_owned()),
        direction: "outbound".to_owned(),
        max_depth: Some(2),
        result_limit: None,
        cache_path: Some(path.display().to_string()),
    })));
    let warnings = json_string_array(&impact["capability_warnings"]);

    assert!(!warnings.iter().any(|warning| {
        warning.contains("view dependency metadata is not tracked")
            || warning.contains("trigger dependency metadata is not tracked")
            || warning.contains("routine dependency metadata is not tracked")
    }));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("cross-object dependency metadata is partially tracked")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn non_sqlite_alias_from_list_databases_round_trips_into_other_tools() {
    let path = temp_cache_path();
    write_snapshot(
        &path,
        "postgres:pg",
        &snapshot_with_capabilities("pg", postgres_capabilities()),
    );
    let server = DatabaseMemoryMcp::new();

    let databases: ListDatabasesResult =
        parse_tool(server.list_databases(Parameters(ListDatabasesRequest {
            cache_path: Some(path.display().to_string()),
        })));
    assert_eq!(databases.snapshots[0].alias, "pg");

    let tables: ListTablesResult = parse_tool(server.list_tables(Parameters(ListTablesRequest {
        alias: databases.snapshots[0].alias.clone(),
        cache_path: Some(path.display().to_string()),
        name_filter: Some("orders".to_owned()),
        offset: None,
        limit: None,
    })));
    assert_eq!(tables.snapshot_key, "postgres:pg");
    assert_eq!(tables.tables, vec!["orders"]);

    let columns: FindColumnResult = parse_tool(server.find_column(Parameters(FindColumnRequest {
        alias: "pg".to_owned(),
        query: "user_id".to_owned(),
        cache_path: Some(path.display().to_string()),
        offset: None,
        limit: None,
    })));
    assert!(columns.columns[0].object_key.starts_with("postgres:pg:"));
    assert!(columns.columns[0].table_key.starts_with("postgres:pg:"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn ambiguous_alias_requires_an_explicit_snapshot_key() {
    let path = temp_cache_path();
    write_snapshot(
        &path,
        "postgres:shared",
        &snapshot_with_capabilities("shared", postgres_capabilities()),
    );
    write_snapshot(
        &path,
        "mysql:shared",
        &snapshot_with_capabilities("shared", unsupported_capabilities("mysql")),
    );
    let server = DatabaseMemoryMcp::new();

    let ambiguous = server
        .list_tables(Parameters(ListTablesRequest {
            alias: "shared".to_owned(),
            cache_path: Some(path.display().to_string()),
            name_filter: None,
            offset: None,
            limit: None,
        }))
        .unwrap_err();
    assert!(ambiguous.contains("alias 'shared' is ambiguous"));

    let explicit: ListTablesResult =
        parse_tool(server.list_tables(Parameters(ListTablesRequest {
            alias: "postgres:shared".to_owned(),
            cache_path: Some(path.display().to_string()),
            name_filter: None,
            offset: None,
            limit: None,
        })));
    assert_eq!(explicit.snapshot_key, "postgres:shared");

    let _ = std::fs::remove_file(path);
}

#[test]
fn multi_schema_table_results_expose_stable_keys_and_reject_ambiguous_names() {
    let path = temp_cache_path();
    let mut multi_schema = snapshot_with_capabilities("pg", postgres_capabilities());
    let audit_schema = ObjectKey::new(
        "postgres",
        "pg",
        "main",
        "audit",
        ObjectKind::Schema,
        "audit",
        None,
    );
    let audit_users = ObjectKey::new(
        "postgres",
        "pg",
        "main",
        "audit",
        ObjectKind::Table,
        "users",
        None,
    );
    multi_schema.schemas.push(SchemaObject {
        key: audit_schema.clone(),
        database_key: multi_schema.database.key.clone(),
        name: "audit".to_owned(),
    });
    multi_schema.tables.push(TableObject {
        key: audit_users.clone(),
        schema_key: audit_schema,
        name: "users".to_owned(),
        kind: TableKind::BaseTable,
    });
    write_snapshot(&path, "postgres:pg", &multi_schema);
    let server = DatabaseMemoryMcp::new();

    let tables: ListTablesResult = parse_tool(server.list_tables(Parameters(ListTablesRequest {
        alias: "pg".to_owned(),
        cache_path: Some(path.display().to_string()),
        name_filter: Some("users".to_owned()),
        offset: None,
        limit: None,
    })));
    assert_eq!(tables.tables, vec!["users", "users"]);
    assert_eq!(tables.table_matches[0].schema, "audit");
    assert_eq!(tables.table_matches[0].object_key, audit_users.to_string());
    assert_eq!(tables.table_matches[1].schema, "main");

    let ambiguous = server
        .describe_table(Parameters(DescribeTableRequest {
            alias: "pg".to_owned(),
            table_name: "users".to_owned(),
            cache_path: Some(path.display().to_string()),
        }))
        .unwrap_err();
    assert!(ambiguous.contains("table 'users' is ambiguous"));

    let explicit: TableDescription =
        parse_tool(server.describe_table(Parameters(DescribeTableRequest {
            alias: "pg".to_owned(),
            table_name: audit_users.to_string(),
            cache_path: Some(path.display().to_string()),
        })));
    assert_eq!(explicit.table, "users");

    let _ = std::fs::remove_file(path);
}

#[test]
fn mcp_pages_inventory_clamps_traversals_and_rejects_missing_start_nodes() {
    let path = temp_cache_path();
    write_snapshot(&path, SNAPSHOT, &snapshot("sample", true, true));
    let server = DatabaseMemoryMcp::new();

    let tables: ListTablesResult = parse_tool(server.list_tables(Parameters(ListTablesRequest {
        alias: "sample".to_owned(),
        cache_path: Some(path.display().to_string()),
        name_filter: None,
        offset: Some(1),
        limit: Some(1),
    })));
    assert_eq!(tables.tables, vec!["users"]);
    assert_eq!(tables.page.total, 2);
    assert_eq!(tables.page.offset, 1);
    assert_eq!(tables.page.limit_applied, 1);
    assert!(!tables.page.has_more);

    let impact: Value = parse_tool(server.impact_analysis(Parameters(ImpactAnalysisRequest {
        alias: "sample".to_owned(),
        object_key: Some(key("sample", ObjectKind::Table, "orders", None).to_string()),
        table: None,
        column: None,
        direction: "both".to_owned(),
        max_depth: Some(99),
        result_limit: Some(999),
        cache_path: Some(path.display().to_string()),
    })));
    assert_eq!(impact["max_depth_applied"], 8);
    assert_eq!(impact["result_limit_applied"], 200);
    assert_eq!(impact["max_depth_clamped"], true);
    assert_eq!(impact["result_limit_clamped"], true);

    let missing = server
        .trace_relationships(Parameters(TraceRelationshipsRequest {
            alias: "sample".to_owned(),
            start_object_key: "missing-node".to_owned(),
            direction: "outbound".to_owned(),
            max_depth: None,
            result_limit: None,
            cache_path: Some(path.display().to_string()),
        }))
        .unwrap_err();
    assert!(missing.contains("graph node 'missing-node' not found"));

    let _ = std::fs::remove_file(path);
}

fn write_snapshot(path: &Path, snapshot_key: &str, snapshot: &SchemaSnapshot) {
    let store = GraphStore::open(path).unwrap();
    insert_schema_snapshot_graph(&store, snapshot_key, 0, snapshot).unwrap();
}

fn parse_tool<T: DeserializeOwned>(result: Result<String, String>) -> T {
    serde_json::from_str(&result.unwrap()).unwrap()
}

fn snapshot(alias: &str, include_orders: bool, include_fk: bool) -> SchemaSnapshot {
    snapshot_for("sqlite", alias, include_orders, include_fk)
}

fn snapshot_for(
    source_kind: &str,
    alias: &str,
    include_orders: bool,
    include_fk: bool,
) -> SchemaSnapshot {
    let database = key_for(source_kind, alias, ObjectKind::Database, "main", None);
    let schema = key_for(source_kind, alias, ObjectKind::Schema, "main", None);
    let users = key_for(source_kind, alias, ObjectKind::Table, "users", None);
    let orders = key_for(source_kind, alias, ObjectKind::Table, "orders", None);
    let users_id = key_for(source_kind, alias, ObjectKind::Column, "users", Some("id"));
    let orders_id = key_for(source_kind, alias, ObjectKind::Column, "orders", Some("id"));
    let orders_user_id = key_for(
        source_kind,
        alias,
        ObjectKind::Column,
        "orders",
        Some("user_id"),
    );

    let mut tables = vec![TableObject {
        key: users.clone(),
        schema_key: schema.clone(),
        name: "users".to_owned(),
        kind: TableKind::BaseTable,
    }];
    let mut columns = vec![column(users_id.clone(), users.clone(), "id", 1)];
    let mut constraints = vec![ConstraintObject {
        key: key_for(
            source_kind,
            alias,
            ObjectKind::PrimaryKey,
            "users",
            Some("pk_users"),
        ),
        table_key: users.clone(),
        name: "pk_users".to_owned(),
        kind: ConstraintKind::PrimaryKey,
        columns: vec![users_id.clone()],
        referenced_table_key: None,
        referenced_columns: vec![],
        expression: None,
    }];
    let mut indexes = Vec::new();

    if include_orders {
        tables.push(TableObject {
            key: orders.clone(),
            schema_key: schema.clone(),
            name: "orders".to_owned(),
            kind: TableKind::BaseTable,
        });
        columns.push(column(orders_id.clone(), orders.clone(), "id", 1));
        columns.push(column(orders_user_id.clone(), orders.clone(), "user_id", 2));
        constraints.push(ConstraintObject {
            key: key_for(
                source_kind,
                alias,
                ObjectKind::PrimaryKey,
                "orders",
                Some("pk_orders"),
            ),
            table_key: orders.clone(),
            name: "pk_orders".to_owned(),
            kind: ConstraintKind::PrimaryKey,
            columns: vec![orders_id],
            referenced_table_key: None,
            referenced_columns: vec![],
            expression: None,
        });
        indexes.push(IndexObject {
            key: key_for(
                source_kind,
                alias,
                ObjectKind::Index,
                "orders",
                Some("idx_orders_user_id"),
            ),
            table_key: orders.clone(),
            name: "idx_orders_user_id".to_owned(),
            columns: vec![orders_user_id.clone()],
            is_unique: false,
            is_primary: false,
            predicate: None,
            expression: None,
        });
    }

    if include_fk {
        constraints.push(ConstraintObject {
            key: key_for(
                source_kind,
                alias,
                ObjectKind::ForeignKey,
                "orders",
                Some("fk_orders_user"),
            ),
            table_key: orders,
            name: "fk_orders_user".to_owned(),
            kind: ConstraintKind::ForeignKey,
            columns: vec![orders_user_id],
            referenced_table_key: Some(users),
            referenced_columns: vec![users_id],
            expression: None,
        });
    }

    SchemaSnapshot {
        source_kind: source_kind.to_owned(),
        connection_alias: alias.to_owned(),
        database: DatabaseObject {
            key: database.clone(),
            name: "main".to_owned(),
        },
        schemas: vec![SchemaObject {
            key: schema,
            database_key: database,
            name: "main".to_owned(),
        }],
        tables,
        columns,
        constraints,
        indexes,
        views: vec![],
        triggers: vec![],
        routines: vec![],
        capabilities: AdapterCapabilities {
            source_kind: "sqlite".to_owned(),
            metadata_only: true,
            schemas: true,
            tables: true,
            columns: true,
            constraints: true,
            indexes: true,
            views: CapabilitySupport::Unsupported,
            triggers: CapabilitySupport::Unsupported,
            routines: CapabilitySupport::Unsupported,
            dependencies: CapabilitySupport::Unsupported,
            limitations: vec![],
            notes: vec![],
        },
    }
}

fn snapshot_with_capabilities(alias: &str, capabilities: AdapterCapabilities) -> SchemaSnapshot {
    let mut snapshot = snapshot_for(&capabilities.source_kind, alias, true, true);
    snapshot.capabilities = capabilities;
    snapshot
}

fn unsupported_capabilities(source_kind: &str) -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: source_kind.to_owned(),
        metadata_only: true,
        schemas: true,
        tables: true,
        columns: true,
        constraints: true,
        indexes: true,
        views: CapabilitySupport::Unsupported,
        triggers: CapabilitySupport::Unsupported,
        routines: CapabilitySupport::Unsupported,
        dependencies: CapabilitySupport::Unsupported,
        limitations: vec![],
        notes: vec![],
    }
}

fn postgres_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: "postgres".to_owned(),
        metadata_only: true,
        schemas: true,
        tables: true,
        columns: true,
        constraints: true,
        indexes: true,
        views: CapabilitySupport::Supported,
        triggers: CapabilitySupport::Supported,
        routines: CapabilitySupport::Supported,
        dependencies: CapabilitySupport::Partial,
        limitations: vec![],
        notes: vec![],
    }
}

fn json_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn column(key: ObjectKey, table_key: ObjectKey, name: &str, ordinal_position: u32) -> ColumnObject {
    ColumnObject {
        key,
        table_key,
        name: name.to_owned(),
        ordinal_position,
        data_type: "INTEGER".to_owned(),
        is_nullable: false,
        default_value: None,
        is_generated: false,
    }
}

fn key(alias: &str, kind: ObjectKind, object_name: &str, sub_object: Option<&str>) -> ObjectKey {
    key_for("sqlite", alias, kind, object_name, sub_object)
}

fn key_for(
    source_kind: &str,
    alias: &str,
    kind: ObjectKind,
    object_name: &str,
    sub_object: Option<&str>,
) -> ObjectKey {
    ObjectKey::new(
        source_kind,
        alias,
        "main",
        "main",
        kind,
        object_name,
        sub_object.map(str::to_owned),
    )
}

fn temp_cache_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("database-memory-mcp-{nanos}.sqlite"))
}
