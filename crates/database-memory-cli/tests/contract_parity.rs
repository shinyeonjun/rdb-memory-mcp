use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use database_memory_core::certification::CompletionStatus;
use database_memory_core::interface_contract::{
    IndexResult, ObjectDetail, ObjectPage, SnapshotDetail, INTERFACE_CONTRACT_VERSION,
};
use database_memory_mcp::{
    DatabaseMemoryMcp, DescribeObjectRequest, DescribeSnapshotRequest, ListObjectsRequest,
};
use rmcp::handler::server::wrapper::Parameters;

#[test]
fn cli_and_mcp_share_the_complete_object_contract() {
    let root = temporary_path("contract-parity");
    fs::create_dir_all(&root).unwrap();
    let ddl_path = root.join("schema.sql");
    let cache_path = root.join("graph.sqlite");
    fs::write(
        &ddl_path,
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE);\n\
         CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));\n\
         CREATE INDEX idx_orders_user_id ON orders(user_id);",
    )
    .unwrap();

    let indexed: IndexResult = cli_json(&[
        "index",
        "--source",
        "ddl-sqlite",
        "--path",
        display(&ddl_path).as_str(),
        "--alias",
        "parity",
        "--cache-path",
        display(&cache_path).as_str(),
        "--json",
    ]);
    assert_eq!(indexed.contract_version, INTERFACE_CONTRACT_VERSION);
    assert_eq!(indexed.completeness.status, CompletionStatus::Complete);

    let cli_snapshot: SnapshotDetail = cli_json(&[
        "describe-snapshot",
        "parity",
        "--cache-path",
        display(&cache_path).as_str(),
        "--json",
    ]);
    let server = DatabaseMemoryMcp::with_allowed_roots([&root]).unwrap();
    let mcp_snapshot: SnapshotDetail = parse_tool(server.describe_snapshot(Parameters(
        DescribeSnapshotRequest {
            snapshot: "parity".to_owned(),
            cache_path: Some(display(&cache_path)),
        },
    )));
    assert_eq!(cli_snapshot, mcp_snapshot);

    let cli_objects: ObjectPage = cli_json(&[
        "list-objects",
        "parity",
        "--kind",
        "table",
        "--cache-path",
        display(&cache_path).as_str(),
        "--json",
    ]);
    let mcp_objects: ObjectPage = parse_tool(server.list_objects(Parameters(ListObjectsRequest {
        snapshot: "parity".to_owned(),
        kind: Some("table".to_owned()),
        offset: None,
        limit: None,
        cache_path: Some(display(&cache_path)),
    })));
    assert_eq!(cli_objects, mcp_objects);

    let object_key = cli_objects.objects[0].object_key.clone();
    let cli_detail: ObjectDetail = cli_json(&[
        "describe-object",
        "parity",
        &object_key,
        "--cache-path",
        display(&cache_path).as_str(),
        "--json",
    ]);
    let mcp_detail: ObjectDetail =
        parse_tool(server.describe_object(Parameters(DescribeObjectRequest {
            snapshot: "parity".to_owned(),
            object_key,
            relationship_limit: None,
            cache_path: Some(display(&cache_path)),
        })));
    assert_eq!(cli_detail, mcp_detail);

    fs::remove_dir_all(root).unwrap();
}

fn cli_json<T: serde::de::DeserializeOwned>(args: &[&str]) -> T {
    let output = Command::new(env!("CARGO_BIN_EXE_database-memory"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn parse_tool<T: serde::de::DeserializeOwned>(result: Result<String, String>) -> T {
    serde_json::from_str(&result.unwrap()).unwrap()
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("database-memory-{label}-{nonce}"))
}
