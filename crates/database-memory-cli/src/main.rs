mod args;
mod metadata;

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use args::{parse_args, Command};
use database_memory_core::graph_builder::insert_schema_snapshot_graph;
use database_memory_core::graph_store::GraphStore;
use database_memory_core::introspect_schema_source;
use metadata::{
    describe_table, open_existing_store, render_find_column, render_find_table,
    render_table_description, require_snapshot, snapshot_key,
};
use serde_json::json;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let output = execute(parse_args(args)?)?;
    print!("{output}");
    Ok(())
}

fn execute(command: Command) -> Result<String, String> {
    match command {
        Command::Index {
            source,
            path,
            connection_string,
            alias,
            format,
            cache_path,
        } => {
            let snapshot = introspect_schema_source(
                &source,
                path.as_deref(),
                connection_string.as_deref(),
                &alias,
            )?;
            ensure_parent_dir(&cache_path).map_err(|err| err.to_string())?;
            let store = GraphStore::open(&cache_path).map_err(|err| err.to_string())?;
            let snapshot_key = format!("{source}:{alias}");
            insert_schema_snapshot_graph(&store, &snapshot_key, now_unix_ms(), &snapshot)
                .map_err(|err| err.to_string())?;

            match format {
                args::OutputFormat::Text => Ok(format!(
                    "snapshot indexed: {snapshot_key}
tables indexed: {}
columns indexed: {}
constraints indexed: {}
indexes indexed: {}
cache path: {}
",
                    snapshot.tables.len(),
                    snapshot.columns.len(),
                    snapshot.constraints.len(),
                    snapshot.indexes.len(),
                    cache_path.display()
                )),
                args::OutputFormat::Json => Ok(format!(
                    "{}\n",
                    serde_json::to_string_pretty(&json!({
                        "snapshot_key": snapshot_key,
                        "tables_indexed": snapshot.tables.len(),
                        "columns_indexed": snapshot.columns.len(),
                        "constraints_indexed": snapshot.constraints.len(),
                        "indexes_indexed": snapshot.indexes.len(),
                        "cache_path": cache_path.display().to_string(),
                    }))
                    .map_err(|err| err.to_string())?
                )),
            }
        }
        Command::DescribeTable {
            alias,
            table_name,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            let description = describe_table(&store, &snapshot_key, &table_name)?;
            Ok(render_table_description(&description, format))
        }
        Command::FindTable {
            alias,
            query,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            render_find_table(&store, &snapshot_key, &query, format)
        }
        Command::FindColumn {
            alias,
            query,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            render_find_column(&store, &snapshot_key, &query, format)
        }
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
