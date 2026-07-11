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
    render_impact_analysis, render_inventory, render_relationship_trace, render_table_description,
    require_snapshot, snapshot_key,
};
use serde_json::json;

pub(crate) const PRODUCT_CONTRACT_VERSION: u32 = 1;

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
        Command::Contract { format } => Ok(render_contract(format)),
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
            object_key,
            table_name,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            let description = describe_table(
                &store,
                &snapshot_key,
                object_key.as_deref(),
                table_name.as_deref(),
            )?;
            Ok(render_table_description(&description, format))
        }
        Command::Inventory {
            alias,
            limit,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            render_inventory(&store, &snapshot_key, limit)
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
        Command::ImpactAnalysis {
            alias,
            object_key,
            table_name,
            column_name,
            direction,
            max_depth,
            limit,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            render_impact_analysis(
                &store,
                &snapshot_key,
                object_key.as_deref(),
                table_name.as_deref(),
                column_name.as_deref(),
                direction,
                max_depth,
                limit,
            )
        }
        Command::TraceRelationships {
            alias,
            object_key,
            direction,
            max_depth,
            limit,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = snapshot_key(&alias);
            require_snapshot(&store, &snapshot_key)?;
            render_relationship_trace(
                &store,
                &snapshot_key,
                &object_key,
                direction,
                max_depth,
                limit,
            )
        }
    }
}

fn render_contract(format: args::OutputFormat) -> String {
    match format {
        args::OutputFormat::Text => format!(
            "database-memory {}\ncontract version: {}\nmetadata only: yes\nrow data access: no\n",
            env!("CARGO_PKG_VERSION"),
            PRODUCT_CONTRACT_VERSION
        ),
        args::OutputFormat::Json => format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "product": "database-memory",
                "version": env!("CARGO_PKG_VERSION"),
                "contract_version": PRODUCT_CONTRACT_VERSION,
                "metadata_only": true,
                "row_data_access": false,
                "commands": [
                    "contract",
                    "index",
                    "describe-table",
                    "inventory",
                    "find-table",
                    "find-column",
                    "impact-analysis",
                    "trace-relationships"
                ],
                "traversal_limits": {
                    "max_depth": args::MAX_TRAVERSAL_DEPTH,
                    "max_results": args::MAX_RESULT_LIMIT,
                },
                "inventory_limits": {
                    "default_tables": args::DEFAULT_INVENTORY_LIMIT,
                    "max_tables": args::MAX_INVENTORY_TABLES,
                }
            }))
            .expect("static contract metadata should serialize")
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_json_is_versioned_and_declares_the_row_data_boundary() {
        let output = execute(Command::Contract {
            format: args::OutputFormat::Json,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["product"], "database-memory");
        assert_eq!(value["contract_version"], PRODUCT_CONTRACT_VERSION);
        assert_eq!(value["metadata_only"], true);
        assert_eq!(value["row_data_access"], false);
        assert!(value["commands"]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|command| command == "describe-table")));
        assert!(value["commands"]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|command| command == "impact-analysis")));
        assert!(value["commands"]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|command| command == "inventory")));
        assert_eq!(
            value["traversal_limits"]["max_depth"],
            args::MAX_TRAVERSAL_DEPTH
        );
        assert_eq!(
            value["inventory_limits"]["max_tables"],
            args::MAX_INVENTORY_TABLES
        );
    }
}
