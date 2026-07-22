mod args;
mod metadata;

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use args::{parse_args, Command};
use database_memory_core::graph_store::GraphStore;
use database_memory_core::interface_contract::{
    describe_object as describe_generic_object, describe_snapshot, index_complete_source,
    list_objects, list_snapshot_summaries, product_contract, CompleteIndexRequest, InterfaceError,
    ObjectDetail, ObjectPage, ProductContract, SnapshotDetail, SnapshotSummary,
    INTERFACE_CONTRACT_VERSION,
};
use metadata::{
    describe_table, open_existing_store, render_find_column, render_find_table,
    render_impact_analysis, render_inventory, render_relationship_trace, render_table_description,
    require_snapshot, resolve_snapshot_key,
};
use serde_json::json;

pub(crate) const PRODUCT_CONTRACT_VERSION: u32 = INTERFACE_CONTRACT_VERSION;

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
            requested_catalogs,
            requested_schemas,
            timeout_ms,
            format,
            cache_path,
        } => {
            ensure_parent_dir(&cache_path).map_err(|error| {
                render_interface_error(
                    &InterfaceError::storage("could not create cache directory", error),
                    format,
                )
            })?;
            let store = GraphStore::open(&cache_path).map_err(|error| {
                render_interface_error(
                    &InterfaceError::storage("could not open graph cache", error),
                    format,
                )
            })?;
            let mut request = CompleteIndexRequest::new(source, path, connection_string, alias);
            request.requested_catalogs = requested_catalogs;
            request.requested_schemas = requested_schemas;
            request.timeout_ms = timeout_ms;
            let indexed = index_complete_source(
                &store,
                &request,
                now_unix_ms(),
                cache_path.display().to_string(),
            )
            .map_err(|error| render_interface_error(&error, format))?;

            match format {
                args::OutputFormat::Text => Ok(format!(
                    "snapshot indexed: {}
status: complete
objects indexed: {}
relationships indexed: {}
adapter: {} {}
server: {} {}
cache path: {}
",
                    indexed.snapshot_key,
                    indexed.objects_indexed,
                    indexed.relationships_indexed,
                    indexed.completeness.adapter.name,
                    indexed.completeness.adapter.version,
                    indexed.completeness.server.product,
                    indexed.completeness.server.version,
                    indexed.cache_path,
                )),
                args::OutputFormat::Json => pretty_json(&indexed),
            }
        }
        Command::ListSnapshots { format, cache_path } => {
            let store = open_contract_store(&cache_path, format)?;
            let snapshots = list_snapshot_summaries(&store)
                .map_err(|error| render_interface_error(&error, format))?;
            render_snapshot_list(&snapshots, format)
        }
        Command::DescribeSnapshot {
            selector,
            format,
            cache_path,
        } => {
            let store = open_contract_store(&cache_path, format)?;
            let detail = describe_snapshot(&store, &selector)
                .map_err(|error| render_interface_error(&error, format))?;
            render_snapshot_detail(&detail, format)
        }
        Command::ListObjects {
            selector,
            kind,
            offset,
            limit,
            format,
            cache_path,
        } => {
            let store = open_contract_store(&cache_path, format)?;
            let page = list_objects(&store, &selector, kind, None, offset, Some(limit))
                .map_err(|error| render_interface_error(&error, format))?;
            render_object_page(&page, format)
        }
        Command::FindObjects {
            selector,
            query,
            kind,
            offset,
            limit,
            format,
            cache_path,
        } => {
            let store = open_contract_store(&cache_path, format)?;
            let page = list_objects(&store, &selector, kind, Some(&query), offset, Some(limit))
                .map_err(|error| render_interface_error(&error, format))?;
            render_object_page(&page, format)
        }
        Command::DescribeObject {
            selector,
            object_key,
            relationship_limit,
            format,
            cache_path,
        } => {
            let store = open_contract_store(&cache_path, format)?;
            let detail =
                describe_generic_object(&store, &selector, &object_key, Some(relationship_limit))
                    .map_err(|error| render_interface_error(&error, format))?;
            render_object_detail(&detail, format)
        }
        Command::DescribeTable {
            alias,
            object_key,
            table_name,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
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
            offset,
            limit,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
            require_snapshot(&store, &snapshot_key)?;
            render_inventory(&store, &snapshot_key, offset, limit)
        }
        Command::FindTable {
            alias,
            query,
            format,
            cache_path,
        } => {
            let store = open_existing_store(&cache_path)?;
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
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
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
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
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
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
            let snapshot_key = resolve_snapshot_key(&store, &alias)?;
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
    let contract = product_contract();
    match format {
        args::OutputFormat::Text => render_contract_text(&contract),
        args::OutputFormat::Json => {
            pretty_json(&contract).expect("static contract metadata should serialize")
        }
    }
}

fn render_contract_text(contract: &ProductContract) -> String {
    let support = contract
        .support
        .iter()
        .map(|entry| {
            format!(
                "{}: {:?}{}",
                entry.source,
                entry.status,
                if entry.entrypoint_available {
                    ""
                } else {
                    " (entrypoint unavailable)"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{} {}\ncontract version: {}\nmetadata only: yes\nrow data access: no\n{}\n",
        contract.product, contract.version, contract.contract_version, support
    )
}

fn render_snapshot_list(
    snapshots: &[SnapshotSummary],
    format: args::OutputFormat,
) -> Result<String, String> {
    match format {
        args::OutputFormat::Json => pretty_json(&json!({
            "contract_version": PRODUCT_CONTRACT_VERSION,
            "snapshots": snapshots,
        })),
        args::OutputFormat::Text => Ok(snapshots
            .iter()
            .map(|snapshot| {
                format!(
                    "{}\t{:?}\t{} objects\t{} relationships",
                    snapshot.snapshot_key,
                    snapshot.authority,
                    snapshot.objects,
                    snapshot.relationships
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
    }
}

fn render_snapshot_detail(
    detail: &SnapshotDetail,
    format: args::OutputFormat,
) -> Result<String, String> {
    match format {
        args::OutputFormat::Json => pretty_json(detail),
        args::OutputFormat::Text => Ok(format!(
            "snapshot: {}\nauthority: {:?}\nobjects: {}\nrelationships: {}\nserver: {} {}\n",
            detail.snapshot.snapshot_key,
            detail.snapshot.authority,
            detail.snapshot.objects,
            detail.snapshot.relationships,
            detail
                .snapshot
                .server_product
                .as_deref()
                .unwrap_or("legacy"),
            detail.snapshot.server_version.as_deref().unwrap_or("")
        )),
    }
}

fn render_object_page(page: &ObjectPage, format: args::OutputFormat) -> Result<String, String> {
    match format {
        args::OutputFormat::Json => pretty_json(page),
        args::OutputFormat::Text => Ok(page
            .objects
            .iter()
            .map(|object| {
                format!(
                    "{}\t{}\t{}",
                    object.kind,
                    object
                        .display_name
                        .as_deref()
                        .unwrap_or(&object.object_name),
                    object.object_key
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
    }
}

fn render_object_detail(
    detail: &ObjectDetail,
    format: args::OutputFormat,
) -> Result<String, String> {
    match format {
        args::OutputFormat::Json => pretty_json(detail),
        args::OutputFormat::Text => Ok(format!(
            "object: {}\nkind: {}\nname: {}\nincoming: {}\noutgoing: {}\n",
            detail.object.object_key,
            detail.object.kind,
            detail
                .object
                .display_name
                .as_deref()
                .unwrap_or(&detail.object.object_name),
            detail.incoming.len(),
            detail.outgoing.len()
        )),
    }
}

fn pretty_json(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|json| format!("{json}\n"))
        .map_err(|error| error.to_string())
}

fn render_interface_error(error: &InterfaceError, format: args::OutputFormat) -> String {
    match format {
        args::OutputFormat::Text => error.to_string(),
        args::OutputFormat::Json => serde_json::to_string(&json!({
            "status": "failed",
            "error": error,
        }))
        .unwrap_or_else(|_| error.to_string()),
    }
}

fn open_contract_store(
    cache_path: &Path,
    format: args::OutputFormat,
) -> Result<GraphStore, String> {
    if !cache_path.exists() {
        return Err(render_interface_error(
            &InterfaceError::invalid_request(
                database_memory_core::interface_contract::InterfaceStage::SnapshotLookup,
                format!("cache path '{}' was not found", cache_path.display()),
                "run index first or provide an existing cache path",
            ),
            format,
        ));
    }
    GraphStore::open(cache_path).map_err(|error| {
        render_interface_error(
            &InterfaceError::storage("could not open graph cache", error),
            format,
        )
    })
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
        assert_eq!(value["inventory_limits"]["offset_pagination"], true);
    }
}
