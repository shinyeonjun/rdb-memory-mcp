use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use database_memory_core::bench_support::{
    synthetic_schema_snapshot, synthetic_table_key, SyntheticSchemaConfig,
};
use database_memory_core::graph_builder::insert_schema_snapshot_graph;
use database_memory_core::graph_store::GraphStore;
use database_memory_core::impact_analysis::{impact_analysis_bounded, Direction};
use serde::Serialize;

const SNAPSHOT_KEY: &str = "scale-audit";
const COLUMNS_PER_TABLE: usize = 8;
const MAX_TARGET_OBJECTS: usize = 1_100_000;

#[derive(Debug)]
struct Arguments {
    target_objects: usize,
    cache_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct ScaleEvidence {
    target_objects: usize,
    actual_objects: u64,
    actual_relationships: u64,
    table_count: usize,
    columns_per_table: usize,
    generated_in_ms: u128,
    indexed_in_ms: u128,
    first_page_in_ms: u128,
    substring_search_in_ms: u128,
    bounded_impact_in_ms: u128,
    total_in_ms: u128,
    first_page_objects: usize,
    substring_matches: usize,
    impact_nodes: usize,
    impact_truncated: bool,
    cache_bytes: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(evidence) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&evidence)
                    .expect("scale evidence must be serializable")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("scale audit failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ScaleEvidence, String> {
    let arguments = parse_arguments(env::args().skip(1))?;
    if arguments.cache_path.exists() {
        return Err(format!(
            "cache path '{}' already exists; refusing to replace it",
            arguments.cache_path.display()
        ));
    }
    if let Some(parent) = arguments.cache_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "could not create scale audit directory '{}': {error}",
                parent.display()
            )
        })?;
    }

    let total_started = Instant::now();
    let table_count = minimum_table_count(arguments.target_objects);
    let config = SyntheticSchemaConfig {
        table_count,
        columns_per_table: COLUMNS_PER_TABLE,
        foreign_key_every: 1,
        index_every: 1,
        ..SyntheticSchemaConfig::default()
    };

    let phase_started = Instant::now();
    let snapshot = synthetic_schema_snapshot(&config);
    let generated_in_ms = phase_started.elapsed().as_millis();

    let store = GraphStore::open(&arguments.cache_path)
        .map_err(|error| format!("could not open scale cache: {error}"))?;
    let phase_started = Instant::now();
    insert_schema_snapshot_graph(&store, SNAPSHOT_KEY, 0, &snapshot)
        .map_err(|error| format!("could not index synthetic schema: {error}"))?;
    let indexed_in_ms = phase_started.elapsed().as_millis();

    let actual_objects = store
        .node_count_for_snapshot(SNAPSHOT_KEY)
        .map_err(|error| format!("could not count indexed objects: {error}"))?;
    let actual_relationships = store
        .edge_count_for_snapshot(SNAPSHOT_KEY)
        .map_err(|error| format!("could not count indexed relationships: {error}"))?;
    if actual_objects < arguments.target_objects as u64 {
        return Err(format!(
            "indexed {actual_objects} objects, below target {}",
            arguments.target_objects
        ));
    }

    let phase_started = Instant::now();
    let (table_total, first_page) = store
        .find_nodes_page(SNAPSHOT_KEY, Some("Table"), None, 0, 100)
        .map_err(|error| format!("could not read first object page: {error}"))?;
    let first_page_in_ms = phase_started.elapsed().as_millis();
    if table_total != table_count as u64 || first_page.len() != table_count.min(100) {
        return Err(format!(
            "table page lost data: expected {table_count}, counted {table_total}, returned {}",
            first_page.len()
        ));
    }

    let last_table_name = format!("table_{:04}", table_count.saturating_sub(1));
    let phase_started = Instant::now();
    let (_, matches) = store
        .find_nodes_page(SNAPSHOT_KEY, Some("Table"), Some(&last_table_name), 0, 10)
        .map_err(|error| format!("could not search the indexed graph: {error}"))?;
    let substring_search_in_ms = phase_started.elapsed().as_millis();
    if matches.len() != 1 {
        return Err(format!(
            "last-table search expected one match for '{last_table_name}', found {}",
            matches.len()
        ));
    }

    let seed = synthetic_table_key(&config, table_count / 2).to_string();
    let phase_started = Instant::now();
    let impact = impact_analysis_bounded(&store, SNAPSHOT_KEY, &seed, Direction::Both, 3, 200)
        .map_err(|error| format!("could not run bounded impact analysis: {error}"))?;
    let bounded_impact_in_ms = phase_started.elapsed().as_millis();
    let impact_nodes = impact
        .result
        .groups
        .iter()
        .map(|group| group.nodes.len())
        .sum();
    if impact_nodes == 0 {
        return Err("bounded impact analysis returned no related metadata".to_owned());
    }

    drop(store);
    drop(snapshot);
    let cache_bytes = fs::metadata(&arguments.cache_path)
        .map_err(|error| format!("could not inspect scale cache: {error}"))?
        .len();

    Ok(ScaleEvidence {
        target_objects: arguments.target_objects,
        actual_objects,
        actual_relationships,
        table_count,
        columns_per_table: COLUMNS_PER_TABLE,
        generated_in_ms,
        indexed_in_ms,
        first_page_in_ms,
        substring_search_in_ms,
        bounded_impact_in_ms,
        total_in_ms: total_started.elapsed().as_millis(),
        first_page_objects: first_page.len(),
        substring_matches: matches.len(),
        impact_nodes,
        impact_truncated: impact.truncated,
        cache_bytes,
    })
}

fn minimum_table_count(target_objects: usize) -> usize {
    // Each table contributes one table, N columns, one PK, one index, and all
    // but the first table contribute one FK. Database and schema add two nodes.
    target_objects
        .saturating_sub(1)
        .div_ceil(COLUMNS_PER_TABLE + 4)
        .max(1)
}

fn parse_arguments(mut args: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut target_objects = None;
    let mut cache_path = None;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for '{argument}'"))?;
        match argument.as_str() {
            "--target" => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid object target '{value}'"))?;
                if parsed == 0 || parsed > MAX_TARGET_OBJECTS {
                    return Err(format!(
                        "object target must be between 1 and {MAX_TARGET_OBJECTS}"
                    ));
                }
                target_objects = Some(parsed);
            }
            "--cache-path" => cache_path = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument '{argument}'")),
        }
    }
    Ok(Arguments {
        target_objects: target_objects.ok_or("missing --target")?,
        cache_path: cache_path.ok_or("missing --cache-path")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_size_rounds_up_without_under_filling() {
        for target in [1, 10_000, 50_000, 100_000, 1_000_000] {
            let tables = minimum_table_count(target);
            let actual = 1 + tables * (COLUMNS_PER_TABLE + 4);
            assert!(actual >= target);
            assert!(actual - target <= COLUMNS_PER_TABLE + 4);
        }
    }
}
