use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};

#[derive(Debug, Clone)]
pub struct SyntheticSchemaConfig {
    pub table_count: usize,
    pub columns_per_table: usize,
    pub foreign_key_every: usize,
    pub index_every: usize,
    pub source_kind: String,
    pub connection_alias: String,
    pub database_name: String,
    pub schema_name: String,
}

impl Default for SyntheticSchemaConfig {
    fn default() -> Self {
        Self {
            table_count: 100,
            columns_per_table: 12,
            foreign_key_every: 2,
            index_every: 1,
            source_kind: "synthetic".to_owned(),
            connection_alias: "perf".to_owned(),
            database_name: "synthetic_db".to_owned(),
            schema_name: "public".to_owned(),
        }
    }
}

pub fn synthetic_schema_snapshot(config: &SyntheticSchemaConfig) -> SchemaSnapshot {
    let columns_per_table = config.columns_per_table.max(1);
    let database_key = synthetic_key(config, ObjectKind::Database, &config.database_name, None);
    let schema_key = synthetic_key(config, ObjectKind::Schema, &config.schema_name, None);
    let mut tables = Vec::with_capacity(config.table_count);
    let mut columns = Vec::with_capacity(config.table_count * columns_per_table);
    let mut constraints = Vec::with_capacity(config.table_count * 2);
    let mut indexes = Vec::with_capacity(config.table_count);

    for table_index in 0..config.table_count {
        let current_table_name = table_name(table_index);
        let table_key = synthetic_key(config, ObjectKind::Table, &current_table_name, None);
        tables.push(TableObject {
            key: table_key.clone(),
            schema_key: schema_key.clone(),
            name: current_table_name.clone(),
            kind: TableKind::BaseTable,
        });

        let mut table_column_keys = Vec::with_capacity(columns_per_table);
        for column_index in 0..columns_per_table {
            let column_name = column_name(column_index);
            let column_key = synthetic_key(
                config,
                ObjectKind::Column,
                &current_table_name,
                Some(column_name.clone()),
            );
            table_column_keys.push(column_key.clone());
            columns.push(ColumnObject {
                key: column_key,
                table_key: table_key.clone(),
                name: column_name,
                ordinal_position: (column_index + 1) as u32,
                data_type: (if column_index == 0 { "integer" } else { "text" }).to_owned(),
                is_nullable: column_index != 0,
                default_value: None,
                is_generated: false,
            });
        }

        constraints.push(ConstraintObject {
            key: synthetic_key(
                config,
                ObjectKind::PrimaryKey,
                &current_table_name,
                Some(format!("pk_{current_table_name}")),
            ),
            table_key: table_key.clone(),
            name: format!("pk_{current_table_name}"),
            kind: ConstraintKind::PrimaryKey,
            columns: vec![table_column_keys[0].clone()],
            referenced_table_key: None,
            referenced_columns: vec![],
            expression: None,
        });

        if table_index > 0
            && columns_per_table > 1
            && config.foreign_key_every > 0
            && table_index % config.foreign_key_every == 0
        {
            let previous_table_name = table_name(table_index - 1);
            constraints.push(ConstraintObject {
                key: synthetic_key(
                    config,
                    ObjectKind::ForeignKey,
                    &current_table_name,
                    Some(format!("fk_{current_table_name}_{previous_table_name}")),
                ),
                table_key: table_key.clone(),
                name: format!("fk_{current_table_name}_{previous_table_name}"),
                kind: ConstraintKind::ForeignKey,
                columns: vec![table_column_keys[1].clone()],
                referenced_table_key: Some(synthetic_key(
                    config,
                    ObjectKind::Table,
                    &previous_table_name,
                    None,
                )),
                referenced_columns: vec![synthetic_key(
                    config,
                    ObjectKind::Column,
                    &previous_table_name,
                    Some(column_name(0)),
                )],
                expression: None,
            });
        }

        if config.index_every > 0 && table_index % config.index_every == 0 {
            indexes.push(IndexObject {
                key: synthetic_key(
                    config,
                    ObjectKind::Index,
                    &current_table_name,
                    Some(format!("idx_{current_table_name}_lookup")),
                ),
                table_key,
                name: format!("idx_{current_table_name}_lookup"),
                columns: vec![table_column_keys[columns_per_table.min(2) - 1].clone()],
                is_unique: false,
                is_primary: false,
                predicate: None,
                expression: None,
            });
        }
    }

    SchemaSnapshot {
        source_kind: config.source_kind.clone(),
        connection_alias: config.connection_alias.clone(),
        database: DatabaseObject {
            key: database_key.clone(),
            name: config.database_name.clone(),
        },
        schemas: vec![SchemaObject {
            key: schema_key,
            database_key,
            name: config.schema_name.clone(),
        }],
        tables,
        columns,
        constraints,
        indexes,
        views: vec![],
        triggers: vec![],
        routines: vec![],
        capabilities: AdapterCapabilities {
            source_kind: config.source_kind.clone(),
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
            notes: vec![
                "Synthetic in-memory schema metadata for performance baselines; no database connection or row data."
                    .to_owned(),
            ],
        },
    }
}

pub fn synthetic_table_key(config: &SyntheticSchemaConfig, table_index: usize) -> ObjectKey {
    synthetic_key(config, ObjectKind::Table, &table_name(table_index), None)
}

pub fn change_first_column_types(
    snapshot: &mut SchemaSnapshot,
    changed_count: usize,
    data_type: &str,
) -> usize {
    let mut changed = 0;
    for column in snapshot
        .columns
        .iter_mut()
        .filter(|column| column.name == column_name(0))
        .take(changed_count)
    {
        column.data_type = data_type.to_owned();
        changed += 1;
    }
    changed
}

fn synthetic_key(
    config: &SyntheticSchemaConfig,
    kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        config.source_kind.clone(),
        config.connection_alias.clone(),
        config.database_name.clone(),
        config.schema_name.clone(),
        kind,
        object_name.to_owned(),
        sub_object,
    )
}

fn table_name(index: usize) -> String {
    format!("table_{index:04}")
}

fn column_name(index: usize) -> String {
    format!("col_{index:03}")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::graph_builder::insert_schema_snapshot_graph;
    use crate::graph_query::{query_graph, GraphQuery};
    use crate::graph_store::GraphStore;
    use crate::impact_analysis::{impact_analysis, Direction};
    use crate::schema_diff::schema_diff;

    const SNAPSHOT: &str = "perf-snapshot";
    const FROM: &str = "perf-from";
    const TO: &str = "perf-to";
    const DIFF_CHANGES: usize = 5;

    #[test]
    fn synthetic_schema_generator_sizes_are_predictable() {
        let config = perf_config();
        let snapshot = synthetic_schema_snapshot(&config);

        assert_eq!(snapshot.tables.len(), 100);
        assert_eq!(snapshot.columns.len(), 1_200);
        assert_eq!(snapshot.indexes.len(), 100);
        assert_eq!(snapshot.constraints.len(), 199);
    }

    #[test]
    fn perf_baseline_indexing_synthetic_schema() {
        let config = perf_config();
        let snapshot = synthetic_schema_snapshot(&config);
        let store = GraphStore::in_memory().unwrap();

        let elapsed =
            timed(|| insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot).unwrap());

        assert_eq!(store.nodes_by_label(SNAPSHOT, "Table").unwrap().len(), 100);
        assert_under(
            "indexing synthetic 100x12 schema",
            elapsed,
            Duration::from_secs(10),
        );
    }

    #[test]
    fn perf_baseline_search_indexed_graph() {
        let config = perf_config();
        let store = indexed_store(&config, SNAPSHOT, &synthetic_schema_snapshot(&config));

        let elapsed = timed(|| {
            let result = query_graph(
                &store,
                &GraphQuery {
                    snapshot_key: SNAPSHOT.to_owned(),
                    node_label: Some("Table".to_owned()),
                    node_key_contains: None,
                    name_contains: Some("table_0099".to_owned()),
                    edge_type: None,
                    payload_array_min_len: None,
                    traversal: None,
                    limit: 10,
                },
            )
            .unwrap();
            assert_eq!(result.nodes.len(), 1);
        });

        assert_under(
            "search indexed 100x12 graph",
            elapsed,
            Duration::from_secs(2),
        );
    }

    #[test]
    fn perf_baseline_impact_analysis_indexed_graph() {
        let config = perf_config();
        let store = indexed_store(&config, SNAPSHOT, &synthetic_schema_snapshot(&config));
        let seed = synthetic_table_key(&config, 50).to_string();

        let elapsed = timed(|| {
            let result = impact_analysis(&store, SNAPSHOT, &seed, Direction::Both, 3).unwrap();
            assert!(!result.groups.is_empty());
        });

        assert_under(
            "impact analysis 100x12 graph",
            elapsed,
            Duration::from_secs(3),
        );
    }

    #[test]
    fn perf_baseline_schema_diff_known_changes() {
        let config = perf_config();
        let from = synthetic_schema_snapshot(&config);
        let mut to = synthetic_schema_snapshot(&config);
        assert_eq!(
            change_first_column_types(&mut to, DIFF_CHANGES, "bigint"),
            DIFF_CHANGES
        );
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, FROM, 0, &from).unwrap();
        insert_schema_snapshot_graph(&store, TO, 1, &to).unwrap();

        let elapsed = timed(|| {
            let diff = schema_diff(&store, FROM, TO).unwrap();
            assert_eq!(diff.changed_nodes.len(), DIFF_CHANGES);
            assert!(diff.added_nodes.is_empty());
            assert!(diff.removed_nodes.is_empty());
        });

        assert_under(
            "schema diff 100x12 graph with 5 changed columns",
            elapsed,
            Duration::from_secs(15),
        );
    }

    fn perf_config() -> SyntheticSchemaConfig {
        SyntheticSchemaConfig {
            foreign_key_every: 1,
            ..SyntheticSchemaConfig::default()
        }
    }

    fn indexed_store(
        config: &SyntheticSchemaConfig,
        snapshot_key: &str,
        snapshot: &SchemaSnapshot,
    ) -> GraphStore {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, snapshot_key, 0, snapshot).unwrap();
        assert_eq!(
            store.nodes_by_label(snapshot_key, "Table").unwrap().len(),
            config.table_count
        );
        store
    }

    fn timed(work: impl FnOnce()) -> Duration {
        let started = Instant::now();
        work();
        started.elapsed()
    }

    fn assert_under(name: &str, elapsed: Duration, budget: Duration) {
        eprintln!("{name}: {:?} (budget {:?})", elapsed, budget);
        assert!(
            elapsed <= budget,
            "{name} took {:?}, budget {:?}",
            elapsed,
            budget
        );
    }
}
