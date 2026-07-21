use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};

use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject, TriggerObject, ViewObject,
};

pub type SqliteAdapterResult<T> = Result<T, SqliteAdapterError>;

#[derive(Debug)]
pub enum SqliteAdapterError {
    Storage(rusqlite::Error),
}

impl fmt::Display for SqliteAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "sqlite adapter storage error: {err}"),
        }
    }
}

impl Error for SqliteAdapterError {}

impl From<rusqlite::Error> for SqliteAdapterError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(err)
    }
}

pub fn introspect_sqlite(
    path: &Path,
    connection_alias: &str,
) -> SqliteAdapterResult<SchemaSnapshot> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    snapshot_from_connection(
        &conn,
        "sqlite",
        "sqlite",
        connection_alias,
        vec!["Level 1 reads sqlite_schema and PRAGMA metadata only.".to_owned()],
    )
}

pub(crate) fn introspect_sqlite_ddl_connection(
    conn: &Connection,
    connection_alias: &str,
) -> SqliteAdapterResult<SchemaSnapshot> {
    snapshot_from_connection(
        conn,
        "ddl-sqlite",
        "sqlite",
        connection_alias,
        vec![
            "SQLite DDL source applies migration files to an in-memory SQLite database, then reads sqlite_schema and PRAGMA metadata only.".to_owned(),
        ],
    )
}

fn snapshot_from_connection(
    conn: &Connection,
    snapshot_source_kind: &str,
    object_source_kind: &str,
    connection_alias: &str,
    notes: Vec<String>,
) -> SqliteAdapterResult<SchemaSnapshot> {
    let database_key = key(
        object_source_kind,
        connection_alias,
        ObjectKind::Database,
        "main",
        None,
    );
    let schema_key = key(
        object_source_kind,
        connection_alias,
        ObjectKind::Schema,
        "main",
        None,
    );
    let table_names = table_names(conn)?;

    let database = DatabaseObject {
        key: database_key.clone(),
        name: "main".to_owned(),
    };
    let schemas = vec![SchemaObject {
        key: schema_key.clone(),
        database_key,
        name: "main".to_owned(),
    }];

    let mut tables = Vec::new();
    let mut table_keys = BTreeMap::new();
    for table_name in table_names {
        let table_key = key(
            object_source_kind,
            connection_alias,
            ObjectKind::Table,
            &table_name,
            None,
        );
        tables.push(TableObject {
            key: table_key.clone(),
            schema_key: schema_key.clone(),
            name: table_name.clone(),
            kind: TableKind::BaseTable,
        });
        table_keys.insert(table_name, table_key);
    }

    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    let mut primary_keys = BTreeMap::new();
    for (table_name, table_key) in &table_keys {
        for column in table_columns(
            conn,
            object_source_kind,
            connection_alias,
            table_name,
            table_key,
        )? {
            if let Some(pk_position) = column.pk_position {
                primary_keys
                    .entry(table_name.clone())
                    .or_insert_with(Vec::new)
                    .push((pk_position, column.object.key.clone()));
            }
            column_keys.insert(
                (table_name.clone(), column.object.name.clone()),
                column.object.key.clone(),
            );
            columns.push(column.object);
        }
    }

    let mut constraints = Vec::new();
    for (table_name, table_key) in &table_keys {
        if let Some(pk_columns) = primary_keys.get_mut(table_name) {
            pk_columns.sort_by_key(|(position, _)| *position);
            constraints.push(ConstraintObject {
                key: key(
                    object_source_kind,
                    connection_alias,
                    ObjectKind::PrimaryKey,
                    table_name,
                    Some(format!("pk_{table_name}")),
                ),
                table_key: table_key.clone(),
                name: format!("pk_{table_name}"),
                kind: ConstraintKind::PrimaryKey,
                columns: pk_columns.iter().map(|(_, key)| key.clone()).collect(),
                referenced_table_key: None,
                referenced_columns: vec![],
                expression: None,
            });
        }
        constraints.extend(table_foreign_keys(
            conn,
            object_source_kind,
            connection_alias,
            table_name,
            table_key,
            &table_keys,
            &column_keys,
            &primary_keys,
        )?);
    }

    let mut indexes = Vec::new();
    for (table_name, table_key) in &table_keys {
        indexes.extend(table_indexes(
            conn,
            object_source_kind,
            connection_alias,
            table_name,
            table_key,
            &column_keys,
        )?);
    }

    let view_rows = schema_entries(conn, "view")?;
    let view_keys = view_rows
        .iter()
        .map(|entry| {
            (
                entry.name.clone(),
                key(
                    object_source_kind,
                    connection_alias,
                    ObjectKind::View,
                    &entry.name,
                    None,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut views = Vec::with_capacity(view_rows.len());
    for view in view_rows {
        views.push(ViewObject {
            key: view_keys[&view.name].clone(),
            schema_key: schema_key.clone(),
            name: view.name.clone(),
            definition: view.sql,
            depends_on: view_dependencies(conn, &view.name, &table_keys, &column_keys, &view_keys)?,
        });
    }

    let triggers = schema_entries(conn, "trigger")?
        .into_iter()
        .filter_map(|trigger| {
            let owner_key = table_keys
                .get(&trigger.owner_name)
                .or_else(|| view_keys.get(&trigger.owner_name))?
                .clone();
            let (timing, events) = trigger_characteristics(trigger.sql.as_deref());
            Some(TriggerObject {
                key: key(
                    object_source_kind,
                    connection_alias,
                    ObjectKind::Trigger,
                    &trigger.owner_name,
                    Some(trigger.name.clone()),
                ),
                table_key: owner_key,
                name: trigger.name,
                timing,
                events,
                definition: trigger.sql,
                executes_routine_key: None,
            })
        })
        .collect::<Vec<_>>();

    Ok(SchemaSnapshot {
        source_kind: snapshot_source_kind.to_owned(),
        connection_alias: connection_alias.to_owned(),
        database,
        schemas,
        tables,
        columns,
        constraints,
        indexes,
        views,
        triggers,
        routines: vec![],
        capabilities: AdapterCapabilities {
            source_kind: snapshot_source_kind.to_owned(),
            metadata_only: true,
            schemas: true,
            tables: true,
            columns: true,
            constraints: true,
            indexes: true,
            views: CapabilitySupport::Supported,
            triggers: CapabilitySupport::Supported,
            routines: CapabilitySupport::Unsupported,
            dependencies: CapabilitySupport::Partial,
            limitations: vec![
                "SQLite CHECK and UNIQUE constraints are not emitted as constraint nodes."
                    .to_owned(),
                "SQLite partial-index predicates and expression-index expressions are not extracted."
                    .to_owned(),
                "SQLite generated columns are identified, but generation expressions are not extracted."
                    .to_owned(),
                "SQLite view dependencies are resolved from prepare-time read authorization; trigger-body dependencies are not emitted."
                    .to_owned(),
            ],
            notes,
        },
    })
}

struct SchemaEntry {
    name: String,
    owner_name: String,
    sql: Option<String>,
}

fn schema_entries(conn: &Connection, object_type: &str) -> SqliteAdapterResult<Vec<SchemaEntry>> {
    let mut stmt = conn.prepare(
        "
        SELECT name, tbl_name, sql
        FROM sqlite_schema
        WHERE type = ?1 AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        ",
    )?;
    let rows = stmt.query_map([object_type], |row| {
        Ok(SchemaEntry {
            name: row.get(0)?,
            owner_name: row.get(1)?,
            sql: row.get(2)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteAdapterError::from)
}

fn view_dependencies(
    conn: &Connection,
    view_name: &str,
    table_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
    view_keys: &BTreeMap<String, ObjectKey>,
) -> SqliteAdapterResult<Vec<ObjectKey>> {
    let selected_columns = relation_column_names(conn, view_name)?;
    let projection = if selected_columns.is_empty() {
        "1".to_owned()
    } else {
        selected_columns
            .iter()
            .map(|column| quote_identifier(column))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let reads = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let captured_reads = Arc::clone(&reads);
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if let AuthAction::Read {
            table_name,
            column_name,
        } = context.action
        {
            if let Ok(mut items) = captured_reads.lock() {
                items.push((table_name.to_owned(), column_name.to_owned()));
            }
        }
        Authorization::Allow
    }));

    let prepare_result = conn
        .prepare(&format!(
            "SELECT {projection} FROM {} LIMIT 0",
            quote_identifier(view_name)
        ))
        .map(|_| ());
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    prepare_result?;

    let mut dependencies = BTreeMap::<String, ObjectKey>::new();
    if let Ok(reads) = reads.lock() {
        for (table_name, column_name) in reads.iter() {
            if let Some(table_key) = table_keys.get(table_name) {
                dependencies.insert(table_key.to_string(), table_key.clone());
                if let Some(column_key) =
                    column_keys.get(&(table_name.clone(), column_name.clone()))
                {
                    dependencies.insert(column_key.to_string(), column_key.clone());
                }
            } else if table_name != view_name {
                if let Some(view_key) = view_keys.get(table_name) {
                    dependencies.insert(view_key.to_string(), view_key.clone());
                }
            }
        }
    }
    Ok(dependencies.into_values().collect())
}

fn relation_column_names(
    conn: &Connection,
    relation_name: &str,
) -> SqliteAdapterResult<Vec<String>> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA table_xinfo({})",
        quote_string(relation_name)
    ))?;
    let rows = stmt.query_map([], |row| row.get(1))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteAdapterError::from)
}

fn trigger_characteristics(definition: Option<&str>) -> (Option<String>, Vec<String>) {
    let tokens = definition
        .unwrap_or_default()
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|character: char| !character.is_ascii_alphabetic())
                .to_ascii_uppercase()
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let timing = if tokens
        .windows(2)
        .any(|window| window[0] == "INSTEAD" && window[1] == "OF")
    {
        Some("INSTEAD OF".to_owned())
    } else {
        tokens
            .iter()
            .find(|token| matches!(token.as_str(), "BEFORE" | "AFTER"))
            .cloned()
    };
    let events = tokens
        .iter()
        .find(|token| matches!(token.as_str(), "INSERT" | "UPDATE" | "DELETE"))
        .cloned()
        .into_iter()
        .collect();
    (timing, events)
}

struct ColumnWithPk {
    object: ColumnObject,
    pk_position: Option<i64>,
}

fn table_names(conn: &Connection) -> SqliteAdapterResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "
        SELECT name
        FROM sqlite_schema
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        ",
    )?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteAdapterError::from)
}

fn table_columns(
    conn: &Connection,
    object_source_kind: &str,
    connection_alias: &str,
    table_name: &str,
    table_key: &ObjectKey,
) -> SqliteAdapterResult<Vec<ColumnWithPk>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_xinfo({})", quote_string(table_name)))?;
    let rows = stmt.query_map([], |row| {
        let cid: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let data_type: String = row.get(2)?;
        let not_null: i64 = row.get(3)?;
        let default_value: Option<String> = row.get(4)?;
        let pk_position: i64 = row.get(5)?;
        let hidden: i64 = row.get(6)?;
        Ok(ColumnWithPk {
            object: ColumnObject {
                key: key(
                    object_source_kind,
                    connection_alias,
                    ObjectKind::Column,
                    table_name,
                    Some(name.clone()),
                ),
                table_key: table_key.clone(),
                name,
                ordinal_position: u32::try_from(cid).unwrap_or(0).saturating_add(1),
                data_type,
                is_nullable: not_null == 0 && pk_position == 0,
                default_value,
                is_generated: matches!(hidden, 2 | 3),
            },
            pk_position: (pk_position > 0).then_some(pk_position),
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteAdapterError::from)
}

#[allow(clippy::too_many_arguments)]
fn table_foreign_keys(
    conn: &Connection,
    object_source_kind: &str,
    connection_alias: &str,
    table_name: &str,
    table_key: &ObjectKey,
    table_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
    primary_keys: &BTreeMap<String, Vec<(i64, ObjectKey)>>,
) -> SqliteAdapterResult<Vec<ConstraintObject>> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA foreign_key_list({})",
        quote_string(table_name)
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?
                .filter(|name| !name.is_empty()),
        ))
    })?;

    let mut grouped = BTreeMap::<i64, Vec<(i64, String, String, Option<String>)>>::new();
    for row in rows {
        let (id, seq, referenced_table, from_column, to_column) = row?;
        grouped
            .entry(id)
            .or_default()
            .push((seq, referenced_table, from_column, to_column));
    }

    let mut constraints = Vec::new();
    for (id, mut parts) in grouped {
        parts.sort_by_key(|(seq, _, _, _)| *seq);
        let Some(referenced_table) = parts.first().map(|(_, table, _, _)| table.clone()) else {
            continue;
        };
        let Some(referenced_table_key) = table_keys.get(&referenced_table).cloned() else {
            continue;
        };
        let columns = parts
            .iter()
            .filter_map(|(_, _, from_column, _)| {
                column_keys
                    .get(&(table_name.to_owned(), from_column.clone()))
                    .cloned()
            })
            .collect::<Vec<_>>();
        let referenced_columns = parts
            .iter()
            .enumerate()
            .filter_map(|(index, (_, _, _, to_column))| {
                to_column
                    .as_ref()
                    .and_then(|name| column_keys.get(&(referenced_table.clone(), name.clone())))
                    .cloned()
                    .or_else(|| {
                        primary_keys
                            .get(&referenced_table)
                            .and_then(|keys| keys.get(index))
                            .map(|(_, key)| key.clone())
                    })
            })
            .collect::<Vec<_>>();
        let name = format!("fk_{table_name}_{id}");
        constraints.push(ConstraintObject {
            key: key(
                object_source_kind,
                connection_alias,
                ObjectKind::ForeignKey,
                table_name,
                Some(name.clone()),
            ),
            table_key: table_key.clone(),
            name,
            kind: ConstraintKind::ForeignKey,
            columns,
            referenced_table_key: Some(referenced_table_key),
            referenced_columns,
            expression: None,
        });
    }

    Ok(constraints)
}

fn table_indexes(
    conn: &Connection,
    object_source_kind: &str,
    connection_alias: &str,
    table_name: &str,
    table_key: &ObjectKey,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> SqliteAdapterResult<Vec<IndexObject>> {
    let mut stmt = conn.prepare(&format!("PRAGMA index_list({})", quote_string(table_name)))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;

    let mut indexes = Vec::new();
    for row in rows {
        let (name, unique, origin, _partial) = row?;
        let columns = index_columns(conn, table_name, &name, column_keys)?;
        indexes.push(IndexObject {
            key: key(
                object_source_kind,
                connection_alias,
                ObjectKind::Index,
                table_name,
                Some(name.clone()),
            ),
            table_key: table_key.clone(),
            name,
            columns,
            is_unique: unique != 0,
            is_primary: origin == "pk",
            predicate: None,
            expression: None,
        });
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

fn index_columns(
    conn: &Connection,
    table_name: &str,
    index_name: &str,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> SqliteAdapterResult<Vec<ObjectKey>> {
    let mut stmt = conn.prepare(&format!("PRAGMA index_info({})", quote_string(index_name)))?;
    let rows = stmt.query_map([], |row| row.get::<_, Option<String>>(2))?;
    let mut columns = Vec::new();
    for row in rows {
        if let Some(name) = row? {
            if let Some(key) = column_keys.get(&(table_name.to_owned(), name)) {
                columns.push(key.clone());
            }
        }
    }
    Ok(columns)
}

fn key(
    source_kind: &str,
    connection_alias: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        source_kind,
        connection_alias,
        "main",
        "main",
        object_kind,
        object_name,
        sub_object,
    )
}

fn quote_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('\"', "\"\""))
}

#[cfg(test)]
mod sqlite_adapter_tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::graph_builder::insert_schema_snapshot_graph;
    use crate::graph_store::GraphStore;
    use crate::impact_analysis::{impact_analysis, Direction};

    #[test]
    fn sqlite_adapter_extracts_tables_and_columns() {
        let path = sample_database_path();
        create_sample_database(&path);

        let snapshot = introspect_sqlite(&path, "sample").unwrap();

        assert_eq!(snapshot.source_kind, "sqlite");
        assert_eq!(snapshot.database.name, "main");
        assert_eq!(snapshot.schemas[0].name, "main");
        assert!(snapshot.tables.iter().any(|table| table.name == "users"));
        assert!(snapshot.tables.iter().any(|table| table.name == "orders"));
        assert!(snapshot
            .columns
            .iter()
            .any(|column| column.name == "user_id" && column.data_type == "INTEGER"));
        assert!(snapshot
            .columns
            .iter()
            .any(|column| column.name == "total_with_tax" && column.is_generated));
        assert!(snapshot.capabilities.metadata_only);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_adapter_extracts_primary_key_foreign_key_and_index() {
        let path = sample_database_path();
        create_sample_database(&path);

        let snapshot = introspect_sqlite(&path, "sample").unwrap();

        assert!(snapshot.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::PrimaryKey
                && constraint.name == "pk_users"
                && constraint.columns.len() == 1
        }));
        assert!(snapshot.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::ForeignKey
                && constraint.table_key.object_name == "orders"
                && constraint
                    .columns
                    .iter()
                    .any(|key| key.sub_object.as_deref() == Some("user_id"))
                && constraint.referenced_columns.iter().any(|key| {
                    key.object_name == "users" && key.sub_object.as_deref() == Some("id")
                })
        }));
        assert!(snapshot.indexes.iter().any(|index| {
            index.name == "idx_orders_user_id"
                && !index.is_unique
                && index
                    .columns
                    .iter()
                    .any(|key| key.sub_object.as_deref() == Some("user_id"))
        }));
        let partial = snapshot
            .indexes
            .iter()
            .find(|index| index.name == "idx_orders_positive_total")
            .unwrap();
        assert_eq!(partial.predicate, None);
        assert!(snapshot
            .capabilities
            .limitations
            .iter()
            .any(|limitation| limitation.contains("partial-index predicates")));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_adapter_preserves_reserved_characters_in_stable_keys() {
        let path = sample_database_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE "order:events" (
                "value:raw%text" TEXT
            );
            "#,
        )
        .unwrap();
        drop(conn);

        let snapshot = introspect_sqlite(&path, "sample:west").unwrap();
        let table = snapshot
            .tables
            .iter()
            .find(|table| table.name == "order:events")
            .unwrap();
        let column = snapshot
            .columns
            .iter()
            .find(|column| column.name == "value:raw%text")
            .unwrap();

        assert_eq!(
            table.key.to_string(),
            "v2:sqlite:sample%3Awest:main:main:table:order%3Aevents"
        );
        assert_eq!(table.key, table.key.to_string().parse().unwrap());
        assert_eq!(column.key, column.key.to_string().parse().unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_adapter_extracts_views_triggers_and_view_dependencies() {
        let path = sample_database_path();
        create_sample_database(&path);

        let snapshot = introspect_sqlite(&path, "sample").unwrap();
        let view = snapshot
            .views
            .iter()
            .find(|view| view.name == "order_totals")
            .unwrap();
        let trigger = snapshot
            .triggers
            .iter()
            .find(|trigger| trigger.name == "trg_orders_touch")
            .unwrap();

        assert!(view
            .definition
            .as_deref()
            .is_some_and(|sql| sql.contains("CREATE VIEW")));
        assert!(view
            .depends_on
            .iter()
            .any(|key| { key.object_kind == ObjectKind::Table && key.object_name == "orders" }));
        assert!(view.depends_on.iter().any(|key| {
            key.object_kind == ObjectKind::Column
                && key.object_name == "orders"
                && key.sub_object.as_deref() == Some("total_cents")
        }));
        assert_eq!(trigger.table_key.object_name, "orders");
        assert_eq!(trigger.timing.as_deref(), Some("AFTER"));
        assert_eq!(trigger.events, vec!["UPDATE"]);
        assert_eq!(snapshot.capabilities.views, CapabilitySupport::Supported);
        assert_eq!(snapshot.capabilities.triggers, CapabilitySupport::Supported);
        assert_eq!(
            snapshot.capabilities.dependencies,
            CapabilitySupport::Partial
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_view_dependency_is_reachable_from_its_source_column() {
        let path = sample_database_path();
        create_sample_database(&path);
        let snapshot = introspect_sqlite(&path, "sample").unwrap();
        let source_column = snapshot
            .columns
            .iter()
            .find(|column| column.table_key.object_name == "orders" && column.name == "total_cents")
            .unwrap();
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, "sqlite-view-impact", 1, &snapshot).unwrap();

        let impact = impact_analysis(
            &store,
            "sqlite-view-impact",
            &source_column.key.to_string(),
            Direction::Inbound,
            1,
        )
        .unwrap();

        assert!(impact.groups.iter().any(|group| {
            group.label == "View"
                && group
                    .nodes
                    .iter()
                    .any(|node| node.display_name.as_deref() == Some("order_totals"))
        }));
        let _ = fs::remove_file(path);
    }

    fn create_sample_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL
            );

            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                total_cents INTEGER NOT NULL,
                total_with_tax INTEGER GENERATED ALWAYS AS (total_cents + 10) STORED,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX idx_orders_user_id ON orders(user_id);
            CREATE INDEX idx_orders_positive_total ON orders(total_cents)
                WHERE total_cents > 0;

            CREATE VIEW order_totals AS
                SELECT id, user_id, total_cents FROM orders;

            CREATE TRIGGER trg_orders_touch
                AFTER UPDATE OF total_cents ON orders
                BEGIN
                    SELECT NEW.total_cents;
                END;
            ",
        )
        .unwrap();
    }

    fn sample_database_path() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "database_memory_core_sqlite_adapter_{}_{}.sqlite",
            std::process::id(),
            suffix
        ))
    }
}
