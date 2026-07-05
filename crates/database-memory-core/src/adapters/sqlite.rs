use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
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

    Ok(SchemaSnapshot {
        source_kind: snapshot_source_kind.to_owned(),
        connection_alias: connection_alias.to_owned(),
        database,
        schemas,
        tables,
        columns,
        constraints,
        indexes,
        views: vec![],
        triggers: vec![],
        routines: vec![],
        capabilities: AdapterCapabilities {
            source_kind: snapshot_source_kind.to_owned(),
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
            notes,
        },
    })
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
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_string(table_name)))?;
    let rows = stmt.query_map([], |row| {
        let cid: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let data_type: String = row.get(2)?;
        let not_null: i64 = row.get(3)?;
        let default_value: Option<String> = row.get(4)?;
        let pk_position: i64 = row.get(5)?;
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
                ordinal_position: (cid + 1) as u32,
                data_type,
                is_nullable: not_null == 0 && pk_position == 0,
                default_value,
                is_generated: false,
            },
            pk_position: (pk_position > 0).then_some(pk_position),
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(SqliteAdapterError::from)
}

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
        let (name, unique, origin, partial) = row?;
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
            predicate: (partial != 0).then_some("partial index predicate unavailable".to_owned()),
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

#[cfg(test)]
mod sqlite_adapter_tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;

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
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX idx_orders_user_id ON orders(user_id);
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
