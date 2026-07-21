use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use mysql::prelude::*;
use mysql::{Pool, PooledConn};

use crate::redact::redact_error_with_connection_string;
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};

pub type MysqlAdapterResult<T> = Result<T, MysqlAdapterError>;

#[derive(Debug)]
pub enum MysqlAdapterError {
    Connection(String),
    Storage(mysql::Error),
    MissingDatabase,
}

impl fmt::Display for MysqlAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "mysql adapter connection error: {err}"),
            Self::Storage(err) => write!(f, "mysql adapter storage error: {err}"),
            Self::MissingDatabase => {
                f.write_str("mysql connection string must select a database/schema")
            }
        }
    }
}

impl Error for MysqlAdapterError {}

impl From<mysql::Error> for MysqlAdapterError {
    fn from(err: mysql::Error) -> Self {
        Self::Storage(err)
    }
}

pub fn introspect_mysql(
    connection_string: &str,
    connection_alias: &str,
) -> MysqlAdapterResult<SchemaSnapshot> {
    let pool = Pool::new(connection_string).map_err(|err| {
        MysqlAdapterError::Connection(redact_error_with_connection_string(err, connection_string))
    })?;
    let mut conn = pool.get_conn().map_err(|err| {
        MysqlAdapterError::Connection(redact_error_with_connection_string(err, connection_string))
    })?;
    introspect_mysql_conn(&mut conn, connection_alias)
}

fn introspect_mysql_conn(
    conn: &mut PooledConn,
    connection_alias: &str,
) -> MysqlAdapterResult<SchemaSnapshot> {
    let database_name = current_database(conn)?;
    let database_key = key(
        connection_alias,
        &database_name,
        ObjectKind::Database,
        &database_name,
        None,
    );
    let schema_key = key(
        connection_alias,
        &database_name,
        ObjectKind::Schema,
        &database_name,
        None,
    );

    let database = DatabaseObject {
        key: database_key.clone(),
        name: database_name.clone(),
    };
    let schemas = vec![SchemaObject {
        key: schema_key.clone(),
        database_key,
        name: database_name.clone(),
    }];

    let mut tables = Vec::new();
    let mut table_keys = BTreeMap::new();
    for table in table_rows(conn, &database_name)? {
        let table_key = key(
            connection_alias,
            &database_name,
            ObjectKind::Table,
            &table.name,
            None,
        );
        tables.push(TableObject {
            key: table_key.clone(),
            schema_key: schema_key.clone(),
            name: table.name.clone(),
            kind: table.kind,
        });
        table_keys.insert(table.name, table_key);
    }

    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    for column in column_rows(conn, &database_name)? {
        let Some(table_key) = table_keys.get(&column.table).cloned() else {
            continue;
        };
        let column_key = key(
            connection_alias,
            &database_name,
            ObjectKind::Column,
            &column.table,
            Some(column.name.clone()),
        );
        column_keys.insert(
            (column.table.clone(), column.name.clone()),
            column_key.clone(),
        );
        columns.push(ColumnObject {
            key: column_key,
            table_key,
            name: column.name,
            ordinal_position: column.ordinal_position,
            data_type: column.data_type,
            is_nullable: column.is_nullable,
            default_value: column.default_value,
            is_generated: column.is_generated,
        });
    }

    let constraints = constraint_rows(conn, &database_name)?
        .into_iter()
        .filter_map(|constraint| {
            let table_key = table_keys.get(&constraint.table).cloned()?;
            let columns = constraint
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(constraint.table.clone(), column.clone()))
                        .cloned()
                })
                .collect::<Vec<_>>();
            let referenced_table_key = constraint
                .referenced_table
                .as_ref()
                .and_then(|table| table_keys.get(table))
                .cloned();
            let referenced_columns = constraint
                .referenced_columns
                .iter()
                .filter_map(|column| {
                    constraint
                        .referenced_table
                        .as_ref()
                        .and_then(|table| column_keys.get(&(table.clone(), column.clone())))
                        .cloned()
                })
                .collect::<Vec<_>>();
            let object_kind = match constraint.kind {
                ConstraintKind::PrimaryKey => ObjectKind::PrimaryKey,
                ConstraintKind::ForeignKey => ObjectKind::ForeignKey,
                ConstraintKind::Unique => ObjectKind::UniqueConstraint,
                ConstraintKind::Check => ObjectKind::CheckConstraint,
            };
            Some(ConstraintObject {
                key: key(
                    connection_alias,
                    &database_name,
                    object_kind,
                    &constraint.table,
                    Some(constraint.name.clone()),
                ),
                table_key,
                name: constraint.name,
                kind: constraint.kind,
                columns,
                referenced_table_key,
                referenced_columns,
                expression: None,
            })
        })
        .collect::<Vec<_>>();

    let indexes = index_rows(conn, &database_name)?
        .into_iter()
        .filter_map(|index| {
            let table_key = table_keys.get(&index.table).cloned()?;
            let columns = index
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(index.table.clone(), column.clone()))
                        .cloned()
                })
                .collect::<Vec<_>>();
            Some(IndexObject {
                key: key(
                    connection_alias,
                    &database_name,
                    ObjectKind::Index,
                    &index.table,
                    Some(index.name.clone()),
                ),
                table_key,
                name: index.name,
                columns,
                is_unique: index.is_unique,
                is_primary: index.is_primary,
                predicate: None,
                expression: None,
            })
        })
        .collect::<Vec<_>>();

    Ok(SchemaSnapshot {
        source_kind: "mysql".to_owned(),
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
        capabilities: mysql_capabilities(),
    })
}

fn current_database(conn: &mut PooledConn) -> MysqlAdapterResult<String> {
    conn.query_first::<Option<String>, _>("SELECT DATABASE()")?
        .flatten()
        .filter(|name| !name.is_empty())
        .ok_or(MysqlAdapterError::MissingDatabase)
}

struct TableRow {
    name: String,
    kind: TableKind,
}

fn table_rows(conn: &mut PooledConn, database_name: &str) -> MysqlAdapterResult<Vec<TableRow>> {
    conn.exec_map(
        "
        SELECT TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = ?
          AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_NAME
        ",
        (database_name,),
        |name| TableRow {
            name,
            kind: TableKind::BaseTable,
        },
    )
    .map_err(MysqlAdapterError::from)
}

struct ColumnRow {
    table: String,
    name: String,
    ordinal_position: u32,
    data_type: String,
    is_nullable: bool,
    default_value: Option<String>,
    is_generated: bool,
}

fn column_rows(conn: &mut PooledConn, database_name: &str) -> MysqlAdapterResult<Vec<ColumnRow>> {
    conn.exec_map(
        "
        SELECT TABLE_NAME,
               COLUMN_NAME,
               ORDINAL_POSITION,
               DATA_TYPE,
               IS_NULLABLE,
               COLUMN_DEFAULT,
               EXTRA,
               GENERATION_EXPRESSION
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ?
        ORDER BY TABLE_NAME, ORDINAL_POSITION
        ",
        (database_name,),
        |(
            table,
            name,
            ordinal_position,
            data_type,
            is_nullable,
            default_value,
            extra,
            generation_expression,
        ): (
            String,
            String,
            u64,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        )| {
            let generated_expression_present = generation_expression
                .as_ref()
                .map(|value| !value.is_empty())
                .unwrap_or(false);
            ColumnRow {
                table,
                name,
                ordinal_position: ordinal_position as u32,
                data_type,
                is_nullable: is_nullable == "YES",
                default_value,
                is_generated: generated_expression_present
                    || extra.to_ascii_uppercase().contains("GENERATED"),
            }
        },
    )
    .map_err(MysqlAdapterError::from)
}

struct ConstraintRow {
    table: String,
    name: String,
    kind: ConstraintKind,
    columns: Vec<String>,
    referenced_table: Option<String>,
    referenced_columns: Vec<String>,
}

fn constraint_rows(
    conn: &mut PooledConn,
    database_name: &str,
) -> MysqlAdapterResult<Vec<ConstraintRow>> {
    let rows = conn.exec_map(
        "
        SELECT k.TABLE_NAME,
               k.CONSTRAINT_NAME,
               tc.CONSTRAINT_TYPE,
               k.COLUMN_NAME,
               k.REFERENCED_TABLE_SCHEMA,
               k.REFERENCED_TABLE_NAME,
               k.REFERENCED_COLUMN_NAME
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k
        JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
          ON tc.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA
         AND tc.TABLE_SCHEMA = k.TABLE_SCHEMA
         AND tc.TABLE_NAME = k.TABLE_NAME
         AND tc.CONSTRAINT_NAME = k.CONSTRAINT_NAME
        WHERE k.TABLE_SCHEMA = ?
          AND tc.CONSTRAINT_TYPE IN ('PRIMARY KEY', 'UNIQUE', 'FOREIGN KEY')
        ORDER BY k.TABLE_NAME, k.CONSTRAINT_NAME, k.ORDINAL_POSITION
        ",
        (database_name,),
        |(
            table,
            name,
            constraint_type,
            column,
            referenced_schema,
            referenced_table,
            referenced_column,
        ): (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )| {
            (
                table,
                name,
                constraint_type,
                column,
                referenced_schema,
                referenced_table,
                referenced_column,
            )
        },
    )?;

    let mut grouped = BTreeMap::<(String, String), ConstraintRow>::new();
    for (
        table,
        name,
        constraint_type,
        column,
        referenced_schema,
        referenced_table,
        referenced_column,
    ) in rows
    {
        let kind = match constraint_type.as_str() {
            "PRIMARY KEY" => ConstraintKind::PrimaryKey,
            "FOREIGN KEY" => ConstraintKind::ForeignKey,
            _ => ConstraintKind::Unique,
        };
        let entry = grouped
            .entry((table.clone(), name.clone()))
            .or_insert_with(|| ConstraintRow {
                table,
                name,
                kind,
                columns: vec![],
                referenced_table: None,
                referenced_columns: vec![],
            });
        entry.columns.push(column);
        if entry.kind == ConstraintKind::ForeignKey
            && referenced_schema.as_deref() == Some(database_name)
        {
            entry.referenced_table = referenced_table;
            if let Some(column) = referenced_column {
                entry.referenced_columns.push(column);
            }
        }
    }

    Ok(grouped.into_values().collect())
}

#[derive(Default)]
struct IndexRow {
    table: String,
    name: String,
    columns: Vec<String>,
    is_unique: bool,
    is_primary: bool,
}

fn index_rows(conn: &mut PooledConn, database_name: &str) -> MysqlAdapterResult<Vec<IndexRow>> {
    let rows = conn.exec_map(
        "
        SELECT TABLE_NAME,
               INDEX_NAME,
               NON_UNIQUE,
               COLUMN_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = ?
        ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
        ",
        (database_name,),
        |(table, name, non_unique, column): (String, String, u64, Option<String>)| {
            (table, name, non_unique, column)
        },
    )?;

    let mut grouped = BTreeMap::<(String, String), IndexRow>::new();
    for (table, name, non_unique, column) in rows {
        let entry = grouped
            .entry((table.clone(), name.clone()))
            .or_insert_with(|| IndexRow {
                table,
                name: name.clone(),
                columns: vec![],
                is_unique: non_unique == 0,
                is_primary: name == "PRIMARY",
            });
        if let Some(column) = column {
            entry.columns.push(column);
        }
    }

    Ok(grouped.into_values().collect())
}

fn key(
    connection_alias: &str,
    database: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        "mysql",
        connection_alias,
        database,
        database,
        object_kind,
        object_name,
        sub_object,
    )
}

fn mysql_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: "mysql".to_owned(),
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
            "Reads INFORMATION_SCHEMA metadata only; no user table rows are read.".to_owned(),
            "MySQL/MariaDB database/catalog names are mapped to the common schema field."
                .to_owned(),
            "Level 1 does not extract views, triggers, routines, or dependency metadata."
                .to_owned(),
        ],
    }
}

#[cfg(test)]
mod mysql_adapter_tests {
    use super::*;

    const TEST_URL_ENV: &str = "DATABASE_MEMORY_TEST_MYSQL_URL";

    #[test]
    fn mysql_capabilities_are_level_1_metadata_only() {
        let capabilities = mysql_capabilities();

        assert_eq!(capabilities.source_kind, "mysql");
        assert!(capabilities.metadata_only);
        assert!(capabilities.tables);
        assert!(capabilities.columns);
        assert!(capabilities.constraints);
        assert!(capabilities.indexes);
        assert_eq!(capabilities.views, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.triggers, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.routines, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.dependencies, CapabilitySupport::Unsupported);
    }

    #[test]
    fn mysql_adapter_live_introspection_is_env_gated() {
        let Ok(connection_string) = std::env::var(TEST_URL_ENV) else {
            eprintln!("skipping live MySQL adapter test; set {TEST_URL_ENV} to run it");
            return;
        };

        let suffix = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let users = format!("dm_mcp_users_{suffix}");
        let orders = format!("dm_mcp_orders_{suffix}");
        let fk = format!("dm_mcp_fk_{suffix}");
        let idx = format!("dm_mcp_idx_{suffix}");

        let pool = Pool::new(connection_string.as_str()).unwrap();
        let mut conn = pool.get_conn().unwrap();
        conn.query_drop(format!("DROP TABLE IF EXISTS {orders}"))
            .unwrap();
        conn.query_drop(format!("DROP TABLE IF EXISTS {users}"))
            .unwrap();
        conn.query_drop(format!(
            "CREATE TABLE {users} (
                id INT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE
            )"
        ))
        .unwrap();
        conn.query_drop(format!(
            "CREATE TABLE {orders} (
                id INT PRIMARY KEY,
                user_id INT NOT NULL,
                total DECIMAL(10,2) DEFAULT 0,
                CONSTRAINT {fk} FOREIGN KEY (user_id) REFERENCES {users}(id)
            )"
        ))
        .unwrap();
        conn.query_drop(format!("CREATE INDEX {idx} ON {orders}(user_id)"))
            .unwrap();

        let snapshot = introspect_mysql(&connection_string, "mysql-test").unwrap();

        conn.query_drop(format!("DROP TABLE IF EXISTS {orders}"))
            .unwrap();
        conn.query_drop(format!("DROP TABLE IF EXISTS {users}"))
            .unwrap();

        assert_eq!(snapshot.source_kind, "mysql");
        assert_eq!(snapshot.connection_alias, "mysql-test");
        assert!(snapshot.capabilities.metadata_only);
        assert_eq!(snapshot.schemas[0].name, snapshot.database.name);
        assert!(snapshot
            .tables
            .iter()
            .any(|item| item.name == orders && item.key.schema == snapshot.database.name));
        assert!(snapshot.columns.iter().any(|item| {
            item.table_key.object_name == orders
                && item.name == "user_id"
                && item.data_type == "int"
        }));
        assert!(snapshot.constraints.iter().any(|item| {
            item.kind == ConstraintKind::PrimaryKey && item.table_key.object_name == users
        }));
        assert!(snapshot.constraints.iter().any(|item| {
            item.kind == ConstraintKind::ForeignKey
                && item.table_key.object_name == orders
                && item
                    .referenced_table_key
                    .as_ref()
                    .map(|key| key.object_name.as_str())
                    == Some(users.as_str())
        }));
        assert!(snapshot.indexes.iter().any(|item| {
            item.name == idx && item.table_key.object_name == orders && !item.is_unique
        }));
    }
}
