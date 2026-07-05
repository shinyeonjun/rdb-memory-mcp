use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use tiberius::{Client, Config, Row};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use crate::redact::redact_error_with_connection_string;
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};

pub type SqlServerAdapterResult<T> = Result<T, SqlServerAdapterError>;

type TdsClient = Client<Compat<TcpStream>>;

#[derive(Debug)]
pub enum SqlServerAdapterError {
    Connection(String),
    Storage(tiberius::error::Error),
    Io(std::io::Error),
    MissingDatabase,
    ThreadPanic,
}

impl fmt::Display for SqlServerAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "sqlserver adapter connection error: {err}"),
            Self::Storage(err) => write!(f, "sqlserver adapter storage error: {err}"),
            Self::Io(err) => write!(f, "sqlserver adapter io error: {err}"),
            Self::MissingDatabase => {
                f.write_str("sqlserver connection string must select a database")
            }
            Self::ThreadPanic => f.write_str("sqlserver adapter worker thread panicked"),
        }
    }
}

impl Error for SqlServerAdapterError {}

impl From<tiberius::error::Error> for SqlServerAdapterError {
    fn from(err: tiberius::error::Error) -> Self {
        Self::Storage(err)
    }
}

impl From<std::io::Error> for SqlServerAdapterError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn introspect_sqlserver(
    connection_string: &str,
    connection_alias: &str,
) -> SqlServerAdapterResult<SchemaSnapshot> {
    let connection_string = connection_string.to_owned();
    let connection_alias = connection_alias.to_owned();

    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(move || {
            introspect_sqlserver_blocking(&connection_string, &connection_alias)
        })
        .join()
        .map_err(|_| SqlServerAdapterError::ThreadPanic)?
    } else {
        introspect_sqlserver_blocking(&connection_string, &connection_alias)
    }
}

fn introspect_sqlserver_blocking(
    connection_string: &str,
    connection_alias: &str,
) -> SqlServerAdapterResult<SchemaSnapshot> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut client = connect_sqlserver(connection_string).await?;
        introspect_sqlserver_client(&mut client, connection_alias).await
    })
}

async fn connect_sqlserver(connection_string: &str) -> SqlServerAdapterResult<TdsClient> {
    let mut config = Config::from_ado_string(connection_string).map_err(|err| {
        SqlServerAdapterError::Connection(redact_error_with_connection_string(
            err,
            connection_string,
        ))
    })?;
    config.readonly(true);
    let tcp = TcpStream::connect(config.get_addr()).await.map_err(|err| {
        SqlServerAdapterError::Connection(redact_error_with_connection_string(
            err,
            connection_string,
        ))
    })?;
    tcp.set_nodelay(true).map_err(|err| {
        SqlServerAdapterError::Connection(redact_error_with_connection_string(
            err,
            connection_string,
        ))
    })?;
    Client::connect(config, tcp.compat_write())
        .await
        .map_err(|err| {
            SqlServerAdapterError::Connection(redact_error_with_connection_string(
                err,
                connection_string,
            ))
        })
}

async fn introspect_sqlserver_client(
    client: &mut TdsClient,
    connection_alias: &str,
) -> SqlServerAdapterResult<SchemaSnapshot> {
    let database_name = current_database(client).await?;
    let database_key = key(
        connection_alias,
        &database_name,
        &database_name,
        ObjectKind::Database,
        &database_name,
        None,
    );
    let database = DatabaseObject {
        key: database_key.clone(),
        name: database_name.clone(),
    };

    let schema_names = schema_names(client).await?;
    let schemas = schema_names
        .iter()
        .map(|schema_name| SchemaObject {
            key: key(
                connection_alias,
                &database_name,
                schema_name,
                ObjectKind::Schema,
                schema_name,
                None,
            ),
            database_key: database_key.clone(),
            name: schema_name.clone(),
        })
        .collect::<Vec<_>>();
    let schema_keys = schemas
        .iter()
        .map(|schema| (schema.name.clone(), schema.key.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut tables = Vec::new();
    let mut table_keys = BTreeMap::new();
    for table in table_rows(client).await? {
        let Some(schema_key) = schema_keys.get(&table.schema).cloned() else {
            continue;
        };
        let table_key = key(
            connection_alias,
            &database_name,
            &table.schema,
            ObjectKind::Table,
            &table.name,
            None,
        );
        tables.push(TableObject {
            key: table_key.clone(),
            schema_key,
            name: table.name.clone(),
            kind: TableKind::BaseTable,
        });
        table_keys.insert((table.schema, table.name), table_key);
    }

    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    for column in column_rows(client).await? {
        let Some(table_key) = table_keys
            .get(&(column.schema.clone(), column.table.clone()))
            .cloned()
        else {
            continue;
        };
        let column_key = key(
            connection_alias,
            &database_name,
            &column.schema,
            ObjectKind::Column,
            &column.table,
            Some(column.name.clone()),
        );
        column_keys.insert(
            (
                column.schema.clone(),
                column.table.clone(),
                column.name.clone(),
            ),
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

    let constraints = constraint_rows(client)
        .await?
        .into_iter()
        .filter_map(|constraint| {
            let table_key = table_keys
                .get(&(constraint.schema.clone(), constraint.table.clone()))
                .cloned()?;
            let columns = constraint
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(
                            constraint.schema.clone(),
                            constraint.table.clone(),
                            column.clone(),
                        ))
                        .cloned()
                })
                .collect::<Vec<_>>();
            let referenced_table_key = constraint
                .referenced_schema
                .as_ref()
                .zip(constraint.referenced_table.as_ref())
                .and_then(|(schema, table)| table_keys.get(&(schema.clone(), table.clone())))
                .cloned();
            let referenced_columns = constraint
                .referenced_columns
                .iter()
                .filter_map(|column| {
                    constraint
                        .referenced_schema
                        .as_ref()
                        .zip(constraint.referenced_table.as_ref())
                        .and_then(|(schema, table)| {
                            column_keys
                                .get(&(schema.clone(), table.clone(), column.clone()))
                                .cloned()
                        })
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
                    &constraint.schema,
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

    let indexes = index_rows(client)
        .await?
        .into_iter()
        .filter_map(|index| {
            let table_key = table_keys
                .get(&(index.schema.clone(), index.table.clone()))
                .cloned()?;
            let columns = index
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(index.schema.clone(), index.table.clone(), column.clone()))
                        .cloned()
                })
                .collect::<Vec<_>>();
            Some(IndexObject {
                key: key(
                    connection_alias,
                    &database_name,
                    &index.schema,
                    ObjectKind::Index,
                    &index.table,
                    Some(index.name.clone()),
                ),
                table_key,
                name: index.name,
                columns,
                is_unique: index.is_unique,
                is_primary: index.is_primary,
                predicate: index.predicate,
                expression: None,
            })
        })
        .collect::<Vec<_>>();

    Ok(SchemaSnapshot {
        source_kind: "sqlserver".to_owned(),
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
        capabilities: sqlserver_capabilities(),
    })
}

async fn current_database(client: &mut TdsClient) -> SqlServerAdapterResult<String> {
    let row = client
        .simple_query("SELECT DB_NAME() AS database_name")
        .await?
        .into_row()
        .await?
        .ok_or(SqlServerAdapterError::MissingDatabase)?;
    row.get::<&str, _>(0)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or(SqlServerAdapterError::MissingDatabase)
}

async fn schema_names(client: &mut TdsClient) -> SqlServerAdapterResult<Vec<String>> {
    Ok(client
        .simple_query(
            "
            SELECT DISTINCT s.name
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name
            ",
        )
        .await?
        .into_first_result()
        .await?
        .into_iter()
        .map(|row| row_str(&row, 0))
        .collect())
}

struct TableRow {
    schema: String,
    name: String,
}

async fn table_rows(client: &mut TdsClient) -> SqlServerAdapterResult<Vec<TableRow>> {
    Ok(client
        .simple_query(
            "
            SELECT s.name, t.name
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name
            ",
        )
        .await?
        .into_first_result()
        .await?
        .into_iter()
        .map(|row| TableRow {
            schema: row_str(&row, 0),
            name: row_str(&row, 1),
        })
        .collect())
}

struct ColumnRow {
    schema: String,
    table: String,
    name: String,
    ordinal_position: u32,
    data_type: String,
    is_nullable: bool,
    default_value: Option<String>,
    is_generated: bool,
}

async fn column_rows(client: &mut TdsClient) -> SqlServerAdapterResult<Vec<ColumnRow>> {
    Ok(client
        .simple_query(
            "
            SELECT s.name,
                   t.name,
                   c.name,
                   c.column_id,
                   ty.name,
                   c.is_nullable,
                   dc.definition,
                   c.is_computed
            FROM sys.columns c
            JOIN sys.tables t ON t.object_id = c.object_id
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.types ty ON ty.user_type_id = c.user_type_id
            LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, c.column_id
            ",
        )
        .await?
        .into_first_result()
        .await?
        .into_iter()
        .map(|row| ColumnRow {
            schema: row_str(&row, 0),
            table: row_str(&row, 1),
            name: row_str(&row, 2),
            ordinal_position: row.get::<i32, _>(3).unwrap_or_default() as u32,
            data_type: row_str(&row, 4),
            is_nullable: row.get::<bool, _>(5).unwrap_or(false),
            default_value: row_opt_str(&row, 6),
            is_generated: row.get::<bool, _>(7).unwrap_or(false),
        })
        .collect())
}

struct ConstraintRow {
    schema: String,
    table: String,
    name: String,
    kind: ConstraintKind,
    columns: Vec<String>,
    referenced_schema: Option<String>,
    referenced_table: Option<String>,
    referenced_columns: Vec<String>,
}

async fn constraint_rows(client: &mut TdsClient) -> SqlServerAdapterResult<Vec<ConstraintRow>> {
    let key_rows = client
        .simple_query(
            "
            SELECT s.name,
                   t.name,
                   kc.name,
                   kc.type,
                   c.name
            FROM sys.key_constraints kc
            JOIN sys.tables t ON t.object_id = kc.parent_object_id
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.index_columns ic
              ON ic.object_id = kc.parent_object_id
             AND ic.index_id = kc.unique_index_id
             AND ic.key_ordinal > 0
            JOIN sys.columns c
              ON c.object_id = ic.object_id
             AND c.column_id = ic.column_id
            WHERE t.is_ms_shipped = 0
              AND kc.type IN ('PK', 'UQ')
            ORDER BY s.name, t.name, kc.name, ic.key_ordinal
            ",
        )
        .await?
        .into_first_result()
        .await?;

    let mut grouped = BTreeMap::<(String, String, String), ConstraintRow>::new();
    for row in key_rows {
        let schema = row_str(&row, 0);
        let table = row_str(&row, 1);
        let name = row_str(&row, 2);
        let kind = match row_str(&row, 3).as_str() {
            "PK" => ConstraintKind::PrimaryKey,
            _ => ConstraintKind::Unique,
        };
        grouped
            .entry((schema.clone(), table.clone(), name.clone()))
            .or_insert_with(|| ConstraintRow {
                schema,
                table,
                name,
                kind,
                columns: vec![],
                referenced_schema: None,
                referenced_table: None,
                referenced_columns: vec![],
            })
            .columns
            .push(row_str(&row, 4));
    }

    let fk_rows = client
        .simple_query(
            "
            SELECT ps.name,
                   pt.name,
                   fk.name,
                   pc.name,
                   rs.name,
                   rt.name,
                   rc.name
            FROM sys.foreign_keys fk
            JOIN sys.tables pt ON pt.object_id = fk.parent_object_id
            JOIN sys.schemas ps ON ps.schema_id = pt.schema_id
            JOIN sys.tables rt ON rt.object_id = fk.referenced_object_id
            JOIN sys.schemas rs ON rs.schema_id = rt.schema_id
            JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
            JOIN sys.columns pc
              ON pc.object_id = fkc.parent_object_id
             AND pc.column_id = fkc.parent_column_id
            JOIN sys.columns rc
              ON rc.object_id = fkc.referenced_object_id
             AND rc.column_id = fkc.referenced_column_id
            WHERE pt.is_ms_shipped = 0
            ORDER BY ps.name, pt.name, fk.name, fkc.constraint_column_id
            ",
        )
        .await?
        .into_first_result()
        .await?;

    for row in fk_rows {
        let schema = row_str(&row, 0);
        let table = row_str(&row, 1);
        let name = row_str(&row, 2);
        let entry = grouped
            .entry((schema.clone(), table.clone(), name.clone()))
            .or_insert_with(|| ConstraintRow {
                schema,
                table,
                name,
                kind: ConstraintKind::ForeignKey,
                columns: vec![],
                referenced_schema: Some(row_str(&row, 4)),
                referenced_table: Some(row_str(&row, 5)),
                referenced_columns: vec![],
            });
        entry.columns.push(row_str(&row, 3));
        entry.referenced_schema = Some(row_str(&row, 4));
        entry.referenced_table = Some(row_str(&row, 5));
        entry.referenced_columns.push(row_str(&row, 6));
    }

    Ok(grouped.into_values().collect())
}

#[derive(Default)]
struct IndexRow {
    schema: String,
    table: String,
    name: String,
    columns: Vec<String>,
    is_unique: bool,
    is_primary: bool,
    predicate: Option<String>,
}

async fn index_rows(client: &mut TdsClient) -> SqlServerAdapterResult<Vec<IndexRow>> {
    let rows = client
        .simple_query(
            "
            SELECT s.name,
                   t.name,
                   i.name,
                   c.name,
                   i.is_unique,
                   i.is_primary_key,
                   i.filter_definition
            FROM sys.indexes i
            JOIN sys.tables t ON t.object_id = i.object_id
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.index_columns ic
              ON ic.object_id = i.object_id
             AND ic.index_id = i.index_id
             AND ic.key_ordinal > 0
            JOIN sys.columns c
              ON c.object_id = ic.object_id
             AND c.column_id = ic.column_id
            WHERE t.is_ms_shipped = 0
              AND i.index_id > 0
              AND i.is_hypothetical = 0
            ORDER BY s.name, t.name, i.name, ic.key_ordinal
            ",
        )
        .await?
        .into_first_result()
        .await?;

    let mut grouped = BTreeMap::<(String, String, String), IndexRow>::new();
    for row in rows {
        let schema = row_str(&row, 0);
        let table = row_str(&row, 1);
        let name = row_str(&row, 2);
        let entry = grouped
            .entry((schema.clone(), table.clone(), name.clone()))
            .or_insert_with(|| IndexRow {
                schema,
                table,
                name,
                columns: vec![],
                is_unique: row.get::<bool, _>(4).unwrap_or(false),
                is_primary: row.get::<bool, _>(5).unwrap_or(false),
                predicate: row_opt_str(&row, 6),
            });
        entry.columns.push(row_str(&row, 3));
    }

    Ok(grouped.into_values().collect())
}

fn row_str(row: &Row, index: usize) -> String {
    row.get::<&str, _>(index).unwrap_or_default().to_owned()
}

fn row_opt_str(row: &Row, index: usize) -> Option<String> {
    row.get::<&str, _>(index).map(str::to_owned)
}

fn key(
    connection_alias: &str,
    database: &str,
    schema: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        "sqlserver",
        connection_alias,
        database,
        schema,
        object_kind,
        object_name,
        sub_object,
    )
}

fn sqlserver_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: "sqlserver".to_owned(),
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
        notes: vec![
            "Reads SQL Server sys catalog metadata only; no user table rows are read.".to_owned(),
            "Level 1 extracts schemas, base tables, columns, primary keys, foreign keys, unique constraints, and indexes.".to_owned(),
            "Level 1 does not extract views, triggers, routines, or cross-object dependency metadata.".to_owned(),
        ],
    }
}

#[cfg(test)]
mod sqlserver_adapter_tests {
    use super::*;

    const TEST_URL_ENV: &str = "DATABASE_MEMORY_TEST_SQLSERVER_URL";

    #[test]
    fn sqlserver_capabilities_are_level_1_metadata_only() {
        let capabilities = sqlserver_capabilities();

        assert_eq!(capabilities.source_kind, "sqlserver");
        assert!(capabilities.metadata_only);
        assert!(capabilities.schemas);
        assert!(capabilities.tables);
        assert!(capabilities.columns);
        assert!(capabilities.constraints);
        assert!(capabilities.indexes);
        assert_eq!(capabilities.views, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.triggers, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.routines, CapabilitySupport::Unsupported);
        assert_eq!(capabilities.dependencies, CapabilitySupport::Unsupported);
        assert!(capabilities
            .notes
            .iter()
            .any(|note| note.contains("sys catalog metadata only")));
    }

    #[test]
    fn sqlserver_adapter_live_introspection_is_env_gated() {
        let Ok(connection_string) = std::env::var(TEST_URL_ENV) else {
            eprintln!("skipping live SQL Server adapter test; set {TEST_URL_ENV} to run it");
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
        let schema = format!("dm_mcp_{suffix}");
        let users = format!("users_{suffix}");
        let orders = format!("orders_{suffix}");
        let pk_users = format!("pk_users_{suffix}");
        let uq_users = format!("uq_users_{suffix}");
        let pk_orders = format!("pk_orders_{suffix}");
        let fk_orders_users = format!("fk_orders_users_{suffix}");
        let idx_orders_user_id = format!("idx_orders_user_id_{suffix}");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime
            .block_on(async {
                let mut client = connect_sqlserver(&connection_string).await.unwrap();
                cleanup(&mut client, &schema, &orders, &users).await.unwrap();
                run_batch(&mut client, &format!("CREATE SCHEMA {schema}")).await?;
                run_batch(
                    &mut client,
                    &format!(
                        "CREATE TABLE {schema}.{users} (
                            id INT NOT NULL CONSTRAINT {pk_users} PRIMARY KEY,
                            email NVARCHAR(255) NOT NULL CONSTRAINT {uq_users} UNIQUE
                        )"
                    ),
                )
                .await?;
                run_batch(
                    &mut client,
                    &format!(
                        "CREATE TABLE {schema}.{orders} (
                            id INT NOT NULL CONSTRAINT {pk_orders} PRIMARY KEY,
                            user_id INT NOT NULL,
                            total DECIMAL(10,2) NULL CONSTRAINT df_orders_total_{suffix} DEFAULT 0,
                            CONSTRAINT {fk_orders_users} FOREIGN KEY (user_id) REFERENCES {schema}.{users}(id)
                        )"
                    ),
                )
                .await?;
                run_batch(
                    &mut client,
                    &format!("CREATE INDEX {idx_orders_user_id} ON {schema}.{orders}(user_id)"),
                )
                .await?;
                Ok::<(), SqlServerAdapterError>(())
            })
            .unwrap();

        let snapshot = introspect_sqlserver(&connection_string, "sqlserver-test").unwrap();

        runtime
            .block_on(async {
                let mut client = connect_sqlserver(&connection_string).await.unwrap();
                cleanup(&mut client, &schema, &orders, &users).await
            })
            .unwrap();

        assert_eq!(snapshot.source_kind, "sqlserver");
        assert_eq!(snapshot.connection_alias, "sqlserver-test");
        assert!(snapshot.capabilities.metadata_only);
        assert!(snapshot.schemas.iter().any(|item| item.name == schema));
        assert!(snapshot.tables.iter().any(|item| {
            item.name == orders && item.key.schema == schema && item.kind == TableKind::BaseTable
        }));
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
            item.name == idx_orders_user_id
                && item.table_key.object_name == orders
                && !item.is_unique
        }));
    }

    async fn cleanup(
        client: &mut TdsClient,
        schema: &str,
        orders: &str,
        users: &str,
    ) -> SqlServerAdapterResult<()> {
        run_batch(client, &format!("DROP TABLE IF EXISTS {schema}.{orders}")).await?;
        run_batch(client, &format!("DROP TABLE IF EXISTS {schema}.{users}")).await?;
        run_batch(client, &format!("DROP SCHEMA IF EXISTS {schema}")).await
    }

    async fn run_batch(client: &mut TdsClient, sql: &str) -> SqlServerAdapterResult<()> {
        client.simple_query(sql).await?.into_results().await?;
        Ok(())
    }
}
