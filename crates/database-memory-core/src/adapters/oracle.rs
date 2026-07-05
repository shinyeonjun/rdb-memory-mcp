use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use oracle::Connection;

use crate::redact::redact_error_with_connection_string;
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};

pub type OracleAdapterResult<T> = Result<T, OracleAdapterError>;

#[derive(Debug)]
pub enum OracleAdapterError {
    Connection(String),
    Storage(oracle::Error),
    InvalidConnectionString,
}

impl fmt::Display for OracleAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "oracle adapter connection error: {err}"),
            Self::Storage(err) => write!(f, "oracle adapter storage error: {err}"),
            Self::InvalidConnectionString => {
                f.write_str("oracle connection string must be user/password@connect_string")
            }
        }
    }
}

impl Error for OracleAdapterError {}

impl From<oracle::Error> for OracleAdapterError {
    fn from(err: oracle::Error) -> Self {
        Self::Storage(err)
    }
}

pub fn introspect_oracle(
    connection_string: &str,
    connection_alias: &str,
) -> OracleAdapterResult<SchemaSnapshot> {
    let parsed = parse_oracle_connection_string(connection_string)?;
    let conn = Connection::connect(parsed.username, parsed.password, parsed.connect_string)
        .map_err(|err| {
            OracleAdapterError::Connection(redact_error_with_connection_string(
                err,
                connection_string,
            ))
        })?;
    introspect_oracle_conn(&conn, connection_alias)
}

fn introspect_oracle_conn(
    conn: &Connection,
    connection_alias: &str,
) -> OracleAdapterResult<SchemaSnapshot> {
    let database_name = current_database(conn)?;
    let schema_name = current_schema(conn)?;
    let database_key = key(
        connection_alias,
        &database_name,
        &schema_name,
        ObjectKind::Database,
        &database_name,
        None,
    );
    let schema_key = key(
        connection_alias,
        &database_name,
        &schema_name,
        ObjectKind::Schema,
        &schema_name,
        None,
    );

    let database = DatabaseObject {
        key: database_key.clone(),
        name: database_name.clone(),
    };
    let schemas = vec![SchemaObject {
        key: schema_key.clone(),
        database_key,
        name: schema_name.clone(),
    }];

    let mut tables = Vec::new();
    let mut table_keys = BTreeMap::new();
    for table in table_rows(conn, &schema_name)? {
        let table_key = key(
            connection_alias,
            &database_name,
            &table.owner,
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
        table_keys.insert((table.owner, table.name), table_key);
    }

    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    for column in column_rows(conn, &schema_name)? {
        let Some(table_key) = table_keys
            .get(&(column.owner.clone(), column.table.clone()))
            .cloned()
        else {
            continue;
        };
        let column_key = key(
            connection_alias,
            &database_name,
            &column.owner,
            ObjectKind::Column,
            &column.table,
            Some(column.name.clone()),
        );
        column_keys.insert(
            (
                column.owner.clone(),
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
            is_generated: false,
        });
    }

    let constraints = constraint_rows(conn, &schema_name)?
        .into_iter()
        .filter_map(|constraint| {
            let table_key = table_keys
                .get(&(constraint.owner.clone(), constraint.table.clone()))
                .cloned()?;
            let columns = constraint
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(
                            constraint.owner.clone(),
                            constraint.table.clone(),
                            column.clone(),
                        ))
                        .cloned()
                })
                .collect::<Vec<_>>();
            let referenced_table_key = constraint
                .referenced_owner
                .as_ref()
                .zip(constraint.referenced_table.as_ref())
                .and_then(|(owner, table)| table_keys.get(&(owner.clone(), table.clone())))
                .cloned();
            let referenced_columns = constraint
                .referenced_columns
                .iter()
                .filter_map(|column| {
                    constraint
                        .referenced_owner
                        .as_ref()
                        .zip(constraint.referenced_table.as_ref())
                        .and_then(|(owner, table)| {
                            column_keys
                                .get(&(owner.clone(), table.clone(), column.clone()))
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
                    &constraint.owner,
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

    let indexes = index_rows(conn, &schema_name)?
        .into_iter()
        .filter_map(|index| {
            let table_key = table_keys
                .get(&(index.owner.clone(), index.table.clone()))
                .cloned()?;
            let columns = index
                .columns
                .iter()
                .filter_map(|column| {
                    column_keys
                        .get(&(index.owner.clone(), index.table.clone(), column.clone()))
                        .cloned()
                })
                .collect::<Vec<_>>();
            Some(IndexObject {
                key: key(
                    connection_alias,
                    &database_name,
                    &index.owner,
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
        source_kind: "oracle".to_owned(),
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
        capabilities: oracle_capabilities(),
    })
}

struct ParsedOracleConnection<'a> {
    username: &'a str,
    password: &'a str,
    connect_string: &'a str,
}

fn parse_oracle_connection_string(value: &str) -> OracleAdapterResult<ParsedOracleConnection<'_>> {
    let (username, rest) = value
        .split_once('/')
        .ok_or(OracleAdapterError::InvalidConnectionString)?;
    let (password, connect_string) = rest
        .rsplit_once('@')
        .ok_or(OracleAdapterError::InvalidConnectionString)?;
    if username.is_empty() || password.is_empty() || connect_string.is_empty() {
        return Err(OracleAdapterError::InvalidConnectionString);
    }
    Ok(ParsedOracleConnection {
        username,
        password,
        connect_string,
    })
}

fn current_database(conn: &Connection) -> OracleAdapterResult<String> {
    Ok(conn.query_row_as("SELECT SYS_CONTEXT('USERENV', 'DB_NAME') FROM DUAL", &[])?)
}

fn current_schema(conn: &Connection) -> OracleAdapterResult<String> {
    Ok(conn.query_row_as(
        "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL",
        &[],
    )?)
}

struct TableRow {
    owner: String,
    name: String,
    kind: TableKind,
}

fn table_rows(conn: &Connection, owner: &str) -> OracleAdapterResult<Vec<TableRow>> {
    let rows = conn.query_as::<(String, String, String)>(
        "
        SELECT OWNER,
               TABLE_NAME,
               TEMPORARY
        FROM ALL_TABLES
        WHERE OWNER = :1
          AND NESTED = 'NO'
          AND SECONDARY = 'N'
          AND TABLE_NAME NOT LIKE 'BIN$%'
        ORDER BY OWNER, TABLE_NAME
        ",
        &[&owner],
    )?;

    let mut out = Vec::new();
    for row in rows {
        let (owner, name, temporary) = row?;
        out.push(TableRow {
            owner,
            name,
            kind: if temporary == "Y" {
                TableKind::Temporary
            } else {
                TableKind::BaseTable
            },
        });
    }
    Ok(out)
}

struct ColumnRow {
    owner: String,
    table: String,
    name: String,
    ordinal_position: u32,
    data_type: String,
    is_nullable: bool,
    default_value: Option<String>,
}

fn column_rows(conn: &Connection, owner: &str) -> OracleAdapterResult<Vec<ColumnRow>> {
    let rows = conn.query_as::<(String, String, String, i64, String, String, Option<String>)>(
        "
        SELECT OWNER,
               TABLE_NAME,
               COLUMN_NAME,
               COLUMN_ID,
               DATA_TYPE,
               NULLABLE,
               DATA_DEFAULT
        FROM ALL_TAB_COLUMNS
        WHERE OWNER = :1
        ORDER BY OWNER, TABLE_NAME, COLUMN_ID
        ",
        &[&owner],
    )?;

    let mut out = Vec::new();
    for row in rows {
        let (owner, table, name, ordinal_position, data_type, nullable, default_value) = row?;
        out.push(ColumnRow {
            owner,
            table,
            name,
            ordinal_position: ordinal_position as u32,
            data_type,
            is_nullable: nullable == "Y",
            default_value: default_value.map(|value| value.trim().to_owned()),
        });
    }
    Ok(out)
}

struct ConstraintRow {
    owner: String,
    table: String,
    name: String,
    kind: ConstraintKind,
    columns: Vec<String>,
    referenced_owner: Option<String>,
    referenced_table: Option<String>,
    referenced_columns: Vec<String>,
}

fn constraint_rows(conn: &Connection, owner: &str) -> OracleAdapterResult<Vec<ConstraintRow>> {
    let rows = conn.query_as::<(
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    )>(
        "
        SELECT c.OWNER,
               c.TABLE_NAME,
               c.CONSTRAINT_NAME,
               c.CONSTRAINT_TYPE,
               col.COLUMN_NAME,
               ref_c.OWNER,
               ref_c.TABLE_NAME,
               ref_col.COLUMN_NAME,
               col.POSITION
        FROM ALL_CONSTRAINTS c
        JOIN ALL_CONS_COLUMNS col
          ON col.OWNER = c.OWNER
         AND col.CONSTRAINT_NAME = c.CONSTRAINT_NAME
        LEFT JOIN ALL_CONSTRAINTS ref_c
          ON c.CONSTRAINT_TYPE = 'R'
         AND ref_c.OWNER = c.R_OWNER
         AND ref_c.CONSTRAINT_NAME = c.R_CONSTRAINT_NAME
        LEFT JOIN ALL_CONS_COLUMNS ref_col
          ON ref_col.OWNER = ref_c.OWNER
         AND ref_col.CONSTRAINT_NAME = ref_c.CONSTRAINT_NAME
         AND ref_col.POSITION = col.POSITION
        WHERE c.OWNER = :1
          AND c.CONSTRAINT_TYPE IN ('P', 'U', 'R')
        ORDER BY c.OWNER, c.TABLE_NAME, c.CONSTRAINT_NAME, col.POSITION
        ",
        &[&owner],
    )?;

    let mut grouped = BTreeMap::<(String, String, String), ConstraintRow>::new();
    for row in rows {
        let (
            owner,
            table,
            name,
            constraint_type,
            column,
            referenced_owner,
            referenced_table,
            referenced_column,
            _position,
        ) = row?;
        let kind = match constraint_type.as_str() {
            "P" => ConstraintKind::PrimaryKey,
            "R" => ConstraintKind::ForeignKey,
            _ => ConstraintKind::Unique,
        };
        let entry = grouped
            .entry((owner.clone(), table.clone(), name.clone()))
            .or_insert_with(|| ConstraintRow {
                owner,
                table,
                name,
                kind,
                columns: vec![],
                referenced_owner: None,
                referenced_table: None,
                referenced_columns: vec![],
            });
        entry.columns.push(column);
        if entry.kind == ConstraintKind::ForeignKey {
            entry.referenced_owner = referenced_owner;
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
    owner: String,
    table: String,
    name: String,
    columns: Vec<String>,
    is_unique: bool,
    is_primary: bool,
}

fn index_rows(conn: &Connection, owner: &str) -> OracleAdapterResult<Vec<IndexRow>> {
    let rows = conn.query_as::<(String, String, String, String, String, Option<String>, i64)>(
        "
        SELECT i.TABLE_OWNER,
               i.TABLE_NAME,
               i.INDEX_NAME,
               i.UNIQUENESS,
               CASE WHEN pk.CONSTRAINT_NAME IS NULL THEN 'NO' ELSE 'YES' END,
               col.COLUMN_NAME,
               col.COLUMN_POSITION
        FROM ALL_INDEXES i
        JOIN ALL_IND_COLUMNS col
          ON col.INDEX_OWNER = i.OWNER
         AND col.INDEX_NAME = i.INDEX_NAME
         AND col.TABLE_OWNER = i.TABLE_OWNER
         AND col.TABLE_NAME = i.TABLE_NAME
        LEFT JOIN ALL_CONSTRAINTS pk
          ON pk.OWNER = i.TABLE_OWNER
         AND pk.TABLE_NAME = i.TABLE_NAME
         AND pk.INDEX_OWNER = i.OWNER
         AND pk.INDEX_NAME = i.INDEX_NAME
         AND pk.CONSTRAINT_TYPE = 'P'
        WHERE i.TABLE_OWNER = :1
        ORDER BY i.TABLE_OWNER, i.TABLE_NAME, i.INDEX_NAME, col.COLUMN_POSITION
        ",
        &[&owner],
    )?;

    let mut grouped = BTreeMap::<(String, String, String), IndexRow>::new();
    for row in rows {
        let (owner, table, name, uniqueness, primary, column, _position) = row?;
        let entry = grouped
            .entry((owner.clone(), table.clone(), name.clone()))
            .or_insert_with(|| IndexRow {
                owner,
                table,
                name,
                columns: vec![],
                is_unique: uniqueness == "UNIQUE",
                is_primary: primary == "YES",
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
    schema: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        "oracle",
        connection_alias,
        database,
        schema,
        object_kind,
        object_name,
        sub_object,
    )
}

fn oracle_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: "oracle".to_owned(),
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
            "Reads Oracle ALL_* data dictionary metadata only; no user table rows are read.".to_owned(),
            "Oracle users/owners are mapped to the common schema field; Phase 21 scopes introspection to the current schema.".to_owned(),
            "Level 1 does not extract views, triggers, routines, or cross-object dependency metadata.".to_owned(),
        ],
    }
}

#[cfg(test)]
mod oracle_adapter_tests {
    use super::*;

    const TEST_URL_ENV: &str = "DATABASE_MEMORY_TEST_ORACLE_URL";

    #[test]
    fn oracle_capabilities_are_level_1_metadata_only() {
        let capabilities = oracle_capabilities();

        assert_eq!(capabilities.source_kind, "oracle");
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
            .any(|note| note.contains("ALL_* data dictionary metadata only")));
    }

    #[test]
    fn oracle_connection_string_parser_splits_user_password_and_connect_string() {
        let parsed = parse_oracle_connection_string("scott/tiger@localhost:1521/FREEPDB1").unwrap();

        assert_eq!(parsed.username, "scott");
        assert_eq!(parsed.password, "tiger");
        assert_eq!(parsed.connect_string, "localhost:1521/FREEPDB1");
        assert!(parse_oracle_connection_string("scott/tiger").is_err());
    }

    #[test]
    fn oracle_adapter_live_introspection_is_env_gated() {
        let Ok(connection_string) = std::env::var(TEST_URL_ENV) else {
            eprintln!("skipping live Oracle adapter test; set {TEST_URL_ENV} to run it");
            return;
        };

        let parsed = parse_oracle_connection_string(&connection_string).unwrap();
        let conn =
            Connection::connect(parsed.username, parsed.password, parsed.connect_string).unwrap();
        let suffix = format!(
            "{}_{}",
            std::process::id() % 10000,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 1_000_000
        );
        let users = format!("DMU_{suffix}");
        let orders = format!("DMO_{suffix}");
        let fk = format!("DMF_{suffix}");
        let idx = format!("DMI_{suffix}");

        cleanup(&conn, &orders, &users).unwrap();
        conn.execute(
            &format!(
                "CREATE TABLE {users} (
                    id NUMBER(10) NOT NULL CONSTRAINT PK_{users} PRIMARY KEY,
                    email VARCHAR2(255) NOT NULL CONSTRAINT UQ_{users} UNIQUE
                )"
            ),
            &[],
        )
        .unwrap();
        conn.execute(
            &format!(
                "CREATE TABLE {orders} (
                    id NUMBER(10) NOT NULL CONSTRAINT PK_{orders} PRIMARY KEY,
                    user_id NUMBER(10) NOT NULL,
                    total NUMBER(10,2) DEFAULT 0,
                    CONSTRAINT {fk} FOREIGN KEY (user_id) REFERENCES {users}(id)
                )"
            ),
            &[],
        )
        .unwrap();
        conn.execute(&format!("CREATE INDEX {idx} ON {orders}(user_id)"), &[])
            .unwrap();

        let snapshot = introspect_oracle(&connection_string, "oracle-test").unwrap();

        cleanup(&conn, &orders, &users).unwrap();

        assert_eq!(snapshot.source_kind, "oracle");
        assert_eq!(snapshot.connection_alias, "oracle-test");
        assert!(snapshot.capabilities.metadata_only);
        assert!(snapshot
            .tables
            .iter()
            .any(|item| { item.name == orders && item.kind == TableKind::BaseTable }));
        assert!(snapshot.columns.iter().any(|item| {
            item.table_key.object_name == orders
                && item.name == "USER_ID"
                && item.data_type == "NUMBER"
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

    fn cleanup(conn: &Connection, orders: &str, users: &str) -> OracleAdapterResult<()> {
        drop_table_if_exists(conn, orders)?;
        drop_table_if_exists(conn, users)
    }

    fn drop_table_if_exists(conn: &Connection, table: &str) -> OracleAdapterResult<()> {
        conn.execute(
            &format!(
                "BEGIN
                    EXECUTE IMMEDIATE 'DROP TABLE {table} CASCADE CONSTRAINTS PURGE';
                 EXCEPTION
                    WHEN OTHERS THEN
                        IF SQLCODE != -942 THEN
                            RAISE;
                        END IF;
                 END;"
            ),
            &[],
        )?;
        Ok(())
    }
}
