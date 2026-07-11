use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use postgres::{Client, NoTls};

use crate::redact::redact_error_with_connection_string;
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, RoutineKind, RoutineObject, SchemaObject,
    SchemaSnapshot, TableKind, TableObject, TriggerObject, ViewObject,
};

pub type PostgresAdapterResult<T> = Result<T, PostgresAdapterError>;

#[derive(Debug)]
pub enum PostgresAdapterError {
    Connection(String),
    Storage(postgres::Error),
}

impl fmt::Display for PostgresAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(err) => write!(f, "postgres adapter connection error: {err}"),
            Self::Storage(err) => write!(f, "postgres adapter storage error: {err}"),
        }
    }
}

impl Error for PostgresAdapterError {}

impl From<postgres::Error> for PostgresAdapterError {
    fn from(err: postgres::Error) -> Self {
        Self::Storage(err)
    }
}

pub fn introspect_postgres(
    connection_string: &str,
    connection_alias: &str,
) -> PostgresAdapterResult<SchemaSnapshot> {
    let mut client = Client::connect(connection_string, NoTls).map_err(|err| {
        PostgresAdapterError::Connection(redact_error_with_connection_string(
            err,
            connection_string,
        ))
    })?;
    introspect_postgres_client(&mut client, connection_alias)
}

fn introspect_postgres_client(
    client: &mut Client,
    connection_alias: &str,
) -> PostgresAdapterResult<SchemaSnapshot> {
    let database_name: String = client.query_one("SELECT current_database()", &[])?.get(0);
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

    let schema_names = schema_names(client)?;
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
    for table in table_rows(client)? {
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
            kind: table.kind,
        });
        table_keys.insert((table.schema, table.name), table_key);
    }

    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    for column in column_rows(client)? {
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

    let constraints = constraint_rows(client)?
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

    let indexes = index_rows(client)?
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
                expression: index.expression,
            })
        })
        .collect::<Vec<_>>();

    let view_dependencies = view_dependency_rows(client)?;
    let views = view_rows(client)?
        .into_iter()
        .filter_map(|view| {
            let schema_key = schema_keys.get(&view.schema).cloned()?;
            let depends_on = view_dependencies
                .get(&(view.schema.clone(), view.name.clone()))
                .map(|dependencies| resolve_dependencies(dependencies, &table_keys, &column_keys))
                .unwrap_or_default();
            Some(ViewObject {
                key: key(
                    connection_alias,
                    &database_name,
                    &view.schema,
                    ObjectKind::View,
                    &view.name,
                    None,
                ),
                schema_key,
                name: view.name,
                definition: view.definition,
                depends_on,
            })
        })
        .collect::<Vec<_>>();

    let routine_rows = routine_rows(client)?;
    let mut routine_keys_by_oid = BTreeMap::new();
    for routine in &routine_rows {
        if let Some(oid) = &routine.oid {
            routine_keys_by_oid.insert(
                oid.clone(),
                key(
                    connection_alias,
                    &database_name,
                    &routine.schema,
                    ObjectKind::Routine,
                    &routine.name,
                    Some(routine.specific_name.clone()),
                ),
            );
        }
    }
    let routine_dependencies = routine_dependency_rows(client)?;
    let routines = routine_rows
        .into_iter()
        .filter_map(|routine| {
            let schema_key = schema_keys.get(&routine.schema).cloned()?;
            let depends_on = routine
                .oid
                .as_ref()
                .and_then(|oid| routine_dependencies.get(oid))
                .map(|dependencies| resolve_dependencies(dependencies, &table_keys, &column_keys))
                .unwrap_or_default();
            Some(RoutineObject {
                key: key(
                    connection_alias,
                    &database_name,
                    &routine.schema,
                    ObjectKind::Routine,
                    &routine.name,
                    Some(routine.specific_name),
                ),
                schema_key,
                name: routine.name,
                kind: routine.kind,
                definition: routine.definition,
                depends_on,
            })
        })
        .collect::<Vec<_>>();

    let triggers = trigger_rows(client)?
        .into_iter()
        .filter_map(|trigger| {
            let table_key = table_keys
                .get(&(trigger.schema.clone(), trigger.table.clone()))
                .cloned()?;
            Some(TriggerObject {
                key: key(
                    connection_alias,
                    &database_name,
                    &trigger.schema,
                    ObjectKind::Trigger,
                    &trigger.table,
                    Some(trigger.name.clone()),
                ),
                table_key,
                name: trigger.name,
                timing: trigger.timing,
                events: trigger.events,
                definition: trigger.definition,
                executes_routine_key: trigger
                    .routine_oid
                    .and_then(|oid| routine_keys_by_oid.get(&oid).cloned()),
            })
        })
        .collect::<Vec<_>>();

    Ok(SchemaSnapshot {
        source_kind: "postgres".to_owned(),
        connection_alias: connection_alias.to_owned(),
        database,
        schemas,
        tables,
        columns,
        constraints,
        indexes,
        views,
        triggers,
        routines,
        capabilities: postgres_capabilities(),
    })
}

fn schema_names(client: &mut Client) -> PostgresAdapterResult<Vec<String>> {
    let rows = client.query(
        "
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name <> 'information_schema'
          AND schema_name NOT LIKE 'pg_%'
        ORDER BY schema_name
        ",
        &[],
    )?;
    Ok(rows.into_iter().map(|row| row.get(0)).collect())
}

struct TableRow {
    schema: String,
    name: String,
    kind: TableKind,
}

fn table_rows(client: &mut Client) -> PostgresAdapterResult<Vec<TableRow>> {
    let rows = client.query(
        "
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_schema <> 'information_schema'
          AND table_schema NOT LIKE 'pg_%'
          AND table_type IN ('BASE TABLE', 'FOREIGN TABLE')
        ORDER BY table_schema, table_name
        ",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| TableRow {
            schema: row.get(0),
            name: row.get(1),
            kind: match row.get::<_, String>(2).as_str() {
                "FOREIGN TABLE" => TableKind::Foreign,
                _ => TableKind::BaseTable,
            },
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

fn column_rows(client: &mut Client) -> PostgresAdapterResult<Vec<ColumnRow>> {
    let rows = client.query(
        "
        SELECT table_schema,
               table_name,
               column_name,
               ordinal_position,
               data_type,
               is_nullable,
               column_default,
               is_generated
        FROM information_schema.columns
        WHERE table_schema <> 'information_schema'
          AND table_schema NOT LIKE 'pg_%'
        ORDER BY table_schema, table_name, ordinal_position
        ",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| ColumnRow {
            schema: row.get(0),
            table: row.get(1),
            name: row.get(2),
            ordinal_position: row.get::<_, i32>(3) as u32,
            data_type: row.get(4),
            is_nullable: row.get::<_, String>(5) == "YES",
            default_value: row.get(6),
            is_generated: row.get::<_, String>(7) != "NEVER",
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

fn constraint_rows(client: &mut Client) -> PostgresAdapterResult<Vec<ConstraintRow>> {
    let rows = client.query(
        "
        SELECT ns.nspname,
               tbl.relname,
               con.conname,
               con.contype::text,
               att.attname,
               ref_ns.nspname,
               ref_tbl.relname,
               ref_att.attname,
               key_part.ordinality
        FROM pg_catalog.pg_constraint con
        JOIN pg_catalog.pg_class tbl ON tbl.oid = con.conrelid
        JOIN pg_catalog.pg_namespace ns ON ns.oid = tbl.relnamespace
        JOIN unnest(con.conkey) WITH ORDINALITY AS key_part(attnum, ordinality) ON true
        JOIN pg_catalog.pg_attribute att
          ON att.attrelid = con.conrelid AND att.attnum = key_part.attnum
        LEFT JOIN pg_catalog.pg_class ref_tbl ON ref_tbl.oid = con.confrelid
        LEFT JOIN pg_catalog.pg_namespace ref_ns ON ref_ns.oid = ref_tbl.relnamespace
        LEFT JOIN unnest(con.confkey) WITH ORDINALITY AS ref_part(attnum, ordinality)
          ON ref_part.ordinality = key_part.ordinality
        LEFT JOIN pg_catalog.pg_attribute ref_att
          ON ref_att.attrelid = con.confrelid AND ref_att.attnum = ref_part.attnum
        WHERE con.contype IN ('p', 'u', 'f')
          AND ns.nspname <> 'information_schema'
          AND ns.nspname NOT LIKE 'pg_%'
        ORDER BY ns.nspname, tbl.relname, con.conname, key_part.ordinality
        ",
        &[],
    )?;

    let mut grouped = BTreeMap::<(String, String, String), ConstraintRow>::new();
    for row in rows {
        let schema: String = row.get(0);
        let table: String = row.get(1);
        let name: String = row.get(2);
        let contype: String = row.get(3);
        let column: String = row.get(4);
        let entry = grouped
            .entry((schema.clone(), table.clone(), name.clone()))
            .or_insert_with(|| ConstraintRow {
                schema,
                table,
                name,
                kind: match contype.as_str() {
                    "p" => ConstraintKind::PrimaryKey,
                    "f" => ConstraintKind::ForeignKey,
                    _ => ConstraintKind::Unique,
                },
                columns: vec![],
                referenced_schema: None,
                referenced_table: None,
                referenced_columns: vec![],
            });
        entry.columns.push(column);
        if entry.kind == ConstraintKind::ForeignKey {
            entry.referenced_schema = row.get(5);
            entry.referenced_table = row.get(6);
            if let Some(column) = row.get::<_, Option<String>>(7) {
                entry.referenced_columns.push(column);
            }
        }
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
    expression: Option<String>,
}

fn index_rows(client: &mut Client) -> PostgresAdapterResult<Vec<IndexRow>> {
    let rows = client.query(
        "
        SELECT ns.nspname,
               tbl.relname,
               idx.relname,
               ix.indisunique,
               ix.indisprimary,
               pg_catalog.pg_get_expr(ix.indpred, ix.indrelid),
               pg_catalog.pg_get_expr(ix.indexprs, ix.indrelid),
               att.attname,
               key_part.ordinality
        FROM pg_catalog.pg_index ix
        JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
        JOIN pg_catalog.pg_namespace ns ON ns.oid = tbl.relnamespace
        JOIN pg_catalog.pg_class idx ON idx.oid = ix.indexrelid
        LEFT JOIN unnest(ix.indkey) WITH ORDINALITY AS key_part(attnum, ordinality)
          ON key_part.attnum > 0
        LEFT JOIN pg_catalog.pg_attribute att
          ON att.attrelid = ix.indrelid AND att.attnum = key_part.attnum
        WHERE ns.nspname <> 'information_schema'
          AND ns.nspname NOT LIKE 'pg_%'
        ORDER BY ns.nspname, tbl.relname, idx.relname, key_part.ordinality
        ",
        &[],
    )?;

    let mut grouped = BTreeMap::<(String, String, String), IndexRow>::new();
    for row in rows {
        let schema: String = row.get(0);
        let table: String = row.get(1);
        let name: String = row.get(2);
        let entry = grouped
            .entry((schema.clone(), table.clone(), name.clone()))
            .or_insert_with(|| IndexRow {
                schema,
                table,
                name,
                is_unique: row.get(3),
                is_primary: row.get(4),
                predicate: row.get(5),
                expression: row.get(6),
                columns: vec![],
            });
        if let Some(column) = row.get::<_, Option<String>>(7) {
            entry.columns.push(column);
        }
    }

    Ok(grouped.into_values().collect())
}

struct ViewRow {
    schema: String,
    name: String,
    definition: Option<String>,
}

fn view_rows(client: &mut Client) -> PostgresAdapterResult<Vec<ViewRow>> {
    let rows = client.query(
        "
        SELECT table_schema, table_name, view_definition
        FROM information_schema.views
        WHERE table_schema <> 'information_schema'
          AND table_schema NOT LIKE 'pg_%'
        ORDER BY table_schema, table_name
        ",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| ViewRow {
            schema: row.get(0),
            name: row.get(1),
            definition: row.get(2),
        })
        .collect())
}

struct DependencyTarget {
    schema: String,
    table: String,
    column: Option<String>,
}

fn view_dependency_rows(
    client: &mut Client,
) -> PostgresAdapterResult<BTreeMap<(String, String), Vec<DependencyTarget>>> {
    let rows = client.query(
        "
        SELECT view_ns.nspname,
               view_cls.relname,
               ref_ns.nspname,
               ref_cls.relname,
               CASE WHEN dep.refobjsubid > 0 THEN att.attname ELSE NULL END
        FROM pg_catalog.pg_rewrite rw
        JOIN pg_catalog.pg_class view_cls ON view_cls.oid = rw.ev_class
        JOIN pg_catalog.pg_namespace view_ns ON view_ns.oid = view_cls.relnamespace
        JOIN pg_catalog.pg_depend dep
          ON dep.classid = 'pg_catalog.pg_rewrite'::regclass AND dep.objid = rw.oid
        JOIN pg_catalog.pg_class ref_cls
          ON dep.refclassid = 'pg_catalog.pg_class'::regclass AND dep.refobjid = ref_cls.oid
        JOIN pg_catalog.pg_namespace ref_ns ON ref_ns.oid = ref_cls.relnamespace
        LEFT JOIN pg_catalog.pg_attribute att
          ON att.attrelid = ref_cls.oid AND att.attnum = dep.refobjsubid
        WHERE rw.rulename = '_RETURN'
          AND view_cls.relkind = 'v'
          AND view_ns.nspname <> 'information_schema'
          AND view_ns.nspname NOT LIKE 'pg_%'
          AND ref_ns.nspname <> 'information_schema'
          AND ref_ns.nspname NOT LIKE 'pg_%'
          AND dep.deptype IN ('n', 'a')
        ORDER BY view_ns.nspname, view_cls.relname, ref_ns.nspname, ref_cls.relname, att.attname
        ",
        &[],
    )?;

    let mut grouped = BTreeMap::<(String, String), Vec<DependencyTarget>>::new();
    for row in rows {
        grouped
            .entry((row.get(0), row.get(1)))
            .or_default()
            .push(DependencyTarget {
                schema: row.get(2),
                table: row.get(3),
                column: row.get(4),
            });
    }
    Ok(grouped)
}

struct RoutineRow {
    schema: String,
    name: String,
    specific_name: String,
    kind: RoutineKind,
    definition: Option<String>,
    oid: Option<String>,
}

fn routine_rows(client: &mut Client) -> PostgresAdapterResult<Vec<RoutineRow>> {
    let rows = client.query(
        "
        SELECT r.routine_schema,
               r.routine_name,
               r.specific_name,
               r.routine_type,
               r.routine_definition,
               p.oid::text
        FROM information_schema.routines r
        JOIN pg_catalog.pg_namespace ns ON ns.nspname = r.routine_schema
        LEFT JOIN pg_catalog.pg_proc p
          ON p.pronamespace = ns.oid
         AND r.specific_name = p.proname || '_' || p.oid::text
        WHERE r.routine_schema <> 'information_schema'
          AND r.routine_schema NOT LIKE 'pg_%'
        ORDER BY r.routine_schema, r.routine_name, r.specific_name
        ",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| RoutineRow {
            schema: row.get(0),
            name: row.get(1),
            specific_name: row.get(2),
            kind: routine_kind_from_information_schema(row.get::<_, Option<String>>(3).as_deref()),
            definition: row.get(4),
            oid: row.get(5),
        })
        .collect())
}

fn routine_kind_from_information_schema(routine_type: Option<&str>) -> RoutineKind {
    match routine_type {
        Some("PROCEDURE") => RoutineKind::Procedure,
        _ => RoutineKind::Function,
    }
}

fn routine_dependency_rows(
    client: &mut Client,
) -> PostgresAdapterResult<BTreeMap<String, Vec<DependencyTarget>>> {
    let rows = client.query(
        "
        SELECT proc.oid::text,
               ref_ns.nspname,
               ref_cls.relname,
               CASE WHEN dep.refobjsubid > 0 THEN att.attname ELSE NULL END
        FROM pg_catalog.pg_proc proc
        JOIN pg_catalog.pg_namespace proc_ns ON proc_ns.oid = proc.pronamespace
        JOIN pg_catalog.pg_depend dep
          ON dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.objid = proc.oid
        JOIN pg_catalog.pg_class ref_cls
          ON dep.refclassid = 'pg_catalog.pg_class'::regclass AND dep.refobjid = ref_cls.oid
        JOIN pg_catalog.pg_namespace ref_ns ON ref_ns.oid = ref_cls.relnamespace
        LEFT JOIN pg_catalog.pg_attribute att
          ON att.attrelid = ref_cls.oid AND att.attnum = dep.refobjsubid
        WHERE proc_ns.nspname <> 'information_schema'
          AND proc_ns.nspname NOT LIKE 'pg_%'
          AND ref_ns.nspname <> 'information_schema'
          AND ref_ns.nspname NOT LIKE 'pg_%'
          AND dep.deptype IN ('n', 'a')
        ORDER BY proc.oid::text, ref_ns.nspname, ref_cls.relname, att.attname
        ",
        &[],
    )?;

    let mut grouped = BTreeMap::<String, Vec<DependencyTarget>>::new();
    for row in rows {
        grouped
            .entry(row.get(0))
            .or_default()
            .push(DependencyTarget {
                schema: row.get(1),
                table: row.get(2),
                column: row.get(3),
            });
    }
    Ok(grouped)
}

struct TriggerRow {
    schema: String,
    table: String,
    name: String,
    timing: Option<String>,
    events: Vec<String>,
    definition: Option<String>,
    routine_oid: Option<String>,
}

fn trigger_rows(client: &mut Client) -> PostgresAdapterResult<Vec<TriggerRow>> {
    let rows = client.query(
        "
        SELECT ns.nspname,
               tbl.relname,
               trg.tgname,
               CASE
                 WHEN (trg.tgtype::int & 2) <> 0 THEN 'BEFORE'
                 WHEN (trg.tgtype::int & 64) <> 0 THEN 'INSTEAD OF'
                 ELSE 'AFTER'
               END,
               (trg.tgtype::int & 4) <> 0,
               (trg.tgtype::int & 8) <> 0,
               (trg.tgtype::int & 16) <> 0,
               (trg.tgtype::int & 32) <> 0,
               pg_catalog.pg_get_triggerdef(trg.oid),
               proc.oid::text
        FROM pg_catalog.pg_trigger trg
        JOIN pg_catalog.pg_class tbl ON tbl.oid = trg.tgrelid
        JOIN pg_catalog.pg_namespace ns ON ns.oid = tbl.relnamespace
        JOIN pg_catalog.pg_proc proc ON proc.oid = trg.tgfoid
        WHERE NOT trg.tgisinternal
          AND ns.nspname <> 'information_schema'
          AND ns.nspname NOT LIKE 'pg_%'
        ORDER BY ns.nspname, tbl.relname, trg.tgname
        ",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let mut events = Vec::new();
            if row.get(4) {
                events.push("INSERT".to_owned());
            }
            if row.get(5) {
                events.push("DELETE".to_owned());
            }
            if row.get(6) {
                events.push("UPDATE".to_owned());
            }
            if row.get(7) {
                events.push("TRUNCATE".to_owned());
            }
            TriggerRow {
                schema: row.get(0),
                table: row.get(1),
                name: row.get(2),
                timing: row.get(3),
                events,
                definition: row.get(8),
                routine_oid: row.get(9),
            }
        })
        .collect())
}

fn resolve_dependencies(
    dependencies: &[DependencyTarget],
    table_keys: &BTreeMap<(String, String), ObjectKey>,
    column_keys: &BTreeMap<(String, String, String), ObjectKey>,
) -> Vec<ObjectKey> {
    let mut resolved = BTreeMap::<String, ObjectKey>::new();
    for dependency in dependencies {
        if let Some(table_key) =
            table_keys.get(&(dependency.schema.clone(), dependency.table.clone()))
        {
            resolved.insert(table_key.to_string(), table_key.clone());
        }
        if let Some(column) = &dependency.column {
            if let Some(column_key) = column_keys.get(&(
                dependency.schema.clone(),
                dependency.table.clone(),
                column.clone(),
            )) {
                resolved.insert(column_key.to_string(), column_key.clone());
            }
        }
    }
    resolved.into_values().collect()
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
        "postgres",
        connection_alias,
        database,
        schema,
        object_kind,
        object_name,
        sub_object,
    )
}

fn postgres_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: "postgres".to_owned(),
        metadata_only: true,
        schemas: true,
        tables: true,
        columns: true,
        constraints: true,
        indexes: true,
        views: CapabilitySupport::Supported,
        triggers: CapabilitySupport::Supported,
        routines: CapabilitySupport::Supported,
        dependencies: CapabilitySupport::Partial,
        notes: vec![
            "Reads information_schema and pg_catalog metadata only; no user table rows are read.".to_owned(),
            "View dependencies use pg_rewrite/pg_depend and are resolved only to known table/column keys.".to_owned(),
            "Routine dependency depth is best-effort because PostgreSQL does not fully track function-body dependencies stored as strings.".to_owned(),
        ],
    }
}

#[cfg(test)]
mod postgres_adapter_tests {
    use super::*;

    const TEST_URL_ENV: &str = "DATABASE_MEMORY_TEST_POSTGRES_URL";

    #[test]
    fn postgres_dependencies_capabilities_include_views_triggers_routines() {
        let capabilities = postgres_capabilities();

        assert_eq!(capabilities.source_kind, "postgres");
        assert!(capabilities.metadata_only);
        assert!(capabilities.tables);
        assert!(capabilities.columns);
        assert!(capabilities.constraints);
        assert!(capabilities.indexes);
        assert_eq!(capabilities.views, CapabilitySupport::Supported);
        assert_eq!(capabilities.triggers, CapabilitySupport::Supported);
        assert_eq!(capabilities.routines, CapabilitySupport::Supported);
        assert_eq!(capabilities.dependencies, CapabilitySupport::Partial);
    }

    #[test]
    fn postgres_null_routine_type_defaults_to_function() {
        assert_eq!(
            routine_kind_from_information_schema(Some("PROCEDURE")),
            RoutineKind::Procedure
        );
        assert_eq!(
            routine_kind_from_information_schema(Some("FUNCTION")),
            RoutineKind::Function
        );
        assert_eq!(
            routine_kind_from_information_schema(None),
            RoutineKind::Function
        );
    }

    #[test]
    fn postgres_adapter_live_introspection_is_env_gated() {
        let Ok(connection_string) = std::env::var(TEST_URL_ENV) else {
            eprintln!("skipping live PostgreSQL adapter test; set {TEST_URL_ENV} to run it");
            return;
        };
        let schema = format!(
            "database_memory_mcp_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "
                DROP SCHEMA IF EXISTS {schema} CASCADE;
                CREATE SCHEMA {schema};
                CREATE TABLE {schema}.users (
                    id integer PRIMARY KEY,
                    email text NOT NULL UNIQUE
                );
                CREATE TABLE {schema}.orders (
                    id integer PRIMARY KEY,
                    user_id integer NOT NULL REFERENCES {schema}.users(id),
                    total numeric DEFAULT 0
                );
                CREATE INDEX idx_orders_user_id ON {schema}.orders(user_id);
                CREATE VIEW {schema}.order_users AS
                    SELECT o.id, o.user_id, u.email
                    FROM {schema}.orders o
                    JOIN {schema}.users u ON u.id = o.user_id;
                CREATE FUNCTION {schema}.orders_touch() RETURNS trigger
                    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
                CREATE TRIGGER trg_orders_touch
                    BEFORE INSERT OR UPDATE ON {schema}.orders
                    FOR EACH ROW EXECUTE FUNCTION {schema}.orders_touch();
                "
            ))
            .unwrap();

        let snapshot = introspect_postgres(&connection_string, "pg-test").unwrap();

        client
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE;"))
            .unwrap();

        assert_eq!(snapshot.source_kind, "postgres");
        assert_eq!(snapshot.connection_alias, "pg-test");
        assert!(snapshot.capabilities.metadata_only);
        assert!(snapshot.schemas.iter().any(|item| item.name == schema));
        assert!(snapshot
            .tables
            .iter()
            .any(|item| item.name == "orders" && item.key.schema == schema));
        assert!(snapshot.columns.iter().any(|item| {
            item.table_key.object_name == "orders"
                && item.table_key.schema == schema
                && item.name == "user_id"
                && item.data_type == "integer"
        }));
        assert!(snapshot.constraints.iter().any(|item| {
            item.kind == ConstraintKind::PrimaryKey
                && item.table_key.object_name == "users"
                && item.table_key.schema == schema
        }));
        assert!(snapshot.constraints.iter().any(|item| {
            item.kind == ConstraintKind::ForeignKey
                && item.table_key.object_name == "orders"
                && item.table_key.schema == schema
                && item
                    .referenced_table_key
                    .as_ref()
                    .map(|key| key.object_name.as_str())
                    == Some("users")
        }));
        assert!(snapshot.indexes.iter().any(|item| {
            item.name == "idx_orders_user_id"
                && item.table_key.object_name == "orders"
                && item.table_key.schema == schema
        }));
        assert!(snapshot.views.iter().any(|item| {
            item.name == "order_users"
                && item.key.schema == schema
                && item
                    .depends_on
                    .iter()
                    .any(|key| key.object_name == "orders")
        }));
        assert!(snapshot.triggers.iter().any(|item| {
            item.name == "trg_orders_touch"
                && item.table_key.object_name == "orders"
                && item.table_key.schema == schema
                && item.executes_routine_key.is_some()
        }));
        assert!(snapshot
            .routines
            .iter()
            .any(|item| { item.name == "orders_touch" && item.key.schema == schema }));
    }
}
