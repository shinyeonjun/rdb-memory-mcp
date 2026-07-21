use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, ErrorCode, OpenFlags};

use super::sqlite::SqliteAdapterError;
use super::sqlite_sql::{
    parse_index_definition, parse_table_definition, parse_trigger_definition, ParsedConstraint,
    ParsedConstraintKind, ParsedIndexDefinition, ParsedTableDefinition, ParsedTriggerDefinition,
};
use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::canonical::{
    CanonicalMetadata, CanonicalSchemaSnapshot, MetadataObject, MetadataRelationship,
    MetadataRelationshipKind, MetadataValue, ObjectAnnotation,
};
use crate::certification::{
    AdapterIdentity, CapabilityCheck, DiscoveredCount, DiscoveryCounts, IntrospectionScope,
    ObjectCategory, RelationshipCategory, ServerIdentity,
};
use crate::introspection::{
    CanonicalSnapshotAssembler, CatalogDiscovery, CatalogIntrospector, DatabaseAnalysisService,
    IntrospectionRequest,
};
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject, TriggerObject, ViewObject,
};

const SQLITE_SOURCE: &str = "sqlite";
const MAIN_CATALOG: &str = "main";
const MAIN_SCHEMA: &str = "main";
const MAX_SCHEMA_SQL_BYTES: usize = 1_048_576;
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;

pub(crate) struct SqlitePathCatalogAdapter {
    path: PathBuf,
}

impl SqlitePathCatalogAdapter {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CatalogIntrospector for SqlitePathCatalogAdapter {
    fn source_kind(&self) -> &'static str {
        SQLITE_SOURCE
    }

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        validate_sqlite_scope(request)?;
        let conn = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| sqlite_open_failure(request, error))?;
        conn.busy_timeout(Duration::from_millis(request.timeout_ms))
            .map_err(|error| sqlite_failure(request, error.into()))?;
        conn.pragma_update(None, "query_only", true)
            .map_err(|error| sqlite_capability_failure(request, error))?;

        let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
        conn.progress_handler(1_000, Some(move || Instant::now() >= deadline));

        let discovery = discover_sqlite_connection(
            &conn,
            SQLITE_SOURCE,
            SQLITE_SOURCE,
            &request.connection_alias,
            vec![
                "SQLite file opened read-only; only sqlite_schema and PRAGMA metadata were read."
                    .to_owned(),
            ],
        );
        conn.progress_handler(0, None::<fn() -> bool>);
        discovery.map_err(|error| sqlite_failure(request, error))
    }
}

pub(crate) fn analyze_sqlite_path(path: &Path, connection_alias: &str) -> AnalysisOutcome {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs: vec![MAIN_CATALOG.to_owned()],
        requested_schemas: vec![MAIN_SCHEMA.to_owned()],
        timeout_ms: 30_000,
    };
    DatabaseAnalysisService::new(SqlitePathCatalogAdapter::new(path)).analyze(&request)
}

pub(crate) fn discover_sqlite_connection(
    conn: &Connection,
    snapshot_source_kind: &str,
    object_source_kind: &str,
    connection_alias: &str,
    notes: Vec<String>,
) -> Result<CatalogDiscovery, SqliteAdapterError> {
    let transaction = conn.unchecked_transaction()?;
    let raw = RawSqliteCatalog::read(&transaction)?;
    let discovery = SqliteSnapshotMapper::new(
        &transaction,
        snapshot_source_kind,
        object_source_kind,
        connection_alias,
        notes,
    )
    .map(raw)?;
    transaction.commit()?;
    Ok(discovery)
}

pub(crate) fn certify_discovery(
    discovery: CatalogDiscovery,
) -> Result<crate::certification::CertifiedSchemaSnapshot, crate::certification::CertificationError>
{
    CanonicalSnapshotAssembler::certify(discovery)
}

fn validate_sqlite_scope(request: &IntrospectionRequest) -> Result<(), AnalysisFailure> {
    let catalogs_are_valid = request.requested_catalogs.is_empty()
        || request.requested_catalogs == [MAIN_CATALOG.to_owned()];
    let schemas_are_valid = request.requested_schemas.is_empty()
        || request.requested_schemas == [MAIN_SCHEMA.to_owned()];
    if catalogs_are_valid && schemas_are_valid {
        if request.timeout_ms <= MAX_INTROSPECTION_TIMEOUT_MS {
            return Ok(());
        }
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            SQLITE_SOURCE,
            &request.connection_alias,
            format!(
                "SQLite introspection timeout exceeds the {MAX_INTROSPECTION_TIMEOUT_MS} ms safety limit"
            ),
            "choose a timeout between 1 ms and 86400000 ms",
            false,
            None,
        ));
    }
    Err(AnalysisFailure::redacted(
        AnalysisFailureCode::InvalidConfiguration,
        AnalysisStage::Configuration,
        SQLITE_SOURCE,
        &request.connection_alias,
        "SQLite certified introspection supports the main catalog/schema only",
        "request catalog 'main' and schema 'main'",
        false,
        None,
    ))
}

fn sqlite_failure(request: &IntrospectionRequest, error: SqliteAdapterError) -> AnalysisFailure {
    if matches!(
        &error,
        SqliteAdapterError::Storage(storage)
            if storage.sqlite_error_code() == Some(ErrorCode::OperationInterrupted)
    ) {
        return AnalysisFailure::redacted(
            AnalysisFailureCode::Timeout,
            AnalysisStage::Discovery,
            SQLITE_SOURCE,
            &request.connection_alias,
            "SQLite metadata introspection exceeded its configured timeout",
            "increase the bounded timeout or reduce schema complexity, then retry",
            true,
            None,
        );
    }
    let (code, stage, remediation) = match &error {
        SqliteAdapterError::Storage(_) => (
            AnalysisFailureCode::MetadataQueryFailed,
            AnalysisStage::Discovery,
            "verify that the SQLite file is readable and retry",
        ),
        SqliteAdapterError::Parse { .. } => (
            AnalysisFailureCode::UnsupportedMetadata,
            AnalysisStage::Mapping,
            "use a supported SQLite schema construct or upgrade the adapter parser",
        ),
        SqliteAdapterError::Mapping { .. } => (
            AnalysisFailureCode::MetadataMappingFailed,
            AnalysisStage::Mapping,
            "repair the inconsistent schema metadata and retry",
        ),
        SqliteAdapterError::Certification(_) => (
            AnalysisFailureCode::ValidationFailed,
            AnalysisStage::Validation,
            "inspect the completeness evidence and repair the adapter mapping",
        ),
    };
    AnalysisFailure::redacted(
        code,
        stage,
        SQLITE_SOURCE,
        &request.connection_alias,
        error.to_string(),
        remediation,
        false,
        None,
    )
}

fn sqlite_open_failure(request: &IntrospectionRequest, error: rusqlite::Error) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::ConnectionFailed,
        AnalysisStage::Connection,
        SQLITE_SOURCE,
        &request.connection_alias,
        error.to_string(),
        "verify that the SQLite file exists and is readable, then retry",
        true,
        None,
    )
}

fn sqlite_capability_failure(
    request: &IntrospectionRequest,
    error: rusqlite::Error,
) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::PermissionDenied,
        AnalysisStage::CapabilityProbe,
        SQLITE_SOURCE,
        &request.connection_alias,
        error.to_string(),
        "allow read-only query_only metadata access and retry",
        false,
        None,
    )
}

#[derive(Clone, Debug)]
struct RawSqliteCatalog {
    sqlite_version: String,
    schema_version: i64,
    database_names: Vec<String>,
    relations: Vec<RawRelation>,
    indexes: Vec<RawIndex>,
    foreign_keys: BTreeMap<String, Vec<RawForeignKey>>,
    triggers: Vec<RawTrigger>,
}

impl RawSqliteCatalog {
    fn read(conn: &Connection) -> Result<Self, SqliteAdapterError> {
        let schema_entries = read_schema_entries(conn)?;
        let database_names = read_database_names(conn)?;
        let schema_version = conn.query_row("PRAGMA main.schema_version", [], |row| row.get(0))?;
        let mut relations = read_relations(conn, &schema_entries)?;
        let mut indexes = Vec::new();
        let mut foreign_keys = BTreeMap::new();
        for relation in relations
            .iter_mut()
            .filter(|relation| relation.kind.is_table())
        {
            relation.columns = read_relation_columns(conn, &relation.name)?;
            if relation.columns.len() != relation.declared_column_count as usize {
                return Err(SqliteAdapterError::mapping(
                    format!("table {}", relation.name),
                    format!(
                        "PRAGMA table_list reports {} column(s), but table_xinfo returned {}",
                        relation.declared_column_count,
                        relation.columns.len()
                    ),
                ));
            }
            relation.parsed_table = parse_relation_table(relation)?;
            indexes.extend(read_indexes(conn, &relation.name, &schema_entries)?);
            foreign_keys.insert(
                relation.name.clone(),
                read_foreign_keys(conn, &relation.name)?,
            );
        }
        for relation in relations
            .iter_mut()
            .filter(|relation| relation.kind == RawRelationKind::View)
        {
            relation.columns = read_relation_columns(conn, &relation.name)?;
            if relation.columns.len() != relation.declared_column_count as usize {
                return Err(SqliteAdapterError::mapping(
                    format!("view {}", relation.name),
                    format!(
                        "PRAGMA table_list reports {} column(s), but table_xinfo returned {}",
                        relation.declared_column_count,
                        relation.columns.len()
                    ),
                ));
            }
        }
        let triggers = read_triggers(&schema_entries)?;

        Ok(Self {
            sqlite_version: rusqlite::version().to_owned(),
            schema_version,
            database_names,
            relations,
            indexes,
            foreign_keys,
            triggers,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawRelationKind {
    Table(TableKind),
    View,
}

impl RawRelationKind {
    fn is_table(self) -> bool {
        matches!(self, Self::Table(_))
    }
}

#[derive(Clone, Debug)]
struct RawRelation {
    name: String,
    kind: RawRelationKind,
    declared_column_count: u32,
    without_rowid: bool,
    strict: bool,
    sql: Option<String>,
    columns: Vec<RawColumn>,
    parsed_table: Option<ParsedTableDefinition>,
}

#[derive(Clone, Debug)]
struct RawColumn {
    cid: i64,
    name: String,
    data_type: String,
    not_null: bool,
    default_value: Option<String>,
    primary_key_position: u32,
    hidden: i64,
}

#[derive(Clone, Debug)]
struct RawIndex {
    table_name: String,
    name: String,
    unique: bool,
    origin: String,
    partial: bool,
    sql: Option<String>,
    parsed: Option<ParsedIndexDefinition>,
    terms: Vec<RawIndexTerm>,
}

#[derive(Clone, Debug)]
struct RawIndexTerm {
    sequence: u32,
    cid: i64,
    column_name: Option<String>,
    descending: bool,
    collation: Option<String>,
    key: bool,
}

#[derive(Clone, Debug)]
struct RawForeignKey {
    id: i64,
    parts: Vec<RawForeignKeyPart>,
    on_update: String,
    on_delete: String,
    match_name: String,
}

#[derive(Clone, Debug)]
struct RawForeignKeyPart {
    sequence: u32,
    referenced_table: String,
    source_column: String,
    referenced_column: Option<String>,
}

#[derive(Clone, Debug)]
struct RawTrigger {
    name: String,
    owner_name: String,
    sql: String,
    parsed: ParsedTriggerDefinition,
}

#[derive(Clone, Debug)]
struct RawSchemaEntry {
    object_type: String,
    name: String,
    owner_name: String,
    sql: Option<String>,
}

fn read_schema_entries(
    conn: &Connection,
) -> Result<BTreeMap<(String, String), RawSchemaEntry>, SqliteAdapterError> {
    let mut stmt = conn
        .prepare("SELECT type, name, tbl_name, sql FROM main.sqlite_schema ORDER BY type, name")?;
    let rows = stmt.query_map([], |row| {
        Ok(RawSchemaEntry {
            object_type: row.get(0)?,
            name: row.get(1)?,
            owner_name: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    let mut entries = BTreeMap::new();
    for row in rows {
        let entry = row?;
        if let Some(sql) = entry.sql.as_deref() {
            require_bounded_sql(&entry.object_type, &entry.name, sql)?;
        }
        entries.insert((entry.object_type.clone(), entry.name.clone()), entry);
    }
    Ok(entries)
}

fn read_database_names(conn: &Connection) -> Result<Vec<String>, SqliteAdapterError> {
    let mut stmt = conn.prepare("PRAGMA database_list")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let names = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if names != [MAIN_CATALOG.to_owned()] {
        return Err(SqliteAdapterError::mapping(
            "database scope",
            format!(
                "certified SQLite introspection expected only the main database, found {}",
                names.join(", ")
            ),
        ));
    }
    Ok(names)
}

fn read_relations(
    conn: &Connection,
    schema_entries: &BTreeMap<(String, String), RawSchemaEntry>,
) -> Result<Vec<RawRelation>, SqliteAdapterError> {
    let mut stmt = conn.prepare("PRAGMA main.table_list")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let mut relations = Vec::new();
    let mut folded_names = BTreeSet::new();
    for row in rows {
        let (schema, name, relation_type, ncol, without_rowid, strict) = row?;
        if schema != MAIN_SCHEMA || name.starts_with("sqlite_") {
            continue;
        }
        if ncol < 0 {
            return Err(SqliteAdapterError::mapping(
                format!("relation {name}"),
                "PRAGMA table_list returned a negative column count",
            ));
        }
        if !folded_names.insert(fold_identifier(&name)) {
            return Err(SqliteAdapterError::mapping(
                format!("relation {name}"),
                "two relations collide under SQLite identifier comparison",
            ));
        }
        let kind = match relation_type.as_str() {
            "table" => RawRelationKind::Table(TableKind::BaseTable),
            "virtual" => RawRelationKind::Table(TableKind::Virtual),
            "shadow" => RawRelationKind::Table(TableKind::Shadow),
            "view" => RawRelationKind::View,
            unsupported => {
                return Err(SqliteAdapterError::mapping(
                    format!("relation {name}"),
                    format!("unsupported PRAGMA table_list relation type '{unsupported}'"),
                ));
            }
        };
        let schema_type = if kind == RawRelationKind::View {
            "view"
        } else {
            "table"
        };
        let sql = schema_entries
            .get(&(schema_type.to_owned(), name.clone()))
            .and_then(|entry| entry.sql.clone());
        if sql.is_none() && kind != RawRelationKind::Table(TableKind::Shadow) {
            return Err(SqliteAdapterError::mapping(
                format!("relation {name}"),
                "sqlite_schema did not provide a definition",
            ));
        }
        relations.push(RawRelation {
            name,
            kind,
            declared_column_count: u32::try_from(ncol).map_err(|_| {
                SqliteAdapterError::mapping("relation column count", "column count exceeds u32")
            })?,
            without_rowid: without_rowid != 0,
            strict: strict != 0,
            sql,
            columns: vec![],
            parsed_table: None,
        });
    }
    relations.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(relations)
}

fn read_relation_columns(
    conn: &Connection,
    relation_name: &str,
) -> Result<Vec<RawColumn>, SqliteAdapterError> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA main.table_xinfo({})",
        quote_string(relation_name)
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok(RawColumn {
            cid: row.get(0)?,
            name: row.get(1)?,
            data_type: row.get(2)?,
            not_null: row.get::<_, i64>(3)? != 0,
            default_value: row.get(4)?,
            primary_key_position: u32::try_from(row.get::<_, i64>(5)?).unwrap_or(u32::MAX),
            hidden: row.get(6)?,
        })
    })?;
    let mut columns = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    columns.sort_by_key(|column| column.cid);
    for (ordinal, column) in columns.iter().enumerate() {
        if column.cid < 0 || column.cid as usize != ordinal {
            return Err(SqliteAdapterError::mapping(
                format!("column {}.{}", relation_name, column.name),
                "table_xinfo returned a non-contiguous column ordinal",
            ));
        }
        if column.primary_key_position == u32::MAX {
            return Err(SqliteAdapterError::mapping(
                format!("column {}.{}", relation_name, column.name),
                "primary-key ordinal exceeds the supported range",
            ));
        }
        if !matches!(column.hidden, 0..=3) {
            return Err(SqliteAdapterError::mapping(
                format!("column {}.{}", relation_name, column.name),
                format!("unknown table_xinfo hidden code {}", column.hidden),
            ));
        }
    }
    Ok(columns)
}

fn parse_relation_table(
    relation: &RawRelation,
) -> Result<Option<ParsedTableDefinition>, SqliteAdapterError> {
    let RawRelationKind::Table(kind) = relation.kind else {
        return Ok(None);
    };
    if kind == TableKind::Virtual || (kind == TableKind::Shadow && relation.sql.is_none()) {
        return Ok(None);
    }
    let sql = relation.sql.as_deref().ok_or_else(|| {
        SqliteAdapterError::mapping(
            format!("table {}", relation.name),
            "sqlite_schema did not provide CREATE TABLE SQL",
        )
    })?;
    let parsed = parse_table_definition(sql).map_err(|message| SqliteAdapterError::Parse {
        object: format!("table {}", relation.name),
        message,
    })?;
    if !same_identifier(&parsed.name, &relation.name) {
        return Err(SqliteAdapterError::mapping(
            format!("table {}", relation.name),
            format!(
                "parsed table name '{}' does not match catalog name",
                parsed.name
            ),
        ));
    }
    if parsed.strict != relation.strict || parsed.without_rowid != relation.without_rowid {
        return Err(SqliteAdapterError::mapping(
            format!("table {}", relation.name),
            "parsed STRICT/WITHOUT ROWID flags disagree with PRAGMA table_list",
        ));
    }
    Ok(Some(parsed))
}

fn read_indexes(
    conn: &Connection,
    table_name: &str,
    schema_entries: &BTreeMap<(String, String), RawSchemaEntry>,
) -> Result<Vec<RawIndex>, SqliteAdapterError> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA main.index_list({})",
        quote_string(table_name)
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? != 0,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)? != 0,
        ))
    })?;
    let mut indexes = Vec::new();
    for row in rows {
        let (name, unique, origin, partial) = row?;
        if !matches!(origin.as_str(), "c" | "u" | "pk") {
            return Err(SqliteAdapterError::mapping(
                format!("index {name}"),
                format!("unknown PRAGMA index_list origin '{origin}'"),
            ));
        }
        let sql = schema_entries
            .get(&("index".to_owned(), name.clone()))
            .and_then(|entry| entry.sql.clone());
        let parsed = match sql.as_deref() {
            Some(sql) => {
                let parsed =
                    parse_index_definition(sql).map_err(|message| SqliteAdapterError::Parse {
                        object: format!("index {name}"),
                        message,
                    })?;
                if !same_identifier(&parsed.name, &name)
                    || !same_identifier(&parsed.table_name, table_name)
                    || parsed.unique != unique
                    || parsed.predicate.is_some() != partial
                {
                    return Err(SqliteAdapterError::mapping(
                        format!("index {name}"),
                        "parsed CREATE INDEX identity or flags disagree with PRAGMA index_list",
                    ));
                }
                Some(parsed)
            }
            None if origin == "c" => {
                return Err(SqliteAdapterError::mapping(
                    format!("index {name}"),
                    "explicit index has no sqlite_schema definition",
                ));
            }
            None => None,
        };
        let terms = read_index_terms(conn, &name)?;
        let key_term_count = terms.iter().filter(|term| term.key).count();
        if parsed
            .as_ref()
            .is_some_and(|definition| definition.terms.len() != key_term_count)
        {
            return Err(SqliteAdapterError::mapping(
                format!("index {name}"),
                format!(
                    "CREATE INDEX has {} key term(s), but index_xinfo returned {key_term_count}",
                    parsed.as_ref().map_or(0, |value| value.terms.len())
                ),
            ));
        }
        indexes.push(RawIndex {
            table_name: table_name.to_owned(),
            name,
            unique,
            origin,
            partial,
            sql,
            parsed,
            terms,
        });
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

fn read_index_terms(
    conn: &Connection,
    index_name: &str,
) -> Result<Vec<RawIndexTerm>, SqliteAdapterError> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA main.index_xinfo({})",
        quote_string(index_name)
    ))?;
    let rows = stmt.query_map([], |row| {
        let sequence = row.get::<_, i64>(0)?;
        Ok((
            sequence,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, i64>(3)? != 0,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i64>(5)? != 0,
        ))
    })?;
    let mut terms = Vec::new();
    for row in rows {
        let (sequence, cid, column_name, descending, collation, key) = row?;
        if sequence < 0 {
            return Err(SqliteAdapterError::mapping(
                format!("index {index_name}"),
                "index_xinfo returned a negative term sequence",
            ));
        }
        if cid >= 0 && column_name.is_none() {
            return Err(SqliteAdapterError::mapping(
                format!("index {index_name}"),
                "index_xinfo omitted the name of a direct column term",
            ));
        }
        if cid < -2 {
            return Err(SqliteAdapterError::mapping(
                format!("index {index_name}"),
                format!("index_xinfo returned unknown column code {cid}"),
            ));
        }
        terms.push(RawIndexTerm {
            sequence: u32::try_from(sequence).map_err(|_| {
                SqliteAdapterError::mapping(
                    format!("index {index_name}"),
                    "index term sequence exceeds u32",
                )
            })?,
            cid,
            column_name,
            descending,
            collation,
            key,
        });
    }
    terms.sort_by_key(|term| term.sequence);
    for (expected, term) in terms.iter().enumerate() {
        if term.sequence as usize != expected {
            return Err(SqliteAdapterError::mapping(
                format!("index {index_name}"),
                "index_xinfo returned non-contiguous term sequences",
            ));
        }
    }
    Ok(terms)
}

fn read_foreign_keys(
    conn: &Connection,
    table_name: &str,
) -> Result<Vec<RawForeignKey>, SqliteAdapterError> {
    let mut stmt = conn.prepare(&format!(
        "PRAGMA main.foreign_key_list({})",
        quote_string(table_name)
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;
    let mut grouped = BTreeMap::<i64, RawForeignKey>::new();
    for row in rows {
        let (
            id,
            sequence,
            referenced_table,
            source_column,
            referenced_column,
            on_update,
            on_delete,
            match_name,
        ) = row?;
        if id < 0 || sequence < 0 {
            return Err(SqliteAdapterError::mapping(
                format!("foreign key on {table_name}"),
                "foreign_key_list returned a negative id or sequence",
            ));
        }
        let entry = grouped.entry(id).or_insert_with(|| RawForeignKey {
            id,
            parts: vec![],
            on_update: normalize_pragma_token(&on_update),
            on_delete: normalize_pragma_token(&on_delete),
            match_name: normalize_pragma_token(&match_name),
        });
        if entry.on_update != normalize_pragma_token(&on_update)
            || entry.on_delete != normalize_pragma_token(&on_delete)
            || entry.match_name != normalize_pragma_token(&match_name)
        {
            return Err(SqliteAdapterError::mapping(
                format!("foreign key {table_name}.{id}"),
                "foreign_key_list returned inconsistent actions for one composite key",
            ));
        }
        entry.parts.push(RawForeignKeyPart {
            sequence: u32::try_from(sequence).map_err(|_| {
                SqliteAdapterError::mapping(
                    format!("foreign key {table_name}.{id}"),
                    "foreign-key sequence exceeds u32",
                )
            })?,
            referenced_table,
            source_column,
            referenced_column: referenced_column.filter(|name| !name.is_empty()),
        });
    }
    let mut foreign_keys = grouped.into_values().collect::<Vec<_>>();
    foreign_keys.sort_by_key(|foreign_key| foreign_key.id);
    for foreign_key in &mut foreign_keys {
        foreign_key.parts.sort_by_key(|part| part.sequence);
        for (expected, part) in foreign_key.parts.iter().enumerate() {
            if part.sequence as usize != expected {
                return Err(SqliteAdapterError::mapping(
                    format!("foreign key {table_name}.{}", foreign_key.id),
                    "foreign_key_list returned non-contiguous column sequences",
                ));
            }
        }
    }
    Ok(foreign_keys)
}

fn read_triggers(
    schema_entries: &BTreeMap<(String, String), RawSchemaEntry>,
) -> Result<Vec<RawTrigger>, SqliteAdapterError> {
    let mut triggers = Vec::new();
    for entry in schema_entries
        .values()
        .filter(|entry| entry.object_type == "trigger" && !entry.name.starts_with("sqlite_"))
    {
        let sql = entry.sql.clone().ok_or_else(|| {
            SqliteAdapterError::mapping(
                format!("trigger {}", entry.name),
                "sqlite_schema did not provide CREATE TRIGGER SQL",
            )
        })?;
        let parsed =
            parse_trigger_definition(&sql).map_err(|message| SqliteAdapterError::Parse {
                object: format!("trigger {}", entry.name),
                message,
            })?;
        if !same_identifier(&parsed.name, &entry.name)
            || !same_identifier(&parsed.owner_name, &entry.owner_name)
        {
            return Err(SqliteAdapterError::mapping(
                format!("trigger {}", entry.name),
                "parsed trigger identity disagrees with sqlite_schema",
            ));
        }
        triggers.push(RawTrigger {
            name: entry.name.clone(),
            owner_name: entry.owner_name.clone(),
            sql,
            parsed,
        });
    }
    triggers.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(triggers)
}

fn normalize_pragma_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(' ', "_")
}

struct SqliteSnapshotMapper<'connection> {
    conn: &'connection Connection,
    snapshot_source_kind: &'connection str,
    object_source_kind: &'connection str,
    connection_alias: &'connection str,
    notes: Vec<String>,
}

impl<'connection> SqliteSnapshotMapper<'connection> {
    fn new(
        conn: &'connection Connection,
        snapshot_source_kind: &'connection str,
        object_source_kind: &'connection str,
        connection_alias: &'connection str,
        notes: Vec<String>,
    ) -> Self {
        Self {
            conn,
            snapshot_source_kind,
            object_source_kind,
            connection_alias,
            notes,
        }
    }

    fn map(self, raw: RawSqliteCatalog) -> Result<CatalogDiscovery, SqliteAdapterError> {
        let database_key = self.key(ObjectKind::Database, MAIN_CATALOG, None);
        let schema_key = self.key(ObjectKind::Schema, MAIN_SCHEMA, None);
        let database = DatabaseObject {
            key: database_key.clone(),
            name: MAIN_CATALOG.to_owned(),
        };
        let schemas = vec![SchemaObject {
            key: schema_key.clone(),
            database_key,
            name: MAIN_SCHEMA.to_owned(),
        }];

        let mut tables = Vec::new();
        let mut table_keys = BTreeMap::new();
        let mut view_keys = BTreeMap::new();
        for relation in &raw.relations {
            match relation.kind {
                RawRelationKind::Table(kind) => {
                    let table_key = self.key(ObjectKind::Table, &relation.name, None);
                    table_keys.insert(fold_identifier(&relation.name), table_key.clone());
                    tables.push(TableObject {
                        key: table_key,
                        schema_key: schema_key.clone(),
                        name: relation.name.clone(),
                        kind,
                    });
                }
                RawRelationKind::View => {
                    view_keys.insert(
                        fold_identifier(&relation.name),
                        self.key(ObjectKind::View, &relation.name, None),
                    );
                }
            }
        }

        let mut columns = Vec::new();
        let mut metadata = CanonicalMetadata::default();
        let mut relation_column_keys = BTreeMap::<(String, String), ObjectKey>::new();
        let mut primary_key_columns = BTreeMap::<String, Vec<ObjectKey>>::new();
        for relation in &raw.relations {
            match relation.kind {
                RawRelationKind::Table(_) => {
                    let table_key = lookup_key(&table_keys, &relation.name, "table")?;
                    let parsed_columns = relation
                        .parsed_table
                        .as_ref()
                        .map(|table| {
                            table
                                .columns
                                .iter()
                                .map(|column| (fold_identifier(&column.name), column))
                                .collect::<BTreeMap<_, _>>()
                        })
                        .unwrap_or_default();
                    let pk_count = relation
                        .columns
                        .iter()
                        .filter(|column| column.primary_key_position > 0)
                        .count();
                    let mut ordered_primary_key = Vec::new();
                    for raw_column in &relation.columns {
                        let column_key = self.key(
                            ObjectKind::Column,
                            &relation.name,
                            Some(raw_column.name.clone()),
                        );
                        let parsed_column = parsed_columns.get(&fold_identifier(&raw_column.name));
                        let generated = matches!(raw_column.hidden, 2 | 3);
                        if generated
                            && parsed_column
                                .and_then(|column| column.generated_expression.as_ref())
                                .is_none()
                        {
                            return Err(SqliteAdapterError::mapping(
                                format!("column {}.{}", relation.name, raw_column.name),
                                "table_xinfo marks the column generated, but CREATE TABLE has no generation expression",
                            ));
                        }
                        let integer_primary_key_alias = pk_count == 1
                            && raw_column.primary_key_position == 1
                            && raw_column.data_type.eq_ignore_ascii_case("INTEGER")
                            && !relation.without_rowid;
                        let primary_key_is_not_null = raw_column.primary_key_position > 0
                            && (relation.without_rowid
                                || relation.strict
                                || integer_primary_key_alias);
                        columns.push(ColumnObject {
                            key: column_key.clone(),
                            table_key: table_key.clone(),
                            name: raw_column.name.clone(),
                            ordinal_position: u32::try_from(raw_column.cid)
                                .map_err(|_| {
                                    SqliteAdapterError::mapping(
                                        format!("column {}.{}", relation.name, raw_column.name),
                                        "column ordinal exceeds u32",
                                    )
                                })?
                                .saturating_add(1),
                            data_type: raw_column.data_type.clone(),
                            is_nullable: !raw_column.not_null && !primary_key_is_not_null,
                            default_value: raw_column.default_value.clone(),
                            is_generated: generated,
                        });
                        relation_column_keys.insert(
                            (
                                fold_identifier(&relation.name),
                                fold_identifier(&raw_column.name),
                            ),
                            column_key.clone(),
                        );
                        if raw_column.primary_key_position > 0 {
                            ordered_primary_key
                                .push((raw_column.primary_key_position, column_key.clone()));
                        }
                        let mut properties = BTreeMap::new();
                        properties.insert(
                            "declared_not_null".to_owned(),
                            MetadataValue::Boolean(raw_column.not_null),
                        );
                        properties.insert(
                            "sqlite_hidden_code".to_owned(),
                            MetadataValue::Integer(raw_column.hidden),
                        );
                        if let Some(parsed_column) = parsed_column {
                            if let Some(storage) = &parsed_column.generated_storage {
                                properties.insert(
                                    "generated_storage".to_owned(),
                                    MetadataValue::String(storage.clone()),
                                );
                            }
                            if let Some(collation) = &parsed_column.collation {
                                properties.insert(
                                    "collation".to_owned(),
                                    MetadataValue::String(collation.clone()),
                                );
                            }
                        }
                        metadata.annotations.push(ObjectAnnotation {
                            object_key: column_key,
                            definition: parsed_column
                                .and_then(|column| column.generated_expression.clone()),
                            properties,
                        });
                    }
                    ordered_primary_key.sort_by_key(|(position, _)| *position);
                    primary_key_columns.insert(
                        fold_identifier(&relation.name),
                        ordered_primary_key
                            .into_iter()
                            .map(|(_, key)| key)
                            .collect(),
                    );
                    metadata
                        .annotations
                        .push(table_annotation(table_key, relation));
                }
                RawRelationKind::View => {
                    let view_key = lookup_key(&view_keys, &relation.name, "view")?;
                    for raw_column in &relation.columns {
                        let column_key = self.key(
                            ObjectKind::ViewColumn,
                            &relation.name,
                            Some(raw_column.name.clone()),
                        );
                        relation_column_keys.insert(
                            (
                                fold_identifier(&relation.name),
                                fold_identifier(&raw_column.name),
                            ),
                            column_key.clone(),
                        );
                        let mut properties = BTreeMap::new();
                        properties.insert(
                            "ordinal_position".to_owned(),
                            MetadataValue::Unsigned(
                                u64::try_from(raw_column.cid).unwrap_or_default() + 1,
                            ),
                        );
                        properties.insert(
                            "data_type".to_owned(),
                            MetadataValue::String(raw_column.data_type.clone()),
                        );
                        properties.insert(
                            "nullable".to_owned(),
                            MetadataValue::Boolean(!raw_column.not_null),
                        );
                        metadata.objects.push(MetadataObject {
                            key: column_key,
                            parent_key: Some(view_key.clone()),
                            name: raw_column.name.clone(),
                            extension_kind: None,
                            definition: None,
                            properties,
                        });
                    }
                }
            }
        }

        let mut constraints = Vec::new();
        let mut check_dependency_count = 0_u64;
        self.map_generated_dependencies(
            &raw.relations,
            &table_keys,
            &relation_column_keys,
            &mut metadata,
        )?;
        for relation in raw
            .relations
            .iter()
            .filter(|relation| relation.kind.is_table())
        {
            let mapped = self.map_constraints(
                relation,
                raw.foreign_keys
                    .get(&relation.name)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                &raw.indexes,
                &table_keys,
                &relation_column_keys,
                &primary_key_columns,
                &mut metadata,
            )?;
            check_dependency_count += mapped.check_dependency_count;
            constraints.extend(mapped.constraints);
        }

        let mapped_indexes = self.map_indexes(
            &raw.indexes,
            &table_keys,
            &relation_column_keys,
            &mut metadata,
        )?;
        let raw_direct_index_columns = raw
            .indexes
            .iter()
            .flat_map(|index| index.terms.iter())
            .filter(|term| term.key && term.cid >= 0)
            .count() as u64;
        if mapped_indexes.direct_column_count != raw_direct_index_columns {
            return Err(SqliteAdapterError::mapping(
                "index column reconciliation",
                format!(
                    "index_xinfo discovered {raw_direct_index_columns} direct key column(s), but mapper emitted {}",
                    mapped_indexes.direct_column_count
                ),
            ));
        }
        let indexes = mapped_indexes.indexes;

        let mut views = Vec::new();
        let mut view_dependency_count = 0_u64;
        for relation in raw
            .relations
            .iter()
            .filter(|relation| relation.kind == RawRelationKind::View)
        {
            let view_key = lookup_key(&view_keys, &relation.name, "view")?;
            let discovered_dependencies =
                self.view_dependencies(relation, &table_keys, &view_keys, &relation_column_keys)?;
            let mut dependencies = Vec::new();
            for dependency in discovered_dependencies {
                if dependency.object_kind == ObjectKind::ViewColumn {
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::DependsOn,
                        from_key: view_key.clone(),
                        to_key: dependency,
                        ordinal: None,
                        properties: BTreeMap::new(),
                    });
                } else {
                    dependencies.push(dependency);
                }
            }
            view_dependency_count += dependencies.len() as u64;
            views.push(ViewObject {
                key: view_key,
                schema_key: schema_key.clone(),
                name: relation.name.clone(),
                definition: relation.sql.clone(),
                depends_on: dependencies,
            });
        }

        let triggers = self.map_triggers(
            &raw.triggers,
            &raw.relations,
            &table_keys,
            &view_keys,
            &relation_column_keys,
            &mut metadata,
        )?;
        deduplicate_metadata_relationships(&mut metadata.relationships);

        let schema = SchemaSnapshot {
            source_kind: self.snapshot_source_kind.to_owned(),
            connection_alias: self.connection_alias.to_owned(),
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
                source_kind: self.snapshot_source_kind.to_owned(),
                metadata_only: true,
                schemas: true,
                tables: true,
                columns: true,
                constraints: true,
                indexes: true,
                views: CapabilitySupport::Supported,
                triggers: CapabilitySupport::Supported,
                routines: CapabilitySupport::Supported,
                dependencies: CapabilitySupport::Supported,
                limitations: vec![],
                notes: self.notes,
            },
        };
        let discovered_counts = discovery_counts(
            &raw,
            check_dependency_count,
            view_dependency_count,
            metadata.relationships.len() as u64,
        );
        let capability_checks = vec![
            CapabilityCheck {
                name: "catalog_scope".to_owned(),
                evidence: format!(
                    "PRAGMA database_list returned [{}]; selected main schema at schema_version {}",
                    raw.database_names.join(", "),
                    raw.schema_version
                ),
            },
            CapabilityCheck {
                name: "metadata_only".to_owned(),
                evidence: "Inventory came from sqlite_schema/table_list/table_xinfo/index_list/index_xinfo/foreign_key_list; dependency probes only prepared EXPLAIN statements and never stepped them".to_owned(),
            },
            CapabilityCheck {
                name: "routines_absent".to_owned(),
                evidence: "SQLite has no persisted schema routine catalog; connection-local functions are outside the selected database schema".to_owned(),
            },
            CapabilityCheck {
                name: "sql_grammar".to_owned(),
                evidence: "Every persisted CREATE TABLE, CREATE INDEX, and CREATE TRIGGER definition requiring semantic mapping was parsed with sqlite3-parser 0.17.0".to_owned(),
            },
            CapabilityCheck {
                name: "system_scope".to_owned(),
                evidence: "SQLite-owned names beginning with sqlite_ were excluded consistently from inventory and count probes".to_owned(),
            },
        ];

        Ok(CatalogDiscovery {
            snapshot: CanonicalSchemaSnapshot { schema, metadata },
            adapter: AdapterIdentity {
                name: "database-memory-sqlite".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            server: ServerIdentity {
                product: "SQLite".to_owned(),
                version: raw.sqlite_version,
            },
            scope: IntrospectionScope {
                catalogs: vec![MAIN_CATALOG.to_owned()],
                schemas: vec![MAIN_SCHEMA.to_owned()],
            },
            discovered_counts,
            capability_checks,
        })
    }

    fn key(
        &self,
        object_kind: ObjectKind,
        object_name: &str,
        sub_object: Option<String>,
    ) -> ObjectKey {
        ObjectKey::new(
            self.object_source_kind,
            self.connection_alias,
            MAIN_CATALOG,
            MAIN_SCHEMA,
            object_kind,
            object_name,
            sub_object,
        )
    }
}

fn table_annotation(table_key: ObjectKey, relation: &RawRelation) -> ObjectAnnotation {
    let mut properties = BTreeMap::new();
    properties.insert("strict".to_owned(), MetadataValue::Boolean(relation.strict));
    properties.insert(
        "without_rowid".to_owned(),
        MetadataValue::Boolean(relation.without_rowid),
    );
    properties.insert(
        "sqlite_relation_type".to_owned(),
        MetadataValue::String(
            match relation.kind {
                RawRelationKind::Table(TableKind::Virtual) => "virtual",
                RawRelationKind::Table(TableKind::Shadow) => "shadow",
                _ => "table",
            }
            .to_owned(),
        ),
    );
    ObjectAnnotation {
        object_key: table_key,
        definition: relation.sql.clone(),
        properties,
    }
}

fn lookup_key(
    keys: &BTreeMap<String, ObjectKey>,
    name: &str,
    object_type: &str,
) -> Result<ObjectKey, SqliteAdapterError> {
    keys.get(&fold_identifier(name)).cloned().ok_or_else(|| {
        SqliteAdapterError::mapping(
            format!("{object_type} {name}"),
            "catalog relationship points outside the selected metadata scope",
        )
    })
}

struct MappedConstraints {
    constraints: Vec<ConstraintObject>,
    check_dependency_count: u64,
}

impl SqliteSnapshotMapper<'_> {
    #[allow(clippy::too_many_arguments)]
    fn map_constraints(
        &self,
        relation: &RawRelation,
        raw_foreign_keys: &[RawForeignKey],
        raw_indexes: &[RawIndex],
        table_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
        primary_key_columns: &BTreeMap<String, Vec<ObjectKey>>,
        metadata: &mut CanonicalMetadata,
    ) -> Result<MappedConstraints, SqliteAdapterError> {
        let table_key = lookup_key(table_keys, &relation.name, "table")?;
        let parsed_constraints = relation
            .parsed_table
            .as_ref()
            .map(|table| table.constraints.as_slice())
            .unwrap_or_default();
        let parsed_primary = parsed_constraints
            .iter()
            .filter(|constraint| constraint.kind == ParsedConstraintKind::PrimaryKey)
            .collect::<Vec<_>>();
        if parsed_primary.len() > 1 {
            return Err(SqliteAdapterError::mapping(
                format!("table {}", relation.name),
                "CREATE TABLE contains more than one PRIMARY KEY",
            ));
        }
        let raw_primary = primary_key_columns
            .get(&fold_identifier(&relation.name))
            .cloned()
            .unwrap_or_default();
        if relation.parsed_table.is_some() {
            match (parsed_primary.first(), raw_primary.is_empty()) {
                (Some(parsed), false) => {
                    let parsed_columns =
                        resolve_named_columns(&relation.name, &parsed.columns, column_keys)?;
                    if !same_key_sequence(&parsed_columns, &raw_primary) {
                        return Err(SqliteAdapterError::mapping(
                            format!("primary key on {}", relation.name),
                            "CREATE TABLE columns disagree with table_xinfo primary-key ordinals",
                        ));
                    }
                }
                (Some(_), true) | (None, false) => {
                    return Err(SqliteAdapterError::mapping(
                        format!("primary key on {}", relation.name),
                        "CREATE TABLE and table_xinfo disagree about primary-key presence",
                    ));
                }
                (None, true) => {}
            }
        }

        let mut names = ConstraintNameAllocator::default();
        let mut constraints = Vec::new();
        if !raw_primary.is_empty() {
            let parsed = parsed_primary.first().copied();
            let (name, declared_name) = names.allocate(
                parsed.and_then(|constraint| constraint.name.as_deref()),
                &format!("pk_{}", relation.name),
            );
            let mut properties = parsed
                .map(|constraint| constraint.properties.clone())
                .unwrap_or_default();
            preserve_declared_name(&mut properties, declared_name);
            let constraint = ConstraintObject {
                key: self.key(ObjectKind::PrimaryKey, &relation.name, Some(name.clone())),
                table_key: table_key.clone(),
                name,
                kind: ConstraintKind::PrimaryKey,
                columns: raw_primary,
                referenced_table_key: None,
                referenced_columns: vec![],
                expression: None,
            };
            push_annotation_if_needed(metadata, &constraint.key, None, properties);
            constraints.push(constraint);
        }

        let table_indexes = raw_indexes
            .iter()
            .filter(|index| same_identifier(&index.table_name, &relation.name))
            .collect::<Vec<_>>();
        let raw_unique_indexes = table_indexes
            .iter()
            .copied()
            .filter(|index| index.origin == "u")
            .collect::<Vec<_>>();
        let parsed_unique = parsed_constraints
            .iter()
            .filter(|constraint| constraint.kind == ParsedConstraintKind::Unique)
            .collect::<Vec<_>>();
        if relation.parsed_table.is_some() && parsed_unique.len() != raw_unique_indexes.len() {
            return Err(SqliteAdapterError::mapping(
                format!("unique constraints on {}", relation.name),
                format!(
                    "CREATE TABLE has {} UNIQUE constraint(s), but index_list reports {}",
                    parsed_unique.len(),
                    raw_unique_indexes.len()
                ),
            ));
        }
        let mut matched_unique = BTreeSet::new();
        for (ordinal, raw_index) in raw_unique_indexes.iter().enumerate() {
            let raw_columns = direct_index_column_names(raw_index)?;
            let parsed_match = parsed_unique
                .iter()
                .enumerate()
                .find(|(index, constraint)| {
                    !matched_unique.contains(index)
                        && same_identifier_sequence(&constraint.columns, &raw_columns)
                });
            let parsed = match (relation.parsed_table.is_some(), parsed_match) {
                (true, Some((index, parsed))) => {
                    matched_unique.insert(index);
                    Some(*parsed)
                }
                (true, None) => {
                    return Err(SqliteAdapterError::mapping(
                        format!("unique index {}", raw_index.name),
                        "index_xinfo columns do not match any parsed UNIQUE constraint",
                    ));
                }
                (false, _) => None,
            };
            let columns = resolve_named_columns(&relation.name, &raw_columns, column_keys)?;
            let (name, declared_name) = names.allocate(
                parsed.and_then(|constraint| constraint.name.as_deref()),
                &format!("uq_{}_{}", relation.name, ordinal + 1),
            );
            let mut properties = parsed
                .map(|constraint| constraint.properties.clone())
                .unwrap_or_default();
            properties.insert(
                "backing_index".to_owned(),
                MetadataValue::String(raw_index.name.clone()),
            );
            preserve_declared_name(&mut properties, declared_name);
            let constraint = ConstraintObject {
                key: self.key(
                    ObjectKind::UniqueConstraint,
                    &relation.name,
                    Some(name.clone()),
                ),
                table_key: table_key.clone(),
                name,
                kind: ConstraintKind::Unique,
                columns,
                referenced_table_key: None,
                referenced_columns: vec![],
                expression: None,
            };
            push_annotation_if_needed(metadata, &constraint.key, None, properties);
            constraints.push(constraint);
        }

        let mut check_dependency_count = 0_u64;
        for (ordinal, parsed) in parsed_constraints
            .iter()
            .filter(|constraint| constraint.kind == ParsedConstraintKind::Check)
            .enumerate()
        {
            let expression = parsed.expression.as_deref().ok_or_else(|| {
                SqliteAdapterError::mapping(
                    format!("check constraint on {}", relation.name),
                    "parsed CHECK constraint has no expression",
                )
            })?;
            let dependencies = self.expression_dependencies(
                &relation.name,
                &[expression],
                table_keys,
                &BTreeMap::new(),
                column_keys,
            )?;
            let columns = dependencies
                .into_iter()
                .filter(|key| {
                    key.object_kind == ObjectKind::Column
                        && same_identifier(&key.object_name, &relation.name)
                })
                .collect::<Vec<_>>();
            check_dependency_count += columns.len() as u64;
            let (name, declared_name) = names.allocate(
                parsed.name.as_deref(),
                &format!("ck_{}_{}", relation.name, ordinal + 1),
            );
            let mut properties = parsed.properties.clone();
            preserve_declared_name(&mut properties, declared_name);
            let constraint = ConstraintObject {
                key: self.key(
                    ObjectKind::CheckConstraint,
                    &relation.name,
                    Some(name.clone()),
                ),
                table_key: table_key.clone(),
                name,
                kind: ConstraintKind::Check,
                columns,
                referenced_table_key: None,
                referenced_columns: vec![],
                expression: Some(expression.to_owned()),
            };
            push_annotation_if_needed(metadata, &constraint.key, None, properties);
            constraints.push(constraint);
        }

        let parsed_foreign_keys = parsed_constraints
            .iter()
            .filter(|constraint| constraint.kind == ParsedConstraintKind::ForeignKey)
            .collect::<Vec<_>>();
        if relation.parsed_table.is_some() && parsed_foreign_keys.len() != raw_foreign_keys.len() {
            return Err(SqliteAdapterError::mapping(
                format!("foreign keys on {}", relation.name),
                format!(
                    "CREATE TABLE has {} FOREIGN KEY constraint(s), but foreign_key_list reports {}",
                    parsed_foreign_keys.len(),
                    raw_foreign_keys.len()
                ),
            ));
        }
        let mut matched_foreign_keys = BTreeSet::new();
        for raw_foreign_key in raw_foreign_keys {
            let mapped = resolve_raw_foreign_key(
                &relation.name,
                raw_foreign_key,
                table_keys,
                column_keys,
                primary_key_columns,
            )?;
            let parsed_match = parsed_foreign_keys
                .iter()
                .enumerate()
                .find(|(index, parsed)| {
                    !matched_foreign_keys.contains(index)
                        && parsed_foreign_key_matches(parsed, &mapped, raw_foreign_key)
                });
            let parsed = match (relation.parsed_table.is_some(), parsed_match) {
                (true, Some((index, parsed))) => {
                    matched_foreign_keys.insert(index);
                    Some(*parsed)
                }
                (true, None) => {
                    return Err(SqliteAdapterError::mapping(
                        format!("foreign key {}.{}", relation.name, raw_foreign_key.id),
                        "foreign_key_list does not match any parsed FOREIGN KEY constraint",
                    ));
                }
                (false, _) => None,
            };
            let (name, declared_name) = names.allocate(
                parsed.and_then(|constraint| constraint.name.as_deref()),
                &format!("fk_{}_{}", relation.name, raw_foreign_key.id),
            );
            let mut properties = parsed
                .map(|constraint| constraint.properties.clone())
                .unwrap_or_default();
            properties.insert(
                "on_update".to_owned(),
                MetadataValue::String(raw_foreign_key.on_update.clone()),
            );
            properties.insert(
                "on_delete".to_owned(),
                MetadataValue::String(raw_foreign_key.on_delete.clone()),
            );
            properties.insert(
                "match".to_owned(),
                MetadataValue::String(raw_foreign_key.match_name.clone()),
            );
            preserve_declared_name(&mut properties, declared_name);
            let constraint = ConstraintObject {
                key: self.key(ObjectKind::ForeignKey, &relation.name, Some(name.clone())),
                table_key: table_key.clone(),
                name,
                kind: ConstraintKind::ForeignKey,
                columns: mapped.source_columns,
                referenced_table_key: Some(mapped.referenced_table),
                referenced_columns: mapped.referenced_columns,
                expression: None,
            };
            push_annotation_if_needed(metadata, &constraint.key, None, properties);
            constraints.push(constraint);
        }

        Ok(MappedConstraints {
            constraints,
            check_dependency_count,
        })
    }
}

#[derive(Default)]
struct ConstraintNameAllocator {
    uses: BTreeMap<String, u32>,
}

impl ConstraintNameAllocator {
    fn allocate(&mut self, declared: Option<&str>, fallback: &str) -> (String, Option<String>) {
        let base = declared.unwrap_or(fallback).to_owned();
        let count = self.uses.entry(fold_identifier(&base)).or_default();
        *count += 1;
        if *count == 1 {
            (base, None)
        } else {
            (format!("{base}#{}", *count), declared.map(str::to_owned))
        }
    }
}

fn preserve_declared_name(
    properties: &mut BTreeMap<String, MetadataValue>,
    declared_name: Option<String>,
) {
    if let Some(declared_name) = declared_name {
        properties.insert(
            "declared_name".to_owned(),
            MetadataValue::String(declared_name),
        );
    }
}

fn push_annotation_if_needed(
    metadata: &mut CanonicalMetadata,
    object_key: &ObjectKey,
    definition: Option<String>,
    properties: BTreeMap<String, MetadataValue>,
) {
    if definition.is_some() || !properties.is_empty() {
        metadata.annotations.push(ObjectAnnotation {
            object_key: object_key.clone(),
            definition,
            properties,
        });
    }
}

fn resolve_named_columns(
    relation_name: &str,
    column_names: &[String],
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> Result<Vec<ObjectKey>, SqliteAdapterError> {
    column_names
        .iter()
        .map(|column_name| {
            column_keys
                .get(&(fold_identifier(relation_name), fold_identifier(column_name)))
                .cloned()
                .ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("column {relation_name}.{column_name}"),
                        "schema relationship references a column absent from table_xinfo",
                    )
                })
        })
        .collect()
}

fn same_key_sequence(left: &[ObjectKey], right: &[ObjectKey]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.sub_object
                .as_deref()
                .zip(right.sub_object.as_deref())
                .is_some_and(|(left, right)| same_identifier(left, right))
        })
}

fn same_identifier_sequence(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| same_identifier(left, right))
}

fn direct_index_column_names(index: &RawIndex) -> Result<Vec<String>, SqliteAdapterError> {
    index
        .terms
        .iter()
        .filter(|term| term.key)
        .map(|term| {
            if term.cid < 0 {
                return Err(SqliteAdapterError::mapping(
                    format!("implicit index {}", index.name),
                    "UNIQUE/PRIMARY KEY backing index contains a non-column key term",
                ));
            }
            term.column_name.clone().ok_or_else(|| {
                SqliteAdapterError::mapping(
                    format!("index {}", index.name),
                    "index_xinfo omitted a direct column name",
                )
            })
        })
        .collect()
}

struct ResolvedForeignKey {
    source_columns: Vec<ObjectKey>,
    referenced_table: ObjectKey,
    referenced_columns: Vec<ObjectKey>,
}

fn resolve_raw_foreign_key(
    source_table: &str,
    raw: &RawForeignKey,
    table_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
    primary_key_columns: &BTreeMap<String, Vec<ObjectKey>>,
) -> Result<ResolvedForeignKey, SqliteAdapterError> {
    let referenced_table_name = raw
        .parts
        .first()
        .map(|part| part.referenced_table.as_str())
        .ok_or_else(|| {
            SqliteAdapterError::mapping(
                format!("foreign key {source_table}.{}", raw.id),
                "foreign key has no column parts",
            )
        })?;
    if raw
        .parts
        .iter()
        .any(|part| !same_identifier(&part.referenced_table, referenced_table_name))
    {
        return Err(SqliteAdapterError::mapping(
            format!("foreign key {source_table}.{}", raw.id),
            "foreign_key_list returned multiple target tables for one key",
        ));
    }
    let source_names = raw
        .parts
        .iter()
        .map(|part| part.source_column.clone())
        .collect::<Vec<_>>();
    let source_columns = resolve_named_columns(source_table, &source_names, column_keys)?;
    let referenced_table = lookup_key(table_keys, referenced_table_name, "referenced table")?;
    let referenced_columns = if raw
        .parts
        .iter()
        .all(|part| part.referenced_column.is_none())
    {
        primary_key_columns
            .get(&fold_identifier(referenced_table_name))
            .cloned()
            .filter(|columns| columns.len() == raw.parts.len())
            .ok_or_else(|| {
                SqliteAdapterError::mapping(
                    format!("foreign key {source_table}.{}", raw.id),
                    "implicit referenced columns do not resolve to a target primary key of equal cardinality",
                )
            })?
    } else {
        if raw
            .parts
            .iter()
            .any(|part| part.referenced_column.is_none())
        {
            return Err(SqliteAdapterError::mapping(
                format!("foreign key {source_table}.{}", raw.id),
                "foreign_key_list mixed explicit and implicit referenced columns",
            ));
        }
        resolve_named_columns(
            referenced_table_name,
            &raw.parts
                .iter()
                .filter_map(|part| part.referenced_column.clone())
                .collect::<Vec<_>>(),
            column_keys,
        )?
    };
    Ok(ResolvedForeignKey {
        source_columns,
        referenced_table,
        referenced_columns,
    })
}

fn parsed_foreign_key_matches(
    parsed: &ParsedConstraint,
    mapped: &ResolvedForeignKey,
    raw: &RawForeignKey,
) -> bool {
    let source_names = mapped
        .source_columns
        .iter()
        .filter_map(|key| key.sub_object.clone())
        .collect::<Vec<_>>();
    let referenced_names = mapped
        .referenced_columns
        .iter()
        .filter_map(|key| key.sub_object.clone())
        .collect::<Vec<_>>();
    let parsed_referenced_names = if parsed.referenced_columns.is_empty() {
        referenced_names.clone()
    } else {
        parsed.referenced_columns.clone()
    };
    let table_matches = parsed
        .referenced_table
        .as_deref()
        .is_some_and(|name| same_identifier(name, &mapped.referenced_table.object_name));
    let actions_match = [
        ("on_update", raw.on_update.as_str(), "no_action"),
        ("on_delete", raw.on_delete.as_str(), "no_action"),
        ("match", raw.match_name.as_str(), "none"),
    ]
    .into_iter()
    .all(|(property, actual, default)| {
        parsed
            .properties
            .get(property)
            .and_then(metadata_string)
            .unwrap_or(default)
            == actual
    });
    table_matches
        && same_identifier_sequence(&parsed.columns, &source_names)
        && same_identifier_sequence(&parsed_referenced_names, &referenced_names)
        && actions_match
}

fn metadata_string(value: &MetadataValue) -> Option<&str> {
    match value {
        MetadataValue::String(value) => Some(value),
        _ => None,
    }
}

struct MappedIndexes {
    indexes: Vec<IndexObject>,
    direct_column_count: u64,
}

impl SqliteSnapshotMapper<'_> {
    fn map_generated_dependencies(
        &self,
        relations: &[RawRelation],
        table_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
        metadata: &mut CanonicalMetadata,
    ) -> Result<(), SqliteAdapterError> {
        for relation in relations.iter().filter(|relation| relation.kind.is_table()) {
            let Some(parsed) = &relation.parsed_table else {
                continue;
            };
            for column in parsed
                .columns
                .iter()
                .filter(|column| column.generated_expression.is_some())
            {
                let expression = column.generated_expression.as_deref().unwrap_or_default();
                let generated_key = column_keys
                    .get(&(
                        fold_identifier(&relation.name),
                        fold_identifier(&column.name),
                    ))
                    .cloned()
                    .ok_or_else(|| {
                        SqliteAdapterError::mapping(
                            format!("generated column {}.{}", relation.name, column.name),
                            "generated column is absent from table_xinfo",
                        )
                    })?;
                for dependency in self
                    .expression_dependencies(
                        &relation.name,
                        &[expression],
                        table_keys,
                        &BTreeMap::new(),
                        column_keys,
                    )?
                    .into_iter()
                    .filter(|key| {
                        key.object_kind == ObjectKind::Column
                            && same_identifier(&key.object_name, &relation.name)
                    })
                {
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::DependsOn,
                        from_key: generated_key.clone(),
                        to_key: dependency,
                        ordinal: None,
                        properties: BTreeMap::new(),
                    });
                }
            }
        }
        Ok(())
    }

    fn map_indexes(
        &self,
        raw_indexes: &[RawIndex],
        table_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
        metadata: &mut CanonicalMetadata,
    ) -> Result<MappedIndexes, SqliteAdapterError> {
        let mut indexes = Vec::new();
        let mut direct_column_count = 0_u64;
        for raw in raw_indexes {
            let table_key = lookup_key(table_keys, &raw.table_name, "index table")?;
            let index_key = self.key(ObjectKind::Index, &raw.table_name, Some(raw.name.clone()));
            let key_terms = raw.terms.iter().filter(|term| term.key).collect::<Vec<_>>();
            let mut columns = Vec::new();
            let mut expression_terms = Vec::new();
            let mut probe_expressions = Vec::<String>::new();
            for (ordinal, term) in key_terms.iter().enumerate() {
                let parsed_term = raw
                    .parsed
                    .as_ref()
                    .and_then(|index| index.terms.get(ordinal));
                if term.cid >= 0 {
                    let column_name = term.column_name.as_deref().ok_or_else(|| {
                        SqliteAdapterError::mapping(
                            format!("index {}", raw.name),
                            "direct index term has no column name",
                        )
                    })?;
                    if parsed_term
                        .and_then(|term| term.column_name.as_deref())
                        .is_some_and(|parsed| !same_identifier(parsed, column_name))
                    {
                        return Err(SqliteAdapterError::mapping(
                            format!("index {}", raw.name),
                            "CREATE INDEX term disagrees with index_xinfo column",
                        ));
                    }
                    columns.extend(resolve_named_columns(
                        &raw.table_name,
                        &[column_name.to_owned()],
                        column_keys,
                    )?);
                    direct_column_count += 1;
                } else if term.cid == -2 {
                    let expression =
                        parsed_term
                            .map(|term| term.expression.clone())
                            .ok_or_else(|| {
                                SqliteAdapterError::mapping(
                                    format!("index {}", raw.name),
                                    "expression index term has no parsed CREATE INDEX expression",
                                )
                            })?;
                    expression_terms.push(expression.clone());
                    probe_expressions.push(expression);
                } else {
                    let expression = parsed_term
                        .map(|term| term.expression.clone())
                        .unwrap_or_else(|| "rowid".to_owned());
                    expression_terms.push(expression.clone());
                    probe_expressions.push(expression);
                }
                if let Some(parsed_term) = parsed_term {
                    let expected_descending = parsed_term.order.as_deref() == Some("DESC");
                    if expected_descending != term.descending {
                        return Err(SqliteAdapterError::mapping(
                            format!("index {} term {}", raw.name, ordinal + 1),
                            "CREATE INDEX ordering disagrees with index_xinfo",
                        ));
                    }
                }
            }
            if let Some(predicate) = raw
                .parsed
                .as_ref()
                .and_then(|index| index.predicate.clone())
            {
                probe_expressions.push(predicate);
            }
            if !probe_expressions.is_empty() {
                for dependency in self.expression_dependencies(
                    &raw.table_name,
                    &probe_expressions
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    table_keys,
                    &BTreeMap::new(),
                    column_keys,
                )? {
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::DependsOn,
                        from_key: index_key.clone(),
                        to_key: dependency,
                        ordinal: None,
                        properties: BTreeMap::new(),
                    });
                }
            }
            let mut auxiliary_columns = Vec::new();
            for term in raw.terms.iter().filter(|term| !term.key && term.cid >= 0) {
                let column_name = term.column_name.as_deref().ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("index {}", raw.name),
                        "auxiliary index term has no column name",
                    )
                })?;
                let column_key =
                    resolve_named_columns(&raw.table_name, &[column_name.to_owned()], column_keys)?
                        .pop()
                        .ok_or_else(|| {
                            SqliteAdapterError::mapping(
                                format!("index {}", raw.name),
                                "auxiliary index column did not resolve",
                            )
                        })?;
                auxiliary_columns.push(column_name.to_owned());
                let mut properties = BTreeMap::new();
                properties.insert(
                    "role".to_owned(),
                    MetadataValue::String("sqlite_auxiliary".to_owned()),
                );
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::IncludesColumn,
                    from_key: index_key.clone(),
                    to_key: column_key,
                    ordinal: Some(term.sequence.saturating_add(1)),
                    properties,
                });
            }
            let mut properties = BTreeMap::new();
            properties.insert(
                "origin".to_owned(),
                MetadataValue::String(raw.origin.clone()),
            );
            properties.insert("partial".to_owned(), MetadataValue::Boolean(raw.partial));
            properties.insert(
                "term_collations".to_owned(),
                MetadataValue::StringList(
                    key_terms
                        .iter()
                        .map(|term| term.collation.clone().unwrap_or_default())
                        .collect(),
                ),
            );
            properties.insert(
                "term_orders".to_owned(),
                MetadataValue::StringList(
                    key_terms
                        .iter()
                        .map(|term| {
                            if term.descending {
                                "DESC".to_owned()
                            } else {
                                "ASC".to_owned()
                            }
                        })
                        .collect(),
                ),
            );
            if let Some(parsed) = &raw.parsed {
                properties.insert(
                    "term_nulls".to_owned(),
                    MetadataValue::StringList(
                        parsed
                            .terms
                            .iter()
                            .map(|term| term.nulls.clone().unwrap_or_default())
                            .collect(),
                    ),
                );
            }
            if !auxiliary_columns.is_empty() {
                properties.insert(
                    "auxiliary_columns".to_owned(),
                    MetadataValue::StringList(auxiliary_columns),
                );
            }
            push_annotation_if_needed(metadata, &index_key, raw.sql.clone(), properties);
            indexes.push(IndexObject {
                key: index_key,
                table_key,
                name: raw.name.clone(),
                columns,
                is_unique: raw.unique,
                is_primary: raw.origin == "pk",
                predicate: raw
                    .parsed
                    .as_ref()
                    .and_then(|index| index.predicate.clone()),
                expression: (!expression_terms.is_empty()).then(|| expression_terms.join(", ")),
            });
        }
        Ok(MappedIndexes {
            indexes,
            direct_column_count,
        })
    }

    fn view_dependencies(
        &self,
        view: &RawRelation,
        table_keys: &BTreeMap<String, ObjectKey>,
        view_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
    ) -> Result<Vec<ObjectKey>, SqliteAdapterError> {
        let projection = if view.columns.is_empty() {
            "1".to_owned()
        } else {
            view.columns
                .iter()
                .map(|column| quote_identifier(&column.name))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let sql = format!(
            "EXPLAIN SELECT {projection} FROM {} LIMIT 0",
            quote_identifier(&view.name)
        );
        let accesses =
            capture_prepare_accesses(self.conn, &sql, AccessorFilter::Exact(view.name.clone()))?;
        map_accesses(accesses, table_keys, view_keys, column_keys)
    }

    fn expression_dependencies(
        &self,
        relation_name: &str,
        expressions: &[&str],
        table_keys: &BTreeMap<String, ObjectKey>,
        view_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
    ) -> Result<Vec<ObjectKey>, SqliteAdapterError> {
        if expressions.is_empty() {
            return Ok(vec![]);
        }
        let projection = expressions
            .iter()
            .map(|expression| format!("({expression})"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "EXPLAIN SELECT {projection} FROM {} LIMIT 0",
            quote_identifier(relation_name)
        );
        let accesses = capture_prepare_accesses(self.conn, &sql, AccessorFilter::Any)?;
        map_accesses(accesses, table_keys, view_keys, column_keys)
    }

    #[allow(clippy::too_many_arguments)]
    fn map_triggers(
        &self,
        raw_triggers: &[RawTrigger],
        relations: &[RawRelation],
        table_keys: &BTreeMap<String, ObjectKey>,
        view_keys: &BTreeMap<String, ObjectKey>,
        column_keys: &BTreeMap<(String, String), ObjectKey>,
        metadata: &mut CanonicalMetadata,
    ) -> Result<Vec<TriggerObject>, SqliteAdapterError> {
        let relation_by_name = relations
            .iter()
            .map(|relation| (fold_identifier(&relation.name), relation))
            .collect::<BTreeMap<_, _>>();
        let mut triggers = Vec::new();
        for raw in raw_triggers {
            let owner = table_keys
                .get(&fold_identifier(&raw.owner_name))
                .or_else(|| view_keys.get(&fold_identifier(&raw.owner_name)))
                .cloned()
                .ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("trigger {}", raw.name),
                        "trigger owner is absent from the selected relation inventory",
                    )
                })?;
            let trigger_key =
                self.key(ObjectKind::Trigger, &raw.owner_name, Some(raw.name.clone()));
            let owner_relation = relation_by_name
                .get(&fold_identifier(&raw.owner_name))
                .copied()
                .ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("trigger {}", raw.name),
                        "trigger owner metadata is unavailable",
                    )
                })?;
            let probe_sql = trigger_probe_sql(raw, owner_relation)?;
            let accesses = capture_prepare_accesses(
                self.conn,
                &probe_sql,
                AccessorFilter::Exact(raw.name.clone()),
            )?;
            let mut dependencies = map_accesses(accesses, table_keys, view_keys, column_keys)?;
            for update_column in &raw.parsed.update_columns {
                let column_key = column_keys
                    .get(&(
                        fold_identifier(&raw.owner_name),
                        fold_identifier(update_column),
                    ))
                    .cloned()
                    .ok_or_else(|| {
                        SqliteAdapterError::mapping(
                            format!("trigger {}", raw.name),
                            format!(
                                "UPDATE OF column '{update_column}' is not present on trigger owner"
                            ),
                        )
                    })?;
                dependencies.push(column_key);
            }
            deduplicate_keys(&mut dependencies);
            for dependency in dependencies {
                let mut properties = BTreeMap::new();
                properties.insert(
                    "access".to_owned(),
                    MetadataValue::String("trigger_prepare".to_owned()),
                );
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: trigger_key.clone(),
                    to_key: dependency,
                    ordinal: None,
                    properties,
                });
            }
            let mut properties = BTreeMap::new();
            if !raw.parsed.update_columns.is_empty() {
                properties.insert(
                    "update_columns".to_owned(),
                    MetadataValue::StringList(raw.parsed.update_columns.clone()),
                );
            }
            if let Some(when_expression) = &raw.parsed.when_expression {
                properties.insert(
                    "when_expression".to_owned(),
                    MetadataValue::String(when_expression.clone()),
                );
            }
            push_annotation_if_needed(metadata, &trigger_key, None, properties);
            triggers.push(TriggerObject {
                key: trigger_key,
                table_key: owner,
                name: raw.name.clone(),
                timing: Some(raw.parsed.timing.clone()),
                events: vec![raw.parsed.event.clone()],
                definition: Some(raw.sql.clone()),
                executes_routine_key: None,
            });
        }
        Ok(triggers)
    }
}

fn trigger_probe_sql(
    trigger: &RawTrigger,
    owner: &RawRelation,
) -> Result<String, SqliteAdapterError> {
    let owner_name = quote_identifier(&owner.name);
    match trigger.parsed.event.as_str() {
        "INSERT" => Ok(format!("EXPLAIN INSERT INTO {owner_name} DEFAULT VALUES")),
        "DELETE" => Ok(format!("EXPLAIN DELETE FROM {owner_name} WHERE 0")),
        "UPDATE" => {
            let column_name = trigger
                .parsed
                .update_columns
                .first()
                .cloned()
                .or_else(|| {
                    owner
                        .columns
                        .iter()
                        .find(|column| !matches!(column.hidden, 2 | 3))
                        .map(|column| column.name.clone())
                })
                .ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("trigger {}", trigger.name),
                        "cannot prepare an UPDATE event for an owner with no writable columns",
                    )
                })?;
            if !owner
                .columns
                .iter()
                .any(|column| same_identifier(&column.name, &column_name))
            {
                return Err(SqliteAdapterError::mapping(
                    format!("trigger {}", trigger.name),
                    format!("UPDATE OF column '{column_name}' is not present on the owner"),
                ));
            }
            let column = quote_identifier(&column_name);
            Ok(format!(
                "EXPLAIN UPDATE {owner_name} SET {column} = {column} WHERE 0"
            ))
        }
        event => Err(SqliteAdapterError::mapping(
            format!("trigger {}", trigger.name),
            format!("unsupported parsed trigger event '{event}'"),
        )),
    }
}

#[derive(Clone)]
enum AccessorFilter {
    Any,
    Exact(String),
}

impl AccessorFilter {
    fn matches(&self, accessor: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => accessor.is_some_and(|value| same_identifier(value, expected)),
        }
    }
}

#[derive(Clone, Debug)]
struct RawAccess {
    relation_name: String,
    column_name: Option<String>,
}

fn capture_prepare_accesses(
    conn: &Connection,
    sql: &str,
    filter: AccessorFilter,
) -> Result<Vec<RawAccess>, SqliteAdapterError> {
    let accesses = Arc::new(Mutex::new(Vec::<RawAccess>::new()));
    let captured = Arc::clone(&accesses);
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if !filter.matches(context.accessor) {
            return Authorization::Allow;
        }
        let access = match context.action {
            AuthAction::Read {
                table_name,
                column_name,
            }
            | AuthAction::Update {
                table_name,
                column_name,
            } => Some(RawAccess {
                relation_name: table_name.to_owned(),
                column_name: (!column_name.is_empty()).then(|| column_name.to_owned()),
            }),
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } => {
                Some(RawAccess {
                    relation_name: table_name.to_owned(),
                    column_name: None,
                })
            }
            _ => None,
        };
        if let Some(access) = access {
            if let Ok(mut values) = captured.lock() {
                values.push(access);
            }
        }
        Authorization::Allow
    }));
    let prepare_result = conn.prepare(sql).map(|_| ());
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    prepare_result.map_err(SqliteAdapterError::from)?;
    let values = accesses.lock().map_err(|_| {
        SqliteAdapterError::mapping(
            "SQLite dependency authorizer",
            "dependency capture lock was poisoned",
        )
    })?;
    Ok(values.clone())
}

fn map_accesses(
    accesses: Vec<RawAccess>,
    table_keys: &BTreeMap<String, ObjectKey>,
    view_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> Result<Vec<ObjectKey>, SqliteAdapterError> {
    let mut keys = Vec::new();
    for access in accesses {
        let relation_folded = fold_identifier(&access.relation_name);
        let relation_key = table_keys
            .get(&relation_folded)
            .or_else(|| view_keys.get(&relation_folded))
            .cloned();
        let Some(relation_key) = relation_key else {
            if access.relation_name.starts_with("sqlite_") {
                continue;
            }
            return Err(SqliteAdapterError::mapping(
                format!("dependency relation {}", access.relation_name),
                "SQLite authorizer reported a relation outside the selected catalog inventory",
            ));
        };
        keys.push(relation_key);
        if let Some(column_name) = access.column_name {
            if is_rowid_alias(&column_name) {
                continue;
            }
            let column_key = column_keys
                .get(&(relation_folded, fold_identifier(&column_name)))
                .cloned()
                .ok_or_else(|| {
                    SqliteAdapterError::mapping(
                        format!("dependency column {}.{column_name}", access.relation_name),
                        "SQLite authorizer reported a column absent from table_xinfo",
                    )
                })?;
            keys.push(column_key);
        }
    }
    deduplicate_keys(&mut keys);
    Ok(keys)
}

fn is_rowid_alias(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "rowid" | "oid" | "_rowid_"
    )
}

fn deduplicate_keys(keys: &mut Vec<ObjectKey>) {
    let mut seen = BTreeSet::new();
    keys.retain(|key| seen.insert(key.to_string()));
    keys.sort_by_key(ObjectKey::to_string);
}

fn deduplicate_metadata_relationships(relationships: &mut Vec<MetadataRelationship>) {
    let mut seen = BTreeSet::new();
    relationships.retain(|relationship| {
        seen.insert((
            relationship.kind.clone(),
            relationship.from_key.to_string(),
            relationship.to_key.to_string(),
            relationship.ordinal,
        ))
    });
}

fn discovery_counts(
    raw: &RawSqliteCatalog,
    check_dependency_count: u64,
    view_dependency_count: u64,
    metadata_relationship_count: u64,
) -> DiscoveryCounts {
    let tables = raw
        .relations
        .iter()
        .filter(|relation| relation.kind.is_table())
        .count() as u64;
    let views = raw
        .relations
        .iter()
        .filter(|relation| relation.kind == RawRelationKind::View)
        .count() as u64;
    let columns = raw
        .relations
        .iter()
        .map(|relation| relation.columns.len() as u64)
        .sum::<u64>();
    let table_columns = raw
        .relations
        .iter()
        .filter(|relation| relation.kind.is_table())
        .map(|relation| relation.columns.len() as u64)
        .sum::<u64>();
    let view_columns = columns.saturating_sub(table_columns);
    let primary_keys = raw
        .relations
        .iter()
        .filter(|relation| {
            relation.kind.is_table()
                && relation
                    .columns
                    .iter()
                    .any(|column| column.primary_key_position > 0)
        })
        .count() as u64;
    let primary_key_columns = raw
        .relations
        .iter()
        .filter(|relation| relation.kind.is_table())
        .flat_map(|relation| relation.columns.iter())
        .filter(|column| column.primary_key_position > 0)
        .count() as u64;
    let foreign_keys = raw
        .foreign_keys
        .values()
        .map(|foreign_keys| foreign_keys.len() as u64)
        .sum::<u64>();
    let foreign_key_pairs = raw
        .foreign_keys
        .values()
        .flatten()
        .map(|foreign_key| foreign_key.parts.len() as u64)
        .sum::<u64>();
    let unique_constraints = raw
        .indexes
        .iter()
        .filter(|index| index.origin == "u")
        .count() as u64;
    let unique_columns = raw
        .indexes
        .iter()
        .filter(|index| index.origin == "u")
        .flat_map(|index| index.terms.iter())
        .filter(|term| term.key)
        .count() as u64;
    let check_constraints = raw
        .relations
        .iter()
        .filter_map(|relation| relation.parsed_table.as_ref())
        .flat_map(|table| table.constraints.iter())
        .filter(|constraint| constraint.kind == ParsedConstraintKind::Check)
        .count() as u64;
    let direct_index_columns = raw
        .indexes
        .iter()
        .flat_map(|index| index.terms.iter())
        .filter(|term| term.key && term.cid >= 0)
        .count() as u64;

    let mut counts = DiscoveryCounts {
        objects: ObjectCategory::ALL
            .into_iter()
            .map(|category| {
                (
                    category,
                    DiscoveredCount {
                        count: 0,
                        evidence:
                            "SQLite selected schema has no persisted object in this vendor category"
                                .to_owned(),
                    },
                )
            })
            .collect(),
        relationships: RelationshipCategory::ALL
            .into_iter()
            .map(|category| {
                (
                    category,
                    DiscoveredCount {
                        count: 0,
                        evidence:
                            "SQLite selected schema has no relationship in this vendor category"
                                .to_owned(),
                    },
                )
            })
            .collect(),
    };
    set_object_count(
        &mut counts,
        ObjectCategory::Database,
        raw.database_names.len() as u64,
        "PRAGMA database_list within the certified main-only scope",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::Schema,
        1,
        "SQLite main catalog maps to one canonical main schema",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::Table,
        tables,
        "PRAGMA main.table_list table/virtual/shadow rows excluding sqlite_*",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::Column,
        table_columns,
        "Sum of PRAGMA main.table_xinfo rows for selected tables",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::ViewColumn,
        view_columns,
        "Sum of PRAGMA main.table_xinfo rows for selected views",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::PrimaryKey,
        primary_keys,
        "Distinct selected tables with table_xinfo pk ordinals",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::ForeignKey,
        foreign_keys,
        "Distinct ids returned by PRAGMA main.foreign_key_list per table",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::UniqueConstraint,
        unique_constraints,
        "PRAGMA main.index_list rows with origin='u'",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::CheckConstraint,
        check_constraints,
        "CHECK clauses parsed from every persisted CREATE TABLE definition",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::Index,
        raw.indexes.len() as u64,
        "All PRAGMA main.index_list rows for selected tables",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::View,
        views,
        "PRAGMA main.table_list rows with type='view' excluding sqlite_*",
    );
    set_object_count(
        &mut counts,
        ObjectCategory::Trigger,
        raw.triggers.len() as u64,
        "sqlite_schema trigger rows excluding sqlite_*",
    );

    set_relationship_count(
        &mut counts,
        RelationshipCategory::DatabaseHasSchema,
        1,
        "Canonical SQLite main catalog-to-schema mapping",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::SchemaHasTable,
        tables,
        "Selected PRAGMA table_list table/virtual/shadow rows",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::TableHasColumn,
        table_columns,
        "PRAGMA table_xinfo rows whose owner is a selected table",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::TableHasConstraint,
        primary_keys + foreign_keys + unique_constraints + check_constraints,
        "Reconciled table_xinfo, foreign_key_list, index_list origin, and parsed CHECK inventory",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::ConstraintColumn,
        primary_key_columns + unique_columns + check_dependency_count,
        "PK/UQ catalog ordinals plus prepare-authorizer CHECK column reads",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::ForeignKeyColumnPair,
        foreign_key_pairs,
        "Rows returned by PRAGMA foreign_key_list",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::TableHasIndex,
        raw.indexes.len() as u64,
        "PRAGMA index_list rows attached to selected tables",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::IndexColumn,
        direct_index_columns,
        "PRAGMA index_xinfo key terms with non-negative column ids",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::SchemaHasView,
        views,
        "Selected PRAGMA table_list view rows",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::ViewDependency,
        view_dependency_count,
        "SQLite prepare authorizer reads while selecting every output column from each view",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::TriggerTarget,
        raw.triggers.len() as u64,
        "sqlite_schema trigger tbl_name ownership",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::MetadataParent,
        view_columns,
        "PRAGMA table_xinfo output columns parented by selected views",
    );
    set_relationship_count(
        &mut counts,
        RelationshipCategory::MetadataRelationship,
        metadata_relationship_count,
        "Deduplicated SQLite authorizer expression/trigger dependencies and index auxiliary terms",
    );
    counts
}

fn set_object_count(
    counts: &mut DiscoveryCounts,
    category: ObjectCategory,
    count: u64,
    evidence: &str,
) {
    counts.objects.insert(
        category,
        DiscoveredCount {
            count,
            evidence: evidence.to_owned(),
        },
    );
}

fn set_relationship_count(
    counts: &mut DiscoveryCounts,
    category: RelationshipCategory,
    count: u64,
    evidence: &str,
) {
    counts.relationships.insert(
        category,
        DiscoveredCount {
            count,
            evidence: evidence.to_owned(),
        },
    );
}

fn require_bounded_sql(
    object_type: &str,
    object_name: &str,
    sql: &str,
) -> Result<(), SqliteAdapterError> {
    if sql.len() > MAX_SCHEMA_SQL_BYTES {
        return Err(SqliteAdapterError::mapping(
            format!("{object_type} {object_name}"),
            format!("schema definition exceeds {MAX_SCHEMA_SQL_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn fold_identifier(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn same_identifier(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn quote_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('\"', "\"\""))
}
