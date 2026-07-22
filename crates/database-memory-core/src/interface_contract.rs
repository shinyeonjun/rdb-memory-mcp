use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::certification::{CompletenessProof, CompletionStatus, COMPLETE_CONTRACT_VERSION};
use crate::graph_builder::insert_certified_schema_snapshot_graph;
use crate::graph_store::{GraphEdgeRecord, GraphNodeRecord, GraphStore, SnapshotAuthority};
use crate::introspection::CancellationToken;
use crate::redact::redact_connection_string;
use crate::{adapters, ddl, ObjectKey, ObjectKind};

pub const INTERFACE_CONTRACT_VERSION: u32 = 2;
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;
pub const DEFAULT_OBJECT_PAGE_LIMIT: usize = 100;
pub const MAX_OBJECT_PAGE_LIMIT: usize = 500;
pub const DEFAULT_RELATIONSHIP_LIMIT: usize = 100;
pub const MAX_RELATIONSHIP_LIMIT: usize = 200;
pub const ALL_OBJECT_KINDS: [ObjectKind; 26] = [
    ObjectKind::Database,
    ObjectKind::Schema,
    ObjectKind::Table,
    ObjectKind::Column,
    ObjectKind::PrimaryKey,
    ObjectKind::ForeignKey,
    ObjectKind::UniqueConstraint,
    ObjectKind::CheckConstraint,
    ObjectKind::Index,
    ObjectKind::View,
    ObjectKind::ViewColumn,
    ObjectKind::Trigger,
    ObjectKind::Routine,
    ObjectKind::MaterializedView,
    ObjectKind::Sequence,
    ObjectKind::RoutineParameter,
    ObjectKind::UserDefinedType,
    ObjectKind::Domain,
    ObjectKind::EnumValue,
    ObjectKind::Synonym,
    ObjectKind::ExclusionConstraint,
    ObjectKind::Event,
    ObjectKind::Package,
    ObjectKind::Principal,
    ObjectKind::Policy,
    ObjectKind::Extension,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteIndexRequest {
    pub source: String,
    pub path: Option<PathBuf>,
    pub connection_string: Option<String>,
    pub alias: String,
    pub requested_catalogs: Vec<String>,
    pub requested_schemas: Vec<String>,
    pub timeout_ms: u64,
}

impl CompleteIndexRequest {
    pub fn new(
        source: impl Into<String>,
        path: Option<PathBuf>,
        connection_string: Option<String>,
        alias: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            path,
            connection_string,
            alias: alias.into(),
            requested_catalogs: Vec::new(),
            requested_schemas: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexResult {
    pub contract_version: u32,
    pub status: CompletionStatus,
    pub snapshot_key: String,
    pub requested_source: String,
    pub analyzed_source: String,
    pub connection_alias: String,
    pub captured_at_unix_ms: i64,
    pub cache_path: String,
    pub objects_indexed: u64,
    pub relationships_indexed: u64,
    pub tables_indexed: usize,
    pub columns_indexed: usize,
    pub constraints_indexed: usize,
    pub indexes_indexed: usize,
    pub completeness: CompletenessProof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceErrorCode {
    InvalidRequest,
    AnalysisFailed,
    StorageFailed,
    SnapshotNotFound,
    ObjectNotFound,
    InvalidMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceStage {
    Configuration,
    Analysis,
    Persistence,
    SnapshotLookup,
    ObjectLookup,
    Serialization,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InterfaceError {
    pub contract_version: u32,
    pub code: InterfaceErrorCode,
    pub stage: InterfaceStage,
    pub message: String,
    pub remediation: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_failure: Option<Box<AnalysisFailure>>,
}

impl InterfaceError {
    fn new(
        code: InterfaceErrorCode,
        stage: InterfaceStage,
        message: impl Into<String>,
        remediation: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            contract_version: INTERFACE_CONTRACT_VERSION,
            code,
            stage,
            message: message.into(),
            remediation: remediation.into(),
            retryable,
            analysis_failure: None,
        }
    }

    fn analysis(failure: AnalysisFailure) -> Self {
        Self {
            contract_version: INTERFACE_CONTRACT_VERSION,
            code: InterfaceErrorCode::AnalysisFailed,
            stage: InterfaceStage::Analysis,
            message: failure.message.clone(),
            remediation: failure.remediation.clone(),
            retryable: failure.retryable,
            analysis_failure: Some(Box::new(failure)),
        }
    }

    pub fn storage(operation: &str, error: impl fmt::Display) -> Self {
        Self::new(
            InterfaceErrorCode::StorageFailed,
            InterfaceStage::Persistence,
            format!("{operation}: {error}"),
            "verify the cache path and local filesystem, then retry",
            true,
        )
    }

    pub fn invalid_request(
        stage: InterfaceStage,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(
            InterfaceErrorCode::InvalidRequest,
            stage,
            message,
            remediation,
            false,
        )
    }
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "interface contract {:?} at {:?}: {}",
            self.code, self.stage, self.message
        )
    }
}

impl std::error::Error for InterfaceError {}

pub fn analyze_complete_source(request: &CompleteIndexRequest) -> AnalysisOutcome {
    if let Some(failure) = validate_index_request(request) {
        return AnalysisOutcome::failed(failure);
    }

    let outcome = match request.source.as_str() {
        "sqlite" => adapters::sqlite::introspect_sqlite_complete_scoped(
            request.path.as_deref().expect("validated SQLite path"),
            &request.alias,
            sqlite_scope(&request.requested_catalogs),
            sqlite_scope(&request.requested_schemas),
            request.timeout_ms,
        ),
        "ddl-sqlite" => match ddl::sqlite::introspect_sqlite_ddl_complete_bounded(
            request.path.as_deref().expect("validated SQLite DDL path"),
            &request.alias,
            request.timeout_ms,
            &CancellationToken::new(),
        ) {
            Ok(snapshot) => AnalysisOutcome::complete(snapshot).unwrap_or_else(|error| {
                AnalysisOutcome::failed(AnalysisFailure::redacted(
                    AnalysisFailureCode::ValidationFailed,
                    AnalysisStage::Validation,
                    &request.source,
                    &request.alias,
                    error.to_string(),
                    "fix the DDL source until it produces a complete certified schema",
                    false,
                    None,
                ))
            }),
            Err(error) => AnalysisOutcome::failed(sqlite_ddl_failure(request, error)),
        },
        "postgres" => adapters::postgres::introspect_postgres_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated PostgreSQL connection string"),
            &request.alias,
            request.requested_schemas.clone(),
            request.timeout_ms,
        ),
        "yugabytedb" => adapters::yugabytedb::introspect_yugabytedb_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated YugabyteDB connection string"),
            &request.alias,
            request.requested_schemas.clone(),
            request.timeout_ms,
        ),
        "mysql" | "mariadb" => adapters::mysql::introspect_mysql_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated MySQL-family connection string"),
            &request.alias,
            request.requested_catalogs.clone(),
            request.timeout_ms,
        ),
        "sqlserver" => adapters::sqlserver::introspect_sqlserver_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated SQL Server connection string"),
            &request.alias,
            request.requested_catalogs.clone(),
            request.requested_schemas.clone(),
            request.timeout_ms,
        ),
        "oracle" => adapters::oracle::introspect_oracle_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated Oracle connection string"),
            &request.alias,
            request.requested_catalogs.clone(),
            request.requested_schemas.clone(),
            request.timeout_ms,
        ),
        "odbc" => adapters::odbc::introspect_odbc_complete_scoped(
            request
                .connection_string
                .as_deref()
                .expect("validated ODBC connection string"),
            &request.alias,
            request.requested_catalogs.clone(),
            request.requested_schemas.clone(),
            request.timeout_ms,
        ),
        _ => unreachable!("validated source kind"),
    };

    enforce_requested_product(request, outcome)
}

fn sqlite_ddl_failure(
    request: &CompleteIndexRequest,
    error: ddl::sqlite::SqliteDdlSourceError,
) -> AnalysisFailure {
    let (code, stage, remediation, retryable) = match &error {
        ddl::sqlite::SqliteDdlSourceError::Timeout(_) => (
            AnalysisFailureCode::Timeout,
            AnalysisStage::Discovery,
            "increase the bounded timeout or reduce the DDL source",
            true,
        ),
        ddl::sqlite::SqliteDdlSourceError::Cancelled(_) => (
            AnalysisFailureCode::Cancelled,
            AnalysisStage::Discovery,
            "start a new analysis when the result is still needed",
            true,
        ),
        ddl::sqlite::SqliteDdlSourceError::InvalidStatement { .. } => (
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Mapping,
            "remove row access, attachment, extensions, or unsupported statements from the DDL input",
            false,
        ),
        ddl::sqlite::SqliteDdlSourceError::InputTooLarge { .. }
        | ddl::sqlite::SqliteDdlSourceError::NoSqlFiles(_)
        | ddl::sqlite::SqliteDdlSourceError::Io { .. } => (
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            "provide a readable bounded SQLite DDL file or directory",
            false,
        ),
        ddl::sqlite::SqliteDdlSourceError::Apply { .. }
        | ddl::sqlite::SqliteDdlSourceError::Adapter(_) => (
            AnalysisFailureCode::MetadataMappingFailed,
            AnalysisStage::Mapping,
            "fix the SQLite DDL input and retry",
            false,
        ),
    };
    AnalysisFailure::redacted(
        code,
        stage,
        &request.source,
        &request.alias,
        error.to_string(),
        remediation,
        retryable,
        None,
    )
}

pub fn index_complete_source(
    store: &GraphStore,
    request: &CompleteIndexRequest,
    captured_at_unix_ms: i64,
    cache_path: impl Into<String>,
) -> Result<IndexResult, InterfaceError> {
    let outcome = analyze_complete_source(request);
    let certified = outcome.certified_snapshot().cloned().ok_or_else(|| {
        InterfaceError::analysis(
            outcome
                .failure()
                .expect("failed outcome must contain an analysis failure")
                .clone(),
        )
    })?;
    let snapshot_key = format!("{}:{}", request.source, request.alias);
    insert_certified_schema_snapshot_graph(store, &snapshot_key, captured_at_unix_ms, &certified)
        .map_err(|error| InterfaceError::storage("could not persist certified snapshot", error))?;

    let schema = &certified.snapshot.schema;
    let objects_indexed = certified
        .completeness
        .object_counts
        .iter()
        .map(|count| count.emitted)
        .sum();
    let relationships_indexed = certified
        .completeness
        .relationship_counts
        .iter()
        .map(|count| count.emitted)
        .sum();
    Ok(IndexResult {
        contract_version: INTERFACE_CONTRACT_VERSION,
        status: CompletionStatus::Complete,
        snapshot_key,
        requested_source: request.source.clone(),
        analyzed_source: schema.source_kind.clone(),
        connection_alias: schema.connection_alias.clone(),
        captured_at_unix_ms,
        cache_path: cache_path.into(),
        objects_indexed,
        relationships_indexed,
        tables_indexed: schema.tables.len(),
        columns_indexed: schema.columns.len(),
        constraints_indexed: schema.constraints.len(),
        indexes_indexed: schema.indexes.len(),
        completeness: certified.completeness,
    })
}

fn validate_index_request(request: &CompleteIndexRequest) -> Option<AnalysisFailure> {
    let connection_string = request.connection_string.as_deref();
    let failure = |message: &str, remediation: &str| {
        AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            &request.source,
            &request.alias,
            message,
            remediation,
            false,
            connection_string,
        )
    };
    if request.alias.trim().is_empty()
        || request.alias.len() > 1_024
        || request.alias.chars().any(char::is_control)
        || redact_connection_string(&request.alias) != request.alias
    {
        return Some(failure(
            "connection alias must be a bounded non-secret label without control characters",
            "provide a short logical alias instead of a path, URL, or connection string",
        ));
    }
    if request.timeout_ms == 0 || request.timeout_ms > MAX_TIMEOUT_MS {
        return Some(failure(
            "introspection timeout must be between 1 and 86400000 milliseconds",
            "provide a bounded positive timeout",
        ));
    }
    if invalid_scope(&request.requested_catalogs) || invalid_scope(&request.requested_schemas) {
        return Some(failure(
            "catalog and schema scopes must contain unique non-empty values of at most 1024 bytes",
            "remove duplicate, empty, or oversized scope values",
        ));
    }

    let file_source = matches!(request.source.as_str(), "sqlite" | "ddl-sqlite");
    let connection_source = matches!(
        request.source.as_str(),
        "postgres" | "yugabytedb" | "mysql" | "mariadb" | "sqlserver" | "oracle" | "odbc"
    );
    if !file_source && !connection_source {
        return Some(failure(
            "unsupported source; expected sqlite, ddl-sqlite, postgres, yugabytedb, mysql, mariadb, sqlserver, oracle, or odbc",
            "select a source listed by the contract support ledger",
        ));
    }
    if file_source && (request.path.is_none() || request.connection_string.is_some()) {
        return Some(failure(
            "SQLite sources require path and do not accept connection_string",
            "provide exactly one local SQLite database or DDL path",
        ));
    }
    if connection_source && (request.connection_string.is_none() || request.path.is_some()) {
        return Some(failure(
            "server and ODBC sources require connection_string and do not accept path",
            "provide exactly one connection string through the secret input field",
        ));
    }
    if matches!(request.source.as_str(), "postgres" | "yugabytedb")
        && !request.requested_catalogs.is_empty()
    {
        return Some(failure(
            "PostgreSQL-wire sources accept schema scope only within the connected database",
            "remove requested_catalogs or connect directly to the intended database",
        ));
    }
    if matches!(request.source.as_str(), "mysql" | "mariadb")
        && !request.requested_schemas.is_empty()
    {
        return Some(failure(
            "MySQL-family sources use requested_catalogs for database scope",
            "move exact database names to requested_catalogs",
        ));
    }
    if request.source == "ddl-sqlite"
        && (!request.requested_catalogs.is_empty() || !request.requested_schemas.is_empty())
    {
        return Some(failure(
            "SQLite DDL sources always produce the isolated main catalog and schema",
            "remove explicit catalog and schema scope",
        ));
    }
    None
}

fn invalid_scope(values: &[String]) -> bool {
    values
        .iter()
        .any(|value| value.trim().is_empty() || value.len() > 1_024 || value.contains('\0'))
        || values.len() != values.iter().collect::<BTreeSet<_>>().len()
}

fn sqlite_scope(values: &[String]) -> Vec<String> {
    if values.is_empty() {
        vec!["main".to_owned()]
    } else {
        values.to_vec()
    }
}

fn enforce_requested_product(
    request: &CompleteIndexRequest,
    outcome: AnalysisOutcome,
) -> AnalysisOutcome {
    let Some(certified) = outcome.certified_snapshot() else {
        return outcome;
    };
    let analyzed = certified.snapshot.schema.source_kind.as_str();
    let exact_product_required = matches!(request.source.as_str(), "mysql" | "mariadb");
    if exact_product_required && analyzed != request.source {
        return AnalysisOutcome::failed(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedProduct,
            AnalysisStage::CapabilityProbe,
            &request.source,
            &request.alias,
            format!(
                "requested product '{}' but the server identified as '{analyzed}'",
                request.source
            ),
            "select the matching mysql or mariadb source explicitly",
            false,
            request.connection_string.as_deref(),
        ));
    }
    outcome
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub contract_version: Option<u32>,
    pub authority: SnapshotAuthority,
    pub snapshot_key: String,
    pub entrypoint_source: String,
    pub source: Option<String>,
    pub alias: String,
    pub connection_alias: String,
    pub captured_at_unix_ms: i64,
    pub objects: u64,
    pub relationships: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDetail {
    pub snapshot: SnapshotSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<CompletenessProof>,
}

pub fn list_snapshot_summaries(store: &GraphStore) -> Result<Vec<SnapshotSummary>, InterfaceError> {
    store
        .list_snapshots()
        .map_err(|error| InterfaceError::storage("could not list snapshots", error))?
        .into_iter()
        .map(|snapshot| snapshot_summary(store, &snapshot.snapshot_key))
        .collect()
}

pub fn describe_snapshot(
    store: &GraphStore,
    selector: &str,
) -> Result<SnapshotDetail, InterfaceError> {
    let snapshot_key = resolve_snapshot_key(store, selector)?;
    let summary = snapshot_summary(store, &snapshot_key)?;
    let completeness = store
        .get_certified_snapshot(&snapshot_key)
        .map_err(|error| InterfaceError::storage("could not read completeness proof", error))?
        .map(|snapshot| snapshot.completeness);
    Ok(SnapshotDetail {
        snapshot: summary,
        completeness,
    })
}

pub fn resolve_snapshot_key(store: &GraphStore, selector: &str) -> Result<String, InterfaceError> {
    if store
        .get_snapshot(selector)
        .map_err(|error| InterfaceError::storage("could not read snapshot", error))?
        .is_some()
    {
        return Ok(selector.to_owned());
    }
    let mut matches = store
        .list_snapshots()
        .map_err(|error| InterfaceError::storage("could not list snapshots", error))?
        .into_iter()
        .filter(|snapshot| alias_from_snapshot_key(&snapshot.snapshot_key) == selector)
        .map(|snapshot| snapshot.snapshot_key)
        .collect::<Vec<_>>();
    matches.sort();
    match matches.as_slice() {
        [snapshot_key] => Ok(snapshot_key.clone()),
        [] => Err(InterfaceError::new(
            InterfaceErrorCode::SnapshotNotFound,
            InterfaceStage::SnapshotLookup,
            format!("snapshot '{selector}' was not found"),
            "run index first or pass an existing snapshot key",
            false,
        )),
        _ => Err(InterfaceError::new(
            InterfaceErrorCode::InvalidRequest,
            InterfaceStage::SnapshotLookup,
            format!(
                "snapshot alias '{selector}' is ambiguous; matching keys: {}",
                matches.join(", ")
            ),
            "pass one exact snapshot key",
            false,
        )),
    }
}

fn snapshot_summary(
    store: &GraphStore,
    snapshot_key: &str,
) -> Result<SnapshotSummary, InterfaceError> {
    let record = store
        .get_snapshot(snapshot_key)
        .map_err(|error| InterfaceError::storage("could not read snapshot", error))?
        .ok_or_else(|| {
            InterfaceError::new(
                InterfaceErrorCode::SnapshotNotFound,
                InterfaceStage::SnapshotLookup,
                format!("snapshot '{snapshot_key}' was not found"),
                "run index first or pass an existing snapshot key",
                false,
            )
        })?;
    let status = store
        .get_snapshot_contract_status(snapshot_key)
        .map_err(|error| InterfaceError::storage("could not verify snapshot authority", error))?
        .expect("snapshot existence was checked");
    let certified = store
        .get_certified_snapshot(snapshot_key)
        .map_err(|error| InterfaceError::storage("could not read certified snapshot", error))?;
    let connection_alias = certified
        .as_ref()
        .map(|snapshot| snapshot.snapshot.schema.connection_alias.clone())
        .unwrap_or_else(|| alias_from_snapshot_key(snapshot_key));
    Ok(SnapshotSummary {
        contract_version: status.contract_version,
        authority: status.authority,
        entrypoint_source: snapshot_key
            .split_once(':')
            .map(|(source, _)| source.to_owned())
            .unwrap_or_else(|| "legacy".to_owned()),
        snapshot_key: record.snapshot_key,
        source: record.source,
        alias: connection_alias.clone(),
        connection_alias,
        captured_at_unix_ms: record.captured_at_unix_ms,
        objects: store
            .node_count_for_snapshot(snapshot_key)
            .map_err(|error| InterfaceError::storage("could not count snapshot objects", error))?,
        relationships: store
            .edge_count_for_snapshot(snapshot_key)
            .map_err(|error| {
                InterfaceError::storage("could not count snapshot relationships", error)
            })?,
        adapter: certified
            .as_ref()
            .map(|snapshot| snapshot.completeness.adapter.name.clone()),
        server_product: certified
            .as_ref()
            .map(|snapshot| snapshot.completeness.server.product.clone()),
        server_version: certified
            .as_ref()
            .map(|snapshot| snapshot.completeness.server.version.clone()),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PageMetadata {
    pub total: u64,
    pub offset: usize,
    pub limit_requested: usize,
    pub limit_applied: usize,
    pub limit_clamped: bool,
    pub has_more: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectSummary {
    pub object_key: String,
    pub kind: ObjectKind,
    pub label: String,
    pub display_name: Option<String>,
    pub source_kind: String,
    pub connection_alias: String,
    pub database: String,
    pub schema: String,
    pub object_name: String,
    pub sub_object: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectPage {
    pub contract_version: u32,
    pub snapshot: SnapshotSummary,
    pub kind_filter: Option<ObjectKind>,
    pub query: Option<String>,
    pub objects: Vec<ObjectSummary>,
    pub page: PageMetadata,
}

pub fn list_objects(
    store: &GraphStore,
    snapshot_selector: &str,
    kind: Option<ObjectKind>,
    query: Option<&str>,
    offset: usize,
    limit: Option<usize>,
) -> Result<ObjectPage, InterfaceError> {
    let snapshot_key = resolve_snapshot_key(store, snapshot_selector)?;
    let limit_requested = limit.unwrap_or(DEFAULT_OBJECT_PAGE_LIMIT);
    if limit_requested == 0 {
        return Err(InterfaceError::new(
            InterfaceErrorCode::InvalidRequest,
            InterfaceStage::ObjectLookup,
            "object page limit must be greater than zero",
            "provide a limit between 1 and 500",
            false,
        ));
    }
    let limit_applied = limit_requested.min(MAX_OBJECT_PAGE_LIMIT);
    let label = kind.map(object_kind_label);
    let (total, nodes) = store
        .find_nodes_page(&snapshot_key, label, query, offset, limit_applied)
        .map_err(|error| InterfaceError::storage("could not list graph objects", error))?;
    let objects = nodes
        .iter()
        .map(object_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = (offset as u64).saturating_add(limit_applied as u64) < total;
    Ok(ObjectPage {
        contract_version: INTERFACE_CONTRACT_VERSION,
        snapshot: snapshot_summary(store, &snapshot_key)?,
        kind_filter: kind,
        query: query
            .map(str::trim)
            .filter(|query| !query.is_empty())
            .map(str::to_owned),
        objects,
        page: PageMetadata {
            total,
            offset,
            limit_requested,
            limit_applied,
            limit_clamped: limit_requested != limit_applied,
            has_more,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationshipSummary {
    pub edge_key: String,
    pub edge_type: String,
    pub direction: RelationshipDirection,
    pub from_object_key: String,
    pub to_object_key: String,
    pub related_object: ObjectSummary,
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationshipPageMetadata {
    pub limit_requested: usize,
    pub limit_applied: usize,
    pub limit_clamped: bool,
    pub incoming_truncated: bool,
    pub outgoing_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectDetail {
    pub contract_version: u32,
    pub snapshot: SnapshotSummary,
    pub object: ObjectSummary,
    pub payload: Value,
    pub incoming: Vec<RelationshipSummary>,
    pub outgoing: Vec<RelationshipSummary>,
    pub relationship_page: RelationshipPageMetadata,
}

pub fn describe_object(
    store: &GraphStore,
    snapshot_selector: &str,
    object_key: &str,
    relationship_limit: Option<usize>,
) -> Result<ObjectDetail, InterfaceError> {
    let snapshot_key = resolve_snapshot_key(store, snapshot_selector)?;
    let node = store
        .get_node(&snapshot_key, object_key)
        .map_err(|error| InterfaceError::storage("could not read graph object", error))?
        .ok_or_else(|| {
            InterfaceError::new(
                InterfaceErrorCode::ObjectNotFound,
                InterfaceStage::ObjectLookup,
                format!("object '{object_key}' was not found in snapshot '{snapshot_key}'"),
                "use list_objects or find_objects to obtain a stable object key",
                false,
            )
        })?;
    let limit_requested = relationship_limit.unwrap_or(DEFAULT_RELATIONSHIP_LIMIT);
    if limit_requested == 0 {
        return Err(InterfaceError::new(
            InterfaceErrorCode::InvalidRequest,
            InterfaceStage::ObjectLookup,
            "relationship limit must be greater than zero",
            "provide a limit between 1 and 200",
            false,
        ));
    }
    let limit_applied = limit_requested.min(MAX_RELATIONSHIP_LIMIT);
    let probe_limit = limit_applied.saturating_add(1);
    let mut incoming_edges = store
        .edges_to_limited(&snapshot_key, object_key, probe_limit)
        .map_err(|error| InterfaceError::storage("could not read incoming relationships", error))?;
    let mut outgoing_edges = store
        .edges_from_limited(&snapshot_key, object_key, probe_limit)
        .map_err(|error| InterfaceError::storage("could not read outgoing relationships", error))?;
    let incoming_truncated = incoming_edges.len() > limit_applied;
    let outgoing_truncated = outgoing_edges.len() > limit_applied;
    incoming_edges.truncate(limit_applied);
    outgoing_edges.truncate(limit_applied);
    let incoming = incoming_edges
        .iter()
        .map(|edge| {
            relationship_summary(store, &snapshot_key, edge, RelationshipDirection::Incoming)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outgoing = outgoing_edges
        .iter()
        .map(|edge| {
            relationship_summary(store, &snapshot_key, edge, RelationshipDirection::Outgoing)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let payload = serde_json::from_str(&node.payload_json).map_err(|error| {
        InterfaceError::new(
            InterfaceErrorCode::InvalidMetadata,
            InterfaceStage::Serialization,
            format!("object '{object_key}' has invalid JSON metadata: {error}"),
            "re-index this source with a compatible database-memory release",
            false,
        )
    })?;
    Ok(ObjectDetail {
        contract_version: INTERFACE_CONTRACT_VERSION,
        snapshot: snapshot_summary(store, &snapshot_key)?,
        object: object_summary(&node)?,
        payload,
        incoming,
        outgoing,
        relationship_page: RelationshipPageMetadata {
            limit_requested,
            limit_applied,
            limit_clamped: limit_requested != limit_applied,
            incoming_truncated,
            outgoing_truncated,
        },
    })
}

fn relationship_summary(
    store: &GraphStore,
    snapshot_key: &str,
    edge: &GraphEdgeRecord,
    direction: RelationshipDirection,
) -> Result<RelationshipSummary, InterfaceError> {
    let related_key = match direction {
        RelationshipDirection::Incoming => &edge.edge_from,
        RelationshipDirection::Outgoing => &edge.edge_to,
    };
    let related = store
        .get_node(snapshot_key, related_key)
        .map_err(|error| InterfaceError::storage("could not read related graph object", error))?
        .ok_or_else(|| {
            InterfaceError::new(
                InterfaceErrorCode::InvalidMetadata,
                InterfaceStage::ObjectLookup,
                format!("relationship '{}' has a missing endpoint", edge.edge_key),
                "re-index this source to rebuild graph integrity",
                false,
            )
        })?;
    let payload = serde_json::from_str(&edge.payload_json).map_err(|error| {
        InterfaceError::new(
            InterfaceErrorCode::InvalidMetadata,
            InterfaceStage::Serialization,
            format!(
                "relationship '{}' has invalid JSON metadata: {error}",
                edge.edge_key
            ),
            "re-index this source with a compatible database-memory release",
            false,
        )
    })?;
    Ok(RelationshipSummary {
        edge_key: edge.edge_key.clone(),
        edge_type: edge.edge_type.clone(),
        direction,
        from_object_key: edge.edge_from.clone(),
        to_object_key: edge.edge_to.clone(),
        related_object: object_summary(&related)?,
        payload,
    })
}

fn object_summary(node: &GraphNodeRecord) -> Result<ObjectSummary, InterfaceError> {
    let key = node.node_key.parse::<ObjectKey>().map_err(|error| {
        InterfaceError::new(
            InterfaceErrorCode::InvalidMetadata,
            InterfaceStage::Serialization,
            format!(
                "graph object '{}' has an invalid stable key: {error}",
                node.node_key
            ),
            "re-index this source with a compatible database-memory release",
            false,
        )
    })?;
    let expected_label = object_kind_label(key.object_kind);
    if node.label != expected_label {
        return Err(InterfaceError::new(
            InterfaceErrorCode::InvalidMetadata,
            InterfaceStage::Serialization,
            format!(
                "graph object '{}' label '{}' does not match kind '{}'",
                node.node_key, node.label, key.object_kind
            ),
            "re-index this source to restore the canonical graph",
            false,
        ));
    }
    Ok(ObjectSummary {
        object_key: node.node_key.clone(),
        kind: key.object_kind,
        label: node.label.clone(),
        display_name: node.display_name.clone(),
        source_kind: key.source_kind,
        connection_alias: key.connection_alias,
        database: key.database,
        schema: key.schema,
        object_name: key.object_name,
        sub_object: key.sub_object,
    })
}

pub const fn object_kind_label(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Database => "Database",
        ObjectKind::Schema => "Schema",
        ObjectKind::Table => "Table",
        ObjectKind::Column => "Column",
        ObjectKind::PrimaryKey => "PrimaryKey",
        ObjectKind::ForeignKey => "ForeignKey",
        ObjectKind::UniqueConstraint => "UniqueConstraint",
        ObjectKind::CheckConstraint => "CheckConstraint",
        ObjectKind::Index => "Index",
        ObjectKind::View => "View",
        ObjectKind::ViewColumn => "ViewColumn",
        ObjectKind::Trigger => "Trigger",
        ObjectKind::Routine => "Routine",
        ObjectKind::MaterializedView => "MaterializedView",
        ObjectKind::Sequence => "Sequence",
        ObjectKind::RoutineParameter => "RoutineParameter",
        ObjectKind::UserDefinedType => "UserDefinedType",
        ObjectKind::Domain => "Domain",
        ObjectKind::EnumValue => "EnumValue",
        ObjectKind::Synonym => "Synonym",
        ObjectKind::ExclusionConstraint => "ExclusionConstraint",
        ObjectKind::Event => "Event",
        ObjectKind::Package => "Package",
        ObjectKind::Principal => "Principal",
        ObjectKind::Policy => "Policy",
        ObjectKind::Extension => "Extension",
    }
}

fn alias_from_snapshot_key(snapshot_key: &str) -> String {
    snapshot_key
        .split_once(':')
        .map(|(_, alias)| alias.to_owned())
        .unwrap_or_else(|| snapshot_key.to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    Certified,
    CapabilityNegotiated,
    DeferredByOwner,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupportLedgerEntry {
    pub source: String,
    pub entrypoint_available: bool,
    pub status: SupportStatus,
    pub versions: Vec<String>,
    pub scope: String,
    pub runtime_requirement: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractLimits {
    pub max_timeout_ms: u64,
    pub default_object_page_limit: usize,
    pub max_object_page_limit: usize,
    pub default_relationship_limit: usize,
    pub max_relationship_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProductContract {
    pub product: String,
    pub version: String,
    pub contract_version: u32,
    pub complete_snapshot_contract_version: u32,
    pub metadata_only: bool,
    pub row_data_access: bool,
    pub authoritative_outcomes: Vec<String>,
    pub legacy_cache_policy: String,
    pub operations: Vec<String>,
    pub commands: Vec<String>,
    pub object_kinds: Vec<String>,
    pub traversal_limits: LegacyTraversalLimits,
    pub inventory_limits: LegacyInventoryLimits,
    pub limits: ContractLimits,
    pub support: Vec<SupportLedgerEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyTraversalLimits {
    pub max_depth: u32,
    pub max_results: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyInventoryLimits {
    pub default_tables: usize,
    pub max_tables: usize,
    pub offset_pagination: bool,
}

pub fn product_contract() -> ProductContract {
    ProductContract {
        product: "database-memory".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        contract_version: INTERFACE_CONTRACT_VERSION,
        complete_snapshot_contract_version: COMPLETE_CONTRACT_VERSION,
        metadata_only: true,
        row_data_access: false,
        authoritative_outcomes: vec!["complete".to_owned(), "failed".to_owned()],
        legacy_cache_policy: "readable but explicitly legacy_non_authoritative; re-index before relying on completeness".to_owned(),
        operations: vec![
            "contract".to_owned(),
            "index".to_owned(),
            "list_snapshots".to_owned(),
            "describe_snapshot".to_owned(),
            "list_objects".to_owned(),
            "find_objects".to_owned(),
            "describe_object".to_owned(),
            "trace_relationships".to_owned(),
            "impact_analysis".to_owned(),
            "schema_diff".to_owned(),
        ],
        commands: vec![
            "contract".to_owned(),
            "index".to_owned(),
            "list-snapshots".to_owned(),
            "describe-snapshot".to_owned(),
            "list-objects".to_owned(),
            "find-objects".to_owned(),
            "describe-object".to_owned(),
            "describe-table".to_owned(),
            "inventory".to_owned(),
            "find-table".to_owned(),
            "find-column".to_owned(),
            "impact-analysis".to_owned(),
            "trace-relationships".to_owned(),
        ],
        object_kinds: ALL_OBJECT_KINDS
            .iter()
            .map(ToString::to_string)
            .collect(),
        traversal_limits: LegacyTraversalLimits {
            max_depth: 8,
            max_results: 200,
        },
        inventory_limits: LegacyInventoryLimits {
            default_tables: 1_000,
            max_tables: 5_000,
            offset_pagination: true,
        },
        limits: ContractLimits {
            max_timeout_ms: MAX_TIMEOUT_MS,
            default_object_page_limit: DEFAULT_OBJECT_PAGE_LIMIT,
            max_object_page_limit: MAX_OBJECT_PAGE_LIMIT,
            default_relationship_limit: DEFAULT_RELATIONSHIP_LIMIT,
            max_relationship_limit: MAX_RELATIONSHIP_LIMIT,
        },
        support: support_ledger(),
    }
}

fn support_ledger() -> Vec<SupportLedgerEntry> {
    vec![
        support(
            "sqlite",
            true,
            SupportStatus::Certified,
            &["bundled SQLite runtime"],
            "main catalog and main schema",
            None,
        ),
        support(
            "ddl-sqlite",
            true,
            SupportStatus::Certified,
            &["SQLite-compatible DDL applied to an isolated in-memory catalog"],
            "main catalog and main schema",
            None,
        ),
        support(
            "postgres",
            true,
            SupportStatus::Certified,
            &["14", "15", "16", "17", "18"],
            "one connected database and selected schemas",
            None,
        ),
        support(
            "yugabytedb",
            true,
            SupportStatus::Certified,
            &["YSQL 15.12-YB-2025.2.3.2-b0"],
            "one connected database and selected schemas; YCQL excluded",
            None,
        ),
        support(
            "mysql",
            true,
            SupportStatus::Certified,
            &["8.0", "8.4", "9.7"],
            "one selected database",
            None,
        ),
        support(
            "mariadb",
            true,
            SupportStatus::Certified,
            &["10.11", "11.4", "11.8", "12.3"],
            "one selected database",
            None,
        ),
        support(
            "sqlserver",
            true,
            SupportStatus::Certified,
            &["2017", "2019", "2022", "2025"],
            "one connected database and selected schemas; Azure variants excluded",
            None,
        ),
        support(
            "oracle",
            true,
            SupportStatus::Certified,
            &["Oracle AI Database 26ai Free 23.26.2.0.0"],
            "one connected PDB/non-CDB and selected owner schemas",
            Some("Oracle Client 11.2 or later"),
        ),
        support(
            "odbc",
            cfg!(feature = "odbc"),
            SupportStatus::CapabilityNegotiated,
            &["SQL Server bridge for native-certified versions; all other products fail closed"],
            "driver-negotiated exact catalog and schema scope",
            Some("matching 64-bit ODBC driver and build feature 'odbc'"),
        ),
        support(
            "db2",
            false,
            SupportStatus::DeferredByOwner,
            &[],
            "not certified",
            Some("separate IBM license/EULA decision required before implementation"),
        ),
    ]
}

fn support(
    source: &str,
    entrypoint_available: bool,
    status: SupportStatus,
    versions: &[&str],
    scope: &str,
    runtime_requirement: Option<&str>,
) -> SupportLedgerEntry {
    SupportLedgerEntry {
        source: source.to_owned(),
        entrypoint_available,
        status,
        versions: versions
            .iter()
            .map(|version| (*version).to_owned())
            .collect(),
        scope: scope.to_owned(),
        runtime_requirement: runtime_requirement.map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::graph_builder::insert_schema_snapshot_graph;

    #[test]
    fn contract_reports_exact_boundaries_and_deferred_db2() {
        let contract = product_contract();

        assert_eq!(contract.contract_version, INTERFACE_CONTRACT_VERSION);
        assert!(contract.metadata_only);
        assert!(!contract.row_data_access);
        assert_eq!(contract.authoritative_outcomes, vec!["complete", "failed"]);
        assert_eq!(contract.object_kinds.len(), ALL_OBJECT_KINDS.len());
        assert_eq!(
            contract
                .support
                .iter()
                .find(|entry| entry.source == "odbc")
                .unwrap()
                .entrypoint_available,
            cfg!(feature = "odbc")
        );
        assert!(contract.support.iter().any(|entry| {
            entry.source == "db2"
                && entry.status == SupportStatus::DeferredByOwner
                && !entry.entrypoint_available
        }));
    }

    #[test]
    fn complete_index_exposes_all_object_kinds_and_preserves_failed_generation() {
        let path = temporary_path("complete-interface", "sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE);\n\
                 CREATE INDEX idx_accounts_email ON accounts(email);",
            )
            .unwrap();
        drop(connection);

        let store = GraphStore::in_memory().unwrap();
        let request = CompleteIndexRequest::new("sqlite", Some(path.clone()), None, "sample");
        let indexed = index_complete_source(&store, &request, 10, "memory").unwrap();
        assert_eq!(indexed.status, CompletionStatus::Complete);
        assert_eq!(indexed.contract_version, INTERFACE_CONTRACT_VERSION);
        assert!(indexed.objects_indexed >= 5);

        let columns = list_objects(
            &store,
            "sample",
            Some(ObjectKind::Column),
            Some("email"),
            0,
            Some(10),
        )
        .unwrap();
        assert_eq!(columns.objects.len(), 1);
        let detail =
            describe_object(&store, "sample", &columns.objects[0].object_key, Some(1)).unwrap();
        assert_eq!(detail.object.kind, ObjectKind::Column);
        assert!(!detail.incoming.is_empty());

        let before = store.get_snapshot("sqlite:sample").unwrap().unwrap();
        fs::remove_file(&path).unwrap();
        let error = index_complete_source(&store, &request, 20, "memory").unwrap_err();
        assert_eq!(error.code, InterfaceErrorCode::AnalysisFailed);
        assert_eq!(
            store.get_snapshot("sqlite:sample").unwrap().unwrap(),
            before
        );
    }

    #[test]
    fn legacy_snapshot_remains_readable_and_is_never_reported_complete() {
        let path = temporary_path("legacy-interface", "sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE users (id INTEGER);")
            .unwrap();
        drop(connection);
        let schema = adapters::sqlite::introspect_sqlite(&path, "legacy").unwrap();
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, "sqlite:legacy", 1, &schema).unwrap();

        let detail = describe_snapshot(&store, "legacy").unwrap();
        assert_eq!(
            detail.snapshot.authority,
            SnapshotAuthority::LegacyNonAuthoritative
        );
        assert_eq!(detail.snapshot.contract_version, None);
        assert!(detail.completeness.is_none());
        assert!(!list_objects(&store, "legacy", None, None, 0, Some(10))
            .unwrap()
            .objects
            .is_empty());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn object_pagination_is_bounded_before_materialization() {
        let path = temporary_path("page-interface", "sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE a (id INTEGER); CREATE TABLE b (id INTEGER);")
            .unwrap();
        drop(connection);
        let store = GraphStore::in_memory().unwrap();
        let request = CompleteIndexRequest::new("sqlite", Some(path.clone()), None, "page");
        index_complete_source(&store, &request, 1, "memory").unwrap();

        let page = list_objects(
            &store,
            "page",
            Some(ObjectKind::Table),
            None,
            0,
            Some(MAX_OBJECT_PAGE_LIMIT + 100),
        )
        .unwrap();
        assert_eq!(page.page.total, 2);
        assert_eq!(page.page.limit_applied, MAX_OBJECT_PAGE_LIMIT);
        assert!(page.page.limit_clamped);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn interface_rejects_secret_shaped_aliases_without_echoing_credentials() {
        let request = CompleteIndexRequest::new(
            "sqlite",
            None,
            None,
            "postgres://app:do-not-echo@localhost/database",
        );

        let outcome = analyze_complete_source(&request);
        let failure = outcome.failure().unwrap();
        let serialized = serde_json::to_string(&outcome).unwrap();

        assert_eq!(failure.code, AnalysisFailureCode::InvalidConfiguration);
        assert!(!failure.connection_alias.contains("do-not-echo"));
        assert!(!serialized.contains("do-not-echo"));
    }

    fn temporary_path(label: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("database-memory-{label}-{nonce}.{extension}"))
    }
}
