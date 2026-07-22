use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::time::Duration;

use postgres::config::{Host, SslMode};
use postgres::error::SqlState;
use postgres::{Config, GenericClient, IsolationLevel};
use postgres_native_tls::MakeTlsConnector;

use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::canonical::{
    CanonicalMetadata, CanonicalSchemaSnapshot, MetadataObject, MetadataRelationship,
    MetadataRelationshipKind, MetadataValue, ObjectAnnotation,
};
use crate::certification::{
    emitted_object_counts, emitted_relationship_counts, AdapterIdentity, CapabilityCheck,
    DiscoveredCount, DiscoveryCounts, IntrospectionScope, ObjectCategory, RelationshipCategory,
    ServerIdentity,
};
use crate::introspection::{
    CancellationToken, CatalogDiscovery, CatalogIntrospector, DatabaseAnalysisService,
    IntrospectionRequest,
};
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, RoutineKind, RoutineObject, SchemaObject,
    SchemaSnapshot, TableKind, TableObject, TriggerObject, ViewObject,
};

const POSTGRES_SOURCE: &str = "postgres";
const MIN_SUPPORTED_MAJOR: i32 = 14;
const MAX_SUPPORTED_MAJOR: i32 = 18;
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_DEFINITION_BYTES: i32 = 1_048_576;
const MAX_PROPERTY_STRING_BYTES: i32 = 65_536;

pub(crate) struct PostgresCatalogAdapter {
    connection_string: String,
}

impl PostgresCatalogAdapter {
    pub(crate) fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
        }
    }
}

impl CatalogIntrospector for PostgresCatalogAdapter {
    fn source_kind(&self) -> &'static str {
        POSTGRES_SOURCE
    }

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        discover_postgres(&self.connection_string, request, &CancellationToken::new())
    }

    fn discover_with_cancellation(
        &mut self,
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        discover_postgres(&self.connection_string, request, cancellation)
    }
}

fn discover_postgres(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    cancellation.checkpoint(
        POSTGRES_SOURCE,
        &request.connection_alias,
        AnalysisStage::Configuration,
    )?;
    validate_request(request)?;
    let mut config = Config::from_str(connection_string)
        .map_err(|error| connection_failure(request, connection_string, error.to_string()))?;
    validate_transport_policy(request, connection_string, &config)?;
    config.connect_timeout(Duration::from_millis(request.timeout_ms));
    let tls = native_tls::TlsConnector::builder()
        .build()
        .map_err(|error| connection_failure(request, connection_string, error.to_string()))?;
    let mut client = config
        .connect(MakeTlsConnector::new(tls))
        .map_err(|error| {
            classify_postgres_error(request, connection_string, error, AnalysisStage::Connection)
        })?;
    cancellation.checkpoint(
        POSTGRES_SOURCE,
        &request.connection_alias,
        AnalysisStage::Connection,
    )?;
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(|error| {
            classify_postgres_error(
                request,
                connection_string,
                error,
                AnalysisStage::CapabilityProbe,
            )
        })?;
    let timeout = format!("{}ms", request.timeout_ms);
    transaction
        .query_one(
            "SELECT set_config('statement_timeout', $1, true)",
            &[&timeout],
        )
        .map_err(|error| {
            classify_postgres_error(
                request,
                connection_string,
                error,
                AnalysisStage::CapabilityProbe,
            )
        })?;
    transaction
        .query_one("SELECT set_config('lock_timeout', $1, true)", &[&timeout])
        .map_err(|error| {
            classify_postgres_error(
                request,
                connection_string,
                error,
                AnalysisStage::CapabilityProbe,
            )
        })?;
    cancellation.checkpoint(
        POSTGRES_SOURCE,
        &request.connection_alias,
        AnalysisStage::CapabilityProbe,
    )?;

    let raw = RawPostgresCatalog::read(&mut transaction, request)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    cancellation.checkpoint(
        POSTGRES_SOURCE,
        &request.connection_alias,
        AnalysisStage::Discovery,
    )?;
    let discovery = PostgresSnapshotMapper::new(&request.connection_alias)
        .map(raw)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    cancellation.checkpoint(
        POSTGRES_SOURCE,
        &request.connection_alias,
        AnalysisStage::Mapping,
    )?;
    transaction.commit().map_err(|error| {
        classify_postgres_error(request, connection_string, error, AnalysisStage::Discovery)
    })?;
    Ok(discovery)
}

pub(crate) fn analyze_postgres(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_postgres_with_cancellation(
        connection_string,
        connection_alias,
        requested_schemas,
        timeout_ms,
        &CancellationToken::new(),
    )
}

pub(crate) fn analyze_postgres_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs: Vec::new(),
        requested_schemas,
        timeout_ms,
    };
    DatabaseAnalysisService::new(PostgresCatalogAdapter::new(connection_string))
        .analyze_with_cancellation(&request, cancellation)
}

#[derive(Debug)]
enum CatalogError {
    Query(postgres::Error),
    InvalidScope(String),
    PermissionDenied(String),
    UnsupportedVersion(i32),
    UnsupportedMetadata(String),
    Mapping(String),
}

impl From<postgres::Error> for CatalogError {
    fn from(error: postgres::Error) -> Self {
        Self::Query(error)
    }
}

fn validate_request(request: &IntrospectionRequest) -> Result<(), AnalysisFailure> {
    if request.timeout_ms > MAX_INTROSPECTION_TIMEOUT_MS {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            POSTGRES_SOURCE,
            &request.connection_alias,
            format!(
                "PostgreSQL introspection timeout exceeds the {MAX_INTROSPECTION_TIMEOUT_MS} ms safety limit"
            ),
            "choose a timeout between 1 ms and 86400000 ms",
            false,
            None,
        ));
    }
    let has_duplicate_catalogs = request.requested_catalogs.len()
        != request
            .requested_catalogs
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
    let has_duplicate_schemas = request.requested_schemas.len()
        != request
            .requested_schemas
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
    if has_duplicate_catalogs || has_duplicate_schemas {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            POSTGRES_SOURCE,
            &request.connection_alias,
            "PostgreSQL scope contains duplicate catalog or schema names",
            "provide each requested catalog and schema exactly once",
            false,
            None,
        ));
    }
    Ok(())
}

fn validate_transport_policy(
    request: &IntrospectionRequest,
    connection_string: &str,
    config: &Config,
) -> Result<(), AnalysisFailure> {
    let has_remote_tcp_host = config.get_hosts().iter().any(|host| match host {
        Host::Tcp(host) => !is_loopback_host(host),
        #[cfg(unix)]
        Host::Unix(_) => false,
    });
    if has_remote_tcp_host && config.get_ssl_mode() != SslMode::Require {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Configuration,
            POSTGRES_SOURCE,
            &request.connection_alias,
            "remote PostgreSQL connections require sslmode=require to prevent plaintext fallback",
            "set sslmode=require and use a certificate trusted by the operating system",
            false,
            Some(connection_string),
        ));
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn connection_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    message: String,
) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::ConnectionFailed,
        AnalysisStage::Connection,
        POSTGRES_SOURCE,
        &request.connection_alias,
        message,
        "verify the PostgreSQL connection settings, network path, and TLS policy",
        true,
        Some(connection_string),
    )
}

fn classify_postgres_error(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: postgres::Error,
    stage: AnalysisStage,
) -> AnalysisFailure {
    let message = postgres_error_message(&error);
    let (code, retryable, remediation) = match error.code() {
        Some(code) if code == &SqlState::INVALID_PASSWORD => (
            AnalysisFailureCode::AuthenticationFailed,
            false,
            "verify the PostgreSQL principal and secret",
        ),
        Some(code) if code == &SqlState::INSUFFICIENT_PRIVILEGE => (
            AnalysisFailureCode::PermissionDenied,
            false,
            "grant metadata visibility for every requested schema and retry",
        ),
        Some(code) if code == &SqlState::QUERY_CANCELED => (
            AnalysisFailureCode::Timeout,
            true,
            "increase the bounded timeout or reduce the requested schema scope",
        ),
        _ if stage == AnalysisStage::Connection => (
            AnalysisFailureCode::ConnectionFailed,
            true,
            "verify the PostgreSQL endpoint and retry",
        ),
        _ => (
            AnalysisFailureCode::MetadataQueryFailed,
            true,
            "inspect the PostgreSQL server state and retry the metadata-only analysis",
        ),
    };
    AnalysisFailure::redacted(
        code,
        stage,
        POSTGRES_SOURCE,
        &request.connection_alias,
        message,
        remediation,
        retryable,
        Some(connection_string),
    )
}

fn postgres_error_message(error: &postgres::Error) -> String {
    match error.as_db_error() {
        Some(database_error) => {
            let mut message = format!(
                "{} (SQLSTATE {})",
                database_error.message(),
                database_error.code().code()
            );
            if let Some(detail) = database_error.detail() {
                message.push_str(": ");
                message.push_str(detail);
            }
            if let Some(hint) = database_error.hint() {
                message.push_str("; hint: ");
                message.push_str(hint);
            }
            message
        }
        None => error.to_string(),
    }
}

fn catalog_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: CatalogError,
) -> AnalysisFailure {
    match error {
        CatalogError::Query(error) => classify_postgres_error(
            request,
            connection_string,
            error,
            AnalysisStage::Discovery,
        ),
        CatalogError::InvalidScope(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::CapabilityProbe,
            POSTGRES_SOURCE,
            &request.connection_alias,
            message,
            "request the current database and existing non-system schemas",
            false,
            Some(connection_string),
        ),
        CatalogError::PermissionDenied(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::PermissionDenied,
            AnalysisStage::CapabilityProbe,
            POSTGRES_SOURCE,
            &request.connection_alias,
            message,
            "grant metadata visibility for every requested schema and retry",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedVersion(major) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedVersion,
            AnalysisStage::CapabilityProbe,
            POSTGRES_SOURCE,
            &request.connection_alias,
            format!(
                "PostgreSQL major version {major} is outside the certified {MIN_SUPPORTED_MAJOR}-{MAX_SUPPORTED_MAJOR} range"
            ),
            "use a certified PostgreSQL version or add and verify a version strategy",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedMetadata(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedMetadata,
            AnalysisStage::CapabilityProbe,
            POSTGRES_SOURCE,
            &request.connection_alias,
            message,
            "remove the unprovable construct or use a catalog-tracked definition, then re-index",
            false,
            Some(connection_string),
        ),
        CatalogError::Mapping(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::MetadataMappingFailed,
            AnalysisStage::Mapping,
            POSTGRES_SOURCE,
            &request.connection_alias,
            message,
            "fix the adapter mapping for every discovered PostgreSQL object before retrying",
            false,
            Some(connection_string),
        ),
    }
}

#[derive(Clone, Debug)]
struct ServerFacts {
    database: String,
    version: String,
    version_num: i32,
    current_user: String,
    session_user: String,
    transaction_read_only: bool,
    transaction_isolation: String,
    tls: bool,
    tls_version: Option<String>,
    tls_cipher: Option<String>,
}

impl ServerFacts {
    fn major(&self) -> i32 {
        self.version_num / 10_000
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostgresCatalogVersion {
    V14,
    V15,
    V16,
    V17,
    V18,
}

impl PostgresCatalogVersion {
    fn detect(version_num: i32) -> Result<Self, CatalogError> {
        let major = version_num / 10_000;
        match major {
            14 => Ok(Self::V14),
            15 => Ok(Self::V15),
            16 => Ok(Self::V16),
            17 => Ok(Self::V17),
            18 => Ok(Self::V18),
            _ => Err(CatalogError::UnsupportedVersion(major)),
        }
    }

    fn major(self) -> i32 {
        match self {
            Self::V14 => 14,
            Self::V15 => 15,
            Self::V16 => 16,
            Self::V17 => 17,
            Self::V18 => 18,
        }
    }

    fn strategy_name(self) -> &'static str {
        match self {
            Self::V14 => "postgresql-14",
            Self::V15 => "postgresql-15",
            Self::V16 => "postgresql-16",
            Self::V17 => "postgresql-17",
            Self::V18 => "postgresql-18",
        }
    }

    fn statistics_target(
        self,
        raw_value: Option<i32>,
    ) -> Result<PostgresStatisticsTarget, CatalogError> {
        match (self, raw_value) {
            (Self::V14 | Self::V15 | Self::V16, Some(-1))
            | (Self::V17 | Self::V18, None) => Ok(PostgresStatisticsTarget::Default),
            (_, Some(0)) => Ok(PostgresStatisticsTarget::Disabled),
            (_, Some(value @ 1..)) => Ok(PostgresStatisticsTarget::Custom(value)),
            (Self::V14 | Self::V15 | Self::V16, None) => {
                Err(CatalogError::UnsupportedMetadata(format!(
                    "{} returned NULL pg_attribute.attstattarget; expected -1 for the default target",
                    self.strategy_name()
                )))
            }
            (Self::V17 | Self::V18, Some(-1)) => {
                Err(CatalogError::UnsupportedMetadata(format!(
                    "{} returned legacy -1 pg_attribute.attstattarget; expected NULL for the default target",
                    self.strategy_name()
                )))
            }
            (_, Some(value)) => Err(CatalogError::UnsupportedMetadata(format!(
                "{} returned unsupported pg_attribute.attstattarget value {value}",
                self.strategy_name()
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostgresStatisticsTarget {
    Default,
    Disabled,
    Custom(i32),
}

#[derive(Clone, Debug)]
struct RawSchema {
    oid: i64,
    name: String,
    owner_oid: i64,
    has_usage: bool,
    comment: Option<String>,
}

#[derive(Clone, Debug)]
struct RawPrincipal {
    oid: i64,
    name: String,
    superuser: bool,
    inherit: bool,
    create_role: bool,
    create_database: bool,
    can_login: bool,
    replication: bool,
    bypass_rls: bool,
    valid_until: Option<String>,
}

#[derive(Clone, Debug)]
struct RawRelation {
    oid: i64,
    row_type_oid: i64,
    schema: String,
    name: String,
    relkind: char,
    persistence: char,
    owner_oid: i64,
    is_partition: bool,
    row_security: bool,
    force_row_security: bool,
    replica_identity: char,
    partition_bound: Option<String>,
    definition: Option<String>,
    definition_too_large: bool,
    comment: Option<String>,
}

#[derive(Clone, Debug)]
struct RawColumn {
    relation_oid: i64,
    relation_kind: char,
    schema: String,
    relation: String,
    attnum: i16,
    name: String,
    type_oid: i64,
    type_schema: String,
    data_type: String,
    nullable: bool,
    default_oid: Option<i64>,
    default_expression: Option<String>,
    default_too_large: bool,
    generated: char,
    identity: char,
    collation: Option<String>,
    compression: Option<String>,
    statistics_target: PostgresStatisticsTarget,
    comment: Option<String>,
}

#[derive(Clone, Debug)]
struct RawConstraint {
    oid: i64,
    schema: String,
    relation_oid: Option<i64>,
    domain_type_oid: Option<i64>,
    name: String,
    kind: char,
    columns: Vec<i16>,
    referenced_relation_oid: Option<i64>,
    referenced_columns: Vec<i16>,
    definition: Option<String>,
    definition_too_large: bool,
    deferrable: bool,
    initially_deferred: bool,
    validated: bool,
    no_inherit: bool,
    delete_action: char,
    update_action: char,
    match_type: char,
}

#[derive(Clone, Debug)]
struct RawIndex {
    oid: i64,
    relation_oid: i64,
    schema: String,
    relation: String,
    name: String,
    access_method: String,
    unique: bool,
    primary: bool,
    exclusion: bool,
    immediate: bool,
    clustered: bool,
    valid: bool,
    ready: bool,
    live: bool,
    replica_identity: bool,
    nulls_not_distinct: bool,
    key_count: i16,
    predicate: Option<String>,
    expression: Option<String>,
    definition: Option<String>,
    definition_too_large: bool,
}

#[derive(Clone, Debug)]
struct RawIndexTerm {
    index_oid: i64,
    ordinal: i16,
    column_number: i16,
    column_name: Option<String>,
    definition: String,
    is_key: bool,
    descending: bool,
    nulls_first: bool,
    operator_class: Option<String>,
    collation: Option<String>,
}

#[derive(Clone, Debug)]
struct RawType {
    oid: i64,
    schema: String,
    name: String,
    kind: char,
    owner_oid: i64,
    category: char,
    relation_oid: Option<i64>,
    base_type_oid: Option<i64>,
    base_type_schema: Option<String>,
    element_type_oid: Option<i64>,
    element_type_schema: Option<String>,
    not_null: bool,
    default_value: Option<String>,
    default_too_large: bool,
    collation: Option<String>,
    range_subtype_oid: Option<i64>,
    range_subtype_schema: Option<String>,
    multirange_type_oid: Option<i64>,
    multirange_type_schema: Option<String>,
    comment: Option<String>,
}

#[derive(Clone, Debug)]
struct RawEnumValue {
    type_oid: i64,
    label: String,
    sort_order: String,
}

#[derive(Clone, Debug)]
struct RawSequence {
    relation_oid: i64,
    type_oid: i64,
    start_value: i64,
    min_value: i64,
    max_value: i64,
    increment_by: i64,
    cycle: bool,
    cache_size: i64,
}

#[derive(Clone, Debug)]
struct RawRoutine {
    oid: i64,
    schema: String,
    name: String,
    identity_arguments: String,
    kind: char,
    owner_oid: i64,
    language: String,
    return_type_oid: i64,
    return_type_schema: String,
    return_type: Option<String>,
    returns_set: bool,
    security_definer: bool,
    leakproof: bool,
    strict: bool,
    volatility: char,
    parallel: char,
    definition: Option<String>,
    definition_too_large: bool,
    arguments_definition: String,
    body_catalog_tracked: bool,
}

#[derive(Clone, Debug)]
struct RawRoutineParameter {
    routine_oid: i64,
    ordinal: i32,
    name: Option<String>,
    mode: char,
    type_oid: i64,
    type_schema: String,
    data_type: String,
}

#[derive(Clone, Debug)]
struct RawTrigger {
    oid: i64,
    relation_oid: i64,
    routine_oid: i64,
    name: String,
    timing: String,
    events: Vec<String>,
    orientation: String,
    enabled: char,
    update_columns: Vec<i16>,
    when_expression: Option<String>,
    definition: Option<String>,
    definition_too_large: bool,
}

#[derive(Clone, Debug)]
struct RawInheritance {
    child_oid: i64,
    parent_oid: i64,
    sequence_number: i32,
    child_is_partition: bool,
}

#[derive(Clone, Debug)]
struct RawDependency {
    owner_oid: i64,
    target_class: String,
    target_oid: i64,
    target_sub_id: i32,
    target_schema: Option<String>,
    dependency_type: char,
}

#[derive(Clone, Debug)]
struct RawViewDependency {
    view_oid: i64,
    target_relation_oid: i64,
    target_column_number: i32,
    target_schema: String,
    dependency_type: char,
}

#[derive(Clone, Debug)]
struct RawSequenceUsage {
    column_relation_oid: i64,
    column_number: i32,
    sequence_oid: i64,
    dependency_type: char,
}

#[derive(Clone, Debug)]
struct RawPolicy {
    oid: i64,
    relation_oid: i64,
    name: String,
    command: char,
    permissive: bool,
    role_oids: Vec<i64>,
    using_expression: Option<String>,
    check_expression: Option<String>,
}

#[derive(Clone, Debug)]
struct RawExtension {
    oid: i64,
    name: String,
    owner_oid: i64,
    schema: Option<String>,
    relocatable: bool,
    version: String,
}

#[derive(Clone, Debug)]
struct RawEventTrigger {
    oid: i64,
    name: String,
    event: String,
    owner_oid: i64,
    routine_oid: i64,
    routine_schema: String,
    enabled: char,
    tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct RawPostgresCatalog {
    server: ServerFacts,
    catalog_version: PostgresCatalogVersion,
    schemas: Vec<RawSchema>,
    principals: Vec<RawPrincipal>,
    relations: Vec<RawRelation>,
    columns: Vec<RawColumn>,
    constraints: Vec<RawConstraint>,
    indexes: Vec<RawIndex>,
    index_terms: Vec<RawIndexTerm>,
    types: Vec<RawType>,
    enum_values: Vec<RawEnumValue>,
    sequences: Vec<RawSequence>,
    routines: Vec<RawRoutine>,
    routine_parameters: Vec<RawRoutineParameter>,
    triggers: Vec<RawTrigger>,
    inheritance: Vec<RawInheritance>,
    view_dependencies: Vec<RawViewDependency>,
    routine_dependencies: Vec<RawDependency>,
    sequence_usages: Vec<RawSequenceUsage>,
    policies: Vec<RawPolicy>,
    extensions: Vec<RawExtension>,
    event_triggers: Vec<RawEventTrigger>,
}

struct PostgresSnapshotMapper<'a> {
    connection_alias: &'a str,
}

impl RawPostgresCatalog {
    fn read(
        client: &mut impl GenericClient,
        request: &IntrospectionRequest,
    ) -> Result<Self, CatalogError> {
        let server = read_server_facts(client)?;
        let catalog_version = PostgresCatalogVersion::detect(server.version_num)?;
        if !request.requested_catalogs.is_empty()
            && request.requested_catalogs != [server.database.clone()]
        {
            return Err(CatalogError::InvalidScope(format!(
                "this PostgreSQL connection can certify only current database '{}', requested {:?}",
                server.database, request.requested_catalogs
            )));
        }

        let available_schemas = read_schemas(client)?;
        let requested = request
            .requested_schemas
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let available_names = available_schemas
            .iter()
            .map(|schema| schema.name.clone())
            .collect::<BTreeSet<_>>();
        let missing = requested
            .difference(&available_names)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(CatalogError::InvalidScope(format!(
                "requested PostgreSQL schemas do not exist or are system schemas: {}",
                missing.join(", ")
            )));
        }
        let schemas = if requested.is_empty() {
            available_schemas
        } else {
            available_schemas
                .into_iter()
                .filter(|schema| requested.contains(&schema.name))
                .collect()
        };
        if schemas.is_empty() {
            return Err(CatalogError::InvalidScope(
                "PostgreSQL scope contains no non-system schemas".to_owned(),
            ));
        }
        let inaccessible = schemas
            .iter()
            .filter(|schema| !schema.has_usage)
            .map(|schema| schema.name.clone())
            .collect::<Vec<_>>();
        if !inaccessible.is_empty() {
            return Err(CatalogError::PermissionDenied(format!(
                "current principal lacks USAGE on requested schema(s): {}",
                inaccessible.join(", ")
            )));
        }
        let schema_names = schemas
            .iter()
            .map(|schema| schema.name.clone())
            .collect::<Vec<_>>();

        reject_unsupported_relations(client, &schema_names)?;

        Ok(Self {
            server,
            catalog_version,
            schemas,
            principals: read_principals(client)?,
            relations: read_relations(client, &schema_names)?,
            columns: read_columns(client, &schema_names, catalog_version)?,
            constraints: read_constraints(client, &schema_names)?,
            indexes: read_indexes(client, &schema_names)?,
            index_terms: read_index_terms(client, &schema_names)?,
            types: read_types(client, &schema_names)?,
            enum_values: read_enum_values(client, &schema_names)?,
            sequences: read_sequences(client, &schema_names)?,
            routines: read_routines(client, &schema_names)?,
            routine_parameters: read_routine_parameters(client, &schema_names)?,
            triggers: read_triggers(client, &schema_names)?,
            inheritance: read_inheritance(client, &schema_names)?,
            view_dependencies: read_view_dependencies(client, &schema_names)?,
            routine_dependencies: read_routine_dependencies(client, &schema_names)?,
            sequence_usages: read_sequence_usages(client, &schema_names)?,
            policies: read_policies(client, &schema_names)?,
            extensions: read_extensions(client)?,
            event_triggers: read_event_triggers(client)?,
        })
    }
}

fn read_server_facts(client: &mut impl GenericClient) -> Result<ServerFacts, CatalogError> {
    let row = client.query_one(
        "
        SELECT current_database()::text,
               current_setting('server_version'),
               current_setting('server_version_num')::integer,
               current_user::text,
               session_user::text,
               current_setting('transaction_read_only') = 'on',
               current_setting('transaction_isolation'),
               COALESCE((SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()), false),
               (SELECT version FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()),
               (SELECT cipher FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid())
        ",
        &[],
    )?;
    Ok(ServerFacts {
        database: row.get(0),
        version: row.get(1),
        version_num: row.get(2),
        current_user: row.get(3),
        session_user: row.get(4),
        transaction_read_only: row.get(5),
        transaction_isolation: row.get(6),
        tls: row.get(7),
        tls_version: row.get(8),
        tls_cipher: row.get(9),
    })
}

fn read_schemas(client: &mut impl GenericClient) -> Result<Vec<RawSchema>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT ns.oid::bigint,
                   ns.nspname,
                   ns.nspowner::bigint,
                   pg_catalog.has_schema_privilege(ns.oid, 'USAGE'),
                   pg_catalog.obj_description(ns.oid, 'pg_namespace')
            FROM pg_catalog.pg_namespace ns
            WHERE ns.nspname <> 'information_schema'
              AND ns.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            ORDER BY ns.nspname
            ",
            &[],
        )?
        .into_iter()
        .map(|row| RawSchema {
            oid: row.get(0),
            name: row.get(1),
            owner_oid: row.get(2),
            has_usage: row.get(3),
            comment: row.get(4),
        })
        .collect())
}

fn read_principals(client: &mut impl GenericClient) -> Result<Vec<RawPrincipal>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT oid::bigint,
                   rolname,
                   rolsuper,
                   rolinherit,
                   rolcreaterole,
                   rolcreatedb,
                   rolcanlogin,
                   rolreplication,
                   rolbypassrls,
                   rolvaliduntil::text
            FROM pg_catalog.pg_roles
            ORDER BY rolname
            ",
            &[],
        )?
        .into_iter()
        .map(|row| RawPrincipal {
            oid: row.get(0),
            name: row.get(1),
            superuser: row.get(2),
            inherit: row.get(3),
            create_role: row.get(4),
            create_database: row.get(5),
            can_login: row.get(6),
            replication: row.get(7),
            bypass_rls: row.get(8),
            valid_until: row.get(9),
        })
        .collect())
}

fn reject_unsupported_relations(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<(), CatalogError> {
    let rows = client.query(
        "
        SELECT ns.nspname, cls.relname, cls.relkind::text
        FROM pg_catalog.pg_class cls
        JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace
        WHERE ns.nspname = ANY($1::text[])
          AND cls.relkind NOT IN ('r', 'p', 'f', 'v', 'm', 'S', 'c', 'i', 'I')
        ORDER BY ns.nspname, cls.relname
        ",
        &[&schemas],
    )?;
    if let Some(row) = rows.first() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "unsupported PostgreSQL relation kind '{}' discovered at {}.{}",
            row.get::<_, String>(2),
            row.get::<_, String>(0),
            row.get::<_, String>(1)
        )));
    }
    Ok(())
}

fn read_relations(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawRelation>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT cls.oid::bigint,
                   cls.reltype::bigint,
                   ns.nspname,
                   cls.relname,
                   cls.relkind::text,
                   cls.relpersistence::text,
                   cls.relowner::bigint,
                   cls.relispartition,
                   cls.relrowsecurity,
                   cls.relforcerowsecurity,
                   cls.relreplident::text,
                   CASE WHEN cls.relispartition
                        THEN pg_catalog.pg_get_expr(cls.relpartbound, cls.oid, true)
                        ELSE NULL END,
                   CASE WHEN cls.relkind IN ('v', 'm')
                             AND pg_catalog.octet_length(pg_catalog.pg_get_viewdef(cls.oid, true)) <= $2
                        THEN pg_catalog.pg_get_viewdef(cls.oid, true)
                        ELSE NULL END,
                   CASE WHEN cls.relkind IN ('v', 'm')
                        THEN pg_catalog.octet_length(pg_catalog.pg_get_viewdef(cls.oid, true)) > $2
                        ELSE false END,
                   pg_catalog.obj_description(cls.oid, 'pg_class')
            FROM pg_catalog.pg_class cls
            JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace
            WHERE ns.nspname = ANY($1::text[])
              AND cls.relkind IN ('r', 'p', 'f', 'v', 'm', 'S', 'c')
            ORDER BY ns.nspname, cls.relname, cls.oid
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| RawRelation {
            oid: row.get(0),
            row_type_oid: row.get(1),
            schema: row.get(2),
            name: row.get(3),
            relkind: one_char(&row.get::<_, String>(4)),
            persistence: one_char(&row.get::<_, String>(5)),
            owner_oid: row.get(6),
            is_partition: row.get(7),
            row_security: row.get(8),
            force_row_security: row.get(9),
            replica_identity: one_char(&row.get::<_, String>(10)),
            partition_bound: row.get(11),
            definition: row.get(12),
            definition_too_large: row.get(13),
            comment: row.get(14),
        })
        .collect())
}

fn read_columns(
    client: &mut impl GenericClient,
    schemas: &[String],
    catalog_version: PostgresCatalogVersion,
) -> Result<Vec<RawColumn>, CatalogError> {
    client
        .query(
            "
            SELECT cls.oid::bigint,
                   cls.relkind::text,
                   ns.nspname,
                   cls.relname,
                   att.attnum,
                   att.attname,
                   att.atttypid::bigint,
                   type_ns.nspname,
                   pg_catalog.format_type(att.atttypid, att.atttypmod),
                   NOT att.attnotnull,
                   def.oid::bigint,
                   CASE WHEN def.oid IS NOT NULL
                             AND pg_catalog.octet_length(pg_catalog.pg_get_expr(def.adbin, def.adrelid, true)) <= $2
                        THEN pg_catalog.pg_get_expr(def.adbin, def.adrelid, true)
                        ELSE NULL END,
                   CASE WHEN def.oid IS NOT NULL
                        THEN pg_catalog.octet_length(pg_catalog.pg_get_expr(def.adbin, def.adrelid, true)) > $2
                        ELSE false END,
                   att.attgenerated::text,
                   att.attidentity::text,
                   CASE WHEN att.attcollation = 0 THEN NULL
                        ELSE coll_ns.nspname || '.' || coll.collname END,
                   NULLIF(pg_catalog.to_jsonb(att)->>'attcompression', ''),
                   att.attstattarget::integer,
                   pg_catalog.col_description(att.attrelid, att.attnum)
            FROM pg_catalog.pg_attribute att
            JOIN pg_catalog.pg_class cls ON cls.oid = att.attrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace
            LEFT JOIN pg_catalog.pg_attrdef def
              ON def.adrelid = att.attrelid AND def.adnum = att.attnum
            JOIN pg_catalog.pg_type data_type ON data_type.oid = att.atttypid
            JOIN pg_catalog.pg_namespace type_ns ON type_ns.oid = data_type.typnamespace
            LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = att.attcollation
            LEFT JOIN pg_catalog.pg_namespace coll_ns ON coll_ns.oid = coll.collnamespace
            WHERE ns.nspname = ANY($1::text[])
              AND cls.relkind IN ('r', 'p', 'f', 'v', 'm', 'c')
              AND att.attnum > 0
              AND NOT att.attisdropped
            ORDER BY ns.nspname, cls.relname, att.attnum
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| {
            let raw_statistics_target = row.try_get(17)?;
            Ok(RawColumn {
                relation_oid: row.get(0),
                relation_kind: one_char(&row.get::<_, String>(1)),
                schema: row.get(2),
                relation: row.get(3),
                attnum: row.get(4),
                name: row.get(5),
                type_oid: row.get(6),
                type_schema: row.get(7),
                data_type: row.get(8),
                nullable: row.get(9),
                default_oid: row.get(10),
                default_expression: row.get(11),
                default_too_large: row.get(12),
                generated: one_char(&row.get::<_, String>(13)),
                identity: one_char(&row.get::<_, String>(14)),
                collation: row.get(15),
                compression: row.get(16),
                statistics_target: catalog_version.statistics_target(raw_statistics_target)?,
                comment: row.get(18),
            })
        })
        .collect()
}

fn one_char(value: &str) -> char {
    value.chars().next().unwrap_or('\0')
}

fn read_constraints(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawConstraint>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT con.oid::bigint,
                   ns.nspname,
                   NULLIF(con.conrelid, 0)::bigint,
                   NULLIF(con.contypid, 0)::bigint,
                   con.conname,
                   con.contype::text,
                   COALESCE(con.conkey, ARRAY[]::smallint[]),
                   NULLIF(con.confrelid, 0)::bigint,
                   COALESCE(con.confkey, ARRAY[]::smallint[]),
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_constraintdef(con.oid, true)) <= $2
                        THEN pg_catalog.pg_get_constraintdef(con.oid, true)
                        ELSE NULL END,
                   pg_catalog.octet_length(pg_catalog.pg_get_constraintdef(con.oid, true)) > $2,
                   con.condeferrable,
                   con.condeferred,
                   con.convalidated,
                   con.connoinherit,
                   con.confdeltype::text,
                   con.confupdtype::text,
                   con.confmatchtype::text
            FROM pg_catalog.pg_constraint con
            LEFT JOIN pg_catalog.pg_class rel ON rel.oid = con.conrelid
            LEFT JOIN pg_catalog.pg_type typ ON typ.oid = con.contypid
            JOIN pg_catalog.pg_namespace ns
              ON ns.oid = COALESCE(rel.relnamespace, typ.typnamespace)
            WHERE ns.nspname = ANY($1::text[])
              AND con.contype IN ('p', 'u', 'f', 'c', 'x')
            ORDER BY ns.nspname, COALESCE(rel.relname, typ.typname), con.conname, con.oid
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| RawConstraint {
            oid: row.get(0),
            schema: row.get(1),
            relation_oid: row.get(2),
            domain_type_oid: row.get(3),
            name: row.get(4),
            kind: one_char(&row.get::<_, String>(5)),
            columns: row.get(6),
            referenced_relation_oid: row.get(7),
            referenced_columns: row.get(8),
            definition: row.get(9),
            definition_too_large: row.get(10),
            deferrable: row.get(11),
            initially_deferred: row.get(12),
            validated: row.get(13),
            no_inherit: row.get(14),
            delete_action: one_char(&row.get::<_, String>(15)),
            update_action: one_char(&row.get::<_, String>(16)),
            match_type: one_char(&row.get::<_, String>(17)),
        })
        .collect())
}

fn read_indexes(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawIndex>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT idx_cls.oid::bigint,
                   tbl.oid::bigint,
                   ns.nspname,
                   tbl.relname,
                   idx_cls.relname,
                   am.amname,
                   idx.indisunique,
                   idx.indisprimary,
                   idx.indisexclusion,
                   idx.indimmediate,
                   idx.indisclustered,
                   idx.indisvalid,
                   idx.indisready,
                   idx.indislive,
                   idx.indisreplident,
                   COALESCE((pg_catalog.to_jsonb(idx)->>'indnullsnotdistinct')::boolean, false),
                   idx.indnkeyatts,
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_indexdef(idx.indexrelid)) <= $2
                        THEN pg_catalog.pg_get_expr(idx.indpred, idx.indrelid, true)
                        ELSE NULL END,
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_indexdef(idx.indexrelid)) <= $2
                        THEN pg_catalog.pg_get_expr(idx.indexprs, idx.indrelid, true)
                        ELSE NULL END,
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_indexdef(idx.indexrelid)) <= $2
                        THEN pg_catalog.pg_get_indexdef(idx.indexrelid)
                        ELSE NULL END,
                   pg_catalog.octet_length(pg_catalog.pg_get_indexdef(idx.indexrelid)) > $2
            FROM pg_catalog.pg_index idx
            JOIN pg_catalog.pg_class tbl ON tbl.oid = idx.indrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = tbl.relnamespace
            JOIN pg_catalog.pg_class idx_cls ON idx_cls.oid = idx.indexrelid
            JOIN pg_catalog.pg_am am ON am.oid = idx_cls.relam
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY ns.nspname, tbl.relname, idx_cls.relname, idx_cls.oid
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| RawIndex {
            oid: row.get(0),
            relation_oid: row.get(1),
            schema: row.get(2),
            relation: row.get(3),
            name: row.get(4),
            access_method: row.get(5),
            unique: row.get(6),
            primary: row.get(7),
            exclusion: row.get(8),
            immediate: row.get(9),
            clustered: row.get(10),
            valid: row.get(11),
            ready: row.get(12),
            live: row.get(13),
            replica_identity: row.get(14),
            nulls_not_distinct: row.get(15),
            key_count: row.get(16),
            predicate: row.get(17),
            expression: row.get(18),
            definition: row.get(19),
            definition_too_large: row.get(20),
        })
        .collect())
}

fn read_index_terms(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawIndexTerm>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT idx.indexrelid::bigint,
                   key_part.ordinality::smallint,
                   key_part.attnum,
                   att.attname,
                   pg_catalog.pg_get_indexdef(
                       idx.indexrelid,
                       key_part.ordinality::integer,
                       true
                   ),
                   key_part.ordinality <= idx.indnkeyatts,
                   COALESCE((option_part.option_value & 1) <> 0, false),
                   COALESCE((option_part.option_value & 2) <> 0, false),
                   CASE WHEN opclass.oid IS NULL THEN NULL
                        ELSE opclass_ns.nspname || '.' || opclass.opcname END,
                   CASE WHEN coll.oid IS NULL OR coll.oid = 0 THEN NULL
                        ELSE coll_ns.nspname || '.' || coll.collname END
            FROM pg_catalog.pg_index idx
            JOIN pg_catalog.pg_class tbl ON tbl.oid = idx.indrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = tbl.relnamespace
            CROSS JOIN LATERAL pg_catalog.unnest(idx.indkey) WITH ORDINALITY
                AS key_part(attnum, ordinality)
            LEFT JOIN pg_catalog.pg_attribute att
              ON att.attrelid = idx.indrelid AND att.attnum = key_part.attnum
            LEFT JOIN LATERAL pg_catalog.unnest(idx.indoption::smallint[]) WITH ORDINALITY
                AS option_part(option_value, ordinality)
              ON option_part.ordinality = key_part.ordinality
            LEFT JOIN LATERAL pg_catalog.unnest(idx.indclass::oid[]) WITH ORDINALITY
                AS class_part(opclass_oid, ordinality)
              ON class_part.ordinality = key_part.ordinality
            LEFT JOIN pg_catalog.pg_opclass opclass ON opclass.oid = class_part.opclass_oid
            LEFT JOIN pg_catalog.pg_namespace opclass_ns ON opclass_ns.oid = opclass.opcnamespace
            LEFT JOIN LATERAL pg_catalog.unnest(idx.indcollation::oid[]) WITH ORDINALITY
                AS coll_part(collation_oid, ordinality)
              ON coll_part.ordinality = key_part.ordinality
            LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = coll_part.collation_oid
            LEFT JOIN pg_catalog.pg_namespace coll_ns ON coll_ns.oid = coll.collnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY idx.indexrelid, key_part.ordinality
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawIndexTerm {
            index_oid: row.get(0),
            ordinal: row.get(1),
            column_number: row.get(2),
            column_name: row.get(3),
            definition: row.get(4),
            is_key: row.get(5),
            descending: row.get(6),
            nulls_first: row.get(7),
            operator_class: row.get(8),
            collation: row.get(9),
        })
        .collect())
}

fn read_types(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawType>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT typ.oid::bigint,
                   ns.nspname,
                   typ.typname,
                   typ.typtype::text,
                   typ.typowner::bigint,
                   typ.typcategory::text,
                   NULLIF(typ.typrelid, 0)::bigint,
                   NULLIF(typ.typbasetype, 0)::bigint,
                   base_ns.nspname,
                   NULLIF(typ.typelem, 0)::bigint,
                   element_ns.nspname,
                   typ.typnotnull,
                   CASE WHEN typ.typdefault IS NOT NULL
                             AND pg_catalog.octet_length(typ.typdefault) <= $2
                        THEN typ.typdefault
                        ELSE NULL END,
                   CASE WHEN typ.typdefault IS NOT NULL
                        THEN pg_catalog.octet_length(typ.typdefault) > $2
                        ELSE false END,
                   CASE WHEN typ.typcollation = 0 THEN NULL
                        ELSE coll_ns.nspname || '.' || coll.collname END,
                   rng.rngsubtype::bigint,
                   range_subtype_ns.nspname,
                   NULLIF(rng.rngmultitypid, 0)::bigint,
                   multirange_ns.nspname,
                   pg_catalog.obj_description(typ.oid, 'pg_type')
            FROM pg_catalog.pg_type typ
            JOIN pg_catalog.pg_namespace ns ON ns.oid = typ.typnamespace
            LEFT JOIN pg_catalog.pg_class rel ON rel.oid = typ.typrelid
            LEFT JOIN pg_catalog.pg_type base_type ON base_type.oid = typ.typbasetype
            LEFT JOIN pg_catalog.pg_namespace base_ns ON base_ns.oid = base_type.typnamespace
            LEFT JOIN pg_catalog.pg_type element_type ON element_type.oid = typ.typelem
            LEFT JOIN pg_catalog.pg_namespace element_ns ON element_ns.oid = element_type.typnamespace
            LEFT JOIN pg_catalog.pg_range rng ON rng.rngtypid = typ.oid
            LEFT JOIN pg_catalog.pg_type range_subtype ON range_subtype.oid = rng.rngsubtype
            LEFT JOIN pg_catalog.pg_namespace range_subtype_ns
              ON range_subtype_ns.oid = range_subtype.typnamespace
            LEFT JOIN pg_catalog.pg_type multirange_type ON multirange_type.oid = rng.rngmultitypid
            LEFT JOIN pg_catalog.pg_namespace multirange_ns
              ON multirange_ns.oid = multirange_type.typnamespace
            LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = typ.typcollation
            LEFT JOIN pg_catalog.pg_namespace coll_ns ON coll_ns.oid = coll.collnamespace
            WHERE ns.nspname = ANY($1::text[])
              AND typ.typisdefined
              AND typ.typtype IN ('b', 'c', 'd', 'e', 'r', 'm')
            ORDER BY ns.nspname, typ.typname, typ.oid
            ",
            &[&schemas, &MAX_PROPERTY_STRING_BYTES],
        )?
        .into_iter()
        .map(|row| RawType {
            oid: row.get(0),
            schema: row.get(1),
            name: row.get(2),
            kind: one_char(&row.get::<_, String>(3)),
            owner_oid: row.get(4),
            category: one_char(&row.get::<_, String>(5)),
            relation_oid: row.get(6),
            base_type_oid: row.get(7),
            base_type_schema: row.get(8),
            element_type_oid: row.get(9),
            element_type_schema: row.get(10),
            not_null: row.get(11),
            default_value: row.get(12),
            default_too_large: row.get(13),
            collation: row.get(14),
            range_subtype_oid: row.get(15),
            range_subtype_schema: row.get(16),
            multirange_type_oid: row.get(17),
            multirange_type_schema: row.get(18),
            comment: row.get(19),
        })
        .collect())
}

fn read_enum_values(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawEnumValue>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT enum.enumtypid::bigint,
                   enum.enumlabel,
                   enum.enumsortorder::text
            FROM pg_catalog.pg_enum enum
            JOIN pg_catalog.pg_type typ ON typ.oid = enum.enumtypid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = typ.typnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY enum.enumtypid, enum.enumsortorder, enum.oid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawEnumValue {
            type_oid: row.get(0),
            label: row.get(1),
            sort_order: row.get(2),
        })
        .collect())
}

fn read_sequences(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawSequence>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT seq.seqrelid::bigint,
                   seq.seqtypid::bigint,
                   seq.seqstart,
                   seq.seqmin,
                   seq.seqmax,
                   seq.seqincrement,
                   seq.seqcycle,
                   seq.seqcache
            FROM pg_catalog.pg_sequence seq
            JOIN pg_catalog.pg_class cls ON cls.oid = seq.seqrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY ns.nspname, cls.relname, cls.oid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawSequence {
            relation_oid: row.get(0),
            type_oid: row.get(1),
            start_value: row.get(2),
            min_value: row.get(3),
            max_value: row.get(4),
            increment_by: row.get(5),
            cycle: row.get(6),
            cache_size: row.get(7),
        })
        .collect())
}

fn read_routines(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawRoutine>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT proc.oid::bigint,
                   ns.nspname,
                   proc.proname,
                   pg_catalog.pg_get_function_identity_arguments(proc.oid),
                   proc.prokind::text,
                   proc.proowner::bigint,
                   lang.lanname,
                   proc.prorettype::bigint,
                   return_ns.nspname,
                   pg_catalog.pg_get_function_result(proc.oid),
                   proc.proretset,
                   proc.prosecdef,
                   proc.proleakproof,
                   proc.proisstrict,
                   proc.provolatile::text,
                   proc.proparallel::text,
                   CASE WHEN proc.prokind IN ('f', 'p')
                             AND pg_catalog.octet_length(pg_catalog.pg_get_functiondef(proc.oid)) <= $2
                        THEN pg_catalog.pg_get_functiondef(proc.oid)
                        ELSE NULL END,
                   CASE WHEN proc.prokind IN ('f', 'p')
                        THEN pg_catalog.octet_length(pg_catalog.pg_get_functiondef(proc.oid)) > $2
                        ELSE false END,
                   pg_catalog.pg_get_function_arguments(proc.oid),
                   lang.lanname = 'sql' AND proc.prosqlbody IS NOT NULL
            FROM pg_catalog.pg_proc proc
            JOIN pg_catalog.pg_namespace ns ON ns.oid = proc.pronamespace
            JOIN pg_catalog.pg_language lang ON lang.oid = proc.prolang
            JOIN pg_catalog.pg_type return_type ON return_type.oid = proc.prorettype
            JOIN pg_catalog.pg_namespace return_ns ON return_ns.oid = return_type.typnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY ns.nspname,
                     proc.proname,
                     pg_catalog.pg_get_function_identity_arguments(proc.oid),
                     proc.oid
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| RawRoutine {
            oid: row.get(0),
            schema: row.get(1),
            name: row.get(2),
            identity_arguments: row.get(3),
            kind: one_char(&row.get::<_, String>(4)),
            owner_oid: row.get(5),
            language: row.get(6),
            return_type_oid: row.get(7),
            return_type_schema: row.get(8),
            return_type: row.get(9),
            returns_set: row.get(10),
            security_definer: row.get(11),
            leakproof: row.get(12),
            strict: row.get(13),
            volatility: one_char(&row.get::<_, String>(14)),
            parallel: one_char(&row.get::<_, String>(15)),
            definition: row.get(16),
            definition_too_large: row.get(17),
            arguments_definition: row.get(18),
            body_catalog_tracked: row.get(19),
        })
        .collect())
}

fn read_routine_parameters(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawRoutineParameter>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT proc.oid::bigint,
                   argument_type.ordinality::integer,
                   NULLIF(proc.proargnames[argument_type.ordinality], ''),
                   COALESCE(proc.proargmodes[argument_type.ordinality], 'i'::\"char\")::text,
                   argument_type.type_oid::bigint,
                   argument_type_ns.nspname,
                   pg_catalog.format_type(argument_type.type_oid, NULL)
            FROM pg_catalog.pg_proc proc
            JOIN pg_catalog.pg_namespace ns ON ns.oid = proc.pronamespace
            CROSS JOIN LATERAL pg_catalog.unnest(
                COALESCE(proc.proallargtypes, proc.proargtypes::oid[])
            ) WITH ORDINALITY AS argument_type(type_oid, ordinality)
            JOIN pg_catalog.pg_type argument_pg_type
              ON argument_pg_type.oid = argument_type.type_oid
            JOIN pg_catalog.pg_namespace argument_type_ns
              ON argument_type_ns.oid = argument_pg_type.typnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY proc.oid, argument_type.ordinality
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawRoutineParameter {
            routine_oid: row.get(0),
            ordinal: row.get(1),
            name: row.get(2),
            mode: one_char(&row.get::<_, String>(3)),
            type_oid: row.get(4),
            type_schema: row.get(5),
            data_type: row.get(6),
        })
        .collect())
}

fn read_triggers(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawTrigger>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT trg.oid::bigint,
                   trg.tgrelid::bigint,
                   trg.tgfoid::bigint,
                   trg.tgname,
                   CASE
                     WHEN (trg.tgtype::integer & 2) <> 0 THEN 'BEFORE'
                     WHEN (trg.tgtype::integer & 64) <> 0 THEN 'INSTEAD OF'
                     ELSE 'AFTER'
                   END,
                   (trg.tgtype::integer & 4) <> 0,
                   (trg.tgtype::integer & 8) <> 0,
                   (trg.tgtype::integer & 16) <> 0,
                   (trg.tgtype::integer & 32) <> 0,
                   CASE WHEN (trg.tgtype::integer & 1) <> 0 THEN 'ROW' ELSE 'STATEMENT' END,
                   trg.tgenabled::text,
                   COALESCE(trg.tgattr::smallint[], ARRAY[]::smallint[]),
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_triggerdef(trg.oid, true)) <= $2
                        THEN pg_catalog.pg_get_expr(trg.tgqual, trg.tgrelid, true)
                        ELSE NULL END,
                   CASE WHEN pg_catalog.octet_length(pg_catalog.pg_get_triggerdef(trg.oid, true)) <= $2
                        THEN pg_catalog.pg_get_triggerdef(trg.oid, true)
                        ELSE NULL END,
                   pg_catalog.octet_length(pg_catalog.pg_get_triggerdef(trg.oid, true)) > $2
            FROM pg_catalog.pg_trigger trg
            JOIN pg_catalog.pg_class rel ON rel.oid = trg.tgrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
            WHERE ns.nspname = ANY($1::text[])
              AND NOT trg.tgisinternal
            ORDER BY ns.nspname, rel.relname, trg.tgname, trg.oid
            ",
            &[&schemas, &MAX_DEFINITION_BYTES],
        )?
        .into_iter()
        .map(|row| {
            let mut events = Vec::new();
            if row.get(5) {
                events.push("INSERT".to_owned());
            }
            if row.get(6) {
                events.push("DELETE".to_owned());
            }
            if row.get(7) {
                events.push("UPDATE".to_owned());
            }
            if row.get(8) {
                events.push("TRUNCATE".to_owned());
            }
            RawTrigger {
                oid: row.get(0),
                relation_oid: row.get(1),
                routine_oid: row.get(2),
                name: row.get(3),
                timing: row.get(4),
                events,
                orientation: row.get(9),
                enabled: one_char(&row.get::<_, String>(10)),
                update_columns: row.get(11),
                when_expression: row.get(12),
                definition: row.get(13),
                definition_too_large: row.get(14),
            }
        })
        .collect())
}

fn read_inheritance(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawInheritance>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT inh.inhrelid::bigint,
                   inh.inhparent::bigint,
                   inh.inhseqno,
                   child.relispartition
            FROM pg_catalog.pg_inherits inh
            JOIN pg_catalog.pg_class child ON child.oid = inh.inhrelid
            JOIN pg_catalog.pg_namespace child_ns ON child_ns.oid = child.relnamespace
            JOIN pg_catalog.pg_class parent ON parent.oid = inh.inhparent
            WHERE child_ns.nspname = ANY($1::text[])
              AND child.relkind IN ('r', 'p', 'f')
              AND parent.relkind IN ('r', 'p', 'f')
            ORDER BY inh.inhrelid, inh.inhseqno, inh.inhparent
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawInheritance {
            child_oid: row.get(0),
            parent_oid: row.get(1),
            sequence_number: row.get(2),
            child_is_partition: row.get(3),
        })
        .collect())
}

fn read_view_dependencies(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawViewDependency>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT view_cls.oid::bigint,
                   target_cls.oid::bigint,
                   dep.refobjsubid,
                   target_ns.nspname,
                   dep.deptype::text
            FROM pg_catalog.pg_rewrite rewrite
            JOIN pg_catalog.pg_class view_cls ON view_cls.oid = rewrite.ev_class
            JOIN pg_catalog.pg_namespace view_ns ON view_ns.oid = view_cls.relnamespace
            JOIN pg_catalog.pg_depend dep
              ON dep.classid = 'pg_catalog.pg_rewrite'::regclass
             AND dep.objid = rewrite.oid
            JOIN pg_catalog.pg_class target_cls
              ON dep.refclassid = 'pg_catalog.pg_class'::regclass
             AND dep.refobjid = target_cls.oid
            JOIN pg_catalog.pg_namespace target_ns ON target_ns.oid = target_cls.relnamespace
            WHERE view_ns.nspname = ANY($1::text[])
              AND view_cls.relkind IN ('v', 'm')
              AND rewrite.rulename = '_RETURN'
              AND dep.deptype IN ('n', 'a', 'i')
              AND target_cls.oid <> view_cls.oid
            GROUP BY view_cls.oid, target_cls.oid, dep.refobjsubid, target_ns.nspname, dep.deptype
            ORDER BY view_cls.oid, target_cls.oid, dep.refobjsubid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawViewDependency {
            view_oid: row.get(0),
            target_relation_oid: row.get(1),
            target_column_number: row.get(2),
            target_schema: row.get(3),
            dependency_type: one_char(&row.get::<_, String>(4)),
        })
        .collect())
}

fn read_routine_dependencies(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawDependency>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT proc.oid::bigint,
                   CASE dep.refclassid
                     WHEN 'pg_catalog.pg_class'::regclass THEN 'relation'
                     WHEN 'pg_catalog.pg_proc'::regclass THEN 'routine'
                     WHEN 'pg_catalog.pg_type'::regclass THEN 'type'
                   END,
                   dep.refobjid::bigint,
                   dep.refobjsubid,
                   COALESCE(rel_ns.nspname, proc_target_ns.nspname, type_ns.nspname),
                   dep.deptype::text
            FROM pg_catalog.pg_proc proc
            JOIN pg_catalog.pg_namespace proc_ns ON proc_ns.oid = proc.pronamespace
            JOIN pg_catalog.pg_depend dep
              ON dep.classid = 'pg_catalog.pg_proc'::regclass
             AND dep.objid = proc.oid
            LEFT JOIN pg_catalog.pg_class rel_target
              ON dep.refclassid = 'pg_catalog.pg_class'::regclass
             AND rel_target.oid = dep.refobjid
            LEFT JOIN pg_catalog.pg_namespace rel_ns ON rel_ns.oid = rel_target.relnamespace
            LEFT JOIN pg_catalog.pg_proc proc_target
              ON dep.refclassid = 'pg_catalog.pg_proc'::regclass
             AND proc_target.oid = dep.refobjid
            LEFT JOIN pg_catalog.pg_namespace proc_target_ns
              ON proc_target_ns.oid = proc_target.pronamespace
            LEFT JOIN pg_catalog.pg_type type_target
              ON dep.refclassid = 'pg_catalog.pg_type'::regclass
             AND type_target.oid = dep.refobjid
            LEFT JOIN pg_catalog.pg_namespace type_ns ON type_ns.oid = type_target.typnamespace
            WHERE proc_ns.nspname = ANY($1::text[])
              AND dep.refclassid IN (
                    'pg_catalog.pg_class'::regclass,
                    'pg_catalog.pg_proc'::regclass,
                    'pg_catalog.pg_type'::regclass
                  )
              AND NOT (
                    dep.refclassid = 'pg_catalog.pg_proc'::regclass
                AND dep.refobjid = proc.oid
              )
              AND dep.deptype IN ('n', 'a', 'i')
            ORDER BY proc.oid, dep.refclassid, dep.refobjid, dep.refobjsubid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawDependency {
            owner_oid: row.get(0),
            target_class: row.get(1),
            target_oid: row.get(2),
            target_sub_id: row.get(3),
            target_schema: row.get(4),
            dependency_type: one_char(&row.get::<_, String>(5)),
        })
        .collect())
}

fn read_sequence_usages(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawSequenceUsage>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT source_relation_oid,
                   source_column_number,
                   sequence_oid,
                   dependency_type
            FROM (
                SELECT dep.refobjid::bigint AS source_relation_oid,
                       dep.refobjsubid AS source_column_number,
                       seq.oid::bigint AS sequence_oid,
                       dep.deptype::text AS dependency_type
                FROM pg_catalog.pg_class seq
                JOIN pg_catalog.pg_namespace seq_ns ON seq_ns.oid = seq.relnamespace
                JOIN pg_catalog.pg_depend dep
                  ON dep.classid = 'pg_catalog.pg_class'::regclass
                 AND dep.objid = seq.oid
                 AND dep.refclassid = 'pg_catalog.pg_class'::regclass
                WHERE seq.relkind = 'S'
                  AND seq_ns.nspname = ANY($1::text[])
                  AND dep.refobjsubid > 0
                  AND dep.deptype IN ('a', 'i')

                UNION

                SELECT attrdef.adrelid::bigint,
                       attrdef.adnum,
                       seq.oid::bigint,
                       dep.deptype::text
                FROM pg_catalog.pg_attrdef attrdef
                JOIN pg_catalog.pg_class source_rel ON source_rel.oid = attrdef.adrelid
                JOIN pg_catalog.pg_namespace source_ns ON source_ns.oid = source_rel.relnamespace
                JOIN pg_catalog.pg_depend dep
                  ON dep.classid = 'pg_catalog.pg_attrdef'::regclass
                 AND dep.objid = attrdef.oid
                 AND dep.refclassid = 'pg_catalog.pg_class'::regclass
                JOIN pg_catalog.pg_class seq ON seq.oid = dep.refobjid AND seq.relkind = 'S'
                WHERE source_ns.nspname = ANY($1::text[])
                  AND dep.deptype IN ('n', 'a', 'i')
            ) usage
            ORDER BY source_relation_oid, source_column_number, sequence_oid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawSequenceUsage {
            column_relation_oid: row.get(0),
            column_number: row.get(1),
            sequence_oid: row.get(2),
            dependency_type: one_char(&row.get::<_, String>(3)),
        })
        .collect())
}

fn read_policies(
    client: &mut impl GenericClient,
    schemas: &[String],
) -> Result<Vec<RawPolicy>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT policy.oid::bigint,
                   policy.polrelid::bigint,
                   policy.polname,
                   policy.polcmd::text,
                   policy.polpermissive,
                   ARRAY(
                       SELECT role_oid::bigint
                       FROM pg_catalog.unnest(policy.polroles) AS role_oid
                       ORDER BY role_oid
                   ),
                   pg_catalog.pg_get_expr(policy.polqual, policy.polrelid, true),
                   pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, true)
            FROM pg_catalog.pg_policy policy
            JOIN pg_catalog.pg_class rel ON rel.oid = policy.polrelid
            JOIN pg_catalog.pg_namespace ns ON ns.oid = rel.relnamespace
            WHERE ns.nspname = ANY($1::text[])
            ORDER BY ns.nspname, rel.relname, policy.polname, policy.oid
            ",
            &[&schemas],
        )?
        .into_iter()
        .map(|row| RawPolicy {
            oid: row.get(0),
            relation_oid: row.get(1),
            name: row.get(2),
            command: one_char(&row.get::<_, String>(3)),
            permissive: row.get(4),
            role_oids: row.get(5),
            using_expression: row.get(6),
            check_expression: row.get(7),
        })
        .collect())
}

fn read_extensions(client: &mut impl GenericClient) -> Result<Vec<RawExtension>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT ext.oid::bigint,
                   ext.extname,
                   ext.extowner::bigint,
                   ns.nspname,
                   ext.extrelocatable,
                   ext.extversion
            FROM pg_catalog.pg_extension ext
            LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid = ext.extnamespace
            ORDER BY ext.extname, ext.oid
            ",
            &[],
        )?
        .into_iter()
        .map(|row| RawExtension {
            oid: row.get(0),
            name: row.get(1),
            owner_oid: row.get(2),
            schema: row.get(3),
            relocatable: row.get(4),
            version: row.get(5),
        })
        .collect())
}

fn read_event_triggers(
    client: &mut impl GenericClient,
) -> Result<Vec<RawEventTrigger>, CatalogError> {
    Ok(client
        .query(
            "
            SELECT event.oid::bigint,
                   event.evtname,
                   event.evtevent,
                   event.evtowner::bigint,
                   event.evtfoid::bigint,
                   proc_ns.nspname,
                   event.evtenabled::text,
                   COALESCE(event.evttags, ARRAY[]::text[])
            FROM pg_catalog.pg_event_trigger event
            JOIN pg_catalog.pg_proc proc ON proc.oid = event.evtfoid
            JOIN pg_catalog.pg_namespace proc_ns ON proc_ns.oid = proc.pronamespace
            ORDER BY event.evtname, event.oid
            ",
            &[],
        )?
        .into_iter()
        .map(|row| RawEventTrigger {
            oid: row.get(0),
            name: row.get(1),
            event: row.get(2),
            owner_oid: row.get(3),
            routine_oid: row.get(4),
            routine_schema: row.get(5),
            enabled: one_char(&row.get::<_, String>(6)),
            tags: row.get(7),
        })
        .collect())
}

impl<'a> PostgresSnapshotMapper<'a> {
    fn new(connection_alias: &'a str) -> Self {
        Self { connection_alias }
    }

    fn map(&self, raw: RawPostgresCatalog) -> Result<CatalogDiscovery, CatalogError> {
        validate_raw_catalog(&raw)?;

        let database_name = raw.server.database.clone();
        let database_key = pg_key(
            self.connection_alias,
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

        let schemas = raw
            .schemas
            .iter()
            .map(|schema| SchemaObject {
                key: pg_key(
                    self.connection_alias,
                    &database_name,
                    &schema.name,
                    ObjectKind::Schema,
                    &schema.name,
                    None,
                ),
                database_key: database_key.clone(),
                name: schema.name.clone(),
            })
            .collect::<Vec<_>>();
        let schema_keys = schemas
            .iter()
            .map(|schema| (schema.name.clone(), schema.key.clone()))
            .collect::<BTreeMap<_, _>>();

        let mut metadata = CanonicalMetadata::default();
        let mut principal_keys = BTreeMap::new();
        for principal in &raw.principals {
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &database_name,
                ObjectKind::Principal,
                &principal.name,
                None,
            );
            principal_keys.insert(principal.oid, key.clone());
            let mut properties = BTreeMap::new();
            insert_bool(&mut properties, "superuser", principal.superuser);
            insert_bool(&mut properties, "inherit", principal.inherit);
            insert_bool(&mut properties, "create_role", principal.create_role);
            insert_bool(
                &mut properties,
                "create_database",
                principal.create_database,
            );
            insert_bool(&mut properties, "can_login", principal.can_login);
            insert_bool(&mut properties, "replication", principal.replication);
            insert_bool(&mut properties, "bypass_rls", principal.bypass_rls);
            insert_optional_string(
                &mut properties,
                "valid_until",
                principal.valid_until.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(database_key.clone()),
                name: principal.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }

        for schema in &raw.schemas {
            let schema_key = required(
                schema_keys.get(&schema.name),
                format!("schema key for {}", schema.name),
            )?;
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "postgres_oid", schema.oid);
            insert_optional_string(&mut properties, "comment", schema.comment.as_deref());
            metadata.annotations.push(ObjectAnnotation {
                object_key: schema_key.clone(),
                definition: None,
                properties,
            });
            add_owned_by(
                &mut metadata.relationships,
                schema_key,
                schema.owner_oid,
                &principal_keys,
                "schema",
            )?;
        }

        let mut type_keys = BTreeMap::new();
        for raw_type in &raw.types {
            let parent = required(
                schema_keys.get(&raw_type.schema),
                format!("schema key for PostgreSQL type {}", raw_type.name),
            )?;
            let kind = if raw_type.kind == 'd' {
                ObjectKind::Domain
            } else {
                ObjectKind::UserDefinedType
            };
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &raw_type.schema,
                kind,
                &raw_type.name,
                None,
            );
            if type_keys.insert(raw_type.oid, key.clone()).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate PostgreSQL type oid {}",
                    raw_type.oid
                )));
            }
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "postgres_oid", raw_type.oid);
            insert_string(
                &mut properties,
                "postgres_type_kind",
                type_kind_name(raw_type.kind),
            );
            insert_string(&mut properties, "category", raw_type.category.to_string());
            insert_bool(&mut properties, "not_null", raw_type.not_null);
            insert_optional_string(
                &mut properties,
                "default",
                raw_type.default_value.as_deref(),
            );
            insert_optional_string(&mut properties, "collation", raw_type.collation.as_deref());
            insert_optional_string(&mut properties, "comment", raw_type.comment.as_deref());
            insert_bool(
                &mut properties,
                "implicit_relation_type",
                raw_type.relation_oid.is_some(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(parent.clone()),
                name: raw_type.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            add_owned_by(
                &mut metadata.relationships,
                &key,
                raw_type.owner_oid,
                &principal_keys,
                "type",
            )?;
        }

        for enum_value in &raw.enum_values {
            let type_key = required(
                type_keys.get(&enum_value.type_oid),
                format!("enum parent type oid {}", enum_value.type_oid),
            )?;
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &type_key.schema,
                ObjectKind::EnumValue,
                &type_key.object_name,
                Some(enum_value.label.clone()),
            );
            let mut properties = BTreeMap::new();
            insert_string(&mut properties, "sort_order", &enum_value.sort_order);
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(type_key.clone()),
                name: enum_value.label.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }

        let sequence_facts = raw
            .sequences
            .iter()
            .map(|sequence| (sequence.relation_oid, sequence))
            .collect::<BTreeMap<_, _>>();
        let mut tables = Vec::new();
        let mut views = Vec::new();
        let mut table_keys = BTreeMap::new();
        let mut view_keys = BTreeMap::new();
        let mut materialized_view_keys = BTreeMap::new();
        let mut sequence_keys = BTreeMap::new();
        let mut relation_keys = BTreeMap::new();
        let mut relation_row_type_keys = BTreeMap::new();
        for relation in &raw.relations {
            if let Some(type_key) = type_keys.get(&relation.row_type_oid) {
                relation_row_type_keys.insert(relation.row_type_oid, type_key.clone());
            }
            let schema_key = required(
                schema_keys.get(&relation.schema),
                format!(
                    "schema key for relation {}.{}",
                    relation.schema, relation.name
                ),
            )?;
            match relation.relkind {
                'r' | 'p' | 'f' => {
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &relation.schema,
                        ObjectKind::Table,
                        &relation.name,
                        None,
                    );
                    table_keys.insert(relation.oid, key.clone());
                    relation_keys.insert(relation.oid, key.clone());
                    tables.push(TableObject {
                        key: key.clone(),
                        schema_key: schema_key.clone(),
                        name: relation.name.clone(),
                        kind: table_kind(relation),
                    });
                    metadata
                        .annotations
                        .push(relation_annotation(relation, &key));
                    add_owned_by(
                        &mut metadata.relationships,
                        &key,
                        relation.owner_oid,
                        &principal_keys,
                        "table",
                    )?;
                }
                'v' => {
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &relation.schema,
                        ObjectKind::View,
                        &relation.name,
                        None,
                    );
                    view_keys.insert(relation.oid, key.clone());
                    relation_keys.insert(relation.oid, key.clone());
                    views.push(ViewObject {
                        key: key.clone(),
                        schema_key: schema_key.clone(),
                        name: relation.name.clone(),
                        definition: relation.definition.clone(),
                        depends_on: Vec::new(),
                    });
                    metadata
                        .annotations
                        .push(relation_annotation(relation, &key));
                    add_owned_by(
                        &mut metadata.relationships,
                        &key,
                        relation.owner_oid,
                        &principal_keys,
                        "view",
                    )?;
                }
                'm' => {
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &relation.schema,
                        ObjectKind::MaterializedView,
                        &relation.name,
                        None,
                    );
                    materialized_view_keys.insert(relation.oid, key.clone());
                    relation_keys.insert(relation.oid, key.clone());
                    metadata.objects.push(MetadataObject {
                        key: key.clone(),
                        parent_key: Some(schema_key.clone()),
                        name: relation.name.clone(),
                        extension_kind: None,
                        definition: relation.definition.clone(),
                        properties: relation_properties(relation),
                    });
                    add_owned_by(
                        &mut metadata.relationships,
                        &key,
                        relation.owner_oid,
                        &principal_keys,
                        "materialized view",
                    )?;
                }
                'S' => {
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &relation.schema,
                        ObjectKind::Sequence,
                        &relation.name,
                        None,
                    );
                    sequence_keys.insert(relation.oid, key.clone());
                    relation_keys.insert(relation.oid, key.clone());
                    let sequence = required(
                        sequence_facts.get(&relation.oid).copied(),
                        format!("pg_sequence row for {}.{}", relation.schema, relation.name),
                    )?;
                    let mut properties = relation_properties(relation);
                    insert_i64(&mut properties, "type_oid", sequence.type_oid);
                    insert_i64(&mut properties, "start", sequence.start_value);
                    insert_i64(&mut properties, "minimum", sequence.min_value);
                    insert_i64(&mut properties, "maximum", sequence.max_value);
                    insert_i64(&mut properties, "increment", sequence.increment_by);
                    insert_bool(&mut properties, "cycle", sequence.cycle);
                    insert_i64(&mut properties, "cache", sequence.cache_size);
                    metadata.objects.push(MetadataObject {
                        key: key.clone(),
                        parent_key: Some(schema_key.clone()),
                        name: relation.name.clone(),
                        extension_kind: None,
                        definition: None,
                        properties,
                    });
                    add_owned_by(
                        &mut metadata.relationships,
                        &key,
                        relation.owner_oid,
                        &principal_keys,
                        "sequence",
                    )?;
                }
                'c' => {}
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped PostgreSQL relation kind '{other}' for {}.{}",
                        relation.schema, relation.name
                    )));
                }
            }
        }

        let mut columns = Vec::new();
        let mut column_keys = BTreeMap::new();
        for column in &raw.columns {
            let parent_key = relation_keys.get(&column.relation_oid);
            match column.relation_kind {
                'r' | 'p' | 'f' => {
                    let table_key = required(
                        parent_key,
                        format!(
                            "table key for column {}.{}.{}",
                            column.schema, column.relation, column.name
                        ),
                    )?;
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &column.schema,
                        ObjectKind::Column,
                        &column.relation,
                        Some(column.name.clone()),
                    );
                    column_keys.insert((column.relation_oid, column.attnum as i32), key.clone());
                    columns.push(ColumnObject {
                        key: key.clone(),
                        table_key: table_key.clone(),
                        name: column.name.clone(),
                        ordinal_position: positive_u32(column.attnum, "column ordinal")?,
                        data_type: column.data_type.clone(),
                        is_nullable: column.nullable,
                        default_value: column.default_expression.clone(),
                        is_generated: column.generated != '\0',
                    });
                    metadata.annotations.push(column_annotation(column, &key));
                    add_type_use(
                        &mut metadata.relationships,
                        &key,
                        column.type_oid,
                        &column.type_schema,
                        &type_keys,
                    )?;
                }
                'v' | 'm' => {
                    let view_key = required(
                        parent_key,
                        format!(
                            "view key for output column {}.{}.{}",
                            column.schema, column.relation, column.name
                        ),
                    )?;
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &column.schema,
                        ObjectKind::ViewColumn,
                        &column.relation,
                        Some(column.name.clone()),
                    );
                    column_keys.insert((column.relation_oid, column.attnum as i32), key.clone());
                    let mut properties = column_properties(column);
                    insert_u64(
                        &mut properties,
                        "ordinal_position",
                        positive_u32(column.attnum, "view column ordinal")? as u64,
                    );
                    insert_string(&mut properties, "data_type", &column.data_type);
                    insert_bool(&mut properties, "nullable", column.nullable);
                    metadata.objects.push(MetadataObject {
                        key: key.clone(),
                        parent_key: Some(view_key.clone()),
                        name: column.name.clone(),
                        extension_kind: None,
                        definition: None,
                        properties,
                    });
                    add_type_use(
                        &mut metadata.relationships,
                        &key,
                        column.type_oid,
                        &column.type_schema,
                        &type_keys,
                    )?;
                }
                'c' => {
                    let parent_type = required(
                        type_keys.get(&relation_row_type_oid(&raw.relations, column.relation_oid)?),
                        format!(
                            "composite type for attribute {}.{}.{}",
                            column.schema, column.relation, column.name
                        ),
                    )?;
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &column.schema,
                        ObjectKind::Extension,
                        &column.relation,
                        Some(column.name.clone()),
                    );
                    column_keys.insert((column.relation_oid, column.attnum as i32), key.clone());
                    let mut properties = column_properties(column);
                    insert_u64(
                        &mut properties,
                        "ordinal_position",
                        positive_u32(column.attnum, "composite attribute ordinal")? as u64,
                    );
                    insert_string(&mut properties, "data_type", &column.data_type);
                    metadata.objects.push(MetadataObject {
                        key: key.clone(),
                        parent_key: Some(parent_type.clone()),
                        name: column.name.clone(),
                        extension_kind: Some("postgres_composite_attribute".to_owned()),
                        definition: None,
                        properties,
                    });
                    if let Some(type_key) = type_keys.get(&column.type_oid) {
                        metadata.relationships.push(MetadataRelationship {
                            kind: MetadataRelationshipKind::DependsOn,
                            from_key: key,
                            to_key: type_key.clone(),
                            ordinal: None,
                            properties: BTreeMap::new(),
                        });
                    }
                }
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped PostgreSQL column relation kind '{other}' for {}.{}.{}",
                        column.schema, column.relation, column.name
                    )));
                }
            }
        }

        let mut constraints = Vec::new();
        for constraint in &raw.constraints {
            if let Some(domain_oid) = constraint.domain_type_oid {
                if constraint.kind != 'c' {
                    return Err(CatalogError::Mapping(format!(
                        "unsupported domain constraint kind '{}' for {}",
                        constraint.kind, constraint.name
                    )));
                }
                let domain_key = required(
                    type_keys.get(&domain_oid),
                    format!(
                        "domain parent oid {domain_oid} for constraint {}",
                        constraint.name
                    ),
                )?;
                let key = pg_key(
                    self.connection_alias,
                    &database_name,
                    &constraint.schema,
                    ObjectKind::CheckConstraint,
                    &domain_key.object_name,
                    Some(constraint.name.clone()),
                );
                metadata.objects.push(MetadataObject {
                    key,
                    parent_key: Some(domain_key.clone()),
                    name: constraint.name.clone(),
                    extension_kind: None,
                    definition: constraint.definition.clone(),
                    properties: constraint_properties(constraint),
                });
                continue;
            }

            let relation_oid = constraint.relation_oid.ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "constraint {} has neither relation nor domain parent",
                    constraint.name
                ))
            })?;
            let table_key = required(
                table_keys.get(&relation_oid),
                format!(
                    "table parent oid {relation_oid} for constraint {}",
                    constraint.name
                ),
            )?;
            if constraint.kind == 'x' {
                let key = pg_key(
                    self.connection_alias,
                    &database_name,
                    &constraint.schema,
                    ObjectKind::ExclusionConstraint,
                    &table_key.object_name,
                    Some(constraint.name.clone()),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(table_key.clone()),
                    name: constraint.name.clone(),
                    extension_kind: None,
                    definition: constraint.definition.clone(),
                    properties: constraint_properties(constraint),
                });
                for (ordinal, column_number) in constraint.columns.iter().enumerate() {
                    if *column_number <= 0 {
                        continue;
                    }
                    let column_key = required(
                        column_keys.get(&(relation_oid, i32::from(*column_number))),
                        format!(
                            "exclusion constraint column {} at ordinal {}",
                            constraint.name,
                            ordinal + 1
                        ),
                    )?;
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::ExcludesWith,
                        from_key: key.clone(),
                        to_key: column_key.clone(),
                        ordinal: Some((ordinal + 1) as u32),
                        properties: BTreeMap::new(),
                    });
                }
                continue;
            }

            let (kind, object_kind) = match constraint.kind {
                'p' => (ConstraintKind::PrimaryKey, ObjectKind::PrimaryKey),
                'u' => (ConstraintKind::Unique, ObjectKind::UniqueConstraint),
                'f' => (ConstraintKind::ForeignKey, ObjectKind::ForeignKey),
                'c' => (ConstraintKind::Check, ObjectKind::CheckConstraint),
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped PostgreSQL constraint kind '{other}' for {}",
                        constraint.name
                    )));
                }
            };
            let local_columns = resolve_columns(
                relation_oid,
                &constraint.columns,
                &column_keys,
                &constraint.name,
            )?;
            let (referenced_table_key, referenced_columns) = if kind == ConstraintKind::ForeignKey {
                let referenced_oid = constraint.referenced_relation_oid.ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key {} has no referenced relation",
                        constraint.name
                    ))
                })?;
                let referenced_table = required(
                    table_keys.get(&referenced_oid),
                    format!(
                        "foreign key {} references a table outside the certified schema scope (oid {referenced_oid})",
                        constraint.name
                    ),
                )?;
                let referenced = resolve_columns(
                    referenced_oid,
                    &constraint.referenced_columns,
                    &column_keys,
                    &constraint.name,
                )?;
                (Some(referenced_table.clone()), referenced)
            } else {
                (None, Vec::new())
            };
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &constraint.schema,
                object_kind,
                &table_key.object_name,
                Some(constraint.name.clone()),
            );
            constraints.push(ConstraintObject {
                key: key.clone(),
                table_key: table_key.clone(),
                name: constraint.name.clone(),
                kind,
                columns: local_columns,
                referenced_table_key,
                referenced_columns,
                expression: (kind == ConstraintKind::Check)
                    .then(|| constraint.definition.clone())
                    .flatten(),
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties: constraint_properties(constraint),
            });
        }

        let terms_by_index = group_index_terms(&raw.index_terms);
        let relation_kind_by_oid = raw
            .relations
            .iter()
            .map(|relation| (relation.oid, relation.relkind))
            .collect::<BTreeMap<_, _>>();
        let mut indexes = Vec::new();
        for index in &raw.indexes {
            let terms = terms_by_index.get(&index.oid).cloned().unwrap_or_default();
            if terms.is_empty() {
                return Err(CatalogError::Mapping(format!(
                    "index {}.{}.{} has no catalog terms",
                    index.schema, index.relation, index.name
                )));
            }
            let relation_kind = required(
                relation_kind_by_oid.get(&index.relation_oid),
                format!("indexed relation oid {}", index.relation_oid),
            )?;
            match *relation_kind {
                'r' | 'p' | 'f' => {
                    let table_key = required(
                        table_keys.get(&index.relation_oid),
                        format!("indexed table oid {}", index.relation_oid),
                    )?;
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &index.schema,
                        ObjectKind::Index,
                        &index.relation,
                        Some(index.name.clone()),
                    );
                    let mut key_columns = Vec::new();
                    for term in &terms {
                        if term.is_key && term.column_number > 0 {
                            let column_key = required(
                                column_keys
                                    .get(&(index.relation_oid, i32::from(term.column_number))),
                                format!(
                                    "index key column for {} ordinal {}",
                                    index.name, term.ordinal
                                ),
                            )?
                            .clone();
                            if !key_columns.contains(&column_key) {
                                key_columns.push(column_key);
                            }
                        }
                    }
                    indexes.push(IndexObject {
                        key: key.clone(),
                        table_key: table_key.clone(),
                        name: index.name.clone(),
                        columns: key_columns,
                        is_unique: index.unique,
                        is_primary: index.primary,
                        predicate: index.predicate.clone(),
                        expression: index.expression.clone(),
                    });
                    metadata.annotations.push(ObjectAnnotation {
                        object_key: key.clone(),
                        definition: index.definition.clone(),
                        properties: index_properties(index, &terms),
                    });
                    add_included_columns(
                        &mut metadata.relationships,
                        &key,
                        index,
                        &terms,
                        &column_keys,
                        false,
                    )?;
                }
                'm' => {
                    let parent = required(
                        materialized_view_keys.get(&index.relation_oid),
                        format!("materialized view parent for index {}", index.name),
                    )?;
                    let key = pg_key(
                        self.connection_alias,
                        &database_name,
                        &index.schema,
                        ObjectKind::Index,
                        &index.relation,
                        Some(index.name.clone()),
                    );
                    metadata.objects.push(MetadataObject {
                        key: key.clone(),
                        parent_key: Some(parent.clone()),
                        name: index.name.clone(),
                        extension_kind: None,
                        definition: index.definition.clone(),
                        properties: index_properties(index, &terms),
                    });
                    add_included_columns(
                        &mut metadata.relationships,
                        &key,
                        index,
                        &terms,
                        &column_keys,
                        true,
                    )?;
                }
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "index {} belongs to unsupported relation kind '{other}'",
                        index.name
                    )));
                }
            }
        }

        let view_position_by_oid = views
            .iter()
            .enumerate()
            .map(|(position, view)| {
                let oid = view_keys
                    .iter()
                    .find_map(|(oid, key)| (key == &view.key).then_some(*oid))
                    .expect("view key was inserted with its oid");
                (oid, position)
            })
            .collect::<BTreeMap<_, _>>();
        let mut view_dependency_ordinals = BTreeMap::<i64, u32>::new();
        for dependency in &raw.view_dependencies {
            let Some(target_key) = resolve_relation_dependency(
                dependency.target_relation_oid,
                dependency.target_column_number,
                &dependency.target_schema,
                &relation_keys,
                &column_keys,
            )?
            else {
                continue;
            };
            let owner_key = view_keys
                .get(&dependency.view_oid)
                .or_else(|| materialized_view_keys.get(&dependency.view_oid))
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "view dependency owner oid {} is not mapped",
                        dependency.view_oid
                    ))
                })?;
            if let Some(position) = view_position_by_oid.get(&dependency.view_oid) {
                if is_base_snapshot_kind(target_key.object_kind) {
                    views[*position].depends_on.push(target_key.clone());
                } else {
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::DependsOn,
                        from_key: owner_key.clone(),
                        to_key: target_key.clone(),
                        ordinal: None,
                        properties: BTreeMap::new(),
                    });
                }
            } else if let Some(materialized_key) = materialized_view_keys.get(&dependency.view_oid)
            {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: materialized_key.clone(),
                    to_key: target_key.clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            } else {
                return Err(CatalogError::Mapping(format!(
                    "view dependency owner oid {} is not mapped",
                    dependency.view_oid
                )));
            }
            let ordinal = view_dependency_ordinals
                .entry(dependency.view_oid)
                .and_modify(|value| *value += 1)
                .or_insert(1);
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "postgres_dependency_type",
                dependency.dependency_type.to_string(),
            );
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::Extension("postgres_catalog_dependency".to_owned()),
                from_key: owner_key.clone(),
                to_key: target_key,
                ordinal: Some(*ordinal),
                properties,
            });
        }

        let mut routine_keys = BTreeMap::new();
        for routine in &raw.routines {
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &routine.schema,
                ObjectKind::Routine,
                &routine.name,
                Some(routine.identity_arguments.clone()),
            );
            if routine_keys.insert(routine.oid, key).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate PostgreSQL routine oid {}",
                    routine.oid
                )));
            }
        }
        let mut routines = Vec::new();
        let mut routine_position_by_oid = BTreeMap::new();
        for routine in &raw.routines {
            let schema_key = required(
                schema_keys.get(&routine.schema),
                format!("schema key for routine {}.{}", routine.schema, routine.name),
            )?;
            let key = required(
                routine_keys.get(&routine.oid),
                format!("routine key oid {}", routine.oid),
            )?;
            routine_position_by_oid.insert(routine.oid, routines.len());
            routines.push(RoutineObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: routine.name.clone(),
                kind: if routine.kind == 'p' {
                    RoutineKind::Procedure
                } else {
                    RoutineKind::Function
                },
                definition: routine.definition.clone(),
                depends_on: Vec::new(),
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key.clone(),
                definition: None,
                properties: routine_properties(routine),
            });
            add_owned_by(
                &mut metadata.relationships,
                key,
                routine.owner_oid,
                &principal_keys,
                "routine",
            )?;
            if let Some(return_type_key) = type_keys.get(&routine.return_type_oid) {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::ReturnsType,
                    from_key: key.clone(),
                    to_key: return_type_key.clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            } else if !is_system_schema(&routine.return_type_schema) {
                return Err(CatalogError::Mapping(format!(
                    "routine {}.{} returns type outside the certified schema scope (type oid {})",
                    routine.schema, routine.name, routine.return_type_oid
                )));
            }
        }

        for parameter in &raw.routine_parameters {
            let routine_key = required(
                routine_keys.get(&parameter.routine_oid),
                format!("parameter parent routine oid {}", parameter.routine_oid),
            )?;
            let ordinal = u32::try_from(parameter.ordinal).map_err(|_| {
                CatalogError::Mapping(format!(
                    "routine parameter ordinal {} is invalid",
                    parameter.ordinal
                ))
            })?;
            if ordinal == 0 {
                return Err(CatalogError::Mapping(
                    "routine parameter ordinal cannot be zero".to_owned(),
                ));
            }
            let display_name = parameter
                .name
                .clone()
                .unwrap_or_else(|| format!("argument_{ordinal}"));
            let identity = format!(
                "{}#{}:{}",
                routine_key.sub_object.as_deref().unwrap_or_default(),
                ordinal,
                display_name
            );
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &routine_key.schema,
                ObjectKind::RoutineParameter,
                &routine_key.object_name,
                Some(identity),
            );
            let mut properties = BTreeMap::new();
            insert_u64(&mut properties, "ordinal_position", ordinal as u64);
            insert_string(
                &mut properties,
                "mode",
                routine_parameter_mode(parameter.mode),
            );
            insert_string(&mut properties, "data_type", &parameter.data_type);
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(routine_key.clone()),
                name: display_name,
                extension_kind: None,
                definition: None,
                properties,
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::HasParameter,
                from_key: routine_key.clone(),
                to_key: key.clone(),
                ordinal: Some(ordinal),
                properties: BTreeMap::new(),
            });
            add_type_use(
                &mut metadata.relationships,
                &key,
                parameter.type_oid,
                &parameter.type_schema,
                &type_keys,
            )?;
        }

        let mut routine_dependency_ordinals = BTreeMap::<i64, u32>::new();
        for dependency in &raw.routine_dependencies {
            let position = required(
                routine_position_by_oid.get(&dependency.owner_oid),
                format!("routine dependency owner oid {}", dependency.owner_oid),
            )?;
            let Some(target) = resolve_routine_dependency(
                dependency,
                &relation_keys,
                &column_keys,
                &routine_keys,
                &type_keys,
            )?
            else {
                continue;
            };
            routines[*position].depends_on.push(target.clone());
            let ordinal = routine_dependency_ordinals
                .entry(dependency.owner_oid)
                .and_modify(|value| *value += 1)
                .or_insert(1);
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "postgres_dependency_type",
                dependency.dependency_type.to_string(),
            );
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::Extension("postgres_catalog_dependency".to_owned()),
                from_key: routines[*position].key.clone(),
                to_key: target,
                ordinal: Some(*ordinal),
                properties,
            });
        }

        let mut triggers = Vec::new();
        for trigger in &raw.triggers {
            let relation_key = required(
                relation_keys.get(&trigger.relation_oid),
                format!("trigger target relation oid {}", trigger.relation_oid),
            )?;
            if !matches!(
                relation_key.object_kind,
                ObjectKind::Table | ObjectKind::View
            ) {
                return Err(CatalogError::Mapping(format!(
                    "trigger {} target kind {} is unsupported",
                    trigger.name, relation_key.object_kind
                )));
            }
            let routine_key = required(
                routine_keys.get(&trigger.routine_oid),
                format!(
                    "trigger {} invokes routine outside the certified schema scope (oid {})",
                    trigger.name, trigger.routine_oid
                ),
            )?;
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &relation_key.schema,
                ObjectKind::Trigger,
                &relation_key.object_name,
                Some(trigger.name.clone()),
            );
            triggers.push(TriggerObject {
                key: key.clone(),
                table_key: relation_key.clone(),
                name: trigger.name.clone(),
                timing: Some(trigger.timing.clone()),
                events: trigger.events.clone(),
                definition: trigger.definition.clone(),
                executes_routine_key: Some(routine_key.clone()),
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties: trigger_properties(trigger, &column_keys)?,
            });
        }

        for inheritance in &raw.inheritance {
            let child = required(
                table_keys.get(&inheritance.child_oid),
                format!("inheritance child table oid {}", inheritance.child_oid),
            )?;
            let parent = required(
                table_keys.get(&inheritance.parent_oid),
                format!(
                    "table {} inherits from a parent outside the certified schema scope (oid {})",
                    child.object_name, inheritance.parent_oid
                ),
            )?;
            let mut properties = BTreeMap::new();
            insert_i64(
                &mut properties,
                "sequence_number",
                i64::from(inheritance.sequence_number),
            );
            metadata.relationships.push(MetadataRelationship {
                kind: if inheritance.child_is_partition {
                    MetadataRelationshipKind::PartitionOf
                } else {
                    MetadataRelationshipKind::InheritsFrom
                },
                from_key: child.clone(),
                to_key: parent.clone(),
                ordinal: None,
                properties,
            });
        }

        for usage in &raw.sequence_usages {
            let column = required(
                column_keys.get(&(usage.column_relation_oid, usage.column_number)),
                format!(
                    "sequence usage source column {}:{}",
                    usage.column_relation_oid, usage.column_number
                ),
            )?;
            if column.object_kind != ObjectKind::Column {
                return Err(CatalogError::Mapping(format!(
                    "sequence usage source {} is not a table column",
                    column
                )));
            }
            let sequence = required(
                sequence_keys.get(&usage.sequence_oid),
                format!(
                    "column {} uses sequence outside the certified schema scope (oid {})",
                    column, usage.sequence_oid
                ),
            )?;
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "postgres_dependency_type",
                usage.dependency_type.to_string(),
            );
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::UsesSequence,
                from_key: column.clone(),
                to_key: sequence.clone(),
                ordinal: None,
                properties,
            });
        }

        add_type_relationships(
            &raw,
            &mut metadata.relationships,
            &type_keys,
            &relation_keys,
        )?;

        for policy in &raw.policies {
            let parent = required(
                relation_keys.get(&policy.relation_oid),
                format!("policy target relation oid {}", policy.relation_oid),
            )?;
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &parent.schema,
                ObjectKind::Policy,
                &parent.object_name,
                Some(policy.name.clone()),
            );
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "postgres_oid", policy.oid);
            insert_string(&mut properties, "command", policy_command(policy.command));
            insert_bool(&mut properties, "permissive", policy.permissive);
            insert_optional_string(
                &mut properties,
                "using_expression",
                policy.using_expression.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "check_expression",
                policy.check_expression.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(parent.clone()),
                name: policy.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            for role_oid in &policy.role_oids {
                if *role_oid == 0 {
                    continue;
                }
                let role = required(
                    principal_keys.get(role_oid),
                    format!("policy {} role oid {role_oid}", policy.name),
                )?;
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::Extension("postgres_policy_role".to_owned()),
                    from_key: key.clone(),
                    to_key: role.clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        for extension in &raw.extensions {
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &database_name,
                ObjectKind::Extension,
                &extension.name,
                None,
            );
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "postgres_oid", extension.oid);
            insert_optional_string(&mut properties, "schema", extension.schema.as_deref());
            insert_bool(&mut properties, "relocatable", extension.relocatable);
            insert_string(&mut properties, "version", &extension.version);
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(database_key.clone()),
                name: extension.name.clone(),
                extension_kind: Some("postgres_extension".to_owned()),
                definition: None,
                properties,
            });
            add_owned_by(
                &mut metadata.relationships,
                &key,
                extension.owner_oid,
                &principal_keys,
                "extension",
            )?;
        }

        for event in &raw.event_triggers {
            let routine = required(
                routine_keys.get(&event.routine_oid),
                format!(
                    "event trigger {} invokes routine outside the certified schema scope ({}. oid {})",
                    event.name, event.routine_schema, event.routine_oid
                ),
            )?;
            let key = pg_key(
                self.connection_alias,
                &database_name,
                &database_name,
                ObjectKind::Event,
                &event.name,
                None,
            );
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "postgres_oid", event.oid);
            insert_string(&mut properties, "event", &event.event);
            insert_string(&mut properties, "enabled", event.enabled.to_string());
            properties.insert(
                "tags".to_owned(),
                MetadataValue::StringList(event.tags.clone()),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(database_key.clone()),
                name: event.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            add_owned_by(
                &mut metadata.relationships,
                &key,
                event.owner_oid,
                &principal_keys,
                "event trigger",
            )?;
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::Invokes,
                from_key: key,
                to_key: routine.clone(),
                ordinal: None,
                properties: BTreeMap::new(),
            });
        }

        deduplicate_metadata_relationships(&mut metadata.relationships)?;
        let snapshot = CanonicalSchemaSnapshot {
            schema: SchemaSnapshot {
                source_kind: POSTGRES_SOURCE.to_owned(),
                connection_alias: self.connection_alias.to_owned(),
                database,
                schemas,
                tables,
                columns,
                constraints,
                indexes,
                views,
                triggers,
                routines,
                capabilities: postgres_complete_capabilities(),
            },
            metadata,
        };
        let discovered_counts = discovery_counts_from_catalog(&raw, &snapshot)?;
        let mut scope_schemas = raw
            .schemas
            .iter()
            .map(|schema| schema.name.clone())
            .collect::<Vec<_>>();
        scope_schemas.sort();

        Ok(CatalogDiscovery {
            snapshot,
            adapter: AdapterIdentity {
                name: "database-memory-postgres-catalog".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            server: ServerIdentity {
                product: "PostgreSQL".to_owned(),
                version: raw.server.version.clone(),
            },
            scope: IntrospectionScope {
                catalogs: vec![database_name],
                schemas: scope_schemas.clone(),
            },
            discovered_counts,
            capability_checks: vec![
                CapabilityCheck {
                    name: "supported_server_version".to_owned(),
                    evidence: format!(
                        "server_version_num={} maps to certified PostgreSQL major {} using strategy {}",
                        raw.server.version_num,
                        raw.catalog_version.major(),
                        raw.catalog_version.strategy_name()
                    ),
                },
                CapabilityCheck {
                    name: "read_only_repeatable_read_transaction".to_owned(),
                    evidence: format!(
                        "transaction_read_only={} and transaction_isolation={}",
                        raw.server.transaction_read_only, raw.server.transaction_isolation
                    ),
                },
                CapabilityCheck {
                    name: "schema_visibility".to_owned(),
                    evidence: format!(
                        "has_schema_privilege(..., USAGE) succeeded for {} requested schema(s)",
                        scope_schemas.len()
                    ),
                },
                CapabilityCheck {
                    name: "metadata_only_catalog_queries".to_owned(),
                    evidence: "adapter queried pg_catalog metadata and server information only; no application relation appears in a FROM clause"
                        .to_owned(),
                },
                CapabilityCheck {
                    name: "routine_dependency_proof".to_owned(),
                    evidence: format!(
                        "all {} selected routine(s) use catalog-tracked SQL-standard bodies; opaque bodies fail before certification",
                        raw.routines.len()
                    ),
                },
                CapabilityCheck {
                    name: "principal_context".to_owned(),
                    evidence: format!(
                        "current_user={} session_user={} and pg_roles inventory was readable",
                        raw.server.current_user, raw.server.session_user
                    ),
                },
                CapabilityCheck {
                    name: "transport_security".to_owned(),
                    evidence: if raw.server.tls {
                        format!(
                            "TLS enabled version={} cipher={}",
                            raw.server.tls_version.as_deref().unwrap_or("reported"),
                            raw.server.tls_cipher.as_deref().unwrap_or("reported")
                        )
                    } else {
                        "plaintext transport accepted only for a loopback/local connection"
                            .to_owned()
                    },
                },
            ],
        })
    }
}

fn validate_raw_catalog(raw: &RawPostgresCatalog) -> Result<(), CatalogError> {
    if raw.server.major() != raw.catalog_version.major() {
        return Err(CatalogError::Mapping(format!(
            "PostgreSQL server major {} does not match selected catalog strategy {}",
            raw.server.major(),
            raw.catalog_version.strategy_name()
        )));
    }
    if !raw.server.transaction_read_only || raw.server.transaction_isolation != "repeatable read" {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "PostgreSQL metadata transaction is not read-only repeatable-read (read_only={}, isolation={})",
            raw.server.transaction_read_only, raw.server.transaction_isolation
        )));
    }
    for relation in &raw.relations {
        if relation.definition_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "definition for {}.{} exceeds {MAX_DEFINITION_BYTES} bytes",
                relation.schema, relation.name
            )));
        }
        validate_property_text(
            &format!(
                "relation {}.{} partition bound",
                relation.schema, relation.name
            ),
            relation.partition_bound.as_deref(),
        )?;
        validate_property_text(
            &format!("relation {}.{} comment", relation.schema, relation.name),
            relation.comment.as_deref(),
        )?;
    }
    for schema in &raw.schemas {
        validate_property_text(
            &format!("schema {} comment", schema.name),
            schema.comment.as_deref(),
        )?;
    }
    for column in &raw.columns {
        if column.default_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "default/generated expression for {}.{}.{} exceeds {MAX_DEFINITION_BYTES} bytes",
                column.schema, column.relation, column.name
            )));
        }
        validate_property_text(
            &format!(
                "column {}.{}.{} comment",
                column.schema, column.relation, column.name
            ),
            column.comment.as_deref(),
        )?;
    }
    for constraint in &raw.constraints {
        if constraint.definition_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "constraint definition {} exceeds {MAX_DEFINITION_BYTES} bytes",
                constraint.name
            )));
        }
    }
    for index in &raw.indexes {
        if index.definition_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "index definition {}.{}.{} exceeds {MAX_DEFINITION_BYTES} bytes",
                index.schema, index.relation, index.name
            )));
        }
    }
    for term in &raw.index_terms {
        validate_property_text("index term definition", Some(&term.definition))?;
    }
    for raw_type in &raw.types {
        if raw_type.default_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "type default {}.{} exceeds {MAX_PROPERTY_STRING_BYTES} bytes",
                raw_type.schema, raw_type.name
            )));
        }
        validate_property_text(
            &format!("type {}.{} comment", raw_type.schema, raw_type.name),
            raw_type.comment.as_deref(),
        )?;
    }
    let opaque = raw
        .routines
        .iter()
        .filter(|routine| !routine.body_catalog_tracked)
        .map(|routine| {
            format!(
                "{}.{}({}) language={} kind={}",
                routine.schema,
                routine.name,
                routine.identity_arguments,
                routine.language,
                routine.kind
            )
        })
        .take(10)
        .collect::<Vec<_>>();
    if !opaque.is_empty() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "routine body dependencies are not catalog-proven for: {}",
            opaque.join(", ")
        )));
    }
    for routine in &raw.routines {
        if routine.definition_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "routine definition {}.{}({}) exceeds {MAX_DEFINITION_BYTES} bytes",
                routine.schema, routine.name, routine.identity_arguments
            )));
        }
        validate_property_text(
            &format!("routine {} arguments", routine.name),
            Some(&routine.arguments_definition),
        )?;
    }
    for trigger in &raw.triggers {
        if trigger.definition_too_large {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "trigger definition {} exceeds {MAX_DEFINITION_BYTES} bytes",
                trigger.name
            )));
        }
        validate_property_text(
            &format!("trigger {} WHEN expression", trigger.name),
            trigger.when_expression.as_deref(),
        )?;
    }
    for policy in &raw.policies {
        validate_property_text(
            &format!("policy {} USING expression", policy.name),
            policy.using_expression.as_deref(),
        )?;
        validate_property_text(
            &format!("policy {} WITH CHECK expression", policy.name),
            policy.check_expression.as_deref(),
        )?;
    }
    Ok(())
}

fn validate_property_text(subject: &str, value: Option<&str>) -> Result<(), CatalogError> {
    if value
        .map(|value| value.len() > MAX_PROPERTY_STRING_BYTES as usize)
        .unwrap_or(false)
    {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "{subject} exceeds {MAX_PROPERTY_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}

fn pg_key(
    connection_alias: &str,
    database: &str,
    schema: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        POSTGRES_SOURCE,
        connection_alias,
        database,
        schema,
        object_kind,
        object_name,
        sub_object,
    )
}

fn required<T>(value: Option<&T>, subject: impl Into<String>) -> Result<&T, CatalogError> {
    value.ok_or_else(|| CatalogError::Mapping(format!("unresolved {0}", subject.into())))
}

fn insert_bool(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: bool) {
    properties.insert(key.to_owned(), MetadataValue::Boolean(value));
}

fn insert_i64(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: i64) {
    properties.insert(key.to_owned(), MetadataValue::Integer(value));
}

fn insert_u64(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: u64) {
    properties.insert(key.to_owned(), MetadataValue::Unsigned(value));
}

fn insert_string(
    properties: &mut BTreeMap<String, MetadataValue>,
    key: &str,
    value: impl AsRef<str>,
) {
    properties.insert(
        key.to_owned(),
        MetadataValue::String(value.as_ref().to_owned()),
    );
}

fn insert_optional_string(
    properties: &mut BTreeMap<String, MetadataValue>,
    key: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        insert_string(properties, key, value);
    }
}

fn positive_u32(value: i16, subject: &str) -> Result<u32, CatalogError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| CatalogError::Mapping(format!("{subject} must be positive, got {value}")))
}

fn type_kind_name(kind: char) -> &'static str {
    match kind {
        'b' => "base",
        'c' => "composite",
        'd' => "domain",
        'e' => "enum",
        'r' => "range",
        'm' => "multirange",
        _ => "unrecognized",
    }
}

fn table_kind(relation: &RawRelation) -> TableKind {
    if relation.is_partition {
        TableKind::Partition
    } else {
        match relation.relkind {
            'p' => TableKind::Partitioned,
            'f' => TableKind::Foreign,
            _ => TableKind::BaseTable,
        }
    }
}

fn relation_properties(relation: &RawRelation) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "postgres_oid", relation.oid);
    insert_string(
        &mut properties,
        "relation_kind",
        relation.relkind.to_string(),
    );
    insert_string(
        &mut properties,
        "persistence",
        match relation.persistence {
            'u' => "unlogged",
            't' => "temporary",
            _ => "permanent",
        },
    );
    insert_bool(&mut properties, "partition", relation.is_partition);
    insert_bool(&mut properties, "row_security", relation.row_security);
    insert_bool(
        &mut properties,
        "force_row_security",
        relation.force_row_security,
    );
    insert_string(
        &mut properties,
        "replica_identity",
        relation.replica_identity.to_string(),
    );
    insert_optional_string(
        &mut properties,
        "partition_bound",
        relation.partition_bound.as_deref(),
    );
    insert_optional_string(&mut properties, "comment", relation.comment.as_deref());
    properties
}

fn relation_annotation(relation: &RawRelation, key: &ObjectKey) -> ObjectAnnotation {
    ObjectAnnotation {
        object_key: key.clone(),
        definition: None,
        properties: relation_properties(relation),
    }
}

fn column_properties(column: &RawColumn) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(
        &mut properties,
        "postgres_attribute_number",
        i64::from(column.attnum),
    );
    insert_string(
        &mut properties,
        "generated",
        match column.generated {
            's' => "stored",
            'v' => "virtual",
            _ => "none",
        },
    );
    insert_string(
        &mut properties,
        "identity",
        match column.identity {
            'a' => "always",
            'd' => "by_default",
            _ => "none",
        },
    );
    insert_optional_string(&mut properties, "collation", column.collation.as_deref());
    insert_optional_string(
        &mut properties,
        "compression",
        column.compression.as_deref(),
    );
    let statistics_target_mode = match column.statistics_target {
        PostgresStatisticsTarget::Default => "default",
        PostgresStatisticsTarget::Disabled => "disabled",
        PostgresStatisticsTarget::Custom(_) => "custom",
    };
    insert_string(
        &mut properties,
        "statistics_target_mode",
        statistics_target_mode,
    );
    if let PostgresStatisticsTarget::Custom(value) = column.statistics_target {
        insert_i64(&mut properties, "statistics_target", i64::from(value));
    } else if column.statistics_target == PostgresStatisticsTarget::Disabled {
        insert_i64(&mut properties, "statistics_target", 0);
    }
    insert_optional_string(&mut properties, "comment", column.comment.as_deref());
    if column.generated != '\0' {
        insert_optional_string(
            &mut properties,
            "generation_expression",
            column.default_expression.as_deref(),
        );
    }
    if let Some(default_oid) = column.default_oid {
        insert_i64(&mut properties, "postgres_default_oid", default_oid);
    }
    properties
}

fn column_annotation(column: &RawColumn, key: &ObjectKey) -> ObjectAnnotation {
    ObjectAnnotation {
        object_key: key.clone(),
        definition: None,
        properties: column_properties(column),
    }
}

fn add_owned_by(
    relationships: &mut Vec<MetadataRelationship>,
    object: &ObjectKey,
    owner_oid: i64,
    principals: &BTreeMap<i64, ObjectKey>,
    subject: &str,
) -> Result<(), CatalogError> {
    let owner = required(
        principals.get(&owner_oid),
        format!("owner principal oid {owner_oid} for {subject} {object}"),
    )?;
    relationships.push(MetadataRelationship {
        kind: MetadataRelationshipKind::OwnedBy,
        from_key: object.clone(),
        to_key: owner.clone(),
        ordinal: None,
        properties: BTreeMap::new(),
    });
    Ok(())
}

fn add_type_use(
    relationships: &mut Vec<MetadataRelationship>,
    object: &ObjectKey,
    type_oid: i64,
    type_schema: &str,
    types: &BTreeMap<i64, ObjectKey>,
) -> Result<(), CatalogError> {
    if let Some(target) = types.get(&type_oid) {
        relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::UsesType,
            from_key: object.clone(),
            to_key: target.clone(),
            ordinal: None,
            properties: BTreeMap::new(),
        });
    } else if !is_system_schema(type_schema) {
        return Err(CatalogError::Mapping(format!(
            "{} uses type outside the certified schema scope ({}. oid {})",
            object, type_schema, type_oid
        )));
    }
    Ok(())
}

fn relation_row_type_oid(
    relations: &[RawRelation],
    relation_oid: i64,
) -> Result<i64, CatalogError> {
    relations
        .iter()
        .find(|relation| relation.oid == relation_oid)
        .map(|relation| relation.row_type_oid)
        .ok_or_else(|| {
            CatalogError::Mapping(format!("unresolved relation oid {relation_oid} row type"))
        })
}

fn constraint_properties(constraint: &RawConstraint) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "postgres_oid", constraint.oid);
    insert_bool(&mut properties, "deferrable", constraint.deferrable);
    insert_bool(
        &mut properties,
        "initially_deferred",
        constraint.initially_deferred,
    );
    insert_bool(&mut properties, "validated", constraint.validated);
    insert_bool(&mut properties, "no_inherit", constraint.no_inherit);
    if constraint.kind == 'f' {
        insert_string(
            &mut properties,
            "on_delete",
            foreign_key_action(constraint.delete_action),
        );
        insert_string(
            &mut properties,
            "on_update",
            foreign_key_action(constraint.update_action),
        );
        insert_string(
            &mut properties,
            "match_type",
            foreign_key_match(constraint.match_type),
        );
    }
    properties
}

fn foreign_key_action(value: char) -> &'static str {
    match value {
        'a' => "no_action",
        'r' => "restrict",
        'c' => "cascade",
        'n' => "set_null",
        'd' => "set_default",
        _ => "not_applicable",
    }
}

fn foreign_key_match(value: char) -> &'static str {
    match value {
        'f' => "full",
        'p' => "partial",
        's' => "simple",
        _ => "not_applicable",
    }
}

fn resolve_columns(
    relation_oid: i64,
    column_numbers: &[i16],
    columns: &BTreeMap<(i64, i32), ObjectKey>,
    subject: &str,
) -> Result<Vec<ObjectKey>, CatalogError> {
    column_numbers
        .iter()
        .enumerate()
        .map(|(position, column_number)| {
            if *column_number <= 0 {
                return Err(CatalogError::Mapping(format!(
                    "{subject} contains expression/system column number {column_number} at ordinal {}",
                    position + 1
                )));
            }
            required(
                columns.get(&(relation_oid, i32::from(*column_number))),
                format!("{subject} column number {column_number}"),
            )
            .cloned()
        })
        .collect()
}

fn group_index_terms(index_terms: &[RawIndexTerm]) -> BTreeMap<i64, Vec<&RawIndexTerm>> {
    let mut grouped = BTreeMap::<i64, Vec<&RawIndexTerm>>::new();
    for term in index_terms {
        grouped.entry(term.index_oid).or_default().push(term);
    }
    grouped
}

fn index_properties(index: &RawIndex, terms: &[&RawIndexTerm]) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "postgres_oid", index.oid);
    insert_string(&mut properties, "access_method", &index.access_method);
    insert_bool(&mut properties, "unique", index.unique);
    insert_bool(&mut properties, "primary", index.primary);
    insert_bool(&mut properties, "exclusion", index.exclusion);
    insert_bool(&mut properties, "immediate", index.immediate);
    insert_bool(&mut properties, "clustered", index.clustered);
    insert_bool(&mut properties, "valid", index.valid);
    insert_bool(&mut properties, "ready", index.ready);
    insert_bool(&mut properties, "live", index.live);
    insert_bool(&mut properties, "replica_identity", index.replica_identity);
    insert_bool(
        &mut properties,
        "nulls_not_distinct",
        index.nulls_not_distinct,
    );
    insert_i64(
        &mut properties,
        "key_term_count",
        i64::from(index.key_count),
    );
    properties.insert(
        "terms".to_owned(),
        MetadataValue::StringList(
            terms
                .iter()
                .map(|term| {
                    format!(
                        "{}|{}|{}|{}|{}|{}|{}|{}",
                        term.ordinal,
                        if term.is_key { "key" } else { "include" },
                        term.column_name.as_deref().unwrap_or_default(),
                        term.definition,
                        if term.descending { "desc" } else { "asc" },
                        if term.nulls_first {
                            "nulls_first"
                        } else {
                            "nulls_last"
                        },
                        term.operator_class.as_deref().unwrap_or_default(),
                        term.collation.as_deref().unwrap_or_default()
                    )
                })
                .collect(),
        ),
    );
    properties
}

fn add_included_columns(
    relationships: &mut Vec<MetadataRelationship>,
    index_key: &ObjectKey,
    index: &RawIndex,
    terms: &[&RawIndexTerm],
    columns: &BTreeMap<(i64, i32), ObjectKey>,
    _materialized_view: bool,
) -> Result<(), CatalogError> {
    for term in terms {
        if term.column_number <= 0 {
            continue;
        }
        let column = required(
            columns.get(&(index.relation_oid, i32::from(term.column_number))),
            format!("index {} term ordinal {}", index.name, term.ordinal),
        )?;
        let mut properties = BTreeMap::new();
        insert_string(
            &mut properties,
            "role",
            if term.is_key { "key" } else { "include" },
        );
        insert_string(&mut properties, "definition", &term.definition);
        insert_bool(&mut properties, "descending", term.descending);
        insert_bool(&mut properties, "nulls_first", term.nulls_first);
        insert_optional_string(
            &mut properties,
            "operator_class",
            term.operator_class.as_deref(),
        );
        insert_optional_string(&mut properties, "collation", term.collation.as_deref());
        relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::IncludesColumn,
            from_key: index_key.clone(),
            to_key: column.clone(),
            ordinal: Some(positive_u32(term.ordinal, "index term ordinal")?),
            properties,
        });
    }
    Ok(())
}

fn resolve_relation_dependency(
    relation_oid: i64,
    column_number: i32,
    target_schema: &str,
    relations: &BTreeMap<i64, ObjectKey>,
    columns: &BTreeMap<(i64, i32), ObjectKey>,
) -> Result<Option<ObjectKey>, CatalogError> {
    if is_system_schema(target_schema) {
        return Ok(None);
    }
    if column_number > 0 {
        return required(
            columns.get(&(relation_oid, column_number)),
            format!(
                "dependency target column outside the certified schema scope ({}. oid {}:{})",
                target_schema, relation_oid, column_number
            ),
        )
        .cloned()
        .map(Some);
    }
    required(
        relations.get(&relation_oid),
        format!(
            "dependency target relation outside the certified schema scope ({}. oid {})",
            target_schema, relation_oid
        ),
    )
    .cloned()
    .map(Some)
}

fn routine_properties(routine: &RawRoutine) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "postgres_oid", routine.oid);
    insert_string(
        &mut properties,
        "routine_kind",
        match routine.kind {
            'p' => "procedure",
            'a' => "aggregate",
            'w' => "window",
            _ => "function",
        },
    );
    insert_string(&mut properties, "language", &routine.language);
    insert_string(
        &mut properties,
        "identity_arguments",
        &routine.identity_arguments,
    );
    insert_string(&mut properties, "arguments", &routine.arguments_definition);
    insert_optional_string(
        &mut properties,
        "return_type",
        routine.return_type.as_deref(),
    );
    insert_bool(&mut properties, "returns_set", routine.returns_set);
    insert_bool(
        &mut properties,
        "security_definer",
        routine.security_definer,
    );
    insert_bool(&mut properties, "leakproof", routine.leakproof);
    insert_bool(&mut properties, "strict", routine.strict);
    insert_string(
        &mut properties,
        "volatility",
        match routine.volatility {
            'i' => "immutable",
            's' => "stable",
            _ => "volatile",
        },
    );
    insert_string(
        &mut properties,
        "parallel",
        match routine.parallel {
            's' => "safe",
            'r' => "restricted",
            _ => "unsafe",
        },
    );
    insert_bool(
        &mut properties,
        "body_catalog_tracked",
        routine.body_catalog_tracked,
    );
    properties
}

fn routine_parameter_mode(mode: char) -> &'static str {
    match mode {
        'o' => "out",
        'b' => "inout",
        'v' => "variadic",
        't' => "table",
        _ => "in",
    }
}

fn resolve_routine_dependency(
    dependency: &RawDependency,
    relations: &BTreeMap<i64, ObjectKey>,
    columns: &BTreeMap<(i64, i32), ObjectKey>,
    routines: &BTreeMap<i64, ObjectKey>,
    types: &BTreeMap<i64, ObjectKey>,
) -> Result<Option<ObjectKey>, CatalogError> {
    let schema = dependency.target_schema.as_deref().unwrap_or_default();
    if is_system_schema(schema) {
        return Ok(None);
    }
    let target = match dependency.target_class.as_str() {
        "relation" if dependency.target_sub_id > 0 => columns
            .get(&(dependency.target_oid, dependency.target_sub_id))
            .cloned(),
        "relation" => relations.get(&dependency.target_oid).cloned(),
        "routine" => routines.get(&dependency.target_oid).cloned(),
        "type" => types.get(&dependency.target_oid).cloned(),
        other => {
            return Err(CatalogError::Mapping(format!(
                "unsupported routine dependency target class '{other}'"
            )));
        }
    };
    target.map(Some).ok_or_else(|| {
        CatalogError::Mapping(format!(
            "routine dependency points outside the certified schema scope (class={}, schema={}, oid={}, subid={})",
            dependency.target_class,
            schema,
            dependency.target_oid,
            dependency.target_sub_id
        ))
    })
}

fn trigger_properties(
    trigger: &RawTrigger,
    columns: &BTreeMap<(i64, i32), ObjectKey>,
) -> Result<BTreeMap<String, MetadataValue>, CatalogError> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "postgres_oid", trigger.oid);
    insert_string(&mut properties, "orientation", &trigger.orientation);
    insert_string(&mut properties, "enabled", trigger.enabled.to_string());
    insert_optional_string(
        &mut properties,
        "when_expression",
        trigger.when_expression.as_deref(),
    );
    let update_columns = trigger
        .update_columns
        .iter()
        .map(|column_number| {
            required(
                columns.get(&(trigger.relation_oid, i32::from(*column_number))),
                format!(
                    "trigger {} UPDATE OF column number {}",
                    trigger.name, column_number
                ),
            )
            .map(|key| {
                key.sub_object
                    .clone()
                    .unwrap_or_else(|| key.object_name.clone())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !update_columns.is_empty() {
        properties.insert(
            "update_columns".to_owned(),
            MetadataValue::StringList(update_columns),
        );
    }
    Ok(properties)
}

fn add_type_relationships(
    raw: &RawPostgresCatalog,
    relationships: &mut Vec<MetadataRelationship>,
    types: &BTreeMap<i64, ObjectKey>,
    relations: &BTreeMap<i64, ObjectKey>,
) -> Result<(), CatalogError> {
    for raw_type in &raw.types {
        let source = required(
            types.get(&raw_type.oid),
            format!("type relationship source oid {}", raw_type.oid),
        )?;
        for (target_oid, target_schema, relation_name) in [
            (
                raw_type.base_type_oid,
                raw_type.base_type_schema.as_deref(),
                "domain_base_type",
            ),
            (
                raw_type.element_type_oid,
                raw_type.element_type_schema.as_deref(),
                "element_type",
            ),
            (
                raw_type.range_subtype_oid,
                raw_type.range_subtype_schema.as_deref(),
                "range_subtype",
            ),
            (
                raw_type.multirange_type_oid,
                raw_type.multirange_type_schema.as_deref(),
                "multirange_type",
            ),
        ] {
            let Some(target_oid) = target_oid else {
                continue;
            };
            if target_oid == raw_type.oid {
                continue;
            }
            if let Some(target) = types.get(&target_oid) {
                let mut properties = BTreeMap::new();
                insert_string(&mut properties, "role", relation_name);
                relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: source.clone(),
                    to_key: target.clone(),
                    ordinal: None,
                    properties,
                });
            } else if !target_schema.map(is_system_schema).unwrap_or(true) {
                return Err(CatalogError::Mapping(format!(
                    "type {} depends on type outside the certified schema scope ({}. oid {})",
                    source,
                    target_schema.unwrap_or_default(),
                    target_oid
                )));
            }
        }
        if let Some(relation_oid) = raw_type.relation_oid {
            if let Some(relation) = relations.get(&relation_oid) {
                relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: source.clone(),
                    to_key: relation.clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }
    }
    Ok(())
}

fn policy_command(command: char) -> &'static str {
    match command {
        'r' => "select",
        'a' => "insert",
        'w' => "update",
        'd' => "delete",
        _ => "all",
    }
}

fn is_system_schema(schema: &str) -> bool {
    schema == "information_schema" || schema.starts_with("pg_")
}

fn is_base_snapshot_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Database
            | ObjectKind::Schema
            | ObjectKind::Table
            | ObjectKind::Column
            | ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::UniqueConstraint
            | ObjectKind::CheckConstraint
            | ObjectKind::Index
            | ObjectKind::View
            | ObjectKind::Trigger
            | ObjectKind::Routine
    )
}

fn deduplicate_metadata_relationships(
    relationships: &mut [MetadataRelationship],
) -> Result<(), CatalogError> {
    relationships.sort_by_key(|relationship| {
        (
            relationship.kind.clone(),
            relationship.from_key.to_string(),
            relationship.to_key.to_string(),
            relationship.ordinal,
        )
    });
    for pair in relationships.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        if left.kind == right.kind
            && left.from_key == right.from_key
            && left.to_key == right.to_key
            && left.ordinal == right.ordinal
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate canonical metadata relationship {}:{}->{}",
                left.kind.graph_edge_type(),
                left.from_key,
                left.to_key
            )));
        }
    }
    Ok(())
}

fn postgres_complete_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: POSTGRES_SOURCE.to_owned(),
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
        limitations: Vec::new(),
        notes: vec![
            "Reads pg_catalog metadata in one read-only repeatable-read transaction; application rows are never queried."
                .to_owned(),
            "Routine dependency completeness requires a PostgreSQL catalog-tracked SQL-standard body; opaque language bodies fail certification."
                .to_owned(),
            "System-schema implementation dependencies are outside the declared application schema scope."
                .to_owned(),
        ],
    }
}

fn discovery_counts_from_catalog(
    raw: &RawPostgresCatalog,
    snapshot: &CanonicalSchemaSnapshot,
) -> Result<DiscoveryCounts, CatalogError> {
    let relation_kinds = raw
        .relations
        .iter()
        .map(|relation| (relation.oid, relation.relkind))
        .collect::<BTreeMap<_, _>>();
    let mut objects = ObjectCategory::ALL
        .into_iter()
        .map(|category| (category, 0_u64))
        .collect::<BTreeMap<_, _>>();
    objects.insert(ObjectCategory::Database, 1);
    objects.insert(ObjectCategory::Schema, raw.schemas.len() as u64);
    objects.insert(
        ObjectCategory::Table,
        raw.relations
            .iter()
            .filter(|relation| matches!(relation.relkind, 'r' | 'p' | 'f'))
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::Column,
        raw.columns
            .iter()
            .filter(|column| matches!(column.relation_kind, 'r' | 'p' | 'f'))
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::PrimaryKey,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'p')
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::ForeignKey,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'f')
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::UniqueConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'u')
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::CheckConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'c')
            .count() as u64,
    );
    objects.insert(ObjectCategory::Index, raw.indexes.len() as u64);
    objects.insert(
        ObjectCategory::View,
        raw.relations
            .iter()
            .filter(|relation| relation.relkind == 'v')
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::ViewColumn,
        raw.columns
            .iter()
            .filter(|column| matches!(column.relation_kind, 'v' | 'm'))
            .count() as u64,
    );
    objects.insert(ObjectCategory::Trigger, raw.triggers.len() as u64);
    objects.insert(ObjectCategory::Routine, raw.routines.len() as u64);
    objects.insert(
        ObjectCategory::MaterializedView,
        raw.relations
            .iter()
            .filter(|relation| relation.relkind == 'm')
            .count() as u64,
    );
    objects.insert(ObjectCategory::Sequence, raw.sequences.len() as u64);
    objects.insert(
        ObjectCategory::RoutineParameter,
        raw.routine_parameters.len() as u64,
    );
    objects.insert(
        ObjectCategory::UserDefinedType,
        raw.types
            .iter()
            .filter(|raw_type| raw_type.kind != 'd')
            .count() as u64,
    );
    objects.insert(
        ObjectCategory::Domain,
        raw.types
            .iter()
            .filter(|raw_type| raw_type.kind == 'd')
            .count() as u64,
    );
    objects.insert(ObjectCategory::EnumValue, raw.enum_values.len() as u64);
    objects.insert(
        ObjectCategory::ExclusionConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'x')
            .count() as u64,
    );
    objects.insert(ObjectCategory::Event, raw.event_triggers.len() as u64);
    objects.insert(ObjectCategory::Principal, raw.principals.len() as u64);
    objects.insert(ObjectCategory::Policy, raw.policies.len() as u64);
    objects.insert(
        ObjectCategory::Extension,
        (raw.extensions.len()
            + raw
                .columns
                .iter()
                .filter(|column| column.relation_kind == 'c')
                .count()) as u64,
    );

    let emitted_objects = emitted_object_counts(snapshot);
    for category in ObjectCategory::ALL {
        let discovered = objects.get(&category).copied().unwrap_or_default();
        let emitted = emitted_objects.get(&category).copied().unwrap_or_default();
        if discovered != emitted {
            return Err(CatalogError::Mapping(format!(
                "PostgreSQL raw/emitted object count mismatch for {category:?}: discovered={discovered}, emitted={emitted}"
            )));
        }
    }

    let mut relationships = emitted_relationship_counts(snapshot);
    relationships.insert(
        RelationshipCategory::DatabaseHasSchema,
        raw.schemas.len() as u64,
    );
    relationships.insert(
        RelationshipCategory::SchemaHasTable,
        raw.relations
            .iter()
            .filter(|relation| matches!(relation.relkind, 'r' | 'p' | 'f'))
            .count() as u64,
    );
    relationships.insert(
        RelationshipCategory::TableHasColumn,
        raw.columns
            .iter()
            .filter(|column| matches!(column.relation_kind, 'r' | 'p' | 'f'))
            .count() as u64,
    );
    relationships.insert(
        RelationshipCategory::TableHasConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.relation_oid.is_some() && constraint.kind != 'x')
            .count() as u64,
    );
    relationships.insert(
        RelationshipCategory::ConstraintColumn,
        raw.constraints
            .iter()
            .filter(|constraint| {
                constraint.relation_oid.is_some() && matches!(constraint.kind, 'p' | 'u' | 'c')
            })
            .map(|constraint| constraint.columns.len() as u64)
            .sum(),
    );
    relationships.insert(
        RelationshipCategory::ForeignKeyColumnPair,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.kind == 'f')
            .map(|constraint| constraint.columns.len() as u64)
            .sum(),
    );
    relationships.insert(
        RelationshipCategory::TableHasIndex,
        raw.indexes
            .iter()
            .filter(|index| {
                relation_kinds
                    .get(&index.relation_oid)
                    .map(|kind| matches!(kind, 'r' | 'p' | 'f'))
                    .unwrap_or(false)
            })
            .count() as u64,
    );
    let base_index_oids = raw
        .indexes
        .iter()
        .filter(|index| {
            relation_kinds
                .get(&index.relation_oid)
                .map(|kind| matches!(kind, 'r' | 'p' | 'f'))
                .unwrap_or(false)
        })
        .map(|index| index.oid)
        .collect::<BTreeSet<_>>();
    let unique_index_columns = raw
        .index_terms
        .iter()
        .filter(|term| {
            base_index_oids.contains(&term.index_oid) && term.is_key && term.column_number > 0
        })
        .map(|term| (term.index_oid, term.column_number))
        .collect::<BTreeSet<_>>();
    relationships.insert(
        RelationshipCategory::IndexColumn,
        unique_index_columns.len() as u64,
    );
    relationships.insert(
        RelationshipCategory::SchemaHasView,
        raw.relations
            .iter()
            .filter(|relation| relation.relkind == 'v')
            .count() as u64,
    );
    relationships.insert(
        RelationshipCategory::ViewDependency,
        raw.view_dependencies
            .iter()
            .filter(|dependency| {
                !is_system_schema(&dependency.target_schema)
                    && relation_kinds.get(&dependency.view_oid) == Some(&'v')
                    && relation_kinds
                        .get(&dependency.target_relation_oid)
                        .map(|kind| {
                            if dependency.target_column_number > 0 {
                                matches!(kind, 'r' | 'p' | 'f')
                            } else {
                                matches!(kind, 'r' | 'p' | 'f' | 'v')
                            }
                        })
                        .unwrap_or(false)
            })
            .map(|dependency| {
                (
                    dependency.view_oid,
                    dependency.target_relation_oid,
                    dependency.target_column_number,
                )
            })
            .collect::<BTreeSet<_>>()
            .len() as u64,
    );
    relationships.insert(
        RelationshipCategory::TriggerTarget,
        raw.triggers.len() as u64,
    );
    relationships.insert(
        RelationshipCategory::TriggerRoutine,
        raw.triggers.len() as u64,
    );
    relationships.insert(
        RelationshipCategory::SchemaHasRoutine,
        raw.routines.len() as u64,
    );
    relationships.insert(
        RelationshipCategory::RoutineDependency,
        raw.routine_dependencies
            .iter()
            .filter(|dependency| {
                !dependency
                    .target_schema
                    .as_deref()
                    .map(is_system_schema)
                    .unwrap_or(true)
            })
            .map(|dependency| {
                (
                    dependency.owner_oid,
                    dependency.target_class.clone(),
                    dependency.target_oid,
                    dependency.target_sub_id,
                )
            })
            .collect::<BTreeSet<_>>()
            .len() as u64,
    );

    let emitted_relationships = emitted_relationship_counts(snapshot);
    for category in RelationshipCategory::ALL {
        let discovered = relationships.get(&category).copied().unwrap_or_default();
        let emitted = emitted_relationships
            .get(&category)
            .copied()
            .unwrap_or_default();
        if discovered != emitted {
            return Err(CatalogError::Mapping(format!(
                "PostgreSQL raw/emitted relationship count mismatch for {category:?}: discovered={discovered}, emitted={emitted}"
            )));
        }
    }

    Ok(DiscoveryCounts {
        objects: objects
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: format!(
                            "PostgreSQL pg_catalog raw object inventory for {category:?} in the declared schema scope"
                        ),
                    },
                )
            })
            .collect(),
        relationships: relationships
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: format!(
                            "PostgreSQL pg_catalog relationship ledger for {category:?} in the declared schema scope"
                        ),
                    },
                )
            })
            .collect(),
    })
}

#[cfg(test)]
mod version_strategy_tests {
    use super::*;

    #[test]
    fn only_explicitly_certified_postgres_majors_select_a_strategy() {
        for major in MIN_SUPPORTED_MAJOR..=MAX_SUPPORTED_MAJOR {
            let strategy = PostgresCatalogVersion::detect(major * 10_000).unwrap();
            assert_eq!(strategy.major(), major);
        }
        assert!(matches!(
            PostgresCatalogVersion::detect(130_000),
            Err(CatalogError::UnsupportedVersion(13))
        ));
        assert!(matches!(
            PostgresCatalogVersion::detect(190_000),
            Err(CatalogError::UnsupportedVersion(19))
        ));
    }

    #[test]
    fn statistics_target_representation_is_normalized_by_version() {
        assert_eq!(
            PostgresCatalogVersion::V16
                .statistics_target(Some(-1))
                .unwrap(),
            PostgresStatisticsTarget::Default
        );
        assert_eq!(
            PostgresCatalogVersion::V17.statistics_target(None).unwrap(),
            PostgresStatisticsTarget::Default
        );
        assert_eq!(
            PostgresCatalogVersion::V18
                .statistics_target(Some(0))
                .unwrap(),
            PostgresStatisticsTarget::Disabled
        );
        assert_eq!(
            PostgresCatalogVersion::V14
                .statistics_target(Some(200))
                .unwrap(),
            PostgresStatisticsTarget::Custom(200)
        );
        assert!(PostgresCatalogVersion::V16.statistics_target(None).is_err());
        assert!(PostgresCatalogVersion::V17
            .statistics_target(Some(-1))
            .is_err());
    }
}
