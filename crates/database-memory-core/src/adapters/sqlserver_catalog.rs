use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use connection_string::AdoNetString;
use sqlparser::dialect::MsSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, Tokenizer};
use tiberius::{Client, Config, FromSql, Row};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

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

const SQLSERVER_SOURCE: &str = "sqlserver";
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_DEFINITION_BYTES: i32 = 1_048_576;
const MAX_PROPERTY_STRING_BYTES: usize = 65_536;
const SQLSERVER_ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

type TdsClient = Client<Compat<TcpStream>>;

pub(crate) struct SqlServerCatalogAdapter {
    connection_string: String,
}

impl SqlServerCatalogAdapter {
    pub(crate) fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
        }
    }
}

impl CatalogIntrospector for SqlServerCatalogAdapter {
    fn source_kind(&self) -> &'static str {
        SQLSERVER_SOURCE
    }

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        self.discover_with_cancellation(request, &CancellationToken::new())
    }

    fn discover_with_cancellation(
        &mut self,
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        cancellation.checkpoint(
            SQLSERVER_SOURCE,
            &request.connection_alias,
            AnalysisStage::Configuration,
        )?;
        validate_request(request)?;
        validate_connection_policy(request, &self.connection_string)?;
        run_catalog_discovery(&self.connection_string, request, cancellation)
    }
}

pub(crate) fn analyze_sqlserver(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_sqlserver_with_cancellation(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
        &CancellationToken::new(),
    )
}

pub(crate) fn analyze_sqlserver_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs,
        requested_schemas,
        timeout_ms,
    };
    DatabaseAnalysisService::new(SqlServerCatalogAdapter::new(connection_string))
        .analyze_with_cancellation(&request, cancellation)
}

fn run_catalog_discovery(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    let connection_string = connection_string.to_owned();
    let request = request.clone();
    let cancellation = cancellation.clone();
    if tokio::runtime::Handle::try_current().is_ok() {
        let worker_request = request.clone();
        let worker_cancellation = cancellation.clone();
        return std::thread::spawn(move || {
            run_catalog_discovery_on_runtime(
                &connection_string,
                &worker_request,
                &worker_cancellation,
            )
        })
        .join()
        .map_err(|_| internal_failure(&request, "SQL Server adapter worker thread panicked"))?;
    }
    run_catalog_discovery_on_runtime(&connection_string, &request, &cancellation)
}

fn run_catalog_discovery_on_runtime(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| internal_failure(request, error.to_string()))?;
    runtime.block_on(async {
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancellation.clone()) => {
                Err(cancelled_failure(request))
            }
            result = tokio::time::timeout(
                Duration::from_millis(request.timeout_ms),
                discover_catalog_async(connection_string, request, cancellation),
            ) => match result {
                Ok(result) => result,
                Err(_) => Err(AnalysisFailure::redacted(
                    AnalysisFailureCode::Timeout,
                    AnalysisStage::Discovery,
                    SQLSERVER_SOURCE,
                    &request.connection_alias,
                    format!(
                        "SQL Server metadata analysis exceeded the {} ms timeout",
                        request.timeout_ms
                    ),
                    "increase the bounded timeout or reduce the requested schema scope",
                    true,
                    Some(connection_string),
                )),
            },
        }
    })
}

async fn wait_for_cancellation(cancellation: CancellationToken) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn cancelled_failure(request: &IntrospectionRequest) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::Cancelled,
        AnalysisStage::Discovery,
        SQLSERVER_SOURCE,
        &request.connection_alias,
        "SQL Server metadata analysis was cancelled",
        "start a new analysis when the result is still needed",
        true,
        None,
    )
}

async fn discover_catalog_async(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    let mut client = connect_sqlserver(connection_string, request).await?;
    cancellation.checkpoint(
        SQLSERVER_SOURCE,
        &request.connection_alias,
        AnalysisStage::Connection,
    )?;
    configure_session(&mut client, request)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    verify_metadata_privileges(&mut client)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    let facts = ServerFacts::read(&mut client)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    let strategy = SqlServerCatalogVersion::detect(&facts)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    validate_scope(request, &facts.database)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    let available_schemas = read_schemas(&mut client)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    let selected_schemas = select_schemas(request, &available_schemas)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    cancellation.checkpoint(
        SQLSERVER_SOURCE,
        &request.connection_alias,
        AnalysisStage::CapabilityProbe,
    )?;

    let first = RawSqlServerCatalog::read(&mut client, strategy, &selected_schemas)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    cancellation.checkpoint(
        SQLSERVER_SOURCE,
        &request.connection_alias,
        AnalysisStage::Discovery,
    )?;
    let second = RawSqlServerCatalog::read(&mut client, strategy, &selected_schemas)
        .await
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    let stable = require_stable_catalog(first, &second)
        .map_err(|error| catalog_failure(request, connection_string, error))?;
    cancellation.checkpoint(
        SQLSERVER_SOURCE,
        &request.connection_alias,
        AnalysisStage::Mapping,
    )?;

    SqlServerSnapshotMapper::new(&request.connection_alias, facts, strategy)
        .map(stable)
        .map_err(|error| catalog_failure(request, connection_string, error))
}

fn require_stable_catalog<T: PartialEq>(first: T, second: &T) -> Result<T, CatalogError> {
    if &first != second {
        return Err(CatalogError::CatalogChanged(
            "SQL Server catalog changed while metadata was being collected".to_owned(),
        ));
    }
    Ok(first)
}

async fn connect_sqlserver(
    connection_string: &str,
    request: &IntrospectionRequest,
) -> Result<TdsClient, AnalysisFailure> {
    let mut config = Config::from_ado_string(connection_string).map_err(|error| {
        connection_failure(request, connection_string, error.to_string(), false)
    })?;
    config.readonly(true);
    config.application_name("database-memory-mcp");
    let tcp = TcpStream::connect(config.get_addr())
        .await
        .map_err(|error| connection_failure(request, connection_string, error.to_string(), true))?;
    tcp.set_nodelay(true)
        .map_err(|error| connection_failure(request, connection_string, error.to_string(), true))?;
    Client::connect(config, tcp.compat_write())
        .await
        .map_err(|error| {
            classify_tiberius_error(request, connection_string, error, AnalysisStage::Connection)
        })
}

async fn configure_session(
    client: &mut TdsClient,
    request: &IntrospectionRequest,
) -> Result<(), CatalogError> {
    let lock_timeout = request.timeout_ms.min(i32::MAX as u64);
    let statement = format!(
        "SET NOCOUNT ON; SET XACT_ABORT ON; SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCK_TIMEOUT {lock_timeout};"
    );
    client.simple_query(statement).await?.into_results().await?;
    Ok(())
}

fn validate_request(request: &IntrospectionRequest) -> Result<(), AnalysisFailure> {
    if request.timeout_ms > MAX_INTROSPECTION_TIMEOUT_MS {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            format!(
                "SQL Server introspection timeout exceeds the {MAX_INTROSPECTION_TIMEOUT_MS} ms safety limit"
            ),
            "choose a timeout between 1 ms and 86400000 ms",
            false,
            None,
        ));
    }
    if has_duplicates(&request.requested_catalogs) || has_duplicates(&request.requested_schemas) {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            "SQL Server scope contains duplicate catalog or schema names",
            "provide each requested catalog and schema exactly once",
            false,
            None,
        ));
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    values.len() != values.iter().collect::<BTreeSet<_>>().len()
}

fn validate_connection_policy(
    request: &IntrospectionRequest,
    connection_string: &str,
) -> Result<(), AnalysisFailure> {
    let values = connection_string.parse::<AdoNetString>().map_err(|error| {
        connection_failure(request, connection_string, error.to_string(), false)
    })?;
    let database = values
        .get("database")
        .or_else(|| values.get("initial catalog"))
        .or_else(|| values.get("databasename"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    if database.is_none() {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            "SQL Server connection string must select one database",
            "set Database or Initial Catalog explicitly",
            false,
            Some(connection_string),
        ));
    }

    let config = Config::from_ado_string(connection_string).map_err(|error| {
        connection_failure(request, connection_string, error.to_string(), false)
    })?;
    let address = config.get_addr();
    let host = host_from_address(&address);
    let remote = !is_loopback_host(host);
    let encrypt = connection_bool(&values, "encrypt").unwrap_or(false);
    let trust_server_certificate =
        connection_bool(&values, "trustservercertificate").unwrap_or(false);
    if remote && (!encrypt || trust_server_certificate) {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Configuration,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            "remote SQL Server connections require encrypted transport with certificate validation",
            "set Encrypt=true and TrustServerCertificate=false, then trust the server CA",
            false,
            Some(connection_string),
        ));
    }
    Ok(())
}

fn connection_bool(values: &AdoNetString, key: &str) -> Option<bool> {
    values
        .get(key)
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" => Some(true),
            "false" | "no" => Some(false),
            _ => None,
        })
}

fn host_from_address(address: &str) -> &str {
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn validate_scope(
    request: &IntrospectionRequest,
    current_database: &str,
) -> Result<(), CatalogError> {
    if request.requested_catalogs.is_empty()
        || request.requested_catalogs == [current_database.to_owned()]
    {
        return Ok(());
    }
    Err(CatalogError::InvalidScope(format!(
        "SQL Server analysis is bound to current database '{current_database}'; requested catalogs were {}",
        request.requested_catalogs.join(", ")
    )))
}

fn select_schemas(
    request: &IntrospectionRequest,
    available: &[RawSchema],
) -> Result<BTreeSet<String>, CatalogError> {
    let names = available
        .iter()
        .map(|schema| schema.name.clone())
        .collect::<BTreeSet<_>>();
    if request.requested_schemas.is_empty() {
        return Ok(names);
    }
    let missing = request
        .requested_schemas
        .iter()
        .filter(|schema| !names.contains(*schema))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CatalogError::InvalidScope(format!(
            "requested SQL Server schemas are missing or system-owned: {}",
            missing.join(", ")
        )));
    }
    Ok(request.requested_schemas.iter().cloned().collect())
}

#[derive(Debug)]
enum CatalogError {
    Query(tiberius::error::Error),
    InvalidScope(String),
    PermissionDenied(String),
    UnsupportedProduct(String),
    UnsupportedVersion(i32),
    UnsupportedMetadata(String),
    CatalogChanged(String),
    Mapping(String),
}

impl From<tiberius::error::Error> for CatalogError {
    fn from(error: tiberius::error::Error) -> Self {
        Self::Query(error)
    }
}

fn connection_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    message: String,
    retryable: bool,
) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::ConnectionFailed,
        AnalysisStage::Connection,
        SQLSERVER_SOURCE,
        &request.connection_alias,
        message,
        "verify the SQL Server connection settings, endpoint, credentials, and TLS policy",
        retryable,
        Some(connection_string),
    )
}

fn classify_tiberius_error(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: tiberius::error::Error,
    stage: AnalysisStage,
) -> AnalysisFailure {
    let code = error.code();
    let (failure_code, retryable, remediation) = match code {
        Some(18456) => (
            AnalysisFailureCode::AuthenticationFailed,
            false,
            "verify the SQL Server principal and secret",
        ),
        Some(229 | 15151 | 916) => (
            AnalysisFailureCode::PermissionDenied,
            false,
            "grant database metadata visibility and dependency catalog access",
        ),
        Some(1222) => (
            AnalysisFailureCode::Timeout,
            true,
            "retry after concurrent schema work finishes or increase the bounded timeout",
        ),
        Some(1205) => (
            AnalysisFailureCode::MetadataQueryFailed,
            true,
            "retry the metadata-only analysis after the deadlock victim transaction ends",
        ),
        _ if stage == AnalysisStage::Connection => (
            AnalysisFailureCode::ConnectionFailed,
            true,
            "verify the SQL Server endpoint and TLS policy, then retry",
        ),
        _ => (
            AnalysisFailureCode::MetadataQueryFailed,
            true,
            "inspect the SQL Server state and retry the metadata-only analysis",
        ),
    };
    AnalysisFailure::redacted(
        failure_code,
        stage,
        SQLSERVER_SOURCE,
        &request.connection_alias,
        error.to_string(),
        remediation,
        retryable,
        Some(connection_string),
    )
}

fn catalog_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: CatalogError,
) -> AnalysisFailure {
    match error {
        CatalogError::Query(error) => classify_tiberius_error(
            request,
            connection_string,
            error,
            AnalysisStage::Discovery,
        ),
        CatalogError::InvalidScope(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::CapabilityProbe,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "select the current database and existing non-system schemas",
            false,
            Some(connection_string),
        ),
        CatalogError::PermissionDenied(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::PermissionDenied,
            AnalysisStage::CapabilityProbe,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "grant VIEW DEFINITION on the database and SELECT on sys.sql_expression_dependencies",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedProduct(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedProduct,
            AnalysisStage::CapabilityProbe,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "use a certified SQL Server Database Engine product or add a live-tested product strategy",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedVersion(major) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedVersion,
            AnalysisStage::CapabilityProbe,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            format!("SQL Server major version {major} is not yet certified"),
            "use SQL Server 2022 while additional major-version strategies are being certified",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedMetadata(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedMetadata,
            AnalysisStage::CapabilityProbe,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "remove or replace the unprovable construct, or extend and live-test the SQL Server strategy",
            false,
            Some(connection_string),
        ),
        CatalogError::CatalogChanged(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::CompletenessMismatch,
            AnalysisStage::Discovery,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "retry after concurrent DDL has completed",
            true,
            Some(connection_string),
        ),
        CatalogError::Mapping(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::MetadataMappingFailed,
            AnalysisStage::Mapping,
            SQLSERVER_SOURCE,
            &request.connection_alias,
            message,
            "fix every SQL Server catalog mapping before retrying",
            false,
            Some(connection_string),
        ),
    }
}

fn internal_failure(request: &IntrospectionRequest, message: impl AsRef<str>) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::Internal,
        AnalysisStage::Discovery,
        SQLSERVER_SOURCE,
        &request.connection_alias,
        message,
        "restart the analysis and inspect the adapter runtime if the failure repeats",
        true,
        None,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServerFacts {
    database: String,
    version: String,
    major: i32,
    engine_edition: i32,
    edition: String,
    current_user: String,
    login: String,
    original_login: String,
    collation: String,
    compatibility_level: u8,
    database_read_only: bool,
    containment: String,
    encrypted_transport: bool,
}

impl ServerFacts {
    async fn read(client: &mut TdsClient) -> Result<Self, CatalogError> {
        let row = query_one(
            client,
            "
            SELECT DB_NAME(),
                   CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)),
                   CAST(SERVERPROPERTY('ProductMajorVersion') AS int),
                   CAST(SERVERPROPERTY('EngineEdition') AS int),
                   CAST(SERVERPROPERTY('Edition') AS nvarchar(128)),
                   USER_NAME(),
                   SUSER_SNAME(),
                   ORIGINAL_LOGIN(),
                   d.collation_name,
                   d.compatibility_level,
                   d.is_read_only,
                   d.containment_desc,
                   CASE WHEN CONNECTIONPROPERTY('encrypt_option') = 'TRUE'
                        THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END
            FROM sys.databases d
            WHERE d.database_id = DB_ID()
            ",
        )
        .await?;
        Ok(Self {
            database: required_string(&row, 0, "database")?,
            version: required_string(&row, 1, "product version")?,
            major: required_value(&row, 2, "product major version")?,
            engine_edition: required_value(&row, 3, "engine edition")?,
            edition: required_string(&row, 4, "edition")?,
            current_user: required_string(&row, 5, "current user")?,
            login: required_string(&row, 6, "login")?,
            original_login: required_string(&row, 7, "original login")?,
            collation: required_string(&row, 8, "database collation")?,
            compatibility_level: required_value(&row, 9, "compatibility level")?,
            database_read_only: required_value(&row, 10, "database read-only state")?,
            containment: required_string(&row, 11, "containment")?,
            encrypted_transport: required_value(&row, 12, "transport encryption state")?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqlServerCatalogVersion {
    V2017,
    V2019,
    V2022,
    V2025,
}

impl SqlServerCatalogVersion {
    fn detect(facts: &ServerFacts) -> Result<Self, CatalogError> {
        if !matches!(facts.engine_edition, 2..=4) {
            return Err(CatalogError::UnsupportedProduct(format!(
                "SQL Server engine edition {} ({}) is not in the live-certified Database Engine matrix",
                facts.engine_edition, facts.edition
            )));
        }
        match facts.major {
            14 => Ok(Self::V2017),
            15 => Ok(Self::V2019),
            16 => Ok(Self::V2022),
            17 => Ok(Self::V2025),
            major => Err(CatalogError::UnsupportedVersion(major)),
        }
    }

    fn strategy_name(self) -> &'static str {
        match self {
            Self::V2017 => "sqlserver-2017",
            Self::V2019 => "sqlserver-2019",
            Self::V2022 => "sqlserver-2022",
            Self::V2025 => "sqlserver-2025",
        }
    }

    fn ledger_expression(self) -> &'static str {
        match self {
            Self::V2017 | Self::V2019 => "N'NONE'",
            Self::V2022 | Self::V2025 => "t.ledger_type_desc",
        }
    }

    fn xml_compression_expression(self) -> &'static str {
        match self {
            Self::V2017 | Self::V2019 => "N'OFF'",
            Self::V2022 | Self::V2025 => "p.xml_compression_desc",
        }
    }

    fn routine_inline_expressions(self) -> (&'static str, &'static str) {
        match self {
            Self::V2017 => ("CAST(0 AS bit)", "CAST(0 AS bit)"),
            Self::V2019 | Self::V2022 | Self::V2025 => (
                "COALESCE(m.is_inlineable, CAST(0 AS bit))",
                "CASE WHEN COALESCE(m.inline_type, 0) = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END",
            ),
        }
    }

    fn edge_constraint_union(self) -> &'static str {
        match self {
            Self::V2017 => "",
            Self::V2019 | Self::V2022 | Self::V2025 => {
                "UNION ALL
                 SELECT s.name, ec.name, N'EC', N'EDGE_CONSTRAINT'
                 FROM sys.edge_constraints ec
                 JOIN sys.schemas s ON s.schema_id = ec.schema_id"
            }
        }
    }
}

async fn verify_metadata_privileges(client: &mut TdsClient) -> Result<(), CatalogError> {
    let row = query_one(
        client,
        "
        SELECT HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION'),
               HAS_PERMS_BY_NAME(N'sys.sql_expression_dependencies', 'OBJECT', 'SELECT')
        ",
    )
    .await?;
    let view_definition: i32 = required_value(&row, 0, "VIEW DEFINITION probe")?;
    let dependency_select: i32 = required_value(&row, 1, "dependency SELECT probe")?;
    if view_definition != 1 || dependency_select != 1 {
        return Err(CatalogError::PermissionDenied(format!(
            "effective metadata permissions are incomplete: VIEW DEFINITION={view_definition}, dependency catalog SELECT={dependency_select}"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSchema {
    id: i32,
    name: String,
    principal_id: i32,
}

async fn read_schemas(client: &mut TdsClient) -> Result<Vec<RawSchema>, CatalogError> {
    rows(
        client,
        "
        SELECT s.schema_id, s.name, s.principal_id
        FROM sys.schemas s
        LEFT JOIN sys.database_principals p ON p.principal_id = s.principal_id
        WHERE s.name NOT IN (N'sys', N'INFORMATION_SCHEMA', N'guest')
          AND NOT (COALESCE(p.is_fixed_role, 0) = 1 AND p.name = s.name)
        ORDER BY s.schema_id
    ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawSchema {
            id: required_value(&row, 0, "schema id")?,
            name: required_string(&row, 1, "schema name")?,
            principal_id: required_value(&row, 2, "schema owner")?,
        })
    })
    .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPrincipal {
    id: i32,
    name: String,
    type_code: String,
    type_desc: String,
    default_schema: Option<String>,
    authentication_type: String,
    fixed_role: bool,
    owning_principal_id: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTable {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    lob_data_space_id: i32,
    filestream_data_space_id: Option<i32>,
    replicated: bool,
    merge_published: bool,
    sync_tran_subscribed: bool,
    cdc_tracked: bool,
    lock_on_bulk_load: bool,
    file_table: bool,
    memory_optimized: bool,
    durability: String,
    temporal_type: String,
    history_schema: Option<String>,
    history_table: Option<String>,
    remote_data_archive: bool,
    external: bool,
    node: bool,
    edge: bool,
    ledger_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawColumn {
    object_id: i32,
    object_type: String,
    schema: String,
    relation: String,
    id: i32,
    name: String,
    type_id: i32,
    type_schema: String,
    type_name: String,
    max_length: i16,
    precision: u8,
    scale: u8,
    collation: Option<String>,
    nullable: bool,
    ansi_padded: bool,
    rowguid: bool,
    identity: bool,
    identity_seed: Option<String>,
    identity_increment: Option<String>,
    computed: bool,
    computed_definition: Option<String>,
    computed_definition_bytes: i32,
    persisted: Option<bool>,
    default_definition: Option<String>,
    default_definition_bytes: i32,
    default_object_id: i32,
    filestream: bool,
    replicated: bool,
    non_sql_subscribed: bool,
    merge_published: bool,
    dts_replicated: bool,
    xml_document: bool,
    xml_collection_id: i32,
    sparse: bool,
    column_set: bool,
    generated_always: String,
    encryption_type: Option<String>,
    hidden: bool,
    masked: bool,
    masking_function: Option<String>,
    graph_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawConstraint {
    id: i32,
    schema: String,
    table: String,
    table_id: i32,
    name: String,
    kind: ConstraintKind,
    columns: Vec<RawConstraintColumn>,
    referenced_schema: Option<String>,
    referenced_table: Option<String>,
    referenced_table_id: Option<i32>,
    delete_action: Option<String>,
    update_action: Option<String>,
    disabled: bool,
    not_trusted: bool,
    not_for_replication: bool,
    expression: Option<String>,
    expression_bytes: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawConstraintColumn {
    ordinal: i32,
    column_id: i32,
    name: String,
    referenced_column_id: Option<i32>,
    referenced_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndex {
    object_id: i32,
    schema: String,
    relation: String,
    relation_type: String,
    id: i32,
    name: String,
    type_code: u8,
    type_desc: String,
    unique: bool,
    primary: bool,
    unique_constraint: bool,
    disabled: bool,
    hypothetical: bool,
    padded: bool,
    fill_factor: u8,
    ignore_duplicate_key: bool,
    allow_row_locks: bool,
    allow_page_locks: bool,
    auto_created: bool,
    filter: Option<String>,
    filter_bytes: i32,
    data_space_id: i32,
    columns: Vec<RawIndexColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndexColumn {
    index_column_id: i32,
    column_id: i32,
    name: String,
    key_ordinal: i32,
    partition_ordinal: i32,
    descending: bool,
    included: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawView {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    replicated: bool,
    replication_filter: bool,
    schema_bound: bool,
    ansi_nulls: bool,
    quoted_identifier: bool,
    execute_as_principal_id: Option<i32>,
    definition: Option<String>,
    definition_bytes: i32,
    indexed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawRoutine {
    id: i32,
    schema: String,
    name: String,
    type_code: String,
    type_desc: String,
    principal_id: Option<i32>,
    schema_bound: bool,
    recompiled: bool,
    native_compilation: bool,
    ansi_nulls: bool,
    quoted_identifier: bool,
    execute_as_principal_id: Option<i32>,
    null_on_null_input: bool,
    inlineable: bool,
    inline_type: bool,
    startup: bool,
    replication: bool,
    definition: Option<String>,
    definition_bytes: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawParameter {
    object_id: i32,
    id: i32,
    name: String,
    type_id: i32,
    type_schema: String,
    type_name: String,
    max_length: i16,
    precision: u8,
    scale: u8,
    output: bool,
    readonly: bool,
    nullable: bool,
    default_value: Option<String>,
    xml_collection_id: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTrigger {
    id: i32,
    name: String,
    parent_class: i32,
    parent_id: i32,
    parent_schema: Option<String>,
    parent_name: Option<String>,
    parent_type: Option<String>,
    instead_of: bool,
    disabled: bool,
    not_for_replication: bool,
    schema_bound: bool,
    execute_as_principal_id: Option<i32>,
    definition: Option<String>,
    definition_bytes: i32,
    insert_event: bool,
    update_event: bool,
    delete_event: bool,
    events: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawUserType {
    id: i32,
    schema: String,
    name: String,
    system_type_id: u8,
    base_type: String,
    max_length: i16,
    precision: u8,
    scale: u8,
    collation: Option<String>,
    nullable: bool,
    user_defined: bool,
    assembly: bool,
    table_type: bool,
    table_object_id: Option<i32>,
    memory_optimized: bool,
    default_object_id: i32,
    rule_object_id: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSequence {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    type_id: i32,
    type_schema: String,
    type_name: String,
    precision: u8,
    scale: u8,
    start_value: String,
    increment: String,
    minimum_value: String,
    maximum_value: String,
    cyclic: bool,
    cache_size: Option<i32>,
    exhausted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSynonym {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    base_object_name: String,
    server: Option<String>,
    database: Option<String>,
    target_schema: Option<String>,
    target_entity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawDependency {
    referencing_class: i32,
    referencing_id: i32,
    referencing_minor_id: i32,
    referenced_class: i32,
    referenced_server: Option<String>,
    referenced_database: Option<String>,
    referenced_schema: Option<String>,
    referenced_entity: String,
    referenced_id: Option<i32>,
    referenced_minor_id: i32,
    schema_bound: bool,
    caller_dependent: bool,
    ambiguous: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionFunction {
    id: i32,
    name: String,
    fanout: i32,
    boundary_on_right: bool,
    system: bool,
    values: Vec<RawPartitionValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionValue {
    boundary_id: i32,
    value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionScheme {
    id: i32,
    name: String,
    function_id: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartition {
    object_id: i32,
    index_id: i32,
    partition_number: i32,
    data_compression: String,
    xml_compression: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSecurityPolicy {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    enabled: bool,
    schema_bound: bool,
    predicates: Vec<RawSecurityPredicate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSecurityPredicate {
    id: i32,
    target_object_id: i32,
    predicate_type: String,
    operation: Option<String>,
    definition: String,
    definition_bytes: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlSchemaCollection {
    id: i32,
    schema: String,
    name: String,
    principal_id: Option<i32>,
    created_at: String,
    modified_at: String,
    namespaces: Vec<RawXmlSchemaNamespace>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawXmlSchemaNamespace {
    id: i32,
    name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawExtendedProperty {
    class: u8,
    class_description: String,
    major_id: i32,
    minor_id: i32,
    name: String,
    value_type: Option<String>,
    value_precision: Option<i32>,
    value_scale: Option<i32>,
    value_max_length: Option<i32>,
    value_collation: Option<String>,
    display_value: Option<String>,
    value_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawUnsupportedObject {
    schema: Option<String>,
    name: String,
    type_code: String,
    type_desc: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSqlServerCatalog {
    schemas: Vec<RawSchema>,
    principals: Vec<RawPrincipal>,
    tables: Vec<RawTable>,
    columns: Vec<RawColumn>,
    constraints: Vec<RawConstraint>,
    indexes: Vec<RawIndex>,
    views: Vec<RawView>,
    routines: Vec<RawRoutine>,
    parameters: Vec<RawParameter>,
    triggers: Vec<RawTrigger>,
    user_types: Vec<RawUserType>,
    sequences: Vec<RawSequence>,
    synonyms: Vec<RawSynonym>,
    dependencies: Vec<RawDependency>,
    partition_functions: Vec<RawPartitionFunction>,
    partition_schemes: Vec<RawPartitionScheme>,
    partitions: Vec<RawPartition>,
    security_policies: Vec<RawSecurityPolicy>,
    xml_schema_collections: Vec<RawXmlSchemaCollection>,
    extended_properties: Vec<RawExtendedProperty>,
}

impl RawSqlServerCatalog {
    async fn read(
        client: &mut TdsClient,
        strategy: SqlServerCatalogVersion,
        selected_schemas: &BTreeSet<String>,
    ) -> Result<Self, CatalogError> {
        let schemas = read_schemas(client)
            .await?
            .into_iter()
            .filter(|schema| selected_schemas.contains(&schema.name))
            .collect::<Vec<_>>();
        let principals = read_principals(client).await?;
        let tables = read_tables(client, strategy, selected_schemas).await?;
        let columns = read_columns(client, selected_schemas).await?;
        let constraints = read_constraints(client, selected_schemas).await?;
        let indexes = read_indexes(client, selected_schemas).await?;
        let views = read_views(client, selected_schemas).await?;
        let routines = read_routines(client, strategy, selected_schemas).await?;
        let parameters = read_parameters(client, &routines).await?;
        let triggers = read_triggers(client, selected_schemas).await?;
        let user_types = read_user_types(client, selected_schemas).await?;
        let sequences = read_sequences(client, selected_schemas).await?;
        let synonyms = read_synonyms(client, selected_schemas).await?;
        let dependencies = read_dependencies(client, selected_schemas).await?;
        let partition_functions = read_partition_functions(client).await?;
        let partition_schemes = read_partition_schemes(client).await?;
        let partitions = read_partitions(client, strategy, &tables, &views).await?;
        let security_policies = read_security_policies(client, selected_schemas).await?;
        let xml_schema_collections = read_xml_schema_collections(client, selected_schemas).await?;
        let extended_properties = select_extended_properties(
            read_extended_properties(client).await?,
            &schemas,
            &principals,
            &tables,
            &columns,
            &constraints,
            &indexes,
            &views,
            &routines,
            &parameters,
            &triggers,
            &user_types,
            &sequences,
            &synonyms,
            &partition_functions,
            &partition_schemes,
            &security_policies,
            &xml_schema_collections,
        );
        let unsupported = read_unsupported_objects(client, strategy, selected_schemas).await?;
        validate_supported_metadata(
            &unsupported,
            &views,
            &routines,
            &triggers,
            &user_types,
            &dependencies,
        )?;
        Ok(Self {
            schemas,
            principals,
            tables,
            columns,
            constraints,
            indexes,
            views,
            routines,
            parameters,
            triggers,
            user_types,
            sequences,
            synonyms,
            dependencies,
            partition_functions,
            partition_schemes,
            partitions,
            security_policies,
            xml_schema_collections,
            extended_properties,
        })
    }
}

async fn read_principals(client: &mut TdsClient) -> Result<Vec<RawPrincipal>, CatalogError> {
    rows(
        client,
        "
        SELECT principal_id,
               name,
               RTRIM(type),
               type_desc,
               default_schema_name,
               authentication_type_desc,
               is_fixed_role,
               owning_principal_id
        FROM sys.database_principals
        WHERE principal_id > 0
          AND name IS NOT NULL
        ORDER BY principal_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawPrincipal {
            id: required_value(&row, 0, "principal id")?,
            name: required_string(&row, 1, "principal name")?,
            type_code: required_string(&row, 2, "principal type")?,
            type_desc: required_string(&row, 3, "principal type description")?,
            default_schema: optional_string(&row, 4)?,
            authentication_type: required_string(&row, 5, "authentication type")?,
            fixed_role: required_value(&row, 6, "fixed role flag")?,
            owning_principal_id: optional_value(&row, 7)?,
        })
    })
    .collect()
}

async fn read_tables(
    client: &mut TdsClient,
    strategy: SqlServerCatalogVersion,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawTable>, CatalogError> {
    let ledger_column = strategy.ledger_expression();
    let sql = format!(
        "
        SELECT t.object_id,
               s.name,
               t.name,
               t.principal_id,
               t.lob_data_space_id,
               NULLIF(t.filestream_data_space_id, 0),
               t.is_replicated,
               t.is_merge_published,
               t.is_sync_tran_subscribed,
               t.is_tracked_by_cdc,
               t.lock_on_bulk_load,
               t.is_filetable,
               t.is_memory_optimized,
               t.durability_desc,
               t.temporal_type_desc,
               hs.name,
               ht.name,
               t.is_remote_data_archive_enabled,
               CAST(0 AS bit),
               t.is_node,
               t.is_edge,
               {ledger_column}
        FROM sys.tables t
        JOIN sys.schemas s ON s.schema_id = t.schema_id
        LEFT JOIN sys.tables ht ON ht.object_id = t.history_table_id
        LEFT JOIN sys.schemas hs ON hs.schema_id = ht.schema_id
        WHERE t.is_ms_shipped = 0
        ORDER BY t.object_id
        "
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawTable {
                id: required_value(&row, 0, "table id")?,
                schema: required_string(&row, 1, "table schema")?,
                name: required_string(&row, 2, "table name")?,
                principal_id: optional_value(&row, 3)?,
                lob_data_space_id: required_value(&row, 4, "LOB data space")?,
                filestream_data_space_id: optional_value(&row, 5)?,
                replicated: required_value(&row, 6, "replication flag")?,
                merge_published: required_value(&row, 7, "merge publication flag")?,
                sync_tran_subscribed: required_value(
                    &row,
                    8,
                    "sync transaction subscription flag",
                )?,
                cdc_tracked: required_value(&row, 9, "CDC flag")?,
                lock_on_bulk_load: required_value(&row, 10, "bulk-load lock flag")?,
                file_table: required_value(&row, 11, "FileTable flag")?,
                memory_optimized: required_value(&row, 12, "memory optimized flag")?,
                durability: required_string(&row, 13, "durability")?,
                temporal_type: required_string(&row, 14, "temporal type")?,
                history_schema: optional_string(&row, 15)?,
                history_table: optional_string(&row, 16)?,
                remote_data_archive: required_value(&row, 17, "remote archive flag")?,
                external: required_value(&row, 18, "external table flag")?,
                node: required_value(&row, 19, "graph node flag")?,
                edge: required_value(&row, 20, "graph edge flag")?,
                ledger_type: required_string(&row, 21, "ledger type")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .map(|tables| {
            tables
                .into_iter()
                .filter(|table| selected_schemas.contains(&table.schema))
                .collect()
        })
}

async fn read_columns(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawColumn>, CatalogError> {
    let sql = format!(
        "
        SELECT c.object_id,
               RTRIM(o.type),
               s.name,
               COALESCE(tt.name, o.name),
               c.column_id,
               c.name,
               c.user_type_id,
               ts.name,
               ty.name,
               c.max_length,
               c.precision,
               c.scale,
               c.collation_name,
               c.is_nullable,
               c.is_ansi_padded,
               c.is_rowguidcol,
               c.is_identity,
               CONVERT(nvarchar(128), ic.seed_value),
               CONVERT(nvarchar(128), ic.increment_value),
               c.is_computed,
               CASE WHEN DATALENGTH(cc.definition) <= {MAX_DEFINITION_BYTES} THEN cc.definition END,
               CAST(COALESCE(DATALENGTH(cc.definition), 0) AS int),
               cc.is_persisted,
               CASE WHEN DATALENGTH(dc.definition) <= {MAX_DEFINITION_BYTES} THEN dc.definition END,
               CAST(COALESCE(DATALENGTH(dc.definition), 0) AS int),
               c.is_filestream,
               c.is_replicated,
               c.is_non_sql_subscribed,
               c.is_merge_published,
               c.is_dts_replicated,
               c.is_xml_document,
               c.xml_collection_id,
               c.is_sparse,
               c.is_column_set,
               c.generated_always_type_desc,
               c.encryption_type_desc,
               c.is_hidden,
               COALESCE(mc.is_masked, CAST(0 AS bit)),
               mc.masking_function,
               c.graph_type_desc,
               c.default_object_id
        FROM sys.columns c
        JOIN sys.objects o ON o.object_id = c.object_id
        LEFT JOIN sys.table_types tt ON tt.type_table_object_id = o.object_id
        JOIN sys.schemas s ON s.schema_id = COALESCE(tt.schema_id, o.schema_id)
        JOIN sys.types ty ON ty.user_type_id = c.user_type_id
        JOIN sys.schemas ts ON ts.schema_id = ty.schema_id
        LEFT JOIN sys.identity_columns ic
          ON ic.object_id = c.object_id AND ic.column_id = c.column_id
        LEFT JOIN sys.computed_columns cc
          ON cc.object_id = c.object_id AND cc.column_id = c.column_id
        LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id
        LEFT JOIN sys.masked_columns mc
          ON mc.object_id = c.object_id AND mc.column_id = c.column_id
        WHERE (o.is_ms_shipped = 0 OR o.type = 'TT')
          AND o.type IN ('U', 'V', 'TT')
        ORDER BY c.object_id, c.column_id
        "
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawColumn {
                object_id: required_value(&row, 0, "column object id")?,
                object_type: required_string(&row, 1, "column object type")?,
                schema: required_string(&row, 2, "column schema")?,
                relation: required_string(&row, 3, "column relation")?,
                id: required_value(&row, 4, "column id")?,
                name: required_string(&row, 5, "column name")?,
                type_id: required_value(&row, 6, "column type id")?,
                type_schema: required_string(&row, 7, "column type schema")?,
                type_name: required_string(&row, 8, "column type name")?,
                max_length: required_value(&row, 9, "column max length")?,
                precision: required_value(&row, 10, "column precision")?,
                scale: required_value(&row, 11, "column scale")?,
                collation: optional_string(&row, 12)?,
                nullable: required_value(&row, 13, "column nullable flag")?,
                ansi_padded: required_value(&row, 14, "column ANSI padded flag")?,
                rowguid: required_value(&row, 15, "column rowguid flag")?,
                identity: required_value(&row, 16, "column identity flag")?,
                identity_seed: optional_string(&row, 17)?,
                identity_increment: optional_string(&row, 18)?,
                computed: required_value(&row, 19, "column computed flag")?,
                computed_definition: optional_string(&row, 20)?,
                computed_definition_bytes: required_value(&row, 21, "computed definition bytes")?,
                persisted: optional_value(&row, 22)?,
                default_definition: optional_string(&row, 23)?,
                default_definition_bytes: required_value(&row, 24, "default definition bytes")?,
                filestream: required_value(&row, 25, "column FILESTREAM flag")?,
                replicated: required_value(&row, 26, "column replicated flag")?,
                non_sql_subscribed: required_value(&row, 27, "column non-SQL subscriber flag")?,
                merge_published: required_value(&row, 28, "column merge publication flag")?,
                dts_replicated: required_value(&row, 29, "column DTS replication flag")?,
                xml_document: required_value(&row, 30, "XML document flag")?,
                xml_collection_id: required_value(&row, 31, "XML collection id")?,
                sparse: required_value(&row, 32, "sparse flag")?,
                column_set: required_value(&row, 33, "column set flag")?,
                generated_always: required_string(&row, 34, "generated always type")?,
                encryption_type: optional_string(&row, 35)?,
                hidden: required_value(&row, 36, "hidden column flag")?,
                masked: required_value(&row, 37, "masked column flag")?,
                masking_function: optional_string(&row, 38)?,
                graph_type: optional_string(&row, 39)?,
                default_object_id: required_value(&row, 40, "default object id")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .and_then(|columns| {
            for column in &columns {
                ensure_definition_size(
                    "computed column",
                    &format!("{}.{}.{}", column.schema, column.relation, column.name),
                    column.computed_definition_bytes,
                )?;
                ensure_definition_size(
                    "default",
                    &format!("{}.{}.{}", column.schema, column.relation, column.name),
                    column.default_definition_bytes,
                )?;
            }
            Ok(columns
                .into_iter()
                .filter(|column| selected_schemas.contains(&column.schema))
                .collect())
        })
}

async fn read_constraints(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawConstraint>, CatalogError> {
    let mut constraints = BTreeMap::<i32, RawConstraint>::new();
    let key_rows = rows(
        client,
        "
        SELECT kc.object_id,
               s.name,
               COALESCE(tt.name, t.name),
               t.object_id,
               kc.name,
               RTRIM(kc.type),
               ic.key_ordinal,
               c.column_id,
               c.name
        FROM sys.key_constraints kc
        JOIN sys.objects t ON t.object_id = kc.parent_object_id
        LEFT JOIN sys.table_types tt ON tt.type_table_object_id = t.object_id
        JOIN sys.schemas s ON s.schema_id = COALESCE(tt.schema_id, t.schema_id)
        JOIN sys.index_columns ic
          ON ic.object_id = kc.parent_object_id
         AND ic.index_id = kc.unique_index_id
         AND ic.key_ordinal > 0
        JOIN sys.columns c
          ON c.object_id = ic.object_id AND c.column_id = ic.column_id
        WHERE (t.is_ms_shipped = 0 OR t.type = 'TT')
          AND t.type IN ('U', 'TT')
          AND kc.type IN ('PK', 'UQ')
        ORDER BY kc.object_id, ic.key_ordinal
        ",
    )
    .await?;
    for row in key_rows {
        let id: i32 = required_value(&row, 0, "key constraint id")?;
        let schema = required_string(&row, 1, "key constraint schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let type_code = required_string(&row, 5, "key constraint type")?;
        let kind = if type_code == "PK" {
            ConstraintKind::PrimaryKey
        } else if type_code == "UQ" {
            ConstraintKind::Unique
        } else {
            return Err(CatalogError::Mapping(format!(
                "key constraint {id} has unsupported type '{type_code}'"
            )));
        };
        let table = required_string(&row, 2, "key constraint table")?;
        let table_id = required_value(&row, 3, "key constraint table id")?;
        let name = required_string(&row, 4, "key constraint name")?;
        let entry = constraints.entry(id).or_insert_with(|| RawConstraint {
            id,
            schema: schema.clone(),
            table: table.clone(),
            table_id,
            name: name.clone(),
            kind,
            columns: Vec::new(),
            referenced_schema: None,
            referenced_table: None,
            referenced_table_id: None,
            delete_action: None,
            update_action: None,
            disabled: false,
            not_trusted: false,
            not_for_replication: false,
            expression: None,
            expression_bytes: 0,
        });
        if entry.schema != schema
            || entry.table != table
            || entry.table_id != table_id
            || entry.name != name
            || entry.kind != kind
        {
            return Err(CatalogError::Mapping(format!(
                "key constraint {id} has inconsistent catalog rows"
            )));
        }
        entry.columns.push(RawConstraintColumn {
            ordinal: i32::from(required_value::<u8>(&row, 6, "constraint column ordinal")?),
            column_id: required_value(&row, 7, "constraint column id")?,
            name: required_string(&row, 8, "constraint column name")?,
            referenced_column_id: None,
            referenced_name: None,
        });
    }

    let fk_rows = rows(
        client,
        "
        SELECT fk.object_id,
               ps.name,
               pt.name,
               pt.object_id,
               fk.name,
               rs.name,
               rt.name,
               rt.object_id,
               fk.delete_referential_action_desc,
               fk.update_referential_action_desc,
               fk.is_disabled,
               fk.is_not_trusted,
               fk.is_not_for_replication,
               fkc.constraint_column_id,
               pc.column_id,
               pc.name,
               rc.column_id,
               rc.name
        FROM sys.foreign_keys fk
        JOIN sys.tables pt ON pt.object_id = fk.parent_object_id
        JOIN sys.schemas ps ON ps.schema_id = pt.schema_id
        JOIN sys.tables rt ON rt.object_id = fk.referenced_object_id
        JOIN sys.schemas rs ON rs.schema_id = rt.schema_id
        JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
        JOIN sys.columns pc
          ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
        JOIN sys.columns rc
          ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
        WHERE pt.is_ms_shipped = 0
        ORDER BY fk.object_id, fkc.constraint_column_id
        ",
    )
    .await?;
    for row in fk_rows {
        let id: i32 = required_value(&row, 0, "foreign key id")?;
        let schema = required_string(&row, 1, "foreign key schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let table = required_string(&row, 2, "foreign key table")?;
        let table_id = required_value(&row, 3, "foreign key table id")?;
        let name = required_string(&row, 4, "foreign key name")?;
        let referenced_schema = required_string(&row, 5, "referenced schema")?;
        let referenced_table = required_string(&row, 6, "referenced table")?;
        let referenced_table_id = required_value(&row, 7, "referenced table id")?;
        let delete_action = required_string(&row, 8, "delete action")?;
        let update_action = required_string(&row, 9, "update action")?;
        let disabled = required_value(&row, 10, "foreign key disabled flag")?;
        let not_trusted = required_value(&row, 11, "foreign key trust flag")?;
        let not_for_replication = required_value(&row, 12, "foreign key replication flag")?;
        let entry = constraints.entry(id).or_insert_with(|| RawConstraint {
            id,
            schema: schema.clone(),
            table: table.clone(),
            table_id,
            name: name.clone(),
            kind: ConstraintKind::ForeignKey,
            columns: Vec::new(),
            referenced_schema: Some(referenced_schema.clone()),
            referenced_table: Some(referenced_table.clone()),
            referenced_table_id: Some(referenced_table_id),
            delete_action: Some(delete_action.clone()),
            update_action: Some(update_action.clone()),
            disabled,
            not_trusted,
            not_for_replication,
            expression: None,
            expression_bytes: 0,
        });
        if entry.schema != schema
            || entry.table != table
            || entry.table_id != table_id
            || entry.name != name
            || entry.kind != ConstraintKind::ForeignKey
            || entry.referenced_schema.as_ref() != Some(&referenced_schema)
            || entry.referenced_table.as_ref() != Some(&referenced_table)
            || entry.referenced_table_id != Some(referenced_table_id)
            || entry.delete_action.as_ref() != Some(&delete_action)
            || entry.update_action.as_ref() != Some(&update_action)
            || entry.disabled != disabled
            || entry.not_trusted != not_trusted
            || entry.not_for_replication != not_for_replication
        {
            return Err(CatalogError::Mapping(format!(
                "foreign key {id} has inconsistent catalog rows"
            )));
        }
        entry.columns.push(RawConstraintColumn {
            ordinal: required_value(&row, 13, "foreign key column ordinal")?,
            column_id: required_value(&row, 14, "foreign key column id")?,
            name: required_string(&row, 15, "foreign key column name")?,
            referenced_column_id: Some(required_value(
                &row,
                16,
                "referenced foreign key column id",
            )?),
            referenced_name: Some(required_string(
                &row,
                17,
                "referenced foreign key column name",
            )?),
        });
    }

    let check_sql = format!(
        "
        SELECT cc.object_id,
               s.name,
               COALESCE(tt.name, t.name),
               t.object_id,
               cc.name,
               cc.parent_column_id,
               c.name,
               cc.is_disabled,
               cc.is_not_trusted,
               cc.is_not_for_replication,
               CASE WHEN DATALENGTH(cc.definition) <= {MAX_DEFINITION_BYTES} THEN cc.definition END,
               CAST(COALESCE(DATALENGTH(cc.definition), 0) AS int)
        FROM sys.check_constraints cc
        JOIN sys.objects t ON t.object_id = cc.parent_object_id
        LEFT JOIN sys.table_types tt ON tt.type_table_object_id = t.object_id
        JOIN sys.schemas s ON s.schema_id = COALESCE(tt.schema_id, t.schema_id)
        LEFT JOIN sys.columns c
          ON c.object_id = cc.parent_object_id AND c.column_id = cc.parent_column_id
        WHERE (t.is_ms_shipped = 0 OR t.type = 'TT')
          AND t.type IN ('U', 'TT')
        ORDER BY cc.object_id
        "
    );
    for row in rows(client, &check_sql).await? {
        let id: i32 = required_value(&row, 0, "check constraint id")?;
        let schema = required_string(&row, 1, "check constraint schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let parent_column_id: i32 = required_value(&row, 5, "check parent column id")?;
        let expression_bytes: i32 = required_value(&row, 11, "check definition bytes")?;
        ensure_definition_size("check constraint", &id.to_string(), expression_bytes)?;
        let mut columns = Vec::new();
        if parent_column_id > 0 {
            columns.push(RawConstraintColumn {
                ordinal: 1,
                column_id: parent_column_id,
                name: required_string(&row, 6, "check constraint column")?,
                referenced_column_id: None,
                referenced_name: None,
            });
        }
        constraints.insert(
            id,
            RawConstraint {
                id,
                schema,
                table: required_string(&row, 2, "check constraint table")?,
                table_id: required_value(&row, 3, "check constraint table id")?,
                name: required_string(&row, 4, "check constraint name")?,
                kind: ConstraintKind::Check,
                columns,
                referenced_schema: None,
                referenced_table: None,
                referenced_table_id: None,
                delete_action: None,
                update_action: None,
                disabled: required_value(&row, 7, "check disabled flag")?,
                not_trusted: required_value(&row, 8, "check trust flag")?,
                not_for_replication: required_value(&row, 9, "check replication flag")?,
                expression: optional_string(&row, 10)?,
                expression_bytes,
            },
        );
    }
    Ok(constraints.into_values().collect())
}

async fn read_indexes(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawIndex>, CatalogError> {
    let sql = format!(
        "
        SELECT i.object_id,
               s.name,
               COALESCE(tt.name, o.name),
               RTRIM(o.type),
               i.index_id,
               i.name,
               i.type,
               i.type_desc,
               i.is_unique,
               i.is_primary_key,
               i.is_unique_constraint,
               i.is_disabled,
               i.is_hypothetical,
               i.is_padded,
               i.fill_factor,
               i.ignore_dup_key,
               i.allow_row_locks,
               i.allow_page_locks,
               i.auto_created,
               CASE WHEN DATALENGTH(i.filter_definition) <= {MAX_DEFINITION_BYTES} THEN i.filter_definition END,
               CAST(COALESCE(DATALENGTH(i.filter_definition), 0) AS int),
               i.data_space_id
        FROM sys.indexes i
        JOIN sys.objects o ON o.object_id = i.object_id
        LEFT JOIN sys.table_types tt ON tt.type_table_object_id = o.object_id
        JOIN sys.schemas s ON s.schema_id = COALESCE(tt.schema_id, o.schema_id)
        WHERE (o.is_ms_shipped = 0 OR o.type = 'TT')
          AND o.type IN ('U', 'V', 'TT')
          AND i.index_id > 0
          AND i.name IS NOT NULL
        ORDER BY i.object_id, i.index_id
        "
    );
    let mut indexes = BTreeMap::<(i32, i32), RawIndex>::new();
    for row in rows(client, &sql).await? {
        let schema = required_string(&row, 1, "index schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let object_id = required_value(&row, 0, "index object id")?;
        let id = required_value(&row, 4, "index id")?;
        let filter_bytes = required_value(&row, 20, "index filter bytes")?;
        ensure_definition_size("filtered index", &format!("{object_id}:{id}"), filter_bytes)?;
        indexes.insert(
            (object_id, id),
            RawIndex {
                object_id,
                schema,
                relation: required_string(&row, 2, "index relation")?,
                relation_type: required_string(&row, 3, "index relation type")?,
                id,
                name: required_string(&row, 5, "index name")?,
                type_code: required_value(&row, 6, "index type")?,
                type_desc: required_string(&row, 7, "index type description")?,
                unique: required_value(&row, 8, "index unique flag")?,
                primary: required_value(&row, 9, "index primary flag")?,
                unique_constraint: required_value(&row, 10, "index constraint flag")?,
                disabled: required_value(&row, 11, "index disabled flag")?,
                hypothetical: required_value(&row, 12, "index hypothetical flag")?,
                padded: required_value(&row, 13, "index padded flag")?,
                fill_factor: required_value(&row, 14, "index fill factor")?,
                ignore_duplicate_key: required_value(&row, 15, "index duplicate-key flag")?,
                allow_row_locks: required_value(&row, 16, "index row-lock flag")?,
                allow_page_locks: required_value(&row, 17, "index page-lock flag")?,
                auto_created: required_value(&row, 18, "index auto-created flag")?,
                filter: optional_string(&row, 19)?,
                filter_bytes,
                data_space_id: required_value(&row, 21, "index data space")?,
                columns: Vec::new(),
            },
        );
    }
    let column_rows = rows(
        client,
        "
        SELECT ic.object_id,
               ic.index_id,
               ic.index_column_id,
               ic.column_id,
               c.name,
               ic.key_ordinal,
               ic.partition_ordinal,
               ic.is_descending_key,
               ic.is_included_column
        FROM sys.index_columns ic
        JOIN sys.columns c
          ON c.object_id = ic.object_id AND c.column_id = ic.column_id
        JOIN sys.objects o ON o.object_id = ic.object_id
        WHERE (o.is_ms_shipped = 0 OR o.type = 'TT')
          AND o.type IN ('U', 'V', 'TT')
        ORDER BY ic.object_id, ic.index_id, ic.index_column_id
        ",
    )
    .await?;
    for row in column_rows {
        let identity = (
            required_value(&row, 0, "index column object id")?,
            required_value(&row, 1, "index column index id")?,
        );
        if let Some(index) = indexes.get_mut(&identity) {
            index.columns.push(RawIndexColumn {
                index_column_id: required_value(&row, 2, "index column id")?,
                column_id: required_value(&row, 3, "indexed column id")?,
                name: required_string(&row, 4, "indexed column name")?,
                key_ordinal: i32::from(required_value::<u8>(&row, 5, "index key ordinal")?),
                partition_ordinal: i32::from(required_value::<u8>(&row, 6, "partition ordinal")?),
                descending: required_value(&row, 7, "descending index flag")?,
                included: required_value(&row, 8, "included column flag")?,
            });
        }
    }
    for index in indexes.values() {
        if index.columns.is_empty() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "index '{}.{}.{}' has no catalog-resolved columns",
                index.schema, index.relation, index.name
            )));
        }
    }
    Ok(indexes.into_values().collect())
}

async fn read_views(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawView>, CatalogError> {
    let sql = format!(
        "
        SELECT v.object_id,
               s.name,
               v.name,
               v.principal_id,
               v.is_replicated,
               v.has_replication_filter,
               COALESCE(m.is_schema_bound, CAST(0 AS bit)),
               COALESCE(m.uses_ansi_nulls, CAST(0 AS bit)),
               COALESCE(m.uses_quoted_identifier, CAST(0 AS bit)),
               m.execute_as_principal_id,
               CASE WHEN DATALENGTH(m.definition) <= {MAX_DEFINITION_BYTES} THEN m.definition END,
               CAST(COALESCE(DATALENGTH(m.definition), 0) AS int),
               CASE WHEN EXISTS (
                   SELECT 1 FROM sys.indexes i
                   WHERE i.object_id = v.object_id
                     AND i.index_id > 0
                     AND i.is_hypothetical = 0
               ) THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END
        FROM sys.views v
        JOIN sys.schemas s ON s.schema_id = v.schema_id
        LEFT JOIN sys.sql_modules m ON m.object_id = v.object_id
        WHERE v.is_ms_shipped = 0
        ORDER BY v.object_id
        "
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawView {
                id: required_value(&row, 0, "view id")?,
                schema: required_string(&row, 1, "view schema")?,
                name: required_string(&row, 2, "view name")?,
                principal_id: optional_value(&row, 3)?,
                replicated: required_value(&row, 4, "view replicated flag")?,
                replication_filter: required_value(&row, 5, "view replication filter flag")?,
                schema_bound: required_value(&row, 6, "view schema-bound flag")?,
                ansi_nulls: required_value(&row, 7, "view ANSI NULL flag")?,
                quoted_identifier: required_value(&row, 8, "view quoted identifier flag")?,
                execute_as_principal_id: optional_value(&row, 9)?,
                definition: optional_string(&row, 10)?,
                definition_bytes: required_value(&row, 11, "view definition bytes")?,
                indexed: required_value(&row, 12, "indexed view flag")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .and_then(|views| {
            for view in &views {
                ensure_definition_size(
                    "view",
                    &format!("{}.{}", view.schema, view.name),
                    view.definition_bytes,
                )?;
            }
            Ok(views
                .into_iter()
                .filter(|view| selected_schemas.contains(&view.schema))
                .collect())
        })
}

async fn read_routines(
    client: &mut TdsClient,
    strategy: SqlServerCatalogVersion,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawRoutine>, CatalogError> {
    let (inlineable, inline_type) = strategy.routine_inline_expressions();
    let sql = format!(
        "
        SELECT o.object_id,
               s.name,
               o.name,
               RTRIM(o.type),
               o.type_desc,
               o.principal_id,
               COALESCE(m.is_schema_bound, CAST(0 AS bit)),
               COALESCE(m.is_recompiled, CAST(0 AS bit)),
               COALESCE(m.uses_native_compilation, CAST(0 AS bit)),
               COALESCE(m.uses_ansi_nulls, CAST(0 AS bit)),
               COALESCE(m.uses_quoted_identifier, CAST(0 AS bit)),
               m.execute_as_principal_id,
               COALESCE(m.null_on_null_input, CAST(0 AS bit)),
               {inlineable},
               {inline_type},
               COALESCE(p.is_auto_executed, CAST(0 AS bit)),
               COALESCE(p.is_execution_replicated, CAST(0 AS bit)),
               CASE WHEN DATALENGTH(m.definition) <= {MAX_DEFINITION_BYTES} THEN m.definition END,
               CAST(COALESCE(DATALENGTH(m.definition), 0) AS int)
        FROM sys.objects o
        JOIN sys.schemas s ON s.schema_id = o.schema_id
        LEFT JOIN sys.sql_modules m ON m.object_id = o.object_id
        LEFT JOIN sys.procedures p ON p.object_id = o.object_id
        WHERE o.is_ms_shipped = 0
          AND o.type IN ('P', 'PC', 'FN', 'IF', 'TF', 'FS', 'FT', 'AF')
        ORDER BY o.object_id
        "
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawRoutine {
                id: required_value(&row, 0, "routine id")?,
                schema: required_string(&row, 1, "routine schema")?,
                name: required_string(&row, 2, "routine name")?,
                type_code: required_string(&row, 3, "routine type")?,
                type_desc: required_string(&row, 4, "routine type description")?,
                principal_id: optional_value(&row, 5)?,
                schema_bound: required_value(&row, 6, "routine schema-bound flag")?,
                recompiled: required_value(&row, 7, "routine recompile flag")?,
                native_compilation: required_value(&row, 8, "native compilation flag")?,
                ansi_nulls: required_value(&row, 9, "routine ANSI NULL flag")?,
                quoted_identifier: required_value(&row, 10, "routine quoted identifier flag")?,
                execute_as_principal_id: optional_value(&row, 11)?,
                null_on_null_input: required_value(&row, 12, "null-on-null flag")?,
                inlineable: required_value(&row, 13, "routine inlineable flag")?,
                inline_type: required_value(&row, 14, "routine inline type")?,
                startup: required_value(&row, 15, "startup procedure flag")?,
                replication: required_value(&row, 16, "routine replication flag")?,
                definition: optional_string(&row, 17)?,
                definition_bytes: required_value(&row, 18, "routine definition bytes")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .and_then(|routines| {
            for routine in &routines {
                ensure_definition_size(
                    "routine",
                    &format!("{}.{}", routine.schema, routine.name),
                    routine.definition_bytes,
                )?;
            }
            Ok(routines
                .into_iter()
                .filter(|routine| selected_schemas.contains(&routine.schema))
                .collect())
        })
}

async fn read_parameters(
    client: &mut TdsClient,
    routines: &[RawRoutine],
) -> Result<Vec<RawParameter>, CatalogError> {
    let routine_ids = routines
        .iter()
        .map(|routine| routine.id)
        .collect::<BTreeSet<_>>();
    rows(
        client,
        "
        SELECT p.object_id,
               p.parameter_id,
               COALESCE(NULLIF(p.name, N''), CASE WHEN p.parameter_id = 0 THEN N'return' ELSE N'unnamed' END),
               p.user_type_id,
               ts.name,
               ty.name,
               p.max_length,
               p.precision,
               p.scale,
               p.is_output,
               p.is_readonly,
               p.is_nullable,
               CONVERT(nvarchar(4000), p.default_value),
               p.xml_collection_id
        FROM sys.parameters p
        JOIN sys.objects o ON o.object_id = p.object_id
        JOIN sys.types ty ON ty.user_type_id = p.user_type_id
        JOIN sys.schemas ts ON ts.schema_id = ty.schema_id
        WHERE o.is_ms_shipped = 0
          AND o.type IN ('P', 'PC', 'FN', 'IF', 'TF', 'FS', 'FT', 'AF')
        ORDER BY p.object_id, p.parameter_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawParameter {
            object_id: required_value(&row, 0, "parameter object id")?,
            id: required_value(&row, 1, "parameter id")?,
            name: required_string(&row, 2, "parameter name")?,
            type_id: required_value(&row, 3, "parameter type id")?,
            type_schema: required_string(&row, 4, "parameter type schema")?,
            type_name: required_string(&row, 5, "parameter type name")?,
            max_length: required_value(&row, 6, "parameter max length")?,
            precision: required_value(&row, 7, "parameter precision")?,
            scale: required_value(&row, 8, "parameter scale")?,
            output: required_value(&row, 9, "parameter output flag")?,
            readonly: required_value(&row, 10, "parameter readonly flag")?,
            nullable: required_value(&row, 11, "parameter nullable flag")?,
            default_value: optional_string(&row, 12)?,
            xml_collection_id: required_value(&row, 13, "parameter XML collection id")?,
        })
    })
    .collect::<Result<Vec<_>, CatalogError>>()
    .map(|parameters| {
        parameters
            .into_iter()
            .filter(|parameter| routine_ids.contains(&parameter.object_id))
            .collect()
    })
}

async fn read_triggers(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawTrigger>, CatalogError> {
    let sql = format!(
        "
        SELECT tr.object_id,
               tr.name,
               tr.parent_class,
               tr.parent_id,
               ps.name,
               po.name,
               RTRIM(po.type),
               tr.is_instead_of_trigger,
               tr.is_disabled,
               tr.is_not_for_replication,
               COALESCE(m.is_schema_bound, CAST(0 AS bit)),
               m.execute_as_principal_id,
               CASE WHEN DATALENGTH(m.definition) <= {MAX_DEFINITION_BYTES} THEN m.definition END,
               CAST(COALESCE(DATALENGTH(m.definition), 0) AS int),
               CASE WHEN OBJECTPROPERTYEX(tr.object_id, 'ExecIsInsertTrigger') = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END,
               CASE WHEN OBJECTPROPERTYEX(tr.object_id, 'ExecIsUpdateTrigger') = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END,
               CASE WHEN OBJECTPROPERTYEX(tr.object_id, 'ExecIsDeleteTrigger') = 1 THEN CAST(1 AS bit) ELSE CAST(0 AS bit) END
        FROM sys.triggers tr
        LEFT JOIN sys.objects po ON po.object_id = tr.parent_id
        LEFT JOIN sys.schemas ps ON ps.schema_id = po.schema_id
        LEFT JOIN sys.sql_modules m ON m.object_id = tr.object_id
        WHERE tr.is_ms_shipped = 0
        ORDER BY tr.object_id
        "
    );
    let mut triggers = BTreeMap::<i32, RawTrigger>::new();
    for row in rows(client, &sql).await? {
        let parent_class = i32::from(required_value::<u8>(&row, 2, "trigger parent class")?);
        let parent_schema = optional_string(&row, 4)?;
        if parent_class == 1
            && !parent_schema
                .as_ref()
                .is_some_and(|schema| selected_schemas.contains(schema))
        {
            continue;
        }
        let id: i32 = required_value(&row, 0, "trigger id")?;
        let definition_bytes: i32 = required_value(&row, 13, "trigger definition bytes")?;
        ensure_definition_size("trigger", &id.to_string(), definition_bytes)?;
        triggers.insert(
            id,
            RawTrigger {
                id,
                name: required_string(&row, 1, "trigger name")?,
                parent_class,
                parent_id: required_value(&row, 3, "trigger parent id")?,
                parent_schema,
                parent_name: optional_string(&row, 5)?,
                parent_type: optional_string(&row, 6)?,
                instead_of: required_value(&row, 7, "instead-of trigger flag")?,
                disabled: required_value(&row, 8, "trigger disabled flag")?,
                not_for_replication: required_value(&row, 9, "trigger replication flag")?,
                schema_bound: required_value(&row, 10, "trigger schema-bound flag")?,
                execute_as_principal_id: optional_value(&row, 11)?,
                definition: optional_string(&row, 12)?,
                definition_bytes,
                insert_event: required_value(&row, 14, "insert trigger event")?,
                update_event: required_value(&row, 15, "update trigger event")?,
                delete_event: required_value(&row, 16, "delete trigger event")?,
                events: Vec::new(),
            },
        );
    }
    for row in rows(
        client,
        "
        SELECT object_id, type_desc
        FROM sys.trigger_events
        ORDER BY object_id, type
        ",
    )
    .await?
    {
        let id: i32 = required_value(&row, 0, "trigger event object id")?;
        if let Some(trigger) = triggers.get_mut(&id) {
            trigger
                .events
                .push(required_string(&row, 1, "trigger event type")?);
        }
    }
    for trigger in triggers.values_mut() {
        if trigger.insert_event {
            trigger.events.push("INSERT".to_owned());
        }
        if trigger.update_event {
            trigger.events.push("UPDATE".to_owned());
        }
        if trigger.delete_event {
            trigger.events.push("DELETE".to_owned());
        }
        trigger.events.sort();
        trigger.events.dedup();
        if trigger.events.is_empty() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "trigger '{}' has no catalog-visible event",
                trigger.name
            )));
        }
    }
    Ok(triggers.into_values().collect())
}

async fn read_user_types(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawUserType>, CatalogError> {
    rows(
        client,
        "
        SELECT ty.user_type_id,
               s.name,
               ty.name,
               ty.system_type_id,
               COALESCE(bt.name, ty.name),
               ty.max_length,
               ty.precision,
               ty.scale,
               ty.collation_name,
               ty.is_nullable,
               ty.is_user_defined,
               ty.is_assembly_type,
               ty.is_table_type,
               tt.type_table_object_id,
               COALESCE(tt.is_memory_optimized, CAST(0 AS bit)),
               ty.default_object_id,
               ty.rule_object_id
        FROM sys.types ty
        JOIN sys.schemas s ON s.schema_id = ty.schema_id
        LEFT JOIN sys.table_types tt ON tt.user_type_id = ty.user_type_id
        LEFT JOIN sys.types bt
          ON bt.user_type_id = bt.system_type_id
         AND bt.system_type_id = ty.system_type_id
        WHERE ty.is_user_defined = 1
        ORDER BY ty.user_type_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawUserType {
            id: required_value(&row, 0, "user type id")?,
            schema: required_string(&row, 1, "user type schema")?,
            name: required_string(&row, 2, "user type name")?,
            system_type_id: required_value(&row, 3, "system type id")?,
            base_type: required_string(&row, 4, "base type")?,
            max_length: required_value(&row, 5, "type max length")?,
            precision: required_value(&row, 6, "type precision")?,
            scale: required_value(&row, 7, "type scale")?,
            collation: optional_string(&row, 8)?,
            nullable: required_value(&row, 9, "type nullable flag")?,
            user_defined: required_value(&row, 10, "user-defined flag")?,
            assembly: required_value(&row, 11, "assembly type flag")?,
            table_type: required_value(&row, 12, "table type flag")?,
            table_object_id: optional_value(&row, 13)?,
            memory_optimized: required_value(&row, 14, "memory optimized table type flag")?,
            default_object_id: required_value(&row, 15, "type default object id")?,
            rule_object_id: required_value(&row, 16, "type rule object id")?,
        })
    })
    .collect::<Result<Vec<_>, CatalogError>>()
    .map(|types| {
        types
            .into_iter()
            .filter(|data_type| selected_schemas.contains(&data_type.schema))
            .collect()
    })
}

async fn read_sequences(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawSequence>, CatalogError> {
    rows(
        client,
        "
        SELECT seq.object_id,
               s.name,
               seq.name,
               seq.principal_id,
               seq.user_type_id,
               ts.name,
               ty.name,
               seq.precision,
               seq.scale,
               CONVERT(nvarchar(128), seq.start_value),
               CONVERT(nvarchar(128), seq.increment),
               CONVERT(nvarchar(128), seq.minimum_value),
               CONVERT(nvarchar(128), seq.maximum_value),
               seq.is_cycling,
               seq.cache_size,
               seq.is_exhausted
        FROM sys.sequences seq
        JOIN sys.schemas s ON s.schema_id = seq.schema_id
        JOIN sys.types ty ON ty.user_type_id = seq.user_type_id
        JOIN sys.schemas ts ON ts.schema_id = ty.schema_id
        ORDER BY seq.object_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawSequence {
            id: required_value(&row, 0, "sequence id")?,
            schema: required_string(&row, 1, "sequence schema")?,
            name: required_string(&row, 2, "sequence name")?,
            principal_id: optional_value(&row, 3)?,
            type_id: required_value(&row, 4, "sequence type id")?,
            type_schema: required_string(&row, 5, "sequence type schema")?,
            type_name: required_string(&row, 6, "sequence type name")?,
            precision: required_value(&row, 7, "sequence precision")?,
            scale: required_value(&row, 8, "sequence scale")?,
            start_value: required_string(&row, 9, "sequence start")?,
            increment: required_string(&row, 10, "sequence increment")?,
            minimum_value: required_string(&row, 11, "sequence minimum")?,
            maximum_value: required_string(&row, 12, "sequence maximum")?,
            cyclic: required_value(&row, 13, "sequence cycle flag")?,
            cache_size: optional_value(&row, 14)?,
            exhausted: required_value(&row, 15, "sequence exhausted flag")?,
        })
    })
    .collect::<Result<Vec<_>, CatalogError>>()
    .map(|sequences| {
        sequences
            .into_iter()
            .filter(|sequence| selected_schemas.contains(&sequence.schema))
            .collect()
    })
}

async fn read_synonyms(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawSynonym>, CatalogError> {
    rows(
        client,
        "
        SELECT sn.object_id,
               s.name,
               sn.name,
               sn.principal_id,
               sn.base_object_name,
               PARSENAME(sn.base_object_name, 4),
               PARSENAME(sn.base_object_name, 3),
               PARSENAME(sn.base_object_name, 2),
               PARSENAME(sn.base_object_name, 1)
        FROM sys.synonyms sn
        JOIN sys.schemas s ON s.schema_id = sn.schema_id
        ORDER BY sn.object_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawSynonym {
            id: required_value(&row, 0, "synonym id")?,
            schema: required_string(&row, 1, "synonym schema")?,
            name: required_string(&row, 2, "synonym name")?,
            principal_id: optional_value(&row, 3)?,
            base_object_name: required_string(&row, 4, "synonym target")?,
            server: optional_string(&row, 5)?,
            database: optional_string(&row, 6)?,
            target_schema: optional_string(&row, 7)?,
            target_entity: optional_string(&row, 8)?,
        })
    })
    .collect::<Result<Vec<_>, CatalogError>>()
    .map(|synonyms| {
        synonyms
            .into_iter()
            .filter(|synonym| selected_schemas.contains(&synonym.schema))
            .collect()
    })
}

async fn read_dependencies(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawDependency>, CatalogError> {
    rows(
        client,
        "
        SELECT sed.referencing_class,
               sed.referencing_id,
               sed.referencing_minor_id,
               sed.referenced_class,
               sed.referenced_server_name,
               sed.referenced_database_name,
               sed.referenced_schema_name,
               sed.referenced_entity_name,
               sed.referenced_id,
               sed.referenced_minor_id,
               sed.is_schema_bound_reference,
               sed.is_caller_dependent,
               sed.is_ambiguous,
               CASE
                   WHEN sed.referencing_class = 12 THEN N'__database__'
                   ELSE OBJECT_SCHEMA_NAME(sed.referencing_id)
               END
        FROM sys.sql_expression_dependencies sed
        ORDER BY sed.referencing_class,
                 sed.referencing_id,
                 sed.referencing_minor_id,
                 sed.referenced_class,
                 sed.referenced_server_name,
                 sed.referenced_database_name,
                 sed.referenced_schema_name,
                 sed.referenced_entity_name,
                 sed.referenced_minor_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        let dependency = RawDependency {
            referencing_class: i32::from(required_value::<u8>(&row, 0, "referencing class")?),
            referencing_id: required_value(&row, 1, "referencing id")?,
            referencing_minor_id: required_value(&row, 2, "referencing minor id")?,
            referenced_class: i32::from(required_value::<u8>(&row, 3, "referenced class")?),
            referenced_server: optional_string(&row, 4)?,
            referenced_database: optional_string(&row, 5)?,
            referenced_schema: optional_string(&row, 6)?,
            referenced_entity: required_string(&row, 7, "referenced entity")?,
            referenced_id: optional_value(&row, 8)?,
            referenced_minor_id: required_value(&row, 9, "referenced minor id")?,
            schema_bound: required_value(&row, 10, "schema-bound dependency flag")?,
            caller_dependent: required_value(&row, 11, "caller-dependent flag")?,
            ambiguous: required_value(&row, 12, "ambiguous dependency flag")?,
        };
        let source_schema = required_string(&row, 13, "dependency source schema")?;
        Ok((source_schema, dependency))
    })
    .collect::<Result<Vec<_>, CatalogError>>()
    .map(|dependencies| {
        dependencies
            .into_iter()
            .filter(|(schema, _)| schema == "__database__" || selected_schemas.contains(schema))
            .map(|(_, dependency)| dependency)
            .collect()
    })
}

async fn read_partition_functions(
    client: &mut TdsClient,
) -> Result<Vec<RawPartitionFunction>, CatalogError> {
    let mut functions = BTreeMap::<i32, RawPartitionFunction>::new();
    for row in rows(
        client,
        "
        SELECT function_id, name, fanout, boundary_value_on_right, is_system
        FROM sys.partition_functions
        ORDER BY function_id
        ",
    )
    .await?
    {
        let id = required_value(&row, 0, "partition function id")?;
        functions.insert(
            id,
            RawPartitionFunction {
                id,
                name: required_string(&row, 1, "partition function name")?,
                fanout: required_value(&row, 2, "partition function fanout")?,
                boundary_on_right: required_value(&row, 3, "partition boundary side")?,
                system: required_value(&row, 4, "system partition function flag")?,
                values: Vec::new(),
            },
        );
    }
    for row in rows(
        client,
        "
        SELECT function_id, boundary_id, CONVERT(nvarchar(4000), value)
        FROM sys.partition_range_values
        ORDER BY function_id, boundary_id
        ",
    )
    .await?
    {
        let function_id: i32 = required_value(&row, 0, "partition value function id")?;
        let function = functions.get_mut(&function_id).ok_or_else(|| {
            CatalogError::Mapping(format!(
                "partition range value references missing function {function_id}"
            ))
        })?;
        function.values.push(RawPartitionValue {
            boundary_id: required_value(&row, 1, "partition boundary id")?,
            value: optional_string(&row, 2)?,
        });
    }
    Ok(functions
        .into_values()
        .filter(|function| !function.system)
        .collect())
}

async fn read_partition_schemes(
    client: &mut TdsClient,
) -> Result<Vec<RawPartitionScheme>, CatalogError> {
    rows(
        client,
        "
        SELECT data_space_id, name, function_id
        FROM sys.partition_schemes
        ORDER BY data_space_id
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawPartitionScheme {
            id: required_value(&row, 0, "partition scheme id")?,
            name: required_string(&row, 1, "partition scheme name")?,
            function_id: required_value(&row, 2, "partition scheme function id")?,
        })
    })
    .collect()
}

async fn read_partitions(
    client: &mut TdsClient,
    strategy: SqlServerCatalogVersion,
    tables: &[RawTable],
    views: &[RawView],
) -> Result<Vec<RawPartition>, CatalogError> {
    let object_ids = tables
        .iter()
        .map(|table| table.id)
        .chain(views.iter().map(|view| view.id))
        .collect::<BTreeSet<_>>();
    let xml_column = strategy.xml_compression_expression();
    let sql = format!(
        "
        SELECT p.object_id,
               p.index_id,
               p.partition_number,
               p.data_compression_desc,
               {xml_column}
        FROM sys.partitions p
        JOIN sys.objects o ON o.object_id = p.object_id
        WHERE o.is_ms_shipped = 0
          AND o.type IN ('U', 'V')
        ORDER BY p.object_id, p.index_id, p.partition_number
        "
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawPartition {
                object_id: required_value(&row, 0, "partition object id")?,
                index_id: required_value(&row, 1, "partition index id")?,
                partition_number: required_value(&row, 2, "partition number")?,
                data_compression: required_string(&row, 3, "partition compression")?,
                xml_compression: required_string(&row, 4, "partition XML compression")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .map(|partitions| {
            partitions
                .into_iter()
                .filter(|partition| object_ids.contains(&partition.object_id))
                .collect()
        })
}

async fn read_security_policies(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawSecurityPolicy>, CatalogError> {
    let mut policies = BTreeMap::<i32, RawSecurityPolicy>::new();
    for row in rows(
        client,
        "
        SELECT sp.object_id,
               s.name,
               sp.name,
               sp.principal_id,
               sp.is_enabled,
               sp.is_schema_bound
        FROM sys.security_policies sp
        JOIN sys.schemas s ON s.schema_id = sp.schema_id
        ORDER BY sp.object_id
        ",
    )
    .await?
    {
        let schema = required_string(&row, 1, "security policy schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let id = required_value(&row, 0, "security policy id")?;
        policies.insert(
            id,
            RawSecurityPolicy {
                id,
                schema,
                name: required_string(&row, 2, "security policy name")?,
                principal_id: optional_value(&row, 3)?,
                enabled: required_value(&row, 4, "security policy enabled flag")?,
                schema_bound: required_value(&row, 5, "security policy schema-bound flag")?,
                predicates: Vec::new(),
            },
        );
    }
    let predicate_sql = format!(
        "
        SELECT object_id,
               security_predicate_id,
               target_object_id,
               predicate_type_desc,
               operation_desc,
               CASE WHEN DATALENGTH(predicate_definition) <= {MAX_DEFINITION_BYTES} THEN predicate_definition END,
               CAST(COALESCE(DATALENGTH(predicate_definition), 0) AS int)
        FROM sys.security_predicates
        ORDER BY object_id, security_predicate_id
        "
    );
    for row in rows(client, &predicate_sql).await? {
        let policy_id: i32 = required_value(&row, 0, "predicate policy id")?;
        if let Some(policy) = policies.get_mut(&policy_id) {
            let id: i32 = required_value(&row, 1, "predicate id")?;
            let definition_bytes: i32 = required_value(&row, 6, "predicate definition bytes")?;
            ensure_definition_size("security predicate", &id.to_string(), definition_bytes)?;
            policy.predicates.push(RawSecurityPredicate {
                id,
                target_object_id: required_value(&row, 2, "predicate target")?,
                predicate_type: required_string(&row, 3, "predicate type")?,
                operation: optional_string(&row, 4)?,
                definition: required_string(&row, 5, "predicate definition")?,
                definition_bytes,
            });
        }
    }
    Ok(policies.into_values().collect())
}

async fn read_xml_schema_collections(
    client: &mut TdsClient,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawXmlSchemaCollection>, CatalogError> {
    let mut collections = BTreeMap::<i32, RawXmlSchemaCollection>::new();
    for row in rows(
        client,
        "
        SELECT xsc.xml_collection_id,
               s.name,
               xsc.name,
               xsc.principal_id,
               CONVERT(nvarchar(33), xsc.create_date, 126),
               CONVERT(nvarchar(33), xsc.modify_date, 126),
               xsn.xml_namespace_id,
               xsn.name
        FROM sys.xml_schema_collections xsc
        JOIN sys.schemas s ON s.schema_id = xsc.schema_id
        LEFT JOIN sys.xml_schema_namespaces xsn
          ON xsn.xml_collection_id = xsc.xml_collection_id
        ORDER BY xsc.xml_collection_id, xsn.xml_namespace_id
        ",
    )
    .await?
    {
        let schema = required_string(&row, 1, "XML schema collection schema")?;
        if !selected_schemas.contains(&schema) {
            continue;
        }
        let id = required_value(&row, 0, "XML schema collection id")?;
        let name = required_string(&row, 2, "XML schema collection name")?;
        let principal_id = optional_value(&row, 3)?;
        let created_at = required_string(&row, 4, "XML schema collection creation time")?;
        let modified_at = required_string(&row, 5, "XML schema collection modification time")?;
        let entry = collections
            .entry(id)
            .or_insert_with(|| RawXmlSchemaCollection {
                id,
                schema: schema.clone(),
                name: name.clone(),
                principal_id,
                created_at: created_at.clone(),
                modified_at: modified_at.clone(),
                namespaces: Vec::new(),
            });
        if entry.schema != schema
            || entry.name != name
            || entry.principal_id != principal_id
            || entry.created_at != created_at
            || entry.modified_at != modified_at
        {
            return Err(CatalogError::Mapping(format!(
                "XML schema collection {id} has inconsistent catalog rows"
            )));
        }
        if let Some(namespace_id) = optional_value(&row, 6)? {
            let namespace_name = optional_value::<&str>(&row, 7)?
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "XML schema collection {id} namespace {namespace_id} has no name"
                    ))
                })?
                .to_owned();
            if namespace_name.len() > MAX_PROPERTY_STRING_BYTES {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "XML namespace exceeds the {MAX_PROPERTY_STRING_BYTES}-byte property limit"
                )));
            }
            entry.namespaces.push(RawXmlSchemaNamespace {
                id: namespace_id,
                name: namespace_name,
            });
        }
    }
    Ok(collections.into_values().collect())
}

async fn read_extended_properties(
    client: &mut TdsClient,
) -> Result<Vec<RawExtendedProperty>, CatalogError> {
    rows(
        client,
        "
        SELECT ep.class,
               ep.class_desc,
               ep.major_id,
               ep.minor_id,
               ep.name,
               CONVERT(nvarchar(128), SQL_VARIANT_PROPERTY(ep.value, 'BaseType')),
               TRY_CONVERT(int, SQL_VARIANT_PROPERTY(ep.value, 'Precision')),
               TRY_CONVERT(int, SQL_VARIANT_PROPERTY(ep.value, 'Scale')),
               TRY_CONVERT(int, SQL_VARIANT_PROPERTY(ep.value, 'MaxLength')),
               CONVERT(nvarchar(128), SQL_VARIANT_PROPERTY(ep.value, 'Collation')),
               CASE
                 WHEN ep.value IS NULL THEN NULL
                 WHEN CONVERT(nvarchar(128), SQL_VARIANT_PROPERTY(ep.value, 'BaseType'))
                      IN (N'binary', N'varbinary')
                   THEN CONVERT(nvarchar(max), CONVERT(varchar(max), CONVERT(varbinary(8000), ep.value), 2))
                 ELSE CONVERT(nvarchar(max), ep.value, 126)
               END,
               CASE WHEN ep.value IS NULL THEN NULL
                    ELSE CONVERT(nvarchar(max), CONVERT(varchar(max), CONVERT(varbinary(8000), ep.value), 2))
               END
        FROM sys.extended_properties ep
        ORDER BY ep.class, ep.major_id, ep.minor_id, ep.name
        ",
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(RawExtendedProperty {
            class: required_value(&row, 0, "extended property class")?,
            class_description: required_string(&row, 1, "extended property class description")?,
            major_id: required_value(&row, 2, "extended property major id")?,
            minor_id: required_value(&row, 3, "extended property minor id")?,
            name: required_string(&row, 4, "extended property name")?,
            value_type: optional_string(&row, 5)?,
            value_precision: optional_value(&row, 6)?,
            value_scale: optional_value(&row, 7)?,
            value_max_length: optional_value(&row, 8)?,
            value_collation: optional_string(&row, 9)?,
            display_value: optional_string(&row, 10)?,
            value_hex: optional_string(&row, 11)?,
        })
    })
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn select_extended_properties(
    properties: Vec<RawExtendedProperty>,
    schemas: &[RawSchema],
    principals: &[RawPrincipal],
    tables: &[RawTable],
    columns: &[RawColumn],
    constraints: &[RawConstraint],
    indexes: &[RawIndex],
    views: &[RawView],
    routines: &[RawRoutine],
    parameters: &[RawParameter],
    triggers: &[RawTrigger],
    user_types: &[RawUserType],
    sequences: &[RawSequence],
    synonyms: &[RawSynonym],
    partition_functions: &[RawPartitionFunction],
    partition_schemes: &[RawPartitionScheme],
    security_policies: &[RawSecurityPolicy],
    xml_schema_collections: &[RawXmlSchemaCollection],
) -> Vec<RawExtendedProperty> {
    let mut object_ids = tables
        .iter()
        .map(|object| object.id)
        .collect::<BTreeSet<_>>();
    object_ids.extend(views.iter().map(|object| object.id));
    object_ids.extend(routines.iter().map(|object| object.id));
    object_ids.extend(triggers.iter().map(|object| object.id));
    object_ids.extend(sequences.iter().map(|object| object.id));
    object_ids.extend(synonyms.iter().map(|object| object.id));
    object_ids.extend(security_policies.iter().map(|object| object.id));
    object_ids.extend(constraints.iter().map(|object| object.id));
    let column_ids = columns
        .iter()
        .map(|column| (column.object_id, column.id))
        .collect::<BTreeSet<_>>();
    let parameter_ids = parameters
        .iter()
        .map(|parameter| (parameter.object_id, parameter.id))
        .collect::<BTreeSet<_>>();
    let schema_ids = schemas
        .iter()
        .map(|schema| schema.id)
        .collect::<BTreeSet<_>>();
    let principal_ids = principals
        .iter()
        .map(|principal| principal.id)
        .collect::<BTreeSet<_>>();
    let type_ids = user_types
        .iter()
        .map(|data_type| data_type.id)
        .collect::<BTreeSet<_>>();
    let index_ids = indexes
        .iter()
        .map(|index| (index.object_id, index.id))
        .collect::<BTreeSet<_>>();
    let table_type_column_ids = user_types
        .iter()
        .filter_map(|data_type| {
            data_type
                .table_object_id
                .map(|object_id| (data_type.id, object_id))
        })
        .flat_map(|(user_type_id, object_id)| {
            columns.iter().filter_map(move |column| {
                (column.object_id == object_id).then_some((user_type_id, column.id))
            })
        })
        .collect::<BTreeSet<_>>();
    let xml_collection_ids = xml_schema_collections
        .iter()
        .map(|collection| collection.id)
        .collect::<BTreeSet<_>>();
    let partition_function_ids = partition_functions
        .iter()
        .map(|function| function.id)
        .collect::<BTreeSet<_>>();
    let partition_scheme_ids = partition_schemes
        .iter()
        .map(|scheme| scheme.id)
        .collect::<BTreeSet<_>>();

    properties
        .into_iter()
        .filter(|property| match property.class {
            0 => property.major_id == 0 && property.minor_id == 0,
            1 if property.minor_id == 0 => object_ids.contains(&property.major_id),
            1 => column_ids.contains(&(property.major_id, property.minor_id)),
            2 => parameter_ids.contains(&(property.major_id, property.minor_id)),
            3 => schema_ids.contains(&property.major_id),
            4 => principal_ids.contains(&property.major_id),
            6 => type_ids.contains(&property.major_id),
            7 => index_ids.contains(&(property.major_id, property.minor_id)),
            8 => table_type_column_ids.contains(&(property.major_id, property.minor_id)),
            10 => xml_collection_ids.contains(&property.major_id),
            20 => partition_scheme_ids.contains(&property.major_id),
            21 => partition_function_ids.contains(&property.major_id),
            _ => false,
        })
        .collect()
}

async fn read_unsupported_objects(
    client: &mut TdsClient,
    strategy: SqlServerCatalogVersion,
    selected_schemas: &BTreeSet<String>,
) -> Result<Vec<RawUnsupportedObject>, CatalogError> {
    let edge_constraints = strategy.edge_constraint_union();
    let sql = format!(
        "
        SELECT s.name, o.name, RTRIM(o.type), o.type_desc
        FROM sys.objects o
        LEFT JOIN sys.schemas s ON s.schema_id = o.schema_id
        WHERE o.is_ms_shipped = 0
          AND ((o.type = 'D' AND o.parent_object_id = 0) OR o.type IN ('R', 'TA'))
        UNION ALL
        SELECT s.name, et.name, N'ET', N'EXTERNAL_TABLE'
        FROM sys.external_tables et
        JOIN sys.schemas s ON s.schema_id = et.schema_id
        {edge_constraints}
        UNION ALL
        SELECT s.name, p.name, N'NP', N'NUMBERED_PROCEDURE'
        FROM sys.numbered_procedures np
        JOIN sys.procedures p ON p.object_id = np.object_id
        JOIN sys.schemas s ON s.schema_id = p.schema_id
        WHERE np.procedure_number > 1
        ORDER BY 1, 2, 3
        ",
    );
    rows(client, &sql)
        .await?
        .into_iter()
        .map(|row| {
            Ok(RawUnsupportedObject {
                schema: optional_string(&row, 0)?,
                name: required_string(&row, 1, "unsupported object name")?,
                type_code: required_string(&row, 2, "unsupported object type")?,
                type_desc: required_string(&row, 3, "unsupported object type description")?,
            })
        })
        .collect::<Result<Vec<_>, CatalogError>>()
        .map(|objects| {
            objects
                .into_iter()
                .filter(|object| {
                    object
                        .schema
                        .as_ref()
                        .is_none_or(|schema| selected_schemas.contains(schema))
                })
                .collect()
        })
}

fn validate_supported_metadata(
    unsupported: &[RawUnsupportedObject],
    views: &[RawView],
    routines: &[RawRoutine],
    triggers: &[RawTrigger],
    user_types: &[RawUserType],
    dependencies: &[RawDependency],
) -> Result<(), CatalogError> {
    if let Some(object) = unsupported.first() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "SQL Server object '{}.{}' has unsupported catalog type {} ({})",
            object.schema.as_deref().unwrap_or("database"),
            object.name,
            object.type_code,
            object.type_desc
        )));
    }
    for view in views {
        require_visible_definition(
            "view",
            &format!("{}.{}", view.schema, view.name),
            view.definition.as_deref(),
        )?;
    }
    for routine in routines {
        if matches!(routine.type_code.as_str(), "PC" | "FS" | "FT" | "AF") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "CLR routine '{}.{}' has no authoritative SQL dependency body",
                routine.schema, routine.name
            )));
        }
        let definition = require_visible_definition(
            "routine",
            &format!("{}.{}", routine.schema, routine.name),
            routine.definition.as_deref(),
        )?;
        reject_dynamic_sql(
            "routine",
            &format!("{}.{}", routine.schema, routine.name),
            definition,
        )?;
    }
    for trigger in triggers {
        let definition =
            require_visible_definition("trigger", &trigger.name, trigger.definition.as_deref())?;
        reject_dynamic_sql("trigger", &trigger.name, definition)?;
    }
    if let Some(data_type) = user_types.iter().find(|data_type| data_type.assembly) {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "CLR user-defined type '{}.{}' requires assembly metadata mapping",
            data_type.schema, data_type.name
        )));
    }
    if let Some(data_type) = user_types.iter().find(|data_type| {
        data_type.table_type != data_type.table_object_id.is_some()
            || (!data_type.table_type && data_type.memory_optimized)
    }) {
        return Err(CatalogError::Mapping(format!(
            "user-defined type '{}.{}' has inconsistent table-type catalog identity",
            data_type.schema, data_type.name
        )));
    }
    if let Some(data_type) = user_types
        .iter()
        .find(|data_type| data_type.default_object_id != 0 || data_type.rule_object_id != 0)
    {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "user-defined type '{}.{}' uses a legacy bound default or rule whose dependencies are not catalog-maintained",
            data_type.schema, data_type.name
        )));
    }
    if let Some(dependency) = dependencies
        .iter()
        .find(|dependency| dependency.caller_dependent || dependency.ambiguous)
    {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "dependency from object {} is resolved only at runtime (caller_dependent={}, ambiguous={})",
            dependency.referencing_id, dependency.caller_dependent, dependency.ambiguous
        )));
    }
    Ok(())
}

fn require_visible_definition<'a>(
    kind: &str,
    name: &str,
    definition: Option<&'a str>,
) -> Result<&'a str, CatalogError> {
    definition
        .filter(|definition| !definition.trim().is_empty())
        .ok_or_else(|| {
            CatalogError::UnsupportedMetadata(format!(
                "{kind} '{name}' has a hidden, encrypted, or unavailable definition"
            ))
        })
}

fn reject_dynamic_sql(kind: &str, name: &str, definition: &str) -> Result<(), CatalogError> {
    let dialect = MsSqlDialect {};
    let tokens = Tokenizer::new(&dialect, definition)
        .tokenize()
        .map_err(|error| {
            CatalogError::UnsupportedMetadata(format!(
                "{kind} '{name}' cannot be tokenized for dynamic SQL validation: {error}"
            ))
        })?;
    let tokens = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = token else {
            continue;
        };
        if !matches!(word.keyword, Keyword::EXEC | Keyword::EXECUTE)
            && !word.value.eq_ignore_ascii_case("EXEC")
            && !word.value.eq_ignore_ascii_case("EXECUTE")
        {
            continue;
        }
        let rest = &tokens[index + 1..];
        if rest
            .first()
            .is_some_and(|token| matches!(token, Token::Word(word) if word.keyword == Keyword::AS))
        {
            continue;
        }
        if execute_target_is_dynamic(rest) {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "{kind} '{name}' executes dynamic SQL whose dependencies are not catalog-maintained"
            )));
        }
    }
    Ok(())
}

fn execute_target_is_dynamic(tokens: &[&Token]) -> bool {
    let Some(first) = tokens.first() else {
        return true;
    };
    if is_string_token(first) {
        return true;
    }
    if matches!(first, Token::LParen) {
        return tokens
            .get(1)
            .is_none_or(|token| is_variable_token(token) || is_string_token(token));
    }
    if is_variable_token(first) {
        if !tokens
            .get(1)
            .is_some_and(|token| matches!(token, Token::Eq))
        {
            return true;
        }
        return tokens
            .get(2)
            .is_none_or(|token| is_variable_token(token) || is_string_token(token));
    }
    tokens.iter().take(7).any(|token| {
        matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case("sp_executesql"))
    })
}

fn is_variable_token(token: &Token) -> bool {
    matches!(token, Token::AtSign)
        || matches!(token, Token::Word(word) if word.value.starts_with('@'))
}

fn is_string_token(token: &Token) -> bool {
    matches!(
        token,
        Token::SingleQuotedString(_)
            | Token::NationalStringLiteral(_)
            | Token::DoubleQuotedString(_)
    )
}

fn ensure_definition_size(kind: &str, name: &str, bytes: i32) -> Result<(), CatalogError> {
    if bytes > MAX_DEFINITION_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "{kind} '{name}' definition is {bytes} bytes; limit is {MAX_DEFINITION_BYTES}"
        )));
    }
    Ok(())
}

async fn rows(client: &mut TdsClient, sql: &str) -> Result<Vec<Row>, CatalogError> {
    Ok(client.simple_query(sql).await?.into_first_result().await?)
}

async fn query_one(client: &mut TdsClient, sql: &str) -> Result<Row, CatalogError> {
    client
        .simple_query(sql)
        .await?
        .into_row()
        .await?
        .ok_or_else(|| CatalogError::Mapping("required catalog query returned no row".to_owned()))
}

fn required_value<'a, T>(row: &'a Row, index: usize, field: &str) -> Result<T, CatalogError>
where
    T: FromSql<'a>,
{
    row.try_get(index)
        .map_err(|error| CatalogError::Mapping(format!("cannot read {field}: {error}")))?
        .ok_or_else(|| CatalogError::Mapping(format!("required {field} is NULL")))
}

fn optional_value<'a, T>(row: &'a Row, index: usize) -> Result<Option<T>, CatalogError>
where
    T: FromSql<'a>,
{
    row.try_get(index).map_err(|error| {
        CatalogError::Mapping(format!(
            "cannot read optional catalog field at column {index}: {error}"
        ))
    })
}

fn required_string(row: &Row, index: usize, field: &str) -> Result<String, CatalogError> {
    let value = required_value::<&str>(row, index, field)?.to_owned();
    if value.is_empty() {
        return Err(CatalogError::Mapping(format!("required {field} is empty")));
    }
    if value.len() > MAX_PROPERTY_STRING_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "{field} exceeds the {MAX_PROPERTY_STRING_BYTES}-byte property limit"
        )));
    }
    Ok(value)
}

fn optional_string(row: &Row, index: usize) -> Result<Option<String>, CatalogError> {
    let value = optional_value::<&str>(row, index)?.map(str::to_owned);
    if value
        .as_ref()
        .is_some_and(|value| value.len() > MAX_PROPERTY_STRING_BYTES)
    {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "catalog property exceeds the {MAX_PROPERTY_STRING_BYTES}-byte limit"
        )));
    }
    Ok(value)
}

struct SqlServerSnapshotMapper {
    connection_alias: String,
    facts: ServerFacts,
    strategy: SqlServerCatalogVersion,
}

impl SqlServerSnapshotMapper {
    fn new(connection_alias: &str, facts: ServerFacts, strategy: SqlServerCatalogVersion) -> Self {
        Self {
            connection_alias: connection_alias.to_owned(),
            facts,
            strategy,
        }
    }

    fn map(self, raw: RawSqlServerCatalog) -> Result<CatalogDiscovery, CatalogError> {
        validate_raw_inventory(&raw)?;
        let database_name = self.facts.database.clone();
        let database_key = sqlserver_key(
            &self.connection_alias,
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
        let mut metadata = CanonicalMetadata::default();
        add_database_annotation(&mut metadata, &database_key, &self.facts, self.strategy);

        let mut principal_keys = BTreeMap::<i32, ObjectKey>::new();
        for principal in &raw.principals {
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &database_name,
                ObjectKind::Principal,
                &principal.name,
                Some(principal.id.to_string()),
            );
            if principal_keys.insert(principal.id, key.clone()).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate database principal id {}",
                    principal.id
                )));
            }
            let mut properties = BTreeMap::new();
            insert_string(&mut properties, "type", &principal.type_code);
            insert_string(&mut properties, "type_description", &principal.type_desc);
            insert_optional_string(
                &mut properties,
                "default_schema",
                principal.default_schema.as_deref(),
            );
            insert_string(
                &mut properties,
                "authentication_type",
                &principal.authentication_type,
            );
            insert_bool(&mut properties, "fixed_role", principal.fixed_role);
            insert_optional_i64(
                &mut properties,
                "owning_principal_id",
                principal.owning_principal_id.map(i64::from),
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

        let mut schemas = Vec::new();
        let mut schema_keys = BTreeMap::<String, ObjectKey>::new();
        let mut schema_id_keys = BTreeMap::<i32, ObjectKey>::new();
        let mut schema_owner_ids = BTreeMap::<String, i32>::new();
        for schema in &raw.schemas {
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &schema.name,
                ObjectKind::Schema,
                &schema.name,
                None,
            );
            if schema_keys
                .insert(schema.name.clone(), key.clone())
                .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "duplicate SQL Server schema '{}'",
                    schema.name
                )));
            }
            insert_unique_id(&mut schema_id_keys, schema.id, &key, "schema")?;
            schema_owner_ids.insert(schema.name.clone(), schema.principal_id);
            schemas.push(SchemaObject {
                key: key.clone(),
                database_key: database_key.clone(),
                name: schema.name.clone(),
            });
            add_owned_by(&mut metadata, &key, schema.principal_id, &principal_keys)?;
        }

        let mut object_keys = BTreeMap::<i32, ObjectKey>::new();
        let mut name_keys = BTreeMap::<(String, String), ObjectKey>::new();
        let mut type_keys = BTreeMap::<i32, ObjectKey>::new();
        let mut table_type_keys = BTreeMap::<i32, ObjectKey>::new();
        let mut table_type_user_ids = BTreeMap::<i32, i32>::new();
        for data_type in &raw.user_types {
            let schema_key =
                required_key(&schema_keys, &data_type.schema, "user-defined type schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &data_type.schema,
                ObjectKind::UserDefinedType,
                &data_type.name,
                None,
            );
            if type_keys.insert(data_type.id, key.clone()).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate user-defined type id {}",
                    data_type.id
                )));
            }
            if let Some(table_object_id) = data_type.table_object_id {
                insert_unique_id(
                    &mut table_type_keys,
                    table_object_id,
                    &key,
                    "table type object",
                )?;
                if object_keys.insert(table_object_id, key.clone()).is_some() {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate SQL Server object id {table_object_id} for table type '{}.{}'",
                        data_type.schema, data_type.name
                    )));
                }
                if table_type_user_ids
                    .insert(table_object_id, data_type.id)
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate SQL Server table type object id {table_object_id}"
                    )));
                }
            }
            let mut properties = BTreeMap::new();
            insert_i64(
                &mut properties,
                "system_type_id",
                i64::from(data_type.system_type_id),
            );
            insert_string(&mut properties, "base_type", &data_type.base_type);
            insert_i64(
                &mut properties,
                "max_length",
                i64::from(data_type.max_length),
            );
            insert_i64(&mut properties, "precision", i64::from(data_type.precision));
            insert_i64(&mut properties, "scale", i64::from(data_type.scale));
            insert_optional_string(&mut properties, "collation", data_type.collation.as_deref());
            insert_bool(&mut properties, "nullable", data_type.nullable);
            insert_bool(&mut properties, "user_defined", data_type.user_defined);
            insert_bool(&mut properties, "table_type", data_type.table_type);
            insert_bool(
                &mut properties,
                "memory_optimized",
                data_type.memory_optimized,
            );
            insert_optional_i64(
                &mut properties,
                "table_object_id",
                data_type.table_object_id.map(i64::from),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(schema_key.clone()),
                name: data_type.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }

        let xml_collection_keys = map_xml_schema_collections(
            &mut metadata,
            &self.connection_alias,
            &database_name,
            &raw.xml_schema_collections,
            &schema_keys,
            &schema_owner_ids,
            &principal_keys,
        )?;

        let mut sequence_keys = BTreeMap::<i32, ObjectKey>::new();
        for sequence in &raw.sequences {
            let schema_key = required_key(&schema_keys, &sequence.schema, "sequence schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &sequence.schema,
                ObjectKind::Sequence,
                &sequence.name,
                None,
            );
            insert_object_identity(
                &mut sequence_keys,
                &mut object_keys,
                &mut name_keys,
                sequence.id,
                &sequence.schema,
                &sequence.name,
                &key,
                "sequence",
            )?;
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "data_type",
                &qualified_type_name(&sequence.type_schema, &sequence.type_name),
            );
            insert_i64(&mut properties, "precision", i64::from(sequence.precision));
            insert_i64(&mut properties, "scale", i64::from(sequence.scale));
            insert_string(&mut properties, "start_value", &sequence.start_value);
            insert_string(&mut properties, "increment", &sequence.increment);
            insert_string(&mut properties, "minimum_value", &sequence.minimum_value);
            insert_string(&mut properties, "maximum_value", &sequence.maximum_value);
            insert_bool(&mut properties, "cyclic", sequence.cyclic);
            insert_optional_i64(
                &mut properties,
                "cache_size",
                sequence.cache_size.map(i64::from),
            );
            insert_bool(&mut properties, "exhausted", sequence.exhausted);
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(schema_key.clone()),
                name: sequence.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            if let Some(type_key) = type_keys.get(&sequence.type_id) {
                add_relationship(
                    &mut metadata,
                    MetadataRelationshipKind::UsesType,
                    &key,
                    type_key,
                    None,
                    BTreeMap::new(),
                );
            }
            add_effective_owner(
                &mut metadata,
                &key,
                sequence.principal_id,
                &sequence.schema,
                &schema_owner_ids,
                &principal_keys,
            )?;
        }

        let mut tables = Vec::new();
        let mut table_keys = BTreeMap::<i32, ObjectKey>::new();
        for table in &raw.tables {
            let schema_key = required_key(&schema_keys, &table.schema, "table schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &table.schema,
                ObjectKind::Table,
                &table.name,
                None,
            );
            insert_object_identity(
                &mut table_keys,
                &mut object_keys,
                &mut name_keys,
                table.id,
                &table.schema,
                &table.name,
                &key,
                "table",
            )?;
            tables.push(TableObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: table.name.clone(),
                kind: if table.external {
                    TableKind::Foreign
                } else {
                    TableKind::BaseTable
                },
            });
            add_table_annotation(&mut metadata, &key, table);
            add_effective_owner(
                &mut metadata,
                &key,
                table.principal_id,
                &table.schema,
                &schema_owner_ids,
                &principal_keys,
            )?;
        }

        let mut views = Vec::<ViewObject>::new();
        let mut view_keys = BTreeMap::<i32, ObjectKey>::new();
        for view in &raw.views {
            let schema_key = required_key(&schema_keys, &view.schema, "view schema")?;
            if view.indexed {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &view.schema,
                    ObjectKind::MaterializedView,
                    &view.name,
                    None,
                );
                insert_view_identity(&mut view_keys, &mut object_keys, &mut name_keys, view, &key)?;
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(schema_key.clone()),
                    name: view.name.clone(),
                    extension_kind: None,
                    definition: view.definition.clone(),
                    properties: view_properties(view),
                });
                add_effective_owner(
                    &mut metadata,
                    &key,
                    view.principal_id,
                    &view.schema,
                    &schema_owner_ids,
                    &principal_keys,
                )?;
            } else {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &view.schema,
                    ObjectKind::View,
                    &view.name,
                    None,
                );
                insert_view_identity(&mut view_keys, &mut object_keys, &mut name_keys, view, &key)?;
                views.push(ViewObject {
                    key: key.clone(),
                    schema_key: schema_key.clone(),
                    name: view.name.clone(),
                    definition: view.definition.clone(),
                    depends_on: Vec::new(),
                });
                add_annotation(&mut metadata, &key, None, view_properties(view));
                add_effective_owner(
                    &mut metadata,
                    &key,
                    view.principal_id,
                    &view.schema,
                    &schema_owner_ids,
                    &principal_keys,
                )?;
            }
        }

        let mut routines = Vec::<RoutineObject>::new();
        let mut routine_keys = BTreeMap::<i32, ObjectKey>::new();
        for routine in &raw.routines {
            let schema_key = required_key(&schema_keys, &routine.schema, "routine schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &routine.schema,
                ObjectKind::Routine,
                &routine.name,
                None,
            );
            insert_object_identity(
                &mut routine_keys,
                &mut object_keys,
                &mut name_keys,
                routine.id,
                &routine.schema,
                &routine.name,
                &key,
                "routine",
            )?;
            routines.push(RoutineObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: routine.name.clone(),
                kind: routine_kind(&routine.type_code)?,
                definition: routine.definition.clone(),
                depends_on: Vec::new(),
            });
            add_annotation(&mut metadata, &key, None, routine_properties(routine));
            add_effective_owner(
                &mut metadata,
                &key,
                routine.principal_id,
                &routine.schema,
                &schema_owner_ids,
                &principal_keys,
            )?;
        }

        let mut triggers = Vec::<TriggerObject>::new();
        let mut trigger_keys = BTreeMap::<i32, ObjectKey>::new();
        for trigger in &raw.triggers {
            let properties = trigger_properties(trigger);
            if trigger.parent_class == 1 {
                let parent_key = object_keys
                    .get(&trigger.parent_id)
                    .cloned()
                    .ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "trigger '{}' references missing parent object {}",
                            trigger.name, trigger.parent_id
                        ))
                    })?;
                if matches!(parent_key.object_kind, ObjectKind::Table | ObjectKind::View) {
                    let key = sqlserver_key(
                        &self.connection_alias,
                        &database_name,
                        &parent_key.schema,
                        ObjectKind::Trigger,
                        &parent_key.object_name,
                        Some(trigger.name.clone()),
                    );
                    insert_unique_id(&mut trigger_keys, trigger.id, &key, "trigger")?;
                    object_keys.insert(trigger.id, key.clone());
                    triggers.push(TriggerObject {
                        key: key.clone(),
                        table_key: parent_key,
                        name: trigger.name.clone(),
                        timing: Some(if trigger.instead_of {
                            "INSTEAD OF".to_owned()
                        } else {
                            "AFTER".to_owned()
                        }),
                        events: trigger.events.clone(),
                        definition: trigger.definition.clone(),
                        executes_routine_key: None,
                    });
                    add_annotation(&mut metadata, &key, None, properties);
                } else {
                    let key = metadata_trigger_key(&self.connection_alias, &database_name, trigger);
                    insert_unique_id(&mut trigger_keys, trigger.id, &key, "trigger")?;
                    object_keys.insert(trigger.id, key.clone());
                    metadata.objects.push(MetadataObject {
                        key,
                        parent_key: Some(parent_key),
                        name: trigger.name.clone(),
                        extension_kind: None,
                        definition: trigger.definition.clone(),
                        properties,
                    });
                }
            } else if trigger.parent_class == 0 {
                let key = metadata_trigger_key(&self.connection_alias, &database_name, trigger);
                insert_unique_id(&mut trigger_keys, trigger.id, &key, "database trigger")?;
                object_keys.insert(trigger.id, key.clone());
                metadata.objects.push(MetadataObject {
                    key,
                    parent_key: Some(database_key.clone()),
                    name: trigger.name.clone(),
                    extension_kind: None,
                    definition: trigger.definition.clone(),
                    properties,
                });
            } else {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "trigger '{}' has unsupported parent class {}",
                    trigger.name, trigger.parent_class
                )));
            }
        }

        let mut columns = Vec::<ColumnObject>::new();
        let mut column_keys = BTreeMap::<(i32, i32), ObjectKey>::new();
        let mut table_type_property_column_keys = BTreeMap::<(i32, i32), ObjectKey>::new();
        let mut dependency_source_keys = BTreeMap::<i32, ObjectKey>::new();
        for column in &raw.columns {
            let parent_key = object_keys.get(&column.object_id).cloned().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "column '{}.{}.{}' references an unmapped parent",
                    column.schema, column.relation, column.name
                ))
            })?;
            let key = if parent_key.object_kind == ObjectKind::Table {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &column.schema,
                    ObjectKind::Column,
                    &column.relation,
                    Some(column.name.clone()),
                );
                columns.push(ColumnObject {
                    key: key.clone(),
                    table_key: parent_key.clone(),
                    name: column.name.clone(),
                    ordinal_position: positive_u32(column.id, "column ordinal")?,
                    data_type: qualified_type_name(&column.type_schema, &column.type_name),
                    is_nullable: column.nullable,
                    default_value: column.default_definition.clone(),
                    is_generated: column.computed
                        || !column
                            .generated_always
                            .eq_ignore_ascii_case("NOT_APPLICABLE"),
                });
                add_annotation(&mut metadata, &key, None, column_properties(column));
                key
            } else if matches!(
                parent_key.object_kind,
                ObjectKind::View | ObjectKind::MaterializedView
            ) {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &column.schema,
                    ObjectKind::ViewColumn,
                    &column.relation,
                    Some(column.name.clone()),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(parent_key.clone()),
                    name: column.name.clone(),
                    extension_kind: None,
                    definition: None,
                    properties: column_properties(column),
                });
                key
            } else if parent_key.object_kind == ObjectKind::UserDefinedType
                && table_type_keys.contains_key(&column.object_id)
            {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &column.schema,
                    ObjectKind::Extension,
                    &parent_key.object_name,
                    Some(format!("table-type-column:{}:{}", column.id, column.name)),
                );
                let mut properties = column_properties(column);
                insert_i64(
                    &mut properties,
                    "ordinal_position",
                    i64::from(positive_u32(column.id, "table type column ordinal")?),
                );
                insert_string(
                    &mut properties,
                    "data_type",
                    &qualified_type_name(&column.type_schema, &column.type_name),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(parent_key.clone()),
                    name: column.name.clone(),
                    extension_kind: Some("sqlserver_table_type_column".to_owned()),
                    definition: column
                        .computed_definition
                        .clone()
                        .or_else(|| column.default_definition.clone()),
                    properties,
                });
                key
            } else {
                return Err(CatalogError::Mapping(format!(
                    "column parent '{}' has unsupported kind {}",
                    parent_key.object_name, parent_key.object_kind
                )));
            };
            if column_keys
                .insert((column.object_id, column.id), key.clone())
                .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "duplicate column identity {}:{}",
                    column.object_id, column.id
                )));
            }
            if let Some(user_type_id) = table_type_user_ids.get(&column.object_id) {
                if table_type_property_column_keys
                    .insert((*user_type_id, column.id), key.clone())
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate table type property column identity {}:{}",
                        user_type_id, column.id
                    )));
                }
            }
            if column.default_object_id > 0
                && dependency_source_keys
                    .insert(column.default_object_id, key.clone())
                    .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "default constraint id {} maps to multiple columns",
                    column.default_object_id
                )));
            }
            if let Some(type_key) = type_keys.get(&column.type_id) {
                add_relationship(
                    &mut metadata,
                    if key.object_kind == ObjectKind::Extension {
                        MetadataRelationshipKind::DependsOn
                    } else {
                        MetadataRelationshipKind::UsesType
                    },
                    &key,
                    type_key,
                    None,
                    BTreeMap::new(),
                );
            }
            if column.xml_collection_id > 0 {
                let collection_key = xml_collection_keys
                    .get(&column.xml_collection_id)
                    .ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "column '{}.{}.{}' references missing XML schema collection {}",
                            column.schema, column.relation, column.name, column.xml_collection_id
                        ))
                    })?;
                add_relationship(
                    &mut metadata,
                    MetadataRelationshipKind::Extension("uses_xml_schema_collection".to_owned()),
                    &key,
                    collection_key,
                    None,
                    BTreeMap::new(),
                );
            }
        }

        let mut constraints = Vec::<ConstraintObject>::new();
        let mut constraint_keys = BTreeMap::<i32, ObjectKey>::new();
        for constraint in &raw.constraints {
            let parent_key = object_keys
                .get(&constraint.table_id)
                .cloned()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "constraint '{}.{}.{}' references an unmapped parent",
                        constraint.schema, constraint.table, constraint.name
                    ))
                })?;
            require_contiguous_ordinals(
                constraint.columns.iter().map(|column| column.ordinal),
                &format!("constraint '{}.{}'", constraint.table, constraint.name),
            )?;
            let resolved_columns = constraint
                .columns
                .iter()
                .map(|column| {
                    column_keys
                        .get(&(constraint.table_id, column.column_id))
                        .cloned()
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "constraint '{}.{}' lost column '{}'",
                                constraint.table, constraint.name, column.name
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (referenced_table_key, referenced_columns) = if constraint.kind
                == ConstraintKind::ForeignKey
            {
                if parent_key.object_kind != ObjectKind::Table {
                    return Err(CatalogError::UnsupportedMetadata(format!(
                        "table type constraint '{}' unexpectedly declares a foreign key",
                        constraint.name
                    )));
                }
                let target_id = constraint.referenced_table_id.ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key '{}' has no referenced table id",
                        constraint.name
                    ))
                })?;
                let target = table_keys.get(&target_id).cloned().ok_or_else(|| {
                    CatalogError::InvalidScope(format!(
                        "foreign key '{}.{}.{}' references a table outside the selected schema scope; include schema '{}'",
                        constraint.schema,
                        constraint.table,
                        constraint.name,
                        constraint.referenced_schema.as_deref().unwrap_or("unknown")
                    ))
                })?;
                let targets = constraint
                    .columns
                    .iter()
                    .map(|column| {
                        let target_column_id = column.referenced_column_id.ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "foreign key '{}' lacks a referenced column id",
                                constraint.name
                            ))
                        })?;
                        column_keys
                            .get(&(target_id, target_column_id))
                            .cloned()
                            .ok_or_else(|| {
                                CatalogError::Mapping(format!(
                                    "foreign key '{}' lost referenced column '{}'",
                                    constraint.name,
                                    column.referenced_name.as_deref().unwrap_or("unknown")
                                ))
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (Some(target), targets)
            } else {
                (None, Vec::new())
            };
            let table_constraint = parent_key.object_kind == ObjectKind::Table;
            let key = if table_constraint {
                sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &constraint.schema,
                    constraint_object_kind(constraint.kind),
                    &constraint.table,
                    Some(constraint.name.clone()),
                )
            } else if parent_key.object_kind == ObjectKind::UserDefinedType
                && table_type_keys.contains_key(&constraint.table_id)
            {
                sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &constraint.schema,
                    ObjectKind::Extension,
                    &parent_key.object_name,
                    Some(format!(
                        "table-type-constraint:{}:{}",
                        constraint.id, constraint.name
                    )),
                )
            } else {
                return Err(CatalogError::Mapping(format!(
                    "constraint '{}' has unsupported parent kind {}",
                    constraint.name, parent_key.object_kind
                )));
            };
            insert_unique_id(&mut constraint_keys, constraint.id, &key, "constraint")?;
            object_keys.insert(constraint.id, key.clone());
            if table_constraint {
                constraints.push(ConstraintObject {
                    key: key.clone(),
                    table_key: parent_key,
                    name: constraint.name.clone(),
                    kind: constraint.kind,
                    columns: resolved_columns,
                    referenced_table_key,
                    referenced_columns,
                    expression: constraint.expression.clone(),
                });
                add_annotation(&mut metadata, &key, None, constraint_properties(constraint));
            } else {
                let mut properties = constraint_properties(constraint);
                insert_string(
                    &mut properties,
                    "constraint_kind",
                    &constraint_object_kind(constraint.kind).to_string(),
                );
                properties.insert(
                    "columns".to_owned(),
                    MetadataValue::StringList(
                        resolved_columns.iter().map(ObjectKey::to_string).collect(),
                    ),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(parent_key),
                    name: constraint.name.clone(),
                    extension_kind: Some("sqlserver_table_type_constraint".to_owned()),
                    definition: constraint.expression.clone(),
                    properties,
                });
                for (ordinal, column_key) in resolved_columns.iter().enumerate() {
                    add_relationship(
                        &mut metadata,
                        MetadataRelationshipKind::Extension(
                            "table_type_constraint_column".to_owned(),
                        ),
                        &key,
                        column_key,
                        Some((ordinal + 1) as u32),
                        BTreeMap::new(),
                    );
                }
            }
        }

        let mut indexes = Vec::<IndexObject>::new();
        let mut index_keys = BTreeMap::<(i32, i32), ObjectKey>::new();
        for index in &raw.indexes {
            let parent_key = object_keys.get(&index.object_id).cloned().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "index '{}.{}.{}' references missing relation",
                    index.schema, index.relation, index.name
                ))
            })?;
            let mut key_columns = index
                .columns
                .iter()
                .filter(|column| column.key_ordinal > 0)
                .collect::<Vec<_>>();
            if key_columns.is_empty() {
                key_columns = index.columns.iter().collect();
            }
            key_columns.sort_by_key(|column| {
                if column.key_ordinal > 0 {
                    column.key_ordinal
                } else {
                    column.index_column_id
                }
            });
            let resolved_columns = key_columns
                .iter()
                .map(|column| {
                    column_keys
                        .get(&(index.object_id, column.column_id))
                        .cloned()
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "index '{}.{}' lost column '{}'",
                                index.relation, index.name, column.name
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parent_key.object_kind == ObjectKind::Table {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &index.schema,
                    ObjectKind::Index,
                    &index.relation,
                    Some(index.name.clone()),
                );
                if index_keys
                    .insert((index.object_id, index.id), key.clone())
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate index identity {}:{}",
                        index.object_id, index.id
                    )));
                }
                indexes.push(IndexObject {
                    key: key.clone(),
                    table_key: parent_key,
                    name: index.name.clone(),
                    columns: resolved_columns,
                    is_unique: index.unique,
                    is_primary: index.primary,
                    predicate: index.filter.clone(),
                    expression: None,
                });
                add_annotation(&mut metadata, &key, None, index_properties(index));
                add_included_column_relationships(&mut metadata, &key, index, &column_keys)?;
            } else if parent_key.object_kind == ObjectKind::MaterializedView {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &index.schema,
                    ObjectKind::Index,
                    &index.relation,
                    Some(index.name.clone()),
                );
                if index_keys
                    .insert((index.object_id, index.id), key.clone())
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate indexed-view index identity {}:{}",
                        index.object_id, index.id
                    )));
                }
                let mut properties = index_properties(index);
                properties.insert(
                    "key_columns".to_owned(),
                    MetadataValue::StringList(
                        resolved_columns.iter().map(ObjectKey::to_string).collect(),
                    ),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(parent_key),
                    name: index.name.clone(),
                    extension_kind: None,
                    definition: index.filter.clone(),
                    properties,
                });
                add_included_column_relationships(&mut metadata, &key, index, &column_keys)?;
            } else if parent_key.object_kind == ObjectKind::UserDefinedType
                && table_type_keys.contains_key(&index.object_id)
            {
                let key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &index.schema,
                    ObjectKind::Extension,
                    &parent_key.object_name,
                    Some(format!("table-type-index:{}:{}", index.id, index.name)),
                );
                if index_keys
                    .insert((index.object_id, index.id), key.clone())
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate table type index identity {}:{}",
                        index.object_id, index.id
                    )));
                }
                let mut properties = index_properties(index);
                properties.insert(
                    "key_columns".to_owned(),
                    MetadataValue::StringList(
                        resolved_columns.iter().map(ObjectKey::to_string).collect(),
                    ),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(parent_key),
                    name: index.name.clone(),
                    extension_kind: Some("sqlserver_table_type_index".to_owned()),
                    definition: index.filter.clone(),
                    properties,
                });
                for column in &index.columns {
                    let column_key = column_keys
                        .get(&(index.object_id, column.column_id))
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "table type index '{}.{}' lost column '{}'",
                                index.relation, index.name, column.name
                            ))
                        })?;
                    let mut relationship_properties = BTreeMap::new();
                    insert_bool(
                        &mut relationship_properties,
                        "descending",
                        column.descending,
                    );
                    insert_bool(&mut relationship_properties, "included", column.included);
                    add_relationship(
                        &mut metadata,
                        MetadataRelationshipKind::Extension("table_type_index_column".to_owned()),
                        &key,
                        column_key,
                        Some(positive_u32(
                            column.index_column_id,
                            "table type index column ordinal",
                        )?),
                        relationship_properties,
                    );
                }
            } else {
                return Err(CatalogError::Mapping(format!(
                    "index '{}' has unsupported parent kind {}",
                    index.name, parent_key.object_kind
                )));
            }
        }

        let mut parameter_keys = BTreeMap::<(i32, i32), ObjectKey>::new();
        for parameter in &raw.parameters {
            let routine_key = routine_keys
                .get(&parameter.object_id)
                .cloned()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "parameter '{}:{}' references missing routine",
                        parameter.object_id, parameter.id
                    ))
                })?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &routine_key.schema,
                ObjectKind::RoutineParameter,
                &routine_key.object_name,
                Some(format!("{}:{}", parameter.id, parameter.name)),
            );
            if parameter_keys
                .insert((parameter.object_id, parameter.id), key.clone())
                .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "duplicate routine parameter identity {}:{}",
                    parameter.object_id, parameter.id
                )));
            }
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(routine_key.clone()),
                name: parameter.name.clone(),
                extension_kind: None,
                definition: None,
                properties: parameter_properties(parameter),
            });
            add_relationship(
                &mut metadata,
                MetadataRelationshipKind::HasParameter,
                &routine_key,
                &key,
                Some(positive_u32_or_return(parameter.id)?),
                BTreeMap::new(),
            );
            if let Some(type_key) = type_keys.get(&parameter.type_id) {
                add_relationship(
                    &mut metadata,
                    if parameter.id == 0 {
                        MetadataRelationshipKind::ReturnsType
                    } else {
                        MetadataRelationshipKind::UsesType
                    },
                    if parameter.id == 0 {
                        &routine_key
                    } else {
                        &key
                    },
                    type_key,
                    None,
                    BTreeMap::new(),
                );
            }
            if parameter.xml_collection_id > 0 {
                let collection_key = xml_collection_keys
                    .get(&parameter.xml_collection_id)
                    .ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "routine parameter '{}:{}' references missing XML schema collection {}",
                            parameter.object_id, parameter.id, parameter.xml_collection_id
                        ))
                    })?;
                add_relationship(
                    &mut metadata,
                    MetadataRelationshipKind::Extension("uses_xml_schema_collection".to_owned()),
                    if parameter.id == 0 {
                        &routine_key
                    } else {
                        &key
                    },
                    collection_key,
                    None,
                    BTreeMap::new(),
                );
            }
        }

        let mut synonym_keys = BTreeMap::<i32, ObjectKey>::new();
        for synonym in &raw.synonyms {
            let schema_key = required_key(&schema_keys, &synonym.schema, "synonym schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &synonym.schema,
                ObjectKind::Synonym,
                &synonym.name,
                None,
            );
            insert_unique_id(&mut synonym_keys, synonym.id, &key, "synonym")?;
            object_keys.insert(synonym.id, key.clone());
            name_keys.insert((synonym.schema.clone(), synonym.name.clone()), key.clone());
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "base_object_name",
                &synonym.base_object_name,
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(schema_key.clone()),
                name: synonym.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            add_effective_owner(
                &mut metadata,
                &key,
                synonym.principal_id,
                &synonym.schema,
                &schema_owner_ids,
                &principal_keys,
            )?;
        }

        let mut policy_keys = BTreeMap::<i32, ObjectKey>::new();
        for policy in &raw.security_policies {
            let schema_key = required_key(&schema_keys, &policy.schema, "security policy schema")?;
            let key = sqlserver_key(
                &self.connection_alias,
                &database_name,
                &policy.schema,
                ObjectKind::Policy,
                &policy.name,
                None,
            );
            insert_unique_id(&mut policy_keys, policy.id, &key, "security policy")?;
            object_keys.insert(policy.id, key.clone());
            let mut properties = BTreeMap::new();
            insert_bool(&mut properties, "enabled", policy.enabled);
            insert_bool(&mut properties, "schema_bound", policy.schema_bound);
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(schema_key.clone()),
                name: policy.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            add_effective_owner(
                &mut metadata,
                &key,
                policy.principal_id,
                &policy.schema,
                &schema_owner_ids,
                &principal_keys,
            )?;
            for predicate in &policy.predicates {
                let predicate_key = sqlserver_key(
                    &self.connection_alias,
                    &database_name,
                    &policy.schema,
                    ObjectKind::Extension,
                    &policy.name,
                    Some(format!("predicate:{}", predicate.id)),
                );
                let mut properties = BTreeMap::new();
                insert_string(&mut properties, "predicate_type", &predicate.predicate_type);
                insert_optional_string(
                    &mut properties,
                    "operation",
                    predicate.operation.as_deref(),
                );
                insert_i64(
                    &mut properties,
                    "definition_bytes",
                    i64::from(predicate.definition_bytes),
                );
                metadata.objects.push(MetadataObject {
                    key: predicate_key.clone(),
                    parent_key: Some(key.clone()),
                    name: format!("{} predicate {}", policy.name, predicate.id),
                    extension_kind: Some("sqlserver_security_predicate".to_owned()),
                    definition: Some(predicate.definition.clone()),
                    properties,
                });
                let target_key = table_keys
                    .get(&predicate.target_object_id)
                    .or_else(|| view_keys.get(&predicate.target_object_id))
                    .cloned()
                    .ok_or_else(|| {
                        CatalogError::InvalidScope(format!(
                            "security policy '{}.{}' targets an object outside the selected schema scope",
                            policy.schema, policy.name
                        ))
                    })?;
                add_relationship(
                    &mut metadata,
                    MetadataRelationshipKind::Extension("security_predicate_applies_to".to_owned()),
                    &predicate_key,
                    &target_key,
                    None,
                    BTreeMap::new(),
                );
            }
        }

        let partition_mapping = map_partitions(
            &mut metadata,
            &self.connection_alias,
            &database_name,
            &database_key,
            &raw,
            &object_keys,
            &index_keys,
        )?;

        map_extended_properties(
            &mut metadata,
            &self.connection_alias,
            &database_name,
            &raw.extended_properties,
            ExtendedPropertyTargetRegistry {
                database: &database_key,
                schemas: &schema_id_keys,
                principals: &principal_keys,
                objects: &object_keys,
                columns: &column_keys,
                table_type_columns: &table_type_property_column_keys,
                parameters: &parameter_keys,
                user_types: &type_keys,
                indexes: &index_keys,
                xml_collections: &xml_collection_keys,
                partition_schemes: &partition_mapping.scheme_keys,
                partition_functions: &partition_mapping.function_keys,
            },
        )?;

        let mut external_reference_keys = BTreeMap::<String, ObjectKey>::new();
        map_synonym_targets(
            &mut metadata,
            &database_name,
            &raw.synonyms,
            &synonym_keys,
            &name_keys,
            &mut external_reference_keys,
            &self.connection_alias,
            &database_key,
        )?;
        let dependency_result = map_dependencies(
            &mut metadata,
            &raw.dependencies,
            &object_keys,
            &column_keys,
            &dependency_source_keys,
            &type_keys,
            &xml_collection_keys,
            &index_keys,
            &partition_mapping.function_keys,
            &name_keys,
            &mut external_reference_keys,
            &self.connection_alias,
            &database_name,
            &database_key,
        )?;

        let view_positions = raw
            .views
            .iter()
            .filter(|view| !view.indexed)
            .enumerate()
            .map(|(position, view)| (view.id, position))
            .collect::<BTreeMap<_, _>>();
        for (view_id, dependencies) in &dependency_result.view_dependencies {
            let position = view_positions.get(view_id).copied().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "dependency ledger references missing ordinary view {view_id}"
                ))
            })?;
            views[position].depends_on = dependencies.clone();
        }
        let routine_positions = raw
            .routines
            .iter()
            .enumerate()
            .map(|(position, routine)| (routine.id, position))
            .collect::<BTreeMap<_, _>>();
        for (routine_id, dependencies) in &dependency_result.routine_dependencies {
            let position = routine_positions.get(routine_id).copied().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "dependency ledger references missing routine {routine_id}"
                ))
            })?;
            routines[position].depends_on = dependencies.clone();
        }

        let projection_ledger = SqlServerProjectionLedger {
            external_reference_objects: external_reference_keys.len() as u64,
            view_dependencies: dependency_result.view_dependency_count(),
            routine_dependencies: dependency_result.routine_dependency_count(),
            dependency_metadata_relationships: dependency_result.metadata_relationship_count,
        };

        add_principal_memberships(&mut metadata, &raw.principals, &principal_keys)?;
        validate_relationship_uniqueness(&metadata.relationships)?;

        let snapshot = CanonicalSchemaSnapshot {
            schema: SchemaSnapshot {
                source_kind: SQLSERVER_SOURCE.to_owned(),
                connection_alias: self.connection_alias.clone(),
                database,
                schemas,
                tables,
                columns,
                constraints,
                indexes,
                views,
                triggers,
                routines,
                capabilities: sqlserver_capabilities(),
            },
            metadata,
        };
        let discovered_counts = discovery_counts_from_catalog(&raw, &snapshot, projection_ledger)?;
        Ok(CatalogDiscovery {
            snapshot,
            adapter: AdapterIdentity {
                name: "database-memory-sqlserver-catalog".to_owned(),
                version: SQLSERVER_ADAPTER_VERSION.to_owned(),
            },
            server: ServerIdentity {
                product: "Microsoft SQL Server".to_owned(),
                version: self.facts.version.clone(),
            },
            scope: IntrospectionScope {
                catalogs: vec![database_name],
                schemas: raw
                    .schemas
                    .iter()
                    .map(|schema| schema.name.clone())
                    .collect(),
            },
            discovered_counts,
            capability_checks: sqlserver_capability_checks(&self.facts, self.strategy),
        })
    }
}

fn validate_raw_inventory(raw: &RawSqlServerCatalog) -> Result<(), CatalogError> {
    require_unique(raw.schemas.iter().map(|schema| schema.id), "schema id")?;
    require_unique(
        raw.principals.iter().map(|principal| principal.id),
        "principal id",
    )?;
    require_unique(raw.tables.iter().map(|table| table.id), "table id")?;
    require_unique(
        raw.columns
            .iter()
            .map(|column| (column.object_id, column.id)),
        "column identity",
    )?;
    require_unique(raw.views.iter().map(|view| view.id), "view id")?;
    require_unique(raw.routines.iter().map(|routine| routine.id), "routine id")?;
    require_unique(
        raw.parameters
            .iter()
            .map(|parameter| (parameter.object_id, parameter.id)),
        "routine parameter identity",
    )?;
    require_unique(raw.triggers.iter().map(|trigger| trigger.id), "trigger id")?;
    require_unique(
        raw.constraints.iter().map(|constraint| constraint.id),
        "constraint id",
    )?;
    require_unique(
        raw.user_types.iter().map(|data_type| data_type.id),
        "user-defined type id",
    )?;
    require_unique(
        raw.sequences.iter().map(|sequence| sequence.id),
        "sequence id",
    )?;
    require_unique(raw.synonyms.iter().map(|synonym| synonym.id), "synonym id")?;
    require_unique(
        raw.indexes.iter().map(|index| (index.object_id, index.id)),
        "index identity",
    )?;
    require_unique(
        raw.partition_functions.iter().map(|function| function.id),
        "partition function id",
    )?;
    require_unique(
        raw.partition_schemes.iter().map(|scheme| scheme.id),
        "partition scheme id",
    )?;
    require_unique(
        raw.security_policies.iter().map(|policy| policy.id),
        "security policy id",
    )?;
    require_unique(
        raw.security_policies.iter().flat_map(|policy| {
            policy
                .predicates
                .iter()
                .map(move |predicate| (policy.id, predicate.id))
        }),
        "security predicate identity",
    )?;
    require_unique(
        raw.xml_schema_collections
            .iter()
            .map(|collection| collection.id),
        "XML schema collection id",
    )?;
    require_unique(
        raw.xml_schema_collections.iter().flat_map(|collection| {
            collection
                .namespaces
                .iter()
                .map(move |namespace| (collection.id, namespace.id))
        }),
        "XML schema namespace identity",
    )?;
    require_unique(
        raw.extended_properties.iter().map(|property| {
            (
                property.class,
                property.major_id,
                property.minor_id,
                property.name.clone(),
            )
        }),
        "extended property identity",
    )?;
    for property in &raw.extended_properties {
        let value_is_null = property.value_type.is_none();
        let typed_fields_are_empty = property.value_precision.is_none()
            && property.value_scale.is_none()
            && property.value_max_length.is_none()
            && property.value_collation.is_none()
            && property.display_value.is_none()
            && property.value_hex.is_none();
        if value_is_null != typed_fields_are_empty {
            return Err(CatalogError::Mapping(format!(
                "extended property '{}:{}:{}:{}' has inconsistent sql_variant metadata",
                property.class, property.major_id, property.minor_id, property.name
            )));
        }
    }
    Ok(())
}

fn require_unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    subject: &str,
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(CatalogError::Mapping(format!(
                "duplicate {subject} in raw catalog"
            )));
        }
    }
    Ok(())
}

fn sqlserver_key(
    connection_alias: &str,
    database: &str,
    schema: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        SQLSERVER_SOURCE,
        connection_alias,
        database,
        schema,
        object_kind,
        object_name,
        sub_object,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_object_identity(
    kind_keys: &mut BTreeMap<i32, ObjectKey>,
    object_keys: &mut BTreeMap<i32, ObjectKey>,
    name_keys: &mut BTreeMap<(String, String), ObjectKey>,
    id: i32,
    schema: &str,
    name: &str,
    key: &ObjectKey,
    kind: &str,
) -> Result<(), CatalogError> {
    insert_unique_id(kind_keys, id, key, kind)?;
    if object_keys.insert(id, key.clone()).is_some() {
        return Err(CatalogError::Mapping(format!(
            "object id {id} is shared by multiple mapped objects"
        )));
    }
    if name_keys
        .insert((schema.to_owned(), name.to_owned()), key.clone())
        .is_some()
    {
        return Err(CatalogError::Mapping(format!(
            "duplicate schema object name '{schema}.{name}'"
        )));
    }
    Ok(())
}

fn insert_view_identity(
    view_keys: &mut BTreeMap<i32, ObjectKey>,
    object_keys: &mut BTreeMap<i32, ObjectKey>,
    name_keys: &mut BTreeMap<(String, String), ObjectKey>,
    view: &RawView,
    key: &ObjectKey,
) -> Result<(), CatalogError> {
    insert_object_identity(
        view_keys,
        object_keys,
        name_keys,
        view.id,
        &view.schema,
        &view.name,
        key,
        "view",
    )
}

fn insert_unique_id(
    keys: &mut BTreeMap<i32, ObjectKey>,
    id: i32,
    key: &ObjectKey,
    subject: &str,
) -> Result<(), CatalogError> {
    if keys.insert(id, key.clone()).is_some() {
        return Err(CatalogError::Mapping(format!(
            "duplicate {subject} id {id}"
        )));
    }
    Ok(())
}

fn required_key<'a>(
    keys: &'a BTreeMap<String, ObjectKey>,
    name: &str,
    subject: &str,
) -> Result<&'a ObjectKey, CatalogError> {
    keys.get(name)
        .ok_or_else(|| CatalogError::Mapping(format!("{subject} '{name}' is not mapped")))
}

fn add_database_annotation(
    metadata: &mut CanonicalMetadata,
    database_key: &ObjectKey,
    facts: &ServerFacts,
    strategy: SqlServerCatalogVersion,
) {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "server_version", &facts.version);
    insert_i64(&mut properties, "server_major", i64::from(facts.major));
    insert_i64(
        &mut properties,
        "engine_edition",
        i64::from(facts.engine_edition),
    );
    insert_string(&mut properties, "edition", &facts.edition);
    insert_string(&mut properties, "current_user", &facts.current_user);
    insert_string(&mut properties, "login", &facts.login);
    insert_string(&mut properties, "original_login", &facts.original_login);
    insert_string(&mut properties, "collation", &facts.collation);
    insert_i64(
        &mut properties,
        "compatibility_level",
        i64::from(facts.compatibility_level),
    );
    insert_bool(
        &mut properties,
        "database_read_only",
        facts.database_read_only,
    );
    insert_string(&mut properties, "containment", &facts.containment);
    insert_bool(
        &mut properties,
        "encrypted_transport",
        facts.encrypted_transport,
    );
    insert_string(
        &mut properties,
        "catalog_strategy",
        strategy.strategy_name(),
    );
    add_annotation(metadata, database_key, None, properties);
}

fn add_table_annotation(metadata: &mut CanonicalMetadata, key: &ObjectKey, table: &RawTable) {
    let mut properties = BTreeMap::new();
    insert_i64(
        &mut properties,
        "lob_data_space_id",
        i64::from(table.lob_data_space_id),
    );
    insert_optional_i64(
        &mut properties,
        "filestream_data_space_id",
        table.filestream_data_space_id.map(i64::from),
    );
    insert_bool(&mut properties, "replicated", table.replicated);
    insert_bool(&mut properties, "merge_published", table.merge_published);
    insert_bool(
        &mut properties,
        "sync_transaction_subscribed",
        table.sync_tran_subscribed,
    );
    insert_bool(&mut properties, "cdc_tracked", table.cdc_tracked);
    insert_bool(
        &mut properties,
        "lock_on_bulk_load",
        table.lock_on_bulk_load,
    );
    insert_bool(&mut properties, "file_table", table.file_table);
    insert_bool(&mut properties, "memory_optimized", table.memory_optimized);
    insert_string(&mut properties, "durability", &table.durability);
    insert_string(&mut properties, "temporal_type", &table.temporal_type);
    insert_optional_string(
        &mut properties,
        "history_schema",
        table.history_schema.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "history_table",
        table.history_table.as_deref(),
    );
    insert_bool(
        &mut properties,
        "remote_data_archive",
        table.remote_data_archive,
    );
    insert_bool(&mut properties, "graph_node", table.node);
    insert_bool(&mut properties, "graph_edge", table.edge);
    insert_string(&mut properties, "ledger_type", &table.ledger_type);
    add_annotation(metadata, key, None, properties);
}

fn view_properties(view: &RawView) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_bool(&mut properties, "replicated", view.replicated);
    insert_bool(
        &mut properties,
        "replication_filter",
        view.replication_filter,
    );
    insert_bool(&mut properties, "schema_bound", view.schema_bound);
    insert_bool(&mut properties, "ansi_nulls", view.ansi_nulls);
    insert_bool(&mut properties, "quoted_identifier", view.quoted_identifier);
    insert_optional_i64(
        &mut properties,
        "execute_as_principal_id",
        view.execute_as_principal_id.map(i64::from),
    );
    insert_bool(&mut properties, "indexed", view.indexed);
    properties
}

fn routine_properties(routine: &RawRoutine) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "type", &routine.type_code);
    insert_string(&mut properties, "type_description", &routine.type_desc);
    insert_bool(&mut properties, "schema_bound", routine.schema_bound);
    insert_bool(&mut properties, "recompiled", routine.recompiled);
    insert_bool(
        &mut properties,
        "native_compilation",
        routine.native_compilation,
    );
    insert_bool(&mut properties, "ansi_nulls", routine.ansi_nulls);
    insert_bool(
        &mut properties,
        "quoted_identifier",
        routine.quoted_identifier,
    );
    insert_optional_i64(
        &mut properties,
        "execute_as_principal_id",
        routine.execute_as_principal_id.map(i64::from),
    );
    insert_bool(
        &mut properties,
        "null_on_null_input",
        routine.null_on_null_input,
    );
    insert_bool(&mut properties, "inlineable", routine.inlineable);
    insert_bool(&mut properties, "inline_type", routine.inline_type);
    insert_bool(&mut properties, "startup", routine.startup);
    insert_bool(&mut properties, "replication", routine.replication);
    properties
}

fn trigger_properties(trigger: &RawTrigger) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(
        &mut properties,
        "parent_class",
        i64::from(trigger.parent_class),
    );
    insert_bool(&mut properties, "instead_of", trigger.instead_of);
    insert_bool(&mut properties, "disabled", trigger.disabled);
    insert_bool(
        &mut properties,
        "not_for_replication",
        trigger.not_for_replication,
    );
    insert_bool(&mut properties, "schema_bound", trigger.schema_bound);
    insert_optional_i64(
        &mut properties,
        "execute_as_principal_id",
        trigger.execute_as_principal_id.map(i64::from),
    );
    properties.insert(
        "events".to_owned(),
        MetadataValue::StringList(trigger.events.clone()),
    );
    properties
}

fn metadata_trigger_key(connection_alias: &str, database: &str, trigger: &RawTrigger) -> ObjectKey {
    sqlserver_key(
        connection_alias,
        database,
        trigger.parent_schema.as_deref().unwrap_or(database),
        ObjectKind::Trigger,
        &trigger.name,
        Some(trigger.id.to_string()),
    )
}

fn column_properties(column: &RawColumn) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "column_id", i64::from(column.id));
    insert_string(
        &mut properties,
        "data_type",
        &qualified_type_name(&column.type_schema, &column.type_name),
    );
    insert_i64(&mut properties, "max_length", i64::from(column.max_length));
    insert_i64(&mut properties, "precision", i64::from(column.precision));
    insert_i64(&mut properties, "scale", i64::from(column.scale));
    insert_optional_string(&mut properties, "collation", column.collation.as_deref());
    insert_bool(&mut properties, "nullable", column.nullable);
    insert_bool(&mut properties, "ansi_padded", column.ansi_padded);
    insert_bool(&mut properties, "rowguid", column.rowguid);
    insert_bool(&mut properties, "identity", column.identity);
    insert_optional_string(
        &mut properties,
        "identity_seed",
        column.identity_seed.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "identity_increment",
        column.identity_increment.as_deref(),
    );
    insert_bool(&mut properties, "computed", column.computed);
    insert_optional_string(
        &mut properties,
        "computed_definition",
        column.computed_definition.as_deref(),
    );
    if let Some(persisted) = column.persisted {
        insert_bool(&mut properties, "computed_persisted", persisted);
    }
    insert_optional_string(
        &mut properties,
        "default_definition",
        column.default_definition.as_deref(),
    );
    insert_bool(&mut properties, "filestream", column.filestream);
    insert_bool(&mut properties, "replicated", column.replicated);
    insert_bool(
        &mut properties,
        "non_sql_subscribed",
        column.non_sql_subscribed,
    );
    insert_bool(&mut properties, "merge_published", column.merge_published);
    insert_bool(&mut properties, "dts_replicated", column.dts_replicated);
    insert_bool(&mut properties, "xml_document", column.xml_document);
    insert_i64(
        &mut properties,
        "xml_collection_id",
        i64::from(column.xml_collection_id),
    );
    insert_bool(&mut properties, "sparse", column.sparse);
    insert_bool(&mut properties, "column_set", column.column_set);
    insert_string(
        &mut properties,
        "generated_always",
        &column.generated_always,
    );
    insert_optional_string(
        &mut properties,
        "encryption_type",
        column.encryption_type.as_deref(),
    );
    insert_bool(&mut properties, "hidden", column.hidden);
    insert_bool(&mut properties, "masked", column.masked);
    insert_optional_string(
        &mut properties,
        "masking_function",
        column.masking_function.as_deref(),
    );
    insert_optional_string(&mut properties, "graph_type", column.graph_type.as_deref());
    properties
}

fn constraint_properties(constraint: &RawConstraint) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_bool(&mut properties, "disabled", constraint.disabled);
    insert_bool(&mut properties, "not_trusted", constraint.not_trusted);
    insert_bool(
        &mut properties,
        "not_for_replication",
        constraint.not_for_replication,
    );
    insert_optional_string(
        &mut properties,
        "delete_action",
        constraint.delete_action.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "update_action",
        constraint.update_action.as_deref(),
    );
    properties
}

fn index_properties(index: &RawIndex) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "index_id", i64::from(index.id));
    insert_i64(&mut properties, "type_code", i64::from(index.type_code));
    insert_string(&mut properties, "type_description", &index.type_desc);
    insert_bool(&mut properties, "unique", index.unique);
    insert_bool(&mut properties, "primary", index.primary);
    insert_bool(
        &mut properties,
        "unique_constraint",
        index.unique_constraint,
    );
    insert_bool(&mut properties, "disabled", index.disabled);
    insert_bool(&mut properties, "hypothetical", index.hypothetical);
    insert_bool(&mut properties, "padded", index.padded);
    insert_i64(&mut properties, "fill_factor", i64::from(index.fill_factor));
    insert_bool(
        &mut properties,
        "ignore_duplicate_key",
        index.ignore_duplicate_key,
    );
    insert_bool(&mut properties, "allow_row_locks", index.allow_row_locks);
    insert_bool(&mut properties, "allow_page_locks", index.allow_page_locks);
    insert_bool(&mut properties, "auto_created", index.auto_created);
    insert_i64(
        &mut properties,
        "data_space_id",
        i64::from(index.data_space_id),
    );
    properties
}

fn parameter_properties(parameter: &RawParameter) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "parameter_id", i64::from(parameter.id));
    insert_string(
        &mut properties,
        "data_type",
        &qualified_type_name(&parameter.type_schema, &parameter.type_name),
    );
    insert_i64(
        &mut properties,
        "max_length",
        i64::from(parameter.max_length),
    );
    insert_i64(&mut properties, "precision", i64::from(parameter.precision));
    insert_i64(&mut properties, "scale", i64::from(parameter.scale));
    insert_bool(&mut properties, "output", parameter.output);
    insert_bool(&mut properties, "readonly", parameter.readonly);
    insert_bool(&mut properties, "nullable", parameter.nullable);
    insert_optional_string(
        &mut properties,
        "default_value",
        parameter.default_value.as_deref(),
    );
    insert_i64(
        &mut properties,
        "xml_collection_id",
        i64::from(parameter.xml_collection_id),
    );
    properties
}

fn add_included_column_relationships(
    metadata: &mut CanonicalMetadata,
    index_key: &ObjectKey,
    index: &RawIndex,
    column_keys: &BTreeMap<(i32, i32), ObjectKey>,
) -> Result<(), CatalogError> {
    for column in index.columns.iter().filter(|column| column.included) {
        let column_key = column_keys
            .get(&(index.object_id, column.column_id))
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "included index column '{}.{}' is not mapped",
                    index.name, column.name
                ))
            })?;
        let mut properties = BTreeMap::new();
        insert_i64(
            &mut properties,
            "index_column_id",
            i64::from(column.index_column_id),
        );
        add_relationship(
            metadata,
            MetadataRelationshipKind::IncludesColumn,
            index_key,
            column_key,
            Some(positive_u32(
                column.index_column_id,
                "index column ordinal",
            )?),
            properties,
        );
    }
    Ok(())
}

fn routine_kind(type_code: &str) -> Result<RoutineKind, CatalogError> {
    match type_code {
        "P" => Ok(RoutineKind::Procedure),
        "FN" | "IF" | "TF" => Ok(RoutineKind::Function),
        unsupported => Err(CatalogError::UnsupportedMetadata(format!(
            "routine type '{unsupported}' is not SQL-backed"
        ))),
    }
}

fn constraint_object_kind(kind: ConstraintKind) -> ObjectKind {
    match kind {
        ConstraintKind::PrimaryKey => ObjectKind::PrimaryKey,
        ConstraintKind::ForeignKey => ObjectKind::ForeignKey,
        ConstraintKind::Unique => ObjectKind::UniqueConstraint,
        ConstraintKind::Check => ObjectKind::CheckConstraint,
    }
}

fn qualified_type_name(schema: &str, name: &str) -> String {
    if schema.eq_ignore_ascii_case("sys") {
        name.to_owned()
    } else {
        format!("{schema}.{name}")
    }
}

fn positive_u32(value: i32, subject: &str) -> Result<u32, CatalogError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| CatalogError::Mapping(format!("{subject} must be a positive u32")))
}

fn positive_u32_or_return(value: i32) -> Result<u32, CatalogError> {
    if value == 0 {
        Ok(1)
    } else {
        positive_u32(value + 1, "parameter relationship ordinal")
    }
}

fn require_contiguous_ordinals(
    ordinals: impl IntoIterator<Item = i32>,
    subject: &str,
) -> Result<(), CatalogError> {
    for (position, ordinal) in ordinals.into_iter().enumerate() {
        let expected = i32::try_from(position + 1)
            .map_err(|_| CatalogError::Mapping(format!("{subject} ordinal overflow")))?;
        if ordinal != expected {
            return Err(CatalogError::Mapping(format!(
                "{subject} has ordinal {ordinal}, expected {expected}"
            )));
        }
    }
    Ok(())
}

fn add_effective_owner(
    metadata: &mut CanonicalMetadata,
    object_key: &ObjectKey,
    principal_id: Option<i32>,
    schema: &str,
    schema_owner_ids: &BTreeMap<String, i32>,
    principal_keys: &BTreeMap<i32, ObjectKey>,
) -> Result<(), CatalogError> {
    let owner = principal_id
        .or_else(|| schema_owner_ids.get(schema).copied())
        .ok_or_else(|| {
            CatalogError::Mapping(format!(
                "object '{}' has no effective owner",
                object_key.object_name
            ))
        })?;
    add_owned_by(metadata, object_key, owner, principal_keys)
}

fn add_owned_by(
    metadata: &mut CanonicalMetadata,
    object_key: &ObjectKey,
    principal_id: i32,
    principal_keys: &BTreeMap<i32, ObjectKey>,
) -> Result<(), CatalogError> {
    let principal_key = principal_keys.get(&principal_id).ok_or_else(|| {
        CatalogError::Mapping(format!(
            "object '{}' references missing principal {principal_id}",
            object_key.object_name
        ))
    })?;
    add_relationship(
        metadata,
        MetadataRelationshipKind::OwnedBy,
        object_key,
        principal_key,
        None,
        BTreeMap::new(),
    );
    Ok(())
}

fn add_principal_memberships(
    metadata: &mut CanonicalMetadata,
    principals: &[RawPrincipal],
    principal_keys: &BTreeMap<i32, ObjectKey>,
) -> Result<(), CatalogError> {
    for principal in principals {
        let Some(owner_id) = principal.owning_principal_id else {
            continue;
        };
        let source = principal_keys.get(&principal.id).ok_or_else(|| {
            CatalogError::Mapping(format!("principal {} lost its key", principal.id))
        })?;
        let owner = principal_keys.get(&owner_id).ok_or_else(|| {
            CatalogError::Mapping(format!(
                "principal '{}' references missing owner {owner_id}",
                principal.name
            ))
        })?;
        add_relationship(
            metadata,
            MetadataRelationshipKind::OwnedBy,
            source,
            owner,
            None,
            BTreeMap::new(),
        );
    }
    Ok(())
}

fn add_annotation(
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

fn add_relationship(
    metadata: &mut CanonicalMetadata,
    kind: MetadataRelationshipKind,
    from_key: &ObjectKey,
    to_key: &ObjectKey,
    ordinal: Option<u32>,
    properties: BTreeMap<String, MetadataValue>,
) {
    metadata.relationships.push(MetadataRelationship {
        kind,
        from_key: from_key.clone(),
        to_key: to_key.clone(),
        ordinal,
        properties,
    });
}

fn insert_string(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: &str) {
    properties.insert(key.to_owned(), MetadataValue::String(value.to_owned()));
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

fn insert_bool(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: bool) {
    properties.insert(key.to_owned(), MetadataValue::Boolean(value));
}

fn insert_i64(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: i64) {
    properties.insert(key.to_owned(), MetadataValue::Integer(value));
}

fn insert_optional_i64(
    properties: &mut BTreeMap<String, MetadataValue>,
    key: &str,
    value: Option<i64>,
) {
    if let Some(value) = value {
        insert_i64(properties, key, value);
    }
}

#[allow(clippy::too_many_arguments)]
fn map_xml_schema_collections(
    metadata: &mut CanonicalMetadata,
    connection_alias: &str,
    database: &str,
    collections: &[RawXmlSchemaCollection],
    schema_keys: &BTreeMap<String, ObjectKey>,
    schema_owner_ids: &BTreeMap<String, i32>,
    principal_keys: &BTreeMap<i32, ObjectKey>,
) -> Result<BTreeMap<i32, ObjectKey>, CatalogError> {
    let mut collection_keys = BTreeMap::<i32, ObjectKey>::new();
    for collection in collections {
        let schema_key = required_key(
            schema_keys,
            &collection.schema,
            "XML schema collection schema",
        )?;
        let key = sqlserver_key(
            connection_alias,
            database,
            &collection.schema,
            ObjectKind::Extension,
            &collection.name,
            Some("xml-schema-collection".to_owned()),
        );
        insert_unique_id(
            &mut collection_keys,
            collection.id,
            &key,
            "XML schema collection",
        )?;
        let mut properties = BTreeMap::new();
        insert_i64(
            &mut properties,
            "xml_collection_id",
            i64::from(collection.id),
        );
        insert_string(&mut properties, "created_at", &collection.created_at);
        insert_string(&mut properties, "modified_at", &collection.modified_at);
        metadata.objects.push(MetadataObject {
            key: key.clone(),
            parent_key: Some(schema_key.clone()),
            name: collection.name.clone(),
            extension_kind: Some("sqlserver_xml_schema_collection".to_owned()),
            definition: None,
            properties,
        });
        add_effective_owner(
            metadata,
            &key,
            collection.principal_id,
            &collection.schema,
            schema_owner_ids,
            principal_keys,
        )?;

        for namespace in &collection.namespaces {
            let namespace_key = sqlserver_key(
                connection_alias,
                database,
                &collection.schema,
                ObjectKind::Extension,
                &collection.name,
                Some(format!("xml-schema-namespace:{}", namespace.id)),
            );
            let mut namespace_properties = BTreeMap::new();
            insert_i64(
                &mut namespace_properties,
                "xml_namespace_id",
                i64::from(namespace.id),
            );
            insert_string(&mut namespace_properties, "namespace", &namespace.name);
            metadata.objects.push(MetadataObject {
                key: namespace_key,
                parent_key: Some(key.clone()),
                name: if namespace.name.is_empty() {
                    "default namespace".to_owned()
                } else {
                    namespace.name.clone()
                },
                extension_kind: Some("sqlserver_xml_schema_namespace".to_owned()),
                definition: None,
                properties: namespace_properties,
            });
        }
    }
    Ok(collection_keys)
}

struct ExtendedPropertyTargetRegistry<'a> {
    database: &'a ObjectKey,
    schemas: &'a BTreeMap<i32, ObjectKey>,
    principals: &'a BTreeMap<i32, ObjectKey>,
    objects: &'a BTreeMap<i32, ObjectKey>,
    columns: &'a BTreeMap<(i32, i32), ObjectKey>,
    table_type_columns: &'a BTreeMap<(i32, i32), ObjectKey>,
    parameters: &'a BTreeMap<(i32, i32), ObjectKey>,
    user_types: &'a BTreeMap<i32, ObjectKey>,
    indexes: &'a BTreeMap<(i32, i32), ObjectKey>,
    xml_collections: &'a BTreeMap<i32, ObjectKey>,
    partition_schemes: &'a BTreeMap<i32, ObjectKey>,
    partition_functions: &'a BTreeMap<i32, ObjectKey>,
}

impl ExtendedPropertyTargetRegistry<'_> {
    fn resolve(&self, property: &RawExtendedProperty) -> Option<&ObjectKey> {
        match property.class {
            0 if property.major_id == 0 && property.minor_id == 0 => Some(self.database),
            1 if property.minor_id == 0 => self.objects.get(&property.major_id),
            1 => self.columns.get(&(property.major_id, property.minor_id)),
            2 => self.parameters.get(&(property.major_id, property.minor_id)),
            3 => self.schemas.get(&property.major_id),
            4 => self.principals.get(&property.major_id),
            6 => self.user_types.get(&property.major_id),
            7 => self.indexes.get(&(property.major_id, property.minor_id)),
            8 => self
                .table_type_columns
                .get(&(property.major_id, property.minor_id)),
            10 => self.xml_collections.get(&property.major_id),
            20 => self.partition_schemes.get(&property.major_id),
            21 => self.partition_functions.get(&property.major_id),
            _ => None,
        }
    }
}

fn map_extended_properties(
    metadata: &mut CanonicalMetadata,
    connection_alias: &str,
    database: &str,
    properties: &[RawExtendedProperty],
    targets: ExtendedPropertyTargetRegistry<'_>,
) -> Result<(), CatalogError> {
    for property in properties {
        let target = targets.resolve(property).ok_or_else(|| {
            CatalogError::Mapping(format!(
                "extended property '{}:{}:{}:{}' references an unmapped target",
                property.class, property.major_id, property.minor_id, property.name
            ))
        })?;
        let key = sqlserver_key(
            connection_alias,
            database,
            &target.schema,
            ObjectKind::Extension,
            &target.object_name,
            Some(format!(
                "extended-property:{}:{}:{}:{}",
                property.class, property.major_id, property.minor_id, property.name
            )),
        );
        let mut values = BTreeMap::new();
        insert_i64(&mut values, "class", i64::from(property.class));
        insert_string(
            &mut values,
            "class_description",
            &property.class_description,
        );
        insert_i64(&mut values, "major_id", i64::from(property.major_id));
        insert_i64(&mut values, "minor_id", i64::from(property.minor_id));
        insert_bool(&mut values, "value_is_null", property.value_type.is_none());
        insert_optional_string(&mut values, "value_type", property.value_type.as_deref());
        insert_optional_i64(
            &mut values,
            "value_precision",
            property.value_precision.map(i64::from),
        );
        insert_optional_i64(
            &mut values,
            "value_scale",
            property.value_scale.map(i64::from),
        );
        insert_optional_i64(
            &mut values,
            "value_max_length",
            property.value_max_length.map(i64::from),
        );
        insert_optional_string(
            &mut values,
            "value_collation",
            property.value_collation.as_deref(),
        );
        insert_optional_string(
            &mut values,
            "display_value",
            property.display_value.as_deref(),
        );
        insert_optional_string(&mut values, "value_hex", property.value_hex.as_deref());
        metadata.objects.push(MetadataObject {
            key,
            parent_key: Some(target.clone()),
            name: property.name.clone(),
            extension_kind: Some("sqlserver_extended_property".to_owned()),
            definition: None,
            properties: values,
        });
    }
    Ok(())
}

struct PartitionMappingResult {
    function_keys: BTreeMap<i32, ObjectKey>,
    scheme_keys: BTreeMap<i32, ObjectKey>,
}

fn map_partitions(
    metadata: &mut CanonicalMetadata,
    connection_alias: &str,
    database: &str,
    database_key: &ObjectKey,
    raw: &RawSqlServerCatalog,
    object_keys: &BTreeMap<i32, ObjectKey>,
    index_keys: &BTreeMap<(i32, i32), ObjectKey>,
) -> Result<PartitionMappingResult, CatalogError> {
    let mut function_keys = BTreeMap::<i32, ObjectKey>::new();
    for function in &raw.partition_functions {
        let key = sqlserver_key(
            connection_alias,
            database,
            database,
            ObjectKind::Extension,
            &function.name,
            Some(format!("partition-function:{}", function.id)),
        );
        if function_keys.insert(function.id, key.clone()).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate partition function id {}",
                function.id
            )));
        }
        let mut properties = BTreeMap::new();
        insert_i64(&mut properties, "fanout", i64::from(function.fanout));
        insert_bool(
            &mut properties,
            "boundary_on_right",
            function.boundary_on_right,
        );
        metadata.objects.push(MetadataObject {
            key: key.clone(),
            parent_key: Some(database_key.clone()),
            name: function.name.clone(),
            extension_kind: Some("sqlserver_partition_function".to_owned()),
            definition: None,
            properties,
        });
        for value in &function.values {
            let value_key = sqlserver_key(
                connection_alias,
                database,
                database,
                ObjectKind::Extension,
                &function.name,
                Some(format!("partition-boundary:{}", value.boundary_id)),
            );
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "boundary_id", i64::from(value.boundary_id));
            insert_optional_string(&mut properties, "value", value.value.as_deref());
            metadata.objects.push(MetadataObject {
                key: value_key,
                parent_key: Some(key.clone()),
                name: format!("{} boundary {}", function.name, value.boundary_id),
                extension_kind: Some("sqlserver_partition_boundary".to_owned()),
                definition: None,
                properties,
            });
        }
    }

    let mut scheme_keys = BTreeMap::<i32, ObjectKey>::new();
    for scheme in &raw.partition_schemes {
        let function_key = function_keys.get(&scheme.function_id).ok_or_else(|| {
            CatalogError::Mapping(format!(
                "partition scheme '{}' references missing function {}",
                scheme.name, scheme.function_id
            ))
        })?;
        let key = sqlserver_key(
            connection_alias,
            database,
            database,
            ObjectKind::Extension,
            &scheme.name,
            Some(format!("partition-scheme:{}", scheme.id)),
        );
        if scheme_keys.insert(scheme.id, key.clone()).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate partition scheme id {}",
                scheme.id
            )));
        }
        metadata.objects.push(MetadataObject {
            key: key.clone(),
            parent_key: Some(database_key.clone()),
            name: scheme.name.clone(),
            extension_kind: Some("sqlserver_partition_scheme".to_owned()),
            definition: None,
            properties: BTreeMap::new(),
        });
        add_relationship(
            metadata,
            MetadataRelationshipKind::Extension("partition_scheme_uses_function".to_owned()),
            &key,
            function_key,
            None,
            BTreeMap::new(),
        );
    }

    let index_data_spaces = raw
        .indexes
        .iter()
        .map(|index| ((index.object_id, index.id), index.data_space_id))
        .collect::<BTreeMap<_, _>>();
    for partition in &raw.partitions {
        let parent_key = if partition.index_id == 0 {
            object_keys.get(&partition.object_id)
        } else {
            index_keys.get(&(partition.object_id, partition.index_id))
        }
        .cloned()
        .ok_or_else(|| {
            CatalogError::Mapping(format!(
                "partition {}:{}:{} references missing parent",
                partition.object_id, partition.index_id, partition.partition_number
            ))
        })?;
        let key = sqlserver_key(
            connection_alias,
            database,
            &parent_key.schema,
            ObjectKind::Extension,
            &parent_key.object_name,
            Some(format!(
                "partition:{}:{}",
                partition.index_id, partition.partition_number
            )),
        );
        let mut properties = BTreeMap::new();
        insert_i64(&mut properties, "index_id", i64::from(partition.index_id));
        insert_i64(
            &mut properties,
            "partition_number",
            i64::from(partition.partition_number),
        );
        insert_string(
            &mut properties,
            "data_compression",
            &partition.data_compression,
        );
        insert_string(
            &mut properties,
            "xml_compression",
            &partition.xml_compression,
        );
        metadata.objects.push(MetadataObject {
            key: key.clone(),
            parent_key: Some(parent_key),
            name: format!("partition {}", partition.partition_number),
            extension_kind: Some("sqlserver_partition".to_owned()),
            definition: None,
            properties,
        });
        if let Some(data_space_id) = index_data_spaces
            .get(&(partition.object_id, partition.index_id))
            .and_then(|id| scheme_keys.get(id))
        {
            add_relationship(
                metadata,
                MetadataRelationshipKind::Extension("partition_uses_scheme".to_owned()),
                &key,
                data_space_id,
                None,
                BTreeMap::new(),
            );
        }
    }

    for table in &raw.tables {
        let (Some(history_schema), Some(history_table)) =
            (table.history_schema.as_ref(), table.history_table.as_ref())
        else {
            continue;
        };
        let source = object_keys.get(&table.id).ok_or_else(|| {
            CatalogError::Mapping(format!("temporal table {} lost its key", table.id))
        })?;
        let target = raw
            .tables
            .iter()
            .find(|candidate| {
                &candidate.schema == history_schema && &candidate.name == history_table
            })
            .and_then(|candidate| object_keys.get(&candidate.id))
            .ok_or_else(|| {
                CatalogError::InvalidScope(format!(
                    "temporal table '{}.{}' history table '{}.{}' is outside the selected schema scope",
                    table.schema, table.name, history_schema, history_table
                ))
            })?;
        add_relationship(
            metadata,
            MetadataRelationshipKind::Extension("temporal_history_table".to_owned()),
            source,
            target,
            None,
            BTreeMap::new(),
        );
    }
    Ok(PartitionMappingResult {
        function_keys,
        scheme_keys,
    })
}

#[allow(clippy::too_many_arguments)]
fn map_synonym_targets(
    metadata: &mut CanonicalMetadata,
    database: &str,
    synonyms: &[RawSynonym],
    synonym_keys: &BTreeMap<i32, ObjectKey>,
    name_keys: &BTreeMap<(String, String), ObjectKey>,
    external_reference_keys: &mut BTreeMap<String, ObjectKey>,
    connection_alias: &str,
    database_key: &ObjectKey,
) -> Result<(), CatalogError> {
    for synonym in synonyms {
        let source = synonym_keys
            .get(&synonym.id)
            .ok_or_else(|| CatalogError::Mapping(format!("synonym {} lost its key", synonym.id)))?;
        let local_database = synonym
            .database
            .as_deref()
            .is_none_or(|target| target.eq_ignore_ascii_case(database));
        let local_server = synonym.server.is_none();
        let local_target = if local_database && local_server {
            synonym
                .target_schema
                .as_ref()
                .zip(synonym.target_entity.as_ref())
                .and_then(|(schema, entity)| name_keys.get(&(schema.clone(), entity.clone())))
                .cloned()
        } else {
            None
        };
        let target = match local_target {
            Some(target) => target,
            None => ensure_external_reference(
                metadata,
                external_reference_keys,
                connection_alias,
                database,
                database_key,
                &synonym.base_object_name,
                synonym.server.as_deref(),
                synonym.database.as_deref(),
                synonym.target_schema.as_deref(),
                synonym.target_entity.as_deref(),
                "synonym_target",
            )?,
        };
        add_relationship(
            metadata,
            MetadataRelationshipKind::SynonymFor,
            source,
            &target,
            None,
            BTreeMap::new(),
        );
    }
    Ok(())
}

#[derive(Default)]
struct DependencyMappingResult {
    view_dependencies: BTreeMap<i32, Vec<ObjectKey>>,
    routine_dependencies: BTreeMap<i32, Vec<ObjectKey>>,
    metadata_relationship_count: u64,
}

impl DependencyMappingResult {
    fn view_dependency_count(&self) -> u64 {
        self.view_dependencies
            .values()
            .map(|dependencies| dependencies.len() as u64)
            .sum()
    }

    fn routine_dependency_count(&self) -> u64 {
        self.routine_dependencies
            .values()
            .map(|dependencies| dependencies.len() as u64)
            .sum()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SqlServerProjectionLedger {
    external_reference_objects: u64,
    view_dependencies: u64,
    routine_dependencies: u64,
    dependency_metadata_relationships: u64,
}

#[allow(clippy::too_many_arguments)]
fn map_dependencies(
    metadata: &mut CanonicalMetadata,
    dependencies: &[RawDependency],
    object_keys: &BTreeMap<i32, ObjectKey>,
    column_keys: &BTreeMap<(i32, i32), ObjectKey>,
    dependency_source_keys: &BTreeMap<i32, ObjectKey>,
    type_keys: &BTreeMap<i32, ObjectKey>,
    xml_collection_keys: &BTreeMap<i32, ObjectKey>,
    index_keys: &BTreeMap<(i32, i32), ObjectKey>,
    partition_function_keys: &BTreeMap<i32, ObjectKey>,
    name_keys: &BTreeMap<(String, String), ObjectKey>,
    external_reference_keys: &mut BTreeMap<String, ObjectKey>,
    connection_alias: &str,
    database: &str,
    database_key: &ObjectKey,
) -> Result<DependencyMappingResult, CatalogError> {
    let mut result = DependencyMappingResult::default();
    for dependency in dependencies {
        let source = if dependency.referencing_minor_id > 0 {
            column_keys
                .get(&(dependency.referencing_id, dependency.referencing_minor_id))
                .or_else(|| object_keys.get(&dependency.referencing_id))
                .cloned()
        } else {
            object_keys
                .get(&dependency.referencing_id)
                .or_else(|| dependency_source_keys.get(&dependency.referencing_id))
                .cloned()
        }
        .ok_or_else(|| {
            CatalogError::UnsupportedMetadata(format!(
                "dependency source class {} identity {}:{} has no canonical representation",
                dependency.referencing_class,
                dependency.referencing_id,
                dependency.referencing_minor_id
            ))
        })?;

        let target = resolve_dependency_target(
            metadata,
            dependency,
            object_keys,
            column_keys,
            type_keys,
            xml_collection_keys,
            index_keys,
            partition_function_keys,
            name_keys,
            external_reference_keys,
            connection_alias,
            database,
            database_key,
        )?;
        if source == target {
            continue;
        }
        match source.object_kind {
            ObjectKind::Column if target.object_kind == ObjectKind::Sequence => {
                add_relationship(
                    metadata,
                    MetadataRelationshipKind::UsesSequence,
                    &source,
                    &target,
                    None,
                    dependency_properties(dependency),
                );
                result.metadata_relationship_count += 1;
            }
            ObjectKind::View if is_legacy_schema_object_kind(target.object_kind) => {
                push_unique_dependency(
                    result
                        .view_dependencies
                        .entry(dependency.referencing_id)
                        .or_default(),
                    target,
                );
            }
            ObjectKind::Routine if is_legacy_schema_object_kind(target.object_kind) => {
                push_unique_dependency(
                    result
                        .routine_dependencies
                        .entry(dependency.referencing_id)
                        .or_default(),
                    target,
                );
            }
            ObjectKind::MaterializedView
                if matches!(target.object_kind, ObjectKind::Table | ObjectKind::View) =>
            {
                add_relationship(
                    metadata,
                    MetadataRelationshipKind::Materializes,
                    &source,
                    &target,
                    None,
                    dependency_properties(dependency),
                );
                result.metadata_relationship_count += 1;
            }
            ObjectKind::Trigger if target.object_kind == ObjectKind::Routine => {
                add_relationship(
                    metadata,
                    MetadataRelationshipKind::Invokes,
                    &source,
                    &target,
                    None,
                    dependency_properties(dependency),
                );
                result.metadata_relationship_count += 1;
            }
            _ => {
                add_relationship(
                    metadata,
                    MetadataRelationshipKind::DependsOn,
                    &source,
                    &target,
                    None,
                    dependency_properties(dependency),
                );
                result.metadata_relationship_count += 1;
            }
        }
    }
    for dependencies in result.view_dependencies.values_mut() {
        dependencies.sort_by_key(ObjectKey::to_string);
        dependencies.dedup();
    }
    for dependencies in result.routine_dependencies.values_mut() {
        dependencies.sort_by_key(ObjectKey::to_string);
        dependencies.dedup();
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn resolve_dependency_target(
    metadata: &mut CanonicalMetadata,
    dependency: &RawDependency,
    object_keys: &BTreeMap<i32, ObjectKey>,
    column_keys: &BTreeMap<(i32, i32), ObjectKey>,
    type_keys: &BTreeMap<i32, ObjectKey>,
    xml_collection_keys: &BTreeMap<i32, ObjectKey>,
    index_keys: &BTreeMap<(i32, i32), ObjectKey>,
    partition_function_keys: &BTreeMap<i32, ObjectKey>,
    name_keys: &BTreeMap<(String, String), ObjectKey>,
    external_reference_keys: &mut BTreeMap<String, ObjectKey>,
    connection_alias: &str,
    database: &str,
    database_key: &ObjectKey,
) -> Result<ObjectKey, CatalogError> {
    let direct = match dependency.referenced_class {
        1 => dependency.referenced_id.and_then(|id| {
            if dependency.referenced_minor_id > 0 {
                column_keys
                    .get(&(id, dependency.referenced_minor_id))
                    .cloned()
            } else {
                object_keys.get(&id).cloned()
            }
        }),
        6 => dependency
            .referenced_id
            .and_then(|id| type_keys.get(&id).cloned()),
        7 => dependency.referenced_id.and_then(|object_id| {
            index_keys
                .get(&(object_id, dependency.referenced_minor_id))
                .cloned()
        }),
        10 => dependency
            .referenced_id
            .and_then(|id| xml_collection_keys.get(&id).cloned()),
        21 => dependency
            .referenced_id
            .and_then(|id| partition_function_keys.get(&id).cloned()),
        other => {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "dependency uses unsupported referenced class {other}"
            )))
        }
    };
    if let Some(key) = direct {
        return Ok(key);
    }

    let local_database = dependency
        .referenced_database
        .as_deref()
        .is_none_or(|name| name.eq_ignore_ascii_case(database));
    if dependency.referenced_server.is_none() && local_database {
        if let Some(key) = dependency
            .referenced_schema
            .as_ref()
            .and_then(|schema| {
                name_keys.get(&(schema.clone(), dependency.referenced_entity.clone()))
            })
            .cloned()
        {
            return Ok(key);
        }
    }
    let full_name = [
        dependency.referenced_server.as_deref(),
        dependency.referenced_database.as_deref(),
        dependency.referenced_schema.as_deref(),
        Some(dependency.referenced_entity.as_str()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(".");
    ensure_external_reference(
        metadata,
        external_reference_keys,
        connection_alias,
        database,
        database_key,
        &full_name,
        dependency.referenced_server.as_deref(),
        dependency.referenced_database.as_deref(),
        dependency.referenced_schema.as_deref(),
        Some(&dependency.referenced_entity),
        if dependency.referenced_id.is_some() {
            "unmodeled_local_reference"
        } else {
            "symbolic_reference"
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn ensure_external_reference(
    metadata: &mut CanonicalMetadata,
    keys: &mut BTreeMap<String, ObjectKey>,
    connection_alias: &str,
    database: &str,
    database_key: &ObjectKey,
    full_name: &str,
    server: Option<&str>,
    target_database: Option<&str>,
    schema: Option<&str>,
    entity: Option<&str>,
    reference_kind: &str,
) -> Result<ObjectKey, CatalogError> {
    if full_name.trim().is_empty() {
        return Err(CatalogError::Mapping(
            "external dependency has no stable name".to_owned(),
        ));
    }
    if let Some(key) = keys.get(full_name) {
        return Ok(key.clone());
    }
    let key = sqlserver_key(
        connection_alias,
        database,
        "external",
        ObjectKind::Extension,
        full_name,
        Some("reference".to_owned()),
    );
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "reference_kind", reference_kind);
    insert_optional_string(&mut properties, "server", server);
    insert_optional_string(&mut properties, "database", target_database);
    insert_optional_string(&mut properties, "schema", schema);
    insert_optional_string(&mut properties, "entity", entity);
    metadata.objects.push(MetadataObject {
        key: key.clone(),
        parent_key: Some(database_key.clone()),
        name: full_name.to_owned(),
        extension_kind: Some("sqlserver_external_reference".to_owned()),
        definition: None,
        properties,
    });
    keys.insert(full_name.to_owned(), key.clone());
    Ok(key)
}

fn dependency_properties(dependency: &RawDependency) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(
        &mut properties,
        "referencing_class",
        i64::from(dependency.referencing_class),
    );
    insert_i64(
        &mut properties,
        "referenced_class",
        i64::from(dependency.referenced_class),
    );
    insert_i64(
        &mut properties,
        "referencing_minor_id",
        i64::from(dependency.referencing_minor_id),
    );
    insert_i64(
        &mut properties,
        "referenced_minor_id",
        i64::from(dependency.referenced_minor_id),
    );
    insert_bool(&mut properties, "schema_bound", dependency.schema_bound);
    properties
}

fn push_unique_dependency(dependencies: &mut Vec<ObjectKey>, key: ObjectKey) {
    if !dependencies.contains(&key) {
        dependencies.push(key);
    }
}

fn is_legacy_schema_object_kind(kind: ObjectKind) -> bool {
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

fn validate_relationship_uniqueness(
    relationships: &[MetadataRelationship],
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    for relationship in relationships {
        let identity = (
            relationship.kind.clone(),
            relationship.from_key.to_string(),
            relationship.to_key.to_string(),
            relationship.ordinal,
        );
        if !seen.insert(identity) {
            return Err(CatalogError::Mapping(format!(
                "duplicate metadata relationship {}:{}->{}",
                relationship.kind.graph_edge_type(),
                relationship.from_key,
                relationship.to_key
            )));
        }
    }
    Ok(())
}

fn discovery_counts_from_catalog(
    raw: &RawSqlServerCatalog,
    snapshot: &CanonicalSchemaSnapshot,
    projection: SqlServerProjectionLedger,
) -> Result<DiscoveryCounts, CatalogError> {
    let emitted_objects = emitted_object_counts(snapshot);
    let emitted_relationships = emitted_relationship_counts(snapshot);
    let table_ids = raw
        .tables
        .iter()
        .map(|table| table.id)
        .collect::<BTreeSet<_>>();
    let table_type_ids = raw
        .user_types
        .iter()
        .filter_map(|data_type| data_type.table_object_id)
        .collect::<BTreeSet<_>>();
    let mut expected_objects = ObjectCategory::ALL
        .into_iter()
        .map(|category| (category, 0_u64))
        .collect::<BTreeMap<_, _>>();
    expected_objects.insert(ObjectCategory::Database, 1);
    expected_objects.insert(ObjectCategory::Schema, raw.schemas.len() as u64);
    expected_objects.insert(ObjectCategory::Principal, raw.principals.len() as u64);
    expected_objects.insert(ObjectCategory::Table, raw.tables.len() as u64);
    expected_objects.insert(
        ObjectCategory::Column,
        raw.columns
            .iter()
            .filter(|column| column.object_type == "U")
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::ViewColumn,
        raw.columns
            .iter()
            .filter(|column| column.object_type == "V")
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::PrimaryKey,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id)
                    && constraint.kind == ConstraintKind::PrimaryKey
            })
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::ForeignKey,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id)
                    && constraint.kind == ConstraintKind::ForeignKey
            })
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::UniqueConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id)
                    && constraint.kind == ConstraintKind::Unique
            })
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::CheckConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id) && constraint.kind == ConstraintKind::Check
            })
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::Index,
        raw.indexes
            .iter()
            .filter(|index| index.relation_type != "TT")
            .count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::View,
        raw.views.iter().filter(|view| !view.indexed).count() as u64,
    );
    expected_objects.insert(
        ObjectCategory::MaterializedView,
        raw.views.iter().filter(|view| view.indexed).count() as u64,
    );
    expected_objects.insert(ObjectCategory::Routine, raw.routines.len() as u64);
    expected_objects.insert(
        ObjectCategory::RoutineParameter,
        raw.parameters.len() as u64,
    );
    expected_objects.insert(ObjectCategory::Trigger, raw.triggers.len() as u64);
    expected_objects.insert(ObjectCategory::UserDefinedType, raw.user_types.len() as u64);
    expected_objects.insert(ObjectCategory::Sequence, raw.sequences.len() as u64);
    expected_objects.insert(ObjectCategory::Synonym, raw.synonyms.len() as u64);
    expected_objects.insert(ObjectCategory::Policy, raw.security_policies.len() as u64);
    expected_objects.insert(
        ObjectCategory::Extension,
        expected_extension_object_count(raw, &table_type_ids, projection),
    );
    if expected_objects != emitted_objects {
        return Err(CatalogError::Mapping(format!(
            "SQL Server raw/emitted object counts differ: raw={expected_objects:?}, emitted={emitted_objects:?}"
        )));
    }

    let mut expected_relationships = RelationshipCategory::ALL
        .into_iter()
        .map(|category| (category, 0_u64))
        .collect::<BTreeMap<_, _>>();
    expected_relationships.insert(
        RelationshipCategory::DatabaseHasSchema,
        raw.schemas.len() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::SchemaHasTable,
        raw.tables.len() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::TableHasColumn,
        raw.columns
            .iter()
            .filter(|column| column.object_type == "U")
            .count() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::TableHasConstraint,
        raw.constraints
            .iter()
            .filter(|constraint| table_ids.contains(&constraint.table_id))
            .count() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::ConstraintColumn,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id)
                    && constraint.kind != ConstraintKind::ForeignKey
            })
            .map(|constraint| constraint.columns.len() as u64)
            .sum(),
    );
    expected_relationships.insert(
        RelationshipCategory::ForeignKeyColumnPair,
        raw.constraints
            .iter()
            .filter(|constraint| {
                table_ids.contains(&constraint.table_id)
                    && constraint.kind == ConstraintKind::ForeignKey
            })
            .map(|constraint| constraint.columns.len() as u64)
            .sum(),
    );
    expected_relationships.insert(
        RelationshipCategory::TableHasIndex,
        raw.indexes
            .iter()
            .filter(|index| index.relation_type == "U")
            .count() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::IndexColumn,
        raw.indexes
            .iter()
            .filter(|index| index.relation_type == "U")
            .map(projected_index_column_count)
            .sum(),
    );
    expected_relationships.insert(
        RelationshipCategory::SchemaHasView,
        raw.views.iter().filter(|view| !view.indexed).count() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::ViewDependency,
        projection.view_dependencies,
    );
    expected_relationships.insert(
        RelationshipCategory::TriggerTarget,
        raw.triggers
            .iter()
            .filter(|trigger| {
                trigger.parent_class == 1
                    && trigger
                        .parent_type
                        .as_deref()
                        .is_some_and(|kind| kind == "U" || kind == "V")
                    && !raw
                        .views
                        .iter()
                        .any(|view| view.indexed && view.id == trigger.parent_id)
            })
            .count() as u64,
    );
    expected_relationships.insert(RelationshipCategory::TriggerRoutine, 0);
    expected_relationships.insert(
        RelationshipCategory::SchemaHasRoutine,
        raw.routines.len() as u64,
    );
    expected_relationships.insert(
        RelationshipCategory::RoutineDependency,
        projection.routine_dependencies,
    );
    expected_relationships.insert(
        RelationshipCategory::MetadataParent,
        expected_metadata_parent_count(raw, &table_type_ids, projection),
    );
    expected_relationships.insert(
        RelationshipCategory::MetadataRelationship,
        expected_metadata_relationship_count(raw, &table_type_ids, projection),
    );
    if expected_relationships != emitted_relationships {
        return Err(CatalogError::Mapping(format!(
            "SQL Server raw/emitted relationship counts differ: raw={expected_relationships:?}, emitted={emitted_relationships:?}"
        )));
    }

    Ok(DiscoveryCounts {
        objects: expected_objects
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: "SQL Server sys catalog raw inventory".to_owned(),
                    },
                )
            })
            .collect(),
        relationships: expected_relationships
            .into_iter()
            .map(|(category, count)| {
                (
                    category,
                    DiscoveredCount {
                        count,
                        evidence: "SQL Server catalog identity and dependency ledger".to_owned(),
                    },
                )
            })
            .collect(),
    })
}

fn expected_extension_object_count(
    raw: &RawSqlServerCatalog,
    table_type_ids: &BTreeSet<i32>,
    projection: SqlServerProjectionLedger,
) -> u64 {
    let table_type_columns = raw
        .columns
        .iter()
        .filter(|column| table_type_ids.contains(&column.object_id))
        .count() as u64;
    let table_type_constraints = raw
        .constraints
        .iter()
        .filter(|constraint| table_type_ids.contains(&constraint.table_id))
        .count() as u64;
    let table_type_indexes = raw
        .indexes
        .iter()
        .filter(|index| table_type_ids.contains(&index.object_id))
        .count() as u64;
    let security_predicates = raw
        .security_policies
        .iter()
        .map(|policy| policy.predicates.len() as u64)
        .sum::<u64>();
    let partition_boundaries = raw
        .partition_functions
        .iter()
        .map(|function| function.values.len() as u64)
        .sum::<u64>();
    let xml_namespaces = raw
        .xml_schema_collections
        .iter()
        .map(|collection| collection.namespaces.len() as u64)
        .sum::<u64>();

    table_type_columns
        + table_type_constraints
        + table_type_indexes
        + security_predicates
        + raw.partition_functions.len() as u64
        + partition_boundaries
        + raw.partition_schemes.len() as u64
        + raw.partitions.len() as u64
        + raw.xml_schema_collections.len() as u64
        + xml_namespaces
        + raw.extended_properties.len() as u64
        + projection.external_reference_objects
}

fn expected_metadata_parent_count(
    raw: &RawSqlServerCatalog,
    table_type_ids: &BTreeSet<i32>,
    projection: SqlServerProjectionLedger,
) -> u64 {
    let indexed_view_ids = raw
        .views
        .iter()
        .filter(|view| view.indexed)
        .map(|view| view.id)
        .collect::<BTreeSet<_>>();
    let metadata_triggers = raw
        .triggers
        .iter()
        .filter(|trigger| {
            trigger.parent_class == 0
                || (trigger.parent_class == 1 && indexed_view_ids.contains(&trigger.parent_id))
        })
        .count() as u64;

    raw.principals.len() as u64
        + raw.user_types.len() as u64
        + raw.sequences.len() as u64
        + indexed_view_ids.len() as u64
        + metadata_triggers
        + raw
            .columns
            .iter()
            .filter(|column| column.object_type == "V")
            .count() as u64
        + raw
            .indexes
            .iter()
            .filter(|index| index.relation_type == "V")
            .count() as u64
        + raw.parameters.len() as u64
        + raw.synonyms.len() as u64
        + raw.security_policies.len() as u64
        + expected_extension_object_count(raw, table_type_ids, projection)
}

fn expected_metadata_relationship_count(
    raw: &RawSqlServerCatalog,
    table_type_ids: &BTreeSet<i32>,
    projection: SqlServerProjectionLedger,
) -> u64 {
    let user_type_ids = raw
        .user_types
        .iter()
        .map(|data_type| data_type.id)
        .collect::<BTreeSet<_>>();
    let ownerships = raw.schemas.len()
        + raw.sequences.len()
        + raw.tables.len()
        + raw.views.len()
        + raw.routines.len()
        + raw.synonyms.len()
        + raw.security_policies.len()
        + raw
            .principals
            .iter()
            .filter(|principal| principal.owning_principal_id.is_some())
            .count();
    let sequence_types = raw
        .sequences
        .iter()
        .filter(|sequence| user_type_ids.contains(&sequence.type_id))
        .count() as u64;
    let column_types = raw
        .columns
        .iter()
        .filter(|column| user_type_ids.contains(&column.type_id))
        .count() as u64;
    let table_type_constraint_columns = raw
        .constraints
        .iter()
        .filter(|constraint| table_type_ids.contains(&constraint.table_id))
        .map(|constraint| constraint.columns.len() as u64)
        .sum::<u64>();
    let table_type_index_columns = raw
        .indexes
        .iter()
        .filter(|index| table_type_ids.contains(&index.object_id))
        .map(|index| index.columns.len() as u64)
        .sum::<u64>();
    let parameter_types = raw
        .parameters
        .iter()
        .filter(|parameter| user_type_ids.contains(&parameter.type_id))
        .count() as u64;
    let security_predicates = raw
        .security_policies
        .iter()
        .map(|policy| policy.predicates.len() as u64)
        .sum::<u64>();
    let included_columns = raw
        .indexes
        .iter()
        .filter(|index| index.relation_type == "U" || index.relation_type == "V")
        .flat_map(|index| &index.columns)
        .filter(|column| column.included)
        .count() as u64;
    let partition_scheme_ids = raw
        .partition_schemes
        .iter()
        .map(|scheme| scheme.id)
        .collect::<BTreeSet<_>>();
    let index_data_spaces = raw
        .indexes
        .iter()
        .map(|index| ((index.object_id, index.id), index.data_space_id))
        .collect::<BTreeMap<_, _>>();
    let partition_scheme_uses = raw
        .partitions
        .iter()
        .filter(|partition| {
            index_data_spaces
                .get(&(partition.object_id, partition.index_id))
                .is_some_and(|id| partition_scheme_ids.contains(id))
        })
        .count() as u64;
    let temporal_histories = raw
        .tables
        .iter()
        .filter(|table| table.history_schema.is_some() && table.history_table.is_some())
        .count() as u64;
    let typed_xml_columns = raw
        .columns
        .iter()
        .filter(|column| column.xml_collection_id > 0)
        .count() as u64;
    let typed_xml_parameters = raw
        .parameters
        .iter()
        .filter(|parameter| parameter.xml_collection_id > 0)
        .count() as u64;

    ownerships as u64
        + sequence_types
        + column_types
        + table_type_constraint_columns
        + table_type_index_columns
        + raw.parameters.len() as u64
        + parameter_types
        + security_predicates
        + included_columns
        + raw.partition_schemes.len() as u64
        + partition_scheme_uses
        + temporal_histories
        + raw.synonyms.len() as u64
        + raw.xml_schema_collections.len() as u64
        + typed_xml_columns
        + typed_xml_parameters
        + projection.dependency_metadata_relationships
}

fn projected_index_column_count(index: &RawIndex) -> u64 {
    let key_columns = index
        .columns
        .iter()
        .filter(|column| column.key_ordinal > 0)
        .count();
    if key_columns == 0 {
        index.columns.len() as u64
    } else {
        key_columns as u64
    }
}

fn sqlserver_capabilities() -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: SQLSERVER_SOURCE.to_owned(),
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
            "Reads SQL Server sys catalog metadata and module definitions only; application table rows are never queried.".to_owned(),
            "Dynamic SQL, encrypted definitions, runtime-bound dependencies, and unsupported CLR or legacy objects fail closed.".to_owned(),
        ],
    }
}

fn sqlserver_capability_checks(
    facts: &ServerFacts,
    strategy: SqlServerCatalogVersion,
) -> Vec<CapabilityCheck> {
    vec![
        CapabilityCheck {
            name: "catalog_version_strategy".to_owned(),
            evidence: strategy.strategy_name().to_owned(),
        },
        CapabilityCheck {
            name: "metadata_visibility".to_owned(),
            evidence: "database VIEW DEFINITION and dependency SELECT effective".to_owned(),
        },
        CapabilityCheck {
            name: "catalog_stability".to_owned(),
            evidence: "two exact ordered raw catalog reads matched under READ COMMITTED".to_owned(),
        },
        CapabilityCheck {
            name: "metadata_only".to_owned(),
            evidence: "adapter queries sys catalogs, SERVERPROPERTY, and metadata functions only"
                .to_owned(),
        },
        CapabilityCheck {
            name: "transport".to_owned(),
            evidence: if facts.encrypted_transport {
                "TDS transport reported encrypted".to_owned()
            } else {
                "loopback TDS transport reported unencrypted".to_owned()
            },
        },
        CapabilityCheck {
            name: "module_dependency_policy".to_owned(),
            evidence: "dynamic, encrypted, CLR, caller-dependent, and ambiguous modules reject certification"
                .to_owned(),
        },
        CapabilityCheck {
            name: "xml_schema_collections".to_owned(),
            evidence: "typed XML columns and parameters resolve to sys.xml_schema_collections"
                .to_owned(),
        },
        CapabilityCheck {
            name: "extended_properties".to_owned(),
            evidence: "supported sys.extended_properties targets preserve sql_variant type, display, and raw hex values"
                .to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStage, AnalysisStatus};

    use super::*;

    #[test]
    fn version_strategy_accepts_only_the_live_certified_engine() {
        for (major, expected) in [
            (14, SqlServerCatalogVersion::V2017),
            (15, SqlServerCatalogVersion::V2019),
            (16, SqlServerCatalogVersion::V2022),
            (17, SqlServerCatalogVersion::V2025),
        ] {
            assert_eq!(
                SqlServerCatalogVersion::detect(&server_facts(major, 3)).unwrap(),
                expected
            );
        }

        let unsupported_version = SqlServerCatalogVersion::detect(&server_facts(13, 3));
        assert!(matches!(
            unsupported_version,
            Err(CatalogError::UnsupportedVersion(13))
        ));

        let unsupported_engine = SqlServerCatalogVersion::detect(&server_facts(16, 5));
        assert!(matches!(
            unsupported_engine,
            Err(CatalogError::UnsupportedProduct(_))
        ));
    }

    #[test]
    fn changed_catalog_signature_is_never_accepted_as_stable() {
        assert_eq!(require_stable_catalog("same", &"same").unwrap(), "same");
        assert!(matches!(
            require_stable_catalog("first", &"second"),
            Err(CatalogError::CatalogChanged(_))
        ));
    }

    #[test]
    fn connection_policy_requires_a_database_and_secures_remote_transport() {
        let request = request("policy");
        let no_database = validate_connection_policy(
            &request,
            "Server=tcp:127.0.0.1,1433;User ID=reader;Password=do-not-echo",
        )
        .unwrap_err();
        assert_eq!(no_database.code, AnalysisFailureCode::InvalidConfiguration);

        let unsafe_remote = validate_connection_policy(
            &request,
            "Server=tcp:db.example.com,1433;Database=app;User ID=reader;Password=do-not-echo;Encrypt=false;TrustServerCertificate=true",
        )
        .unwrap_err();
        assert_eq!(unsafe_remote.code, AnalysisFailureCode::UnsafeSource);
        assert!(!unsafe_remote.message.contains("do-not-echo"));

        validate_connection_policy(
            &request,
            "Server=tcp:db.example.com,1433;Database=app;User ID=reader;Password=do-not-echo;Encrypt=true;TrustServerCertificate=false",
        )
        .unwrap();
        validate_connection_policy(
            &request,
            "Server=tcp:127.0.0.1,1433;Database=app;User ID=reader;Password=do-not-echo;Encrypt=false;TrustServerCertificate=true",
        )
        .unwrap();
    }

    #[test]
    fn dynamic_sql_is_rejected_without_blocking_static_execution_contexts() {
        reject_dynamic_sql(
            "routine",
            "dbo.static_proc",
            "CREATE PROCEDURE dbo.static_proc AS EXEC dbo.child_proc @id = 1",
        )
        .unwrap();
        reject_dynamic_sql(
            "routine",
            "dbo.execute_as_proc",
            "CREATE PROCEDURE dbo.execute_as_proc WITH EXECUTE AS OWNER AS SELECT 1",
        )
        .unwrap();

        for definition in [
            "CREATE PROCEDURE dbo.dynamic_var AS DECLARE @sql nvarchar(max); EXEC(@sql)",
            "CREATE PROCEDURE dbo.dynamic_text AS EXEC(N'SELECT 1')",
            "CREATE PROCEDURE dbo.dynamic_system AS EXEC sys.sp_executesql N'SELECT 1'",
        ] {
            assert!(
                matches!(
                    reject_dynamic_sql("routine", "dbo.dynamic", definition),
                    Err(CatalogError::UnsupportedMetadata(_))
                ),
                "accepted dynamic SQL: {definition}"
            );
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL"]
    fn sqlserver_2022_live_catalog_is_certified() {
        let _guard = live_test_guard();
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_SQLSERVER2022_URL")
            .expect("live SQL Server test requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL");

        let outcome = analyze_sqlserver(
            &connection_string,
            "sqlserver-2022-live",
            Vec::new(),
            Vec::new(),
            30_000,
        );

        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{:?}",
            outcome.failure()
        );
        let snapshot = outcome.certified_snapshot().unwrap();
        assert_eq!(snapshot.snapshot.schema.source_kind, SQLSERVER_SOURCE);
        assert!(snapshot.snapshot.schema.capabilities.metadata_only);
        assert_eq!(snapshot.completeness.server.product, "Microsoft SQL Server");
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_SQLSERVER*_URL"]
    fn rich_sqlserver_catalog_is_certified_across_the_live_matrix() {
        let _guard = live_test_guard();
        let configured = required_sqlserver_matrix();
        for (strategy, connection_string) in configured {
            let schema = format!("dm_{}", unique_suffix());
            let fixture = SqlServerFixture::new(&schema);
            fixture.create(&connection_string);

            let outcome = analyze_sqlserver(
                &connection_string,
                &format!("{strategy}-rich"),
                vec!["master".to_owned()],
                vec![schema.clone()],
                60_000,
            );
            let failure = outcome.failure().cloned();
            let certified = outcome.certified_snapshot().cloned();
            fixture.drop(&connection_string);

            assert_eq!(outcome.status(), AnalysisStatus::Complete, "{failure:?}");
            let certified = certified.unwrap();
            assert!(certified
                .completeness
                .capability_checks
                .iter()
                .any(|check| {
                    check.name == "catalog_version_strategy" && check.evidence == strategy
                }));
            let snapshot = &certified.snapshot;
            assert_eq!(
                snapshot
                    .schema
                    .schemas
                    .iter()
                    .map(|item| item.name.as_str())
                    .collect::<Vec<_>>(),
                vec![schema.as_str()]
            );
            for table in [
                "users",
                "secured_accounts",
                "orders",
                "audit_log",
                "partitioned_events",
                "temporal_records",
                "temporal_records_history",
            ] {
                assert!(snapshot
                    .schema
                    .tables
                    .iter()
                    .any(|item| { item.key.schema == schema && item.name == table }));
            }
            for kind in [
                ConstraintKind::PrimaryKey,
                ConstraintKind::ForeignKey,
                ConstraintKind::Unique,
                ConstraintKind::Check,
            ] {
                assert!(
                    snapshot
                        .schema
                        .constraints
                        .iter()
                        .any(|constraint| constraint.kind == kind),
                    "missing {kind:?}"
                );
            }
            assert!(snapshot.schema.columns.iter().any(|column| {
                column.table_key.schema == schema
                    && column.name == "email_key"
                    && column.is_generated
            }));
            assert!(snapshot
                .schema
                .indexes
                .iter()
                .any(|index| index.name == "ix_orders_open"));
            assert!(snapshot
                .schema
                .views
                .iter()
                .any(|view| view.name == "order_summary" && view.depends_on.len() >= 2));
            assert!(snapshot
                .schema
                .routines
                .iter()
                .any(|routine| routine.name == "active_users" && !routine.depends_on.is_empty()));
            assert!(snapshot
                .schema
                .triggers
                .iter()
                .any(|trigger| trigger.name == "tr_orders_audit"));
            for (kind, name) in [
                (ObjectKind::UserDefinedType, "account_code"),
                (ObjectKind::Sequence, "order_numbers"),
                (ObjectKind::Synonym, "users_alias"),
            ] {
                assert!(snapshot
                    .metadata
                    .objects
                    .iter()
                    .any(|object| object.key.object_kind == kind && object.name == name));
            }
            assert!(snapshot.metadata.relationships.iter().any(|relationship| {
                relationship.kind == MetadataRelationshipKind::IncludesColumn
            }));
            assert!(snapshot
                .metadata
                .relationships
                .iter()
                .any(|relationship| { relationship.kind == MetadataRelationshipKind::SynonymFor }));
            assert!(snapshot.metadata.relationships.iter().any(|relationship| {
                relationship.kind == MetadataRelationshipKind::UsesSequence
            }));
            assert!(snapshot.metadata.objects.iter().any(|object| {
                object.key.object_kind == ObjectKind::MaterializedView
                    && object.name == "user_tenant_counts"
            }));
            assert!(snapshot.metadata.objects.iter().any(|object| {
                object.key.object_kind == ObjectKind::Policy && object.name == "tenant_policy"
            }));
            assert!(snapshot.metadata.objects.iter().any(|object| {
                object.key.object_kind == ObjectKind::Trigger
                    && object.name == fixture.database_trigger()
            }));
            assert!(snapshot.metadata.objects.iter().any(|object| {
                object.extension_kind.as_deref() == Some("sqlserver_partition_function")
                    && object.name == fixture.partition_function()
            }));
            for relationship in [
                MetadataRelationshipKind::Materializes,
                MetadataRelationshipKind::Extension("temporal_history_table".to_owned()),
                MetadataRelationshipKind::Extension("security_predicate_applies_to".to_owned()),
            ] {
                assert!(
                    snapshot
                        .metadata
                        .relationships
                        .iter()
                        .any(|item| item.kind == relationship),
                    "missing relationship {relationship:?}"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL"]
    fn unprovable_sqlserver_metadata_fails_closed_on_the_live_server() {
        let _guard = live_test_guard();
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_SQLSERVER2022_URL").expect(
            "SQL Server unsupported-metadata test requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL",
        );
        let schema = format!("dm_{}", unique_suffix());
        execute_admin_batches(
            &connection_string,
            &[format!("CREATE SCHEMA [{schema}] AUTHORIZATION [dbo]")],
        )
        .unwrap();

        execute_admin_batches(
            &connection_string,
            &[format!(
                "CREATE PROCEDURE [{schema}].[dynamic_reader] AS DECLARE @sql nvarchar(max) = N'SELECT 1'; EXEC(@sql)"
            )],
        )
        .unwrap();
        let dynamic = analyze_sqlserver(
            &connection_string,
            "sqlserver-dynamic",
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );
        execute_admin_batches(
            &connection_string,
            &[format!(
                "DROP PROCEDURE IF EXISTS [{schema}].[dynamic_reader]"
            )],
        )
        .unwrap();

        execute_admin_batches(
            &connection_string,
            &[format!(
                "CREATE PROCEDURE [{schema}].[encrypted_reader] WITH ENCRYPTION AS SELECT 1 AS [value]"
            )],
        )
        .unwrap();
        let encrypted = analyze_sqlserver(
            &connection_string,
            "sqlserver-encrypted",
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );
        execute_admin_batches(
            &connection_string,
            &[
                format!("DROP PROCEDURE IF EXISTS [{schema}].[encrypted_reader]"),
                format!("DROP SCHEMA IF EXISTS [{schema}]"),
            ],
        )
        .unwrap();

        for (label, outcome) in [("dynamic", dynamic), ("encrypted", encrypted)] {
            assert_eq!(
                outcome.status(),
                AnalysisStatus::Failed,
                "{label}: {:?}",
                outcome.failure()
            );
            assert_eq!(
                outcome.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::UnsupportedMetadata),
                "{label}"
            );
            assert!(outcome.certified_snapshot().is_none(), "{label}");
        }
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_SQLSERVER*_URL"]
    fn table_types_are_fully_mapped_across_the_live_matrix() {
        let _guard = live_test_guard();
        let configured = required_sqlserver_matrix();
        for (strategy, connection_string) in configured {
            assert_table_type_catalog(strategy, &connection_string);
        }
    }

    fn assert_table_type_catalog(strategy: &str, connection_string: &str) {
        let schema = format!("dm_{}", unique_suffix());
        let creation = execute_admin_batches(
            connection_string,
            &[
                format!("CREATE SCHEMA [{schema}] AUTHORIZATION [dbo]"),
                format!("CREATE TYPE [{schema}].[code] FROM nvarchar(20) NOT NULL"),
                format!(
                    "CREATE TYPE [{schema}].[payload] AS TABLE (\
                     [id] int IDENTITY(1,1) NOT NULL PRIMARY KEY, \
                     [code] [{schema}].[code] NOT NULL UNIQUE, \
                     [amount] decimal(10,2) NULL CHECK ([amount] >= 0), \
                     [doubled] AS ([amount] * 2), \
                     [created_at] datetime2 NOT NULL DEFAULT SYSUTCDATETIME(), \
                     INDEX [ix_payload_amount] NONCLUSTERED ([amount] DESC))"
                ),
                format!(
                    "CREATE PROCEDURE [{schema}].[consume_payload] \
                     @items [{schema}].[payload] READONLY AS \
                     SELECT [id] FROM @items"
                ),
            ],
        );
        if let Err(error) = creation {
            let cleanup = drop_table_type_fixture(connection_string, &schema);
            panic!("{strategy}: failed to create table-type fixture: {error}; cleanup={cleanup:?}");
        }

        let outcome = analyze_sqlserver(
            connection_string,
            &format!("{strategy}-table-type"),
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );
        let failure = outcome.failure().cloned();
        let certified = outcome.certified_snapshot().cloned();
        drop_table_type_fixture(connection_string, &schema).unwrap();

        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{strategy}: {failure:?}"
        );
        let certified = certified.unwrap();
        let extension_reconciliation = certified
            .completeness
            .object_counts
            .iter()
            .find(|count| count.category == ObjectCategory::Extension)
            .unwrap();
        assert_eq!(extension_reconciliation.discovered, 11, "{strategy}");
        assert_eq!(
            extension_reconciliation.discovered, extension_reconciliation.emitted,
            "{strategy}"
        );
        let snapshot = &certified.snapshot;
        let payload = snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::UserDefinedType
                    && object.key.schema == schema
                    && object.name == "payload"
            })
            .unwrap();
        assert_eq!(
            payload.properties.get("table_type"),
            Some(&MetadataValue::Boolean(true))
        );
        assert!(!snapshot
            .schema
            .tables
            .iter()
            .any(|table| table.key.schema == schema));

        let extension_count = |kind: &str| {
            snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| object.extension_kind.as_deref() == Some(kind))
                .count()
        };
        assert_eq!(extension_count("sqlserver_table_type_column"), 5);
        assert_eq!(extension_count("sqlserver_table_type_constraint"), 3);
        assert_eq!(extension_count("sqlserver_table_type_index"), 3);
        for relationship_kind in ["table_type_constraint_column", "table_type_index_column"] {
            assert!(snapshot.metadata.relationships.iter().any(|relationship| {
                relationship.kind
                    == MetadataRelationshipKind::Extension(relationship_kind.to_owned())
            }));
        }
        let parameter = snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::RoutineParameter && object.name == "@items"
            })
            .unwrap();
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind == MetadataRelationshipKind::UsesType
                && relationship.from_key == parameter.key
                && relationship.to_key == payload.key
        }));
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_SQLSERVER*_URL"]
    fn xml_schema_and_extended_properties_are_certified_across_the_live_matrix() {
        let _guard = live_test_guard();
        let configured = required_sqlserver_matrix();
        for (strategy, connection_string) in configured {
            assert_xml_metadata_catalog(strategy, &connection_string);
        }
    }

    fn assert_xml_metadata_catalog(strategy: &str, connection_string: &str) {
        let schema = format!("dm_{}", unique_suffix());
        let creation = execute_admin_batches(
            connection_string,
            &[
                format!("CREATE SCHEMA [{schema}] AUTHORIZATION [dbo]"),
                format!(
                    "CREATE XML SCHEMA COLLECTION [{schema}].[payload_xsd] AS \
                     N'<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" \
                     targetNamespace=\"urn:dbmcp:test\" elementFormDefault=\"qualified\">\
                     <xs:element name=\"payload\" type=\"xs:string\"/>\
                     </xs:schema>'"
                ),
                format!(
                    "CREATE TABLE [{schema}].[typed_documents] (\
                     [id] int NOT NULL PRIMARY KEY, \
                     [payload] xml(CONTENT [{schema}].[payload_xsd]) NULL); \
                     CREATE INDEX [ix_typed_documents_payload] \
                     ON [{schema}].[typed_documents] ([id]) INCLUDE ([payload])"
                ),
                format!(
                    "CREATE PROCEDURE [{schema}].[read_payload] \
                     @payload xml(CONTENT [{schema}].[payload_xsd]) AS \
                     SELECT @payload AS [payload]"
                ),
                format!(
                    "CREATE TYPE [{schema}].[payload_type] AS TABLE (\
                     [id] int NOT NULL PRIMARY KEY, [label] nvarchar(20) NULL)"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'MS_Description', \
                     @value=N'XML metadata fixture schema', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'MS_Description', \
                     @value=N'Typed document table', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TABLE', @level1name=N'typed_documents'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'DisplayLabel', \
                     @value=N'Validated XML payload', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TABLE', @level1name=N'typed_documents', \
                     @level2type=N'COLUMN', @level2name=N'payload'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'LookupIndex', @value=7, \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TABLE', @level1name=N'typed_documents', \
                     @level2type=N'INDEX', @level2name=N'ix_typed_documents_payload'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'InputContract', \
                     @value=N'Validated payload input', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'PROCEDURE', @level1name=N'read_payload', \
                     @level2type=N'PARAMETER', @level2name=N'@payload'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'ContractKind', \
                     @value=N'table-valued payload', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TYPE', @level1name=N'payload_type'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'FieldHint', \
                     @value=N'payload label', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TYPE', @level1name=N'payload_type', \
                     @level2type=N'COLUMN', @level2name=N'label'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'NamespaceOwner', \
                     @value=N'backend-map', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'XML SCHEMA COLLECTION', @level1name=N'payload_xsd'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'BinaryMarker', \
                     @value=0x01020304, \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TABLE', @level1name=N'typed_documents'"
                ),
                format!(
                    "EXEC sys.sp_addextendedproperty @name=N'NullMarker', \
                     @level0type=N'SCHEMA', @level0name=N'{schema}', \
                     @level1type=N'TABLE', @level1name=N'typed_documents'"
                ),
            ],
        );
        if let Err(error) = creation {
            let cleanup = drop_xml_metadata_fixture(connection_string, &schema);
            panic!(
                "{strategy}: failed to create XML metadata fixture: {error}; cleanup={cleanup:?}"
            );
        }

        let outcome = analyze_sqlserver(
            connection_string,
            &format!("{strategy}-xml-metadata"),
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );
        let failure = outcome.failure().cloned();
        let certified = outcome.certified_snapshot().cloned();
        drop_xml_metadata_fixture(connection_string, &schema).unwrap();

        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{strategy}: {failure:?}"
        );
        let certified = certified.unwrap();
        let snapshot = &certified.snapshot;
        let collection = snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.extension_kind.as_deref() == Some("sqlserver_xml_schema_collection")
                    && object.key.schema == schema
                    && object.name == "payload_xsd"
            })
            .unwrap();
        assert!(snapshot.metadata.objects.iter().any(|object| {
            object.extension_kind.as_deref() == Some("sqlserver_xml_schema_namespace")
                && object.properties.get("namespace")
                    == Some(&MetadataValue::String("urn:dbmcp:test".to_owned()))
        }));
        assert_eq!(
            snapshot
                .metadata
                .relationships
                .iter()
                .filter(|relationship| {
                    relationship.kind
                        == MetadataRelationshipKind::Extension(
                            "uses_xml_schema_collection".to_owned(),
                        )
                        && relationship.to_key == collection.key
                })
                .count(),
            2,
            "{strategy}"
        );

        let extended_properties = snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.extension_kind.as_deref() == Some("sqlserver_extended_property")
            })
            .collect::<Vec<_>>();
        assert_eq!(extended_properties.len(), 10, "{strategy}");
        let binary = extended_properties
            .iter()
            .find(|property| property.name == "BinaryMarker")
            .unwrap();
        assert_eq!(
            binary.properties.get("value_hex"),
            Some(&MetadataValue::String("01020304".to_owned())),
            "{strategy}"
        );
        let null_value = extended_properties
            .iter()
            .find(|property| property.name == "NullMarker")
            .unwrap();
        assert_eq!(
            null_value.properties.get("value_is_null"),
            Some(&MetadataValue::Boolean(true)),
            "{strategy}"
        );
        let extension_reconciliation = certified
            .completeness
            .object_counts
            .iter()
            .find(|count| count.category == ObjectCategory::Extension)
            .unwrap();
        assert_eq!(
            extension_reconciliation.discovered, extension_reconciliation.emitted,
            "{strategy}"
        );
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_SQLSERVER*_URL"]
    fn cross_schema_foreign_keys_require_a_complete_scope_across_the_live_matrix() {
        let _guard = live_test_guard();
        let configured = required_sqlserver_matrix();
        for (strategy, connection_string) in configured {
            let suffix = unique_suffix();
            let child_schema = format!("dm_child_{suffix}");
            let parent_schema = format!("dm_parent_{suffix}");
            let creation = execute_admin_batches(
                &connection_string,
                &[
                    format!("CREATE SCHEMA [{parent_schema}] AUTHORIZATION [dbo]"),
                    format!("CREATE SCHEMA [{child_schema}] AUTHORIZATION [dbo]"),
                    format!(
                        "CREATE TABLE [{parent_schema}].[accounts] (\
                         [id] int NOT NULL PRIMARY KEY)"
                    ),
                    format!(
                        "CREATE TABLE [{child_schema}].[orders] (\
                         [id] int NOT NULL PRIMARY KEY, [account_id] int NOT NULL, \
                         CONSTRAINT [fk_orders_accounts] FOREIGN KEY ([account_id]) \
                         REFERENCES [{parent_schema}].[accounts] ([id]))"
                    ),
                ],
            );
            if let Err(error) = creation {
                let cleanup =
                    drop_cross_schema_fixture(&connection_string, &child_schema, &parent_schema);
                panic!("{strategy}: failed to create scope fixture: {error}; cleanup={cleanup:?}");
            }

            let incomplete = analyze_sqlserver(
                &connection_string,
                &format!("{strategy}-incomplete-scope"),
                Vec::new(),
                vec![child_schema.clone()],
                30_000,
            );
            assert_eq!(incomplete.status(), AnalysisStatus::Failed, "{strategy}");
            assert_eq!(
                incomplete.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::InvalidConfiguration),
                "{strategy}: {:?}",
                incomplete.failure()
            );
            assert!(
                incomplete
                    .failure()
                    .is_some_and(|failure| failure.message.contains(&parent_schema)),
                "{strategy}: {:?}",
                incomplete.failure()
            );
            assert!(incomplete.certified_snapshot().is_none(), "{strategy}");

            let complete = analyze_sqlserver(
                &connection_string,
                &format!("{strategy}-complete-scope"),
                Vec::new(),
                vec![child_schema.clone(), parent_schema.clone()],
                30_000,
            );
            let failure = complete.failure().cloned();
            let certified = complete.certified_snapshot().cloned();
            drop_cross_schema_fixture(&connection_string, &child_schema, &parent_schema).unwrap();

            assert_eq!(
                complete.status(),
                AnalysisStatus::Complete,
                "{strategy}: {failure:?}"
            );
            let snapshot = &certified.unwrap().snapshot;
            let foreign_key = snapshot
                .schema
                .constraints
                .iter()
                .find(|constraint| constraint.name == "fk_orders_accounts")
                .unwrap();
            assert_eq!(
                foreign_key
                    .referenced_table_key
                    .as_ref()
                    .map(|key| key.schema.as_str()),
                Some(parent_schema.as_str()),
                "{strategy}"
            );
        }
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_SQLSERVER*_URL"]
    fn timeout_never_emits_a_partial_snapshot_across_the_live_matrix() {
        let _guard = live_test_guard();
        let configured = required_sqlserver_matrix();
        for (strategy, connection_string) in configured {
            let outcome = analyze_sqlserver(
                &connection_string,
                &format!("{strategy}-timeout"),
                Vec::new(),
                Vec::new(),
                1,
            );
            assert_eq!(outcome.status(), AnalysisStatus::Failed, "{strategy}");
            let failure = outcome.failure().unwrap();
            assert_eq!(failure.code, AnalysisFailureCode::Timeout, "{strategy}");
            assert_eq!(failure.stage, AnalysisStage::Discovery, "{strategy}");
            assert!(failure.retryable, "{strategy}");
            assert!(outcome.certified_snapshot().is_none(), "{strategy}");
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL"]
    fn metadata_visibility_is_required_and_sufficient_on_the_live_server() {
        let _guard = live_test_guard();
        let admin_connection = std::env::var("DATABASE_MEMORY_TEST_SQLSERVER2022_URL")
            .expect("SQL Server privilege test requires DATABASE_MEMORY_TEST_SQLSERVER2022_URL");
        let suffix = unique_suffix();
        let schema = format!("dm_{suffix}");
        let principal = format!("dm_reader_{suffix}");
        let password = format!("DmRead1!{suffix}");
        let reader_connection =
            connection_with_credentials(&admin_connection, &principal, &password);

        execute_admin_batches(
            &admin_connection,
            &[
                format!("CREATE SCHEMA [{schema}] AUTHORIZATION [dbo]"),
                format!(
                    "CREATE TABLE [{schema}].[visible_table] ([id] int NOT NULL PRIMARY KEY)"
                ),
                format!(
                    "CREATE LOGIN [{principal}] WITH PASSWORD = N'{}', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF",
                    password.replace('\'', "''")
                ),
                format!(
                    "CREATE USER [{principal}] FOR LOGIN [{principal}] WITH DEFAULT_SCHEMA = [{schema}]"
                ),
            ],
        )
        .unwrap();

        let denied = analyze_sqlserver(
            &reader_connection,
            "sqlserver-low-privilege",
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );
        execute_admin_batches(
            &admin_connection,
            &[
                format!("GRANT VIEW DEFINITION TO [{principal}]"),
                format!(
                    "GRANT SELECT ON OBJECT::[sys].[sql_expression_dependencies] TO [{principal}]"
                ),
            ],
        )
        .unwrap();
        let allowed = analyze_sqlserver(
            &reader_connection,
            "sqlserver-metadata-reader",
            Vec::new(),
            vec![schema.clone()],
            30_000,
        );

        execute_admin_batches(
            &admin_connection,
            &[
                format!("DROP TABLE IF EXISTS [{schema}].[visible_table]"),
                format!("DROP SCHEMA IF EXISTS [{schema}]"),
                format!("DROP USER IF EXISTS [{principal}]"),
                format!(
                    "IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{principal}') DROP LOGIN [{principal}]"
                ),
            ],
        )
        .unwrap();

        assert_eq!(denied.status(), AnalysisStatus::Failed);
        assert_eq!(
            denied.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::PermissionDenied),
            "{:?}",
            denied.failure()
        );
        assert_eq!(
            allowed.status(),
            AnalysisStatus::Complete,
            "{:?}",
            allowed.failure()
        );
        assert!(allowed
            .certified_snapshot()
            .unwrap()
            .snapshot
            .schema
            .tables
            .iter()
            .any(|table| table.name == "visible_table"));
    }

    #[test]
    fn async_runtime_cancellation_preempts_connection_work() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let failure = run_catalog_discovery_on_runtime(
            "not-a-sqlserver-connection-string",
            &request("sqlserver-cancelled-runtime"),
            &cancellation,
        )
        .expect_err("cancelled runtime must fail");

        assert_eq!(failure.code, AnalysisFailureCode::Cancelled);
        assert_eq!(failure.stage, AnalysisStage::Discovery);
    }

    fn request(alias: &str) -> IntrospectionRequest {
        IntrospectionRequest {
            connection_alias: alias.to_owned(),
            requested_catalogs: Vec::new(),
            requested_schemas: Vec::new(),
            timeout_ms: 1_000,
        }
    }

    fn server_facts(major: i32, engine_edition: i32) -> ServerFacts {
        ServerFacts {
            database: "app".to_owned(),
            version: format!("{major}.0.0.0"),
            major,
            engine_edition,
            edition: "Developer Edition".to_owned(),
            current_user: "dbo".to_owned(),
            login: "sa".to_owned(),
            original_login: "sa".to_owned(),
            collation: "SQL_Latin1_General_CP1_CI_AS".to_owned(),
            compatibility_level: 160,
            database_read_only: false,
            containment: "NONE".to_owned(),
            encrypted_transport: true,
        }
    }

    fn live_test_guard() -> MutexGuard<'static, ()> {
        static LIVE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LIVE_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn required_sqlserver_matrix() -> Vec<(&'static str, String)> {
        let configured = [
            ("DATABASE_MEMORY_TEST_SQLSERVER2017_URL", "sqlserver-2017"),
            ("DATABASE_MEMORY_TEST_SQLSERVER2019_URL", "sqlserver-2019"),
            ("DATABASE_MEMORY_TEST_SQLSERVER2022_URL", "sqlserver-2022"),
            ("DATABASE_MEMORY_TEST_SQLSERVER2025_URL", "sqlserver-2025"),
        ]
        .into_iter()
        .filter_map(|(environment, strategy)| {
            std::env::var(environment)
                .ok()
                .map(|connection_string| (strategy, connection_string))
        })
        .collect::<Vec<_>>();
        assert!(
            !configured.is_empty(),
            "live SQL Server matrix test requires at least one DATABASE_MEMORY_TEST_SQLSERVER*_URL"
        );
        configured
    }

    fn unique_suffix() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{:x}_{:x}_{:x}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    struct SqlServerFixture {
        schema: String,
    }

    impl SqlServerFixture {
        fn new(schema: &str) -> Self {
            Self {
                schema: schema.to_owned(),
            }
        }

        fn create(&self, connection_string: &str) {
            let schema = &self.schema;
            let partition_function = self.partition_function();
            let partition_scheme = self.partition_scheme();
            let database_trigger = self.database_trigger();
            let creation = execute_admin_batches(
                connection_string,
                &[
                    format!("CREATE SCHEMA [{schema}] AUTHORIZATION [dbo]"),
                    format!(
                        "CREATE TYPE [{schema}].[account_code] FROM nvarchar(32) NOT NULL"
                    ),
                    format!(
                        "CREATE SEQUENCE [{schema}].[order_numbers] AS bigint START WITH 1000 INCREMENT BY 5 MINVALUE 1000 MAXVALUE 999999 CYCLE CACHE 20"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[users] (\
                         [id] bigint IDENTITY(10, 2) NOT NULL CONSTRAINT [pk_users] PRIMARY KEY,\
                         [tenant_id] int NOT NULL,\
                         [email] nvarchar(320) NOT NULL,\
                         [code] [{schema}].[account_code] NOT NULL,\
                         [email_key] AS LOWER(CONVERT(nvarchar(320), [email])) PERSISTED,\
                         [status] varchar(16) NOT NULL CONSTRAINT [df_users_status] DEFAULT ('active'),\
                         [created_at] datetime2(3) NOT NULL CONSTRAINT [df_users_created] DEFAULT (SYSUTCDATETIME()),\
                         CONSTRAINT [uq_users_email] UNIQUE ([email]),\
                         CONSTRAINT [ck_users_status] CHECK ([status] IN ('active', 'disabled')))"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[secured_accounts] (\
                         [id] bigint NOT NULL CONSTRAINT [pk_secured_accounts] PRIMARY KEY,\
                         [tenant_id] int NOT NULL,\
                         [display_name] nvarchar(200) NOT NULL)"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[orders] (\
                         [id] bigint NOT NULL CONSTRAINT [df_orders_id] DEFAULT (NEXT VALUE FOR [{schema}].[order_numbers]) CONSTRAINT [pk_orders] PRIMARY KEY,\
                         [user_id] bigint NOT NULL,\
                         [amount] decimal(18, 2) NOT NULL,\
                         [state] varchar(16) NOT NULL CONSTRAINT [df_orders_state] DEFAULT ('open'),\
                         [note] nvarchar(500) NULL,\
                         CONSTRAINT [fk_orders_users] FOREIGN KEY ([user_id]) REFERENCES [{schema}].[users]([id]) ON DELETE CASCADE,\
                         CONSTRAINT [ck_orders_amount] CHECK ([amount] >= 0))"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[audit_log] (\
                         [id] bigint IDENTITY(1, 1) NOT NULL CONSTRAINT [pk_audit_log] PRIMARY KEY,\
                         [order_id] bigint NOT NULL,\
                         [event_name] varchar(16) NOT NULL,\
                         [recorded_at] datetime2(3) NOT NULL CONSTRAINT [df_audit_recorded] DEFAULT (SYSUTCDATETIME()))"
                    ),
                    format!(
                        "CREATE PARTITION FUNCTION [{partition_function}](int) AS RANGE RIGHT FOR VALUES (100, 1000)"
                    ),
                    format!(
                        "CREATE PARTITION SCHEME [{partition_scheme}] AS PARTITION [{partition_function}] ALL TO ([PRIMARY])"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[partitioned_events] (\
                         [bucket] int NOT NULL,\
                         [payload] nvarchar(200) NULL) ON [{partition_scheme}]([bucket])"
                    ),
                    format!(
                        "CREATE INDEX [ix_partitioned_events] ON [{schema}].[partitioned_events]([bucket]) ON [{partition_scheme}]([bucket])"
                    ),
                    format!(
                        "CREATE TABLE [{schema}].[temporal_records] (\
                         [id] int NOT NULL CONSTRAINT [pk_temporal_records] PRIMARY KEY,\
                         [payload] nvarchar(200) NULL,\
                         [valid_from] datetime2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,\
                         [valid_to] datetime2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL,\
                         PERIOD FOR SYSTEM_TIME ([valid_from], [valid_to]))\
                         WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = [{schema}].[temporal_records_history], DATA_CONSISTENCY_CHECK = ON))"
                    ),
                    format!(
                        "CREATE INDEX [ix_orders_open] ON [{schema}].[orders] ([user_id] ASC, [amount] DESC) INCLUDE ([note]) WHERE [state] = 'open' WITH (FILLFACTOR = 90)"
                    ),
                    format!(
                        "CREATE VIEW [{schema}].[active_users_view] AS SELECT [id], [email], [tenant_id] FROM [{schema}].[users] WHERE [status] = 'active'"
                    ),
                    format!(
                        "CREATE VIEW [{schema}].[order_summary] AS SELECT o.[id], u.[email], o.[amount] FROM [{schema}].[orders] AS o JOIN [{schema}].[active_users_view] AS u ON u.[id] = o.[user_id]"
                    ),
                    "SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON; SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF".to_owned(),
                    format!(
                        "CREATE VIEW [{schema}].[user_tenant_counts] WITH SCHEMABINDING AS SELECT [tenant_id], COUNT_BIG(*) AS [user_count] FROM [{schema}].[users] GROUP BY [tenant_id]"
                    ),
                    format!(
                        "CREATE UNIQUE CLUSTERED INDEX [cix_user_tenant_counts] ON [{schema}].[user_tenant_counts]([tenant_id])"
                    ),
                    format!(
                        "CREATE FUNCTION [{schema}].[active_users](@minimum_id bigint) RETURNS TABLE WITH SCHEMABINDING AS RETURN (SELECT [id], [email] FROM [{schema}].[users] WHERE [id] >= @minimum_id)"
                    ),
                    format!(
                        "CREATE PROCEDURE [{schema}].[read_orders] @minimum_amount decimal(18, 2) AS SELECT [id], [user_id], [amount] FROM [{schema}].[orders] WHERE [amount] >= @minimum_amount"
                    ),
                    format!(
                        "CREATE FUNCTION [{schema}].[tenant_filter](@tenant_id int) RETURNS TABLE WITH SCHEMABINDING AS RETURN SELECT 1 AS [allowed] WHERE @tenant_id = CONVERT(int, SESSION_CONTEXT(N'tenant_id'))"
                    ),
                    format!(
                        "CREATE SECURITY POLICY [{schema}].[tenant_policy] ADD FILTER PREDICATE [{schema}].[tenant_filter]([tenant_id]) ON [{schema}].[secured_accounts] WITH (STATE = ON, SCHEMABINDING = ON)"
                    ),
                    format!(
                        "CREATE TRIGGER [{schema}].[tr_orders_audit] ON [{schema}].[orders] AFTER INSERT, UPDATE AS INSERT INTO [{schema}].[audit_log]([order_id], [event_name]) SELECT [id], 'changed' FROM inserted"
                    ),
                    format!(
                        "CREATE SYNONYM [{schema}].[users_alias] FOR [{schema}].[users]"
                    ),
                    format!(
                        "CREATE TRIGGER [{database_trigger}] ON DATABASE FOR CREATE_TABLE AS RETURN"
                    ),
                ],
            );
            if let Err(error) = creation {
                let cleanup = self.try_drop(connection_string);
                panic!("failed to create SQL Server fixture: {error}; cleanup: {cleanup:?}");
            }
        }

        fn drop(&self, connection_string: &str) {
            self.try_drop(connection_string).unwrap();
        }

        fn try_drop(&self, connection_string: &str) -> Result<(), String> {
            let schema = &self.schema;
            let partition_function = self.partition_function();
            let partition_scheme = self.partition_scheme();
            let database_trigger = self.database_trigger();
            execute_admin_batches(
                connection_string,
                &[
                    format!(
                        "IF EXISTS (SELECT 1 FROM sys.triggers WHERE parent_class = 0 AND name = N'{database_trigger}') DROP TRIGGER [{database_trigger}] ON DATABASE"
                    ),
                    format!("DROP SECURITY POLICY IF EXISTS [{schema}].[tenant_policy]"),
                    format!("DROP SYNONYM IF EXISTS [{schema}].[users_alias]"),
                    format!("DROP TRIGGER IF EXISTS [{schema}].[tr_orders_audit]"),
                    format!("DROP PROCEDURE IF EXISTS [{schema}].[read_orders]"),
                    format!("DROP FUNCTION IF EXISTS [{schema}].[tenant_filter]"),
                    format!("DROP FUNCTION IF EXISTS [{schema}].[active_users]"),
                    format!("DROP VIEW IF EXISTS [{schema}].[user_tenant_counts]"),
                    format!("DROP VIEW IF EXISTS [{schema}].[order_summary]"),
                    format!("DROP VIEW IF EXISTS [{schema}].[active_users_view]"),
                    format!(
                        "IF OBJECT_ID(N'{schema}.temporal_records', N'U') IS NOT NULL ALTER TABLE [{schema}].[temporal_records] SET (SYSTEM_VERSIONING = OFF)"
                    ),
                    format!("DROP TABLE IF EXISTS [{schema}].[temporal_records_history]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[temporal_records]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[partitioned_events]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[orders]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[audit_log]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[secured_accounts]"),
                    format!("DROP TABLE IF EXISTS [{schema}].[users]"),
                    format!(
                        "IF EXISTS (SELECT 1 FROM sys.partition_schemes WHERE name = N'{partition_scheme}') DROP PARTITION SCHEME [{partition_scheme}]"
                    ),
                    format!(
                        "IF EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = N'{partition_function}') DROP PARTITION FUNCTION [{partition_function}]"
                    ),
                    format!("DROP SEQUENCE IF EXISTS [{schema}].[order_numbers]"),
                    format!("DROP TYPE IF EXISTS [{schema}].[account_code]"),
                    format!("DROP SCHEMA IF EXISTS [{schema}]"),
                ],
            )
        }

        fn partition_function(&self) -> String {
            format!("pf_{}", self.schema)
        }

        fn partition_scheme(&self) -> String {
            format!("ps_{}", self.schema)
        }

        fn database_trigger(&self) -> String {
            format!("tr_database_{}", self.schema)
        }
    }

    fn drop_table_type_fixture(connection_string: &str, schema: &str) -> Result<(), String> {
        execute_admin_batches(
            connection_string,
            &[
                format!("DROP PROCEDURE IF EXISTS [{schema}].[consume_payload]"),
                format!("DROP TYPE IF EXISTS [{schema}].[payload]"),
                format!("DROP TYPE IF EXISTS [{schema}].[code]"),
                format!("DROP SCHEMA IF EXISTS [{schema}]"),
            ],
        )
    }

    fn drop_xml_metadata_fixture(connection_string: &str, schema: &str) -> Result<(), String> {
        execute_admin_batches(
            connection_string,
            &[
                format!("DROP PROCEDURE IF EXISTS [{schema}].[read_payload]"),
                format!("DROP TABLE IF EXISTS [{schema}].[typed_documents]"),
                format!("DROP TYPE IF EXISTS [{schema}].[payload_type]"),
                format!(
                    "IF EXISTS (SELECT 1 FROM sys.xml_schema_collections xsc \
                     JOIN sys.schemas s ON s.schema_id = xsc.schema_id \
                     WHERE s.name = N'{schema}' AND xsc.name = N'payload_xsd') \
                     DROP XML SCHEMA COLLECTION [{schema}].[payload_xsd]"
                ),
                format!("DROP SCHEMA IF EXISTS [{schema}]"),
            ],
        )
    }

    fn drop_cross_schema_fixture(
        connection_string: &str,
        child_schema: &str,
        parent_schema: &str,
    ) -> Result<(), String> {
        execute_admin_batches(
            connection_string,
            &[
                format!("DROP TABLE IF EXISTS [{child_schema}].[orders]"),
                format!("DROP TABLE IF EXISTS [{parent_schema}].[accounts]"),
                format!("DROP SCHEMA IF EXISTS [{child_schema}]"),
                format!("DROP SCHEMA IF EXISTS [{parent_schema}]"),
            ],
        )
    }

    fn execute_admin_batches(connection_string: &str, batches: &[String]) -> Result<(), String> {
        let connection_string = connection_string.to_owned();
        let batches = batches.to_vec();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async move {
            let config =
                Config::from_ado_string(&connection_string).map_err(|error| error.to_string())?;
            let tcp = TcpStream::connect(config.get_addr())
                .await
                .map_err(|error| error.to_string())?;
            tcp.set_nodelay(true).map_err(|error| error.to_string())?;
            let mut client = Client::connect(config, tcp.compat_write())
                .await
                .map_err(|error| error.to_string())?;
            for (batch_index, batch) in batches.into_iter().enumerate() {
                client
                    .simple_query(batch)
                    .await
                    .map_err(|error| format!("batch #{} failed: {error}", batch_index + 1))?
                    .into_results()
                    .await
                    .map_err(|error| {
                        format!("batch #{} result failed: {error}", batch_index + 1)
                    })?;
            }
            Ok(())
        })
    }

    fn connection_with_credentials(connection_string: &str, user: &str, password: &str) -> String {
        let mut values = connection_string.parse::<AdoNetString>().unwrap();
        for key in [
            "user",
            "uid",
            "user id",
            "username",
            "password",
            "pwd",
            "integrated security",
            "trusted_connection",
        ] {
            values.remove(key);
        }
        values.insert("user id".to_owned(), user.to_owned());
        values.insert("password".to_owned(), password.to_owned());
        values.to_string()
    }
}
