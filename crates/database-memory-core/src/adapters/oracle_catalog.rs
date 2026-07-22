use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use oracle::{Connection, Version};

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
    CatalogDiscovery, CatalogIntrospector, DatabaseAnalysisService, IntrospectionRequest,
};
use crate::{
    AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintKind, ConstraintObject,
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, RoutineKind, RoutineObject, SchemaObject,
    SchemaSnapshot, TableKind, TableObject, TriggerObject, ViewObject,
};

const ORACLE_SOURCE: &str = "oracle";
const ORACLE_ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_DEFINITION_BYTES: usize = 1_048_576;
const MAX_ROUTINE_SIGNATURE_BYTES: usize = 4_096;

pub(crate) struct OracleCatalogAdapter {
    connection_string: String,
}

impl OracleCatalogAdapter {
    pub(crate) fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
        }
    }
}

impl CatalogIntrospector for OracleCatalogAdapter {
    fn source_kind(&self) -> &'static str {
        ORACLE_SOURCE
    }

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        validate_request(request)?;
        validate_connection_policy(request, &self.connection_string)?;
        discover_oracle(&self.connection_string, request)
    }
}

pub(crate) fn analyze_oracle(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs,
        requested_schemas,
        timeout_ms,
    };
    DatabaseAnalysisService::new(OracleCatalogAdapter::new(connection_string)).analyze(&request)
}

fn discover_oracle(
    connection_string: &str,
    request: &IntrospectionRequest,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    let parsed = parse_oracle_connection_string(connection_string).map_err(|error| {
        catalog_failure(
            request,
            connection_string,
            error,
            AnalysisStage::Configuration,
        )
    })?;
    let connection = Connection::connect(parsed.username, parsed.password, parsed.connect_string)
        .map_err(|error| connection_failure(request, connection_string, error))?;
    connection
        .set_call_timeout(Some(Duration::from_millis(request.timeout_ms)))
        .map_err(|error| {
            catalog_failure(
                request,
                connection_string,
                CatalogError::Query(error),
                AnalysisStage::Connection,
            )
        })?;

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(request.timeout_ms))
        .ok_or_else(|| {
            catalog_failure(
                request,
                connection_string,
                CatalogError::Timeout,
                AnalysisStage::Configuration,
            )
        })?;
    prepare_call(&connection, deadline).map_err(|error| {
        catalog_failure(request, connection_string, error, AnalysisStage::Connection)
    })?;
    connection
        .execute("SET TRANSACTION READ ONLY", &[])
        .map_err(|error| {
            catalog_failure(
                request,
                connection_string,
                CatalogError::Query(error),
                AnalysisStage::CapabilityProbe,
            )
        })?;

    let result = discover_connected(&connection, request, deadline).map_err(|error| {
        let stage = error.stage();
        catalog_failure(request, connection_string, error, stage)
    });
    let rollback = connection.rollback().map_err(|error| {
        catalog_failure(
            request,
            connection_string,
            CatalogError::Query(error),
            AnalysisStage::CapabilityProbe,
        )
    });

    match (result, rollback) {
        (Ok(discovery), Ok(())) => Ok(discovery),
        (Err(failure), _) => Err(failure),
        (Ok(_), Err(failure)) => Err(failure),
    }
}

fn discover_connected(
    connection: &Connection,
    request: &IntrospectionRequest,
    deadline: Instant,
) -> Result<CatalogDiscovery, CatalogError> {
    let facts = ServerFacts::read(connection, deadline)?;
    let strategy = OracleCatalogVersion::detect(&facts.version, &facts.release)?;
    validate_catalog_scope(request, &facts)?;
    let scope = DictionaryScope::select(connection, request, &facts, deadline)?;

    let first = RawOracleCatalog::read(connection, &scope, deadline)?;
    let second = RawOracleCatalog::read(connection, &scope, deadline)?;
    let stable = require_stable_catalog(first, &second)?;
    validate_raw_catalog(&stable, &scope)?;

    OracleSnapshotMapper::new(&request.connection_alias, facts, strategy, scope).map(stable)
}

fn require_stable_catalog<T: PartialEq>(first: T, second: &T) -> Result<T, CatalogError> {
    if &first != second {
        return Err(CatalogError::CatalogChanged(
            "Oracle data dictionary changed while metadata was being collected".to_owned(),
        ));
    }
    Ok(first)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OracleCatalogVersion {
    Oracle26Ai,
}

impl OracleCatalogVersion {
    fn detect(version: &Version, release: &str) -> Result<Self, CatalogError> {
        if version.major() == 23 && release.to_ascii_uppercase().contains("26AI") {
            Ok(Self::Oracle26Ai)
        } else {
            Err(CatalogError::UnsupportedVersion(format!(
                "{} ({release})",
                version
            )))
        }
    }

    fn strategy_name(self) -> &'static str {
        match self {
            Self::Oracle26Ai => "oracle-26ai-dictionary-v1",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ServerFacts {
    database: String,
    container: String,
    container_id: i64,
    session_user: String,
    current_schema: String,
    version: Version,
    release: String,
}

impl ServerFacts {
    fn read(connection: &Connection, deadline: Instant) -> Result<Self, CatalogError> {
        prepare_call(connection, deadline)?;
        let (version, release) = connection.server_version()?;
        let release = normalize_server_release(&release)?;
        prepare_call(connection, deadline)?;
        let (database, container, container_id, session_user, current_schema) = connection
            .query_row_as::<(String, String, String, String, String)>(
                "
                SELECT SYS_CONTEXT('USERENV', 'DB_NAME'),
                       SYS_CONTEXT('USERENV', 'CON_NAME'),
                       SYS_CONTEXT('USERENV', 'CON_ID'),
                       SYS_CONTEXT('USERENV', 'SESSION_USER'),
                       SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')
                FROM DUAL
                ",
                &[],
            )?;
        let container_id = container_id.parse::<i64>().map_err(|error| {
            CatalogError::Mapping(format!("invalid Oracle container id: {error}"))
        })?;
        if container.eq_ignore_ascii_case("CDB$ROOT") || container_id == 1 {
            return Err(CatalogError::InvalidScope(
                "root-container discovery is not part of the certified single-PDB contract"
                    .to_owned(),
            ));
        }
        Ok(Self {
            database,
            container,
            container_id,
            session_user,
            current_schema,
            version,
            release,
        })
    }
}

fn normalize_server_release(value: &str) -> Result<String, CatalogError> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() || normalized.len() > MAX_DEFINITION_BYTES {
        return Err(CatalogError::Mapping(
            "Oracle server release text is empty or exceeds the safety limit".to_owned(),
        ));
    }
    Ok(normalized)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DictionaryScopeMode {
    User,
    Dba,
}

impl DictionaryScopeMode {
    fn label(self) -> &'static str {
        match self {
            Self::User => "USER_* owned-schema scope",
            Self::Dba => "DBA_* selected-schema scope",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DictionaryScope {
    mode: DictionaryScopeMode,
    owners: Vec<String>,
    principals: Vec<RawPrincipal>,
}

impl DictionaryScope {
    fn select(
        connection: &Connection,
        request: &IntrospectionRequest,
        facts: &ServerFacts,
        deadline: Instant,
    ) -> Result<Self, CatalogError> {
        let owners = normalize_requested_schemas(request, &facts.session_user)?;
        let mode = if owners.len() == 1 && owners[0] == facts.session_user {
            DictionaryScopeMode::User
        } else {
            DictionaryScopeMode::Dba
        };
        let principals = read_principals(connection, mode, &owners, deadline)?;
        if principals.len() != owners.len() {
            let found = principals
                .iter()
                .map(|principal| principal.name.as_str())
                .collect::<BTreeSet<_>>();
            let missing = owners
                .iter()
                .filter(|owner| !found.contains(owner.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            return Err(CatalogError::InvalidScope(format!(
                "requested Oracle schema owner(s) do not exist or are not visible: {}",
                missing.join(", ")
            )));
        }
        for principal in &principals {
            if principal.oracle_maintained {
                return Err(CatalogError::InvalidScope(format!(
                    "Oracle-maintained schema '{}' is outside the application-schema contract",
                    principal.name
                )));
            }
        }
        Ok(Self {
            mode,
            owners,
            principals,
        })
    }

    fn contains_owner(&self, owner: &str) -> bool {
        self.owners
            .binary_search_by(|value| value.as_str().cmp(owner))
            .is_ok()
    }
}

fn validate_request(request: &IntrospectionRequest) -> Result<(), AnalysisFailure> {
    if request.timeout_ms > MAX_INTROSPECTION_TIMEOUT_MS {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            ORACLE_SOURCE,
            &request.connection_alias,
            format!(
                "Oracle introspection timeout {} exceeds the {} ms maximum",
                request.timeout_ms, MAX_INTROSPECTION_TIMEOUT_MS
            ),
            "use a bounded timeout of at most 86400000 milliseconds",
            false,
            None,
        ));
    }
    for value in request
        .requested_catalogs
        .iter()
        .chain(&request.requested_schemas)
    {
        if value.trim().is_empty() {
            return Err(AnalysisFailure::redacted(
                AnalysisFailureCode::InvalidConfiguration,
                AnalysisStage::Configuration,
                ORACLE_SOURCE,
                &request.connection_alias,
                "Oracle catalog and schema selectors must not be blank",
                "remove blank selectors and retry",
                false,
                None,
            ));
        }
    }
    Ok(())
}

fn validate_catalog_scope(
    request: &IntrospectionRequest,
    facts: &ServerFacts,
) -> Result<(), CatalogError> {
    if request.requested_catalogs.len() > 1 {
        return Err(CatalogError::InvalidScope(
            "an Oracle connection certifies exactly one connected PDB or non-CDB".to_owned(),
        ));
    }
    if let Some(requested) = request.requested_catalogs.first() {
        if requested != &facts.container && requested != &facts.database {
            return Err(CatalogError::InvalidScope(format!(
                "connected Oracle catalog is '{}' (database '{}'), requested '{}'",
                facts.container, facts.database, requested
            )));
        }
    }
    Ok(())
}

fn normalize_requested_schemas(
    request: &IntrospectionRequest,
    session_user: &str,
) -> Result<Vec<String>, CatalogError> {
    let mut owners = if request.requested_schemas.is_empty() {
        vec![session_user.to_owned()]
    } else {
        request.requested_schemas.clone()
    };
    owners.sort();
    if owners.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CatalogError::InvalidScope(
            "Oracle schema selection contains duplicate owners".to_owned(),
        ));
    }
    Ok(owners)
}

struct ParsedOracleConnection<'a> {
    username: &'a str,
    password: &'a str,
    connect_string: &'a str,
}

fn parse_oracle_connection_string(value: &str) -> Result<ParsedOracleConnection<'_>, CatalogError> {
    let (username, rest) = value
        .split_once('/')
        .ok_or(CatalogError::InvalidConnectionString)?;
    let (password, connect_string) = rest
        .rsplit_once('@')
        .ok_or(CatalogError::InvalidConnectionString)?;
    if username.is_empty() || password.is_empty() || connect_string.is_empty() {
        return Err(CatalogError::InvalidConnectionString);
    }
    Ok(ParsedOracleConnection {
        username,
        password,
        connect_string,
    })
}

fn validate_connection_policy(
    request: &IntrospectionRequest,
    connection_string: &str,
) -> Result<(), AnalysisFailure> {
    let parsed = parse_oracle_connection_string(connection_string).map_err(|error| {
        catalog_failure(
            request,
            connection_string,
            error,
            AnalysisStage::Configuration,
        )
    })?;
    let connect = parsed.connect_string.trim();
    let normalized = connect.to_ascii_lowercase();
    if normalized.starts_with("tcps://") || normalized.contains("(protocol=tcps)") {
        return Ok(());
    }
    if extract_oracle_host(connect).is_some_and(is_loopback_host) {
        return Ok(());
    }
    Err(AnalysisFailure::redacted(
        AnalysisFailureCode::UnsafeSource,
        AnalysisStage::Configuration,
        ORACLE_SOURCE,
        &request.connection_alias,
        "remote Oracle metadata connections must use a verifiable TCPS endpoint",
        "use a tcps:// Easy Connect string or a descriptor with PROTOCOL=TCPS; plain TCP is allowed only for loopback test databases",
        false,
        Some(connection_string),
    ))
}

fn extract_oracle_host(connect: &str) -> Option<&str> {
    let trimmed = connect.trim();
    let normalized = trimmed.to_ascii_lowercase();
    if let Some(position) = normalized.find("(host=") {
        let start = position + "(host=".len();
        let end = trimmed[start..].find(')')? + start;
        return Some(trimmed[start..end].trim());
    }
    let easy = trimmed
        .strip_prefix("//")
        .or_else(|| trimmed.strip_prefix("tcp://"))
        .or_else(|| trimmed.strip_prefix("TCP://"))
        .unwrap_or(trimmed);
    let authority = easy.split(['/', '?']).next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next();
    }
    let (host, port) = authority.rsplit_once(':')?;
    if port.parse::<u16>().is_err() {
        return None;
    }
    Some(host)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host == "."
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn prepare_call(connection: &Connection, deadline: Instant) -> Result<(), CatalogError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(CatalogError::Timeout)?;
    if remaining < Duration::from_millis(1) {
        return Err(CatalogError::Timeout);
    }
    connection.set_call_timeout(Some(remaining))?;
    Ok(())
}

#[derive(Debug)]
enum CatalogError {
    InvalidConnectionString,
    InvalidScope(String),
    UnsupportedVersion(String),
    UnsupportedMetadata(String),
    CatalogChanged(String),
    Mapping(String),
    Timeout,
    Query(oracle::Error),
    QueryContext {
        catalog: &'static str,
        source: oracle::Error,
    },
}

impl CatalogError {
    fn stage(&self) -> AnalysisStage {
        match self {
            Self::InvalidConnectionString | Self::InvalidScope(_) => AnalysisStage::Configuration,
            Self::UnsupportedVersion(_) => AnalysisStage::CapabilityProbe,
            Self::UnsupportedMetadata(_) | Self::CatalogChanged(_) | Self::Timeout => {
                AnalysisStage::Discovery
            }
            Self::Mapping(_) => AnalysisStage::Mapping,
            Self::Query(_) | Self::QueryContext { .. } => AnalysisStage::Discovery,
        }
    }

    fn catalog_context(self, catalog: &'static str) -> Self {
        match self {
            Self::Query(source) => Self::QueryContext { catalog, source },
            other => other,
        }
    }
}

impl From<oracle::Error> for CatalogError {
    fn from(error: oracle::Error) -> Self {
        if is_timeout_error(&error) {
            Self::Timeout
        } else {
            Self::Query(error)
        }
    }
}

fn connection_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: oracle::Error,
) -> AnalysisFailure {
    let authentication = error.oci_code() == Some(1017);
    AnalysisFailure::redacted(
        if authentication {
            AnalysisFailureCode::AuthenticationFailed
        } else if is_timeout_error(&error) {
            AnalysisFailureCode::Timeout
        } else {
            AnalysisFailureCode::ConnectionFailed
        },
        AnalysisStage::Connection,
        ORACLE_SOURCE,
        &request.connection_alias,
        error.to_string(),
        if authentication {
            "verify the Oracle username, password, and authentication policy"
        } else {
            "verify the Oracle listener, service name, network policy, and native client availability"
        },
        !authentication,
        Some(connection_string),
    )
}

fn catalog_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    error: CatalogError,
    stage: AnalysisStage,
) -> AnalysisFailure {
    let (code, message, remediation, retryable) = match error {
        CatalogError::InvalidConnectionString => (
            AnalysisFailureCode::InvalidConfiguration,
            "Oracle connection string must be user/password@connect_string".to_owned(),
            "provide a non-empty username, password, and Oracle connect string".to_owned(),
            false,
        ),
        CatalogError::InvalidScope(message) => (
            AnalysisFailureCode::InvalidConfiguration,
            message,
            "select the connected PDB and non-Oracle-maintained schema owners, then retry"
                .to_owned(),
            false,
        ),
        CatalogError::UnsupportedVersion(version) => (
            AnalysisFailureCode::UnsupportedVersion,
            format!("Oracle server version '{version}' has no live-certified catalog strategy"),
            "use a certified Oracle version or add and live-verify a version strategy".to_owned(),
            false,
        ),
        CatalogError::UnsupportedMetadata(message) => (
            AnalysisFailureCode::UnsupportedMetadata,
            message,
            "extend the Oracle catalog mapper for every reported object before retrying".to_owned(),
            false,
        ),
        CatalogError::CatalogChanged(message) => (
            AnalysisFailureCode::CompletenessMismatch,
            message,
            "retry after schema migrations and DDL activity have completed".to_owned(),
            true,
        ),
        CatalogError::Mapping(message) => (
            AnalysisFailureCode::MetadataMappingFailed,
            message,
            "inspect the Oracle catalog identities and fix every unresolved mapping".to_owned(),
            false,
        ),
        CatalogError::Timeout => (
            AnalysisFailureCode::Timeout,
            format!(
                "Oracle metadata analysis exceeded the {} ms timeout",
                request.timeout_ms
            ),
            "increase the bounded timeout or reduce the selected schema scope".to_owned(),
            true,
        ),
        CatalogError::Query(error) => {
            let timeout = is_timeout_error(&error);
            let permission = matches!(error.oci_code(), Some(942 | 1031));
            (
                if timeout {
                    AnalysisFailureCode::Timeout
                } else if permission {
                    AnalysisFailureCode::PermissionDenied
                } else {
                    AnalysisFailureCode::MetadataQueryFailed
                },
                if timeout {
                    format!(
                        "Oracle metadata analysis exceeded the {} ms timeout",
                        request.timeout_ms
                    )
                } else {
                    error.to_string()
                },
                if timeout {
                    "increase the bounded timeout or reduce the selected schema scope".to_owned()
                } else if permission {
                    "use USER_* for the session owner or grant direct/role access to every required DBA_* dictionary view"
                        .to_owned()
                } else {
                    "verify Oracle dictionary availability and retry after transient catalog errors"
                        .to_owned()
                },
                !permission,
            )
        }
        CatalogError::QueryContext { catalog, source } => {
            let timeout = is_timeout_error(&source);
            let permission = matches!(source.oci_code(), Some(942 | 1031));
            (
                if timeout {
                    AnalysisFailureCode::Timeout
                } else if permission {
                    AnalysisFailureCode::PermissionDenied
                } else {
                    AnalysisFailureCode::MetadataQueryFailed
                },
                if timeout {
                    format!(
                        "Oracle metadata analysis exceeded the {} ms timeout while reading {catalog}",
                        request.timeout_ms
                    )
                } else {
                    format!("Oracle {catalog} query failed: {source}")
                },
                if timeout {
                    "increase the bounded timeout or reduce the selected schema scope".to_owned()
                } else if permission {
                    "use USER_* for the session owner or grant direct/role access to every required DBA_* dictionary view"
                        .to_owned()
                } else {
                    "verify Oracle dictionary availability and the catalog column contract"
                        .to_owned()
                },
                !permission,
            )
        }
    };
    AnalysisFailure::redacted(
        code,
        stage,
        ORACLE_SOURCE,
        &request.connection_alias,
        message,
        remediation,
        retryable,
        Some(connection_string),
    )
}

fn is_timeout_error(error: &oracle::Error) -> bool {
    error.dpi_code() == Some(1067) || error.oci_code() == Some(1013)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPrincipal {
    name: String,
    user_id: i64,
    account_status: String,
    common: bool,
    oracle_maintained: bool,
    default_collation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawInventoryObject {
    owner: String,
    name: String,
    subobject: Option<String>,
    object_id: i64,
    data_object_id: Option<i64>,
    object_type: String,
    status: String,
    temporary: bool,
    generated: bool,
    secondary: bool,
    namespace: i64,
    edition_name: Option<String>,
    editionable: Option<String>,
    default_collation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTable {
    owner: String,
    name: String,
    status: String,
    temporary: bool,
    partitioned: bool,
    iot_type: Option<String>,
    nested: bool,
    read_only: bool,
    has_identity: bool,
    duration: Option<String>,
    external: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawColumn {
    owner: String,
    table: String,
    name: String,
    column_id: Option<i64>,
    internal_column_id: i64,
    data_type: String,
    data_type_owner: Option<String>,
    data_length: i64,
    data_precision: Option<i64>,
    data_scale: Option<i64>,
    nullable: bool,
    default_value: Option<String>,
    hidden: bool,
    virtual_column: bool,
    user_generated: bool,
    default_on_null: bool,
    identity: bool,
    char_length: Option<i64>,
    char_used: Option<String>,
    collation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSequence {
    owner: String,
    name: String,
    min_value: Option<String>,
    max_value: Option<String>,
    increment_by: String,
    cycle: Option<String>,
    ordered: Option<String>,
    cache_size: String,
    scale: Option<String>,
    extend: Option<String>,
    sharded: Option<String>,
    session: Option<String>,
    keep_value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIdentityColumn {
    owner: String,
    table: String,
    column: String,
    generation_type: Option<String>,
    sequence_name: String,
    options: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawView {
    owner: String,
    name: String,
    text_length: Option<i64>,
    definition: Option<String>,
    type_owner: Option<String>,
    view_type: Option<String>,
    superview: Option<String>,
    editioning: Option<String>,
    read_only: Option<String>,
    container_data: Option<String>,
    bequeath: Option<String>,
    default_collation: Option<String>,
    has_sensitive_column: Option<String>,
    admit_null: Option<String>,
    pdb_local_only: Option<String>,
    duality_view: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawMaterializedView {
    owner: String,
    name: String,
    container_name: String,
    query_length: Option<i64>,
    definition: Option<String>,
    updatable: Option<String>,
    master_link: Option<String>,
    rewrite_enabled: Option<String>,
    rewrite_capability: Option<String>,
    refresh_mode: Option<String>,
    refresh_method: Option<String>,
    build_mode: Option<String>,
    fast_refreshable: Option<String>,
    compile_state: Option<String>,
    use_no_index: Option<String>,
    segment_created: Option<String>,
    default_collation: Option<String>,
    on_query_computation: Option<String>,
    automatic: Option<String>,
    concurrent_refresh: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSynonym {
    owner: String,
    name: String,
    target_owner: String,
    target_name: String,
    database_link: Option<String>,
    origin_container_id: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionedTable {
    owner: String,
    table: String,
    partitioning_type: String,
    subpartitioning_type: String,
    partition_count: i64,
    default_subpartition_count: i64,
    partitioning_key_count: i64,
    subpartitioning_key_count: i64,
    status: String,
    default_tablespace: Option<String>,
    interval: Option<String>,
    autolist: Option<String>,
    interval_subpartition: Option<String>,
    autolist_subpartition: Option<String>,
    automatic: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTablePartition {
    owner: String,
    table: String,
    composite: String,
    name: String,
    subpartition_count: i64,
    high_value: Option<String>,
    high_value_length: i64,
    position: i64,
    tablespace: Option<String>,
    compression: String,
    compress_for: Option<String>,
    interval: String,
    segment_created: String,
    indexing: String,
    read_only: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTableSubpartition {
    owner: String,
    table: String,
    partition: String,
    name: String,
    high_value: Option<String>,
    high_value_length: i64,
    partition_position: i64,
    position: i64,
    tablespace: Option<String>,
    compression: String,
    compress_for: Option<String>,
    interval: String,
    segment_created: String,
    indexing: String,
    read_only: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionedIndex {
    owner: String,
    index: String,
    table: String,
    partitioning_type: String,
    subpartitioning_type: String,
    partition_count: i64,
    default_subpartition_count: i64,
    partitioning_key_count: i64,
    subpartitioning_key_count: i64,
    locality: String,
    alignment: String,
    default_tablespace: Option<String>,
    interval: Option<String>,
    autolist: Option<String>,
    interval_subpartition: Option<String>,
    autolist_subpartition: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndexPartition {
    owner: String,
    index: String,
    composite: String,
    name: String,
    subpartition_count: i64,
    high_value: Option<String>,
    high_value_length: i64,
    position: i64,
    status: String,
    tablespace: Option<String>,
    compression: String,
    interval: String,
    segment_created: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndexSubpartition {
    owner: String,
    index: String,
    partition: String,
    name: String,
    high_value: Option<String>,
    high_value_length: i64,
    partition_position: i64,
    position: i64,
    status: String,
    tablespace: Option<String>,
    compression: String,
    interval: String,
    segment_created: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPartitionKeyColumn {
    owner: String,
    name: String,
    object_type: String,
    column: String,
    position: i64,
    collated_column_id: Option<i64>,
    subpartition: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawLob {
    owner: String,
    table: String,
    column: String,
    segment_name: String,
    tablespace: Option<String>,
    index_name: String,
    chunk: i64,
    pctversion: Option<i64>,
    retention: Option<i64>,
    freepools: Option<i64>,
    cache: String,
    logging: String,
    encrypt: String,
    compression: String,
    deduplication: String,
    in_row: String,
    format: String,
    partitioned: String,
    securefile: String,
    segment_created: String,
    retention_type: Option<String>,
    retention_value: Option<i64>,
    value_based: Option<String>,
    max_inline: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawLobPartition {
    owner: String,
    table: String,
    column: String,
    lob_name: String,
    table_partition: String,
    name: String,
    index_partition_name: String,
    position: i64,
    composite: String,
    chunk: i64,
    pctversion: Option<i64>,
    cache: String,
    in_row: String,
    tablespace: Option<String>,
    retention: Option<String>,
    logging: String,
    encrypt: String,
    compression: String,
    deduplication: String,
    securefile: String,
    segment_created: String,
    max_inline: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawLobSubpartition {
    owner: String,
    table: String,
    column: String,
    lob_name: String,
    lob_partition_name: String,
    table_subpartition: String,
    name: String,
    index_subpartition_name: String,
    position: i64,
    chunk: i64,
    pctversion: Option<i64>,
    cache: String,
    in_row: String,
    tablespace: Option<String>,
    retention: Option<String>,
    logging: String,
    encrypt: String,
    compression: String,
    deduplication: String,
    securefile: String,
    segment_created: String,
    max_inline: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawUserType {
    owner: String,
    name: String,
    oid: String,
    typecode: String,
    attribute_count: i64,
    method_count: i64,
    predefined: String,
    incomplete: String,
    final_type: String,
    instantiable: String,
    persistable: String,
    supertype_owner: Option<String>,
    supertype_name: Option<String>,
    local_attribute_count: Option<i64>,
    local_method_count: Option<i64>,
    type_id: Option<String>,
    specification: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTypeAttribute {
    owner: String,
    type_name: String,
    name: String,
    type_modifier: Option<String>,
    data_type_owner: Option<String>,
    data_type_name: String,
    length: Option<i64>,
    precision: Option<i64>,
    scale: Option<i64>,
    character_set: Option<String>,
    position: i64,
    inherited: String,
    char_used: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawCollectionType {
    owner: String,
    type_name: String,
    collection_type: String,
    upper_bound: Option<i64>,
    element_type_modifier: Option<String>,
    element_type_owner: Option<String>,
    element_type_name: String,
    length: Option<i64>,
    precision: Option<i64>,
    scale: Option<i64>,
    character_set: Option<String>,
    element_storage: Option<String>,
    nulls_stored: Option<String>,
    char_used: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTypeMethod {
    owner: String,
    type_name: String,
    name: String,
    method_number: i64,
    method_type: String,
    parameter_count: i64,
    result_count: i64,
    final_method: String,
    instantiable: String,
    overriding: String,
    inherited: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTypeMethodParameter {
    owner: String,
    type_name: String,
    method_name: String,
    method_number: i64,
    name: String,
    position: i64,
    mode: String,
    type_modifier: Option<String>,
    data_type_owner: Option<String>,
    data_type_name: String,
    character_set: Option<String>,
    return_value: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawTrigger {
    owner: String,
    name: String,
    trigger_type: String,
    triggering_event: String,
    table_owner: Option<String>,
    base_object_type: String,
    table_name: Option<String>,
    column_name: Option<String>,
    referencing_names: Option<String>,
    when_clause: Option<String>,
    status: String,
    description: Option<String>,
    action_type: String,
    body: Option<String>,
    crossedition: Option<String>,
    fire_once: Option<String>,
    apply_server_only: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawRoutine {
    owner: String,
    name: String,
    object_id: i64,
    subprogram_id: i64,
    overload: Option<String>,
    object_type: String,
    aggregate: bool,
    pipelined: bool,
    parallel: bool,
    interface: bool,
    deterministic: bool,
    authid: String,
    polymorphic: Option<String>,
    definition: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawRoutineArgument {
    owner: String,
    routine: String,
    package_name: Option<String>,
    name: Option<String>,
    position: i64,
    sequence: i64,
    data_level: i64,
    data_type: Option<String>,
    defaulted: bool,
    default_length: Option<i64>,
    default_value: Option<String>,
    mode: String,
    data_length: Option<i64>,
    data_precision: Option<i64>,
    data_scale: Option<i64>,
    type_owner: Option<String>,
    type_name: Option<String>,
    type_subname: Option<String>,
    pls_type: Option<String>,
    char_length: Option<i64>,
    char_used: Option<String>,
    subprogram_id: i64,
    overload: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPackage {
    owner: String,
    name: String,
    object_id: i64,
    authid: String,
    specification: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPackageRoutine {
    owner: String,
    package: String,
    name: String,
    object_id: i64,
    subprogram_id: i64,
    overload: Option<String>,
    aggregate: bool,
    pipelined: bool,
    parallel: bool,
    interface: bool,
    deterministic: bool,
    authid: String,
    polymorphic: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawConstraintColumn {
    name: String,
    position: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawConstraint {
    owner: String,
    table: String,
    name: String,
    constraint_type: String,
    search_condition: Option<String>,
    referenced_owner: Option<String>,
    referenced_constraint: Option<String>,
    delete_rule: Option<String>,
    status: String,
    deferrable: String,
    deferred: String,
    validated: String,
    generated: String,
    index_owner: Option<String>,
    index_name: Option<String>,
    invalid: Option<String>,
    view_related: Option<String>,
    columns: Vec<RawConstraintColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndexColumn {
    name: String,
    position: i64,
    descending: bool,
    expression: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawIndex {
    owner: String,
    table_owner: String,
    table: String,
    name: String,
    index_type: String,
    unique: bool,
    status: String,
    partitioned: bool,
    temporary: bool,
    generated: bool,
    secondary: bool,
    visibility: String,
    function_status: Option<String>,
    constraint_index: bool,
    columns: Vec<RawIndexColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawDependency {
    owner: String,
    name: String,
    object_type: String,
    referenced_owner: String,
    referenced_name: String,
    referenced_type: String,
    referenced_link: Option<String>,
    dependency_type: String,
    referenced_owner_oracle_maintained: bool,
}

type CollapsedDependencyIdentity = (String, String, String, String, String);

#[derive(Default)]
struct CollapsedDependencyEvidence {
    source_object_types: BTreeSet<String>,
    dependency_types: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawOracleCatalog {
    inventory: Vec<RawInventoryObject>,
    tables: Vec<RawTable>,
    columns: Vec<RawColumn>,
    sequences: Vec<RawSequence>,
    identity_columns: Vec<RawIdentityColumn>,
    views: Vec<RawView>,
    view_columns: Vec<RawColumn>,
    materialized_views: Vec<RawMaterializedView>,
    synonyms: Vec<RawSynonym>,
    user_types: Vec<RawUserType>,
    type_attributes: Vec<RawTypeAttribute>,
    collection_types: Vec<RawCollectionType>,
    type_methods: Vec<RawTypeMethod>,
    type_method_parameters: Vec<RawTypeMethodParameter>,
    triggers: Vec<RawTrigger>,
    routines: Vec<RawRoutine>,
    routine_arguments: Vec<RawRoutineArgument>,
    packages: Vec<RawPackage>,
    package_routines: Vec<RawPackageRoutine>,
    package_arguments: Vec<RawRoutineArgument>,
    constraints: Vec<RawConstraint>,
    indexes: Vec<RawIndex>,
    partitioned_tables: Vec<RawPartitionedTable>,
    table_partitions: Vec<RawTablePartition>,
    table_subpartitions: Vec<RawTableSubpartition>,
    partitioned_indexes: Vec<RawPartitionedIndex>,
    index_partitions: Vec<RawIndexPartition>,
    index_subpartitions: Vec<RawIndexSubpartition>,
    partition_key_columns: Vec<RawPartitionKeyColumn>,
    lobs: Vec<RawLob>,
    lob_partitions: Vec<RawLobPartition>,
    lob_subpartitions: Vec<RawLobSubpartition>,
    dependencies: Vec<RawDependency>,
}

impl RawOracleCatalog {
    fn read(
        connection: &Connection,
        scope: &DictionaryScope,
        deadline: Instant,
    ) -> Result<Self, CatalogError> {
        reject_database_links(connection, scope, deadline)
            .map_err(|error| error.catalog_context("database-link"))?;
        let recycle = read_recycle_bin(connection, scope, deadline)
            .map_err(|error| error.catalog_context("recycle-bin"))?;
        let inventory = read_inventory(connection, scope, &recycle, deadline)
            .map_err(|error| error.catalog_context("object-inventory"))?;
        let tables = read_tables(connection, scope, &recycle, deadline)
            .map_err(|error| error.catalog_context("table"))?;
        let columns = read_columns(connection, scope, &recycle, deadline)
            .map_err(|error| error.catalog_context("column"))?;
        let sequences = read_sequences(connection, scope, deadline)
            .map_err(|error| error.catalog_context("sequence"))?;
        let identity_columns = read_identity_columns(connection, scope, deadline)
            .map_err(|error| error.catalog_context("identity-column"))?;
        let views = read_views(connection, scope, deadline)
            .map_err(|error| error.catalog_context("view"))?;
        let view_columns = read_view_columns(connection, scope, deadline)
            .map_err(|error| error.catalog_context("view-column"))?;
        let materialized_views = read_materialized_views(connection, scope, deadline)
            .map_err(|error| error.catalog_context("materialized-view"))?;
        let synonyms = read_synonyms(connection, scope, deadline)
            .map_err(|error| error.catalog_context("synonym"))?;
        let mut user_types = read_user_types(connection, scope, deadline)
            .map_err(|error| error.catalog_context("type"))?;
        attach_type_sources(connection, scope, &mut user_types, deadline)
            .map_err(|error| error.catalog_context("type-source"))?;
        let type_attributes = read_type_attributes(connection, scope, deadline)
            .map_err(|error| error.catalog_context("type-attribute"))?;
        let collection_types = read_collection_types(connection, scope, deadline)
            .map_err(|error| error.catalog_context("collection-type"))?;
        let type_methods = read_type_methods(connection, scope, deadline)
            .map_err(|error| error.catalog_context("type-method"))?;
        let type_method_parameters = read_type_method_parameters(connection, scope, deadline)
            .map_err(|error| error.catalog_context("type-method-parameter"))?;
        let triggers = read_triggers(connection, scope, deadline)
            .map_err(|error| error.catalog_context("trigger"))?;
        let mut routines = read_routines(connection, scope, deadline)
            .map_err(|error| error.catalog_context("routine"))?;
        attach_routine_sources(connection, scope, &mut routines, deadline)
            .map_err(|error| error.catalog_context("routine-source"))?;
        let routine_arguments = read_routine_arguments(connection, scope, deadline)
            .map_err(|error| error.catalog_context("routine-argument"))?;
        let mut packages = read_packages(connection, scope, deadline)
            .map_err(|error| error.catalog_context("package"))?;
        attach_package_sources(connection, scope, &mut packages, deadline)
            .map_err(|error| error.catalog_context("package-source"))?;
        let package_routines = read_package_routines(connection, scope, deadline)
            .map_err(|error| error.catalog_context("package-routine"))?;
        let package_arguments = read_package_arguments(connection, scope, deadline)
            .map_err(|error| error.catalog_context("package-argument"))?;
        let mut constraints = read_constraints(connection, scope, &recycle, deadline)
            .map_err(|error| error.catalog_context("constraint"))?;
        attach_constraint_columns(connection, scope, &mut constraints, deadline)
            .map_err(|error| error.catalog_context("constraint-column"))?;
        let mut indexes = read_indexes(connection, scope, &recycle, deadline)
            .map_err(|error| error.catalog_context("index"))?;
        attach_index_columns(connection, scope, &mut indexes, deadline)
            .map_err(|error| error.catalog_context("index-column"))?;
        attach_index_expressions(connection, scope, &mut indexes, deadline)
            .map_err(|error| error.catalog_context("index-expression"))?;
        let partitioned_tables = read_partitioned_tables(connection, scope, deadline)
            .map_err(|error| error.catalog_context("partitioned-table"))?;
        let table_partitions = read_table_partitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("table-partition"))?;
        let table_subpartitions = read_table_subpartitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("table-subpartition"))?;
        let partitioned_indexes = read_partitioned_indexes(connection, scope, deadline)
            .map_err(|error| error.catalog_context("partitioned-index"))?;
        let index_partitions = read_index_partitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("index-partition"))?;
        let index_subpartitions = read_index_subpartitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("index-subpartition"))?;
        let partition_key_columns = read_partition_key_columns(connection, scope, deadline)
            .map_err(|error| error.catalog_context("partition-key-column"))?;
        let lobs =
            read_lobs(connection, scope, deadline).map_err(|error| error.catalog_context("lob"))?;
        let lob_partitions = read_lob_partitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("lob-partition"))?;
        let lob_subpartitions = read_lob_subpartitions(connection, scope, deadline)
            .map_err(|error| error.catalog_context("lob-subpartition"))?;
        let dependencies = read_dependencies(connection, scope, deadline)
            .map_err(|error| error.catalog_context("dependency"))?;
        if Instant::now() >= deadline {
            return Err(CatalogError::Timeout);
        }
        Ok(Self {
            inventory,
            tables,
            columns,
            sequences,
            identity_columns,
            views,
            view_columns,
            materialized_views,
            synonyms,
            user_types,
            type_attributes,
            collection_types,
            type_methods,
            type_method_parameters,
            triggers,
            routines,
            routine_arguments,
            packages,
            package_routines,
            package_arguments,
            constraints,
            indexes,
            partitioned_tables,
            table_partitions,
            table_subpartitions,
            partitioned_indexes,
            index_partitions,
            index_subpartitions,
            partition_key_columns,
            lobs,
            lob_partitions,
            lob_subpartitions,
            dependencies,
        })
    }
}

fn read_principals(
    connection: &Connection,
    mode: DictionaryScopeMode,
    owners: &[String],
    deadline: Instant,
) -> Result<Vec<RawPrincipal>, CatalogError> {
    prepare_call(connection, deadline)?;
    let mut principals = Vec::new();
    match mode {
        DictionaryScopeMode::User => {
            let rows = connection
                .query_as::<(String, i64, String, String, String, Option<String>)>(
                    "
                SELECT USERNAME,
                       USER_ID,
                       ACCOUNT_STATUS,
                       COMMON,
                       ORACLE_MAINTAINED,
                       DEFAULT_COLLATION
                FROM USER_USERS
                ",
                    &[],
                )?;
            for row in rows {
                let (name, user_id, account_status, common, maintained, collation) = row?;
                principals.push(RawPrincipal {
                    name,
                    user_id,
                    account_status,
                    common: common == "YES",
                    oracle_maintained: maintained == "Y",
                    default_collation: collation,
                });
            }
        }
        DictionaryScopeMode::Dba => {
            for owner in owners {
                prepare_call(connection, deadline)?;
                let rows = connection
                    .query_as::<(String, i64, String, String, String, Option<String>)>(
                        "
                    SELECT USERNAME,
                           USER_ID,
                           ACCOUNT_STATUS,
                           COMMON,
                           ORACLE_MAINTAINED,
                           DEFAULT_COLLATION
                    FROM DBA_USERS
                    WHERE USERNAME = :1
                    ",
                        &[owner],
                    )?;
                for row in rows {
                    let (name, user_id, account_status, common, maintained, collation) = row?;
                    principals.push(RawPrincipal {
                        name,
                        user_id,
                        account_status,
                        common: common == "YES",
                        oracle_maintained: maintained == "Y",
                        default_collation: collation,
                    });
                }
            }
        }
    }
    principals.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(principals)
}

fn reject_database_links(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<(), CatalogError> {
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => "SELECT :1, DB_LINK FROM USER_DB_LINKS ORDER BY DB_LINK",
            DictionaryScopeMode::Dba => {
                "SELECT OWNER, DB_LINK FROM DBA_DB_LINKS WHERE OWNER = :1 ORDER BY OWNER, DB_LINK"
            }
        };
        let mut rows = connection.query_as::<(String, String)>(sql, &[owner])?;
        if let Some(row) = rows.next() {
            let (link_owner, link_name) = row?;
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle schema {link_owner} contains unsupported database link '{link_name}'"
            )));
        }
    }
    Ok(())
}

fn read_recycle_bin(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<BTreeSet<(String, String)>, CatalogError> {
    let mut recycle = BTreeSet::new();
    match scope.mode {
        DictionaryScopeMode::User => {
            prepare_call(connection, deadline)?;
            let rows = connection.query_as::<String>(
                "SELECT OBJECT_NAME FROM USER_RECYCLEBIN ORDER BY OBJECT_NAME",
                &[],
            )?;
            for row in rows {
                recycle.insert((scope.owners[0].clone(), row?));
            }
        }
        DictionaryScopeMode::Dba => {
            for owner in &scope.owners {
                prepare_call(connection, deadline)?;
                let rows = connection.query_as::<(String, String)>(
                    "
                    SELECT OWNER, OBJECT_NAME
                    FROM DBA_RECYCLEBIN
                    WHERE OWNER = :1
                    ORDER BY OWNER, OBJECT_NAME
                    ",
                    &[owner],
                )?;
                for row in rows {
                    recycle.insert(row?);
                }
            }
        }
    }
    Ok(recycle)
}

fn read_inventory(
    connection: &Connection,
    scope: &DictionaryScope,
    recycle: &BTreeSet<(String, String)>,
    deadline: Instant,
) -> Result<Vec<RawInventoryObject>, CatalogError> {
    type InventoryTuple = (
        String,
        String,
        Option<String>,
        i64,
        Option<i64>,
        String,
        String,
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut inventory = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       OBJECT_NAME,
                       SUBOBJECT_NAME,
                       OBJECT_ID,
                       DATA_OBJECT_ID,
                       OBJECT_TYPE,
                       STATUS,
                       TEMPORARY,
                       GENERATED,
                       SECONDARY,
                       NAMESPACE,
                       EDITION_NAME,
                       EDITIONABLE,
                       DEFAULT_COLLATION
                FROM USER_OBJECTS
                WHERE ORACLE_MAINTAINED = 'N'
                ORDER BY OBJECT_TYPE, OBJECT_NAME, SUBOBJECT_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       OBJECT_NAME,
                       SUBOBJECT_NAME,
                       OBJECT_ID,
                       DATA_OBJECT_ID,
                       OBJECT_TYPE,
                       STATUS,
                       TEMPORARY,
                       GENERATED,
                       SECONDARY,
                       NAMESPACE,
                       EDITION_NAME,
                       EDITIONABLE,
                       DEFAULT_COLLATION
                FROM DBA_OBJECTS
                WHERE OWNER = :1
                  AND ORACLE_MAINTAINED = 'N'
                ORDER BY OBJECT_TYPE, OBJECT_NAME, SUBOBJECT_NAME
                "
            }
        };
        let rows = connection.query_as::<InventoryTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                subobject,
                object_id,
                data_object_id,
                object_type,
                status,
                temporary,
                generated,
                secondary,
                namespace,
                edition_name,
                editionable,
                default_collation,
            ) = row?;
            if recycle.contains(&(owner.clone(), name.clone())) {
                continue;
            }
            inventory.push(RawInventoryObject {
                owner,
                name,
                subobject,
                object_id,
                data_object_id,
                object_type,
                status,
                temporary: temporary == "Y",
                generated: generated == "Y",
                secondary: secondary == "Y",
                namespace,
                edition_name,
                editionable,
                default_collation,
            });
        }
    }
    inventory.sort_by(|left, right| {
        (&left.owner, &left.object_type, &left.name, &left.subobject).cmp(&(
            &right.owner,
            &right.object_type,
            &right.name,
            &right.subobject,
        ))
    });
    Ok(inventory)
}

fn read_tables(
    connection: &Connection,
    scope: &DictionaryScope,
    recycle: &BTreeSet<(String, String)>,
    deadline: Instant,
) -> Result<Vec<RawTable>, CatalogError> {
    type TableTuple = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        Option<String>,
        String,
    );
    let mut tables = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TABLE_NAME,
                       STATUS,
                       TEMPORARY,
                       PARTITIONED,
                       IOT_TYPE,
                       NESTED,
                       READ_ONLY,
                       HAS_IDENTITY,
                       DURATION,
                       EXTERNAL
                FROM USER_TABLES
                WHERE SECONDARY = 'N'
                  AND DROPPED = 'NO'
                ORDER BY TABLE_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TABLE_NAME,
                       STATUS,
                       TEMPORARY,
                       PARTITIONED,
                       IOT_TYPE,
                       NESTED,
                       READ_ONLY,
                       HAS_IDENTITY,
                       DURATION,
                       EXTERNAL
                FROM DBA_TABLES
                WHERE OWNER = :1
                  AND SECONDARY = 'N'
                  AND DROPPED = 'NO'
                ORDER BY OWNER, TABLE_NAME
                "
            }
        };
        let rows = connection.query_as::<TableTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                status,
                temporary,
                partitioned,
                iot_type,
                nested,
                read_only,
                has_identity,
                duration,
                external,
            ) = row?;
            if recycle.contains(&(owner.clone(), name.clone())) {
                continue;
            }
            tables.push(RawTable {
                owner,
                name,
                status,
                temporary: temporary == "Y",
                partitioned: partitioned == "YES",
                iot_type,
                nested: nested == "YES",
                read_only: read_only == "YES",
                has_identity: has_identity == "YES",
                duration,
                external: external == "YES",
            });
        }
    }
    tables.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(tables)
}

fn read_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    recycle: &BTreeSet<(String, String)>,
    deadline: Instant,
) -> Result<Vec<RawColumn>, CatalogError> {
    type ColumnTuple = (
        String,
        String,
        String,
        Option<i64>,
        i64,
        String,
        Option<String>,
        i64,
        Option<i64>,
        Option<i64>,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
    );
    let mut columns = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       c.TABLE_NAME,
                       c.COLUMN_NAME,
                       c.COLUMN_ID,
                       c.INTERNAL_COLUMN_ID,
                       c.DATA_TYPE,
                       c.DATA_TYPE_OWNER,
                       c.DATA_LENGTH,
                       c.DATA_PRECISION,
                       c.DATA_SCALE,
                       c.NULLABLE,
                       c.DATA_DEFAULT,
                       c.HIDDEN_COLUMN,
                       c.VIRTUAL_COLUMN,
                       c.USER_GENERATED,
                       c.DEFAULT_ON_NULL,
                       c.IDENTITY_COLUMN,
                       c.CHAR_LENGTH,
                       c.CHAR_USED,
                       c.COLLATION
                FROM USER_TAB_COLS c
                JOIN USER_TABLES t ON t.TABLE_NAME = c.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY c.TABLE_NAME, c.INTERNAL_COLUMN_ID
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT c.OWNER,
                       c.TABLE_NAME,
                       c.COLUMN_NAME,
                       c.COLUMN_ID,
                       c.INTERNAL_COLUMN_ID,
                       c.DATA_TYPE,
                       c.DATA_TYPE_OWNER,
                       c.DATA_LENGTH,
                       c.DATA_PRECISION,
                       c.DATA_SCALE,
                       c.NULLABLE,
                       c.DATA_DEFAULT,
                       c.HIDDEN_COLUMN,
                       c.VIRTUAL_COLUMN,
                       c.USER_GENERATED,
                       c.DEFAULT_ON_NULL,
                       c.IDENTITY_COLUMN,
                       c.CHAR_LENGTH,
                       c.CHAR_USED,
                       c.COLLATION
                FROM DBA_TAB_COLS c
                JOIN DBA_TABLES t
                  ON t.OWNER = c.OWNER
                 AND t.TABLE_NAME = c.TABLE_NAME
                WHERE c.OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY c.OWNER, c.TABLE_NAME, c.INTERNAL_COLUMN_ID
                "
            }
        };
        let rows = connection.query_as::<ColumnTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                table,
                name,
                column_id,
                internal_column_id,
                data_type,
                data_type_owner,
                data_length,
                data_precision,
                data_scale,
                nullable,
                default_value,
                hidden,
                virtual_column,
                user_generated,
                default_on_null,
                identity,
                char_length,
                char_used,
                collation,
            ) = row?;
            if recycle.contains(&(owner.clone(), table.clone())) {
                continue;
            }
            columns.push(RawColumn {
                owner,
                table,
                name,
                column_id,
                internal_column_id,
                data_type,
                data_type_owner,
                data_length,
                data_precision,
                data_scale,
                nullable: nullable == "Y",
                default_value: normalize_definition(default_value)?,
                hidden: hidden == "YES",
                virtual_column: virtual_column == "YES",
                user_generated: user_generated == "YES",
                default_on_null: default_on_null == "YES",
                identity: identity == "YES",
                char_length,
                char_used,
                collation,
            });
        }
    }
    columns.sort_by(|left, right| {
        (&left.owner, &left.table, left.internal_column_id).cmp(&(
            &right.owner,
            &right.table,
            right.internal_column_id,
        ))
    });
    Ok(columns)
}

fn read_sequences(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawSequence>, CatalogError> {
    type SequenceTuple = (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut sequences = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       SEQUENCE_NAME,
                       TO_CHAR(MIN_VALUE, 'TM9'),
                       TO_CHAR(MAX_VALUE, 'TM9'),
                       TO_CHAR(INCREMENT_BY, 'TM9'),
                       CYCLE_FLAG,
                       ORDER_FLAG,
                       TO_CHAR(CACHE_SIZE, 'TM9'),
                       SCALE_FLAG,
                       EXTEND_FLAG,
                       SHARDED_FLAG,
                       SESSION_FLAG,
                       KEEP_VALUE
                FROM USER_SEQUENCES
                ORDER BY SEQUENCE_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT SEQUENCE_OWNER,
                       SEQUENCE_NAME,
                       TO_CHAR(MIN_VALUE, 'TM9'),
                       TO_CHAR(MAX_VALUE, 'TM9'),
                       TO_CHAR(INCREMENT_BY, 'TM9'),
                       CYCLE_FLAG,
                       ORDER_FLAG,
                       TO_CHAR(CACHE_SIZE, 'TM9'),
                       SCALE_FLAG,
                       EXTEND_FLAG,
                       SHARDED_FLAG,
                       SESSION_FLAG,
                       KEEP_VALUE
                FROM DBA_SEQUENCES
                WHERE SEQUENCE_OWNER = :1
                ORDER BY SEQUENCE_OWNER, SEQUENCE_NAME
                "
            }
        };
        let rows = connection.query_as::<SequenceTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                min_value,
                max_value,
                increment_by,
                cycle,
                ordered,
                cache_size,
                scale,
                extend,
                sharded,
                session,
                keep_value,
            ) = row?;
            sequences.push(RawSequence {
                owner,
                name,
                min_value,
                max_value,
                increment_by,
                cycle,
                ordered,
                cache_size,
                scale,
                extend,
                sharded,
                session,
                keep_value,
            });
        }
    }
    sequences.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(sequences)
}

fn read_identity_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawIdentityColumn>, CatalogError> {
    let mut identities = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TABLE_NAME,
                       COLUMN_NAME,
                       GENERATION_TYPE,
                       SEQUENCE_NAME,
                       IDENTITY_OPTIONS
                FROM USER_TAB_IDENTITY_COLS
                ORDER BY TABLE_NAME, COLUMN_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TABLE_NAME,
                       COLUMN_NAME,
                       GENERATION_TYPE,
                       SEQUENCE_NAME,
                       IDENTITY_OPTIONS
                FROM DBA_TAB_IDENTITY_COLS
                WHERE OWNER = :1
                ORDER BY OWNER, TABLE_NAME, COLUMN_NAME
                "
            }
        };
        let rows = connection.query_as::<(
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        )>(sql, &[owner])?;
        for row in rows {
            let (owner, table, column, generation_type, sequence_name, options) = row?;
            identities.push(RawIdentityColumn {
                owner,
                table,
                column,
                generation_type,
                sequence_name,
                options: normalize_definition(options)?,
            });
        }
    }
    identities.sort_by(|left, right| {
        (&left.owner, &left.table, &left.column).cmp(&(&right.owner, &right.table, &right.column))
    });
    Ok(identities)
}

fn read_views(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawView>, CatalogError> {
    type ViewTuple = (
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut views = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       VIEW_NAME,
                       TEXT_LENGTH,
                       TEXT,
                       VIEW_TYPE_OWNER,
                       VIEW_TYPE,
                       SUPERVIEW_NAME,
                       EDITIONING_VIEW,
                       READ_ONLY,
                       CONTAINER_DATA,
                       BEQUEATH,
                       DEFAULT_COLLATION,
                       HAS_SENSITIVE_COLUMN,
                       ADMIT_NULL,
                       PDB_LOCAL_ONLY,
                       DUALITY_VIEW
                FROM USER_VIEWS
                ORDER BY VIEW_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       VIEW_NAME,
                       TEXT_LENGTH,
                       TEXT,
                       VIEW_TYPE_OWNER,
                       VIEW_TYPE,
                       SUPERVIEW_NAME,
                       EDITIONING_VIEW,
                       READ_ONLY,
                       CONTAINER_DATA,
                       BEQUEATH,
                       DEFAULT_COLLATION,
                       HAS_SENSITIVE_COLUMN,
                       ADMIT_NULL,
                       PDB_LOCAL_ONLY,
                       DUALITY_VIEW
                FROM DBA_VIEWS
                WHERE OWNER = :1
                ORDER BY OWNER, VIEW_NAME
                "
            }
        };
        let rows = connection.query_as::<ViewTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                text_length,
                definition,
                type_owner,
                view_type,
                superview,
                editioning,
                read_only,
                container_data,
                bequeath,
                default_collation,
                has_sensitive_column,
                admit_null,
                pdb_local_only,
                duality_view,
            ) = row?;
            if text_length.is_some_and(|length| length > MAX_DEFINITION_BYTES as i64) {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle view definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {owner}.{name}"
                )));
            }
            views.push(RawView {
                owner,
                name,
                text_length,
                definition: normalize_definition(definition)?,
                type_owner,
                view_type,
                superview,
                editioning,
                read_only,
                container_data,
                bequeath,
                default_collation,
                has_sensitive_column,
                admit_null,
                pdb_local_only,
                duality_view,
            });
        }
    }
    views.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(views)
}

fn read_materialized_views(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawMaterializedView>, CatalogError> {
    type MaterializedViewTuple = (
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut materialized_views = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let view = match scope.mode {
            DictionaryScopeMode::User => "USER_MVIEWS",
            DictionaryScopeMode::Dba => "DBA_MVIEWS",
        };
        let sql = format!(
            "
            SELECT OWNER,
                   MVIEW_NAME,
                   CONTAINER_NAME,
                   QUERY_LEN,
                   QUERY,
                   UPDATABLE,
                   MASTER_LINK,
                   REWRITE_ENABLED,
                   REWRITE_CAPABILITY,
                   REFRESH_MODE,
                   REFRESH_METHOD,
                   BUILD_MODE,
                   FAST_REFRESHABLE,
                   COMPILE_STATE,
                   USE_NO_INDEX,
                   SEGMENT_CREATED,
                   DEFAULT_COLLATION,
                   ON_QUERY_COMPUTATION,
                   AUTO,
                   CONCURRENT_REFRESH_ENABLED
            FROM {view}
            WHERE OWNER = :1
            ORDER BY OWNER, MVIEW_NAME
            "
        );
        let rows = connection.query_as::<MaterializedViewTuple>(&sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                container_name,
                query_length,
                definition,
                updatable,
                master_link,
                rewrite_enabled,
                rewrite_capability,
                refresh_mode,
                refresh_method,
                build_mode,
                fast_refreshable,
                compile_state,
                use_no_index,
                segment_created,
                default_collation,
                on_query_computation,
                automatic,
                concurrent_refresh,
            ) = row?;
            if query_length.is_some_and(|length| length > MAX_DEFINITION_BYTES as i64) {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle materialized-view definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {owner}.{name}"
                )));
            }
            materialized_views.push(RawMaterializedView {
                owner,
                name,
                container_name,
                query_length,
                definition: normalize_definition(definition)?,
                updatable,
                master_link,
                rewrite_enabled,
                rewrite_capability,
                refresh_mode,
                refresh_method,
                build_mode,
                fast_refreshable,
                compile_state,
                use_no_index,
                segment_created,
                default_collation,
                on_query_computation,
                automatic,
                concurrent_refresh,
            });
        }
    }
    materialized_views
        .sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(materialized_views)
}

fn read_synonyms(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawSynonym>, CatalogError> {
    let mut synonyms = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       SYNONYM_NAME,
                       TABLE_OWNER,
                       TABLE_NAME,
                       DB_LINK,
                       ORIGIN_CON_ID
                FROM USER_SYNONYMS
                ORDER BY SYNONYM_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       SYNONYM_NAME,
                       TABLE_OWNER,
                       TABLE_NAME,
                       DB_LINK,
                       ORIGIN_CON_ID
                FROM DBA_SYNONYMS
                WHERE OWNER = :1
                ORDER BY OWNER, SYNONYM_NAME
                "
            }
        };
        let rows = connection
            .query_as::<(String, String, String, String, Option<String>, i64)>(sql, &[owner])?;
        for row in rows {
            let (owner, name, target_owner, target_name, database_link, origin_container_id) = row?;
            synonyms.push(RawSynonym {
                owner,
                name,
                target_owner,
                target_name,
                database_link: normalize_optional_token(database_link),
                origin_container_id,
            });
        }
    }
    synonyms.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(synonyms)
}

fn read_user_types(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawUserType>, CatalogError> {
    type TypeTuple = (
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<String>,
    );
    let mut types = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       RAWTOHEX(TYPE_OID),
                       TYPECODE,
                       ATTRIBUTES,
                       METHODS,
                       PREDEFINED,
                       INCOMPLETE,
                       FINAL,
                       INSTANTIABLE,
                       PERSISTABLE,
                       SUPERTYPE_OWNER,
                       SUPERTYPE_NAME,
                       LOCAL_ATTRIBUTES,
                       LOCAL_METHODS,
                       RAWTOHEX(TYPEID)
                FROM USER_TYPES
                ORDER BY TYPE_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       RAWTOHEX(TYPE_OID),
                       TYPECODE,
                       ATTRIBUTES,
                       METHODS,
                       PREDEFINED,
                       INCOMPLETE,
                       FINAL,
                       INSTANTIABLE,
                       PERSISTABLE,
                       SUPERTYPE_OWNER,
                       SUPERTYPE_NAME,
                       LOCAL_ATTRIBUTES,
                       LOCAL_METHODS,
                       RAWTOHEX(TYPEID)
                FROM DBA_TYPES
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME
                "
            }
        };
        let rows = connection.query_as::<TypeTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                oid,
                typecode,
                attribute_count,
                method_count,
                predefined,
                incomplete,
                final_type,
                instantiable,
                persistable,
                supertype_owner,
                supertype_name,
                local_attribute_count,
                local_method_count,
                type_id,
            ) = row?;
            types.push(RawUserType {
                owner: owner.clone(),
                name: name.clone(),
                oid,
                typecode: required_catalog_token(
                    typecode,
                    &format!("typecode for {owner}.{name}"),
                )?,
                attribute_count: attribute_count.ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle type {owner}.{name} has no attribute count"
                    ))
                })?,
                method_count: method_count.ok_or_else(|| {
                    CatalogError::Mapping(format!("Oracle type {owner}.{name} has no method count"))
                })?,
                predefined: required_catalog_token(
                    predefined,
                    &format!("predefined flag for {owner}.{name}"),
                )?,
                incomplete: required_catalog_token(
                    incomplete,
                    &format!("incomplete flag for {owner}.{name}"),
                )?,
                final_type: required_catalog_token(
                    final_type,
                    &format!("final flag for {owner}.{name}"),
                )?,
                instantiable: required_catalog_token(
                    instantiable,
                    &format!("instantiable flag for {owner}.{name}"),
                )?,
                persistable: required_catalog_token(
                    persistable,
                    &format!("persistable flag for {owner}.{name}"),
                )?,
                supertype_owner: normalize_optional_token(supertype_owner),
                supertype_name: normalize_optional_token(supertype_name),
                local_attribute_count,
                local_method_count,
                type_id: normalize_optional_token(type_id),
                specification: None,
                body: None,
            });
        }
    }
    types.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(types)
}

fn attach_type_sources(
    connection: &Connection,
    scope: &DictionaryScope,
    types: &mut [RawUserType],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let positions = types
        .iter()
        .enumerate()
        .map(|(position, user_type)| ((user_type.owner.clone(), user_type.name.clone()), position))
        .collect::<BTreeMap<_, _>>();
    let mut sources = BTreeMap::<(usize, String), String>::new();
    let mut last_lines = BTreeMap::<(usize, String), i64>::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1, NAME, TYPE, LINE, TEXT
                FROM USER_SOURCE
                WHERE TYPE IN ('TYPE', 'TYPE BODY')
                ORDER BY NAME, TYPE, LINE
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER, NAME, TYPE, LINE, TEXT
                FROM DBA_SOURCE
                WHERE OWNER = :1
                  AND TYPE IN ('TYPE', 'TYPE BODY')
                ORDER BY OWNER, NAME, TYPE, LINE
                "
            }
        };
        let rows =
            connection.query_as::<(String, String, String, i64, Option<String>)>(sql, &[owner])?;
        for row in rows {
            let (source_owner, name, object_type, line, text) = row?;
            let position = positions
                .get(&(source_owner.clone(), name.clone()))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle type source {source_owner}.{name} ({object_type}) has no type header"
                    ))
                })?;
            let source_key = (position, object_type.clone());
            let expected_line = last_lines.get(&source_key).copied().unwrap_or(0) + 1;
            if line != expected_line {
                return Err(CatalogError::Mapping(format!(
                    "Oracle type source {source_owner}.{name} ({object_type}) expected line {expected_line}, found {line}"
                )));
            }
            last_lines.insert(source_key.clone(), line);
            let source = sources.entry(source_key).or_default();
            source.push_str(text.as_deref().unwrap_or_default());
            if source.len() > MAX_DEFINITION_BYTES {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle type definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {source_owner}.{name} ({object_type})"
                )));
            }
        }
    }
    for (position, user_type) in types.iter_mut().enumerate() {
        user_type.specification =
            normalize_definition(sources.remove(&(position, "TYPE".to_owned())))?;
        user_type.body = normalize_definition(sources.remove(&(position, "TYPE BODY".to_owned())))?;
        if user_type.specification.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle type {}.{} has no complete specification",
                user_type.owner, user_type.name
            )));
        }
    }
    Ok(())
}

fn read_type_attributes(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTypeAttribute>, CatalogError> {
    type AttributeTuple = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        i64,
        Option<String>,
        Option<String>,
    );
    let mut attributes = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       ATTR_NAME,
                       ATTR_TYPE_MOD,
                       ATTR_TYPE_OWNER,
                       ATTR_TYPE_NAME,
                       LENGTH,
                       PRECISION,
                       SCALE,
                       CHARACTER_SET_NAME,
                       ATTR_NO,
                       INHERITED,
                       CHAR_USED
                FROM USER_TYPE_ATTRS
                ORDER BY TYPE_NAME, ATTR_NO
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       ATTR_NAME,
                       ATTR_TYPE_MOD,
                       ATTR_TYPE_OWNER,
                       ATTR_TYPE_NAME,
                       LENGTH,
                       PRECISION,
                       SCALE,
                       CHARACTER_SET_NAME,
                       ATTR_NO,
                       INHERITED,
                       CHAR_USED
                FROM DBA_TYPE_ATTRS
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME, ATTR_NO
                "
            }
        };
        let rows = connection.query_as::<AttributeTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                type_name,
                name,
                type_modifier,
                data_type_owner,
                data_type_name,
                length,
                precision,
                scale,
                character_set,
                position,
                inherited,
                char_used,
            ) = row?;
            attributes.push(RawTypeAttribute {
                owner: owner.clone(),
                type_name: type_name.clone(),
                name: name.clone(),
                type_modifier: normalize_optional_token(type_modifier),
                data_type_owner: normalize_optional_token(data_type_owner),
                data_type_name: required_catalog_token(
                    data_type_name,
                    &format!("attribute type for {owner}.{type_name}.{name}"),
                )?,
                length,
                precision,
                scale,
                character_set: normalize_optional_token(character_set),
                position,
                inherited: required_catalog_token(
                    inherited,
                    &format!("inherited flag for {owner}.{type_name}.{name}"),
                )?,
                char_used: normalize_optional_token(char_used),
            });
        }
    }
    attributes.sort_by(|left, right| {
        (&left.owner, &left.type_name, left.position).cmp(&(
            &right.owner,
            &right.type_name,
            right.position,
        ))
    });
    Ok(attributes)
}

fn read_collection_types(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawCollectionType>, CatalogError> {
    type CollectionTuple = (
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut collections = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       COLL_TYPE,
                       UPPER_BOUND,
                       ELEM_TYPE_MOD,
                       ELEM_TYPE_OWNER,
                       ELEM_TYPE_NAME,
                       LENGTH,
                       PRECISION,
                       SCALE,
                       CHARACTER_SET_NAME,
                       ELEM_STORAGE,
                       NULLS_STORED,
                       CHAR_USED
                FROM USER_COLL_TYPES
                ORDER BY TYPE_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       COLL_TYPE,
                       UPPER_BOUND,
                       ELEM_TYPE_MOD,
                       ELEM_TYPE_OWNER,
                       ELEM_TYPE_NAME,
                       LENGTH,
                       PRECISION,
                       SCALE,
                       CHARACTER_SET_NAME,
                       ELEM_STORAGE,
                       NULLS_STORED,
                       CHAR_USED
                FROM DBA_COLL_TYPES
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME
                "
            }
        };
        let rows = connection.query_as::<CollectionTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                type_name,
                collection_type,
                upper_bound,
                element_type_modifier,
                element_type_owner,
                element_type_name,
                length,
                precision,
                scale,
                character_set,
                element_storage,
                nulls_stored,
                char_used,
            ) = row?;
            collections.push(RawCollectionType {
                owner: owner.clone(),
                type_name: type_name.clone(),
                collection_type: collection_type.trim().to_owned(),
                upper_bound,
                element_type_modifier: normalize_optional_token(element_type_modifier),
                element_type_owner: normalize_optional_token(element_type_owner),
                element_type_name: required_catalog_token(
                    element_type_name,
                    &format!("collection element type for {owner}.{type_name}"),
                )?,
                length,
                precision,
                scale,
                character_set: normalize_optional_token(character_set),
                element_storage: normalize_optional_token(element_storage),
                nulls_stored: normalize_optional_token(nulls_stored),
                char_used: normalize_optional_token(char_used),
            });
        }
    }
    collections.sort_by(|left, right| {
        (&left.owner, &left.type_name).cmp(&(&right.owner, &right.type_name))
    });
    Ok(collections)
}

fn read_type_methods(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTypeMethod>, CatalogError> {
    type MethodTuple = (
        String,
        String,
        String,
        i64,
        Option<String>,
        i64,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut methods = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       METHOD_TYPE,
                       PARAMETERS,
                       RESULTS,
                       FINAL,
                       INSTANTIABLE,
                       OVERRIDING,
                       INHERITED
                FROM USER_TYPE_METHODS
                ORDER BY TYPE_NAME, METHOD_NO
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       METHOD_TYPE,
                       PARAMETERS,
                       RESULTS,
                       FINAL,
                       INSTANTIABLE,
                       OVERRIDING,
                       INHERITED
                FROM DBA_TYPE_METHODS
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME, METHOD_NO
                "
            }
        };
        let rows = connection.query_as::<MethodTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                type_name,
                name,
                method_number,
                method_type,
                parameter_count,
                result_count,
                final_method,
                instantiable,
                overriding,
                inherited,
            ) = row?;
            methods.push(RawTypeMethod {
                owner: owner.clone(),
                type_name: type_name.clone(),
                name: name.clone(),
                method_number,
                method_type: required_catalog_token(
                    method_type,
                    &format!("method type for {owner}.{type_name}.{name}"),
                )?,
                parameter_count,
                result_count,
                final_method: required_catalog_token(
                    final_method,
                    &format!("final flag for {owner}.{type_name}.{name}"),
                )?,
                instantiable: required_catalog_token(
                    instantiable,
                    &format!("instantiable flag for {owner}.{type_name}.{name}"),
                )?,
                overriding: required_catalog_token(
                    overriding,
                    &format!("overriding flag for {owner}.{type_name}.{name}"),
                )?,
                inherited: required_catalog_token(
                    inherited,
                    &format!("inherited flag for {owner}.{type_name}.{name}"),
                )?,
            });
        }
    }
    methods.sort_by(|left, right| {
        (&left.owner, &left.type_name, left.method_number).cmp(&(
            &right.owner,
            &right.type_name,
            right.method_number,
        ))
    });
    Ok(methods)
}

fn read_type_method_parameters(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTypeMethodParameter>, CatalogError> {
    type ParameterTuple = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    type ResultTuple = (
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut parameters = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let parameter_sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       PARAM_NAME,
                       PARAM_NO,
                       PARAM_MODE,
                       PARAM_TYPE_MOD,
                       PARAM_TYPE_OWNER,
                       PARAM_TYPE_NAME,
                       CHARACTER_SET_NAME
                FROM USER_METHOD_PARAMS
                ORDER BY TYPE_NAME, METHOD_NO, PARAM_NO
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       PARAM_NAME,
                       PARAM_NO,
                       PARAM_MODE,
                       PARAM_TYPE_MOD,
                       PARAM_TYPE_OWNER,
                       PARAM_TYPE_NAME,
                       CHARACTER_SET_NAME
                FROM DBA_METHOD_PARAMS
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME, METHOD_NO, PARAM_NO
                "
            }
        };
        let rows = connection.query_as::<ParameterTuple>(parameter_sql, &[owner])?;
        for row in rows {
            let (
                owner,
                type_name,
                method_name,
                method_number,
                name,
                position,
                mode,
                type_modifier,
                data_type_owner,
                data_type_name,
                character_set,
            ) = row?;
            parameters.push(RawTypeMethodParameter {
                owner: owner.clone(),
                type_name: type_name.clone(),
                method_name: method_name.clone(),
                method_number,
                name,
                position,
                mode: required_catalog_token(
                    mode,
                    &format!("method parameter mode for {owner}.{type_name}.{method_name}"),
                )?,
                type_modifier: normalize_optional_token(type_modifier),
                data_type_owner: normalize_optional_token(data_type_owner),
                data_type_name: required_catalog_token(
                    data_type_name,
                    &format!("method parameter type for {owner}.{type_name}.{method_name}"),
                )?,
                character_set: normalize_optional_token(character_set),
                return_value: false,
            });
        }

        prepare_call(connection, deadline)?;
        let result_sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       RESULT_TYPE_MOD,
                       RESULT_TYPE_OWNER,
                       RESULT_TYPE_NAME,
                       CHARACTER_SET_NAME
                FROM USER_METHOD_RESULTS
                ORDER BY TYPE_NAME, METHOD_NO
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TYPE_NAME,
                       METHOD_NAME,
                       METHOD_NO,
                       RESULT_TYPE_MOD,
                       RESULT_TYPE_OWNER,
                       RESULT_TYPE_NAME,
                       CHARACTER_SET_NAME
                FROM DBA_METHOD_RESULTS
                WHERE OWNER = :1
                ORDER BY OWNER, TYPE_NAME, METHOD_NO
                "
            }
        };
        let rows = connection.query_as::<ResultTuple>(result_sql, &[owner])?;
        for row in rows {
            let (
                owner,
                type_name,
                method_name,
                method_number,
                type_modifier,
                data_type_owner,
                data_type_name,
                character_set,
            ) = row?;
            parameters.push(RawTypeMethodParameter {
                owner: owner.clone(),
                type_name: type_name.clone(),
                method_name: method_name.clone(),
                method_number,
                name: "RETURN".to_owned(),
                position: 0,
                mode: "OUT".to_owned(),
                type_modifier: normalize_optional_token(type_modifier),
                data_type_owner: normalize_optional_token(data_type_owner),
                data_type_name: required_catalog_token(
                    data_type_name,
                    &format!("method result type for {owner}.{type_name}.{method_name}"),
                )?,
                character_set: normalize_optional_token(character_set),
                return_value: true,
            });
        }
    }
    parameters.sort_by(|left, right| {
        (
            &left.owner,
            &left.type_name,
            left.method_number,
            left.position,
            &left.name,
        )
            .cmp(&(
                &right.owner,
                &right.type_name,
                right.method_number,
                right.position,
                &right.name,
            ))
    });
    Ok(parameters)
}

fn read_triggers(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTrigger>, CatalogError> {
    type TriggerTuple = (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut triggers = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       TRIGGER_NAME,
                       TRIGGER_TYPE,
                       TRIGGERING_EVENT,
                       TABLE_OWNER,
                       BASE_OBJECT_TYPE,
                       TABLE_NAME,
                       COLUMN_NAME,
                       REFERENCING_NAMES,
                       WHEN_CLAUSE,
                       STATUS,
                       DESCRIPTION,
                       ACTION_TYPE,
                       TRIGGER_BODY,
                       CROSSEDITION,
                       FIRE_ONCE,
                       APPLY_SERVER_ONLY
                FROM USER_TRIGGERS
                ORDER BY TRIGGER_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       TRIGGER_NAME,
                       TRIGGER_TYPE,
                       TRIGGERING_EVENT,
                       TABLE_OWNER,
                       BASE_OBJECT_TYPE,
                       TABLE_NAME,
                       COLUMN_NAME,
                       REFERENCING_NAMES,
                       WHEN_CLAUSE,
                       STATUS,
                       DESCRIPTION,
                       ACTION_TYPE,
                       TRIGGER_BODY,
                       CROSSEDITION,
                       FIRE_ONCE,
                       APPLY_SERVER_ONLY
                FROM DBA_TRIGGERS
                WHERE OWNER = :1
                ORDER BY OWNER, TRIGGER_NAME
                "
            }
        };
        let rows = connection.query_as::<TriggerTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                trigger_type,
                triggering_event,
                table_owner,
                base_object_type,
                table_name,
                column_name,
                referencing_names,
                when_clause,
                status,
                description,
                action_type,
                body,
                crossedition,
                fire_once,
                apply_server_only,
            ) = row?;
            triggers.push(RawTrigger {
                owner,
                name,
                trigger_type: trigger_type.trim().to_owned(),
                triggering_event: triggering_event.trim().to_owned(),
                table_owner: normalize_optional_token(table_owner),
                base_object_type: base_object_type.trim().to_owned(),
                table_name: normalize_optional_token(table_name),
                column_name: normalize_optional_token(column_name),
                referencing_names: normalize_optional_token(referencing_names),
                when_clause: normalize_optional_token(when_clause),
                status: status.trim().to_owned(),
                description: normalize_definition(description)?,
                action_type: action_type.trim().to_owned(),
                body: normalize_definition(body)?,
                crossedition: normalize_optional_token(crossedition),
                fire_once: normalize_optional_token(fire_once),
                apply_server_only: normalize_optional_token(apply_server_only),
            });
        }
    }
    triggers.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(triggers)
}

fn read_routines(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawRoutine>, CatalogError> {
    type RoutineTuple = (
        String,
        String,
        i64,
        i64,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
    );
    let mut routines = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       OBJECT_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       OBJECT_TYPE,
                       AGGREGATE,
                       PIPELINED,
                       PARALLEL,
                       INTERFACE,
                       DETERMINISTIC,
                       AUTHID,
                       POLYMORPHIC,
                       PROCEDURE_NAME
                FROM USER_PROCEDURES
                WHERE PROCEDURE_NAME IS NULL
                  AND OBJECT_TYPE IN ('FUNCTION', 'PROCEDURE')
                ORDER BY OBJECT_NAME, SUBPROGRAM_ID
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       OBJECT_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       OBJECT_TYPE,
                       AGGREGATE,
                       PIPELINED,
                       PARALLEL,
                       INTERFACE,
                       DETERMINISTIC,
                       AUTHID,
                       POLYMORPHIC,
                       PROCEDURE_NAME
                FROM DBA_PROCEDURES
                WHERE OWNER = :1
                  AND PROCEDURE_NAME IS NULL
                  AND OBJECT_TYPE IN ('FUNCTION', 'PROCEDURE')
                ORDER BY OWNER, OBJECT_NAME, SUBPROGRAM_ID
                "
            }
        };
        let rows = connection.query_as::<RoutineTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                object_id,
                subprogram_id,
                overload,
                object_type,
                aggregate,
                pipelined,
                parallel,
                interface,
                deterministic,
                authid,
                polymorphic,
                procedure_name,
            ) = row?;
            if procedure_name.is_some() {
                return Err(CatalogError::Mapping(format!(
                    "Oracle standalone routine {}.{} unexpectedly has PROCEDURE_NAME metadata",
                    owner, name
                )));
            }
            routines.push(RawRoutine {
                owner,
                name,
                object_id,
                subprogram_id,
                overload: normalize_optional_token(overload),
                object_type: object_type.trim().to_owned(),
                aggregate: aggregate.trim() == "YES",
                pipelined: pipelined.trim() == "YES",
                parallel: parallel.trim() == "YES",
                interface: interface.trim() == "YES",
                deterministic: deterministic.trim() == "YES",
                authid: authid.trim().to_owned(),
                polymorphic: match polymorphic.trim() {
                    "" | "NULL" => None,
                    value => Some(value.to_owned()),
                },
                definition: None,
            });
        }
    }
    routines.sort_by(|left, right| {
        (&left.owner, &left.name, left.subprogram_id).cmp(&(
            &right.owner,
            &right.name,
            right.subprogram_id,
        ))
    });
    Ok(routines)
}

fn attach_routine_sources(
    connection: &Connection,
    scope: &DictionaryScope,
    routines: &mut [RawRoutine],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let positions = routines
        .iter()
        .enumerate()
        .map(|(position, routine)| {
            (
                (
                    routine.owner.clone(),
                    routine.name.clone(),
                    routine.object_type.clone(),
                ),
                position,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut sources = BTreeMap::<usize, String>::new();
    let mut last_lines = BTreeMap::<usize, i64>::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1, NAME, TYPE, LINE, TEXT
                FROM USER_SOURCE
                WHERE TYPE IN ('FUNCTION', 'PROCEDURE')
                ORDER BY NAME, TYPE, LINE
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER, NAME, TYPE, LINE, TEXT
                FROM DBA_SOURCE
                WHERE OWNER = :1
                  AND TYPE IN ('FUNCTION', 'PROCEDURE')
                ORDER BY OWNER, NAME, TYPE, LINE
                "
            }
        };
        let rows =
            connection.query_as::<(String, String, String, i64, Option<String>)>(sql, &[owner])?;
        for row in rows {
            let (source_owner, name, object_type, line, text) = row?;
            let position = positions
                .get(&(source_owner.clone(), name.clone(), object_type.clone()))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle source {}.{} ({object_type}) has no routine header",
                        source_owner, name
                    ))
                })?;
            let expected_line = last_lines.get(&position).copied().unwrap_or(0) + 1;
            if line != expected_line {
                return Err(CatalogError::Mapping(format!(
                    "Oracle routine source {}.{} expected line {expected_line}, found {line}",
                    source_owner, name
                )));
            }
            last_lines.insert(position, line);
            let source = sources.entry(position).or_default();
            source.push_str(text.as_deref().unwrap_or_default());
            if source.len() > MAX_DEFINITION_BYTES {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle routine definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{}",
                    source_owner, name
                )));
            }
        }
    }
    for (position, routine) in routines.iter_mut().enumerate() {
        routine.definition = normalize_definition(sources.remove(&position))?;
        if routine.definition.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine {}.{} has no complete source",
                routine.owner, routine.name
            )));
        }
    }
    Ok(())
}

fn read_packages(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawPackage>, CatalogError> {
    let mut packages = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       OBJECT_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       OBJECT_TYPE,
                       AUTHID,
                       PROCEDURE_NAME
                FROM USER_PROCEDURES
                WHERE PROCEDURE_NAME IS NULL
                  AND OBJECT_TYPE = 'PACKAGE'
                ORDER BY OBJECT_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       OBJECT_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       OBJECT_TYPE,
                       AUTHID,
                       PROCEDURE_NAME
                FROM DBA_PROCEDURES
                WHERE OWNER = :1
                  AND PROCEDURE_NAME IS NULL
                  AND OBJECT_TYPE = 'PACKAGE'
                ORDER BY OWNER, OBJECT_NAME
                "
            }
        };
        let rows = connection.query_as::<(
            String,
            String,
            i64,
            i64,
            Option<String>,
            String,
            String,
            Option<String>,
        )>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                object_id,
                subprogram_id,
                overload,
                object_type,
                authid,
                procedure_name,
            ) = row?;
            if subprogram_id != 0
                || overload.is_some()
                || object_type.trim() != "PACKAGE"
                || procedure_name.is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "Oracle package header metadata is malformed for {}.{}",
                    owner, name
                )));
            }
            packages.push(RawPackage {
                owner,
                name,
                object_id,
                authid: authid.trim().to_owned(),
                specification: None,
                body: None,
            });
        }
    }
    packages.sort_by(|left, right| (&left.owner, &left.name).cmp(&(&right.owner, &right.name)));
    Ok(packages)
}

fn attach_package_sources(
    connection: &Connection,
    scope: &DictionaryScope,
    packages: &mut [RawPackage],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let positions = packages
        .iter()
        .enumerate()
        .map(|(position, package)| ((package.owner.clone(), package.name.clone()), position))
        .collect::<BTreeMap<_, _>>();
    let mut sources = BTreeMap::<(usize, String), String>::new();
    let mut last_lines = BTreeMap::<(usize, String), i64>::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1, NAME, TYPE, LINE, TEXT
                FROM USER_SOURCE
                WHERE TYPE IN ('PACKAGE', 'PACKAGE BODY')
                ORDER BY NAME, TYPE, LINE
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER, NAME, TYPE, LINE, TEXT
                FROM DBA_SOURCE
                WHERE OWNER = :1
                  AND TYPE IN ('PACKAGE', 'PACKAGE BODY')
                ORDER BY OWNER, NAME, TYPE, LINE
                "
            }
        };
        let rows =
            connection.query_as::<(String, String, String, i64, Option<String>)>(sql, &[owner])?;
        for row in rows {
            let (source_owner, name, object_type, line, text) = row?;
            let position = positions
                .get(&(source_owner.clone(), name.clone()))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle package source {}.{} ({object_type}) has no package header",
                        source_owner, name
                    ))
                })?;
            let source_key = (position, object_type.clone());
            let expected_line = last_lines.get(&source_key).copied().unwrap_or(0) + 1;
            if line != expected_line {
                return Err(CatalogError::Mapping(format!(
                    "Oracle package source {}.{} ({object_type}) expected line {expected_line}, found {line}",
                    source_owner, name
                )));
            }
            last_lines.insert(source_key.clone(), line);
            let source = sources.entry(source_key).or_default();
            source.push_str(text.as_deref().unwrap_or_default());
            if source.len() > MAX_DEFINITION_BYTES {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle package definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{} ({object_type})",
                    source_owner, name
                )));
            }
        }
    }
    for (position, package) in packages.iter_mut().enumerate() {
        package.specification =
            normalize_definition(sources.remove(&(position, "PACKAGE".to_owned())))?;
        package.body =
            normalize_definition(sources.remove(&(position, "PACKAGE BODY".to_owned())))?;
        if package.specification.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle package {}.{} has no complete specification",
                package.owner, package.name
            )));
        }
    }
    Ok(())
}

fn read_package_routines(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawPackageRoutine>, CatalogError> {
    type PackageRoutineTuple = (
        String,
        String,
        String,
        i64,
        i64,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let mut routines = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       OBJECT_NAME,
                       PROCEDURE_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       AGGREGATE,
                       PIPELINED,
                       PARALLEL,
                       INTERFACE,
                       DETERMINISTIC,
                       AUTHID,
                       POLYMORPHIC
                FROM USER_PROCEDURES
                WHERE PROCEDURE_NAME IS NOT NULL
                  AND OBJECT_TYPE = 'PACKAGE'
                ORDER BY OBJECT_NAME, SUBPROGRAM_ID
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       OBJECT_NAME,
                       PROCEDURE_NAME,
                       OBJECT_ID,
                       SUBPROGRAM_ID,
                       OVERLOAD,
                       AGGREGATE,
                       PIPELINED,
                       PARALLEL,
                       INTERFACE,
                       DETERMINISTIC,
                       AUTHID,
                       POLYMORPHIC
                FROM DBA_PROCEDURES
                WHERE OWNER = :1
                  AND PROCEDURE_NAME IS NOT NULL
                  AND OBJECT_TYPE = 'PACKAGE'
                ORDER BY OWNER, OBJECT_NAME, SUBPROGRAM_ID
                "
            }
        };
        let rows = connection.query_as::<PackageRoutineTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                package,
                name,
                object_id,
                subprogram_id,
                overload,
                aggregate,
                pipelined,
                parallel,
                interface,
                deterministic,
                authid,
                polymorphic,
            ) = row?;
            routines.push(RawPackageRoutine {
                owner,
                package,
                name,
                object_id,
                subprogram_id,
                overload: normalize_optional_token(overload),
                aggregate: aggregate.trim() == "YES",
                pipelined: pipelined.trim() == "YES",
                parallel: parallel.trim() == "YES",
                interface: interface.trim() == "YES",
                deterministic: deterministic.trim() == "YES",
                authid: authid.trim().to_owned(),
                polymorphic: match polymorphic.trim() {
                    "" | "NULL" => None,
                    value => Some(value.to_owned()),
                },
            });
        }
    }
    routines.sort_by(|left, right| {
        (&left.owner, &left.package, left.subprogram_id).cmp(&(
            &right.owner,
            &right.package,
            right.subprogram_id,
        ))
    });
    Ok(routines)
}

fn read_routine_arguments(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawRoutineArgument>, CatalogError> {
    read_arguments(connection, scope, deadline, false)
}

fn read_package_arguments(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawRoutineArgument>, CatalogError> {
    read_arguments(connection, scope, deadline, true)
}

fn read_arguments(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
    packaged: bool,
) -> Result<Vec<RawRoutineArgument>, CatalogError> {
    type ArgumentTuple = (
        String,
        String,
        Option<String>,
        Option<String>,
        i64,
        i64,
        i64,
        Option<String>,
        String,
        Option<i64>,
        Option<String>,
        String,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        i64,
        Option<String>,
    );
    let mut arguments = Vec::new();
    let package_predicate = if packaged { "IS NOT NULL" } else { "IS NULL" };
    let user_package_inventory_predicate = if packaged {
        "AND EXISTS (
                    SELECT 1
                    FROM USER_OBJECTS package_object
                    WHERE package_object.OBJECT_ID = USER_ARGUMENTS.OBJECT_ID
                      AND package_object.OBJECT_TYPE = 'PACKAGE'
                 )"
    } else {
        ""
    };
    let dba_package_inventory_predicate = if packaged {
        "AND EXISTS (
                    SELECT 1
                    FROM DBA_OBJECTS package_object
                    WHERE package_object.OWNER = DBA_ARGUMENTS.OWNER
                      AND package_object.OBJECT_ID = DBA_ARGUMENTS.OBJECT_ID
                      AND package_object.OBJECT_TYPE = 'PACKAGE'
                 )"
    } else {
        ""
    };
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                format!(
                    "
                SELECT :1,
                       OBJECT_NAME,
                       PACKAGE_NAME,
                       ARGUMENT_NAME,
                       POSITION,
                       SEQUENCE,
                       DATA_LEVEL,
                       DATA_TYPE,
                       DEFAULTED,
                       DEFAULT_LENGTH,
                       DEFAULT_VALUE,
                       IN_OUT,
                       DATA_LENGTH,
                       DATA_PRECISION,
                       DATA_SCALE,
                       TYPE_OWNER,
                       TYPE_NAME,
                       TYPE_SUBNAME,
                       PLS_TYPE,
                       CHAR_LENGTH,
                       CHAR_USED,
                       SUBPROGRAM_ID,
                       OVERLOAD
                FROM USER_ARGUMENTS
                WHERE PACKAGE_NAME {package_predicate}
                  {user_package_inventory_predicate}
                ORDER BY OBJECT_NAME, SUBPROGRAM_ID, SEQUENCE
                "
                )
            }
            DictionaryScopeMode::Dba => {
                format!(
                    "
                SELECT OWNER,
                       OBJECT_NAME,
                       PACKAGE_NAME,
                       ARGUMENT_NAME,
                       POSITION,
                       SEQUENCE,
                       DATA_LEVEL,
                       DATA_TYPE,
                       DEFAULTED,
                       DEFAULT_LENGTH,
                       DEFAULT_VALUE,
                       IN_OUT,
                       DATA_LENGTH,
                       DATA_PRECISION,
                       DATA_SCALE,
                       TYPE_OWNER,
                       TYPE_NAME,
                       TYPE_SUBNAME,
                       PLS_TYPE,
                       CHAR_LENGTH,
                       CHAR_USED,
                       SUBPROGRAM_ID,
                       OVERLOAD
                FROM DBA_ARGUMENTS
                WHERE OWNER = :1
                  AND PACKAGE_NAME {package_predicate}
                  {dba_package_inventory_predicate}
                ORDER BY OWNER, OBJECT_NAME, SUBPROGRAM_ID, SEQUENCE
                "
                )
            }
        };
        let rows = connection.query_as::<ArgumentTuple>(&sql, &[owner])?;
        for row in rows {
            let (
                owner,
                routine,
                package_name,
                name,
                position,
                sequence,
                data_level,
                data_type,
                defaulted,
                default_length,
                default_value,
                mode,
                data_length,
                data_precision,
                data_scale,
                type_owner,
                type_name,
                type_subname,
                pls_type,
                char_length,
                char_used,
                subprogram_id,
                overload,
            ) = row?;
            arguments.push(RawRoutineArgument {
                owner,
                routine,
                package_name: normalize_optional_token(package_name),
                name: normalize_optional_token(name),
                position,
                sequence,
                data_level,
                data_type: normalize_optional_token(data_type),
                defaulted: defaulted.trim() == "Y",
                default_length,
                default_value: normalize_definition(default_value)?,
                mode: mode.trim().to_owned(),
                data_length,
                data_precision,
                data_scale,
                type_owner: normalize_optional_token(type_owner),
                type_name: normalize_optional_token(type_name),
                type_subname: normalize_optional_token(type_subname),
                pls_type: normalize_optional_token(pls_type),
                char_length,
                char_used: normalize_optional_token(char_used),
                subprogram_id,
                overload: normalize_optional_token(overload),
            });
        }
    }
    arguments.sort_by(|left, right| {
        (
            &left.owner,
            &left.routine,
            left.subprogram_id,
            left.sequence,
        )
            .cmp(&(
                &right.owner,
                &right.routine,
                right.subprogram_id,
                right.sequence,
            ))
    });
    Ok(arguments)
}

fn read_view_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawColumn>, CatalogError> {
    type ColumnTuple = (
        String,
        String,
        String,
        Option<i64>,
        i64,
        String,
        Option<String>,
        i64,
        Option<i64>,
        Option<i64>,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
    );
    let mut columns = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       c.TABLE_NAME,
                       c.COLUMN_NAME,
                       c.COLUMN_ID,
                       c.INTERNAL_COLUMN_ID,
                       c.DATA_TYPE,
                       c.DATA_TYPE_OWNER,
                       c.DATA_LENGTH,
                       c.DATA_PRECISION,
                       c.DATA_SCALE,
                       c.NULLABLE,
                       c.DATA_DEFAULT,
                       c.HIDDEN_COLUMN,
                       c.VIRTUAL_COLUMN,
                       c.USER_GENERATED,
                       c.DEFAULT_ON_NULL,
                       c.IDENTITY_COLUMN,
                       c.CHAR_LENGTH,
                       c.CHAR_USED,
                       c.COLLATION
                FROM USER_TAB_COLS c
                JOIN USER_VIEWS v ON v.VIEW_NAME = c.TABLE_NAME
                ORDER BY c.TABLE_NAME, c.INTERNAL_COLUMN_ID
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT c.OWNER,
                       c.TABLE_NAME,
                       c.COLUMN_NAME,
                       c.COLUMN_ID,
                       c.INTERNAL_COLUMN_ID,
                       c.DATA_TYPE,
                       c.DATA_TYPE_OWNER,
                       c.DATA_LENGTH,
                       c.DATA_PRECISION,
                       c.DATA_SCALE,
                       c.NULLABLE,
                       c.DATA_DEFAULT,
                       c.HIDDEN_COLUMN,
                       c.VIRTUAL_COLUMN,
                       c.USER_GENERATED,
                       c.DEFAULT_ON_NULL,
                       c.IDENTITY_COLUMN,
                       c.CHAR_LENGTH,
                       c.CHAR_USED,
                       c.COLLATION
                FROM DBA_TAB_COLS c
                JOIN DBA_VIEWS v
                  ON v.OWNER = c.OWNER
                 AND v.VIEW_NAME = c.TABLE_NAME
                WHERE c.OWNER = :1
                ORDER BY c.OWNER, c.TABLE_NAME, c.INTERNAL_COLUMN_ID
                "
            }
        };
        let rows = connection.query_as::<ColumnTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                table,
                name,
                column_id,
                internal_column_id,
                data_type,
                data_type_owner,
                data_length,
                data_precision,
                data_scale,
                nullable,
                default_value,
                hidden,
                virtual_column,
                user_generated,
                default_on_null,
                identity,
                char_length,
                char_used,
                collation,
            ) = row?;
            columns.push(RawColumn {
                owner,
                table,
                name,
                column_id,
                internal_column_id,
                data_type,
                data_type_owner,
                data_length,
                data_precision,
                data_scale,
                nullable: nullable == "Y",
                default_value: normalize_definition(default_value)?,
                hidden: hidden == "YES",
                virtual_column: virtual_column == "YES",
                user_generated: user_generated == "YES",
                default_on_null: default_on_null == "YES",
                identity: identity == "YES",
                char_length,
                char_used,
                collation,
            });
        }
    }
    columns.sort_by(|left, right| {
        (&left.owner, &left.table, left.internal_column_id).cmp(&(
            &right.owner,
            &right.table,
            right.internal_column_id,
        ))
    });
    Ok(columns)
}

fn normalize_definition(value: Option<String>) -> Result<Option<String>, CatalogError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_owned();
    if normalized.len() > MAX_DEFINITION_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle metadata definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit"
        )));
    }
    Ok((!normalized.is_empty()).then_some(normalized))
}

fn normalize_optional_token(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required_catalog_token(value: Option<String>, subject: &str) -> Result<String, CatalogError> {
    normalize_optional_token(value)
        .ok_or_else(|| CatalogError::Mapping(format!("Oracle catalog is missing {subject}")))
}

fn ensure_yes_no(value: &str, subject: &str) -> Result<(), CatalogError> {
    if matches!(value, "YES" | "NO") {
        Ok(())
    } else {
        Err(CatalogError::Mapping(format!(
            "{subject} has unrecognized value '{value}'"
        )))
    }
}

fn ensure_user_type_reference(
    scope: &DictionaryScope,
    user_types: &BTreeMap<(String, String), &RawUserType>,
    owner: Option<&str>,
    name: &str,
    subject: &str,
) -> Result<(), CatalogError> {
    if name.trim().is_empty() {
        return Err(CatalogError::Mapping(format!(
            "{subject} has no data type name"
        )));
    }
    let Some(owner) = owner else {
        return Ok(());
    };
    ensure_reference_owner(scope, owner, subject)?;
    if user_types.contains_key(&(owner.to_owned(), name.to_owned())) {
        Ok(())
    } else {
        Err(CatalogError::Mapping(format!(
            "{subject} references missing type {owner}.{name}"
        )))
    }
}

fn reject_dynamic_plsql(kind: &str, name: &str, definition: &str) -> Result<(), CatalogError> {
    let words = oracle_plsql_words(definition)?;
    let execute_immediate = words
        .windows(2)
        .any(|words| words == ["EXECUTE", "IMMEDIATE"]);
    let dbms_sql = words.iter().any(|word| word == "DBMS_SQL");
    let execute_ddl = words
        .windows(2)
        .any(|words| words == ["DBMS_UTILITY", "EXEC_DDL_STATEMENT"]);
    let dynamic_open = words.iter().enumerate().any(|(index, word)| {
        if word != "OPEN" {
            return false;
        }
        let Some(for_offset) = words[index + 1..]
            .iter()
            .take(3)
            .position(|word| word == "FOR")
        else {
            return false;
        };
        !matches!(
            words.get(index + for_offset + 2).map(String::as_str),
            Some("SELECT" | "WITH")
        )
    });
    if execute_immediate || dbms_sql || execute_ddl || dynamic_open {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle {kind} {name} contains dynamic PL/SQL that prevents complete dependency proof"
        )));
    }
    Ok(())
}

fn oracle_plsql_words(source: &str) -> Result<Vec<String>, CatalogError> {
    let chars = source.chars().collect::<Vec<_>>();
    let mut words = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '-' && chars.get(index + 1) == Some(&'-') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                index += 1;
            }
            if index + 1 >= chars.len() {
                return Err(CatalogError::UnsupportedMetadata(
                    "Oracle PL/SQL contains an unterminated block comment".to_owned(),
                ));
            }
            index += 2;
            continue;
        }
        let q_delimiter_index =
            if matches!(chars[index], 'q' | 'Q') && chars.get(index + 1) == Some(&'\'') {
                Some(index + 2)
            } else if matches!(chars[index], 'n' | 'N')
                && matches!(chars.get(index + 1), Some('q' | 'Q'))
                && chars.get(index + 2) == Some(&'\'')
            {
                Some(index + 3)
            } else {
                None
            };
        if let Some(delimiter_index) = q_delimiter_index {
            let Some(opening) = chars.get(delimiter_index).copied() else {
                return Err(CatalogError::UnsupportedMetadata(
                    "Oracle PL/SQL contains an incomplete alternative-quoted literal".to_owned(),
                ));
            };
            let closing = match opening {
                '[' => ']',
                '{' => '}',
                '(' => ')',
                '<' => '>',
                other => other,
            };
            index = delimiter_index + 1;
            while index + 1 < chars.len() && !(chars[index] == closing && chars[index + 1] == '\'')
            {
                index += 1;
            }
            if index + 1 >= chars.len() {
                return Err(CatalogError::UnsupportedMetadata(
                    "Oracle PL/SQL contains an unterminated alternative-quoted literal".to_owned(),
                ));
            }
            index += 2;
            continue;
        }
        if chars[index] == '\'' {
            index += 1;
            loop {
                let Some(character) = chars.get(index) else {
                    return Err(CatalogError::UnsupportedMetadata(
                        "Oracle PL/SQL contains an unterminated string literal".to_owned(),
                    ));
                };
                if *character != '\'' {
                    index += 1;
                    continue;
                }
                if chars.get(index + 1) == Some(&'\'') {
                    index += 2;
                    continue;
                }
                index += 1;
                break;
            }
            continue;
        }
        if chars[index] == '"' {
            index += 1;
            loop {
                let Some(character) = chars.get(index) else {
                    return Err(CatalogError::UnsupportedMetadata(
                        "Oracle PL/SQL contains an unterminated quoted identifier".to_owned(),
                    ));
                };
                if *character != '"' {
                    index += 1;
                    continue;
                }
                if chars.get(index + 1) == Some(&'"') {
                    index += 2;
                    continue;
                }
                index += 1;
                break;
            }
            continue;
        }
        if chars[index].is_ascii_alphabetic() || matches!(chars[index], '_' | '$' | '#') {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || matches!(chars[index], '_' | '$' | '#'))
            {
                index += 1;
            }
            words.push(
                chars[start..index]
                    .iter()
                    .collect::<String>()
                    .to_uppercase(),
            );
            continue;
        }
        index += 1;
    }
    Ok(words)
}

fn oracle_trigger_timing(trigger_type: &str) -> Result<String, CatalogError> {
    for timing in ["INSTEAD OF", "BEFORE", "AFTER", "COMPOUND"] {
        if trigger_type.starts_with(timing) {
            return Ok(timing.to_owned());
        }
    }
    Err(CatalogError::UnsupportedMetadata(format!(
        "Oracle trigger type '{trigger_type}' has no covered timing"
    )))
}

fn oracle_trigger_events(triggering_event: &str) -> Result<Vec<String>, CatalogError> {
    let events = triggering_event
        .split(" OR ")
        .map(str::trim)
        .filter(|event| !event.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if events.is_empty() {
        Err(CatalogError::Mapping(
            "Oracle trigger has no triggering events".to_owned(),
        ))
    } else {
        Ok(events)
    }
}

fn read_constraints(
    connection: &Connection,
    scope: &DictionaryScope,
    recycle: &BTreeSet<(String, String)>,
    deadline: Instant,
) -> Result<Vec<RawConstraint>, CatalogError> {
    type ConstraintTuple = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut constraints = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       c.TABLE_NAME,
                       c.CONSTRAINT_NAME,
                       c.CONSTRAINT_TYPE,
                       c.SEARCH_CONDITION,
                       c.R_OWNER,
                       c.R_CONSTRAINT_NAME,
                       c.DELETE_RULE,
                       c.STATUS,
                       c.DEFERRABLE,
                       c.DEFERRED,
                       c.VALIDATED,
                       c.GENERATED,
                       c.INDEX_OWNER,
                       c.INDEX_NAME,
                       c.INVALID,
                       c.VIEW_RELATED
                FROM USER_CONSTRAINTS c
                JOIN USER_TABLES t ON t.TABLE_NAME = c.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY c.TABLE_NAME, c.CONSTRAINT_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT c.OWNER,
                       c.TABLE_NAME,
                       c.CONSTRAINT_NAME,
                       c.CONSTRAINT_TYPE,
                       c.SEARCH_CONDITION,
                       c.R_OWNER,
                       c.R_CONSTRAINT_NAME,
                       c.DELETE_RULE,
                       c.STATUS,
                       c.DEFERRABLE,
                       c.DEFERRED,
                       c.VALIDATED,
                       c.GENERATED,
                       c.INDEX_OWNER,
                       c.INDEX_NAME,
                       c.INVALID,
                       c.VIEW_RELATED
                FROM DBA_CONSTRAINTS c
                JOIN DBA_TABLES t
                  ON t.OWNER = c.OWNER
                 AND t.TABLE_NAME = c.TABLE_NAME
                WHERE c.OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY c.OWNER, c.TABLE_NAME, c.CONSTRAINT_NAME
                "
            }
        };
        let rows = connection.query_as::<ConstraintTuple>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                table,
                name,
                constraint_type,
                search_condition,
                referenced_owner,
                referenced_constraint,
                delete_rule,
                status,
                deferrable,
                deferred,
                validated,
                generated,
                index_owner,
                index_name,
                invalid,
                view_related,
            ) = row?;
            if recycle.contains(&(owner.clone(), table.clone())) {
                continue;
            }
            constraints.push(RawConstraint {
                owner,
                table,
                name,
                constraint_type,
                search_condition: normalize_definition(search_condition)?,
                referenced_owner,
                referenced_constraint,
                delete_rule,
                status,
                deferrable,
                deferred,
                validated,
                generated,
                index_owner,
                index_name,
                invalid,
                view_related,
                columns: Vec::new(),
            });
        }
    }
    constraints.sort_by(|left, right| {
        (&left.owner, &left.table, &left.name).cmp(&(&right.owner, &right.table, &right.name))
    });
    Ok(constraints)
}

fn attach_constraint_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    constraints: &mut [RawConstraint],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let mut positions = BTreeMap::new();
    for (position, constraint) in constraints.iter().enumerate() {
        let identity = (constraint.owner.clone(), constraint.name.clone());
        if positions.insert(identity.clone(), position).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle constraint identity {}.{}",
                identity.0, identity.1
            )));
        }
    }

    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       cc.CONSTRAINT_NAME,
                       cc.TABLE_NAME,
                       cc.COLUMN_NAME,
                       cc.POSITION
                FROM USER_CONS_COLUMNS cc
                JOIN USER_CONSTRAINTS c
                  ON c.CONSTRAINT_NAME = cc.CONSTRAINT_NAME
                 AND c.TABLE_NAME = cc.TABLE_NAME
                JOIN USER_TABLES t ON t.TABLE_NAME = cc.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY cc.TABLE_NAME, cc.CONSTRAINT_NAME, cc.POSITION
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT cc.OWNER,
                       cc.CONSTRAINT_NAME,
                       cc.TABLE_NAME,
                       cc.COLUMN_NAME,
                       cc.POSITION
                FROM DBA_CONS_COLUMNS cc
                JOIN DBA_CONSTRAINTS c
                  ON c.OWNER = cc.OWNER
                 AND c.CONSTRAINT_NAME = cc.CONSTRAINT_NAME
                 AND c.TABLE_NAME = cc.TABLE_NAME
                JOIN DBA_TABLES t
                  ON t.OWNER = cc.OWNER
                 AND t.TABLE_NAME = cc.TABLE_NAME
                WHERE cc.OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                ORDER BY cc.OWNER, cc.TABLE_NAME, cc.CONSTRAINT_NAME, cc.POSITION
                "
            }
        };
        let rows =
            connection.query_as::<(String, String, String, String, Option<i64>)>(sql, &[owner])?;
        for row in rows {
            let (column_owner, constraint_name, table_name, column_name, position) = row?;
            let index = positions
                .get(&(column_owner.clone(), constraint_name.clone()))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle constraint column references missing header {}.{}",
                        column_owner, constraint_name
                    ))
                })?;
            if constraints[index].table != table_name {
                return Err(CatalogError::Mapping(format!(
                    "Oracle constraint column table mismatch for {}.{}",
                    column_owner, constraint_name
                )));
            }
            constraints[index].columns.push(RawConstraintColumn {
                name: column_name,
                position,
            });
        }
    }
    for constraint in constraints {
        constraint.columns.sort_by(|left, right| {
            left.position
                .cmp(&right.position)
                .then_with(|| left.name.cmp(&right.name))
        });
    }
    Ok(())
}

fn read_indexes(
    connection: &Connection,
    scope: &DictionaryScope,
    recycle: &BTreeSet<(String, String)>,
    deadline: Instant,
) -> Result<Vec<RawIndex>, CatalogError> {
    type IndexTuple = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
    );
    let mut indexes = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       i.TABLE_OWNER,
                       i.TABLE_NAME,
                       i.INDEX_NAME,
                       i.INDEX_TYPE,
                       i.UNIQUENESS,
                       i.STATUS,
                       i.PARTITIONED,
                       i.TEMPORARY,
                       i.GENERATED,
                       i.SECONDARY,
                       i.VISIBILITY,
                       i.FUNCIDX_STATUS,
                       i.CONSTRAINT_INDEX
                FROM USER_INDEXES i
                JOIN USER_TABLES t ON t.TABLE_NAME = i.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY i.TABLE_NAME, i.INDEX_NAME
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT i.OWNER,
                       i.TABLE_OWNER,
                       i.TABLE_NAME,
                       i.INDEX_NAME,
                       i.INDEX_TYPE,
                       i.UNIQUENESS,
                       i.STATUS,
                       i.PARTITIONED,
                       i.TEMPORARY,
                       i.GENERATED,
                       i.SECONDARY,
                       i.VISIBILITY,
                       i.FUNCIDX_STATUS,
                       i.CONSTRAINT_INDEX
                FROM DBA_INDEXES i
                JOIN DBA_TABLES t
                  ON t.OWNER = i.TABLE_OWNER
                 AND t.TABLE_NAME = i.TABLE_NAME
                WHERE i.TABLE_OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY i.OWNER, i.TABLE_NAME, i.INDEX_NAME
                "
            }
        };
        let rows = connection.query_as::<IndexTuple>(sql, &[owner])?;
        for row in rows {
            let (
                index_owner,
                table_owner,
                table,
                name,
                index_type,
                uniqueness,
                status,
                partitioned,
                temporary,
                generated,
                secondary,
                visibility,
                function_status,
                constraint_index,
            ) = row?;
            if recycle.contains(&(table_owner.clone(), table.clone())) {
                continue;
            }
            indexes.push(RawIndex {
                owner: index_owner,
                table_owner,
                table,
                name,
                index_type,
                unique: uniqueness == "UNIQUE",
                status,
                partitioned: partitioned == "YES",
                temporary: temporary == "Y",
                generated: generated == "Y",
                secondary: secondary == "Y",
                visibility,
                function_status,
                constraint_index: constraint_index == "YES",
                columns: Vec::new(),
            });
        }
    }
    indexes.sort_by(|left, right| {
        (&left.owner, &left.table_owner, &left.table, &left.name).cmp(&(
            &right.owner,
            &right.table_owner,
            &right.table,
            &right.name,
        ))
    });
    Ok(indexes)
}

fn attach_index_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    indexes: &mut [RawIndex],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let mut positions = BTreeMap::new();
    for (position, index) in indexes.iter().enumerate() {
        let identity = (index.owner.clone(), index.name.clone());
        if positions.insert(identity.clone(), position).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle index identity {}.{}",
                identity.0, identity.1
            )));
        }
    }

    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       ic.INDEX_NAME,
                       :1,
                       ic.TABLE_NAME,
                       ic.COLUMN_NAME,
                       ic.COLUMN_POSITION,
                       ic.DESCEND
                FROM USER_IND_COLUMNS ic
                JOIN USER_INDEXES i
                  ON i.INDEX_NAME = ic.INDEX_NAME
                 AND i.TABLE_NAME = ic.TABLE_NAME
                JOIN USER_TABLES t ON t.TABLE_NAME = ic.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY ic.TABLE_NAME, ic.INDEX_NAME, ic.COLUMN_POSITION
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT ic.INDEX_OWNER,
                       ic.INDEX_NAME,
                       ic.TABLE_OWNER,
                       ic.TABLE_NAME,
                       ic.COLUMN_NAME,
                       ic.COLUMN_POSITION,
                       ic.DESCEND
                FROM DBA_IND_COLUMNS ic
                JOIN DBA_INDEXES i
                  ON i.OWNER = ic.INDEX_OWNER
                 AND i.INDEX_NAME = ic.INDEX_NAME
                 AND i.TABLE_OWNER = ic.TABLE_OWNER
                 AND i.TABLE_NAME = ic.TABLE_NAME
                JOIN DBA_TABLES t
                  ON t.OWNER = ic.TABLE_OWNER
                 AND t.TABLE_NAME = ic.TABLE_NAME
                WHERE ic.TABLE_OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY ic.INDEX_OWNER, ic.TABLE_NAME, ic.INDEX_NAME, ic.COLUMN_POSITION
                "
            }
        };
        let rows = connection
            .query_as::<(String, String, String, String, String, i64, String)>(sql, &[owner])?;
        for row in rows {
            let (index_owner, index_name, table_owner, table_name, column_name, position, descend) =
                row?;
            let index = positions
                .get(&(index_owner.clone(), index_name.clone()))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle index column references missing header {}.{}",
                        index_owner, index_name
                    ))
                })?;
            if indexes[index].table_owner != table_owner || indexes[index].table != table_name {
                return Err(CatalogError::Mapping(format!(
                    "Oracle index column table mismatch for {}.{}",
                    index_owner, index_name
                )));
            }
            indexes[index].columns.push(RawIndexColumn {
                name: column_name,
                position,
                descending: descend == "DESC",
                expression: None,
            });
        }
    }
    for index in indexes {
        index.columns.sort_by_key(|column| column.position);
    }
    Ok(())
}

fn attach_index_expressions(
    connection: &Connection,
    scope: &DictionaryScope,
    indexes: &mut [RawIndex],
    deadline: Instant,
) -> Result<(), CatalogError> {
    let mut positions = BTreeMap::new();
    for (index_position, index) in indexes.iter().enumerate() {
        for (column_position, column) in index.columns.iter().enumerate() {
            let identity = (index.owner.clone(), index.name.clone(), column.position);
            if positions
                .insert(identity.clone(), (index_position, column_position))
                .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "duplicate Oracle index-expression position {} for {}.{}",
                    identity.2, identity.0, identity.1
                )));
            }
        }
    }

    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       e.INDEX_NAME,
                       :1,
                       e.TABLE_NAME,
                       e.COLUMN_EXPRESSION,
                       e.COLUMN_POSITION
                FROM USER_IND_EXPRESSIONS e
                JOIN USER_INDEXES i
                  ON i.INDEX_NAME = e.INDEX_NAME
                 AND i.TABLE_NAME = e.TABLE_NAME
                JOIN USER_TABLES t ON t.TABLE_NAME = e.TABLE_NAME
                WHERE t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY e.TABLE_NAME, e.INDEX_NAME, e.COLUMN_POSITION
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT e.INDEX_OWNER,
                       e.INDEX_NAME,
                       e.TABLE_OWNER,
                       e.TABLE_NAME,
                       e.COLUMN_EXPRESSION,
                       e.COLUMN_POSITION
                FROM DBA_IND_EXPRESSIONS e
                JOIN DBA_INDEXES i
                  ON i.OWNER = e.INDEX_OWNER
                 AND i.INDEX_NAME = e.INDEX_NAME
                 AND i.TABLE_OWNER = e.TABLE_OWNER
                 AND i.TABLE_NAME = e.TABLE_NAME
                JOIN DBA_TABLES t
                  ON t.OWNER = e.TABLE_OWNER
                 AND t.TABLE_NAME = e.TABLE_NAME
                WHERE e.TABLE_OWNER = :1
                  AND t.SECONDARY = 'N'
                  AND t.DROPPED = 'NO'
                  AND i.INDEX_TYPE <> 'LOB'
                ORDER BY e.INDEX_OWNER, e.TABLE_NAME, e.INDEX_NAME, e.COLUMN_POSITION
                "
            }
        };
        let rows = connection
            .query_as::<(String, String, String, String, Option<String>, i64)>(sql, &[owner])?;
        for row in rows {
            let (index_owner, index_name, table_owner, table_name, expression, position) = row?;
            let (index_position, column_position) = positions
                .get(&(index_owner.clone(), index_name.clone(), position))
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle index expression references missing key position {position} for {index_owner}.{index_name}"
                    ))
                })?;
            let index = &mut indexes[index_position];
            if index.table_owner != table_owner || index.table != table_name {
                return Err(CatalogError::Mapping(format!(
                    "Oracle index expression table mismatch for {index_owner}.{index_name}"
                )));
            }
            let expression = normalize_definition(expression)?.ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle index expression is empty for {index_owner}.{index_name} position {position}"
                ))
            })?;
            let column = &mut index.columns[column_position];
            if column.expression.replace(expression).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate Oracle index expression for {index_owner}.{index_name} position {position}"
                )));
            }
        }
    }
    Ok(())
}

fn read_partitioned_tables(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawPartitionedTable>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut tables = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_PART_TABLES", ":1", ""),
            DictionaryScopeMode::Dba => ("DBA_PART_TABLES", "OWNER", "WHERE OWNER = :1"),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   PARTITIONING_TYPE,
                   SUBPARTITIONING_TYPE,
                   PARTITION_COUNT,
                   DEF_SUBPARTITION_COUNT,
                   PARTITIONING_KEY_COUNT,
                   SUBPARTITIONING_KEY_COUNT,
                   STATUS,
                   DEF_TABLESPACE_NAME,
                   INTERVAL,
                   AUTOLIST,
                   INTERVAL_SUBPARTITION,
                   AUTOLIST_SUBPARTITION,
                   AUTO
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                partitioning_type,
                subpartitioning_type,
                partition_count,
                default_subpartition_count,
                partitioning_key_count,
                subpartitioning_key_count,
                status,
                default_tablespace,
                interval,
                autolist,
                interval_subpartition,
                autolist_subpartition,
                automatic,
            ) = row?;
            tables.push(RawPartitionedTable {
                owner,
                table,
                partitioning_type: partitioning_type.trim().to_owned(),
                subpartitioning_type: subpartitioning_type.trim().to_owned(),
                partition_count,
                default_subpartition_count,
                partitioning_key_count,
                subpartitioning_key_count,
                status: status.trim().to_owned(),
                default_tablespace: normalize_optional_token(default_tablespace),
                interval: normalize_definition(interval)?,
                autolist: normalize_optional_token(autolist),
                interval_subpartition: normalize_definition(interval_subpartition)?,
                autolist_subpartition: normalize_optional_token(autolist_subpartition),
                automatic: normalize_optional_token(automatic),
            });
        }
    }
    tables.sort_by(|left, right| (&left.owner, &left.table).cmp(&(&right.owner, &right.table)));
    Ok(tables)
}

fn read_table_partitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTablePartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        i64,
        Option<String>,
        i64,
        i64,
        Option<String>,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
    );
    let mut partitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_TAB_PARTITIONS", ":1", ""),
            DictionaryScopeMode::Dba => (
                "DBA_TAB_PARTITIONS",
                "TABLE_OWNER",
                "WHERE TABLE_OWNER = :1",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   COMPOSITE,
                   PARTITION_NAME,
                   SUBPARTITION_COUNT,
                   HIGH_VALUE_CLOB,
                   HIGH_VALUE_LENGTH,
                   PARTITION_POSITION,
                   TABLESPACE_NAME,
                   COMPRESSION,
                   COMPRESS_FOR,
                   INTERVAL,
                   SEGMENT_CREATED,
                   INDEXING,
                   READ_ONLY
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME, PARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                composite,
                name,
                subpartition_count,
                high_value,
                high_value_length,
                position,
                tablespace,
                compression,
                compress_for,
                interval,
                segment_created,
                indexing,
                read_only,
            ) = row?;
            let high_value = normalize_partition_high_value(
                &owner,
                &table,
                &name,
                high_value_length,
                high_value,
            )?;
            partitions.push(RawTablePartition {
                owner,
                table,
                composite: composite.trim().to_owned(),
                name,
                subpartition_count,
                high_value,
                high_value_length,
                position,
                tablespace: normalize_optional_token(tablespace),
                compression: compression.trim().to_owned(),
                compress_for: normalize_optional_token(compress_for),
                interval: interval.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
                indexing: indexing.trim().to_owned(),
                read_only: read_only.trim().to_owned(),
            });
        }
    }
    partitions.sort_by(|left, right| {
        (&left.owner, &left.table, left.position).cmp(&(&right.owner, &right.table, right.position))
    });
    Ok(partitions)
}

fn read_table_subpartitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawTableSubpartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        i64,
        i64,
        Option<String>,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
    );
    let mut subpartitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_TAB_SUBPARTITIONS", ":1", ""),
            DictionaryScopeMode::Dba => (
                "DBA_TAB_SUBPARTITIONS",
                "TABLE_OWNER",
                "WHERE TABLE_OWNER = :1",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   PARTITION_NAME,
                   SUBPARTITION_NAME,
                   HIGH_VALUE_CLOB,
                   HIGH_VALUE_LENGTH,
                   PARTITION_POSITION,
                   SUBPARTITION_POSITION,
                   TABLESPACE_NAME,
                   COMPRESSION,
                   COMPRESS_FOR,
                   INTERVAL,
                   SEGMENT_CREATED,
                   INDEXING,
                   READ_ONLY
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME, PARTITION_POSITION, SUBPARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                partition,
                name,
                high_value,
                high_value_length,
                partition_position,
                position,
                tablespace,
                compression,
                compress_for,
                interval,
                segment_created,
                indexing,
                read_only,
            ) = row?;
            let high_value = normalize_partition_high_value(
                &owner,
                &table,
                &name,
                high_value_length,
                high_value,
            )?;
            subpartitions.push(RawTableSubpartition {
                owner,
                table,
                partition,
                name,
                high_value,
                high_value_length,
                partition_position,
                position,
                tablespace: normalize_optional_token(tablespace),
                compression: compression.trim().to_owned(),
                compress_for: normalize_optional_token(compress_for),
                interval: interval.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
                indexing: indexing.trim().to_owned(),
                read_only: read_only.trim().to_owned(),
            });
        }
    }
    subpartitions.sort_by(|left, right| {
        (
            &left.owner,
            &left.table,
            left.partition_position,
            left.position,
        )
            .cmp(&(
                &right.owner,
                &right.table,
                right.partition_position,
                right.position,
            ))
    });
    Ok(subpartitions)
}

fn read_partitioned_indexes(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawPartitionedIndex>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut indexes = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => (
                "USER_PART_INDEXES",
                ":1",
                "WHERE INDEX_NAME IN (SELECT INDEX_NAME FROM USER_INDEXES WHERE INDEX_TYPE <> 'LOB')",
            ),
            DictionaryScopeMode::Dba => (
                "DBA_PART_INDEXES",
                "OWNER",
                "WHERE OWNER = :1 AND INDEX_NAME IN (SELECT INDEX_NAME FROM DBA_INDEXES WHERE OWNER = :1 AND INDEX_TYPE <> 'LOB')",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   INDEX_NAME,
                   TABLE_NAME,
                   PARTITIONING_TYPE,
                   SUBPARTITIONING_TYPE,
                   PARTITION_COUNT,
                   DEF_SUBPARTITION_COUNT,
                   PARTITIONING_KEY_COUNT,
                   SUBPARTITIONING_KEY_COUNT,
                   LOCALITY,
                   ALIGNMENT,
                   DEF_TABLESPACE_NAME,
                   INTERVAL,
                   AUTOLIST,
                   INTERVAL_SUBPARTITION,
                   AUTOLIST_SUBPARTITION
            FROM {view}
            {owner_filter}
            ORDER BY INDEX_NAME
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                index,
                table,
                partitioning_type,
                subpartitioning_type,
                partition_count,
                default_subpartition_count,
                partitioning_key_count,
                subpartitioning_key_count,
                locality,
                alignment,
                default_tablespace,
                interval,
                autolist,
                interval_subpartition,
                autolist_subpartition,
            ) = row?;
            indexes.push(RawPartitionedIndex {
                owner,
                index,
                table,
                partitioning_type: partitioning_type.trim().to_owned(),
                subpartitioning_type: subpartitioning_type.trim().to_owned(),
                partition_count,
                default_subpartition_count,
                partitioning_key_count,
                subpartitioning_key_count,
                locality: locality.trim().to_owned(),
                alignment: alignment.trim().to_owned(),
                default_tablespace: normalize_optional_token(default_tablespace),
                interval: normalize_definition(interval)?,
                autolist: normalize_optional_token(autolist),
                interval_subpartition: normalize_definition(interval_subpartition)?,
                autolist_subpartition: normalize_optional_token(autolist_subpartition),
            });
        }
    }
    indexes.sort_by(|left, right| (&left.owner, &left.index).cmp(&(&right.owner, &right.index)));
    Ok(indexes)
}

fn read_index_partitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawIndexPartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        i64,
        Option<String>,
        i64,
        i64,
        String,
        Option<String>,
        String,
        String,
        String,
    );
    let mut partitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => (
                "USER_IND_PARTITIONS",
                ":1",
                "WHERE INDEX_NAME IN (SELECT INDEX_NAME FROM USER_INDEXES WHERE INDEX_TYPE <> 'LOB')",
            ),
            DictionaryScopeMode::Dba => (
                "DBA_IND_PARTITIONS",
                "INDEX_OWNER",
                "WHERE INDEX_OWNER = :1 AND INDEX_NAME IN (SELECT INDEX_NAME FROM DBA_INDEXES WHERE OWNER = :1 AND INDEX_TYPE <> 'LOB')",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   INDEX_NAME,
                   COMPOSITE,
                   PARTITION_NAME,
                   SUBPARTITION_COUNT,
                   HIGH_VALUE_CLOB,
                   HIGH_VALUE_LENGTH,
                   PARTITION_POSITION,
                   STATUS,
                   TABLESPACE_NAME,
                   COMPRESSION,
                   INTERVAL,
                   SEGMENT_CREATED
            FROM {view}
            {owner_filter}
            ORDER BY INDEX_NAME, PARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                index,
                composite,
                name,
                subpartition_count,
                high_value,
                high_value_length,
                position,
                status,
                tablespace,
                compression,
                interval,
                segment_created,
            ) = row?;
            let high_value = normalize_partition_high_value(
                &owner,
                &index,
                &name,
                high_value_length,
                high_value,
            )?;
            partitions.push(RawIndexPartition {
                owner,
                index,
                composite: composite.trim().to_owned(),
                name,
                subpartition_count,
                high_value,
                high_value_length,
                position,
                status: status.trim().to_owned(),
                tablespace: normalize_optional_token(tablespace),
                compression: compression.trim().to_owned(),
                interval: interval.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
            });
        }
    }
    partitions.sort_by(|left, right| {
        (&left.owner, &left.index, left.position).cmp(&(&right.owner, &right.index, right.position))
    });
    Ok(partitions)
}

fn read_index_subpartitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawIndexSubpartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        i64,
        i64,
        String,
        Option<String>,
        String,
        String,
        String,
    );
    let mut subpartitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => (
                "USER_IND_SUBPARTITIONS",
                ":1",
                "WHERE INDEX_NAME IN (SELECT INDEX_NAME FROM USER_INDEXES WHERE INDEX_TYPE <> 'LOB')",
            ),
            DictionaryScopeMode::Dba => (
                "DBA_IND_SUBPARTITIONS",
                "INDEX_OWNER",
                "WHERE INDEX_OWNER = :1 AND INDEX_NAME IN (SELECT INDEX_NAME FROM DBA_INDEXES WHERE OWNER = :1 AND INDEX_TYPE <> 'LOB')",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   INDEX_NAME,
                   PARTITION_NAME,
                   SUBPARTITION_NAME,
                   HIGH_VALUE_CLOB,
                   HIGH_VALUE_LENGTH,
                   PARTITION_POSITION,
                   SUBPARTITION_POSITION,
                   STATUS,
                   TABLESPACE_NAME,
                   COMPRESSION,
                   INTERVAL,
                   SEGMENT_CREATED
            FROM {view}
            {owner_filter}
            ORDER BY INDEX_NAME, PARTITION_POSITION, SUBPARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                index,
                partition,
                name,
                high_value,
                high_value_length,
                partition_position,
                position,
                status,
                tablespace,
                compression,
                interval,
                segment_created,
            ) = row?;
            let high_value = normalize_partition_high_value(
                &owner,
                &index,
                &name,
                high_value_length,
                high_value,
            )?;
            subpartitions.push(RawIndexSubpartition {
                owner,
                index,
                partition,
                name,
                high_value,
                high_value_length,
                partition_position,
                position,
                status: status.trim().to_owned(),
                tablespace: normalize_optional_token(tablespace),
                compression: compression.trim().to_owned(),
                interval: interval.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
            });
        }
    }
    subpartitions.sort_by(|left, right| {
        (
            &left.owner,
            &left.index,
            left.partition_position,
            left.position,
        )
            .cmp(&(
                &right.owner,
                &right.index,
                right.partition_position,
                right.position,
            ))
    });
    Ok(subpartitions)
}

fn read_partition_key_columns(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawPartitionKeyColumn>, CatalogError> {
    let mut columns = Vec::new();
    for subpartition in [false, true] {
        for owner in &scope.owners {
            prepare_call(connection, deadline)?;
            let (view, owner_expression, owner_filter) = match (scope.mode, subpartition) {
                (DictionaryScopeMode::User, false) => (
                    "USER_PART_KEY_COLUMNS",
                    ":1",
                    "WHERE OBJECT_TYPE <> 'INDEX' OR NAME NOT IN (SELECT INDEX_NAME FROM USER_INDEXES WHERE INDEX_TYPE = 'LOB')",
                ),
                (DictionaryScopeMode::User, true) => (
                    "USER_SUBPART_KEY_COLUMNS",
                    ":1",
                    "WHERE OBJECT_TYPE <> 'INDEX' OR NAME NOT IN (SELECT INDEX_NAME FROM USER_INDEXES WHERE INDEX_TYPE = 'LOB')",
                ),
                (DictionaryScopeMode::Dba, false) => (
                    "DBA_PART_KEY_COLUMNS",
                    "OWNER",
                    "WHERE OWNER = :1 AND (OBJECT_TYPE <> 'INDEX' OR NAME NOT IN (SELECT INDEX_NAME FROM DBA_INDEXES WHERE OWNER = :1 AND INDEX_TYPE = 'LOB'))",
                ),
                (DictionaryScopeMode::Dba, true) => (
                    "DBA_SUBPART_KEY_COLUMNS",
                    "OWNER",
                    "WHERE OWNER = :1 AND (OBJECT_TYPE <> 'INDEX' OR NAME NOT IN (SELECT INDEX_NAME FROM DBA_INDEXES WHERE OWNER = :1 AND INDEX_TYPE = 'LOB'))",
                ),
            };
            let sql = format!(
                "
                SELECT {owner_expression},
                       NAME,
                       OBJECT_TYPE,
                       COLUMN_NAME,
                       COLUMN_POSITION,
                       COLLATED_COLUMN_ID
                FROM {view}
                {owner_filter}
                ORDER BY NAME, OBJECT_TYPE, COLUMN_POSITION
                "
            );
            let rows = connection
                .query_as::<(String, String, String, String, i64, Option<i64>)>(&sql, &[owner])?;
            for row in rows {
                let (owner, name, object_type, column, position, collated_column_id) = row?;
                columns.push(RawPartitionKeyColumn {
                    owner,
                    name,
                    object_type: object_type.trim().to_owned(),
                    column,
                    position,
                    collated_column_id,
                    subpartition,
                });
            }
        }
    }
    columns.sort_by(|left, right| {
        (
            &left.owner,
            &left.name,
            &left.object_type,
            left.subpartition,
            left.position,
        )
            .cmp(&(
                &right.owner,
                &right.name,
                &right.object_type,
                right.subpartition,
                right.position,
            ))
    });
    Ok(columns)
}

fn read_lobs(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawLob>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<i64>,
    );
    let mut lobs = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_LOBS", ":1", ""),
            DictionaryScopeMode::Dba => ("DBA_LOBS", "OWNER", "WHERE OWNER = :1"),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   COLUMN_NAME,
                   SEGMENT_NAME,
                   TABLESPACE_NAME,
                   INDEX_NAME,
                   CHUNK,
                   PCTVERSION,
                   RETENTION,
                   FREEPOOLS,
                   CACHE,
                   LOGGING,
                   ENCRYPT,
                   COMPRESSION,
                   DEDUPLICATION,
                   IN_ROW,
                   FORMAT,
                   PARTITIONED,
                   SECUREFILE,
                   SEGMENT_CREATED,
                   RETENTION_TYPE,
                   RETENTION_VALUE,
                   VALUE_BASED,
                   MAX_INLINE
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME, COLUMN_NAME
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                column,
                segment_name,
                tablespace,
                index_name,
                chunk,
                pctversion,
                retention,
                freepools,
                cache,
                logging,
                encrypt,
                compression,
                deduplication,
                in_row,
                format,
                partitioned,
                securefile,
                segment_created,
                retention_type,
                retention_value,
                value_based,
                max_inline,
            ) = row?;
            lobs.push(RawLob {
                owner,
                table,
                column,
                segment_name,
                tablespace: normalize_optional_token(tablespace),
                index_name,
                chunk,
                pctversion,
                retention,
                freepools,
                cache: cache.trim().to_owned(),
                logging: logging.trim().to_owned(),
                encrypt: encrypt.trim().to_owned(),
                compression: compression.trim().to_owned(),
                deduplication: deduplication.trim().to_owned(),
                in_row: in_row.trim().to_owned(),
                format: format.trim().to_owned(),
                partitioned: partitioned.trim().to_owned(),
                securefile: securefile.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
                retention_type: normalize_optional_token(retention_type),
                retention_value,
                value_based: normalize_optional_token(value_based),
                max_inline,
            });
        }
    }
    lobs.sort_by(|left, right| {
        (&left.owner, &left.table, &left.column).cmp(&(&right.owner, &right.table, &right.column))
    });
    Ok(lobs)
}

fn read_lob_partitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawLobPartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        Option<i64>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
    );
    let mut partitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_LOB_PARTITIONS", ":1", ""),
            DictionaryScopeMode::Dba => (
                "DBA_LOB_PARTITIONS",
                "TABLE_OWNER",
                "WHERE TABLE_OWNER = :1",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   COLUMN_NAME,
                   LOB_NAME,
                   PARTITION_NAME,
                   LOB_PARTITION_NAME,
                   LOB_INDPART_NAME,
                   PARTITION_POSITION,
                   COMPOSITE,
                   CHUNK,
                   PCTVERSION,
                   CACHE,
                   IN_ROW,
                   TABLESPACE_NAME,
                   RETENTION,
                   LOGGING,
                   ENCRYPT,
                   COMPRESSION,
                   DEDUPLICATION,
                   SECUREFILE,
                   SEGMENT_CREATED,
                   MAX_INLINE
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME, COLUMN_NAME, PARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                column,
                lob_name,
                table_partition,
                name,
                index_partition_name,
                position,
                composite,
                chunk,
                pctversion,
                cache,
                in_row,
                tablespace,
                retention,
                logging,
                encrypt,
                compression,
                deduplication,
                securefile,
                segment_created,
                max_inline,
            ) = row?;
            partitions.push(RawLobPartition {
                owner,
                table,
                column,
                lob_name,
                table_partition,
                name,
                index_partition_name,
                position,
                composite: composite.trim().to_owned(),
                chunk,
                pctversion,
                cache: cache.trim().to_owned(),
                in_row: in_row.trim().to_owned(),
                tablespace: normalize_optional_token(tablespace),
                retention: normalize_optional_token(retention),
                logging: logging.trim().to_owned(),
                encrypt: encrypt.trim().to_owned(),
                compression: compression.trim().to_owned(),
                deduplication: deduplication.trim().to_owned(),
                securefile: securefile.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
                max_inline,
            });
        }
    }
    partitions.sort_by(|left, right| {
        (&left.owner, &left.table, &left.column, left.position).cmp(&(
            &right.owner,
            &right.table,
            &right.column,
            right.position,
        ))
    });
    Ok(partitions)
}

fn read_lob_subpartitions(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawLobSubpartition>, CatalogError> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        Option<i64>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<i64>,
    );
    let mut subpartitions = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let (view, owner_expression, owner_filter) = match scope.mode {
            DictionaryScopeMode::User => ("USER_LOB_SUBPARTITIONS", ":1", ""),
            DictionaryScopeMode::Dba => (
                "DBA_LOB_SUBPARTITIONS",
                "TABLE_OWNER",
                "WHERE TABLE_OWNER = :1",
            ),
        };
        let sql = format!(
            "
            SELECT {owner_expression},
                   TABLE_NAME,
                   COLUMN_NAME,
                   LOB_NAME,
                   LOB_PARTITION_NAME,
                   SUBPARTITION_NAME,
                   LOB_SUBPARTITION_NAME,
                   LOB_INDSUBPART_NAME,
                   SUBPARTITION_POSITION,
                   CHUNK,
                   PCTVERSION,
                   CACHE,
                   IN_ROW,
                   TABLESPACE_NAME,
                   RETENTION,
                   LOGGING,
                   ENCRYPT,
                   COMPRESSION,
                   DEDUPLICATION,
                   SECUREFILE,
                   SEGMENT_CREATED,
                   MAX_INLINE
            FROM {view}
            {owner_filter}
            ORDER BY TABLE_NAME, COLUMN_NAME, LOB_PARTITION_NAME, SUBPARTITION_POSITION
            "
        );
        for row in connection.query_as::<Row>(&sql, &[owner])? {
            let (
                owner,
                table,
                column,
                lob_name,
                lob_partition_name,
                table_subpartition,
                name,
                index_subpartition_name,
                position,
                chunk,
                pctversion,
                cache,
                in_row,
                tablespace,
                retention,
                logging,
                encrypt,
                compression,
                deduplication,
                securefile,
                segment_created,
                max_inline,
            ) = row?;
            subpartitions.push(RawLobSubpartition {
                owner,
                table,
                column,
                lob_name,
                lob_partition_name,
                table_subpartition,
                name,
                index_subpartition_name,
                position,
                chunk,
                pctversion,
                cache: cache.trim().to_owned(),
                in_row: in_row.trim().to_owned(),
                tablespace: normalize_optional_token(tablespace),
                retention: normalize_optional_token(retention),
                logging: logging.trim().to_owned(),
                encrypt: encrypt.trim().to_owned(),
                compression: compression.trim().to_owned(),
                deduplication: deduplication.trim().to_owned(),
                securefile: securefile.trim().to_owned(),
                segment_created: segment_created.trim().to_owned(),
                max_inline,
            });
        }
    }
    subpartitions.sort_by(|left, right| {
        (
            &left.owner,
            &left.table,
            &left.column,
            &left.lob_partition_name,
            left.position,
        )
            .cmp(&(
                &right.owner,
                &right.table,
                &right.column,
                &right.lob_partition_name,
                right.position,
            ))
    });
    Ok(subpartitions)
}

fn normalize_partition_high_value(
    owner: &str,
    object: &str,
    partition: &str,
    length: i64,
    value: Option<String>,
) -> Result<Option<String>, CatalogError> {
    if length < 0 {
        return Err(CatalogError::Mapping(format!(
            "Oracle partition {owner}.{object}.{partition} has negative high-value length"
        )));
    }
    if length > MAX_DEFINITION_BYTES as i64 {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle partition boundary exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {owner}.{object}.{partition}"
        )));
    }
    normalize_definition(value)
}

fn read_dependencies(
    connection: &Connection,
    scope: &DictionaryScope,
    deadline: Instant,
) -> Result<Vec<RawDependency>, CatalogError> {
    let mut dependencies = Vec::new();
    for owner in &scope.owners {
        prepare_call(connection, deadline)?;
        let sql = match scope.mode {
            DictionaryScopeMode::User => {
                "
                SELECT :1,
                       D.NAME,
                       D.TYPE,
                       D.REFERENCED_OWNER,
                       D.REFERENCED_NAME,
                       D.REFERENCED_TYPE,
                       D.REFERENCED_LINK_NAME,
                       D.DEPENDENCY_TYPE,
                       U.ORACLE_MAINTAINED
                FROM USER_DEPENDENCIES D
                LEFT JOIN ALL_USERS U ON U.USERNAME = D.REFERENCED_OWNER
                ORDER BY D.NAME, D.TYPE, D.REFERENCED_OWNER, D.REFERENCED_NAME, D.REFERENCED_TYPE
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT D.OWNER,
                       D.NAME,
                       D.TYPE,
                       D.REFERENCED_OWNER,
                       D.REFERENCED_NAME,
                       D.REFERENCED_TYPE,
                       D.REFERENCED_LINK_NAME,
                       D.DEPENDENCY_TYPE,
                       U.ORACLE_MAINTAINED
                FROM DBA_DEPENDENCIES D
                LEFT JOIN DBA_USERS U ON U.USERNAME = D.REFERENCED_OWNER
                WHERE D.OWNER = :1
                ORDER BY D.OWNER, D.NAME, D.TYPE, D.REFERENCED_OWNER, D.REFERENCED_NAME, D.REFERENCED_TYPE
                "
            }
        };
        let rows = connection.query_as::<(
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        )>(sql, &[owner])?;
        for row in rows {
            let (
                owner,
                name,
                object_type,
                referenced_owner,
                referenced_name,
                referenced_type,
                referenced_link,
                dependency_type,
                referenced_owner_oracle_maintained,
            ) = row?;
            let referenced_owner_oracle_maintained = match referenced_owner_oracle_maintained
                .as_deref()
            {
                Some("Y") => true,
                Some("N") => false,
                value => {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle dependency target owner {referenced_owner} has unprovable ORACLE_MAINTAINED state '{}'",
                        value.unwrap_or("missing")
                    )));
                }
            };
            dependencies.push(RawDependency {
                owner,
                name,
                object_type,
                referenced_owner,
                referenced_name,
                referenced_type,
                referenced_link,
                dependency_type,
                referenced_owner_oracle_maintained,
            });
        }
    }
    dependencies.sort_by(|left, right| {
        (
            &left.owner,
            &left.name,
            &left.object_type,
            &left.referenced_owner,
            &left.referenced_name,
            &left.referenced_type,
        )
            .cmp(&(
                &right.owner,
                &right.name,
                &right.object_type,
                &right.referenced_owner,
                &right.referenced_name,
                &right.referenced_type,
            ))
    });
    dependencies.dedup();
    Ok(dependencies)
}

fn oracle_package_dependency_groups(
    dependencies: &[RawDependency],
) -> BTreeMap<CollapsedDependencyIdentity, CollapsedDependencyEvidence> {
    let mut groups = BTreeMap::<CollapsedDependencyIdentity, CollapsedDependencyEvidence>::new();
    for dependency in dependencies.iter().filter(|dependency| {
        matches!(dependency.object_type.as_str(), "PACKAGE" | "PACKAGE BODY")
            && !dependency.referenced_owner_oracle_maintained
            && !(dependency.object_type == "PACKAGE BODY"
                && dependency.referenced_type == "PACKAGE"
                && dependency.owner == dependency.referenced_owner
                && dependency.name == dependency.referenced_name)
    }) {
        let evidence = groups
            .entry((
                dependency.owner.clone(),
                dependency.name.clone(),
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
                dependency.referenced_type.clone(),
            ))
            .or_default();
        evidence
            .source_object_types
            .insert(dependency.object_type.clone());
        evidence
            .dependency_types
            .insert(dependency.dependency_type.clone());
    }
    groups
}

fn oracle_type_dependency_groups(
    dependencies: &[RawDependency],
) -> BTreeMap<CollapsedDependencyIdentity, CollapsedDependencyEvidence> {
    let mut groups = BTreeMap::<CollapsedDependencyIdentity, CollapsedDependencyEvidence>::new();
    for dependency in dependencies.iter().filter(|dependency| {
        matches!(dependency.object_type.as_str(), "TYPE" | "TYPE BODY")
            && !dependency.referenced_owner_oracle_maintained
            && !(dependency.object_type == "TYPE BODY"
                && dependency.referenced_type == "TYPE"
                && dependency.owner == dependency.referenced_owner
                && dependency.name == dependency.referenced_name)
    }) {
        let evidence = groups
            .entry((
                dependency.owner.clone(),
                dependency.name.clone(),
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
                dependency.referenced_type.clone(),
            ))
            .or_default();
        evidence
            .source_object_types
            .insert(dependency.object_type.clone());
        evidence
            .dependency_types
            .insert(dependency.dependency_type.clone());
    }
    groups
}

fn validate_raw_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
) -> Result<(), CatalogError> {
    let inventory_all = raw
        .inventory
        .iter()
        .filter(|object| !object.secondary)
        .collect::<Vec<_>>();
    let unsupported = inventory_all
        .iter()
        .filter(|object| {
            !matches!(
                object.object_type.as_str(),
                "TABLE"
                    | "INDEX"
                    | "SEQUENCE"
                    | "VIEW"
                    | "MATERIALIZED VIEW"
                    | "TRIGGER"
                    | "FUNCTION"
                    | "PROCEDURE"
                    | "PACKAGE"
                    | "PACKAGE BODY"
                    | "SYNONYM"
                    | "TYPE"
                    | "TYPE BODY"
                    | "TABLE PARTITION"
                    | "TABLE SUBPARTITION"
                    | "INDEX PARTITION"
                    | "INDEX SUBPARTITION"
                    | "LOB"
                    | "LOB PARTITION"
                    | "LOB SUBPARTITION"
            )
        })
        .take(8)
        .map(|object| format!("{}.{} ({})", object.owner, object.name, object.object_type))
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle schema contains object types not yet covered by the certified mapper: {}",
            unsupported.join(", ")
        )));
    }
    let inventory = inventory_all
        .iter()
        .copied()
        .filter(|object| object.subobject.is_none())
        .collect::<Vec<_>>();
    let mut inventory_ids = BTreeSet::new();
    let mut inventory_keys = BTreeSet::new();
    let mut inventory_subobject_keys = BTreeSet::new();
    for object in &inventory_all {
        ensure_owner(scope, &object.owner, "inventory object")?;
        if object.status != "VALID" {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle inventory object {}.{} ({}) has non-valid status '{}'",
                object.owner, object.name, object.object_type, object.status
            )));
        }
        if !inventory_ids.insert(object.object_id) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle object id {}",
                object.object_id
            )));
        }
        let partition_subobject = matches!(
            object.object_type.as_str(),
            "TABLE PARTITION"
                | "TABLE SUBPARTITION"
                | "INDEX PARTITION"
                | "INDEX SUBPARTITION"
                | "LOB PARTITION"
                | "LOB SUBPARTITION"
        );
        if partition_subobject != object.subobject.is_some() {
            return Err(CatalogError::Mapping(format!(
                "Oracle inventory subobject identity is inconsistent for {}.{} ({})",
                object.owner, object.name, object.object_type
            )));
        }
        match object.subobject.as_deref() {
            Some(subobject) => {
                let identity = (
                    object.owner.clone(),
                    object.object_type.clone(),
                    object.name.clone(),
                    subobject.to_owned(),
                );
                if !inventory_subobject_keys.insert(identity.clone()) {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate Oracle subobject inventory identity {}.{} ({}, {})",
                        identity.0, identity.2, identity.1, identity.3
                    )));
                }
            }
            None => {
                let identity = (
                    object.owner.clone(),
                    object.object_type.clone(),
                    object.name.clone(),
                );
                if !inventory_keys.insert(identity.clone()) {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate Oracle inventory identity {}.{} ({})",
                        identity.0, identity.2, identity.1
                    )));
                }
            }
        }
    }

    let mut tables = BTreeSet::new();
    for table in &raw.tables {
        ensure_owner(scope, &table.owner, "table")?;
        if !tables.insert((table.owner.clone(), table.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle table {}.{}",
                table.owner, table.name
            )));
        }
        if table.iot_type.is_some() || table.nested || table.external {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle table shape is not yet covered for {}.{} (partitioned={}, iot_type={}, nested={}, external={})",
                table.owner,
                table.name,
                table.partitioned,
                table.iot_type.as_deref().unwrap_or("none"),
                table.nested,
                table.external
            )));
        }
        if !inventory_keys.contains(&(table.owner.clone(), "TABLE".to_owned(), table.name.clone()))
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle table {}.{} is missing from the independent object inventory",
                table.owner, table.name
            )));
        }
    }
    let inventory_table_count = inventory
        .iter()
        .filter(|object| object.object_type == "TABLE")
        .count();
    if inventory_table_count != raw.tables.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle table inventory mismatch: USER/DBA_OBJECTS reports {inventory_table_count}, USER/DBA_TABLES reports {}",
            raw.tables.len()
        )));
    }

    let mut column_keys = BTreeSet::new();
    let mut column_ordinals = BTreeSet::new();
    for column in &raw.columns {
        ensure_owner(scope, &column.owner, "column")?;
        if !tables.contains(&(column.owner.clone(), column.table.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle column {}.{}.{} has no mapped table",
                column.owner, column.table, column.name
            )));
        }
        positive_u32(column.internal_column_id, "Oracle internal column ordinal")?;
        if !column_keys.insert((
            column.owner.clone(),
            column.table.clone(),
            column.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle column {}.{}.{}",
                column.owner, column.table, column.name
            )));
        }
        if !column_ordinals.insert((
            column.owner.clone(),
            column.table.clone(),
            column.internal_column_id,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle internal column ordinal {} for {}.{}",
                column.internal_column_id, column.owner, column.table
            )));
        }
    }

    let mut sequences = BTreeSet::new();
    for sequence in &raw.sequences {
        ensure_owner(scope, &sequence.owner, "sequence")?;
        if sequence.increment_by.trim().is_empty() || sequence.cache_size.trim().is_empty() {
            return Err(CatalogError::Mapping(format!(
                "Oracle sequence {}.{} has incomplete numeric metadata",
                sequence.owner, sequence.name
            )));
        }
        if !sequences.insert((sequence.owner.clone(), sequence.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle sequence {}.{}",
                sequence.owner, sequence.name
            )));
        }
        if !inventory_keys.contains(&(
            sequence.owner.clone(),
            "SEQUENCE".to_owned(),
            sequence.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle sequence {}.{} is missing from the independent object inventory",
                sequence.owner, sequence.name
            )));
        }
    }
    let inventory_sequence_count = inventory
        .iter()
        .filter(|object| object.object_type == "SEQUENCE")
        .count();
    if inventory_sequence_count != raw.sequences.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle sequence inventory mismatch: USER/DBA_OBJECTS reports {inventory_sequence_count}, USER/DBA_SEQUENCES reports {}",
            raw.sequences.len()
        )));
    }

    let identity_columns = raw
        .columns
        .iter()
        .filter(|column| column.identity)
        .map(|column| {
            (
                column.owner.clone(),
                column.table.clone(),
                column.name.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut identity_details = BTreeSet::new();
    for identity in &raw.identity_columns {
        ensure_owner(scope, &identity.owner, "identity column")?;
        let key = (
            identity.owner.clone(),
            identity.table.clone(),
            identity.column.clone(),
        );
        if !identity_details.insert(key.clone()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle identity metadata for {}.{}.{}",
                identity.owner, identity.table, identity.column
            )));
        }
        if !identity_columns.contains(&key) {
            return Err(CatalogError::Mapping(format!(
                "Oracle identity catalog references a non-identity column {}.{}.{}",
                identity.owner, identity.table, identity.column
            )));
        }
        if !sequences.contains(&(identity.owner.clone(), identity.sequence_name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle identity column {}.{}.{} references missing sequence {}.{}",
                identity.owner,
                identity.table,
                identity.column,
                identity.owner,
                identity.sequence_name
            )));
        }
    }
    if identity_columns != identity_details {
        return match identity_columns.difference(&identity_details).next() {
            Some(missing) => Err(CatalogError::Mapping(format!(
                "Oracle identity column {}.{}.{} is missing *_TAB_IDENTITY_COLS metadata",
                missing.0, missing.1, missing.2
            ))),
            None => Err(CatalogError::Mapping(
                "Oracle identity-column catalogs disagree".to_owned(),
            )),
        };
    }
    for table in &raw.tables {
        let discovered_identity = identity_columns
            .iter()
            .any(|(owner, name, _)| owner == &table.owner && name == &table.name);
        if table.has_identity != discovered_identity {
            return Err(CatalogError::Mapping(format!(
                "Oracle table identity flag mismatch for {}.{}",
                table.owner, table.name
            )));
        }
    }

    let mut views = BTreeSet::new();
    for view in &raw.views {
        ensure_owner(scope, &view.owner, "view")?;
        if !views.insert((view.owner.clone(), view.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle view {}.{}",
                view.owner, view.name
            )));
        }
        if view.definition.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle view {}.{} has no complete definition",
                view.owner, view.name
            )));
        }
        if view.type_owner.is_some() || view.view_type.is_some() || view.superview.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "typed Oracle view metadata is not yet covered for {}.{}",
                view.owner, view.name
            )));
        }
        if !inventory_keys.contains(&(view.owner.clone(), "VIEW".to_owned(), view.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle view {}.{} is missing from the independent object inventory",
                view.owner, view.name
            )));
        }
    }
    let inventory_view_count = inventory
        .iter()
        .filter(|object| object.object_type == "VIEW")
        .count();
    if inventory_view_count != raw.views.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle view inventory mismatch: USER/DBA_OBJECTS reports {inventory_view_count}, USER/DBA_VIEWS reports {}",
            raw.views.len()
        )));
    }

    let mut materialized_views = BTreeSet::new();
    for view in &raw.materialized_views {
        ensure_owner(scope, &view.owner, "materialized view")?;
        if !materialized_views.insert((view.owner.clone(), view.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle materialized view {}.{}",
                view.owner, view.name
            )));
        }
        if view.definition.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle materialized view {}.{} has no complete definition",
                view.owner, view.name
            )));
        }
        if view.master_link.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle materialized view {}.{} uses remote master link '{}'",
                view.owner,
                view.name,
                view.master_link.as_deref().unwrap_or_default()
            )));
        }
        if view.compile_state.as_deref() != Some("VALID") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle materialized view {}.{} has compile state '{}'",
                view.owner,
                view.name,
                view.compile_state.as_deref().unwrap_or("missing")
            )));
        }
        if view.container_name != view.name {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle materialized view {}.{} uses non-default container table '{}'",
                view.owner, view.name, view.container_name
            )));
        }
        if !tables.contains(&(view.owner.clone(), view.container_name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle materialized view {}.{} has no storage table {}.{}",
                view.owner, view.name, view.owner, view.container_name
            )));
        }
        for object_type in ["MATERIALIZED VIEW", "TABLE"] {
            if !inventory_keys.contains(&(
                view.owner.clone(),
                object_type.to_owned(),
                view.name.clone(),
            )) {
                return Err(CatalogError::Mapping(format!(
                    "Oracle materialized view {}.{} is missing its {object_type} inventory row",
                    view.owner, view.name
                )));
            }
        }
    }
    let inventory_mview_count = inventory
        .iter()
        .filter(|object| object.object_type == "MATERIALIZED VIEW")
        .count();
    if inventory_mview_count != raw.materialized_views.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle materialized-view inventory mismatch: USER/DBA_OBJECTS reports {inventory_mview_count}, USER/DBA_MVIEWS reports {}",
            raw.materialized_views.len()
        )));
    }

    let mut synonyms = BTreeSet::new();
    for synonym in &raw.synonyms {
        ensure_owner(scope, &synonym.owner, "synonym")?;
        ensure_reference_owner(
            scope,
            &synonym.target_owner,
            &format!("synonym {}.{}", synonym.owner, synonym.name),
        )?;
        if synonym.database_link.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle synonym {}.{} uses remote database link '{}'",
                synonym.owner,
                synonym.name,
                synonym.database_link.as_deref().unwrap_or_default()
            )));
        }
        if synonym.origin_container_id < 0 {
            return Err(CatalogError::Mapping(format!(
                "Oracle synonym {}.{} has invalid origin container id {}",
                synonym.owner, synonym.name, synonym.origin_container_id
            )));
        }
        if !synonyms.insert((synonym.owner.clone(), synonym.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle synonym {}.{}",
                synonym.owner, synonym.name
            )));
        }
        if !inventory_keys.contains(&(
            synonym.owner.clone(),
            "SYNONYM".to_owned(),
            synonym.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle synonym {}.{} is missing from the independent object inventory",
                synonym.owner, synonym.name
            )));
        }
    }
    let inventory_synonym_count = inventory
        .iter()
        .filter(|object| object.object_type == "SYNONYM")
        .count();
    if inventory_synonym_count != raw.synonyms.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle synonym inventory mismatch: USER/DBA_OBJECTS reports {inventory_synonym_count}, USER/DBA_SYNONYMS reports {}",
            raw.synonyms.len()
        )));
    }

    let mut user_types = BTreeMap::new();
    let mut type_oids = BTreeSet::new();
    for user_type in &raw.user_types {
        ensure_owner(scope, &user_type.owner, "type")?;
        if !matches!(user_type.typecode.as_str(), "OBJECT" | "COLLECTION") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle type {}.{} has unsupported typecode '{}'",
                user_type.owner, user_type.name, user_type.typecode
            )));
        }
        for (name, value) in [
            ("predefined", user_type.predefined.as_str()),
            ("incomplete", user_type.incomplete.as_str()),
            ("final", user_type.final_type.as_str()),
            ("instantiable", user_type.instantiable.as_str()),
            ("persistable", user_type.persistable.as_str()),
        ] {
            ensure_yes_no(
                value,
                &format!("Oracle type {}.{} {name}", user_type.owner, user_type.name),
            )?;
        }
        if user_type.predefined != "NO" || user_type.incomplete != "NO" {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle type {}.{} is predefined or incomplete",
                user_type.owner, user_type.name
            )));
        }
        if user_type.attribute_count < 0
            || user_type.method_count < 0
            || user_type
                .local_attribute_count
                .is_some_and(|count| count < 0)
            || user_type.local_method_count.is_some_and(|count| count < 0)
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle type {}.{} has negative member counts",
                user_type.owner, user_type.name
            )));
        }
        if user_type.oid.is_empty() || !type_oids.insert(user_type.oid.clone()) {
            return Err(CatalogError::Mapping(format!(
                "Oracle type {}.{} has a missing or duplicate OID",
                user_type.owner, user_type.name
            )));
        }
        if user_type.specification.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle type {}.{} has no complete specification",
                user_type.owner, user_type.name
            )));
        }
        if let Some(body) = user_type.body.as_deref() {
            reject_dynamic_plsql(
                "type body",
                &format!("{}.{}", user_type.owner, user_type.name),
                body,
            )?;
        }
        let identity = (user_type.owner.clone(), user_type.name.clone());
        if user_types.insert(identity, user_type).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle type {}.{}",
                user_type.owner, user_type.name
            )));
        }
        if !inventory_keys.contains(&(
            user_type.owner.clone(),
            "TYPE".to_owned(),
            user_type.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle type {}.{} is missing from the independent object inventory",
                user_type.owner, user_type.name
            )));
        }
        let has_body_inventory = inventory_keys.contains(&(
            user_type.owner.clone(),
            "TYPE BODY".to_owned(),
            user_type.name.clone(),
        ));
        if has_body_inventory != user_type.body.is_some() {
            return Err(CatalogError::Mapping(format!(
                "Oracle type body inventory mismatch for {}.{}",
                user_type.owner, user_type.name
            )));
        }
    }
    let inventory_type_count = inventory
        .iter()
        .filter(|object| object.object_type == "TYPE")
        .count();
    let inventory_type_body_count = inventory
        .iter()
        .filter(|object| object.object_type == "TYPE BODY")
        .count();
    if inventory_type_count != raw.user_types.len()
        || inventory_type_body_count
            != raw
                .user_types
                .iter()
                .filter(|user_type| user_type.body.is_some())
                .count()
    {
        return Err(CatalogError::Mapping(format!(
            "Oracle type inventory mismatch: TYPE={inventory_type_count}, TYPE BODY={inventory_type_body_count}"
        )));
    }
    for user_type in &raw.user_types {
        match (
            user_type.supertype_owner.as_deref(),
            user_type.supertype_name.as_deref(),
        ) {
            (Some(owner), Some(name)) => {
                ensure_reference_owner(
                    scope,
                    owner,
                    &format!("type {}.{}", user_type.owner, user_type.name),
                )?;
                if !user_types.contains_key(&(owner.to_owned(), name.to_owned()))
                    || (owner == user_type.owner && name == user_type.name)
                    || user_type.local_attribute_count.is_none()
                    || user_type.local_method_count.is_none()
                {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle type {}.{} has inconsistent supertype metadata",
                        user_type.owner, user_type.name
                    )));
                }
            }
            (None, None) => {}
            _ => {
                return Err(CatalogError::Mapping(format!(
                    "Oracle type {}.{} has a partial supertype identity",
                    user_type.owner, user_type.name
                )));
            }
        }
    }

    let mut attribute_identities = BTreeSet::new();
    let mut attributes_by_type = BTreeMap::<(String, String), Vec<&RawTypeAttribute>>::new();
    for attribute in &raw.type_attributes {
        ensure_owner(scope, &attribute.owner, "type attribute")?;
        if !user_types.contains_key(&(attribute.owner.clone(), attribute.type_name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle type attribute {}.{}.{} has no parent type",
                attribute.owner, attribute.type_name, attribute.name
            )));
        }
        positive_u32(attribute.position, "Oracle type attribute position")?;
        ensure_yes_no(
            &attribute.inherited,
            &format!(
                "Oracle type attribute {}.{}.{} inherited",
                attribute.owner, attribute.type_name, attribute.name
            ),
        )?;
        ensure_user_type_reference(
            scope,
            &user_types,
            attribute.data_type_owner.as_deref(),
            &attribute.data_type_name,
            &format!(
                "Oracle type attribute {}.{}.{}",
                attribute.owner, attribute.type_name, attribute.name
            ),
        )?;
        if !attribute_identities.insert((
            attribute.owner.clone(),
            attribute.type_name.clone(),
            attribute.position,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle type attribute position {} for {}.{}",
                attribute.position, attribute.owner, attribute.type_name
            )));
        }
        attributes_by_type
            .entry((attribute.owner.clone(), attribute.type_name.clone()))
            .or_default()
            .push(attribute);
    }
    for user_type in &raw.user_types {
        let attributes = attributes_by_type
            .get(&(user_type.owner.clone(), user_type.name.clone()))
            .map(Vec::as_slice)
            .unwrap_or_default();
        if attributes.len() != user_type.attribute_count as usize
            || attributes
                .iter()
                .enumerate()
                .any(|(offset, attribute)| attribute.position != (offset + 1) as i64)
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle type attribute catalog mismatch for {}.{}",
                user_type.owner, user_type.name
            )));
        }
    }

    let mut collection_names = BTreeSet::new();
    for collection in &raw.collection_types {
        ensure_owner(scope, &collection.owner, "collection type")?;
        let parent = user_types
            .get(&(collection.owner.clone(), collection.type_name.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle collection {}.{} has no parent type",
                    collection.owner, collection.type_name
                ))
            })?;
        if parent.typecode != "COLLECTION"
            || !matches!(
                collection.collection_type.as_str(),
                "TABLE" | "VARYING ARRAY"
            )
            || (collection.collection_type == "VARYING ARRAY" && collection.upper_bound.is_none())
            || (collection.collection_type == "TABLE" && collection.upper_bound.is_some())
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle collection metadata is inconsistent for {}.{}",
                collection.owner, collection.type_name
            )));
        }
        ensure_user_type_reference(
            scope,
            &user_types,
            collection.element_type_owner.as_deref(),
            &collection.element_type_name,
            &format!(
                "Oracle collection {}.{}",
                collection.owner, collection.type_name
            ),
        )?;
        if !collection_names.insert((collection.owner.clone(), collection.type_name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle collection type {}.{}",
                collection.owner, collection.type_name
            )));
        }
    }
    let expected_collection_names = raw
        .user_types
        .iter()
        .filter(|user_type| user_type.typecode == "COLLECTION")
        .map(|user_type| (user_type.owner.clone(), user_type.name.clone()))
        .collect::<BTreeSet<_>>();
    if collection_names != expected_collection_names {
        return Err(CatalogError::Mapping(
            "Oracle USER/DBA_COLL_TYPES does not exactly match collection TYPE rows".to_owned(),
        ));
    }

    let mut method_identities = BTreeSet::new();
    let mut methods_by_type = BTreeMap::<(String, String), Vec<&RawTypeMethod>>::new();
    for method in &raw.type_methods {
        ensure_owner(scope, &method.owner, "type method")?;
        let parent = user_types
            .get(&(method.owner.clone(), method.type_name.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle type method {}.{}.{} has no parent type",
                    method.owner, method.type_name, method.name
                ))
            })?;
        if parent.typecode != "OBJECT" || method.parameter_count < 0 || method.result_count < 0 {
            return Err(CatalogError::Mapping(format!(
                "Oracle type method metadata is malformed for {}.{}.{}",
                method.owner, method.type_name, method.name
            )));
        }
        positive_u32(method.method_number, "Oracle type method number")?;
        for (name, value) in [
            ("final", method.final_method.as_str()),
            ("instantiable", method.instantiable.as_str()),
            ("overriding", method.overriding.as_str()),
            ("inherited", method.inherited.as_str()),
        ] {
            ensure_yes_no(
                value,
                &format!(
                    "Oracle type method {}.{}.{} {name}",
                    method.owner, method.type_name, method.name
                ),
            )?;
        }
        if !method_identities.insert((
            method.owner.clone(),
            method.type_name.clone(),
            method.method_number,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle type method number {} for {}.{}",
                method.method_number, method.owner, method.type_name
            )));
        }
        methods_by_type
            .entry((method.owner.clone(), method.type_name.clone()))
            .or_default()
            .push(method);
    }
    for user_type in &raw.user_types {
        let method_count = methods_by_type
            .get(&(user_type.owner.clone(), user_type.name.clone()))
            .map_or(0, Vec::len);
        if method_count != user_type.method_count as usize {
            return Err(CatalogError::Mapping(format!(
                "Oracle type method catalog mismatch for {}.{}",
                user_type.owner, user_type.name
            )));
        }
    }

    let mut method_parameter_identities = BTreeSet::new();
    let mut parameters_by_method =
        BTreeMap::<(String, String, i64), Vec<&RawTypeMethodParameter>>::new();
    for parameter in &raw.type_method_parameters {
        ensure_owner(scope, &parameter.owner, "type method parameter")?;
        let method_key = (
            parameter.owner.clone(),
            parameter.type_name.clone(),
            parameter.method_number,
        );
        let method = raw
            .type_methods
            .iter()
            .find(|method| {
                method.owner == parameter.owner
                    && method.type_name == parameter.type_name
                    && method.method_number == parameter.method_number
            })
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle type method parameter {}.{}.{} has no method",
                    parameter.owner, parameter.type_name, parameter.name
                ))
            })?;
        if parameter.method_name != method.name
            || parameter.position < 0
            || !matches!(parameter.mode.as_str(), "IN" | "OUT" | "IN/OUT")
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle type method parameter metadata is malformed for {}.{}.{}",
                parameter.owner, parameter.type_name, parameter.name
            )));
        }
        ensure_user_type_reference(
            scope,
            &user_types,
            parameter.data_type_owner.as_deref(),
            &parameter.data_type_name,
            &format!(
                "Oracle type method parameter {}.{}.{}",
                parameter.owner, parameter.type_name, parameter.name
            ),
        )?;
        if !method_parameter_identities.insert((
            method_key.clone(),
            parameter.return_value,
            parameter.position,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle type method parameter position {} for {}.{}",
                parameter.position, parameter.owner, parameter.type_name
            )));
        }
        parameters_by_method
            .entry(method_key)
            .or_default()
            .push(parameter);
    }
    for method in &raw.type_methods {
        let parameters = parameters_by_method
            .get(&(
                method.owner.clone(),
                method.type_name.clone(),
                method.method_number,
            ))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let parameter_count = parameters
            .iter()
            .filter(|parameter| !parameter.return_value)
            .count();
        let result_count = parameters
            .iter()
            .filter(|parameter| parameter.return_value)
            .count();
        if parameter_count != method.parameter_count as usize
            || result_count != method.result_count as usize
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle type method parameter catalog mismatch for {}.{}.{}",
                method.owner, method.type_name, method.name
            )));
        }
    }

    for column in raw.columns.iter().chain(&raw.view_columns) {
        ensure_user_type_reference(
            scope,
            &user_types,
            column.data_type_owner.as_deref(),
            &column.data_type,
            &format!(
                "Oracle column {}.{}.{}",
                column.owner, column.table, column.name
            ),
        )?;
    }

    let mut triggers = BTreeSet::new();
    for trigger in &raw.triggers {
        ensure_owner(scope, &trigger.owner, "trigger")?;
        if !triggers.insert((trigger.owner.clone(), trigger.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle trigger {}.{}",
                trigger.owner, trigger.name
            )));
        }
        if !inventory_keys.contains(&(
            trigger.owner.clone(),
            "TRIGGER".to_owned(),
            trigger.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle trigger {}.{} is missing from the independent object inventory",
                trigger.owner, trigger.name
            )));
        }
        match trigger.base_object_type.as_str() {
            "TABLE" | "VIEW" => {
                let target_owner = trigger.table_owner.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle {} trigger {}.{} has no target owner",
                        trigger.base_object_type.to_lowercase(),
                        trigger.owner,
                        trigger.name
                    ))
                })?;
                let target_name = trigger.table_name.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle {} trigger {}.{} has no target object",
                        trigger.base_object_type.to_lowercase(),
                        trigger.owner,
                        trigger.name
                    ))
                })?;
                ensure_owner(scope, target_owner, "trigger target")?;
                if trigger.owner != target_owner {
                    return Err(CatalogError::UnsupportedMetadata(format!(
                        "cross-owner Oracle trigger {}.{} on {}.{target_name} is outside the certified contract",
                        trigger.owner, trigger.name, target_owner
                    )));
                }
                let target_exists = if trigger.base_object_type == "TABLE" {
                    tables.contains(&(target_owner.to_owned(), target_name.to_owned()))
                        && !materialized_views
                            .contains(&(target_owner.to_owned(), target_name.to_owned()))
                } else {
                    views.contains(&(target_owner.to_owned(), target_name.to_owned()))
                };
                if !target_exists {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle trigger {}.{} targets missing {} {}.{}",
                        trigger.owner,
                        trigger.name,
                        trigger.base_object_type.to_lowercase(),
                        target_owner,
                        target_name
                    )));
                }
            }
            "SCHEMA" => {
                let target_owner = trigger.table_owner.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle schema trigger {}.{} has no target owner",
                        trigger.owner, trigger.name
                    ))
                })?;
                ensure_owner(scope, target_owner, "schema trigger target")?;
                if trigger.owner != target_owner || trigger.table_name.is_some() {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle schema trigger {}.{} has inconsistent target metadata",
                        trigger.owner, trigger.name
                    )));
                }
            }
            "DATABASE" => {
                if trigger.table_name.is_some() {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle database trigger {}.{} unexpectedly names a table target",
                        trigger.owner, trigger.name
                    )));
                }
            }
            other => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle trigger target kind '{other}' is not covered for {}.{}",
                    trigger.owner, trigger.name
                )));
            }
        }
        if !matches!(trigger.action_type.as_str(), "PL/SQL" | "CALL") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle trigger action type '{}' is not covered for {}.{}",
                trigger.action_type, trigger.owner, trigger.name
            )));
        }
        if !matches!(trigger.status.as_str(), "ENABLED" | "DISABLED") {
            return Err(CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has unrecognized status '{}'",
                trigger.owner, trigger.name, trigger.status
            )));
        }
        let body = trigger.body.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has no complete body",
                trigger.owner, trigger.name
            ))
        })?;
        reject_dynamic_plsql(
            "trigger",
            &format!("{}.{}", trigger.owner, trigger.name),
            body,
        )?;
        oracle_trigger_timing(&trigger.trigger_type)?;
    }
    let inventory_trigger_count = inventory
        .iter()
        .filter(|object| object.object_type == "TRIGGER")
        .count();
    if inventory_trigger_count != raw.triggers.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle trigger inventory mismatch: USER/DBA_OBJECTS reports {inventory_trigger_count}, USER/DBA_TRIGGERS reports {}",
            raw.triggers.len()
        )));
    }

    let mut routines = BTreeMap::new();
    let mut routines_by_name = BTreeMap::new();
    for routine in &raw.routines {
        ensure_owner(scope, &routine.owner, "routine")?;
        if !matches!(routine.object_type.as_str(), "FUNCTION" | "PROCEDURE") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle routine type '{}' is not covered for {}.{}",
                routine.object_type, routine.owner, routine.name
            )));
        }
        let identity = (
            routine.owner.clone(),
            routine.name.clone(),
            routine.object_type.clone(),
        );
        if routines.insert(identity, routine).is_some()
            || routines_by_name
                .insert((routine.owner.clone(), routine.name.clone()), routine)
                .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle standalone routine {}.{}",
                routine.owner, routine.name
            )));
        }
        let inventory_object = inventory
            .iter()
            .find(|object| {
                object.owner == routine.owner
                    && object.object_type == routine.object_type
                    && object.name == routine.name
            })
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle routine {}.{} is missing from the independent object inventory",
                    routine.owner, routine.name
                ))
            })?;
        if inventory_object.object_id != routine.object_id {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine object id mismatch for {}.{}: inventory={}, procedure catalog={}",
                routine.owner, routine.name, inventory_object.object_id, routine.object_id
            )));
        }
        if routine.subprogram_id != 1 || routine.overload.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle standalone routine {}.{} has unexpected overload identity subprogram_id={} overload='{}'",
                routine.owner,
                routine.name,
                routine.subprogram_id,
                routine.overload.as_deref().unwrap_or("none")
            )));
        }
        if routine.aggregate
            || routine.pipelined
            || routine.interface
            || routine.polymorphic.is_some()
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle routine shape is not yet covered for {}.{} (aggregate={}, pipelined={}, interface={}, polymorphic={})",
                routine.owner,
                routine.name,
                routine.aggregate,
                routine.pipelined,
                routine.interface,
                routine.polymorphic.as_deref().unwrap_or("none")
            )));
        }
        if !matches!(routine.authid.as_str(), "DEFINER" | "CURRENT_USER") {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine {}.{} has unrecognized AUTHID '{}'",
                routine.owner, routine.name, routine.authid
            )));
        }
        let definition = routine.definition.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle routine {}.{} has no complete definition",
                routine.owner, routine.name
            ))
        })?;
        reject_dynamic_plsql(
            "routine",
            &format!("{}.{}", routine.owner, routine.name),
            definition,
        )?;
    }
    let inventory_routine_count = inventory
        .iter()
        .filter(|object| matches!(object.object_type.as_str(), "FUNCTION" | "PROCEDURE"))
        .count();
    if inventory_routine_count != raw.routines.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle routine inventory mismatch: USER/DBA_OBJECTS reports {inventory_routine_count}, USER/DBA_PROCEDURES reports {} standalone routine(s)",
            raw.routines.len()
        )));
    }

    let mut argument_identities = BTreeSet::new();
    let mut arguments_by_routine = BTreeMap::<(String, String), Vec<&RawRoutineArgument>>::new();
    for argument in &raw.routine_arguments {
        ensure_owner(scope, &argument.owner, "routine argument")?;
        if argument.package_name.is_some() {
            return Err(CatalogError::Mapping(format!(
                "standalone Oracle argument {}.{} unexpectedly belongs to package '{}'",
                argument.owner,
                argument.routine,
                argument.package_name.as_deref().unwrap_or_default()
            )));
        }
        let routine = routines_by_name
            .get(&(argument.owner.clone(), argument.routine.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle argument references missing standalone routine {}.{}",
                    argument.owner, argument.routine
                ))
            })?;
        if argument.subprogram_id != routine.subprogram_id || argument.overload != routine.overload
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle argument overload identity does not match routine {}.{}",
                argument.owner, argument.routine
            )));
        }
        if argument.data_level != 0 || argument.type_subname.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle nested or package-defined routine argument is not covered for {}.{} position {}",
                argument.owner, argument.routine, argument.position
            )));
        }
        match (
            argument.type_owner.as_deref(),
            argument.type_name.as_deref(),
        ) {
            (Some(owner), Some(name)) => ensure_user_type_reference(
                scope,
                &user_types,
                Some(owner),
                name,
                &format!(
                    "Oracle routine argument {}.{} position {}",
                    argument.owner, argument.routine, argument.position
                ),
            )?,
            (None, None) => {}
            _ => {
                return Err(CatalogError::Mapping(format!(
                    "Oracle routine argument {}.{} position {} has a partial type identity",
                    argument.owner, argument.routine, argument.position
                )));
            }
        }
        if argument.data_type.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine argument {}.{} position {} has no data type",
                argument.owner, argument.routine, argument.position
            )));
        }
        if !matches!(argument.mode.as_str(), "IN" | "OUT" | "IN/OUT") {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine argument {}.{} position {} has unrecognized mode '{}'",
                argument.owner, argument.routine, argument.position, argument.mode
            )));
        }
        positive_u32(argument.sequence, "Oracle routine argument sequence")?;
        if argument.position < 0 {
            return Err(CatalogError::Mapping(format!(
                "Oracle routine argument {}.{} has negative position {}",
                argument.owner, argument.routine, argument.position
            )));
        }
        if !argument_identities.insert((
            argument.owner.clone(),
            argument.routine.clone(),
            argument.subprogram_id,
            argument.sequence,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle routine argument sequence {} for {}.{}",
                argument.sequence, argument.owner, argument.routine
            )));
        }
        arguments_by_routine
            .entry((argument.owner.clone(), argument.routine.clone()))
            .or_default()
            .push(argument);
    }
    for routine in &raw.routines {
        let arguments = arguments_by_routine
            .get(&(routine.owner.clone(), routine.name.clone()))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let return_count = arguments
            .iter()
            .filter(|argument| argument.position == 0)
            .count();
        let expected_return_count = usize::from(routine.object_type == "FUNCTION");
        if return_count != expected_return_count {
            return Err(CatalogError::Mapping(format!(
                "Oracle {} {}.{} has {return_count} return rows; expected {expected_return_count}",
                routine.object_type, routine.owner, routine.name
            )));
        }
        for (offset, argument) in arguments.iter().enumerate() {
            let expected_sequence = i64::try_from(offset + 1).map_err(|_| {
                CatalogError::Mapping("too many Oracle routine arguments".to_owned())
            })?;
            if argument.sequence != expected_sequence {
                return Err(CatalogError::Mapping(format!(
                    "Oracle routine argument sequence gap for {}.{}: expected {expected_sequence}, found {}",
                    routine.owner, routine.name, argument.sequence
                )));
            }
            let expected_position = if routine.object_type == "FUNCTION" {
                i64::try_from(offset).map_err(|_| {
                    CatalogError::Mapping("too many Oracle routine arguments".to_owned())
                })?
            } else {
                expected_sequence
            };
            if argument.position != expected_position {
                return Err(CatalogError::Mapping(format!(
                    "Oracle routine argument position mismatch for {}.{}: expected {expected_position}, found {}",
                    routine.owner, routine.name, argument.position
                )));
            }
            if argument.position == 0 && (argument.name.is_some() || argument.mode != "OUT") {
                return Err(CatalogError::Mapping(format!(
                    "Oracle function return metadata is malformed for {}.{}",
                    routine.owner, routine.name
                )));
            }
        }
    }

    let mut packages = BTreeMap::new();
    for package in &raw.packages {
        ensure_owner(scope, &package.owner, "package")?;
        if packages
            .insert((package.owner.clone(), package.name.clone()), package)
            .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle package {}.{}",
                package.owner, package.name
            )));
        }
        if !matches!(package.authid.as_str(), "DEFINER" | "CURRENT_USER") {
            return Err(CatalogError::Mapping(format!(
                "Oracle package {}.{} has unrecognized AUTHID '{}'",
                package.owner, package.name, package.authid
            )));
        }
        if package.specification.is_none() {
            return Err(CatalogError::Mapping(format!(
                "Oracle package {}.{} has no complete specification",
                package.owner, package.name
            )));
        }
        if let Some(body) = package.body.as_deref() {
            reject_dynamic_plsql(
                "package body",
                &format!("{}.{}", package.owner, package.name),
                body,
            )?;
        }
        let inventory_object = inventory
            .iter()
            .find(|object| {
                object.owner == package.owner
                    && object.object_type == "PACKAGE"
                    && object.name == package.name
            })
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle package {}.{} is missing from the independent object inventory",
                    package.owner, package.name
                ))
            })?;
        if inventory_object.object_id != package.object_id {
            return Err(CatalogError::Mapping(format!(
                "Oracle package object id mismatch for {}.{}: inventory={}, procedure catalog={}",
                package.owner, package.name, inventory_object.object_id, package.object_id
            )));
        }
        let body_in_inventory = inventory_keys.contains(&(
            package.owner.clone(),
            "PACKAGE BODY".to_owned(),
            package.name.clone(),
        ));
        if body_in_inventory != package.body.is_some() {
            return Err(CatalogError::Mapping(format!(
                "Oracle package body inventory/source mismatch for {}.{}",
                package.owner, package.name
            )));
        }
    }
    let inventory_package_count = inventory
        .iter()
        .filter(|object| object.object_type == "PACKAGE")
        .count();
    let inventory_package_body_count = inventory
        .iter()
        .filter(|object| object.object_type == "PACKAGE BODY")
        .count();
    if inventory_package_count != raw.packages.len()
        || inventory_package_body_count
            != raw
                .packages
                .iter()
                .filter(|package| package.body.is_some())
                .count()
    {
        return Err(CatalogError::Mapping(format!(
            "Oracle package inventory mismatch: packages={inventory_package_count}/{}, bodies={inventory_package_body_count}/{}",
            raw.packages.len(),
            raw.packages
                .iter()
                .filter(|package| package.body.is_some())
                .count()
        )));
    }

    let mut package_routines = BTreeMap::new();
    for routine in &raw.package_routines {
        ensure_owner(scope, &routine.owner, "package routine")?;
        let package = packages
            .get(&(routine.owner.clone(), routine.package.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle package routine {}.{}.{} has no package",
                    routine.owner, routine.package, routine.name
                ))
            })?;
        if routine.object_id != package.object_id || routine.subprogram_id <= 0 {
            return Err(CatalogError::Mapping(format!(
                "Oracle package routine identity is malformed for {}.{}.{}",
                routine.owner, routine.package, routine.name
            )));
        }
        if routine.aggregate
            || routine.pipelined
            || routine.interface
            || routine.polymorphic.is_some()
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle package routine shape is not yet covered for {}.{}.{} (aggregate={}, pipelined={}, interface={}, polymorphic={})",
                routine.owner,
                routine.package,
                routine.name,
                routine.aggregate,
                routine.pipelined,
                routine.interface,
                routine.polymorphic.as_deref().unwrap_or("none")
            )));
        }
        if routine.authid != package.authid {
            return Err(CatalogError::Mapping(format!(
                "Oracle package routine AUTHID mismatch for {}.{}.{}",
                routine.owner, routine.package, routine.name
            )));
        }
        if package_routines
            .insert(
                (
                    routine.owner.clone(),
                    routine.package.clone(),
                    routine.subprogram_id,
                ),
                routine,
            )
            .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle package subprogram id {} for {}.{}",
                routine.subprogram_id, routine.owner, routine.package
            )));
        }
    }

    let mut package_argument_identities = BTreeSet::new();
    let mut package_arguments_by_routine =
        BTreeMap::<(String, String, i64), Vec<&RawRoutineArgument>>::new();
    for argument in &raw.package_arguments {
        ensure_owner(scope, &argument.owner, "package argument")?;
        let package_name = argument.package_name.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle package argument {}.{} has no package name",
                argument.owner, argument.routine
            ))
        })?;
        let routine = package_routines
            .get(&(
                argument.owner.clone(),
                package_name.to_owned(),
                argument.subprogram_id,
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle package argument references missing routine {}.{}.{}",
                    argument.owner, package_name, argument.routine
                ))
            })?;
        if argument.routine != routine.name || argument.overload != routine.overload {
            return Err(CatalogError::Mapping(format!(
                "Oracle package argument overload identity does not match {}.{}.{}",
                argument.owner, package_name, argument.routine
            )));
        }
        if argument.data_level != 0 || argument.type_subname.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle nested or package-defined package argument is not covered for {}.{}.{} position {}",
                argument.owner, package_name, argument.routine, argument.position
            )));
        }
        match (
            argument.type_owner.as_deref(),
            argument.type_name.as_deref(),
        ) {
            (Some(owner), Some(name)) => ensure_user_type_reference(
                scope,
                &user_types,
                Some(owner),
                name,
                &format!(
                    "Oracle package argument {}.{}.{} position {}",
                    argument.owner, package_name, argument.routine, argument.position
                ),
            )?,
            (None, None) => {}
            _ => {
                return Err(CatalogError::Mapping(format!(
                    "Oracle package argument {}.{}.{} position {} has a partial type identity",
                    argument.owner, package_name, argument.routine, argument.position
                )));
            }
        }
        if argument.data_type.is_none()
            || !matches!(argument.mode.as_str(), "IN" | "OUT" | "IN/OUT")
            || argument.position < 0
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle package argument metadata is malformed for {}.{}.{} position {}",
                argument.owner, package_name, argument.routine, argument.position
            )));
        }
        positive_u32(argument.sequence, "Oracle package argument sequence")?;
        if !package_argument_identities.insert((
            argument.owner.clone(),
            package_name.to_owned(),
            argument.subprogram_id,
            argument.sequence,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle package argument sequence {} for {}.{}.{}",
                argument.sequence, argument.owner, package_name, argument.routine
            )));
        }
        package_arguments_by_routine
            .entry((
                argument.owner.clone(),
                package_name.to_owned(),
                argument.subprogram_id,
            ))
            .or_default()
            .push(argument);
    }
    let mut package_signatures = BTreeSet::new();
    for routine in &raw.package_routines {
        let arguments = package_arguments_by_routine
            .get(&(
                routine.owner.clone(),
                routine.package.clone(),
                routine.subprogram_id,
            ))
            .map(Vec::as_slice)
            .unwrap_or_default();
        validate_package_argument_order(routine, arguments)?;
        let signature = oracle_package_routine_signature(routine, arguments)?;
        if !package_signatures.insert((
            routine.owner.clone(),
            routine.package.clone(),
            signature.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle package routine signature {}.{}.{signature}",
                routine.owner, routine.package
            )));
        }
    }

    let mut view_column_keys = BTreeSet::new();
    let mut view_column_ordinals = BTreeSet::new();
    for column in &raw.view_columns {
        ensure_owner(scope, &column.owner, "view column")?;
        if !views.contains(&(column.owner.clone(), column.table.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle view column {}.{}.{} has no mapped view",
                column.owner, column.table, column.name
            )));
        }
        positive_u32(column.internal_column_id, "Oracle view-column ordinal")?;
        if !view_column_keys.insert((
            column.owner.clone(),
            column.table.clone(),
            column.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle view column {}.{}.{}",
                column.owner, column.table, column.name
            )));
        }
        if !view_column_ordinals.insert((
            column.owner.clone(),
            column.table.clone(),
            column.internal_column_id,
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle view-column ordinal {} for {}.{}",
                column.internal_column_id, column.owner, column.table
            )));
        }
    }

    for dependency in &raw.dependencies {
        ensure_owner(scope, &dependency.owner, "dependency source")?;
        if dependency.referenced_link.is_some() {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle dependency {}.{} uses remote database link '{}'",
                dependency.owner,
                dependency.name,
                dependency.referenced_link.as_deref().unwrap_or_default()
            )));
        }
        let source_is_view = dependency.object_type == "VIEW"
            && views.contains(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_mview = dependency.object_type == "MATERIALIZED VIEW"
            && materialized_views.contains(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_trigger = dependency.object_type == "TRIGGER"
            && triggers.contains(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_routine = matches!(dependency.object_type.as_str(), "FUNCTION" | "PROCEDURE")
            && routines.contains_key(&(
                dependency.owner.clone(),
                dependency.name.clone(),
                dependency.object_type.clone(),
            ));
        let source_is_package =
            matches!(dependency.object_type.as_str(), "PACKAGE" | "PACKAGE BODY")
                && packages.contains_key(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_synonym = dependency.object_type == "SYNONYM"
            && synonyms.contains(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_type = matches!(dependency.object_type.as_str(), "TYPE" | "TYPE BODY")
            && user_types.contains_key(&(dependency.owner.clone(), dependency.name.clone()));
        let source_is_table = dependency.object_type == "TABLE"
            && tables.contains(&(dependency.owner.clone(), dependency.name.clone()));
        if !source_is_view
            && !source_is_mview
            && !source_is_trigger
            && !source_is_routine
            && !source_is_package
            && !source_is_synonym
            && !source_is_type
            && !source_is_table
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle dependency source is not yet covered: {}.{} ({})",
                dependency.owner, dependency.name, dependency.object_type
            )));
        }
        let expected_dependency_type = if source_is_mview { "REF" } else { "HARD" };
        if dependency.dependency_type != expected_dependency_type {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle dependency type '{}' is not covered for {}.{}; expected '{}'",
                dependency.dependency_type,
                dependency.owner,
                dependency.name,
                expected_dependency_type
            )));
        }
        if dependency.referenced_owner_oracle_maintained {
            continue;
        }
        if source_is_table && dependency.referenced_type != "TYPE" {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle table dependency {}.{} -> {}.{} ({}) is not covered by typed-column mapping",
                dependency.owner,
                dependency.name,
                dependency.referenced_owner,
                dependency.referenced_name,
                dependency.referenced_type
            )));
        }
        ensure_reference_owner(
            scope,
            &dependency.referenced_owner,
            &format!(
                "dependency {}.{} ({})",
                dependency.owner, dependency.name, dependency.object_type
            ),
        )?;
        let target_exists = match dependency.referenced_type.as_str() {
            "TABLE" => tables.contains(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "VIEW" => views.contains(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "MATERIALIZED VIEW" => materialized_views.contains(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "SEQUENCE" => sequences.contains(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "FUNCTION" | "PROCEDURE" => routines.contains_key(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
                dependency.referenced_type.clone(),
            )),
            "PACKAGE" => packages.contains_key(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "SYNONYM" => synonyms.contains(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            "TYPE" => user_types.contains_key(&(
                dependency.referenced_owner.clone(),
                dependency.referenced_name.clone(),
            )),
            _ => false,
        };
        if !target_exists {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle dependency target is outside the covered object set: {}.{} ({})",
                dependency.referenced_owner, dependency.referenced_name, dependency.referenced_type
            )));
        }
    }
    for synonym in &raw.synonyms {
        let target_dependency_count = raw
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.object_type == "SYNONYM"
                    && dependency.owner == synonym.owner
                    && dependency.name == synonym.name
                    && !dependency.referenced_owner_oracle_maintained
                    && dependency.referenced_owner == synonym.target_owner
                    && dependency.referenced_name == synonym.target_name
            })
            .count();
        if target_dependency_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle synonym {}.{} has {target_dependency_count} matching target dependency rows; expected exactly one",
                synonym.owner, synonym.name
            )));
        }
    }
    let typed_column_dependencies = raw
        .columns
        .iter()
        .filter_map(|column| {
            Some((
                column.owner.as_str(),
                column.table.as_str(),
                column.data_type_owner.as_deref()?,
                column.data_type.as_str(),
            ))
        })
        .collect::<BTreeSet<_>>();
    for (owner, table, type_owner, type_name) in typed_column_dependencies {
        let dependency_count = raw
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.owner == owner
                    && dependency.name == table
                    && dependency.object_type == "TABLE"
                    && dependency.referenced_owner == type_owner
                    && dependency.referenced_name == type_name
                    && dependency.referenced_type == "TYPE"
                    && !dependency.referenced_owner_oracle_maintained
            })
            .count();
        if dependency_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle typed table {owner}.{table} has {dependency_count} dependency rows for {type_owner}.{type_name}; expected exactly one"
            )));
        }
    }
    for view in &raw.materialized_views {
        let storage_dependency_count = raw
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.object_type == "MATERIALIZED VIEW"
                    && dependency.owner == view.owner
                    && dependency.name == view.name
                    && dependency.referenced_type == "TABLE"
                    && dependency.referenced_owner == view.owner
                    && dependency.referenced_name == view.container_name
            })
            .count();
        if storage_dependency_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle materialized view {}.{} has {storage_dependency_count} storage-table dependency rows; expected exactly one",
                view.owner, view.name
            )));
        }
    }
    for trigger in raw
        .triggers
        .iter()
        .filter(|trigger| matches!(trigger.base_object_type.as_str(), "TABLE" | "VIEW"))
    {
        let target_owner = trigger.table_owner.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has no target owner",
                trigger.owner, trigger.name
            ))
        })?;
        let target_name = trigger.table_name.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has no target table",
                trigger.owner, trigger.name
            ))
        })?;
        let target_dependency_count = raw
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.object_type == "TRIGGER"
                    && dependency.owner == trigger.owner
                    && dependency.name == trigger.name
                    && !dependency.referenced_owner_oracle_maintained
                    && dependency.referenced_type == trigger.base_object_type
                    && dependency.referenced_owner == target_owner
                    && dependency.referenced_name == target_name
            })
            .count();
        if target_dependency_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has {target_dependency_count} target-{} dependency rows; expected exactly one",
                trigger.owner,
                trigger.name,
                trigger.base_object_type.to_lowercase()
            )));
        }
    }
    for package in raw.packages.iter().filter(|package| package.body.is_some()) {
        let body_link_count = raw
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.object_type == "PACKAGE BODY"
                    && dependency.owner == package.owner
                    && dependency.name == package.name
                    && !dependency.referenced_owner_oracle_maintained
                    && dependency.referenced_type == "PACKAGE"
                    && dependency.referenced_owner == package.owner
                    && dependency.referenced_name == package.name
            })
            .count();
        if body_link_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle package body {}.{} has {body_link_count} specification-link dependency rows; expected exactly one",
                package.owner, package.name
            )));
        }
    }

    let mut constraints = BTreeMap::new();
    for constraint in &raw.constraints {
        ensure_owner(scope, &constraint.owner, "constraint")?;
        if !tables.contains(&(constraint.owner.clone(), constraint.table.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle constraint {}.{} has no mapped table {}",
                constraint.owner, constraint.name, constraint.table
            )));
        }
        if !matches!(constraint.constraint_type.as_str(), "P" | "U" | "R" | "C") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle constraint type '{}' is not covered for {}.{}",
                constraint.constraint_type, constraint.owner, constraint.name
            )));
        }
        if materialized_views.contains(&(constraint.owner.clone(), constraint.table.clone()))
            && !matches!(constraint.constraint_type.as_str(), "P" | "U" | "C")
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle materialized-view constraint type '{}' is not covered for {}.{}",
                constraint.constraint_type, constraint.owner, constraint.name
            )));
        }
        if matches!(constraint.constraint_type.as_str(), "P" | "U" | "R")
            && constraint.columns.is_empty()
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle constraint {}.{} has no catalog columns",
                constraint.owner, constraint.name
            )));
        }
        let mut positions = BTreeSet::new();
        for column in &constraint.columns {
            if let Some(position) = column.position {
                positive_u32(position, "Oracle constraint column ordinal")?;
                if !positions.insert(position) {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate Oracle constraint column ordinal {} for {}.{}",
                        position, constraint.owner, constraint.name
                    )));
                }
            } else if constraint.constraint_type != "C" {
                return Err(CatalogError::Mapping(format!(
                    "Oracle constraint {}.{} has a column without an ordinal",
                    constraint.owner, constraint.name
                )));
            }
            if !column_keys.contains(&(
                constraint.owner.clone(),
                constraint.table.clone(),
                column.name.clone(),
            )) {
                return Err(CatalogError::Mapping(format!(
                    "Oracle constraint {}.{} references missing column {}.{}.{}",
                    constraint.owner,
                    constraint.name,
                    constraint.owner,
                    constraint.table,
                    column.name
                )));
            }
        }
        let identity = (constraint.owner.clone(), constraint.name.clone());
        if constraints.insert(identity.clone(), constraint).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle constraint identity {}.{}",
                identity.0, identity.1
            )));
        }
    }
    for constraint in &raw.constraints {
        if constraint.constraint_type != "R" {
            continue;
        }
        let referenced_owner = constraint.referenced_owner.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle foreign key {}.{} has no referenced owner",
                constraint.owner, constraint.name
            ))
        })?;
        ensure_reference_owner(
            scope,
            referenced_owner,
            &format!("foreign key {}.{}", constraint.owner, constraint.name),
        )?;
        let referenced_name = constraint.referenced_constraint.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle foreign key {}.{} has no referenced constraint",
                constraint.owner, constraint.name
            ))
        })?;
        let referenced = constraints
            .get(&(referenced_owner.to_owned(), referenced_name.to_owned()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle foreign key {}.{} references constraint outside the certified scope: {}.{}",
                    constraint.owner, constraint.name, referenced_owner, referenced_name
                ))
            })?;
        if !matches!(referenced.constraint_type.as_str(), "P" | "U") {
            return Err(CatalogError::Mapping(format!(
                "Oracle foreign key {}.{} references non-key constraint {}.{}",
                constraint.owner, constraint.name, referenced_owner, referenced_name
            )));
        }
        if referenced.columns.len() != constraint.columns.len() {
            return Err(CatalogError::Mapping(format!(
                "Oracle foreign key {}.{} has {} column(s), referenced constraint {}.{} has {}",
                constraint.owner,
                constraint.name,
                constraint.columns.len(),
                referenced_owner,
                referenced_name,
                referenced.columns.len()
            )));
        }
    }

    let columns_by_identity = raw
        .columns
        .iter()
        .map(|column| {
            (
                (
                    column.owner.clone(),
                    column.table.clone(),
                    column.name.clone(),
                ),
                column,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut indexes = BTreeSet::new();
    for index in &raw.indexes {
        ensure_owner(scope, &index.owner, "index")?;
        ensure_owner(scope, &index.table_owner, "indexed table")?;
        if index.owner != index.table_owner {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "cross-owner Oracle index {}.{} on {}.{} is outside the certified contract",
                index.owner, index.name, index.table_owner, index.table
            )));
        }
        if !tables.contains(&(index.table_owner.clone(), index.table.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle index {}.{} has no mapped table {}.{}",
                index.owner, index.name, index.table_owner, index.table
            )));
        }
        let function_based = matches!(
            index.index_type.as_str(),
            "FUNCTION-BASED NORMAL" | "FUNCTION-BASED BITMAP"
        );
        if !matches!(
            index.index_type.as_str(),
            "NORMAL" | "BITMAP" | "FUNCTION-BASED NORMAL" | "FUNCTION-BASED BITMAP"
        ) || index.secondary
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle index shape is not yet covered for {}.{} (type={}, partitioned={}, secondary={})",
                index.owner, index.name, index.index_type, index.partitioned, index.secondary
            )));
        }
        if index.columns.is_empty() {
            return Err(CatalogError::Mapping(format!(
                "Oracle index {}.{} has no catalog columns",
                index.owner, index.name
            )));
        }
        let mut positions = BTreeSet::new();
        let mut expression_count = 0;
        for column in &index.columns {
            positive_u32(column.position, "Oracle index column ordinal")?;
            if !positions.insert(column.position) {
                return Err(CatalogError::Mapping(format!(
                    "duplicate Oracle index column ordinal {} for {}.{}",
                    column.position, index.owner, index.name
                )));
            }
            let column_identity = (
                index.table_owner.clone(),
                index.table.clone(),
                column.name.clone(),
            );
            if !column_keys.contains(&column_identity) {
                return Err(CatalogError::Mapping(format!(
                    "Oracle index {}.{} references missing column {}.{}.{}",
                    index.owner, index.name, index.table_owner, index.table, column.name
                )));
            }
            let referenced_column = columns_by_identity
                .get(&column_identity)
                .copied()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle index {}.{} has no column metadata for {}",
                        index.owner, index.name, column.name
                    ))
                })?;
            match column.expression.as_deref() {
                Some(expression) => {
                    expression_count += 1;
                    if !function_based
                        || expression.trim().is_empty()
                        || !referenced_column.hidden
                        || referenced_column.user_generated
                    {
                        return Err(CatalogError::Mapping(format!(
                            "Oracle index expression metadata is inconsistent for {}.{} position {}",
                            index.owner, index.name, column.position
                        )));
                    }
                }
                None if function_based
                    && referenced_column.hidden
                    && !referenced_column.user_generated =>
                {
                    return Err(CatalogError::Mapping(format!(
                        "Oracle function-based index {}.{} is missing expression metadata at position {}",
                        index.owner, index.name, column.position
                    )));
                }
                None => {}
            }
        }
        if function_based != (expression_count > 0) {
            return Err(CatalogError::Mapping(format!(
                "Oracle index type and expression catalog disagree for {}.{}",
                index.owner, index.name
            )));
        }
        match (function_based, index.function_status.as_deref()) {
            (true, Some("ENABLED")) | (false, None) => {}
            (true, status) => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "Oracle function-based index {}.{} is not enabled (status={})",
                    index.owner,
                    index.name,
                    status.unwrap_or("missing")
                )));
            }
            (false, Some(status)) => {
                return Err(CatalogError::Mapping(format!(
                    "Oracle non-function index {}.{} unexpectedly reports function status '{status}'",
                    index.owner, index.name
                )));
            }
        }
        let expression = oracle_index_expression(index);
        if expression
            .as_ref()
            .is_some_and(|expression| expression.len() > MAX_DEFINITION_BYTES)
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle index expression exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{}",
                index.owner, index.name
            )));
        }
        if !indexes.insert((index.owner.clone(), index.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle index identity {}.{}",
                index.owner, index.name
            )));
        }
        if !inventory_keys.contains(&(index.owner.clone(), "INDEX".to_owned(), index.name.clone()))
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle index {}.{} is missing from the independent object inventory",
                index.owner, index.name
            )));
        }
    }
    let inventory_index_count = inventory
        .iter()
        .filter(|object| object.object_type == "INDEX")
        .count();
    if inventory_index_count != raw.indexes.len() + raw.lobs.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle index inventory mismatch: USER/DBA_OBJECTS reports {inventory_index_count}, regular indexes plus LOB indexes report {}",
            raw.indexes.len() + raw.lobs.len()
        )));
    }

    validate_partition_catalog(
        raw,
        scope,
        &inventory_subobject_keys,
        &tables,
        &column_keys,
        &indexes,
    )?;
    validate_lob_catalog(
        raw,
        scope,
        &inventory_keys,
        &inventory_subobject_keys,
        &tables,
        &column_keys,
    )?;

    Ok(())
}

fn validate_partition_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
    inventory_subobject_keys: &BTreeSet<(String, String, String, String)>,
    tables: &BTreeSet<(String, String)>,
    column_keys: &BTreeSet<(String, String, String)>,
    indexes: &BTreeSet<(String, String)>,
) -> Result<(), CatalogError> {
    let lob_index_names = raw
        .lobs
        .iter()
        .map(|lob| (lob.owner.clone(), lob.index_name.clone()))
        .collect::<BTreeSet<_>>();
    let raw_tables = raw
        .tables
        .iter()
        .map(|table| ((table.owner.clone(), table.name.clone()), table))
        .collect::<BTreeMap<_, _>>();
    let expected_partitioned_tables = raw
        .tables
        .iter()
        .filter(|table| table.partitioned)
        .map(|table| (table.owner.clone(), table.name.clone()))
        .collect::<BTreeSet<_>>();
    let mut partitioned_tables = BTreeMap::new();
    for table in &raw.partitioned_tables {
        ensure_owner(scope, &table.owner, "partitioned table")?;
        if !tables.contains(&(table.owner.clone(), table.table.clone()))
            || !raw_tables
                .get(&(table.owner.clone(), table.table.clone()))
                .is_some_and(|raw_table| raw_table.partitioned)
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle partition metadata references non-partitioned table {}.{}",
                table.owner, table.table
            )));
        }
        ensure_partitioning_type(
            &table.partitioning_type,
            false,
            &format!("Oracle table {}.{}", table.owner, table.table),
        )?;
        ensure_partitioning_type(
            &table.subpartitioning_type,
            true,
            &format!("Oracle table {}.{}", table.owner, table.table),
        )?;
        if table.status != "VALID"
            || table.partition_count <= 0
            || table.partitioning_key_count <= 0
            || table.default_subpartition_count < 0
            || table.subpartitioning_key_count < 0
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle partition header is malformed for {}.{}",
                table.owner, table.table
            )));
        }
        let has_subpartitions = table.subpartitioning_type != "NONE";
        if has_subpartitions
            != (table.default_subpartition_count > 0 && table.subpartitioning_key_count > 0)
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle subpartition header is inconsistent for {}.{}",
                table.owner, table.table
            )));
        }
        for (name, value) in [
            ("autolist", table.autolist.as_deref()),
            (
                "autolist_subpartition",
                table.autolist_subpartition.as_deref(),
            ),
            ("auto", table.automatic.as_deref()),
        ] {
            if let Some(value) = value {
                ensure_yes_no(
                    value,
                    &format!("Oracle table {}.{} {name}", table.owner, table.table),
                )?;
            }
        }
        let identity = (table.owner.clone(), table.table.clone());
        if partitioned_tables.insert(identity.clone(), table).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle partitioned-table header {}.{}",
                identity.0, identity.1
            )));
        }
    }
    if partitioned_tables.keys().cloned().collect::<BTreeSet<_>>() != expected_partitioned_tables {
        return Err(CatalogError::Mapping(
            "Oracle USER/DBA_PART_TABLES does not exactly match partitioned USER/DBA_TABLES rows"
                .to_owned(),
        ));
    }

    let mut table_partitions_by_table =
        BTreeMap::<(String, String), Vec<&RawTablePartition>>::new();
    let mut table_partition_identities = BTreeMap::new();
    for partition in &raw.table_partitions {
        ensure_owner(scope, &partition.owner, "table partition")?;
        let header = partitioned_tables
            .get(&(partition.owner.clone(), partition.table.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle table partition {}.{}.{} has no partitioned-table header",
                    partition.owner, partition.table, partition.name
                ))
            })?;
        positive_u32(partition.position, "Oracle table partition position")?;
        if partition.subpartition_count < 0
            || !matches!(partition.composite.as_str(), "YES" | "NO")
            || (partition.composite == "YES") != (header.subpartitioning_type != "NONE")
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle table partition metadata is malformed for {}.{}.{}",
                partition.owner, partition.table, partition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            partition.owner.clone(),
            "TABLE PARTITION".to_owned(),
            partition.table.clone(),
            partition.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle table partition {}.{}.{} is missing from the independent object inventory",
                partition.owner, partition.table, partition.name
            )));
        }
        let identity = (
            partition.owner.clone(),
            partition.table.clone(),
            partition.name.clone(),
        );
        if table_partition_identities
            .insert(identity.clone(), partition)
            .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle table partition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        table_partitions_by_table
            .entry((partition.owner.clone(), partition.table.clone()))
            .or_default()
            .push(partition);
    }
    for (identity, header) in &partitioned_tables {
        let partitions = table_partitions_by_table
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if partitions.len() != header.partition_count as usize {
            return Err(CatalogError::Mapping(format!(
                "Oracle table partition count mismatch for {}.{}",
                identity.0, identity.1
            )));
        }
        ensure_contiguous_positions(
            partitions.iter().map(|partition| partition.position),
            &format!("Oracle table partitions {}.{}", identity.0, identity.1),
        )?;
    }
    let inventory_table_partition_count = inventory_subobject_keys
        .iter()
        .filter(|key| key.1 == "TABLE PARTITION")
        .count();
    if inventory_table_partition_count != raw.table_partitions.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle table-partition inventory mismatch: USER/DBA_OBJECTS reports {inventory_table_partition_count}, USER/DBA_TAB_PARTITIONS reports {}",
            raw.table_partitions.len()
        )));
    }

    let mut table_subpartitions_by_partition =
        BTreeMap::<(String, String, String), Vec<&RawTableSubpartition>>::new();
    let mut table_subpartition_identities = BTreeSet::new();
    for subpartition in &raw.table_subpartitions {
        ensure_owner(scope, &subpartition.owner, "table subpartition")?;
        let parent = table_partition_identities
            .get(&(
                subpartition.owner.clone(),
                subpartition.table.clone(),
                subpartition.partition.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle table subpartition {}.{}.{} has no parent partition {}",
                    subpartition.owner,
                    subpartition.table,
                    subpartition.name,
                    subpartition.partition
                ))
            })?;
        positive_u32(subpartition.position, "Oracle table subpartition position")?;
        if subpartition.partition_position != parent.position {
            return Err(CatalogError::Mapping(format!(
                "Oracle table subpartition parent position mismatch for {}.{}.{}",
                subpartition.owner, subpartition.table, subpartition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            subpartition.owner.clone(),
            "TABLE SUBPARTITION".to_owned(),
            subpartition.table.clone(),
            subpartition.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle table subpartition {}.{}.{} is missing from the independent object inventory",
                subpartition.owner, subpartition.table, subpartition.name
            )));
        }
        let identity = (
            subpartition.owner.clone(),
            subpartition.table.clone(),
            subpartition.name.clone(),
        );
        if !table_subpartition_identities.insert(identity.clone()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle table subpartition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        table_subpartitions_by_partition
            .entry((
                subpartition.owner.clone(),
                subpartition.table.clone(),
                subpartition.partition.clone(),
            ))
            .or_default()
            .push(subpartition);
    }
    for (identity, parent) in &table_partition_identities {
        let subpartitions = table_subpartitions_by_partition
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if subpartitions.len() != parent.subpartition_count as usize {
            return Err(CatalogError::Mapping(format!(
                "Oracle table subpartition count mismatch for {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        ensure_contiguous_positions(
            subpartitions
                .iter()
                .map(|subpartition| subpartition.position),
            &format!(
                "Oracle table subpartitions {}.{}.{}",
                identity.0, identity.1, identity.2
            ),
        )?;
    }
    let inventory_table_subpartition_count = inventory_subobject_keys
        .iter()
        .filter(|key| key.1 == "TABLE SUBPARTITION")
        .count();
    if inventory_table_subpartition_count != raw.table_subpartitions.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle table-subpartition inventory mismatch: USER/DBA_OBJECTS reports {inventory_table_subpartition_count}, USER/DBA_TAB_SUBPARTITIONS reports {}",
            raw.table_subpartitions.len()
        )));
    }

    let raw_indexes = raw
        .indexes
        .iter()
        .map(|index| ((index.owner.clone(), index.name.clone()), index))
        .collect::<BTreeMap<_, _>>();
    let expected_partitioned_indexes = raw
        .indexes
        .iter()
        .filter(|index| index.partitioned)
        .map(|index| (index.owner.clone(), index.name.clone()))
        .collect::<BTreeSet<_>>();
    let mut partitioned_indexes = BTreeMap::new();
    for index in &raw.partitioned_indexes {
        ensure_owner(scope, &index.owner, "partitioned index")?;
        if !indexes.contains(&(index.owner.clone(), index.index.clone())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle partition metadata references missing index {}.{}",
                index.owner, index.index
            )));
        }
        let raw_index = raw_indexes
            .get(&(index.owner.clone(), index.index.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle partitioned-index header has no index {}.{}",
                    index.owner, index.index
                ))
            })?;
        if !raw_index.partitioned || raw_index.table != index.table {
            return Err(CatalogError::Mapping(format!(
                "Oracle partitioned-index header disagrees with USER/DBA_INDEXES for {}.{}",
                index.owner, index.index
            )));
        }
        ensure_partitioning_type(
            &index.partitioning_type,
            false,
            &format!("Oracle index {}.{}", index.owner, index.index),
        )?;
        ensure_partitioning_type(
            &index.subpartitioning_type,
            true,
            &format!("Oracle index {}.{}", index.owner, index.index),
        )?;
        if index.partition_count <= 0
            || index.partitioning_key_count <= 0
            || index.default_subpartition_count < 0
            || index.subpartitioning_key_count < 0
            || !matches!(index.locality.as_str(), "LOCAL" | "GLOBAL")
            || !matches!(index.alignment.as_str(), "PREFIXED" | "NON_PREFIXED")
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle partitioned-index header is malformed for {}.{}",
                index.owner, index.index
            )));
        }
        let has_subpartitions = index.subpartitioning_type != "NONE";
        if has_subpartitions
            != (index.default_subpartition_count > 0 && index.subpartitioning_key_count > 0)
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle index subpartition header is inconsistent for {}.{}",
                index.owner, index.index
            )));
        }
        for (name, value) in [
            ("autolist", index.autolist.as_deref()),
            (
                "autolist_subpartition",
                index.autolist_subpartition.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                ensure_yes_no(
                    value,
                    &format!("Oracle index {}.{} {name}", index.owner, index.index),
                )?;
            }
        }
        let identity = (index.owner.clone(), index.index.clone());
        if partitioned_indexes
            .insert(identity.clone(), index)
            .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle partitioned-index header {}.{}",
                identity.0, identity.1
            )));
        }
    }
    if partitioned_indexes.keys().cloned().collect::<BTreeSet<_>>() != expected_partitioned_indexes
    {
        return Err(CatalogError::Mapping(
            "Oracle USER/DBA_PART_INDEXES does not exactly match partitioned USER/DBA_INDEXES rows"
                .to_owned(),
        ));
    }

    let mut index_partitions_by_index =
        BTreeMap::<(String, String), Vec<&RawIndexPartition>>::new();
    let mut index_partition_identities = BTreeMap::new();
    for partition in &raw.index_partitions {
        ensure_owner(scope, &partition.owner, "index partition")?;
        let header = partitioned_indexes
            .get(&(partition.owner.clone(), partition.index.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle index partition {}.{}.{} has no partitioned-index header",
                    partition.owner, partition.index, partition.name
                ))
            })?;
        positive_u32(partition.position, "Oracle index partition position")?;
        if partition.subpartition_count < 0
            || !matches!(partition.composite.as_str(), "YES" | "NO")
            || (partition.composite == "YES") != (header.subpartitioning_type != "NONE")
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle index partition metadata is malformed for {}.{}.{}",
                partition.owner, partition.index, partition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            partition.owner.clone(),
            "INDEX PARTITION".to_owned(),
            partition.index.clone(),
            partition.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle index partition {}.{}.{} is missing from the independent object inventory",
                partition.owner, partition.index, partition.name
            )));
        }
        let identity = (
            partition.owner.clone(),
            partition.index.clone(),
            partition.name.clone(),
        );
        if index_partition_identities
            .insert(identity.clone(), partition)
            .is_some()
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle index partition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        index_partitions_by_index
            .entry((partition.owner.clone(), partition.index.clone()))
            .or_default()
            .push(partition);
    }
    for (identity, header) in &partitioned_indexes {
        let partitions = index_partitions_by_index
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if partitions.len() != header.partition_count as usize {
            return Err(CatalogError::Mapping(format!(
                "Oracle index partition count mismatch for {}.{}",
                identity.0, identity.1
            )));
        }
        ensure_contiguous_positions(
            partitions.iter().map(|partition| partition.position),
            &format!("Oracle index partitions {}.{}", identity.0, identity.1),
        )?;
    }
    let inventory_index_partition_count = inventory_subobject_keys
        .iter()
        .filter(|key| {
            key.1 == "INDEX PARTITION" && !lob_index_names.contains(&(key.0.clone(), key.2.clone()))
        })
        .count();
    if inventory_index_partition_count != raw.index_partitions.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle index-partition inventory mismatch: USER/DBA_OBJECTS reports {inventory_index_partition_count}, USER/DBA_IND_PARTITIONS reports {}",
            raw.index_partitions.len()
        )));
    }

    let mut index_subpartitions_by_partition =
        BTreeMap::<(String, String, String), Vec<&RawIndexSubpartition>>::new();
    let mut index_subpartition_identities = BTreeSet::new();
    for subpartition in &raw.index_subpartitions {
        ensure_owner(scope, &subpartition.owner, "index subpartition")?;
        let parent = index_partition_identities
            .get(&(
                subpartition.owner.clone(),
                subpartition.index.clone(),
                subpartition.partition.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle index subpartition {}.{}.{} has no parent partition {}",
                    subpartition.owner,
                    subpartition.index,
                    subpartition.name,
                    subpartition.partition
                ))
            })?;
        positive_u32(subpartition.position, "Oracle index subpartition position")?;
        if subpartition.partition_position != parent.position {
            return Err(CatalogError::Mapping(format!(
                "Oracle index subpartition parent position mismatch for {}.{}.{}",
                subpartition.owner, subpartition.index, subpartition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            subpartition.owner.clone(),
            "INDEX SUBPARTITION".to_owned(),
            subpartition.index.clone(),
            subpartition.name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle index subpartition {}.{}.{} is missing from the independent object inventory",
                subpartition.owner, subpartition.index, subpartition.name
            )));
        }
        let identity = (
            subpartition.owner.clone(),
            subpartition.index.clone(),
            subpartition.name.clone(),
        );
        if !index_subpartition_identities.insert(identity.clone()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle index subpartition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        index_subpartitions_by_partition
            .entry((
                subpartition.owner.clone(),
                subpartition.index.clone(),
                subpartition.partition.clone(),
            ))
            .or_default()
            .push(subpartition);
    }
    for (identity, parent) in &index_partition_identities {
        let subpartitions = index_subpartitions_by_partition
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if subpartitions.len() != parent.subpartition_count as usize {
            return Err(CatalogError::Mapping(format!(
                "Oracle index subpartition count mismatch for {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        ensure_contiguous_positions(
            subpartitions
                .iter()
                .map(|subpartition| subpartition.position),
            &format!(
                "Oracle index subpartitions {}.{}.{}",
                identity.0, identity.1, identity.2
            ),
        )?;
    }
    let inventory_index_subpartition_count = inventory_subobject_keys
        .iter()
        .filter(|key| {
            key.1 == "INDEX SUBPARTITION"
                && !lob_index_names.contains(&(key.0.clone(), key.2.clone()))
        })
        .count();
    if inventory_index_subpartition_count != raw.index_subpartitions.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle index-subpartition inventory mismatch: USER/DBA_OBJECTS reports {inventory_index_subpartition_count}, USER/DBA_IND_SUBPARTITIONS reports {}",
            raw.index_subpartitions.len()
        )));
    }

    let mut keys_by_object =
        BTreeMap::<(String, String, String, bool), Vec<&RawPartitionKeyColumn>>::new();
    let mut key_identities = BTreeSet::new();
    for key_column in &raw.partition_key_columns {
        ensure_owner(scope, &key_column.owner, "partition key column")?;
        if !matches!(key_column.object_type.as_str(), "TABLE" | "INDEX") {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle partition key {}.{} has unsupported object type '{}'",
                key_column.owner, key_column.name, key_column.object_type
            )));
        }
        positive_u32(key_column.position, "Oracle partition key column position")?;
        if key_column.collated_column_id.is_some_and(|id| id <= 0) {
            return Err(CatalogError::Mapping(format!(
                "Oracle partition key {}.{}.{} has invalid collated column id",
                key_column.owner, key_column.name, key_column.column
            )));
        }
        let target_table = if key_column.object_type == "TABLE" {
            key_column.name.as_str()
        } else {
            raw_indexes
                .get(&(key_column.owner.clone(), key_column.name.clone()))
                .map(|index| index.table.as_str())
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "Oracle index partition key references missing index {}.{}",
                        key_column.owner, key_column.name
                    ))
                })?
        };
        if !column_keys.contains(&(
            key_column.owner.clone(),
            target_table.to_owned(),
            key_column.column.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle partition key {}.{}.{} references a missing column",
                key_column.owner, key_column.name, key_column.column
            )));
        }
        let identity = (
            key_column.owner.clone(),
            key_column.name.clone(),
            key_column.object_type.clone(),
            key_column.subpartition,
            key_column.position,
        );
        if !key_identities.insert(identity) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle partition key position for {}.{}",
                key_column.owner, key_column.name
            )));
        }
        keys_by_object
            .entry((
                key_column.owner.clone(),
                key_column.name.clone(),
                key_column.object_type.clone(),
                key_column.subpartition,
            ))
            .or_default()
            .push(key_column);
    }
    for table in &raw.partitioned_tables {
        for (subpartition, expected) in [
            (false, table.partitioning_key_count),
            (true, table.subpartitioning_key_count),
        ] {
            let key = (
                table.owner.clone(),
                table.table.clone(),
                "TABLE".to_owned(),
                subpartition,
            );
            let columns = keys_by_object
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if columns.len() != expected as usize {
                return Err(CatalogError::Mapping(format!(
                    "Oracle table partition-key count mismatch for {}.{}",
                    table.owner, table.table
                )));
            }
            ensure_contiguous_positions(
                columns.iter().map(|column| column.position),
                &format!(
                    "Oracle table partition keys {}.{}",
                    table.owner, table.table
                ),
            )?;
        }
    }
    for index in &raw.partitioned_indexes {
        for (subpartition, expected) in [
            (false, index.partitioning_key_count),
            (true, index.subpartitioning_key_count),
        ] {
            let key = (
                index.owner.clone(),
                index.index.clone(),
                "INDEX".to_owned(),
                subpartition,
            );
            let columns = keys_by_object
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if columns.len() != expected as usize {
                return Err(CatalogError::Mapping(format!(
                    "Oracle index partition-key count mismatch for {}.{}",
                    index.owner, index.index
                )));
            }
            ensure_contiguous_positions(
                columns.iter().map(|column| column.position),
                &format!(
                    "Oracle index partition keys {}.{}",
                    index.owner, index.index
                ),
            )?;
        }
    }
    let expected_key_count = raw
        .partitioned_tables
        .iter()
        .map(|table| table.partitioning_key_count + table.subpartitioning_key_count)
        .chain(
            raw.partitioned_indexes
                .iter()
                .map(|index| index.partitioning_key_count + index.subpartitioning_key_count),
        )
        .sum::<i64>();
    if expected_key_count < 0 || raw.partition_key_columns.len() != expected_key_count as usize {
        return Err(CatalogError::Mapping(
            "Oracle partition-key catalogs contain unclaimed or missing rows".to_owned(),
        ));
    }

    Ok(())
}

fn validate_lob_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
    inventory_keys: &BTreeSet<(String, String, String)>,
    inventory_subobject_keys: &BTreeSet<(String, String, String, String)>,
    tables: &BTreeSet<(String, String)>,
    column_keys: &BTreeSet<(String, String, String)>,
) -> Result<(), CatalogError> {
    let raw_tables = raw
        .tables
        .iter()
        .map(|table| ((table.owner.clone(), table.name.clone()), table))
        .collect::<BTreeMap<_, _>>();
    let mut lobs = BTreeMap::new();
    let mut segment_names = BTreeSet::new();
    let mut index_names = BTreeSet::new();
    for lob in &raw.lobs {
        ensure_owner(scope, &lob.owner, "LOB")?;
        let table = raw_tables
            .get(&(lob.owner.clone(), lob.table.clone()))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB {}.{}.{} has no parent table",
                    lob.owner, lob.table, lob.column
                ))
            })?;
        if !tables.contains(&(lob.owner.clone(), lob.table.clone()))
            || !column_keys.contains(&(lob.owner.clone(), lob.table.clone(), lob.column.clone()))
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB {}.{}.{} has no parent column",
                lob.owner, lob.table, lob.column
            )));
        }
        ensure_yes_no(
            &lob.partitioned,
            &format!(
                "Oracle LOB {}.{}.{} partitioned",
                lob.owner, lob.table, lob.column
            ),
        )?;
        ensure_yes_no(
            &lob.securefile,
            &format!(
                "Oracle LOB {}.{}.{} securefile",
                lob.owner, lob.table, lob.column
            ),
        )?;
        if (lob.partitioned == "YES") != table.partitioned
            || lob.chunk <= 0
            || lob.pctversion.is_some_and(|value| value < 0)
            || lob.retention.is_some_and(|value| value < 0)
            || lob.freepools.is_some_and(|value| value < 0)
            || lob.retention_value.is_some_and(|value| value < 0)
            || lob.max_inline.is_some_and(|value| value < 0)
            || [
                lob.cache.as_str(),
                lob.logging.as_str(),
                lob.encrypt.as_str(),
                lob.compression.as_str(),
                lob.deduplication.as_str(),
                lob.in_row.as_str(),
                lob.format.as_str(),
                lob.segment_created.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB metadata is malformed for {}.{}.{}",
                lob.owner, lob.table, lob.column
            )));
        }
        if !inventory_keys.contains(&(
            lob.owner.clone(),
            "LOB".to_owned(),
            lob.segment_name.clone(),
        )) || !inventory_keys.contains(&(
            lob.owner.clone(),
            "INDEX".to_owned(),
            lob.index_name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB {}.{}.{} is missing its segment or index inventory row",
                lob.owner, lob.table, lob.column
            )));
        }
        if !segment_names.insert((lob.owner.clone(), lob.segment_name.clone()))
            || !index_names.insert((lob.owner.clone(), lob.index_name.clone()))
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle LOB segment or index identity for {}.{}.{}",
                lob.owner, lob.table, lob.column
            )));
        }
        let identity = (lob.owner.clone(), lob.table.clone(), lob.column.clone());
        if lobs.insert(identity.clone(), lob).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle LOB column {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
    }
    let inventory_lob_count = inventory_keys.iter().filter(|key| key.1 == "LOB").count();
    if inventory_lob_count != raw.lobs.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle LOB inventory mismatch: USER/DBA_OBJECTS reports {inventory_lob_count}, USER/DBA_LOBS reports {}",
            raw.lobs.len()
        )));
    }

    let table_partitions = raw
        .table_partitions
        .iter()
        .map(|partition| {
            (
                (
                    partition.owner.clone(),
                    partition.table.clone(),
                    partition.name.clone(),
                ),
                partition,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut lob_partitions = BTreeMap::new();
    let mut lob_partitions_by_lob =
        BTreeMap::<(String, String, String), Vec<&RawLobPartition>>::new();
    let mut lob_index_partition_names = BTreeSet::new();
    for partition in &raw.lob_partitions {
        ensure_owner(scope, &partition.owner, "LOB partition")?;
        let lob = lobs
            .get(&(
                partition.owner.clone(),
                partition.table.clone(),
                partition.column.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB partition {}.{}.{} has no parent LOB",
                    partition.owner, partition.table, partition.name
                ))
            })?;
        let table_partition = table_partitions
            .get(&(
                partition.owner.clone(),
                partition.table.clone(),
                partition.table_partition.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB partition {}.{}.{} has no table partition {}",
                    partition.owner, partition.table, partition.name, partition.table_partition
                ))
            })?;
        positive_u32(partition.position, "Oracle LOB partition position")?;
        if lob.segment_name != partition.lob_name
            || partition.position != table_partition.position
            || partition.composite != table_partition.composite
            || partition.chunk <= 0
            || partition.pctversion.is_some_and(|value| value < 0)
            || partition.max_inline.is_some_and(|value| value < 0)
            || [
                partition.cache.as_str(),
                partition.in_row.as_str(),
                partition.logging.as_str(),
                partition.encrypt.as_str(),
                partition.compression.as_str(),
                partition.deduplication.as_str(),
                partition.securefile.as_str(),
                partition.segment_created.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB partition metadata is inconsistent for {}.{}.{}",
                partition.owner, partition.table, partition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            partition.owner.clone(),
            "LOB PARTITION".to_owned(),
            partition.lob_name.clone(),
            partition.name.clone(),
        )) || !inventory_subobject_keys.contains(&(
            partition.owner.clone(),
            "INDEX PARTITION".to_owned(),
            lob.index_name.clone(),
            partition.index_partition_name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB partition {}.{}.{} is missing its segment or index inventory row",
                partition.owner, partition.table, partition.name
            )));
        }
        if !lob_index_partition_names.insert((
            partition.owner.clone(),
            lob.index_name.clone(),
            partition.index_partition_name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle LOB index partition {}.{}",
                partition.owner, partition.index_partition_name
            )));
        }
        let identity = (
            partition.owner.clone(),
            partition.lob_name.clone(),
            partition.name.clone(),
        );
        if lob_partitions.insert(identity.clone(), partition).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle LOB partition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        lob_partitions_by_lob
            .entry((
                partition.owner.clone(),
                partition.table.clone(),
                partition.column.clone(),
            ))
            .or_default()
            .push(partition);
    }
    for (identity, lob) in &lobs {
        let partitions = lob_partitions_by_lob
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let expected = if lob.partitioned == "YES" {
            raw.table_partitions
                .iter()
                .filter(|partition| partition.owner == lob.owner && partition.table == lob.table)
                .count()
        } else {
            0
        };
        if partitions.len() != expected {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB partition count mismatch for {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        ensure_contiguous_positions(
            partitions.iter().map(|partition| partition.position),
            &format!(
                "Oracle LOB partitions {}.{}.{}",
                identity.0, identity.1, identity.2
            ),
        )?;
    }
    let inventory_lob_partition_count = inventory_subobject_keys
        .iter()
        .filter(|key| key.1 == "LOB PARTITION")
        .count();
    let inventory_lob_index_partition_count = inventory_subobject_keys
        .iter()
        .filter(|key| {
            key.1 == "INDEX PARTITION" && index_names.contains(&(key.0.clone(), key.2.clone()))
        })
        .count();
    if inventory_lob_partition_count != raw.lob_partitions.len()
        || inventory_lob_index_partition_count != raw.lob_partitions.len()
        || lob_index_partition_names.len() != raw.lob_partitions.len()
    {
        return Err(CatalogError::Mapping(format!(
            "Oracle LOB-partition inventory mismatch: LOB={inventory_lob_partition_count}, INDEX={inventory_lob_index_partition_count}, catalog={}",
            lob_index_partition_names.len()
        )));
    }

    let table_subpartitions = raw
        .table_subpartitions
        .iter()
        .map(|subpartition| {
            (
                (
                    subpartition.owner.clone(),
                    subpartition.table.clone(),
                    subpartition.name.clone(),
                ),
                subpartition,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut lob_subpartition_identities = BTreeSet::new();
    let mut lob_subpartitions_by_partition =
        BTreeMap::<(String, String, String), Vec<&RawLobSubpartition>>::new();
    let mut lob_index_subpartition_names = BTreeSet::new();
    for subpartition in &raw.lob_subpartitions {
        ensure_owner(scope, &subpartition.owner, "LOB subpartition")?;
        let lob = lobs
            .get(&(
                subpartition.owner.clone(),
                subpartition.table.clone(),
                subpartition.column.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB subpartition {}.{}.{} has no parent LOB",
                    subpartition.owner, subpartition.table, subpartition.name
                ))
            })?;
        let parent = lob_partitions
            .get(&(
                subpartition.owner.clone(),
                subpartition.lob_name.clone(),
                subpartition.lob_partition_name.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB subpartition {}.{}.{} has no parent LOB partition",
                    subpartition.owner, subpartition.table, subpartition.name
                ))
            })?;
        let table_subpartition = table_subpartitions
            .get(&(
                subpartition.owner.clone(),
                subpartition.table.clone(),
                subpartition.table_subpartition.clone(),
            ))
            .copied()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle LOB subpartition {}.{}.{} has no table subpartition {}",
                    subpartition.owner,
                    subpartition.table,
                    subpartition.name,
                    subpartition.table_subpartition
                ))
            })?;
        positive_u32(subpartition.position, "Oracle LOB subpartition position")?;
        if subpartition.lob_name != lob.segment_name
            || table_subpartition.partition != parent.table_partition
            || subpartition.position != table_subpartition.position
            || subpartition.chunk <= 0
            || subpartition.pctversion.is_some_and(|value| value < 0)
            || subpartition.max_inline.is_some_and(|value| value < 0)
            || [
                subpartition.cache.as_str(),
                subpartition.in_row.as_str(),
                subpartition.logging.as_str(),
                subpartition.encrypt.as_str(),
                subpartition.compression.as_str(),
                subpartition.deduplication.as_str(),
                subpartition.securefile.as_str(),
                subpartition.segment_created.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB subpartition metadata is inconsistent for {}.{}.{}",
                subpartition.owner, subpartition.table, subpartition.name
            )));
        }
        if !inventory_subobject_keys.contains(&(
            subpartition.owner.clone(),
            "LOB SUBPARTITION".to_owned(),
            subpartition.lob_name.clone(),
            subpartition.name.clone(),
        )) || !inventory_subobject_keys.contains(&(
            subpartition.owner.clone(),
            "INDEX SUBPARTITION".to_owned(),
            lob.index_name.clone(),
            subpartition.index_subpartition_name.clone(),
        )) {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB subpartition {}.{}.{} is missing its segment or index inventory row",
                subpartition.owner, subpartition.table, subpartition.name
            )));
        }
        let identity = (
            subpartition.owner.clone(),
            subpartition.lob_name.clone(),
            subpartition.name.clone(),
        );
        if !lob_subpartition_identities.insert(identity.clone())
            || !lob_index_subpartition_names.insert((
                subpartition.owner.clone(),
                lob.index_name.clone(),
                subpartition.index_subpartition_name.clone(),
            ))
        {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle LOB subpartition {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        lob_subpartitions_by_partition
            .entry((
                subpartition.owner.clone(),
                subpartition.lob_name.clone(),
                subpartition.lob_partition_name.clone(),
            ))
            .or_default()
            .push(subpartition);
    }
    for (identity, partition) in &lob_partitions {
        let subpartitions = lob_subpartitions_by_partition
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let expected = table_partitions
            .get(&(
                partition.owner.clone(),
                partition.table.clone(),
                partition.table_partition.clone(),
            ))
            .map_or(0, |table_partition| {
                table_partition.subpartition_count as usize
            });
        if subpartitions.len() != expected {
            return Err(CatalogError::Mapping(format!(
                "Oracle LOB subpartition count mismatch for {}.{}.{}",
                identity.0, identity.1, identity.2
            )));
        }
        ensure_contiguous_positions(
            subpartitions
                .iter()
                .map(|subpartition| subpartition.position),
            &format!(
                "Oracle LOB subpartitions {}.{}.{}",
                identity.0, identity.1, identity.2
            ),
        )?;
    }
    let inventory_lob_subpartition_count = inventory_subobject_keys
        .iter()
        .filter(|key| key.1 == "LOB SUBPARTITION")
        .count();
    let inventory_lob_index_subpartition_count = inventory_subobject_keys
        .iter()
        .filter(|key| {
            key.1 == "INDEX SUBPARTITION" && index_names.contains(&(key.0.clone(), key.2.clone()))
        })
        .count();
    if inventory_lob_subpartition_count != raw.lob_subpartitions.len()
        || inventory_lob_index_subpartition_count != raw.lob_subpartitions.len()
        || lob_index_subpartition_names.len() != raw.lob_subpartitions.len()
    {
        return Err(CatalogError::Mapping(format!(
            "Oracle LOB-subpartition inventory mismatch: LOB={inventory_lob_subpartition_count}, INDEX={inventory_lob_index_subpartition_count}, catalog={}",
            lob_index_subpartition_names.len()
        )));
    }

    Ok(())
}

fn ensure_partitioning_type(
    value: &str,
    allow_none: bool,
    subject: &str,
) -> Result<(), CatalogError> {
    if matches!(
        value,
        "RANGE" | "HASH" | "LIST" | "REFERENCE" | "SYSTEM" | "CONSISTENT HASH"
    ) || (allow_none && value == "NONE")
    {
        Ok(())
    } else {
        Err(CatalogError::UnsupportedMetadata(format!(
            "{subject} has unsupported partitioning type '{value}'"
        )))
    }
}

fn ensure_contiguous_positions(
    positions: impl Iterator<Item = i64>,
    subject: &str,
) -> Result<(), CatalogError> {
    let positions = positions.collect::<Vec<_>>();
    if positions
        .iter()
        .enumerate()
        .all(|(offset, position)| *position == (offset + 1) as i64)
    {
        Ok(())
    } else {
        Err(CatalogError::Mapping(format!(
            "{subject} do not have contiguous 1-based positions"
        )))
    }
}

fn ensure_owner(scope: &DictionaryScope, owner: &str, subject: &str) -> Result<(), CatalogError> {
    if scope.contains_owner(owner) {
        Ok(())
    } else {
        Err(CatalogError::Mapping(format!(
            "Oracle {subject} owner '{owner}' is outside the certified schema scope"
        )))
    }
}

fn ensure_reference_owner(
    scope: &DictionaryScope,
    owner: &str,
    source: &str,
) -> Result<(), CatalogError> {
    if scope.contains_owner(owner) {
        Ok(())
    } else {
        Err(CatalogError::InvalidScope(format!(
            "Oracle schema selection is not relationship-closed: {source} references application owner '{owner}'; include that owner and retry"
        )))
    }
}

struct OracleSnapshotMapper<'a> {
    connection_alias: &'a str,
    facts: ServerFacts,
    strategy: OracleCatalogVersion,
    scope: DictionaryScope,
}

impl<'a> OracleSnapshotMapper<'a> {
    fn new(
        connection_alias: &'a str,
        facts: ServerFacts,
        strategy: OracleCatalogVersion,
        scope: DictionaryScope,
    ) -> Self {
        Self {
            connection_alias,
            facts,
            strategy,
            scope,
        }
    }

    fn map(self, raw: RawOracleCatalog) -> Result<CatalogDiscovery, CatalogError> {
        let database_name = self.facts.container.clone();
        let database_key = oracle_key(
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

        let schemas = self
            .scope
            .owners
            .iter()
            .map(|owner| SchemaObject {
                key: oracle_key(
                    self.connection_alias,
                    &database_name,
                    owner,
                    ObjectKind::Schema,
                    owner,
                    None,
                ),
                database_key: database_key.clone(),
                name: owner.clone(),
            })
            .collect::<Vec<_>>();
        let schema_keys = schemas
            .iter()
            .map(|schema| (schema.name.clone(), schema.key.clone()))
            .collect::<BTreeMap<_, _>>();

        let mut metadata = CanonicalMetadata::default();
        for principal in &self.scope.principals {
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &database_name,
                ObjectKind::Principal,
                &principal.name,
                None,
            );
            let mut properties = BTreeMap::new();
            insert_i64(&mut properties, "oracle_user_id", principal.user_id);
            insert_string(&mut properties, "account_status", &principal.account_status);
            insert_bool(&mut properties, "common", principal.common);
            insert_bool(
                &mut properties,
                "oracle_maintained",
                principal.oracle_maintained,
            );
            insert_optional_string(
                &mut properties,
                "default_collation",
                principal.default_collation.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(database_key.clone()),
                name: principal.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }

        let inventory = raw
            .inventory
            .iter()
            .filter(|object| !object.secondary && object.subobject.is_none())
            .map(|object| {
                (
                    (
                        object.owner.clone(),
                        object.object_type.clone(),
                        object.name.clone(),
                    ),
                    object,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let subobject_inventory = raw
            .inventory
            .iter()
            .filter(|object| !object.secondary)
            .filter_map(|object| {
                Some((
                    (
                        object.owner.clone(),
                        object.object_type.clone(),
                        object.name.clone(),
                        object.subobject.clone()?,
                    ),
                    object,
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let partitioned_tables = raw
            .partitioned_tables
            .iter()
            .map(|table| ((table.owner.clone(), table.table.clone()), table))
            .collect::<BTreeMap<_, _>>();
        let partitioned_indexes = raw
            .partitioned_indexes
            .iter()
            .map(|index| ((index.owner.clone(), index.index.clone()), index))
            .collect::<BTreeMap<_, _>>();

        let collection_by_type = raw
            .collection_types
            .iter()
            .map(|collection| {
                (
                    (collection.owner.clone(), collection.type_name.clone()),
                    collection,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut type_keys = BTreeMap::new();
        for user_type in &raw.user_types {
            let schema_key = required(
                schema_keys.get(&user_type.owner),
                format!(
                    "schema key for Oracle type {}.{}",
                    user_type.owner, user_type.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &user_type.owner,
                ObjectKind::UserDefinedType,
                &user_type.name,
                None,
            );
            type_keys.insert(
                (user_type.owner.clone(), user_type.name.clone()),
                key.clone(),
            );
            let inventory_object = required(
                inventory.get(&(
                    user_type.owner.clone(),
                    "TYPE".to_owned(),
                    user_type.name.clone(),
                )),
                format!(
                    "inventory row for Oracle type {}.{}",
                    user_type.owner, user_type.name
                ),
            )?;
            let body_inventory = inventory
                .get(&(
                    user_type.owner.clone(),
                    "TYPE BODY".to_owned(),
                    user_type.name.clone(),
                ))
                .copied();
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(schema_key.clone()),
                name: user_type.name.clone(),
                extension_kind: None,
                definition: Some(oracle_type_definition(user_type)?),
                properties: oracle_type_properties(
                    user_type,
                    inventory_object,
                    body_inventory,
                    collection_by_type
                        .get(&(user_type.owner.clone(), user_type.name.clone()))
                        .copied(),
                ),
            });
        }
        for user_type in &raw.user_types {
            let Some(supertype_owner) = user_type.supertype_owner.as_deref() else {
                continue;
            };
            let supertype_name = user_type.supertype_name.as_deref().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle type {}.{} has no supertype name",
                    user_type.owner, user_type.name
                ))
            })?;
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::InheritsFrom,
                from_key: required(
                    type_keys.get(&(user_type.owner.clone(), user_type.name.clone())),
                    format!("subtype key for {}.{}", user_type.owner, user_type.name),
                )?
                .clone(),
                to_key: required(
                    type_keys.get(&(supertype_owner.to_owned(), supertype_name.to_owned())),
                    format!("supertype key for {supertype_owner}.{supertype_name}"),
                )?
                .clone(),
                ordinal: None,
                properties: BTreeMap::new(),
            });
        }
        for attribute in &raw.type_attributes {
            let parent_key = required(
                type_keys.get(&(attribute.owner.clone(), attribute.type_name.clone())),
                format!(
                    "parent type key for Oracle attribute {}.{}.{}",
                    attribute.owner, attribute.type_name, attribute.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &attribute.owner,
                ObjectKind::Extension,
                &attribute.type_name,
                Some(format!(
                    "attribute:{}:{}",
                    attribute.position, attribute.name
                )),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(parent_key.clone()),
                name: attribute.name.clone(),
                extension_kind: Some("oracle_type_attribute".to_owned()),
                definition: None,
                properties: oracle_type_attribute_properties(attribute),
            });
            if let Some(owner) = attribute.data_type_owner.as_deref() {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), attribute.data_type_name.clone())),
                        format!(
                            "type key for Oracle attribute {}.{}.{}",
                            attribute.owner, attribute.type_name, attribute.name
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }
        for collection in &raw.collection_types {
            let Some(element_owner) = collection.element_type_owner.as_deref() else {
                continue;
            };
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::UsesType,
                from_key: required(
                    type_keys.get(&(collection.owner.clone(), collection.type_name.clone())),
                    format!(
                        "collection type key for {}.{}",
                        collection.owner, collection.type_name
                    ),
                )?
                .clone(),
                to_key: required(
                    type_keys.get(&(
                        element_owner.to_owned(),
                        collection.element_type_name.clone(),
                    )),
                    format!(
                        "element type key for {}.{}",
                        element_owner, collection.element_type_name
                    ),
                )?
                .clone(),
                ordinal: None,
                properties: BTreeMap::new(),
            });
        }

        let mut type_method_keys = BTreeMap::new();
        for method in &raw.type_methods {
            let parent_key = required(
                type_keys.get(&(method.owner.clone(), method.type_name.clone())),
                format!(
                    "parent type key for Oracle method {}.{}.{}",
                    method.owner, method.type_name, method.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &method.owner,
                ObjectKind::Routine,
                &method.type_name,
                Some(format!("method:{}:{}", method.method_number, method.name)),
            );
            type_method_keys.insert(
                (
                    method.owner.clone(),
                    method.type_name.clone(),
                    method.method_number,
                ),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: method.name.clone(),
                extension_kind: None,
                definition: None,
                properties: oracle_type_method_properties(method),
            });
        }
        for parameter in &raw.type_method_parameters {
            let method_key = required(
                type_method_keys.get(&(
                    parameter.owner.clone(),
                    parameter.type_name.clone(),
                    parameter.method_number,
                )),
                format!(
                    "method key for Oracle parameter {}.{}.{}",
                    parameter.owner, parameter.type_name, parameter.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &parameter.owner,
                ObjectKind::RoutineParameter,
                &parameter.type_name,
                Some(format!(
                    "method:{}:{}#parameter:{}:{}",
                    parameter.method_number,
                    parameter.method_name,
                    parameter.position,
                    parameter.name
                )),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(method_key.clone()),
                name: parameter.name.clone(),
                extension_kind: None,
                definition: None,
                properties: oracle_type_method_parameter_properties(parameter),
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::HasParameter,
                from_key: method_key.clone(),
                to_key: key.clone(),
                ordinal: Some(positive_u32(
                    parameter.position + 1,
                    "Oracle type method parameter relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
            if let Some(owner) = parameter.data_type_owner.as_deref() {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), parameter.data_type_name.clone())),
                        format!(
                            "type key for Oracle method parameter {}.{}.{}",
                            parameter.owner, parameter.type_name, parameter.name
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let mut sequence_keys = BTreeMap::new();
        for sequence in &raw.sequences {
            let schema_key = required(
                schema_keys.get(&sequence.owner),
                format!(
                    "schema key for Oracle sequence {}.{}",
                    sequence.owner, sequence.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &sequence.owner,
                ObjectKind::Sequence,
                &sequence.name,
                None,
            );
            sequence_keys.insert((sequence.owner.clone(), sequence.name.clone()), key.clone());
            let inventory_object = required(
                inventory.get(&(
                    sequence.owner.clone(),
                    "SEQUENCE".to_owned(),
                    sequence.name.clone(),
                )),
                format!(
                    "inventory row for Oracle sequence {}.{}",
                    sequence.owner, sequence.name
                ),
            )?;
            let mut properties = inventory_properties(inventory_object);
            insert_optional_string(&mut properties, "minimum", sequence.min_value.as_deref());
            insert_optional_string(&mut properties, "maximum", sequence.max_value.as_deref());
            insert_string(&mut properties, "increment", &sequence.increment_by);
            insert_string(&mut properties, "cache_size", &sequence.cache_size);
            insert_optional_string(&mut properties, "cycle", sequence.cycle.as_deref());
            insert_optional_string(&mut properties, "ordered", sequence.ordered.as_deref());
            insert_optional_string(&mut properties, "scale", sequence.scale.as_deref());
            insert_optional_string(&mut properties, "extend", sequence.extend.as_deref());
            insert_optional_string(&mut properties, "sharded", sequence.sharded.as_deref());
            insert_optional_string(&mut properties, "session", sequence.session.as_deref());
            insert_optional_string(
                &mut properties,
                "keep_value",
                sequence.keep_value.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(schema_key.clone()),
                name: sequence.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }

        let materialized_view_names = raw
            .materialized_views
            .iter()
            .map(|view| (view.owner.clone(), view.name.clone()))
            .collect::<BTreeSet<_>>();
        let mut materialized_view_keys = BTreeMap::new();
        for view in &raw.materialized_views {
            let schema_key = required(
                schema_keys.get(&view.owner),
                format!(
                    "schema key for Oracle materialized view {}.{}",
                    view.owner, view.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &view.owner,
                ObjectKind::MaterializedView,
                &view.name,
                None,
            );
            materialized_view_keys.insert((view.owner.clone(), view.name.clone()), key.clone());
            let inventory_object = required(
                inventory.get(&(
                    view.owner.clone(),
                    "MATERIALIZED VIEW".to_owned(),
                    view.name.clone(),
                )),
                format!(
                    "inventory row for Oracle materialized view {}.{}",
                    view.owner, view.name
                ),
            )?;
            let mut properties = inventory_properties(inventory_object);
            let storage_object = required(
                inventory.get(&(
                    view.owner.clone(),
                    "TABLE".to_owned(),
                    view.container_name.clone(),
                )),
                format!(
                    "storage inventory row for Oracle materialized view {}.{}",
                    view.owner, view.name
                ),
            )?;
            insert_i64(
                &mut properties,
                "storage_object_id",
                storage_object.object_id,
            );
            insert_optional_i64(
                &mut properties,
                "storage_data_object_id",
                storage_object.data_object_id,
            );
            insert_string(
                &mut properties,
                "storage_object_status",
                &storage_object.status,
            );
            insert_bool(
                &mut properties,
                "storage_generated",
                storage_object.generated,
            );
            insert_string(&mut properties, "container_name", &view.container_name);
            insert_optional_i64(&mut properties, "query_length", view.query_length);
            insert_optional_string(&mut properties, "updatable", view.updatable.as_deref());
            insert_optional_string(
                &mut properties,
                "rewrite_enabled",
                view.rewrite_enabled.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "rewrite_capability",
                view.rewrite_capability.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "refresh_mode",
                view.refresh_mode.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "refresh_method",
                view.refresh_method.as_deref(),
            );
            insert_optional_string(&mut properties, "build_mode", view.build_mode.as_deref());
            insert_optional_string(
                &mut properties,
                "fast_refreshable",
                view.fast_refreshable.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "compile_state",
                view.compile_state.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "use_no_index",
                view.use_no_index.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "segment_created",
                view.segment_created.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "default_collation",
                view.default_collation.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "on_query_computation",
                view.on_query_computation.as_deref(),
            );
            insert_optional_string(&mut properties, "automatic", view.automatic.as_deref());
            insert_optional_string(
                &mut properties,
                "concurrent_refresh",
                view.concurrent_refresh.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(schema_key.clone()),
                name: view.name.clone(),
                extension_kind: None,
                definition: view.definition.clone(),
                properties,
            });
        }

        let mut tables = Vec::new();
        let mut table_keys = BTreeMap::new();
        for table in &raw.tables {
            if materialized_view_names.contains(&(table.owner.clone(), table.name.clone())) {
                continue;
            }
            let schema_key = required(
                schema_keys.get(&table.owner),
                format!("schema key for Oracle table {}.{}", table.owner, table.name),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &table.owner,
                ObjectKind::Table,
                &table.name,
                None,
            );
            table_keys.insert((table.owner.clone(), table.name.clone()), key.clone());
            tables.push(TableObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: table.name.clone(),
                kind: if table.partitioned {
                    TableKind::Partitioned
                } else if table.temporary {
                    TableKind::Temporary
                } else {
                    TableKind::BaseTable
                },
            });
            let inventory_object = required(
                inventory.get(&(table.owner.clone(), "TABLE".to_owned(), table.name.clone())),
                format!(
                    "inventory row for Oracle table {}.{}",
                    table.owner, table.name
                ),
            )?;
            let mut properties = inventory_properties(inventory_object);
            insert_string(&mut properties, "table_status", &table.status);
            insert_bool(&mut properties, "temporary", table.temporary);
            insert_bool(&mut properties, "read_only", table.read_only);
            insert_bool(&mut properties, "has_identity", table.has_identity);
            insert_optional_string(&mut properties, "duration", table.duration.as_deref());
            if let Some(partitioning) =
                partitioned_tables.get(&(table.owner.clone(), table.name.clone()))
            {
                add_oracle_partitioned_table_properties(
                    &mut properties,
                    partitioning,
                    &raw.partition_key_columns,
                );
            }
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties,
            });
        }

        let mut views = Vec::new();
        let mut view_keys = BTreeMap::new();
        let mut view_positions = BTreeMap::new();
        for view in &raw.views {
            let schema_key = required(
                schema_keys.get(&view.owner),
                format!("schema key for Oracle view {}.{}", view.owner, view.name),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &view.owner,
                ObjectKind::View,
                &view.name,
                None,
            );
            view_keys.insert((view.owner.clone(), view.name.clone()), key.clone());
            view_positions.insert((view.owner.clone(), view.name.clone()), views.len());
            views.push(ViewObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: view.name.clone(),
                definition: view.definition.clone(),
                depends_on: Vec::new(),
            });
            let inventory_object = required(
                inventory.get(&(view.owner.clone(), "VIEW".to_owned(), view.name.clone())),
                format!("inventory row for Oracle view {}.{}", view.owner, view.name),
            )?;
            let mut properties = inventory_properties(inventory_object);
            insert_optional_i64(&mut properties, "text_length", view.text_length);
            insert_optional_string(&mut properties, "editioning", view.editioning.as_deref());
            insert_optional_string(&mut properties, "read_only", view.read_only.as_deref());
            insert_optional_string(
                &mut properties,
                "container_data",
                view.container_data.as_deref(),
            );
            insert_optional_string(&mut properties, "bequeath", view.bequeath.as_deref());
            insert_optional_string(
                &mut properties,
                "default_collation",
                view.default_collation.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "has_sensitive_column",
                view.has_sensitive_column.as_deref(),
            );
            insert_optional_string(&mut properties, "admit_null", view.admit_null.as_deref());
            insert_optional_string(
                &mut properties,
                "pdb_local_only",
                view.pdb_local_only.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "duality_view",
                view.duality_view.as_deref(),
            );
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties,
            });
        }

        for column in &raw.view_columns {
            let view_key = required(
                view_keys.get(&(column.owner.clone(), column.table.clone())),
                format!(
                    "view key for Oracle output column {}.{}.{}",
                    column.owner, column.table, column.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &column.owner,
                ObjectKind::ViewColumn,
                &column.table,
                Some(column.name.clone()),
            );
            let mut properties = oracle_column_properties(column);
            insert_i64(
                &mut properties,
                "ordinal_position",
                i64::from(positive_u32(
                    column.internal_column_id,
                    "Oracle view-column ordinal",
                )?),
            );
            insert_string(
                &mut properties,
                "data_type",
                format_oracle_data_type(column),
            );
            insert_bool(&mut properties, "nullable", column.nullable);
            insert_optional_string(
                &mut properties,
                "default_value",
                column.default_value.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(view_key.clone()),
                name: column.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            if let Some(owner) = column.data_type_owner.as_deref() {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), column.data_type.clone())),
                        format!(
                            "type key for Oracle view column {}.{}.{}",
                            column.owner, column.table, column.name
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let mut materialized_view_column_keys = BTreeMap::new();
        for column in raw.columns.iter().filter(|column| {
            materialized_view_names.contains(&(column.owner.clone(), column.table.clone()))
        }) {
            let view_key = required(
                materialized_view_keys.get(&(column.owner.clone(), column.table.clone())),
                format!(
                    "materialized-view key for Oracle output column {}.{}.{}",
                    column.owner, column.table, column.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &column.owner,
                ObjectKind::ViewColumn,
                &column.table,
                Some(column.name.clone()),
            );
            materialized_view_column_keys.insert(
                (
                    column.owner.clone(),
                    column.table.clone(),
                    column.name.clone(),
                ),
                key.clone(),
            );
            let mut properties = oracle_column_properties(column);
            insert_i64(
                &mut properties,
                "ordinal_position",
                i64::from(positive_u32(
                    column.internal_column_id,
                    "Oracle materialized-view column ordinal",
                )?),
            );
            insert_string(
                &mut properties,
                "data_type",
                format_oracle_data_type(column),
            );
            insert_bool(&mut properties, "nullable", column.nullable);
            insert_optional_string(
                &mut properties,
                "default_value",
                column.default_value.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(view_key.clone()),
                name: column.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
            if let Some(owner) = column.data_type_owner.as_deref() {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), column.data_type.clone())),
                        format!(
                            "type key for Oracle materialized-view column {}.{}.{}",
                            column.owner, column.table, column.name
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let mut routines = Vec::new();
        let mut routine_keys = BTreeMap::new();
        let mut routine_positions = BTreeMap::new();
        for routine in &raw.routines {
            let schema_key = required(
                schema_keys.get(&routine.owner),
                format!(
                    "schema key for Oracle routine {}.{}",
                    routine.owner, routine.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &routine.owner,
                ObjectKind::Routine,
                &routine.name,
                None,
            );
            let identity = (
                routine.owner.clone(),
                routine.name.clone(),
                routine.object_type.clone(),
            );
            routine_keys.insert(identity.clone(), key.clone());
            routine_positions.insert(identity, routines.len());
            routines.push(RoutineObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: routine.name.clone(),
                kind: match routine.object_type.as_str() {
                    "FUNCTION" => RoutineKind::Function,
                    "PROCEDURE" => RoutineKind::Procedure,
                    other => {
                        return Err(CatalogError::Mapping(format!(
                            "unmapped Oracle routine type '{other}'"
                        )));
                    }
                },
                definition: routine.definition.clone(),
                depends_on: Vec::new(),
            });
            let inventory_object = required(
                inventory.get(&(
                    routine.owner.clone(),
                    routine.object_type.clone(),
                    routine.name.clone(),
                )),
                format!(
                    "inventory row for Oracle routine {}.{}",
                    routine.owner, routine.name
                ),
            )?;
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties: oracle_routine_properties(routine, inventory_object),
            });
        }
        for argument in &raw.routine_arguments {
            let routine = raw
                .routines
                .iter()
                .find(|routine| routine.owner == argument.owner && routine.name == argument.routine)
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "parent routine for Oracle argument {}.{}",
                        argument.owner, argument.routine
                    ))
                })?;
            let routine_key = required(
                routine_keys.get(&(
                    routine.owner.clone(),
                    routine.name.clone(),
                    routine.object_type.clone(),
                )),
                format!(
                    "parent key for Oracle argument {}.{}",
                    argument.owner, argument.routine
                ),
            )?;
            let display_name = if argument.position == 0 {
                "RETURN".to_owned()
            } else {
                argument
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("ARGUMENT_{}", argument.position))
            };
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &argument.owner,
                ObjectKind::RoutineParameter,
                &argument.routine,
                Some(format!("{}:{display_name}", argument.sequence)),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(routine_key.clone()),
                name: display_name,
                extension_kind: None,
                definition: argument.default_value.clone(),
                properties: oracle_routine_argument_properties(argument),
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::HasParameter,
                from_key: routine_key.clone(),
                to_key: key.clone(),
                ordinal: Some(positive_u32(
                    argument.sequence,
                    "Oracle routine argument relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
            if let (Some(owner), Some(name)) = (
                argument.type_owner.as_deref(),
                argument.type_name.as_deref(),
            ) {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), name.to_owned())),
                        format!(
                            "type key for Oracle routine argument {}.{}",
                            argument.owner, argument.routine
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let mut package_keys = BTreeMap::new();
        for package in &raw.packages {
            let schema_key = required(
                schema_keys.get(&package.owner),
                format!(
                    "schema key for Oracle package {}.{}",
                    package.owner, package.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &package.owner,
                ObjectKind::Package,
                &package.name,
                None,
            );
            package_keys.insert((package.owner.clone(), package.name.clone()), key.clone());
            let inventory_object = required(
                inventory.get(&(
                    package.owner.clone(),
                    "PACKAGE".to_owned(),
                    package.name.clone(),
                )),
                format!(
                    "inventory row for Oracle package {}.{}",
                    package.owner, package.name
                ),
            )?;
            let body_inventory = inventory
                .get(&(
                    package.owner.clone(),
                    "PACKAGE BODY".to_owned(),
                    package.name.clone(),
                ))
                .copied();
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(schema_key.clone()),
                name: package.name.clone(),
                extension_kind: None,
                definition: Some(oracle_package_definition(package)?),
                properties: oracle_package_properties(package, inventory_object, body_inventory),
            });
        }
        let package_arguments_by_routine = raw.package_arguments.iter().fold(
            BTreeMap::<(String, String, i64), Vec<&RawRoutineArgument>>::new(),
            |mut map, argument| {
                if let Some(package) = argument.package_name.as_deref() {
                    map.entry((
                        argument.owner.clone(),
                        package.to_owned(),
                        argument.subprogram_id,
                    ))
                    .or_default()
                    .push(argument);
                }
                map
            },
        );
        let mut package_routine_keys = BTreeMap::new();
        let mut package_routine_signatures = BTreeMap::new();
        for routine in &raw.package_routines {
            let package_key = required(
                package_keys.get(&(routine.owner.clone(), routine.package.clone())),
                format!(
                    "package key for Oracle routine {}.{}.{}",
                    routine.owner, routine.package, routine.name
                ),
            )?;
            let arguments = package_arguments_by_routine
                .get(&(
                    routine.owner.clone(),
                    routine.package.clone(),
                    routine.subprogram_id,
                ))
                .map(Vec::as_slice)
                .unwrap_or_default();
            let signature = oracle_package_routine_signature(routine, arguments)?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &routine.owner,
                ObjectKind::Routine,
                &routine.package,
                Some(signature.clone()),
            );
            let identity = (
                routine.owner.clone(),
                routine.package.clone(),
                routine.subprogram_id,
            );
            package_routine_keys.insert(identity.clone(), key.clone());
            package_routine_signatures.insert(identity, signature.clone());
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(package_key.clone()),
                name: routine.name.clone(),
                extension_kind: None,
                definition: None,
                properties: oracle_package_routine_properties(routine, &signature),
            });
        }
        for argument in &raw.package_arguments {
            let package_name = argument.package_name.as_deref().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle package argument {}.{} has no package",
                    argument.owner, argument.routine
                ))
            })?;
            let identity = (
                argument.owner.clone(),
                package_name.to_owned(),
                argument.subprogram_id,
            );
            let routine_key = required(
                package_routine_keys.get(&identity),
                format!(
                    "package routine key for Oracle argument {}.{}.{}",
                    argument.owner, package_name, argument.routine
                ),
            )?;
            let signature = required(
                package_routine_signatures.get(&identity),
                format!(
                    "package routine signature for Oracle argument {}.{}.{}",
                    argument.owner, package_name, argument.routine
                ),
            )?;
            let display_name = if argument.position == 0 {
                "RETURN".to_owned()
            } else {
                argument
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("ARGUMENT_{}", argument.position))
            };
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &argument.owner,
                ObjectKind::RoutineParameter,
                package_name,
                Some(format!("{signature}#{}:{display_name}", argument.sequence)),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(routine_key.clone()),
                name: display_name,
                extension_kind: None,
                definition: argument.default_value.clone(),
                properties: oracle_routine_argument_properties(argument),
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::HasParameter,
                from_key: routine_key.clone(),
                to_key: key.clone(),
                ordinal: Some(positive_u32(
                    argument.sequence,
                    "Oracle package argument relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
            if let (Some(owner), Some(name)) = (
                argument.type_owner.as_deref(),
                argument.type_name.as_deref(),
            ) {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), name.to_owned())),
                        format!(
                            "type key for Oracle package argument {}.{}.{}",
                            argument.owner, package_name, argument.routine
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let mut synonym_keys = BTreeMap::new();
        for synonym in &raw.synonyms {
            let schema_key = required(
                schema_keys.get(&synonym.owner),
                format!(
                    "schema key for Oracle synonym {}.{}",
                    synonym.owner, synonym.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &synonym.owner,
                ObjectKind::Synonym,
                &synonym.name,
                None,
            );
            synonym_keys.insert((synonym.owner.clone(), synonym.name.clone()), key.clone());
            let inventory_object = required(
                inventory.get(&(
                    synonym.owner.clone(),
                    "SYNONYM".to_owned(),
                    synonym.name.clone(),
                )),
                format!(
                    "inventory row for Oracle synonym {}.{}",
                    synonym.owner, synonym.name
                ),
            )?;
            let mut properties = inventory_properties(inventory_object);
            insert_string(&mut properties, "target_owner", &synonym.target_owner);
            insert_string(&mut properties, "target_name", &synonym.target_name);
            insert_optional_string(
                &mut properties,
                "database_link",
                synonym.database_link.as_deref(),
            );
            insert_i64(
                &mut properties,
                "origin_container_id",
                synonym.origin_container_id,
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(schema_key.clone()),
                name: synonym.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
        }
        for dependency in raw
            .dependencies
            .iter()
            .filter(|dependency| dependency.object_type == "SYNONYM")
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        {
            let source_key = required(
                synonym_keys.get(&(dependency.owner.clone(), dependency.name.clone())),
                format!(
                    "source key for Oracle synonym dependency {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            let target_key = match dependency.referenced_type.as_str() {
                "TABLE" => match materialized_view_keys.get(&(
                    dependency.referenced_owner.clone(),
                    dependency.referenced_name.clone(),
                )) {
                    Some(key) => key,
                    None => required(
                        table_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "table target for Oracle synonym dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                },
                "VIEW" => required(
                    view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "view target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "MATERIALIZED VIEW" => required(
                    materialized_view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "materialized-view target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "SEQUENCE" => required(
                    sequence_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "sequence target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "FUNCTION" | "PROCEDURE" => required(
                    routine_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                        dependency.referenced_type.clone(),
                    )),
                    format!(
                        "routine target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "PACKAGE" => required(
                    package_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "package target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "SYNONYM" => required(
                    synonym_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "synonym target for Oracle dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "TYPE" => required(
                    type_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "type target for Oracle synonym dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle synonym target type '{other}'"
                    )));
                }
            };
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::SynonymFor,
                from_key: source_key.clone(),
                to_key: target_key.clone(),
                ordinal: None,
                properties: BTreeMap::from([(
                    "oracle_dependency_type".to_owned(),
                    MetadataValue::String(dependency.dependency_type.clone()),
                )]),
            });
        }

        for dependency in &raw.dependencies {
            if dependency.object_type != "VIEW" || dependency.referenced_owner_oracle_maintained {
                continue;
            }
            let source_position = required(
                view_positions.get(&(dependency.owner.clone(), dependency.name.clone())),
                format!(
                    "view position for Oracle dependency {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            let target_key = match dependency.referenced_type.as_str() {
                "TABLE" => match materialized_view_keys.get(&(
                    dependency.referenced_owner.clone(),
                    dependency.referenced_name.clone(),
                )) {
                    Some(key) => key,
                    None => required(
                        table_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "table target for Oracle view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                },
                "VIEW" => required(
                    view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "view target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "MATERIALIZED VIEW" => required(
                    materialized_view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "materialized-view target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "SEQUENCE" => required(
                    sequence_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "sequence target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "FUNCTION" | "PROCEDURE" => required(
                    routine_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                        dependency.referenced_type.clone(),
                    )),
                    format!(
                        "routine target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "PACKAGE" => required(
                    package_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "package target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "TYPE" => required(
                    type_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "type target for Oracle view dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle view dependency target type '{other}'"
                    )));
                }
            };
            if dependency.referenced_type == "TYPE" {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: views[*source_position].key.clone(),
                    to_key: target_key.clone(),
                    ordinal: None,
                    properties: BTreeMap::from([(
                        "oracle_dependency_type".to_owned(),
                        MetadataValue::String(dependency.dependency_type.clone()),
                    )]),
                });
            } else {
                views[*source_position].depends_on.push(target_key.clone());
            }
        }

        for dependency in raw
            .dependencies
            .iter()
            .filter(|dependency| dependency.object_type == "MATERIALIZED VIEW")
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        {
            if dependency.referenced_type == "TABLE"
                && dependency.owner == dependency.referenced_owner
                && dependency.name == dependency.referenced_name
            {
                continue;
            }
            let source_key = required(
                materialized_view_keys.get(&(dependency.owner.clone(), dependency.name.clone())),
                format!(
                    "source key for Oracle materialized-view dependency {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            let (target_key, relationship_kind) = match dependency.referenced_type.as_str() {
                "TABLE" => match materialized_view_keys.get(&(
                    dependency.referenced_owner.clone(),
                    dependency.referenced_name.clone(),
                )) {
                    Some(key) => (key, MetadataRelationshipKind::DependsOn),
                    None => (
                        required(
                            table_keys.get(&(
                                dependency.referenced_owner.clone(),
                                dependency.referenced_name.clone(),
                            )),
                            format!(
                                "table target for Oracle materialized-view dependency {}.{}",
                                dependency.referenced_owner, dependency.referenced_name
                            ),
                        )?,
                        MetadataRelationshipKind::Materializes,
                    ),
                },
                "VIEW" => (
                    required(
                        view_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "view target for Oracle materialized-view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::Materializes,
                ),
                "MATERIALIZED VIEW" => (
                    required(
                        materialized_view_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "materialized-view target for Oracle dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "SEQUENCE" => (
                    required(
                        sequence_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "sequence target for Oracle materialized-view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "FUNCTION" | "PROCEDURE" => (
                    required(
                        routine_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                            dependency.referenced_type.clone(),
                        )),
                        format!(
                            "routine target for Oracle materialized-view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "PACKAGE" => (
                    required(
                        package_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "package target for Oracle materialized-view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "TYPE" => (
                    required(
                        type_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "type target for Oracle materialized-view dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle materialized-view dependency target type '{other}'"
                    )));
                }
            };
            let mut properties = BTreeMap::new();
            insert_string(
                &mut properties,
                "oracle_dependency_type",
                &dependency.dependency_type,
            );
            metadata.relationships.push(MetadataRelationship {
                kind: relationship_kind,
                from_key: source_key.clone(),
                to_key: target_key.clone(),
                ordinal: None,
                properties,
            });
        }

        for dependency in raw
            .dependencies
            .iter()
            .filter(|dependency| {
                matches!(dependency.object_type.as_str(), "FUNCTION" | "PROCEDURE")
            })
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        {
            let source_identity = (
                dependency.owner.clone(),
                dependency.name.clone(),
                dependency.object_type.clone(),
            );
            let source_position = required(
                routine_positions.get(&source_identity),
                format!(
                    "source position for Oracle routine dependency {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            let target_key = match dependency.referenced_type.as_str() {
                "TABLE" => match materialized_view_keys.get(&(
                    dependency.referenced_owner.clone(),
                    dependency.referenced_name.clone(),
                )) {
                    Some(key) => key,
                    None => required(
                        table_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "table target for Oracle routine dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                },
                "VIEW" => required(
                    view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "view target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "MATERIALIZED VIEW" => required(
                    materialized_view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "materialized-view target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "SEQUENCE" => required(
                    sequence_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "sequence target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "FUNCTION" | "PROCEDURE" => required(
                    routine_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                        dependency.referenced_type.clone(),
                    )),
                    format!(
                        "routine target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "PACKAGE" => required(
                    package_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "package target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                "TYPE" => required(
                    type_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )),
                    format!(
                        "type target for Oracle routine dependency {}.{}",
                        dependency.referenced_owner, dependency.referenced_name
                    ),
                )?,
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle routine dependency target type '{other}'"
                    )));
                }
            };
            if dependency.referenced_type == "TYPE" {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::DependsOn,
                    from_key: routines[*source_position].key.clone(),
                    to_key: target_key.clone(),
                    ordinal: None,
                    properties: BTreeMap::from([(
                        "oracle_dependency_type".to_owned(),
                        MetadataValue::String(dependency.dependency_type.clone()),
                    )]),
                });
            } else {
                routines[*source_position]
                    .depends_on
                    .push(target_key.clone());
            }
        }

        for (identity, evidence) in oracle_package_dependency_groups(&raw.dependencies) {
            let (owner, package, referenced_owner, referenced_name, referenced_type) = identity;
            let source_key = required(
                package_keys.get(&(owner.clone(), package.clone())),
                format!("source key for Oracle package dependency {owner}.{package}"),
            )?;
            let target_key = match referenced_type.as_str() {
                "TABLE" => match materialized_view_keys
                    .get(&(referenced_owner.clone(), referenced_name.clone()))
                {
                    Some(key) => key,
                    None => required(
                        table_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                        format!(
                            "table target for Oracle package dependency {referenced_owner}.{referenced_name}"
                        ),
                    )?,
                },
                "VIEW" => required(
                    view_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "view target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "MATERIALIZED VIEW" => required(
                    materialized_view_keys
                        .get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "materialized-view target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "SEQUENCE" => required(
                    sequence_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "sequence target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "FUNCTION" | "PROCEDURE" => required(
                    routine_keys.get(&(
                        referenced_owner.clone(),
                        referenced_name.clone(),
                        referenced_type.clone(),
                    )),
                    format!(
                        "routine target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "PACKAGE" => required(
                    package_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "package target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "TYPE" => required(
                    type_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "type target for Oracle package dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle package dependency target type '{other}'"
                    )));
                }
            };
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::DependsOn,
                from_key: source_key.clone(),
                to_key: target_key.clone(),
                ordinal: None,
                properties: BTreeMap::from([
                    (
                        "oracle_source_object_types".to_owned(),
                        MetadataValue::StringList(
                            evidence.source_object_types.into_iter().collect(),
                        ),
                    ),
                    (
                        "oracle_dependency_types".to_owned(),
                        MetadataValue::StringList(evidence.dependency_types.into_iter().collect()),
                    ),
                ]),
            });
        }

        for (identity, evidence) in oracle_type_dependency_groups(&raw.dependencies) {
            let (owner, type_name, referenced_owner, referenced_name, referenced_type) = identity;
            let source_key = required(
                type_keys.get(&(owner.clone(), type_name.clone())),
                format!("source key for Oracle type dependency {owner}.{type_name}"),
            )?;
            let target_key = match referenced_type.as_str() {
                "TABLE" => match materialized_view_keys
                    .get(&(referenced_owner.clone(), referenced_name.clone()))
                {
                    Some(key) => key,
                    None => required(
                        table_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                        format!(
                            "table target for Oracle type dependency {referenced_owner}.{referenced_name}"
                        ),
                    )?,
                },
                "VIEW" => required(
                    view_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "view target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "MATERIALIZED VIEW" => required(
                    materialized_view_keys
                        .get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "materialized-view target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "SEQUENCE" => required(
                    sequence_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "sequence target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "FUNCTION" | "PROCEDURE" => required(
                    routine_keys.get(&(
                        referenced_owner.clone(),
                        referenced_name.clone(),
                        referenced_type.clone(),
                    )),
                    format!(
                        "routine target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "PACKAGE" => required(
                    package_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "package target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "SYNONYM" => required(
                    synonym_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "synonym target for Oracle type dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                "TYPE" => required(
                    type_keys.get(&(referenced_owner.clone(), referenced_name.clone())),
                    format!(
                        "type target for Oracle dependency {referenced_owner}.{referenced_name}"
                    ),
                )?,
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle type dependency target type '{other}'"
                    )));
                }
            };
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::DependsOn,
                from_key: source_key.clone(),
                to_key: target_key.clone(),
                ordinal: None,
                properties: BTreeMap::from([
                    (
                        "oracle_source_object_types".to_owned(),
                        MetadataValue::StringList(
                            evidence.source_object_types.into_iter().collect(),
                        ),
                    ),
                    (
                        "oracle_dependency_types".to_owned(),
                        MetadataValue::StringList(evidence.dependency_types.into_iter().collect()),
                    ),
                ]),
            });
        }

        let identities = raw
            .identity_columns
            .iter()
            .map(|identity| {
                (
                    (
                        identity.owner.clone(),
                        identity.table.clone(),
                        identity.column.clone(),
                    ),
                    identity,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut columns = Vec::new();
        let mut column_keys = BTreeMap::new();
        for column in &raw.columns {
            if materialized_view_names.contains(&(column.owner.clone(), column.table.clone())) {
                continue;
            }
            let table_key = required(
                table_keys.get(&(column.owner.clone(), column.table.clone())),
                format!(
                    "table key for Oracle column {}.{}.{}",
                    column.owner, column.table, column.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
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
                key.clone(),
            );
            columns.push(ColumnObject {
                key: key.clone(),
                table_key: table_key.clone(),
                name: column.name.clone(),
                ordinal_position: positive_u32(
                    column.internal_column_id,
                    "Oracle internal column ordinal",
                )?,
                data_type: format_oracle_data_type(column),
                is_nullable: column.nullable,
                default_value: column.default_value.clone(),
                is_generated: column.virtual_column
                    || column.hidden
                    || !column.user_generated
                    || column.identity,
            });
            let mut properties = oracle_column_properties(column);
            if let Some(identity) = identities.get(&(
                column.owner.clone(),
                column.table.clone(),
                column.name.clone(),
            )) {
                insert_optional_string(
                    &mut properties,
                    "identity_generation_type",
                    identity.generation_type.as_deref(),
                );
                insert_optional_string(
                    &mut properties,
                    "identity_options",
                    identity.options.as_deref(),
                );
                let sequence_key = required(
                    sequence_keys.get(&(identity.owner.clone(), identity.sequence_name.clone())),
                    format!(
                        "identity sequence key {}.{}",
                        identity.owner, identity.sequence_name
                    ),
                )?;
                let mut relationship_properties = BTreeMap::new();
                insert_optional_string(
                    &mut relationship_properties,
                    "generation_type",
                    identity.generation_type.as_deref(),
                );
                insert_optional_string(
                    &mut relationship_properties,
                    "identity_options",
                    identity.options.as_deref(),
                );
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesSequence,
                    from_key: key.clone(),
                    to_key: sequence_key.clone(),
                    ordinal: None,
                    properties: relationship_properties,
                });
            }
            metadata.annotations.push(ObjectAnnotation {
                object_key: key.clone(),
                definition: None,
                properties,
            });
            if let Some(owner) = column.data_type_owner.as_deref() {
                metadata.relationships.push(MetadataRelationship {
                    kind: MetadataRelationshipKind::UsesType,
                    from_key: key,
                    to_key: required(
                        type_keys.get(&(owner.to_owned(), column.data_type.clone())),
                        format!(
                            "type key for Oracle column {}.{}.{}",
                            column.owner, column.table, column.name
                        ),
                    )?
                    .clone(),
                    ordinal: None,
                    properties: BTreeMap::new(),
                });
            }
        }

        let constraint_by_identity = raw
            .constraints
            .iter()
            .map(|constraint| {
                (
                    (constraint.owner.clone(), constraint.name.clone()),
                    constraint,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut constraints = Vec::new();
        for constraint in &raw.constraints {
            if let Some(materialized_view_key) =
                materialized_view_keys.get(&(constraint.owner.clone(), constraint.table.clone()))
            {
                let object_kind = match constraint.constraint_type.as_str() {
                    "P" => ObjectKind::PrimaryKey,
                    "U" => ObjectKind::UniqueConstraint,
                    "C" => ObjectKind::CheckConstraint,
                    other => {
                        return Err(CatalogError::Mapping(format!(
                            "unmapped Oracle materialized-view constraint type '{other}'"
                        )));
                    }
                };
                let key = oracle_key(
                    self.connection_alias,
                    &database_name,
                    &constraint.owner,
                    object_kind,
                    &constraint.table,
                    Some(constraint.name.clone()),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(materialized_view_key.clone()),
                    name: constraint.name.clone(),
                    extension_kind: None,
                    definition: constraint.search_condition.clone(),
                    properties: constraint_properties(constraint),
                });
                for column in &constraint.columns {
                    let column_key = required(
                        materialized_view_column_keys.get(&(
                            constraint.owner.clone(),
                            constraint.table.clone(),
                            column.name.clone(),
                        )),
                        format!(
                            "column {} for Oracle materialized-view constraint {}.{}",
                            column.name, constraint.owner, constraint.name
                        ),
                    )?;
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::Extension(
                            "oracle_constraint_column".to_owned(),
                        ),
                        from_key: key.clone(),
                        to_key: column_key.clone(),
                        ordinal: column
                            .position
                            .map(|position| {
                                positive_u32(
                                    position,
                                    "Oracle materialized-view constraint ordinal",
                                )
                            })
                            .transpose()?,
                        properties: BTreeMap::new(),
                    });
                }
                continue;
            }
            let table_key = required(
                table_keys.get(&(constraint.owner.clone(), constraint.table.clone())),
                format!(
                    "table key for Oracle constraint {}.{}",
                    constraint.owner, constraint.name
                ),
            )?;
            let (kind, object_kind) = match constraint.constraint_type.as_str() {
                "P" => (ConstraintKind::PrimaryKey, ObjectKind::PrimaryKey),
                "U" => (ConstraintKind::Unique, ObjectKind::UniqueConstraint),
                "R" => (ConstraintKind::ForeignKey, ObjectKind::ForeignKey),
                "C" => (ConstraintKind::Check, ObjectKind::CheckConstraint),
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle constraint type '{other}' for {}.{}",
                        constraint.owner, constraint.name
                    )));
                }
            };
            let local_columns = resolve_named_columns(
                &constraint.owner,
                &constraint.table,
                &constraint.columns,
                &column_keys,
                &constraint.name,
            )?;
            let (referenced_table_key, referenced_columns) = if kind == ConstraintKind::ForeignKey {
                let referenced_owner = constraint.referenced_owner.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key {}.{} has no referenced owner",
                        constraint.owner, constraint.name
                    ))
                })?;
                let referenced_name =
                    constraint.referenced_constraint.as_deref().ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "foreign key {}.{} has no referenced constraint",
                            constraint.owner, constraint.name
                        ))
                    })?;
                let referenced = required(
                    constraint_by_identity
                        .get(&(referenced_owner.to_owned(), referenced_name.to_owned())),
                    format!(
                        "referenced Oracle constraint {}.{}",
                        referenced_owner, referenced_name
                    ),
                )?;
                let referenced_table = required(
                    table_keys.get(&(referenced.owner.clone(), referenced.table.clone())),
                    format!(
                        "referenced Oracle table {}.{}",
                        referenced.owner, referenced.table
                    ),
                )?;
                let referenced_columns = resolve_named_columns(
                    &referenced.owner,
                    &referenced.table,
                    &referenced.columns,
                    &column_keys,
                    &constraint.name,
                )?;
                (Some(referenced_table.clone()), referenced_columns)
            } else {
                (None, Vec::new())
            };
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &constraint.owner,
                object_kind,
                &constraint.table,
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
                    .then(|| constraint.search_condition.clone())
                    .flatten(),
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties: constraint_properties(constraint),
            });
        }

        let primary_indexes = raw
            .constraints
            .iter()
            .filter(|constraint| constraint.constraint_type == "P")
            .filter_map(|constraint| {
                Some((
                    constraint.index_owner.clone()?,
                    constraint.index_name.clone()?,
                ))
            })
            .collect::<BTreeSet<_>>();
        let mut indexes = Vec::new();
        let mut index_keys = BTreeMap::new();
        for index in &raw.indexes {
            let expression = oracle_index_expression(index);
            let inventory_object = required(
                inventory.get(&(index.owner.clone(), "INDEX".to_owned(), index.name.clone())),
                format!(
                    "inventory row for Oracle index {}.{}",
                    index.owner, index.name
                ),
            )?;
            let mut properties = oracle_index_properties(index, inventory_object);
            if let Some(partitioning) =
                partitioned_indexes.get(&(index.owner.clone(), index.name.clone()))
            {
                add_oracle_partitioned_index_properties(
                    &mut properties,
                    partitioning,
                    &raw.partition_key_columns,
                );
            }
            if let Some(materialized_view_key) =
                materialized_view_keys.get(&(index.table_owner.clone(), index.table.clone()))
            {
                let key = oracle_key(
                    self.connection_alias,
                    &database_name,
                    &index.table_owner,
                    ObjectKind::Index,
                    &index.table,
                    Some(index.name.clone()),
                );
                index_keys.insert((index.owner.clone(), index.name.clone()), key.clone());
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(materialized_view_key.clone()),
                    name: index.name.clone(),
                    extension_kind: None,
                    definition: expression,
                    properties,
                });
                for column in index
                    .columns
                    .iter()
                    .filter(|column| column.expression.is_none())
                {
                    let column_key = required(
                        materialized_view_column_keys.get(&(
                            index.table_owner.clone(),
                            index.table.clone(),
                            column.name.clone(),
                        )),
                        format!(
                            "column {} for Oracle materialized-view index {}.{}",
                            column.name, index.owner, index.name
                        ),
                    )?;
                    metadata.relationships.push(MetadataRelationship {
                        kind: MetadataRelationshipKind::IncludesColumn,
                        from_key: key.clone(),
                        to_key: column_key.clone(),
                        ordinal: Some(positive_u32(
                            column.position,
                            "Oracle materialized-view index ordinal",
                        )?),
                        properties: BTreeMap::from([(
                            "descending".to_owned(),
                            MetadataValue::Boolean(column.descending),
                        )]),
                    });
                }
                continue;
            }
            let table_key = required(
                table_keys.get(&(index.table_owner.clone(), index.table.clone())),
                format!("table key for Oracle index {}.{}", index.owner, index.name),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &index.table_owner,
                ObjectKind::Index,
                &index.table,
                Some(index.name.clone()),
            );
            index_keys.insert((index.owner.clone(), index.name.clone()), key.clone());
            let direct_columns = index
                .columns
                .iter()
                .filter(|column| column.expression.is_none())
                .cloned()
                .collect::<Vec<_>>();
            let index_columns = resolve_named_columns(
                &index.table_owner,
                &index.table,
                &direct_columns,
                &column_keys,
                &index.name,
            )?;
            indexes.push(IndexObject {
                key: key.clone(),
                table_key: table_key.clone(),
                name: index.name.clone(),
                columns: index_columns,
                is_unique: index.unique,
                is_primary: primary_indexes.contains(&(index.owner.clone(), index.name.clone())),
                predicate: None,
                expression: expression.clone(),
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: expression,
                properties,
            });
        }

        let mut table_partition_keys = BTreeMap::new();
        for partition in &raw.table_partitions {
            let parent_key = match materialized_view_keys
                .get(&(partition.owner.clone(), partition.table.clone()))
            {
                Some(key) => key,
                None => required(
                    table_keys.get(&(partition.owner.clone(), partition.table.clone())),
                    format!(
                        "parent table for Oracle partition {}.{}.{}",
                        partition.owner, partition.table, partition.name
                    ),
                )?,
            };
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &partition.owner,
                ObjectKind::Extension,
                &partition.table,
                Some(format!("partition:{}", partition.name)),
            );
            let inventory_object = required(
                subobject_inventory.get(&(
                    partition.owner.clone(),
                    "TABLE PARTITION".to_owned(),
                    partition.table.clone(),
                    partition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle table partition {}.{}.{}",
                    partition.owner, partition.table, partition.name
                ),
            )?;
            table_partition_keys.insert(
                (
                    partition.owner.clone(),
                    partition.table.clone(),
                    partition.name.clone(),
                ),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: partition.name.clone(),
                extension_kind: Some("oracle_table_partition".to_owned()),
                definition: partition.high_value.clone(),
                properties: oracle_table_partition_properties(partition, inventory_object),
            });
        }
        let mut table_subpartition_keys = BTreeMap::new();
        for subpartition in &raw.table_subpartitions {
            let parent_key = required(
                table_partition_keys.get(&(
                    subpartition.owner.clone(),
                    subpartition.table.clone(),
                    subpartition.partition.clone(),
                )),
                format!(
                    "parent partition for Oracle table subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &subpartition.owner,
                ObjectKind::Extension,
                &subpartition.table,
                Some(format!(
                    "partition:{}:subpartition:{}",
                    subpartition.partition, subpartition.name
                )),
            );
            let inventory_object = required(
                subobject_inventory.get(&(
                    subpartition.owner.clone(),
                    "TABLE SUBPARTITION".to_owned(),
                    subpartition.table.clone(),
                    subpartition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle table subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            table_subpartition_keys.insert(
                (
                    subpartition.owner.clone(),
                    subpartition.table.clone(),
                    subpartition.name.clone(),
                ),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: subpartition.name.clone(),
                extension_kind: Some("oracle_table_subpartition".to_owned()),
                definition: subpartition.high_value.clone(),
                properties: oracle_table_subpartition_properties(subpartition, inventory_object),
            });
        }

        let mut index_partition_keys = BTreeMap::new();
        for partition in &raw.index_partitions {
            let parent_key = required(
                index_keys.get(&(partition.owner.clone(), partition.index.clone())),
                format!(
                    "parent index for Oracle partition {}.{}.{}",
                    partition.owner, partition.index, partition.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &partition.owner,
                ObjectKind::Extension,
                &parent_key.object_name,
                Some(format!(
                    "index:{}:partition:{}",
                    partition.index, partition.name
                )),
            );
            let inventory_object = required(
                subobject_inventory.get(&(
                    partition.owner.clone(),
                    "INDEX PARTITION".to_owned(),
                    partition.index.clone(),
                    partition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle index partition {}.{}.{}",
                    partition.owner, partition.index, partition.name
                ),
            )?;
            index_partition_keys.insert(
                (
                    partition.owner.clone(),
                    partition.index.clone(),
                    partition.name.clone(),
                ),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: partition.name.clone(),
                extension_kind: Some("oracle_index_partition".to_owned()),
                definition: partition.high_value.clone(),
                properties: oracle_index_partition_properties(partition, inventory_object),
            });
        }
        for subpartition in &raw.index_subpartitions {
            let parent_key = required(
                index_partition_keys.get(&(
                    subpartition.owner.clone(),
                    subpartition.index.clone(),
                    subpartition.partition.clone(),
                )),
                format!(
                    "parent partition for Oracle index subpartition {}.{}.{}",
                    subpartition.owner, subpartition.index, subpartition.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &subpartition.owner,
                ObjectKind::Extension,
                &parent_key.object_name,
                Some(format!(
                    "index:{}:partition:{}:subpartition:{}",
                    subpartition.index, subpartition.partition, subpartition.name
                )),
            );
            let inventory_object = required(
                subobject_inventory.get(&(
                    subpartition.owner.clone(),
                    "INDEX SUBPARTITION".to_owned(),
                    subpartition.index.clone(),
                    subpartition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle index subpartition {}.{}.{}",
                    subpartition.owner, subpartition.index, subpartition.name
                ),
            )?;
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: subpartition.name.clone(),
                extension_kind: Some("oracle_index_subpartition".to_owned()),
                definition: subpartition.high_value.clone(),
                properties: oracle_index_subpartition_properties(subpartition, inventory_object),
            });
        }

        let mut lob_keys = BTreeMap::new();
        for lob in &raw.lobs {
            let parent_key = required(
                column_keys.get(&(lob.owner.clone(), lob.table.clone(), lob.column.clone())),
                format!(
                    "parent column for Oracle LOB {}.{}.{}",
                    lob.owner, lob.table, lob.column
                ),
            )?;
            let segment_inventory = required(
                inventory.get(&(
                    lob.owner.clone(),
                    "LOB".to_owned(),
                    lob.segment_name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB segment {}.{}",
                    lob.owner, lob.segment_name
                ),
            )?;
            let index_inventory = required(
                inventory.get(&(
                    lob.owner.clone(),
                    "INDEX".to_owned(),
                    lob.index_name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB index {}.{}",
                    lob.owner, lob.index_name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &lob.owner,
                ObjectKind::Extension,
                &lob.table,
                Some(format!("column:{}:lob:{}", lob.column, lob.segment_name)),
            );
            lob_keys.insert(
                (lob.owner.clone(), lob.table.clone(), lob.column.clone()),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(parent_key.clone()),
                name: lob.segment_name.clone(),
                extension_kind: Some("oracle_lob_storage".to_owned()),
                definition: None,
                properties: oracle_lob_properties(lob, segment_inventory, index_inventory),
            });
        }

        let lobs_by_identity = raw
            .lobs
            .iter()
            .map(|lob| {
                (
                    (lob.owner.clone(), lob.table.clone(), lob.column.clone()),
                    lob,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut lob_partition_keys = BTreeMap::new();
        for partition in &raw.lob_partitions {
            let lob_identity = (
                partition.owner.clone(),
                partition.table.clone(),
                partition.column.clone(),
            );
            let lob = required(
                lobs_by_identity.get(&lob_identity),
                format!(
                    "parent LOB for Oracle partition {}.{}.{}",
                    partition.owner, partition.table, partition.name
                ),
            )?;
            let parent_key = required(
                lob_keys.get(&lob_identity),
                format!(
                    "parent LOB key for Oracle partition {}.{}.{}",
                    partition.owner, partition.table, partition.name
                ),
            )?;
            let table_partition_key = required(
                table_partition_keys.get(&(
                    partition.owner.clone(),
                    partition.table.clone(),
                    partition.table_partition.clone(),
                )),
                format!(
                    "table partition key for Oracle LOB partition {}.{}.{}",
                    partition.owner, partition.table, partition.name
                ),
            )?;
            let segment_inventory = required(
                subobject_inventory.get(&(
                    partition.owner.clone(),
                    "LOB PARTITION".to_owned(),
                    partition.lob_name.clone(),
                    partition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB partition {}.{}.{}",
                    partition.owner, partition.table, partition.name
                ),
            )?;
            let index_inventory = required(
                subobject_inventory.get(&(
                    partition.owner.clone(),
                    "INDEX PARTITION".to_owned(),
                    lob.index_name.clone(),
                    partition.index_partition_name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB index partition {}.{}",
                    partition.owner, partition.index_partition_name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &partition.owner,
                ObjectKind::Extension,
                &partition.table,
                Some(format!(
                    "column:{}:lob:{}:partition:{}",
                    partition.column, partition.lob_name, partition.name
                )),
            );
            lob_partition_keys.insert(
                (
                    partition.owner.clone(),
                    partition.lob_name.clone(),
                    partition.name.clone(),
                ),
                key.clone(),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(parent_key.clone()),
                name: partition.name.clone(),
                extension_kind: Some("oracle_lob_partition".to_owned()),
                definition: None,
                properties: oracle_lob_partition_properties(
                    partition,
                    segment_inventory,
                    index_inventory,
                ),
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::Extension(
                    "oracle_lob_partition_storage".to_owned(),
                ),
                from_key: key,
                to_key: table_partition_key.clone(),
                ordinal: Some(positive_u32(
                    partition.position,
                    "Oracle LOB partition relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
        }

        for subpartition in &raw.lob_subpartitions {
            let lob = required(
                lobs_by_identity.get(&(
                    subpartition.owner.clone(),
                    subpartition.table.clone(),
                    subpartition.column.clone(),
                )),
                format!(
                    "parent LOB for Oracle subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            let parent_key = required(
                lob_partition_keys.get(&(
                    subpartition.owner.clone(),
                    subpartition.lob_name.clone(),
                    subpartition.lob_partition_name.clone(),
                )),
                format!(
                    "parent LOB partition key for Oracle subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            let table_subpartition_key = required(
                table_subpartition_keys.get(&(
                    subpartition.owner.clone(),
                    subpartition.table.clone(),
                    subpartition.table_subpartition.clone(),
                )),
                format!(
                    "table subpartition key for Oracle LOB subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            let segment_inventory = required(
                subobject_inventory.get(&(
                    subpartition.owner.clone(),
                    "LOB SUBPARTITION".to_owned(),
                    subpartition.lob_name.clone(),
                    subpartition.name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB subpartition {}.{}.{}",
                    subpartition.owner, subpartition.table, subpartition.name
                ),
            )?;
            let index_inventory = required(
                subobject_inventory.get(&(
                    subpartition.owner.clone(),
                    "INDEX SUBPARTITION".to_owned(),
                    lob.index_name.clone(),
                    subpartition.index_subpartition_name.clone(),
                )),
                format!(
                    "inventory row for Oracle LOB index subpartition {}.{}",
                    subpartition.owner, subpartition.index_subpartition_name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                &subpartition.owner,
                ObjectKind::Extension,
                &subpartition.table,
                Some(format!(
                    "column:{}:lob:{}:partition:{}:subpartition:{}",
                    subpartition.column,
                    subpartition.lob_name,
                    subpartition.lob_partition_name,
                    subpartition.name
                )),
            );
            metadata.objects.push(MetadataObject {
                key: key.clone(),
                parent_key: Some(parent_key.clone()),
                name: subpartition.name.clone(),
                extension_kind: Some("oracle_lob_subpartition".to_owned()),
                definition: None,
                properties: oracle_lob_subpartition_properties(
                    subpartition,
                    segment_inventory,
                    index_inventory,
                ),
            });
            metadata.relationships.push(MetadataRelationship {
                kind: MetadataRelationshipKind::Extension(
                    "oracle_lob_subpartition_storage".to_owned(),
                ),
                from_key: key,
                to_key: table_subpartition_key.clone(),
                ordinal: Some(positive_u32(
                    subpartition.position,
                    "Oracle LOB subpartition relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
        }

        let mut triggers = Vec::new();
        let mut trigger_keys = BTreeMap::new();
        let mut trigger_targets = BTreeMap::new();
        for trigger in &raw.triggers {
            let inventory_object = required(
                inventory.get(&(
                    trigger.owner.clone(),
                    "TRIGGER".to_owned(),
                    trigger.name.clone(),
                )),
                format!(
                    "inventory row for Oracle trigger {}.{}",
                    trigger.owner, trigger.name
                ),
            )?;
            let definition = oracle_trigger_definition(trigger)?;
            let properties = oracle_trigger_properties(trigger, inventory_object);
            match trigger.base_object_type.as_str() {
                "TABLE" | "VIEW" => {
                    let target_owner = trigger.table_owner.as_deref().ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "Oracle trigger {}.{} has no target owner",
                            trigger.owner, trigger.name
                        ))
                    })?;
                    let target_name = trigger.table_name.as_deref().ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "Oracle trigger {}.{} has no target object",
                            trigger.owner, trigger.name
                        ))
                    })?;
                    let target_key = if trigger.base_object_type == "TABLE" {
                        required(
                            table_keys.get(&(target_owner.to_owned(), target_name.to_owned())),
                            format!(
                                "target table key for Oracle trigger {}.{}",
                                trigger.owner, trigger.name
                            ),
                        )?
                    } else {
                        required(
                            view_keys.get(&(target_owner.to_owned(), target_name.to_owned())),
                            format!(
                                "target view key for Oracle trigger {}.{}",
                                trigger.owner, trigger.name
                            ),
                        )?
                    };
                    let key = oracle_key(
                        self.connection_alias,
                        &database_name,
                        target_owner,
                        ObjectKind::Trigger,
                        target_name,
                        Some(trigger.name.clone()),
                    );
                    trigger_keys.insert((trigger.owner.clone(), trigger.name.clone()), key.clone());
                    trigger_targets.insert(
                        (trigger.owner.clone(), trigger.name.clone()),
                        (
                            target_owner.to_owned(),
                            target_name.to_owned(),
                            trigger.base_object_type.clone(),
                        ),
                    );
                    triggers.push(TriggerObject {
                        key: key.clone(),
                        table_key: target_key.clone(),
                        name: trigger.name.clone(),
                        timing: Some(oracle_trigger_timing(&trigger.trigger_type)?),
                        events: oracle_trigger_events(&trigger.triggering_event)?,
                        definition: Some(definition),
                        executes_routine_key: None,
                    });
                    metadata.annotations.push(ObjectAnnotation {
                        object_key: key,
                        definition: None,
                        properties,
                    });
                }
                "SCHEMA" | "DATABASE" => {
                    let (parent_key, target_name) = if trigger.base_object_type == "SCHEMA" {
                        (
                            required(
                                schema_keys.get(&trigger.owner),
                                format!(
                                    "schema key for Oracle trigger {}.{}",
                                    trigger.owner, trigger.name
                                ),
                            )?,
                            trigger.owner.as_str(),
                        )
                    } else {
                        (&database_key, database_name.as_str())
                    };
                    let key = oracle_key(
                        self.connection_alias,
                        &database_name,
                        &trigger.owner,
                        ObjectKind::Trigger,
                        target_name,
                        Some(trigger.name.clone()),
                    );
                    trigger_keys.insert((trigger.owner.clone(), trigger.name.clone()), key.clone());
                    metadata.objects.push(MetadataObject {
                        key,
                        parent_key: Some(parent_key.clone()),
                        name: trigger.name.clone(),
                        extension_kind: None,
                        definition: Some(definition),
                        properties,
                    });
                }
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle trigger target kind '{other}'"
                    )));
                }
            }
        }
        for dependency in raw
            .dependencies
            .iter()
            .filter(|dependency| dependency.object_type == "TRIGGER")
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        {
            if let Some(target) =
                trigger_targets.get(&(dependency.owner.clone(), dependency.name.clone()))
            {
                if dependency.referenced_owner == target.0
                    && dependency.referenced_name == target.1
                    && dependency.referenced_type == target.2
                {
                    continue;
                }
            }
            let source_key = required(
                trigger_keys.get(&(dependency.owner.clone(), dependency.name.clone())),
                format!(
                    "source key for Oracle trigger dependency {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            let (target_key, relationship_kind) = match dependency.referenced_type.as_str() {
                "TABLE" => (
                    match materialized_view_keys.get(&(
                        dependency.referenced_owner.clone(),
                        dependency.referenced_name.clone(),
                    )) {
                        Some(key) => key,
                        None => required(
                            table_keys.get(&(
                                dependency.referenced_owner.clone(),
                                dependency.referenced_name.clone(),
                            )),
                            format!(
                                "table target for Oracle trigger dependency {}.{}",
                                dependency.referenced_owner, dependency.referenced_name
                            ),
                        )?,
                    },
                    MetadataRelationshipKind::DependsOn,
                ),
                "VIEW" => (
                    required(
                        view_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "view target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "MATERIALIZED VIEW" => (
                    required(
                        materialized_view_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "materialized-view target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "SEQUENCE" => (
                    required(
                        sequence_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "sequence target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "FUNCTION" | "PROCEDURE" => (
                    required(
                        routine_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                            dependency.referenced_type.clone(),
                        )),
                        format!(
                            "routine target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::Invokes,
                ),
                "PACKAGE" => (
                    required(
                        package_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "package target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                "TYPE" => (
                    required(
                        type_keys.get(&(
                            dependency.referenced_owner.clone(),
                            dependency.referenced_name.clone(),
                        )),
                        format!(
                            "type target for Oracle trigger dependency {}.{}",
                            dependency.referenced_owner, dependency.referenced_name
                        ),
                    )?,
                    MetadataRelationshipKind::DependsOn,
                ),
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle trigger dependency target type '{other}'"
                    )));
                }
            };
            metadata.relationships.push(MetadataRelationship {
                kind: relationship_kind,
                from_key: source_key.clone(),
                to_key: target_key.clone(),
                ordinal: None,
                properties: BTreeMap::from([(
                    "oracle_dependency_type".to_owned(),
                    MetadataValue::String(dependency.dependency_type.clone()),
                )]),
            });
        }

        let snapshot = CanonicalSchemaSnapshot {
            schema: SchemaSnapshot {
                source_kind: ORACLE_SOURCE.to_owned(),
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
                capabilities: oracle_complete_capabilities(&self.scope),
            },
            metadata,
        };
        let discovered_counts = discovery_counts_from_catalog(&raw, &self.scope);
        let server_version = format!("{} ({})", self.facts.version, self.facts.release);
        Ok(CatalogDiscovery {
            snapshot,
            adapter: AdapterIdentity {
                name: "database-memory-oracle-catalog".to_owned(),
                version: ORACLE_ADAPTER_VERSION.to_owned(),
            },
            server: ServerIdentity {
                product: "Oracle Database".to_owned(),
                version: server_version,
            },
            scope: IntrospectionScope {
                catalogs: vec![database_name],
                schemas: self.scope.owners.clone(),
            },
            discovered_counts,
            capability_checks: vec![
                CapabilityCheck {
                    name: "supported_server_version".to_owned(),
                    evidence: format!(
                        "server release '{}' maps to live-certified strategy {}",
                        self.facts.release,
                        self.strategy.strategy_name()
                    ),
                },
                CapabilityCheck {
                    name: "single_container_scope".to_owned(),
                    evidence: format!(
                        "connected container={} con_id={} database={} and root aggregation was rejected",
                        self.facts.container, self.facts.container_id, self.facts.database
                    ),
                },
                CapabilityCheck {
                    name: "dictionary_scope".to_owned(),
                    evidence: format!(
                        "{} covered {} owner(s): {}",
                        self.scope.mode.label(),
                        self.scope.owners.len(),
                        self.scope.owners.join(", ")
                    ),
                },
                CapabilityCheck {
                    name: "stable_read_only_catalog".to_owned(),
                    evidence: "SET TRANSACTION READ ONLY succeeded and two complete dictionary reads were identical"
                        .to_owned(),
                },
                CapabilityCheck {
                    name: "independent_inventory_reconciliation".to_owned(),
                    evidence: format!(
                        "{} non-secondary USER/DBA_OBJECTS rows reconciled against table, index, partition, LOB storage, sequence, view, materialized-view, synonym, type, trigger, routine, and package detail catalogs",
                        raw.inventory.iter().filter(|object| !object.secondary).count()
                    ),
                },
                CapabilityCheck {
                    name: "metadata_only_catalog_queries".to_owned(),
                    evidence: "adapter queried Oracle data dictionary and session metadata only; no application table appears in a FROM clause"
                        .to_owned(),
                },
                CapabilityCheck {
                    name: "dependency_coverage".to_owned(),
                    evidence: format!(
                        "{} unique USER/DBA_DEPENDENCIES row(s) were resolved; {} Oracle-maintained target row(s) were explicitly collapsed",
                        raw.dependencies.len(),
                        raw.dependencies
                            .iter()
                            .filter(|dependency| dependency.referenced_owner_oracle_maintained)
                            .count()
                    ),
                },
                CapabilityCheck {
                    name: "principal_context".to_owned(),
                    evidence: format!(
                        "session_user={} current_schema={} and {} selected principal row(s) were readable",
                        self.facts.session_user,
                        self.facts.current_schema,
                        self.scope.principals.len()
                    ),
                },
            ],
        })
    }
}

trait NamedCatalogColumn {
    fn name(&self) -> &str;
}

impl NamedCatalogColumn for RawConstraintColumn {
    fn name(&self) -> &str {
        &self.name
    }
}

impl NamedCatalogColumn for RawIndexColumn {
    fn name(&self) -> &str {
        &self.name
    }
}

fn resolve_named_columns<T: NamedCatalogColumn>(
    owner: &str,
    table: &str,
    raw_columns: &[T],
    column_keys: &BTreeMap<(String, String, String), ObjectKey>,
    subject: &str,
) -> Result<Vec<ObjectKey>, CatalogError> {
    raw_columns
        .iter()
        .map(|column| {
            required(
                column_keys.get(&(owner.to_owned(), table.to_owned(), column.name().to_owned())),
                format!(
                    "Oracle column {}.{}.{} for {}",
                    owner,
                    table,
                    column.name(),
                    subject
                ),
            )
            .cloned()
        })
        .collect()
}

fn inventory_properties(object: &RawInventoryObject) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "oracle_object_id", object.object_id);
    insert_optional_i64(
        &mut properties,
        "oracle_data_object_id",
        object.data_object_id,
    );
    insert_string(&mut properties, "object_status", &object.status);
    insert_bool(&mut properties, "temporary", object.temporary);
    insert_bool(&mut properties, "generated", object.generated);
    insert_bool(&mut properties, "secondary", object.secondary);
    insert_i64(&mut properties, "namespace", object.namespace);
    insert_optional_string(
        &mut properties,
        "edition_name",
        object.edition_name.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "editionable",
        object.editionable.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "default_collation",
        object.default_collation.as_deref(),
    );
    properties
}

fn oracle_column_properties(column: &RawColumn) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_optional_i64(&mut properties, "column_id", column.column_id);
    insert_i64(
        &mut properties,
        "internal_column_id",
        column.internal_column_id,
    );
    insert_i64(&mut properties, "data_length", column.data_length);
    insert_optional_i64(&mut properties, "data_precision", column.data_precision);
    insert_optional_i64(&mut properties, "data_scale", column.data_scale);
    insert_optional_i64(&mut properties, "char_length", column.char_length);
    insert_optional_string(&mut properties, "char_used", column.char_used.as_deref());
    insert_optional_string(&mut properties, "collation", column.collation.as_deref());
    insert_optional_string(
        &mut properties,
        "data_type_owner",
        column.data_type_owner.as_deref(),
    );
    insert_bool(&mut properties, "hidden", column.hidden);
    insert_bool(&mut properties, "virtual", column.virtual_column);
    insert_bool(&mut properties, "user_generated", column.user_generated);
    insert_bool(&mut properties, "default_on_null", column.default_on_null);
    insert_bool(&mut properties, "identity", column.identity);
    properties
}

fn oracle_index_properties(
    index: &RawIndex,
    inventory_object: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory_object);
    insert_string(&mut properties, "index_type", &index.index_type);
    insert_string(&mut properties, "index_status", &index.status);
    insert_bool(&mut properties, "temporary", index.temporary);
    insert_bool(&mut properties, "generated", index.generated);
    insert_string(&mut properties, "visibility", &index.visibility);
    insert_optional_string(
        &mut properties,
        "function_status",
        index.function_status.as_deref(),
    );
    insert_bool(&mut properties, "constraint_index", index.constraint_index);
    properties.insert(
        "key_parts".to_owned(),
        MetadataValue::StringList(
            index
                .columns
                .iter()
                .map(|column| {
                    let value = column.expression.as_deref().unwrap_or(&column.name);
                    if column.descending {
                        format!("{value} DESC")
                    } else {
                        value.to_owned()
                    }
                })
                .collect(),
        ),
    );
    properties.insert(
        "descending_columns".to_owned(),
        MetadataValue::StringList(
            index
                .columns
                .iter()
                .filter(|column| column.descending)
                .map(|column| column.name.clone())
                .collect(),
        ),
    );
    properties
}

fn oracle_index_expression(index: &RawIndex) -> Option<String> {
    let expressions = index
        .columns
        .iter()
        .filter_map(|column| {
            column.expression.as_ref().map(|expression| {
                if column.descending {
                    format!("{expression} DESC")
                } else {
                    expression.clone()
                }
            })
        })
        .collect::<Vec<_>>();
    (!expressions.is_empty()).then(|| expressions.join(", "))
}

fn add_oracle_partitioned_table_properties(
    properties: &mut BTreeMap<String, MetadataValue>,
    table: &RawPartitionedTable,
    key_columns: &[RawPartitionKeyColumn],
) {
    insert_bool(properties, "partitioned", true);
    insert_string(properties, "partitioning_type", &table.partitioning_type);
    insert_string(
        properties,
        "subpartitioning_type",
        &table.subpartitioning_type,
    );
    insert_i64(properties, "partition_count", table.partition_count);
    insert_i64(
        properties,
        "default_subpartition_count",
        table.default_subpartition_count,
    );
    insert_optional_string(
        properties,
        "default_partition_tablespace",
        table.default_tablespace.as_deref(),
    );
    insert_optional_string(properties, "partition_interval", table.interval.as_deref());
    insert_optional_string(properties, "autolist", table.autolist.as_deref());
    insert_optional_string(
        properties,
        "subpartition_interval",
        table.interval_subpartition.as_deref(),
    );
    insert_optional_string(
        properties,
        "subpartition_autolist",
        table.autolist_subpartition.as_deref(),
    );
    insert_optional_string(properties, "automatic", table.automatic.as_deref());
    properties.insert(
        "partition_key_columns".to_owned(),
        MetadataValue::StringList(oracle_partition_key_names(
            key_columns,
            &table.owner,
            &table.table,
            "TABLE",
            false,
        )),
    );
    properties.insert(
        "subpartition_key_columns".to_owned(),
        MetadataValue::StringList(oracle_partition_key_names(
            key_columns,
            &table.owner,
            &table.table,
            "TABLE",
            true,
        )),
    );
    let collated =
        oracle_partition_collated_columns(key_columns, &table.owner, &table.table, "TABLE");
    if !collated.is_empty() {
        properties.insert(
            "collated_partition_key_columns".to_owned(),
            MetadataValue::StringList(collated),
        );
    }
}

fn add_oracle_partitioned_index_properties(
    properties: &mut BTreeMap<String, MetadataValue>,
    index: &RawPartitionedIndex,
    key_columns: &[RawPartitionKeyColumn],
) {
    insert_bool(properties, "partitioned", true);
    insert_string(properties, "partitioning_type", &index.partitioning_type);
    insert_string(
        properties,
        "subpartitioning_type",
        &index.subpartitioning_type,
    );
    insert_i64(properties, "partition_count", index.partition_count);
    insert_i64(
        properties,
        "default_subpartition_count",
        index.default_subpartition_count,
    );
    insert_string(properties, "locality", &index.locality);
    insert_string(properties, "alignment", &index.alignment);
    insert_optional_string(
        properties,
        "default_partition_tablespace",
        index.default_tablespace.as_deref(),
    );
    insert_optional_string(properties, "partition_interval", index.interval.as_deref());
    insert_optional_string(properties, "autolist", index.autolist.as_deref());
    insert_optional_string(
        properties,
        "subpartition_interval",
        index.interval_subpartition.as_deref(),
    );
    insert_optional_string(
        properties,
        "subpartition_autolist",
        index.autolist_subpartition.as_deref(),
    );
    properties.insert(
        "partition_key_columns".to_owned(),
        MetadataValue::StringList(oracle_partition_key_names(
            key_columns,
            &index.owner,
            &index.index,
            "INDEX",
            false,
        )),
    );
    properties.insert(
        "subpartition_key_columns".to_owned(),
        MetadataValue::StringList(oracle_partition_key_names(
            key_columns,
            &index.owner,
            &index.index,
            "INDEX",
            true,
        )),
    );
    let collated =
        oracle_partition_collated_columns(key_columns, &index.owner, &index.index, "INDEX");
    if !collated.is_empty() {
        properties.insert(
            "collated_partition_key_columns".to_owned(),
            MetadataValue::StringList(collated),
        );
    }
}

fn oracle_partition_key_names(
    key_columns: &[RawPartitionKeyColumn],
    owner: &str,
    name: &str,
    object_type: &str,
    subpartition: bool,
) -> Vec<String> {
    key_columns
        .iter()
        .filter(|column| {
            column.owner == owner
                && column.name == name
                && column.object_type == object_type
                && column.subpartition == subpartition
        })
        .map(|column| column.column.clone())
        .collect()
}

fn oracle_partition_collated_columns(
    key_columns: &[RawPartitionKeyColumn],
    owner: &str,
    name: &str,
    object_type: &str,
) -> Vec<String> {
    key_columns
        .iter()
        .filter(|column| {
            column.owner == owner && column.name == name && column.object_type == object_type
        })
        .filter_map(|column| Some(format!("{}={}", column.column, column.collated_column_id?)))
        .collect()
}

fn oracle_table_partition_properties(
    partition: &RawTablePartition,
    inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory);
    insert_i64(&mut properties, "position", partition.position);
    insert_bool(&mut properties, "composite", partition.composite == "YES");
    insert_i64(
        &mut properties,
        "subpartition_count",
        partition.subpartition_count,
    );
    insert_i64(
        &mut properties,
        "high_value_length",
        partition.high_value_length,
    );
    insert_optional_string(
        &mut properties,
        "tablespace",
        partition.tablespace.as_deref(),
    );
    insert_string(&mut properties, "compression", &partition.compression);
    insert_optional_string(
        &mut properties,
        "compress_for",
        partition.compress_for.as_deref(),
    );
    insert_string(&mut properties, "interval", &partition.interval);
    insert_string(
        &mut properties,
        "segment_created",
        &partition.segment_created,
    );
    insert_string(&mut properties, "indexing", &partition.indexing);
    insert_string(&mut properties, "read_only", &partition.read_only);
    properties
}

fn oracle_table_subpartition_properties(
    subpartition: &RawTableSubpartition,
    inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory);
    insert_string(&mut properties, "partition", &subpartition.partition);
    insert_i64(
        &mut properties,
        "partition_position",
        subpartition.partition_position,
    );
    insert_i64(&mut properties, "position", subpartition.position);
    insert_i64(
        &mut properties,
        "high_value_length",
        subpartition.high_value_length,
    );
    insert_optional_string(
        &mut properties,
        "tablespace",
        subpartition.tablespace.as_deref(),
    );
    insert_string(&mut properties, "compression", &subpartition.compression);
    insert_optional_string(
        &mut properties,
        "compress_for",
        subpartition.compress_for.as_deref(),
    );
    insert_string(&mut properties, "interval", &subpartition.interval);
    insert_string(
        &mut properties,
        "segment_created",
        &subpartition.segment_created,
    );
    insert_string(&mut properties, "indexing", &subpartition.indexing);
    insert_string(&mut properties, "read_only", &subpartition.read_only);
    properties
}

fn oracle_index_partition_properties(
    partition: &RawIndexPartition,
    inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory);
    insert_i64(&mut properties, "position", partition.position);
    insert_bool(&mut properties, "composite", partition.composite == "YES");
    insert_i64(
        &mut properties,
        "subpartition_count",
        partition.subpartition_count,
    );
    insert_i64(
        &mut properties,
        "high_value_length",
        partition.high_value_length,
    );
    insert_string(&mut properties, "partition_status", &partition.status);
    insert_optional_string(
        &mut properties,
        "tablespace",
        partition.tablespace.as_deref(),
    );
    insert_string(&mut properties, "compression", &partition.compression);
    insert_string(&mut properties, "interval", &partition.interval);
    insert_string(
        &mut properties,
        "segment_created",
        &partition.segment_created,
    );
    properties
}

fn oracle_index_subpartition_properties(
    subpartition: &RawIndexSubpartition,
    inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory);
    insert_string(&mut properties, "partition", &subpartition.partition);
    insert_i64(
        &mut properties,
        "partition_position",
        subpartition.partition_position,
    );
    insert_i64(&mut properties, "position", subpartition.position);
    insert_i64(
        &mut properties,
        "high_value_length",
        subpartition.high_value_length,
    );
    insert_string(&mut properties, "partition_status", &subpartition.status);
    insert_optional_string(
        &mut properties,
        "tablespace",
        subpartition.tablespace.as_deref(),
    );
    insert_string(&mut properties, "compression", &subpartition.compression);
    insert_string(&mut properties, "interval", &subpartition.interval);
    insert_string(
        &mut properties,
        "segment_created",
        &subpartition.segment_created,
    );
    properties
}

fn oracle_lob_properties(
    lob: &RawLob,
    segment_inventory: &RawInventoryObject,
    index_inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(segment_inventory);
    insert_string(&mut properties, "column", &lob.column);
    insert_string(&mut properties, "segment_name", &lob.segment_name);
    insert_string(&mut properties, "index_name", &lob.index_name);
    insert_optional_string(&mut properties, "tablespace", lob.tablespace.as_deref());
    insert_i64(&mut properties, "chunk", lob.chunk);
    insert_optional_i64(&mut properties, "pctversion", lob.pctversion);
    insert_optional_i64(&mut properties, "retention", lob.retention);
    insert_optional_i64(&mut properties, "freepools", lob.freepools);
    insert_string(&mut properties, "cache", &lob.cache);
    insert_string(&mut properties, "logging", &lob.logging);
    insert_string(&mut properties, "encrypt", &lob.encrypt);
    insert_string(&mut properties, "compression", &lob.compression);
    insert_string(&mut properties, "deduplication", &lob.deduplication);
    insert_string(&mut properties, "in_row", &lob.in_row);
    insert_string(&mut properties, "format", &lob.format);
    insert_bool(&mut properties, "partitioned", lob.partitioned == "YES");
    insert_bool(&mut properties, "securefile", lob.securefile == "YES");
    insert_string(&mut properties, "segment_created", &lob.segment_created);
    insert_optional_string(
        &mut properties,
        "retention_type",
        lob.retention_type.as_deref(),
    );
    insert_optional_i64(&mut properties, "retention_value", lob.retention_value);
    insert_optional_string(&mut properties, "value_based", lob.value_based.as_deref());
    insert_optional_i64(&mut properties, "max_inline", lob.max_inline);
    add_oracle_lob_index_inventory_properties(&mut properties, index_inventory);
    properties
}

fn oracle_lob_partition_properties(
    partition: &RawLobPartition,
    segment_inventory: &RawInventoryObject,
    index_inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(segment_inventory);
    insert_string(
        &mut properties,
        "table_partition",
        &partition.table_partition,
    );
    insert_string(&mut properties, "lob_name", &partition.lob_name);
    insert_string(
        &mut properties,
        "lob_index_partition_name",
        &partition.index_partition_name,
    );
    insert_i64(&mut properties, "position", partition.position);
    insert_bool(&mut properties, "composite", partition.composite == "YES");
    insert_i64(&mut properties, "chunk", partition.chunk);
    insert_optional_i64(&mut properties, "pctversion", partition.pctversion);
    insert_string(&mut properties, "cache", &partition.cache);
    insert_string(&mut properties, "in_row", &partition.in_row);
    insert_optional_string(
        &mut properties,
        "tablespace",
        partition.tablespace.as_deref(),
    );
    insert_optional_string(&mut properties, "retention", partition.retention.as_deref());
    insert_string(&mut properties, "logging", &partition.logging);
    insert_string(&mut properties, "encrypt", &partition.encrypt);
    insert_string(&mut properties, "compression", &partition.compression);
    insert_string(&mut properties, "deduplication", &partition.deduplication);
    insert_string(&mut properties, "securefile", &partition.securefile);
    insert_string(
        &mut properties,
        "segment_created",
        &partition.segment_created,
    );
    insert_optional_i64(&mut properties, "max_inline", partition.max_inline);
    add_oracle_lob_index_inventory_properties(&mut properties, index_inventory);
    properties
}

fn oracle_lob_subpartition_properties(
    subpartition: &RawLobSubpartition,
    segment_inventory: &RawInventoryObject,
    index_inventory: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(segment_inventory);
    insert_string(
        &mut properties,
        "lob_partition_name",
        &subpartition.lob_partition_name,
    );
    insert_string(
        &mut properties,
        "table_subpartition",
        &subpartition.table_subpartition,
    );
    insert_string(
        &mut properties,
        "lob_index_subpartition_name",
        &subpartition.index_subpartition_name,
    );
    insert_i64(&mut properties, "position", subpartition.position);
    insert_i64(&mut properties, "chunk", subpartition.chunk);
    insert_optional_i64(&mut properties, "pctversion", subpartition.pctversion);
    insert_string(&mut properties, "cache", &subpartition.cache);
    insert_string(&mut properties, "in_row", &subpartition.in_row);
    insert_optional_string(
        &mut properties,
        "tablespace",
        subpartition.tablespace.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "retention",
        subpartition.retention.as_deref(),
    );
    insert_string(&mut properties, "logging", &subpartition.logging);
    insert_string(&mut properties, "encrypt", &subpartition.encrypt);
    insert_string(&mut properties, "compression", &subpartition.compression);
    insert_string(
        &mut properties,
        "deduplication",
        &subpartition.deduplication,
    );
    insert_string(&mut properties, "securefile", &subpartition.securefile);
    insert_string(
        &mut properties,
        "segment_created",
        &subpartition.segment_created,
    );
    insert_optional_i64(&mut properties, "max_inline", subpartition.max_inline);
    add_oracle_lob_index_inventory_properties(&mut properties, index_inventory);
    properties
}

fn add_oracle_lob_index_inventory_properties(
    properties: &mut BTreeMap<String, MetadataValue>,
    inventory: &RawInventoryObject,
) {
    insert_i64(properties, "lob_index_object_id", inventory.object_id);
    insert_optional_i64(
        properties,
        "lob_index_data_object_id",
        inventory.data_object_id,
    );
    insert_string(properties, "lob_index_status", &inventory.status);
    insert_bool(properties, "lob_index_generated", inventory.generated);
}

fn oracle_trigger_definition(trigger: &RawTrigger) -> Result<String, CatalogError> {
    let description = trigger.description.as_deref().ok_or_else(|| {
        CatalogError::Mapping(format!(
            "Oracle trigger {}.{} has no complete description",
            trigger.owner, trigger.name
        ))
    })?;
    let body = trigger.body.as_deref().ok_or_else(|| {
        CatalogError::Mapping(format!(
            "Oracle trigger {}.{} has no complete body",
            trigger.owner, trigger.name
        ))
    })?;
    let definition = format!("CREATE OR REPLACE TRIGGER {description}\n{body}");
    if definition.len() > MAX_DEFINITION_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle trigger definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{}",
            trigger.owner, trigger.name
        )));
    }
    Ok(definition)
}

fn oracle_trigger_properties(
    trigger: &RawTrigger,
    inventory_object: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory_object);
    insert_string(&mut properties, "trigger_type", &trigger.trigger_type);
    insert_string(
        &mut properties,
        "triggering_event",
        &trigger.triggering_event,
    );
    insert_optional_string(
        &mut properties,
        "table_owner",
        trigger.table_owner.as_deref(),
    );
    insert_string(
        &mut properties,
        "base_object_type",
        &trigger.base_object_type,
    );
    insert_optional_string(&mut properties, "table_name", trigger.table_name.as_deref());
    insert_optional_string(
        &mut properties,
        "column_name",
        trigger.column_name.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "referencing_names",
        trigger.referencing_names.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "when_clause",
        trigger.when_clause.as_deref(),
    );
    insert_string(&mut properties, "status", &trigger.status);
    insert_string(&mut properties, "action_type", &trigger.action_type);
    insert_optional_string(
        &mut properties,
        "crossedition",
        trigger.crossedition.as_deref(),
    );
    insert_optional_string(&mut properties, "fire_once", trigger.fire_once.as_deref());
    insert_optional_string(
        &mut properties,
        "apply_server_only",
        trigger.apply_server_only.as_deref(),
    );
    properties
}

fn oracle_routine_properties(
    routine: &RawRoutine,
    inventory_object: &RawInventoryObject,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory_object);
    insert_i64(&mut properties, "object_id", routine.object_id);
    insert_i64(&mut properties, "subprogram_id", routine.subprogram_id);
    insert_optional_string(&mut properties, "overload", routine.overload.as_deref());
    insert_string(&mut properties, "object_type", &routine.object_type);
    insert_bool(&mut properties, "aggregate", routine.aggregate);
    insert_bool(&mut properties, "pipelined", routine.pipelined);
    insert_bool(&mut properties, "parallel", routine.parallel);
    insert_bool(&mut properties, "interface", routine.interface);
    insert_bool(&mut properties, "deterministic", routine.deterministic);
    insert_string(&mut properties, "authid", &routine.authid);
    insert_optional_string(
        &mut properties,
        "polymorphic",
        routine.polymorphic.as_deref(),
    );
    properties
}

fn oracle_routine_argument_properties(
    argument: &RawRoutineArgument,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "position", argument.position);
    insert_i64(&mut properties, "sequence", argument.sequence);
    insert_i64(&mut properties, "data_level", argument.data_level);
    insert_string(
        &mut properties,
        "data_type",
        format_oracle_argument_type(argument),
    );
    insert_string(&mut properties, "mode", &argument.mode);
    insert_bool(&mut properties, "defaulted", argument.defaulted);
    insert_optional_i64(&mut properties, "default_length", argument.default_length);
    insert_optional_string(
        &mut properties,
        "default_value",
        argument.default_value.as_deref(),
    );
    insert_optional_i64(&mut properties, "data_length", argument.data_length);
    insert_optional_i64(&mut properties, "data_precision", argument.data_precision);
    insert_optional_i64(&mut properties, "data_scale", argument.data_scale);
    insert_optional_string(&mut properties, "pls_type", argument.pls_type.as_deref());
    insert_optional_i64(&mut properties, "char_length", argument.char_length);
    insert_optional_string(&mut properties, "char_used", argument.char_used.as_deref());
    properties
}

fn validate_package_argument_order(
    routine: &RawPackageRoutine,
    arguments: &[&RawRoutineArgument],
) -> Result<(), CatalogError> {
    let return_count = arguments
        .iter()
        .filter(|argument| argument.position == 0)
        .count();
    if return_count > 1 {
        return Err(CatalogError::Mapping(format!(
            "Oracle package routine {}.{}.{} has {return_count} return rows",
            routine.owner, routine.package, routine.name
        )));
    }
    for (offset, argument) in arguments.iter().enumerate() {
        let expected_sequence = i64::try_from(offset + 1)
            .map_err(|_| CatalogError::Mapping("too many Oracle package arguments".to_owned()))?;
        if argument.sequence != expected_sequence {
            return Err(CatalogError::Mapping(format!(
                "Oracle package argument sequence gap for {}.{}.{}: expected {expected_sequence}, found {}",
                routine.owner, routine.package, routine.name, argument.sequence
            )));
        }
        let expected_position = if return_count == 1 {
            i64::try_from(offset).map_err(|_| {
                CatalogError::Mapping("too many Oracle package arguments".to_owned())
            })?
        } else {
            expected_sequence
        };
        if argument.position != expected_position {
            return Err(CatalogError::Mapping(format!(
                "Oracle package argument position mismatch for {}.{}.{}: expected {expected_position}, found {}",
                routine.owner, routine.package, routine.name, argument.position
            )));
        }
        if argument.position == 0 && (argument.name.is_some() || argument.mode != "OUT") {
            return Err(CatalogError::Mapping(format!(
                "Oracle package function return metadata is malformed for {}.{}.{}",
                routine.owner, routine.package, routine.name
            )));
        }
    }
    Ok(())
}

fn oracle_package_definition(package: &RawPackage) -> Result<String, CatalogError> {
    let specification = package.specification.as_deref().ok_or_else(|| {
        CatalogError::Mapping(format!(
            "Oracle package {}.{} has no specification",
            package.owner, package.name
        ))
    })?;
    let definition = package
        .body
        .as_deref()
        .map(|body| format!("{specification}\n\n{body}"))
        .unwrap_or_else(|| specification.to_owned());
    if definition.len() > MAX_DEFINITION_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "combined Oracle package definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{}",
            package.owner, package.name
        )));
    }
    Ok(definition)
}

fn oracle_type_definition(user_type: &RawUserType) -> Result<String, CatalogError> {
    let specification = user_type.specification.as_deref().ok_or_else(|| {
        CatalogError::Mapping(format!(
            "Oracle type {}.{} has no specification",
            user_type.owner, user_type.name
        ))
    })?;
    let definition = user_type
        .body
        .as_deref()
        .map(|body| format!("{specification}\n\n{body}"))
        .unwrap_or_else(|| specification.to_owned());
    if definition.len() > MAX_DEFINITION_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "combined Oracle type definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit for {}.{}",
            user_type.owner, user_type.name
        )));
    }
    Ok(definition)
}

fn oracle_type_properties(
    user_type: &RawUserType,
    inventory_object: &RawInventoryObject,
    body_inventory: Option<&RawInventoryObject>,
    collection: Option<&RawCollectionType>,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory_object);
    insert_string(&mut properties, "type_oid", &user_type.oid);
    insert_string(&mut properties, "typecode", &user_type.typecode);
    insert_i64(
        &mut properties,
        "attribute_count",
        user_type.attribute_count,
    );
    insert_i64(&mut properties, "method_count", user_type.method_count);
    insert_string(&mut properties, "predefined", &user_type.predefined);
    insert_string(&mut properties, "incomplete", &user_type.incomplete);
    insert_string(&mut properties, "final", &user_type.final_type);
    insert_string(&mut properties, "instantiable", &user_type.instantiable);
    insert_string(&mut properties, "persistable", &user_type.persistable);
    insert_optional_string(
        &mut properties,
        "supertype_owner",
        user_type.supertype_owner.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "supertype_name",
        user_type.supertype_name.as_deref(),
    );
    insert_optional_i64(
        &mut properties,
        "local_attribute_count",
        user_type.local_attribute_count,
    );
    insert_optional_i64(
        &mut properties,
        "local_method_count",
        user_type.local_method_count,
    );
    insert_optional_string(&mut properties, "type_id", user_type.type_id.as_deref());
    insert_bool(&mut properties, "has_body", user_type.body.is_some());
    if let Some(body_inventory) = body_inventory {
        insert_i64(&mut properties, "body_object_id", body_inventory.object_id);
        insert_string(&mut properties, "body_status", &body_inventory.status);
    }
    if let Some(collection) = collection {
        insert_string(
            &mut properties,
            "collection_type",
            &collection.collection_type,
        );
        insert_optional_i64(&mut properties, "upper_bound", collection.upper_bound);
        insert_optional_string(
            &mut properties,
            "element_type_modifier",
            collection.element_type_modifier.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "element_type_owner",
            collection.element_type_owner.as_deref(),
        );
        insert_string(
            &mut properties,
            "element_type_name",
            &collection.element_type_name,
        );
        insert_optional_i64(&mut properties, "element_length", collection.length);
        insert_optional_i64(&mut properties, "element_precision", collection.precision);
        insert_optional_i64(&mut properties, "element_scale", collection.scale);
        insert_optional_string(
            &mut properties,
            "element_character_set",
            collection.character_set.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "element_storage",
            collection.element_storage.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "nulls_stored",
            collection.nulls_stored.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "element_char_used",
            collection.char_used.as_deref(),
        );
    }
    properties
}

fn oracle_type_attribute_properties(
    attribute: &RawTypeAttribute,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "position", attribute.position);
    insert_string(&mut properties, "data_type", &attribute.data_type_name);
    insert_optional_string(
        &mut properties,
        "type_modifier",
        attribute.type_modifier.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "data_type_owner",
        attribute.data_type_owner.as_deref(),
    );
    insert_optional_i64(&mut properties, "length", attribute.length);
    insert_optional_i64(&mut properties, "precision", attribute.precision);
    insert_optional_i64(&mut properties, "scale", attribute.scale);
    insert_optional_string(
        &mut properties,
        "character_set",
        attribute.character_set.as_deref(),
    );
    insert_bool(&mut properties, "inherited", attribute.inherited == "YES");
    insert_optional_string(&mut properties, "char_used", attribute.char_used.as_deref());
    properties
}

fn oracle_type_method_properties(method: &RawTypeMethod) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "method_number", method.method_number);
    insert_string(&mut properties, "method_type", &method.method_type);
    insert_i64(&mut properties, "parameter_count", method.parameter_count);
    insert_i64(&mut properties, "result_count", method.result_count);
    insert_bool(&mut properties, "final", method.final_method == "YES");
    insert_bool(
        &mut properties,
        "instantiable",
        method.instantiable == "YES",
    );
    insert_bool(&mut properties, "overriding", method.overriding == "YES");
    insert_bool(&mut properties, "inherited", method.inherited == "YES");
    properties
}

fn oracle_type_method_parameter_properties(
    parameter: &RawTypeMethodParameter,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "position", parameter.position);
    insert_string(&mut properties, "mode", &parameter.mode);
    insert_string(&mut properties, "data_type", &parameter.data_type_name);
    insert_optional_string(
        &mut properties,
        "type_modifier",
        parameter.type_modifier.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "data_type_owner",
        parameter.data_type_owner.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "character_set",
        parameter.character_set.as_deref(),
    );
    insert_bool(&mut properties, "return_value", parameter.return_value);
    properties
}

fn oracle_package_properties(
    package: &RawPackage,
    inventory_object: &RawInventoryObject,
    body_inventory: Option<&RawInventoryObject>,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = inventory_properties(inventory_object);
    insert_string(&mut properties, "authid", &package.authid);
    insert_bool(&mut properties, "has_body", package.body.is_some());
    insert_i64(
        &mut properties,
        "specification_bytes",
        package
            .specification
            .as_ref()
            .map_or(0, |definition| definition.len()) as i64,
    );
    insert_i64(
        &mut properties,
        "body_bytes",
        package
            .body
            .as_ref()
            .map_or(0, |definition| definition.len()) as i64,
    );
    if let Some(body) = body_inventory {
        insert_i64(&mut properties, "body_object_id", body.object_id);
        insert_optional_i64(&mut properties, "body_data_object_id", body.data_object_id);
        insert_string(&mut properties, "body_status", &body.status);
        insert_bool(&mut properties, "body_generated", body.generated);
    }
    properties
}

fn oracle_package_routine_signature(
    routine: &RawPackageRoutine,
    arguments: &[&RawRoutineArgument],
) -> Result<String, CatalogError> {
    let parameters = arguments
        .iter()
        .filter(|argument| argument.position > 0)
        .map(|argument| {
            format!(
                "{} {}",
                argument.mode,
                format_oracle_argument_type(argument)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let return_type = arguments
        .iter()
        .find(|argument| argument.position == 0)
        .map(|argument| format!("->{}", format_oracle_argument_type(argument)))
        .unwrap_or_default();
    let signature = format!("{}({parameters}){return_type}", routine.name);
    if signature.len() > MAX_ROUTINE_SIGNATURE_BYTES {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle package routine signature exceeds {MAX_ROUTINE_SIGNATURE_BYTES} bytes for {}.{}.{}",
            routine.owner, routine.package, routine.name
        )));
    }
    Ok(signature)
}

fn oracle_package_routine_properties(
    routine: &RawPackageRoutine,
    signature: &str,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_i64(&mut properties, "object_id", routine.object_id);
    insert_i64(&mut properties, "subprogram_id", routine.subprogram_id);
    insert_optional_string(&mut properties, "overload", routine.overload.as_deref());
    insert_string(&mut properties, "signature", signature);
    insert_bool(&mut properties, "aggregate", routine.aggregate);
    insert_bool(&mut properties, "pipelined", routine.pipelined);
    insert_bool(&mut properties, "parallel", routine.parallel);
    insert_bool(&mut properties, "interface", routine.interface);
    insert_bool(&mut properties, "deterministic", routine.deterministic);
    insert_string(&mut properties, "authid", &routine.authid);
    insert_optional_string(
        &mut properties,
        "polymorphic",
        routine.polymorphic.as_deref(),
    );
    properties
}

fn format_oracle_argument_type(argument: &RawRoutineArgument) -> String {
    let data_type = argument
        .data_type
        .as_deref()
        .unwrap_or("UNSPECIFIED")
        .to_owned();
    match data_type.as_str() {
        "NUMBER" => match (argument.data_precision, argument.data_scale) {
            (Some(precision), Some(scale)) => format!("{data_type}({precision},{scale})"),
            (Some(precision), None) => format!("{data_type}({precision})"),
            _ => data_type,
        },
        "CHAR" | "VARCHAR2" | "NCHAR" | "NVARCHAR2" => argument
            .char_length
            .map(|length| {
                let unit = match argument.char_used.as_deref() {
                    Some("C") => " CHAR",
                    Some("B") => " BYTE",
                    _ => "",
                };
                format!("{data_type}({length}{unit})")
            })
            .unwrap_or(data_type),
        _ => data_type,
    }
}

fn constraint_properties(constraint: &RawConstraint) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "status", &constraint.status);
    insert_string(&mut properties, "deferrable", &constraint.deferrable);
    insert_string(&mut properties, "deferred", &constraint.deferred);
    insert_string(&mut properties, "validated", &constraint.validated);
    insert_string(&mut properties, "generated", &constraint.generated);
    insert_optional_string(
        &mut properties,
        "delete_rule",
        constraint.delete_rule.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "index_owner",
        constraint.index_owner.as_deref(),
    );
    insert_optional_string(
        &mut properties,
        "index_name",
        constraint.index_name.as_deref(),
    );
    insert_optional_string(&mut properties, "invalid", constraint.invalid.as_deref());
    insert_optional_string(
        &mut properties,
        "view_related",
        constraint.view_related.as_deref(),
    );
    properties
}

fn format_oracle_data_type(column: &RawColumn) -> String {
    let type_name = column
        .data_type_owner
        .as_deref()
        .map(|owner| format!("{owner}.{}", column.data_type))
        .unwrap_or_else(|| column.data_type.clone());
    match column.data_type.as_str() {
        "NUMBER" => match (column.data_precision, column.data_scale) {
            (Some(precision), Some(scale)) => format!("{type_name}({precision},{scale})"),
            (Some(precision), None) => format!("{type_name}({precision})"),
            _ => type_name,
        },
        "FLOAT" => column
            .data_precision
            .map(|precision| format!("{type_name}({precision})"))
            .unwrap_or(type_name),
        "CHAR" | "VARCHAR2" | "NCHAR" | "NVARCHAR2" => {
            let unit = match column.char_used.as_deref() {
                Some("C") => " CHAR",
                Some("B") => " BYTE",
                _ => "",
            };
            format!(
                "{type_name}({}{unit})",
                column.char_length.unwrap_or(column.data_length)
            )
        }
        "RAW" | "UROWID" => format!("{type_name}({})", column.data_length),
        _ => type_name,
    }
}

fn oracle_complete_capabilities(scope: &DictionaryScope) -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: ORACLE_SOURCE.to_owned(),
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
        notes: vec![format!(
            "{}; unsupported Oracle object shapes fail the analysis instead of producing a partial snapshot",
            scope.mode.label()
        )],
    }
}

fn discovery_counts_from_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
) -> DiscoveryCounts {
    let object_evidence =
        "Oracle USER/DBA dictionary inventory after explicit application-scope filtering";
    let relationship_evidence =
        "Oracle USER/DBA dictionary parent and ordered-column reconciliation";
    let mut objects = ObjectCategory::ALL
        .into_iter()
        .map(|category| {
            (
                category,
                DiscoveredCount {
                    count: 0,
                    evidence: object_evidence.to_owned(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut relationships = RelationshipCategory::ALL
        .into_iter()
        .map(|category| {
            (
                category,
                DiscoveredCount {
                    count: 0,
                    evidence: relationship_evidence.to_owned(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let materialized_view_names = raw
        .materialized_views
        .iter()
        .map(|view| (view.owner.as_str(), view.name.as_str()))
        .collect::<BTreeSet<_>>();
    let base_table_count = raw
        .tables
        .iter()
        .filter(|table| {
            !materialized_view_names.contains(&(table.owner.as_str(), table.name.as_str()))
        })
        .count();
    let base_column_count = raw
        .columns
        .iter()
        .filter(|column| {
            !materialized_view_names.contains(&(column.owner.as_str(), column.table.as_str()))
        })
        .count();
    let materialized_view_column_count = raw.columns.len() - base_column_count;
    let base_constraint_count = raw
        .constraints
        .iter()
        .filter(|constraint| {
            !materialized_view_names
                .contains(&(constraint.owner.as_str(), constraint.table.as_str()))
        })
        .count();
    let materialized_view_constraint_count = raw.constraints.len() - base_constraint_count;
    let base_index_count = raw
        .indexes
        .iter()
        .filter(|index| {
            !materialized_view_names.contains(&(index.table_owner.as_str(), index.table.as_str()))
        })
        .count();
    let materialized_view_index_count = raw.indexes.len() - base_index_count;
    let materialized_view_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| dependency.object_type == "MATERIALIZED VIEW")
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .filter(|dependency| {
            !(dependency.referenced_type == "TABLE"
                && dependency.owner == dependency.referenced_owner
                && dependency.name == dependency.referenced_name)
        })
        .count();
    let trigger_targets = raw
        .triggers
        .iter()
        .filter_map(|trigger| {
            if !matches!(trigger.base_object_type.as_str(), "TABLE" | "VIEW") {
                return None;
            }
            Some((
                (trigger.owner.as_str(), trigger.name.as_str()),
                (
                    trigger.table_owner.as_deref()?,
                    trigger.table_name.as_deref()?,
                    trigger.base_object_type.as_str(),
                ),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let trigger_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| dependency.object_type == "TRIGGER")
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .filter(|dependency| {
            trigger_targets
                .get(&(dependency.owner.as_str(), dependency.name.as_str()))
                .is_none_or(|target| {
                    !(dependency.referenced_owner == target.0
                        && dependency.referenced_name == target.1
                        && dependency.referenced_type == target.2)
                })
        })
        .count();
    let routine_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| matches!(dependency.object_type.as_str(), "FUNCTION" | "PROCEDURE"))
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .filter(|dependency| dependency.referenced_type != "TYPE")
        .count();
    let metadata_only_type_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| {
            matches!(
                dependency.object_type.as_str(),
                "VIEW" | "FUNCTION" | "PROCEDURE"
            ) && dependency.referenced_type == "TYPE"
        })
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .count();
    let package_dependency_count = oracle_package_dependency_groups(&raw.dependencies).len();
    let type_dependency_count = oracle_type_dependency_groups(&raw.dependencies).len();
    let synonym_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| dependency.object_type == "SYNONYM")
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .count();
    let type_reference_count = raw
        .type_attributes
        .iter()
        .filter(|attribute| attribute.data_type_owner.is_some())
        .count()
        + raw
            .collection_types
            .iter()
            .filter(|collection| collection.element_type_owner.is_some())
            .count()
        + raw
            .type_method_parameters
            .iter()
            .filter(|parameter| parameter.data_type_owner.is_some())
            .count()
        + raw
            .columns
            .iter()
            .filter(|column| column.data_type_owner.is_some())
            .count()
        + raw
            .view_columns
            .iter()
            .filter(|column| column.data_type_owner.is_some())
            .count()
        + raw
            .routine_arguments
            .iter()
            .filter(|argument| argument.type_owner.is_some())
            .count()
        + raw
            .package_arguments
            .iter()
            .filter(|argument| argument.type_owner.is_some())
            .count();
    let type_inheritance_count = raw
        .user_types
        .iter()
        .filter(|user_type| user_type.supertype_owner.is_some())
        .count();

    set_object_count(&mut objects, ObjectCategory::Database, 1);
    set_object_count(&mut objects, ObjectCategory::Schema, scope.owners.len());
    set_object_count(&mut objects, ObjectCategory::Table, base_table_count);
    set_object_count(&mut objects, ObjectCategory::Column, base_column_count);
    set_object_count(&mut objects, ObjectCategory::Index, raw.indexes.len());
    set_object_count(&mut objects, ObjectCategory::Sequence, raw.sequences.len());
    set_object_count(&mut objects, ObjectCategory::View, raw.views.len());
    set_object_count(&mut objects, ObjectCategory::Synonym, raw.synonyms.len());
    set_object_count(
        &mut objects,
        ObjectCategory::UserDefinedType,
        raw.user_types.len(),
    );
    set_object_count(
        &mut objects,
        ObjectCategory::Extension,
        raw.type_attributes.len()
            + raw.table_partitions.len()
            + raw.table_subpartitions.len()
            + raw.index_partitions.len()
            + raw.index_subpartitions.len()
            + raw.lobs.len()
            + raw.lob_partitions.len()
            + raw.lob_subpartitions.len(),
    );
    set_object_count(&mut objects, ObjectCategory::Trigger, raw.triggers.len());
    set_object_count(
        &mut objects,
        ObjectCategory::Routine,
        raw.routines.len() + raw.package_routines.len() + raw.type_methods.len(),
    );
    set_object_count(
        &mut objects,
        ObjectCategory::RoutineParameter,
        raw.routine_arguments.len()
            + raw.package_arguments.len()
            + raw.type_method_parameters.len(),
    );
    set_object_count(&mut objects, ObjectCategory::Package, raw.packages.len());
    set_object_count(
        &mut objects,
        ObjectCategory::ViewColumn,
        raw.view_columns.len() + materialized_view_column_count,
    );
    set_object_count(
        &mut objects,
        ObjectCategory::MaterializedView,
        raw.materialized_views.len(),
    );
    set_object_count(
        &mut objects,
        ObjectCategory::Principal,
        scope.principals.len(),
    );
    for constraint in &raw.constraints {
        let category = match constraint.constraint_type.as_str() {
            "P" => ObjectCategory::PrimaryKey,
            "R" => ObjectCategory::ForeignKey,
            "U" => ObjectCategory::UniqueConstraint,
            "C" => ObjectCategory::CheckConstraint,
            _ => continue,
        };
        objects.entry(category).and_modify(|count| count.count += 1);
    }

    set_relationship_count(
        &mut relationships,
        RelationshipCategory::DatabaseHasSchema,
        scope.owners.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::SchemaHasTable,
        base_table_count,
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasColumn,
        base_column_count,
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasConstraint,
        base_constraint_count,
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::ConstraintColumn,
        raw.constraints
            .iter()
            .filter(|constraint| {
                !materialized_view_names
                    .contains(&(constraint.owner.as_str(), constraint.table.as_str()))
            })
            .filter(|constraint| constraint.constraint_type != "R")
            .map(|constraint| constraint.columns.len())
            .sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::ForeignKeyColumnPair,
        raw.constraints
            .iter()
            .filter(|constraint| {
                !materialized_view_names
                    .contains(&(constraint.owner.as_str(), constraint.table.as_str()))
            })
            .filter(|constraint| constraint.constraint_type == "R")
            .map(|constraint| constraint.columns.len())
            .sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasIndex,
        base_index_count,
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::IndexColumn,
        raw.indexes
            .iter()
            .filter(|index| {
                !materialized_view_names
                    .contains(&(index.table_owner.as_str(), index.table.as_str()))
            })
            .map(|index| {
                index
                    .columns
                    .iter()
                    .filter(|column| column.expression.is_none())
                    .count()
            })
            .sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::SchemaHasView,
        raw.views.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::ViewDependency,
        raw.dependencies
            .iter()
            .filter(|dependency| dependency.object_type == "VIEW")
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
            .filter(|dependency| dependency.referenced_type != "TYPE")
            .count(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TriggerTarget,
        trigger_targets.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::SchemaHasRoutine,
        raw.routines.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::RoutineDependency,
        routine_dependency_count,
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::MetadataParent,
        scope.principals.len()
            + raw.sequences.len()
            + raw.synonyms.len()
            + raw.user_types.len()
            + raw.type_attributes.len()
            + raw.table_partitions.len()
            + raw.table_subpartitions.len()
            + raw.index_partitions.len()
            + raw.index_subpartitions.len()
            + raw.lobs.len()
            + raw.lob_partitions.len()
            + raw.lob_subpartitions.len()
            + raw.type_methods.len()
            + raw.type_method_parameters.len()
            + raw.view_columns.len()
            + raw.materialized_views.len()
            + materialized_view_column_count
            + materialized_view_constraint_count
            + materialized_view_index_count
            + raw.routine_arguments.len()
            + raw.packages.len()
            + raw.package_routines.len()
            + raw.package_arguments.len()
            + raw
                .triggers
                .iter()
                .filter(|trigger| {
                    matches!(trigger.base_object_type.as_str(), "SCHEMA" | "DATABASE")
                })
                .count(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::MetadataRelationship,
        raw.identity_columns.len()
            + materialized_view_dependency_count
            + trigger_dependency_count
            + synonym_dependency_count
            + type_dependency_count
            + type_reference_count
            + type_inheritance_count
            + metadata_only_type_dependency_count
            + raw.routine_arguments.len()
            + raw.package_arguments.len()
            + raw.type_method_parameters.len()
            + package_dependency_count
            + raw.lob_partitions.len()
            + raw.lob_subpartitions.len()
            + raw
                .constraints
                .iter()
                .filter(|constraint| {
                    materialized_view_names
                        .contains(&(constraint.owner.as_str(), constraint.table.as_str()))
                })
                .map(|constraint| constraint.columns.len())
                .sum::<usize>()
            + raw
                .indexes
                .iter()
                .filter(|index| {
                    materialized_view_names
                        .contains(&(index.table_owner.as_str(), index.table.as_str()))
                })
                .map(|index| {
                    index
                        .columns
                        .iter()
                        .filter(|column| column.expression.is_none())
                        .count()
                })
                .sum::<usize>(),
    );

    DiscoveryCounts {
        objects,
        relationships,
    }
}

fn set_object_count(
    counts: &mut BTreeMap<ObjectCategory, DiscoveredCount>,
    category: ObjectCategory,
    count: usize,
) {
    counts
        .get_mut(&category)
        .expect("all object categories exist")
        .count = count as u64;
}

fn set_relationship_count(
    counts: &mut BTreeMap<RelationshipCategory, DiscoveredCount>,
    category: RelationshipCategory,
    count: usize,
) {
    counts
        .get_mut(&category)
        .expect("all relationship categories exist")
        .count = count as u64;
}

fn oracle_key(
    connection_alias: &str,
    database: &str,
    schema: &str,
    kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        ORACLE_SOURCE,
        connection_alias,
        database,
        schema,
        kind,
        object_name,
        sub_object,
    )
}

fn required<T>(value: Option<&T>, subject: impl Into<String>) -> Result<&T, CatalogError> {
    value.ok_or_else(|| {
        CatalogError::Mapping(format!("missing {subject}", subject = subject.into()))
    })
}

fn positive_u32(value: i64, subject: &str) -> Result<u32, CatalogError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| CatalogError::Mapping(format!("invalid {subject}: {value}")))
}

fn insert_bool(properties: &mut BTreeMap<String, MetadataValue>, name: &str, value: bool) {
    properties.insert(name.to_owned(), MetadataValue::Boolean(value));
}

fn insert_i64(properties: &mut BTreeMap<String, MetadataValue>, name: &str, value: i64) {
    properties.insert(name.to_owned(), MetadataValue::Integer(value));
}

fn insert_optional_i64(
    properties: &mut BTreeMap<String, MetadataValue>,
    name: &str,
    value: Option<i64>,
) {
    if let Some(value) = value {
        insert_i64(properties, name, value);
    }
}

fn insert_string(
    properties: &mut BTreeMap<String, MetadataValue>,
    name: &str,
    value: impl ToString,
) {
    properties.insert(name.to_owned(), MetadataValue::String(value.to_string()));
}

fn insert_optional_string(
    properties: &mut BTreeMap<String, MetadataValue>,
    name: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        insert_string(properties, name, value);
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStatus};

    use super::*;

    #[test]
    fn connection_parser_preserves_password_delimiters() {
        let parsed =
            parse_oracle_connection_string("backend/pa/ss@word@127.0.0.1:1521/FREEPDB1").unwrap();

        assert_eq!(parsed.username, "backend");
        assert_eq!(parsed.password, "pa/ss@word");
        assert_eq!(parsed.connect_string, "127.0.0.1:1521/FREEPDB1");
        assert!(parse_oracle_connection_string("missing-delimiters").is_err());
        assert!(parse_oracle_connection_string("/@host").is_err());
    }

    #[test]
    fn connection_policy_requires_tcps_away_from_loopback() {
        let request = request();

        assert!(
            validate_connection_policy(&request, "backend/secret@127.0.0.1:1521/FREEPDB1").is_ok()
        );
        assert!(validate_connection_policy(&request, "backend/secret@[::1]:1521/FREEPDB1").is_ok());
        assert!(validate_connection_policy(
            &request,
            "backend/secret@tcps://oracle.example.com:1522/FREEPDB1"
        )
        .is_ok());

        let failure =
            validate_connection_policy(&request, "backend/secret@oracle.example.com:1521/FREEPDB1")
                .unwrap_err();
        assert_eq!(failure.code, AnalysisFailureCode::UnsafeSource);
        assert!(!failure.message.contains("secret"));
    }

    #[test]
    fn version_strategy_accepts_only_the_live_certified_release() {
        assert_eq!(
            OracleCatalogVersion::detect(
                &Version::new(23, 26, 2, 0, 0),
                "Oracle AI Database 26ai Free Release 23.26.2.0.0"
            )
            .unwrap(),
            OracleCatalogVersion::Oracle26Ai
        );
        assert!(
            OracleCatalogVersion::detect(&Version::new(19, 0, 0, 0, 0), "Oracle Database 19c")
                .is_err()
        );
        assert!(
            OracleCatalogVersion::detect(&Version::new(23, 0, 0, 0, 0), "Oracle Database 23c")
                .is_err()
        );
    }

    #[test]
    fn stability_gate_rejects_catalog_changes() {
        assert_eq!(
            require_stable_catalog(vec![1, 2], &vec![1, 2]).unwrap(),
            vec![1, 2]
        );
        assert!(matches!(
            require_stable_catalog(vec![1, 2], &vec![1, 3]),
            Err(CatalogError::CatalogChanged(_))
        ));
    }

    #[test]
    fn dynamic_plsql_detection_ignores_literals_and_comments() {
        reject_dynamic_plsql(
            "trigger",
            "STATIC_TRIGGER",
            "BEGIN -- EXECUTE IMMEDIATE ignored\n :NEW.note := q'[DBMS_SQL.PARSE]'; END;",
        )
        .unwrap();
        for body in [
            "BEGIN EXECUTE IMMEDIATE statement_text; END;",
            "BEGIN DBMS_SQL.PARSE(cursor_id, statement_text, DBMS_SQL.NATIVE); END;",
            "BEGIN OPEN result_set FOR statement_text; END;",
            "BEGIN DBMS_UTILITY.EXEC_DDL_STATEMENT(statement_text); END;",
        ] {
            assert!(matches!(
                reject_dynamic_plsql("trigger", "DYNAMIC_TRIGGER", body),
                Err(CatalogError::UnsupportedMetadata(_))
            ));
        }
    }

    #[test]
    fn oracle_catalog_live_contract_is_env_gated() {
        let Some(admin_url) = env::var("DATABASE_MEMORY_TEST_ORACLE_URL").ok() else {
            return;
        };
        let parsed = parse_oracle_connection_string(&admin_url).unwrap();
        let connect_string = parsed.connect_string.to_owned();
        let admin = Connection::connect(parsed.username, parsed.password, parsed.connect_string)
            .expect("connect to Oracle certification database");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000;
        let username = format!("DBMCP_T{}_{}", std::process::id(), suffix);
        let password = "DbmcpTest1!";
        admin
            .execute(
                &format!(
                    "CREATE USER {username} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS"
                ),
                &[],
            )
            .expect("create isolated Oracle test user");
        let cleanup = TestUserGuard { admin, username };
        cleanup
            .admin
            .execute(
                &format!(
                    "GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE MATERIALIZED VIEW, CREATE TRIGGER, CREATE PROCEDURE, CREATE SYNONYM, CREATE TYPE, CREATE DATABASE LINK, ADMINISTER DATABASE TRIGGER TO {}",
                    cleanup.username
                ),
                &[],
            )
            .expect("grant metadata fixture privileges");

        let user_url = format!("{}/{password}@{connect_string}", cleanup.username);
        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("connect as isolated Oracle test user");
        setup
            .execute(
                "CREATE TABLE PARENT_ENTITY (ID NUMBER GENERATED BY DEFAULT AS IDENTITY, CODE VARCHAR2(32 CHAR), CONSTRAINT PK_PARENT_ENTITY PRIMARY KEY (ID), CONSTRAINT UQ_PARENT_ENTITY_CODE UNIQUE (CODE), CONSTRAINT CK_PARENT_ENTITY_ID CHECK (ID > 0))",
                &[],
            )
            .expect("create parent table");
        setup
            .execute(
                "CREATE TABLE CHILD_ENTITY (ID NUMBER(10), PARENT_ID NUMBER(10), LABEL VARCHAR2(64 CHAR) DEFAULT 'new', CONSTRAINT PK_CHILD_ENTITY PRIMARY KEY (ID), CONSTRAINT FK_CHILD_PARENT FOREIGN KEY (PARENT_ID) REFERENCES PARENT_ENTITY (ID) ON DELETE CASCADE)",
                &[],
            )
            .expect("create child table");
        setup
            .execute(
                "CREATE INDEX IX_CHILD_PARENT ON CHILD_ENTITY (PARENT_ID)",
                &[],
            )
            .expect("create secondary index");
        setup
            .execute(
                "CREATE INDEX IX_PARENT_CODE_SEARCH ON PARENT_ENTITY (UPPER(CODE), ID)",
                &[],
            )
            .expect("create function-based index");
        setup
            .execute(
                "CREATE BITMAP INDEX IX_CHILD_LABEL_BITMAP ON CHILD_ENTITY (LABEL)",
                &[],
            )
            .expect("create bitmap index");
        setup
            .execute(
                "CREATE BITMAP INDEX IX_CHILD_LABEL_BITMAP_FN ON CHILD_ENTITY (UPPER(LABEL))",
                &[],
            )
            .expect("create function-based bitmap index");
        setup
            .execute(
                "CREATE INDEX IX_CHILD_LABEL_DESC ON CHILD_ENTITY (LABEL DESC)",
                &[],
            )
            .expect("create descending function-based index");
        setup
            .execute("CREATE SEQUENCE AUDIT_SEQUENCE START WITH 10", &[])
            .expect("create explicit sequence");
        setup
            .execute(
                "CREATE TYPE ADDRESS_T AS OBJECT (STREET VARCHAR2(100), ZIP_CODE VARCHAR2(12))",
                &[],
            )
            .expect("create object type");
        setup
            .execute("CREATE TYPE ADDRESS_LIST_T AS TABLE OF ADDRESS_T", &[])
            .expect("create nested-table type");
        setup
            .execute("CREATE TYPE TAG_LIST_T AS VARRAY(5) OF VARCHAR2(30)", &[])
            .expect("create varray type");
        setup
            .execute(
                "CREATE TYPE PERSON_T AS OBJECT (NAME VARCHAR2(100), ADDRESS ADDRESS_T, MEMBER FUNCTION DISPLAY_NAME(P_PREFIX VARCHAR2) RETURN VARCHAR2) NOT FINAL",
                &[],
            )
            .expect("create object type with method");
        setup
            .execute(
                "CREATE TYPE BODY PERSON_T AS MEMBER FUNCTION DISPLAY_NAME(P_PREFIX VARCHAR2) RETURN VARCHAR2 IS BEGIN RETURN P_PREFIX || NAME; END; END;",
                &[],
            )
            .expect("create object type body");
        setup
            .execute(
                "CREATE TYPE EMPLOYEE_T UNDER PERSON_T (EMPLOYEE_NO NUMBER)",
                &[],
            )
            .expect("create object subtype");
        setup
            .execute(
                "CREATE TABLE TYPE_USAGE (ID NUMBER, ADDRESS ADDRESS_T, TAGS TAG_LIST_T)",
                &[],
            )
            .expect("create typed-column table");
        setup
            .execute(
                "CREATE TABLE LOB_DOCUMENTS (ID NUMBER, CONTENT CLOB, BINARY_CONTENT BLOB)",
                &[],
            )
            .expect("create unpartitioned LOB table");
        setup
            .execute(
                "CREATE TABLE PARTITIONED_EVENTS (ID NUMBER, EVENT_DATE DATE, REGION VARCHAR2(10), PAYLOAD CLOB) LOB (PAYLOAD) STORE AS SECUREFILE PARTITION BY RANGE (EVENT_DATE) SUBPARTITION BY HASH (REGION) SUBPARTITIONS 2 (PARTITION P_2025 VALUES LESS THAN (DATE '2026-01-01'), PARTITION P_MAX VALUES LESS THAN (MAXVALUE))",
                &[],
            )
            .expect("create composite-partitioned table");
        setup
            .execute(
                "CREATE INDEX IX_PART_EVENTS_LOCAL ON PARTITIONED_EVENTS (EVENT_DATE) LOCAL",
                &[],
            )
            .expect("create local composite-partitioned index");
        setup
            .execute(
                "CREATE INDEX IX_PART_EVENTS_GLOBAL ON PARTITIONED_EVENTS (ID) GLOBAL PARTITION BY RANGE (ID) (PARTITION IP_LOW VALUES LESS THAN (1000), PARTITION IP_MAX VALUES LESS THAN (MAXVALUE))",
                &[],
            )
            .expect("create global partitioned index");
        setup
            .execute(
                "CREATE VIEW ACTIVE_PARENT AS SELECT ID, CODE FROM PARENT_ENTITY WHERE ID > 0",
                &[],
            )
            .expect("create view");
        setup
            .execute(
                "CREATE OR REPLACE FUNCTION NORMALIZE_LABEL(P_LABEL IN VARCHAR2) RETURN VARCHAR2 DETERMINISTIC AUTHID CURRENT_USER AS BEGIN RETURN UPPER(P_LABEL); END;",
                &[],
            )
            .expect("create standalone function");
        setup
            .execute(
                "CREATE OR REPLACE FUNCTION ECHO_ADDRESS(P_ADDRESS IN ADDRESS_T) RETURN ADDRESS_T AUTHID DEFINER AS BEGIN RETURN P_ADDRESS; END;",
                &[],
            )
            .expect("create standalone function using an object type");
        setup
            .execute(
                "CREATE OR REPLACE PROCEDURE UPDATE_CHILD_LABEL(P_ID IN NUMBER, P_LABEL IN VARCHAR2 DEFAULT 'new', P_ROWS OUT NUMBER) AUTHID DEFINER AS BEGIN UPDATE CHILD_ENTITY SET LABEL = P_LABEL WHERE ID = P_ID; P_ROWS := SQL%ROWCOUNT; END;",
                &[],
            )
            .expect("create standalone procedure");
        setup
            .execute(
                "CREATE OR REPLACE PACKAGE ITEM_API AUTHID DEFINER AS PROCEDURE TOUCH(P_ID IN NUMBER); PROCEDURE TOUCH(P_LABEL IN VARCHAR2); FUNCTION LABEL_FOR(P_ID IN NUMBER) RETURN VARCHAR2; END ITEM_API;",
                &[],
            )
            .expect("create package specification");
        setup
            .execute(
                "CREATE OR REPLACE PACKAGE BODY ITEM_API AS PROCEDURE PRIVATE_HELPER(P_TEXT IN VARCHAR2) AS BEGIN NULL; END; PROCEDURE TOUCH(P_ID IN NUMBER) AS BEGIN UPDATE CHILD_ENTITY SET LABEL = LABEL WHERE ID = P_ID; END; PROCEDURE TOUCH(P_LABEL IN VARCHAR2) AS BEGIN UPDATE CHILD_ENTITY SET LABEL = P_LABEL; END; FUNCTION LABEL_FOR(P_ID IN NUMBER) RETURN VARCHAR2 AS V_LABEL VARCHAR2(64); BEGIN SELECT LABEL INTO V_LABEL FROM CHILD_ENTITY WHERE ID = P_ID; PRIVATE_HELPER(V_LABEL); RETURN V_LABEL; END; END ITEM_API;",
                &[],
            )
            .expect("create package body");
        for statement in [
            "CREATE SYNONYM CHILD_ALIAS FOR CHILD_ENTITY",
            "CREATE SYNONYM ACTIVE_PARENT_ALIAS FOR ACTIVE_PARENT",
            "CREATE SYNONYM AUDIT_SEQUENCE_ALIAS FOR AUDIT_SEQUENCE",
            "CREATE SYNONYM NORMALIZE_LABEL_ALIAS FOR NORMALIZE_LABEL",
            "CREATE SYNONYM ITEM_API_ALIAS FOR ITEM_API",
            "CREATE SYNONYM CHILD_ALIAS_CHAIN FOR CHILD_ALIAS",
        ] {
            setup.execute(statement, &[]).expect("create local synonym");
        }
        drop(setup);

        let timed_out = analyze_oracle(&user_url, "oracle-timeout-live", Vec::new(), Vec::new(), 1);
        assert_eq!(timed_out.status(), AnalysisStatus::Failed);
        let timed_out_failure = timed_out.failure().expect("bounded deadline must fail");
        assert_eq!(
            timed_out_failure.code,
            AnalysisFailureCode::Timeout,
            "unexpected Oracle timeout failure: {timed_out_failure:?}"
        );
        assert!(timed_out.certified_snapshot().is_none());

        let reader = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("connect Oracle read-only stability reader");
        reader
            .set_call_timeout(Some(Duration::from_secs(30)))
            .expect("set Oracle stability reader timeout");
        reader
            .execute("SET TRANSACTION READ ONLY", &[])
            .expect("start Oracle read-only stability transaction");
        let deadline = Instant::now() + Duration::from_secs(30);
        let facts = ServerFacts::read(&reader, deadline).expect("read Oracle stability facts");
        let scope = DictionaryScope::select(&reader, &request(), &facts, deadline)
            .expect("select Oracle stability dictionary scope");
        let before = RawOracleCatalog::read(&reader, &scope, deadline)
            .expect("read Oracle catalog before concurrent DDL");

        let mutator = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("connect Oracle catalog mutator");
        mutator
            .execute("CREATE TABLE CATALOG_MUTATION_PROBE (ID NUMBER)", &[])
            .expect("create concurrent Oracle catalog mutation");
        let during = RawOracleCatalog::read(&reader, &scope, deadline)
            .expect("read Oracle catalog after concurrent DDL in the same snapshot");
        assert_eq!(before, during);
        reader
            .rollback()
            .expect("finish Oracle read-only stability transaction");

        reader
            .execute("SET TRANSACTION READ ONLY", &[])
            .expect("start fresh Oracle read-only transaction");
        let deadline = Instant::now() + Duration::from_secs(30);
        let facts =
            ServerFacts::read(&reader, deadline).expect("read fresh Oracle stability facts");
        let scope = DictionaryScope::select(&reader, &request(), &facts, deadline)
            .expect("select fresh Oracle stability dictionary scope");
        let after = RawOracleCatalog::read(&reader, &scope, deadline)
            .expect("read Oracle catalog in a fresh snapshot");
        assert_ne!(before, after);
        reader
            .rollback()
            .expect("finish fresh Oracle read-only transaction");
        mutator
            .execute("DROP TABLE CATALOG_MUTATION_PROBE PURGE", &[])
            .expect("drop concurrent Oracle catalog mutation");

        let complete = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(
            complete.status(),
            AnalysisStatus::Complete,
            "Oracle live analysis failed: {:?}",
            complete.failure()
        );
        let certified = complete
            .certified_snapshot()
            .expect("simple Oracle schema must be certified");
        let dba_complete = analyze_oracle(
            &admin_url,
            "oracle-dba-live",
            Vec::new(),
            vec![cleanup.username.clone()],
            30_000,
        );
        assert_eq!(
            dba_complete.status(),
            AnalysisStatus::Complete,
            "Oracle DBA-scope analysis failed: {:?}",
            dba_complete.failure()
        );
        let dba_certified = dba_complete
            .certified_snapshot()
            .expect("DBA-scoped Oracle schema must be certified");
        assert_eq!(dba_certified.snapshot.schema.tables.len(), 5);
        assert_eq!(
            dba_certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| { object.extension_kind.as_deref() == Some("oracle_lob_storage") })
                .count(),
            3
        );
        assert!(dba_certified.snapshot.schema.indexes.iter().any(|index| {
            index.name == "IX_PARENT_CODE_SEARCH"
                && index
                    .expression
                    .as_deref()
                    .is_some_and(|expression| expression.contains("UPPER"))
        }));
        assert_eq!(certified.snapshot.schema.tables.len(), 5);
        assert!(certified
            .snapshot
            .schema
            .constraints
            .iter()
            .any(|constraint| constraint.kind == ConstraintKind::ForeignKey));
        assert!(certified.snapshot.schema.indexes.len() >= 7);
        let function_index = certified
            .snapshot
            .schema
            .indexes
            .iter()
            .find(|index| index.name == "IX_PARENT_CODE_SEARCH")
            .expect("function-based index is mapped");
        assert_eq!(function_index.columns.len(), 1);
        assert_eq!(function_index.columns[0].sub_object.as_deref(), Some("ID"));
        assert!(function_index
            .expression
            .as_deref()
            .is_some_and(|expression| expression.contains("UPPER") && expression.contains("CODE")));
        let function_index_annotation = certified
            .snapshot
            .metadata
            .annotations
            .iter()
            .find(|annotation| annotation.object_key == function_index.key)
            .expect("function-based index evidence is mapped");
        assert!(matches!(
            function_index_annotation.properties.get("index_type"),
            Some(MetadataValue::String(value)) if value == "FUNCTION-BASED NORMAL"
        ));
        assert!(matches!(
            function_index_annotation.properties.get("function_status"),
            Some(MetadataValue::String(value)) if value == "ENABLED"
        ));
        assert!(matches!(
            function_index_annotation.properties.get("key_parts"),
            Some(MetadataValue::StringList(parts))
                if parts.len() == 2 && parts[0].contains("UPPER") && parts[1] == "ID"
        ));
        let bitmap_index = certified
            .snapshot
            .schema
            .indexes
            .iter()
            .find(|index| index.name == "IX_CHILD_LABEL_BITMAP")
            .expect("bitmap index is mapped");
        assert_eq!(bitmap_index.columns.len(), 1);
        assert_eq!(bitmap_index.columns[0].sub_object.as_deref(), Some("LABEL"));
        assert!(bitmap_index.expression.is_none());
        let function_bitmap_index = certified
            .snapshot
            .schema
            .indexes
            .iter()
            .find(|index| index.name == "IX_CHILD_LABEL_BITMAP_FN")
            .expect("function-based bitmap index is mapped");
        assert!(function_bitmap_index.columns.is_empty());
        assert!(function_bitmap_index
            .expression
            .as_deref()
            .is_some_and(|expression| expression.contains("UPPER")));
        let descending_index = certified
            .snapshot
            .schema
            .indexes
            .iter()
            .find(|index| index.name == "IX_CHILD_LABEL_DESC")
            .expect("descending index is mapped");
        assert!(descending_index.columns.is_empty());
        assert!(
            descending_index
                .expression
                .as_deref()
                .is_some_and(
                    |expression| expression.contains("LABEL") && expression.ends_with("DESC")
                )
        );
        assert!(
            certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| object.key.object_kind == ObjectKind::Sequence)
                .count()
                >= 2
        );
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| relationship.kind == MetadataRelationshipKind::UsesSequence));
        let view = certified
            .snapshot
            .schema
            .views
            .iter()
            .find(|view| view.name == "ACTIVE_PARENT")
            .expect("view is mapped");
        assert!(view
            .depends_on
            .iter()
            .any(|key| key.object_kind == ObjectKind::Table && key.object_name == "PARENT_ENTITY"));
        assert_eq!(
            certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| object.key.object_kind == ObjectKind::ViewColumn)
                .count(),
            2
        );
        assert_eq!(certified.snapshot.schema.routines.len(), 3);
        let procedure = certified
            .snapshot
            .schema
            .routines
            .iter()
            .find(|routine| routine.name == "UPDATE_CHILD_LABEL")
            .expect("standalone procedure is mapped");
        assert!(procedure
            .depends_on
            .iter()
            .any(|key| key.object_kind == ObjectKind::Table && key.object_name == "CHILD_ENTITY"));
        assert_eq!(
            certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| object.key.object_kind == ObjectKind::RoutineParameter)
                .count(),
            17
        );
        let user_types = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| object.key.object_kind == ObjectKind::UserDefinedType)
            .collect::<Vec<_>>();
        assert_eq!(user_types.len(), 5);
        let person_type = user_types
            .iter()
            .find(|object| object.name == "PERSON_T")
            .expect("object type is mapped");
        assert!(person_type
            .definition
            .as_deref()
            .is_some_and(|definition| definition.contains("TYPE BODY PERSON_T")));
        assert!(matches!(
            person_type.properties.get("has_body"),
            Some(MetadataValue::Boolean(true))
        ));
        let employee_type = user_types
            .iter()
            .find(|object| object.name == "EMPLOYEE_T")
            .expect("object subtype is mapped");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::InheritsFrom
                    && relationship.from_key == employee_type.key
                    && relationship.to_key == person_type.key
            }));
        let address_type = user_types
            .iter()
            .find(|object| object.name == "ADDRESS_T")
            .expect("referenced object type is mapped");
        let address_list_type = user_types
            .iter()
            .find(|object| object.name == "ADDRESS_LIST_T")
            .expect("nested-table type is mapped");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::UsesType
                    && relationship.from_key == address_list_type.key
                    && relationship.to_key == address_type.key
            }));
        let person_address_attribute = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Extension
                    && object.extension_kind.as_deref() == Some("oracle_type_attribute")
                    && object.parent_key.as_ref() == Some(&person_type.key)
                    && object.name == "ADDRESS"
            })
            .expect("object type attribute is mapped");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::UsesType
                    && relationship.from_key == person_address_attribute.key
                    && relationship.to_key == address_type.key
            }));
        let person_method = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Routine
                    && object.parent_key.as_ref() == Some(&person_type.key)
                    && object.name == "DISPLAY_NAME"
            })
            .expect("object type method is mapped");
        assert_eq!(
            certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| {
                    object.key.object_kind == ObjectKind::RoutineParameter
                        && object.parent_key.as_ref() == Some(&person_method.key)
                })
                .count(),
            3
        );
        let type_usage = certified
            .snapshot
            .schema
            .tables
            .iter()
            .find(|table| table.name == "TYPE_USAGE")
            .expect("typed-column table is mapped");
        for (column_name, target_name) in [("ADDRESS", "ADDRESS_T"), ("TAGS", "TAG_LIST_T")] {
            let column = certified
                .snapshot
                .schema
                .columns
                .iter()
                .find(|column| column.table_key == type_usage.key && column.name == column_name)
                .expect("typed column is mapped");
            assert!(certified
                .snapshot
                .metadata
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.kind == MetadataRelationshipKind::UsesType
                        && relationship.from_key == column.key
                        && relationship.to_key.object_kind == ObjectKind::UserDefinedType
                        && relationship.to_key.object_name == target_name
                }));
        }
        let echo_address = certified
            .snapshot
            .schema
            .routines
            .iter()
            .find(|routine| routine.name == "ECHO_ADDRESS")
            .expect("routine using an object type is mapped");
        assert_eq!(
            certified
                .snapshot
                .metadata
                .relationships
                .iter()
                .filter(|relationship| {
                    relationship.kind == MetadataRelationshipKind::UsesType
                        && relationship.to_key == address_type.key
                        && certified.snapshot.metadata.objects.iter().any(|object| {
                            object.key == relationship.from_key
                                && object.parent_key.as_ref() == Some(&echo_address.key)
                        })
                })
                .count(),
            2
        );
        let partitioned_table = certified
            .snapshot
            .schema
            .tables
            .iter()
            .find(|table| table.name == "PARTITIONED_EVENTS")
            .expect("partitioned table is mapped");
        assert_eq!(partitioned_table.kind, TableKind::Partitioned);
        let partitioned_table_annotation = certified
            .snapshot
            .metadata
            .annotations
            .iter()
            .find(|annotation| annotation.object_key == partitioned_table.key)
            .expect("partitioned table annotation is mapped");
        assert!(matches!(
            partitioned_table_annotation
                .properties
                .get("partition_key_columns"),
            Some(MetadataValue::StringList(columns)) if columns == &["EVENT_DATE"]
        ));
        assert!(matches!(
            partitioned_table_annotation
                .properties
                .get("subpartition_key_columns"),
            Some(MetadataValue::StringList(columns)) if columns == &["REGION"]
        ));
        let table_partitions = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.extension_kind.as_deref() == Some("oracle_table_partition")
                    && object.parent_key.as_ref() == Some(&partitioned_table.key)
            })
            .collect::<Vec<_>>();
        assert_eq!(table_partitions.len(), 2);
        assert!(table_partitions.iter().any(|partition| {
            partition.name == "P_MAX" && partition.definition.as_deref() == Some("MAXVALUE")
        }));
        let table_subpartitions = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.extension_kind.as_deref() == Some("oracle_table_subpartition")
                    && object.parent_key.as_ref().is_some_and(|parent| {
                        table_partitions
                            .iter()
                            .any(|partition| partition.key == *parent)
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(table_subpartitions.len(), 4);
        let lob_storage = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| object.extension_kind.as_deref() == Some("oracle_lob_storage"))
            .collect::<Vec<_>>();
        assert_eq!(lob_storage.len(), 3);
        let payload_column = certified
            .snapshot
            .schema
            .columns
            .iter()
            .find(|column| column.table_key == partitioned_table.key && column.name == "PAYLOAD")
            .expect("partitioned LOB column is mapped");
        let payload_lob = lob_storage
            .iter()
            .find(|object| object.parent_key.as_ref() == Some(&payload_column.key))
            .expect("partitioned LOB storage is mapped");
        assert!(matches!(
            payload_lob.properties.get("partitioned"),
            Some(MetadataValue::Boolean(true))
        ));
        assert!(matches!(
            payload_lob.properties.get("securefile"),
            Some(MetadataValue::Boolean(true))
        ));
        let lob_partitions = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.extension_kind.as_deref() == Some("oracle_lob_partition")
                    && object.parent_key.as_ref() == Some(&payload_lob.key)
            })
            .collect::<Vec<_>>();
        assert_eq!(lob_partitions.len(), 2);
        for partition in &lob_partitions {
            assert!(certified
                .snapshot
                .metadata
                .relationships
                .iter()
                .any(|relationship| {
                    matches!(
                        &relationship.kind,
                        MetadataRelationshipKind::Extension(kind)
                            if kind == "oracle_lob_partition_storage"
                    ) && relationship.from_key == partition.key
                        && table_partitions
                            .iter()
                            .any(|table_partition| table_partition.key == relationship.to_key)
                }));
        }
        let lob_subpartitions = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.extension_kind.as_deref() == Some("oracle_lob_subpartition")
                    && object.parent_key.as_ref().is_some_and(|parent| {
                        lob_partitions
                            .iter()
                            .any(|partition| partition.key == *parent)
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(lob_subpartitions.len(), 4);
        for subpartition in &lob_subpartitions {
            assert!(certified
                .snapshot
                .metadata
                .relationships
                .iter()
                .any(|relationship| {
                    matches!(
                        &relationship.kind,
                        MetadataRelationshipKind::Extension(kind)
                            if kind == "oracle_lob_subpartition_storage"
                    ) && relationship.from_key == subpartition.key
                        && table_subpartitions
                            .iter()
                            .any(|table_subpartition| table_subpartition.key == relationship.to_key)
                }));
        }
        for storage in &lob_storage {
            let Some(MetadataValue::String(index_name)) = storage.properties.get("index_name")
            else {
                panic!("LOB storage must expose its generated index name");
            };
            assert!(certified
                .snapshot
                .schema
                .indexes
                .iter()
                .all(|index| index.name != *index_name));
        }
        assert_eq!(
            lob_storage
                .iter()
                .filter(|storage| matches!(
                    storage.properties.get("partitioned"),
                    Some(MetadataValue::Boolean(false))
                ))
                .count(),
            2
        );
        for (index_name, locality, partition_count, subpartition_count) in [
            ("IX_PART_EVENTS_LOCAL", "LOCAL", 2, 4),
            ("IX_PART_EVENTS_GLOBAL", "GLOBAL", 2, 0),
        ] {
            let index = certified
                .snapshot
                .schema
                .indexes
                .iter()
                .find(|index| index.name == index_name)
                .expect("partitioned index is mapped");
            let annotation = certified
                .snapshot
                .metadata
                .annotations
                .iter()
                .find(|annotation| annotation.object_key == index.key)
                .expect("partitioned index annotation is mapped");
            assert!(matches!(
                annotation.properties.get("locality"),
                Some(MetadataValue::String(value)) if value == locality
            ));
            let partitions = certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| {
                    object.extension_kind.as_deref() == Some("oracle_index_partition")
                        && object.parent_key.as_ref() == Some(&index.key)
                })
                .collect::<Vec<_>>();
            assert_eq!(partitions.len(), partition_count);
            assert_eq!(
                certified
                    .snapshot
                    .metadata
                    .objects
                    .iter()
                    .filter(|object| {
                        object.extension_kind.as_deref() == Some("oracle_index_subpartition")
                            && object.parent_key.as_ref().is_some_and(|parent| {
                                partitions.iter().any(|partition| partition.key == *parent)
                            })
                    })
                    .count(),
                subpartition_count
            );
        }
        let package = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Package && object.name == "ITEM_API"
            })
            .expect("package is mapped");
        assert!(package
            .definition
            .as_deref()
            .is_some_and(|definition| definition.contains("PRIVATE_HELPER")));
        let packaged_routines = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| {
                object.key.object_kind == ObjectKind::Routine
                    && object.parent_key.as_ref() == Some(&package.key)
            })
            .collect::<Vec<_>>();
        assert_eq!(packaged_routines.len(), 3);
        assert_eq!(
            packaged_routines
                .iter()
                .filter(|routine| routine.name == "TOUCH")
                .map(|routine| routine.key.to_string())
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::DependsOn
                    && relationship.from_key == package.key
                    && relationship.to_key.object_kind == ObjectKind::Table
                    && relationship.to_key.object_name == "CHILD_ENTITY"
            }));
        for (synonym_name, target_kind, target_name) in [
            ("CHILD_ALIAS", ObjectKind::Table, "CHILD_ENTITY"),
            ("ACTIVE_PARENT_ALIAS", ObjectKind::View, "ACTIVE_PARENT"),
            (
                "AUDIT_SEQUENCE_ALIAS",
                ObjectKind::Sequence,
                "AUDIT_SEQUENCE",
            ),
            (
                "NORMALIZE_LABEL_ALIAS",
                ObjectKind::Routine,
                "NORMALIZE_LABEL",
            ),
            ("ITEM_API_ALIAS", ObjectKind::Package, "ITEM_API"),
            ("CHILD_ALIAS_CHAIN", ObjectKind::Synonym, "CHILD_ALIAS"),
        ] {
            let synonym = certified
                .snapshot
                .metadata
                .objects
                .iter()
                .find(|object| {
                    object.key.object_kind == ObjectKind::Synonym && object.name == synonym_name
                })
                .expect("synonym is mapped");
            assert!(certified
                .snapshot
                .metadata
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.kind == MetadataRelationshipKind::SynonymFor
                        && relationship.from_key == synonym.key
                        && relationship.to_key.object_kind == target_kind
                        && relationship.to_key.object_name == target_name
                }));
        }

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute(
                "CREATE MATERIALIZED VIEW PARENT_SUMMARY_MV BUILD IMMEDIATE REFRESH COMPLETE ON DEMAND AS SELECT ID, CODE FROM PARENT_ENTITY",
                &[],
            )
            .expect("create materialized view");
        drop(setup);

        let complete = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(
            complete.status(),
            AnalysisStatus::Complete,
            "Oracle materialized-view analysis failed: {:?}",
            complete.failure()
        );
        let certified = complete
            .certified_snapshot()
            .expect("Oracle materialized-view schema must be certified");
        assert_eq!(certified.snapshot.schema.tables.len(), 5);
        assert!(certified
            .snapshot
            .schema
            .tables
            .iter()
            .all(|table| table.name != "PARENT_SUMMARY_MV"));
        let materialized_view = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::MaterializedView
                    && object.name == "PARENT_SUMMARY_MV"
            })
            .expect("materialized view is mapped");
        assert_eq!(
            certified
                .snapshot
                .metadata
                .objects
                .iter()
                .filter(|object| {
                    object.key.object_kind == ObjectKind::ViewColumn
                        && object.parent_key.as_ref() == Some(&materialized_view.key)
                })
                .count(),
            2
        );
        assert!(certified.snapshot.metadata.objects.iter().any(|object| {
            object.key.object_kind == ObjectKind::Index
                && object.parent_key.as_ref() == Some(&materialized_view.key)
        }));
        assert!(certified.snapshot.metadata.objects.iter().any(|object| {
            object.key.object_kind == ObjectKind::PrimaryKey
                && object.parent_key.as_ref() == Some(&materialized_view.key)
        }));
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::Materializes
                    && relationship.from_key == materialized_view.key
                    && relationship.to_key.object_kind == ObjectKind::Table
                    && relationship.to_key.object_name == "PARENT_ENTITY"
            }));

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute(
                "CREATE OR REPLACE PROCEDURE LOG_CHILD(P_ID IN NUMBER) AS BEGIN NULL; END;",
                &[],
            )
            .expect("create CALL trigger routine");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER CHILD_LABEL_BIU BEFORE INSERT OR UPDATE ON CHILD_ENTITY FOR EACH ROW BEGIN :NEW.LABEL := NORMALIZE_LABEL(:NEW.LABEL); END;",
                &[],
            )
            .expect("create static trigger");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER ACTIVE_PARENT_IO INSTEAD OF INSERT ON ACTIVE_PARENT FOR EACH ROW BEGIN INSERT INTO PARENT_ENTITY (ID, CODE) VALUES (:NEW.ID, :NEW.CODE); END;",
                &[],
            )
            .expect("create view trigger");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER CHILD_LOG_CALL AFTER INSERT ON CHILD_ENTITY FOR EACH ROW CALL LOG_CHILD(:NEW.ID)",
                &[],
            )
            .expect("create CALL trigger");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER SCHEMA_DDL_AUDIT AFTER CREATE ON SCHEMA BEGIN NULL; END;",
                &[],
            )
            .expect("create schema trigger");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER DATABASE_ERROR_AUDIT AFTER SERVERERROR ON DATABASE BEGIN NULL; END;",
                &[],
            )
            .expect("create database trigger");
        setup
            .execute("ALTER TRIGGER DATABASE_ERROR_AUDIT DISABLE", &[])
            .expect("disable database trigger fixture");
        drop(setup);

        let complete = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(
            complete.status(),
            AnalysisStatus::Complete,
            "Oracle trigger analysis failed: {:?}",
            complete.failure()
        );
        let certified = complete
            .certified_snapshot()
            .expect("Oracle trigger schema must be certified");
        let trigger = certified
            .snapshot
            .schema
            .triggers
            .iter()
            .find(|trigger| trigger.name == "CHILD_LABEL_BIU")
            .expect("static trigger is mapped");
        assert_eq!(trigger.timing.as_deref(), Some("BEFORE"));
        assert_eq!(trigger.events, ["INSERT", "UPDATE"]);
        assert_eq!(trigger.table_key.object_name, "CHILD_ENTITY");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::Invokes
                    && relationship.from_key == trigger.key
                    && relationship.to_key.object_kind == ObjectKind::Routine
                    && relationship.to_key.object_name == "NORMALIZE_LABEL"
            }));
        let view_trigger = certified
            .snapshot
            .schema
            .triggers
            .iter()
            .find(|trigger| trigger.name == "ACTIVE_PARENT_IO")
            .expect("view trigger is mapped");
        assert_eq!(view_trigger.table_key.object_kind, ObjectKind::View);
        assert_eq!(view_trigger.table_key.object_name, "ACTIVE_PARENT");
        let call_trigger = certified
            .snapshot
            .schema
            .triggers
            .iter()
            .find(|trigger| trigger.name == "CHILD_LOG_CALL")
            .expect("CALL trigger is mapped");
        assert!(certified
            .snapshot
            .metadata
            .annotations
            .iter()
            .any(|annotation| {
                annotation.object_key == call_trigger.key
                    && matches!(
                        annotation.properties.get("action_type"),
                        Some(MetadataValue::String(value)) if value == "CALL"
                    )
            }));
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::Invokes
                    && relationship.from_key == call_trigger.key
                    && relationship.to_key.object_kind == ObjectKind::Routine
                    && relationship.to_key.object_name == "LOG_CHILD"
            }));
        let schema_trigger = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Trigger && object.name == "SCHEMA_DDL_AUDIT"
            })
            .expect("schema trigger is mapped");
        assert_eq!(
            schema_trigger
                .parent_key
                .as_ref()
                .expect("schema trigger parent")
                .object_kind,
            ObjectKind::Schema
        );
        let database_trigger = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Trigger
                    && object.name == "DATABASE_ERROR_AUDIT"
            })
            .expect("database trigger is mapped");
        assert_eq!(
            database_trigger
                .parent_key
                .as_ref()
                .expect("database trigger parent"),
            &certified.snapshot.schema.database.key
        );
        assert!(matches!(
            database_trigger.properties.get("status"),
            Some(MetadataValue::String(value)) if value == "DISABLED"
        ));

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute(
                &format!(
                    "CREATE DATABASE LINK REMOTE_LOOPBACK CONNECT TO {} IDENTIFIED BY \"{password}\" USING '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)))'",
                    cleanup.username
                ),
                &[],
            )
            .expect("create remote database-link fixture");
        setup
            .execute(
                "CREATE SYNONYM REMOTE_CHILD_ALIAS FOR CHILD_ENTITY@REMOTE_LOOPBACK",
                &[],
            )
            .expect("create remote synonym fixture");
        drop(setup);

        let failed = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(failed.status(), AnalysisStatus::Failed);
        let remote_failure = failed.failure().expect("remote link must fail");
        assert_eq!(
            remote_failure.code,
            AnalysisFailureCode::UnsupportedMetadata,
            "unexpected Oracle remote-link failure: {remote_failure:?}"
        );
        assert!(failed.certified_snapshot().is_none());

        let dba_failed = analyze_oracle(
            &admin_url,
            "oracle-dba-remote-link",
            Vec::new(),
            vec![cleanup.username.clone()],
            30_000,
        );
        assert_eq!(dba_failed.status(), AnalysisStatus::Failed);
        assert_eq!(
            dba_failed
                .failure()
                .expect("DBA-scoped remote link must fail")
                .code,
            AnalysisFailureCode::UnsupportedMetadata
        );
        assert!(dba_failed.certified_snapshot().is_none());

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute("DROP SYNONYM REMOTE_CHILD_ALIAS", &[])
            .expect("drop remote synonym fixture");
        setup
            .execute("DROP DATABASE LINK REMOTE_LOOPBACK", &[])
            .expect("drop remote database-link fixture");
        setup
            .execute(
                "CREATE FORCE VIEW INVALID_PARENT AS SELECT ID FROM MISSING_PARENT",
                &[],
            )
            .expect("create invalid Oracle object fixture");
        drop(setup);

        let failed = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(failed.status(), AnalysisStatus::Failed);
        assert_eq!(
            failed.failure().expect("failed outcome").code,
            AnalysisFailureCode::UnsupportedMetadata
        );
        assert!(failed.certified_snapshot().is_none());

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute("DROP VIEW INVALID_PARENT", &[])
            .expect("drop invalid Oracle object fixture");
        setup
            .execute("CREATE SYNONYM MISSING_ALIAS FOR MISSING_TARGET", &[])
            .expect("create unresolved synonym fixture");
        drop(setup);

        let failed = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(failed.status(), AnalysisStatus::Failed);
        assert!(failed.certified_snapshot().is_none());

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute("DROP SYNONYM MISSING_ALIAS", &[])
            .expect("drop unresolved synonym fixture");
        setup
            .execute(
                "CREATE TYPE DYNAMIC_TYPE_T AS OBJECT (PAYLOAD VARCHAR2(20), MEMBER PROCEDURE RUN_STATEMENT)",
                &[],
            )
            .expect("create dynamic type fixture specification");
        setup
            .execute(
                "CREATE TYPE BODY DYNAMIC_TYPE_T AS MEMBER PROCEDURE RUN_STATEMENT IS BEGIN EXECUTE IMMEDIATE 'BEGIN NULL; END;'; END; END;",
                &[],
            )
            .expect("create dynamic type fixture body");
        drop(setup);

        let failed = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(failed.status(), AnalysisStatus::Failed);
        assert_eq!(
            failed.failure().expect("failed outcome").code,
            AnalysisFailureCode::UnsupportedMetadata
        );
        assert!(failed.certified_snapshot().is_none());

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute("DROP TYPE DYNAMIC_TYPE_T FORCE", &[])
            .expect("drop dynamic type fixture");
        setup
            .execute(
                "CREATE OR REPLACE TRIGGER DYNAMIC_TRIGGER BEFORE UPDATE ON CHILD_ENTITY FOR EACH ROW BEGIN EXECUTE IMMEDIATE 'BEGIN NULL; END;'; END;",
                &[],
            )
            .expect("create fail-closed dynamic trigger fixture");
        drop(setup);

        let failed = analyze_oracle(&user_url, "oracle-live", Vec::new(), Vec::new(), 30_000);
        assert_eq!(failed.status(), AnalysisStatus::Failed);
        assert_eq!(
            failed.failure().expect("failed outcome").code,
            AnalysisFailureCode::UnsupportedMetadata
        );
        assert!(failed.certified_snapshot().is_none());
    }

    #[test]
    fn oracle_multi_schema_contract_is_env_gated() {
        let Some(admin_url) = env::var("DATABASE_MEMORY_TEST_ORACLE_URL").ok() else {
            return;
        };
        let parsed = parse_oracle_connection_string(&admin_url).unwrap();
        let connect_string = parsed.connect_string.to_owned();
        let password = "DbmcpTest1!";
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000;
        let parent_name = format!("DBMCP_P{}_{}", std::process::id(), suffix);
        let child_name = format!("DBMCP_C{}_{}", std::process::id(), suffix);

        let parent_admin =
            Connection::connect(parsed.username, parsed.password, parsed.connect_string)
                .expect("connect to Oracle certification database for parent schema");
        parent_admin
            .execute(
                &format!(
                    "CREATE USER {parent_name} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS"
                ),
                &[],
            )
            .expect("create Oracle parent test user");
        let parent_cleanup = TestUserGuard {
            admin: parent_admin,
            username: parent_name,
        };

        let child_admin =
            Connection::connect(parsed.username, parsed.password, parsed.connect_string)
                .expect("connect to Oracle certification database for child schema");
        child_admin
            .execute(
                &format!(
                    "CREATE USER {child_name} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS"
                ),
                &[],
            )
            .expect("create Oracle child test user");
        let child_cleanup = TestUserGuard {
            admin: child_admin,
            username: child_name,
        };

        for cleanup in [&parent_cleanup, &child_cleanup] {
            cleanup
                .admin
                .execute(
                    &format!(
                        "GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, CREATE SYNONYM, CREATE TYPE TO {}",
                        cleanup.username
                    ),
                    &[],
                )
                .expect("grant Oracle multi-schema fixture privileges");
        }

        let parent = Connection::connect(&parent_cleanup.username, password, &connect_string)
            .expect("connect as Oracle parent test user");
        parent
            .execute(
                "CREATE TABLE SHARED_PARENT (ID NUMBER, CODE VARCHAR2(32), CONSTRAINT PK_SHARED_PARENT PRIMARY KEY (ID))",
                &[],
            )
            .expect("create shared parent table");
        parent
            .execute(
                "CREATE TYPE SHARED_PAYLOAD_T AS OBJECT (VALUE_TEXT VARCHAR2(64))",
                &[],
            )
            .expect("create shared object type");
        parent
            .execute(
                "CREATE FUNCTION SHARED_LABEL(P_ID IN NUMBER) RETURN VARCHAR2 AUTHID DEFINER AS V_CODE VARCHAR2(32); BEGIN SELECT CODE INTO V_CODE FROM SHARED_PARENT WHERE ID = P_ID; RETURN V_CODE; END;",
                &[],
            )
            .expect("create shared function");
        for statement in [
            format!(
                "GRANT SELECT, REFERENCES ON SHARED_PARENT TO {}",
                child_cleanup.username
            ),
            format!(
                "GRANT EXECUTE ON SHARED_PAYLOAD_T TO {}",
                child_cleanup.username
            ),
            format!(
                "GRANT EXECUTE ON SHARED_LABEL TO {}",
                child_cleanup.username
            ),
        ] {
            parent
                .execute(&statement, &[])
                .expect("grant cross-schema object privilege");
        }
        drop(parent);

        let child = Connection::connect(&child_cleanup.username, password, &connect_string)
            .expect("connect as Oracle child test user");
        child
            .execute(
                &format!(
                    "CREATE TABLE CHILD_RECORD (ID NUMBER, PARENT_ID NUMBER, PAYLOAD {}.SHARED_PAYLOAD_T, CONSTRAINT PK_CHILD_RECORD PRIMARY KEY (ID), CONSTRAINT FK_CHILD_SHARED FOREIGN KEY (PARENT_ID) REFERENCES {}.SHARED_PARENT (ID))",
                    parent_cleanup.username, parent_cleanup.username
                ),
                &[],
            )
            .expect("create cross-schema foreign key and typed column");
        child
            .execute(
                &format!(
                    "CREATE VIEW SHARED_PARENT_VIEW AS SELECT ID, CODE FROM {}.SHARED_PARENT",
                    parent_cleanup.username
                ),
                &[],
            )
            .expect("create cross-schema view");
        child
            .execute(
                &format!(
                    "CREATE SYNONYM SHARED_PARENT_ALIAS FOR {}.SHARED_PARENT",
                    parent_cleanup.username
                ),
                &[],
            )
            .expect("create cross-schema synonym");
        child
            .execute(
                &format!(
                    "CREATE PROCEDURE READ_SHARED(P_ID IN NUMBER, P_VALUE OUT VARCHAR2) AUTHID DEFINER AS BEGIN P_VALUE := {}.SHARED_LABEL(P_ID); END;",
                    parent_cleanup.username
                ),
                &[],
            )
            .expect("create cross-schema routine call");
        drop(child);

        let child_url = format!("{}/{password}@{connect_string}", child_cleanup.username);
        let denied = analyze_oracle(
            &child_url,
            "oracle-multi-denied",
            Vec::new(),
            vec![
                parent_cleanup.username.clone(),
                child_cleanup.username.clone(),
            ],
            30_000,
        );
        assert_eq!(denied.status(), AnalysisStatus::Failed);
        assert_eq!(
            denied.failure().expect("denied scope must fail").code,
            AnalysisFailureCode::PermissionDenied
        );
        assert!(denied.certified_snapshot().is_none());

        let incomplete = analyze_oracle(
            &admin_url,
            "oracle-multi-incomplete",
            Vec::new(),
            vec![child_cleanup.username.clone()],
            30_000,
        );
        assert_eq!(incomplete.status(), AnalysisStatus::Failed);
        assert!(incomplete.certified_snapshot().is_none());
        let incomplete_failure = incomplete.failure().expect("incomplete scope must fail");
        assert_eq!(
            incomplete_failure.code,
            AnalysisFailureCode::InvalidConfiguration,
            "unexpected incomplete-scope failure: {incomplete_failure:?}"
        );
        assert!(incomplete_failure.message.contains("relationship-closed"));
        assert!(incomplete_failure
            .message
            .contains(&parent_cleanup.username));

        let complete = analyze_oracle(
            &admin_url,
            "oracle-multi-live",
            Vec::new(),
            vec![
                parent_cleanup.username.clone(),
                child_cleanup.username.clone(),
            ],
            30_000,
        );
        assert_eq!(
            complete.status(),
            AnalysisStatus::Complete,
            "Oracle multi-schema analysis failed: {:?}",
            complete.failure()
        );
        let certified = complete
            .certified_snapshot()
            .expect("Oracle multi-schema snapshot must be certified");
        assert_eq!(certified.snapshot.schema.schemas.len(), 2);
        assert_eq!(certified.snapshot.schema.tables.len(), 2);

        let parent_table = certified
            .snapshot
            .schema
            .tables
            .iter()
            .find(|table| {
                table.key.schema == parent_cleanup.username && table.name == "SHARED_PARENT"
            })
            .expect("cross-schema parent table is mapped");
        let child_table = certified
            .snapshot
            .schema
            .tables
            .iter()
            .find(|table| {
                table.key.schema == child_cleanup.username && table.name == "CHILD_RECORD"
            })
            .expect("cross-schema child table is mapped");
        let foreign_key = certified
            .snapshot
            .schema
            .constraints
            .iter()
            .find(|constraint| {
                constraint.table_key == child_table.key && constraint.name == "FK_CHILD_SHARED"
            })
            .expect("cross-schema foreign key is mapped");
        assert_eq!(
            foreign_key.referenced_table_key.as_ref(),
            Some(&parent_table.key)
        );

        let view = certified
            .snapshot
            .schema
            .views
            .iter()
            .find(|view| {
                view.key.schema == child_cleanup.username && view.name == "SHARED_PARENT_VIEW"
            })
            .expect("cross-schema view is mapped");
        assert!(view.depends_on.contains(&parent_table.key));

        let shared_function = certified
            .snapshot
            .schema
            .routines
            .iter()
            .find(|routine| {
                routine.key.schema == parent_cleanup.username && routine.name == "SHARED_LABEL"
            })
            .expect("shared function is mapped");
        let child_procedure = certified
            .snapshot
            .schema
            .routines
            .iter()
            .find(|routine| {
                routine.key.schema == child_cleanup.username && routine.name == "READ_SHARED"
            })
            .expect("cross-schema procedure is mapped");
        assert!(child_procedure.depends_on.contains(&shared_function.key));

        let shared_type = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::UserDefinedType
                    && object.key.schema == parent_cleanup.username
                    && object.name == "SHARED_PAYLOAD_T"
            })
            .expect("shared object type is mapped");
        let payload_column = certified
            .snapshot
            .schema
            .columns
            .iter()
            .find(|column| column.table_key == child_table.key && column.name == "PAYLOAD")
            .expect("cross-schema typed column is mapped");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::UsesType
                    && relationship.from_key == payload_column.key
                    && relationship.to_key == shared_type.key
            }));

        let synonym = certified
            .snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.key.object_kind == ObjectKind::Synonym
                    && object.key.schema == child_cleanup.username
                    && object.name == "SHARED_PARENT_ALIAS"
            })
            .expect("cross-schema synonym is mapped");
        assert!(certified
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.kind == MetadataRelationshipKind::SynonymFor
                    && relationship.from_key == synonym.key
                    && relationship.to_key == parent_table.key
            }));
    }

    fn request() -> IntrospectionRequest {
        IntrospectionRequest {
            connection_alias: "oracle-test".to_owned(),
            requested_catalogs: Vec::new(),
            requested_schemas: Vec::new(),
            timeout_ms: 30_000,
        }
    }

    struct TestUserGuard {
        admin: Connection,
        username: String,
    }

    impl Drop for TestUserGuard {
        fn drop(&mut self) {
            let _ = self
                .admin
                .execute(&format!("DROP USER {} CASCADE", self.username), &[]);
        }
    }
}
