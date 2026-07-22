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
    if remaining.is_zero() {
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
            let permission = matches!(error.oci_code(), Some(942 | 1031));
            (
                if permission {
                    AnalysisFailureCode::PermissionDenied
                } else {
                    AnalysisFailureCode::MetadataQueryFailed
                },
                error.to_string(),
                if permission {
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
            let permission = matches!(source.oci_code(), Some(942 | 1031));
            (
                if permission {
                    AnalysisFailureCode::PermissionDenied
                } else {
                    AnalysisFailureCode::MetadataQueryFailed
                },
                format!("Oracle {catalog} query failed: {source}"),
                if permission {
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

type PackageDependencyIdentity = (String, String, String, String, String);

#[derive(Default)]
struct PackageDependencyEvidence {
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
    triggers: Vec<RawTrigger>,
    routines: Vec<RawRoutine>,
    routine_arguments: Vec<RawRoutineArgument>,
    packages: Vec<RawPackage>,
    package_routines: Vec<RawPackageRoutine>,
    package_arguments: Vec<RawRoutineArgument>,
    constraints: Vec<RawConstraint>,
    indexes: Vec<RawIndex>,
    dependencies: Vec<RawDependency>,
}

impl RawOracleCatalog {
    fn read(
        connection: &Connection,
        scope: &DictionaryScope,
        deadline: Instant,
    ) -> Result<Self, CatalogError> {
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
            triggers,
            routines,
            routine_arguments,
            packages,
            package_routines,
            package_arguments,
            constraints,
            indexes,
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
            });
        }
    }
    for index in indexes {
        index.columns.sort_by_key(|column| column.position);
    }
    Ok(())
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
) -> BTreeMap<PackageDependencyIdentity, PackageDependencyEvidence> {
    let mut groups = BTreeMap::<PackageDependencyIdentity, PackageDependencyEvidence>::new();
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

fn validate_raw_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
) -> Result<(), CatalogError> {
    let inventory = raw
        .inventory
        .iter()
        .filter(|object| !object.secondary)
        .collect::<Vec<_>>();
    let unsupported = inventory
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
    if let Some(object) = inventory.iter().find(|object| object.subobject.is_some()) {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle subobject inventory is not yet covered: {}.{} ({}, subobject {})",
            object.owner,
            object.name,
            object.object_type,
            object.subobject.as_deref().unwrap_or_default()
        )));
    }
    let mut inventory_ids = BTreeSet::new();
    let mut inventory_keys = BTreeSet::new();
    for object in &inventory {
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

    let mut tables = BTreeSet::new();
    for table in &raw.tables {
        ensure_owner(scope, &table.owner, "table")?;
        if !tables.insert((table.owner.clone(), table.name.clone())) {
            return Err(CatalogError::Mapping(format!(
                "duplicate Oracle table {}.{}",
                table.owner, table.name
            )));
        }
        if table.partitioned || table.iot_type.is_some() || table.nested || table.external {
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
        if trigger.base_object_type != "TABLE" {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle trigger target kind '{}' is not yet covered for {}.{}",
                trigger.base_object_type, trigger.owner, trigger.name
            )));
        }
        let table_owner = trigger.table_owner.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle table trigger {}.{} has no target owner",
                trigger.owner, trigger.name
            ))
        })?;
        let table_name = trigger.table_name.as_deref().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "Oracle table trigger {}.{} has no target table",
                trigger.owner, trigger.name
            ))
        })?;
        ensure_owner(scope, table_owner, "trigger target")?;
        if trigger.owner != table_owner {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "cross-owner Oracle trigger {}.{} on {}.{table_name} is outside the certified contract",
                trigger.owner, trigger.name, table_owner
            )));
        }
        if !tables.contains(&(table_owner.to_owned(), table_name.to_owned())) {
            return Err(CatalogError::Mapping(format!(
                "Oracle trigger {}.{} targets missing table {}.{}",
                trigger.owner, trigger.name, table_owner, table_name
            )));
        }
        if materialized_views.contains(&(table_owner.to_owned(), table_name.to_owned())) {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle trigger {}.{} targets materialized view {}.{table_name}, which is not yet covered",
                trigger.owner, trigger.name, table_owner
            )));
        }
        if trigger.action_type != "PL/SQL" {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle trigger action type '{}' is not yet covered for {}.{}",
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
        if argument.data_level != 0
            || argument.type_owner.is_some()
            || argument.type_name.is_some()
            || argument.type_subname.is_some()
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle composite or user-defined routine argument is not yet covered for {}.{} position {}",
                argument.owner, argument.routine, argument.position
            )));
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
        if argument.data_level != 0
            || argument.type_owner.is_some()
            || argument.type_name.is_some()
            || argument.type_subname.is_some()
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle composite or user-defined package argument is not yet covered for {}.{}.{} position {}",
                argument.owner, package_name, argument.routine, argument.position
            )));
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
        if !source_is_view
            && !source_is_mview
            && !source_is_trigger
            && !source_is_routine
            && !source_is_package
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
        ensure_owner(scope, &dependency.referenced_owner, "dependency target")?;
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
            _ => false,
        };
        if !target_exists {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle dependency target is outside the covered object set: {}.{} ({})",
                dependency.referenced_owner, dependency.referenced_name, dependency.referenced_type
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
    for trigger in &raw.triggers {
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
                    && dependency.referenced_type == "TABLE"
                    && dependency.referenced_owner == target_owner
                    && dependency.referenced_name == target_name
            })
            .count();
        if target_dependency_count != 1 {
            return Err(CatalogError::Mapping(format!(
                "Oracle trigger {}.{} has {target_dependency_count} target-table dependency rows; expected exactly one",
                trigger.owner, trigger.name
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
        ensure_owner(scope, referenced_owner, "foreign-key target")?;
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
        if index.index_type != "NORMAL" || index.partitioned || index.secondary {
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
        for column in &index.columns {
            positive_u32(column.position, "Oracle index column ordinal")?;
            if !positions.insert(column.position) {
                return Err(CatalogError::Mapping(format!(
                    "duplicate Oracle index column ordinal {} for {}.{}",
                    column.position, index.owner, index.name
                )));
            }
            if !column_keys.contains(&(
                index.table_owner.clone(),
                index.table.clone(),
                column.name.clone(),
            )) {
                return Err(CatalogError::Mapping(format!(
                    "Oracle index {}.{} references missing column {}.{}.{}",
                    index.owner, index.name, index.table_owner, index.table, column.name
                )));
            }
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
    if inventory_index_count != raw.indexes.len() {
        return Err(CatalogError::Mapping(format!(
            "Oracle index inventory mismatch: USER/DBA_OBJECTS reports {inventory_index_count}, USER/DBA_INDEXES reports {}",
            raw.indexes.len()
        )));
    }

    Ok(())
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
                key,
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
            .filter(|object| !object.secondary)
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
                kind: if table.temporary {
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
                key,
                parent_key: Some(view_key.clone()),
                name: column.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
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
                key,
                parent_key: Some(view_key.clone()),
                name: column.name.clone(),
                extension_kind: None,
                definition: None,
                properties,
            });
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
                to_key: key,
                ordinal: Some(positive_u32(
                    argument.sequence,
                    "Oracle routine argument relationship ordinal",
                )?),
                properties: BTreeMap::new(),
            });
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
                to_key: key,
                ordinal: Some(positive_u32(
                    argument.sequence,
                    "Oracle package argument relationship ordinal",
                )?),
                properties: BTreeMap::new(),
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
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle view dependency target type '{other}'"
                    )));
                }
            };
            views[*source_position].depends_on.push(target_key.clone());
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
                other => {
                    return Err(CatalogError::Mapping(format!(
                        "unmapped Oracle routine dependency target type '{other}'"
                    )));
                }
            };
            routines[*source_position]
                .depends_on
                .push(target_key.clone());
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
                object_key: key,
                definition: None,
                properties,
            });
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
        for index in &raw.indexes {
            let inventory_object = required(
                inventory.get(&(index.owner.clone(), "INDEX".to_owned(), index.name.clone())),
                format!(
                    "inventory row for Oracle index {}.{}",
                    index.owner, index.name
                ),
            )?;
            let properties = oracle_index_properties(index, inventory_object);
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
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(materialized_view_key.clone()),
                    name: index.name.clone(),
                    extension_kind: None,
                    definition: None,
                    properties,
                });
                for column in &index.columns {
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
            let index_columns = resolve_named_columns(
                &index.table_owner,
                &index.table,
                &index.columns,
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
                expression: None,
            });
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties,
            });
        }

        let mut triggers = Vec::new();
        let mut trigger_keys = BTreeMap::new();
        let mut trigger_targets = BTreeMap::new();
        for trigger in &raw.triggers {
            let table_owner = trigger.table_owner.as_deref().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle trigger {}.{} has no target owner",
                    trigger.owner, trigger.name
                ))
            })?;
            let table_name = trigger.table_name.as_deref().ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "Oracle trigger {}.{} has no target table",
                    trigger.owner, trigger.name
                ))
            })?;
            let table_key = required(
                table_keys.get(&(table_owner.to_owned(), table_name.to_owned())),
                format!(
                    "target table key for Oracle trigger {}.{}",
                    trigger.owner, trigger.name
                ),
            )?;
            let key = oracle_key(
                self.connection_alias,
                &database_name,
                table_owner,
                ObjectKind::Trigger,
                table_name,
                Some(trigger.name.clone()),
            );
            trigger_keys.insert((trigger.owner.clone(), trigger.name.clone()), key.clone());
            trigger_targets.insert(
                (trigger.owner.clone(), trigger.name.clone()),
                (table_owner.to_owned(), table_name.to_owned()),
            );
            triggers.push(TriggerObject {
                key: key.clone(),
                table_key: table_key.clone(),
                name: trigger.name.clone(),
                timing: Some(oracle_trigger_timing(&trigger.trigger_type)?),
                events: oracle_trigger_events(&trigger.triggering_event)?,
                definition: Some(oracle_trigger_definition(trigger)?),
                executes_routine_key: None,
            });
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
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties: oracle_trigger_properties(trigger, inventory_object),
            });
        }
        for dependency in raw
            .dependencies
            .iter()
            .filter(|dependency| dependency.object_type == "TRIGGER")
            .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        {
            let target = required(
                trigger_targets.get(&(dependency.owner.clone(), dependency.name.clone())),
                format!(
                    "target identity for Oracle trigger {}.{}",
                    dependency.owner, dependency.name
                ),
            )?;
            if dependency.referenced_type == "TABLE"
                && dependency.referenced_owner == target.0
                && dependency.referenced_name == target.1
            {
                continue;
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
                        "{} non-secondary USER/DBA_OBJECTS rows reconciled against table, index, sequence, view, materialized-view, trigger, routine, and package detail catalogs",
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
            Some((
                (trigger.owner.as_str(), trigger.name.as_str()),
                (
                    trigger.table_owner.as_deref()?,
                    trigger.table_name.as_deref()?,
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
                    !(dependency.referenced_type == "TABLE"
                        && dependency.referenced_owner == target.0
                        && dependency.referenced_name == target.1)
                })
        })
        .count();
    let routine_dependency_count = raw
        .dependencies
        .iter()
        .filter(|dependency| matches!(dependency.object_type.as_str(), "FUNCTION" | "PROCEDURE"))
        .filter(|dependency| !dependency.referenced_owner_oracle_maintained)
        .count();
    let package_dependency_count = oracle_package_dependency_groups(&raw.dependencies).len();

    set_object_count(&mut objects, ObjectCategory::Database, 1);
    set_object_count(&mut objects, ObjectCategory::Schema, scope.owners.len());
    set_object_count(&mut objects, ObjectCategory::Table, base_table_count);
    set_object_count(&mut objects, ObjectCategory::Column, base_column_count);
    set_object_count(&mut objects, ObjectCategory::Index, raw.indexes.len());
    set_object_count(&mut objects, ObjectCategory::Sequence, raw.sequences.len());
    set_object_count(&mut objects, ObjectCategory::View, raw.views.len());
    set_object_count(&mut objects, ObjectCategory::Trigger, raw.triggers.len());
    set_object_count(
        &mut objects,
        ObjectCategory::Routine,
        raw.routines.len() + raw.package_routines.len(),
    );
    set_object_count(
        &mut objects,
        ObjectCategory::RoutineParameter,
        raw.routine_arguments.len() + raw.package_arguments.len(),
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
            .map(|index| index.columns.len())
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
            .count(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TriggerTarget,
        raw.triggers.len(),
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
            + raw.view_columns.len()
            + raw.materialized_views.len()
            + materialized_view_column_count
            + materialized_view_constraint_count
            + materialized_view_index_count
            + raw.routine_arguments.len()
            + raw.packages.len()
            + raw.package_routines.len()
            + raw.package_arguments.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::MetadataRelationship,
        raw.identity_columns.len()
            + materialized_view_dependency_count
            + trigger_dependency_count
            + raw.routine_arguments.len()
            + raw.package_arguments.len()
            + package_dependency_count
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
                .map(|index| index.columns.len())
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
                    "GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE MATERIALIZED VIEW, CREATE TRIGGER, CREATE PROCEDURE TO {}",
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
            .execute("CREATE SEQUENCE AUDIT_SEQUENCE START WITH 10", &[])
            .expect("create explicit sequence");
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
        drop(setup);

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
        assert_eq!(certified.snapshot.schema.tables.len(), 2);
        assert!(certified
            .snapshot
            .schema
            .constraints
            .iter()
            .any(|constraint| constraint.kind == ConstraintKind::ForeignKey));
        assert!(certified.snapshot.schema.indexes.len() >= 3);
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
        assert_eq!(certified.snapshot.schema.routines.len(), 2);
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
            9
        );
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
        assert_eq!(certified.snapshot.schema.tables.len(), 2);
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
                "CREATE OR REPLACE TRIGGER CHILD_LABEL_BIU BEFORE INSERT OR UPDATE ON CHILD_ENTITY FOR EACH ROW BEGIN :NEW.LABEL := NORMALIZE_LABEL(:NEW.LABEL); END;",
                &[],
            )
            .expect("create static trigger");
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

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
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
