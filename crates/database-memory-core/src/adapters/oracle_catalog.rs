use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use oracle::{Connection, Version};

use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::canonical::{
    CanonicalMetadata, CanonicalSchemaSnapshot, MetadataObject, MetadataValue, ObjectAnnotation,
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
    DatabaseObject, IndexObject, ObjectKey, ObjectKind, SchemaObject, SchemaSnapshot, TableKind,
    TableObject,
};

const ORACLE_SOURCE: &str = "oracle";
const ORACLE_ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_DEFINITION_BYTES: usize = 1_048_576;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawOracleCatalog {
    inventory: Vec<RawInventoryObject>,
    tables: Vec<RawTable>,
    columns: Vec<RawColumn>,
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
                       NAME,
                       TYPE,
                       REFERENCED_OWNER,
                       REFERENCED_NAME,
                       REFERENCED_TYPE,
                       REFERENCED_LINK_NAME,
                       DEPENDENCY_TYPE
                FROM USER_DEPENDENCIES
                ORDER BY NAME, TYPE, REFERENCED_OWNER, REFERENCED_NAME, REFERENCED_TYPE
                "
            }
            DictionaryScopeMode::Dba => {
                "
                SELECT OWNER,
                       NAME,
                       TYPE,
                       REFERENCED_OWNER,
                       REFERENCED_NAME,
                       REFERENCED_TYPE,
                       REFERENCED_LINK_NAME,
                       DEPENDENCY_TYPE
                FROM DBA_DEPENDENCIES
                WHERE OWNER = :1
                ORDER BY OWNER, NAME, TYPE, REFERENCED_OWNER, REFERENCED_NAME, REFERENCED_TYPE
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
            ) = row?;
            dependencies.push(RawDependency {
                owner,
                name,
                object_type,
                referenced_owner,
                referenced_name,
                referenced_type,
                referenced_link,
                dependency_type,
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
    Ok(dependencies)
}

fn validate_raw_catalog(
    raw: &RawOracleCatalog,
    scope: &DictionaryScope,
) -> Result<(), CatalogError> {
    if raw.inventory.iter().any(|object| object.secondary) {
        // Secondary objects are Oracle-maintained implementation artifacts and are
        // intentionally outside the application-schema inventory contract.
    }

    let inventory = raw
        .inventory
        .iter()
        .filter(|object| !object.secondary)
        .collect::<Vec<_>>();
    let unsupported = inventory
        .iter()
        .filter(|object| !matches!(object.object_type.as_str(), "TABLE" | "INDEX"))
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
    if let Some(dependency) = raw.dependencies.first() {
        let remote = dependency
            .referenced_link
            .as_deref()
            .map(|link| format!(" over database link {link}"))
            .unwrap_or_default();
        return Err(CatalogError::UnsupportedMetadata(format!(
            "Oracle dependency mapping is not yet certified: {}.{} ({}) references {}.{} ({}){} using {} dependency",
            dependency.owner,
            dependency.name,
            dependency.object_type,
            dependency.referenced_owner,
            dependency.referenced_name,
            dependency.referenced_type,
            remote,
            dependency.dependency_type
        )));
    }

    let mut inventory_ids = BTreeSet::new();
    let mut inventory_keys = BTreeSet::new();
    for object in &inventory {
        ensure_owner(scope, &object.owner, "inventory object")?;
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
        if table.partitioned
            || table.iot_type.is_some()
            || table.nested
            || table.external
            || table.has_identity
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "Oracle table shape is not yet covered for {}.{} (partitioned={}, iot_type={}, nested={}, external={}, identity={})",
                table.owner,
                table.name,
                table.partitioned,
                table.iot_type.as_deref().unwrap_or("none"),
                table.nested,
                table.external,
                table.has_identity
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

        let mut tables = Vec::new();
        let mut table_keys = BTreeMap::new();
        for table in &raw.tables {
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
            insert_optional_string(&mut properties, "duration", table.duration.as_deref());
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties,
            });
        }

        let mut columns = Vec::new();
        let mut column_keys = BTreeMap::new();
        for column in &raw.columns {
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
                is_generated: column.virtual_column || column.hidden || !column.user_generated,
            });
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
            let inventory_object = required(
                inventory.get(&(index.owner.clone(), "INDEX".to_owned(), index.name.clone())),
                format!(
                    "inventory row for Oracle index {}.{}",
                    index.owner, index.name
                ),
            )?;
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
            metadata.annotations.push(ObjectAnnotation {
                object_key: key,
                definition: None,
                properties,
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
                views: Vec::new(),
                triggers: Vec::new(),
                routines: Vec::new(),
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
                        "{} non-secondary USER/DBA_OBJECTS rows reconciled against table and index detail catalogs",
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
                    evidence: "USER/DBA_DEPENDENCIES reported zero rows for the accepted base-schema object set; any dependency fails closed until mapped"
                        .to_owned(),
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

    set_object_count(&mut objects, ObjectCategory::Database, 1);
    set_object_count(&mut objects, ObjectCategory::Schema, scope.owners.len());
    set_object_count(&mut objects, ObjectCategory::Table, raw.tables.len());
    set_object_count(&mut objects, ObjectCategory::Column, raw.columns.len());
    set_object_count(&mut objects, ObjectCategory::Index, raw.indexes.len());
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
        raw.tables.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasColumn,
        raw.columns.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasConstraint,
        raw.constraints.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::ConstraintColumn,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.constraint_type != "R")
            .map(|constraint| constraint.columns.len())
            .sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::ForeignKeyColumnPair,
        raw.constraints
            .iter()
            .filter(|constraint| constraint.constraint_type == "R")
            .map(|constraint| constraint.columns.len())
            .sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::TableHasIndex,
        raw.indexes.len(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::IndexColumn,
        raw.indexes.iter().map(|index| index.columns.len()).sum(),
    );
    set_relationship_count(
        &mut relationships,
        RelationshipCategory::MetadataParent,
        scope.principals.len(),
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
                    "GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE TO {}",
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
                "CREATE TABLE PARENT_ENTITY (ID NUMBER(10) NOT NULL, CODE VARCHAR2(32 CHAR), CONSTRAINT PK_PARENT_ENTITY PRIMARY KEY (ID), CONSTRAINT UQ_PARENT_ENTITY_CODE UNIQUE (CODE), CONSTRAINT CK_PARENT_ENTITY_ID CHECK (ID > 0))",
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

        let setup = Connection::connect(&cleanup.username, password, &connect_string)
            .expect("reconnect as isolated Oracle test user");
        setup
            .execute("CREATE SEQUENCE UNSUPPORTED_SEQUENCE START WITH 1", &[])
            .expect("create fail-closed fixture");
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
