use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use mysql::prelude::Queryable;
use mysql::{
    AccessMode, Conn, Error as MysqlError, IsolationLevel, LocalInfileHandler, Opts, OptsBuilder,
    Row, SslOpts, TxOpts,
};
use sqlparser::ast::{visit_relations, ObjectName, ObjectNamePart, Query, Visit, Visitor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;

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

const MYSQL_FAMILY_SOURCE: &str = "mysql-family";
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_DEFINITION_BYTES: u64 = 1_048_576;
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct MysqlFamilyCatalogAdapter {
    connection_string: String,
}

impl MysqlFamilyCatalogAdapter {
    pub(crate) fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
        }
    }
}

impl CatalogIntrospector for MysqlFamilyCatalogAdapter {
    fn source_kind(&self) -> &'static str {
        MYSQL_FAMILY_SOURCE
    }

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        discover_mysql_family(&self.connection_string, request, &CancellationToken::new())
    }

    fn discover_with_cancellation(
        &mut self,
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<CatalogDiscovery, AnalysisFailure> {
        discover_mysql_family(&self.connection_string, request, cancellation)
    }
}

fn discover_mysql_family(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<CatalogDiscovery, AnalysisFailure> {
    cancellation.checkpoint(
        MYSQL_FAMILY_SOURCE,
        &request.connection_alias,
        AnalysisStage::Configuration,
    )?;
    validate_request(request)?;
    let opts = secure_connection_options(request, connection_string)?;
    let mut connection = Conn::new(opts).map_err(|error| {
        classify_mysql_error(
            request,
            connection_string,
            MYSQL_FAMILY_SOURCE,
            error,
            AnalysisStage::Connection,
        )
    })?;
    cancellation.checkpoint(
        MYSQL_FAMILY_SOURCE,
        &request.connection_alias,
        AnalysisStage::Connection,
    )?;
    let facts = ServerFacts::read(&mut connection)
        .map_err(|error| catalog_failure(request, connection_string, MYSQL_FAMILY_SOURCE, error))?;
    let strategy = MysqlFamilyVersion::detect(&facts.version)
        .map_err(|error| catalog_failure(request, connection_string, facts.source_kind(), error))?;
    validate_scope(request, &facts.database).map_err(|error| {
        catalog_failure(request, connection_string, strategy.source_kind(), error)
    })?;
    configure_session(&mut connection, strategy, request.timeout_ms).map_err(|error| {
        catalog_failure(request, connection_string, strategy.source_kind(), error)
    })?;
    cancellation.checkpoint(
        strategy.source_kind(),
        &request.connection_alias,
        AnalysisStage::CapabilityProbe,
    )?;

    let tx_options = TxOpts::default()
        .set_isolation_level(Some(IsolationLevel::RepeatableRead))
        .set_access_mode(Some(AccessMode::ReadOnly))
        .set_with_consistent_snapshot(true);
    let mut transaction = connection.start_transaction(tx_options).map_err(|error| {
        classify_mysql_error(
            request,
            connection_string,
            strategy.source_kind(),
            error,
            AnalysisStage::CapabilityProbe,
        )
    })?;
    let raw = RawMysqlFamilyCatalog::read(&mut transaction, &facts, strategy).map_err(|error| {
        catalog_failure(request, connection_string, strategy.source_kind(), error)
    })?;
    cancellation.checkpoint(
        strategy.source_kind(),
        &request.connection_alias,
        AnalysisStage::Discovery,
    )?;
    let discovery = MysqlFamilySnapshotMapper::new(&request.connection_alias, strategy)
        .map(raw)
        .map_err(|error| {
            catalog_failure(request, connection_string, strategy.source_kind(), error)
        })?;
    cancellation.checkpoint(
        strategy.source_kind(),
        &request.connection_alias,
        AnalysisStage::Mapping,
    )?;
    transaction.commit().map_err(|error| {
        classify_mysql_error(
            request,
            connection_string,
            strategy.source_kind(),
            error,
            AnalysisStage::Discovery,
        )
    })?;
    Ok(discovery)
}

pub(crate) fn analyze_mysql_family(
    connection_string: &str,
    connection_alias: &str,
    requested_databases: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_mysql_family_with_cancellation(
        connection_string,
        connection_alias,
        requested_databases,
        timeout_ms,
        &CancellationToken::new(),
    )
}

pub(crate) fn analyze_mysql_family_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_databases: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs: requested_databases.clone(),
        requested_schemas: requested_databases,
        timeout_ms,
    };
    DatabaseAnalysisService::new(MysqlFamilyCatalogAdapter::new(connection_string))
        .analyze_with_cancellation(&request, cancellation)
}

fn validate_request(request: &IntrospectionRequest) -> Result<(), AnalysisFailure> {
    if request.timeout_ms > MAX_INTROSPECTION_TIMEOUT_MS {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            MYSQL_FAMILY_SOURCE,
            &request.connection_alias,
            format!(
                "MySQL-family introspection timeout exceeds the {MAX_INTROSPECTION_TIMEOUT_MS} ms safety limit"
            ),
            "choose a timeout between 1 ms and 86400000 ms",
            false,
            None,
        ));
    }
    let duplicate_catalogs = request.requested_catalogs.len()
        != request
            .requested_catalogs
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
    let duplicate_schemas = request.requested_schemas.len()
        != request
            .requested_schemas
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
    if duplicate_catalogs || duplicate_schemas {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            MYSQL_FAMILY_SOURCE,
            &request.connection_alias,
            "MySQL-family scope contains duplicate database names",
            "provide each requested database exactly once",
            false,
            None,
        ));
    }
    Ok(())
}

fn secure_connection_options(
    request: &IntrospectionRequest,
    connection_string: &str,
) -> Result<Opts, AnalysisFailure> {
    let parsed = Opts::from_url(connection_string).map_err(|error| {
        AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            MYSQL_FAMILY_SOURCE,
            &request.connection_alias,
            error.to_string(),
            "provide a valid mysql:// connection URL selecting one database",
            false,
            Some(connection_string),
        )
    })?;
    if parsed.get_db_name().is_none_or(str::is_empty) {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::Configuration,
            MYSQL_FAMILY_SOURCE,
            &request.connection_alias,
            "MySQL-family connection URL must select one database",
            "append the database name to the connection URL path",
            false,
            Some(connection_string),
        ));
    }
    if parsed.get_enable_cleartext_plugin() {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Configuration,
            MYSQL_FAMILY_SOURCE,
            &request.connection_alias,
            "mysql_clear_password authentication is disabled by the metadata reader policy",
            "use a challenge-response authentication plugin over a verified TLS connection",
            false,
            Some(connection_string),
        ));
    }
    if let Some(ssl) = parsed.get_ssl_opts() {
        if ssl.accept_invalid_certs() || ssl.skip_domain_validation() {
            return Err(AnalysisFailure::redacted(
                AnalysisFailureCode::UnsafeSource,
                AnalysisStage::Configuration,
                MYSQL_FAMILY_SOURCE,
                &request.connection_alias,
                "TLS certificate or hostname verification cannot be disabled",
                "use a certificate trusted by the operating system or configure a trusted CA",
                false,
                Some(connection_string),
            ));
        }
    }

    let host = parsed.get_ip_or_hostname().into_owned();
    let remote_tcp = parsed.get_socket().is_none() && !is_loopback_host(&host);
    let timeout = Duration::from_millis(request.timeout_ms);
    let mut builder = OptsBuilder::from_opts(parsed)
        .tcp_connect_timeout(Some(timeout))
        .read_timeout(Some(timeout))
        .write_timeout(Some(timeout))
        .local_infile_handler(Some(LocalInfileHandler::new(|_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LOCAL INFILE is disabled for metadata introspection",
            ))
        })));
    if remote_tcp {
        builder = builder.ssl_opts(Some(SslOpts::default()));
    }
    Ok(Opts::from(builder))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn validate_scope(request: &IntrospectionRequest, database: &str) -> Result<(), CatalogError> {
    let requested = request
        .requested_catalogs
        .iter()
        .chain(&request.requested_schemas)
        .collect::<BTreeSet<_>>();
    if requested.is_empty() || (requested.len() == 1 && requested.contains(&database.to_owned())) {
        return Ok(());
    }
    Err(CatalogError::InvalidScope(format!(
        "the connection selects database '{database}', but the requested scope is {}",
        requested
            .into_iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn configure_session<Q: Queryable>(
    connection: &mut Q,
    strategy: MysqlFamilyVersion,
    timeout_ms: u64,
) -> Result<(), CatalogError> {
    match strategy.product() {
        MysqlProduct::Mysql => {
            connection.query_drop(format!("SET SESSION MAX_EXECUTION_TIME = {timeout_ms}"))?
        }
        MysqlProduct::MariaDb => {
            let seconds = timeout_ms as f64 / 1_000.0;
            connection.query_drop(format!("SET SESSION max_statement_time = {seconds}"))?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MysqlProduct {
    Mysql,
    MariaDb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MysqlFamilyVersion {
    Mysql80,
    Mysql84,
    Mysql97,
    MariaDb1011,
    MariaDb114,
    MariaDb118,
    MariaDb123,
}

impl MysqlFamilyVersion {
    fn detect(version: &str) -> Result<Self, CatalogError> {
        let maria_db = version.to_ascii_lowercase().contains("mariadb");
        let numeric = version
            .split(['-', '+'])
            .next()
            .unwrap_or(version)
            .split('.')
            .take(2)
            .map(|part| part.parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CatalogError::UnsupportedVersion(version.to_owned()))?;
        if numeric.len() != 2 {
            return Err(CatalogError::UnsupportedVersion(version.to_owned()));
        }
        match (maria_db, numeric[0], numeric[1]) {
            (false, 8, 0) => Ok(Self::Mysql80),
            (false, 8, 4) => Ok(Self::Mysql84),
            (false, 9, 7) => Ok(Self::Mysql97),
            (true, 10, 11) => Ok(Self::MariaDb1011),
            (true, 11, 4) => Ok(Self::MariaDb114),
            (true, 11, 8) => Ok(Self::MariaDb118),
            (true, 12, 3) => Ok(Self::MariaDb123),
            _ => Err(CatalogError::UnsupportedVersion(version.to_owned())),
        }
    }

    fn product(self) -> MysqlProduct {
        match self {
            Self::Mysql80 | Self::Mysql84 | Self::Mysql97 => MysqlProduct::Mysql,
            Self::MariaDb1011 | Self::MariaDb114 | Self::MariaDb118 | Self::MariaDb123 => {
                MysqlProduct::MariaDb
            }
        }
    }

    fn source_kind(self) -> &'static str {
        match self.product() {
            MysqlProduct::Mysql => "mysql",
            MysqlProduct::MariaDb => "mariadb",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Mysql80 => "mysql-8.0",
            Self::Mysql84 => "mysql-8.4",
            Self::Mysql97 => "mysql-9.7",
            Self::MariaDb1011 => "mariadb-10.11",
            Self::MariaDb114 => "mariadb-11.4",
            Self::MariaDb118 => "mariadb-11.8",
            Self::MariaDb123 => "mariadb-12.3",
        }
    }

    fn signature_queries(self) -> &'static [&'static str] {
        match self.product() {
            MysqlProduct::Mysql => MYSQL_SIGNATURE_QUERIES,
            MysqlProduct::MariaDb => MARIADB_SIGNATURE_QUERIES,
        }
    }
}

const COMMON_SIGNATURE_QUERIES: &[&str] = &[
    "SELECT CONCAT('table:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, TABLE_TYPE, \
        COALESCE(ENGINE, '<null>'), COALESCE(ROW_FORMAT, '<null>'), \
        COALESCE(TABLE_COLLATION, '<null>'), COALESCE(CREATE_OPTIONS, '<null>'), \
        COALESCE(TABLE_COMMENT, '<null>')), 256)) AS signature \
     FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
    "SELECT CONCAT('key:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, CONSTRAINT_NAME, \
        COLUMN_NAME, ORDINAL_POSITION, COALESCE(POSITION_IN_UNIQUE_CONSTRAINT, '<null>'), \
        COALESCE(REFERENCED_TABLE_SCHEMA, '<null>'), COALESCE(REFERENCED_TABLE_NAME, '<null>'), \
        COALESCE(REFERENCED_COLUMN_NAME, '<null>')), 256)) AS signature \
     FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? \
     ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION",
    "SELECT CONCAT('reference:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, CONSTRAINT_NAME, \
        MATCH_OPTION, UPDATE_RULE, DELETE_RULE, COALESCE(REFERENCED_TABLE_NAME, '<null>')), 256)) \
        AS signature FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS \
     WHERE CONSTRAINT_SCHEMA = ? ORDER BY TABLE_NAME, CONSTRAINT_NAME",
    "SELECT CONCAT('routine:', SHA2(CONCAT_WS(CHAR(31), SPECIFIC_NAME, ROUTINE_NAME, \
        ROUTINE_TYPE, COALESCE(DTD_IDENTIFIER, '<null>'), COALESCE(ROUTINE_DEFINITION, '<null>'), \
        IS_DETERMINISTIC, SQL_DATA_ACCESS, SECURITY_TYPE, SQL_MODE, COALESCE(ROUTINE_COMMENT, '<null>'), \
        DEFINER), 256)) AS signature FROM INFORMATION_SCHEMA.ROUTINES \
     WHERE ROUTINE_SCHEMA = ? ORDER BY SPECIFIC_NAME",
    "SELECT CONCAT('parameter:', SHA2(CONCAT_WS(CHAR(31), SPECIFIC_NAME, ORDINAL_POSITION, \
        COALESCE(PARAMETER_MODE, '<null>'), COALESCE(PARAMETER_NAME, '<null>'), DATA_TYPE, \
        COALESCE(DTD_IDENTIFIER, '<null>'), ROUTINE_TYPE), 256)) AS signature \
     FROM INFORMATION_SCHEMA.PARAMETERS WHERE SPECIFIC_SCHEMA = ? \
     ORDER BY SPECIFIC_NAME, ORDINAL_POSITION",
    "SELECT CONCAT('trigger:', SHA2(CONCAT_WS(CHAR(31), TRIGGER_NAME, EVENT_MANIPULATION, \
        EVENT_OBJECT_TABLE, ACTION_ORDER, COALESCE(ACTION_CONDITION, '<null>'), \
        COALESCE(ACTION_STATEMENT, '<null>'), ACTION_ORIENTATION, ACTION_TIMING, SQL_MODE, DEFINER), 256)) \
        AS signature FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = ? \
     ORDER BY TRIGGER_NAME",
    "SELECT CONCAT('event:', SHA2(CONCAT_WS(CHAR(31), EVENT_NAME, DEFINER, TIME_ZONE, EVENT_BODY, \
        COALESCE(EVENT_DEFINITION, '<null>'), EVENT_TYPE, COALESCE(CAST(EXECUTE_AT AS CHAR), '<null>'), \
        COALESCE(INTERVAL_VALUE, '<null>'), COALESCE(INTERVAL_FIELD, '<null>'), SQL_MODE, \
        COALESCE(CAST(STARTS AS CHAR), '<null>'), COALESCE(CAST(ENDS AS CHAR), '<null>'), STATUS, \
        ON_COMPLETION, COALESCE(EVENT_COMMENT, '<null>')), 256)) AS signature \
     FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME",
    "SELECT CONCAT('partition:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, PARTITION_NAME, \
        COALESCE(SUBPARTITION_NAME, '<null>'), PARTITION_ORDINAL_POSITION, \
        COALESCE(SUBPARTITION_ORDINAL_POSITION, '<null>'), COALESCE(PARTITION_METHOD, '<null>'), \
        COALESCE(SUBPARTITION_METHOD, '<null>'), COALESCE(PARTITION_EXPRESSION, '<null>'), \
        COALESCE(SUBPARTITION_EXPRESSION, '<null>'), COALESCE(PARTITION_DESCRIPTION, '<null>')), 256)) \
        AS signature FROM INFORMATION_SCHEMA.PARTITIONS \
     WHERE TABLE_SCHEMA = ? AND PARTITION_NAME IS NOT NULL \
     ORDER BY TABLE_NAME, PARTITION_ORDINAL_POSITION, SUBPARTITION_ORDINAL_POSITION",
];

const MYSQL_SIGNATURE_QUERIES: &[&str] = &[
    COMMON_SIGNATURE_QUERIES[0],
    "SELECT CONCAT('column:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, \
        COALESCE(COLUMN_DEFAULT, '<null>'), IS_NULLABLE, DATA_TYPE, COLUMN_TYPE, \
        COALESCE(CHARACTER_SET_NAME, '<null>'), COALESCE(COLLATION_NAME, '<null>'), COLUMN_KEY, \
        EXTRA, PRIVILEGES, COALESCE(COLUMN_COMMENT, '<null>'), \
        COALESCE(GENERATION_EXPRESSION, '<null>'), COALESCE(SRS_ID, '<null>')), 256)) AS signature \
     FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, ORDINAL_POSITION",
    "SELECT CONCAT('constraint:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, CONSTRAINT_NAME, \
        CONSTRAINT_TYPE, ENFORCED), 256)) AS signature FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, CONSTRAINT_NAME",
    COMMON_SIGNATURE_QUERIES[1],
    COMMON_SIGNATURE_QUERIES[2],
    "SELECT CONCAT('check:', SHA2(CONCAT_WS(CHAR(31), tc.TABLE_NAME, cc.CONSTRAINT_NAME, \
        cc.CHECK_CLAUSE), 256)) AS signature FROM INFORMATION_SCHEMA.CHECK_CONSTRAINTS cc \
     JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc ON tc.CONSTRAINT_SCHEMA = cc.CONSTRAINT_SCHEMA \
       AND tc.CONSTRAINT_NAME = cc.CONSTRAINT_NAME AND tc.CONSTRAINT_TYPE = 'CHECK' \
     WHERE cc.CONSTRAINT_SCHEMA = ? ORDER BY tc.TABLE_NAME, cc.CONSTRAINT_NAME",
    "SELECT CONCAT('index:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, INDEX_NAME, NON_UNIQUE, \
        SEQ_IN_INDEX, COALESCE(COLUMN_NAME, '<null>'), COALESCE(COLLATION, '<null>'), \
        COALESCE(SUB_PART, '<null>'), INDEX_TYPE, COMMENT, INDEX_COMMENT, IS_VISIBLE, \
        COALESCE(EXPRESSION, '<null>')), 256)) AS signature FROM INFORMATION_SCHEMA.STATISTICS \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
    "SELECT CONCAT('view:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, COALESCE(VIEW_DEFINITION, '<null>'), \
        CHECK_OPTION, IS_UPDATABLE, DEFINER, SECURITY_TYPE, CHARACTER_SET_CLIENT, \
        COLLATION_CONNECTION), 256)) AS signature FROM INFORMATION_SCHEMA.VIEWS \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
    "SELECT CONCAT('view-table:', SHA2(CONCAT_WS(CHAR(31), VIEW_NAME, TABLE_SCHEMA, TABLE_NAME), 256)) \
        AS signature FROM INFORMATION_SCHEMA.VIEW_TABLE_USAGE WHERE VIEW_SCHEMA = ? \
     ORDER BY VIEW_NAME, TABLE_SCHEMA, TABLE_NAME",
    "SELECT CONCAT('view-routine:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, SPECIFIC_SCHEMA, \
        SPECIFIC_NAME), 256)) AS signature FROM INFORMATION_SCHEMA.VIEW_ROUTINE_USAGE \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, SPECIFIC_SCHEMA, SPECIFIC_NAME",
    COMMON_SIGNATURE_QUERIES[3],
    COMMON_SIGNATURE_QUERIES[4],
    COMMON_SIGNATURE_QUERIES[5],
    COMMON_SIGNATURE_QUERIES[6],
    COMMON_SIGNATURE_QUERIES[7],
];

const MARIADB_SIGNATURE_QUERIES: &[&str] = &[
    COMMON_SIGNATURE_QUERIES[0],
    "SELECT CONCAT('column:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, \
        COALESCE(COLUMN_DEFAULT, '<null>'), IS_NULLABLE, DATA_TYPE, COLUMN_TYPE, \
        COALESCE(CHARACTER_SET_NAME, '<null>'), COALESCE(COLLATION_NAME, '<null>'), COLUMN_KEY, \
        EXTRA, PRIVILEGES, COALESCE(COLUMN_COMMENT, '<null>'), IS_GENERATED, \
        COALESCE(GENERATION_EXPRESSION, '<null>')), 256)) AS signature \
     FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, ORDINAL_POSITION",
    "SELECT CONCAT('constraint:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, CONSTRAINT_NAME, \
        CONSTRAINT_TYPE), 256)) AS signature FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, CONSTRAINT_NAME",
    COMMON_SIGNATURE_QUERIES[1],
    COMMON_SIGNATURE_QUERIES[2],
    "SELECT CONCAT('check:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, CONSTRAINT_NAME, CHECK_CLAUSE), 256)) \
        AS signature FROM INFORMATION_SCHEMA.CHECK_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ? \
     ORDER BY TABLE_NAME, CONSTRAINT_NAME",
    "SELECT CONCAT('index:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, INDEX_NAME, NON_UNIQUE, \
        SEQ_IN_INDEX, COALESCE(COLUMN_NAME, '<null>'), COALESCE(COLLATION, '<null>'), \
        COALESCE(SUB_PART, '<null>'), INDEX_TYPE, COMMENT, INDEX_COMMENT, IGNORED), 256)) AS signature \
     FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = ? \
     ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
    "SELECT CONCAT('view:', SHA2(CONCAT_WS(CHAR(31), TABLE_NAME, COALESCE(VIEW_DEFINITION, '<null>'), \
        CHECK_OPTION, IS_UPDATABLE, DEFINER, SECURITY_TYPE, CHARACTER_SET_CLIENT, \
        COLLATION_CONNECTION, ALGORITHM), 256)) AS signature FROM INFORMATION_SCHEMA.VIEWS \
     WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
    COMMON_SIGNATURE_QUERIES[3],
    COMMON_SIGNATURE_QUERIES[4],
    COMMON_SIGNATURE_QUERIES[5],
    COMMON_SIGNATURE_QUERIES[6],
    COMMON_SIGNATURE_QUERIES[7],
];

#[derive(Clone, Debug)]
struct ServerFacts {
    database: String,
    version: String,
    version_comment: String,
    current_user: String,
    session_user: String,
    lower_case_table_names: u64,
    tls_cipher: Option<String>,
}

impl ServerFacts {
    fn read<Q: Queryable>(connection: &mut Q) -> Result<Self, CatalogError> {
        let row = connection
            .query_first::<Row, _>(
                "SELECT DATABASE() AS database_name, VERSION() AS version_value, \
                        @@version_comment AS version_comment, CURRENT_USER() AS current_user_value, \
                        USER() AS session_user_value, @@lower_case_table_names AS lower_case_table_names",
            )?
            .ok_or_else(|| CatalogError::Mapping("server identity query returned no row".into()))?;
        let tls_cipher = connection
            .query_first::<Row, _>("SHOW SESSION STATUS LIKE 'Ssl_cipher'")?
            .map(|row| optional_at::<String>(&row, 1))
            .transpose()?
            .flatten()
            .filter(|value| !value.is_empty());
        Ok(Self {
            database: required(&row, "database_name")?,
            version: required(&row, "version_value")?,
            version_comment: required(&row, "version_comment")?,
            current_user: required(&row, "current_user_value")?,
            session_user: required(&row, "session_user_value")?,
            lower_case_table_names: required(&row, "lower_case_table_names")?,
            tls_cipher,
        })
    }

    fn source_kind(&self) -> &'static str {
        if self.version.to_ascii_lowercase().contains("mariadb") {
            "mariadb"
        } else {
            "mysql"
        }
    }
}

#[derive(Debug)]
enum CatalogError {
    Query(MysqlError),
    InvalidScope(String),
    PermissionDenied(String),
    UnsupportedVersion(String),
    UnsupportedMetadata(String),
    ConcurrentDdl(String),
    Mapping(String),
}

impl From<MysqlError> for CatalogError {
    fn from(error: MysqlError) -> Self {
        Self::Query(error)
    }
}

fn classify_mysql_error(
    request: &IntrospectionRequest,
    connection_string: &str,
    source_kind: &str,
    error: MysqlError,
    stage: AnalysisStage,
) -> AnalysisFailure {
    let (code, retryable, remediation) = match &error {
        MysqlError::MySqlError(server) if server.code == 1045 => (
            AnalysisFailureCode::AuthenticationFailed,
            false,
            "verify the MySQL-family principal and secret",
        ),
        MysqlError::MySqlError(server) if matches!(server.code, 1044 | 1142 | 1227) => (
            AnalysisFailureCode::PermissionDenied,
            false,
            "grant schema-wide metadata visibility and retry",
        ),
        MysqlError::MySqlError(server) if matches!(server.code, 1317 | 3024) => (
            AnalysisFailureCode::Timeout,
            true,
            "increase the bounded timeout or reduce the selected database scope",
        ),
        _ if stage == AnalysisStage::Connection => (
            AnalysisFailureCode::ConnectionFailed,
            true,
            "verify the MySQL-family endpoint, TLS trust, and network path",
        ),
        _ => (
            AnalysisFailureCode::MetadataQueryFailed,
            true,
            "inspect the server state and retry the metadata-only analysis",
        ),
    };
    AnalysisFailure::redacted(
        code,
        stage,
        source_kind,
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
    source_kind: &str,
    error: CatalogError,
) -> AnalysisFailure {
    match error {
        CatalogError::Query(error) => classify_mysql_error(
            request,
            connection_string,
            source_kind,
            error,
            AnalysisStage::Discovery,
        ),
        CatalogError::InvalidScope(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::InvalidConfiguration,
            AnalysisStage::CapabilityProbe,
            source_kind,
            &request.connection_alias,
            message,
            "select and request exactly one current MySQL-family database",
            false,
            Some(connection_string),
        ),
        CatalogError::PermissionDenied(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::PermissionDenied,
            AnalysisStage::CapabilityProbe,
            source_kind,
            &request.connection_alias,
            message,
            "grant SELECT, SHOW VIEW, EXECUTE, EVENT, and TRIGGER for the selected database",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedVersion(version) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedVersion,
            AnalysisStage::CapabilityProbe,
            source_kind,
            &request.connection_alias,
            format!("server version '{version}' has no certified MySQL-family strategy"),
            "use MySQL 8.0, 8.4, or 9.7, or MariaDB 10.11, 11.4, 11.8, or 12.3",
            false,
            Some(connection_string),
        ),
        CatalogError::UnsupportedMetadata(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedMetadata,
            AnalysisStage::CapabilityProbe,
            source_kind,
            &request.connection_alias,
            message,
            "remove the unprovable construct or extend and verify the product strategy",
            false,
            Some(connection_string),
        ),
        CatalogError::ConcurrentDdl(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::CompletenessMismatch,
            AnalysisStage::Validation,
            source_kind,
            &request.connection_alias,
            message,
            "retry after concurrent DDL activity has finished",
            true,
            Some(connection_string),
        ),
        CatalogError::Mapping(message) => AnalysisFailure::redacted(
            AnalysisFailureCode::MetadataMappingFailed,
            AnalysisStage::Mapping,
            source_kind,
            &request.connection_alias,
            message,
            "fix every unresolved catalog mapping before retrying",
            false,
            Some(connection_string),
        ),
    }
}

fn required<T>(row: &Row, column: &str) -> Result<T, CatalogError>
where
    T: mysql::prelude::FromValue,
{
    row.get_opt(column)
        .ok_or_else(|| CatalogError::Mapping(format!("catalog column '{column}' is missing")))?
        .map_err(|error| {
            CatalogError::Mapping(format!(
                "catalog column '{column}' has an incompatible value: {error}"
            ))
        })
}

fn optional<T>(row: &Row, column: &str) -> Result<Option<T>, CatalogError>
where
    T: mysql::prelude::FromValue,
{
    match row.get_opt::<Option<T>, _>(column) {
        Some(result) => result.map_err(|error| {
            CatalogError::Mapping(format!(
                "catalog column '{column}' has an incompatible optional value: {error}"
            ))
        }),
        None => Err(CatalogError::Mapping(format!(
            "catalog column '{column}' is missing"
        ))),
    }
}

fn optional_at<T>(row: &Row, index: usize) -> Result<Option<T>, CatalogError>
where
    T: mysql::prelude::FromValue,
{
    match row.get_opt::<Option<T>, _>(index) {
        Some(result) => result.map_err(|error| {
            CatalogError::Mapping(format!(
                "catalog column at index {index} has an incompatible optional value: {error}"
            ))
        }),
        None => Err(CatalogError::Mapping(format!(
            "catalog column at index {index} is missing"
        ))),
    }
}

fn required_at<T>(row: &Row, index: usize) -> Result<T, CatalogError>
where
    T: mysql::prelude::FromValue,
{
    row.get_opt(index)
        .ok_or_else(|| {
            CatalogError::Mapping(format!("catalog column at index {index} is missing"))
        })?
        .map_err(|error| {
            CatalogError::Mapping(format!(
                "catalog column at index {index} has an incompatible value: {error}"
            ))
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogSignature(Vec<String>);

impl CatalogSignature {
    fn read<Q: Queryable>(
        connection: &mut Q,
        database: &str,
        strategy: MysqlFamilyVersion,
    ) -> Result<Self, CatalogError> {
        let mut values = Vec::new();
        for query in strategy.signature_queries() {
            let rows = connection.exec::<Row, _, _>(query, (database,))?;
            for row in rows {
                values.push(required(&row, "signature")?);
            }
        }
        if strategy.product() == MysqlProduct::MariaDb {
            let sequence_rows = connection.exec::<Row, _, _>(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES \
                 WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'SEQUENCE' ORDER BY TABLE_NAME",
                (database,),
            )?;
            for row in sequence_rows {
                let name: String = required(&row, "TABLE_NAME")?;
                let statement = format!(
                    "SHOW CREATE SEQUENCE {}.{}",
                    quote_identifier(database),
                    quote_identifier(&name)
                );
                let definition_row =
                    connection
                        .query_first::<Row, _>(statement)?
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                            "sequence '{name}' disappeared while computing the catalog signature"
                        ))
                        })?;
                let definition = optional_at::<String>(&definition_row, 1)?.ok_or_else(|| {
                    CatalogError::PermissionDenied(format!(
                        "sequence '{name}' definition is hidden"
                    ))
                })?;
                values.push(format!("sequence-definition:{name}:{definition}"));
            }
        }
        values.sort();
        Ok(Self(values))
    }
}

#[derive(Clone, Debug)]
struct RawTable {
    name: String,
    table_type: String,
    engine: Option<String>,
    row_format: Option<String>,
    collation: Option<String>,
    create_options: Option<String>,
    comment: String,
}

#[derive(Clone, Debug)]
struct RawColumn {
    table: String,
    name: String,
    ordinal: u32,
    data_type: String,
    column_type: String,
    nullable: bool,
    default_value: Option<String>,
    character_set: Option<String>,
    collation: Option<String>,
    extra: String,
    privileges: String,
    comment: String,
    generation_expression: Option<String>,
    spatial_reference_id: Option<u64>,
    system_period_start: bool,
    system_period_end: bool,
}

#[derive(Clone, Debug)]
struct RawConstraint {
    table: String,
    name: String,
    constraint_type: String,
    enforced: bool,
}

#[derive(Clone, Debug)]
struct RawKeyUsage {
    table: String,
    constraint: String,
    column: String,
    ordinal: u32,
    referenced_schema: Option<String>,
    referenced_table: Option<String>,
    referenced_column: Option<String>,
}

#[derive(Clone, Debug)]
struct RawReferenceRule {
    table: String,
    constraint: String,
    match_option: String,
    update_rule: String,
    delete_rule: String,
}

#[derive(Clone, Debug)]
struct RawCheck {
    table: String,
    constraint: String,
    clause: String,
}

#[derive(Clone, Debug)]
struct RawIndexPart {
    table: String,
    index: String,
    non_unique: bool,
    ordinal: u32,
    column: Option<String>,
    collation: Option<String>,
    prefix_length: Option<u64>,
    index_type: String,
    comment: String,
    index_comment: String,
    visible: bool,
    expression: Option<String>,
}

#[derive(Clone, Debug)]
struct RawView {
    name: String,
    definition: Option<String>,
    check_option: String,
    updatable: bool,
    definer: String,
    security_type: String,
    character_set: String,
    collation: String,
    algorithm: Option<String>,
}

#[derive(Clone, Debug)]
struct RawViewTableUsage {
    view: String,
    target_schema: String,
    target_name: String,
}

#[derive(Clone, Debug)]
struct RawViewRoutineUsage {
    view: String,
    routine_schema: String,
    specific_name: String,
}

#[derive(Clone, Debug)]
struct RawRoutine {
    specific_name: String,
    name: String,
    routine_type: String,
    data_type: String,
    dtd_identifier: Option<String>,
    definition: Option<String>,
    deterministic: bool,
    sql_data_access: String,
    security_type: String,
    sql_mode: String,
    comment: String,
    definer: String,
    character_set: Option<String>,
    collation: Option<String>,
    database_collation: String,
}

#[derive(Clone, Debug)]
struct RawParameter {
    specific_name: String,
    ordinal: u32,
    mode: Option<String>,
    name: Option<String>,
    data_type: String,
    dtd_identifier: Option<String>,
    routine_type: String,
    default_value: Option<String>,
}

#[derive(Clone, Debug)]
struct RawTrigger {
    name: String,
    event: String,
    table: String,
    action_order: u64,
    condition: Option<String>,
    statement: Option<String>,
    orientation: String,
    timing: String,
    sql_mode: String,
    definer: String,
    character_set: String,
    collation: String,
    database_collation: String,
}

#[derive(Clone, Debug)]
struct RawEvent {
    name: String,
    definer: String,
    time_zone: String,
    body: String,
    definition: Option<String>,
    event_type: String,
    execute_at: Option<String>,
    interval_value: Option<String>,
    interval_field: Option<String>,
    sql_mode: String,
    starts: Option<String>,
    ends: Option<String>,
    status: String,
    on_completion: String,
    comment: String,
}

#[derive(Clone, Debug)]
struct RawPartition {
    table: String,
    partition: String,
    subpartition: Option<String>,
    partition_ordinal: u32,
    subpartition_ordinal: Option<u32>,
    method: Option<String>,
    subpartition_method: Option<String>,
    expression: Option<String>,
    subpartition_expression: Option<String>,
    description: Option<String>,
    comment: String,
    tablespace: Option<String>,
}

#[derive(Clone, Debug)]
struct RawSequence {
    name: String,
    definition: Option<String>,
    data_type: Option<String>,
    start_value: Option<String>,
    minimum_value: Option<String>,
    maximum_value: Option<String>,
    increment: Option<String>,
    cycles: Option<bool>,
}

#[derive(Clone, Debug)]
struct RawMysqlFamilyCatalog {
    facts: ServerFacts,
    strategy: MysqlFamilyVersion,
    grants: BTreeSet<String>,
    active_roles: Vec<String>,
    transaction_read_only: bool,
    transaction_isolation: String,
    tables: Vec<RawTable>,
    columns: Vec<RawColumn>,
    constraints: Vec<RawConstraint>,
    key_usage: Vec<RawKeyUsage>,
    reference_rules: Vec<RawReferenceRule>,
    checks: Vec<RawCheck>,
    index_parts: Vec<RawIndexPart>,
    views: Vec<RawView>,
    view_table_usage: Vec<RawViewTableUsage>,
    view_routine_usage: Vec<RawViewRoutineUsage>,
    routines: Vec<RawRoutine>,
    parameters: Vec<RawParameter>,
    triggers: Vec<RawTrigger>,
    events: Vec<RawEvent>,
    partitions: Vec<RawPartition>,
    sequences: Vec<RawSequence>,
}

impl RawMysqlFamilyCatalog {
    fn read<Q: Queryable>(
        connection: &mut Q,
        facts: &ServerFacts,
        strategy: MysqlFamilyVersion,
    ) -> Result<Self, CatalogError> {
        let active_roles = read_active_roles(connection, strategy)?;
        let grants = read_effective_privileges(connection, facts)?;
        require_metadata_privileges(&grants)?;
        // The mysql driver reached this reader only after the server accepted
        // SET TRANSACTION READ ONLY and REPEATABLE READ. The @@tx_read_only
        // variables expose session defaults, not the active transaction mode.
        let transaction_read_only = true;
        let transaction_isolation = "REPEATABLE-READ".to_owned();
        check_definition_sizes(connection, &facts.database)?;
        let before = CatalogSignature::read(connection, &facts.database, strategy)?;

        let tables = read_tables(connection, &facts.database)?;
        let columns = read_columns(connection, &facts.database, strategy)?;
        let constraints = read_constraints(connection, &facts.database, strategy)?;
        let key_usage = read_key_usage(connection, &facts.database)?;
        let reference_rules = read_reference_rules(connection, &facts.database)?;
        let checks = read_checks(connection, &facts.database, strategy)?;
        let index_parts = read_index_parts(connection, &facts.database, strategy)?;
        let views = read_views(connection, &facts.database, strategy)?;
        let view_table_usage = read_view_table_usage(connection, &facts.database, strategy)?;
        let view_routine_usage = read_view_routine_usage(connection, &facts.database, strategy)?;
        let routines = read_routines(connection, &facts.database)?;
        let parameters = read_parameters(connection, &facts.database, strategy)?;
        let triggers = read_triggers(connection, &facts.database)?;
        let events = read_events(connection, &facts.database)?;
        let partitions = read_partitions(connection, &facts.database)?;
        let sequences = read_sequences(connection, &facts.database, strategy, &tables)?;

        let after = CatalogSignature::read(connection, &facts.database, strategy)?;
        require_stable_signature(&before, &after)?;

        Ok(Self {
            facts: facts.clone(),
            strategy,
            grants,
            active_roles,
            transaction_read_only,
            transaction_isolation,
            tables,
            columns,
            constraints,
            key_usage,
            reference_rules,
            checks,
            index_parts,
            views,
            view_table_usage,
            view_routine_usage,
            routines,
            parameters,
            triggers,
            events,
            partitions,
            sequences,
        })
    }
}

fn require_stable_signature(
    before: &CatalogSignature,
    after: &CatalogSignature,
) -> Result<(), CatalogError> {
    if before == after {
        Ok(())
    } else {
        Err(CatalogError::ConcurrentDdl(
            "the selected database catalog changed during introspection".to_owned(),
        ))
    }
}

fn read_active_roles<Q: Queryable>(
    connection: &mut Q,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<String>, CatalogError> {
    let sql = match strategy.product() {
        MysqlProduct::Mysql => {
            "SELECT CONCAT(ROLE_NAME, '@', ROLE_HOST) AS role_name \
             FROM INFORMATION_SCHEMA.ENABLED_ROLES ORDER BY ROLE_NAME, ROLE_HOST"
        }
        MysqlProduct::MariaDb => {
            "SELECT ROLE_NAME AS role_name FROM INFORMATION_SCHEMA.ENABLED_ROLES \
             WHERE ROLE_NAME IS NOT NULL ORDER BY ROLE_NAME"
        }
    };
    connection
        .query::<Row, _>(sql)?
        .into_iter()
        .map(|row| required(&row, "role_name"))
        .collect()
}

fn read_effective_privileges<Q: Queryable>(
    connection: &mut Q,
    facts: &ServerFacts,
) -> Result<BTreeSet<String>, CatalogError> {
    let rows = connection.query::<Row, _>("SHOW GRANTS")?;
    let mut privileges = BTreeSet::new();
    for row in rows {
        let grant: String = required_at(&row, 0)?;
        if let Some(parsed) = parse_schema_grant(&grant, &facts.database)? {
            privileges.extend(parsed);
        }
    }
    Ok(privileges)
}

fn parse_schema_grant(
    grant: &str,
    database: &str,
) -> Result<Option<BTreeSet<String>>, CatalogError> {
    let Some(body) = grant.strip_prefix("GRANT ") else {
        return Ok(None);
    };
    let Some(on_offset) = body.find(" ON ") else {
        return Ok(None);
    };
    let privileges_text = &body[..on_offset];
    let scoped = &body[on_offset + 4..];
    let Some(to_offset) = scoped.find(" TO ") else {
        return Err(CatalogError::Mapping(format!(
            "SHOW GRANTS row has ON without TO: {grant}"
        )));
    };
    let scope = &scoped[..to_offset];
    if !grant_scope_matches(scope, database)? {
        return Ok(None);
    }
    let mut privileges = BTreeSet::new();
    if privileges_text.eq_ignore_ascii_case("ALL PRIVILEGES")
        || privileges_text.eq_ignore_ascii_case("ALL")
    {
        privileges.extend(
            ["SELECT", "SHOW VIEW", "EXECUTE", "EVENT", "TRIGGER"]
                .into_iter()
                .map(str::to_owned),
        );
        privileges.insert("ALL PRIVILEGES".to_owned());
        return Ok(Some(privileges));
    }
    for privilege in privileges_text.split(',') {
        let privilege = privilege.trim().to_ascii_uppercase();
        if privilege.is_empty()
            || privilege.chars().any(|character| {
                !(character.is_ascii_alphabetic() || character == ' ' || character == '_')
            })
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "SHOW GRANTS contains an unrecognized schema privilege token '{privilege}'"
            )));
        }
        privileges.insert(privilege);
    }
    Ok(Some(privileges))
}

fn grant_scope_matches(scope: &str, database: &str) -> Result<bool, CatalogError> {
    if scope == "*.*" {
        return Ok(true);
    }
    if !scope.starts_with('`') {
        return Ok(false);
    }
    let (identifier, rest) = parse_backtick_identifier(scope)?;
    if rest != ".*" {
        return Ok(false);
    }
    Ok(identifier == database)
}

fn parse_backtick_identifier(value: &str) -> Result<(String, &str), CatalogError> {
    let Some(mut remaining) = value.strip_prefix('`') else {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "SHOW GRANTS scope '{value}' is not a server-quoted identifier"
        )));
    };
    let mut identifier = String::new();
    loop {
        let Some(position) = remaining.find('`') else {
            return Err(CatalogError::Mapping(format!(
                "SHOW GRANTS scope '{value}' has an unterminated identifier"
            )));
        };
        identifier.push_str(&remaining[..position]);
        remaining = &remaining[position + 1..];
        if let Some(after_escape) = remaining.strip_prefix('`') {
            identifier.push('`');
            remaining = after_escape;
        } else {
            return Ok((identifier, remaining));
        }
    }
}

fn normalize_principal(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '`' | '\'' | '"' | ' '))
        .collect::<String>()
        .to_ascii_lowercase()
}

fn require_metadata_privileges(privileges: &BTreeSet<String>) -> Result<(), CatalogError> {
    let required = ["SELECT", "SHOW VIEW", "EXECUTE", "EVENT", "TRIGGER"];
    let missing = required
        .iter()
        .filter(|privilege| !privileges.contains(**privilege))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(CatalogError::PermissionDenied(format!(
            "the selected database lacks schema-wide metadata visibility privileges: {}",
            missing.join(", ")
        )))
    }
}

fn check_definition_sizes<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<(), CatalogError> {
    let rows = connection.exec::<Row, _, _>(
        "SELECT 'view' AS object_kind, TABLE_NAME AS object_name, \
                OCTET_LENGTH(VIEW_DEFINITION) AS definition_bytes \
         FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA = ? \
           AND OCTET_LENGTH(VIEW_DEFINITION) > 1048576 \
         UNION ALL \
         SELECT 'routine', SPECIFIC_NAME, OCTET_LENGTH(ROUTINE_DEFINITION) \
         FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA = ? \
           AND OCTET_LENGTH(ROUTINE_DEFINITION) > 1048576 \
         UNION ALL \
         SELECT 'trigger', TRIGGER_NAME, OCTET_LENGTH(ACTION_STATEMENT) \
         FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = ? \
           AND OCTET_LENGTH(ACTION_STATEMENT) > 1048576 \
         UNION ALL \
         SELECT 'event', EVENT_NAME, OCTET_LENGTH(EVENT_DEFINITION) \
         FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = ? \
           AND OCTET_LENGTH(EVENT_DEFINITION) > 1048576",
        (database, database, database, database),
    )?;
    if let Some(row) = rows.first() {
        let kind: String = required(row, "object_kind")?;
        let name: String = required(row, "object_name")?;
        let bytes: u64 = required(row, "definition_bytes")?;
        return Err(CatalogError::UnsupportedMetadata(format!(
            "{kind} '{name}' definition is {bytes} bytes and exceeds the {MAX_DEFINITION_BYTES}-byte safety limit"
        )));
    }
    Ok(())
}

fn read_tables<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawTable>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT TABLE_NAME, TABLE_TYPE, ENGINE, ROW_FORMAT, TABLE_COLLATION, \
                    CREATE_OPTIONS, COALESCE(TABLE_COMMENT, '') AS TABLE_COMMENT \
             FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawTable {
                name: required(&row, "TABLE_NAME")?,
                table_type: required(&row, "TABLE_TYPE")?,
                engine: optional(&row, "ENGINE")?,
                row_format: optional(&row, "ROW_FORMAT")?,
                collation: optional(&row, "TABLE_COLLATION")?,
                create_options: optional(&row, "CREATE_OPTIONS")?,
                comment: required(&row, "TABLE_COMMENT")?,
            })
        })
        .collect()
}

fn read_columns<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawColumn>, CatalogError> {
    let (spatial, period_start, period_end) = match strategy {
        MysqlFamilyVersion::Mysql80 | MysqlFamilyVersion::Mysql84 | MysqlFamilyVersion::Mysql97 => {
            (
                "SRS_ID",
                "'NO' AS IS_SYSTEM_TIME_PERIOD_START",
                "'NO' AS IS_SYSTEM_TIME_PERIOD_END",
            )
        }
        MysqlFamilyVersion::MariaDb123 => (
            "NULL AS SRS_ID",
            "IS_SYSTEM_TIME_PERIOD_START",
            "IS_SYSTEM_TIME_PERIOD_END",
        ),
        MysqlFamilyVersion::MariaDb1011
        | MysqlFamilyVersion::MariaDb114
        | MysqlFamilyVersion::MariaDb118 => (
            "NULL AS SRS_ID",
            "'NO' AS IS_SYSTEM_TIME_PERIOD_START",
            "'NO' AS IS_SYSTEM_TIME_PERIOD_END",
        ),
    };
    let sql = format!(
        "SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, COLUMN_TYPE, \
                IS_NULLABLE, COLUMN_DEFAULT, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA, \
                PRIVILEGES, COALESCE(COLUMN_COMMENT, '') AS COLUMN_COMMENT, \
                GENERATION_EXPRESSION, {spatial}, {period_start}, {period_end} \
         FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? \
         ORDER BY TABLE_NAME, ORDINAL_POSITION"
    );
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            let nullable: String = required(&row, "IS_NULLABLE")?;
            let period_start: String = required(&row, "IS_SYSTEM_TIME_PERIOD_START")?;
            let period_end: String = required(&row, "IS_SYSTEM_TIME_PERIOD_END")?;
            Ok(RawColumn {
                table: required(&row, "TABLE_NAME")?,
                name: required(&row, "COLUMN_NAME")?,
                ordinal: u32_from_u64(required(&row, "ORDINAL_POSITION")?, "column ordinal")?,
                data_type: required(&row, "DATA_TYPE")?,
                column_type: required(&row, "COLUMN_TYPE")?,
                nullable: nullable.eq_ignore_ascii_case("YES"),
                default_value: optional(&row, "COLUMN_DEFAULT")?,
                character_set: optional(&row, "CHARACTER_SET_NAME")?,
                collation: optional(&row, "COLLATION_NAME")?,
                extra: required(&row, "EXTRA")?,
                privileges: required(&row, "PRIVILEGES")?,
                comment: required(&row, "COLUMN_COMMENT")?,
                generation_expression: optional(&row, "GENERATION_EXPRESSION")?,
                spatial_reference_id: optional(&row, "SRS_ID")?,
                system_period_start: period_start.eq_ignore_ascii_case("YES"),
                system_period_end: period_end.eq_ignore_ascii_case("YES"),
            })
        })
        .collect()
}

fn read_constraints<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawConstraint>, CatalogError> {
    let enforced = match strategy.product() {
        MysqlProduct::Mysql => "ENFORCED",
        MysqlProduct::MariaDb => "'YES' AS ENFORCED",
    };
    let sql = format!(
        "SELECT TABLE_NAME, CONSTRAINT_NAME, CONSTRAINT_TYPE, {enforced} \
         FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA = ? \
         ORDER BY TABLE_NAME, CONSTRAINT_NAME"
    );
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            let enforced: String = required(&row, "ENFORCED")?;
            Ok(RawConstraint {
                table: required(&row, "TABLE_NAME")?,
                name: required(&row, "CONSTRAINT_NAME")?,
                constraint_type: required(&row, "CONSTRAINT_TYPE")?,
                enforced: enforced.eq_ignore_ascii_case("YES"),
            })
        })
        .collect()
}

fn read_key_usage<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawKeyUsage>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT TABLE_NAME, CONSTRAINT_NAME, COLUMN_NAME, ORDINAL_POSITION, \
                    REFERENCED_TABLE_SCHEMA, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME \
             FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? \
             ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawKeyUsage {
                table: required(&row, "TABLE_NAME")?,
                constraint: required(&row, "CONSTRAINT_NAME")?,
                column: required(&row, "COLUMN_NAME")?,
                ordinal: u32_from_u64(required(&row, "ORDINAL_POSITION")?, "key ordinal")?,
                referenced_schema: optional(&row, "REFERENCED_TABLE_SCHEMA")?,
                referenced_table: optional(&row, "REFERENCED_TABLE_NAME")?,
                referenced_column: optional(&row, "REFERENCED_COLUMN_NAME")?,
            })
        })
        .collect()
}

fn read_reference_rules<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawReferenceRule>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT TABLE_NAME, CONSTRAINT_NAME, MATCH_OPTION, UPDATE_RULE, DELETE_RULE \
             FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ? \
             ORDER BY TABLE_NAME, CONSTRAINT_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawReferenceRule {
                table: required(&row, "TABLE_NAME")?,
                constraint: required(&row, "CONSTRAINT_NAME")?,
                match_option: required(&row, "MATCH_OPTION")?,
                update_rule: required(&row, "UPDATE_RULE")?,
                delete_rule: required(&row, "DELETE_RULE")?,
            })
        })
        .collect()
}

fn read_checks<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawCheck>, CatalogError> {
    let sql = match strategy.product() {
        MysqlProduct::Mysql => {
            "SELECT tc.TABLE_NAME, cc.CONSTRAINT_NAME, cc.CHECK_CLAUSE \
             FROM INFORMATION_SCHEMA.CHECK_CONSTRAINTS cc \
             JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc \
               ON tc.CONSTRAINT_SCHEMA = cc.CONSTRAINT_SCHEMA \
              AND tc.CONSTRAINT_NAME = cc.CONSTRAINT_NAME \
              AND tc.CONSTRAINT_TYPE = 'CHECK' \
             WHERE cc.CONSTRAINT_SCHEMA = ? ORDER BY tc.TABLE_NAME, cc.CONSTRAINT_NAME"
        }
        MysqlProduct::MariaDb => {
            "SELECT TABLE_NAME, CONSTRAINT_NAME, CHECK_CLAUSE \
             FROM INFORMATION_SCHEMA.CHECK_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ? \
             ORDER BY TABLE_NAME, CONSTRAINT_NAME"
        }
    };
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            Ok(RawCheck {
                table: required(&row, "TABLE_NAME")?,
                constraint: required(&row, "CONSTRAINT_NAME")?,
                clause: required(&row, "CHECK_CLAUSE")?,
            })
        })
        .collect()
}

fn read_index_parts<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawIndexPart>, CatalogError> {
    let (visible, expression) = match strategy.product() {
        MysqlProduct::Mysql => ("IS_VISIBLE", "EXPRESSION"),
        MysqlProduct::MariaDb => (
            "CASE WHEN IGNORED = 'YES' THEN 'NO' ELSE 'YES' END AS IS_VISIBLE",
            "NULL AS EXPRESSION",
        ),
    };
    let sql = format!(
        "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, COLLATION, \
                SUB_PART, INDEX_TYPE, COMMENT, INDEX_COMMENT, {visible}, {expression} \
         FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = ? \
         ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX"
    );
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            let non_unique: u64 = required(&row, "NON_UNIQUE")?;
            let visible: String = required(&row, "IS_VISIBLE")?;
            Ok(RawIndexPart {
                table: required(&row, "TABLE_NAME")?,
                index: required(&row, "INDEX_NAME")?,
                non_unique: non_unique != 0,
                ordinal: u32_from_u64(required(&row, "SEQ_IN_INDEX")?, "index ordinal")?,
                column: optional(&row, "COLUMN_NAME")?,
                collation: optional(&row, "COLLATION")?,
                prefix_length: optional(&row, "SUB_PART")?,
                index_type: required(&row, "INDEX_TYPE")?,
                comment: required(&row, "COMMENT")?,
                index_comment: required(&row, "INDEX_COMMENT")?,
                visible: visible.eq_ignore_ascii_case("YES"),
                expression: optional(&row, "EXPRESSION")?,
            })
        })
        .collect()
}

fn read_views<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawView>, CatalogError> {
    let algorithm = match strategy.product() {
        MysqlProduct::Mysql => "NULL AS ALGORITHM",
        MysqlProduct::MariaDb => "ALGORITHM",
    };
    let sql = format!(
        "SELECT TABLE_NAME, VIEW_DEFINITION, CHECK_OPTION, IS_UPDATABLE, DEFINER, SECURITY_TYPE, \
                CHARACTER_SET_CLIENT, COLLATION_CONNECTION, {algorithm} \
         FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME"
    );
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            let updatable: String = required(&row, "IS_UPDATABLE")?;
            Ok(RawView {
                name: required(&row, "TABLE_NAME")?,
                definition: optional(&row, "VIEW_DEFINITION")?,
                check_option: required(&row, "CHECK_OPTION")?,
                updatable: updatable.eq_ignore_ascii_case("YES"),
                definer: required(&row, "DEFINER")?,
                security_type: required(&row, "SECURITY_TYPE")?,
                character_set: required(&row, "CHARACTER_SET_CLIENT")?,
                collation: required(&row, "COLLATION_CONNECTION")?,
                algorithm: optional(&row, "ALGORITHM")?,
            })
        })
        .collect()
}

fn read_view_table_usage<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawViewTableUsage>, CatalogError> {
    if strategy.product() == MysqlProduct::MariaDb {
        return Ok(Vec::new());
    }
    connection
        .exec::<Row, _, _>(
            "SELECT VIEW_NAME, TABLE_SCHEMA, TABLE_NAME \
             FROM INFORMATION_SCHEMA.VIEW_TABLE_USAGE WHERE VIEW_SCHEMA = ? \
             ORDER BY VIEW_NAME, TABLE_SCHEMA, TABLE_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawViewTableUsage {
                view: required(&row, "VIEW_NAME")?,
                target_schema: required(&row, "TABLE_SCHEMA")?,
                target_name: required(&row, "TABLE_NAME")?,
            })
        })
        .collect()
}

fn read_view_routine_usage<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawViewRoutineUsage>, CatalogError> {
    if strategy.product() == MysqlProduct::MariaDb {
        return Ok(Vec::new());
    }
    connection
        .exec::<Row, _, _>(
            "SELECT TABLE_NAME, SPECIFIC_SCHEMA, SPECIFIC_NAME \
             FROM INFORMATION_SCHEMA.VIEW_ROUTINE_USAGE WHERE TABLE_SCHEMA = ? \
             ORDER BY TABLE_NAME, SPECIFIC_SCHEMA, SPECIFIC_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawViewRoutineUsage {
                view: required(&row, "TABLE_NAME")?,
                routine_schema: required(&row, "SPECIFIC_SCHEMA")?,
                specific_name: required(&row, "SPECIFIC_NAME")?,
            })
        })
        .collect()
}

fn read_routines<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawRoutine>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT SPECIFIC_NAME, ROUTINE_NAME, ROUTINE_TYPE, DATA_TYPE, DTD_IDENTIFIER, \
                    ROUTINE_DEFINITION, IS_DETERMINISTIC, SQL_DATA_ACCESS, SECURITY_TYPE, \
                    SQL_MODE, COALESCE(ROUTINE_COMMENT, '') AS ROUTINE_COMMENT, DEFINER, \
                    CHARACTER_SET_CLIENT, COLLATION_CONNECTION, DATABASE_COLLATION \
             FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA = ? ORDER BY SPECIFIC_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            let deterministic: String = required(&row, "IS_DETERMINISTIC")?;
            Ok(RawRoutine {
                specific_name: required(&row, "SPECIFIC_NAME")?,
                name: required(&row, "ROUTINE_NAME")?,
                routine_type: required(&row, "ROUTINE_TYPE")?,
                data_type: required(&row, "DATA_TYPE")?,
                dtd_identifier: optional(&row, "DTD_IDENTIFIER")?,
                definition: optional(&row, "ROUTINE_DEFINITION")?,
                deterministic: deterministic.eq_ignore_ascii_case("YES"),
                sql_data_access: required(&row, "SQL_DATA_ACCESS")?,
                security_type: required(&row, "SECURITY_TYPE")?,
                sql_mode: required(&row, "SQL_MODE")?,
                comment: required(&row, "ROUTINE_COMMENT")?,
                definer: required(&row, "DEFINER")?,
                character_set: optional(&row, "CHARACTER_SET_CLIENT")?,
                collation: optional(&row, "COLLATION_CONNECTION")?,
                database_collation: required(&row, "DATABASE_COLLATION")?,
            })
        })
        .collect()
}

fn read_parameters<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
) -> Result<Vec<RawParameter>, CatalogError> {
    let default_value = match strategy {
        MysqlFamilyVersion::MariaDb123 => "PARAMETER_DEFAULT",
        _ => "NULL AS PARAMETER_DEFAULT",
    };
    let sql = format!(
        "SELECT SPECIFIC_NAME, ORDINAL_POSITION, PARAMETER_MODE, PARAMETER_NAME, DATA_TYPE, \
                DTD_IDENTIFIER, ROUTINE_TYPE, {default_value} \
         FROM INFORMATION_SCHEMA.PARAMETERS WHERE SPECIFIC_SCHEMA = ? \
         ORDER BY SPECIFIC_NAME, ORDINAL_POSITION"
    );
    connection
        .exec::<Row, _, _>(sql, (database,))?
        .into_iter()
        .map(|row| {
            Ok(RawParameter {
                specific_name: required(&row, "SPECIFIC_NAME")?,
                ordinal: u32_from_u64(required(&row, "ORDINAL_POSITION")?, "parameter ordinal")?,
                mode: optional(&row, "PARAMETER_MODE")?,
                name: optional(&row, "PARAMETER_NAME")?,
                data_type: required(&row, "DATA_TYPE")?,
                dtd_identifier: optional(&row, "DTD_IDENTIFIER")?,
                routine_type: required(&row, "ROUTINE_TYPE")?,
                default_value: optional(&row, "PARAMETER_DEFAULT")?,
            })
        })
        .collect()
}

fn read_triggers<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawTrigger>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_ORDER, \
                    ACTION_CONDITION, ACTION_STATEMENT, ACTION_ORIENTATION, ACTION_TIMING, \
                    SQL_MODE, DEFINER, CHARACTER_SET_CLIENT, COLLATION_CONNECTION, DATABASE_COLLATION \
             FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY TRIGGER_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawTrigger {
                name: required(&row, "TRIGGER_NAME")?,
                event: required(&row, "EVENT_MANIPULATION")?,
                table: required(&row, "EVENT_OBJECT_TABLE")?,
                action_order: required(&row, "ACTION_ORDER")?,
                condition: optional(&row, "ACTION_CONDITION")?,
                statement: optional(&row, "ACTION_STATEMENT")?,
                orientation: required(&row, "ACTION_ORIENTATION")?,
                timing: required(&row, "ACTION_TIMING")?,
                sql_mode: required(&row, "SQL_MODE")?,
                definer: required(&row, "DEFINER")?,
                character_set: required(&row, "CHARACTER_SET_CLIENT")?,
                collation: required(&row, "COLLATION_CONNECTION")?,
                database_collation: required(&row, "DATABASE_COLLATION")?,
            })
        })
        .collect()
}

fn read_events<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawEvent>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT EVENT_NAME, DEFINER, TIME_ZONE, EVENT_BODY, EVENT_DEFINITION, EVENT_TYPE, \
                    CAST(EXECUTE_AT AS CHAR) AS EXECUTE_AT_TEXT, INTERVAL_VALUE, INTERVAL_FIELD, \
                    SQL_MODE, CAST(STARTS AS CHAR) AS STARTS_TEXT, CAST(ENDS AS CHAR) AS ENDS_TEXT, \
                    STATUS, ON_COMPLETION, COALESCE(EVENT_COMMENT, '') AS EVENT_COMMENT \
             FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawEvent {
                name: required(&row, "EVENT_NAME")?,
                definer: required(&row, "DEFINER")?,
                time_zone: required(&row, "TIME_ZONE")?,
                body: required(&row, "EVENT_BODY")?,
                definition: optional(&row, "EVENT_DEFINITION")?,
                event_type: required(&row, "EVENT_TYPE")?,
                execute_at: optional(&row, "EXECUTE_AT_TEXT")?,
                interval_value: optional(&row, "INTERVAL_VALUE")?,
                interval_field: optional(&row, "INTERVAL_FIELD")?,
                sql_mode: required(&row, "SQL_MODE")?,
                starts: optional(&row, "STARTS_TEXT")?,
                ends: optional(&row, "ENDS_TEXT")?,
                status: required(&row, "STATUS")?,
                on_completion: required(&row, "ON_COMPLETION")?,
                comment: required(&row, "EVENT_COMMENT")?,
            })
        })
        .collect()
}

fn read_partitions<Q: Queryable>(
    connection: &mut Q,
    database: &str,
) -> Result<Vec<RawPartition>, CatalogError> {
    connection
        .exec::<Row, _, _>(
            "SELECT TABLE_NAME, PARTITION_NAME, SUBPARTITION_NAME, PARTITION_ORDINAL_POSITION, \
                    SUBPARTITION_ORDINAL_POSITION, PARTITION_METHOD, SUBPARTITION_METHOD, \
                    PARTITION_EXPRESSION, SUBPARTITION_EXPRESSION, PARTITION_DESCRIPTION, \
                    COALESCE(PARTITION_COMMENT, '') AS PARTITION_COMMENT, TABLESPACE_NAME \
             FROM INFORMATION_SCHEMA.PARTITIONS \
             WHERE TABLE_SCHEMA = ? AND PARTITION_NAME IS NOT NULL \
             ORDER BY TABLE_NAME, PARTITION_ORDINAL_POSITION, SUBPARTITION_ORDINAL_POSITION",
            (database,),
        )?
        .into_iter()
        .map(|row| {
            Ok(RawPartition {
                table: required(&row, "TABLE_NAME")?,
                partition: required(&row, "PARTITION_NAME")?,
                subpartition: optional(&row, "SUBPARTITION_NAME")?,
                partition_ordinal: u32_from_u64(
                    required(&row, "PARTITION_ORDINAL_POSITION")?,
                    "partition ordinal",
                )?,
                subpartition_ordinal: optional::<u64>(&row, "SUBPARTITION_ORDINAL_POSITION")?
                    .map(|value| u32_from_u64(value, "subpartition ordinal"))
                    .transpose()?,
                method: optional(&row, "PARTITION_METHOD")?,
                subpartition_method: optional(&row, "SUBPARTITION_METHOD")?,
                expression: optional(&row, "PARTITION_EXPRESSION")?,
                subpartition_expression: optional(&row, "SUBPARTITION_EXPRESSION")?,
                description: optional(&row, "PARTITION_DESCRIPTION")?,
                comment: required(&row, "PARTITION_COMMENT")?,
                tablespace: optional(&row, "TABLESPACE_NAME")?,
            })
        })
        .collect()
}

fn read_sequences<Q: Queryable>(
    connection: &mut Q,
    database: &str,
    strategy: MysqlFamilyVersion,
    tables: &[RawTable],
) -> Result<Vec<RawSequence>, CatalogError> {
    if strategy.product() == MysqlProduct::Mysql {
        return Ok(Vec::new());
    }
    let sequence_names = tables
        .iter()
        .filter(|table| table.table_type.eq_ignore_ascii_case("SEQUENCE"))
        .map(|table| table.name.clone())
        .collect::<Vec<_>>();
    let mut definitions = BTreeMap::new();
    for name in &sequence_names {
        let statement = format!(
            "SHOW CREATE SEQUENCE {}.{}",
            quote_identifier(database),
            quote_identifier(name)
        );
        let row = connection
            .query_first::<Row, _>(statement)?
            .ok_or_else(|| CatalogError::Mapping(format!("sequence '{name}' has no definition")))?;
        let definition = optional_at::<String>(&row, 1)?.ok_or_else(|| {
            CatalogError::Mapping(format!("sequence '{name}' has a hidden definition"))
        })?;
        if definition.len() as u64 > MAX_DEFINITION_BYTES {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "sequence '{name}' definition exceeds the {MAX_DEFINITION_BYTES}-byte safety limit"
            )));
        }
        definitions.insert(name.clone(), definition);
    }

    if matches!(
        strategy,
        MysqlFamilyVersion::MariaDb118 | MysqlFamilyVersion::MariaDb123
    ) {
        let rows = connection.exec::<Row, _, _>(
            "SELECT SEQUENCE_NAME, DATA_TYPE, CAST(START_VALUE AS CHAR) AS START_VALUE_TEXT, \
                    CAST(MINIMUM_VALUE AS CHAR) AS MINIMUM_VALUE_TEXT, \
                    CAST(MAXIMUM_VALUE AS CHAR) AS MAXIMUM_VALUE_TEXT, \
                    CAST(INCREMENT AS CHAR) AS INCREMENT_TEXT, CYCLE_OPTION \
             FROM INFORMATION_SCHEMA.SEQUENCES WHERE SEQUENCE_SCHEMA = ? ORDER BY SEQUENCE_NAME",
            (database,),
        )?;
        let mut sequences = Vec::new();
        for row in rows {
            let name: String = required(&row, "SEQUENCE_NAME")?;
            let cycle: String = required(&row, "CYCLE_OPTION")?;
            sequences.push(RawSequence {
                definition: definitions.remove(&name),
                name,
                data_type: optional(&row, "DATA_TYPE")?,
                start_value: optional(&row, "START_VALUE_TEXT")?,
                minimum_value: optional(&row, "MINIMUM_VALUE_TEXT")?,
                maximum_value: optional(&row, "MAXIMUM_VALUE_TEXT")?,
                increment: optional(&row, "INCREMENT_TEXT")?,
                cycles: Some(cycle.eq_ignore_ascii_case("YES")),
            });
        }
        if !definitions.is_empty() || sequences.len() != sequence_names.len() {
            return Err(CatalogError::Mapping(
                "MariaDB SEQUENCES rows do not reconcile with TABLES sequence rows".to_owned(),
            ));
        }
        Ok(sequences)
    } else {
        Ok(sequence_names
            .into_iter()
            .map(|name| RawSequence {
                definition: definitions.remove(&name),
                name,
                data_type: None,
                start_value: None,
                minimum_value: None,
                maximum_value: None,
                increment: None,
                cycles: None,
            })
            .collect())
    }
}

fn quote_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

fn u32_from_u64(value: u64, subject: &str) -> Result<u32, CatalogError> {
    u32::try_from(value)
        .map_err(|_| CatalogError::Mapping(format!("{subject} {value} exceeds u32 range")))
}

struct MysqlFamilySnapshotMapper {
    connection_alias: String,
    strategy: MysqlFamilyVersion,
}

impl MysqlFamilySnapshotMapper {
    fn new(connection_alias: &str, strategy: MysqlFamilyVersion) -> Self {
        Self {
            connection_alias: connection_alias.to_owned(),
            strategy,
        }
    }

    fn map(self, raw: RawMysqlFamilyCatalog) -> Result<CatalogDiscovery, CatalogError> {
        if raw.strategy != self.strategy {
            return Err(CatalogError::Mapping(format!(
                "reader strategy {} differs from mapper strategy {}",
                raw.strategy.label(),
                self.strategy.label()
            )));
        }
        validate_raw_table_inventory(&raw)?;

        let source_kind = self.strategy.source_kind();
        let database_name = raw.facts.database.clone();
        let database_key = family_key(
            source_kind,
            &self.connection_alias,
            &database_name,
            ObjectKind::Database,
            &database_name,
            None,
        );
        let schema_key = family_key(
            source_kind,
            &self.connection_alias,
            &database_name,
            ObjectKind::Schema,
            &database_name,
            None,
        );
        let database = DatabaseObject {
            key: database_key.clone(),
            name: database_name.clone(),
        };
        let schemas = vec![SchemaObject {
            key: schema_key.clone(),
            database_key: database_key.clone(),
            name: database_name.clone(),
        }];

        let mut metadata = CanonicalMetadata::default();
        add_database_annotation(&mut metadata, &database_key, &raw);
        let principal_keys = map_principals(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            &database_key,
            &raw,
        )?;
        let sequence_keys = map_sequences(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            &schema_key,
            raw.facts.lower_case_table_names,
            &raw.sequences,
        )?;

        let mut tables = Vec::new();
        let mut table_keys = BTreeMap::new();
        let mut table_types = BTreeMap::new();
        for table in &raw.tables {
            let normalized = normalize_object_name(&table.name, raw.facts.lower_case_table_names);
            if table_types
                .insert(normalized.clone(), table.table_type.clone())
                .is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "duplicate table-like catalog name '{}'",
                    table.name
                )));
            }
            if !table.table_type.eq_ignore_ascii_case("BASE TABLE") {
                continue;
            }
            let key = family_key(
                source_kind,
                &self.connection_alias,
                &database_name,
                ObjectKind::Table,
                &table.name,
                None,
            );
            if table_keys.insert(normalized, key.clone()).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate base table '{}'",
                    table.name
                )));
            }
            tables.push(TableObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: table.name.clone(),
                kind: TableKind::BaseTable,
            });
            add_table_annotation(&mut metadata, &key, table);
        }

        let mut view_keys = BTreeMap::new();
        for view in &raw.views {
            let normalized = normalize_object_name(&view.name, raw.facts.lower_case_table_names);
            let key = family_key(
                source_kind,
                &self.connection_alias,
                &database_name,
                ObjectKind::View,
                &view.name,
                None,
            );
            if view_keys.insert(normalized, key).is_some() {
                return Err(CatalogError::Mapping(format!(
                    "duplicate view '{}'",
                    view.name
                )));
            }
        }

        let dependencies = resolve_view_dependencies(&raw, &table_keys, &view_keys)?;
        let mut views = Vec::new();
        for view in &raw.views {
            let normalized = normalize_object_name(&view.name, raw.facts.lower_case_table_names);
            let key = view_keys.get(&normalized).cloned().ok_or_else(|| {
                CatalogError::Mapping(format!("view '{}' lost its stable key", view.name))
            })?;
            let definition = view.definition.clone().ok_or_else(|| {
                CatalogError::PermissionDenied(format!(
                    "view '{}' definition is hidden; SHOW VIEW is not effective",
                    view.name
                ))
            })?;
            views.push(ViewObject {
                key: key.clone(),
                schema_key: schema_key.clone(),
                name: view.name.clone(),
                definition: Some(definition.clone()),
                depends_on: dependencies.get(&normalized).cloned().unwrap_or_default(),
            });
            add_view_annotation(&mut metadata, &key, view, definition);
        }

        let MappedColumns {
            objects: columns,
            keys: column_keys,
        } = map_columns(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            raw.facts.lower_case_table_names,
            &raw.columns,
            &table_keys,
            &view_keys,
            &sequence_keys,
            &table_types,
        )?;
        let constraints = map_constraints(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            raw.facts.lower_case_table_names,
            &raw,
            &table_keys,
            &column_keys,
        )?;
        let indexes = map_indexes(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            raw.facts.lower_case_table_names,
            &raw.index_parts,
            &table_keys,
            &column_keys,
        )?;
        let (routines, routine_keys) = map_routines(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            &schema_key,
            &raw.routines,
            &raw.parameters,
        )?;
        let triggers = map_triggers(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            raw.facts.lower_case_table_names,
            &raw.triggers,
            &table_keys,
        )?;
        map_events(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            &schema_key,
            &raw.events,
        )?;
        map_partitions(
            &mut metadata,
            source_kind,
            &self.connection_alias,
            &database_name,
            raw.facts.lower_case_table_names,
            &raw.partitions,
            &table_keys,
        )?;
        map_view_routine_relationships(&mut metadata, &raw, &view_keys, &routine_keys)?;
        add_principal_relationships(&mut metadata, &principal_keys)?;
        validate_relationship_uniqueness(&metadata.relationships)?;

        ensure_dependency_closure(&raw)?;
        let snapshot = CanonicalSchemaSnapshot {
            schema: SchemaSnapshot {
                source_kind: source_kind.to_owned(),
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
                capabilities: mysql_family_capabilities(source_kind),
            },
            metadata,
        };
        let discovered_counts = discovery_counts_from_catalog(&raw, &snapshot)?;

        Ok(CatalogDiscovery {
            snapshot,
            adapter: AdapterIdentity {
                name: format!("database-memory-{}-catalog", source_kind),
                version: ADAPTER_VERSION.to_owned(),
            },
            server: ServerIdentity {
                product: match self.strategy.product() {
                    MysqlProduct::Mysql => "MySQL".to_owned(),
                    MysqlProduct::MariaDb => "MariaDB".to_owned(),
                },
                version: raw.facts.version.clone(),
            },
            scope: IntrospectionScope {
                catalogs: vec![database_name.clone()],
                schemas: vec![database_name],
            },
            discovered_counts,
            capability_checks: mysql_family_capability_checks(&raw),
        })
    }
}

fn validate_raw_table_inventory(raw: &RawMysqlFamilyCatalog) -> Result<(), CatalogError> {
    let mut table_names = BTreeSet::new();
    let mut catalog_views = BTreeSet::new();
    let mut catalog_sequences = BTreeSet::new();
    for table in &raw.tables {
        let name = normalize_object_name(&table.name, raw.facts.lower_case_table_names);
        if !table_names.insert(name.clone()) {
            return Err(CatalogError::Mapping(format!(
                "TABLES contains duplicate name '{}'",
                table.name
            )));
        }
        match table.table_type.to_ascii_uppercase().as_str() {
            "BASE TABLE" => {}
            "VIEW" => {
                catalog_views.insert(name);
            }
            "SEQUENCE" if raw.strategy.product() == MysqlProduct::MariaDb => {
                catalog_sequences.insert(name);
            }
            unsupported => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "table-like object '{}' has unsupported TABLE_TYPE '{unsupported}'",
                    table.name
                )));
            }
        }
    }
    let views = raw
        .views
        .iter()
        .map(|view| normalize_object_name(&view.name, raw.facts.lower_case_table_names))
        .collect::<BTreeSet<_>>();
    if catalog_views != views || views.len() != raw.views.len() {
        return Err(CatalogError::Mapping(
            "TABLES view inventory does not reconcile with VIEWS".to_owned(),
        ));
    }
    let sequences = raw
        .sequences
        .iter()
        .map(|sequence| normalize_object_name(&sequence.name, raw.facts.lower_case_table_names))
        .collect::<BTreeSet<_>>();
    if catalog_sequences != sequences || sequences.len() != raw.sequences.len() {
        return Err(CatalogError::Mapping(
            "TABLES sequence inventory does not reconcile with sequence metadata".to_owned(),
        ));
    }
    Ok(())
}

fn family_key(
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    object_kind: ObjectKind,
    object_name: &str,
    sub_object: Option<String>,
) -> ObjectKey {
    ObjectKey::new(
        source_kind,
        connection_alias,
        database,
        database,
        object_kind,
        object_name,
        sub_object,
    )
}

fn normalize_object_name(value: &str, lower_case_table_names: u64) -> String {
    if lower_case_table_names == 0 {
        value.to_owned()
    } else {
        value.to_ascii_lowercase()
    }
}

fn normalize_column_name(value: &str) -> String {
    value.to_ascii_lowercase()
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

fn insert_u64(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: u64) {
    properties.insert(key.to_owned(), MetadataValue::Unsigned(value));
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

fn add_database_annotation(
    metadata: &mut CanonicalMetadata,
    database_key: &ObjectKey,
    raw: &RawMysqlFamilyCatalog,
) {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "server_version", &raw.facts.version);
    insert_string(
        &mut properties,
        "server_version_comment",
        &raw.facts.version_comment,
    );
    insert_string(&mut properties, "current_user", &raw.facts.current_user);
    insert_string(&mut properties, "session_user", &raw.facts.session_user);
    insert_u64(
        &mut properties,
        "lower_case_table_names",
        raw.facts.lower_case_table_names,
    );
    insert_string(&mut properties, "catalog_strategy", raw.strategy.label());
    add_annotation(metadata, database_key, None, properties);
}

#[derive(Clone, Debug)]
struct PrincipalKeys {
    current: ObjectKey,
    roles: Vec<ObjectKey>,
}

fn map_principals(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    database_key: &ObjectKey,
    raw: &RawMysqlFamilyCatalog,
) -> Result<PrincipalKeys, CatalogError> {
    let current_key = family_key(
        source_kind,
        connection_alias,
        database,
        ObjectKind::Principal,
        &raw.facts.current_user,
        None,
    );
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "principal_kind", "current_user");
    properties.insert(
        "schema_privileges".to_owned(),
        MetadataValue::StringList(raw.grants.iter().cloned().collect()),
    );
    metadata.objects.push(MetadataObject {
        key: current_key.clone(),
        parent_key: Some(database_key.clone()),
        name: raw.facts.current_user.clone(),
        extension_kind: None,
        definition: None,
        properties,
    });

    let mut roles = Vec::new();
    let mut seen = BTreeSet::new();
    for role in &raw.active_roles {
        let normalized = normalize_principal(role);
        if !seen.insert(normalized) {
            return Err(CatalogError::Mapping(format!(
                "duplicate active role '{role}'"
            )));
        }
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Principal,
            role,
            Some("active_role".to_owned()),
        );
        let mut properties = BTreeMap::new();
        insert_string(&mut properties, "principal_kind", "active_role");
        metadata.objects.push(MetadataObject {
            key: key.clone(),
            parent_key: Some(database_key.clone()),
            name: role.clone(),
            extension_kind: None,
            definition: None,
            properties,
        });
        roles.push(key);
    }
    Ok(PrincipalKeys {
        current: current_key,
        roles,
    })
}

fn add_principal_relationships(
    metadata: &mut CanonicalMetadata,
    principals: &PrincipalKeys,
) -> Result<(), CatalogError> {
    for role in &principals.roles {
        metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::Extension("active_role".to_owned()),
            from_key: principals.current.clone(),
            to_key: role.clone(),
            ordinal: None,
            properties: BTreeMap::new(),
        });
    }
    Ok(())
}

fn map_sequences(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    schema_key: &ObjectKey,
    lower_case_table_names: u64,
    raw_sequences: &[RawSequence],
) -> Result<BTreeMap<String, ObjectKey>, CatalogError> {
    let mut keys = BTreeMap::new();
    for sequence in raw_sequences {
        let normalized = normalize_object_name(&sequence.name, lower_case_table_names);
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Sequence,
            &sequence.name,
            None,
        );
        if keys.insert(normalized, key.clone()).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate sequence '{}'",
                sequence.name
            )));
        }
        let mut properties = BTreeMap::new();
        insert_optional_string(&mut properties, "data_type", sequence.data_type.as_deref());
        insert_optional_string(
            &mut properties,
            "start_value",
            sequence.start_value.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "minimum_value",
            sequence.minimum_value.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "maximum_value",
            sequence.maximum_value.as_deref(),
        );
        insert_optional_string(&mut properties, "increment", sequence.increment.as_deref());
        if let Some(cycles) = sequence.cycles {
            insert_bool(&mut properties, "cycles", cycles);
        }
        metadata.objects.push(MetadataObject {
            key,
            parent_key: Some(schema_key.clone()),
            name: sequence.name.clone(),
            extension_kind: None,
            definition: sequence.definition.clone(),
            properties,
        });
    }
    Ok(keys)
}

fn add_table_annotation(metadata: &mut CanonicalMetadata, table_key: &ObjectKey, table: &RawTable) {
    let mut properties = BTreeMap::new();
    insert_optional_string(&mut properties, "engine", table.engine.as_deref());
    insert_optional_string(&mut properties, "row_format", table.row_format.as_deref());
    insert_optional_string(&mut properties, "collation", table.collation.as_deref());
    insert_optional_string(
        &mut properties,
        "create_options",
        table.create_options.as_deref(),
    );
    insert_string(&mut properties, "comment", &table.comment);
    add_annotation(metadata, table_key, None, properties);
}

fn add_view_annotation(
    metadata: &mut CanonicalMetadata,
    view_key: &ObjectKey,
    view: &RawView,
    _definition: String,
) {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "check_option", &view.check_option);
    insert_bool(&mut properties, "updatable", view.updatable);
    insert_string(&mut properties, "definer", &view.definer);
    insert_string(&mut properties, "security_type", &view.security_type);
    insert_string(&mut properties, "character_set_client", &view.character_set);
    insert_string(&mut properties, "collation_connection", &view.collation);
    insert_optional_string(&mut properties, "algorithm", view.algorithm.as_deref());
    add_annotation(metadata, view_key, None, properties);
}

#[allow(clippy::too_many_arguments)]
fn map_columns(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    lower_case_table_names: u64,
    raw_columns: &[RawColumn],
    table_keys: &BTreeMap<String, ObjectKey>,
    view_keys: &BTreeMap<String, ObjectKey>,
    sequence_keys: &BTreeMap<String, ObjectKey>,
    table_types: &BTreeMap<String, String>,
) -> Result<MappedColumns, CatalogError> {
    let mut columns = Vec::new();
    let mut column_keys = BTreeMap::new();
    for column in raw_columns {
        let relation_name = normalize_object_name(&column.table, lower_case_table_names);
        let column_name = normalize_column_name(&column.name);
        let table_type = table_types.get(&relation_name).ok_or_else(|| {
            CatalogError::Mapping(format!(
                "column '{}.{}' references a missing table-like object",
                column.table, column.name
            ))
        })?;
        match table_type.to_ascii_uppercase().as_str() {
            "BASE TABLE" => {
                let table_key = table_keys.get(&relation_name).cloned().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "column '{}.{}' lost its table key",
                        column.table, column.name
                    ))
                })?;
                let key = family_key(
                    source_kind,
                    connection_alias,
                    database,
                    ObjectKind::Column,
                    &column.table,
                    Some(column.name.clone()),
                );
                if column_keys
                    .insert((relation_name.clone(), column_name), key.clone())
                    .is_some()
                {
                    return Err(CatalogError::Mapping(format!(
                        "duplicate column '{}.{}'",
                        column.table, column.name
                    )));
                }
                columns.push(ColumnObject {
                    key: key.clone(),
                    table_key,
                    name: column.name.clone(),
                    ordinal_position: column.ordinal,
                    data_type: column.column_type.clone(),
                    is_nullable: column.nullable,
                    default_value: column.default_value.clone(),
                    is_generated: column
                        .generation_expression
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                        || column.extra.to_ascii_uppercase().contains("GENERATED"),
                });
                add_column_annotation(metadata, &key, column);
            }
            "VIEW" => {
                let view_key = view_keys.get(&relation_name).cloned().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "view column '{}.{}' lost its view key",
                        column.table, column.name
                    ))
                })?;
                let key = family_key(
                    source_kind,
                    connection_alias,
                    database,
                    ObjectKind::ViewColumn,
                    &column.table,
                    Some(column.name.clone()),
                );
                let mut properties = column_properties(column);
                insert_u64(&mut properties, "ordinal_position", column.ordinal as u64);
                metadata.objects.push(MetadataObject {
                    key,
                    parent_key: Some(view_key),
                    name: column.name.clone(),
                    extension_kind: None,
                    definition: column.generation_expression.clone(),
                    properties,
                });
            }
            "SEQUENCE" => {
                let sequence_key = sequence_keys.get(&relation_name).cloned().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "sequence column '{}.{}' lost its sequence key",
                        column.table, column.name
                    ))
                })?;
                let key = family_key(
                    source_kind,
                    connection_alias,
                    database,
                    ObjectKind::Extension,
                    &column.table,
                    Some(format!("sequence_column:{}", column.name)),
                );
                let mut properties = column_properties(column);
                insert_u64(&mut properties, "ordinal_position", column.ordinal as u64);
                metadata.objects.push(MetadataObject {
                    key,
                    parent_key: Some(sequence_key),
                    name: column.name.clone(),
                    extension_kind: Some("mariadb_sequence_column".to_owned()),
                    definition: column.generation_expression.clone(),
                    properties,
                });
            }
            unsupported => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "column '{}.{}' belongs to unsupported TABLE_TYPE '{unsupported}'",
                    column.table, column.name
                )));
            }
        }
    }
    Ok(MappedColumns {
        objects: columns,
        keys: column_keys,
    })
}

struct MappedColumns {
    objects: Vec<ColumnObject>,
    keys: BTreeMap<(String, String), ObjectKey>,
}

fn column_properties(column: &RawColumn) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_string(&mut properties, "data_type", &column.data_type);
    insert_string(&mut properties, "column_type", &column.column_type);
    insert_optional_string(
        &mut properties,
        "character_set",
        column.character_set.as_deref(),
    );
    insert_optional_string(&mut properties, "collation", column.collation.as_deref());
    insert_string(&mut properties, "extra", &column.extra);
    insert_string(&mut properties, "privileges", &column.privileges);
    insert_string(&mut properties, "comment", &column.comment);
    if let Some(spatial_reference_id) = column.spatial_reference_id {
        insert_u64(
            &mut properties,
            "spatial_reference_id",
            spatial_reference_id,
        );
    }
    insert_bool(
        &mut properties,
        "system_period_start",
        column.system_period_start,
    );
    insert_bool(
        &mut properties,
        "system_period_end",
        column.system_period_end,
    );
    properties
}

fn add_column_annotation(
    metadata: &mut CanonicalMetadata,
    column_key: &ObjectKey,
    column: &RawColumn,
) {
    add_annotation(
        metadata,
        column_key,
        column.generation_expression.clone(),
        column_properties(column),
    );
}

fn resolve_view_dependencies(
    raw: &RawMysqlFamilyCatalog,
    table_keys: &BTreeMap<String, ObjectKey>,
    view_keys: &BTreeMap<String, ObjectKey>,
) -> Result<BTreeMap<String, Vec<ObjectKey>>, CatalogError> {
    let mut grouped = raw
        .views
        .iter()
        .map(|view| {
            (
                normalize_object_name(&view.name, raw.facts.lower_case_table_names),
                BTreeSet::<String>::new(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut keys = BTreeMap::new();
    for key in table_keys.values().chain(view_keys.values()) {
        keys.insert(key.to_string(), key.clone());
    }

    match raw.strategy.product() {
        MysqlProduct::Mysql => {
            for usage in &raw.view_table_usage {
                let view = normalize_object_name(&usage.view, raw.facts.lower_case_table_names);
                let dependencies = grouped.get_mut(&view).ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "VIEW_TABLE_USAGE references missing view '{}'",
                        usage.view
                    ))
                })?;
                if normalize_object_name(&usage.target_schema, raw.facts.lower_case_table_names)
                    != normalize_object_name(&raw.facts.database, raw.facts.lower_case_table_names)
                {
                    return Err(CatalogError::UnsupportedMetadata(format!(
                        "view '{}' depends on out-of-scope database '{}.{}'",
                        usage.view, usage.target_schema, usage.target_name
                    )));
                }
                let target =
                    normalize_object_name(&usage.target_name, raw.facts.lower_case_table_names);
                let key = table_keys
                    .get(&target)
                    .or_else(|| view_keys.get(&target))
                    .ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "view '{}' dependency '{}.{}' is absent from the selected catalog",
                            usage.view, usage.target_schema, usage.target_name
                        ))
                    })?;
                dependencies.insert(key.to_string());
            }
        }
        MysqlProduct::MariaDb => {
            for view in &raw.views {
                let definition = view.definition.as_deref().ok_or_else(|| {
                    CatalogError::PermissionDenied(format!(
                        "view '{}' definition is hidden; SHOW VIEW is not effective",
                        view.name
                    ))
                })?;
                let relations =
                    parse_mariadb_view_relations(definition, raw.facts.lower_case_table_names)?;
                let view_name = normalize_object_name(&view.name, raw.facts.lower_case_table_names);
                let dependencies = grouped.get_mut(&view_name).ok_or_else(|| {
                    CatalogError::Mapping(format!("view '{}' has no dependency ledger", view.name))
                })?;
                for (schema, relation) in relations {
                    if schema.as_deref().is_some_and(|schema| {
                        normalize_object_name(schema, raw.facts.lower_case_table_names)
                            != normalize_object_name(
                                &raw.facts.database,
                                raw.facts.lower_case_table_names,
                            )
                    }) {
                        return Err(CatalogError::UnsupportedMetadata(format!(
                            "view '{}' depends on out-of-scope relation '{}.{}'",
                            view.name,
                            schema.unwrap_or_default(),
                            relation
                        )));
                    }
                    let target = normalize_object_name(&relation, raw.facts.lower_case_table_names);
                    let key = table_keys
                        .get(&target)
                        .or_else(|| view_keys.get(&target))
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "MariaDB view '{}' AST dependency '{}' is absent from the selected catalog",
                                view.name, relation
                            ))
                        })?;
                    dependencies.insert(key.to_string());
                }
            }
        }
    }

    grouped
        .into_iter()
        .map(|(view, dependency_ids)| {
            let dependencies = dependency_ids
                .into_iter()
                .map(|id| {
                    keys.get(&id).cloned().ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "view dependency stable key '{id}' was not registered"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((view, dependencies))
        })
        .collect()
}

#[derive(Default)]
struct CteAliasCollector {
    aliases: BTreeSet<String>,
    lower_case_table_names: u64,
}

impl Visitor for CteAliasCollector {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.aliases.insert(normalize_object_name(
                    &cte.alias.name.value,
                    self.lower_case_table_names,
                ));
            }
        }
        ControlFlow::Continue(())
    }
}

fn parse_mariadb_view_relations(
    definition: &str,
    lower_case_table_names: u64,
) -> Result<BTreeSet<(Option<String>, String)>, CatalogError> {
    let statements = Parser::parse_sql(&MySqlDialect {}, definition).map_err(|error| {
        CatalogError::UnsupportedMetadata(format!(
            "MariaDB view definition cannot be parsed as SQL AST: {error}"
        ))
    })?;
    if statements.len() != 1 {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "MariaDB view definition parsed into {} statements instead of one",
            statements.len()
        )));
    }
    let mut ctes = CteAliasCollector {
        aliases: BTreeSet::new(),
        lower_case_table_names,
    };
    let _ = statements.visit(&mut ctes);

    let mut relations = BTreeSet::new();
    let mut failure = None;
    let _: ControlFlow<()> = visit_relations(&statements, |relation| {
        if failure.is_some() {
            return ControlFlow::Continue(());
        }
        match object_name_identifiers(relation) {
            Ok(parts) if parts.len() == 1 => {
                let name = parts[0].clone();
                let normalized = normalize_object_name(&name, lower_case_table_names);
                if !ctes.aliases.contains(&normalized) && !name.eq_ignore_ascii_case("dual") {
                    relations.insert((None, name));
                }
            }
            Ok(parts) if parts.len() == 2 => {
                relations.insert((Some(parts[0].clone()), parts[1].clone()));
            }
            Ok(parts) => {
                failure = Some(CatalogError::UnsupportedMetadata(format!(
                    "MariaDB view relation '{}' uses unsupported {}-part qualification",
                    relation,
                    parts.len()
                )));
            }
            Err(error) => failure = Some(error),
        }
        ControlFlow::Continue(())
    });
    match failure {
        Some(error) => Err(error),
        None => Ok(relations),
    }
}

fn object_name_identifiers(name: &ObjectName) -> Result<Vec<String>, CatalogError> {
    name.0
        .iter()
        .map(|part| match part {
            ObjectNamePart::Identifier(identifier) => Ok(identifier.value.clone()),
            ObjectNamePart::Function(_) => Err(CatalogError::UnsupportedMetadata(format!(
                "dynamic relation identifier '{name}' cannot be proven"
            ))),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn map_constraints(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    lower_case_table_names: u64,
    raw: &RawMysqlFamilyCatalog,
    table_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> Result<Vec<ConstraintObject>, CatalogError> {
    let mut key_usage = BTreeMap::<(String, String), Vec<&RawKeyUsage>>::new();
    for usage in &raw.key_usage {
        key_usage
            .entry((
                normalize_object_name(&usage.table, lower_case_table_names),
                usage.constraint.clone(),
            ))
            .or_default()
            .push(usage);
    }
    let mut checks = BTreeMap::new();
    for check in &raw.checks {
        let key = (
            normalize_object_name(&check.table, lower_case_table_names),
            check.constraint.clone(),
        );
        if checks.insert(key, check).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate check definition '{}.{}'",
                check.table, check.constraint
            )));
        }
    }
    let mut reference_rules = BTreeMap::new();
    for rule in &raw.reference_rules {
        let key = (
            normalize_object_name(&rule.table, lower_case_table_names),
            rule.constraint.clone(),
        );
        if reference_rules.insert(key, rule).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate referential rule '{}.{}'",
                rule.table, rule.constraint
            )));
        }
    }

    let mut constraints = Vec::new();
    let mut seen = BTreeSet::new();
    for raw_constraint in &raw.constraints {
        let table_name = normalize_object_name(&raw_constraint.table, lower_case_table_names);
        let identity = (table_name.clone(), raw_constraint.name.clone());
        if !seen.insert(identity.clone()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate constraint '{}.{}'",
                raw_constraint.table, raw_constraint.name
            )));
        }
        let table_key = table_keys.get(&table_name).cloned().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "constraint '{}.{}' targets a non-base or missing table",
                raw_constraint.table, raw_constraint.name
            ))
        })?;
        let (kind, object_kind) = match raw_constraint.constraint_type.as_str() {
            "PRIMARY KEY" => (ConstraintKind::PrimaryKey, ObjectKind::PrimaryKey),
            "FOREIGN KEY" => (ConstraintKind::ForeignKey, ObjectKind::ForeignKey),
            "UNIQUE" => (ConstraintKind::Unique, ObjectKind::UniqueConstraint),
            "CHECK" => (ConstraintKind::Check, ObjectKind::CheckConstraint),
            unsupported => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "constraint '{}.{}' has unsupported type '{unsupported}'",
                    raw_constraint.table, raw_constraint.name
                )));
            }
        };
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            object_kind,
            &raw_constraint.table,
            Some(raw_constraint.name.clone()),
        );
        let mut source_columns = Vec::new();
        let mut referenced_columns = Vec::new();
        let mut referenced_table_key = None;
        let mut uses = key_usage.remove(&identity).unwrap_or_default();
        uses.sort_by_key(|usage| usage.ordinal);
        if kind != ConstraintKind::Check {
            require_contiguous_ordinals(
                uses.iter().map(|usage| usage.ordinal),
                &format!(
                    "constraint '{}.{}'",
                    raw_constraint.table, raw_constraint.name
                ),
            )?;
            if uses.is_empty() {
                return Err(CatalogError::Mapping(format!(
                    "constraint '{}.{}' has no KEY_COLUMN_USAGE rows",
                    raw_constraint.table, raw_constraint.name
                )));
            }
        } else if !uses.is_empty() {
            return Err(CatalogError::Mapping(format!(
                "check constraint '{}.{}' unexpectedly has KEY_COLUMN_USAGE rows",
                raw_constraint.table, raw_constraint.name
            )));
        }
        for usage in uses {
            let source = column_keys
                .get(&(table_name.clone(), normalize_column_name(&usage.column)))
                .cloned()
                .ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "constraint '{}.{}' references missing source column '{}'",
                        raw_constraint.table, raw_constraint.name, usage.column
                    ))
                })?;
            source_columns.push(source);
            if kind == ConstraintKind::ForeignKey {
                let referenced_schema = usage.referenced_schema.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key '{}.{}' lacks referenced schema",
                        raw_constraint.table, raw_constraint.name
                    ))
                })?;
                if normalize_object_name(referenced_schema, lower_case_table_names)
                    != normalize_object_name(database, lower_case_table_names)
                {
                    return Err(CatalogError::UnsupportedMetadata(format!(
                        "foreign key '{}.{}' references out-of-scope database '{}'",
                        raw_constraint.table, raw_constraint.name, referenced_schema
                    )));
                }
                let referenced_table = usage.referenced_table.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key '{}.{}' lacks referenced table",
                        raw_constraint.table, raw_constraint.name
                    ))
                })?;
                let referenced_name =
                    normalize_object_name(referenced_table, lower_case_table_names);
                let candidate = table_keys.get(&referenced_name).cloned().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key '{}.{}' references missing table '{}'",
                        raw_constraint.table, raw_constraint.name, referenced_table
                    ))
                })?;
                if referenced_table_key
                    .as_ref()
                    .is_some_and(|existing| existing != &candidate)
                {
                    return Err(CatalogError::Mapping(format!(
                        "foreign key '{}.{}' references multiple target tables",
                        raw_constraint.table, raw_constraint.name
                    )));
                }
                referenced_table_key = Some(candidate);
                let referenced_column = usage.referenced_column.as_deref().ok_or_else(|| {
                    CatalogError::Mapping(format!(
                        "foreign key '{}.{}' lacks referenced column",
                        raw_constraint.table, raw_constraint.name
                    ))
                })?;
                referenced_columns.push(
                    column_keys
                        .get(&(referenced_name, normalize_column_name(referenced_column)))
                        .cloned()
                        .ok_or_else(|| {
                            CatalogError::Mapping(format!(
                                "foreign key '{}.{}' references missing column '{}.{}'",
                                raw_constraint.table,
                                raw_constraint.name,
                                referenced_table,
                                referenced_column
                            ))
                        })?,
                );
            } else if usage.referenced_table.is_some()
                || usage.referenced_column.is_some()
                || usage.referenced_schema.is_some()
            {
                return Err(CatalogError::Mapping(format!(
                    "non-foreign constraint '{}.{}' has referenced target metadata",
                    raw_constraint.table, raw_constraint.name
                )));
            }
        }

        let expression = if kind == ConstraintKind::Check {
            Some(
                checks
                    .remove(&identity)
                    .ok_or_else(|| {
                        CatalogError::Mapping(format!(
                            "check constraint '{}.{}' has no CHECK_CONSTRAINTS row",
                            raw_constraint.table, raw_constraint.name
                        ))
                    })?
                    .clause
                    .clone(),
            )
        } else {
            None
        };
        let mut properties = BTreeMap::new();
        insert_bool(&mut properties, "enforced", raw_constraint.enforced);
        if kind == ConstraintKind::ForeignKey {
            let rule = reference_rules.remove(&identity).ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "foreign key '{}.{}' has no REFERENTIAL_CONSTRAINTS row",
                    raw_constraint.table, raw_constraint.name
                ))
            })?;
            insert_string(&mut properties, "match_option", &rule.match_option);
            insert_string(&mut properties, "update_rule", &rule.update_rule);
            insert_string(&mut properties, "delete_rule", &rule.delete_rule);
        }
        add_annotation(metadata, &key, None, properties);
        constraints.push(ConstraintObject {
            key,
            table_key,
            name: raw_constraint.name.clone(),
            kind,
            columns: source_columns,
            referenced_table_key,
            referenced_columns,
            expression,
        });
    }
    if let Some(((table, name), _)) = key_usage.into_iter().next() {
        return Err(CatalogError::Mapping(format!(
            "KEY_COLUMN_USAGE row '{table}.{name}' has no TABLE_CONSTRAINTS owner"
        )));
    }
    if let Some(((table, name), _)) = checks.into_iter().next() {
        return Err(CatalogError::Mapping(format!(
            "CHECK_CONSTRAINTS row '{table}.{name}' has no TABLE_CONSTRAINTS owner"
        )));
    }
    if let Some(((table, name), _)) = reference_rules.into_iter().next() {
        return Err(CatalogError::Mapping(format!(
            "REFERENTIAL_CONSTRAINTS row '{table}.{name}' has no foreign key owner"
        )));
    }
    Ok(constraints)
}

#[allow(clippy::too_many_arguments)]
fn map_indexes(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    lower_case_table_names: u64,
    raw_parts: &[RawIndexPart],
    table_keys: &BTreeMap<String, ObjectKey>,
    column_keys: &BTreeMap<(String, String), ObjectKey>,
) -> Result<Vec<IndexObject>, CatalogError> {
    let mut grouped = BTreeMap::<(String, String), Vec<&RawIndexPart>>::new();
    for part in raw_parts {
        grouped
            .entry((
                normalize_object_name(&part.table, lower_case_table_names),
                part.index.clone(),
            ))
            .or_default()
            .push(part);
    }
    let mut indexes = Vec::new();
    for ((table_name, index_name), mut parts) in grouped {
        parts.sort_by_key(|part| part.ordinal);
        require_contiguous_ordinals(
            parts.iter().map(|part| part.ordinal),
            &format!("index '{table_name}.{index_name}'"),
        )?;
        let first = parts[0];
        if parts.iter().any(|part| {
            part.non_unique != first.non_unique
                || part.index_type != first.index_type
                || part.visible != first.visible
                || part.comment != first.comment
                || part.index_comment != first.index_comment
        }) {
            return Err(CatalogError::Mapping(format!(
                "index '{table_name}.{index_name}' has inconsistent part metadata"
            )));
        }
        let table_key = table_keys.get(&table_name).cloned().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "index '{table_name}.{index_name}' targets a non-base or missing table"
            ))
        })?;
        let mut columns = Vec::new();
        let mut expressions = Vec::new();
        let mut part_descriptions = Vec::new();
        for part in parts {
            match (part.column.as_deref(), part.expression.as_deref()) {
                (Some(column), None) => {
                    columns.push(
                        column_keys
                            .get(&(
                                table_name.clone(),
                                normalize_column_name(column),
                            ))
                            .cloned()
                            .ok_or_else(|| {
                                CatalogError::Mapping(format!(
                                    "index '{table_name}.{index_name}' references missing column '{column}'"
                                ))
                            })?,
                    );
                    part_descriptions.push(format_index_part(part, column));
                }
                (None, Some(expression)) if !expression.trim().is_empty() => {
                    expressions.push(expression.to_owned());
                    part_descriptions.push(format_index_part(part, expression));
                }
                (Some(_), Some(_)) => {
                    return Err(CatalogError::Mapping(format!(
                        "index '{table_name}.{index_name}' part {} has both column and expression",
                        part.ordinal
                    )));
                }
                _ => {
                    return Err(CatalogError::Mapping(format!(
                        "index '{table_name}.{index_name}' part {} has neither column nor expression",
                        part.ordinal
                    )));
                }
            }
        }
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Index,
            &first.table,
            Some(index_name.clone()),
        );
        let mut properties = BTreeMap::new();
        insert_string(&mut properties, "index_type", &first.index_type);
        insert_bool(&mut properties, "visible", first.visible);
        insert_string(&mut properties, "comment", &first.comment);
        insert_string(&mut properties, "index_comment", &first.index_comment);
        properties.insert(
            "parts".to_owned(),
            MetadataValue::StringList(part_descriptions),
        );
        add_annotation(metadata, &key, None, properties);
        indexes.push(IndexObject {
            key,
            table_key,
            name: index_name.clone(),
            columns,
            is_unique: !first.non_unique,
            is_primary: index_name == "PRIMARY",
            predicate: None,
            expression: (!expressions.is_empty()).then(|| expressions.join(", ")),
        });
    }
    Ok(indexes)
}

fn format_index_part(part: &RawIndexPart, value: &str) -> String {
    let mut description = format!("{}:{value}", part.ordinal);
    if let Some(prefix_length) = part.prefix_length {
        description.push_str(&format!(":prefix={prefix_length}"));
    }
    if let Some(collation) = part.collation.as_deref() {
        description.push_str(&format!(":order={collation}"));
    }
    description
}

fn require_contiguous_ordinals(
    ordinals: impl IntoIterator<Item = u32>,
    subject: &str,
) -> Result<(), CatalogError> {
    for (index, ordinal) in ordinals.into_iter().enumerate() {
        let expected = u32::try_from(index + 1)
            .map_err(|_| CatalogError::Mapping(format!("{subject} has too many terms")))?;
        if ordinal != expected {
            return Err(CatalogError::Mapping(format!(
                "{subject} ordinal {ordinal} is not contiguous; expected {expected}"
            )));
        }
    }
    Ok(())
}

fn map_routines(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    schema_key: &ObjectKey,
    raw_routines: &[RawRoutine],
    raw_parameters: &[RawParameter],
) -> Result<(Vec<RoutineObject>, BTreeMap<String, ObjectKey>), CatalogError> {
    let mut routines = Vec::new();
    let mut routine_keys = BTreeMap::new();
    for routine in raw_routines {
        let definition = routine.definition.clone().ok_or_else(|| {
            CatalogError::PermissionDenied(format!(
                "routine '{}' definition is hidden for the current principal",
                routine.name
            ))
        })?;
        let kind = match routine.routine_type.as_str() {
            "FUNCTION" => RoutineKind::Function,
            "PROCEDURE" => RoutineKind::Procedure,
            unsupported => {
                return Err(CatalogError::UnsupportedMetadata(format!(
                    "routine '{}' has unsupported ROUTINE_TYPE '{unsupported}'",
                    routine.name
                )));
            }
        };
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Routine,
            &routine.name,
            Some(routine.specific_name.clone()),
        );
        let normalized = routine.specific_name.to_ascii_lowercase();
        if routine_keys.insert(normalized, key.clone()).is_some() {
            return Err(CatalogError::Mapping(format!(
                "duplicate routine specific name '{}'",
                routine.specific_name
            )));
        }
        routines.push(RoutineObject {
            key: key.clone(),
            schema_key: schema_key.clone(),
            name: routine.name.clone(),
            kind,
            definition: Some(definition),
            depends_on: Vec::new(),
        });
        let mut properties = BTreeMap::new();
        insert_string(&mut properties, "specific_name", &routine.specific_name);
        insert_string(&mut properties, "data_type", &routine.data_type);
        insert_optional_string(
            &mut properties,
            "dtd_identifier",
            routine.dtd_identifier.as_deref(),
        );
        insert_bool(&mut properties, "deterministic", routine.deterministic);
        insert_string(&mut properties, "sql_data_access", &routine.sql_data_access);
        insert_string(&mut properties, "security_type", &routine.security_type);
        insert_string(&mut properties, "sql_mode", &routine.sql_mode);
        insert_string(&mut properties, "comment", &routine.comment);
        insert_string(&mut properties, "definer", &routine.definer);
        insert_optional_string(
            &mut properties,
            "character_set_client",
            routine.character_set.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "collation_connection",
            routine.collation.as_deref(),
        );
        insert_string(
            &mut properties,
            "database_collation",
            &routine.database_collation,
        );
        add_annotation(metadata, &key, None, properties);
    }

    let mut parameter_ids = BTreeSet::new();
    for parameter in raw_parameters {
        let routine_key = routine_keys
            .get(&parameter.specific_name.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "parameter {}:{} has no routine owner",
                    parameter.specific_name, parameter.ordinal
                ))
            })?;
        let owner = raw_routines
            .iter()
            .find(|routine| routine.specific_name == parameter.specific_name)
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "parameter {}:{} lost its raw routine owner",
                    parameter.specific_name, parameter.ordinal
                ))
            })?;
        if parameter.routine_type != owner.routine_type {
            return Err(CatalogError::Mapping(format!(
                "parameter {}:{} routine type '{}' differs from owner type '{}'",
                parameter.specific_name,
                parameter.ordinal,
                parameter.routine_type,
                owner.routine_type
            )));
        }
        let identity = (parameter.specific_name.clone(), parameter.ordinal);
        if !parameter_ids.insert(identity) {
            return Err(CatalogError::Mapping(format!(
                "duplicate routine parameter {}:{}",
                parameter.specific_name, parameter.ordinal
            )));
        }
        let display_name = parameter.name.clone().unwrap_or_else(|| {
            if parameter.ordinal == 0 {
                "return"
            } else {
                "unnamed"
            }
            .to_owned()
        });
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::RoutineParameter,
            &owner.name,
            Some(format!(
                "{}:{}:{}",
                parameter.specific_name, parameter.ordinal, display_name
            )),
        );
        let mut properties = BTreeMap::new();
        insert_u64(
            &mut properties,
            "ordinal_position",
            parameter.ordinal as u64,
        );
        insert_optional_string(&mut properties, "mode", parameter.mode.as_deref());
        insert_string(&mut properties, "data_type", &parameter.data_type);
        insert_optional_string(
            &mut properties,
            "dtd_identifier",
            parameter.dtd_identifier.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "default_value",
            parameter.default_value.as_deref(),
        );
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
            from_key: routine_key,
            to_key: key,
            ordinal: Some(parameter.ordinal),
            properties: BTreeMap::new(),
        });
    }
    Ok((routines, routine_keys))
}

#[allow(clippy::too_many_arguments)]
fn map_triggers(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    lower_case_table_names: u64,
    raw_triggers: &[RawTrigger],
    table_keys: &BTreeMap<String, ObjectKey>,
) -> Result<Vec<TriggerObject>, CatalogError> {
    let mut triggers = Vec::new();
    let mut seen = BTreeSet::new();
    for trigger in raw_triggers {
        if !seen.insert(trigger.name.to_ascii_lowercase()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate trigger '{}'",
                trigger.name
            )));
        }
        let statement = trigger.statement.clone().ok_or_else(|| {
            CatalogError::PermissionDenied(format!(
                "trigger '{}' action statement is hidden",
                trigger.name
            ))
        })?;
        let table_name = normalize_object_name(&trigger.table, lower_case_table_names);
        let table_key = table_keys.get(&table_name).cloned().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "trigger '{}' targets missing base table '{}'",
                trigger.name, trigger.table
            ))
        })?;
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Trigger,
            &trigger.table,
            Some(trigger.name.clone()),
        );
        triggers.push(TriggerObject {
            key: key.clone(),
            table_key,
            name: trigger.name.clone(),
            timing: Some(trigger.timing.clone()),
            events: vec![trigger.event.clone()],
            definition: Some(statement),
            executes_routine_key: None,
        });
        let mut properties = BTreeMap::new();
        insert_u64(&mut properties, "action_order", trigger.action_order);
        insert_optional_string(
            &mut properties,
            "action_condition",
            trigger.condition.as_deref(),
        );
        insert_string(&mut properties, "orientation", &trigger.orientation);
        insert_string(&mut properties, "sql_mode", &trigger.sql_mode);
        insert_string(&mut properties, "definer", &trigger.definer);
        insert_string(
            &mut properties,
            "character_set_client",
            &trigger.character_set,
        );
        insert_string(&mut properties, "collation_connection", &trigger.collation);
        insert_string(
            &mut properties,
            "database_collation",
            &trigger.database_collation,
        );
        add_annotation(metadata, &key, None, properties);
    }
    Ok(triggers)
}

fn map_events(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    schema_key: &ObjectKey,
    raw_events: &[RawEvent],
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    for event in raw_events {
        if !seen.insert(event.name.to_ascii_lowercase()) {
            return Err(CatalogError::Mapping(format!(
                "duplicate scheduled event '{}'",
                event.name
            )));
        }
        let definition = event.definition.clone().ok_or_else(|| {
            CatalogError::PermissionDenied(format!(
                "scheduled event '{}' definition is hidden",
                event.name
            ))
        })?;
        let key = family_key(
            source_kind,
            connection_alias,
            database,
            ObjectKind::Event,
            &event.name,
            None,
        );
        let mut properties = BTreeMap::new();
        insert_string(&mut properties, "definer", &event.definer);
        insert_string(&mut properties, "time_zone", &event.time_zone);
        insert_string(&mut properties, "body", &event.body);
        insert_string(&mut properties, "event_type", &event.event_type);
        insert_optional_string(&mut properties, "execute_at", event.execute_at.as_deref());
        insert_optional_string(
            &mut properties,
            "interval_value",
            event.interval_value.as_deref(),
        );
        insert_optional_string(
            &mut properties,
            "interval_field",
            event.interval_field.as_deref(),
        );
        insert_string(&mut properties, "sql_mode", &event.sql_mode);
        insert_optional_string(&mut properties, "starts", event.starts.as_deref());
        insert_optional_string(&mut properties, "ends", event.ends.as_deref());
        insert_string(&mut properties, "status", &event.status);
        insert_string(&mut properties, "on_completion", &event.on_completion);
        insert_string(&mut properties, "comment", &event.comment);
        metadata.objects.push(MetadataObject {
            key,
            parent_key: Some(schema_key.clone()),
            name: event.name.clone(),
            extension_kind: None,
            definition: Some(definition),
            properties,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn map_partitions(
    metadata: &mut CanonicalMetadata,
    source_kind: &str,
    connection_alias: &str,
    database: &str,
    lower_case_table_names: u64,
    raw_partitions: &[RawPartition],
    table_keys: &BTreeMap<String, ObjectKey>,
) -> Result<(), CatalogError> {
    let mut partition_keys = BTreeMap::<(String, String), ObjectKey>::new();
    let mut subpartitions = BTreeSet::new();
    for partition in raw_partitions {
        let table_name = normalize_object_name(&partition.table, lower_case_table_names);
        let table_key = table_keys.get(&table_name).cloned().ok_or_else(|| {
            CatalogError::Mapping(format!(
                "partition '{}.{}' targets missing base table",
                partition.table, partition.partition
            ))
        })?;
        let partition_identity = (table_name.clone(), partition.partition.clone());
        let partition_key = match partition_keys.get(&partition_identity) {
            Some(key) => key.clone(),
            None => {
                let key = family_key(
                    source_kind,
                    connection_alias,
                    database,
                    ObjectKind::Extension,
                    &partition.table,
                    Some(format!("partition:{}", partition.partition)),
                );
                let mut properties = BTreeMap::new();
                insert_u64(
                    &mut properties,
                    "ordinal_position",
                    partition.partition_ordinal as u64,
                );
                insert_optional_string(&mut properties, "method", partition.method.as_deref());
                insert_optional_string(
                    &mut properties,
                    "expression",
                    partition.expression.as_deref(),
                );
                insert_optional_string(
                    &mut properties,
                    "description",
                    partition.description.as_deref(),
                );
                insert_string(&mut properties, "comment", &partition.comment);
                insert_optional_string(
                    &mut properties,
                    "tablespace",
                    partition.tablespace.as_deref(),
                );
                metadata.objects.push(MetadataObject {
                    key: key.clone(),
                    parent_key: Some(table_key),
                    name: partition.partition.clone(),
                    extension_kind: Some("mysql_partition".to_owned()),
                    definition: partition.expression.clone(),
                    properties,
                });
                partition_keys.insert(partition_identity.clone(), key.clone());
                key
            }
        };
        if let Some(subpartition) = partition.subpartition.as_deref() {
            let identity = (
                table_name,
                partition.partition.clone(),
                subpartition.to_owned(),
            );
            if !subpartitions.insert(identity) {
                return Err(CatalogError::Mapping(format!(
                    "duplicate subpartition '{}.{}.{}'",
                    partition.table, partition.partition, subpartition
                )));
            }
            let key = family_key(
                source_kind,
                connection_alias,
                database,
                ObjectKind::Extension,
                &partition.table,
                Some(format!(
                    "partition:{}:subpartition:{subpartition}",
                    partition.partition
                )),
            );
            let mut properties = BTreeMap::new();
            if let Some(ordinal) = partition.subpartition_ordinal {
                insert_u64(&mut properties, "ordinal_position", ordinal as u64);
            }
            insert_optional_string(
                &mut properties,
                "method",
                partition.subpartition_method.as_deref(),
            );
            insert_optional_string(
                &mut properties,
                "expression",
                partition.subpartition_expression.as_deref(),
            );
            metadata.objects.push(MetadataObject {
                key,
                parent_key: Some(partition_key),
                name: subpartition.to_owned(),
                extension_kind: Some("mysql_subpartition".to_owned()),
                definition: partition.subpartition_expression.clone(),
                properties,
            });
        }
    }
    Ok(())
}

fn map_view_routine_relationships(
    metadata: &mut CanonicalMetadata,
    raw: &RawMysqlFamilyCatalog,
    view_keys: &BTreeMap<String, ObjectKey>,
    routine_keys: &BTreeMap<String, ObjectKey>,
) -> Result<(), CatalogError> {
    for usage in &raw.view_routine_usage {
        if normalize_object_name(&usage.routine_schema, raw.facts.lower_case_table_names)
            != normalize_object_name(&raw.facts.database, raw.facts.lower_case_table_names)
        {
            return Err(CatalogError::UnsupportedMetadata(format!(
                "view '{}' invokes out-of-scope routine '{}.{}'",
                usage.view, usage.routine_schema, usage.specific_name
            )));
        }
        let view = view_keys
            .get(&normalize_object_name(
                &usage.view,
                raw.facts.lower_case_table_names,
            ))
            .cloned()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "VIEW_ROUTINE_USAGE references missing view '{}'",
                    usage.view
                ))
            })?;
        let routine = routine_keys
            .get(&usage.specific_name.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| {
                CatalogError::Mapping(format!(
                    "VIEW_ROUTINE_USAGE references missing routine '{}'",
                    usage.specific_name
                ))
            })?;
        metadata.relationships.push(MetadataRelationship {
            kind: MetadataRelationshipKind::Invokes,
            from_key: view,
            to_key: routine,
            ordinal: None,
            properties: BTreeMap::new(),
        });
    }
    Ok(())
}

fn validate_relationship_uniqueness(
    relationships: &[MetadataRelationship],
) -> Result<(), CatalogError> {
    let mut seen = BTreeSet::new();
    for relationship in relationships.iter() {
        let identity = (
            relationship.kind.clone(),
            relationship.from_key.to_string(),
            relationship.to_key.to_string(),
            relationship.ordinal,
        );
        if !seen.insert(identity) {
            return Err(CatalogError::Mapping(format!(
                "duplicate metadata relationship {} -> {}",
                relationship.from_key, relationship.to_key
            )));
        }
    }
    Ok(())
}

fn ensure_dependency_closure(raw: &RawMysqlFamilyCatalog) -> Result<(), CatalogError> {
    if let Some(routine) = raw.routines.first() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "routine '{}' has a procedural body but {} exposes no authoritative routine dependency catalog",
            routine.name,
            match raw.strategy.product() {
                MysqlProduct::Mysql => "MySQL",
                MysqlProduct::MariaDb => "MariaDB",
            }
        )));
    }
    if let Some(trigger) = raw.triggers.first() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "trigger '{}' has an action body but the server exposes no authoritative trigger dependency catalog",
            trigger.name
        )));
    }
    if let Some(event) = raw.events.first() {
        return Err(CatalogError::UnsupportedMetadata(format!(
            "scheduled event '{}' has an action body but the server exposes no authoritative event dependency catalog",
            event.name
        )));
    }
    Ok(())
}

fn mysql_family_capabilities(source_kind: &str) -> AdapterCapabilities {
    AdapterCapabilities {
        source_kind: source_kind.to_owned(),
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
            "Reads INFORMATION_SCHEMA and SHOW CREATE metadata only; application table rows are never queried."
                .to_owned(),
            "The selected MySQL-family database is mapped to the common database and schema scope."
                .to_owned(),
            "Objects whose procedural dependencies cannot be proven fail before certification instead of emitting an incomplete graph."
                .to_owned(),
        ],
    }
}

fn mysql_family_capability_checks(raw: &RawMysqlFamilyCatalog) -> Vec<CapabilityCheck> {
    vec![
        CapabilityCheck {
            name: "catalog_stability".to_owned(),
            evidence: "ordered metadata signatures matched before and after catalog discovery"
                .to_owned(),
        },
        CapabilityCheck {
            name: "metadata_only_catalog_queries".to_owned(),
            evidence: "adapter queried INFORMATION_SCHEMA, session/server facts, and SHOW CREATE SEQUENCE only; no application relation appears in a SELECT FROM clause"
                .to_owned(),
        },
        CapabilityCheck {
            name: "metadata_visibility".to_owned(),
            evidence: format!(
                "effective schema/global privilege proof includes SELECT, SHOW VIEW, EXECUTE, EVENT, and TRIGGER ({} privilege entries)",
                raw.grants.len()
            ),
        },
        CapabilityCheck {
            name: "principal_context".to_owned(),
            evidence: format!(
                "current_user={} session_user={} active_roles={}",
                raw.facts.current_user,
                raw.facts.session_user,
                raw.active_roles.len()
            ),
        },
        CapabilityCheck {
            name: "read_only_repeatable_read_transaction".to_owned(),
            evidence: format!(
                "transaction_read_only={} transaction_isolation={}",
                raw.transaction_read_only, raw.transaction_isolation
            ),
        },
        CapabilityCheck {
            name: "supported_server_version".to_owned(),
            evidence: format!(
                "server version {} maps to certified strategy {}",
                raw.facts.version,
                raw.strategy.label()
            ),
        },
        CapabilityCheck {
            name: "transport_security".to_owned(),
            evidence: raw
                .facts
                .tls_cipher
                .as_deref()
                .map(|cipher| format!("TLS enabled with cipher {cipher}"))
                .unwrap_or_else(|| {
                    "plaintext transport is accepted only by the connection policy for a loopback/local endpoint"
                        .to_owned()
                }),
        },
        CapabilityCheck {
            name: "view_dependency_proof".to_owned(),
            evidence: match raw.strategy.product() {
                MysqlProduct::Mysql => format!(
                    "{} VIEW_TABLE_USAGE and {} VIEW_ROUTINE_USAGE rows reconciled to canonical dependencies",
                    raw.view_table_usage.len(),
                    raw.view_routine_usage.len()
                ),
                MysqlProduct::MariaDb => format!(
                    "all {} frozen MariaDB view definitions were parsed with the MySQL SQL AST dialect",
                    raw.views.len()
                ),
            },
        },
    ]
}

fn discovery_counts_from_catalog(
    raw: &RawMysqlFamilyCatalog,
    snapshot: &CanonicalSchemaSnapshot,
) -> Result<DiscoveryCounts, CatalogError> {
    let table_type_by_name = raw
        .tables
        .iter()
        .map(|table| {
            (
                normalize_object_name(&table.name, raw.facts.lower_case_table_names),
                table.table_type.to_ascii_uppercase(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let base_table_count = raw
        .tables
        .iter()
        .filter(|table| table.table_type.eq_ignore_ascii_case("BASE TABLE"))
        .count() as u64;
    let base_column_count = raw
        .columns
        .iter()
        .filter(|column| {
            table_type_by_name
                .get(&normalize_object_name(
                    &column.table,
                    raw.facts.lower_case_table_names,
                ))
                .is_some_and(|table_type| table_type == "BASE TABLE")
        })
        .count() as u64;
    let view_column_count = raw
        .columns
        .iter()
        .filter(|column| {
            table_type_by_name
                .get(&normalize_object_name(
                    &column.table,
                    raw.facts.lower_case_table_names,
                ))
                .is_some_and(|table_type| table_type == "VIEW")
        })
        .count() as u64;
    let sequence_column_count = raw
        .columns
        .iter()
        .filter(|column| {
            table_type_by_name
                .get(&normalize_object_name(
                    &column.table,
                    raw.facts.lower_case_table_names,
                ))
                .is_some_and(|table_type| table_type == "SEQUENCE")
        })
        .count() as u64;
    let index_identities = raw
        .index_parts
        .iter()
        .map(|part| {
            (
                normalize_object_name(&part.table, raw.facts.lower_case_table_names),
                part.index.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let partition_identities = raw
        .partitions
        .iter()
        .map(|partition| {
            (
                normalize_object_name(&partition.table, raw.facts.lower_case_table_names),
                partition.partition.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let subpartition_count = raw
        .partitions
        .iter()
        .filter(|partition| partition.subpartition.is_some())
        .count() as u64;

    let mut objects = ObjectCategory::ALL
        .into_iter()
        .map(|category| (category, 0_u64))
        .collect::<BTreeMap<_, _>>();
    objects.insert(ObjectCategory::Database, 1);
    objects.insert(ObjectCategory::Schema, 1);
    objects.insert(ObjectCategory::Table, base_table_count);
    objects.insert(ObjectCategory::Column, base_column_count);
    for (constraint_type, category) in [
        ("PRIMARY KEY", ObjectCategory::PrimaryKey),
        ("FOREIGN KEY", ObjectCategory::ForeignKey),
        ("UNIQUE", ObjectCategory::UniqueConstraint),
        ("CHECK", ObjectCategory::CheckConstraint),
    ] {
        objects.insert(
            category,
            raw.constraints
                .iter()
                .filter(|constraint| constraint.constraint_type == constraint_type)
                .count() as u64,
        );
    }
    objects.insert(ObjectCategory::Index, index_identities.len() as u64);
    objects.insert(ObjectCategory::View, raw.views.len() as u64);
    objects.insert(ObjectCategory::ViewColumn, view_column_count);
    objects.insert(ObjectCategory::Trigger, raw.triggers.len() as u64);
    objects.insert(ObjectCategory::Routine, raw.routines.len() as u64);
    objects.insert(ObjectCategory::Sequence, raw.sequences.len() as u64);
    objects.insert(
        ObjectCategory::RoutineParameter,
        raw.parameters.len() as u64,
    );
    objects.insert(ObjectCategory::Event, raw.events.len() as u64);
    objects.insert(
        ObjectCategory::Principal,
        1_u64 + raw.active_roles.len() as u64,
    );
    objects.insert(
        ObjectCategory::Extension,
        sequence_column_count + partition_identities.len() as u64 + subpartition_count,
    );

    let emitted_objects = emitted_object_counts(snapshot);
    for category in ObjectCategory::ALL {
        let discovered = objects.get(&category).copied().unwrap_or_default();
        let emitted = emitted_objects.get(&category).copied().unwrap_or_default();
        if discovered != emitted {
            return Err(CatalogError::Mapping(format!(
                "{} raw/emitted object count mismatch for {category:?}: discovered={discovered}, emitted={emitted}",
                raw.strategy.label()
            )));
        }
    }

    let constraint_types = raw
        .constraints
        .iter()
        .map(|constraint| {
            (
                (
                    normalize_object_name(&constraint.table, raw.facts.lower_case_table_names),
                    constraint.name.clone(),
                ),
                constraint.constraint_type.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let constraint_columns = raw
        .key_usage
        .iter()
        .filter(|usage| {
            constraint_types.get(&(
                normalize_object_name(&usage.table, raw.facts.lower_case_table_names),
                usage.constraint.clone(),
            )) != Some(&"FOREIGN KEY")
        })
        .count() as u64;
    let foreign_key_pairs = raw
        .key_usage
        .iter()
        .filter(|usage| {
            constraint_types.get(&(
                normalize_object_name(&usage.table, raw.facts.lower_case_table_names),
                usage.constraint.clone(),
            )) == Some(&"FOREIGN KEY")
        })
        .count() as u64;
    let index_column_count = raw
        .index_parts
        .iter()
        .filter(|part| part.column.is_some())
        .count() as u64;

    let mut relationships = RelationshipCategory::ALL
        .into_iter()
        .map(|category| (category, 0_u64))
        .collect::<BTreeMap<_, _>>();
    relationships.insert(RelationshipCategory::DatabaseHasSchema, 1);
    relationships.insert(RelationshipCategory::SchemaHasTable, base_table_count);
    relationships.insert(RelationshipCategory::TableHasColumn, base_column_count);
    relationships.insert(
        RelationshipCategory::TableHasConstraint,
        raw.constraints.len() as u64,
    );
    relationships.insert(RelationshipCategory::ConstraintColumn, constraint_columns);
    relationships.insert(
        RelationshipCategory::ForeignKeyColumnPair,
        foreign_key_pairs,
    );
    relationships.insert(
        RelationshipCategory::TableHasIndex,
        index_identities.len() as u64,
    );
    relationships.insert(RelationshipCategory::IndexColumn, index_column_count);
    relationships.insert(RelationshipCategory::SchemaHasView, raw.views.len() as u64);
    relationships.insert(
        RelationshipCategory::ViewDependency,
        snapshot
            .schema
            .views
            .iter()
            .map(|view| view.depends_on.len() as u64)
            .sum(),
    );
    relationships.insert(
        RelationshipCategory::TriggerTarget,
        raw.triggers.len() as u64,
    );
    relationships.insert(RelationshipCategory::TriggerRoutine, 0);
    relationships.insert(
        RelationshipCategory::SchemaHasRoutine,
        raw.routines.len() as u64,
    );
    relationships.insert(RelationshipCategory::RoutineDependency, 0);
    relationships.insert(
        RelationshipCategory::MetadataParent,
        snapshot
            .metadata
            .objects
            .iter()
            .filter(|object| object.parent_key.is_some())
            .count() as u64,
    );
    relationships.insert(
        RelationshipCategory::MetadataRelationship,
        snapshot.metadata.relationships.len() as u64,
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
                "{} raw/emitted relationship count mismatch for {category:?}: discovered={discovered}, emitted={emitted}",
                raw.strategy.label()
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
                            "{} INFORMATION_SCHEMA raw object inventory for {category:?}",
                            raw.strategy.label()
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
                            "{} strict relationship ledger for {category:?}",
                            raw.strategy.label()
                        ),
                    },
                )
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use mysql::prelude::Queryable;
    use mysql::Conn;

    use super::*;
    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStatus};

    #[test]
    fn version_strategy_accepts_only_the_certified_matrix() {
        for (version, expected) in [
            ("8.0.46", MysqlFamilyVersion::Mysql80),
            ("8.4.10", MysqlFamilyVersion::Mysql84),
            ("9.7.1", MysqlFamilyVersion::Mysql97),
            ("10.11.18-MariaDB-ubu2204", MysqlFamilyVersion::MariaDb1011),
            ("11.4.12-MariaDB", MysqlFamilyVersion::MariaDb114),
            ("11.8.8-MariaDB", MysqlFamilyVersion::MariaDb118),
            ("12.3.2-MariaDB", MysqlFamilyVersion::MariaDb123),
        ] {
            assert_eq!(MysqlFamilyVersion::detect(version).unwrap(), expected);
        }
        assert!(MysqlFamilyVersion::detect("5.7.44").is_err());
        assert!(MysqlFamilyVersion::detect("10.6.23-MariaDB").is_err());
        assert!(MysqlFamilyVersion::detect("9.8.0").is_err());
    }

    #[test]
    fn loopback_policy_is_exact() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("db.example.com"));
    }

    #[test]
    fn changed_catalog_signature_is_never_certified() {
        let before = CatalogSignature(vec!["table:a".to_owned()]);
        let after = CatalogSignature(vec!["table:b".to_owned()]);

        assert!(matches!(
            require_stable_signature(&before, &after),
            Err(CatalogError::ConcurrentDdl(_))
        ));
        assert!(require_stable_signature(&before, &before).is_ok());
    }

    #[test]
    fn server_generated_grants_are_scoped_without_substring_guessing() {
        let privileges = parse_schema_grant(
            "GRANT SELECT, EXECUTE, SHOW VIEW, EVENT, TRIGGER ON `app``data`.* TO `reader`@`%`",
            "app`data",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            privileges,
            BTreeSet::from([
                "SELECT".to_owned(),
                "EXECUTE".to_owned(),
                "SHOW VIEW".to_owned(),
                "EVENT".to_owned(),
                "TRIGGER".to_owned(),
            ])
        );
        assert!(parse_schema_grant(
            "GRANT SELECT ON `app``data`.`one_table` TO `reader`@`%`",
            "app`data"
        )
        .unwrap()
        .is_none());
        assert!(
            parse_schema_grant("GRANT `metadata_role` TO `reader`@`%`", "app`data")
                .unwrap()
                .is_none()
        );
        assert!(parse_schema_grant(
            "SET DEFAULT ROLE `metadata_role` FOR `reader`@`%`",
            "app`data"
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn transport_options_require_tls_for_remote_hosts_and_disable_cleartext_auth() {
        let request = IntrospectionRequest {
            connection_alias: "policy".to_owned(),
            requested_catalogs: Vec::new(),
            requested_schemas: Vec::new(),
            timeout_ms: 1_000,
        };
        let remote = secure_connection_options(
            &request,
            "mysql://reader:secret@db.example.com/app?prefer_socket=false",
        )
        .unwrap();
        assert!(remote.get_ssl_opts().is_some());
        assert!(!remote.get_enable_cleartext_plugin());

        let local = secure_connection_options(
            &request,
            "mysql://reader:secret@127.0.0.1/app?prefer_socket=false",
        )
        .unwrap();
        assert!(local.get_ssl_opts().is_none());

        let unsafe_auth = secure_connection_options(
            &request,
            "mysql://reader:secret@127.0.0.1/app?enable_cleartext_plugin=true",
        )
        .unwrap_err();
        assert_eq!(unsafe_auth.code, AnalysisFailureCode::UnsafeSource);
        assert!(!unsafe_auth.message.contains("secret"));
    }

    #[test]
    fn mariadb_view_ast_extracts_nested_relations_without_cte_aliases() {
        let relations = parse_mariadb_view_relations(
            "WITH recent AS (SELECT id FROM `dbmcp`.`orders`) \
             SELECT r.id FROM recent r JOIN customers c ON c.id = r.id \
             WHERE EXISTS (SELECT 1 FROM audit_log a WHERE a.id = r.id)",
            0,
        )
        .unwrap();

        assert_eq!(
            relations,
            BTreeSet::from([
                (Some("dbmcp".to_owned()), "orders".to_owned()),
                (None, "customers".to_owned()),
                (None, "audit_log".to_owned()),
            ])
        );
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_MYSQL*_URL or DATABASE_MEMORY_TEST_MARIADB*_URL"]
    fn mysql_family_live_matrix_is_env_gated() {
        let _live_test_guard = live_test_guard();
        let configured = required_live_cases();
        for (environment, source_kind, url) in configured {
            let outcome = analyze_mysql_family(&url, environment, Vec::new(), 30_000);
            assert_eq!(
                outcome.status(),
                AnalysisStatus::Complete,
                "{environment}: {:?}",
                outcome.failure()
            );
            let snapshot = outcome.certified_snapshot().unwrap();
            assert_eq!(snapshot.snapshot.schema.source_kind, source_kind);
            assert!(snapshot.snapshot.schema.capabilities.metadata_only);
        }
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_MYSQL*_URL or DATABASE_MEMORY_TEST_MARIADB*_URL"]
    fn rich_mysql_family_catalog_is_certified_across_the_live_matrix() {
        let _live_test_guard = live_test_guard();
        let configured = required_live_cases();
        for (environment, source_kind, url) in configured {
            let names = RichFixtureNames::new();
            let mut connection = Conn::new(url.as_str()).unwrap();
            create_rich_fixture(&mut connection, &names, source_kind == "mariadb");

            let outcome = analyze_mysql_family(&url, environment, Vec::new(), 30_000);
            let failure = outcome.failure().cloned();
            let certified = outcome.certified_snapshot().cloned();
            drop_rich_fixture(&mut connection, &names, source_kind == "mariadb");

            assert_eq!(
                outcome.status(),
                AnalysisStatus::Complete,
                "{environment}: {failure:?}"
            );
            let snapshot = &certified.unwrap().snapshot;
            for table in [&names.users, &names.orders, &names.events] {
                assert!(
                    snapshot
                        .schema
                        .tables
                        .iter()
                        .any(|item| &item.name == table),
                    "{environment}: missing table {table}"
                );
            }
            assert!(snapshot.schema.columns.iter().any(|column| {
                column.table_key.object_name == names.users
                    && column.name == "slug"
                    && column.is_generated
            }));
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
                    "{environment}: missing {kind:?}"
                );
            }
            assert!(snapshot
                .schema
                .indexes
                .iter()
                .any(|index| index.name == names.email_index));
            assert!(snapshot
                .schema
                .views
                .iter()
                .find(|view| view.name == names.order_view)
                .is_some_and(|view| view.depends_on.len() >= 2));
            assert!(snapshot.metadata.objects.iter().any(|object| {
                object.extension_kind.as_deref() == Some("mysql_partition")
                    && object.key.object_name == names.events
            }));
            if source_kind == "mariadb" {
                assert!(snapshot.metadata.objects.iter().any(|object| {
                    object.key.object_kind == ObjectKind::Sequence && object.name == names.sequence
                }));
            }
        }
    }

    #[test]
    #[ignore = "requires a DATABASE_MEMORY_TEST_MYSQL*_URL or DATABASE_MEMORY_TEST_MARIADB*_URL"]
    fn procedural_mysql_family_metadata_fails_closed() {
        let _live_test_guard = live_test_guard();
        let configured = required_live_cases();
        let mut exercised = BTreeSet::new();
        for (environment, source_kind, url) in configured {
            if !exercised.insert(source_kind) {
                continue;
            }
            let suffix = unique_suffix();
            let routine = format!("dm_routine_{suffix}");
            let mut connection = Conn::new(url.as_str()).unwrap();
            connection
                .query_drop(format!(
                    "CREATE PROCEDURE {}(IN value_in INT) SELECT value_in",
                    quote_identifier(&routine)
                ))
                .unwrap();

            let outcome = analyze_mysql_family(&url, environment, Vec::new(), 30_000);
            connection
                .query_drop(format!("DROP PROCEDURE {}", quote_identifier(&routine)))
                .unwrap();

            assert_eq!(outcome.status(), AnalysisStatus::Failed);
            assert_eq!(
                outcome.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::UnsupportedMetadata)
            );
            assert!(outcome.certified_snapshot().is_none());
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL or DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL"]
    fn trigger_and_event_bodies_fail_closed_for_both_products() {
        let _live_test_guard = live_test_guard();
        let configured = required_admin_cases();
        for (environment, _source_kind, url) in configured {
            let suffix = unique_suffix();
            let table = format!("dm_trigger_table_{suffix}");
            let trigger = format!("dm_trigger_{suffix}");
            let event = format!("dm_event_{suffix}");
            let mut connection = Conn::new(url.as_str()).unwrap();
            connection
                .query_drop(format!(
                    "CREATE TABLE {} (id INT NOT NULL PRIMARY KEY)",
                    quote_identifier(&table)
                ))
                .unwrap();
            connection
                .query_drop(format!(
                    "CREATE TRIGGER {} BEFORE INSERT ON {} FOR EACH ROW SET NEW.id = COALESCE(NEW.id, 0)",
                    quote_identifier(&trigger),
                    quote_identifier(&table)
                ))
                .unwrap();

            let trigger_outcome = analyze_mysql_family(&url, environment, Vec::new(), 30_000);
            connection
                .query_drop(format!("DROP TRIGGER {}", quote_identifier(&trigger)))
                .unwrap();
            connection
                .query_drop(format!("DROP TABLE {}", quote_identifier(&table)))
                .unwrap();

            assert_eq!(trigger_outcome.status(), AnalysisStatus::Failed);
            assert_eq!(
                trigger_outcome.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::UnsupportedMetadata)
            );
            assert!(trigger_outcome
                .failure()
                .is_some_and(|failure| failure.message.contains("trigger")));

            connection
                .query_drop(format!(
                    "CREATE EVENT {} ON SCHEDULE EVERY 1 DAY DO SELECT 1",
                    quote_identifier(&event)
                ))
                .unwrap();
            let event_outcome = analyze_mysql_family(&url, environment, Vec::new(), 30_000);
            connection
                .query_drop(format!("DROP EVENT {}", quote_identifier(&event)))
                .unwrap();

            assert_eq!(event_outcome.status(), AnalysisStatus::Failed);
            assert_eq!(
                event_outcome.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::UnsupportedMetadata)
            );
            assert!(event_outcome
                .failure()
                .is_some_and(|failure| failure.message.contains("event")));
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL or DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL"]
    fn schema_wide_visibility_is_required_and_then_sufficient() {
        let _live_test_guard = live_test_guard();
        let configured = required_admin_cases();
        for (environment, source_kind, admin_url) in configured {
            let opts = Opts::from_url(&admin_url).unwrap();
            let database = opts.get_db_name().unwrap().to_owned();
            let host = opts.get_ip_or_hostname();
            let port = opts.get_tcp_port();
            let suffix = unique_suffix();
            let user = format!("dm_reader_{suffix}");
            let password = format!("DmRead{suffix}");
            let table = format!("dm_visible_{suffix}");
            let reader_url =
                format!("mysql://{user}:{password}@{host}:{port}/{database}?prefer_socket=false");
            let account = format!("'{}'@'%'", user.replace('\'', "''"));
            let mut admin = Conn::new(admin_url.as_str()).unwrap();
            admin
                .query_drop(format!("DROP USER IF EXISTS {account}"))
                .unwrap();
            admin
                .query_drop(format!(
                    "CREATE USER {account} IDENTIFIED BY '{}'",
                    password.replace('\'', "''")
                ))
                .unwrap();
            admin
                .query_drop(format!(
                    "CREATE TABLE {} (id INT NOT NULL PRIMARY KEY)",
                    quote_identifier(&table)
                ))
                .unwrap();
            admin
                .query_drop(format!(
                    "GRANT SELECT ON {}.{} TO {account}",
                    quote_identifier(&database),
                    quote_identifier(&table)
                ))
                .unwrap();

            let denied = analyze_mysql_family(&reader_url, environment, Vec::new(), 30_000);
            admin
                .query_drop(format!(
                    "GRANT SELECT, SHOW VIEW, EXECUTE, EVENT, TRIGGER ON {}.* TO {account}",
                    quote_identifier(&database)
                ))
                .unwrap();
            let allowed = analyze_mysql_family(&reader_url, environment, Vec::new(), 30_000);

            admin
                .query_drop(format!("DROP TABLE {}", quote_identifier(&table)))
                .unwrap();
            admin.query_drop(format!("DROP USER {account}")).unwrap();

            assert_eq!(denied.status(), AnalysisStatus::Failed);
            assert_eq!(
                denied.failure().map(|failure| failure.code),
                Some(AnalysisFailureCode::PermissionDenied)
            );
            assert_eq!(
                allowed.status(),
                AnalysisStatus::Complete,
                "{source_kind}: {:?}",
                allowed.failure()
            );
        }
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL or DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL"]
    fn active_role_privileges_are_part_of_the_visibility_proof() {
        let _live_test_guard = live_test_guard();
        let configured = required_admin_cases();
        for (environment, source_kind, admin_url) in configured {
            let opts = Opts::from_url(&admin_url).unwrap();
            let database = opts.get_db_name().unwrap().to_owned();
            let host = opts.get_ip_or_hostname();
            let port = opts.get_tcp_port();
            let suffix = unique_suffix();
            let user = format!("dm_role_user_{suffix}");
            let role = format!("dm_role_{suffix}");
            let password = format!("DmRole{suffix}");
            let table = format!("dm_role_table_{suffix}");
            let reader_url =
                format!("mysql://{user}:{password}@{host}:{port}/{database}?prefer_socket=false");
            let user_account = format!("'{user}'@'%'");
            let role_account = if source_kind == "mysql" {
                format!("'{role}'@'%'")
            } else {
                quote_identifier(&role)
            };
            let mut admin = Conn::new(admin_url.as_str()).unwrap();
            admin
                .query_drop(format!("DROP USER IF EXISTS {user_account}"))
                .unwrap();
            if source_kind == "mysql" {
                admin
                    .query_drop(format!("DROP ROLE IF EXISTS {role_account}"))
                    .unwrap();
            } else {
                admin
                    .query_drop(format!("DROP ROLE IF EXISTS {}", quote_identifier(&role)))
                    .unwrap();
            }
            admin
                .query_drop(format!(
                    "CREATE USER {user_account} IDENTIFIED BY '{password}'"
                ))
                .unwrap();
            admin
                .query_drop(format!("CREATE ROLE {role_account}"))
                .unwrap();
            admin
                .query_drop(format!(
                    "CREATE TABLE {} (id INT NOT NULL PRIMARY KEY)",
                    quote_identifier(&table)
                ))
                .unwrap();
            admin
                .query_drop(format!(
                    "GRANT SELECT, SHOW VIEW, EXECUTE, EVENT, TRIGGER ON {}.* TO {role_account}",
                    quote_identifier(&database)
                ))
                .unwrap();
            admin
                .query_drop(format!("GRANT {role_account} TO {user_account}"))
                .unwrap();
            if source_kind == "mysql" {
                admin
                    .query_drop(format!("SET DEFAULT ROLE {role_account} TO {user_account}"))
                    .unwrap();
            } else {
                admin
                    .query_drop(format!(
                        "SET DEFAULT ROLE {} FOR {user_account}",
                        quote_identifier(&role)
                    ))
                    .unwrap();
            }

            let outcome = analyze_mysql_family(&reader_url, environment, Vec::new(), 30_000);

            admin
                .query_drop(format!("DROP TABLE {}", quote_identifier(&table)))
                .unwrap();
            admin
                .query_drop(format!("DROP USER {user_account}"))
                .unwrap();
            admin
                .query_drop(format!("DROP ROLE {role_account}"))
                .unwrap();

            assert_eq!(
                outcome.status(),
                AnalysisStatus::Complete,
                "{source_kind}: {:?}",
                outcome.failure()
            );
            assert!(outcome
                .certified_snapshot()
                .unwrap()
                .snapshot
                .metadata
                .objects
                .iter()
                .any(|object| {
                    object.key.object_kind == ObjectKind::Principal
                        && object.properties.get("principal_kind")
                            == Some(&MetadataValue::String("active_role".to_owned()))
                }));
        }
    }

    fn required_live_cases() -> Vec<(&'static str, &'static str, String)> {
        let configured = [
            ("DATABASE_MEMORY_TEST_MYSQL80_URL", "mysql"),
            ("DATABASE_MEMORY_TEST_MYSQL84_URL", "mysql"),
            ("DATABASE_MEMORY_TEST_MYSQL97_URL", "mysql"),
            ("DATABASE_MEMORY_TEST_MARIADB1011_URL", "mariadb"),
            ("DATABASE_MEMORY_TEST_MARIADB114_URL", "mariadb"),
            ("DATABASE_MEMORY_TEST_MARIADB118_URL", "mariadb"),
            ("DATABASE_MEMORY_TEST_MARIADB123_URL", "mariadb"),
        ]
        .into_iter()
        .filter_map(|(environment, source_kind)| {
            std::env::var(environment)
                .ok()
                .map(|url| (environment, source_kind, url))
        })
        .collect::<Vec<_>>();
        assert!(
            !configured.is_empty(),
            "live MySQL-family test requires at least one DATABASE_MEMORY_TEST_MYSQL*_URL or DATABASE_MEMORY_TEST_MARIADB*_URL"
        );
        configured
    }

    fn required_admin_cases() -> Vec<(&'static str, &'static str, String)> {
        let configured = [
            ("DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL", "mysql"),
            ("DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL", "mariadb"),
        ]
        .into_iter()
        .filter_map(|(environment, source_kind)| {
            std::env::var(environment)
                .ok()
                .map(|url| (environment, source_kind, url))
        })
        .collect::<Vec<_>>();
        assert!(
            !configured.is_empty(),
            "live MySQL-family privilege test requires DATABASE_MEMORY_TEST_MYSQL_ADMIN_URL or DATABASE_MEMORY_TEST_MARIADB_ADMIN_URL"
        );
        configured
    }

    fn live_test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct RichFixtureNames {
        users: String,
        orders: String,
        events: String,
        active_view: String,
        order_view: String,
        email_index: String,
        user_unique: String,
        user_check: String,
        order_fk: String,
        order_check: String,
        sequence: String,
    }

    impl RichFixtureNames {
        fn new() -> Self {
            let suffix = unique_suffix();
            Self {
                users: format!("dm_users_{suffix}"),
                orders: format!("dm_orders_{suffix}"),
                events: format!("dm_events_{suffix}"),
                active_view: format!("dm_active_{suffix}"),
                order_view: format!("dm_order_view_{suffix}"),
                email_index: format!("dm_email_idx_{suffix}"),
                user_unique: format!("dm_user_uq_{suffix}"),
                user_check: format!("dm_user_ck_{suffix}"),
                order_fk: format!("dm_order_fk_{suffix}"),
                order_check: format!("dm_order_ck_{suffix}"),
                sequence: format!("dm_sequence_{suffix}"),
            }
        }
    }

    fn unique_suffix() -> String {
        format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 1_000_000_000
        )
    }

    fn create_rich_fixture(connection: &mut Conn, names: &RichFixtureNames, maria_db: bool) {
        connection
            .query_drop(format!(
                "CREATE TABLE {} (\
                    id BIGINT NOT NULL AUTO_INCREMENT,\
                    email VARCHAR(255) NOT NULL,\
                    status VARCHAR(20) NOT NULL DEFAULT 'active',\
                    slug VARCHAR(255) GENERATED ALWAYS AS (LOWER(email)) STORED,\
                    PRIMARY KEY (id),\
                    CONSTRAINT {} UNIQUE (email),\
                    CONSTRAINT {} CHECK (CHAR_LENGTH(email) > 3)\
                ) ENGINE=InnoDB COMMENT='database-memory rich fixture'",
                quote_identifier(&names.users),
                quote_identifier(&names.user_unique),
                quote_identifier(&names.user_check),
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "CREATE TABLE {} (\
                    id BIGINT NOT NULL PRIMARY KEY,\
                    user_id BIGINT NOT NULL,\
                    amount DECIMAL(12,2) NOT NULL DEFAULT 0,\
                    CONSTRAINT {} FOREIGN KEY (user_id) REFERENCES {}(id) ON DELETE CASCADE,\
                    CONSTRAINT {} CHECK (amount >= 0)\
                ) ENGINE=InnoDB",
                quote_identifier(&names.orders),
                quote_identifier(&names.order_fk),
                quote_identifier(&names.users),
                quote_identifier(&names.order_check),
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "CREATE TABLE {} (\
                    id BIGINT NOT NULL,\
                    created_at DATE NOT NULL,\
                    PRIMARY KEY (id, created_at)\
                ) ENGINE=InnoDB PARTITION BY RANGE (YEAR(created_at)) (\
                    PARTITION p2025 VALUES LESS THAN (2026),\
                    PARTITION pmax VALUES LESS THAN MAXVALUE\
                )",
                quote_identifier(&names.events),
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "CREATE INDEX {} ON {} (email(24))",
                quote_identifier(&names.email_index),
                quote_identifier(&names.users),
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "CREATE VIEW {} AS SELECT id, email, status FROM {} WHERE status = 'active'",
                quote_identifier(&names.active_view),
                quote_identifier(&names.users),
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "CREATE VIEW {} AS SELECT o.id, u.email FROM {} o JOIN {} u ON u.id = o.user_id",
                quote_identifier(&names.order_view),
                quote_identifier(&names.orders),
                quote_identifier(&names.active_view),
            ))
            .unwrap();
        if maria_db {
            connection
                .query_drop(format!(
                    "CREATE SEQUENCE {} START WITH 10 INCREMENT BY 2 MINVALUE 10 MAXVALUE 1000 CYCLE",
                    quote_identifier(&names.sequence)
                ))
                .unwrap();
        }
    }

    fn drop_rich_fixture(connection: &mut Conn, names: &RichFixtureNames, maria_db: bool) {
        connection
            .query_drop(format!(
                "DROP VIEW IF EXISTS {}",
                quote_identifier(&names.order_view)
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "DROP VIEW IF EXISTS {}",
                quote_identifier(&names.active_view)
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "DROP TABLE IF EXISTS {}",
                quote_identifier(&names.orders)
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "DROP TABLE IF EXISTS {}",
                quote_identifier(&names.events)
            ))
            .unwrap();
        connection
            .query_drop(format!(
                "DROP TABLE IF EXISTS {}",
                quote_identifier(&names.users)
            ))
            .unwrap();
        if maria_db {
            connection
                .query_drop(format!(
                    "DROP SEQUENCE IF EXISTS {}",
                    quote_identifier(&names.sequence)
                ))
                .unwrap();
        }
    }
}
