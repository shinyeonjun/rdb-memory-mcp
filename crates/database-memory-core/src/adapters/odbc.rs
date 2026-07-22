use std::collections::BTreeSet;
use std::net::IpAddr;
#[cfg(feature = "odbc")]
use std::time::{Duration, Instant};

use connection_string::AdoNetString;
use serde::{Deserialize, Serialize};

use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::introspection::{CancellationToken, IntrospectionRequest};
use crate::redact::redact_connection_string;

const ODBC_SOURCE: &str = "odbc";
#[cfg(feature = "odbc")]
const ODBC_PROBE_CONTRACT_VERSION: u32 = 1;
const MAX_INTROSPECTION_TIMEOUT_MS: u64 = 86_400_000;
const MAX_SCOPE_VALUE_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdbcCapabilityReport {
    pub contract_version: u32,
    pub source_kind: String,
    pub connection_alias: String,
    pub driver: OdbcDriverIdentity,
    pub server: OdbcServerIdentity,
    pub current_catalog: Option<String>,
    pub metadata_functions_only: bool,
    pub read_only_access_mode: bool,
    pub data_source_read_only: bool,
    pub transaction_capability: OdbcTransactionCapability,
    pub catalog_functions: Vec<OdbcCatalogFunctionCapability>,
    pub completeness: OdbcCompletenessAssessment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdbcDriverIdentity {
    pub name: String,
    pub version: String,
    pub odbc_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdbcServerIdentity {
    pub product: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OdbcTransactionCapability {
    None,
    DmlOnly,
    DdlAndDml,
    DdlCommits,
    DdlIgnored,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OdbcCatalogFunction {
    Tables,
    Columns,
    Statistics,
    SpecialColumns,
    PrimaryKeys,
    ForeignKeys,
    TablePrivileges,
    ColumnPrivileges,
    Procedures,
    ProcedureColumns,
    TypeInfo,
}

impl OdbcCatalogFunction {
    pub const ALL: [Self; 11] = [
        Self::Tables,
        Self::Columns,
        Self::Statistics,
        Self::SpecialColumns,
        Self::PrimaryKeys,
        Self::ForeignKeys,
        Self::TablePrivileges,
        Self::ColumnPrivileges,
        Self::Procedures,
        Self::ProcedureColumns,
        Self::TypeInfo,
    ];

    #[cfg(feature = "odbc")]
    const fn function_id(self) -> u16 {
        match self {
            Self::Columns => 40,
            Self::TypeInfo => 47,
            Self::SpecialColumns => 52,
            Self::Statistics => 53,
            Self::Tables => 54,
            Self::ColumnPrivileges => 56,
            Self::ForeignKeys => 60,
            Self::PrimaryKeys => 65,
            Self::ProcedureColumns => 66,
            Self::Procedures => 67,
            Self::TablePrivileges => 70,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdbcCatalogFunctionCapability {
    pub function: OdbcCatalogFunction,
    pub support: OdbcCatalogFunctionSupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OdbcCatalogFunctionSupport {
    NotSupported,
    DriverDeclared,
    RuntimeCallVerified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OdbcCompletenessAssessment {
    Rejected { blockers: Vec<String> },
    Eligible { strategy: String },
}

pub const fn odbc_runtime_available() -> bool {
    cfg!(feature = "odbc")
}

pub fn probe_odbc_capabilities(
    connection_string: &str,
    connection_alias: &str,
    timeout_ms: u64,
) -> Result<OdbcCapabilityReport, AnalysisFailure> {
    probe_odbc_capabilities_with_cancellation(
        connection_string,
        connection_alias,
        timeout_ms,
        &CancellationToken::new(),
    )
}

pub fn probe_odbc_capabilities_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> Result<OdbcCapabilityReport, AnalysisFailure> {
    let request = IntrospectionRequest {
        connection_alias: connection_alias.to_owned(),
        requested_catalogs: Vec::new(),
        requested_schemas: Vec::new(),
        timeout_ms,
    };
    probe_request(connection_string, &request, cancellation)
}

pub fn introspect_odbc_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    introspect_odbc_complete_scoped(
        connection_string,
        connection_alias,
        Vec::new(),
        Vec::new(),
        30_000,
    )
}

pub fn introspect_odbc_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    introspect_odbc_complete_scoped_with_cancellation(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
        &CancellationToken::new(),
    )
}

pub fn introspect_odbc_complete_scoped_with_cancellation(
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
    #[cfg(feature = "odbc")]
    let started = Instant::now();
    let report = match probe_request(connection_string, &request, cancellation) {
        Ok(report) => report,
        Err(failure) => return AnalysisOutcome::failed(failure),
    };
    #[cfg(feature = "odbc")]
    {
        let Some(remaining) =
            Duration::from_millis(request.timeout_ms).checked_sub(started.elapsed())
        else {
            return AnalysisOutcome::failed(AnalysisFailure::redacted(
                AnalysisFailureCode::Timeout,
                AnalysisStage::CapabilityProbe,
                ODBC_SOURCE,
                &request.connection_alias,
                "ODBC capability negotiation exhausted the introspection deadline",
                "increase the bounded timeout or inspect driver and network latency",
                true,
                Some(connection_string),
            ));
        };
        let remaining_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        if remaining_ms == 0 {
            return AnalysisOutcome::failed(AnalysisFailure::redacted(
                AnalysisFailureCode::Timeout,
                AnalysisStage::CapabilityProbe,
                ODBC_SOURCE,
                &request.connection_alias,
                "ODBC capability negotiation left no time for authoritative discovery",
                "increase the bounded timeout or inspect driver and network latency",
                true,
                Some(connection_string),
            ));
        }
        let mut strategy_request = request.clone();
        strategy_request.timeout_ms = remaining_ms;
        if let Some(outcome) = runtime::analyze_with_registered_strategy(
            connection_string,
            &strategy_request,
            cancellation,
            &report,
        ) {
            return outcome;
        }
    }
    AnalysisOutcome::failed(AnalysisFailure::redacted(
        AnalysisFailureCode::UnsupportedProduct,
        AnalysisStage::CapabilityProbe,
        ODBC_SOURCE,
        &request.connection_alias,
        format!(
            "ODBC connected to {} {}, but no live-certified product strategy matches this source",
            report.server.product, report.server.version
        ),
        "use a certified native adapter or add a product-specific ODBC strategy with live completeness evidence",
        false,
        Some(connection_string),
    ))
}

fn probe_request(
    connection_string: &str,
    request: &IntrospectionRequest,
    cancellation: &CancellationToken,
) -> Result<OdbcCapabilityReport, AnalysisFailure> {
    validate_request(request, connection_string)?;
    cancellation.checkpoint(
        ODBC_SOURCE,
        &request.connection_alias,
        AnalysisStage::Configuration,
    )?;
    validate_connection_policy(request, connection_string)?;

    #[cfg(feature = "odbc")]
    {
        runtime::probe(connection_string, request, cancellation)
    }
    #[cfg(not(feature = "odbc"))]
    {
        let _ = cancellation;
        Err(AnalysisFailure::redacted(
            AnalysisFailureCode::DriverUnavailable,
            AnalysisStage::Configuration,
            ODBC_SOURCE,
            &request.connection_alias,
            "this database-memory build does not include the optional ODBC runtime",
            "build database-memory-core with the 'odbc' feature and install a matching 64-bit ODBC driver",
            false,
            Some(connection_string),
        ))
    }
}

fn validate_request(
    request: &IntrospectionRequest,
    connection_string: &str,
) -> Result<(), AnalysisFailure> {
    request.validate(ODBC_SOURCE)?;
    if request.connection_alias.len() > MAX_SCOPE_VALUE_BYTES
        || redact_connection_string(&request.connection_alias) != request.connection_alias
    {
        return Err(configuration_failure(
            request,
            connection_string,
            "ODBC connection alias must be a bounded non-secret label",
            "use a short logical alias that contains no credentials or connection string",
        ));
    }
    if request.timeout_ms > MAX_INTROSPECTION_TIMEOUT_MS {
        return Err(configuration_failure(
            request,
            connection_string,
            format!(
                "ODBC introspection timeout exceeds the {MAX_INTROSPECTION_TIMEOUT_MS} ms safety limit"
            ),
            "choose a timeout between 1 ms and 86400000 ms",
        ));
    }
    if connection_string.trim().is_empty() || connection_string.contains('\0') {
        return Err(configuration_failure(
            request,
            connection_string,
            "ODBC connection string must be non-empty and contain no NUL bytes",
            "provide a non-secret alias and a valid ODBC connection string",
        ));
    }
    if has_duplicates(&request.requested_catalogs) || has_duplicates(&request.requested_schemas) {
        return Err(configuration_failure(
            request,
            connection_string,
            "ODBC scope contains duplicate catalog or schema names",
            "provide each requested catalog and schema exactly once",
        ));
    }
    if request
        .requested_catalogs
        .iter()
        .chain(&request.requested_schemas)
        .any(|value| value.trim().is_empty() || value.len() > MAX_SCOPE_VALUE_BYTES)
    {
        return Err(configuration_failure(
            request,
            connection_string,
            "ODBC scope values must be non-empty and at most 1024 bytes",
            "provide bounded exact catalog and schema names",
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
        configuration_failure(
            request,
            connection_string,
            format!("invalid ODBC connection string: {error}"),
            "use a driver connection string with explicit Driver, Server, and database settings",
        )
    })?;
    let driver = connection_value(&values, &["driver"]);
    let dsn = connection_value(&values, &["dsn"]);
    if driver.is_none() && dsn.is_none() {
        return Err(configuration_failure(
            request,
            connection_string,
            "ODBC connection string must identify an installed Driver",
            "set Driver explicitly; opaque DSN-only sources are not accepted by the generic path",
        ));
    }
    if dsn.is_some() {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Configuration,
            ODBC_SOURCE,
            &request.connection_alias,
            "generic ODBC analysis cannot verify the endpoint and transport policy hidden inside a DSN",
            "use an explicit driver connection string or a product adapter that validates the DSN policy",
            false,
            Some(connection_string),
        ));
    }

    let endpoint = connection_value(
        &values,
        &[
            "server",
            "host",
            "hostname",
            "address",
            "addr",
            "network address",
        ],
    )
    .ok_or_else(|| {
        configuration_failure(
            request,
            connection_string,
            "generic ODBC analysis requires an explicit server endpoint",
            "set Server or Host explicitly so local-versus-remote transport can be verified",
        )
    })?;
    let host = endpoint_host(endpoint);
    if !is_loopback_host(host) && !has_verified_remote_transport(&values) {
        return Err(AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Configuration,
            ODBC_SOURCE,
            &request.connection_alias,
            "remote ODBC sources require an explicit encrypted transport with certificate verification",
            "enable verified TLS in the driver connection string and disable trust-server-certificate bypasses",
            false,
            Some(connection_string),
        ));
    }
    Ok(())
}

fn connection_value<'a>(values: &'a AdoNetString, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| values.get(*key))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn endpoint_host(endpoint: &str) -> &str {
    let endpoint = endpoint
        .trim()
        .strip_prefix("tcp:")
        .unwrap_or(endpoint.trim());
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    let host = endpoint
        .split_once(['\\', ','])
        .map_or(endpoint, |(host, _)| host);
    host.split_once(':').map_or(host, |(host, _)| host).trim()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "."
        || host.eq_ignore_ascii_case("(local)")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn has_verified_remote_transport(values: &AdoNetString) -> bool {
    if connection_flag(
        values,
        &["trustservercertificate", "trust server certificate"],
    ) == Some(true)
    {
        return false;
    }
    let encrypt = connection_value(values, &["encrypt"])
        .map(|value| value.to_ascii_lowercase())
        .is_some_and(|value| matches!(value.as_str(), "yes" | "true" | "mandatory" | "strict"));
    let ssl_mode = connection_value(values, &["sslmode", "ssl mode", "ssl-mode"])
        .map(|value| value.replace('-', "_").to_ascii_lowercase())
        .is_some_and(|value| {
            matches!(
                value.as_str(),
                "verify_ca" | "verify_full" | "verify_identity"
            )
        });
    let explicit_verify = connection_flag(values, &["ssl", "use ssl"]) == Some(true)
        && connection_flag(values, &["sslverify", "verify server certificate"]) == Some(true);
    encrypt || ssl_mode || explicit_verify
}

fn connection_flag(values: &AdoNetString, keys: &[&str]) -> Option<bool> {
    connection_value(values, keys).and_then(|value| {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" | "on" => Some(true),
            "false" | "no" | "0" | "off" => Some(false),
            _ => None,
        }
    })
}

fn configuration_failure(
    request: &IntrospectionRequest,
    connection_string: &str,
    message: impl AsRef<str>,
    remediation: impl AsRef<str>,
) -> AnalysisFailure {
    AnalysisFailure::redacted(
        AnalysisFailureCode::InvalidConfiguration,
        AnalysisStage::Configuration,
        ODBC_SOURCE,
        &request.connection_alias,
        message,
        remediation,
        false,
        Some(connection_string),
    )
}

#[cfg(any(feature = "odbc", test))]
fn rejected_assessment(
    functions: &[OdbcCatalogFunctionCapability],
    strategy: Option<&str>,
) -> OdbcCompletenessAssessment {
    let mut blockers = functions
        .iter()
        .filter(|capability| capability.support == OdbcCatalogFunctionSupport::NotSupported)
        .map(|capability| {
            format!(
                "driver does not declare support for {:?}",
                capability.function
            )
        })
        .collect::<Vec<_>>();
    blockers.push(match strategy {
        Some(strategy) => format!(
            "ODBC strategy '{strategy}' cannot run because its required catalog functions are unavailable"
        ),
        None => "no live-certified product strategy is registered for this ODBC identity".to_owned(),
    });
    blockers.extend([
        "ODBC catalog functions do not prove unique and check constraint semantics".to_owned(),
        "ODBC catalog functions do not expose a complete trigger inventory".to_owned(),
        "ODBC catalog functions do not expose complete cross-object dependencies".to_owned(),
        "driver-declared function support is not completeness evidence without live reconciliation"
            .to_owned(),
    ]);
    blockers.sort();
    blockers.dedup();
    OdbcCompletenessAssessment::Rejected { blockers }
}

#[cfg(feature = "odbc")]
mod runtime {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::null_mut;
    use std::time::{Duration, Instant};

    use odbc_api::handles::{
        slice_to_utf8, Connection, Diagnostics, Environment, Record, SqlResult, SqlText, Statement,
    };
    use odbc_api::sys::{
        AttrOdbcVersion, ConnectionAttribute, HDbc, InfoType, Pointer, SQLGetConnectAttr,
        SQLGetInfo, SQLGetInfoW, SQLSetConnectAttr, SqlReturn, IS_UINTEGER,
    };
    use odbc_api::{Error, Preallocated};

    use super::*;

    const INFO_BUFFER_UNITS: usize = 1_024;
    const SQL_MODE_READ_ONLY: usize = 1;
    const CATALOG_PROBE_SENTINEL: &str = "__database_memory_odbc_capability_probe__";
    const SQLSERVER_BRIDGE_STRATEGY: &str = "sqlserver-native-bridge-v1";
    const SQLSERVER_REQUIRED_FUNCTIONS: [OdbcCatalogFunction; 4] = [
        OdbcCatalogFunction::Tables,
        OdbcCatalogFunction::Columns,
        OdbcCatalogFunction::PrimaryKeys,
        OdbcCatalogFunction::ForeignKeys,
    ];

    trait OdbcProductStrategy: Sync {
        fn id(&self) -> &'static str;
        fn matches(&self, driver: &OdbcDriverIdentity, server: &OdbcServerIdentity) -> bool;
        fn required_functions(&self) -> &'static [OdbcCatalogFunction];
        fn analyze(
            &self,
            connection_string: &str,
            request: &IntrospectionRequest,
            cancellation: &CancellationToken,
        ) -> AnalysisOutcome;
    }

    struct SqlServerOdbcStrategy;

    impl OdbcProductStrategy for SqlServerOdbcStrategy {
        fn id(&self) -> &'static str {
            SQLSERVER_BRIDGE_STRATEGY
        }

        fn matches(&self, _driver: &OdbcDriverIdentity, server: &OdbcServerIdentity) -> bool {
            server
                .product
                .trim()
                .eq_ignore_ascii_case("Microsoft SQL Server")
        }

        fn required_functions(&self) -> &'static [OdbcCatalogFunction] {
            &SQLSERVER_REQUIRED_FUNCTIONS
        }

        fn analyze(
            &self,
            connection_string: &str,
            request: &IntrospectionRequest,
            cancellation: &CancellationToken,
        ) -> AnalysisOutcome {
            let connection_string =
                match sqlserver_native_connection_string(connection_string, request) {
                    Ok(connection_string) => connection_string,
                    Err(failure) => return AnalysisOutcome::failed(failure),
                };
            crate::adapters::sqlserver_catalog::analyze_sqlserver_with_cancellation(
                &connection_string,
                &request.connection_alias,
                request.requested_catalogs.clone(),
                request.requested_schemas.clone(),
                request.timeout_ms,
                cancellation,
            )
        }
    }

    static SQLSERVER_ODBC_STRATEGY: SqlServerOdbcStrategy = SqlServerOdbcStrategy;
    static BUILTIN_ODBC_STRATEGIES: [&dyn OdbcProductStrategy; 1] = [&SQLSERVER_ODBC_STRATEGY];

    extern "system" {
        #[link_name = "SQLGetFunctions"]
        fn sql_get_functions(
            connection_handle: HDbc,
            function_id: u16,
            supported: *mut u16,
        ) -> SqlReturn;
    }

    pub(super) fn probe(
        connection_string: &str,
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
    ) -> Result<OdbcCapabilityReport, AnalysisFailure> {
        let deadline = Deadline::new(request.timeout_ms);
        checkpoint(request, cancellation, &deadline, AnalysisStage::Connection)?;
        let environment = allocate_environment().map_err(|error| {
            classify_error(request, connection_string, error, AnalysisStage::Connection)
        })?;
        environment
            .declare_version(AttrOdbcVersion::Odbc3_80)
            .into_result(&environment)
            .map_err(OdbcCallError::from)
            .map_err(|error| {
                classify_error(request, connection_string, error, AnalysisStage::Connection)
            })?;
        let mut connection = environment
            .allocate_connection()
            .into_result(&environment)
            .map_err(OdbcCallError::from)
            .map_err(|error| {
                classify_error(request, connection_string, error, AnalysisStage::Connection)
            })?;
        set_read_only_access(&connection).map_err(|error| {
            unsafe_source_failure(request, connection_string, error.to_string())
        })?;
        connection
            .set_login_timeout_sec(deadline.remaining_seconds(request, AnalysisStage::Connection)?)
            .into_result(&connection)
            .map_err(OdbcCallError::from)
            .map_err(|error| {
                classify_error(request, connection_string, error, AnalysisStage::Connection)
            })?;
        connection
            .connect_with_connection_string(&SqlText::new(connection_string))
            .into_result(&connection)
            .map_err(OdbcCallError::from)
            .map_err(|error| {
                classify_error(request, connection_string, error, AnalysisStage::Connection)
            })?;
        let session = OdbcSession::new(connection);
        checkpoint(
            request,
            cancellation,
            &deadline,
            AnalysisStage::CapabilityProbe,
        )?;
        verify_read_only_access(session.connection()).map_err(|error| {
            unsafe_source_failure(request, connection_string, error.to_string())
        })?;

        let driver = OdbcDriverIdentity {
            name: info_string(session.connection(), InfoType::DriverName).map_err(|error| {
                classify_error(
                    request,
                    connection_string,
                    error,
                    AnalysisStage::CapabilityProbe,
                )
            })?,
            version: info_string(session.connection(), InfoType::DriverVer).map_err(|error| {
                classify_error(
                    request,
                    connection_string,
                    error,
                    AnalysisStage::CapabilityProbe,
                )
            })?,
            odbc_version: info_string(session.connection(), InfoType::DriverOdbcVer).map_err(
                |error| {
                    classify_error(
                        request,
                        connection_string,
                        error,
                        AnalysisStage::CapabilityProbe,
                    )
                },
            )?,
        };
        let server = OdbcServerIdentity {
            product: info_string(session.connection(), InfoType::DbmsName).map_err(|error| {
                classify_error(
                    request,
                    connection_string,
                    error,
                    AnalysisStage::CapabilityProbe,
                )
            })?,
            version: info_string(session.connection(), InfoType::DbmsVer).map_err(|error| {
                classify_error(
                    request,
                    connection_string,
                    error,
                    AnalysisStage::CapabilityProbe,
                )
            })?,
        };
        let data_source_read_only =
            match info_string(session.connection(), InfoType::DataSourceReadOnly)
                .map_err(|error| {
                    classify_error(
                        request,
                        connection_string,
                        error,
                        AnalysisStage::CapabilityProbe,
                    )
                })?
                .trim()
                .to_ascii_uppercase()
                .as_str()
            {
                "Y" => true,
                "N" => false,
                value => {
                    return Err(metadata_failure(
                        request,
                        connection_string,
                        format!(
                        "ODBC driver returned invalid SQL_DATA_SOURCE_READ_ONLY value '{value}'"
                    ),
                    ));
                }
            };
        let transaction_capability =
            transaction_capability(session.connection()).map_err(|error| {
                classify_error(
                    request,
                    connection_string,
                    error,
                    AnalysisStage::CapabilityProbe,
                )
            })?;
        let current_catalog = current_catalog(session.connection()).map_err(|error| {
            classify_error(
                request,
                connection_string,
                error,
                AnalysisStage::CapabilityProbe,
            )
        })?;
        validate_scope(request, current_catalog.as_deref(), connection_string)?;

        let mut catalog_functions = Vec::with_capacity(OdbcCatalogFunction::ALL.len());
        for function in OdbcCatalogFunction::ALL {
            checkpoint(
                request,
                cancellation,
                &deadline,
                AnalysisStage::CapabilityProbe,
            )?;
            let declared_supported =
                function_supported(session.connection(), function).map_err(|error| {
                    classify_error(
                        request,
                        connection_string,
                        error,
                        AnalysisStage::CapabilityProbe,
                    )
                })?;
            let support = if !declared_supported {
                OdbcCatalogFunctionSupport::NotSupported
            } else if runtime_verifiable(function) {
                verify_catalog_function_call(
                    session.connection(),
                    function,
                    current_catalog.as_deref(),
                    request.requested_schemas.first().map(String::as_str),
                    deadline.remaining_seconds(request, AnalysisStage::CapabilityProbe)?,
                )
                .map_err(|error| {
                    classify_error(
                        request,
                        connection_string,
                        error,
                        AnalysisStage::CapabilityProbe,
                    )
                })?;
                OdbcCatalogFunctionSupport::RuntimeCallVerified
            } else {
                OdbcCatalogFunctionSupport::DriverDeclared
            };
            catalog_functions.push(OdbcCatalogFunctionCapability { function, support });
        }
        checkpoint(
            request,
            cancellation,
            &deadline,
            AnalysisStage::CapabilityProbe,
        )?;
        session.disconnect().map_err(|error| {
            classify_error(request, connection_string, error, AnalysisStage::Connection)
        })?;

        let completeness = completeness_assessment(&driver, &server, &catalog_functions);
        Ok(OdbcCapabilityReport {
            contract_version: ODBC_PROBE_CONTRACT_VERSION,
            source_kind: ODBC_SOURCE.to_owned(),
            connection_alias: request.connection_alias.clone(),
            driver,
            server,
            current_catalog,
            metadata_functions_only: true,
            read_only_access_mode: true,
            data_source_read_only,
            transaction_capability,
            catalog_functions,
            completeness,
        })
    }

    pub(super) fn analyze_with_registered_strategy(
        connection_string: &str,
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
        report: &OdbcCapabilityReport,
    ) -> Option<AnalysisOutcome> {
        let strategy = strategy_for(&report.driver, &report.server)?;
        let OdbcCompletenessAssessment::Eligible { strategy: eligible } = &report.completeness
        else {
            return None;
        };
        (eligible == strategy.id())
            .then(|| strategy.analyze(connection_string, request, cancellation))
    }

    pub(super) fn completeness_assessment(
        driver: &OdbcDriverIdentity,
        server: &OdbcServerIdentity,
        functions: &[OdbcCatalogFunctionCapability],
    ) -> OdbcCompletenessAssessment {
        let Some(strategy) = strategy_for(driver, server) else {
            return rejected_assessment(functions, None);
        };
        let requirements_met = strategy.required_functions().iter().all(|required| {
            functions.iter().any(|capability| {
                capability.function == *required
                    && if runtime_verifiable(*required) {
                        capability.support == OdbcCatalogFunctionSupport::RuntimeCallVerified
                    } else {
                        capability.support != OdbcCatalogFunctionSupport::NotSupported
                    }
            })
        });
        if requirements_met {
            OdbcCompletenessAssessment::Eligible {
                strategy: strategy.id().to_owned(),
            }
        } else {
            rejected_assessment(functions, Some(strategy.id()))
        }
    }

    fn strategy_for(
        driver: &OdbcDriverIdentity,
        server: &OdbcServerIdentity,
    ) -> Option<&'static dyn OdbcProductStrategy> {
        BUILTIN_ODBC_STRATEGIES
            .iter()
            .copied()
            .find(|strategy| strategy.matches(driver, server))
    }

    pub(super) fn sqlserver_native_connection_string(
        connection_string: &str,
        request: &IntrospectionRequest,
    ) -> Result<String, AnalysisFailure> {
        let mut values = connection_string.parse::<AdoNetString>().map_err(|error| {
            configuration_failure(
                request,
                connection_string,
                format!("cannot translate ODBC settings for SQL Server: {error}"),
                "use an explicit SQL Server ODBC driver connection string",
            )
        })?;

        values.remove("driver");
        values.remove("dsn");
        move_connection_value(
            &mut values,
            &["host", "hostname", "address", "addr", "network address"],
            "server",
        );
        move_connection_value(
            &mut values,
            &["trust server certificate"],
            "trustservercertificate",
        );
        move_connection_value(
            &mut values,
            &["trusted_connection", "trusted connection"],
            "integrated security",
        );

        if connection_value(&values, &["server"]).is_none() {
            return Err(configuration_failure(
                request,
                connection_string,
                "SQL Server ODBC bridge requires an explicit server endpoint",
                "set Server explicitly in the ODBC connection string",
            ));
        }
        if connection_value(&values, &["database", "initial catalog", "databasename"]).is_none() {
            return Err(configuration_failure(
                request,
                connection_string,
                "SQL Server ODBC bridge requires one explicit database",
                "set Database or Initial Catalog explicitly",
            ));
        }
        Ok(values.to_string())
    }

    fn move_connection_value(values: &mut AdoNetString, aliases: &[&str], canonical: &str) {
        if values.contains_key(canonical) {
            for alias in aliases {
                values.remove(*alias);
            }
            return;
        }
        if let Some(value) = aliases.iter().find_map(|alias| values.remove(*alias)) {
            values.insert(canonical.to_owned(), value);
        }
        for alias in aliases {
            values.remove(*alias);
        }
    }

    fn allocate_environment() -> Result<Environment, OdbcCallError> {
        match Environment::new() {
            SqlResult::Success(environment) => Ok(environment),
            SqlResult::SuccessWithInfo(_) => Err(OdbcCallError::new(
                None,
                "ODBC environment allocation returned an uninspectable warning",
            )),
            SqlResult::Error { function } => Err(OdbcCallError::new(
                None,
                format!("ODBC call '{function}' failed before diagnostics were available"),
            )),
            unexpected => Err(OdbcCallError::new(
                None,
                format!("ODBC environment allocation returned {unexpected:?}"),
            )),
        }
    }

    struct OdbcSession<'environment> {
        connection: Option<Connection<'environment>>,
    }

    impl<'environment> OdbcSession<'environment> {
        fn new(connection: Connection<'environment>) -> Self {
            Self {
                connection: Some(connection),
            }
        }

        fn connection(&self) -> &Connection<'environment> {
            self.connection.as_ref().expect("ODBC session is connected")
        }

        fn disconnect(mut self) -> Result<(), OdbcCallError> {
            disconnect_connection(self.connection.take().expect("ODBC session is connected"))
        }
    }

    impl Drop for OdbcSession<'_> {
        fn drop(&mut self) {
            if let Some(connection) = self.connection.take() {
                let _ = disconnect_connection(connection);
            }
        }
    }

    fn disconnect_connection(mut connection: Connection<'_>) -> Result<(), OdbcCallError> {
        match connection.disconnect().into_result(&connection) {
            Ok(()) => Ok(()),
            Err(first_error) => {
                let _ = connection.rollback();
                match connection.disconnect().into_result(&connection) {
                    Ok(()) => Err(OdbcCallError::from(first_error)),
                    Err(second_error) => {
                        std::mem::forget(connection);
                        Err(OdbcCallError::new(
                            diagnostic_state(&second_error),
                            format!("ODBC disconnect failed after rollback: {second_error}"),
                        ))
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Deadline {
        expires_at: Instant,
    }

    impl Deadline {
        fn new(timeout_ms: u64) -> Self {
            Self {
                expires_at: Instant::now() + Duration::from_millis(timeout_ms),
            }
        }

        fn remaining_seconds(
            self,
            request: &IntrospectionRequest,
            stage: AnalysisStage,
        ) -> Result<u32, AnalysisFailure> {
            let remaining = self.expires_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout_failure(request, stage));
            }
            let rounded_up = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() > 0));
            Ok(rounded_up.clamp(1, u32::MAX as u64) as u32)
        }
    }

    fn checkpoint(
        request: &IntrospectionRequest,
        cancellation: &CancellationToken,
        deadline: &Deadline,
        stage: AnalysisStage,
    ) -> Result<(), AnalysisFailure> {
        cancellation.checkpoint(ODBC_SOURCE, &request.connection_alias, stage)?;
        deadline.remaining_seconds(request, stage).map(|_| ())
    }

    fn timeout_failure(request: &IntrospectionRequest, stage: AnalysisStage) -> AnalysisFailure {
        AnalysisFailure::redacted(
            AnalysisFailureCode::Timeout,
            stage,
            ODBC_SOURCE,
            &request.connection_alias,
            format!(
                "ODBC metadata analysis exceeded the {} ms timeout",
                request.timeout_ms
            ),
            "increase the bounded timeout or reduce the requested metadata scope",
            true,
            None,
        )
    }

    fn set_read_only_access(connection: &Connection<'_>) -> Result<(), OdbcCallError> {
        let result = unsafe {
            SQLSetConnectAttr(
                connection.as_sys(),
                ConnectionAttribute::ACCESS_MODE,
                SQL_MODE_READ_ONLY as Pointer,
                IS_UINTEGER,
            )
        };
        require_clean_success(
            connection,
            result,
            "SQLSetConnectAttr(SQL_ATTR_ACCESS_MODE)",
        )
    }

    fn verify_read_only_access(connection: &Connection<'_>) -> Result<(), OdbcCallError> {
        let mut access_mode = 0u32;
        let result = unsafe {
            SQLGetConnectAttr(
                connection.as_sys(),
                ConnectionAttribute::ACCESS_MODE,
                &mut access_mode as *mut u32 as *mut c_void,
                IS_UINTEGER,
                null_mut(),
            )
        };
        require_clean_success(
            connection,
            result,
            "SQLGetConnectAttr(SQL_ATTR_ACCESS_MODE)",
        )?;
        if access_mode as usize != SQL_MODE_READ_ONLY {
            return Err(OdbcCallError::new(
                None,
                format!("ODBC driver reported access mode {access_mode} instead of read-only"),
            ));
        }
        Ok(())
    }

    fn function_supported(
        connection: &Connection<'_>,
        function: OdbcCatalogFunction,
    ) -> Result<bool, OdbcCallError> {
        let mut supported = 0u16;
        let result = unsafe {
            sql_get_functions(connection.as_sys(), function.function_id(), &mut supported)
        };
        require_clean_success(connection, result, "SQLGetFunctions")?;
        match supported {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(OdbcCallError::new(
                None,
                format!("ODBC driver returned invalid SQLGetFunctions value {value}"),
            )),
        }
    }

    fn runtime_verifiable(function: OdbcCatalogFunction) -> bool {
        matches!(
            function,
            OdbcCatalogFunction::Tables
                | OdbcCatalogFunction::Columns
                | OdbcCatalogFunction::PrimaryKeys
                | OdbcCatalogFunction::ForeignKeys
        )
    }

    fn verify_catalog_function_call(
        connection: &Connection<'_>,
        function: OdbcCatalogFunction,
        catalog: Option<&str>,
        schema: Option<&str>,
        timeout_seconds: u32,
    ) -> Result<(), OdbcCallError> {
        let mut statement = connection
            .allocate_statement()
            .into_result(connection)
            .map_err(OdbcCallError::from)?;
        statement
            .set_query_timeout_sec(timeout_seconds as usize)
            .into_result(&statement)
            .map_err(OdbcCallError::from)?;
        let actual_timeout = statement
            .query_timeout_sec()
            .into_result(&statement)
            .map_err(OdbcCallError::from)?;
        if actual_timeout == 0 || actual_timeout > timeout_seconds as usize {
            return Err(OdbcCallError::new(
                None,
                format!(
                    "ODBC driver reported unsafe query timeout {actual_timeout}s for a {timeout_seconds}s deadline"
                ),
            ));
        }
        let mut statement = unsafe { Preallocated::new(statement) };
        let catalog = catalog.unwrap_or("");
        let schema = schema.unwrap_or("");
        match function {
            OdbcCatalogFunction::Tables => {
                let mut rows = statement
                    .tables(catalog, schema, CATALOG_PROBE_SENTINEL, "")
                    .map_err(OdbcCallError::from)?;
                if let Some(row) = rows.next() {
                    row.map_err(OdbcCallError::from)?;
                }
            }
            OdbcCatalogFunction::Columns => {
                let mut rows = statement
                    .columns(
                        catalog,
                        schema,
                        CATALOG_PROBE_SENTINEL,
                        CATALOG_PROBE_SENTINEL,
                    )
                    .map_err(OdbcCallError::from)?;
                if let Some(row) = rows.next() {
                    row.map_err(OdbcCallError::from)?;
                }
            }
            OdbcCatalogFunction::PrimaryKeys => {
                let mut rows = statement
                    .primary_keys(
                        (!catalog.is_empty()).then_some(catalog),
                        (!schema.is_empty()).then_some(schema),
                        CATALOG_PROBE_SENTINEL,
                    )
                    .map_err(OdbcCallError::from)?;
                if let Some(row) = rows.next() {
                    row.map_err(OdbcCallError::from)?;
                }
            }
            OdbcCatalogFunction::ForeignKeys => {
                let mut rows = statement
                    .foreign_keys("", "", "", catalog, schema, CATALOG_PROBE_SENTINEL)
                    .map_err(OdbcCallError::from)?;
                if let Some(row) = rows.next() {
                    row.map_err(OdbcCallError::from)?;
                }
            }
            _ => {
                return Err(OdbcCallError::new(
                    None,
                    "ODBC catalog function has no runtime verifier",
                ));
            }
        }
        Ok(())
    }

    fn transaction_capability(
        connection: &Connection<'_>,
    ) -> Result<OdbcTransactionCapability, OdbcCallError> {
        match info_u16(connection, InfoType::TransactionCapable)? {
            0 => Ok(OdbcTransactionCapability::None),
            1 => Ok(OdbcTransactionCapability::DmlOnly),
            2 => Ok(OdbcTransactionCapability::DdlAndDml),
            3 => Ok(OdbcTransactionCapability::DdlCommits),
            4 => Ok(OdbcTransactionCapability::DdlIgnored),
            value => Err(OdbcCallError::new(
                None,
                format!("ODBC driver returned invalid transaction capability {value}"),
            )),
        }
    }

    fn info_u16(connection: &Connection<'_>, info_type: InfoType) -> Result<u16, OdbcCallError> {
        let mut value = 0u16;
        let result = unsafe {
            SQLGetInfo(
                connection.as_sys(),
                info_type,
                &mut value as *mut u16 as Pointer,
                size_of::<u16>() as i16,
                null_mut(),
            )
        };
        require_clean_success(connection, result, "SQLGetInfo")?;
        Ok(value)
    }

    #[cfg(target_os = "windows")]
    fn info_string(
        connection: &Connection<'_>,
        info_type: InfoType,
    ) -> Result<String, OdbcCallError> {
        let mut buffer = vec![0u16; INFO_BUFFER_UNITS];
        let mut length_bytes = 0i16;
        let result = unsafe {
            SQLGetInfoW(
                connection.as_sys(),
                info_type,
                buffer.as_mut_ptr() as Pointer,
                (buffer.len() * size_of::<u16>()) as i16,
                &mut length_bytes,
            )
        };
        require_clean_success(connection, result, "SQLGetInfoW")?;
        if length_bytes < 0
            || length_bytes as usize >= buffer.len() * size_of::<u16>()
            || !(length_bytes as usize).is_multiple_of(size_of::<u16>())
        {
            return Err(OdbcCallError::new(
                None,
                "ODBC driver returned an invalid or truncated SQLGetInfoW string",
            ));
        }
        let units = length_bytes as usize / size_of::<u16>();
        let value = String::from_utf16(&buffer[..units]).map_err(|error| {
            OdbcCallError::new(None, format!("ODBC identity is not valid UTF-16: {error}"))
        })?;
        non_empty_identity(value)
    }

    #[cfg(not(target_os = "windows"))]
    fn info_string(
        connection: &Connection<'_>,
        info_type: InfoType,
    ) -> Result<String, OdbcCallError> {
        let mut buffer = vec![0u8; INFO_BUFFER_UNITS];
        let mut length_bytes = 0i16;
        let result = unsafe {
            SQLGetInfo(
                connection.as_sys(),
                info_type,
                buffer.as_mut_ptr() as Pointer,
                buffer.len() as i16,
                &mut length_bytes,
            )
        };
        require_clean_success(connection, result, "SQLGetInfo")?;
        if length_bytes < 0 || length_bytes as usize >= buffer.len() {
            return Err(OdbcCallError::new(
                None,
                "ODBC driver returned an invalid or truncated SQLGetInfo string",
            ));
        }
        let value =
            String::from_utf8(buffer[..length_bytes as usize].to_vec()).map_err(|error| {
                OdbcCallError::new(None, format!("ODBC identity is not valid UTF-8: {error}"))
            })?;
        non_empty_identity(value)
    }

    fn non_empty_identity(value: String) -> Result<String, OdbcCallError> {
        let value = value.trim().to_owned();
        if value.is_empty() {
            Err(OdbcCallError::new(
                None,
                "ODBC driver returned an empty identity field",
            ))
        } else {
            Ok(value)
        }
    }

    fn current_catalog(connection: &Connection<'_>) -> Result<Option<String>, OdbcCallError> {
        let mut buffer = Vec::new();
        match connection
            .fetch_current_catalog(&mut buffer)
            .into_result(connection)
        {
            Ok(()) => {
                let value = slice_to_utf8(&buffer)
                    .map_err(|error| {
                        OdbcCallError::new(
                            None,
                            format!("ODBC current catalog is not valid text: {error}"),
                        )
                    })?
                    .trim()
                    .to_owned();
                if value.len() > MAX_SCOPE_VALUE_BYTES {
                    return Err(OdbcCallError::new(
                        None,
                        "ODBC current catalog exceeds the 1024-byte contract limit",
                    ));
                }
                Ok((!value.is_empty()).then_some(value))
            }
            Err(error) if is_unsupported_error(&error) => Ok(None),
            Err(error) => Err(OdbcCallError::from(error)),
        }
    }

    fn validate_scope(
        request: &IntrospectionRequest,
        current_catalog: Option<&str>,
        connection_string: &str,
    ) -> Result<(), AnalysisFailure> {
        if request.requested_catalogs.is_empty() {
            return Ok(());
        }
        if current_catalog.is_some_and(|catalog| request.requested_catalogs == [catalog]) {
            return Ok(());
        }
        Err(configuration_failure(
            request,
            connection_string,
            format!(
                "generic ODBC analysis is bound to current catalog '{}'; requested catalogs were {}",
                current_catalog.unwrap_or("<not reported>"),
                request.requested_catalogs.join(", ")
            ),
            "connect directly to one catalog and request only that exact catalog",
        ))
    }

    fn require_clean_success(
        handle: &impl Diagnostics,
        result: SqlReturn,
        function: &'static str,
    ) -> Result<(), OdbcCallError> {
        match result {
            SqlReturn::SUCCESS => Ok(()),
            SqlReturn::SUCCESS_WITH_INFO => Err(diagnostic_error(
                handle,
                format!("{function} returned a warning; strict capability proof rejects substituted values"),
            )),
            other => Err(diagnostic_error(
                handle,
                format!("{function} failed with return code {}", other.0),
            )),
        }
    }

    fn diagnostic_error(handle: &impl Diagnostics, fallback: impl Into<String>) -> OdbcCallError {
        let mut record = Record::with_capacity(512);
        if record.fill_from(handle, 1) {
            OdbcCallError::new(Some(record.state.as_str().to_owned()), record.to_string())
        } else {
            OdbcCallError::new(None, fallback)
        }
    }

    #[derive(Debug)]
    struct OdbcCallError {
        state: Option<String>,
        message: String,
    }

    impl OdbcCallError {
        fn new(state: Option<String>, message: impl Into<String>) -> Self {
            Self {
                state,
                message: message.into(),
            }
        }
    }

    impl std::fmt::Display for OdbcCallError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl From<Error> for OdbcCallError {
        fn from(error: Error) -> Self {
            Self::new(diagnostic_state(&error), error.to_string())
        }
    }

    fn diagnostic_state(error: &Error) -> Option<String> {
        match error {
            Error::Diagnostics { record, .. } => Some(record.state.as_str().to_owned()),
            _ => None,
        }
    }

    fn is_unsupported_error(error: &Error) -> bool {
        diagnostic_state(error).is_some_and(|state| matches!(state.as_str(), "HYC00" | "IM001"))
    }

    fn classify_error(
        request: &IntrospectionRequest,
        connection_string: &str,
        error: OdbcCallError,
        stage: AnalysisStage,
    ) -> AnalysisFailure {
        let state = error.state.as_deref().unwrap_or("");
        let (code, retryable, remediation) = match state {
            "28000" => (
                AnalysisFailureCode::AuthenticationFailed,
                false,
                "verify the ODBC principal and secret",
            ),
            "IM002" | "IM003" | "IM004" | "IM005" | "IM006" | "IM014" => (
                AnalysisFailureCode::DriverUnavailable,
                false,
                "install and select a matching ODBC driver with the same process architecture",
            ),
            "HYT00" | "HYT01" | "S1T00" => (
                AnalysisFailureCode::Timeout,
                true,
                "increase the bounded timeout or reduce the metadata scope",
            ),
            "HY008" => (
                AnalysisFailureCode::Cancelled,
                true,
                "start a new analysis when the result is still needed",
            ),
            "42501" => (
                AnalysisFailureCode::PermissionDenied,
                false,
                "grant metadata visibility for every requested catalog and schema",
            ),
            "HYC00" | "IM001" => (
                AnalysisFailureCode::UnsupportedMetadata,
                false,
                "use a driver that implements the required ODBC metadata capability",
            ),
            value if value.starts_with("08") => (
                AnalysisFailureCode::ConnectionFailed,
                true,
                "verify the ODBC endpoint, network path, and TLS policy",
            ),
            _ if stage == AnalysisStage::Connection => (
                AnalysisFailureCode::ConnectionFailed,
                true,
                "verify the ODBC driver, endpoint, credentials, and transport policy",
            ),
            _ => (
                AnalysisFailureCode::MetadataQueryFailed,
                true,
                "inspect the ODBC driver diagnostics and retry the metadata-only probe",
            ),
        };
        AnalysisFailure::redacted(
            code,
            stage,
            ODBC_SOURCE,
            &request.connection_alias,
            error.to_string(),
            remediation,
            retryable,
            Some(connection_string),
        )
    }

    fn unsafe_source_failure(
        request: &IntrospectionRequest,
        connection_string: &str,
        message: impl AsRef<str>,
    ) -> AnalysisFailure {
        AnalysisFailure::redacted(
            AnalysisFailureCode::UnsafeSource,
            AnalysisStage::Connection,
            ODBC_SOURCE,
            &request.connection_alias,
            message,
            "use an ODBC driver that accepts and reports SQL_MODE_READ_ONLY for metadata analysis",
            false,
            Some(connection_string),
        )
    }

    fn metadata_failure(
        request: &IntrospectionRequest,
        connection_string: &str,
        message: impl AsRef<str>,
    ) -> AnalysisFailure {
        AnalysisFailure::redacted(
            AnalysisFailureCode::UnsupportedMetadata,
            AnalysisStage::CapabilityProbe,
            ODBC_SOURCE,
            &request.connection_alias,
            message,
            "use a conforming ODBC driver or a certified native adapter",
            false,
            Some(connection_string),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_outcome::AnalysisStatus;

    const LOCAL_SQLSERVER: &str = "Driver={ODBC Driver 17 for SQL Server};Server=127.0.0.1,11433;Database=master;UID=sa;PWD={Password123!};Encrypt=no";

    #[test]
    fn runtime_availability_matches_the_build_feature() {
        assert_eq!(odbc_runtime_available(), cfg!(feature = "odbc"));
    }

    #[test]
    fn connection_policy_rejects_opaque_or_unverified_remote_sources() {
        let request = request();
        let dsn =
            validate_connection_policy(&request, "DSN=production;UID=app;PWD=secret").unwrap_err();
        assert_eq!(dsn.code, AnalysisFailureCode::UnsafeSource);
        assert!(!dsn.message.contains("secret"));

        let remote = validate_connection_policy(
            &request,
            "Driver={ODBC Driver 17 for SQL Server};Server=db.example;UID=app;PWD=secret;Encrypt=no",
        )
        .unwrap_err();
        assert_eq!(remote.code, AnalysisFailureCode::UnsafeSource);

        validate_connection_policy(
            &request,
            "Driver={ODBC Driver 17 for SQL Server};Server=db.example;UID=app;PWD=secret;Encrypt=yes;TrustServerCertificate=no",
        )
        .unwrap();
        validate_connection_policy(&request, LOCAL_SQLSERVER).unwrap();
    }

    #[test]
    fn rejected_assessment_names_every_unproven_contract() {
        let capabilities = OdbcCatalogFunction::ALL
            .into_iter()
            .map(|function| OdbcCatalogFunctionCapability {
                function,
                support: OdbcCatalogFunctionSupport::DriverDeclared,
            })
            .collect::<Vec<_>>();
        let OdbcCompletenessAssessment::Rejected { blockers } =
            rejected_assessment(&capabilities, None)
        else {
            panic!("generic ODBC must remain rejected without a certified strategy");
        };
        assert!(blockers.iter().any(|blocker| blocker.contains("trigger")));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.contains("dependencies")));
        assert!(blockers
            .iter()
            .any(|blocker| blocker.contains("live-certified")));
    }

    #[cfg(feature = "odbc")]
    #[test]
    fn sqlserver_strategy_requires_runtime_verified_catalog_calls() {
        let driver = OdbcDriverIdentity {
            name: "ODBC Driver 17 for SQL Server".to_owned(),
            version: "17.10".to_owned(),
            odbc_version: "03.80".to_owned(),
        };
        let server = OdbcServerIdentity {
            product: "Microsoft SQL Server".to_owned(),
            version: "16.00".to_owned(),
        };
        let declared = OdbcCatalogFunction::ALL
            .into_iter()
            .map(|function| OdbcCatalogFunctionCapability {
                function,
                support: OdbcCatalogFunctionSupport::DriverDeclared,
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            runtime::completeness_assessment(&driver, &server, &declared),
            OdbcCompletenessAssessment::Rejected { .. }
        ));

        let verified = declared
            .into_iter()
            .map(|capability| OdbcCatalogFunctionCapability {
                support: if matches!(
                    capability.function,
                    OdbcCatalogFunction::Tables
                        | OdbcCatalogFunction::Columns
                        | OdbcCatalogFunction::PrimaryKeys
                        | OdbcCatalogFunction::ForeignKeys
                ) {
                    OdbcCatalogFunctionSupport::RuntimeCallVerified
                } else {
                    capability.support
                },
                ..capability
            })
            .collect::<Vec<_>>();
        assert_eq!(
            runtime::completeness_assessment(&driver, &server, &verified),
            OdbcCompletenessAssessment::Eligible {
                strategy: "sqlserver-native-bridge-v1".to_owned()
            }
        );

        let impostor = OdbcServerIdentity {
            product: "SQL Server compatible proxy".to_owned(),
            version: "16.00".to_owned(),
        };
        assert!(matches!(
            runtime::completeness_assessment(&driver, &impostor, &verified),
            OdbcCompletenessAssessment::Rejected { .. }
        ));
    }

    #[cfg(feature = "odbc")]
    #[test]
    fn sqlserver_bridge_normalizes_odbc_aliases_without_losing_secrets() {
        let input = "Driver={ODBC Driver 17 for SQL Server};Address=127.0.0.1,1433;Initial Catalog=app;UID=reader;PWD={p;a};Encrypt=no;Trust Server Certificate=yes";
        let translated = runtime::sqlserver_native_connection_string(input, &request()).unwrap();
        let values = translated.parse::<AdoNetString>().unwrap();

        assert!(!values.contains_key("driver"));
        assert_eq!(
            values.get("server").map(String::as_str),
            Some("127.0.0.1,1433")
        );
        assert_eq!(
            values.get("initial catalog").map(String::as_str),
            Some("app")
        );
        assert_eq!(values.get("uid").map(String::as_str), Some("reader"));
        assert_eq!(values.get("pwd").map(String::as_str), Some("p;a"));
        assert_eq!(
            values.get("trustservercertificate").map(String::as_str),
            Some("yes")
        );
    }

    #[test]
    fn cancellation_prevents_driver_work() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let failure = probe_odbc_capabilities_with_cancellation(
            "not-even-an-odbc-connection-string",
            "cancelled",
            1_000,
            &cancellation,
        )
        .unwrap_err();
        assert_eq!(failure.code, AnalysisFailureCode::Cancelled);
    }

    #[cfg(not(feature = "odbc"))]
    #[test]
    fn disabled_runtime_fails_without_a_snapshot() {
        let outcome = introspect_odbc_complete(LOCAL_SQLSERVER, "disabled");
        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::DriverUnavailable)
        );
        assert!(outcome.certified_snapshot().is_none());
    }

    #[cfg(feature = "odbc")]
    #[test]
    fn sqlserver_capability_probe_is_live_and_env_gated() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_ODBC_SQLSERVER_URL") else {
            return;
        };
        let report = probe_odbc_capabilities(&connection_string, "odbc-sqlserver", 30_000)
            .expect("live ODBC capability probe must succeed");
        assert!(report
            .server
            .product
            .to_ascii_lowercase()
            .contains("sql server"));
        assert!(report.read_only_access_mode);
        assert!(report.metadata_functions_only);
        for function in [
            OdbcCatalogFunction::Tables,
            OdbcCatalogFunction::Columns,
            OdbcCatalogFunction::PrimaryKeys,
            OdbcCatalogFunction::ForeignKeys,
        ] {
            assert!(report
                .catalog_functions
                .iter()
                .find(|capability| capability.function == function)
                .is_some_and(|capability| {
                    capability.support == OdbcCatalogFunctionSupport::RuntimeCallVerified
                }));
        }
        assert!(matches!(
            report.completeness,
            OdbcCompletenessAssessment::Eligible { ref strategy }
                if strategy == "sqlserver-native-bridge-v1"
        ));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(&connection_string));
        assert!(!serialized.contains("PWD"));

        let outcome = introspect_odbc_complete(&connection_string, "odbc-sqlserver");
        assert_eq!(outcome.status(), AnalysisStatus::Complete);
        let snapshot = outcome
            .certified_snapshot()
            .expect("SQL Server ODBC bridge must return the native certified snapshot");
        assert_eq!(snapshot.snapshot.schema.source_kind, "sqlserver");
        assert_eq!(
            snapshot.completeness.status,
            crate::certification::CompletionStatus::Complete
        );
        assert!(outcome.failure().is_none());
    }

    fn request() -> IntrospectionRequest {
        IntrospectionRequest {
            connection_alias: "odbc-test".to_owned(),
            requested_catalogs: Vec::new(),
            requested_schemas: Vec::new(),
            timeout_ms: 30_000,
        }
    }
}
