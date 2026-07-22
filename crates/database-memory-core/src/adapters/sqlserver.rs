use std::error::Error;
use std::fmt;

use crate::analysis_outcome::{AnalysisFailure, AnalysisOutcome};
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

use super::sqlserver_catalog::{analyze_sqlserver, analyze_sqlserver_with_cancellation};

pub type SqlServerAdapterResult<T> = Result<T, SqlServerAdapterError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlServerAdapterError {
    AnalysisFailed(AnalysisFailure),
}

impl fmt::Display for SqlServerAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed(failure) => write!(
                formatter,
                "SQL Server adapter {:?} at {:?}: {}",
                failure.code, failure.stage, failure.message
            ),
        }
    }
}

impl Error for SqlServerAdapterError {}

/// Compatibility facade. A legacy schema is exposed only after contract-v2
/// certification; an incomplete analysis can never be downgraded to success.
pub fn introspect_sqlserver(
    connection_string: &str,
    connection_alias: &str,
) -> SqlServerAdapterResult<SchemaSnapshot> {
    schema_from_outcome(introspect_sqlserver_complete(
        connection_string,
        connection_alias,
    ))
}

pub fn introspect_sqlserver_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    analyze_sqlserver(
        connection_string,
        connection_alias,
        Vec::new(),
        Vec::new(),
        30_000,
    )
}

pub fn introspect_sqlserver_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_sqlserver(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
    )
}

pub fn introspect_sqlserver_complete_scoped_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    analyze_sqlserver_with_cancellation(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
        cancellation,
    )
}

fn schema_from_outcome(outcome: AnalysisOutcome) -> SqlServerAdapterResult<SchemaSnapshot> {
    match outcome.certified_snapshot() {
        Some(snapshot) => Ok(snapshot.snapshot.schema.clone()),
        None => Err(SqlServerAdapterError::AnalysisFailed(
            outcome
                .failure()
                .expect("failed analysis outcome must include its failure")
                .clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStatus};

    use super::*;

    #[test]
    fn invalid_connection_returns_a_closed_failed_outcome() {
        let outcome = introspect_sqlserver_complete(
            "Server=tcp:127.0.0.1,1;Database=missing;User ID=sa;Password=do-not-echo;Encrypt=true;TrustServerCertificate=true",
            "unreachable",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::ConnectionFailed)
        );
        assert!(!outcome.failure().unwrap().message.contains("do-not-echo"));
        assert!(outcome.certified_snapshot().is_none());
    }

    #[test]
    fn remote_untrusted_transport_is_rejected_before_connecting() {
        let outcome = introspect_sqlserver_complete(
            "Server=tcp:example.invalid,1433;Database=app;User ID=app;Password=do-not-echo;Encrypt=false;TrustServerCertificate=true",
            "remote-unsafe",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        let failure = outcome.failure().unwrap();
        assert_eq!(failure.code, AnalysisFailureCode::UnsafeSource);
        assert!(!failure.message.contains("do-not-echo"));
    }
}
