use std::error::Error;
use std::fmt;

use crate::analysis_outcome::{AnalysisFailure, AnalysisOutcome};
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

use super::oracle_catalog::{analyze_oracle, analyze_oracle_with_cancellation};

pub type OracleAdapterResult<T> = Result<T, OracleAdapterError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleAdapterError {
    AnalysisFailed(AnalysisFailure),
}

impl fmt::Display for OracleAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed(failure) => write!(
                formatter,
                "oracle adapter {:?} at {:?}: {}",
                failure.code, failure.stage, failure.message
            ),
        }
    }
}

impl Error for OracleAdapterError {}

/// Compatibility facade. A legacy schema is returned only after contract-v2
/// certification; a failed Oracle analysis is never downgraded to success.
pub fn introspect_oracle(
    connection_string: &str,
    connection_alias: &str,
) -> OracleAdapterResult<SchemaSnapshot> {
    schema_from_outcome(introspect_oracle_complete(
        connection_string,
        connection_alias,
    ))
}

pub fn introspect_oracle_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    analyze_oracle(
        connection_string,
        connection_alias,
        Vec::new(),
        Vec::new(),
        30_000,
    )
}

pub fn introspect_oracle_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_oracle(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
    )
}

pub fn introspect_oracle_complete_scoped_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_catalogs: Vec<String>,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    analyze_oracle_with_cancellation(
        connection_string,
        connection_alias,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
        cancellation,
    )
}

fn schema_from_outcome(outcome: AnalysisOutcome) -> OracleAdapterResult<SchemaSnapshot> {
    match outcome.certified_snapshot() {
        Some(snapshot) => Ok(snapshot.snapshot.schema.clone()),
        None => Err(OracleAdapterError::AnalysisFailed(
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
        let outcome =
            introspect_oracle_complete("dbmcp/never-echo@127.0.0.1:1/MISSING", "unreachable");

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert!(matches!(
            outcome.failure().unwrap().code,
            AnalysisFailureCode::ConnectionFailed | AnalysisFailureCode::Timeout
        ));
        assert!(outcome.certified_snapshot().is_none());
        assert!(!outcome.failure().unwrap().message.contains("never-echo"));
    }
}
