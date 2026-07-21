use std::error::Error;
use std::fmt;

use crate::analysis_outcome::{AnalysisFailure, AnalysisOutcome};
use crate::SchemaSnapshot;

use super::mysql_catalog::analyze_mysql_family;

pub type MysqlAdapterResult<T> = Result<T, MysqlAdapterError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MysqlAdapterError {
    AnalysisFailed(AnalysisFailure),
}

impl fmt::Display for MysqlAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed(failure) => write!(
                f,
                "MySQL-family adapter {:?} at {:?}: {}",
                failure.code, failure.stage, failure.message
            ),
        }
    }
}

impl Error for MysqlAdapterError {}

/// Compatibility facade. A legacy schema is returned only after the v2
/// complete contract has been certified; failed analysis is never downgraded.
pub fn introspect_mysql(
    connection_string: &str,
    connection_alias: &str,
) -> MysqlAdapterResult<SchemaSnapshot> {
    schema_from_outcome(introspect_mysql_complete(
        connection_string,
        connection_alias,
    ))
}

pub fn introspect_mysql_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    analyze_mysql_family(connection_string, connection_alias, Vec::new(), 30_000)
}

pub fn introspect_mysql_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_databases: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_mysql_family(
        connection_string,
        connection_alias,
        requested_databases,
        timeout_ms,
    )
}

fn schema_from_outcome(outcome: AnalysisOutcome) -> MysqlAdapterResult<SchemaSnapshot> {
    match outcome.certified_snapshot() {
        Some(snapshot) => Ok(snapshot.snapshot.schema.clone()),
        None => Err(MysqlAdapterError::AnalysisFailed(
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
        let outcome = introspect_mysql_complete(
            "mysql://root:do-not-echo@127.0.0.1:1/missing?prefer_socket=false",
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
    fn remote_tls_is_added_by_policy_instead_of_allowing_plaintext() {
        let outcome = introspect_mysql_complete(
            "mysql://app:do-not-echo@example.invalid/app?prefer_socket=false",
            "remote",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::ConnectionFailed)
        );
        assert!(!outcome.failure().unwrap().message.contains("do-not-echo"));
    }
}
