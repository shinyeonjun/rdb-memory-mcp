use serde::{Deserialize, Serialize};

use crate::certification::{
    verify_certified_schema_snapshot, CertificationError, CertifiedSchemaSnapshot,
};
use crate::redact::{redact_connection_string, redact_error_with_connection_string};

pub const MAX_FAILURE_TEXT_BYTES: usize = 8_192;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AnalysisOutcome(AnalysisOutcomePayload);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AnalysisOutcomePayload {
    Complete {
        snapshot: Box<CertifiedSchemaSnapshot>,
    },
    Failed {
        failure: AnalysisFailure,
    },
}

impl AnalysisOutcome {
    pub fn complete(snapshot: CertifiedSchemaSnapshot) -> Result<Self, CertificationError> {
        verify_certified_schema_snapshot(&snapshot)?;
        Ok(Self(AnalysisOutcomePayload::Complete {
            snapshot: Box::new(snapshot),
        }))
    }

    pub fn failed(failure: AnalysisFailure) -> Self {
        Self(AnalysisOutcomePayload::Failed { failure })
    }

    pub fn status(&self) -> AnalysisStatus {
        match &self.0 {
            AnalysisOutcomePayload::Complete { .. } => AnalysisStatus::Complete,
            AnalysisOutcomePayload::Failed { .. } => AnalysisStatus::Failed,
        }
    }

    pub fn certified_snapshot(&self) -> Option<&CertifiedSchemaSnapshot> {
        match &self.0 {
            AnalysisOutcomePayload::Complete { snapshot } => Some(snapshot),
            AnalysisOutcomePayload::Failed { .. } => None,
        }
    }

    pub fn failure(&self) -> Option<&AnalysisFailure> {
        match &self.0 {
            AnalysisOutcomePayload::Complete { .. } => None,
            AnalysisOutcomePayload::Failed { failure } => Some(failure),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisFailure {
    pub code: AnalysisFailureCode,
    pub stage: AnalysisStage,
    pub source_kind: String,
    pub connection_alias: String,
    pub message: String,
    pub remediation: String,
    pub retryable: bool,
}

impl AnalysisFailure {
    #[allow(clippy::too_many_arguments)]
    pub fn redacted(
        code: AnalysisFailureCode,
        stage: AnalysisStage,
        source_kind: impl Into<String>,
        connection_alias: impl Into<String>,
        message: impl AsRef<str>,
        remediation: impl AsRef<str>,
        retryable: bool,
        connection_string: Option<&str>,
    ) -> Self {
        Self {
            code,
            stage,
            source_kind: bounded_redacted(source_kind.into(), connection_string),
            connection_alias: bounded_redacted(connection_alias.into(), connection_string),
            message: bounded_redacted(message.as_ref(), connection_string),
            remediation: bounded_redacted(remediation.as_ref(), connection_string),
            retryable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisFailureCode {
    InvalidConfiguration,
    UnsafeSource,
    DriverUnavailable,
    ConnectionFailed,
    AuthenticationFailed,
    PermissionDenied,
    UnsupportedProduct,
    UnsupportedVersion,
    UnsupportedMetadata,
    MetadataQueryFailed,
    MetadataMappingFailed,
    ValidationFailed,
    CompletenessMismatch,
    Timeout,
    Cancelled,
    StorageFailed,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStage {
    Configuration,
    Connection,
    CapabilityProbe,
    Discovery,
    Mapping,
    Validation,
    Persistence,
}

fn bounded_redacted(value: impl AsRef<str>, connection_string: Option<&str>) -> String {
    let value = match connection_string {
        Some(connection_string) => {
            redact_error_with_connection_string(value.as_ref(), connection_string)
        }
        None => redact_connection_string(value.as_ref()),
    };
    truncate_utf8(&value, MAX_FAILURE_TEXT_BYTES)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_outcome_has_only_the_failed_authority_state() {
        let outcome = AnalysisOutcome::failed(AnalysisFailure::redacted(
            AnalysisFailureCode::PermissionDenied,
            AnalysisStage::CapabilityProbe,
            "postgres",
            "prod",
            "metadata privilege is missing",
            "grant metadata visibility and retry",
            false,
            None,
        ));
        let value = serde_json::to_value(outcome).unwrap();

        assert_eq!(value["status"], "failed");
        assert_eq!(value["failure"]["code"], "permission_denied");
        assert!(value.get("complete").is_none());
    }

    #[test]
    fn failure_text_is_redacted_and_bounded_without_breaking_utf8() {
        let connection = "postgres://app:secret@localhost/main";
        let message = format!("{connection} {}", "가".repeat(MAX_FAILURE_TEXT_BYTES));
        let failure = AnalysisFailure::redacted(
            AnalysisFailureCode::ConnectionFailed,
            AnalysisStage::Connection,
            "postgres",
            "prod",
            message,
            "check connection",
            true,
            Some(connection),
        );

        assert!(!failure.message.contains("secret"));
        assert!(failure.message.len() <= MAX_FAILURE_TEXT_BYTES);
        assert!(std::str::from_utf8(failure.message.as_bytes()).is_ok());
    }
}
