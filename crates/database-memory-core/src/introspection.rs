use crate::analysis_outcome::{
    AnalysisFailure, AnalysisFailureCode, AnalysisOutcome, AnalysisStage,
};
use crate::canonical::CanonicalSchemaSnapshot;
use crate::certification::{
    certify_schema_snapshot, AdapterIdentity, CapabilityCheck, CertificationError,
    CertifiedSchemaSnapshot, DiscoveryCounts, IntrospectionScope, ServerIdentity,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntrospectionRequest {
    pub connection_alias: String,
    pub requested_catalogs: Vec<String>,
    pub requested_schemas: Vec<String>,
    pub timeout_ms: u64,
}

impl IntrospectionRequest {
    pub fn validate(&self, source_kind: &str) -> Result<(), AnalysisFailure> {
        if self.connection_alias.trim().is_empty() {
            return Err(AnalysisFailure::redacted(
                AnalysisFailureCode::InvalidConfiguration,
                AnalysisStage::Configuration,
                source_kind,
                &self.connection_alias,
                "connection alias must not be empty",
                "provide a stable non-secret connection alias",
                false,
                None,
            ));
        }
        if self.timeout_ms == 0 {
            return Err(AnalysisFailure::redacted(
                AnalysisFailureCode::InvalidConfiguration,
                AnalysisStage::Configuration,
                source_kind,
                &self.connection_alias,
                "introspection timeout must be greater than zero",
                "set a bounded timeout in milliseconds",
                false,
                None,
            ));
        }
        Ok(())
    }
}

pub trait CatalogIntrospector {
    fn source_kind(&self) -> &'static str;

    fn discover(
        &mut self,
        request: &IntrospectionRequest,
    ) -> Result<CatalogDiscovery, AnalysisFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogDiscovery {
    pub snapshot: CanonicalSchemaSnapshot,
    pub adapter: AdapterIdentity,
    pub server: ServerIdentity,
    pub scope: IntrospectionScope,
    pub discovered_counts: DiscoveryCounts,
    pub capability_checks: Vec<CapabilityCheck>,
}

pub struct CanonicalSnapshotAssembler;

impl CanonicalSnapshotAssembler {
    pub fn certify(
        discovery: CatalogDiscovery,
    ) -> Result<CertifiedSchemaSnapshot, CertificationError> {
        certify_schema_snapshot(
            discovery.snapshot,
            discovery.adapter,
            discovery.server,
            discovery.scope,
            discovery.discovered_counts,
            discovery.capability_checks,
        )
    }
}

pub struct DatabaseAnalysisService<A> {
    adapter: A,
}

impl<A: CatalogIntrospector> DatabaseAnalysisService<A> {
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    pub fn analyze(&mut self, request: &IntrospectionRequest) -> AnalysisOutcome {
        if let Err(failure) = request.validate(self.adapter.source_kind()) {
            return AnalysisOutcome::failed(failure);
        }
        let discovery = match self.adapter.discover(request) {
            Ok(discovery) => discovery,
            Err(failure) => return AnalysisOutcome::failed(failure),
        };
        let source_kind = discovery.snapshot.schema.source_kind.clone();
        let connection_alias = discovery.snapshot.schema.connection_alias.clone();
        match CanonicalSnapshotAssembler::certify(discovery) {
            Ok(snapshot) => match AnalysisOutcome::complete(snapshot) {
                Ok(outcome) => outcome,
                Err(error) => AnalysisOutcome::failed(certification_failure(
                    &source_kind,
                    &connection_alias,
                    error,
                )),
            },
            Err(error) => AnalysisOutcome::failed(certification_failure(
                &source_kind,
                &connection_alias,
                error,
            )),
        }
    }
}

fn certification_failure(
    source_kind: &str,
    connection_alias: &str,
    error: CertificationError,
) -> AnalysisFailure {
    let count_mismatch = error.issues.iter().any(|issue| {
        matches!(
            issue.code.as_str(),
            "object_count_mismatch"
                | "relationship_count_mismatch"
                | "discovered_count_missing"
                | "discovered_relationship_count_missing"
        )
    });
    AnalysisFailure::redacted(
        if count_mismatch {
            AnalysisFailureCode::CompletenessMismatch
        } else {
            AnalysisFailureCode::ValidationFailed
        },
        AnalysisStage::Validation,
        source_kind,
        connection_alias,
        error.to_string(),
        "inspect the adapter discovery evidence and fix every reported mapping before retrying",
        false,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalSchemaSnapshot;
    use crate::certification::fixture_discovery_counts;
    use crate::{
        AdapterCapabilities, CapabilitySupport, DatabaseObject, ObjectKey, ObjectKind,
        SchemaObject, SchemaSnapshot,
    };

    struct FakeAdapter {
        discovery: Option<Result<CatalogDiscovery, AnalysisFailure>>,
    }

    impl CatalogIntrospector for FakeAdapter {
        fn source_kind(&self) -> &'static str {
            "fake-rdb"
        }

        fn discover(
            &mut self,
            _request: &IntrospectionRequest,
        ) -> Result<CatalogDiscovery, AnalysisFailure> {
            self.discovery.take().expect("fake called once")
        }
    }

    #[test]
    fn service_runs_adapter_then_assembler_to_a_complete_outcome() {
        let snapshot = snapshot();
        let discovery = discovery(snapshot.clone(), fixture_discovery_counts(&snapshot));
        let mut service = DatabaseAnalysisService::new(FakeAdapter {
            discovery: Some(Ok(discovery)),
        });

        let outcome = service.analyze(&request());

        assert_eq!(
            outcome.status(),
            crate::analysis_outcome::AnalysisStatus::Complete
        );
        assert!(outcome.certified_snapshot().is_some());
    }

    #[test]
    fn service_turns_count_loss_into_an_exact_failed_outcome() {
        let snapshot = snapshot();
        let mut counts = fixture_discovery_counts(&snapshot);
        counts
            .objects
            .get_mut(&crate::certification::ObjectCategory::Schema)
            .unwrap()
            .count = 0;
        let mut service = DatabaseAnalysisService::new(FakeAdapter {
            discovery: Some(Ok(discovery(snapshot, counts))),
        });

        let outcome = service.analyze(&request());

        let failure = outcome.failure().expect("count loss must fail");
        assert_eq!(failure.code, AnalysisFailureCode::CompletenessMismatch);
        assert_eq!(failure.stage, AnalysisStage::Validation);
    }

    #[test]
    fn invalid_request_fails_before_the_adapter_is_called() {
        let mut request = request();
        request.timeout_ms = 0;
        let mut service = DatabaseAnalysisService::new(FakeAdapter { discovery: None });

        let outcome = service.analyze(&request);

        assert_eq!(
            outcome.failure().unwrap().code,
            AnalysisFailureCode::InvalidConfiguration
        );
    }

    fn discovery(
        snapshot: CanonicalSchemaSnapshot,
        discovered_counts: DiscoveryCounts,
    ) -> CatalogDiscovery {
        CatalogDiscovery {
            snapshot,
            adapter: AdapterIdentity {
                name: "fake-rdb".to_owned(),
                version: "1".to_owned(),
            },
            server: ServerIdentity {
                product: "Fake RDB".to_owned(),
                version: "1".to_owned(),
            },
            scope: IntrospectionScope {
                catalogs: vec!["main".to_owned()],
                schemas: vec!["public".to_owned()],
            },
            discovered_counts,
            capability_checks: vec![CapabilityCheck {
                name: "catalog_visibility".to_owned(),
                evidence: "all catalog probes completed".to_owned(),
            }],
        }
    }

    fn request() -> IntrospectionRequest {
        IntrospectionRequest {
            connection_alias: "sample".to_owned(),
            requested_catalogs: vec!["main".to_owned()],
            requested_schemas: vec!["public".to_owned()],
            timeout_ms: 30_000,
        }
    }

    fn snapshot() -> CanonicalSchemaSnapshot {
        let database_key = key(ObjectKind::Database, "main", None);
        CanonicalSchemaSnapshot::from(SchemaSnapshot {
            source_kind: "fake-rdb".to_owned(),
            connection_alias: "sample".to_owned(),
            database: DatabaseObject {
                key: database_key.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: key(ObjectKind::Schema, "public", None),
                database_key,
                name: "public".to_owned(),
            }],
            tables: vec![],
            columns: vec![],
            constraints: vec![],
            indexes: vec![],
            views: vec![],
            triggers: vec![],
            routines: vec![],
            capabilities: AdapterCapabilities {
                source_kind: "fake-rdb".to_owned(),
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
                limitations: vec![],
                notes: vec![],
            },
        })
    }

    fn key(kind: ObjectKind, object_name: &str, sub_object: Option<&str>) -> ObjectKey {
        ObjectKey::new(
            "fake-rdb",
            "sample",
            "main",
            if kind == ObjectKind::Database {
                "main"
            } else {
                "public"
            },
            kind,
            object_name,
            sub_object.map(str::to_owned),
        )
    }
}
