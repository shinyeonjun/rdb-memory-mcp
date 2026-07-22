use std::error::Error;
use std::fmt;

use crate::analysis_outcome::{AnalysisFailure, AnalysisOutcome};
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

use super::postgres_catalog::{analyze_postgres, analyze_postgres_with_cancellation};

pub type PostgresAdapterResult<T> = Result<T, PostgresAdapterError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostgresAdapterError {
    AnalysisFailed(AnalysisFailure),
}

impl fmt::Display for PostgresAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed(failure) => write!(
                f,
                "postgres adapter {:?} at {:?}: {}",
                failure.code, failure.stage, failure.message
            ),
        }
    }
}

impl Error for PostgresAdapterError {}

/// Compatibility facade. It now returns only a schema extracted from a certified
/// complete v2 result; a failed or partial analysis is never downgraded to v1.
pub fn introspect_postgres(
    connection_string: &str,
    connection_alias: &str,
) -> PostgresAdapterResult<SchemaSnapshot> {
    schema_from_outcome(introspect_postgres_complete(
        connection_string,
        connection_alias,
    ))
}

pub fn introspect_postgres_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    analyze_postgres(connection_string, connection_alias, Vec::new(), 30_000)
}

pub fn introspect_postgres_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_postgres(
        connection_string,
        connection_alias,
        requested_schemas,
        timeout_ms,
    )
}

pub fn introspect_postgres_complete_scoped_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    analyze_postgres_with_cancellation(
        connection_string,
        connection_alias,
        requested_schemas,
        timeout_ms,
        cancellation,
    )
}

fn schema_from_outcome(outcome: AnalysisOutcome) -> PostgresAdapterResult<SchemaSnapshot> {
    match outcome.certified_snapshot() {
        Some(snapshot) => Ok(snapshot.snapshot.schema.clone()),
        None => Err(PostgresAdapterError::AnalysisFailed(
            outcome
                .failure()
                .expect("failed analysis outcome must include its failure")
                .clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use postgres::{Client, NoTls};

    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStatus};
    use crate::ObjectKind;

    use super::*;

    #[test]
    fn invalid_connection_returns_a_closed_failed_outcome() {
        let outcome = introspect_postgres_complete(
            "postgresql://127.0.0.1:1/missing?connect_timeout=1",
            "unreachable",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::ConnectionFailed)
        );
        assert!(outcome.certified_snapshot().is_none());
    }

    #[test]
    fn remote_plaintext_fallback_is_rejected_before_credentials_leave_process() {
        let outcome = introspect_postgres_complete(
            "postgresql://app:do-not-echo@example.invalid/app",
            "remote-unsafe",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        let failure = outcome.failure().unwrap();
        assert_eq!(failure.code, AnalysisFailureCode::UnsafeSource);
        assert!(!failure.message.contains("do-not-echo"));
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_POSTGRES_URL"]
    fn postgres_adapter_live_introspection_is_env_gated() {
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_POSTGRES_URL")
            .expect("live PostgreSQL test requires DATABASE_MEMORY_TEST_POSTGRES_URL");
        let outcome = introspect_postgres_complete_scoped(
            &connection_string,
            "pg-live",
            vec!["public".to_owned()],
            30_000,
        );
        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{:?}",
            outcome.failure()
        );
        let snapshot = outcome.certified_snapshot().unwrap();
        assert_eq!(snapshot.snapshot.schema.source_kind, "postgres");
        assert!(snapshot.snapshot.schema.capabilities.metadata_only);
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_YUGABYTE_URL"]
    fn postgres_entrypoint_rejects_yugabyte_identity() {
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_URL")
            .expect("YugabyteDB identity test requires DATABASE_MEMORY_TEST_YUGABYTE_URL");
        let outcome = introspect_postgres_complete_scoped(
            &connection_string,
            "yb-through-postgres",
            vec!["public".to_owned()],
            30_000,
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::UnsupportedProduct)
        );
        assert!(outcome.certified_snapshot().is_none());
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_POSTGRES_URL"]
    fn rich_postgres_catalog_is_certified_without_silent_drops() {
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_POSTGRES_URL")
            .expect("rich PostgreSQL test requires DATABASE_MEMORY_TEST_POSTGRES_URL");
        let schema = unique_schema("rich");
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "
                CREATE SCHEMA {schema};
                CREATE TYPE {schema}.account_status AS ENUM ('active', 'paused');
                CREATE TYPE {schema}.postal_address AS (city text, postal_code text);
                CREATE DOMAIN {schema}.positive_amount AS numeric
                    CHECK (VALUE >= 0);
                CREATE SEQUENCE {schema}.audit_number START 100 INCREMENT 5;
                CREATE TABLE {schema}.accounts (
                    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    email text NOT NULL UNIQUE,
                    status {schema}.account_status NOT NULL DEFAULT 'active',
                    balance {schema}.positive_amount NOT NULL DEFAULT 0,
                    label text GENERATED ALWAYS AS (email || ':account') STORED,
                    audit_no bigint DEFAULT nextval('{schema}.audit_number'),
                    CONSTRAINT email_length CHECK (char_length(email) > 3)
                );
                CREATE TABLE {schema}.bookings (
                    id bigint PRIMARY KEY,
                    account_id bigint NOT NULL REFERENCES {schema}.accounts(id)
                        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
                    occupied int4range NOT NULL,
                    EXCLUDE USING gist (occupied WITH &&)
                );
                CREATE TABLE {schema}.events (
                    id bigint NOT NULL,
                    created_at date NOT NULL,
                    PRIMARY KEY (id, created_at)
                ) PARTITION BY RANGE (created_at);
                CREATE TABLE {schema}.events_2026 PARTITION OF {schema}.events
                    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
                CREATE INDEX accounts_email_cover
                    ON {schema}.accounts (lower(email) text_pattern_ops)
                    INCLUDE (status) WHERE status = 'active';
                ALTER TABLE {schema}.accounts ALTER COLUMN email SET STATISTICS 200;
                CREATE VIEW {schema}.active_accounts AS
                    SELECT id, email, status FROM {schema}.accounts WHERE status = 'active';
                CREATE VIEW {schema}.active_account_ids AS
                    SELECT id FROM {schema}.active_accounts;
                CREATE MATERIALIZED VIEW {schema}.account_totals AS
                    SELECT account_id, count(*) AS booking_count
                    FROM {schema}.bookings GROUP BY account_id;
                CREATE UNIQUE INDEX account_totals_pk
                    ON {schema}.account_totals(account_id);
                ALTER TABLE {schema}.accounts ENABLE ROW LEVEL SECURITY;
                CREATE POLICY account_reader ON {schema}.accounts
                    FOR SELECT TO PUBLIC USING (status = 'active');
                CREATE FUNCTION {schema}.account_email(account_id bigint)
                    RETURNS text LANGUAGE SQL STABLE
                    RETURN (SELECT email FROM {schema}.accounts WHERE id = account_id);
                CREATE FUNCTION {schema}.account_email(email_value text)
                    RETURNS text LANGUAGE SQL IMMUTABLE
                    RETURN email_value;
                CREATE PROCEDURE {schema}.record_account_check(account_id bigint)
                    LANGUAGE SQL
                    BEGIN ATOMIC
                        SELECT account_id;
                    END;
                "
            ))
            .unwrap();

        let outcome = introspect_postgres_complete_scoped(
            &connection_string,
            "pg-rich",
            vec![schema.clone()],
            30_000,
        );
        let failure = outcome.failure().cloned();
        let certified = outcome.certified_snapshot().cloned();
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .unwrap();

        assert_eq!(outcome.status(), AnalysisStatus::Complete, "{failure:?}");
        let snapshot = &certified.unwrap().snapshot;
        assert!(snapshot
            .schema
            .tables
            .iter()
            .any(|table| table.name == "events_2026"));
        assert!(snapshot
            .schema
            .constraints
            .iter()
            .any(|constraint| constraint.name == "email_length"));
        for kind in [
            ObjectKind::MaterializedView,
            ObjectKind::Sequence,
            ObjectKind::RoutineParameter,
            ObjectKind::UserDefinedType,
            ObjectKind::Domain,
            ObjectKind::EnumValue,
            ObjectKind::ExclusionConstraint,
            ObjectKind::Policy,
        ] {
            assert!(
                snapshot
                    .metadata
                    .objects
                    .iter()
                    .any(|object| object.key.object_kind == kind),
                "missing {kind}"
            );
        }
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind == crate::canonical::MetadataRelationshipKind::PartitionOf
        }));
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind == crate::canonical::MetadataRelationshipKind::UsesSequence
        }));
        let account_email_overloads = snapshot
            .schema
            .routines
            .iter()
            .filter(|routine| routine.name == "account_email")
            .collect::<Vec<_>>();
        assert_eq!(account_email_overloads.len(), 2);
        assert_ne!(
            account_email_overloads[0].key,
            account_email_overloads[1].key
        );
        assert!(snapshot.schema.routines.iter().any(|routine| {
            routine.name == "record_account_check" && routine.kind == crate::RoutineKind::Procedure
        }));
        let email = snapshot
            .metadata
            .annotations
            .iter()
            .find(|annotation| {
                annotation.object_key.object_kind == ObjectKind::Column
                    && annotation.object_key.object_name == "accounts"
                    && annotation.object_key.sub_object.as_deref() == Some("email")
            })
            .expect("accounts.email metadata");
        assert_eq!(
            email.properties.get("statistics_target_mode"),
            Some(&crate::canonical::MetadataValue::String(
                "custom".to_owned()
            ))
        );
        assert_eq!(
            email.properties.get("statistics_target"),
            Some(&crate::canonical::MetadataValue::Integer(200))
        );
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_POSTGRES_URL"]
    fn opaque_postgres_routine_fails_instead_of_claiming_complete_dependencies() {
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_POSTGRES_URL")
            .expect("opaque PostgreSQL routine test requires DATABASE_MEMORY_TEST_POSTGRES_URL");
        let schema = unique_schema("opaque");
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "
                CREATE SCHEMA {schema};
                CREATE TABLE {schema}.trigger_target (id bigint PRIMARY KEY);
                CREATE FUNCTION {schema}.hidden_dependency()
                    RETURNS trigger LANGUAGE plpgsql
                    AS $$ BEGIN RETURN NEW; END $$;
                CREATE TRIGGER hidden_dependency_trigger
                    BEFORE INSERT ON {schema}.trigger_target
                    FOR EACH ROW EXECUTE FUNCTION {schema}.hidden_dependency();
                "
            ))
            .unwrap();

        let outcome = introspect_postgres_complete_scoped(
            &connection_string,
            "pg-opaque",
            vec![schema.clone()],
            30_000,
        );
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .unwrap();

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::UnsupportedMetadata)
        );
        assert!(outcome.certified_snapshot().is_none());
    }

    #[test]
    #[ignore = "requires DATABASE_MEMORY_TEST_POSTGRES_URL"]
    fn postgres_schema_privilege_is_a_closed_completeness_gate() {
        let connection_string = std::env::var("DATABASE_MEMORY_TEST_POSTGRES_URL")
            .expect("PostgreSQL privilege test requires DATABASE_MEMORY_TEST_POSTGRES_URL");
        let schema = unique_schema("privilege");
        let role = unique_schema("role");
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "
                CREATE SCHEMA {schema};
                CREATE TABLE {schema}.visible_table (
                    id bigint PRIMARY KEY,
                    payload text NOT NULL
                );
                CREATE ROLE {role} NOLOGIN;
                "
            ))
            .unwrap();

        let role_connection = connection_string_with_startup_role(&connection_string, &role);
        let denied = introspect_postgres_complete_scoped(
            &role_connection,
            "pg-restricted",
            vec![schema.clone()],
            30_000,
        );
        client
            .batch_execute(&format!("GRANT USAGE ON SCHEMA {schema} TO {role};"))
            .unwrap();
        let allowed = introspect_postgres_complete_scoped(
            &role_connection,
            "pg-restricted",
            vec![schema.clone()],
            30_000,
        );

        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE; DROP ROLE {role};"))
            .unwrap();

        assert_eq!(denied.status(), AnalysisStatus::Failed);
        assert_eq!(
            denied.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::PermissionDenied)
        );
        assert!(denied.certified_snapshot().is_none());

        assert_eq!(
            allowed.status(),
            AnalysisStatus::Complete,
            "{:?}",
            allowed.failure()
        );
        let snapshot = &allowed.certified_snapshot().unwrap().snapshot;
        assert!(snapshot
            .schema
            .tables
            .iter()
            .any(|table| table.name == "visible_table"));
    }

    fn connection_string_with_startup_role(connection_string: &str, role: &str) -> String {
        let separator = if connection_string.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{connection_string}{separator}options=-c%20role%3D{role}")
    }

    fn unique_schema(label: &str) -> String {
        format!(
            "database_memory_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}
