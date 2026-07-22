use std::error::Error;
use std::fmt;

use crate::analysis_outcome::{AnalysisFailure, AnalysisOutcome};
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

use super::postgres_catalog::{analyze_yugabytedb, analyze_yugabytedb_with_cancellation};

pub type YugabyteDbAdapterResult<T> = Result<T, YugabyteDbAdapterError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YugabyteDbAdapterError {
    AnalysisFailed(AnalysisFailure),
}

impl fmt::Display for YugabyteDbAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed(failure) => write!(
                f,
                "YugabyteDB adapter {:?} at {:?}: {}",
                failure.code, failure.stage, failure.message
            ),
        }
    }
}

impl Error for YugabyteDbAdapterError {}

pub fn introspect_yugabytedb(
    connection_string: &str,
    connection_alias: &str,
) -> YugabyteDbAdapterResult<SchemaSnapshot> {
    schema_from_outcome(introspect_yugabytedb_complete(
        connection_string,
        connection_alias,
    ))
}

pub fn introspect_yugabytedb_complete(
    connection_string: &str,
    connection_alias: &str,
) -> AnalysisOutcome {
    analyze_yugabytedb(connection_string, connection_alias, Vec::new(), 30_000)
}

pub fn introspect_yugabytedb_complete_scoped(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
) -> AnalysisOutcome {
    analyze_yugabytedb(
        connection_string,
        connection_alias,
        requested_schemas,
        timeout_ms,
    )
}

pub fn introspect_yugabytedb_complete_scoped_with_cancellation(
    connection_string: &str,
    connection_alias: &str,
    requested_schemas: Vec<String>,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    analyze_yugabytedb_with_cancellation(
        connection_string,
        connection_alias,
        requested_schemas,
        timeout_ms,
        cancellation,
    )
}

fn schema_from_outcome(outcome: AnalysisOutcome) -> YugabyteDbAdapterResult<SchemaSnapshot> {
    match outcome.certified_snapshot() {
        Some(snapshot) => Ok(snapshot.snapshot.schema.clone()),
        None => Err(YugabyteDbAdapterError::AnalysisFailed(
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
    use crate::canonical::{MetadataRelationshipKind, MetadataValue};
    use crate::ObjectKind;

    use super::*;

    #[test]
    fn invalid_connection_returns_a_closed_failed_outcome() {
        let outcome = introspect_yugabytedb_complete(
            "postgresql://127.0.0.1:1/missing?connect_timeout=1",
            "unreachable",
        );

        assert_eq!(outcome.status(), AnalysisStatus::Failed);
        assert_eq!(
            outcome.failure().map(|failure| failure.code),
            Some(AnalysisFailureCode::ConnectionFailed)
        );
        assert_eq!(
            outcome
                .failure()
                .map(|failure| failure.source_kind.as_str()),
            Some("yugabytedb")
        );
        assert!(outcome.certified_snapshot().is_none());
    }

    #[test]
    fn yugabytedb_entrypoint_rejects_postgres_identity() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_POSTGRES_URL") else {
            return;
        };
        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "postgres-through-yugabyte",
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
    fn certified_yugabytedb_release_is_live_and_env_gated() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_URL") else {
            return;
        };
        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "yb-live",
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
        assert_eq!(snapshot.snapshot.schema.source_kind, "yugabytedb");
        assert_eq!(
            snapshot.snapshot.schema.capabilities.source_kind,
            "yugabytedb"
        );
        assert_eq!(snapshot.completeness.server.product, "YugabyteDB");
        assert_eq!(
            snapshot.completeness.adapter.name,
            "database-memory-yugabytedb-catalog"
        );
        assert!(snapshot.snapshot.schema.capabilities.metadata_only);
    }

    #[test]
    fn rich_yugabytedb_catalog_preserves_distributed_metadata_without_silent_drops() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_URL") else {
            return;
        };
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
                CREATE TABLE {schema}.hash_accounts (
                    id bigint PRIMARY KEY,
                    email text NOT NULL UNIQUE,
                    status {schema}.account_status NOT NULL DEFAULT 'active',
                    balance {schema}.positive_amount NOT NULL DEFAULT 0,
                    audit_no bigint DEFAULT nextval('{schema}.audit_number'),
                    CONSTRAINT email_length CHECK (char_length(email) > 3)
                ) SPLIT INTO 3 TABLETS;
                CREATE TABLE {schema}.bookings (
                    id bigint PRIMARY KEY,
                    account_id bigint NOT NULL REFERENCES {schema}.hash_accounts(id)
                        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
                );
                CREATE TABLE {schema}.range_events (
                    id bigint,
                    payload text,
                    PRIMARY KEY (id ASC)
                ) SPLIT AT VALUES ((10), (20));
                CREATE INDEX hash_accounts_email_idx
                    ON {schema}.hash_accounts (lower(email))
                    INCLUDE (status) SPLIT INTO 2 TABLETS
                    WHERE status = 'active';
                CREATE VIEW {schema}.active_accounts AS
                    SELECT id, email, status
                    FROM {schema}.hash_accounts WHERE status = 'active';
                CREATE MATERIALIZED VIEW {schema}.account_totals AS
                    SELECT account_id, count(*) AS booking_count
                    FROM {schema}.bookings GROUP BY account_id;
                CREATE UNIQUE INDEX account_totals_pk
                    ON {schema}.account_totals(account_id);
                CREATE FUNCTION {schema}.account_email(account_id bigint)
                    RETURNS text LANGUAGE SQL STABLE
                    RETURN (SELECT email FROM {schema}.hash_accounts WHERE id = account_id);
                "
            ))
            .unwrap();

        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "yb-rich",
            vec![schema.clone()],
            30_000,
        );
        let failure = outcome.failure().cloned();
        let certified = outcome.certified_snapshot().cloned();
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .unwrap();

        assert_eq!(outcome.status(), AnalysisStatus::Complete, "{failure:?}");
        let certified = certified.unwrap();
        let snapshot = &certified.snapshot;
        assert_eq!(snapshot.schema.source_kind, "yugabytedb");

        assert_property(
            snapshot,
            ObjectKind::Table,
            "hash_accounts",
            None,
            "yugabytedb_num_tablets",
            MetadataValue::Integer(3),
        );
        assert_property(
            snapshot,
            ObjectKind::Table,
            "hash_accounts",
            None,
            "yugabytedb_num_hash_key_columns",
            MetadataValue::Integer(1),
        );
        assert_property(
            snapshot,
            ObjectKind::Index,
            "hash_accounts",
            Some("hash_accounts_email_idx"),
            "yugabytedb_num_tablets",
            MetadataValue::Integer(2),
        );
        assert_property(
            snapshot,
            ObjectKind::Index,
            "hash_accounts",
            Some("hash_accounts_pkey"),
            "yugabytedb_storage_backed",
            MetadataValue::Boolean(false),
        );
        assert_property(
            snapshot,
            ObjectKind::Table,
            "range_events",
            None,
            "yugabytedb_num_hash_key_columns",
            MetadataValue::Integer(0),
        );
        assert_property(
            snapshot,
            ObjectKind::Table,
            "range_events",
            None,
            "yugabytedb_range_split_clause",
            MetadataValue::String("SPLIT AT VALUES ((10), (20))".to_owned()),
        );
        assert_property(
            snapshot,
            ObjectKind::MaterializedView,
            "account_totals",
            None,
            "yugabytedb_storage_backed",
            MetadataValue::Boolean(true),
        );
        assert_property(
            snapshot,
            ObjectKind::Sequence,
            "audit_number",
            None,
            "yugabytedb_storage_backed",
            MetadataValue::Boolean(false),
        );
        assert_property(
            snapshot,
            ObjectKind::Database,
            &certified.snapshot.schema.database.name,
            None,
            "yugabytedb_database_colocated",
            MetadataValue::Boolean(false),
        );

        assert!(snapshot.metadata.objects.iter().any(|object| {
            object.extension_kind.as_deref() == Some("yugabytedb_tablespace")
                && object.name == "pg_default"
        }));
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind
                == MetadataRelationshipKind::Extension("yugabytedb_uses_tablespace".to_owned())
                && relationship.from_key.object_name == "hash_accounts"
        }));
        for kind in [
            ObjectKind::MaterializedView,
            ObjectKind::Sequence,
            ObjectKind::RoutineParameter,
            ObjectKind::UserDefinedType,
            ObjectKind::Domain,
            ObjectKind::EnumValue,
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
        assert!(snapshot
            .schema
            .constraints
            .iter()
            .any(|constraint| { constraint.name == "bookings_account_id_fkey" }));
        assert!(certified
            .completeness
            .capability_checks
            .iter()
            .any(|check| { check.name == "yugabytedb_distributed_metadata" }));
        assert!(certified
            .completeness
            .capability_checks
            .iter()
            .any(|check| { check.name == "yugabytedb_placement_metadata" }));
    }

    #[test]
    fn opaque_yugabytedb_routine_fails_instead_of_claiming_complete_dependencies() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_URL") else {
            return;
        };
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

        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "yb-opaque",
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
    fn colocated_yugabytedb_database_preserves_tablegroup_membership() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_COLOCATED_URL")
        else {
            return;
        };
        let schema = unique_schema("colocated");
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "
                CREATE SCHEMA {schema};
                CREATE TABLE {schema}.colocated_accounts (
                    id bigint PRIMARY KEY,
                    email text NOT NULL
                );
                CREATE INDEX colocated_accounts_email_idx
                    ON {schema}.colocated_accounts(email);
                "
            ))
            .unwrap();

        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "yb-colocated",
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
        assert_property(
            snapshot,
            ObjectKind::Database,
            &snapshot.schema.database.name,
            None,
            "yugabytedb_database_colocated",
            MetadataValue::Boolean(true),
        );
        assert_property(
            snapshot,
            ObjectKind::Table,
            "colocated_accounts",
            None,
            "yugabytedb_is_colocated",
            MetadataValue::Boolean(true),
        );
        assert!(snapshot.metadata.objects.iter().any(|object| {
            object.extension_kind.as_deref() == Some("yugabytedb_tablegroup")
                && object.name == "default"
        }));
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind
                == MetadataRelationshipKind::Extension("yugabytedb_member_of_tablegroup".to_owned())
                && relationship.from_key.object_name == "colocated_accounts"
        }));
    }

    #[test]
    fn yugabytedb_tablespace_placement_is_linked_to_its_relations() {
        let Ok(connection_string) = std::env::var("DATABASE_MEMORY_TEST_YUGABYTE_URL") else {
            return;
        };
        let schema = unique_schema("placement");
        let tablespace = unique_schema("tablespace");
        let mut client = Client::connect(&connection_string, NoTls).unwrap();
        client
            .batch_execute(&format!(
                "CREATE TABLESPACE {tablespace} WITH (
                    replica_placement='{{\"num_replicas\":1,\"placement_blocks\":[{{\"cloud\":\"cloud1\",\"region\":\"datacenter1\",\"zone\":\"rack1\",\"min_num_replicas\":1}}]}}'
                );"
            ))
            .unwrap();
        client
            .batch_execute(&format!(
                "
                CREATE SCHEMA {schema};
                CREATE TABLE {schema}.placed_records (
                    id bigint PRIMARY KEY,
                    payload text
                ) TABLESPACE {tablespace};
                "
            ))
            .unwrap();

        let outcome = introspect_yugabytedb_complete_scoped(
            &connection_string,
            "yb-placement",
            vec![schema.clone()],
            30_000,
        );
        let failure = outcome.failure().cloned();
        let certified = outcome.certified_snapshot().cloned();
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .unwrap();
        client
            .batch_execute(&format!("DROP TABLESPACE {tablespace};"))
            .unwrap();

        assert_eq!(outcome.status(), AnalysisStatus::Complete, "{failure:?}");
        let snapshot = &certified.unwrap().snapshot;
        assert_property(
            snapshot,
            ObjectKind::Table,
            "placed_records",
            None,
            "yugabytedb_effective_tablespace",
            MetadataValue::String(tablespace.clone()),
        );
        let tablespace_object = snapshot
            .metadata
            .objects
            .iter()
            .find(|object| {
                object.extension_kind.as_deref() == Some("yugabytedb_tablespace")
                    && object.name == tablespace
            })
            .expect("custom YugabyteDB tablespace metadata");
        assert!(matches!(
            tablespace_object.properties.get("placement_options"),
            Some(MetadataValue::StringList(options))
                if options.iter().any(|option| option.starts_with("replica_placement="))
        ));
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.kind
                == MetadataRelationshipKind::Extension("yugabytedb_uses_tablespace".to_owned())
                && relationship.from_key.object_name == "placed_records"
                && relationship.to_key == tablespace_object.key
        }));
    }

    fn assert_property(
        snapshot: &crate::canonical::CanonicalSchemaSnapshot,
        object_kind: ObjectKind,
        object_name: &str,
        sub_object: Option<&str>,
        property: &str,
        expected: MetadataValue,
    ) {
        let properties = snapshot
            .metadata
            .annotations
            .iter()
            .find(|annotation| {
                annotation.object_key.object_kind == object_kind
                    && annotation.object_key.object_name == object_name
                    && annotation.object_key.sub_object.as_deref() == sub_object
            })
            .map(|annotation| &annotation.properties)
            .or_else(|| {
                snapshot
                    .metadata
                    .objects
                    .iter()
                    .find(|object| {
                        object.key.object_kind == object_kind
                            && object.key.object_name == object_name
                            && object.key.sub_object.as_deref() == sub_object
                    })
                    .map(|object| &object.properties)
            })
            .unwrap_or_else(|| {
                panic!("missing annotation for {object_kind}:{object_name}:{sub_object:?}")
            });
        assert_eq!(properties.get(property), Some(&expected));
    }

    fn unique_schema(label: &str) -> String {
        format!(
            "database_memory_yb_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}
