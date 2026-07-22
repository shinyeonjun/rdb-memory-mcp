use std::error::Error;
use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use super::sqlite_catalog::{
    analyze_sqlite_path, analyze_sqlite_path_with_cancellation, certify_discovery,
    discover_sqlite_connection,
};
use crate::analysis_outcome::AnalysisOutcome;
use crate::certification::{CertificationError, CertifiedSchemaSnapshot};
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

pub type SqliteAdapterResult<T> = Result<T, SqliteAdapterError>;

pub fn introspect_sqlite_complete(path: &Path, connection_alias: &str) -> AnalysisOutcome {
    analyze_sqlite_path(path, connection_alias)
}

pub fn introspect_sqlite_complete_with_cancellation(
    path: &Path,
    connection_alias: &str,
    cancellation: &CancellationToken,
) -> AnalysisOutcome {
    analyze_sqlite_path_with_cancellation(path, connection_alias, cancellation)
}

pub fn introspect_sqlite(
    path: &Path,
    connection_alias: &str,
) -> SqliteAdapterResult<SchemaSnapshot> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "query_only", true)?;
    discover_sqlite_connection(
        &conn,
        "sqlite",
        "sqlite",
        connection_alias,
        vec![
            "SQLite file opened read-only; only sqlite_schema and PRAGMA metadata were read."
                .to_owned(),
        ],
    )
    .map(|discovery| discovery.snapshot.schema)
}

pub(crate) fn introspect_sqlite_ddl_connection(
    conn: &Connection,
    connection_alias: &str,
) -> SqliteAdapterResult<SchemaSnapshot> {
    discover_sqlite_connection(
        conn,
        "ddl-sqlite",
        "sqlite",
        connection_alias,
        vec![
            "SQLite DDL source applies migration files to an isolated in-memory database, then reads catalog metadata only.".to_owned(),
        ],
    )
    .map(|discovery| discovery.snapshot.schema)
}

pub(crate) fn introspect_sqlite_ddl_connection_complete(
    conn: &Connection,
    connection_alias: &str,
) -> SqliteAdapterResult<CertifiedSchemaSnapshot> {
    let discovery = discover_sqlite_connection(
        conn,
        "ddl-sqlite",
        "sqlite",
        connection_alias,
        vec![
            "SQLite DDL source applies migration files to an isolated in-memory database, then reads catalog metadata only.".to_owned(),
        ],
    )?;
    certify_discovery(discovery).map_err(SqliteAdapterError::from)
}

#[derive(Debug)]
pub enum SqliteAdapterError {
    Storage(rusqlite::Error),
    Parse { object: String, message: String },
    Mapping { subject: String, message: String },
    Certification(CertificationError),
}

impl SqliteAdapterError {
    pub(crate) fn mapping(subject: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Mapping {
            subject: subject.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for SqliteAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "SQLite adapter storage error: {error}"),
            Self::Parse { object, message } => {
                write!(f, "failed to parse SQLite {object}: {message}")
            }
            Self::Mapping { subject, message } => {
                write!(f, "inconsistent SQLite metadata for {subject}: {message}")
            }
            Self::Certification(error) => write!(f, "SQLite certification failed: {error}"),
        }
    }
}

impl Error for SqliteAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Certification(error) => Some(error),
            Self::Parse { .. } | Self::Mapping { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteAdapterError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<CertificationError> for SqliteAdapterError {
    fn from(error: CertificationError) -> Self {
        Self::Certification(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::analysis_outcome::{AnalysisFailureCode, AnalysisStatus};
    use crate::canonical::MetadataRelationshipKind;
    use crate::graph_builder::insert_certified_schema_snapshot_graph;
    use crate::graph_store::GraphStore;
    use crate::impact_analysis::{impact_analysis, Direction};
    use crate::{CapabilitySupport, ConstraintKind, ObjectKind};

    #[test]
    fn default_and_certified_entrypoints_share_the_complete_mapper() {
        let path = sample_database_path();
        create_rich_database(&path);

        let legacy_shape = introspect_sqlite(&path, "sample").unwrap();
        assert!(legacy_shape.capabilities.limitations.is_empty());
        assert_eq!(
            legacy_shape.capabilities.dependencies,
            CapabilitySupport::Supported
        );
        assert!(legacy_shape.indexes.iter().any(|index| {
            index.name == "idx_accounts_email_search"
                && index.expression.as_deref() == Some("lower (email)")
                && index.predicate.as_deref() == Some("age >= 18")
        }));

        let outcome = introspect_sqlite_complete(&path, "sample");
        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{:?}",
            outcome.failure()
        );
        let certified = outcome.certified_snapshot().unwrap();
        assert!(certified
            .completeness
            .object_counts
            .iter()
            .all(|count| count.discovered == count.emitted));
        assert!(certified
            .completeness
            .relationship_counts
            .iter()
            .all(|count| count.discovered == count.emitted));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn complete_snapshot_preserves_constraints_view_columns_and_trigger_dependencies() {
        let path = sample_database_path();
        create_rich_database(&path);

        let outcome = introspect_sqlite_complete(&path, "rich");
        let snapshot = &outcome.certified_snapshot().unwrap().snapshot;

        assert!(snapshot.schema.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::Unique
                && constraint.name == "uq_accounts_email"
                && constraint.columns.len() == 2
        }));
        assert!(snapshot.schema.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::Check
                && constraint.name == "ck_accounts_age"
                && constraint.columns.len() == 2
        }));
        assert!(snapshot.schema.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::ForeignKey
                && constraint.name == "fk_sessions_account"
                && constraint.columns.len() == 2
                && constraint.referenced_columns.len() == 2
        }));
        assert!(snapshot.metadata.objects.iter().any(|object| {
            object.key.object_kind == ObjectKind::ViewColumn
                && object.key.object_name == "active_sessions"
                && object.name == "email"
        }));
        let trigger = snapshot
            .schema
            .triggers
            .iter()
            .find(|trigger| trigger.name == "trg_sessions_audit")
            .unwrap();
        assert!(snapshot.metadata.relationships.iter().any(|relationship| {
            relationship.from_key == trigger.key
                && relationship.to_key.object_name == "audit_log"
                && relationship.kind == MetadataRelationshipKind::DependsOn
        }));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn certified_graph_keeps_view_impact_reachable() {
        let path = sample_database_path();
        create_rich_database(&path);
        let outcome = introspect_sqlite_complete(&path, "impact");
        let certified = outcome.certified_snapshot().unwrap();
        let source_column = certified
            .snapshot
            .schema
            .columns
            .iter()
            .find(|column| column.table_key.object_name == "sessions" && column.name == "active")
            .unwrap();
        let store = GraphStore::in_memory().unwrap();
        insert_certified_schema_snapshot_graph(&store, "sqlite-impact", 1, certified).unwrap();

        let impact = impact_analysis(
            &store,
            "sqlite-impact",
            &source_column.key.to_string(),
            Direction::Inbound,
            1,
        )
        .unwrap();

        assert!(impact.groups.iter().any(|group| {
            group.label == "View"
                && group
                    .nodes
                    .iter()
                    .any(|node| node.display_name.as_deref() == Some("active_sessions"))
        }));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn application_rows_never_escape_and_broken_metadata_never_looks_complete() {
        let private_path = sample_database_path();
        let conn = Connection::open(&private_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE secrets(id INTEGER PRIMARY KEY, value TEXT);\
             INSERT INTO secrets(value) VALUES ('ROW_SECRET_MUST_NOT_ESCAPE');",
        )
        .unwrap();
        drop(conn);
        let private_outcome = introspect_sqlite_complete(&private_path, "privacy");
        assert_eq!(private_outcome.status(), AnalysisStatus::Complete);
        assert!(!serde_json::to_string(&private_outcome)
            .unwrap()
            .contains("ROW_SECRET_MUST_NOT_ESCAPE"));

        let broken_path = sample_database_path();
        let conn = Connection::open(&broken_path).unwrap();
        conn.execute_batch("CREATE VIEW broken AS SELECT id FROM missing_table;")
            .unwrap();
        drop(conn);
        let broken_outcome = introspect_sqlite_complete(&broken_path, "broken");
        assert_eq!(broken_outcome.status(), AnalysisStatus::Failed);
        assert!(matches!(
            broken_outcome.failure().unwrap().code,
            AnalysisFailureCode::MetadataQueryFailed | AnalysisFailureCode::MetadataMappingFailed
        ));

        let _ = fs::remove_file(private_path);
        let _ = fs::remove_file(broken_path);
    }

    #[test]
    fn missing_database_is_reported_as_a_connection_failure() {
        let path = sample_database_path();

        let outcome = introspect_sqlite_complete(&path, "missing");

        let failure = outcome.failure().unwrap();
        assert_eq!(failure.code, AnalysisFailureCode::ConnectionFailed);
        assert_eq!(
            failure.stage,
            crate::analysis_outcome::AnalysisStage::Connection
        );
    }

    #[test]
    fn live_virtual_and_shadow_tables_are_inventory_objects() {
        let path = sample_database_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE VIRTUAL TABLE docs USING fts5(title, body);")
            .unwrap();
        drop(conn);

        let outcome = introspect_sqlite_complete(&path, "virtual");
        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{:?}",
            outcome.failure()
        );
        let tables = &outcome.certified_snapshot().unwrap().snapshot.schema.tables;
        assert!(tables
            .iter()
            .any(|table| table.name == "docs" && table.kind == crate::TableKind::Virtual));
        assert!(tables
            .iter()
            .any(|table| table.kind == crate::TableKind::Shadow));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn nested_views_keep_direct_dependencies_instead_of_flattening_the_chain() {
        let path = sample_database_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE base(id INTEGER PRIMARY KEY, value TEXT);\
             CREATE VIEW first_view AS SELECT id, value FROM base;\
             CREATE VIEW second_view AS SELECT value FROM first_view;",
        )
        .unwrap();
        drop(conn);

        let outcome = introspect_sqlite_complete(&path, "views");
        assert_eq!(
            outcome.status(),
            AnalysisStatus::Complete,
            "{:?}",
            outcome.failure()
        );
        let views = &outcome.certified_snapshot().unwrap().snapshot.schema.views;
        let second = views
            .iter()
            .find(|view| view.name == "second_view")
            .unwrap();
        assert!(second
            .depends_on
            .iter()
            .any(|key| { key.object_kind == ObjectKind::View && key.object_name == "first_view" }));
        assert!(!second
            .depends_on
            .iter()
            .any(|key| key.object_kind == ObjectKind::Table && key.object_name == "base"));
        assert!(outcome
            .certified_snapshot()
            .unwrap()
            .snapshot
            .metadata
            .relationships
            .iter()
            .any(|relationship| {
                relationship.from_key == second.key
                    && relationship.to_key.object_kind == ObjectKind::ViewColumn
                    && relationship.to_key.object_name == "first_view"
                    && relationship.to_key.sub_object.as_deref() == Some("value")
            }));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn reserved_identifier_characters_keep_round_trip_stable_keys() {
        let path = sample_database_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(r#"CREATE TABLE "order:events" ("value:raw%text" TEXT);"#)
            .unwrap();
        drop(conn);

        let snapshot = introspect_sqlite(&path, "sample:west").unwrap();
        let table = snapshot
            .tables
            .iter()
            .find(|table| table.name == "order:events")
            .unwrap();
        let column = snapshot
            .columns
            .iter()
            .find(|column| column.name == "value:raw%text")
            .unwrap();
        assert_eq!(
            table.key.to_string(),
            "v2:sqlite:sample%3Awest:main:main:table:order%3Aevents"
        );
        assert_eq!(table.key, table.key.to_string().parse().unwrap());
        assert_eq!(column.key, column.key.to_string().parse().unwrap());
        let _ = fs::remove_file(path);
    }

    fn create_rich_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE accounts (
                id INTEGER,
                tenant_id TEXT,
                email TEXT COLLATE NOCASE,
                age INTEGER,
                email_key TEXT GENERATED ALWAYS AS (lower(email)) STORED,
                CONSTRAINT pk_accounts PRIMARY KEY (id, tenant_id),
                CONSTRAINT uq_accounts_email UNIQUE (tenant_id, email),
                CONSTRAINT ck_accounts_age CHECK (age >= 0 AND length(email) > 3)
            ) WITHOUT ROWID, STRICT;

            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY,
                account_id INTEGER,
                tenant_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                CONSTRAINT fk_sessions_account
                    FOREIGN KEY (account_id, tenant_id)
                    REFERENCES accounts(id, tenant_id)
                    ON UPDATE RESTRICT ON DELETE CASCADE
                    DEFERRABLE INITIALLY DEFERRED,
                CONSTRAINT ck_sessions_active CHECK (active IN (0, 1))
            ) STRICT;

            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                account_id INTEGER,
                action TEXT
            );

            CREATE UNIQUE INDEX idx_accounts_email_search
                ON accounts(lower(email) DESC, tenant_id)
                WHERE age >= 18;

            CREATE VIEW active_sessions AS
                SELECT s.id, a.email
                FROM sessions AS s
                JOIN accounts AS a
                  ON a.id = s.account_id AND a.tenant_id = s.tenant_id
                WHERE s.active = 1;

            CREATE TRIGGER trg_sessions_audit
                AFTER INSERT ON sessions
                WHEN NEW.active = 1
                BEGIN
                    INSERT INTO audit_log(account_id, action)
                    VALUES (NEW.account_id, 'created');
                END;
            "#,
        )
        .unwrap();
    }

    fn sample_database_path() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "database_memory_core_sqlite_adapter_{}_{}.sqlite",
            std::process::id(),
            suffix
        ))
    }
}
