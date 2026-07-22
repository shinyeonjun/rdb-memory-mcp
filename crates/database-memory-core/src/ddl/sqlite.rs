use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::Connection;

use crate::adapters::sqlite::{
    introspect_sqlite_ddl_connection, introspect_sqlite_ddl_connection_complete, SqliteAdapterError,
};
use crate::adapters::sqlite_sql::validate_schema_ddl;
use crate::certification::CertifiedSchemaSnapshot;
use crate::introspection::CancellationToken;
use crate::SchemaSnapshot;

const DEFAULT_DDL_TIMEOUT_MS: u64 = 30_000;
const MAX_DDL_BYTES: u64 = 64 * 1024 * 1024;

pub type SqliteDdlSourceResult<T> = Result<T, SqliteDdlSourceError>;

#[derive(Debug)]
pub enum SqliteDdlSourceError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Apply {
        path: PathBuf,
        source: rusqlite::Error,
    },
    InvalidStatement {
        path: PathBuf,
        message: String,
    },
    NoSqlFiles(PathBuf),
    InputTooLarge {
        path: PathBuf,
        bytes: u64,
    },
    Timeout(PathBuf),
    Cancelled(PathBuf),
    Adapter(SqliteAdapterError),
}

impl fmt::Display for SqliteDdlSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read '{}': {source}", path.display()),
            Self::Apply { path, source } => {
                write!(
                    f,
                    "failed to apply SQLite DDL '{}': {source}",
                    path.display()
                )
            }
            Self::InvalidStatement { path, message } => write!(
                f,
                "unsafe or unsupported SQLite DDL '{}': {message}",
                path.display()
            ),
            Self::NoSqlFiles(path) => write!(f, "no .sql files found in '{}'", path.display()),
            Self::InputTooLarge { path, bytes } => write!(
                f,
                "SQLite DDL input '{}' is {bytes} bytes; the bounded limit is {MAX_DDL_BYTES} bytes",
                path.display()
            ),
            Self::Timeout(path) => write!(
                f,
                "SQLite DDL analysis exceeded its deadline while processing '{}'",
                path.display()
            ),
            Self::Cancelled(path) => write!(
                f,
                "SQLite DDL analysis was cancelled while processing '{}'",
                path.display()
            ),
            Self::Adapter(source) => {
                write!(f, "failed to introspect SQLite DDL snapshot: {source}")
            }
        }
    }
}

impl Error for SqliteDdlSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Apply { source, .. } => Some(source),
            Self::InvalidStatement { .. }
            | Self::NoSqlFiles(_)
            | Self::InputTooLarge { .. }
            | Self::Timeout(_)
            | Self::Cancelled(_) => None,
            Self::Adapter(source) => Some(source),
        }
    }
}

impl From<SqliteAdapterError> for SqliteDdlSourceError {
    fn from(source: SqliteAdapterError) -> Self {
        Self::Adapter(source)
    }
}

pub fn introspect_sqlite_ddl(
    path: &Path,
    connection_alias: &str,
) -> SqliteDdlSourceResult<SchemaSnapshot> {
    let cancellation = CancellationToken::new();
    let deadline = deadline(DEFAULT_DDL_TIMEOUT_MS);
    let conn = load_ddl_connection(path, deadline, &cancellation)?;
    introspect_sqlite_ddl_connection(&conn, connection_alias).map_err(SqliteDdlSourceError::from)
}

pub fn introspect_sqlite_ddl_complete(
    path: &Path,
    connection_alias: &str,
) -> SqliteDdlSourceResult<CertifiedSchemaSnapshot> {
    introspect_sqlite_ddl_complete_bounded(
        path,
        connection_alias,
        DEFAULT_DDL_TIMEOUT_MS,
        &CancellationToken::new(),
    )
}

pub fn introspect_sqlite_ddl_complete_bounded(
    path: &Path,
    connection_alias: &str,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> SqliteDdlSourceResult<CertifiedSchemaSnapshot> {
    let deadline = deadline(timeout_ms);
    let conn = load_ddl_connection(path, deadline, cancellation)?;
    checkpoint(path, deadline, cancellation)?;
    match introspect_sqlite_ddl_connection_complete(&conn, connection_alias) {
        Ok(snapshot) => {
            checkpoint(path, deadline, cancellation)?;
            conn.progress_handler(0, None::<fn() -> bool>);
            Ok(snapshot)
        }
        Err(_) if cancellation.is_cancelled() => {
            Err(SqliteDdlSourceError::Cancelled(path.to_path_buf()))
        }
        Err(_) if Instant::now() >= deadline => {
            Err(SqliteDdlSourceError::Timeout(path.to_path_buf()))
        }
        Err(error) => Err(SqliteDdlSourceError::Adapter(error)),
    }
}

fn load_ddl_connection(
    path: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> SqliteDdlSourceResult<Connection> {
    checkpoint(path, deadline, cancellation)?;
    let conn = Connection::open_in_memory().map_err(|source| SqliteDdlSourceError::Apply {
        path: PathBuf::from(":memory:"),
        source,
    })?;
    conn.authorizer(Some(authorize_ddl));
    let progress_cancellation = cancellation.clone();
    conn.progress_handler(
        1_000,
        Some(move || progress_cancellation.is_cancelled() || Instant::now() >= deadline),
    );

    let mut total_bytes = 0_u64;
    for file in sql_files(path)? {
        checkpoint(&file, deadline, cancellation)?;
        let source = fs::File::open(&file).map_err(|source| SqliteDdlSourceError::Io {
            path: file.clone(),
            source,
        })?;
        let bytes = source
            .metadata()
            .map_err(|source| SqliteDdlSourceError::Io {
                path: file.clone(),
                source,
            })?
            .len();
        let remaining = MAX_DDL_BYTES.saturating_sub(total_bytes);
        if bytes > remaining {
            return Err(SqliteDdlSourceError::InputTooLarge {
                path: file,
                bytes: total_bytes.saturating_add(bytes),
            });
        }
        let mut sql = String::with_capacity(usize::try_from(bytes).unwrap_or(usize::MAX));
        let bytes_read = source
            .take(remaining.saturating_add(1))
            .read_to_string(&mut sql)
            .map_err(|source| SqliteDdlSourceError::Io {
                path: file.clone(),
                source,
            })? as u64;
        total_bytes = total_bytes.saturating_add(bytes_read);
        if total_bytes > MAX_DDL_BYTES {
            return Err(SqliteDdlSourceError::InputTooLarge {
                path: file,
                bytes: total_bytes,
            });
        }
        checkpoint(&file, deadline, cancellation)?;
        validate_schema_ddl(&sql).map_err(|message| SqliteDdlSourceError::InvalidStatement {
            path: file.clone(),
            message,
        })?;
        match conn.execute_batch(&sql) {
            Ok(()) => {}
            Err(_) if cancellation.is_cancelled() => {
                return Err(SqliteDdlSourceError::Cancelled(file));
            }
            Err(_) if Instant::now() >= deadline => {
                return Err(SqliteDdlSourceError::Timeout(file));
            }
            Err(source) => return Err(SqliteDdlSourceError::Apply { path: file, source }),
        }
    }
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    Ok(conn)
}

fn deadline(timeout_ms: u64) -> Instant {
    Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .unwrap_or_else(Instant::now)
}

fn checkpoint(
    path: &Path,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> SqliteDdlSourceResult<()> {
    if cancellation.is_cancelled() {
        return Err(SqliteDdlSourceError::Cancelled(path.to_path_buf()));
    }
    if Instant::now() >= deadline {
        return Err(SqliteDdlSourceError::Timeout(path.to_path_buf()));
    }
    Ok(())
}

fn authorize_ddl(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Attach { .. }
        | AuthAction::Detach { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropVtable { .. }
        | AuthAction::CreateTempIndex { .. }
        | AuthAction::CreateTempTable { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        | AuthAction::DropTempIndex { .. }
        | AuthAction::DropTempTable { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::DropTempView { .. }
        | AuthAction::Unknown { .. } => Authorization::Deny,
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }
}

fn sql_files(path: &Path) -> SqliteDdlSourceResult<Vec<PathBuf>> {
    let metadata = fs::metadata(path).map_err(|source| SqliteDdlSourceError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|source| SqliteDdlSourceError::Io {
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| SqliteDdlSourceError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        if entry_path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
        {
            files.push(entry_path);
        }
    }

    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    if files.is_empty() {
        return Err(SqliteDdlSourceError::NoSqlFiles(path.to_path_buf()));
    }
    Ok(files)
}

#[cfg(test)]
mod ddl_source_tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::adapters::sqlite::introspect_sqlite;
    use crate::graph_builder::insert_schema_snapshot_graph;
    use crate::graph_store::GraphStore;
    use crate::schema_diff::schema_diff;
    use crate::{ConstraintKind, ObjectKind};

    #[test]
    fn sqlite_ddl_directory_builds_schema_snapshot_in_filename_order() {
        let dir = sample_dir("snapshot");
        write_migrations(&dir);

        let snapshot = introspect_sqlite_ddl(&dir, "app").unwrap();

        assert_eq!(snapshot.source_kind, "ddl-sqlite");
        assert!(snapshot.tables.iter().any(|table| table.name == "users"));
        assert!(snapshot
            .columns
            .iter()
            .any(|column| column.name == "email" && column.ordinal_position == 2));
        assert!(snapshot.constraints.iter().any(|constraint| {
            constraint.kind == ConstraintKind::PrimaryKey && constraint.name == "pk_users"
        }));
        assert!(snapshot.indexes.iter().any(|index| {
            index.name == "idx_users_email"
                && index.key.source_kind == "sqlite"
                && index.key.object_kind == ObjectKind::Index
        }));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sqlite_ddl_directory_produces_a_certified_complete_snapshot() {
        let dir = sample_dir("complete");
        write_migrations(&dir);

        let certified = introspect_sqlite_ddl_complete(&dir, "app").unwrap();

        assert_eq!(certified.snapshot.schema.source_kind, "ddl-sqlite");
        assert!(certified
            .snapshot
            .schema
            .capabilities
            .limitations
            .is_empty());
        assert_eq!(
            certified.snapshot.schema.capabilities.dependencies,
            crate::CapabilitySupport::Supported
        );
        assert!(certified
            .completeness
            .object_counts
            .iter()
            .all(|count| count.discovered == count.emitted));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_ddl_analysis_honors_deadline_and_cancellation_before_work() {
        let dir = sample_dir("bounded");
        write_migrations(&dir);

        let timed_out =
            introspect_sqlite_ddl_complete_bounded(&dir, "app", 0, &CancellationToken::new())
                .unwrap_err();
        assert!(matches!(timed_out, SqliteDdlSourceError::Timeout(_)));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled =
            introspect_sqlite_ddl_complete_bounded(&dir, "app", 30_000, &cancellation).unwrap_err();
        assert!(matches!(cancelled, SqliteDdlSourceError::Cancelled(_)));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sqlite_ddl_snapshot_diffs_cleanly_against_live_sqlite_snapshot() {
        let dir = sample_dir("diff");
        write_migrations(&dir);
        let db_path = sample_db_path();
        create_live_database(&db_path);

        let live = introspect_sqlite(&db_path, "app").unwrap();
        let ddl = introspect_sqlite_ddl(&dir, "app").unwrap();
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, "sqlite:app", 0, &live).unwrap();
        insert_schema_snapshot_graph(&store, "ddl-sqlite:app", 1, &ddl).unwrap();

        let diff = schema_diff(&store, "sqlite:app", "ddl-sqlite:app").unwrap();

        assert!(diff.added_nodes.is_empty());
        assert!(diff.removed_nodes.is_empty());
        assert!(diff.changed_nodes.is_empty());
        assert!(diff.added_edges.is_empty());
        assert!(diff.removed_edges.is_empty());

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn sqlite_ddl_rejects_external_database_attachment() {
        let dir = sample_dir("attach-denied");
        fs::create_dir_all(&dir).unwrap();
        let attached = dir.join("outside.sqlite");
        fs::write(
            dir.join("001_schema.sql"),
            format!(
                "ATTACH DATABASE '{}' AS outside; CREATE TABLE outside.users(id INTEGER);",
                attached.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();

        let error = introspect_sqlite_ddl(&dir, "app").unwrap_err();

        assert!(matches!(
            error,
            SqliteDdlSourceError::InvalidStatement { .. }
        ));
        assert!(!attached.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sqlite_ddl_rejects_application_rows_and_virtual_table_modules() {
        for (name, sql) in [
            (
                "insert",
                "CREATE TABLE users(id INTEGER); INSERT INTO users VALUES (1);",
            ),
            (
                "select",
                "CREATE TABLE users(id INTEGER); SELECT * FROM users;",
            ),
            ("virtual", "CREATE VIRTUAL TABLE docs USING fts5(body);"),
        ] {
            let dir = sample_dir(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("001_schema.sql"), sql).unwrap();

            let error = introspect_sqlite_ddl(&dir, "app").unwrap_err();

            assert!(matches!(
                error,
                SqliteDdlSourceError::InvalidStatement { .. }
            ));
            let _ = fs::remove_dir_all(dir);
        }
    }

    fn write_migrations(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("001_init.sql"),
            "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY
            );
            ",
        )
        .unwrap();
        fs::write(
            dir.join("002_add_column.sql"),
            "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';",
        )
        .unwrap();
        fs::write(
            dir.join("003_add_index.sql"),
            "CREATE INDEX idx_users_email ON users(email);",
        )
        .unwrap();
    }

    fn create_live_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY
            );
            ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
            CREATE INDEX idx_users_email ON users(email);
            ",
        )
        .unwrap();
    }

    fn sample_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "database_memory_core_sqlite_ddl_{name}_{}_{}",
            std::process::id(),
            suffix
        ))
    }

    fn sample_db_path() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "database_memory_core_sqlite_ddl_live_{}_{}.sqlite",
            std::process::id(),
            suffix
        ))
    }
}
