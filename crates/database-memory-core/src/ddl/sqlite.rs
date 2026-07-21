use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::Connection;

use crate::adapters::sqlite::{introspect_sqlite_ddl_connection, SqliteAdapterError};
use crate::SchemaSnapshot;

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
    NoSqlFiles(PathBuf),
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
            Self::NoSqlFiles(path) => write!(f, "no .sql files found in '{}'", path.display()),
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
            Self::NoSqlFiles(_) => None,
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
    let conn = Connection::open_in_memory().map_err(|source| SqliteDdlSourceError::Apply {
        path: PathBuf::from(":memory:"),
        source,
    })?;
    conn.authorizer(Some(authorize_ddl));

    for file in sql_files(path)? {
        let sql = fs::read_to_string(&file).map_err(|source| SqliteDdlSourceError::Io {
            path: file.clone(),
            source,
        })?;
        conn.execute_batch(&sql)
            .map_err(|source| SqliteDdlSourceError::Apply { path: file, source })?;
    }
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

    introspect_sqlite_ddl_connection(&conn, connection_alias).map_err(SqliteDdlSourceError::from)
}

fn authorize_ddl(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Attach { .. } | AuthAction::Detach { .. } | AuthAction::Unknown { .. } => {
            Authorization::Deny
        }
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

        assert!(matches!(error, SqliteDdlSourceError::Apply { .. }));
        assert!(!attached.exists());
        let _ = fs::remove_dir_all(dir);
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
