pub mod adapters;
#[cfg(any(test, feature = "bench-support"))]
pub mod bench_support;
pub mod config;
pub mod ddl;
pub mod graph_builder;
pub mod graph_query;
pub mod graph_store;
pub mod impact_analysis;
pub mod redact;
pub mod relationship_trace;
pub mod schema_diff;

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const PRODUCT_BOUNDARY: &str = "RDB schema graph memory";

pub fn product_boundary() -> &'static str {
    PRODUCT_BOUNDARY
}

pub fn introspect_schema_source(
    source: &str,
    path: Option<&Path>,
    connection_string: Option<&str>,
    alias: &str,
) -> Result<SchemaSnapshot, String> {
    match source {
        "sqlite" => {
            let path = path.ok_or("missing path")?;
            adapters::sqlite::introspect_sqlite(path, alias).map_err(|err| err.to_string())
        }
        "ddl-sqlite" => {
            let path = path.ok_or("missing path")?;
            ddl::sqlite::introspect_sqlite_ddl(path, alias).map_err(|err| err.to_string())
        }
        "postgres" => {
            let connection_string = connection_string.ok_or("missing connection_string")?;
            adapters::postgres::introspect_postgres(connection_string, alias)
                .map_err(|err| redact::redact_error_with_connection_string(err, connection_string))
        }
        "mysql" => {
            let connection_string = connection_string.ok_or("missing connection_string")?;
            adapters::mysql::introspect_mysql(connection_string, alias)
                .map_err(|err| redact::redact_error_with_connection_string(err, connection_string))
        }
        "oracle" => {
            let connection_string = connection_string.ok_or("missing connection_string")?;
            adapters::oracle::introspect_oracle(connection_string, alias)
                .map_err(|err| redact::redact_error_with_connection_string(err, connection_string))
        }
        "sqlserver" => {
            let connection_string = connection_string.ok_or("missing connection_string")?;
            adapters::sqlserver::introspect_sqlserver(connection_string, alias)
                .map_err(|err| redact::redact_error_with_connection_string(err, connection_string))
        }
        unsupported_source => Err(format!(
            "source '{unsupported_source}' is not supported; supported sources: sqlite, ddl-sqlite, postgres, mysql, sqlserver, oracle"
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaSnapshot {
    pub source_kind: String,
    pub connection_alias: String,
    pub database: DatabaseObject,
    pub schemas: Vec<SchemaObject>,
    pub tables: Vec<TableObject>,
    pub columns: Vec<ColumnObject>,
    pub constraints: Vec<ConstraintObject>,
    pub indexes: Vec<IndexObject>,
    pub views: Vec<ViewObject>,
    pub triggers: Vec<TriggerObject>,
    pub routines: Vec<RoutineObject>,
    pub capabilities: AdapterCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey {
    pub source_kind: String,
    pub connection_alias: String,
    pub database: String,
    pub schema: String,
    pub object_kind: ObjectKind,
    pub object_name: String,
    pub sub_object: Option<String>,
}

impl ObjectKey {
    pub fn new(
        source_kind: impl Into<String>,
        connection_alias: impl Into<String>,
        database: impl Into<String>,
        schema: impl Into<String>,
        object_kind: ObjectKind,
        object_name: impl Into<String>,
        sub_object: Option<String>,
    ) -> Self {
        Self {
            source_kind: source_kind.into(),
            connection_alias: connection_alias.into(),
            database: database.into(),
            schema: schema.into(),
            object_kind,
            object_name: object_name.into(),
            sub_object,
        }
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}",
            self.source_kind,
            self.connection_alias,
            self.database,
            self.schema,
            self.object_kind,
            self.object_name
        )?;

        if let Some(sub_object) = &self.sub_object {
            write!(f, ":{sub_object}")?;
        }

        Ok(())
    }
}

impl FromStr for ObjectKey {
    type Err = ObjectKeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split(':').collect::<Vec<_>>();
        if !(parts.len() == 6 || parts.len() == 7) || parts.iter().any(|part| part.is_empty()) {
            return Err(ObjectKeyParseError);
        }

        Ok(Self {
            source_kind: parts[0].to_owned(),
            connection_alias: parts[1].to_owned(),
            database: parts[2].to_owned(),
            schema: parts[3].to_owned(),
            object_kind: parts[4].parse()?,
            object_name: parts[5].to_owned(),
            sub_object: parts.get(6).map(|part| (*part).to_owned()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Database,
    Schema,
    Table,
    Column,
    PrimaryKey,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Index,
    View,
    Trigger,
    Routine,
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "database",
            Self::Schema => "schema",
            Self::Table => "table",
            Self::Column => "column",
            Self::PrimaryKey => "primary_key",
            Self::ForeignKey => "foreign_key",
            Self::UniqueConstraint => "unique_constraint",
            Self::CheckConstraint => "check_constraint",
            Self::Index => "index",
            Self::View => "view",
            Self::Trigger => "trigger",
            Self::Routine => "routine",
        })
    }
}

impl FromStr for ObjectKind {
    type Err = ObjectKeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "database" => Ok(Self::Database),
            "schema" => Ok(Self::Schema),
            "table" => Ok(Self::Table),
            "column" => Ok(Self::Column),
            "primary_key" => Ok(Self::PrimaryKey),
            "foreign_key" => Ok(Self::ForeignKey),
            "unique_constraint" => Ok(Self::UniqueConstraint),
            "check_constraint" => Ok(Self::CheckConstraint),
            "index" => Ok(Self::Index),
            "view" => Ok(Self::View),
            "trigger" => Ok(Self::Trigger),
            "routine" => Ok(Self::Routine),
            _ => Err(ObjectKeyParseError),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectKeyParseError;

impl fmt::Display for ObjectKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid stable database object key")
    }
}

impl std::error::Error for ObjectKeyParseError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseObject {
    pub key: ObjectKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaObject {
    pub key: ObjectKey,
    pub database_key: ObjectKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableObject {
    pub key: ObjectKey,
    pub schema_key: ObjectKey,
    pub name: String,
    pub kind: TableKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    BaseTable,
    Temporary,
    Foreign,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnObject {
    pub key: ObjectKey,
    pub table_key: ObjectKey,
    pub name: String,
    pub ordinal_position: u32,
    pub data_type: String,
    pub is_nullable: bool,
    pub default_value: Option<String>,
    pub is_generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintObject {
    pub key: ObjectKey,
    pub table_key: ObjectKey,
    pub name: String,
    pub kind: ConstraintKind,
    pub columns: Vec<ObjectKey>,
    pub referenced_table_key: Option<ObjectKey>,
    pub referenced_columns: Vec<ObjectKey>,
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    PrimaryKey,
    ForeignKey,
    Unique,
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexObject {
    pub key: ObjectKey,
    pub table_key: ObjectKey,
    pub name: String,
    pub columns: Vec<ObjectKey>,
    pub is_unique: bool,
    pub is_primary: bool,
    pub predicate: Option<String>,
    pub expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewObject {
    pub key: ObjectKey,
    pub schema_key: ObjectKey,
    pub name: String,
    pub definition: Option<String>,
    pub depends_on: Vec<ObjectKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerObject {
    pub key: ObjectKey,
    pub table_key: ObjectKey,
    pub name: String,
    pub timing: Option<String>,
    pub events: Vec<String>,
    pub definition: Option<String>,
    pub executes_routine_key: Option<ObjectKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineObject {
    pub key: ObjectKey,
    pub schema_key: ObjectKey,
    pub name: String,
    pub kind: RoutineKind,
    pub definition: Option<String>,
    pub depends_on: Vec<ObjectKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutineKind {
    Function,
    Procedure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub source_kind: String,
    pub metadata_only: bool,
    pub schemas: bool,
    pub tables: bool,
    pub columns: bool,
    pub constraints: bool,
    pub indexes: bool,
    pub views: CapabilitySupport,
    pub triggers: CapabilitySupport,
    pub routines: CapabilitySupport,
    pub dependencies: CapabilitySupport,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    Partial,
    Unsupported,
    Unknown,
}

pub fn capability_warnings(capabilities: &AdapterCapabilities) -> Vec<String> {
    let mut warnings = Vec::new();
    push_capability_warning(
        &mut warnings,
        &capabilities.source_kind,
        "view dependency metadata",
        capabilities.views,
    );
    push_capability_warning(
        &mut warnings,
        &capabilities.source_kind,
        "trigger dependency metadata",
        capabilities.triggers,
    );
    push_capability_warning(
        &mut warnings,
        &capabilities.source_kind,
        "routine dependency metadata",
        capabilities.routines,
    );
    push_capability_warning(
        &mut warnings,
        &capabilities.source_kind,
        "cross-object dependency metadata",
        capabilities.dependencies,
    );
    warnings
}

fn push_capability_warning(
    warnings: &mut Vec<String>,
    source_kind: &str,
    capability: &str,
    support: CapabilitySupport,
) {
    match support {
        CapabilitySupport::Supported => {}
        CapabilitySupport::Partial => warnings.push(format!(
            "{capability} is partially tracked by the {source_kind} adapter."
        )),
        CapabilitySupport::Unsupported => warnings.push(format!(
            "{capability} is not tracked by the {source_kind} adapter."
        )),
        CapabilitySupport::Unknown => warnings.push(format!(
            "{capability} support is unknown for the {source_kind} adapter."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_boundary_stays_rdb_first() {
        assert_eq!("RDB schema graph memory", product_boundary());
    }

    #[test]
    fn adapter_sources_do_not_contain_obvious_row_selects() {
        let sources = [
            ("sqlite", include_str!("adapters/sqlite.rs")),
            ("postgres", include_str!("adapters/postgres.rs")),
            ("mysql", include_str!("adapters/mysql.rs")),
            ("sqlserver", include_str!("adapters/sqlserver.rs")),
            ("oracle", include_str!("adapters/oracle.rs")),
        ];

        for (name, source) in sources {
            let production_source = source
                .split("#[cfg(test)]")
                .next()
                .unwrap_or(source)
                .to_ascii_lowercase();
            assert!(
                !production_source.contains("select *"),
                "{name} adapter must not select all columns from live tables"
            );
            for pattern in ["from users", "from orders", "from {schema}", "from {table}"] {
                assert!(
                    !production_source.contains(pattern),
                    "{name} adapter contains a suspicious row-data select pattern: {pattern}"
                );
            }
        }

        assert!(
            !include_str!("graph_query.rs")
                .to_ascii_lowercase()
                .contains("select "),
            "graph_query must stay a JSON metadata filter, not SQL"
        );
    }

    #[test]
    fn stable_object_key_formats_and_parses() {
        let key = ObjectKey::new(
            "postgres",
            "prod",
            "app",
            "public",
            ObjectKind::Column,
            "users",
            Some("id".to_owned()),
        );

        let formatted = key.to_string();
        assert_eq!("postgres:prod:app:public:column:users:id", formatted);
        assert_eq!(key, formatted.parse::<ObjectKey>().unwrap());
        assert!("postgres:prod:app:public:unknown:users"
            .parse::<ObjectKey>()
            .is_err());
    }
}
