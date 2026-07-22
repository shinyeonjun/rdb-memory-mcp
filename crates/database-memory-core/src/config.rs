use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = ".database-memory/config.toml";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct DatabaseMemoryConfig {
    pub profiles: BTreeMap<String, ConnectionProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionProfile {
    pub source: String,
    pub path: Option<PathBuf>,
    pub connection_string: Option<String>,
    pub cache_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConnectionProfile {
    pub source: String,
    pub path: Option<PathBuf>,
    pub connection_string: Option<String>,
    pub cache_path: Option<PathBuf>,
}

impl DatabaseMemoryConfig {
    pub fn profile(&self, alias: &str) -> Option<ResolvedConnectionProfile> {
        self.profiles
            .get(alias)
            .map(|profile| ResolvedConnectionProfile {
                source: profile.source.clone(),
                path: profile.path.as_ref().map(|path| {
                    std::env::var_os(path_env_var(alias))
                        .map(PathBuf::from)
                        .unwrap_or_else(|| path.clone())
                }),
                connection_string: std::env::var(connection_string_env_var(alias))
                    .ok()
                    .or_else(|| profile.connection_string.clone()),
                cache_path: profile.cache_path.clone(),
            })
    }
}

pub fn default_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

pub fn parse_config_toml(input: &str) -> Result<DatabaseMemoryConfig, toml::de::Error> {
    toml::from_str(input)
}

pub fn load_optional_config(
    path: impl AsRef<Path>,
) -> Result<Option<DatabaseMemoryConfig>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(input) => parse_config_toml(&input)
            .map(Some)
            .map_err(ConfigError::Toml),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(ConfigError::Io(err)),
    }
}

pub fn connection_string_env_var(alias: &str) -> String {
    format!(
        "DATABASE_MEMORY_{}_CONNECTION_STRING",
        sanitized_alias(alias)
    )
}

pub fn path_env_var(alias: &str) -> String {
    format!("DATABASE_MEMORY_{}_PATH", sanitized_alias(alias))
}

fn sanitized_alias(alias: &str) -> String {
    let sanitized = alias
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    sanitized
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Toml(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn config_parses_valid_toml_profiles() {
        let config = parse_config_toml(
            r#"
[app]
source = "sqlite"
path = "db/app.sqlite"
cache_path = ".database-memory/app.sqlite"

[reporting]
source = "sqlite"
path = "db/reporting.sqlite"
"#,
        )
        .unwrap();

        assert_eq!(config.profiles["app"].source, "sqlite");
        assert_eq!(
            config.profiles["app"].path,
            Some(PathBuf::from("db/app.sqlite"))
        );
        assert_eq!(
            config.profiles["app"].cache_path,
            Some(PathBuf::from(".database-memory/app.sqlite"))
        );
        assert_eq!(config.profiles["reporting"].cache_path, None);
    }

    #[test]
    fn config_rejects_query_fields_so_default_stays_metadata_only() {
        assert!(parse_config_toml(
            r#"
[app]
source = "sqlite"
path = "db/app.sqlite"
query = "select * from users"
"#
        )
        .is_err());

        assert!(parse_config_toml(
            r#"
[app]
source = "sqlite"
path = "db/app.sqlite"
sql = "select * from users"
"#
        )
        .is_err());
    }

    #[test]
    fn config_missing_file_returns_none() {
        let missing = std::env::temp_dir().join("database-memory-config-missing.toml");
        assert!(load_optional_config(missing).unwrap().is_none());
    }

    #[test]
    fn config_parses_postgres_connection_string() {
        let config = parse_config_toml(
            r#"
[warehouse]
source = "postgres"
connection_string = "postgres://user:pass@localhost/warehouse"
"#,
        )
        .unwrap();

        let profile = config.profile("warehouse").unwrap();
        assert_eq!(profile.path, None);
        assert_eq!(
            profile.connection_string,
            Some("postgres://user:pass@localhost/warehouse".to_owned())
        );
    }

    #[test]
    fn config_path_env_var_overrides_profile_path() {
        let alias = "phase13-env-test";
        let env_var = path_env_var(alias);
        std::env::set_var(&env_var, "override.sqlite");

        let config = parse_config_toml(
            r#"
[phase13-env-test]
source = "sqlite"
path = "db/app.sqlite"
"#,
        )
        .unwrap();

        let profile = config.profile(alias).unwrap();
        std::env::remove_var(env_var);

        assert_eq!(profile.path, Some(PathBuf::from("override.sqlite")));
    }

    #[test]
    fn config_connection_string_env_var_supplies_secret_without_persisting_it() {
        let alias = "security-env-secret-test";
        let env_var = connection_string_env_var(alias);
        std::env::set_var(&env_var, "postgresql://runtime-secret@localhost/app");

        let config = parse_config_toml(
            r#"
[security-env-secret-test]
source = "postgres"
"#,
        )
        .unwrap();

        let profile = config.profile(alias).unwrap();
        std::env::remove_var(env_var);

        assert_eq!(
            profile.connection_string,
            Some("postgresql://runtime-secret@localhost/app".to_owned())
        );
        assert!(!format!("{config:?}").contains("runtime-secret"));
    }
}
