use std::path::{Path, PathBuf};

use database_memory_core::config::{
    default_config_path as default_config_file_path, load_optional_config, DatabaseMemoryConfig,
    ResolvedConnectionProfile,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Index {
        source: String,
        path: Option<PathBuf>,
        connection_string: Option<String>,
        alias: String,
        cache_path: PathBuf,
    },
    DescribeTable {
        alias: String,
        table_name: String,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    FindTable {
        alias: String,
        query: String,
        cache_path: PathBuf,
    },
    FindColumn {
        alias: String,
        query: String,
        cache_path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

pub(crate) fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    parse_args_with_config(args, |path| load_optional_config(path).ok().flatten())
}

pub(crate) fn parse_args_with_config(
    args: impl IntoIterator<Item = String>,
    config_loader: impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("index") => parse_index_args(args, &config_loader),
        Some("describe-table") => parse_describe_table_args(args, &config_loader),
        Some("find-table") => parse_find_args("find-table", args, &config_loader),
        Some("find-column") => parse_find_args("find-column", args, &config_loader),
        Some(command) => Err(format!("unknown command '{command}'")),
        None => Err(usage().to_owned()),
    }
}

fn parse_index_args(
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut source = None;
    let mut path = None;
    let mut alias = None;
    let mut connection_string = None;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--source" => source = Some(value),
            "--path" => path = Some(PathBuf::from(value)),
            "--connection-string" => connection_string = Some(value),
            "--alias" => alias = Some(value),
            "--cache-path" => cache_path = Some(PathBuf::from(value)),
            "--config-path" => config_path = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown index flag '{flag}'")),
        }
    }

    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(alias.as_deref(), &config_path, config_loader);

    let source = source
        .or_else(|| profile.as_ref().map(|profile| profile.source.clone()))
        .ok_or("missing --source")?;
    let path = path.or_else(|| profile.as_ref().and_then(|profile| profile.path.clone()));
    let connection_string = connection_string.or_else(|| {
        profile
            .as_ref()
            .and_then(|profile| profile.connection_string.clone())
    });

    match source.as_str() {
        "sqlite" | "ddl-sqlite" if path.is_none() => return Err("missing --path".to_owned()),
        "postgres" | "mysql" | "sqlserver" | "oracle" if connection_string.is_none() => {
            return Err("missing --connection-string".to_owned());
        }
        _ => {}
    }

    Ok(Command::Index {
        source,
        path,
        connection_string,
        alias: alias.ok_or("missing --alias")?,
        cache_path: cache_path
            .or_else(|| profile.and_then(|profile| profile.cache_path))
            .unwrap_or_else(default_cache_path),
    })
}

fn parse_describe_table_args(
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut positionals = Vec::new();
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                format = parse_format(&value)?;
            }
            "--cache-path" => {
                let value = args.next().ok_or("missing value for --cache-path")?;
                cache_path = Some(PathBuf::from(value));
            }
            "--config-path" => {
                let value = args.next().ok_or("missing value for --config-path")?;
                config_path = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--") => {
                return Err(format!("unknown describe-table flag '{arg}'"));
            }
            _ => positionals.push(arg),
        }
    }

    if positionals.len() != 2 {
        return Err("usage: database-memory describe-table <alias> <table-name> [--format text|json] [--cache-path <path>] [--config-path <path>]".to_owned());
    }

    let alias = positionals.remove(0);
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(Some(&alias), &config_path, config_loader);

    Ok(Command::DescribeTable {
        alias,
        table_name: positionals.remove(0),
        format,
        cache_path: cache_path
            .or_else(|| profile.and_then(|profile| profile.cache_path))
            .unwrap_or_else(default_cache_path),
    })
}

fn parse_find_args(
    command: &str,
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut positionals = Vec::new();
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cache-path" => {
                let value = args.next().ok_or("missing value for --cache-path")?;
                cache_path = Some(PathBuf::from(value));
            }
            "--config-path" => {
                let value = args.next().ok_or("missing value for --config-path")?;
                config_path = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--") => return Err(format!("unknown {command} flag '{arg}'")),
            _ => positionals.push(arg),
        }
    }

    if positionals.len() != 2 {
        return Err(format!(
            "usage: database-memory {command} <alias> <query> [--cache-path <path>] [--config-path <path>]"
        ));
    }

    let alias = positionals.remove(0);
    let query = positionals.remove(0);
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(Some(&alias), &config_path, config_loader);
    let cache_path = cache_path
        .or_else(|| profile.and_then(|profile| profile.cache_path))
        .unwrap_or_else(default_cache_path);
    match command {
        "find-table" => Ok(Command::FindTable {
            alias,
            query,
            cache_path,
        }),
        "find-column" => Ok(Command::FindColumn {
            alias,
            query,
            cache_path,
        }),
        _ => unreachable!(),
    }
}

fn profile_for_alias(
    alias: Option<&str>,
    config_path: &Path,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Option<ResolvedConnectionProfile> {
    alias.and_then(|alias| config_loader(config_path).and_then(|config| config.profile(alias)))
}

fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(format!("unknown format '{value}'; expected text or json")),
    }
}

fn usage() -> &'static str {
    "usage: database-memory index --source sqlite --path <db> --alias <name> [--cache-path <path>] [--config-path <path>]\n       database-memory index --source ddl-sqlite --path <sql-file-or-dir> --alias <name> [--cache-path <path>]
       database-memory index --source postgres --connection-string <url> --alias <name> [--cache-path <path>]
       database-memory index --source mysql --connection-string <url> --alias <name> [--cache-path <path>]
       database-memory index --source sqlserver --connection-string <ado-connection-string> --alias <name> [--cache-path <path>]
       database-memory index --source oracle --connection-string <user/password@connect_string> --alias <name> [--cache-path <path>]
       database-memory describe-table <alias> <table-name> [--format text|json] [--cache-path <path>] [--config-path <path>]
       database-memory find-table <alias> <query> [--cache-path <path>] [--config-path <path>]
       database-memory find-column <alias> <query> [--cache-path <path>] [--config-path <path>]"
}

fn default_cache_path() -> PathBuf {
    PathBuf::from(".database-memory").join("graph.sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_index_and_describe_commands() {
        assert_eq!(
            parse_args(
                [
                    "index",
                    "--source",
                    "sqlite",
                    "--path",
                    "sample.sqlite",
                    "--alias",
                    "sample"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::Index {
                source: "sqlite".to_owned(),
                path: Some(PathBuf::from("sample.sqlite")),
                connection_string: None,
                alias: "sample".to_owned(),
                cache_path: PathBuf::from(".database-memory").join("graph.sqlite"),
            }
        );

        assert_eq!(
            parse_args(
                [
                    "describe-table",
                    "sample",
                    "orders",
                    "--format",
                    "json",
                    "--cache-path",
                    "cache.sqlite"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::DescribeTable {
                alias: "sample".to_owned(),
                table_name: "orders".to_owned(),
                format: OutputFormat::Json,
                cache_path: PathBuf::from("cache.sqlite"),
            }
        );
    }
}
