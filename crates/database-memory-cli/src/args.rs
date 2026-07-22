use std::path::{Path, PathBuf};

use database_memory_core::config::{
    default_config_path as default_config_file_path, load_optional_config, DatabaseMemoryConfig,
    ResolvedConnectionProfile,
};
use database_memory_core::impact_analysis::Direction;
use database_memory_core::interface_contract::{
    DEFAULT_OBJECT_PAGE_LIMIT, DEFAULT_RELATIONSHIP_LIMIT, DEFAULT_TIMEOUT_MS,
};
use database_memory_core::ObjectKind;

pub(crate) const DEFAULT_TRAVERSAL_DEPTH: u32 = 3;
pub(crate) const DEFAULT_RESULT_LIMIT: usize = 100;
pub(crate) const MAX_TRAVERSAL_DEPTH: u32 = 8;
pub(crate) const MAX_RESULT_LIMIT: usize = 200;
pub(crate) const DEFAULT_INVENTORY_LIMIT: usize = 1_000;
pub(crate) const MAX_INVENTORY_TABLES: usize = 5_000;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Contract {
        format: OutputFormat,
    },
    Index {
        source: String,
        path: Option<PathBuf>,
        connection_string: Option<String>,
        alias: String,
        requested_catalogs: Vec<String>,
        requested_schemas: Vec<String>,
        timeout_ms: u64,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    ListSnapshots {
        format: OutputFormat,
        cache_path: PathBuf,
    },
    DescribeSnapshot {
        selector: String,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    ListObjects {
        selector: String,
        kind: Option<ObjectKind>,
        offset: usize,
        limit: usize,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    FindObjects {
        selector: String,
        query: String,
        kind: Option<ObjectKind>,
        offset: usize,
        limit: usize,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    DescribeObject {
        selector: String,
        object_key: String,
        relationship_limit: usize,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    DescribeTable {
        alias: String,
        object_key: Option<String>,
        table_name: Option<String>,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    Inventory {
        alias: String,
        offset: usize,
        limit: usize,
        cache_path: PathBuf,
    },
    FindTable {
        alias: String,
        query: String,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    FindColumn {
        alias: String,
        query: String,
        format: OutputFormat,
        cache_path: PathBuf,
    },
    ImpactAnalysis {
        alias: String,
        object_key: Option<String>,
        table_name: Option<String>,
        column_name: Option<String>,
        direction: Direction,
        max_depth: u32,
        limit: usize,
        cache_path: PathBuf,
    },
    TraceRelationships {
        alias: String,
        object_key: String,
        direction: Direction,
        max_depth: u32,
        limit: usize,
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
        Some("contract") => parse_contract_args(args),
        Some("index") => parse_index_args(args, &config_loader),
        Some("list-snapshots") => parse_list_snapshots_args(args),
        Some("describe-snapshot") => parse_describe_snapshot_args(args, &config_loader),
        Some(command @ ("list-objects" | "find-objects" | "describe-object")) => {
            parse_object_command(command, args, &config_loader)
        }
        Some("describe-table") => parse_describe_table_args(args, &config_loader),
        Some("inventory") => parse_inventory_args(args, &config_loader),
        Some("find-table") => parse_find_args("find-table", args, &config_loader),
        Some("find-column") => parse_find_args("find-column", args, &config_loader),
        Some("impact-analysis") => parse_traversal_args("impact-analysis", args, &config_loader),
        Some("trace-relationships") => {
            parse_traversal_args("trace-relationships", args, &config_loader)
        }
        Some(command) => Err(format!("unknown command '{command}'")),
        None => Err(usage().to_owned()),
    }
}

fn parse_inventory_args(
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut alias = None;
    let mut offset = 0;
    let mut limit = DEFAULT_INVENTORY_LIMIT;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => {}
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                if parse_format(&value)? != OutputFormat::Json {
                    return Err("inventory supports JSON output only".to_owned());
                }
            }
            "--limit" => {
                let value = args.next().ok_or("missing value for --limit")?;
                limit = value
                    .parse()
                    .map_err(|_| format!("invalid inventory limit '{value}'"))?;
                if limit == 0 {
                    return Err("inventory limit must be at least 1".to_owned());
                }
            }
            "--offset" => {
                let value = args.next().ok_or("missing value for --offset")?;
                offset = value
                    .parse()
                    .map_err(|_| format!("invalid inventory offset '{value}'"))?;
            }
            "--cache-path" => {
                cache_path = Some(PathBuf::from(
                    args.next().ok_or("missing value for --cache-path")?,
                ));
            }
            "--config-path" => {
                config_path = Some(PathBuf::from(
                    args.next().ok_or("missing value for --config-path")?,
                ));
            }
            _ if arg.starts_with("--") => {
                return Err(format!("unknown inventory flag '{arg}'"));
            }
            _ if alias.is_none() => alias = Some(arg),
            _ => return Err(inventory_usage().to_owned()),
        }
    }

    let alias = alias.ok_or_else(|| inventory_usage().to_owned())?;
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(Some(&alias), &config_path, config_loader);
    Ok(Command::Inventory {
        alias,
        offset,
        limit,
        cache_path: cache_path
            .or_else(|| profile.and_then(|profile| profile.cache_path))
            .unwrap_or_else(default_cache_path),
    })
}

fn parse_contract_args(mut args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut format = OutputFormat::Text;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                format = parse_format(&value)?;
            }
            _ => return Err(format!("unknown contract flag '{arg}'")),
        }
    }
    Ok(Command::Contract { format })
}

fn parse_index_args(
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut source = None;
    let mut path = None;
    let mut alias = None;
    let mut connection_string = None;
    let mut requested_catalogs = Vec::new();
    let mut requested_schemas = Vec::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(flag) = args.next() {
        if flag == "--json" {
            format = OutputFormat::Json;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--source" => source = Some(value),
            "--path" => path = Some(PathBuf::from(value)),
            "--connection-string" => connection_string = Some(value),
            "--alias" => alias = Some(value),
            "--catalog" => requested_catalogs.push(value),
            "--schema" => requested_schemas.push(value),
            "--timeout-ms" => {
                timeout_ms = value
                    .parse()
                    .map_err(|_| format!("invalid timeout '{value}'"))?;
            }
            "--format" => format = parse_format(&value)?,
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
        "postgres" | "yugabytedb" | "mysql" | "mariadb" | "sqlserver" | "oracle" | "odbc"
            if connection_string.is_none() =>
        {
            return Err("missing --connection-string".to_owned());
        }
        _ => {}
    }

    Ok(Command::Index {
        source,
        path,
        connection_string,
        alias: alias.ok_or("missing --alias")?,
        requested_catalogs,
        requested_schemas,
        timeout_ms,
        format,
        cache_path: cache_path
            .or_else(|| profile.and_then(|profile| profile.cache_path))
            .unwrap_or_else(default_cache_path),
    })
}

fn parse_list_snapshots_args(mut args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--format" => {
                format = parse_format(&args.next().ok_or("missing value for --format")?)?;
            }
            "--cache-path" => {
                cache_path = Some(PathBuf::from(
                    args.next().ok_or("missing value for --cache-path")?,
                ));
            }
            _ => return Err(format!("unknown list-snapshots flag '{arg}'")),
        }
    }
    Ok(Command::ListSnapshots {
        format,
        cache_path: cache_path.unwrap_or_else(default_cache_path),
    })
}

fn parse_describe_snapshot_args(
    args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let ParsedReadCommand {
        mut positionals,
        format,
        cache_path,
        ..
    } = parse_read_command_args("describe-snapshot", args, config_loader)?;
    if positionals.len() != 1 {
        return Err("usage: database-memory describe-snapshot <alias-or-snapshot-key> [--format text|json] [--cache-path <path>]".to_owned());
    }
    Ok(Command::DescribeSnapshot {
        selector: positionals.remove(0),
        format,
        cache_path,
    })
}

fn parse_object_command(
    command: &str,
    args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let ParsedReadCommand {
        mut positionals,
        kind,
        offset,
        limit,
        relationship_limit,
        format,
        cache_path,
    } = parse_read_command_args(command, args, config_loader)?;
    match command {
        "list-objects" if positionals.len() == 1 => Ok(Command::ListObjects {
            selector: positionals.remove(0),
            kind,
            offset,
            limit,
            format,
            cache_path,
        }),
        "find-objects" if positionals.len() == 2 => Ok(Command::FindObjects {
            selector: positionals.remove(0),
            query: positionals.remove(0),
            kind,
            offset,
            limit,
            format,
            cache_path,
        }),
        "describe-object" if positionals.len() == 2 && kind.is_none() => {
            Ok(Command::DescribeObject {
                selector: positionals.remove(0),
                object_key: positionals.remove(0),
                relationship_limit,
                format,
                cache_path,
            })
        }
        "list-objects" => Err("usage: database-memory list-objects <alias-or-snapshot-key> [--kind <object-kind>] [--offset <n>] [--limit <n>] [--format text|json] [--cache-path <path>]".to_owned()),
        "find-objects" => Err("usage: database-memory find-objects <alias-or-snapshot-key> <query> [--kind <object-kind>] [--offset <n>] [--limit <n>] [--format text|json] [--cache-path <path>]".to_owned()),
        "describe-object" => Err("usage: database-memory describe-object <alias-or-snapshot-key> <object-key> [--relationship-limit <n>] [--format text|json] [--cache-path <path>]".to_owned()),
        _ => unreachable!(),
    }
}

struct ParsedReadCommand {
    positionals: Vec<String>,
    kind: Option<ObjectKind>,
    offset: usize,
    limit: usize,
    relationship_limit: usize,
    format: OutputFormat,
    cache_path: PathBuf,
}

fn parse_read_command_args(
    command: &str,
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<ParsedReadCommand, String> {
    let mut positionals = Vec::new();
    let mut kind = None;
    let mut offset = 0;
    let mut limit = DEFAULT_OBJECT_PAGE_LIMIT;
    let mut relationship_limit = DEFAULT_RELATIONSHIP_LIMIT;
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    let mut config_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--format" => {
                format = parse_format(&args.next().ok_or("missing value for --format")?)?;
            }
            "--kind" if matches!(command, "list-objects" | "find-objects") => {
                let value = args.next().ok_or("missing value for --kind")?;
                kind = Some(value.parse().map_err(|_| {
                    format!("unknown object kind '{value}'; use a contract object kind")
                })?);
            }
            "--offset" if matches!(command, "list-objects" | "find-objects") => {
                let value = args.next().ok_or("missing value for --offset")?;
                offset = value
                    .parse()
                    .map_err(|_| format!("invalid object offset '{value}'"))?;
            }
            "--limit" if matches!(command, "list-objects" | "find-objects") => {
                let value = args.next().ok_or("missing value for --limit")?;
                limit = positive_usize("object limit", &value)?;
            }
            "--relationship-limit" if command == "describe-object" => {
                let value = args
                    .next()
                    .ok_or("missing value for --relationship-limit")?;
                relationship_limit = positive_usize("relationship limit", &value)?;
            }
            "--cache-path" => {
                cache_path = Some(PathBuf::from(
                    args.next().ok_or("missing value for --cache-path")?,
                ));
            }
            "--config-path" => {
                config_path = Some(PathBuf::from(
                    args.next().ok_or("missing value for --config-path")?,
                ));
            }
            _ if arg.starts_with("--") => return Err(format!("unknown {command} flag '{arg}'")),
            _ => positionals.push(arg),
        }
    }
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(
        positionals.first().map(String::as_str),
        &config_path,
        config_loader,
    );
    Ok(ParsedReadCommand {
        positionals,
        kind,
        offset,
        limit,
        relationship_limit,
        format,
        cache_path: cache_path
            .or_else(|| profile.and_then(|profile| profile.cache_path))
            .unwrap_or_else(default_cache_path),
    })
}

fn positive_usize(label: &str, value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {label} '{value}'"))?;
    if value == 0 {
        return Err(format!("{label} must be at least 1"));
    }
    Ok(value)
}

fn parse_describe_table_args(
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut positionals = Vec::new();
    let mut object_key = None;
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                format = parse_format(&value)?;
            }
            "--object-key" => {
                object_key = Some(args.next().ok_or("missing value for --object-key")?);
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

    if positionals.is_empty() || positionals.len() > 2 {
        return Err(describe_table_usage().to_owned());
    }

    let alias = positionals.remove(0);
    let table_name = positionals.pop();
    if object_key.is_some() == table_name.is_some() {
        return Err("pass one table selector: a positional table name or --object-key".to_owned());
    }
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(Some(&alias), &config_path, config_loader);

    Ok(Command::DescribeTable {
        alias,
        object_key,
        table_name,
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
    let mut format = OutputFormat::Text;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
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
            format,
            cache_path,
        }),
        "find-column" => Ok(Command::FindColumn {
            alias,
            query,
            format,
            cache_path,
        }),
        _ => unreachable!(),
    }
}

fn parse_traversal_args(
    command: &str,
    mut args: impl Iterator<Item = String>,
    config_loader: &impl Fn(&Path) -> Option<DatabaseMemoryConfig>,
) -> Result<Command, String> {
    let mut positionals = Vec::new();
    let mut object_key = None;
    let mut table_name = None;
    let mut column_name = None;
    let mut direction = Direction::Both;
    let mut max_depth = DEFAULT_TRAVERSAL_DEPTH;
    let mut limit = DEFAULT_RESULT_LIMIT;
    let mut cache_path = None;
    let mut config_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => {}
            "--format" => {
                let value = args.next().ok_or("missing value for --format")?;
                if parse_format(&value)? != OutputFormat::Json {
                    return Err(format!("{command} supports JSON output only"));
                }
            }
            "--object-key" => {
                object_key = Some(args.next().ok_or("missing value for --object-key")?);
            }
            "--table" if command == "impact-analysis" => {
                table_name = Some(args.next().ok_or("missing value for --table")?);
            }
            "--column" if command == "impact-analysis" => {
                column_name = Some(args.next().ok_or("missing value for --column")?);
            }
            "--direction" => {
                let value = args.next().ok_or("missing value for --direction")?;
                direction = parse_direction(&value)?;
            }
            "--max-depth" => {
                let value = args.next().ok_or("missing value for --max-depth")?;
                max_depth = value
                    .parse()
                    .map_err(|_| format!("invalid max depth '{value}'"))?;
            }
            "--limit" => {
                let value = args.next().ok_or("missing value for --limit")?;
                limit = value
                    .parse()
                    .map_err(|_| format!("invalid result limit '{value}'"))?;
                if limit == 0 {
                    return Err("result limit must be at least 1".to_owned());
                }
            }
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

    if positionals.is_empty() || positionals.len() > 2 {
        return Err(traversal_usage(command).to_owned());
    }

    let alias = positionals.remove(0);
    let positional_selector = positionals.pop();
    let config_path = config_path.unwrap_or_else(default_config_file_path);
    let profile = profile_for_alias(Some(&alias), &config_path, config_loader);
    let cache_path = cache_path
        .or_else(|| profile.and_then(|profile| profile.cache_path))
        .unwrap_or_else(default_cache_path);

    match command {
        "impact-analysis" => {
            if positional_selector.is_some() && (object_key.is_some() || table_name.is_some()) {
                return Err(
                    "pass one impact target: a positional table, --table, or --object-key"
                        .to_owned(),
                );
            }
            if object_key.is_some() && (table_name.is_some() || column_name.is_some()) {
                return Err("--object-key cannot be combined with --table or --column".to_owned());
            }
            let table_name = table_name.or(positional_selector);
            if object_key.is_none() && table_name.is_none() {
                return Err(traversal_usage(command).to_owned());
            }
            if column_name.is_some() && table_name.is_none() {
                return Err("--column requires --table".to_owned());
            }
            Ok(Command::ImpactAnalysis {
                alias,
                object_key,
                table_name,
                column_name,
                direction,
                max_depth,
                limit,
                cache_path,
            })
        }
        "trace-relationships" => {
            if positional_selector.is_some() && object_key.is_some() {
                return Err("pass the start object key once".to_owned());
            }
            Ok(Command::TraceRelationships {
                alias,
                object_key: object_key
                    .or(positional_selector)
                    .ok_or_else(|| traversal_usage(command).to_owned())?,
                direction,
                max_depth,
                limit,
                cache_path,
            })
        }
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

fn parse_direction(value: &str) -> Result<Direction, String> {
    match value {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        "both" => Ok(Direction::Both),
        _ => Err(format!(
            "unknown direction '{value}'; expected inbound, outbound, or both"
        )),
    }
}

fn traversal_usage(command: &str) -> &'static str {
    match command {
        "impact-analysis" => "usage: database-memory impact-analysis <alias> [<table-name> | --table <name> [--column <name>] | --object-key <key>] [--direction inbound|outbound|both] [--max-depth <n>] [--limit <n>] [--cache-path <path>] [--config-path <path>]",
        "trace-relationships" => "usage: database-memory trace-relationships <alias> <object-key> [--direction inbound|outbound|both] [--max-depth <n>] [--limit <n>] [--cache-path <path>] [--config-path <path>]",
        _ => unreachable!(),
    }
}

fn describe_table_usage() -> &'static str {
    "usage: database-memory describe-table <alias> [<table-name> | --object-key <stable-key>] [--format text|json] [--cache-path <path>] [--config-path <path>]"
}

fn inventory_usage() -> &'static str {
    "usage: database-memory inventory <alias> [--offset <n>] [--limit <n>] [--format json] [--cache-path <path>] [--config-path <path>]"
}

fn usage() -> &'static str {
    "usage: database-memory contract [--format text|json]\n       database-memory index --source <source> (--path <path> | --connection-string <secret>) --alias <name> [--catalog <name>]... [--schema <name>]... [--timeout-ms <n>] [--format text|json] [--cache-path <path>] [--config-path <path>]
       database-memory list-snapshots [--format text|json] [--cache-path <path>]
       database-memory describe-snapshot <alias-or-snapshot-key> [--format text|json] [--cache-path <path>]
       database-memory list-objects <alias-or-snapshot-key> [--kind <object-kind>] [--offset <n>] [--limit <n>] [--format text|json] [--cache-path <path>]
       database-memory find-objects <alias-or-snapshot-key> <query> [--kind <object-kind>] [--offset <n>] [--limit <n>] [--format text|json] [--cache-path <path>]
       database-memory describe-object <alias-or-snapshot-key> <object-key> [--relationship-limit <n>] [--format text|json] [--cache-path <path>]
       database-memory describe-table <alias> [<table-name> | --object-key <stable-key>] [--format text|json] [--cache-path <path>] [--config-path <path>]
       database-memory inventory <alias> [--offset <n>] [--limit <n>] [--format json] [--cache-path <path>] [--config-path <path>]
       database-memory find-table <alias> <query> [--format text|json] [--cache-path <path>] [--config-path <path>]
       database-memory find-column <alias> <query> [--format text|json] [--cache-path <path>] [--config-path <path>]
       database-memory impact-analysis <alias> [<table-name> | --table <name> [--column <name>] | --object-key <key>] [--direction inbound|outbound|both] [--max-depth <n>] [--limit <n>] [--cache-path <path>] [--config-path <path>]
       database-memory trace-relationships <alias> <object-key> [--direction inbound|outbound|both] [--max-depth <n>] [--limit <n>] [--cache-path <path>] [--config-path <path>]"
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
                ["contract", "--format", "json"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .unwrap(),
            Command::Contract {
                format: OutputFormat::Json,
            }
        );

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
                requested_catalogs: vec![],
                requested_schemas: vec![],
                timeout_ms: DEFAULT_TIMEOUT_MS,
                format: OutputFormat::Text,
                cache_path: PathBuf::from(".database-memory").join("graph.sqlite"),
            }
        );

        assert_eq!(
            parse_args(
                [
                    "index",
                    "--source",
                    "yugabytedb",
                    "--connection-string",
                    "postgresql://yugabyte@localhost:5433/yugabyte",
                    "--alias",
                    "yb-local",
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::Index {
                source: "yugabytedb".to_owned(),
                path: None,
                connection_string: Some("postgresql://yugabyte@localhost:5433/yugabyte".to_owned()),
                alias: "yb-local".to_owned(),
                requested_catalogs: vec![],
                requested_schemas: vec![],
                timeout_ms: DEFAULT_TIMEOUT_MS,
                format: OutputFormat::Text,
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
                object_key: None,
                table_name: Some("orders".to_owned()),
                format: OutputFormat::Json,
                cache_path: PathBuf::from("cache.sqlite"),
            }
        );

        assert_eq!(
            parse_args(
                [
                    "describe-table",
                    "sample",
                    "--object-key",
                    "sqlite:sample:main:audit:table:orders"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::DescribeTable {
                alias: "sample".to_owned(),
                object_key: Some("sqlite:sample:main:audit:table:orders".to_owned()),
                table_name: None,
                format: OutputFormat::Text,
                cache_path: PathBuf::from(".database-memory").join("graph.sqlite"),
            }
        );

        assert!(parse_args(
            [
                "describe-table",
                "sample",
                "orders",
                "--object-key",
                "sqlite:sample:main:main:table:orders"
            ]
            .into_iter()
            .map(str::to_owned)
        )
        .unwrap_err()
        .contains("pass one table selector"));
    }

    #[test]
    fn parses_complete_scope_and_generic_object_commands() {
        assert_eq!(
            parse_args(
                [
                    "index",
                    "--source",
                    "sqlserver",
                    "--connection-string",
                    "Driver=SQL Server;Server=localhost",
                    "--alias",
                    "prod",
                    "--catalog",
                    "app",
                    "--schema",
                    "dbo",
                    "--timeout-ms",
                    "45000",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .unwrap(),
            Command::Index {
                source: "sqlserver".to_owned(),
                path: None,
                connection_string: Some("Driver=SQL Server;Server=localhost".to_owned()),
                alias: "prod".to_owned(),
                requested_catalogs: vec!["app".to_owned()],
                requested_schemas: vec!["dbo".to_owned()],
                timeout_ms: 45_000,
                format: OutputFormat::Text,
                cache_path: default_cache_path(),
            }
        );

        assert_eq!(
            parse_args(
                [
                    "find-objects",
                    "prod",
                    "account",
                    "--kind",
                    "table",
                    "--offset",
                    "10",
                    "--limit",
                    "25",
                    "--json",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .unwrap(),
            Command::FindObjects {
                selector: "prod".to_owned(),
                query: "account".to_owned(),
                kind: Some(ObjectKind::Table),
                offset: 10,
                limit: 25,
                format: OutputFormat::Json,
                cache_path: default_cache_path(),
            }
        );

        assert!(parse_args(
            ["list-objects", "prod", "--kind", "not-a-kind"]
                .into_iter()
                .map(str::to_owned)
        )
        .unwrap_err()
        .contains("unknown object kind"));
    }

    #[test]
    fn parses_bounded_json_traversal_commands() {
        assert_eq!(
            parse_args(
                [
                    "impact-analysis",
                    "ddl-sqlite:sample",
                    "--table",
                    "orders",
                    "--column",
                    "user_id",
                    "--direction",
                    "outbound",
                    "--max-depth",
                    "99",
                    "--limit",
                    "999",
                    "--format",
                    "json",
                    "--cache-path",
                    "cache.sqlite",
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::ImpactAnalysis {
                alias: "ddl-sqlite:sample".to_owned(),
                object_key: None,
                table_name: Some("orders".to_owned()),
                column_name: Some("user_id".to_owned()),
                direction: Direction::Outbound,
                max_depth: 99,
                limit: 999,
                cache_path: PathBuf::from("cache.sqlite"),
            }
        );

        assert_eq!(
            parse_args(
                [
                    "trace-relationships",
                    "sample",
                    "sqlite:sample:main:main:table:orders",
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::TraceRelationships {
                alias: "sample".to_owned(),
                object_key: "sqlite:sample:main:main:table:orders".to_owned(),
                direction: Direction::Both,
                max_depth: DEFAULT_TRAVERSAL_DEPTH,
                limit: DEFAULT_RESULT_LIMIT,
                cache_path: PathBuf::from(".database-memory").join("graph.sqlite"),
            }
        );

        assert!(parse_args(
            ["impact-analysis", "sample", "orders", "--format", "text"]
                .into_iter()
                .map(str::to_owned)
        )
        .unwrap_err()
        .contains("JSON output only"));
    }

    #[test]
    fn parses_json_inventory_and_rejects_invalid_limits() {
        assert_eq!(
            parse_args(
                [
                    "inventory",
                    "postgres:sample",
                    "--offset",
                    "1000",
                    "--limit",
                    "6000",
                    "--format",
                    "json",
                    "--cache-path",
                    "cache.sqlite",
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .unwrap(),
            Command::Inventory {
                alias: "postgres:sample".to_owned(),
                offset: 1_000,
                limit: 6_000,
                cache_path: PathBuf::from("cache.sqlite"),
            }
        );

        assert_eq!(
            parse_args(["inventory", "sample"].into_iter().map(str::to_owned)).unwrap(),
            Command::Inventory {
                alias: "sample".to_owned(),
                offset: 0,
                limit: DEFAULT_INVENTORY_LIMIT,
                cache_path: PathBuf::from(".database-memory").join("graph.sqlite"),
            }
        );
        assert!(parse_args(
            ["inventory", "sample", "--limit", "0"]
                .into_iter()
                .map(str::to_owned)
        )
        .unwrap_err()
        .contains("at least 1"));
        assert!(parse_args(
            ["inventory", "sample", "--format", "text"]
                .into_iter()
                .map(str::to_owned)
        )
        .unwrap_err()
        .contains("JSON output only"));
    }
}
