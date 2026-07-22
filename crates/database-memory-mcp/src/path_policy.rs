use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

pub const ALLOWED_ROOTS_ENV: &str = "DATABASE_MEMORY_MCP_ALLOWED_ROOTS";
pub(crate) const DEFAULT_CACHE_PATH: &str = ".database-memory/graph.sqlite";

#[derive(Clone, Debug)]
pub(crate) struct McpPathPolicy {
    roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct McpPathError {
    pub code: &'static str,
    pub message: String,
    pub remediation: String,
}

impl McpPathError {
    fn configuration(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_path_policy",
            message: message.into(),
            remediation: format!(
                "set {ALLOWED_ROOTS_ENV} to existing trusted roots using the platform path separator"
            ),
        }
    }

    fn denied() -> Self {
        Self {
            code: "path_outside_allowed_roots",
            message: "requested local path is outside the MCP server's allowed roots".to_owned(),
            remediation: format!(
                "move the source/cache under an allowed root or update {ALLOWED_ROOTS_ENV} when starting the server"
            ),
        }
    }
}

impl fmt::Display for McpPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for McpPathError {}

impl McpPathPolicy {
    pub(crate) fn from_environment() -> Result<Self, McpPathError> {
        let roots = match std::env::var_os(ALLOWED_ROOTS_ENV) {
            Some(value) => std::env::split_paths(&value).collect::<Vec<_>>(),
            None => vec![std::env::current_dir().map_err(|error| {
                McpPathError::configuration(format!(
                    "could not resolve the MCP server working directory: {error}"
                ))
            })?],
        };

        #[cfg(test)]
        let roots = roots
            .into_iter()
            .chain([std::env::temp_dir()])
            .collect::<Vec<_>>();

        Self::new(roots)
    }

    pub(crate) fn new(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self, McpPathError> {
        let mut canonical_roots = roots
            .into_iter()
            .filter(|root| !root.as_os_str().is_empty())
            .map(|root| {
                std::fs::canonicalize(root).map_err(|error| {
                    McpPathError::configuration(format!(
                        "an MCP allowed root could not be resolved: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        canonical_roots.sort();
        canonical_roots.dedup();
        if canonical_roots.is_empty() {
            return Err(McpPathError::configuration(
                "the MCP path policy contains no usable roots",
            ));
        }
        Ok(Self {
            roots: canonical_roots,
        })
    }

    pub(crate) fn validate(&self, path: &Path) -> Result<(), McpPathError> {
        if path.as_os_str().is_empty() {
            return Err(McpPathError::denied());
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    McpPathError::configuration(format!(
                        "could not resolve the MCP server working directory: {error}"
                    ))
                })?
                .join(path)
        };
        let canonical = canonicalize_with_missing_tail(&absolute)?;
        if self.roots.iter().any(|root| canonical.starts_with(root)) {
            Ok(())
        } else {
            Err(McpPathError::denied())
        }
    }
}

fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf, McpPathError> {
    let mut cursor = path;
    let mut missing = Vec::<OsString>::new();
    loop {
        match std::fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = cursor.file_name().ok_or_else(McpPathError::denied)?;
                if component == "." || component == ".." {
                    return Err(McpPathError::denied());
                }
                missing.push(component.to_os_string());
                cursor = cursor.parent().ok_or_else(McpPathError::denied)?;
            }
            Err(error) => {
                return Err(McpPathError::configuration(format!(
                    "requested path could not be resolved safely: {error}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn policy_allows_missing_descendants_and_rejects_sibling_paths() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("database-memory-path-policy-{nonce}"));
        let allowed = base.join("allowed");
        let sibling = base.join("sibling");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let policy = McpPathPolicy::new([allowed.clone()]).unwrap();

        assert!(policy.validate(&allowed.join("new/cache.sqlite")).is_ok());
        assert_eq!(
            policy
                .validate(&sibling.join("cache.sqlite"))
                .unwrap_err()
                .code,
            "path_outside_allowed_roots"
        );

        std::fs::remove_dir(sibling).unwrap();
        std::fs::remove_dir(allowed).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
}
