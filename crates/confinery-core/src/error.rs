//! Errors returned by the core profile and policy layer.

use std::path::PathBuf;

/// Result alias used throughout `confinery-core`.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors produced while loading, parsing, or validating profiles.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("failed to read profile `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse TOML profile: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("failed to parse JSON profile: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unknown profile format for `{0}` (expected .toml or .json)")]
    UnknownFormat(PathBuf),

    #[error("invalid value for `{field}`: {message}")]
    Invalid { field: String, message: String },

    #[error("profile failed validation with {errors} error(s)")]
    Validation { errors: usize },

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl CoreError {
    /// Convenience constructor for field validation failures.
    pub fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        CoreError::Invalid {
            field: field.into(),
            message: message.into(),
        }
    }
}
