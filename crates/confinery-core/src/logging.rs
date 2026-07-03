//! Structured logging setup built on `tracing`.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tracing_subscriber::filter::EnvFilter;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Compact, human-readable lines.
    #[default]
    Human,
    /// One JSON object per line.
    Json,
}

impl FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" | "pretty" => Ok(LogFormat::Human),
            "json" => Ok(LogFormat::Json),
            other => Err(format!("unknown log format `{other}`")),
        }
    }
}

/// Initialise the global tracing subscriber.
///
/// `level` seeds the filter when `RUST_LOG` is not set. Safe to call once at
/// startup; subsequent calls are ignored by the subscriber.
pub fn init(format: LogFormat, level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);

    match format {
        LogFormat::Json => {
            let _ = builder.json().try_init();
        }
        LogFormat::Human => {
            let _ = builder.with_target(false).try_init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats() {
        assert_eq!(LogFormat::from_str("json").unwrap(), LogFormat::Json);
        assert_eq!(LogFormat::from_str("human").unwrap(), LogFormat::Human);
        assert!(LogFormat::from_str("xml").is_err());
    }
}
