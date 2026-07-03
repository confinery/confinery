//! Environment variable policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How the child process inherits environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnvMode {
    /// Inherit the full parent environment (least private).
    Passthrough,
    /// Inherit only the variables named in `allow`.
    #[default]
    Allowlist,
    /// Start from an empty environment.
    Clear,
}

/// Environment policy: an allowlist plus explicit overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvPolicy {
    #[serde(default)]
    pub mode: EnvMode,

    /// Variable names inherited when `mode = "allowlist"`.
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,

    /// Variables set (or overridden) unconditionally.
    #[serde(default)]
    pub set: BTreeMap<String, String>,
}

fn default_allow() -> Vec<String> {
    [
        "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for EnvPolicy {
    fn default() -> Self {
        EnvPolicy {
            mode: EnvMode::Allowlist,
            allow: default_allow(),
            set: BTreeMap::new(),
        }
    }
}
