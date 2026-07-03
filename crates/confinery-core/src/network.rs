//! Network access policy.

use serde::{Deserialize, Serialize};

/// How much network access the sandbox is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network at all (isolated network namespace, loopback down).
    #[default]
    None,
    /// Loopback only; no external routes.
    Loopback,
    /// Only the hosts listed in `allow` are reachable.
    Allowlist,
    /// Unrestricted host network (opt-in, least isolated).
    Full,
}

/// Network policy for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub mode: NetworkMode,

    /// `host:port` entries permitted when `mode = "allowlist"`.
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy {
            mode: NetworkMode::None,
            allow: Vec::new(),
        }
    }
}

impl NetworkPolicy {
    /// Whether the policy needs an isolated network namespace.
    pub fn wants_isolation(&self) -> bool {
        matches!(self.mode, NetworkMode::None | NetworkMode::Loopback)
    }
}
