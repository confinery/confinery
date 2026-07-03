//! Filesystem exposure policy: deny-by-default with explicit allowlists.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Controls which host paths are visible inside the sandbox and how.
///
/// The model is deny-by-default: only paths listed here are exposed. `deny`
/// masks sensitive locations even when a parent directory is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths mounted read-only (and executable).
    #[serde(default = "default_read_only")]
    pub read_only: Vec<PathBuf>,

    /// Paths the sandbox may modify.
    #[serde(default)]
    pub read_write: Vec<PathBuf>,

    /// Paths backed by a fresh in-memory tmpfs.
    #[serde(default = "default_tmpfs")]
    pub tmpfs: Vec<PathBuf>,

    /// Paths masked with an empty mount even if a parent is allowed.
    #[serde(default = "default_deny")]
    pub deny: Vec<PathBuf>,

    /// Expose a minimal `/dev` (null, zero, full, random, urandom, tty).
    #[serde(default = "crate::default_true")]
    pub minimal_dev: bool,
}

fn default_read_only() -> Vec<PathBuf> {
    [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/resolv.conf",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

fn default_tmpfs() -> Vec<PathBuf> {
    vec![PathBuf::from("/tmp")]
}

fn default_deny() -> Vec<PathBuf> {
    [
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "~/.config/gh",
        "~/.kube",
        "~/.docker/config.json",
        "/etc/shadow",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        FilesystemPolicy {
            read_only: default_read_only(),
            read_write: Vec::new(),
            tmpfs: default_tmpfs(),
            deny: default_deny(),
            minimal_dev: true,
        }
    }
}
