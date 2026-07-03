//! Seccomp syscall filtering policy.
//!
//! Two shapes are supported:
//!
//! * **Denylist** (`default = "allow"`): everything runs except a curated set
//!   of dangerous syscalls, which are blocked with `block_action`. Robust and
//!   rarely breaks ordinary programs. This is the default.
//! * **Allowlist** (`default = "errno"` or `"kill"`): only syscalls from the
//!   preset plus `allow` run; everything else gets the default action.
//!
//! Syscall names are resolved to numbers by the platform sandbox, so this
//! module deals only in names and presets.

use serde::{Deserialize, Serialize};

/// Action taken when a seccomp rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    /// Permit the syscall.
    Allow,
    /// Fail the syscall with `EPERM`.
    #[default]
    Errno,
    /// Kill the whole process (`SECCOMP_RET_KILL_PROCESS`).
    Kill,
    /// Log the syscall but permit it (useful for tuning allowlists).
    Log,
}

/// Named presets that expand to a curated list of syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallPreset {
    /// Curated denylist of dangerous syscalls (mount, ptrace, bpf, ...).
    Hardened,
    /// Allowlist sized for interpreters and build tools.
    Assistant,
    /// Minimal allowlist for simple, single-purpose programs.
    Minimal,
}

/// Seccomp policy for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallPolicy {
    /// Whether the filter is active at all.
    #[serde(default = "crate::default_true")]
    pub enabled: bool,

    /// Action for syscalls that match no rule. `Allow` selects denylist mode.
    #[serde(default = "default_default_action")]
    pub default: SeccompAction,

    /// Preset expanded into the rule set.
    #[serde(default = "default_preset")]
    pub preset: Option<SyscallPreset>,

    /// Extra syscalls to allow (added to the allowlist).
    #[serde(default)]
    pub allow: Vec<String>,

    /// Extra syscalls to block (added to the denylist).
    #[serde(default)]
    pub deny: Vec<String>,

    /// Action for blocked syscalls in denylist mode.
    #[serde(default = "default_block_action")]
    pub block_action: SeccompAction,
}

fn default_default_action() -> SeccompAction {
    SeccompAction::Allow
}

fn default_preset() -> Option<SyscallPreset> {
    Some(SyscallPreset::Hardened)
}

fn default_block_action() -> SeccompAction {
    SeccompAction::Errno
}

impl Default for SyscallPolicy {
    fn default() -> Self {
        SyscallPolicy {
            enabled: true,
            default: SeccompAction::Allow,
            preset: Some(SyscallPreset::Hardened),
            allow: Vec::new(),
            deny: Vec::new(),
            block_action: SeccompAction::Errno,
        }
    }
}

impl SyscallPolicy {
    /// True when the policy is an allowlist (default action blocks).
    pub fn is_allowlist(&self) -> bool {
        !matches!(self.default, SeccompAction::Allow)
    }
}
