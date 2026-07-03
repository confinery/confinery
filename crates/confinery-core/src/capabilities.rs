//! Linux capability policy. Capabilities are dropped by default.

use serde::{Deserialize, Serialize};

/// Which Linux capabilities survive into the sandboxed process.
///
/// The default is to drop everything. Names are the short kernel form without
/// the `CAP_` prefix, e.g. `net_bind_service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityPolicy {
    /// Capabilities to retain in the ambient and bounding sets.
    #[serde(default)]
    pub keep: Vec<String>,
}

impl CapabilityPolicy {
    pub fn drops_all(&self) -> bool {
        self.keep.is_empty()
    }
}

/// Canonical Linux capability names (without the `CAP_` prefix).
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

/// Whether `name` is a recognised capability (case-insensitive, optional
/// `cap_` prefix).
pub fn is_known(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let n = n.strip_prefix("cap_").unwrap_or(&n);
    KNOWN_CAPABILITIES.contains(&n)
}
