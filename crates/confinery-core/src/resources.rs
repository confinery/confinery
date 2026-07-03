//! Resource limits applied through cgroups v2 and rlimits.

use serde::{Deserialize, Serialize};

use crate::units::{ByteSize, HumanDuration};

/// Bounds on CPU, memory, process count, and wall-clock time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Hard memory ceiling (cgroup `memory.max`).
    #[serde(default = "default_memory")]
    pub memory: Option<ByteSize>,

    /// CPU quota expressed in cores, e.g. `1.5` (cgroup `cpu.max`).
    #[serde(default)]
    pub cpu: Option<f64>,

    /// Maximum number of processes/threads (cgroup `pids.max`).
    #[serde(default = "default_pids")]
    pub pids: Option<u32>,

    /// Maximum open file descriptors (`RLIMIT_NOFILE`).
    #[serde(default = "default_open_files")]
    pub open_files: Option<u64>,

    /// Wall-clock timeout after which the sandbox is terminated.
    #[serde(default)]
    pub timeout: Option<HumanDuration>,

    /// Allow core dumps. Disabled by default to avoid leaking memory contents.
    #[serde(default)]
    pub core_dumps: bool,
}

fn default_memory() -> Option<ByteSize> {
    Some(ByteSize(2 << 30))
}

fn default_pids() -> Option<u32> {
    Some(512)
}

fn default_open_files() -> Option<u64> {
    Some(1024)
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            memory: default_memory(),
            cpu: None,
            pids: default_pids(),
            open_files: default_open_files(),
            timeout: None,
            core_dumps: false,
        }
    }
}
