//! Best-effort cgroups v2 resource control.
//!
//! Creating a child cgroup requires write access to the unified hierarchy,
//! which is available under root or a delegated (e.g. systemd user) slice.
//! When it is not, this layer reports itself as skipped and the rlimit layer
//! carries the load instead.

use std::io;
use std::path::{Path, PathBuf};

use confinery_core::resources::ResourceLimits;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Desired cgroup limits derived from the profile.
#[derive(Debug, Clone, Default)]
pub struct CgroupPlan {
    memory_max: Option<u64>,
    cpu_cores: Option<f64>,
    pids_max: Option<u32>,
}

impl CgroupPlan {
    pub fn from_limits(limits: &ResourceLimits) -> Self {
        CgroupPlan {
            memory_max: limits.memory.map(|m| m.bytes()),
            cpu_cores: limits.cpu,
            pids_max: limits.pids,
        }
    }

    fn is_empty(&self) -> bool {
        self.memory_max.is_none() && self.cpu_cores.is_none() && self.pids_max.is_none()
    }

    /// Create a dedicated cgroup and write the limits. Returns `Ok(None)` when
    /// the hierarchy is not writable (an expected, non-fatal condition).
    pub fn create(&self, id: &str) -> io::Result<Option<CgroupHandle>> {
        if self.is_empty() {
            return Ok(None);
        }
        let Some(base) = current_cgroup() else {
            return Ok(None);
        };
        let dir = base.join(format!("confinery-{id}"));

        // Enable controllers for children (best-effort; may be pre-delegated).
        let _ = std::fs::write(base.join("cgroup.subtree_control"), b"+memory +cpu +pids");

        if std::fs::create_dir(&dir).is_err() {
            return Ok(None);
        }

        if let Some(mem) = self.memory_max {
            let _ = std::fs::write(dir.join("memory.max"), mem.to_string());
            let _ = std::fs::write(dir.join("memory.swap.max"), b"0");
        }
        if let Some(cores) = self.cpu_cores {
            const PERIOD: u64 = 100_000;
            let quota = (cores * PERIOD as f64) as u64;
            let _ = std::fs::write(dir.join("cpu.max"), format!("{quota} {PERIOD}"));
        }
        if let Some(pids) = self.pids_max {
            let _ = std::fs::write(dir.join("pids.max"), pids.to_string());
        }

        Ok(Some(CgroupHandle { dir }))
    }
}

/// A live cgroup that processes can be attached to and cleaned up afterwards.
#[derive(Debug)]
pub struct CgroupHandle {
    dir: PathBuf,
}

impl CgroupHandle {
    /// Move a process into the cgroup so the limits take effect.
    pub fn add_process(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// Remove the cgroup. Only succeeds once every member process has exited.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Resolve the absolute path of the current process's cgroup v2 directory.
fn current_cgroup() -> Option<PathBuf> {
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
        return None;
    }
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // Unified hierarchy line looks like `0::/user.slice/...`.
    let rel = content
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_start_matches('/');
    Some(Path::new(CGROUP_ROOT).join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plan_creates_nothing() {
        let plan = CgroupPlan::default();
        assert!(plan.create("test").unwrap().is_none());
    }

    #[test]
    fn plan_from_defaults_has_limits() {
        let plan = CgroupPlan::from_limits(&ResourceLimits::default());
        assert!(!plan.is_empty());
        assert_eq!(plan.memory_max, Some(2 << 30));
        assert_eq!(plan.pids_max, Some(512));
    }
}
