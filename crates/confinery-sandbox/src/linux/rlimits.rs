//! Resource limits applied via `setrlimit` in the child before exec.
//!
//! Memory and process caps are primarily enforced by cgroups v2; the rlimits
//! here are a portable second line of defence that also works when cgroup
//! delegation is unavailable.

use confinery_core::resources::ResourceLimits;
use nix::sys::resource::{setrlimit, Resource};

/// Precomputed rlimit values, safe to move into the pre-exec closure.
#[derive(Debug, Clone, Default)]
pub struct RlimitPlan {
    nofile: Option<u64>,
    core: u64,
    nproc: Option<u64>,
}

impl RlimitPlan {
    pub fn from_limits(limits: &ResourceLimits) -> Self {
        RlimitPlan {
            nofile: limits.open_files,
            core: if limits.core_dumps { u64::MAX } else { 0 },
            nproc: limits.pids.map(u64::from),
        }
    }

    /// Apply the limits. Fd and core limits are enforced strictly; the process
    /// limit is best-effort because it is counted per-uid and may already be
    /// exceeded on a busy host.
    pub fn apply(&self) -> std::io::Result<()> {
        if let Some(nofile) = self.nofile {
            setrlimit(Resource::RLIMIT_NOFILE, nofile, nofile).map_err(std::io::Error::from)?;
        }
        setrlimit(Resource::RLIMIT_CORE, self.core, self.core).map_err(std::io::Error::from)?;
        if let Some(nproc) = self.nproc {
            let _ = setrlimit(Resource::RLIMIT_NPROC, nproc, nproc);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_plan_from_defaults() {
        let plan = RlimitPlan::from_limits(&ResourceLimits::default());
        assert_eq!(plan.nofile, Some(1024));
        assert_eq!(plan.core, 0);
        assert_eq!(plan.nproc, Some(512));
    }

    #[test]
    fn core_dumps_toggle() {
        let limits = ResourceLimits {
            core_dumps: true,
            ..Default::default()
        };
        assert_eq!(RlimitPlan::from_limits(&limits).core, u64::MAX);
    }
}
