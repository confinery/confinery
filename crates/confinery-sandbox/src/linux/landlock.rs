//! Landlock filesystem access control.
//!
//! Landlock enforces a path allowlist without requiring privileges, only
//! `no_new_privs`. It is best-effort: on kernels that lack it (or a given ABI
//! level) it degrades and reports partial or no enforcement rather than
//! failing the run. Under the namespace plan it complements mount isolation;
//! under the confine plan it is the primary filesystem boundary.

use std::path::{Path, PathBuf};

use confinery_core::filesystem::FilesystemPolicy;
use confinery_core::profile::{expand_home, resolve_relative};
use landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};

/// Landlock enforcement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockStatus {
    Enforced,
    Partial,
    Unsupported,
}

/// Resolved paths for a Landlock ruleset.
#[derive(Debug, Clone, Default)]
pub struct LandlockPlan {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
}

impl LandlockPlan {
    /// Build a plan from the filesystem policy, expanding `~` and resolving
    /// any still-relative path (e.g. `./`) against `workdir`.
    pub fn from_policy(policy: &FilesystemPolicy, home: &Path, workdir: &Path) -> Self {
        let expand = |p: &PathBuf| resolve_relative(&expand_home(p, home), workdir);
        let mut read_only: Vec<PathBuf> = policy.read_only.iter().map(expand).collect();
        // procfs and sysfs are needed by most runtimes for read access.
        read_only.push(PathBuf::from("/proc"));
        read_only.push(PathBuf::from("/sys"));

        let mut read_write: Vec<PathBuf> = policy.read_write.iter().map(expand).collect();
        // tmpfs mounts are writable scratch space; /dev nodes need read+write.
        read_write.extend(policy.tmpfs.iter().map(expand));
        if policy.minimal_dev {
            read_write.push(PathBuf::from("/dev"));
        }
        LandlockPlan {
            read_only,
            read_write,
        }
    }

    /// Apply the ruleset to the current thread.
    pub fn apply(&self) -> std::io::Result<LandlockStatus> {
        let abi = ABI::V2;
        let created = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create());

        let mut ruleset = match created {
            Ok(r) => r,
            Err(_) => return Ok(LandlockStatus::Unsupported),
        };

        for path in &self.read_only {
            ruleset = with_rule(ruleset, path, AccessFs::from_read(abi))?;
        }
        for path in &self.read_write {
            ruleset = with_rule(ruleset, path, AccessFs::from_all(abi))?;
        }

        match ruleset.restrict_self() {
            Ok(status) => Ok(match status.ruleset {
                RulesetStatus::FullyEnforced => LandlockStatus::Enforced,
                RulesetStatus::PartiallyEnforced => LandlockStatus::Partial,
                RulesetStatus::NotEnforced => LandlockStatus::Unsupported,
            }),
            Err(e) => Err(std::io::Error::other(format!(
                "landlock restrict failed: {e}"
            ))),
        }
    }
}

/// Add a path rule, skipping paths that do not exist on this host.
fn with_rule(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> std::io::Result<RulesetCreated> {
    match PathFd::new(path) {
        Ok(fd) => ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| std::io::Error::other(format!("landlock add_rule failed: {e}"))),
        Err(_) => Ok(ruleset),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_plan_with_expanded_home() {
        let policy = FilesystemPolicy {
            read_write: vec![PathBuf::from("~/work")],
            ..Default::default()
        };
        let plan = LandlockPlan::from_policy(&policy, Path::new("/home/u"), Path::new("/work"));
        assert!(plan.read_write.contains(&PathBuf::from("/home/u/work")));
        // tmpfs folded into writable set.
        assert!(plan.read_write.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn resolves_relative_paths_against_workdir() {
        let policy = FilesystemPolicy {
            read_write: vec![PathBuf::from("./")],
            ..Default::default()
        };
        let plan = LandlockPlan::from_policy(&policy, Path::new("/home/u"), Path::new("/proj"));
        assert!(
            plan.read_write.contains(&PathBuf::from("/proj/./")),
            "{:?}",
            plan.read_write
        );
    }
}
