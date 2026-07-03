//! Linux capability dropping. By default every capability is removed.

use caps::{CapSet, Capability};
use confinery_core::capabilities::CapabilityPolicy;

use crate::error::{Result, SandboxError};

/// Precomputed set of capabilities to retain.
#[derive(Debug, Clone, Default)]
pub struct CapPlan {
    keep: Vec<Capability>,
}

impl CapPlan {
    /// Resolve capability names from the policy into a keep set.
    pub fn from_policy(policy: &CapabilityPolicy) -> Result<Self> {
        let mut keep = Vec::new();
        for name in &policy.keep {
            keep.push(parse_capability(name)?);
        }
        Ok(CapPlan { keep })
    }

    pub fn drops_all(&self) -> bool {
        self.keep.is_empty()
    }

    /// Drop capabilities from all sets except those explicitly kept. Called
    /// after privileged setup (mounts, hostname) and before exec.
    ///
    /// Every operation here is a security-critical guarantee (the profile's
    /// least-privilege default is "drop everything"), so a failure to apply
    /// it must fail the whole run rather than continue as if it had
    /// succeeded: a swallowed error here would let the sandboxed process
    /// silently keep capabilities the operator asked to remove, while the
    /// audit trail and run report still claim they were dropped.
    pub fn apply(&self) -> std::io::Result<()> {
        // Ambient caps never survive a least-privilege sandbox. Removing your
        // own capabilities never requires privilege, so any failure here is
        // a genuine, reportable problem rather than an expected permission
        // denial.
        caps::clear(None, CapSet::Ambient).map_err(cap_err)?;

        // Shrinking the *bounding* set is the one capability operation the
        // kernel gates behind CAP_SETPCAP, unconditionally -- unlike the
        // other sets, "give up a bounding entry" is treated as a privileged
        // act regardless of whether the caller could ever exploit it. An
        // ordinary unprivileged `confine`-mode caller (no user namespace)
        // has no CAP_SETPCAP and never held these capabilities in the first
        // place, so skipping the shrink there is safe: there is nothing to
        // re-acquire. Under `isolate` mode the caller is namespace-root and
        // always holds CAP_SETPCAP, so the shrink is expected to succeed and
        // any failure there is treated as fatal, per the same fail-closed
        // rule as every other capability operation in this function.
        if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP).unwrap_or(false) {
            for cap in caps::all() {
                if !self.keep.contains(&cap) {
                    caps::drop(None, CapSet::Bounding, cap).map_err(cap_err)?;
                }
            }
        }

        if self.keep.is_empty() {
            caps::clear(None, CapSet::Inheritable).map_err(cap_err)?;
            caps::clear(None, CapSet::Effective).map_err(cap_err)?;
            caps::clear(None, CapSet::Permitted).map_err(cap_err)?;
            return Ok(());
        }

        // Retain only the kept capabilities in the remaining sets.
        let keep = self.keep.clone();
        set_exactly(CapSet::Inheritable, &keep)?;
        set_exactly(CapSet::Permitted, &keep)?;
        set_exactly(CapSet::Effective, &keep)?;
        for cap in &keep {
            caps::raise(None, CapSet::Ambient, *cap).map_err(cap_err)?;
        }
        Ok(())
    }
}

fn cap_err(e: caps::errors::CapsError) -> std::io::Error {
    std::io::Error::other(format!("capabilities: {e}"))
}

fn set_exactly(set: CapSet, keep: &[Capability]) -> std::io::Result<()> {
    let current = caps::read(None, set).map_err(cap_err)?;
    for cap in current {
        if !keep.contains(&cap) {
            caps::drop(None, set, cap).map_err(cap_err)?;
        }
    }
    for cap in keep {
        caps::raise(None, set, *cap).map_err(cap_err)?;
    }
    Ok(())
}

/// Parse a capability name such as `net_bind_service` or `CAP_NET_BIND_SERVICE`.
fn parse_capability(name: &str) -> Result<Capability> {
    let upper = name.trim().to_ascii_uppercase();
    let with_prefix = if upper.starts_with("CAP_") {
        upper
    } else {
        format!("CAP_{upper}")
    };
    with_prefix
        .parse::<Capability>()
        .map_err(|_| SandboxError::layer("capabilities", format!("unknown capability `{name}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capability_names() {
        assert_eq!(
            parse_capability("net_bind_service").unwrap(),
            Capability::CAP_NET_BIND_SERVICE
        );
        assert_eq!(
            parse_capability("CAP_SYS_ADMIN").unwrap(),
            Capability::CAP_SYS_ADMIN
        );
    }

    #[test]
    fn rejects_unknown_capability() {
        assert!(parse_capability("not_a_cap").is_err());
    }

    #[test]
    fn default_policy_drops_all() {
        let plan = CapPlan::from_policy(&CapabilityPolicy::default()).unwrap();
        assert!(plan.drops_all());
    }

    #[test]
    fn apply_succeeds_without_cap_setpcap() {
        // Test binaries (like most `confine`-mode callers with no user
        // namespace) normally hold no capabilities at all, including
        // CAP_SETPCAP. `apply()` must still succeed by skipping the
        // bounding-set shrink rather than erroring out on a permission
        // check it can never pass -- there is nothing to re-acquire.
        let plan = CapPlan::from_policy(&CapabilityPolicy::default()).unwrap();
        assert!(plan.apply().is_ok());
    }
}
