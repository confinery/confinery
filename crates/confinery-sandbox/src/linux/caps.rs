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
    pub fn apply(&self) -> std::io::Result<()> {
        // Ambient caps never survive a least-privilege sandbox.
        let _ = caps::clear(None, CapSet::Ambient);

        // Shrink the bounding set so kept caps cannot be re-acquired via exec.
        for cap in caps::all() {
            if !self.keep.contains(&cap) {
                let _ = caps::drop(None, CapSet::Bounding, cap);
            }
        }

        if self.keep.is_empty() {
            let _ = caps::clear(None, CapSet::Inheritable);
            let _ = caps::clear(None, CapSet::Effective);
            let _ = caps::clear(None, CapSet::Permitted);
            return Ok(());
        }

        // Retain only the kept capabilities in the remaining sets.
        let keep = self.keep.clone();
        set_exactly(CapSet::Inheritable, &keep);
        set_exactly(CapSet::Permitted, &keep);
        set_exactly(CapSet::Effective, &keep);
        for cap in &keep {
            let _ = caps::raise(None, CapSet::Ambient, *cap);
        }
        Ok(())
    }
}

fn set_exactly(set: CapSet, keep: &[Capability]) {
    if let Ok(current) = caps::read(None, set) {
        for cap in current {
            if !keep.contains(&cap) {
                let _ = caps::drop(None, set, cap);
            }
        }
    }
    for cap in keep {
        let _ = caps::raise(None, set, *cap);
    }
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
}
