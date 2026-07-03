//! Compile a [`SyscallPolicy`] into an installable seccomp-BPF program.

use std::collections::BTreeMap;

use confinery_core::syscalls::{SeccompAction as PolicyAction, SyscallPolicy, SyscallPreset};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

use super::syscall_table;
use crate::error::{Result, SandboxError};

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Compile the policy into a BPF program, or `None` when seccomp is disabled.
pub fn compile(policy: &SyscallPolicy) -> Result<Option<BpfProgram>> {
    if !policy.enabled {
        return Ok(None);
    }

    let (rules, mismatch_action, match_action) = if policy.is_allowlist() {
        allowlist_rules(policy)?
    } else {
        denylist_rules(policy)?
    };

    let filter = SeccompFilter::new(rules, mismatch_action, match_action, TARGET_ARCH)
        .map_err(|e| SandboxError::layer("seccomp", format!("filter build failed: {e}")))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| SandboxError::layer("seccomp", format!("bpf conversion failed: {e}")))?;
    Ok(Some(program))
}

/// Install a compiled program on the current thread. Requires `no_new_privs`.
pub fn install(program: &BpfProgram) -> std::io::Result<()> {
    seccompiler::apply_filter(program)
        .map_err(|e| std::io::Error::other(format!("seccomp apply failed: {e}")))
}

type Rules = BTreeMap<i64, Vec<seccompiler::SeccompRule>>;

fn allowlist_rules(policy: &SyscallPolicy) -> Result<(Rules, SeccompAction, SeccompAction)> {
    let mut names: Vec<String> = Vec::new();
    match policy.preset {
        Some(SyscallPreset::Assistant) => {
            names.extend(syscall_table::ASSISTANT_ALLOW.iter().map(|s| s.to_string()))
        }
        Some(SyscallPreset::Minimal) => {
            names.extend(syscall_table::MINIMAL_ALLOW.iter().map(|s| s.to_string()))
        }
        // Hardened is a denylist preset; it contributes nothing to an allowlist.
        Some(SyscallPreset::Hardened) | None => {}
    }
    names.extend(policy.allow.iter().cloned());

    let mut rules: Rules = BTreeMap::new();
    for name in &names {
        if let Some(num) = syscall_table::resolve(name) {
            rules.entry(num).or_default();
        } else if policy.allow.contains(name) {
            // Explicit user entries must resolve; preset gaps are tolerated.
            return Err(SandboxError::UnknownSyscall(name.clone()));
        }
    }

    Ok((rules, action(policy.default), SeccompAction::Allow))
}

fn denylist_rules(policy: &SyscallPolicy) -> Result<(Rules, SeccompAction, SeccompAction)> {
    let mut names: Vec<String> = Vec::new();
    if matches!(policy.preset, Some(SyscallPreset::Hardened)) {
        names.extend(syscall_table::DANGEROUS.iter().map(|s| s.to_string()));
    }
    names.extend(policy.deny.iter().cloned());

    let mut rules: Rules = BTreeMap::new();
    for name in &names {
        match syscall_table::resolve(name) {
            Some(num) => {
                rules.entry(num).or_default();
            }
            None if policy.deny.contains(name) => {
                return Err(SandboxError::UnknownSyscall(name.clone()));
            }
            None => {}
        }
    }

    Ok((rules, SeccompAction::Allow, action(policy.block_action)))
}

fn action(a: PolicyAction) -> SeccompAction {
    match a {
        PolicyAction::Allow => SeccompAction::Allow,
        PolicyAction::Errno => SeccompAction::Errno(libc::EPERM as u32),
        PolicyAction::Kill => SeccompAction::KillProcess,
        PolicyAction::Log => SeccompAction::Log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_default_denylist() {
        let policy = SyscallPolicy::default();
        let prog = compile(&policy).unwrap();
        assert!(prog.is_some());
        assert!(!prog.unwrap().is_empty());
    }

    #[test]
    fn compiles_assistant_allowlist() {
        let policy = SyscallPolicy {
            default: PolicyAction::Errno,
            preset: Some(SyscallPreset::Assistant),
            ..Default::default()
        };
        let prog = compile(&policy).unwrap();
        assert!(prog.is_some());
    }

    #[test]
    fn disabled_policy_compiles_to_none() {
        let policy = SyscallPolicy {
            enabled: false,
            ..Default::default()
        };
        assert!(compile(&policy).unwrap().is_none());
    }

    #[test]
    fn unknown_user_syscall_is_rejected() {
        let policy = SyscallPolicy {
            deny: vec!["not_a_real_syscall".into()],
            ..Default::default()
        };
        assert!(matches!(
            compile(&policy),
            Err(SandboxError::UnknownSyscall(_))
        ));
    }
}
