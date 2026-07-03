//! Compile a [`SyscallPolicy`] into an installable seccomp-BPF program.

use std::collections::BTreeMap;

use confinery_core::syscalls::{SeccompAction as PolicyAction, SyscallPolicy, SyscallPreset};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

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
    guard_clone_against_new_user_namespace(&mut rules, true)?;

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
    guard_clone_against_new_user_namespace(&mut rules, false)?;

    Ok((rules, SeccompAction::Allow, action(policy.block_action)))
}

/// Block `clone(2)` calls that request `CLONE_NEWUSER`, i.e. creating a
/// nested user namespace, without disturbing ordinary thread/process
/// creation (which does not set that flag).
///
/// This is defense in depth, not a load-bearing boundary: every syscall a
/// nested namespace's "root" could actually abuse (`mount`, `pivot_root`,
/// `ptrace`, ...) is already blocked unconditionally by the `hardened`
/// denylist regardless of which namespace the caller sits in, since
/// seccomp filters apply to the syscall itself, not the caller's
/// capabilities. But nested unprivileged user namespaces are a
/// long-running source of *kernel* privilege-escalation bugs (extra code
/// paths reachable only with a fresh namespace's ambient capabilities), so
/// shrinking that surface further is worthwhile.
///
/// Deliberately does not attempt the same for `clone3(2)`: seccomp-BPF can
/// only compare raw syscall *arguments* (registers), and `clone3`'s flags
/// live inside a `struct clone_args` behind a pointer -- reading through
/// that pointer to filter on its contents is exactly what seccomp-BPF
/// cannot do. Blocking `clone3` outright would be safe today (glibc/musl
/// both still fall back to `clone` when it's unavailable) but is a
/// meaningfully different, coarser tradeoff than this targeted guard, so
/// it's left alone rather than folded in silently.
fn guard_clone_against_new_user_namespace(rules: &mut Rules, is_allowlist: bool) -> Result<()> {
    let Some(clone_num) = syscall_table::resolve("clone") else {
        return Ok(());
    };
    // Only add the guard where `clone` would otherwise be an unconditional
    // match (an empty rule list): if it already has conditions (not done by
    // this module today) or isn't present at all in denylist mode, leave it
    // alone rather than second-guess an existing, more specific rule.
    let should_guard = match rules.get(&clone_num) {
        Some(existing) => existing.is_empty(),
        None => !is_allowlist,
    };
    if !should_guard {
        return Ok(());
    }

    // MaskedEq(mask) matches when `argument & mask == value`. `value` is
    // the mask itself for "the bit is set", or 0 for "the bit is clear".
    let newuser_bit = u64::try_from(libc::CLONE_NEWUSER).unwrap_or(0);
    let match_value = if is_allowlist { 0 } else { newuser_bit };
    let condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(newuser_bit),
        match_value,
    )
    .map_err(|e| SandboxError::layer("seccomp", format!("clone guard condition: {e}")))?;
    let rule = SeccompRule::new(vec![condition])
        .map_err(|e| SandboxError::layer("seccomp", format!("clone guard rule: {e}")))?;
    rules.insert(clone_num, vec![rule]);
    Ok(())
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
