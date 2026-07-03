//! Static validation of profiles: catches mistakes before a sandbox is built.

use std::fmt;

use crate::capabilities;
use crate::network::NetworkMode;
use crate::profile::Profile;
use crate::syscalls::SeccompAction;

/// Matches the cgroup `cpu.max` period the Linux backend uses
/// (linux/cgroups.rs's `PERIOD` constant, in microseconds).
const CGROUP_CPU_PERIOD_US: f64 = 100_000.0;

/// Severity of a validation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => f.write_str("error"),
            Severity::Warning => f.write_str("warning"),
        }
    }
}

/// A single validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] {}: {}",
            self.severity, self.code, self.field, self.message
        )
    }
}

/// The outcome of validating a profile.
#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    fn error(&mut self, code: &'static str, field: impl Into<String>, msg: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Error,
            code,
            field: field.into(),
            message: msg.into(),
        });
    }

    fn warn(&mut self, code: &'static str, field: impl Into<String>, msg: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code,
            field: field.into(),
            message: msg.into(),
        });
    }

    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
    }

    pub fn error_count(&self) -> usize {
        self.errors().count()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings().count()
    }

    /// True when there are no error-level diagnostics.
    pub fn is_valid(&self) -> bool {
        self.error_count() == 0
    }
}

/// Validate a profile and collect all findings.
pub fn validate(profile: &Profile) -> ValidationReport {
    let mut r = ValidationReport::default();

    if profile.name.trim().is_empty() {
        r.error("name.empty", "name", "profile name must not be empty");
    }

    validate_resources(profile, &mut r);
    validate_network(profile, &mut r);
    validate_filesystem(profile, &mut r);
    validate_syscalls(profile, &mut r);
    validate_capabilities(profile, &mut r);
    validate_env(profile, &mut r);
    validate_tools(profile, &mut r);
    validate_secret_exposure(profile, &mut r);

    r
}

/// Case-insensitive fragments that suggest an environment variable name
/// carries a credential rather than ordinary configuration.
const SECRET_LIKE_ENV_FRAGMENTS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"];

fn looks_like_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_LIKE_ENV_FRAGMENTS
        .iter()
        .any(|frag| upper.contains(frag))
}

/// Flag the specific combination this project's threat model exists to
/// prevent: a profile that forwards what looks like a credential from the
/// host environment into a sandbox with unrestricted network egress. `full`
/// is the only network mode with no enforcement at all -- `allowlist` is
/// enforced in-kernel via seccomp user notification (see
/// docs/security-model.md) -- so `full` plus a forwarded secret is the one
/// case where a compromised or prompt-injected process inside the sandbox
/// has both a secret worth stealing and an unmonitored path to exfiltrate
/// it. Deliberately an error, not a warning: this is the one validation in
/// this module that fails a run rather than just flagging it, because the
/// warning-only version of this check already exists (`network.full`) and
/// evidently was not enough to stop the project's own shipped
/// `assistant.toml` template from defaulting to exactly this shape.
fn validate_secret_exposure(profile: &Profile, r: &mut ValidationReport) {
    if !matches!(profile.network.mode, NetworkMode::Full) {
        return;
    }
    if matches!(profile.env.mode, crate::env::EnvMode::Clear) {
        return;
    }
    let mut offenders: Vec<&str> = profile
        .env
        .allow
        .iter()
        .map(String::as_str)
        .filter(|n| looks_like_secret(n))
        .collect();
    offenders.extend(
        profile
            .env
            .set
            .keys()
            .map(String::as_str)
            .filter(|n| looks_like_secret(n)),
    );
    if offenders.is_empty() {
        return;
    }
    offenders.sort_unstable();
    offenders.dedup();
    r.error(
        "network.full_with_secrets",
        "network.mode",
        format!(
            "network mode is `full` (unrestricted egress) while the environment forwards what \
             looks like credential(s): {}. A compromised or prompt-injected process in this \
             sandbox can exfiltrate them to any host. Use `network.mode = \"none\"`, \
             `\"loopback\"`, or `\"allowlist\"`, or remove these variables from `[env]`, \
             before running this profile.",
            offenders.join(", ")
        ),
    );
}

fn validate_resources(profile: &Profile, r: &mut ValidationReport) {
    let res = &profile.resources;
    if let Some(mem) = res.memory {
        if mem.bytes() == 0 {
            r.error(
                "memory.zero",
                "resources.memory",
                "must be greater than zero",
            );
        } else if mem.bytes() < (16 << 20) {
            r.warn(
                "memory.low",
                "resources.memory",
                "under 16 MiB is likely too small for most tools",
            );
        }
    }
    if let Some(cpu) = res.cpu {
        if cpu <= 0.0 {
            r.error("cpu.zero", "resources.cpu", "must be greater than zero");
        } else if cpu * CGROUP_CPU_PERIOD_US < 1.0 {
            // The Linux backend quantizes this into a cgroup `cpu.max` quota
            // as `(cpu * period) as u64` microseconds out of a 100ms period
            // (see linux/cgroups.rs); anything below one microsecond of
            // quota per period truncates to a literal 0% CPU allowance, so
            // the process would never be scheduled rather than just being
            // slow.
            r.warn(
                "cpu.rounds_to_zero",
                "resources.cpu",
                format!(
                    "`{cpu}` is small enough to round down to a 0% CPU quota on Linux (cgroup \
                     quotas are quantized to a 100ms period); the process would never run"
                ),
            );
        }
    }
    if let Some(pids) = res.pids {
        if pids == 0 {
            r.error("pids.zero", "resources.pids", "must be at least 1");
        }
    }
    if let Some(nofile) = res.open_files {
        if nofile == 0 {
            r.error(
                "open_files.zero",
                "resources.open_files",
                "must be at least 1",
            );
        }
    }
}

fn validate_network(profile: &Profile, r: &mut ValidationReport) {
    let net = &profile.network;
    match net.mode {
        NetworkMode::Allowlist => {
            if net.allow.is_empty() {
                r.warn(
                    "network.empty_allowlist",
                    "network.allow",
                    "allowlist mode with no entries blocks all hosts",
                );
            }
            for entry in &net.allow {
                if !is_valid_host_port(entry) {
                    r.error(
                        "network.bad_endpoint",
                        "network.allow",
                        format!("`{entry}` is not a valid host:port"),
                    );
                }
            }
        }
        NetworkMode::Full => r.warn(
            "network.full",
            "network.mode",
            "full network access is the least isolated option",
        ),
        _ => {}
    }
}

fn validate_filesystem(profile: &Profile, r: &mut ValidationReport) {
    let fs = &profile.filesystem;
    if fs.read_only.is_empty() && fs.read_write.is_empty() && fs.tmpfs.is_empty() {
        r.warn(
            "fs.empty",
            "filesystem",
            "no paths are exposed; most programs will fail to start",
        );
    }
    for p in &fs.read_write {
        if fs.read_only.iter().any(|ro| ro == p) {
            r.error(
                "fs.conflict",
                "filesystem.read_write",
                format!("`{}` appears in both read_only and read_write", p.display()),
            );
        }
    }
}

fn validate_syscalls(profile: &Profile, r: &mut ValidationReport) {
    let sc = &profile.syscalls;
    if !sc.enabled {
        r.warn(
            "syscalls.disabled",
            "syscalls.enabled",
            "seccomp is disabled; syscall attack surface is unrestricted",
        );
        return;
    }
    if sc.is_allowlist() && sc.preset.is_none() && sc.allow.is_empty() {
        r.error(
            "syscalls.empty_allowlist",
            "syscalls.allow",
            "allowlist mode needs a preset or explicit allow list, or nothing will run",
        );
    }
    if matches!(sc.default, SeccompAction::Log) {
        r.warn(
            "syscalls.log_default",
            "syscalls.default",
            "a logging default action permits every syscall",
        );
    }
}

fn validate_capabilities(profile: &Profile, r: &mut ValidationReport) {
    for cap in &profile.capabilities.keep {
        if !capabilities::is_known(cap) {
            r.error(
                "capabilities.unknown",
                "capabilities.keep",
                format!("`{cap}` is not a known Linux capability"),
            );
        }
        if capabilities::is_known(cap)
            && matches!(
                cap.to_ascii_lowercase().trim_start_matches("cap_"),
                "sys_admin" | "sys_ptrace" | "sys_module"
            )
        {
            r.warn(
                "capabilities.dangerous",
                "capabilities.keep",
                format!("`{cap}` substantially weakens the sandbox"),
            );
        }
    }
}

fn validate_env(profile: &Profile, r: &mut ValidationReport) {
    if matches!(profile.env.mode, crate::env::EnvMode::Passthrough) {
        r.warn(
            "env.passthrough",
            "env.mode",
            "passthrough forwards the full environment, which may include secrets",
        );
    }
}

fn validate_tools(profile: &Profile, r: &mut ValidationReport) {
    for tool in &profile.tools.allow {
        if tool.contains('/') || tool.contains('\\') {
            r.warn(
                "tools.path",
                "tools.allow",
                format!("`{tool}` looks like a path; basenames are recommended"),
            );
        }
    }
}

/// Validate a `host:port` endpoint. Accepts IPv6 in brackets.
fn is_valid_host_port(entry: &str) -> bool {
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        // [::1]:443
        match rest.split_once("]:") {
            Some((h, p)) => (h, p),
            None => return false,
        }
    } else {
        match entry.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => return false,
        }
    };
    if host.is_empty() {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(p) if p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkPolicy;

    #[test]
    fn default_profile_is_valid() {
        let report = validate(&Profile::default());
        assert!(report.is_valid(), "{:?}", report.diagnostics);
    }

    #[test]
    fn flags_zero_memory() {
        let mut p = Profile::default();
        p.resources.memory = Some(crate::units::ByteSize(0));
        let report = validate(&p);
        assert!(!report.is_valid());
        assert!(report.errors().any(|d| d.code == "memory.zero"));
    }

    #[test]
    fn warns_cpu_quota_rounds_to_zero() {
        let mut p = Profile::default();
        p.resources.cpu = Some(0.000001); // 0.1us of quota per 100ms period
        let report = validate(&p);
        assert!(report.is_valid(), "{:?}", report.diagnostics);
        assert!(report.warnings().any(|d| d.code == "cpu.rounds_to_zero"));
    }

    #[test]
    fn normal_cpu_value_does_not_warn() {
        let mut p = Profile::default();
        p.resources.cpu = Some(2.0);
        let report = validate(&p);
        assert!(!report.warnings().any(|d| d.code == "cpu.rounds_to_zero"));
    }

    #[test]
    fn flags_full_network_with_api_key_env() {
        let mut p = Profile::default();
        p.network.mode = NetworkMode::Full;
        p.env.allow.push("ANTHROPIC_API_KEY".into());
        let report = validate(&p);
        assert!(!report.is_valid(), "{:?}", report.diagnostics);
        assert!(report
            .errors()
            .any(|d| d.code == "network.full_with_secrets"));
    }

    #[test]
    fn full_network_alone_is_only_a_warning() {
        let mut p = Profile::default();
        p.network.mode = NetworkMode::Full;
        let report = validate(&p);
        assert!(report.is_valid(), "{:?}", report.diagnostics);
        assert!(report.warnings().any(|d| d.code == "network.full"));
    }

    #[test]
    fn full_network_with_non_secret_env_is_fine() {
        let mut p = Profile::default();
        p.network.mode = NetworkMode::Full;
        p.env.allow.push("EDITOR".into());
        let report = validate(&p);
        assert!(report.is_valid(), "{:?}", report.diagnostics);
    }

    #[test]
    fn flags_bad_network_endpoint() {
        let p = Profile {
            network: NetworkPolicy {
                mode: NetworkMode::Allowlist,
                allow: vec!["not-a-host".into()],
            },
            ..Default::default()
        };
        let report = validate(&p);
        assert!(report.errors().any(|d| d.code == "network.bad_endpoint"));
    }

    #[test]
    fn accepts_host_port_forms() {
        assert!(is_valid_host_port("api.example.com:443"));
        assert!(is_valid_host_port("[::1]:8080"));
        assert!(!is_valid_host_port("host"));
        assert!(!is_valid_host_port("host:0"));
        assert!(!is_valid_host_port("host:notaport"));
    }

    #[test]
    fn flags_unknown_capability() {
        let mut p = Profile::default();
        p.capabilities.keep = vec!["not_a_cap".into()];
        let report = validate(&p);
        assert!(report.errors().any(|d| d.code == "capabilities.unknown"));
    }

    #[test]
    fn empty_allowlist_syscalls_is_error() {
        let mut p = Profile::default();
        p.syscalls.default = SeccompAction::Errno;
        p.syscalls.preset = None;
        p.syscalls.allow = vec![];
        let report = validate(&p);
        assert!(report
            .errors()
            .any(|d| d.code == "syscalls.empty_allowlist"));
    }
}
