//! Linux sandbox backend.
//!
//! Two isolation plans are selected automatically:
//!
//! * **isolate** — user + mount + network + UTS + IPC namespaces with a
//!   `pivot_root` filesystem, used when unprivileged user namespaces are
//!   available.
//! * **confine** — no namespaces; Landlock, seccomp, rlimits, and capability
//!   dropping still apply. Used as a graceful fallback.
//!
//! Both plans install seccomp last, after `no_new_privs`, so the filter also
//! covers the `execve` into the target program.

mod caps;
mod cgroups;
mod landlock;
mod mounts;
mod namespaces;
mod rlimits;
mod seccomp;
mod syscall_table;

use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use confinery_core::audit::{AuditEvent, Auditor};
use confinery_core::network::NetworkMode;
use confinery_core::profile::expand_home;
use nix::unistd::{getgid, getuid};
use seccompiler::BpfProgram;

use self::caps::CapPlan;
use self::cgroups::CgroupPlan;
use self::landlock::{LandlockPlan, LandlockStatus};
use self::mounts::MountPlan;
use self::namespaces::NamespacePlan;
use self::rlimits::RlimitPlan;
use crate::error::{Result, SandboxError};
use crate::report::{LayerOutcome, SandboxReport};
use crate::spec::SandboxSpec;
use crate::Sandbox;

/// The Linux sandbox engine.
pub struct LinuxSandbox;

impl LinuxSandbox {
    pub fn new() -> Self {
        LinuxSandbox
    }
}

impl Sandbox for LinuxSandbox {
    fn backend(&self) -> &'static str {
        "linux-namespaces"
    }

    fn run(&self, spec: &SandboxSpec, auditor: &mut Auditor) -> Result<SandboxReport> {
        let program = spec.program()?.to_string();
        spec.check_tool_allowed()?;

        auditor.record(AuditEvent::SandboxStart {
            id: spec.id.clone(),
            profile: spec.profile.name.clone(),
            command: spec.command.clone(),
        });

        let profile = &spec.profile;
        let host = crate::detect::detect();
        let isolate =
            spec.allow_namespaces && host.has("user_namespaces") && host.has("mount_namespace");
        let net_isolate = isolate && profile.network.wants_isolation() && host.has("net_namespace");

        let home = spec.home.clone();
        let workdir = spec
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/"));

        let ns_plan = NamespacePlan {
            user: isolate,
            mount: isolate,
            net: net_isolate,
            uts: isolate,
            ipc: isolate,
            uid: getuid().as_raw(),
            gid: getgid().as_raw(),
            hostname: hostname_for(&profile.name),
            loopback_up: profile.network.mode == NetworkMode::Loopback,
        };

        let mount_plan = MountPlan {
            read_only: expand_all(&profile.filesystem.read_only, &home),
            read_write: expand_all(&profile.filesystem.read_write, &home),
            tmpfs: expand_all(&profile.filesystem.tmpfs, &home),
            deny: expand_all(&profile.filesystem.deny, &home),
            minimal_dev: profile.filesystem.minimal_dev,
            workdir: workdir.clone(),
        };

        let landlock_plan = LandlockPlan::from_policy(&profile.filesystem, &home);
        let rlimit_plan = RlimitPlan::from_limits(&profile.resources);
        let cap_plan = CapPlan::from_policy(&profile.capabilities)?;
        let seccomp_prog: Option<BpfProgram> = seccomp::compile(&profile.syscalls)?;

        // Assemble the audit + report view of the layers.
        let mut layers = Vec::new();
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "namespaces",
            isolate,
            if isolate {
                "user+mount+uts+ipc"
            } else {
                "unavailable or disabled; using confine plan"
            },
        );
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "filesystem",
            true,
            if isolate {
                "pivot_root mount allowlist"
            } else if host.has("landlock") {
                "landlock path allowlist"
            } else {
                "landlock unavailable (run will fail closed)"
            },
        );
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "network",
            net_isolate || !profile.network.wants_isolation(),
            network_detail(profile.network.mode, net_isolate),
        );
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "seccomp",
            seccomp_prog.is_some(),
            if seccomp_prog.is_some() {
                "bpf filter installed"
            } else {
                "disabled by policy"
            },
        );
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "capabilities",
            true,
            if cap_plan.drops_all() {
                "all dropped"
            } else {
                "restricted keep-set"
            },
        );
        record_layer(auditor, &spec.id, &mut layers, "rlimits", true, "applied");

        if spec.dry_run {
            record_layer(
                auditor,
                &spec.id,
                &mut layers,
                "cgroups",
                true,
                "planned (best-effort at run time)",
            );
            return Ok(SandboxReport {
                id: spec.id.clone(),
                exit_code: None,
                signal: None,
                duration: Duration::ZERO,
                layers,
                dry_run: true,
            });
        }

        // cgroups are created in the parent and the child is attached after spawn.
        let cgroup = CgroupPlan::from_limits(&profile.resources)
            .create(&spec.id)
            .ok()
            .flatten();
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "cgroups",
            cgroup.is_some(),
            if cgroup.is_some() {
                "resource limits set"
            } else {
                "hierarchy not writable; rlimits only"
            },
        );

        let mut cmd = Command::new(&program);
        cmd.args(&spec.command[1..]);
        crate::common::apply_env(&mut cmd, &profile.env);

        let exec = ExecPlan {
            isolate,
            namespaces: ns_plan,
            mounts: mount_plan,
            caps: cap_plan,
            landlock: landlock_plan,
            rlimits: rlimit_plan,
            seccomp: seccomp_prog,
        };
        // SAFETY: the closure only calls async-signal-safe-ish setup on a
        // single-threaded parent and returns a plain io::Result.
        unsafe {
            cmd.pre_exec(move || exec.apply());
        }

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|source| SandboxError::Spawn {
            command: program.clone(),
            source,
        })?;
        let pid = child.id() as i32;

        if let Some(cg) = &cgroup {
            if let Err(err) = cg.add_process(child.id()) {
                tracing::warn!(%err, "failed to attach process to cgroup");
            }
        }

        let timeout = profile.resources.timeout.map(|d| d.as_duration());
        let (status, timed_out) = wait_with_timeout(&mut child, pid, timeout)?;
        let duration = start.elapsed();

        if let Some(cg) = &cgroup {
            cg.cleanup();
        }

        let exit_code = status.code();
        let signal = if timed_out {
            Some(libc::SIGKILL)
        } else {
            status.signal()
        };

        if timed_out {
            auditor.record(AuditEvent::Violation {
                id: spec.id.clone(),
                kind: "timeout".into(),
                detail: format!(
                    "killed after {}",
                    profile
                        .resources
                        .timeout
                        .map(|d| d.human())
                        .unwrap_or_default()
                ),
            });
        }
        auditor.record(AuditEvent::SandboxExit {
            id: spec.id.clone(),
            code: exit_code,
            signal,
            duration_ms: duration.as_millis(),
        });

        if timed_out {
            return Err(SandboxError::Timeout {
                timeout: profile
                    .resources
                    .timeout
                    .map(|d| d.human())
                    .unwrap_or_default(),
            });
        }

        Ok(SandboxReport {
            id: spec.id.clone(),
            exit_code,
            signal,
            duration,
            layers,
            dry_run: false,
        })
    }
}

/// The owned setup steps executed in the pre-exec child.
struct ExecPlan {
    isolate: bool,
    namespaces: NamespacePlan,
    mounts: MountPlan,
    caps: CapPlan,
    landlock: LandlockPlan,
    rlimits: RlimitPlan,
    seccomp: Option<BpfProgram>,
}

impl ExecPlan {
    fn apply(&self) -> io::Result<()> {
        if self.isolate {
            self.namespaces.enter()?;
            self.mounts.setup()?;
        }
        // Capabilities are dropped after privileged setup and before the
        // no_new_privs latch, which Landlock and seccomp both require.
        self.caps.apply()?;
        set_no_new_privs()?;

        if !self.isolate {
            // In confine mode Landlock is the only filesystem boundary, so a
            // kernel without it must fail closed rather than run unconfined.
            if self.landlock.apply()? == LandlockStatus::Unsupported {
                return Err(io::Error::other(
                    "Landlock unavailable; cannot confine filesystem (try namespace isolation)",
                ));
            }
        }

        self.rlimits.apply()?;
        if let Some(prog) = &self.seccomp {
            seccomp::install(prog)?;
        }
        Ok(())
    }
}

fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn expand_all(paths: &[PathBuf], home: &Path) -> Vec<PathBuf> {
    paths.iter().map(|p| expand_home(p, home)).collect()
}

fn hostname_for(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("confinery-{sanitized}").chars().take(63).collect()
}

fn network_detail(mode: NetworkMode, isolated: bool) -> String {
    match mode {
        NetworkMode::None if isolated => "isolated netns, no routes".into(),
        NetworkMode::Loopback if isolated => "isolated netns, loopback only".into(),
        NetworkMode::None | NetworkMode::Loopback => {
            "requested isolation unavailable (no netns)".into()
        }
        NetworkMode::Allowlist => "host network (allowlist not yet enforced in-kernel)".into(),
        NetworkMode::Full => "host network".into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_layer(
    auditor: &mut Auditor,
    id: &str,
    layers: &mut Vec<LayerOutcome>,
    layer: &str,
    applied: bool,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    if applied {
        auditor.record(AuditEvent::LayerApplied {
            id: id.to_string(),
            layer: layer.to_string(),
            detail: detail.clone(),
        });
        layers.push(LayerOutcome::applied(layer, detail));
    } else {
        auditor.record(AuditEvent::LayerSkipped {
            id: id.to_string(),
            layer: layer.to_string(),
            reason: detail.clone(),
        });
        layers.push(LayerOutcome::skipped(layer, detail));
    }
}

fn wait_with_timeout(
    child: &mut Child,
    pid: i32,
    timeout: Option<Duration>,
) -> io::Result<(ExitStatus, bool)> {
    let Some(timeout) = timeout else {
        return Ok((child.wait()?, false));
    };

    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let killer = thread::spawn(move || {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if flag.load(Ordering::SeqCst) {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if flag.load(Ordering::SeqCst) {
            return false;
        }
        unsafe { libc::kill(pid, libc::SIGKILL) };
        true
    });

    let status = child.wait()?;
    done.store(true, Ordering::SeqCst);
    let killed = killer.join().unwrap_or(false);
    Ok((status, killed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_sanitized_and_bounded() {
        assert_eq!(hostname_for("dev"), "confinery-dev");
        assert_eq!(hostname_for("a b/c"), "confinery-a-b-c");
        assert!(hostname_for(&"x".repeat(100)).len() <= 63);
    }

    #[test]
    fn network_detail_reflects_mode() {
        assert!(network_detail(NetworkMode::None, true).contains("no routes"));
        assert!(network_detail(NetworkMode::None, false).contains("unavailable"));
        assert!(network_detail(NetworkMode::Full, false).contains("host network"));
    }
}
