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
mod connect_filter;
mod landlock;
mod mounts;
mod namespaces;
mod rlimits;
mod seccomp;
mod syscall_table;

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use confinery_core::audit::{AuditEvent, Auditor};
use confinery_core::network::NetworkMode;
use confinery_core::profile::{expand_home, resolve_relative};
use nix::fcntl::OFlag;
use nix::unistd::{getgid, getuid};
use seccompiler::BpfProgram;

use self::connect_filter::DeniedAttempt;

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
            read_only: expand_all(&profile.filesystem.read_only, &home, &workdir),
            read_write: expand_all(&profile.filesystem.read_write, &home, &workdir),
            tmpfs: expand_all(&profile.filesystem.tmpfs, &home, &workdir),
            deny: expand_all(&profile.filesystem.deny, &home, &workdir),
            minimal_dev: profile.filesystem.minimal_dev,
            workdir: workdir.clone(),
        };

        let landlock_plan = LandlockPlan::from_policy(&profile.filesystem, &home, &workdir);
        let rlimit_plan = RlimitPlan::from_limits(&profile.resources);
        let cap_plan = CapPlan::from_policy(&profile.capabilities)?;
        let seccomp_prog: Option<BpfProgram> = seccomp::compile(&profile.syscalls)?;

        // `allowlist` network mode is enforced by intercepting connect(2)
        // via seccomp user notification (see connect_filter.rs), not by
        // network namespace isolation -- the sandboxed process keeps the
        // host's real network stack either way, same as `full` always has.
        // Resolution happens here, in the trusted parent, before anything
        // in the sandbox runs.
        let allowed_endpoints = if profile.network.mode == NetworkMode::Allowlist {
            Some(
                connect_filter::resolve_allowlist(&profile.network.allow).map_err(|e| {
                    SandboxError::layer("network", format!("allowlist resolution: {e}"))
                })?,
            )
        } else {
            None
        };

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
        // Not implemented: entering a PID namespace requires forking after
        // unshare(CLONE_NEWPID), which the calling process itself never
        // moves into -- a mismatch with the current single pre_exec-then-
        // execve spawn path. Recorded explicitly, always skipped, so
        // `confinery doctor`/`--dry-run`/the audit trail never imply a
        // boundary this build doesn't have. See docs/security-model.md.
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "pid_namespace",
            false,
            "not implemented; sandboxed process shares the host PID namespace",
        );
        record_layer(
            auditor,
            &spec.id,
            &mut layers,
            "filesystem",
            true,
            if isolate {
                "pivot_root mount allowlist + landlock (best-effort backstop)"
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
            net_isolate
                || matches!(profile.network.mode, NetworkMode::Full)
                || allowed_endpoints.is_some(),
            network_detail(
                profile.network.mode,
                net_isolate,
                allowed_endpoints.as_ref().map(Vec::len),
            ),
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

        // Rust's `pre_exec` can only carry a bare OS error code back across
        // the fork boundary: if the closure returns anything other than a
        // raw-errno `io::Error`, the detail is discarded and the parent sees
        // a generic, unhelpful `EINVAL`. Every error built inside this
        // module (`mount_err`, `cap_err`, `labeled`, ...) is exactly that
        // kind of custom error, so without a side channel every failure in
        // isolation setup -- namespaces, mounts, capabilities, Landlock,
        // seccomp -- looks identical and undiagnosable from the outside.
        // A `O_CLOEXEC` pipe closes itself on a successful `execve` with no
        // data written; on failure the child writes the real error text
        // before dying, and the parent reads it back to build a report that
        // actually says what went wrong.
        let (err_read, err_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| {
            SandboxError::layer("setup", format!("failed to create diagnostics pipe: {e}"))
        })?;

        // A second, independent hand-off channel for the connect-notify fd
        // (see connect_filter.rs) -- only created when it'll actually be
        // used, since it's a real kernel resource (a socket pair) held
        // open for the run's whole lifetime.
        let (connect_parent_sock, connect_child_sock) = match &allowed_endpoints {
            Some(_) => {
                let (p, c) = connect_filter::create_channel().map_err(|e| {
                    SandboxError::layer("network", format!("allowlist channel: {e}"))
                })?;
                (Some(p), Some(c))
            }
            None => (None, None),
        };

        let exec = ExecPlan {
            isolate,
            namespaces: ns_plan,
            mounts: mount_plan,
            caps: cap_plan,
            landlock: landlock_plan,
            rlimits: rlimit_plan,
            seccomp: seccomp_prog,
            err_write,
            connect_child_sock,
        };
        // SAFETY: the closure only calls async-signal-safe-ish setup on a
        // single-threaded parent and returns a plain io::Result.
        unsafe {
            cmd.pre_exec(move || exec.apply());
        }

        let start = Instant::now();
        let spawn_result = cmd.spawn();
        // `cmd` (and the pre_exec closure it owns, and that closure's copy
        // of the pipe's write end) is kept alive by Rust's `Command` after
        // `spawn()` returns, in case the caller spawns again. Drop it
        // explicitly so our copy of the write end closes too -- otherwise a
        // successful run (which writes nothing) would leave the read below
        // blocked forever waiting for an EOF that a still-open write end
        // would never deliver.
        drop(cmd);
        let detail = read_setup_error(err_read);
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(source) => {
                return Err(match detail {
                    Some(detail) => SandboxError::layer("setup", detail),
                    None => SandboxError::Spawn {
                        command: program.clone(),
                        source,
                    },
                });
            }
        };
        let pid = child.id() as i32;

        // The child sends the connect-notify fd very early in its own
        // pre_exec, well before it execs the target program, so a blocking
        // receive here does not race it in practice. If this fails, the
        // child reached spawn() successfully but the allowlist filter
        // never came up -- `allowlist` mode must not silently run
        // unfiltered, so this is fatal, not a warning.
        let denied_connections: Arc<Mutex<Vec<DeniedAttempt>>> = Arc::new(Mutex::new(Vec::new()));
        if let (Some(sock), Some(endpoints)) = (connect_parent_sock, &allowed_endpoints) {
            if let Err(err) = connect_filter::receive_and_supervise(
                sock,
                endpoints.clone(),
                denied_connections.clone(),
            ) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::layer(
                    "network",
                    format!("allowlist filter did not start: {err}"),
                ));
            }
        }

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
        // A best-effort snapshot: the supervisor thread isn't joined here
        // (it may still be serving a lingering grandchild process that
        // inherited the filter but outlived the direct child, and there is
        // no PID namespace -- see the pid_namespace layer above -- to
        // guarantee those are gone by now), so a denied attempt in the
        // narrow window between this read and process exit could be
        // missed. The whole `confinery` process exiting cleans up the
        // detached thread either way.
        if let Ok(denied) = denied_connections.lock() {
            for attempt in denied.iter() {
                auditor.record(AuditEvent::Violation {
                    id: spec.id.clone(),
                    kind: "network.denied".into(),
                    detail: format!("connect() to {} refused (not in allowlist)", attempt.addr),
                });
            }
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
    /// Write end of a diagnostics pipe back to the parent. `pre_exec` can
    /// only carry a bare OS error code across the fork boundary, so on
    /// failure the real error text is written here before returning -- see
    /// the comment where this pipe is created in `run()`.
    err_write: OwnedFd,
    /// Present only for `network.mode = "allowlist"`: the child installs
    /// the connect-notify filter and sends its fd back over this socket.
    /// See connect_filter.rs.
    connect_child_sock: Option<UnixDatagram>,
}

impl ExecPlan {
    fn apply(&self) -> io::Result<()> {
        match self.apply_inner() {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                let bytes = &msg.as_bytes()[..msg.len().min(4096)];
                // Best-effort: if the pipe write itself fails there is
                // nothing more diagnosable to do, and the original error is
                // still returned and still aborts the run either way.
                let _ = nix::unistd::write(&self.err_write, bytes);
                Err(e)
            }
        }
    }

    fn apply_inner(&self) -> io::Result<()> {
        if self.isolate {
            self.namespaces.enter()?;
            self.mounts.setup()?;
        }
        // Capabilities are dropped after privileged setup and before the
        // no_new_privs latch, which Landlock and seccomp both require.
        self.caps.apply()?;
        set_no_new_privs()?;

        // Landlock is applied in both plans: under `isolate` the mount
        // namespace + pivot_root is the primary filesystem boundary, but
        // layering Landlock on top is genuine defense in depth -- a bug or
        // bypass in the mount setup has an independent, in-kernel backstop
        // instead of none at all. Under `confine` (no namespaces) Landlock
        // *is* the filesystem boundary, so a kernel without it must fail
        // closed rather than run unconfined.
        let landlock_status = self.landlock.apply()?;
        if !self.isolate && landlock_status == LandlockStatus::Unsupported {
            return Err(io::Error::other(
                "Landlock unavailable; cannot confine filesystem (try namespace isolation)",
            ));
        }

        self.rlimits.apply()?;
        if let Some(prog) = &self.seccomp {
            seccomp::install(prog)?;
        }
        // Stacked alongside (not replacing) the filter just installed --
        // see connect_filter.rs's module docs for why this needs its own
        // separate filter rather than folding into the one above.
        if let Some(sock) = &self.connect_child_sock {
            connect_filter::install_and_send(sock)?;
        }
        Ok(())
    }
}

/// Read whatever the child wrote to the setup-diagnostics pipe before
/// dying, if anything. Returns `None` on a clean EOF (no error occurred, or
/// the child never got far enough to report one) and ignores read errors
/// the same way, since this is a best-effort diagnostic, not a boundary.
fn read_setup_error(read_end: OwnedFd) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = nix::unistd::read(read_end.as_raw_fd(), &mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn expand_all(paths: &[PathBuf], home: &Path, workdir: &Path) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|p| resolve_relative(&expand_home(p, home), workdir))
        .collect()
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

fn network_detail(mode: NetworkMode, isolated: bool, allowed_count: Option<usize>) -> String {
    match mode {
        NetworkMode::None if isolated => "isolated netns, no routes".into(),
        NetworkMode::Loopback if isolated => "isolated netns, loopback only".into(),
        NetworkMode::None | NetworkMode::Loopback => {
            "requested isolation unavailable (no netns)".into()
        }
        NetworkMode::Allowlist => match allowed_count {
            Some(n) => format!(
                "host network, connect() filtered via seccomp notify ({n} endpoint(s) allowed)"
            ),
            None => "host network (allowlist filter unavailable)".into(),
        },
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
        assert!(network_detail(NetworkMode::None, true, None).contains("no routes"));
        assert!(network_detail(NetworkMode::None, false, None).contains("unavailable"));
        assert!(network_detail(NetworkMode::Full, false, None).contains("host network"));
        assert!(network_detail(NetworkMode::Allowlist, false, Some(2)).contains("2 endpoint"));
        assert!(network_detail(NetworkMode::Allowlist, false, None).contains("unavailable"));
    }

    #[test]
    fn read_setup_error_returns_none_on_clean_eof() {
        let (read_end, write_end) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        drop(write_end); // no error written, and the only writer is gone
        assert_eq!(read_setup_error(read_end), None);
    }

    #[test]
    fn read_setup_error_recovers_the_written_message() {
        let (read_end, write_end) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        nix::unistd::write(&write_end, b"mount bind: Permission denied").unwrap();
        drop(write_end);
        assert_eq!(
            read_setup_error(read_end).as_deref(),
            Some("mount bind: Permission denied")
        );
    }
}
