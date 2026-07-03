//! Host capability detection, surfaced by `confinery doctor`.

use std::fmt;

/// One detected host feature.
#[derive(Debug, Clone)]
pub struct Feature {
    pub name: &'static str,
    pub available: bool,
    pub detail: String,
}

impl Feature {
    fn yes(name: &'static str, detail: impl Into<String>) -> Self {
        Feature {
            name,
            available: true,
            detail: detail.into(),
        }
    }
    fn no(name: &'static str, detail: impl Into<String>) -> Self {
        Feature {
            name,
            available: false,
            detail: detail.into(),
        }
    }
}

/// Summary of isolation primitives available on this host.
#[derive(Debug, Clone)]
pub struct HostCapabilities {
    pub platform: &'static str,
    pub features: Vec<Feature>,
}

impl HostCapabilities {
    /// Whether a named feature is available.
    pub fn has(&self, name: &str) -> bool {
        self.features.iter().any(|f| f.name == name && f.available)
    }
}

impl fmt::Display for HostCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "platform: {}", self.platform)?;
        for feat in &self.features {
            let mark = if feat.available { "ok " } else { "-- " };
            writeln!(f, "  [{mark}] {:<20} {}", feat.name, feat.detail)?;
        }
        Ok(())
    }
}

/// Detect the isolation primitives available on the current host.
pub fn detect() -> HostCapabilities {
    #[cfg(target_os = "linux")]
    {
        linux::detect()
    }
    #[cfg(windows)]
    {
        windows::detect()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        HostCapabilities {
            platform: "unsupported",
            features: vec![Feature::no("sandbox", "no isolation backend for this OS")],
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Feature, HostCapabilities};
    use std::io::{self, Write};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;

    fn read_trim(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn detect() -> HostCapabilities {
        let mut features = Vec::new();

        // User namespaces. The sysctls below are necessary but not
        // sufficient: a host can pass both and still deny the actual
        // uid_map write via an LSM policy Confinery has no static file to
        // check -- notably Ubuntu's AppArmor-based restriction on
        // unprivileged user namespaces, enabled by default on GitHub
        // Actions' `ubuntu-latest` runners. That combination let this
        // detector report "available" on a host where every sandboxed run
        // then failed deep inside namespace setup, with `confinery doctor`
        // giving no warning beforehand. So the sysctls are only a cheap
        // pre-filter; `userns_actually_works()` confirms with a real,
        // throwaway attempt at exactly the sequence the sandbox itself uses
        // before trusting the result.
        let max_userns = read_trim("/proc/sys/user/max_user_namespaces")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let sysctls_ok = max_userns > 0
            && read_trim("/proc/sys/kernel/unprivileged_userns_clone")
                .map(|v| v != "0")
                .unwrap_or(true);
        let userns_ok = sysctls_ok && userns_actually_works();
        features.push(if userns_ok {
            Feature::yes("user_namespaces", format!("max={max_userns}"))
        } else if sysctls_ok {
            Feature::no(
                "user_namespaces",
                "sysctls allow it, but the kernel denied mapping a uid inside a \
                 new namespace (commonly an LSM policy such as Ubuntu's AppArmor \
                 unprivileged-userns restriction)",
            )
        } else {
            Feature::no(
                "user_namespaces",
                "unprivileged user namespaces unavailable",
            )
        });

        for (name, ns) in [
            ("mount_namespace", "mnt"),
            ("pid_namespace", "pid"),
            ("net_namespace", "net"),
        ] {
            let present = Path::new(&format!("/proc/self/ns/{ns}")).exists();
            features.push(if present {
                Feature::yes(name, "supported")
            } else {
                Feature::no(name, "not present")
            });
        }

        // cgroup v2.
        let cgroup2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        let controllers = read_trim("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
        features.push(if cgroup2 {
            Feature::yes("cgroup_v2", format!("controllers: {controllers}"))
        } else {
            Feature::no("cgroup_v2", "unified hierarchy not mounted")
        });

        // seccomp.
        let seccomp = std::fs::read_to_string("/proc/self/status")
            .map(|s| s.contains("Seccomp:"))
            .unwrap_or(false);
        features.push(if seccomp {
            Feature::yes("seccomp", "seccomp-bpf available")
        } else {
            Feature::no("seccomp", "kernel lacks seccomp")
        });

        // Landlock (query ABI version).
        features.push(match landlock_abi() {
            Some(v) if v > 0 => Feature::yes("landlock", format!("ABI v{v}")),
            _ => Feature::no("landlock", "not enabled in kernel"),
        });

        // AppArmor / SELinux.
        let apparmor = read_trim("/sys/module/apparmor/parameters/enabled")
            .map(|v| v == "Y")
            .unwrap_or(false);
        features.push(if apparmor {
            Feature::yes("apparmor", "enabled")
        } else {
            Feature::no("apparmor", "disabled or absent")
        });
        let selinux = Path::new("/sys/fs/selinux").exists();
        features.push(if selinux {
            Feature::yes("selinux", "present")
        } else {
            Feature::no("selinux", "not present")
        });

        HostCapabilities {
            platform: "linux",
            features,
        }
    }

    /// Actually attempt the unshare(CLONE_NEWUSER) + uid_map dance the
    /// sandbox depends on, in a disposable child that never reaches exec
    /// under normal conditions and is killed immediately regardless. Memoized
    /// for the process lifetime: the answer cannot change between calls and
    /// each attempt costs a real fork+exec.
    fn userns_actually_works() -> bool {
        static RESULT: OnceLock<bool> = OnceLock::new();
        *RESULT.get_or_init(|| {
            let Ok(exe) = std::env::current_exe() else {
                return false;
            };
            // Must be read here, in the parent, before any unshare happens:
            // once the probe closure runs in the child it is already inside
            // the fresh (unmapped) user namespace, where getuid() returns
            // the overflow uid (65534) instead of the real one -- mapping
            // that would always be rejected regardless of what the host
            // actually allows. This mirrors exactly how the real sandbox
            // captures `uid`/`gid` in `LinuxSandbox::run()` before spawning.
            let uid = nix::unistd::getuid().as_raw();
            let mut cmd = Command::new(exe);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: the closure only unshares a namespace and writes to
            // /proc files it just gained from that unshare; nothing here
            // touches shared parent state, and the child is killed right
            // after spawn() returns, before it can do anything else even if
            // the probe (and thus the exec that follows it) succeeds.
            unsafe {
                cmd.pre_exec(move || probe_uid_map_writable(uid));
            }
            match cmd.spawn() {
                Ok(mut child) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    true
                }
                Err(_) => false,
            }
        })
    }

    /// Runs inside the disposable probe child: mirrors exactly the sequence
    /// `linux::namespaces::enter_user_namespace` uses for a real run.
    fn probe_uid_map_writable(uid: u32) -> io::Result<()> {
        use nix::sched::{unshare, CloneFlags};
        unshare(CloneFlags::CLONE_NEWUSER).map_err(io::Error::from)?;
        let _ = std::fs::write("/proc/self/setgroups", b"deny");
        std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/uid_map")?
            .write_all(format!("0 {uid} 1\n").as_bytes())
    }

    /// Query the supported Landlock ABI version, or `None` if unsupported.
    fn landlock_abi() -> Option<i64> {
        // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if ret >= 0 {
            Some(ret as i64)
        } else {
            None
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Feature, HostCapabilities};

    pub fn detect() -> HostCapabilities {
        let mut features = Vec::new();
        features.push(Feature::yes(
            "job_object",
            "process resource limits available",
        ));
        // Deliberately no "restricted_token" entry here: nothing in the
        // Windows backend actually creates a restricted token or lowers
        // the process integrity level today (see docs/security-model.md's
        // Known limits) -- the sandboxed process keeps the full token of
        // the invoking user. A previous version of this detector claimed
        // this capability unconditionally with no code behind it at all;
        // `confinery doctor` must never assert a boundary that isn't real.

        let wsl = std::path::Path::new(r"C:\Windows\System32\wsl.exe").exists();
        features.push(if wsl {
            Feature::yes("wsl2", "wsl.exe present")
        } else {
            Feature::no("wsl2", "wsl.exe not found")
        });

        let sandbox = std::path::Path::new(r"C:\Windows\System32\WindowsSandbox.exe").exists();
        features.push(if sandbox {
            Feature::yes("windows_sandbox", "WindowsSandbox.exe present")
        } else {
            Feature::no("windows_sandbox", "feature not installed")
        });

        HostCapabilities {
            platform: "windows",
            features,
        }
    }
}
