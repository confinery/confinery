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
    use std::path::Path;

    fn read_trim(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn detect() -> HostCapabilities {
        let mut features = Vec::new();

        // User namespaces.
        let max_userns = read_trim("/proc/sys/user/max_user_namespaces")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let userns_ok = max_userns > 0
            && read_trim("/proc/sys/kernel/unprivileged_userns_clone")
                .map(|v| v != "0")
                .unwrap_or(true);
        features.push(if userns_ok {
            Feature::yes("user_namespaces", format!("max={max_userns}"))
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
        features.push(Feature::yes(
            "restricted_token",
            "least-privilege token supported",
        ));

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
