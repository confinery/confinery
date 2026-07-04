//! Windows sandbox backend via `wslc.exe` (WSL Containers).
//!
//! `wslc` is a Microsoft *public preview* (announced 2026-07-02; GA
//! targeted for fall 2026) that runs real OCI Linux containers from
//! Windows -- backed by Moby inside a dedicated Hyper-V VM, no Docker
//! Desktop required. Unlike the default [`super::WindowsSandbox`] (a Job
//! Object: resource limits and environment filtering only), a container is
//! genuinely filesystem- and network-confined by construction: it sees
//! only what's explicitly mounted, and reaches the network only if one is
//! attached. See `docs/security-model.md` for the full picture.
//!
//! ## Why this is opt-in, not automatic
//!
//! Running a command in a Linux container only makes sense for a command
//! that has (or can run from) a Linux build -- there is no way to run a
//! native Windows `.exe` inside an OCI container this way. A profile opts
//! in explicitly by setting `windows.container_image`; see
//! [`confinery_core::windows::WindowsPolicy`].
//!
//! ## What's confirmed vs. assumed
//!
//! This preview's CLI reference is not fully published yet (checked
//! 2026-07: Microsoft Learn's own tutorial and multiple independent
//! write-ups do not document exact flag syntax for resource limits or
//! fine-grained network modes). To avoid claiming a boundary this code
//! cannot actually verify, only flags with strong corroboration are used:
//!
//! - `run --rm -v HOST:/workspace -w /workspace -e KEY=VALUE -- IMAGE CMD...`
//!   -- standard Docker CLI syntax; every `wslc` writeup describes it as
//!   deliberately Docker-CLI-compatible, and Microsoft's own tutorial uses
//!   `-v`-shaped bind mounts, `-p` port publishing, and `-e`-shaped env
//!   vars in its examples.
//! - `--network none` for `network.mode = "none"` -- identical to Docker's
//!   own flag, and containers are documented to support a `none` network
//!   type.
//!
//! Everything else this backend cannot confirm is reported as *skipped*,
//! never silently assumed: per-profile resource limits (memory/cpu/pids)
//! and the `loopback`/`allowlist` network modes (which have no
//! single-flag OCI equivalent -- a container's default network, active
//! for anything other than `none`, is an unfiltered NAT, not a
//! confinery-style allowlist). This has not been run against a real `wslc`
//! preview install; treat it as a starting point to verify on real
//! hardware, not a finished, load-bearing boundary.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use confinery_core::audit::{AuditEvent, Auditor};
use confinery_core::network::NetworkMode;

use crate::common;
use crate::error::{Result, SandboxError};
use crate::report::{LayerOutcome, SandboxReport};
use crate::spec::SandboxSpec;
use crate::Sandbox;

const WSLC_PATH: &str = r"C:\Windows\System32\wslc.exe";

/// The `wslc`-backed sandbox engine.
pub(crate) struct WslcSandbox;

impl WslcSandbox {
    pub fn new() -> Self {
        WslcSandbox
    }

    /// Whether `wslc.exe` is present on this host. Presence alone, same as
    /// the `wsl2`/`windows_sandbox` checks in `detect.rs` -- doesn't mean a
    /// profile has opted in via `windows.container_image`.
    pub fn is_available() -> bool {
        std::path::Path::new(WSLC_PATH).exists()
    }
}

impl Sandbox for WslcSandbox {
    fn backend(&self) -> &'static str {
        "windows-wslc"
    }

    fn run(&self, spec: &SandboxSpec, auditor: &mut Auditor) -> Result<SandboxReport> {
        spec.check_tool_allowed()?;

        auditor.record(AuditEvent::SandboxStart {
            id: spec.id.clone(),
            profile: spec.profile.name.clone(),
            command: spec.command.clone(),
        });

        let workdir = spec
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let args = build_wslc_args(spec, &workdir)?;

        let mut layers = Vec::new();
        record(
            auditor,
            &spec.id,
            &mut layers,
            "filesystem",
            true,
            "workdir mounted read-write at /workspace; nothing else is visible \
             (containers are deny-by-default by construction) -- other \
             [filesystem] read_only/read_write/deny entries are not applied by \
             this backend",
        );
        let net_applied = spec.profile.network.mode == NetworkMode::None;
        record(
            auditor,
            &spec.id,
            &mut layers,
            "network",
            net_applied,
            if net_applied {
                "container has no network (--network none)"
            } else {
                "only `none` is enforced by this backend; loopback/allowlist/full \
                 all get the container runtime's default network (unfiltered NAT)"
            },
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "resources",
            false,
            "wslc's resource-limit flag syntax is not yet confirmed against a \
             real preview build; memory/cpu/pids from [resources] are not applied",
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "environment",
            true,
            "filtered, passed as `-e` per variable",
        );

        if spec.dry_run {
            return Ok(SandboxReport {
                id: spec.id.clone(),
                backend: self.backend(),
                exit_code: None,
                signal: None,
                duration: std::time::Duration::ZERO,
                layers,
                dry_run: true,
            });
        }

        let start = Instant::now();
        let mut child = Command::new(WSLC_PATH)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|source| SandboxError::Spawn {
                command: "wslc".to_string(),
                source,
            })?;

        let timeout = spec.profile.resources.timeout.map(|d| d.as_duration());
        let (status, timed_out) = common::wait_with_timeout(&mut child, timeout)?;
        let duration = start.elapsed();
        let exit_code = status.code();

        if timed_out {
            auditor.record(AuditEvent::Violation {
                id: spec.id.clone(),
                kind: "timeout".into(),
                detail: "wslc container killed after timeout".into(),
            });
        }
        auditor.record(AuditEvent::SandboxExit {
            id: spec.id.clone(),
            code: exit_code,
            signal: None,
            duration_ms: duration.as_millis(),
        });

        if timed_out {
            return Err(SandboxError::Timeout {
                timeout: "configured".to_string(),
            });
        }

        Ok(SandboxReport {
            id: spec.id.clone(),
            backend: self.backend(),
            exit_code,
            signal: None,
            duration,
            layers,
            dry_run: false,
        })
    }
}

/// Compile a spec into `wslc run` arguments. Pure and separately testable
/// so the argument shape can be checked without `wslc.exe` installed.
fn build_wslc_args(spec: &SandboxSpec, workdir: &std::path::Path) -> Result<Vec<String>> {
    let image = spec
        .profile
        .windows
        .container_image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            SandboxError::layer(
                "setup",
                "windows.container_image must be set to use the wslc backend",
            )
        })?;

    let mut args = vec!["run".to_string(), "--rm".to_string()];

    // Host-side path syntax assumes wslc, like Docker Desktop on Windows,
    // parses a drive-letter colon (`C:\...`) specially rather than as the
    // HOST:CONTAINER separator -- unverified against a real install (see
    // module docs), but it's the same ambiguity Docker itself solved this
    // way, and wslc is explicitly Docker-CLI-compatible.
    args.push("-v".to_string());
    args.push(format!("{}:/workspace", workdir.display()));
    args.push("-w".to_string());
    args.push("/workspace".to_string());

    if spec.profile.network.mode == NetworkMode::None {
        args.push("--network".to_string());
        args.push("none".to_string());
    }

    for (k, v) in common::resolved_env_vars(&spec.profile.env) {
        args.push("-e".to_string());
        args.push(format!("{k}={v}"));
    }

    args.push(image.to_string());
    args.extend(spec.command.iter().cloned());
    Ok(args)
}

#[allow(clippy::too_many_arguments)]
fn record(
    auditor: &mut Auditor,
    id: &str,
    layers: &mut Vec<LayerOutcome>,
    layer: &str,
    applied: bool,
    detail: &str,
) {
    if applied {
        auditor.record(AuditEvent::LayerApplied {
            id: id.to_string(),
            layer: layer.to_string(),
            detail: detail.to_string(),
        });
        layers.push(LayerOutcome::applied(layer, detail));
    } else {
        auditor.record(AuditEvent::LayerSkipped {
            id: id.to_string(),
            layer: layer.to_string(),
            reason: detail.to_string(),
        });
        layers.push(LayerOutcome::skipped(layer, detail));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confinery_core::network::{NetworkMode, NetworkPolicy};
    use confinery_core::windows::WindowsPolicy;
    use confinery_core::Profile;

    fn spec_with(profile: Profile) -> SandboxSpec {
        SandboxSpec::new(profile, vec!["claude".to_string(), "--version".to_string()])
    }

    #[test]
    fn requires_container_image() {
        let spec = spec_with(Profile::default());
        let err = build_wslc_args(&spec, std::path::Path::new("C:\\proj")).unwrap_err();
        assert!(matches!(err, SandboxError::Layer { .. }));
    }

    #[test]
    fn rejects_blank_container_image() {
        let mut profile = Profile::default();
        profile.windows.container_image = Some("   ".to_string());
        let spec = spec_with(profile);
        assert!(build_wslc_args(&spec, std::path::Path::new("C:\\proj")).is_err());
    }

    #[test]
    fn builds_mount_and_workdir_and_image_and_command() {
        let profile = Profile {
            windows: WindowsPolicy {
                container_image: Some("node:20".to_string()),
            },
            ..Profile::default()
        };
        let spec = spec_with(profile);
        let args = build_wslc_args(&spec, std::path::Path::new("C:\\proj")).unwrap();

        assert_eq!(args[0], "run");
        assert!(args.contains(&"--rm".to_string()));
        let v_pos = args.iter().position(|a| a == "-v").unwrap();
        assert_eq!(args[v_pos + 1], "C:\\proj:/workspace");
        let w_pos = args.iter().position(|a| a == "-w").unwrap();
        assert_eq!(args[w_pos + 1], "/workspace");
        assert_eq!(args[args.len() - 2], "claude");
        assert_eq!(args[args.len() - 1], "--version");
        // The image comes right before the command.
        let image_pos = args.len() - 3;
        assert_eq!(args[image_pos], "node:20");
    }

    #[test]
    fn network_none_adds_flag() {
        let mut profile = Profile::default();
        profile.windows.container_image = Some("node:20".to_string());
        profile.network = NetworkPolicy {
            mode: NetworkMode::None,
            allow: vec![],
        };
        let spec = spec_with(profile);
        let args = build_wslc_args(&spec, std::path::Path::new("C:\\proj")).unwrap();
        assert!(args.windows(2).any(|w| w == ["--network", "none"]));
    }

    #[test]
    fn network_full_omits_flag() {
        let mut profile = Profile::default();
        profile.windows.container_image = Some("node:20".to_string());
        profile.network = NetworkPolicy {
            mode: NetworkMode::Full,
            allow: vec![],
        };
        let spec = spec_with(profile);
        let args = build_wslc_args(&spec, std::path::Path::new("C:\\proj")).unwrap();
        assert!(!args.contains(&"--network".to_string()));
    }

    #[test]
    fn env_allowlist_becomes_dash_e_flags() {
        std::env::set_var("CONFINERY_WSLC_TEST_VAR", "hello");
        let mut profile = Profile::default();
        profile.windows.container_image = Some("node:20".to_string());
        profile
            .env
            .allow
            .push("CONFINERY_WSLC_TEST_VAR".to_string());
        let spec = spec_with(profile);
        let args = build_wslc_args(&spec, std::path::Path::new("C:\\proj")).unwrap();
        assert!(args
            .windows(2)
            .any(|w| w[0] == "-e" && w[1] == "CONFINERY_WSLC_TEST_VAR=hello"));
        std::env::remove_var("CONFINERY_WSLC_TEST_VAR");
    }

    #[test]
    fn not_available_when_binary_missing() {
        // On this (non-Windows) test host the path can never exist; this
        // just documents the check is a plain existence probe, matching
        // the wsl2/windows_sandbox checks in detect.rs.
        assert!(!WslcSandbox::is_available());
    }
}
