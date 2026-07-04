//! Platform-agnostic helpers shared by the sandbox backends.

use std::process::Command;

use confinery_core::env::{EnvMode, EnvPolicy};

#[cfg(windows)]
use std::process::Child;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};

/// Apply an environment policy to a command builder.
///
/// The parent environment is filtered according to `mode`, explicit overrides
/// are set last, and a `PATH` is guaranteed so relative program names resolve.
pub fn apply_env(cmd: &mut Command, env: &EnvPolicy) {
    cmd.env_clear();
    // `resolved_env_vars` drops non-UTF-8 values (it has to, for backends
    // that need plain strings); passthrough mode here can still carry them
    // through untouched via `cmd.env`, so handle it separately rather than
    // going through the shared resolver and losing that fidelity.
    match env.mode {
        EnvMode::Passthrough => {
            for (k, v) in std::env::vars_os() {
                cmd.env(k, v);
            }
            for (k, v) in &env.set {
                cmd.env(k, v);
            }
        }
        EnvMode::Allowlist | EnvMode::Clear => {
            for (k, v) in resolved_env_vars(env) {
                cmd.env(k, v);
            }
        }
    }
    let has_path = cmd.get_envs().any(|(k, _)| k.eq_ignore_ascii_case("PATH"));
    if !has_path {
        cmd.env("PATH", default_path());
    }
}

/// Resolve an environment policy to concrete `(name, value)` pairs.
///
/// Same filtering as [`apply_env`], but as owned strings instead of applied
/// directly to a [`Command`] -- for backends that hand environment
/// variables to a subprocess indirectly (e.g. as repeated `-e KEY=VALUE`
/// CLI arguments to another program, rather than inheriting the calling
/// process's environment). Non-UTF-8 values are dropped rather than
/// lossily mangled, since a CLI argument has no other way to carry them.
pub fn resolved_env_vars(env: &EnvPolicy) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = Vec::new();
    match env.mode {
        EnvMode::Passthrough => {
            for (k, v) in std::env::vars_os() {
                if let (Ok(k), Ok(v)) = (k.into_string(), v.into_string()) {
                    vars.push((k, v));
                }
            }
        }
        EnvMode::Allowlist => {
            for name in &env.allow {
                if let Ok(v) = std::env::var(name) {
                    vars.push((name.clone(), v));
                }
            }
        }
        EnvMode::Clear => {}
    }
    for (k, v) in &env.set {
        match vars.iter_mut().find(|(k2, _)| k2 == k) {
            Some(existing) => existing.1 = v.clone(),
            None => vars.push((k.clone(), v.clone())),
        }
    }
    if !vars.iter().any(|(k, _)| k.eq_ignore_ascii_case("PATH")) {
        vars.push(("PATH".to_string(), default_path().to_string()));
    }
    vars
}

/// Wait for `child` to exit, killing it by PID if `timeout` elapses first.
///
/// Same shape as the Linux backend's own `wait_with_timeout` (a watcher
/// thread kills by PID while the main thread blocks in `child.wait()`,
/// since a `&mut Child` can't be shared between the two) -- Windows-only
/// today because that Linux version already exists and is untouched; this
/// is for the `wslc` backend (see `windows/wslc.rs`), which has no
/// equivalent of its own. Returns `(exit_status, was_killed_for_timeout)`.
#[cfg(windows)]
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Option<Duration>,
) -> std::io::Result<(std::process::ExitStatus, bool)> {
    let Some(timeout) = timeout else {
        return Ok((child.wait()?, false));
    };

    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let pid = child.id();
    let killer = thread::spawn(move || -> bool {
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
        kill_by_pid(pid);
        true
    });

    let status = child.wait()?;
    done.store(true, Ordering::SeqCst);
    let timed_out = killer.join().unwrap_or(false);
    Ok((status, timed_out))
}

#[cfg(windows)]
fn kill_by_pid(pid: u32) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle);
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn kill_by_pid(_pid: u32) {}

#[cfg(windows)]
fn default_path() -> &'static str {
    r"C:\Windows\System32;C:\Windows"
}

#[cfg(not(windows))]
fn default_path() -> &'static str {
    "/usr/local/bin:/usr/bin:/bin"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_injects_default_path_when_missing() {
        std::env::remove_var("PATH");
        let env = EnvPolicy {
            mode: EnvMode::Clear,
            ..EnvPolicy::default()
        };
        let mut cmd = Command::new("true");
        apply_env(&mut cmd, &env);
        assert!(cmd.get_envs().any(|(k, v)| k == "PATH" && v.is_some()));
    }
}
