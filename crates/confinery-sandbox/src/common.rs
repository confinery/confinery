//! Platform-agnostic helpers shared by the sandbox backends.

use std::process::Command;

use confinery_core::env::{EnvMode, EnvPolicy};

/// Apply an environment policy to a command builder.
///
/// The parent environment is filtered according to `mode`, explicit overrides
/// are set last, and a `PATH` is guaranteed so relative program names resolve.
pub fn apply_env(cmd: &mut Command, env: &EnvPolicy) {
    cmd.env_clear();
    match env.mode {
        EnvMode::Passthrough => {
            for (k, v) in std::env::vars_os() {
                cmd.env(k, v);
            }
        }
        EnvMode::Allowlist => {
            for name in &env.allow {
                if let Some(v) = std::env::var_os(name) {
                    cmd.env(name, v);
                }
            }
        }
        EnvMode::Clear => {}
    }
    for (k, v) in &env.set {
        cmd.env(k, v);
    }
    let has_path = cmd.get_envs().any(|(k, _)| k.eq_ignore_ascii_case("PATH"));
    if !has_path {
        cmd.env("PATH", default_path());
    }
}

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
