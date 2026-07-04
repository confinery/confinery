//! The reproducible sandbox profile: the top-level configuration unit.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::capabilities::CapabilityPolicy;
use crate::env::EnvPolicy;
use crate::error::{CoreError, Result};
use crate::filesystem::FilesystemPolicy;
use crate::network::NetworkPolicy;
use crate::resources::ResourceLimits;
use crate::syscalls::SyscallPolicy;
use crate::windows::WindowsPolicy;

/// Executable allowlist. An empty list allows any command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolPolicy {
    /// Basenames of executables permitted to launch, e.g. `python3`.
    #[serde(default)]
    pub allow: Vec<String>,
}

impl ToolPolicy {
    /// Whether `command` may run under this policy.
    pub fn allows(&self, command: &str) -> bool {
        if self.allow.is_empty() {
            return true;
        }
        let base = Path::new(command)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(command);
        self.allow.iter().any(|t| t == base || t == command)
    }
}

/// Supported on-disk profile formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Toml,
    Json,
}

/// A complete sandbox profile. Missing sections fall back to least-privilege
/// defaults, so a minimal profile is still fully specified once loaded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Short identifier for the profile.
    pub name: String,

    /// Optional human description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub resources: ResourceLimits,

    #[serde(default)]
    pub capabilities: CapabilityPolicy,

    #[serde(default)]
    pub syscalls: SyscallPolicy,

    #[serde(default)]
    pub env: EnvPolicy,

    #[serde(default)]
    pub tools: ToolPolicy,

    /// Opt-in settings for Windows-only backends (currently just `wslc`).
    /// Meaningless -- and harmless -- on every other platform.
    #[serde(default)]
    pub windows: WindowsPolicy,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            name: "default".to_string(),
            description: Some("Least-privilege baseline sandbox".to_string()),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            resources: ResourceLimits::default(),
            capabilities: CapabilityPolicy::default(),
            syscalls: SyscallPolicy::default(),
            env: EnvPolicy::default(),
            tools: ToolPolicy::default(),
            windows: WindowsPolicy::default(),
        }
    }
}

impl Profile {
    /// Parse a profile from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }

    /// Parse a profile from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Load a profile from disk, choosing the format by file extension.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let format = format_of(path).ok_or_else(|| CoreError::UnknownFormat(path.to_path_buf()))?;
        let text = std::fs::read_to_string(path).map_err(|source| CoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        match format {
            Format::Toml => Self::from_toml_str(&text),
            Format::Json => Self::from_json_str(&text),
        }
    }

    /// Serialize the fully-resolved profile back to TOML.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| CoreError::invalid("profile", format!("cannot serialize: {e}")))
    }

    /// Serialize the fully-resolved profile to pretty JSON.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

fn format_of(path: &Path) -> Option<Format> {
    match path.extension().and_then(|s| s.to_str()) {
        Some("toml") => Some(Format::Toml),
        Some("json") => Some(Format::Json),
        _ => None,
    }
}

/// Expand a leading `~` in a path using the given home directory.
pub fn expand_home(path: &Path, home: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        home.join(rest)
    } else {
        path.to_path_buf()
    }
}

/// Resolve a profile path (after `~` expansion) to an absolute one, anchored
/// at `workdir` if it's still relative.
///
/// Every backend needs this: a bind-mount target built from an unresolved
/// relative path such as `./` does not error, but does not do what a
/// profile author means by it either. `Path::join`/the mount(2) syscall
/// both treat a bare `.` component as "here", so mounting a relative
/// `read_write` entry lands the caller's whole working directory *at the
/// sandbox's root* instead of as a subtree within it -- silently shadowing
/// every previously bound `read_only` path (`/usr`, `/bin`, ...) rather
/// than failing loudly. `read_write = ["./"]` is the exact form used in
/// every shipped profile template and the README's own example, so this
/// isn't a hypothetical edge case.
pub fn resolve_relative(path: &Path, workdir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workdir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_round_trips_through_toml() {
        let p = Profile::default();
        let toml = p.to_toml_string().unwrap();
        let back = Profile::from_toml_str(&toml).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn minimal_profile_fills_defaults() {
        let p = Profile::from_toml_str("name = \"mini\"\n").unwrap();
        assert_eq!(p.name, "mini");
        // Section defaults applied.
        assert!(!p.filesystem.read_only.is_empty());
        assert!(p.syscalls.enabled);
    }

    #[test]
    fn tool_allowlist_matches_basename() {
        let tools = ToolPolicy {
            allow: vec!["python3".into()],
        };
        assert!(tools.allows("/usr/bin/python3"));
        assert!(tools.allows("python3"));
        assert!(!tools.allows("bash"));
    }

    #[test]
    fn empty_tool_allowlist_permits_anything() {
        let tools = ToolPolicy::default();
        assert!(tools.allows("anything"));
    }

    #[test]
    fn windows_container_image_round_trips_through_toml() {
        let mut p = Profile::default();
        p.windows.container_image = Some("node:20".to_string());
        let toml = p.to_toml_string().unwrap();
        assert!(toml.contains("container_image"));
        let back = Profile::from_toml_str(&toml).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn windows_section_is_absent_by_default() {
        let p = Profile::default();
        let toml = p.to_toml_string().unwrap();
        assert!(!toml.contains("container_image"));
    }

    #[test]
    fn expands_home_paths() {
        let home = Path::new("/home/u");
        assert_eq!(
            expand_home(Path::new("~/.ssh"), home),
            PathBuf::from("/home/u/.ssh")
        );
        assert_eq!(
            expand_home(Path::new("/etc/hosts"), home),
            PathBuf::from("/etc/hosts")
        );
    }
}
