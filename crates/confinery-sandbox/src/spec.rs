//! The runtime specification handed to a platform sandbox.

use std::path::PathBuf;

use confinery_core::Profile;
use uuid_lite::new_id;

use crate::error::{Result, SandboxError};

/// Everything a sandbox implementation needs to launch one command.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Unique id for this run, used in audit records.
    pub id: String,
    /// Fully-resolved profile.
    pub profile: Profile,
    /// Command and arguments (`argv`).
    pub command: Vec<String>,
    /// Working directory inside the sandbox. Defaults to the current dir.
    pub workdir: Option<PathBuf>,
    /// Home directory used to expand `~` in profile paths.
    pub home: PathBuf,
    /// Allow OS namespace isolation (may be disabled for constrained hosts).
    pub allow_namespaces: bool,
    /// Prepare everything but do not exec; report the plan instead.
    pub dry_run: bool,
}

impl SandboxSpec {
    /// Build a spec from a profile and command, filling runtime defaults.
    pub fn new(profile: Profile, command: Vec<String>) -> Self {
        SandboxSpec {
            id: new_id(),
            profile,
            command,
            workdir: None,
            home: home_dir(),
            allow_namespaces: true,
            dry_run: false,
        }
    }

    /// The program to execute (`argv[0]`).
    pub fn program(&self) -> Result<&str> {
        self.command
            .first()
            .map(String::as_str)
            .ok_or(SandboxError::EmptyCommand)
    }

    /// Verify the command is permitted by the tool allowlist.
    pub fn check_tool_allowed(&self) -> Result<()> {
        let program = self.program()?;
        if self.profile.tools.allows(program) {
            Ok(())
        } else {
            Err(SandboxError::ToolDenied(program.to_string()))
        }
    }
}

fn home_dir() -> PathBuf {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    std::env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Tiny UUID-v4 generator to avoid a heavy dependency in the sandbox crate.
mod uuid_lite {
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Generate a random-ish 128-bit id rendered as a hyphenated hex string.
    ///
    /// This is used only to correlate audit records, so a cheap seed mixing
    /// time, pid, and address entropy is sufficient.
    pub fn new_id() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let stack = &nanos as *const _ as u128;
        let mut state = nanos ^ (pid << 64) ^ stack.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15;

        let mut bytes = [0u8; 16];
        for chunk in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let v = (state as u64).to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        // Set version (4) and variant bits.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        format!(
            "{}-{}-{}-{}-{}",
            h(&bytes[0..4]),
            h(&bytes[4..6]),
            h(&bytes[6..8]),
            h(&bytes[8..10]),
            h(&bytes[10..16])
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ids_are_unique_and_well_formed() {
            let a = new_id();
            let b = new_id();
            assert_ne!(a, b);
            assert_eq!(a.len(), 36);
            assert_eq!(a.as_bytes()[14], b'4'); // version nibble
        }
    }
}
