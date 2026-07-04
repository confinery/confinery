//! Windows-specific policy: opt-in configuration for backends that only
//! exist on that platform. Harmless, unused defaults elsewhere.

use serde::{Deserialize, Serialize};

/// Settings for the `wslc` (WSL Containers) backend.
///
/// `wslc` is a Microsoft public preview (announced 2026-07) that runs real
/// OCI Linux containers from Windows via a built-in `wslc.exe` CLI, backed
/// by Moby inside a dedicated Hyper-V VM -- no Docker Desktop required. It
/// gives genuine filesystem and network confinement (a container only sees
/// what's explicitly mounted, and has no network unless one is attached),
/// unlike the default Job Object backend, which only bounds resources and
/// filters the environment.
///
/// This is opt-in, not automatic: choosing it means running the sandboxed
/// command inside a Linux container rather than as a native Windows
/// process, which only makes sense for commands that have (or can run
/// from) a Linux build -- e.g. a Node.js or Python CLI. Leave this unset to
/// keep using the native Job Object backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPolicy {
    /// OCI image to run the command inside, e.g. `"node:20"`. When set (and
    /// `wslc.exe` is present -- see `confinery doctor`), `confinery run`
    /// uses the `wslc` backend instead of the Job Object backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
}
