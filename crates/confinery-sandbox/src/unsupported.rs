//! Fallback backend for platforms without a native isolation implementation.

use confinery_core::audit::Auditor;

use crate::error::{Result, SandboxError};
use crate::spec::SandboxSpec;
use crate::{Sandbox, SandboxReport};

/// Refuses to run: better to fail closed than to run unsandboxed.
pub struct UnsupportedSandbox;

impl Sandbox for UnsupportedSandbox {
    fn run(&self, _spec: &SandboxSpec, _auditor: &mut Auditor) -> Result<SandboxReport> {
        Err(SandboxError::Unsupported)
    }

    fn backend(&self) -> &'static str {
        "unsupported"
    }
}
