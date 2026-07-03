//! Confinery sandbox engine.
//!
//! A [`Sandbox`] takes a [`SandboxSpec`] (a resolved profile plus a command)
//! and runs it under the strongest isolation the host supports, reporting
//! which layers were applied. Each OS has its own backend; unsupported systems
//! fall back to an implementation that refuses to run.

pub mod detect;
pub mod error;
pub mod report;
pub mod spec;

mod common;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

use confinery_core::audit::Auditor;

pub use detect::{detect, HostCapabilities};
pub use error::{Result, SandboxError};
pub use report::{LayerOutcome, LayerStatus, SandboxReport};
pub use spec::SandboxSpec;

/// A platform sandbox capable of running one command under isolation.
pub trait Sandbox {
    /// Run the command described by `spec`, emitting audit events to `auditor`.
    fn run(&self, spec: &SandboxSpec, auditor: &mut Auditor) -> Result<SandboxReport>;

    /// Human-readable backend name, e.g. `linux-namespaces`.
    fn backend(&self) -> &'static str;
}

/// Build the sandbox backend for the current platform.
pub fn platform_sandbox() -> Box<dyn Sandbox> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxSandbox::new())
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsSandbox::new())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Box::new(unsupported::UnsupportedSandbox)
    }
}
