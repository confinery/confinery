//! Core domain model for Confinery: profiles, policies, validation, and auditing.
//!
//! This crate is platform-agnostic. It describes *what* a sandbox should
//! enforce; the `confinery-sandbox` crate decides *how* to enforce it on a given OS.

pub mod audit;
pub mod capabilities;
pub mod env;
pub mod error;
pub mod filesystem;
pub mod logging;
pub mod network;
pub mod policy;
pub mod profile;
pub mod resources;
pub mod syscalls;
pub mod units;
pub mod windows;

pub use error::{CoreError, Result};
pub use profile::Profile;

/// Serde helper: default a `bool` field to `true`.
pub(crate) fn default_true() -> bool {
    true
}
