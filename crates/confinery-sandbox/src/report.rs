//! The outcome of a sandbox run and the layers that were applied.

use std::time::Duration;

/// Whether a security layer took effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerStatus {
    /// The layer was applied.
    Applied,
    /// The layer was skipped (unsupported host or disabled by policy).
    Skipped,
}

/// Record of a single security layer's fate for one run.
#[derive(Debug, Clone)]
pub struct LayerOutcome {
    pub layer: String,
    pub status: LayerStatus,
    pub detail: String,
}

impl LayerOutcome {
    pub fn applied(layer: impl Into<String>, detail: impl Into<String>) -> Self {
        LayerOutcome {
            layer: layer.into(),
            status: LayerStatus::Applied,
            detail: detail.into(),
        }
    }

    pub fn skipped(layer: impl Into<String>, detail: impl Into<String>) -> Self {
        LayerOutcome {
            layer: layer.into(),
            status: LayerStatus::Skipped,
            detail: detail.into(),
        }
    }

    pub fn is_applied(&self) -> bool {
        self.status == LayerStatus::Applied
    }
}

/// Result of running (or planning) a sandboxed command.
#[derive(Debug, Clone)]
pub struct SandboxReport {
    pub id: String,
    /// Process exit code, when it exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal number, when killed by a signal.
    pub signal: Option<i32>,
    /// Wall-clock time the process ran.
    pub duration: Duration,
    /// Layers considered for this run.
    pub layers: Vec<LayerOutcome>,
    /// True when this was a dry run (nothing was executed).
    pub dry_run: bool,
}

impl SandboxReport {
    /// Exit code suitable for the CLI to propagate. Signals map to 128+signum,
    /// mirroring shell conventions.
    pub fn process_exit_code(&self) -> i32 {
        if let Some(code) = self.exit_code {
            code
        } else if let Some(sig) = self.signal {
            128 + sig
        } else {
            0
        }
    }

    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }

    pub fn applied_layers(&self) -> impl Iterator<Item = &LayerOutcome> {
        self.layers.iter().filter(|l| l.is_applied())
    }
}
