//! Errors from the sandbox engine.

/// Result alias for sandbox operations.
pub type Result<T> = std::result::Result<T, SandboxError>;

/// Errors raised while preparing or running a sandbox.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("this platform is not supported by the Confinery sandbox engine")]
    Unsupported,

    #[error("empty command: nothing to run")]
    EmptyCommand,

    #[error("tool `{0}` is not in the profile allowlist")]
    ToolDenied(String),

    #[error("failed to set up isolation layer `{layer}`: {message}")]
    Layer { layer: String, message: String },

    #[error("failed to spawn `{command}`: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("sandboxed process was terminated by the {timeout} timeout")]
    Timeout { timeout: String },

    #[error("unknown syscall `{0}` in policy")]
    UnknownSyscall(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl SandboxError {
    pub fn layer(layer: impl Into<String>, message: impl Into<String>) -> Self {
        SandboxError::Layer {
            layer: layer.into(),
            message: message.into(),
        }
    }
}
