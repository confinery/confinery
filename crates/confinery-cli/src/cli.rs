//! Command-line surface for Confinery, defined with clap derive.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Securely sandbox ("confinery") AI assistants and the tools they run.
#[derive(Debug, Parser)]
#[command(name = "confinery", version, about, propagate_version = true)]
pub struct Cli {
    /// Log output format.
    #[arg(long, global = true, default_value = "human")]
    pub log_format: String,

    /// Log level when RUST_LOG is unset (error, warn, info, debug, trace).
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command inside a sandbox.
    Run(RunArgs),

    /// Inspect and validate profiles.
    #[command(subcommand)]
    Profile(ProfileCommand),

    /// Report which isolation features this host supports.
    Doctor,

    /// Write a starter profile to a file or stdout.
    Init(InitArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Profile file (.toml or .json). Uses the built-in baseline when omitted.
    #[arg(short, long)]
    pub profile: Option<PathBuf>,

    /// Append a JSONL audit trail to this file.
    #[arg(long)]
    pub audit: Option<PathBuf>,

    /// Isolation strategy.
    #[arg(long, value_enum, default_value_t = Isolation::Auto)]
    pub isolation: Isolation,

    /// Working directory inside the sandbox.
    #[arg(long)]
    pub workdir: Option<PathBuf>,

    /// Prepare and report the plan without executing the command.
    #[arg(long)]
    pub dry_run: bool,

    /// Print the run report as JSON on stderr.
    #[arg(long)]
    pub json: bool,

    /// The command to run, after `--`.
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Isolation {
    /// Use namespaces when available, otherwise fall back to confinement.
    Auto,
    /// Require namespace isolation; fail if unavailable.
    Namespaces,
    /// Skip namespaces; rely on seccomp, Landlock, rlimits, and capabilities.
    Confine,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Validate a profile and print diagnostics.
    Validate {
        /// Path to the profile.
        path: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the fully-resolved profile (defaults filled in).
    Show {
        /// Path to the profile.
        path: PathBuf,
        /// Emit JSON instead of TOML.
        #[arg(long)]
        json: bool,
    },
    /// List the built-in profile templates.
    List,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Which template to emit.
    #[arg(value_enum, default_value_t = Template::Assistant)]
    pub template: Template,

    /// Write to this path instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Template {
    /// Balanced profile for an AI coding assistant.
    Assistant,
    /// Maximum isolation.
    Strict,
    /// Developer profile with generous limits.
    Dev,
    /// Least-privilege baseline generated from defaults.
    Minimal,
}
