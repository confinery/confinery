//! Built-in profile templates embedded into the binary.

use confinery_core::Profile;

pub const ASSISTANT: &str = include_str!("../../../profiles/assistant.toml");
pub const STRICT: &str = include_str!("../../../profiles/strict.toml");
pub const DEV: &str = include_str!("../../../profiles/dev.toml");

/// A named template with a one-line summary.
pub struct Template {
    pub name: &'static str,
    pub description: &'static str,
}

pub const BUILTINS: &[Template] = &[
    Template {
        name: "assistant",
        description: "Balanced sandbox for an AI coding assistant",
    },
    Template {
        name: "strict",
        description: "Maximum isolation: no network, seccomp allowlist",
    },
    Template {
        name: "dev",
        description: "Developer sandbox with generous limits",
    },
];

/// The least-privilege baseline profile serialized to TOML.
pub fn minimal() -> String {
    Profile::default()
        .to_toml_string()
        .unwrap_or_else(|_| String::from("name = \"minimal\"\n"))
}
