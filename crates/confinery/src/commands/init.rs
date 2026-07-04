//! `confinery init` — emit a starter profile.

use std::io::Write;

use crate::cli::{InitArgs, Template};
use crate::templates;

pub fn run(args: InitArgs) -> anyhow::Result<i32> {
    let body = match args.template {
        Template::Assistant => templates::ASSISTANT.to_string(),
        Template::Strict => templates::STRICT.to_string(),
        Template::Dev => templates::DEV.to_string(),
        Template::Minimal => templates::minimal(),
    };

    match args.output {
        Some(path) => {
            std::fs::write(&path, body)?;
            eprintln!("wrote {}", path.display());
        }
        None => {
            std::io::stdout().write_all(body.as_bytes())?;
        }
    }
    Ok(0)
}
