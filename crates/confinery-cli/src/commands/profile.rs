//! `confinery profile` — validate, show, and list profiles.

use confinery_core::policy;
use confinery_core::Profile;

use crate::cli::ProfileCommand;
use crate::templates;

pub fn run(command: ProfileCommand) -> anyhow::Result<i32> {
    match command {
        ProfileCommand::Validate { path, json } => validate(&path, json),
        ProfileCommand::Show { path, json } => show(&path, json),
        ProfileCommand::List => list(),
    }
}

fn validate(path: &std::path::Path, json: bool) -> anyhow::Result<i32> {
    let profile = Profile::load(path)?;
    let report = policy::validate(&profile);

    if json {
        let diagnostics: Vec<_> = report
            .diagnostics
            .iter()
            .map(|d| {
                serde_json::json!({
                    "severity": d.severity.to_string(),
                    "code": d.code,
                    "field": d.field,
                    "message": d.message,
                })
            })
            .collect();
        let out = serde_json::json!({
            "valid": report.is_valid(),
            "errors": report.error_count(),
            "warnings": report.warning_count(),
            "diagnostics": diagnostics,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for d in &report.diagnostics {
            println!("{d}");
        }
        if report.diagnostics.is_empty() {
            println!("ok: no issues");
        } else {
            println!(
                "{} error(s), {} warning(s)",
                report.error_count(),
                report.warning_count()
            );
        }
    }

    Ok(if report.is_valid() { 0 } else { 1 })
}

fn show(path: &std::path::Path, json: bool) -> anyhow::Result<i32> {
    let profile = Profile::load(path)?;
    if json {
        println!("{}", profile.to_json_string()?);
    } else {
        print!("{}", profile.to_toml_string()?);
    }
    Ok(0)
}

fn list() -> anyhow::Result<i32> {
    println!("built-in templates (use with `confinery init <name>`):");
    for t in templates::BUILTINS {
        println!("  {:<10} {}", t.name, t.description);
    }
    let name = "minimal";
    let desc = "least-privilege baseline from defaults";
    println!("  {name:<10} {desc}");
    Ok(0)
}
