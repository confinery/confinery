//! `confinery run` — launch a command inside a sandbox.

use anyhow::{bail, Context};
use confinery_core::audit::Auditor;
use confinery_core::policy;
use confinery_core::Profile;
use confinery_sandbox::{detect, platform_sandbox, LayerStatus, SandboxReport, SandboxSpec};

use crate::cli::{Isolation, RunArgs};

pub fn run(args: RunArgs) -> anyhow::Result<i32> {
    let profile = match &args.profile {
        Some(path) => {
            Profile::load(path).with_context(|| format!("loading profile {}", path.display()))?
        }
        None => Profile::default(),
    };

    // Refuse to run an invalid profile.
    let validation = policy::validate(&profile);
    for diag in validation.warnings() {
        tracing::warn!(code = diag.code, field = %diag.field, "{}", diag.message);
    }
    if !validation.is_valid() {
        for diag in validation.errors() {
            eprintln!("confinery: {diag}");
        }
        bail!("profile failed validation");
    }

    let host = detect();
    let allow_namespaces = match args.isolation {
        Isolation::Auto => true,
        Isolation::Namespaces => {
            if !host.has("user_namespaces") || !host.has("mount_namespace") {
                bail!("namespace isolation requested but unavailable on this host (see `confinery doctor`)");
            }
            true
        }
        Isolation::Confine => false,
    };

    let mut spec = SandboxSpec::new(profile, args.command.clone());
    spec.allow_namespaces = allow_namespaces;
    spec.dry_run = args.dry_run;
    if let Some(workdir) = args.workdir {
        spec.workdir = Some(workdir);
    }

    let mut auditor = match &args.audit {
        Some(path) => Auditor::to_file(path)
            .with_context(|| format!("opening audit log {}", path.display()))?,
        None => Auditor::disabled(),
    };

    let sandbox = platform_sandbox();
    let report = sandbox.run(&spec, &mut auditor)?;

    if args.dry_run {
        print_plan(&report, sandbox.backend());
        return Ok(0);
    }
    if args.json {
        eprintln!("{}", report_json(&report));
    }

    Ok(report.process_exit_code())
}

fn print_plan(report: &SandboxReport, backend: &str) {
    println!("sandbox {} ({backend}) — dry run", report.id);
    println!("plan:");
    for layer in &report.layers {
        let mark = match layer.status {
            LayerStatus::Applied => "ok",
            LayerStatus::Skipped => "--",
        };
        println!("  [{mark}] {:<14} {}", layer.layer, layer.detail);
    }
}

fn report_json(report: &SandboxReport) -> String {
    let layers: Vec<_> = report
        .layers
        .iter()
        .map(|l| {
            serde_json::json!({
                "layer": l.layer,
                "status": match l.status {
                    LayerStatus::Applied => "applied",
                    LayerStatus::Skipped => "skipped",
                },
                "detail": l.detail,
            })
        })
        .collect();
    let value = serde_json::json!({
        "id": report.id,
        "exit_code": report.exit_code,
        "signal": report.signal,
        "duration_ms": report.duration.as_millis(),
        "dry_run": report.dry_run,
        "layers": layers,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}
