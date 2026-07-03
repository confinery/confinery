//! End-to-end tests driving the `confinery` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn confinery() -> Command {
    Command::cargo_bin("confinery").unwrap()
}

fn write_profile(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn doctor_reports_platform() {
    confinery()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("platform:"))
        .stdout(predicate::str::contains("backend:"));
}

#[test]
fn init_emits_named_template() {
    confinery()
        .args(["init", "strict"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name = \"strict\""));
}

#[test]
fn init_minimal_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let out = confinery()
        .args(["init", "minimal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let path = dir.path().join("minimal.toml");
    std::fs::write(&path, out).unwrap();
    confinery()
        .args(["profile", "validate"])
        .arg(&path)
        .assert()
        .success();
}

#[test]
fn validate_flags_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_profile(
        &dir,
        "bad.toml",
        "name = \"\"\n[resources]\nmemory = \"0\"\n",
    );
    confinery()
        .args(["profile", "validate"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(predicate::str::contains("memory.zero"));
}

#[test]
fn validate_json_is_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_profile(&dir, "ok.toml", "name = \"ok\"\n");
    confinery()
        .args(["profile", "validate", "--json"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"valid\": true"));
}

#[test]
fn show_fills_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_profile(&dir, "min.toml", "name = \"x\"\n");
    confinery()
        .args(["profile", "show"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("[filesystem]"))
        .stdout(predicate::str::contains("[syscalls]"));
}

#[test]
fn list_shows_builtins() {
    confinery()
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("assistant"))
        .stdout(predicate::str::contains("strict"));
}

#[test]
fn run_requires_a_command() {
    confinery().arg("run").assert().failure();
}

#[test]
fn dry_run_prints_plan() {
    confinery()
        .args(["run", "--dry-run", "--", "echo", "hi"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dry run"))
        .stdout(predicate::str::contains("seccomp"));
}

#[test]
fn tool_allowlist_denies_other_tools() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_profile(
        &dir,
        "tools.toml",
        "name = \"t\"\n[tools]\nallow = [\"python3\"]\n",
    );
    confinery()
        .args(["run", "--profile"])
        .arg(&path)
        .args(["--dry-run", "--", "echo", "hi"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the profile allowlist"));
}

#[test]
fn invalid_profile_blocks_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_profile(&dir, "bad.toml", "name = \"\"\n");
    confinery()
        .args(["run", "--profile"])
        .arg(&path)
        .args(["--dry-run", "--", "echo", "hi"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("validation"));
}

// Actually launches a process under isolation. Requires unprivileged user
// namespaces (available on GitHub-hosted Ubuntu runners).
#[cfg(target_os = "linux")]
#[test]
fn runs_a_command_in_the_sandbox() {
    confinery()
        .args(["run", "--", "echo", "hello-confinery"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello-confinery"));
}
