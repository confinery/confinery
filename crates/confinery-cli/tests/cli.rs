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

/// A tempdir suitable for use as a sandboxed `read_only`/`read_write`/`deny`
/// path -- i.e. *not* under `/tmp`. Confinery's own mount setup stages its
/// new root by mounting a fresh tmpfs directly onto `/tmp` before it
/// processes the filesystem allowlist, which silently shadows the host's
/// real `/tmp` (and anything under it, including whatever
/// `tempfile::tempdir()`'s default location would produce) for the rest of
/// that setup. A profile pointing at a path under `/tmp` doesn't fail --
/// `bind_path` treats "doesn't exist here" as a silent no-op, matching its
/// handling of any other absent host path -- so a test built on one can
/// pass for the wrong reason (the command fails because the path was never
/// bound at all, not because a boundary it's supposed to test rejected
/// something). `CARGO_TARGET_TMPDIR` is Cargo's own answer to exactly this
/// class of problem for test binaries.
fn non_tmp_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// Whether this host actually supports Confinery's `isolate` (namespace)
/// plan, per `confinery doctor`. Sysctls alone are not a reliable signal --
/// some CI hosts (notably GitHub Actions' `ubuntu-latest`, which enables an
/// AppArmor policy restricting unprivileged user namespaces by default)
/// pass the static checks but still deny the operation at runtime, which is
/// exactly what `confinery doctor` now probes for directly. Tests that are
/// specific to the mount-namespace/pivot_root mechanism must check this and
/// skip gracefully rather than fail on such a host, per this project's own
/// testing rule ("Isolation tests must degrade gracefully on hosts that
/// lack a feature", CONTRIBUTING.md).
#[cfg(target_os = "linux")]
fn namespaces_available() -> bool {
    let out = confinery().arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    stdout
        .lines()
        .any(|l| l.contains("user_namespaces") && l.trim_start().starts_with("[ok"))
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

// Actually launches a process under isolation. `--isolation auto` (the
// default) degrades to the `confine` plan when the host's `isolate` plan
// isn't usable -- including hosts that pass the static namespace sysctls
// but still deny it at runtime, such as GitHub Actions' `ubuntu-latest`
// runners (see the `detect::userns_actually_works` probe) -- so this test
// intentionally does not force a specific isolation mode.
#[cfg(target_os = "linux")]
#[test]
fn runs_a_command_in_the_sandbox() {
    confinery()
        .args(["run", "--", "echo", "hello-confinery"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello-confinery"));
}

// Regression test for the `deny` masking fix: a denied path bound in through
// an allowed parent must actually be unreadable inside the sandbox, not just
// "masked if the mount happens to succeed". This exercises the mount/
// pivot_root mechanism specifically (Landlock, used by the `confine`
// fallback, cannot carve a denied child out of an allowed parent at all --
// that is a documented, intentional difference between the two plans, not
// something this test should be asserting on), so it forces `isolate` mode
// and skips on hosts where that plan genuinely isn't available.
#[cfg(target_os = "linux")]
#[test]
fn deny_list_masks_secret_file_contents() {
    if !namespaces_available() {
        eprintln!("skipping: isolate (namespace) mode unavailable on this host");
        return;
    }
    let dir = non_tmp_tempdir();
    let ro = dir.path().join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    let secret = ro.join("secret");
    std::fs::write(&secret, "topsecret-value").unwrap();

    let profile = format!(
        "name = \"deny-test\"\n\
         [filesystem]\n\
         read_only = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", {:?}]\n\
         deny = [{:?}]\n\
         [network]\n\
         mode = \"none\"\n",
        ro, secret
    );
    let path = write_profile(&dir, "deny.toml", &profile);

    // `.success()` matters as much as the content check: if the path were
    // never bound at all (e.g. it lived somewhere Confinery's own setup
    // shadows), `cat` would fail for an unrelated reason and the "does not
    // contain the secret" assertion would pass for the wrong reason.
    confinery()
        .args(["run", "--isolation", "namespaces", "--profile"])
        .arg(&path)
        .args(["--", "cat", secret.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("topsecret-value").not());
}

// Regression test for the symlink-safe masking fix: a `deny` entry that
// names a symlink must mask the symlink node itself, not follow it and mask
// whatever it points to -- especially when that target is *also* separately
// reachable through another allowed path, which is exactly the case a naive
// path-based mount() gets wrong (it follows the link and masks the wrong
// location, leaving the symlink fully readable). Confirmed manually before
// writing this test: reverting the fix makes this test fail with the real
// secret content on stdout.
#[cfg(target_os = "linux")]
#[test]
fn deny_masks_symlink_without_leaking_its_separately_allowed_target() {
    if !namespaces_available() {
        eprintln!("skipping: isolate (namespace) mode unavailable on this host");
        return;
    }
    let dir = non_tmp_tempdir();
    let ro = dir.path().join("ro");
    let other = dir.path().join("other");
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let real = other.join("real-secret.txt");
    std::fs::write(&real, "leaked-secret-content").unwrap();
    let link = ro.join("secret-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let profile = format!(
        "name = \"symlink-deny-test\"\n\
         [filesystem]\n\
         read_only = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", {:?}, {:?}]\n\
         deny = [{:?}]\n\
         [network]\n\
         mode = \"none\"\n",
        ro, other, link
    );
    let path = write_profile(&dir, "symlink-deny.toml", &profile);

    // The symlink itself must be masked...
    confinery()
        .args(["run", "--isolation", "namespaces", "--profile"])
        .arg(&path)
        .args(["--", "cat", link.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("leaked-secret-content").not());

    // ...without over-masking the target, which is legitimately allowed via
    // its own separate, non-denied path.
    confinery()
        .args(["run", "--isolation", "namespaces", "--profile"])
        .arg(&path)
        .args(["--", "cat", real.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("leaked-secret-content"));
}

// Regression test for the read-only-remount fix: a `read_only` path must
// actually reject writes inside the sandbox, and the fix must not silently
// let the write through. Specific to the mount/pivot_root mechanism (see
// the comment on `deny_list_masks_secret_file_contents`), so it forces
// `isolate` mode and skips where that plan isn't available.
#[cfg(target_os = "linux")]
#[test]
fn read_only_paths_reject_writes() {
    if !namespaces_available() {
        eprintln!("skipping: isolate (namespace) mode unavailable on this host");
        return;
    }
    let dir = non_tmp_tempdir();
    let ro = dir.path().join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    let target = ro.join("public.txt");
    std::fs::write(&target, "original").unwrap();

    let profile = format!(
        "name = \"ro-test\"\n\
         [filesystem]\n\
         read_only = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", {:?}]\n\
         [network]\n\
         mode = \"none\"\n",
        ro
    );
    let path = write_profile(&dir, "ro.toml", &profile);

    // Prove the path is actually bound and readable first: otherwise a
    // write failing because the path doesn't exist at all would pass this
    // test for the wrong reason (see `non_tmp_tempdir`).
    confinery()
        .args(["run", "--isolation", "namespaces", "--profile"])
        .arg(&path)
        .args(["--", "cat", target.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("original"));

    confinery()
        .args(["run", "--isolation", "namespaces", "--profile"])
        .arg(&path)
        .args([
            "--",
            "sh",
            "-c",
            &format!("echo modified > {}", target.to_str().unwrap()),
        ])
        .assert()
        .failure();

    // The write must not have reached the host file either.
    let contents = std::fs::read_to_string(&target).unwrap();
    assert_eq!(contents, "original");
}
