# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-04

First public release.

### Added

- `confinery run` sandboxes a command using the strongest isolation the host
  supports: user/mount/net/UTS/IPC namespaces with `pivot_root` on Linux
  when unprivileged user namespaces are available (**isolate**), falling
  back to Landlock, seccomp, rlimits, and capability dropping when they
  aren't (**confine**), and a Job Object on Windows.
- Layered controls: deny-by-default filesystem allowlisting, network
  isolation (`none`/`loopback`/`allowlist`/`full`), seccomp-BPF syscall
  filtering (denylist or allowlist), cgroups v2 + rlimit resource limits,
  full capability dropping, and environment variable filtering.
- Host-based network allowlisting (`network.mode = "allowlist"`): every
  `connect(2)` from the sandboxed process is routed through a seccomp
  user-notification filter to the parent, which allows or refuses it
  against a set of endpoints resolved once at startup. See
  [docs/security-model.md](docs/security-model.md#known-limits) for what
  this does and does not cover.
- `confinery doctor` reports which isolation features the current host
  actually supports, before you rely on any of them.
- `confinery profile validate`/`show` for checking and inspecting a
  profile, and `confinery init` for starter templates (`assistant`,
  `strict`, `dev`, `minimal`).
- An append-only JSONL audit trail (`--audit`) and a structured run report
  (`--json`) recording exactly which layers were applied, skipped, or
  unavailable for a given run — Confinery never claims a boundary it did
  not build.
- Shell completion generation (`confinery completions`).
- A CycloneDX SBOM generated and signed for every released binary.

### Security

- Every isolation layer fails closed: a layer that cannot be applied
  aborts the run (or is explicitly recorded as unenforced in the audit
  trail and report) rather than silently degrading.
- `confinery profile validate` refuses (as an error, not a warning) a
  profile that combines unrestricted network egress with forwarded
  credential-like environment variables.
- Read-only filesystem mounts are recursively read-only where the kernel
  supports it; masked (`deny`) paths are bound via `O_PATH|O_NOFOLLOW` to
  close a symlink-swap race.
- Audit log files are created with `0600` permissions.
- All GitHub Actions in CI/release workflows are pinned to commit SHAs.

### Known limitations

- PID namespace isolation is not implemented; the sandboxed process
  shares the host PID namespace. See
  [docs/security-model.md](docs/security-model.md#known-limits).
- On Windows, filesystem and network confinement are not implemented —
  only a Job Object (memory/process limits, whole-tree termination, UI
  restrictions) and environment filtering are enforced. WSL2 or Windows
  Sandbox are needed for real filesystem/network isolation there.
- Host-based network allowlisting only intercepts `connect(2)` (not
  connectionless UDP), resolves hostnames once at startup rather than
  pinning them, and cannot be layered a second time if Confinery itself
  runs inside another seccomp-user-notification-based sandbox.
