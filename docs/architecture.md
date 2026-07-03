# Architecture

Confinery is a Cargo workspace of three crates. The split keeps the policy model free of platform code, so the same profile drives every backend.

```
confinery-core ──► confinery-sandbox ──► confinery-cli (binary: confinery)
   model                engine                  commands
```

## Crates

**`confinery-core`** — the domain model, no OS calls.

- `profile` — the `Profile` struct and TOML/JSON loading.
- `filesystem`, `network`, `resources`, `capabilities`, `syscalls`, `env` — the policy sections, each with least-privilege defaults.
- `units` — `ByteSize` and `HumanDuration` parsers (`2GiB`, `10m`).
- `policy` — static validation producing structured diagnostics.
- `audit` — JSONL event sink.
- `logging` — `tracing` setup.

**`confinery-sandbox`** — the execution engine.

- `Sandbox` trait: takes a `SandboxSpec`, returns a `SandboxReport`.
- `spec` / `report` — the compiled run request and its outcome.
- `detect` — host capability probing (`confinery doctor`).
- `linux/` — namespaces, mounts (`pivot_root`), cgroups, seccomp, Landlock, rlimits, capability dropping, and the syscall table.
- `windows/` — Job Object backend.
- `unsupported` — fails closed on other platforms.

**`confinery-cli`** — the `confinery` binary: argument parsing (clap), the `run`, `profile`, `doctor`, and `init` commands, and the embedded profile templates.

## How a run flows

1. `confinery-cli` loads the profile (or the built-in default) and validates it. Errors stop the run before anything is spawned.
2. It builds a `SandboxSpec` (profile + command + runtime options) and picks an isolation mode from `--isolation` and host detection.
3. `confinery-sandbox` selects the platform backend and compiles the policy into concrete plans: a seccomp BPF program, a mount layout, a Landlock ruleset, rlimit values, a capability set.
4. Resource limits that live in the parent (cgroups) are set up, then the child is spawned. A pre-exec hook applies the in-process layers in order and installs seccomp last, immediately before `execve`.
5. The parent waits (enforcing any wall-clock timeout), writes audit events, and returns a report. The CLI propagates the child's exit code.

## Extending it

- **New policy field:** add it to the relevant `confinery-core` section with a default, extend `policy::validate`, then honour it in a backend.
- **New backend:** implement `Sandbox` for the platform and wire it into `platform_sandbox()` behind a `cfg`.
- **New syscall preset:** add a name list to `linux/syscall_table.rs` and map it in `linux/seccomp.rs`.

Every layer is independent and best-effort where the host allows, so adding one never weakens the others.
