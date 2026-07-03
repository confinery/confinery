# Profiles

A profile describes one sandbox. Write it in TOML (or JSON) and pass it with `--profile`. Every section is optional; anything you omit falls back to a least-privilege default, so a profile stays as short as your intent.

```
confinery init assistant -o assistant.toml   # start from a template
confinery profile show assistant.toml         # see it with all defaults filled in
confinery profile validate assistant.toml     # check before you run
```

## `name`, `description`

```toml
name = "assistant"
description = "Sandbox for a coding agent"
```

`name` is required and becomes the sandbox hostname (`confinery-<name>`).

## `[filesystem]`

Deny-by-default. Only listed paths are visible. `~` expands to the caller's home.

```toml
[filesystem]
read_only  = ["/usr", "/bin", "/etc/ssl"]   # visible, not writable
read_write = ["./"]                          # visible and writable
tmpfs      = ["/tmp"]                         # fresh in-memory scratch
deny       = ["~/.ssh", "~/.aws"]            # masked even if a parent is allowed
minimal_dev = true                            # expose null, zero, random, tty, ...
```

Defaults expose common system directories read-only, a `/tmp` tmpfs, and mask `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.kube`, `~/.docker/config.json`, and `/etc/shadow`. Nothing is writable by default.

On distros using the usr-merge layout, `/bin`, `/sbin`, `/lib`, and `/lib64` are symlinks into `/usr`. Listing one of them in `read_only`/`read_write` without also listing `/usr` produces a dangling symlink inside the sandbox rather than an error -- the tool you expected at `/bin/sh` simply won't be there. The default and shipped-template lists always include `/usr` alongside the others for this reason; if you trim a profile down, keep them together.

## `[network]`

```toml
[network]
mode  = "none"                    # none | loopback | allowlist | full
allow = ["api.anthropic.com:443"] # used when mode = "allowlist"
```

- `none` — isolated stack, no routes (default).
- `loopback` — isolated stack with `lo` up.
- `allowlist` — host network, but every `connect(2)` is routed through a seccomp user-notification filter to the parent, which allows it only if it matches a resolved `network.allow` entry; anything else gets a refused connection. Hostnames are resolved once at startup, and only `connect(2)` is covered (not connectionless UDP) — see [docs/security-model.md](security-model.md#known-limits).
- `full` — host network, unrestricted. Validation warns.

## `[resources]`

```toml
[resources]
memory     = "2GiB"   # 2GiB, 512MiB, 1GB, or a raw byte count
cpu        = 2        # cores (fractional allowed)
pids       = 512      # max processes/threads
open_files = 1024     # RLIMIT_NOFILE
timeout    = "10m"    # wall clock: 30s, 10m, 1h30m
core_dumps = false
```

Memory and CPU need a writable cgroup hierarchy; otherwise rlimits apply and `confinery doctor` shows cgroups as unavailable.

## `[syscalls]`

```toml
[syscalls]
enabled      = true
default      = "allow"      # allow => denylist; errno/kill => allowlist
preset       = "hardened"   # hardened | assistant | minimal
allow        = []           # extra syscalls to permit
deny         = []           # extra syscalls to block
block_action = "errno"      # errno | kill | log, for the denylist
```

Two modes:

- **Denylist** (`default = "allow"`, `preset = "hardened"`): block the curated dangerous set. Robust default.
- **Allowlist** (`default = "errno"` or `"kill"`, `preset = "assistant"` or `"minimal"`): only the preset plus `allow` run. Tighter; use `block_action = "log"` while tuning to discover missing calls.

## `[capabilities]`

```toml
[capabilities]
keep = []   # e.g. ["net_bind_service"]; default drops everything
```

Names are the kernel short form without `CAP_`.

## `[env]`

```toml
[env]
mode  = "allowlist"          # allowlist | passthrough | clear
allow = ["PATH", "HOME", "TERM", "LANG"]
set   = { CONFINERY = "1" }
```

`allowlist` forwards only the named variables (the default set covers `PATH`, `HOME`, `USER`, `LANG`, `TERM`, and similar). `passthrough` forwards the whole environment and is flagged by validation because it can leak secrets.

## `[tools]`

```toml
[tools]
allow = ["python3", "node", "git"]   # empty = any command
```

Checked against the command's basename before the sandbox starts.

**This is a usability guard, not a security boundary.** It only checks the program named on the command line -- an allowed interpreter (`python3`, `bash`, ...) can still `exec`/spawn anything else once running, unaffected by this list. The syscall, capability, filesystem, and network layers are what actually confine the process; `[tools]` exists to catch "wrong command" mistakes early, not to restrict what a running program can do.

## Built-in templates

| Template | For |
|----------|-----|
| `assistant` | balanced sandbox for a coding agent (loopback network by default; see the profile's own comments before switching to `full`) |
| `strict` | maximum isolation, no network, seccomp allowlist |
| `dev` | generous limits, loopback network |
| `minimal` | least-privilege baseline from defaults |

See the shipped examples in [`profiles/`](../profiles).
