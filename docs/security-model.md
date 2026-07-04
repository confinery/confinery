# Security model

Confinery layers independent controls so no single failure exposes the host. This page describes each layer, what it stops, and where it stops short.

## Threat model

Confinery targets a semi-trusted program: an AI assistant or a tool it runs that you expect to behave, but do not want reaching credentials, deleting files outside its workspace, or phoning home. It raises the cost and blast radius of a mistake or a prompt injection.

Confinery is **not** a hypervisor. Against a kernel exploit or a determined attacker running native code you control, use a VM. Confinery reduces attack surface; it does not assume the kernel is hostile-proof.

## Linux layers

Applied in the child between `fork` and `execve`, so the target program is already constrained before its first instruction.

### User namespace

The caller is mapped to root inside a new user namespace. This grants the privileges needed to set up mounts and other namespaces without any real privilege on the host. Nothing inside the sandbox maps to a privileged host user.

### Mount namespace + pivot_root (isolate mode)

A fresh `tmpfs` becomes the root. Only allowlisted paths are bind mounted in, so anything not listed simply does not exist inside the sandbox — stronger than access control, because unlisted paths cannot even be named. Read-only mounts are remounted `MS_RDONLY`; `deny` paths are masked with empty mounts. `/dev` carries a minimal set of nodes; `/proc` is a fresh instance where possible.

### Landlock (confine mode)

When namespaces are unavailable, Landlock enforces the same path allowlist in-kernel using `no_new_privs`. It is an allowlist, so it cannot carve a denied child out of an allowed parent — that is the mount layer's job. In confine mode Confinery fails closed if Landlock is unavailable.

### Process isolation

UTS and IPC namespaces are unshared, giving the sandbox its own hostname and
IPC objects. **PID namespace isolation is not implemented.** Entering one
requires the process that calls `unshare(CLONE_NEWPID)` to then `fork()` a
child that becomes PID 1 of the new namespace -- the caller itself never
moves into it. That doesn't compose with how Confinery spawns today (a
single `pre_exec` hook that ends in `execve` of the target, not a fork), so
the sandboxed process shares the host's PID namespace. Combined with the
user namespace mapping the caller's own real UID, this means the sandboxed
process can see every process on the host owned by that UID via `/proc`,
and can signal (including `SIGKILL`) any of them -- a materially larger
blast radius than "confined to the sandbox". Restructuring the spawn path
around a small supervisor/init process (so the real target can become PID 1
of a genuine new namespace) is tracked as future work; until then, treat
process visibility and signaling as unconfined.

### Network namespace

`none` and `loopback` modes get an isolated network stack with no route off the host. `loopback` additionally raises `lo`. `allowlist` and `full` share the host network, since real network namespace isolation (a fresh namespace bridged to the host via veth/NAT) needs `CAP_NET_ADMIN` in the *host's* network namespace, which an unprivileged sandbox never has. `allowlist` is nonetheless enforced in-kernel: every `network.allow` entry is resolved to concrete addresses once, up front, and a seccomp user-notification filter routes every `connect(2)` call to the parent process, which allows or denies it against that resolved list — see [Known limits](#known-limits) for what this does and does not cover.

### Seccomp

A seccomp-BPF filter is installed last, covering the `execve` into the target. Two shapes:

- **Denylist** (default): everything runs except a curated dangerous set — `mount`, `ptrace`, `bpf`, `kexec_*`, module loading, keyrings, `unshare`, `io_uring`, and more. Rarely breaks normal programs.
- **Allowlist**: only a preset plus explicit entries run; everything else gets `EPERM` or `SIGKILL`. Tighter, needs tuning per workload.

### Capabilities and no_new_privs

All capabilities are dropped from every set by default, including the bounding set, so they cannot return across `execve`. `PR_SET_NO_NEW_PRIVS` blocks privilege escalation through setuid binaries and is required by Landlock and seccomp.

### Resource limits

cgroups v2 caps memory, CPU, and process count when the hierarchy is writable (root or a delegated slice). rlimits (`RLIMIT_NOFILE`, `RLIMIT_CORE`, `RLIMIT_NPROC`) apply everywhere as a portable fallback. A wall-clock timeout kills the process when it overruns.

## Windows layers

A Job Object bounds committed memory and active process count, terminates the whole tree together (`KILL_ON_JOB_CLOSE`), and applies UI restrictions (no desktop, clipboard, or global atoms). The environment is filtered like every backend. Filesystem and network confinement require WSL2, Windows Sandbox, or the `wslc` backend, and are otherwise reported as not enforced — Confinery never claims a boundary it did not build.

Setting `windows.container_image` in a profile switches to the `wslc` backend (Microsoft's public-preview WSL Containers), running the command in a real OCI Linux container instead: the working directory is mounted read-write at `/workspace` and nothing else is visible, and `network.mode = "none"` gets a real `--network none`. `[resources]` limits and the `loopback`/`allowlist`/`full` network modes are not enforced by this backend — see [docs/platform-support.md](platform-support.md#wslc-backend-experimental-preview-dependent) for exactly what's confirmed vs. assumed about this preview's CLI, and for why it hasn't been verified against a real install.

## Defaults

Least privilege out of the box: no network, deny-by-default filesystem, all capabilities dropped, dangerous syscalls blocked, secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, cloud and container configs) masked, and a filtered environment that does not forward the full parent env.

## Known limits

- PID namespace isolation is not implemented; see [Process isolation](#process-isolation) above.
- Read-only bind mounts are made recursively read-only on Linux 5.12+ via `mount_setattr`; older kernels (still new enough to support unprivileged user namespaces) fall back to a non-recursive remount, so a submount under a read-only path could stay writable there. System directories rarely carry any.
- `deny` masking is a mount-layer mechanism and only applies under the `isolate` plan. Landlock (the `confine` fallback's filesystem boundary) is an allowlist and cannot carve a denied child out of an allowed parent, so a `deny` entry has no effect when a host can't do namespaces.
- Host-based network allowlisting (`network.mode = "allowlist"`) only intercepts `connect(2)`; a connectionless UDP flow (e.g. a DNS query via `sendto` on an unconnected socket) is not covered, so this does not by itself close a UDP/DNS-based exfiltration channel. Hostnames in `network.allow` are resolved once, at startup, against the *parent's* resolver — not re-resolved or pinned for the run, so it is not DNS-rebinding-proof. It also can't be layered a second time if Confinery itself runs inside another seccomp-user-notification sandbox (the kernel permits only one such filter per thread's lifetime, checked across the whole inherited process ancestry); that case fails closed with an explicit error rather than silently running unfiltered.
- cgroup limits are skipped without a writable, delegated hierarchy; rlimits still apply.
- Windows filesystem/network isolation is not implemented on the Job Object backend, which does not otherwise restrict privileges either: the sandboxed process keeps the full token, group memberships, and filesystem ACL access of the invoking user.
- The `wslc` backend is unverified against a real preview install (developed without Windows/WSL-preview access) and only wires flags with strong independent corroboration; resource limits and non-`none` network modes are not enforced by it. Treat it as a starting point, not a finished boundary.

When a layer cannot be applied, Confinery records it in the audit trail and the run report rather than pretending it succeeded.
