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

### Network namespace

`none` and `loopback` modes get an isolated network stack with no route off the host. `loopback` additionally raises `lo`. `allowlist` and `full` share the host network; host-based allowlisting is not yet enforced in-kernel and is reported as such.

### Seccomp

A seccomp-BPF filter is installed last, covering the `execve` into the target. Two shapes:

- **Denylist** (default): everything runs except a curated dangerous set — `mount`, `ptrace`, `bpf`, `kexec_*`, module loading, keyrings, `unshare`, `io_uring`, and more. Rarely breaks normal programs.
- **Allowlist**: only a preset plus explicit entries run; everything else gets `EPERM` or `SIGKILL`. Tighter, needs tuning per workload.

### Capabilities and no_new_privs

All capabilities are dropped from every set by default, including the bounding set, so they cannot return across `execve`. `PR_SET_NO_NEW_PRIVS` blocks privilege escalation through setuid binaries and is required by Landlock and seccomp.

### Resource limits

cgroups v2 caps memory, CPU, and process count when the hierarchy is writable (root or a delegated slice). rlimits (`RLIMIT_NOFILE`, `RLIMIT_CORE`, `RLIMIT_NPROC`) apply everywhere as a portable fallback. A wall-clock timeout kills the process when it overruns.

## Windows layers

A Job Object bounds committed memory and active process count, terminates the whole tree together (`KILL_ON_JOB_CLOSE`), and applies UI restrictions (no desktop, clipboard, or global atoms). The environment is filtered like every backend. Filesystem and network confinement require WSL2 or Windows Sandbox and are reported as not enforced — Confinery never claims a boundary it did not build.

## Defaults

Least privilege out of the box: no network, deny-by-default filesystem, all capabilities dropped, dangerous syscalls blocked, secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, cloud and container configs) masked, and a filtered environment that does not forward the full parent env.

## Known limits

- Read-only bind mounts are not made read-only recursively; submounts under a read-only path may stay writable. System directories rarely have any.
- Host-based network allowlisting is not enforced in-kernel yet.
- cgroup limits are skipped without a writable, delegated hierarchy; rlimits still apply.
- Windows filesystem/network isolation is not implemented.

When a layer cannot be applied, Confinery records it in the audit trail and the run report rather than pretending it succeeded.
