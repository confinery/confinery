# Platform support

Run `confinery doctor` to see exactly what your host offers.

## Linux

The primary target. Confinery picks the strongest plan available:

- **isolate** — unprivileged user namespace plus mount, network, PID, UTS, and IPC namespaces with a `pivot_root` filesystem. Requires unprivileged user namespaces (`kernel.unprivileged_userns_clone` / a non-zero `user.max_user_namespaces`). This is the default on modern distributions.
- **confine** — no namespaces; Landlock, seccomp, rlimits, and capability dropping. Used when user namespaces are disabled.

Force one with `--isolation namespaces|confine|auto`.

| Feature | Needs |
|---------|-------|
| Namespaces | unprivileged user namespaces enabled |
| Landlock | kernel 5.13+ with Landlock built in |
| seccomp | `CONFIG_SECCOMP_FILTER` (universal on modern kernels) |
| cgroup limits | cgroups v2 and a writable/delegated hierarchy |

cgroup limits usually need root or a systemd user slice with delegation. Without them, rlimits still bound file descriptors, core dumps, and process count.

Kernels 5.13+ are recommended for full Landlock; namespaces and seccomp work further back. WSL2 is supported and used to develop Confinery.

## Windows

A Job Object backend provides:

- committed-memory and active-process limits,
- whole-tree termination on exit,
- UI restrictions (no desktop, clipboard, or global atoms),
- environment filtering.

Filesystem and network confinement are **not** implemented on the native Job Object backend. For those, run Confinery inside a WSL2 distribution (full Linux isolation) or use Windows Sandbox. `confinery doctor` reports whether `wsl.exe` and Windows Sandbox are present. Confinery marks unenforced layers as skipped rather than implying protection it does not provide.

## Other platforms

macOS and other systems have no backend; Confinery fails closed rather than running a command unsandboxed.

## Reproducibility

The toolchain is pinned in `rust-toolchain.toml`, `Cargo.lock` is committed, and release binaries are built and signed only through GitHub Actions. The Linux release is a static musl binary with no runtime dependencies.
