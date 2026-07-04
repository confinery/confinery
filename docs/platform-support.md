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

### CPU architecture

The seccomp filter compiler only targets `x86_64` and `aarch64` -- the two
architectures `seccompiler` (and this project's own release pipeline)
support. Confinery does not build at all on other Linux architectures
(32-bit ARM, RISC-V, etc.); this is a build-time limitation, not a
runtime fallback, since `rust-toolchain.toml` only installs the
`x86_64-unknown-linux-musl` target. Namespaces, Landlock, and cgroups have
no such restriction and would work on any architecture the kernel
supports; only the seccomp compilation step is narrowed.

## Windows

A Job Object backend provides:

- committed-memory and active-process limits,
- whole-tree termination on exit,
- UI restrictions (no desktop, clipboard, or global atoms),
- environment filtering.

Filesystem and network confinement are **not** implemented on the native Job Object backend. For those, run Confinery inside a WSL2 distribution (full Linux isolation), use Windows Sandbox, or opt into the `wslc` backend below. `confinery doctor` reports whether `wsl.exe`, Windows Sandbox, and `wslc.exe` are present. Confinery marks unenforced layers as skipped rather than implying protection it does not provide.

### `wslc` backend (experimental, preview-dependent)

Setting `windows.container_image` in a profile switches `confinery run` from the Job Object backend to `wslc` (WSL Containers) -- a Microsoft *public preview* (announced 2026-07-02, GA targeted fall 2026) that runs real OCI Linux containers via a built-in `wslc.exe`, no Docker Desktop required. This gives genuine filesystem confinement (only the working directory is mounted, at `/workspace`) and network confinement (`network.mode = "none"` gets a real `--network none`), unlike the Job Object backend.

```toml
[windows]
container_image = "node:20"  # any OCI image with a Linux build of your tool
```

Only run a command this way if it has a Linux build -- this executes it inside a Linux container, not as a native Windows process.

**Preview caveats, read before relying on this:**

- `wslc`'s CLI reference for resource limits and finer-grained network modes isn't fully published yet. This backend only wires the flags with strong, independently-corroborated evidence (`-v`, `-w`, `-e`, `--network none`); `[resources]` (memory/cpu/pids) is reported as *not enforced* here rather than guessing at unconfirmed flag syntax.
- `network.mode` values other than `none` (`loopback`, `allowlist`, `full`) all fall through to the container runtime's default network (unfiltered NAT) -- there's no OCI-level equivalent of confinery's seccomp-based allowlist.
- This has not been verified against a real `wslc` preview install (developed without Windows/WSL-preview access); treat it as a starting point, not a finished boundary. Cross-compiles and passes `clippy`/tests for the pure argument-building logic, but the actual `wslc run` invocation is unverified.

## Other platforms

macOS and other systems have no backend; Confinery fails closed rather than running a command unsandboxed.

## Reproducibility

The toolchain is pinned in `rust-toolchain.toml`, `Cargo.lock` is committed, and release binaries are built and signed only through GitHub Actions. The Linux release is a static musl binary with no runtime dependencies. Each release also ships a CycloneDX SBOM (`*.cdx.json`, one per target) alongside the binaries, checksummed and signed the same way.
