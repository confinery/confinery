//! Mapping syscall names to numbers and the curated policy lists.

use std::str::FromStr;

use syscalls::Sysno;

/// Resolve a syscall name to its number for the target architecture.
pub fn resolve(name: &str) -> Option<i64> {
    Sysno::from_str(name).ok().map(|s| s.id() as i64)
}

/// Dangerous syscalls blocked by the `hardened` denylist preset.
///
/// These grant kernel-level reach (module loading, tracing, mount and
/// namespace manipulation, key management, raw io_uring) that a sandboxed
/// assistant never needs. Confinery performs its own mount and namespace setup
/// before seccomp is installed, so blocking these here does not interfere.
pub const DANGEROUS: &[&str] = &[
    // Mount and root manipulation.
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "mount_setattr",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    // Namespace manipulation.
    "unshare",
    "setns",
    // Process tracing and memory peeking.
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // Kernel modules and reboot.
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    // eBPF and performance interfaces.
    "bpf",
    "perf_event_open",
    // Kernel keyring.
    "add_key",
    "request_key",
    "keyctl",
    // Swap and accounting.
    "swapon",
    "swapoff",
    "acct",
    // Clock and domain changes.
    "settimeofday",
    "clock_settime",
    "adjtimex",
    "clock_adjtime",
    "sethostname",
    "setdomainname",
    // Large attack-surface async IO.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "userfaultfd",
    // x86 port and descriptor tricks.
    "modify_ldt",
    "ioperm",
    "iopl",
    // Legacy / quotas.
    "quotactl",
    "nfsservctl",
    "_sysctl",
];

/// Allowlist tuned for interpreters, compilers, and common developer tools.
pub const ASSISTANT_ALLOW: &[&str] = &[
    // Process lifecycle.
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "gettid",
    "getpid",
    "getppid",
    "arch_prctl",
    "prctl",
    "rseq",
    "futex",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "getrandom",
    // Memory.
    "brk",
    "mmap",
    "mmap2",
    "munmap",
    "mremap",
    "mprotect",
    "madvise",
    "mlock",
    "munlock",
    "membarrier",
    // File IO.
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "open",
    "openat",
    "openat2",
    "close",
    "close_range",
    "creat",
    "lseek",
    "_llseek",
    "dup",
    "dup2",
    "dup3",
    "pipe",
    "pipe2",
    "fcntl",
    "fcntl64",
    "flock",
    "fsync",
    "fdatasync",
    "ftruncate",
    "truncate",
    "fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
    "tee",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "eventfd",
    "eventfd2",
    "signalfd",
    "signalfd4",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "inotify_init",
    "inotify_init1",
    "inotify_add_watch",
    "inotify_rm_watch",
    // Filesystem metadata.
    "stat",
    "stat64",
    "lstat",
    "fstat",
    "fstat64",
    "fstatat64",
    "newfstatat",
    "statx",
    "statfs",
    "statfs64",
    "fstatfs",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getcwd",
    "chdir",
    "fchdir",
    "getdents",
    "getdents64",
    "mkdir",
    "mkdirat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "unlink",
    "unlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "umask",
    "utime",
    "utimes",
    "utimensat",
    "futimesat",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "sync",
    "syncfs",
    // Identity.
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getgroups",
    "getresuid",
    "getresgid",
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "setfsuid",
    "setfsgid",
    "setpgid",
    "getpgid",
    "getpgrp",
    "setsid",
    "getsid",
    "getpriority",
    "setpriority",
    // Signals.
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigpending",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "sigaltstack",
    "kill",
    "tkill",
    "tgkill",
    "pause",
    "restart_syscall",
    // Time.
    "gettimeofday",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "nanosleep",
    "times",
    "getrusage",
    // Resource limits (read-only side).
    "getrlimit",
    "setrlimit",
    "prlimit64",
    "getcpu",
    "sysinfo",
    "uname",
    "capget",
    "capset",
    // Networking (needed even for loopback/unix sockets).
    "socket",
    "socketpair",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "getsockopt",
    "setsockopt",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
    "shutdown",
];

/// Minimal allowlist for simple, single-purpose programs.
pub const MINIMAL_ALLOW: &[&str] = &[
    "read",
    "write",
    "readv",
    "writev",
    "open",
    "openat",
    "close",
    "lseek",
    "fstat",
    "newfstatat",
    "statx",
    "mmap",
    "munmap",
    "mprotect",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "getrandom",
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "futex",
    "exit",
    "exit_group",
    "execve",
    "getpid",
    "gettid",
    "clock_gettime",
    "nanosleep",
    "poll",
    "ppoll",
    "getdents64",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_common_syscalls() {
        assert!(resolve("read").is_some());
        assert!(resolve("openat").is_some());
        assert!(resolve("execve").is_some());
    }

    #[test]
    fn rejects_unknown_syscalls() {
        assert!(resolve("definitely_not_a_syscall").is_none());
    }

    #[test]
    fn dangerous_list_all_resolve() {
        for name in DANGEROUS {
            // Every dangerous name must map on this arch, or the denylist has a
            // typo that would silently do nothing.
            assert!(
                resolve(name).is_some(),
                "unresolved dangerous syscall: {name}"
            );
        }
    }
}
