//! Host-based network allowlisting via seccomp user-space notification.
//!
//! `network.mode = "allowlist"` cannot be enforced the way a container
//! runtime normally would -- a fresh network namespace bridged to the host
//! via a veth pair, NAT, and an nftables ruleset -- because every one of
//! those operations requires `CAP_NET_ADMIN` in the *host's* network
//! namespace, which an unprivileged-user-namespace sandbox deliberately
//! never has (that privilege gap is the whole reason rootless container
//! tools ship a userspace network stack like `slirp4netns`/`pasta` instead
//! of real veth+NAT). Confinery does not depend on an external tool for
//! this, so this module takes the other unprivileged path: the sandboxed
//! process keeps the host's real network namespace (as it already did for
//! `allowlist`/`full` before this module existed), and a seccomp filter
//! routes every `connect(2)` call to the parent process for a decision.
//!
//! ## How it works
//!
//! 1. The parent resolves every `host:port` allowlist entry to concrete
//!    `(IpAddr, port)` pairs *once*, using its own trusted DNS resolution,
//!    before the sandbox starts.
//! 2. The child installs a small, separate seccomp-BPF filter -- stacked
//!    alongside the existing hardened/allowlist syscall filter, not
//!    replacing it -- that returns `SECCOMP_RET_USER_NOTIF` for `connect`
//!    and `SECCOMP_RET_ALLOW` for everything else. Seccomp filter stacking
//!    is resolved by action precedence, not installation order (see
//!    `seccomp(2)`): `USER_NOTIF` outranks the other filter's `ALLOW` for
//!    `connect`, and the other filter's `ERRNO`/`KILL_PROCESS` decisions
//!    for dangerous syscalls are untouched since this filter defers
//!    (`ALLOW`) to everything else.
//! 3. Installing that filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
//!    returns a notification fd. The child has no use for it -- only the
//!    *parent* can safely inspect another process's memory -- so it's
//!    handed off immediately over a `UnixDatagram` via `SCM_RIGHTS`.
//! 4. The parent runs a supervisor loop on that fd: for each `connect`
//!    notification, it reads the target's `sockaddr` argument out of the
//!    target's own memory (`process_vm_readv`, an ordinary parent-of-child
//!    operation needing no special privilege), and allows or denies the
//!    call against the resolved list.
//!
//! ## Known limits (see docs/security-model.md)
//!
//! - Hostnames are resolved once, at sandbox startup. A hostname whose IP
//!   changes mid-run is not re-resolved or pinned; this is not
//!   DNS-rebinding-proof.
//! - Only `connect(2)` is intercepted. A connectionless UDP flow (e.g. a
//!   DNS query via `sendto` on an unconnected socket) is not, so this does
//!   not close a UDP/DNS-based exfiltration channel by itself.
//! - The kernel's own seccomp-notify documentation notes a narrow TOCTOU
//!   window: the argument memory this module reads could, in principle, be
//!   rewritten by another thread in the target between the read and the
//!   kernel's actual (deferred) execution of the syscall. Checking
//!   `SECCOMP_IOCTL_NOTIF_ID_VALID` immediately before trusting the read
//!   narrows this to the documented, kernel-acknowledged residual risk
//!   rather than eliminating it; treat this layer as defense in depth
//!   alongside the syscall/capability/filesystem layers, not a standalone
//!   guarantee.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::io::IoSliceMut;

use super::syscall_table;

/// One endpoint permitted by `network.allow`, resolved to a concrete
/// address so the supervisor never needs to trust DNS answers the
/// sandboxed process itself could have influenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedEndpoint {
    ip: IpAddr,
    port: u16,
}

/// A connection attempt the supervisor refused, kept for the audit trail.
#[derive(Debug, Clone)]
pub struct DeniedAttempt {
    pub addr: SocketAddr,
}

/// Resolve every `host:port` entry in a `network.allow` list to concrete
/// addresses, in the caller's own (trusted) context. Both IPv4 and IPv6
/// results for a hostname are kept, since which one a program's resolver
/// prefers isn't something this can predict.
pub fn resolve_allowlist(entries: &[String]) -> io::Result<Vec<AllowedEndpoint>> {
    let mut resolved = Vec::new();
    for entry in entries {
        let addrs = entry.to_socket_addrs().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to resolve network.allow entry `{entry}`: {e}"),
            )
        })?;
        for addr in addrs {
            resolved.push(AllowedEndpoint {
                ip: addr.ip(),
                port: addr.port(),
            });
        }
    }
    Ok(resolved)
}

/// Create the fd-passing channel between parent and child. The child sends
/// the seccomp notification fd back over this once it installs the filter;
/// nothing else is ever sent on it.
pub fn create_channel() -> io::Result<(UnixDatagram, UnixDatagram)> {
    UnixDatagram::pair()
}

// --- Classic BPF construction -----------------------------------------
//
// seccompiler (already used for the rest of this crate's seccomp support)
// has no `SECCOMP_RET_USER_NOTIF` action -- Firecracker, the crate it was
// built for, never needed one -- so this hand-rolls the tiny 3-instruction
// program itself: load the syscall number, compare it to `connect`, return
// USER_NOTIF or ALLOW. This does not need its own architecture-confusion
// check the way a standalone filter would: it is always installed stacked
// alongside the existing seccompiler-built filter, which already begins
// with an architecture validation sequence returning
// `SECCOMP_RET_KILL_PROCESS` on mismatch (the highest-precedence action
// there is), so a 32-bit-ABI confusion attempt is already fatal before
// either filter's syscall-specific logic runs.
//
// Opcodes are the stable, decades-old classic-BPF/seccomp constants from
// `linux/bpf_common.h` / `linux/filter.h`; they are not re-exposed by
// `libc` the way the `sock_filter`/`sock_fprog` structs they build are.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Offset of `nr` within `struct seccomp_data`; the first field, always 0
/// on every architecture this project supports.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

fn build_connect_notify_program() -> io::Result<Vec<libc::sock_filter>> {
    let connect_nr = syscall_table::resolve("connect").ok_or_else(|| {
        io::Error::other("could not resolve `connect` syscall number for this architecture")
    })?;
    Ok(vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, connect_nr as u32, 0, 1),
        bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF),
        bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW),
    ])
}

/// Install the connect-notify filter on the calling thread and return the
/// notification fd. Must run in the sandboxed child, after `no_new_privs`
/// (the kernel requires it for any unprivileged seccomp filter install,
/// same as the main syscall filter).
fn install_notify_filter() -> io::Result<OwnedFd> {
    let program = build_connect_notify_program()?;
    let fprog = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `fprog` borrows `program`, which outlives this call; the
    // syscall only reads it. `seccomp(2)` with SECCOMP_SET_MODE_FILTER and
    // NEW_LISTENER returns a new fd on success instead of the usual 0,
    // which is why this can't go through the ordinary
    // prctl(PR_SET_SECCOMP, ...) path `seccompiler::apply_filter` uses.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // The kernel allows only one SECCOMP_FILTER_FLAG_NEW_LISTENER filter
        // for the lifetime of a thread, and that restriction is checked
        // across the whole inherited filter chain
        // (`has_duplicate_listener()` walks `current->seccomp.filter->prev`
        // in kernel/seccomp.c), not just filters this process installed
        // itself. So this fires with EBUSY whenever confinery is itself
        // launched from inside another seccomp-user-notify sandbox (a CI
        // runner, container tool, or coding agent that already intercepts
        // syscalls this way) -- there is no way to shed an inherited
        // filter, so this is unrecoverable for the current process tree.
        if err.raw_os_error() == Some(libc::EBUSY) {
            return Err(io::Error::other(format!(
                "cannot install the network-allowlist seccomp listener: a seccomp \
                 user-notification filter is already installed somewhere in this \
                 process's ancestry (the kernel permits only one per thread's \
                 lifetime, checked across the whole inherited filter chain). This \
                 usually means confinery is itself running inside another \
                 seccomp-notify-based sandbox or container tool. Run confinery \
                 from a shell that is not already sandboxed this way, or use \
                 `network.mode = \"loopback\"`/`\"full\"` instead of `\"allowlist\"` \
                 in this environment. (root cause: {err})"
            )));
        }
        return Err(err);
    }
    // SAFETY: a non-negative return from this specific seccomp() call is
    // documented to be a newly created, owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// Install the connect-notify filter and hand its fd to the parent over
/// `channel`. Runs inside the pre_exec child; the parent side is
/// `receive_and_supervise`.
pub fn install_and_send(channel: &UnixDatagram) -> io::Result<()> {
    let notify_fd = install_notify_filter()?;
    let cmsg = [ControlMessage::ScmRights(&[notify_fd.as_raw_fd()])];
    sendmsg::<()>(channel.as_raw_fd(), &[], &cmsg, MsgFlags::empty(), None)
        .map_err(|e| io::Error::other(format!("failed to send seccomp notify fd: {e}")))?;
    Ok(())
}

/// Receive the notify fd the child sent and spawn the supervisor thread
/// that answers its `connect` notifications. `denied` accumulates refused
/// attempts for the caller to fold into the audit trail once the
/// sandboxed process (and everything it forked) has exited and the
/// supervisor loop ends on its own.
pub fn receive_and_supervise(
    channel: UnixDatagram,
    allowed: Vec<AllowedEndpoint>,
    denied: Arc<Mutex<Vec<DeniedAttempt>>>,
) -> io::Result<JoinHandle<()>> {
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);
    let mut iobuf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut iobuf)];
    let msg = recvmsg::<()>(
        channel.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| io::Error::other(format!("failed to receive seccomp notify fd: {e}")))?;

    let mut notify_fd = None;
    for cmsg in msg.cmsgs().map_err(io::Error::other)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                // SAFETY: freshly received via SCM_RIGHTS; we own it now.
                notify_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    let notify_fd =
        notify_fd.ok_or_else(|| io::Error::other("child did not send a seccomp notify fd"))?;

    Ok(std::thread::spawn(move || {
        supervise(notify_fd, &allowed, &denied);
    }))
}

fn supervise(
    notify_fd: OwnedFd,
    allowed: &[AllowedEndpoint],
    denied: &Arc<Mutex<Vec<DeniedAttempt>>>,
) {
    loop {
        let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: `notif` is sized for exactly this ioctl's expected
        // output per `seccomp_unotify(2)`.
        let ret = unsafe {
            libc::ioctl(
                notify_fd.as_raw_fd(),
                seccomp_ioctl_notif_recv(),
                &mut notif as *mut libc::seccomp_notif,
            )
        };
        if ret < 0 {
            // ENOENT (and friends): the notifying task, and everything
            // that inherited its filter, has exited. Nothing left to
            // supervise.
            return;
        }

        let target = Pid::from_raw(notif.pid as i32);
        let addr_ptr = notif.data.args[1] as usize;
        let addr_len = (notif.data.args[2] as usize).min(std::mem::size_of::<libc::sockaddr_in6>());
        let decision = read_sockaddr(target, addr_ptr, addr_len)
            .map(|addr| classify(addr, allowed))
            .unwrap_or(Decision::Allow); // couldn't read it (e.g. AF_UNIX-sized/garbage) -> not our concern

        // Re-check the notification is still live immediately before
        // trusting what was read and responding -- narrows, though per
        // the kernel's own documentation does not eliminate, the TOCTOU
        // window described in this module's doc comment.
        let still_valid = unsafe {
            libc::ioctl(
                notify_fd.as_raw_fd(),
                seccomp_ioctl_notif_id_valid(),
                &notif.id as *const u64,
            )
        } >= 0;
        if !still_valid {
            continue;
        }

        if let Decision::Deny(addr) = decision {
            if let Ok(mut d) = denied.lock() {
                d.push(DeniedAttempt { addr });
            }
        }

        let mut resp = libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: 0,
        };
        match decision {
            Decision::Allow => resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
            Decision::Deny(_) => resp.error = -libc::ECONNREFUSED,
        }
        // SAFETY: `resp` is a fully initialized, correctly sized response
        // for the notification just received.
        let _ = unsafe {
            libc::ioctl(
                notify_fd.as_raw_fd(),
                seccomp_ioctl_notif_send(),
                &resp as *const libc::seccomp_notif_resp,
            )
        };
    }
}

enum Decision {
    Allow,
    Deny(SocketAddr),
}

fn classify(addr: SocketAddr, allowed: &[AllowedEndpoint]) -> Decision {
    let ok = allowed
        .iter()
        .any(|a| a.ip == addr.ip() && a.port == addr.port());
    if ok {
        Decision::Allow
    } else {
        Decision::Deny(addr)
    }
}

/// Read the `sockaddr` a notified `connect()` call was given, out of the
/// target process's own memory. Returns `None` for anything that isn't a
/// plain `AF_INET`/`AF_INET6` address (e.g. `AF_UNIX`, `AF_NETLINK`),
/// which this module has no opinion on and always allows.
fn read_sockaddr(target: Pid, addr_ptr: usize, addr_len: usize) -> Option<SocketAddr> {
    if addr_ptr == 0 || addr_len < std::mem::size_of::<libc::sa_family_t>() {
        return None;
    }
    let mut buf = [0u8; std::mem::size_of::<libc::sockaddr_in6>()];
    let read_len = addr_len.min(buf.len());
    let mut iov = [IoSliceMut::new(&mut buf[..read_len])];
    let remote = [RemoteIoVec {
        base: addr_ptr,
        len: read_len,
    }];
    let n = process_vm_readv(target, &mut iov, &remote).ok()?;
    if n < std::mem::size_of::<libc::sa_family_t>() {
        return None;
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family as i32 {
        libc::AF_INET if n >= std::mem::size_of::<libc::sockaddr_in>() => {
            let mut raw = [0u8; std::mem::size_of::<libc::sockaddr_in>()];
            let len = raw.len();
            raw.copy_from_slice(&buf[..len]);
            // SAFETY: `raw` was read directly from the target's memory at
            // the address it gave to `connect(2)` for an AF_INET call, and
            // is exactly `sockaddr_in`-sized.
            let sin: libc::sockaddr_in = unsafe { std::mem::transmute(raw) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if n >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let mut raw = [0u8; std::mem::size_of::<libc::sockaddr_in6>()];
            let len = raw.len();
            raw.copy_from_slice(&buf[..len]);
            // SAFETY: same as above, for an AF_INET6 call.
            let sin6: libc::sockaddr_in6 = unsafe { std::mem::transmute(raw) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

// --- seccomp notify ioctl numbers --------------------------------------
//
// Not exposed as constants by `libc`; computed the same way the kernel
// headers (`linux/seccomp.h`) define them, using the stable classic ioctl
// encoding (`_IOWR('!', nr, size)` with magic `'!'` = 0x21) rather than
// hardcoding the resulting numbers.
const SECCOMP_IOC_MAGIC: u32 = 0x21;
const IOC_READ: u32 = 2;
const IOC_WRITE: u32 = 1;

const fn ioc(dir: u32, nr: u32, size: usize) -> libc::c_ulong {
    ((dir << 30) | (SECCOMP_IOC_MAGIC << 8) | nr | ((size as u32) << 16)) as libc::c_ulong
}

fn seccomp_ioctl_notif_recv() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<libc::seccomp_notif>(),
    )
}

fn seccomp_ioctl_notif_send() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>(),
    )
}

fn seccomp_ioctl_notif_id_valid() -> libc::c_ulong {
    ioc(IOC_WRITE, 2, std::mem::size_of::<u64>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_literal_ip_allowlist_entries() {
        let resolved = resolve_allowlist(&["127.0.0.1:443".to_string()]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(resolved[0].port, 443);
    }

    #[test]
    fn rejects_unresolvable_hostnames() {
        let result =
            resolve_allowlist(&["this-host-should-never-resolve.invalid.example:443".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn connect_notify_program_is_well_formed() {
        let program = build_connect_notify_program().unwrap();
        assert_eq!(program.len(), 4);
        // Every instruction must decode to a real classic-BPF opcode this
        // module actually emits; a garbled encoding would still "compile"
        // (it's just a u16) but silently do the wrong thing at runtime.
        assert_eq!(program[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(program[2].code, BPF_RET | BPF_K);
        assert_eq!(program[2].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(program[3].k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn classifies_allowed_and_denied_endpoints() {
        let allowed = vec![AllowedEndpoint {
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
        }];
        let ok: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let bad_port: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let bad_ip: SocketAddr = "1.2.3.4:443".parse().unwrap();
        assert!(matches!(classify(ok, &allowed), Decision::Allow));
        assert!(matches!(classify(bad_port, &allowed), Decision::Deny(_)));
        assert!(matches!(classify(bad_ip, &allowed), Decision::Deny(_)));
    }
}
