//! Namespace creation: user, mount, network, UTS, and IPC.
//!
//! All methods run inside the pre-exec child. A user namespace is entered
//! first so the remaining namespaces and mount operations succeed without real
//! privileges. PID namespaces are intentionally omitted: entering one requires
//! a fork after `unshare`, which does not compose with `execve`-based spawning.

use std::io::{self, Write};

use nix::sched::{unshare, CloneFlags};
use nix::unistd::sethostname;

/// What namespaces to create and how to configure them.
#[derive(Debug, Clone)]
pub struct NamespacePlan {
    pub user: bool,
    pub mount: bool,
    pub net: bool,
    pub uts: bool,
    pub ipc: bool,
    pub uid: u32,
    pub gid: u32,
    pub hostname: String,
    pub loopback_up: bool,
}

impl NamespacePlan {
    /// Enter the requested namespaces. Must be called before mount setup.
    pub fn enter(&self) -> io::Result<()> {
        if self.user {
            enter_user_namespace(self.uid, self.gid)?;
        }

        let mut flags = CloneFlags::empty();
        if self.mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.uts {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.ipc {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if !flags.is_empty() {
            unshare(flags).map_err(|e| labeled("unshare(namespaces)", e))?;
        }

        if self.uts {
            sethostname(&self.hostname).map_err(|e| labeled("sethostname", e))?;
        }
        if self.net && self.loopback_up {
            // Loopback is a convenience for `loopback` network mode; failure to
            // raise it must not abort the run.
            let _ = bring_up_loopback();
        }
        Ok(())
    }
}

/// Enter a new user namespace and map the invoking user to root inside it.
fn enter_user_namespace(uid: u32, gid: u32) -> io::Result<()> {
    unshare(CloneFlags::CLONE_NEWUSER).map_err(|e| labeled("unshare(user)", e))?;
    // setgroups must be denied before writing the gid map for unprivileged
    // mapping. The file is absent on very old kernels, which is fine.
    let _ = std::fs::write("/proc/self/setgroups", b"deny");
    write_map("/proc/self/uid_map", &format!("0 {uid} 1\n"))
        .map_err(|e| io::Error::new(e.kind(), format!("write uid_map: {e}")))?;
    write_map("/proc/self/gid_map", &format!("0 {gid} 1\n"))
        .map_err(|e| io::Error::new(e.kind(), format!("write gid_map: {e}")))?;
    Ok(())
}

fn labeled(step: &str, err: nix::Error) -> io::Error {
    io::Error::other(format!("namespaces {step}: {err}"))
}

/// Map files require the whole mapping in a single `write` call.
fn write_map(path: &str, contents: &str) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(contents.as_bytes())
}

/// Bring the loopback interface up inside a fresh network namespace.
fn bring_up_loopback() -> io::Result<()> {
    #[repr(C)]
    struct IfReqFlags {
        ifr_name: [libc::c_char; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| -> io::Result<()> {
        let mut req: IfReqFlags = unsafe { std::mem::zeroed() };
        // "lo"
        req.ifr_name[0] = b'l' as libc::c_char;
        req.ifr_name[1] = b'o' as libc::c_char;

        if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        req.ifr_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    unsafe { libc::close(fd) };
    result
}
