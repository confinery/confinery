//! Filesystem isolation via bind mounts and `pivot_root`.
//!
//! A fresh tmpfs becomes the new root. Only allowlisted host paths are bind
//! mounted into it, so anything not listed is invisible — a stronger guarantee
//! than access control alone. Runs inside the pre-exec child after a mount
//! namespace has been entered.

use std::io;
use std::path::{Path, PathBuf};

use nix::mount::{mount, umount2, MntFlags, MsFlags};

const STAGE: &str = "/tmp";
const NEWROOT: &str = "/tmp/.confinery-root";
const OLDROOT_NAME: &str = ".oldroot";
const DEV_NODES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

/// Resolved mount layout for one sandbox.
#[derive(Debug, Clone)]
pub struct MountPlan {
    pub read_only: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub tmpfs: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
    pub minimal_dev: bool,
    pub workdir: PathBuf,
}

impl MountPlan {
    /// Build the new root and pivot into it.
    pub fn setup(&self) -> io::Result<()> {
        // 1. Stop mount events propagating back to the host.
        mount(NONE, "/", NONE, MsFlags::MS_REC | MsFlags::MS_PRIVATE, NONE)
            .map_err(mount_err("make-rprivate"))?;

        // 2. Fresh tmpfs staging area, then the new root inside it.
        mount(
            Some("tmpfs"),
            STAGE,
            Some("tmpfs"),
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        )
        .map_err(mount_err("stage-tmpfs"))?;
        std::fs::create_dir_all(NEWROOT)?;
        mount(
            Some(NEWROOT),
            NEWROOT,
            NONE,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            NONE,
        )
        .map_err(mount_err("newroot-bind"))?;

        // 3. Bind the allowlisted paths.
        for path in &self.read_only {
            self.bind_path(path, true)?;
        }
        for path in &self.read_write {
            self.bind_path(path, false)?;
        }

        // 4. Writable tmpfs mounts.
        for path in &self.tmpfs {
            let target = self.target_of(path);
            std::fs::create_dir_all(&target)?;
            mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("mode=1777"),
            )
            .map_err(mount_err("tmpfs"))?;
        }

        // 5. Minimal /dev and /proc.
        if self.minimal_dev {
            self.setup_dev()?;
        }
        self.setup_proc()?;

        // 6. Mask denied paths that ended up visible. This is the boundary
        // that protects secrets like `~/.ssh` and `~/.aws`, so a masking
        // failure must abort the run rather than continue with the path
        // silently still reachable.
        for path in &self.deny {
            self.mask_path(path)?;
        }

        // 7. Pivot into the new root and detach the old one.
        self.pivot()?;
        Ok(())
    }

    fn target_of(&self, path: &Path) -> PathBuf {
        let rel = path.strip_prefix("/").unwrap_or(path);
        Path::new(NEWROOT).join(rel)
    }

    fn bind_path(&self, path: &Path, read_only: bool) -> io::Result<()> {
        let lmeta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(()), // silently skip absent host paths
        };
        let target = self.target_of(path);

        if lmeta.file_type().is_symlink() {
            // Distro usr-merge makes /bin, /lib, ... symlinks to /usr/*.
            // Recreate directory symlinks as symlinks so their real target
            // (bind mounted separately) resolves inside the new root. A
            // directory cannot be bind mounted onto a file, which is EINVAL.
            match std::fs::metadata(path) {
                Ok(m) if m.is_dir() => {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    if let Ok(dest) = std::fs::read_link(path) {
                        let _ = std::os::unix::fs::symlink(dest, &target);
                    }
                    return Ok(());
                }
                Ok(_) => {
                    // Symlink to a file: bind the resolved file below.
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let _ = std::fs::File::create(&target);
                }
                Err(_) => return Ok(()), // dangling symlink
            }
        } else if lmeta.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::File::create(&target);
        }

        mount(
            Some(path),
            &target,
            NONE,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            NONE,
        )
        .map_err(mount_err("bind"))?;

        if read_only {
            // This is a security boundary the operator explicitly asked
            // for, so a failure to enforce it must abort the run rather
            // than leave the path silently writable.
            remount_readonly(&target)?;
        }
        Ok(())
    }

    fn setup_dev(&self) -> io::Result<()> {
        let dev = self.target_of(Path::new("/dev"));
        std::fs::create_dir_all(&dev)?;
        mount(
            Some("tmpfs"),
            &dev,
            Some("tmpfs"),
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        )
        .map_err(mount_err("dev-tmpfs"))?;

        for node in DEV_NODES {
            let src = PathBuf::from("/dev").join(node);
            if !src.exists() {
                continue;
            }
            let dst = dev.join(node);
            let _ = std::fs::File::create(&dst);
            let _ = mount(Some(&src), &dst, NONE, MsFlags::MS_BIND, NONE);
        }

        // Standard descriptor symlinks.
        let _ = std::os::unix::fs::symlink("/proc/self/fd", dev.join("fd"));
        let _ = std::os::unix::fs::symlink("/proc/self/fd/0", dev.join("stdin"));
        let _ = std::os::unix::fs::symlink("/proc/self/fd/1", dev.join("stdout"));
        let _ = std::os::unix::fs::symlink("/proc/self/fd/2", dev.join("stderr"));

        // Writable shared memory.
        let shm = dev.join("shm");
        let _ = std::fs::create_dir_all(&shm);
        let _ = mount(
            Some("tmpfs"),
            &shm,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777"),
        );
        Ok(())
    }

    fn setup_proc(&self) -> io::Result<()> {
        let proc = self.target_of(Path::new("/proc"));
        std::fs::create_dir_all(&proc)?;
        // A private procfs is preferred; fall back to bind mounting the host's.
        if mount(Some("proc"), &proc, Some("proc"), MsFlags::MS_NOSUID, NONE).is_err() {
            let _ = mount(
                Some("/proc"),
                &proc,
                NONE,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                NONE,
            );
        }
        Ok(())
    }

    /// Mask a `deny`-listed path that ended up visible through a bind mount.
    /// This is the boundary protecting secrets such as `~/.ssh` and
    /// `~/.aws`, so every failure mode here must be reported, not absorbed:
    /// a path that doesn't exist inside the sandbox is nothing to mask (safe
    /// no-op), but a path that exists and fails to mask must abort the run.
    fn mask_path(&self, path: &Path) -> io::Result<()> {
        let target = self.target_of(path);
        let meta = match std::fs::symlink_metadata(&target) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if meta.is_dir() {
            mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("mode=0000"),
            )
            .map_err(mount_err("mask-dir"))
        } else if PathBuf::from("/dev/null").exists() {
            mount(Some("/dev/null"), &target, NONE, MsFlags::MS_BIND, NONE)
                .map_err(mount_err("mask-file"))
        } else {
            Err(io::Error::other(format!(
                "cannot mask `{}`: /dev/null is unavailable",
                path.display()
            )))
        }
    }

    fn pivot(&self) -> io::Result<()> {
        let oldroot = Path::new(NEWROOT).join(OLDROOT_NAME);
        std::fs::create_dir_all(&oldroot)?;

        nix::unistd::chdir(NEWROOT).map_err(io::Error::from)?;
        pivot_root(NEWROOT, &oldroot)
            .map_err(|e| io::Error::new(e.kind(), format!("pivot_root({NEWROOT}): {e}")))?;
        nix::unistd::chdir("/").map_err(io::Error::from)?;

        let old = format!("/{OLDROOT_NAME}");
        umount2(old.as_str(), MntFlags::MNT_DETACH).map_err(mount_err("umount-oldroot"))?;
        let _ = std::fs::remove_dir(&old);

        // Move into the requested working directory if it survived the pivot.
        if nix::unistd::chdir(&self.workdir).is_err() {
            let _ = nix::unistd::chdir("/");
        }
        Ok(())
    }
}

/// `None` typed for nix's generic mount signature.
const NONE: Option<&Path> = None;

/// Make `target` read-only, recursively including any submounts under it.
///
/// A plain `MS_REMOUNT|MS_RDONLY` (as used elsewhere in this file for
/// non-recursive cases) only affects the top of the bind mount: a
/// filesystem mounted *under* an allowed read-only path -- not unusual on
/// systems where e.g. `/usr` carries its own submounts -- stays writable
/// despite the operator's `read_only` request. `mount_setattr(2)` with
/// `AT_RECURSIVE` (Linux 5.12+) closes that gap by applying the read-only
/// attribute to the whole mount subtree in one atomic call. On older
/// kernels that don't have the syscall, we fall back to the non-recursive
/// remount so hosts between the namespace-isolation floor (unprivileged
/// user namespaces, much older) and 5.12 still get top-level enforcement
/// rather than failing closed entirely.
fn remount_readonly(target: &Path) -> io::Result<()> {
    match mount_setattr_readonly_recursive(target) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => mount(
            NONE,
            target,
            NONE,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID,
            NONE,
        )
        .map_err(mount_err("readonly-remount")),
        Err(e) => Err(e),
    }
}

fn mount_setattr_readonly_recursive(target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    let path = CString::new(target.as_os_str().as_encoded_bytes())?;
    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_RECURSIVE,
            &attr as *const libc::mount_attr as *mut libc::c_void,
            std::mem::size_of::<libc::mount_attr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn pivot_root(new_root: &str, put_old: &Path) -> io::Result<()> {
    use std::ffi::CString;
    let new = CString::new(new_root)?;
    let old = CString::new(put_old.as_os_str().as_encoded_bytes())?;
    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, new.as_ptr(), old.as_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mount_err(what: &'static str) -> impl Fn(nix::Error) -> io::Error {
    move |e| io::Error::other(format!("mount {what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_rebased_under_newroot() {
        let plan = MountPlan {
            read_only: vec![],
            read_write: vec![],
            tmpfs: vec![],
            deny: vec![],
            minimal_dev: true,
            workdir: PathBuf::from("/"),
        };
        assert_eq!(
            plan.target_of(Path::new("/usr/bin")),
            PathBuf::from("/tmp/.confinery-root/usr/bin")
        );
    }

    // Exit codes for `check_recursive_readonly`, distinguishing "the
    // environment can't even set up the namespace" (skip -- not what this
    // test is about) from "the read-only guarantee itself didn't hold"
    // (real failure). Some hosts pass the static namespace sysctls but
    // still deny the operation at runtime (e.g. GitHub Actions'
    // `ubuntu-latest`, which restricts unprivileged user namespaces via
    // AppArmor by default) -- see `detect::userns_actually_works`.
    const SETUP_UNAVAILABLE: i32 = 2;

    // Regression test for the recursive-read-only fix: a submount nested
    // under a read-only path must become read-only too, not just the top
    // of the bind mount. Runs the actual check in a disposable, unprivileged
    // user+mount namespace (forked, never exec'd) so it needs no real
    // privilege and never touches the test binary's own mount table.
    #[test]
    fn readonly_remount_covers_nested_submounts() {
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {}", io::Error::last_os_error()),
            0 => {
                let code = match check_recursive_readonly() {
                    Ok(()) => 0,
                    Err(SetupError::Unavailable(e)) => {
                        eprintln!("namespace setup unavailable: {e}");
                        SETUP_UNAVAILABLE
                    }
                    Err(SetupError::Failed(e)) => {
                        eprintln!("check_recursive_readonly: {e}");
                        1
                    }
                };
                std::process::exit(code);
            }
            pid => {
                let mut status: libc::c_int = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == SETUP_UNAVAILABLE {
                    eprintln!(
                        "skipping: unprivileged user+mount namespaces unavailable on this host"
                    );
                    return;
                }
                assert!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "recursive read-only check failed in child (status {status})"
                );
            }
        }
    }

    enum SetupError {
        /// The namespace/uid-mapping setup itself failed -- not what this
        /// test is checking, and known to happen on hosts whose sysctls
        /// allow it but an LSM policy denies it anyway.
        Unavailable(io::Error),
        /// Setup succeeded but the actual check failed.
        Failed(io::Error),
    }

    impl From<io::Error> for SetupError {
        fn from(e: io::Error) -> Self {
            SetupError::Failed(e)
        }
    }

    fn check_recursive_readonly() -> Result<(), SetupError> {
        use nix::sched::{unshare, CloneFlags};

        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
            .map_err(|e| SetupError::Unavailable(io::Error::from(e)))?;
        let _ = std::fs::write("/proc/self/setgroups", b"deny");
        std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
            .map_err(SetupError::Unavailable)?;
        std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
            .map_err(SetupError::Unavailable)?;

        let outer = tempfile::tempdir()?;
        let sub = outer.path().join("sub");
        std::fs::create_dir_all(&sub)?;
        let inner = tempfile::tempdir()?;
        std::fs::write(inner.path().join("f"), b"original")?;

        // Make `outer` a mount in its own right, then bind `inner` onto a
        // subdirectory of it -- a submount nested under the path we are
        // about to make read-only, mirroring e.g. /usr carrying its own
        // submounts on some distros.
        mount(
            Some(outer.path()),
            outer.path(),
            NONE,
            MsFlags::MS_BIND,
            NONE,
        )
        .map_err(mount_err("outer-bind"))?;
        mount(Some(inner.path()), &sub, NONE, MsFlags::MS_BIND, NONE)
            .map_err(mount_err("inner-bind"))?;

        remount_readonly(outer.path())?;

        let result: io::Result<()> = match std::fs::write(sub.join("f"), b"overwritten") {
            Ok(()) => Err(io::Error::other(
                "submount under the read-only path was still writable",
            )),
            Err(e) if e.raw_os_error() == Some(libc::EROFS) => Ok(()),
            Err(e) => Err(e),
        };
        result.map_err(SetupError::Failed)
    }
}
