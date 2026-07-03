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

        // 6. Mask denied paths that ended up visible.
        for path in &self.deny {
            self.mask_path(path);
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
            // Remount the top of the bind read-only. Submounts are not made
            // read-only recursively; system dirs rarely carry any.
            let _ = mount(
                NONE,
                &target,
                NONE,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID,
                NONE,
            );
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

    fn mask_path(&self, path: &Path) {
        let target = self.target_of(path);
        let Ok(meta) = std::fs::symlink_metadata(&target) else {
            return;
        };
        if meta.is_dir() {
            let _ = mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("mode=0000"),
            );
        } else if PathBuf::from("/dev/null").exists() {
            let _ = mount(Some("/dev/null"), &target, NONE, MsFlags::MS_BIND, NONE);
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
}
