use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{PreparedRootfs, RootfsCleanup, RootfsConfig, RootfsError, RootfsProvider};

const INIT_GUEST_PATH: &str = "usr/local/bin/playpencil-init";
const ROOTFS_MERGED_DIR: &str = "merged";

pub struct LinuxRootfsProvider;

/// Guard that cleans up a sandbox directory on drop unless disarmed.
/// For the overlay path, also unmounts fuse-overlayfs.
struct SandboxGuard {
    sandbox_dir: Option<PathBuf>,
    mount_point: Option<PathBuf>,
}

impl SandboxGuard {
    fn new(sandbox_dir: PathBuf) -> Self {
        Self {
            sandbox_dir: Some(sandbox_dir),
            mount_point: None,
        }
    }

    fn set_mount_point(&mut self, mp: PathBuf) {
        self.mount_point = Some(mp);
    }

    fn disarm(&mut self) {
        self.sandbox_dir = None;
        self.mount_point = None;
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if let Some(mp) = &self.mount_point {
            let _ = Command::new("fusermount")
                .args(["-u", &mp.to_string_lossy()])
                .status();
        }
        if let Some(dir) = &self.sandbox_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl RootfsProvider for LinuxRootfsProvider {
    fn prepare(&self, config: &RootfsConfig) -> Result<PreparedRootfs, RootfsError> {
        validate_sandbox_id(&config.sandbox_id)?;
        let sandbox_dir = config.session_dir.join(&config.sandbox_id);
        let merged = sandbox_dir.join(ROOTFS_MERGED_DIR);
        let mut guard = SandboxGuard::new(sandbox_dir.clone());

        if self.fuse_overlayfs_available() {
            let upper = sandbox_dir.join("upper");
            let work = sandbox_dir.join("work");
            fs::create_dir_all(&upper)?;
            fs::create_dir_all(&work)?;
            fs::create_dir_all(&merged)?;

            let status = Command::new("fuse-overlayfs")
                .arg("-o")
                .arg(format!(
                    "lowerdir={},upperdir={},workdir={}",
                    config.base_rootfs.display(),
                    upper.display(),
                    work.display()
                ))
                .arg(&merged)
                .status()
                .map_err(|e| RootfsError::OverlaySetup(format!("fuse-overlayfs exec: {e}")))?;

            if !status.success() {
                return Err(RootfsError::OverlaySetup(format!(
                    "fuse-overlayfs exited with {status}"
                )));
            }

            guard.set_mount_point(merged.clone());
            inject_init(&merged, &config.init_binary)?;
            guard.disarm();

            Ok(PreparedRootfs {
                root: merged.clone(),
                cleanup: RootfsCleanup::FuseOverlayfs {
                    mount_point: merged,
                    work_dir: work,
                    upper_dir: upper,
                },
            })
        } else {
            tracing::warn!(
                "fuse-overlayfs not found; falling back to full rootfs copy. \
                 Install fuse-overlayfs for better performance with shared base images."
            );

            fs::create_dir_all(&merged)?;

            let status = Command::new("cp")
                .args([
                    "-a",
                    "--reflink=auto",
                    &format!("{}/.", &config.base_rootfs.to_string_lossy()),
                    &merged.to_string_lossy(),
                ])
                .status()
                .map_err(|e| RootfsError::CopyFailed(format!("cp: {e}")))?;

            if !status.success() {
                return Err(RootfsError::CopyFailed(format!(
                    "cp -a exited with {status}"
                )));
            }

            inject_init(&merged, &config.init_binary)?;
            guard.disarm();

            Ok(PreparedRootfs {
                root: merged.clone(),
                cleanup: RootfsCleanup::CopyBased { dir: sandbox_dir },
            })
        }
    }

    fn fuse_overlayfs_available(&self) -> bool {
        Command::new("which")
            .arg("fuse-overlayfs")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn clear_session_dir(&self, sessions_root: &Path, sandbox_id: &str) -> Result<(), RootfsError> {
        clear_session_dir(sessions_root, sandbox_id)
    }

    fn fuse_rootfs_unmounted(
        &self,
        sessions_root: &Path,
        sandbox_id: &str,
    ) -> Result<bool, RootfsError> {
        fuse_rootfs_unmounted(sessions_root, sandbox_id)
    }

    fn session_rootfs_path(
        &self,
        sessions_root: &Path,
        sandbox_id: &str,
    ) -> Result<PathBuf, RootfsError> {
        session_rootfs_path(sessions_root, sandbox_id)
    }
}

fn validate_sandbox_id(id: &str) -> Result<(), RootfsError> {
    if id.is_empty() || id.contains('/') || id.contains("..") || id == "." {
        return Err(RootfsError::OverlaySetup(format!(
            "invalid sandbox_id: {id:?}"
        )));
    }
    Ok(())
}

fn inject_init(rootfs: &Path, init_binary: &Path) -> Result<(), RootfsError> {
    let dest = rootfs.join(INIT_GUEST_PATH);
    let init_path = Path::new(INIT_GUEST_PATH);
    let components: Vec<_> = init_path
        .components()
        .filter_map(|c| {
            if let std::path::Component::Normal(n) = c {
                Some(n)
            } else {
                None
            }
        })
        .collect();

    // Walk each component, treating parent dirs and the final file differently.
    let mut current = rootfs.to_path_buf();
    for (i, component) in components.iter().enumerate() {
        current.push(component);
        let is_final = i == components.len() - 1;

        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_symlink() => {
                fs::remove_file(&current)
                    .map_err(|e| RootfsError::InitInjection(format!("remove symlink: {e}")))?;
                if !is_final {
                    fs::create_dir(&current)
                        .map_err(|e| RootfsError::InitInjection(format!("mkdir: {e}")))?;
                }
            }
            Ok(meta) if meta.is_dir() => {
                if is_final {
                    // Final component is a directory — remove so we can write a file
                    fs::remove_dir_all(&current)
                        .map_err(|e| RootfsError::InitInjection(format!("rmdir: {e}")))?;
                }
            }
            Ok(_) => {
                if is_final {
                    fs::remove_file(&current)
                        .map_err(|e| RootfsError::InitInjection(format!("remove: {e}")))?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !is_final {
                    fs::create_dir(&current)
                        .map_err(|e| RootfsError::InitInjection(format!("mkdir: {e}")))?;
                }
            }
            Err(e) => return Err(RootfsError::InitInjection(format!("stat: {e}"))),
        }
    }

    fs::copy(init_binary, &dest).map_err(|e| RootfsError::InitInjection(format!("copy: {e}")))?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))
        .map_err(|e| RootfsError::InitInjection(format!("chmod: {e}")))?;
    Ok(())
}

/// The canonical prepared-rootfs root for a sandbox: `session_root/<validated
/// id>/<merged>`. Lets callers reconstruct the deletion/boot path from the
/// validated id alone, never a trusted stored path.
pub fn session_rootfs_path(session_root: &Path, sandbox_id: &str) -> Result<PathBuf, RootfsError> {
    validate_sandbox_id(sandbox_id)?;
    Ok(session_root.join(sandbox_id).join(ROOTFS_MERGED_DIR))
}

/// Remove any partial per-sandbox session directory left by a crashed or
/// cancelled provision before a fresh prepare reuses the path. `session_root`
/// is the directory prepare() joins the sandbox id onto. Bounded to
/// `session_root/<validated id>` and idempotent (no-op when absent).
pub fn clear_session_dir(session_root: &Path, sandbox_id: &str) -> Result<(), RootfsError> {
    validate_sandbox_id(sandbox_id)?;
    let sandbox_dir = session_root.join(sandbox_id);
    // A crashed overlay provision may leave a live mount at the merged root;
    // cleanup_session_dir unmounts it (if mounted) then removes the sandbox dir.
    cleanup_session_dir(&sandbox_dir.join(ROOTFS_MERGED_DIR))
}

/// Tear down a sandbox session directory given its prepared rootfs path. If the
/// rootfs is still a mount point (e.g. a fuse-overlayfs mount that outlived its
/// daemon), it is unmounted first; an already-unmounted rootfs is left alone.
/// The enclosing session directory (the rootfs path's parent) is then removed
/// with a bounded retry to absorb transient EBUSY. Idempotent: a missing
/// directory is success.
pub fn cleanup_session_dir(rootfs_path: &Path) -> Result<(), RootfsError> {
    if is_mount_point(rootfs_path) {
        let status = Command::new("fusermount")
            .args(["-u", &rootfs_path.to_string_lossy()])
            .status()
            .map_err(|e| RootfsError::Cleanup(format!("fusermount: {e}")))?;
        if !status.success() {
            return Err(RootfsError::Cleanup(format!(
                "fusermount -u exited with {status}"
            )));
        }
    }
    let session_dir = rootfs_path.parent().unwrap_or(rootfs_path);
    remove_dir_all_retry(session_dir)
}

/// Decode the octal escapes the kernel writes into mountinfo path fields
/// (space=\\040, tab=\\011, newline=\\012, backslash=\\134). A backslash
/// not followed by three octal digits is left verbatim.
fn unescape_mountinfo(field: &str) -> String {
    let b = field.as_bytes();
    let is_oct = |c: u8| (b'0'..=b'7').contains(&c);
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && is_oct(b[i + 1])
            && is_oct(b[i + 2])
            && is_oct(b[i + 3])
        {
            let val = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True if `path` resolves to a current mount point per /proc/self/mountinfo.
fn is_mount_point(path: &Path) -> bool {
    let Ok(target) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    // Each line's 5th whitespace-separated field is the (octal-escaped) mount point.
    mountinfo.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .map(|mp| Path::new(&unescape_mountinfo(mp)) == target)
            .unwrap_or(false)
    })
}

/// True if a fuse-overlay-mode sandbox rootfs persists on disk but is no longer
/// mounted (e.g. a fuse-overlay mount torn down by a host reboot). Overlay mode
/// is detected by the sibling `upper` dir; such a rootfs must not be booted (it
/// would be empty) nor reprovisioned (that discards `upper`). Copy-mode rootfs
/// (no `upper` sibling) is always usable and returns false. Derived from and
/// bounded to `session_root/<validated id>`.
pub fn fuse_rootfs_unmounted(session_root: &Path, sandbox_id: &str) -> Result<bool, RootfsError> {
    validate_sandbox_id(sandbox_id)?;
    let sandbox_dir = session_root.join(sandbox_id);
    let fuse_mode = sandbox_dir.join("upper").is_dir();
    Ok(fuse_mode && !is_mount_point(&sandbox_dir.join(ROOTFS_MERGED_DIR)))
}

/// Remove a directory tree, retrying briefly on transient errors (e.g. EBUSY
/// just after an unmount). A missing directory is treated as success.
fn remove_dir_all_retry(dir: &Path) -> Result<(), RootfsError> {
    let mut last_err = None;
    for attempt in 0..5 {
        match fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt + 1)));
            }
        }
    }
    Err(RootfsError::Cleanup(format!(
        "remove {}: {}",
        dir.display(),
        last_err.expect("loop ran at least once")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_session_dir_removes_stale_and_is_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let sessions = tmp.path().join("sessions");
        let sandbox_dir = sessions.join("sb-7");
        fs::create_dir_all(sandbox_dir.join("merged/etc")).unwrap();
        fs::write(sandbox_dir.join("merged/etc/junk"), b"stale").unwrap();

        clear_session_dir(&sessions, "sb-7").unwrap();
        assert!(!sandbox_dir.exists());

        // Idempotent when nothing is present.
        clear_session_dir(&sessions, "sb-7").unwrap();

        // Bounded: a traversing id is rejected, not cleared.
        assert!(clear_session_dir(&sessions, "../escape").is_err());
    }

    #[test]
    fn unescape_mountinfo_decodes_octal_escapes() {
        assert_eq!(unescape_mountinfo(r"/tmp/has\040space"), "/tmp/has space");
        assert_eq!(unescape_mountinfo(r"/a\011b"), "/a\tb");
        assert_eq!(unescape_mountinfo(r"/a\012b"), "/a\nb");
        assert_eq!(unescape_mountinfo(r"/a\134b"), r"/a\b");
        // Passthrough and non-octal escapes stay verbatim.
        assert_eq!(unescape_mountinfo("/plain/path"), "/plain/path");
        assert_eq!(unescape_mountinfo(r"/a\09b"), r"/a\09b");
        assert_eq!(unescape_mountinfo(r"/a\b"), r"/a\b");
    }

    #[test]
    fn cleanup_session_dir_handles_spaced_path() {
        let tmp = tempfile::tempdir().unwrap();
        let sandbox_dir = tmp.path().join("has space").join("sb-1");
        let merged = sandbox_dir.join("merged");
        fs::create_dir_all(merged.join("etc")).unwrap();
        // Not mounted: the spaced canonical path matches no mountinfo line and
        // removal of the parent session dir proceeds.
        cleanup_session_dir(&merged).unwrap();
        assert!(!sandbox_dir.exists());
    }

    #[test]
    fn fuse_rootfs_unmounted_detects_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let sessions = tmp.path().join("sessions");

        // Absent session dir -> not fuse-mode -> false.
        assert!(!fuse_rootfs_unmounted(&sessions, "sb-1").unwrap());

        // Copy-mode: merged exists, no upper sibling -> usable.
        let sandbox_dir = sessions.join("sb-1");
        fs::create_dir_all(sandbox_dir.join("merged")).unwrap();
        assert!(!fuse_rootfs_unmounted(&sessions, "sb-1").unwrap());

        // Overlay-mode: upper sibling exists, merged not mounted -> unmounted.
        fs::create_dir_all(sandbox_dir.join("upper")).unwrap();
        assert!(fuse_rootfs_unmounted(&sessions, "sb-1").unwrap());

        // Bounded: a traversing id is rejected.
        assert!(fuse_rootfs_unmounted(&sessions, "../escape").is_err());
    }

    #[test]
    fn inject_init_creates_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let init_src = tmp.path().join("playpencil-init");
        fs::write(&init_src, b"#!/bin/sh\necho init").unwrap();

        inject_init(&rootfs, &init_src).unwrap();

        let dest = rootfs.join(INIT_GUEST_PATH);
        assert!(dest.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"#!/bin/sh\necho init");

        let perms = fs::metadata(&dest).unwrap().permissions();
        assert!(perms.mode() & 0o111 != 0);
    }

    #[test]
    fn inject_init_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("empty-rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let init_src = tmp.path().join("init");
        fs::write(&init_src, b"binary").unwrap();

        inject_init(&rootfs, &init_src).unwrap();
        assert!(rootfs.join(INIT_GUEST_PATH).exists());
    }

    #[test]
    fn inject_init_missing_source_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let result = inject_init(&rootfs, Path::new("/nonexistent/init"));
        assert!(result.is_err());
    }

    #[test]
    fn fuse_overlayfs_available_returns_bool() {
        let provider = LinuxRootfsProvider;
        let _ = provider.fuse_overlayfs_available();
    }

    #[test]
    fn validate_sandbox_id_rejects_traversal() {
        assert!(validate_sandbox_id("../escape").is_err());
        assert!(validate_sandbox_id("foo/../../bar").is_err());
        assert!(validate_sandbox_id("").is_err());
        assert!(validate_sandbox_id(".").is_err());
        assert!(validate_sandbox_id("foo/bar").is_err());
    }

    #[test]
    fn validate_sandbox_id_accepts_valid() {
        assert!(validate_sandbox_id("my-sandbox-123").is_ok());
        assert!(validate_sandbox_id("sandbox_abc").is_ok());
        assert!(validate_sandbox_id("a").is_ok());
    }

    #[test]
    fn inject_init_replaces_symlink_in_path() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        fs::create_dir_all(&rootfs).unwrap();

        let escape_target = tmp.path().join("escape");
        fs::create_dir_all(&escape_target).unwrap();
        std::os::unix::fs::symlink(&escape_target, rootfs.join("usr")).unwrap();

        let init_src = tmp.path().join("init");
        fs::write(&init_src, b"binary").unwrap();

        inject_init(&rootfs, &init_src).unwrap();

        let usr_meta = fs::symlink_metadata(rootfs.join("usr")).unwrap();
        assert!(usr_meta.is_dir());
        assert!(!usr_meta.is_symlink());

        assert!(rootfs.join(INIT_GUEST_PATH).exists());
        assert_eq!(fs::read(rootfs.join(INIT_GUEST_PATH)).unwrap(), b"binary");
    }

    #[test]
    fn inject_init_replaces_final_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        fs::create_dir_all(rootfs.join("usr/local/bin")).unwrap();

        // Final component is a symlink pointing outside
        let escape_file = tmp.path().join("escape-file");
        fs::write(&escape_file, b"escape").unwrap();
        std::os::unix::fs::symlink(&escape_file, rootfs.join(INIT_GUEST_PATH)).unwrap();

        let init_src = tmp.path().join("init");
        fs::write(&init_src, b"real-init").unwrap();

        inject_init(&rootfs, &init_src).unwrap();

        // Should be a regular file now, not a symlink
        let meta = fs::symlink_metadata(rootfs.join(INIT_GUEST_PATH)).unwrap();
        assert!(!meta.is_symlink());
        assert_eq!(
            fs::read(rootfs.join(INIT_GUEST_PATH)).unwrap(),
            b"real-init"
        );
        // Original escape file should be unmodified
        assert_eq!(fs::read(&escape_file).unwrap(), b"escape");
    }
}
