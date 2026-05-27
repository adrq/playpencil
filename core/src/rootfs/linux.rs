use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{PreparedRootfs, RootfsCleanup, RootfsConfig, RootfsError, RootfsProvider};

const INIT_GUEST_PATH: &str = "usr/local/bin/playpencil-init";

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
        let merged = sandbox_dir.join("merged");
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

#[cfg(test)]
mod tests {
    use super::*;

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
