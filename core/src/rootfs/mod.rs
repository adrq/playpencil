#[cfg(target_os = "linux")]
pub mod linux;

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("fuse-overlayfs failed: {0}")]
    OverlaySetup(String),

    #[error("rootfs copy failed: {0}")]
    CopyFailed(String),

    #[error("init injection failed: {0}")]
    InitInjection(String),

    #[error("cleanup failed: {0}")]
    Cleanup(String),

    #[error("unsupported on this platform: {0}")]
    Unsupported(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct RootfsConfig {
    pub sandbox_id: String,
    pub base_rootfs: PathBuf,
    pub session_dir: PathBuf,
    pub init_binary: PathBuf,
}

pub struct PreparedRootfs {
    pub root: PathBuf,
    pub cleanup: RootfsCleanup,
}

pub enum RootfsCleanup {
    FuseOverlayfs {
        mount_point: PathBuf,
        work_dir: PathBuf,
        upper_dir: PathBuf,
    },
    CopyBased {
        dir: PathBuf,
    },
}

impl PreparedRootfs {
    pub fn destroy(self) -> Result<(), RootfsError> {
        match self.cleanup {
            RootfsCleanup::FuseOverlayfs {
                mount_point,
                work_dir: _,
                upper_dir: _,
            } => {
                let status = std::process::Command::new("fusermount")
                    .args(["-u", &mount_point.to_string_lossy()])
                    .status()
                    .map_err(|e| RootfsError::Cleanup(format!("fusermount: {e}")))?;
                if !status.success() {
                    return Err(RootfsError::Cleanup(format!(
                        "fusermount -u exited with {status}"
                    )));
                }
                let session_dir = mount_point.parent().unwrap_or(&mount_point);
                std::fs::remove_dir_all(session_dir)
                    .map_err(|e| RootfsError::Cleanup(format!("remove session dir: {e}")))?;
                Ok(())
            }
            RootfsCleanup::CopyBased { dir } => {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| RootfsError::Cleanup(format!("remove copy dir: {e}")))?;
                Ok(())
            }
        }
    }
}

pub trait RootfsProvider {
    fn prepare(&self, config: &RootfsConfig) -> Result<PreparedRootfs, RootfsError>;
    fn fuse_overlayfs_available(&self) -> bool;

    /// Remove a partial per-sandbox session directory under `sessions_root`
    /// before a fresh prepare reuses the path. Bounded to the validated id;
    /// idempotent (a missing directory is success).
    fn clear_session_dir(&self, sessions_root: &Path, sandbox_id: &str) -> Result<(), RootfsError>;

    /// True if an overlay-mode rootfs under `sessions_root` persists on disk but
    /// is no longer mounted (must not be booted nor reprovisioned).
    fn fuse_rootfs_unmounted(
        &self,
        sessions_root: &Path,
        sandbox_id: &str,
    ) -> Result<bool, RootfsError>;

    /// The canonical prepared-rootfs root for a sandbox, derived from the
    /// validated id and `sessions_root` (never a trusted stored path).
    fn session_rootfs_path(
        &self,
        sessions_root: &Path,
        sandbox_id: &str,
    ) -> Result<PathBuf, RootfsError>;
}

/// Provider for platforms without the Linux rootfs machinery. Every operation
/// fails with `Unsupported` rather than silently succeeding.
#[cfg(not(target_os = "linux"))]
pub struct UnsupportedRootfsProvider;

#[cfg(not(target_os = "linux"))]
impl RootfsProvider for UnsupportedRootfsProvider {
    fn prepare(&self, _config: &RootfsConfig) -> Result<PreparedRootfs, RootfsError> {
        Err(RootfsError::Unsupported("rootfs preparation".into()))
    }
    fn fuse_overlayfs_available(&self) -> bool {
        false
    }
    fn clear_session_dir(
        &self,
        _sessions_root: &Path,
        _sandbox_id: &str,
    ) -> Result<(), RootfsError> {
        Err(RootfsError::Unsupported("clear_session_dir".into()))
    }
    fn fuse_rootfs_unmounted(
        &self,
        _sessions_root: &Path,
        _sandbox_id: &str,
    ) -> Result<bool, RootfsError> {
        Err(RootfsError::Unsupported("fuse_rootfs_unmounted".into()))
    }
    fn session_rootfs_path(
        &self,
        _sessions_root: &Path,
        _sandbox_id: &str,
    ) -> Result<PathBuf, RootfsError> {
        Err(RootfsError::Unsupported("session_rootfs_path".into()))
    }
}
