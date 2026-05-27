#[cfg(target_os = "linux")]
pub mod linux;

use std::path::PathBuf;

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
}
