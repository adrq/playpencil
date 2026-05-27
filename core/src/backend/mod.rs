pub mod mock;

use crate::types::{ExecId, ExecRequest, SandboxConfig, SandboxId, SandboxStatus};
use std::fmt;

#[derive(Debug)]
pub enum BackendError {
    NotFound,
    InvalidState,
    Internal(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("sandbox not found"),
            Self::InvalidState => f.write_str("operation not valid in current state"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for BackendError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub hardware_isolation: bool,
    pub network_policy: bool,
    pub host_mounts: bool,
}

#[allow(async_fn_in_trait)]
pub trait SandboxBackend {
    async fn create(&self, config: SandboxConfig) -> Result<SandboxId, BackendError>;
    async fn start(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn status(&self, id: &SandboxId) -> Result<SandboxStatus, BackendError>;
    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecId, BackendError>;
    fn capabilities(&self) -> Capabilities;
}
