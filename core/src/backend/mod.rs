pub mod libkrun;
pub mod mock;

use crate::types::{ExecHandle, ExecRequest, SandboxConfig, SandboxId, SandboxStatus};
use std::fmt;

#[derive(Debug)]
pub enum BackendError {
    NotFound,
    InvalidState,
    /// Caller-supplied input failed validation (e.g. a malformed mount). The
    /// message is user-facing prose and maps to a 4xx, not a server fault.
    InvalidInput(String),
    Internal(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("sandbox not found"),
            Self::InvalidState => f.write_str("operation not valid in current state"),
            Self::InvalidInput(msg) => write!(f, "{msg}"),
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

#[trait_variant::make(SandboxBackendSend: Send)]
pub trait SandboxBackend {
    async fn create(&self, config: SandboxConfig) -> Result<SandboxId, BackendError>;
    async fn start(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError>;
    /// Tear down the sandbox, transitioning it to the terminal Destroyed state.
    ///
    /// Implementations retain the destroyed sandbox in this terminal state
    /// (subject to later pruning) rather than dropping the record immediately,
    /// so a subsequent `status` call reports it as Destroyed rather than
    /// `NotFound`. Callers must not rely on `status` returning `NotFound`
    /// right after a successful `destroy`.
    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError>;
    /// Report the current status of a sandbox.
    ///
    /// After a successful `destroy`, this continues to report the sandbox in
    /// the terminal Destroyed state until the record is pruned; it returns
    /// `NotFound` only for sandboxes that never existed or were pruned.
    async fn status(&self, id: &SandboxId) -> Result<SandboxStatus, BackendError>;
    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError>;
    async fn list(&self) -> Result<Vec<SandboxStatus>, BackendError>;
    fn capabilities(&self) -> Capabilities;
}
