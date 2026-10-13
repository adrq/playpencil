pub mod health;
pub mod libkrun;
pub mod mock;
pub mod reconciler;

use crate::types::{
    EntrypointExit, ExecHandle, ExecRequest, SandboxConfig, SandboxId, SandboxStatus, SandboxView,
};
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

/// Accepted-not-converged lifecycle backend.
///
/// `create_and_start`/`start`/`stop`/`destroy` return once the new intent is durably
/// persisted (accepted), NOT once the sandbox converges. Provision and start
/// failures surface asynchronously as `state == Failed` via `status`, never as
/// a return error. A destroyed sandbox's record is retained (reported as
/// `Destroyed`) until pruned, so `status` returns `NotFound` only for sandboxes
/// that never existed.
#[trait_variant::make(SandboxBackendSend: Send)]
pub trait SandboxBackend {
    /// Genesis with `desired = Running` (durable run-intent before provisioning).
    async fn create_and_start(&self, config: SandboxConfig) -> Result<SandboxId, BackendError>;
    async fn start(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError>;
    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError>;
    /// Snapshot of the sandbox's status and persisted config.
    async fn status(&self, id: &SandboxId) -> Result<SandboxView, BackendError>;
    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError>;
    async fn list(&self) -> Result<Vec<SandboxView>, BackendError>;
    /// How the sandbox's main process finished, if it has and the outcome is
    /// retained. Backend-internal diagnostics, distinct from `status`.
    async fn entrypoint_exit(&self, id: &SandboxId)
    -> Result<Option<EntrypointExit>, BackendError>;
    /// Subscribe to committed `state` transitions for one sandbox.
    fn subscribe(
        &self,
        id: &SandboxId,
    ) -> Result<tokio::sync::broadcast::Receiver<SandboxStatus>, BackendError>;
    fn capabilities(&self) -> Capabilities;
    /// Whether the daemon can serve requests. Daemon-wide failures only: a
    /// failed or poisoned individual sandbox does not make this an error.
    async fn health(&self) -> Result<(), health::Unhealthy>;
}
