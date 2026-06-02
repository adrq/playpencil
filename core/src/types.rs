use serde::{Deserialize, Serialize};

use crate::lifecycle::{DesiredState, FailureReason, State};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpus: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountConfig {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPolicy {
    Isolated,
    Allowlist { allowed_domains: Vec<String> },
    Unrestricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub name: Option<String>,
    pub image: String,
    pub resource_limits: ResourceLimits,
    pub mounts: Vec<MountConfig>,
    pub network: NetworkPolicy,
    pub env: Vec<(String, String)>,
}

/// Native sandbox status. The wire projection lives in the server adapter; this
/// carries the raw lifecycle fields (never wire strings).
#[derive(Clone, Debug, Serialize)]
pub struct SandboxStatus {
    pub sandbox_id: SandboxId,
    /// `None` is genesis.
    pub state: Option<State>,
    pub desired: DesiredState,
    pub generation: u64,
    /// `observed_generation < generation` means a transition is in progress.
    pub observed_generation: u64,
    pub reason: Option<FailureReason>,
    pub message: Option<String>,
    pub created_at: Option<String>,
    pub last_transition_at: Option<String>,
}

/// A status snapshot paired with the persisted config, so readers can build a
/// full response without a separate config store.
#[derive(Clone, Debug, Serialize)]
pub struct SandboxView {
    pub status: SandboxStatus,
    pub config: SandboxConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: i32 },
}

/// Control messages for a running exec session (signals, terminal resize).
pub enum ExecControl {
    Signal(i32),
    Resize { cols: u16, rows: u16 },
}

pub struct ExecHandle {
    pub exec_id: ExecId,
    /// Receives stdout/stderr/exit events from the running process.
    pub events: tokio::sync::mpsc::Receiver<ExecEvent>,
    /// Send raw bytes to the process's stdin.
    pub stdin: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Send control messages (signals, resize) to the running process.
    pub control: tokio::sync::mpsc::Sender<ExecControl>,
}

impl ExecHandle {
    /// Send a signal to the process's process group.
    pub async fn signal(
        &self,
        sig: i32,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ExecControl>> {
        self.control.send(ExecControl::Signal(sig)).await
    }

    /// Request a terminal resize for the process.
    pub async fn resize(
        &self,
        cols: u16,
        rows: u16,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ExecControl>> {
        self.control.send(ExecControl::Resize { cols, rows }).await
    }
}
