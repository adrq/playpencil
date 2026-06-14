use serde::{Deserialize, Serialize};

use crate::lifecycle::{DesiredState, FailureReason, State};

// The exec wire protocol, flow-control constants, command-interpretation mode,
// and the shared ExecHandle type family now live in `playpencil_exec`. Re-export
// the pieces here so the long-standing `core::types::*` paths (used across core,
// the server faces, and the C ABI) keep resolving.
pub use playpencil_exec::handle::{
    ExecCanceller, ExecControl, ExecEvent, ExecHandle, ExecId, ExecIo, ExecRequest,
};
pub use playpencil_exec::protocol::ExecMode;
pub use playpencil_exec::protocol::limits::STDIN_FRAME_RAW_MAX;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

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
    /// Optional command run as the sandbox's main process once it is running.
    /// `None` leaves the sandbox idle (serving exec requests only). Persisted so
    /// it is re-launched on every (re)boot from this config.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
}

/// How a sandbox's main process finished, for backend-internal diagnostics. Held
/// only on the durable record and read through a backend seam — never serialized
/// onto the status wire (HTTP or C ABI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointExit {
    /// The process ran and exited with this code.
    Exited { code: i32 },
    /// The process never started as intended (bad command, missing shell, …).
    StartError { message: String },
}

/// Validate a main-process command. `None` is always valid (idle sandbox); a
/// `Some` must be a non-empty argv with a non-empty program and no NUL bytes
/// (which truncate at the C boundary). The single source of truth, shared by the
/// create paths, the HTTP mirror, and the durable record validator.
pub fn validate_entrypoint(entrypoint: Option<&[String]>) -> Result<(), String> {
    let Some(argv) = entrypoint else {
        return Ok(());
    };
    if argv.is_empty() {
        return Err("entrypoint must not be empty".into());
    }
    if argv[0].is_empty() {
        return Err("entrypoint program must not be empty".into());
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Err("entrypoint arguments must not contain NUL".into());
    }
    Ok(())
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
