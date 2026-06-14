use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::adapter::NetworkPolicyWire;

#[derive(Deserialize)]
pub(crate) struct CreateSandboxRequest {
    pub image: ImageWire,
    #[serde(default)]
    pub resource_limits: ResourceLimitsWire,
    #[serde(default)]
    pub mounts: Vec<MountConfigWire>,
    #[serde(default = "default_network")]
    pub network: NetworkPolicyWire,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub name: Option<String>,
    /// Optional command to run as the sandbox's main process.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
}

/// Image reference (object form). Only `uri` is used today; `auth` is accepted but ignored.
#[derive(Deserialize)]
pub(crate) struct ImageWire {
    pub uri: String,
}

fn default_network() -> NetworkPolicyWire {
    NetworkPolicyWire::Simple("isolated".into())
}

#[derive(Deserialize, Default)]
pub(crate) struct ResourceLimitsWire {
    pub cpus: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct MountConfigWire {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
}

#[derive(Serialize)]
pub(crate) struct SandboxResponse {
    pub id: String,
    pub status: StatusWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    // Config-derived fields. The durable record retains config across destroy, so
    // these remain present for Terminated sandboxes; `env` is never put on the wire.
    // `image`/`network` are always Some today (build_response fills them), so their
    // skip_serializing_if is currently inert but kept for shape stability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPolicyWire>,
}

#[derive(Serialize)]
pub(crate) struct StatusWire {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "lastTransitionAt", skip_serializing_if = "Option::is_none")]
    pub last_transition_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ListSandboxesResponse {
    pub items: Vec<SandboxResponse>,
}

/// Query: `?state=running,stopped` (comma-separated, single key).
/// serde_urlencoded does not support repeated keys for Vec<T>.
#[derive(Deserialize)]
pub(crate) struct ListParams {
    pub state: Option<String>,
}

/// Body of a foreground command request on the execd-compatible command face.
#[derive(Deserialize)]
pub(crate) struct CommandRequest {
    pub command: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub background: bool,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub envs: HashMap<String, String>,
}

/// Query for `DELETE …/execd/command?id=<command-id>`.
#[derive(Deserialize)]
pub(crate) struct CommandDeleteParams {
    pub id: String,
}
