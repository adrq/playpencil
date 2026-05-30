use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use playpencil_core::types::NetworkPolicy;

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

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum NetworkPolicyWire {
    Allowlist { allowlist: AllowlistConfig },
    Simple(String),
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct AllowlistConfig {
    pub allowed_domains: Vec<String>,
}

impl TryFrom<NetworkPolicyWire> for NetworkPolicy {
    type Error = String;

    fn try_from(wire: NetworkPolicyWire) -> Result<Self, Self::Error> {
        match wire {
            NetworkPolicyWire::Simple(s) if s == "isolated" => Ok(NetworkPolicy::Isolated),
            NetworkPolicyWire::Simple(s) if s == "unrestricted" => Ok(NetworkPolicy::Unrestricted),
            NetworkPolicyWire::Simple(s) => Err(format!("unknown network policy: {s}")),
            NetworkPolicyWire::Allowlist { allowlist } => Ok(NetworkPolicy::Allowlist {
                allowed_domains: allowlist.allowed_domains,
            }),
        }
    }
}

impl From<&NetworkPolicy> for NetworkPolicyWire {
    fn from(np: &NetworkPolicy) -> Self {
        match np {
            NetworkPolicy::Isolated => NetworkPolicyWire::Simple("isolated".into()),
            NetworkPolicy::Unrestricted => NetworkPolicyWire::Simple("unrestricted".into()),
            NetworkPolicy::Allowlist { allowed_domains } => NetworkPolicyWire::Allowlist {
                allowlist: AllowlistConfig {
                    allowed_domains: allowed_domains.clone(),
                },
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct SandboxResponse {
    pub id: String,
    pub status: StatusWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    // Config-derived fields are absent for destroyed sandboxes (config removed on destroy).
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
