use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CapabilitiesResponse {
    /// Concrete `addr:port`s the daemon listens on, the streaming link included; wildcard binds are expanded.
    pub(crate) listeners: Vec<String>,
    pub(crate) backends: Vec<Backend>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Backend {
    /// Value for `config.backend`.
    pub(crate) backend_id: String,
    /// `hardware` or `process`.
    pub(crate) isolation_tier: String,
    pub(crate) provenance: Provenance,
    pub(crate) dials: Vec<Dial>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Provenance {
    pub(crate) backend_id: String,
    pub(crate) version: String,
    pub(crate) build: String,
    pub(crate) os: String,
    pub(crate) kernel: String,
    pub(crate) schema: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Dial {
    /// `egress_none`, `egress_allowlist`, `fs_workspace_confinement` or `teardown_confirmation` (`Strong`: verified empty; `BestEffort`: escaped descendants may survive).
    pub(crate) dial: String,
    /// `Strong`, `BestEffort` or `Unsupported`.
    pub(crate) level: String,
    pub(crate) mechanism: String,
    pub(crate) known_limitations: Vec<String>,
}
