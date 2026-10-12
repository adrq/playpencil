use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::command::{CommandSpecRead, CommandSpecWrite, EnvNames, EnvWrite};
use super::network::{NetworkRead, NetworkWrite};
use super::serde_util::non_null;

/// A host directory bound into the sandbox; `guest_path`s are unique. Access is limited to the daemon user's permissions and stays within the directory. Close-to-open consistency, POSIX locks, atomic rename. Unflushed writes can be lost on abrupt death; a graceful stop flushes them.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct Mount {
    pub(crate) host_path: String,
    pub(crate) guest_path: String,
    pub(crate) read_only: bool,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct ConfigCreate {
    /// A `backend_id` from `/v1/capabilities`.
    #[schema(required = true, nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) backend: Option<String>,
    /// Defined by the backend; `libkrun` requires `image: {uri}`.
    #[schema(value_type = Object, nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) backend_options: Option<serde_json::Map<String, serde_json::Value>>,
    #[schema(required = true, nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) network: Option<NetworkWrite>,
    #[schema(nullable = false, default = json!([]))]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) mounts: Option<Vec<Mount>>,
    #[schema(nullable = false, default = json!({}))]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) env: Option<EnvWrite>,
    /// Its exit stops the sandbox (`exited` if clean, else `crashed`) and kills its descendants; some may escape on `BestEffort` backends. Absent: the sandbox is idle and exec-only, with exec-spawned processes unbounded.
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) main: Option<CommandSpecWrite>,
}

/// Present members replace the current value wholesale; absent ones are unchanged.
#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct ConfigPatch {
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) backend: Option<String>,
    #[schema(value_type = Object, nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) backend_options: Option<serde_json::Map<String, serde_json::Value>>,
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) network: Option<NetworkWrite>,
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) mounts: Option<Vec<Mount>>,
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) env: Option<EnvWrite>,
    /// `null` removes it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub(crate) main: Option<Option<CommandSpecWrite>>,
}

/// As written; members omitted at create are omitted.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ConfigRead {
    pub(crate) backend: String,
    #[schema(value_type = Object, nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend_options: Option<serde_json::Map<String, serde_json::Value>>,
    pub(crate) network: NetworkRead,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mounts: Option<Vec<Mount>>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) env: Option<EnvNames>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) main: Option<CommandSpecRead>,
}

super::serde_util::object_only!(Mount, ConfigCreate, ConfigPatch);
