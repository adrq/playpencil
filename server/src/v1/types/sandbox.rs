use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::config::{ConfigCreate, ConfigPatch, ConfigRead};
use super::serde_util::{non_null, non_null_counter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub(crate) enum DesiredState {
    Stopped,
    Running,
    Destroyed,
}

impl TryFrom<String> for DesiredState {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        match value.as_str() {
            "stopped" => Ok(Self::Stopped),
            "running" => Ok(Self::Running),
            "destroyed" => Ok(Self::Destroyed),
            other => Err(format!(
                "unknown variant `{other}`, expected one of `stopped`, `running`, `destroyed`"
            )),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct CreateSandboxRequest {
    /// Unique per daemon; immutable.
    #[schema(pattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    pub(crate) name: String,
    /// Exact and case-sensitive; `"*"` is reserved; immutable.
    pub(crate) namespace: String,
    /// `stopped` stops gracefully (see `flush_incomplete`); `destroyed` keeps the record.
    #[schema(nullable = false, default = "running")]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) desired_state: Option<DesiredState>,
    pub(crate) config: ConfigCreate,
}

#[derive(Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
pub(crate) struct PatchSandboxRequest {
    /// The `version` last read.
    #[schema(
        required = true,
        nullable = false,
        minimum = 0,
        maximum = 9223372036854775807_i64
    )]
    #[serde(
        default,
        deserialize_with = "non_null_counter",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) if_version: Option<u64>,
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) desired_state: Option<DesiredState>,
    /// The `reason.id` being acknowledged.
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) clear_reason: Option<String>,
    #[schema(nullable = false)]
    #[serde(
        default,
        deserialize_with = "non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) config: Option<ConfigPatch>,
}

/// Why `state` differs from `desired`. Latched: no action until acknowledged.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Reason {
    pub(crate) id: String,
    /// `provision_failed`, `start_failed`, `destroy_failed`, `crashed`, or `exited` (clean main-process exit).
    pub(crate) code: String,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

/// `running` is set when compute is created. Converged: `state` equals `desired`, or a `reason` is set. After a daemon restart, a running sandbox becomes `stopped` with a `reason`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Status {
    /// `stopped`, `running` or `destroyed`.
    #[schema(value_type = String)]
    pub(crate) desired: DesiredState,
    /// Same values, or `null` before the first commit.
    #[schema(value_type = Option<String>, required = true)]
    pub(crate) state: Option<DesiredState>,
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<Reason>,
    #[schema(format = DateTime)]
    pub(crate) created_at: String,
    /// `created_at` until the first change.
    #[schema(format = DateTime)]
    pub(crate) last_transition_at: String,
    /// Teardown fidelity after `stopped` or `destroyed`.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) teardown: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SandboxDocument {
    pub(crate) id: String,
    #[schema(pattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    pub(crate) name: String,
    pub(crate) namespace: String,
    /// Bumped by every accepted write; send it as `if_version`.
    #[schema(minimum = 0, maximum = 9223372036854775807_i64)]
    pub(crate) version: u64,
    pub(crate) status: Status,
    pub(crate) config: ConfigRead,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SandboxList {
    pub(crate) items: Vec<SandboxDocument>,
}

super::serde_util::object_only!(CreateSandboxRequest, PatchSandboxRequest);
