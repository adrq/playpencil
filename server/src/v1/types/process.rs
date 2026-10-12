use serde::Serialize;
use utoipa::ToSchema;

use super::command::CommandSpecRead;

#[expect(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProcessState {
    Running,
    Exited {
        code: i32,
    },
    StartFailed {
        message: String,
    },
    /// Outcome and liveness unknown.
    Lost {
        /// `Strong`: gone. `BestEffort`: may still be alive.
        teardown: String,
    },
}

/// A process in a sandbox. Records don't survive a daemon restart; processes do only if they escaped a `BestEffort` teardown. Output is never stored.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProcessRecord {
    /// Never reused; also used on `/v1/streams`.
    pub(crate) id: String,
    /// Boot incarnation.
    #[schema(minimum = 0, maximum = 9223372036854775807_i64)]
    pub(crate) boot: u64,
    /// `main` for the main process (current: highest `boot`).
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Informational.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pid: Option<u32>,
    pub(crate) command_spec: CommandSpecRead,
    pub(crate) state: ProcessState,
    /// Absent if not observed.
    #[schema(nullable = false, format = DateTime)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) started_at: Option<String>,
    /// Only for `exited`.
    #[schema(nullable = false, format = DateTime)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exited_at: Option<String>,
    /// Stays set on a `running` process that can't be killed.
    pub(crate) interrupt_requested: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ProcessList {
    /// Includes the main process.
    pub(crate) items: Vec<ProcessRecord>,
}
