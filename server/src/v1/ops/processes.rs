use crate::v1::types::command::CommandSpecWrite;
use crate::v1::types::problem::{
    InvalidInputProblem, NotFoundProblem, Problem, ProcessConflictProblem,
};
use crate::v1::types::process::{ProcessList, ProcessRecord};

/// Spawn a detached process in a sandbox.
///
/// Any failure after the spawn is admitted is `start_failed` on the process record and its stream. Not ready: `409`.
#[expect(dead_code)]
#[utoipa::path(
    post,
    path = "/v1/sandboxes/{id}/processes",
    operation_id = "spawn_process",
    tag = "processes",
    params(("id" = String, Path, description = "Sandbox id.")),
    request_body = CommandSpecWrite,
    responses(
        (status = 201, description = "Process.", body = ProcessRecord),
        (status = 400, description = "Unparseable.", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict.", body = ProcessConflictProblem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid.", body = InvalidInputProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn spawn_process() {}

/// List a sandbox's processes.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/sandboxes/{id}/processes",
    operation_id = "list_processes",
    tag = "processes",
    params(("id" = String, Path, description = "Sandbox id.")),
    responses(
        (status = 200, description = "Processes.", body = ProcessList),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn list_processes() {}

/// Read a process.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/sandboxes/{id}/processes/{pid}",
    operation_id = "get_process",
    tag = "processes",
    params(
        ("id" = String, Path, description = "Sandbox id."),
        ("pid" = String, Path, description = "Process id."),
    ),
    responses(
        (status = 200, description = "Process.", body = ProcessRecord),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn get_process() {}

/// Interrupt a process (TERM, grace period, KILL).
///
/// The record turns terminal only on confirmed termination. Ended or superseded: `409`.
#[expect(dead_code)]
#[utoipa::path(
    delete,
    path = "/v1/sandboxes/{id}/processes/{pid}",
    operation_id = "interrupt_process",
    tag = "processes",
    params(
        ("id" = String, Path, description = "Sandbox id."),
        ("pid" = String, Path, description = "Process id."),
    ),
    responses(
        (status = 202, description = "Accepted."),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict.", body = ProcessConflictProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn interrupt_process() {}
