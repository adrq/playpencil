use crate::v1::types::problem::{
    CreateConflictProblem, InternalProblem, InvalidInputProblem, NotFoundProblem,
    PatchConflictProblem, Problem,
};
use crate::v1::types::query::ListSandboxesQuery;
use crate::v1::types::sandbox::{
    CreateSandboxRequest, PatchSandboxRequest, SandboxDocument, SandboxList,
};

/// Create a sandbox.
///
/// Idempotent on `name`: the same namespace and configuration (defaults applied, `desired_state` ignored) returns the existing document; otherwise `409` with `existing_id`. A missing `config.network`, or a missing or unknown `config.backend` (with `available_backends`), is `422`.
#[expect(dead_code)]
#[utoipa::path(
    post,
    path = "/v1/sandboxes",
    operation_id = "create_sandbox",
    tag = "sandboxes",
    request_body = CreateSandboxRequest,
    responses(
        (status = 202, description = "Sandbox.", body = SandboxDocument),
        (status = 400, description = "Unparseable.", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 409, description = "Conflict.", body = CreateConflictProblem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid.", body = InvalidInputProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn create_sandbox() {}

/// List sandboxes.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/sandboxes",
    operation_id = "list_sandboxes",
    tag = "sandboxes",
    params(ListSandboxesQuery),
    responses(
        (status = 200, description = "Sandboxes.", body = SandboxList),
        (status = 400, description = "Unparseable.", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 422, description = "Invalid.", body = InvalidInputProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn list_sandboxes() {}

/// Read a sandbox.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/sandboxes/{id}",
    operation_id = "get_sandbox",
    tag = "sandboxes",
    params(("id" = String, Path, description = "Sandbox id.")),
    responses(
        (status = 200, description = "Sandbox.", body = SandboxDocument),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn get_sandbox() {}

/// Change a sandbox's target state or configuration.
///
/// `202` even when nothing changes.
/// - No `if_version`: `422`; stale: `409` with `current_version`.
/// - `network` (hot) is accepted in any state. `mounts`, `env` and `main` (cold) only when `state` is `stopped` and `desired` is `stopped` or a `reason` is set, else `409`; they take effect at the next start. `backend` and `backend_options` are immutable (`422`).
/// - `destroyed` is final (`409`). While a `reason` is set, changing `desired_state` needs `clear_reason` = `reason.id`, else `409`; configuration-only writes leave `reason` unchanged.
/// - Validation is all-or-nothing. `config` applies before `desired_state`; `network` is enforced before the response, and if that fails: `500`, the old policy stays and `desired_state` isn't applied.
#[expect(dead_code)]
#[utoipa::path(
    patch,
    path = "/v1/sandboxes/{id}",
    operation_id = "update_sandbox",
    tag = "sandboxes",
    params(("id" = String, Path, description = "Sandbox id.")),
    request_body = PatchSandboxRequest,
    responses(
        (status = 202, description = "Sandbox.", body = SandboxDocument),
        (status = 400, description = "Unparseable.", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict.", body = PatchConflictProblem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid.", body = InvalidInputProblem, content_type = "application/problem+json"),
        (status = 500, description = "Policy not applied.", body = InternalProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn update_sandbox() {}
