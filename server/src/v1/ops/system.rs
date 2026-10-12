use crate::v1::types::capabilities::CapabilitiesResponse;

/// Enforcement fidelity and listening addresses.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/capabilities",
    operation_id = "get_capabilities",
    tag = "system",
    responses(
        (status = 200, description = "Capabilities.", body = CapabilitiesResponse),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
    ),
)]
pub(crate) async fn get_capabilities() {}

/// Daemon liveness; no body.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/health",
    operation_id = "get_health",
    tag = "system",
    responses(
        (status = 200, description = "Healthy."),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 503, description = "Unhealthy."),
    ),
)]
pub(crate) async fn get_health() {}
