use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use playpencil_core::backend::SandboxBackendSend;

use crate::drain::{self, Admission};
use crate::exec;
use crate::handlers;
use crate::health::HealthState;
use crate::state::AppState;

/// The complete application: every route behind the admission gate.
pub(crate) fn build_app<B: SandboxBackendSend + Sync + 'static>(state: AppState<B>) -> Router {
    let admission = state.admission.clone();
    let health = HealthState::new(state.backend.clone(), admission.clone());
    with_admission(
        build_router(state).merge(crate::v1::routes::router(health)),
        admission,
    )
}

/// Wraps `router`, including its fallback, in the admission gate.
pub(crate) fn with_admission(router: Router, admission: Arc<Admission>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        admission,
        drain::admit,
    ))
}

pub(crate) fn build_router<B: SandboxBackendSend + Sync + 'static>(state: AppState<B>) -> Router {
    Router::new()
        // Standard lifecycle endpoints
        .route(
            "/v1/sandboxes",
            post(handlers::create_sandbox::<B>).get(handlers::list_sandboxes::<B>),
        )
        .route(
            "/v1/sandboxes/{id}",
            get(handlers::get_sandbox::<B>).delete(handlers::destroy_sandbox::<B>),
        )
        // Extension endpoints
        .route(
            "/v1x/sandboxes/{id}/start",
            post(handlers::start_sandbox::<B>),
        )
        .route(
            "/v1x/sandboxes/{id}/stop",
            post(handlers::stop_sandbox::<B>),
        )
        .route(
            "/v1x/sandboxes/{id}/events",
            get(handlers::sandbox_events::<B>),
        )
        // execd-compatible command face.
        .route(
            "/v1x/sandboxes/{id}/execd/command",
            post(exec::command::run_command::<B>).delete(exec::command::delete_command::<B>),
        )
        // Neutral duplex exec face (WebSocket, one connection per exec).
        .route("/v1x/sandboxes/{id}/exec", get(exec::duplex::duplex::<B>))
        .with_state(state)
}
