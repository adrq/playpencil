use axum::Router;
use axum::routing::{get, post};

use playpencil_core::backend::SandboxBackendSend;

use crate::handlers;
use crate::state::AppState;

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
        .route(
            "/v1/sandboxes/{id}/pause",
            post(handlers::pause_sandbox::<B>),
        )
        .route(
            "/v1/sandboxes/{id}/resume",
            post(handlers::resume_sandbox::<B>),
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
        .with_state(state)
}
