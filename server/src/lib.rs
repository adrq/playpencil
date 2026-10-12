mod adapter;
mod api_types;
mod endpoints;
mod error;
mod exec;
mod handlers;
mod router;
mod state;
pub mod v1;

pub use v1::openapi_json;

use std::net::SocketAddr;

use playpencil_core::backend::SandboxBackendSend;

use crate::router::build_router;
use crate::state::AppState;

pub struct ServerConfig {
    pub bind_addr: SocketAddr,
}

pub async fn run_server<B: SandboxBackendSend + Sync + 'static>(
    config: ServerConfig,
    backend: B,
) -> std::io::Result<()> {
    // Bind first so the discovery endpoint can surface the real bound address.
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;

    let state = AppState::new(backend).with_public_addr(local_addr);
    // Cancelled before axum starts draining so SSE streams end and graceful
    // shutdown can complete; otherwise an open /events stream would block it.
    let shutdown = state.shutdown.clone();
    let router = build_router(state);

    println!("listening on {local_addr}");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            shutdown.cancel();
        })
        .await
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
    tracing::info!("shutdown signal received");
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received");
}
