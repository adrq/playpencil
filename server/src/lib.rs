mod adapter;
mod api_types;
mod error;
mod handlers;
mod router;
mod state;

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
    let state = AppState::new(backend);
    // Cancelled before axum starts draining so SSE streams end and graceful
    // shutdown can complete; otherwise an open /events stream would block it.
    let shutdown = state.shutdown.clone();
    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;
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
