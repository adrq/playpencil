mod adapter;
mod api_types;
mod drain;
mod error;
mod exec;
mod handlers;
mod health;
mod router;
#[cfg(test)]
mod serve_tests;
mod state;
#[cfg(test)]
mod test_support;
pub mod v1;

pub use v1::openapi_json;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use playpencil_core::backend::SandboxBackendSend;
use tokio_util::sync::CancellationToken;

use crate::drain::Admission;
use crate::router::build_app;
use crate::state::AppState;

pub struct ServerConfig {
    pub bind_addr: SocketAddr,
}

/// Serves until SIGTERM or SIGINT, then drains and returns.
///
/// The signal handlers are installed before the `listening on` line is
/// printed. On a signal: new requests other than `GET /v1/health` get a bare
/// 503 with `Retry-After`, health answers 503, admitted requests complete,
/// then streams are cancelled, the listener closes and open connections
/// finish their responses.
pub async fn run_server<B: SandboxBackendSend + Sync + 'static>(
    config: ServerConfig,
    backend: B,
) -> std::io::Result<()> {
    let signal = shutdown_signal()?;

    // Bind before building the router; the readiness line prints the bound address.
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;

    let state = AppState::new(backend);

    println!("listening on {local_addr}");

    serve(listener, state, signal).await
}

/// Serves `state` on `listener` and drains when `signal` completes.
pub(crate) async fn serve<B: SandboxBackendSend + Sync + 'static>(
    listener: tokio::net::TcpListener,
    state: AppState<B>,
    signal: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let admission = state.admission.clone();
    let shutdown = state.shutdown.clone();
    serve_app(listener, build_app(state), admission, shutdown, signal).await
}

/// Serves `app` and runs the drain when `signal` completes: stop admitting,
/// wait for admitted requests, cancel `shutdown`, then close the listener and
/// wait for open connections to finish.
pub(crate) async fn serve_app(
    listener: tokio::net::TcpListener,
    app: Router,
    admission: Arc<Admission>,
    shutdown: CancellationToken,
    signal: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            signal.await;
            tracing::info!("shutdown signal received; draining");
            admission.begin_drain();
            admission.wait_drained().await;
            shutdown.cancel();
        })
        .await
}

/// Installs SIGTERM and SIGINT handlers and returns a future that completes
/// on the first of them.
#[cfg(unix)]
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = interrupt.recv() => {},
        }
    })
}

#[cfg(not(unix))]
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
    Ok(async {
        let _ = tokio::signal::ctrl_c().await;
    })
}
