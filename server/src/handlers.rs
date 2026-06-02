use std::convert::Infallible;
use std::pin::Pin;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, Sse};
use tokio_stream::wrappers::ReceiverStream;

use playpencil_core::backend::{BackendError, SandboxBackendSend};
use playpencil_core::types::{
    MountConfig, NetworkPolicy, ResourceLimits, SandboxConfig, SandboxId,
};

use crate::adapter::{build_response, project_wire_state};
use crate::api_types::{CreateSandboxRequest, ListParams, ListSandboxesResponse, SandboxResponse};
use crate::error::{ApiError, ErrorResponse, ValidatedJson};
use crate::state::AppState;

fn request_to_config(body: CreateSandboxRequest) -> Result<SandboxConfig, ApiError> {
    if body.image.uri.is_empty() {
        return Err(ApiError::Validation("image.uri must not be empty".into()));
    }
    // Reject control chars before they reach the OCI pull / C boundary, where
    // they risk silent CString truncation or framing breaks.
    if body.image.uri.chars().any(|c| c.is_ascii_control()) {
        return Err(ApiError::Validation(
            "image.uri must not contain control characters".into(),
        ));
    }
    let network: NetworkPolicy = body.network.try_into().map_err(ApiError::Validation)?;
    Ok(SandboxConfig {
        name: body.name,
        image: body.image.uri,
        resource_limits: ResourceLimits {
            cpus: body.resource_limits.cpus,
            memory_bytes: body.resource_limits.memory_bytes,
            disk_bytes: body.resource_limits.disk_bytes,
        },
        mounts: body
            .mounts
            .into_iter()
            .map(|m| MountConfig {
                host_path: m.host_path,
                guest_path: m.guest_path,
                read_only: m.read_only,
            })
            .collect(),
        network,
        env: body.env.into_iter().collect(),
    })
}

pub(crate) async fn create_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    ValidatedJson(body): ValidatedJson<CreateSandboxRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let config = request_to_config(body)?;
    let id = state.backend.create_and_start(config).await?;
    let view = state
        .backend
        .status(&id)
        .await
        .map_err(|e| ApiError::StatusQueryFailed {
            sandbox_id: id.0.clone(),
            source: e,
        })?;
    Ok((StatusCode::ACCEPTED, Json(build_response(&view))).into_response())
}

pub(crate) async fn list_sandboxes<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Query(params): Query<ListParams>,
) -> Result<Json<ListSandboxesResponse>, ApiError> {
    let views = state.backend.list().await?;
    // Drop empty tokens so `?state=` or `?state=,` collapse to "no filter".
    let state_filter: Vec<String> = params
        .state
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let items: Vec<SandboxResponse> = views
        .iter()
        .filter(|v| {
            if state_filter.is_empty() {
                return true;
            }
            let wire = project_wire_state(
                v.status.state,
                v.status.desired,
                v.status.generation,
                v.status.observed_generation,
            );
            state_filter.iter().any(|f| f.eq_ignore_ascii_case(wire))
        })
        .map(build_response)
        .collect();

    Ok(Json(ListSandboxesResponse { items }))
}

pub(crate) async fn get_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let view = state.backend.status(&SandboxId(id)).await?;
    Ok(Json(build_response(&view)))
}

pub(crate) async fn start_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sid = SandboxId(id);
    state.backend.start(&sid).await?;
    let view = state.backend.status(&sid).await?;
    Ok(Json(build_response(&view)))
}

pub(crate) async fn stop_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sid = SandboxId(id);
    state.backend.stop(&sid).await?;
    let view = state.backend.status(&sid).await?;
    Ok(Json(build_response(&view)))
}

pub(crate) async fn destroy_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.backend.destroy(&SandboxId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

type EventStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>>;

fn terminated_event(id: &str) -> Event {
    Event::default()
        .event("state_change")
        .json_data(serde_json::json!({ "sandbox_id": id, "state": "Terminated" }))
        .unwrap_or_else(|_| Event::default())
}

fn single_terminated_response(
    id: &str,
    shutdown: &tokio_util::sync::CancellationToken,
) -> axum::response::Response {
    let stream: EventStream = Box::pin(futures_util::StreamExt::take_until(
        tokio_stream::iter(vec![Ok(terminated_event(id))]),
        shutdown.clone().cancelled_owned(),
    ));
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

pub(crate) async fn sandbox_events<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let sid = SandboxId(id.clone());
    // (a) Existence + already-terminal check (404 if it never existed).
    let view = state.backend.status(&sid).await?;
    let wire = project_wire_state(
        view.status.state,
        view.status.desired,
        view.status.generation,
        view.status.observed_generation,
    );
    if wire == "Terminated" {
        return Ok(single_terminated_response(&id, &state.shutdown));
    }

    // (b) Subscribe.
    let rx = match state.backend.subscribe(&sid) {
        Ok(rx) => rx,
        Err(BackendError::NotFound) => {
            return Ok(single_terminated_response(&id, &state.shutdown));
        }
        Err(e) => return Err(e.into()),
    };

    // (c) Re-check to close the TOCTOU window between (a) and (b).
    let gone = match state.backend.status(&sid).await {
        Ok(v) => {
            project_wire_state(
                v.status.state,
                v.status.desired,
                v.status.generation,
                v.status.observed_generation,
            ) == "Terminated"
        }
        Err(BackendError::NotFound) => true,
        Err(_) => false,
    };
    if gone {
        drop(rx);
        return Ok(single_terminated_response(&id, &state.shutdown));
    }

    // Forward committed transitions. A forwarded Terminated ends the stream
    // (the retained per-sandbox sender never closes on its own).
    let (tx, out_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);
    let shutdown = state.shutdown.clone();
    let stream_id = id.clone();
    tokio::spawn(async move {
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                msg = rx.recv() => match msg {
                    Ok(status) => {
                        let wire = project_wire_state(
                            status.state,
                            status.desired,
                            status.generation,
                            status.observed_generation,
                        );
                        let ev = Event::default()
                            .event("state_change")
                            .json_data(serde_json::json!({
                                "sandbox_id": stream_id,
                                "state": wire,
                            }))
                            .unwrap_or_else(|_| Event::default());
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                        if wire == "Terminated" {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(sandbox_id = %stream_id, "SSE subscriber lagged by {n}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    });

    let stream: EventStream = Box::pin(ReceiverStream::new(out_rx));
    Ok(Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response())
}

pub(crate) async fn pause_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.backend.status(&SandboxId(id)).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "not_implemented".into(),
            detail: Some("pause is not supported".into()),
            sandbox_id: None,
        }),
    ))
}

pub(crate) async fn resume_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.backend.status(&SandboxId(id)).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "not_implemented".into(),
            detail: Some("resume is not supported".into()),
            sandbox_id: None,
        }),
    ))
}
