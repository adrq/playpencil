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
) -> Result<impl IntoResponse, ApiError> {
    let sid = SandboxId(id);
    state.backend.start(&sid).await?;
    let view = state.backend.status(&sid).await?;
    // Accepted-not-converged: intent is set; convergence is observed by polling.
    Ok((StatusCode::ACCEPTED, Json(build_response(&view))).into_response())
}

pub(crate) async fn stop_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let sid = SandboxId(id);
    state.backend.stop(&sid).await?;
    let view = state.backend.status(&sid).await?;
    // Accepted-not-converged: intent is set; convergence is observed by polling.
    Ok((StatusCode::ACCEPTED, Json(build_response(&view))).into_response())
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

    // (c) Re-check to close the TOCTOU window between (a) and (b), and capture
    // the current projected wire state to seed the stream (snapshot-on-connect).
    // The backend channel is a plain broadcast with no replay, so a subscriber
    // that joins after a transition completed would otherwise hang waiting for
    // the next delta; the seed lets it observe the current state immediately.
    // After the seed the stream is BEST-EFFORT: backend transitions are forwarded
    // as-is, so a transition committed in the [subscribe, snapshot] window may be
    // re-emitted (at-least-once duplicate / brief reorder at connect). Polling GET
    // to the per-verb terminal target is the canonical convergence mechanism; SSE
    // is a supplementary live feed. Subscribe-first ordering is
    // kept deliberately (reordering would reintroduce a miss/hang).
    //
    // NotFound/Terminated collapses to the single terminal response; a transient
    // status error yields no snapshot (no seed) but still forwards deltas.
    let snapshot: Option<&'static str> = match state.backend.status(&sid).await {
        Ok(v) => Some(project_wire_state(
            v.status.state,
            v.status.desired,
            v.status.generation,
            v.status.observed_generation,
        )),
        Err(BackendError::NotFound) => Some("Terminated"),
        Err(_) => None,
    };
    if snapshot == Some("Terminated") {
        drop(rx);
        return Ok(single_terminated_response(&id, &state.shutdown));
    }

    // Forward committed transitions. A forwarded Terminated ends the stream
    // (the retained per-sandbox sender never closes on its own).
    let (tx, out_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);
    // Seed with a snapshot of the current state. snapshot is non-terminal here
    // (Terminated returned above); the channel is fresh (capacity 64) so the
    // send cannot block.
    if let Some(wire) = snapshot {
        let ev = Event::default()
            .event("state_change")
            .json_data(serde_json::json!({ "sandbox_id": id, "state": wire }))
            .unwrap_or_else(|_| Event::default());
        let _ = tx.try_send(Ok(ev));
    }
    let shutdown = state.shutdown.clone();
    let stream_id = id.clone();
    tokio::spawn(async move {
        let mut rx = rx;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                // Client disconnected (out_rx dropped): wake even on a quiet
                // stream so the broadcast receiver is released promptly instead
                // of leaking until the next event or server shutdown.
                _ = tx.closed() => break,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tower::ServiceExt;

    use playpencil_core::backend::mock::MockBackend;
    use playpencil_core::lifecycle::State;
    use playpencil_core::types::{NetworkPolicy, ResourceLimits, SandboxConfig};

    use crate::router::build_router;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "test:latest".into(),
            resource_limits: ResourceLimits {
                cpus: None,
                memory_bytes: None,
                disk_bytes: None,
            },
            mounts: vec![],
            network: NetworkPolicy::Isolated,
            env: vec![],
        }
    }

    async fn await_running(backend: &MockBackend, id: &SandboxId) {
        for _ in 0..200 {
            if let Ok(v) = backend.status(id).await
                && v.status.state == Some(State::Running)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("sandbox did not reach Running");
    }

    // Start/stop are accepted-not-converged and return 202, matching create.
    #[tokio::test]
    async fn start_and_stop_return_202() {
        let state = AppState::new(MockBackend::new());
        let backend = state.backend.clone();
        let id = backend.create_and_start(test_config()).await.unwrap();
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1x/sandboxes/{}/start", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1x/sandboxes/{}/stop", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    // A subscriber that connects after the sandbox has settled still receives
    // a snapshot event carrying the current state (no replay from the backend
    // broadcast, so without the seed it would hang).
    #[tokio::test]
    async fn events_snapshot_on_connect_after_settled() {
        let state = AppState::new(MockBackend::new());
        let backend = state.backend.clone();
        let id = backend.create_and_start(test_config()).await.unwrap();
        await_running(&backend, &id).await;
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1x/sandboxes/{}/events", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut stream = resp.into_body().into_data_stream();
        let chunk = tokio::time::timeout(
            Duration::from_secs(2),
            futures_util::StreamExt::next(&mut stream),
        )
        .await
        .expect("snapshot event not received before timeout")
        .expect("event stream ended without a snapshot")
        .expect("event stream body error");
        let text = String::from_utf8_lossy(&chunk);
        assert!(
            text.contains("state_change") && text.contains("Running"),
            "expected snapshot state_change=Running, got: {text:?}"
        );
    }
}
