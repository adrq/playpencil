use std::convert::Infallible;
use std::pin::Pin;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, Sse};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use playpencil_core::backend::{BackendError, SandboxBackendSend};
use playpencil_core::types::{
    MountConfig, NetworkPolicy, ResourceLimits, SandboxConfig, SandboxId, SandboxStatus,
};

use crate::api_types::{
    CreateSandboxRequest, ListParams, ListSandboxesResponse, SandboxResponse, StatusWire,
};
use crate::error::{ApiError, ErrorResponse, ValidatedJson};
use crate::state::{AppState, SandboxEvent, StoredConfig};

/// Map internal lifecycle state names to the public wire state names.
/// Returns the raw string unchanged for unknown states to avoid silently
/// hiding newly added lifecycle states.
fn map_state_to_wire(internal: &str) -> String {
    match internal {
        "creating" | "ready" | "starting" => "Pending".into(),
        "running" => "Running".into(),
        "stopping" => "Stopping".into(),
        "stopped" => "Stopped".into(),
        "destroyed" => "Terminated".into(),
        other => {
            tracing::error!("unmapped internal state: {other}, passing through as-is");
            other.into()
        }
    }
}

/// Build the wire response. `config` is absent for destroyed sandboxes whose
/// stored config was removed on destroy; those config-derived fields are then
/// omitted from the response.
fn build_sandbox_response(
    status: &SandboxStatus,
    config: Option<&StoredConfig>,
) -> SandboxResponse {
    SandboxResponse {
        id: status.sandbox_id.0.clone(),
        status: StatusWire {
            state: map_state_to_wire(&status.state),
            reason: None,
            message: None,
        },
        created_at: status.created_at.clone(),
        image: config.map(|c| c.image.clone()),
        name: config.and_then(|c| c.name.clone()),
        network: config.map(|c| c.network.clone()),
    }
}

pub(crate) async fn create_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    ValidatedJson(body): ValidatedJson<CreateSandboxRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.image.uri.is_empty() {
        return Err(ApiError::Validation("image.uri must not be empty".into()));
    }
    // Reject control chars (null, newline, etc.) before they reach the OCI pull
    // / C boundary, where they risk silent CString truncation or framing breaks.
    // Legit image refs are printable; malformed-but-printable refs fail at pull.
    if body.image.uri.chars().any(|c| c.is_ascii_control()) {
        return Err(ApiError::Validation(
            "image.uri must not contain control characters".into(),
        ));
    }

    let network: NetworkPolicy = body
        .network
        .clone()
        .try_into()
        .map_err(ApiError::Validation)?;

    let config = SandboxConfig {
        name: body.name.clone(),
        image: body.image.uri.clone(),
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
    };

    let stored = StoredConfig {
        image: body.image.uri,
        name: body.name,
        network: body.network,
    };

    let id = state.backend.create(config).await?;

    // Store config before start. Event channels are created lazily on first
    // SSE subscribe, so there is nothing to insert or clean up here.
    let stored_clone = stored.clone();
    {
        let mut configs = state.configs.lock().unwrap_or_else(|e| e.into_inner());
        configs.insert(id.clone(), stored);
    }

    if let Err(e) = state.backend.start(&id).await {
        tracing::error!(sandbox_id = %id.0, "start after create failed: {e}");
        // Sandbox exists and is discoverable via GET.
        return Err(ApiError::StartFailed {
            sandbox_id: id.0,
            source: e,
        });
    }

    let status = match state.backend.status(&id).await {
        Ok(s) => s,
        Err(e) => {
            return Err(ApiError::StatusQueryFailed {
                sandbox_id: id.0.clone(),
                source: e,
            });
        }
    };
    // We deliberately do not publish the post-auto-start state here. The backend
    // inserts the record early, so a racing client can discover this id via
    // GET /v1/sandboxes and subscribe to /events before this 201 returns; such
    // an early subscriber may therefore miss the Running transition.
    let resp = build_sandbox_response(&status, Some(&stored_clone));
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

pub(crate) async fn list_sandboxes<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Query(params): Query<ListParams>,
) -> Result<Json<ListSandboxesResponse>, ApiError> {
    let statuses = state.backend.list().await?;
    let configs = state.configs.lock().unwrap_or_else(|e| e.into_inner());
    // Drop empty tokens so `?state=` or `?state=,` collapse to "no filter"
    // (return all), matching the absent-state case, and stray empty tokens in a
    // list (e.g. `running,,stopped`) are ignored.
    let state_filter: Vec<String> = params
        .state
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let items: Vec<SandboxResponse> = statuses
        .iter()
        .filter(|s| {
            if state_filter.is_empty() {
                return true;
            }
            let wire = map_state_to_wire(&s.state);
            state_filter.iter().any(|f| f.eq_ignore_ascii_case(&wire))
        })
        .map(|s| build_sandbox_response(s, configs.get(&s.sandbox_id)))
        .collect();

    Ok(Json(ListSandboxesResponse { items }))
}

pub(crate) async fn get_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sid = SandboxId(id);
    let status = state.backend.status(&sid).await?;
    let configs = state.configs.lock().unwrap_or_else(|e| e.into_inner());
    // Config may be absent for a destroyed sandbox; response omits config fields.
    Ok(Json(build_sandbox_response(&status, configs.get(&sid))))
}

pub(crate) async fn start_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sid = SandboxId(id);
    state.backend.start(&sid).await?;
    let status = state.backend.status(&sid).await?;
    // A racing destroy can make this post-op status read as terminal; the
    // terminal event is owned by destroy_sandbox, so skip publishing it here to
    // avoid a duplicate/misattributed Terminated. Event channels are created
    // lazily on subscribe, so publish is a no-op when no client is listening.
    let wire = map_state_to_wire(&status.state);
    if wire != "Terminated" {
        state.publish_event(&sid, SandboxEvent::StateChange { state: wire });
    }
    let configs = state.configs.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(build_sandbox_response(&status, configs.get(&sid))))
}

pub(crate) async fn stop_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sid = SandboxId(id);
    state.backend.stop(&sid).await?;
    let status = state.backend.status(&sid).await?;
    // A racing destroy can make this post-op status read as terminal; the
    // terminal event is owned by destroy_sandbox, so skip publishing it here to
    // avoid a duplicate/misattributed Terminated.
    let wire = map_state_to_wire(&status.state);
    if wire != "Terminated" {
        state.publish_event(&sid, SandboxEvent::StateChange { state: wire });
    }
    let configs = state.configs.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(build_sandbox_response(&status, configs.get(&sid))))
}

pub(crate) async fn destroy_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let sid = SandboxId(id);
    state.backend.destroy(&sid).await?;
    // Atomically remove the Sender and send Terminated through it, all under the
    // events lock. Removing first means any concurrent stop/start publish that
    // acquires the lock after us finds no Sender and is a no-op, so a subscriber
    // can never see a non-terminal state AFTER Terminated. The send is
    // non-blocking, so holding the lock across it is fine. Removing also bounds
    // map growth and closes the channel so subscribers' streams end after the
    // terminal event drains.
    {
        let mut map = state.events.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = map.remove(&sid) {
            let _ = tx.send(SandboxEvent::StateChange {
                state: "Terminated".into(),
            });
        }
    }
    // Remove the stored config to bound map growth. A subsequent GET returns
    // backend status without config fields.
    state
        .configs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&sid);
    Ok(StatusCode::NO_CONTENT)
}

type EventStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>>;

pub(crate) async fn sandbox_events<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let sid = SandboxId(id.clone());
    // Verify the sandbox exists before creating a channel (404 if not).
    state.backend.status(&sid).await?;
    // Lazily create the broadcast channel on first subscribe.
    let rx = {
        let mut map = state.events.lock().unwrap_or_else(|e| e.into_inner());
        let tx = map
            .entry(sid.clone())
            .or_insert_with(|| tokio::sync::broadcast::channel(64).0);
        tx.subscribe()
    };

    // TOCTOU guard: between the existence check above and our subscribe, a
    // concurrent destroy may publish the terminal event and remove the channel.
    // A broadcast Receiver only observes messages sent AFTER it subscribed, so
    // depending on the interleaving `rx` either missed the real Terminated
    // (published before we subscribed, possibly on a since-removed channel) or
    // holds it (published after we subscribed). Re-check status; if the sandbox
    // is gone, drop `rx` (so the case where it holds the event does not
    // duplicate) and emit a single synthetic Terminated, guaranteeing the
    // client sees exactly one terminal event before the stream ends.
    let gone = match state.backend.status(&sid).await {
        Ok(s) => map_state_to_wire(&s.state) == "Terminated",
        Err(BackendError::NotFound) => true,
        Err(_) => false,
    };
    if gone {
        // Drop our own receiver first so it is not counted below.
        drop(rx);
        // Only evict the channel if no other receiver is still attached. A live
        // subscriber from the non-gone path may be waiting for destroy's later
        // Terminated publish; removing the channel here would drop its Sender
        // and close that stream before it sees the terminal event. When other
        // receivers remain, leave the channel for destroy (publish-then-remove)
        // or the last subscriber to clean up.
        {
            let mut map = state.events.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&sid)
                && tx.receiver_count() == 0
            {
                map.remove(&sid);
            }
        }
        let data = serde_json::json!({
            "sandbox_id": id,
            "state": "Terminated",
        });
        let ev = Event::default()
            .event("state_change")
            .json_data(data)
            .unwrap_or_else(|_| Event::default());
        // take_until lets the stream end on server shutdown so graceful drain
        // completes (a single-item stream ends quickly, but keep it uniform).
        // Fully-qualified to avoid clashing with tokio_stream::StreamExt above.
        let stream: EventStream = Box::pin(futures_util::StreamExt::take_until(
            tokio_stream::iter(vec![Ok(ev)]),
            state.shutdown.clone().cancelled_owned(),
        ));
        return Ok(Sse::new(stream)
            .keep_alive(axum::response::sse::KeepAlive::default())
            .into_response());
    }

    let broadcast_stream = BroadcastStream::new(rx).filter_map(move |result| {
        let sandbox_id = id.clone();
        match result {
            Ok(event) => {
                let (event_type, data) = match event {
                    SandboxEvent::StateChange { state } => (
                        "state_change",
                        serde_json::json!({
                            "sandbox_id": sandbox_id,
                            "state": state,
                        }),
                    ),
                };
                let sse_event = Event::default()
                    .event(event_type)
                    .json_data(data)
                    .unwrap_or_else(|_| Event::default());
                Some(Ok(sse_event))
            }
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                tracing::warn!(sandbox_id = %sandbox_id, "SSE subscriber lagged by {n}");
                None
            }
        }
    });

    // take_until ends the stream on server shutdown so an open SSE connection
    // does not block axum's graceful drain (and thus backend teardown).
    // Fully-qualified to avoid clashing with tokio_stream::StreamExt above.
    let stream: EventStream = Box::pin(futures_util::StreamExt::take_until(
        broadcast_stream,
        state.shutdown.clone().cancelled_owned(),
    ));
    Ok(Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response())
}

pub(crate) async fn pause_sandbox<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let sid = SandboxId(id);
    state.backend.status(&sid).await?;
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
    let sid = SandboxId(id);
    state.backend.status(&sid).await?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "not_implemented".into(),
            detail: Some("resume is not supported".into()),
            sandbox_id: None,
        }),
    ))
}
