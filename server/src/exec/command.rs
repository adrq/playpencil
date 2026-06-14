//! The execd-compatible foreground command face: `POST …/execd/command` streams
//! results as Server-Sent-Events, `DELETE …/execd/command?id=` interrupts.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use playpencil_core::backend::SandboxBackendSend;
use playpencil_core::types::{ExecCanceller, ExecEvent, ExecMode, ExecRequest, SandboxId};

use playpencil_exec::consumer::{Utf8StreamDecoder, spawn_escalation};

use crate::api_types::{CommandDeleteParams, CommandRequest};
use crate::error::ApiError;
use crate::state::{AppState, LiveControl};

/// Bound on the SSE body channel: ties the credit-release boundary to consumer
/// progress (an item is credited only once the channel accepts it).
const SSE_CHANNEL: usize = 16;

#[derive(Serialize)]
struct StreamEvent {
    #[serde(rename = "type")]
    kind: StreamEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<StreamError>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum StreamEventKind {
    Init,
    Stdout,
    Stderr,
    ExecutionComplete,
    Error,
}

#[derive(Serialize)]
struct StreamError {
    ename: String,
    evalue: String,
}

impl StreamEvent {
    fn simple(kind: StreamEventKind, text: Option<String>) -> Self {
        Self {
            kind,
            text,
            execution_time: None,
            error: None,
        }
    }

    /// Frame as raw SSE bytes: a JSON object followed by a blank line. This is
    /// the command-face wire form (NOT axum's `event:`/`data:` encoding).
    fn frame(&self) -> Bytes {
        let json = serde_json::to_string(self).expect("StreamEvent serializes");
        Bytes::from(format!("{json}\n\n"))
    }
}

type SseTx = mpsc::Sender<Result<Bytes, Infallible>>;

/// Send one SSE frame, observing server shutdown. Returns true if the frame was
/// accepted by the body channel; false if shutdown fired or the channel closed
/// (the client disconnected). This keeps a backpressured stream cancellation-
/// aware: parking inside `send()` would otherwise hide a shutdown and strand the
/// stream task + its live-command registry entry.
async fn send_sse(tx: &SseTx, shutdown: &CancellationToken, bytes: Bytes) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => false,
        r = tx.send(Ok(bytes)) => r.is_ok(),
    }
}

pub(crate) async fn run_command<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
    crate::error::ValidatedJson(req): crate::error::ValidatedJson<CommandRequest>,
) -> Result<Response, ApiError> {
    let sid = SandboxId(id.clone());
    // Resolve the sandbox FIRST so an unknown id is 404 before any semantic 422
    // or the 501 below.
    state.backend.status(&sid).await?;

    // Semantic validation (after the sandbox resolves).
    if req.command.is_empty() {
        return Err(ApiError::Validation("command must not be empty".into()));
    }
    if req.gid.is_some() && req.uid.is_none() {
        return Err(ApiError::Validation("gid requires uid".into()));
    }
    if req.background {
        return Err(ApiError::NotImplemented(
            "background execution is not supported".into(),
        ));
    }

    // Spawn the command (shell mode). Not-running maps to 409 via BackendError.
    let exec_req = ExecRequest {
        command: vec![req.command],
        working_dir: req.cwd,
        env: req.envs.into_iter().collect(),
        uid: req.uid,
        gid: req.gid,
        mode: ExecMode::Shell,
    };
    let handle = state.backend.exec(&sid, exec_req).await?;
    // The command face sends no stdin: signal EOF so a stdin-reading command
    // does not block.
    let _ = handle.close_stdin().await;

    let command_id = handle.exec_id.0.clone();
    let canceller = handle.canceller();
    let cleanup_started = Arc::new(AtomicBool::new(false));
    state.live.insert(
        id.clone(),
        command_id.clone(),
        LiveControl {
            canceller: canceller.clone(),
            cleanup_started: cleanup_started.clone(),
        },
    );

    let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(SSE_CHANNEL);
    let shutdown = state.shutdown.clone();
    let live = state.live.clone();
    tokio::spawn(stream_command(
        handle,
        tx,
        shutdown,
        live,
        id,
        command_id.clone(),
        canceller,
        cleanup_started,
        req.timeout,
    ));

    let body = Body::from_stream(ReceiverStream::new(rx));
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(body)
        .expect("valid SSE response"))
}

#[allow(clippy::too_many_arguments)]
async fn stream_command(
    mut handle: playpencil_core::types::ExecHandle,
    tx: SseTx,
    shutdown: tokio_util::sync::CancellationToken,
    live: Arc<crate::state::LiveControlRegistry>,
    sandbox_id: String,
    command_id: String,
    canceller: ExecCanceller,
    cleanup_started: Arc<AtomicBool>,
    timeout: Option<u64>,
) {
    let start = Instant::now();
    let mut dec_out = Utf8StreamDecoder::new();
    let mut dec_err = Utf8StreamDecoder::new();

    // Optional host-side timeout: TERM then (after a grace) KILL. Cancelled when
    // the command completes naturally.
    let timer_cancel = tokio_util::sync::CancellationToken::new();
    if let Some(ms) = timeout {
        let c = canceller.clone();
        let cl = cleanup_started.clone();
        let tc = timer_cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tc.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_millis(ms)) => {
                    if !cl.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        spawn_escalation(c);
                    }
                }
            }
        });
    }

    // The init event carries the minted command id.
    let mut completed = false;
    let init = StreamEvent::simple(StreamEventKind::Init, Some(command_id.clone())).frame();
    if send_sse(&tx, &shutdown, init).await {
        completed = stream_loop(
            &mut handle,
            &tx,
            &shutdown,
            &mut dec_out,
            &mut dec_err,
            start,
        )
        .await;
    }

    timer_cancel.cancel();
    live.remove(&sandbox_id, &command_id);
    if !completed && !cleanup_started.swap(true, std::sync::atomic::Ordering::AcqRel) {
        // Client disconnected (or server shutdown) before the terminal: kill the
        // command so it does not orphan.
        spawn_escalation(canceller);
    }
}

/// Returns true if a terminal was observed and emitted (natural completion);
/// false on client disconnect / server shutdown.
async fn stream_loop(
    handle: &mut playpencil_core::types::ExecHandle,
    tx: &SseTx,
    shutdown: &tokio_util::sync::CancellationToken,
    dec_out: &mut Utf8StreamDecoder,
    dec_err: &mut Utf8StreamDecoder,
    start: Instant,
) -> bool {
    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => return false,
            e = handle.events.recv() => match e {
                Some(e) => e,
                None => return false, // channel closed without a terminal
            },
        };
        match event {
            ExecEvent::Stdout(b) => {
                let (text, raw) = dec_out.push(&b);
                if !text.is_empty() {
                    let frame = StreamEvent::simple(StreamEventKind::Stdout, Some(text)).frame();
                    if !send_sse(tx, shutdown, frame).await {
                        return false;
                    }
                }
                handle.release_credit(raw);
            }
            ExecEvent::Stderr(b) => {
                let (text, raw) = dec_err.push(&b);
                if !text.is_empty() {
                    let frame = StreamEvent::simple(StreamEventKind::Stderr, Some(text)).frame();
                    if !send_sse(tx, shutdown, frame).await {
                        return false;
                    }
                }
                handle.release_credit(raw);
            }
            ExecEvent::StartError(msg) => {
                flush_decoders(handle, tx, shutdown, dec_out, dec_err).await;
                let _ = send_sse(tx, shutdown, error_event(msg).frame()).await;
                return true;
            }
            ExecEvent::Exit { code } => {
                flush_decoders(handle, tx, shutdown, dec_out, dec_err).await;
                let terminal = exit_terminal(code, start.elapsed().as_millis() as u64);
                let _ = send_sse(tx, shutdown, terminal.frame()).await;
                return true;
            }
        }
    }
}

/// Flush both decoders before the terminal, emitting and crediting any residual.
async fn flush_decoders(
    handle: &mut playpencil_core::types::ExecHandle,
    tx: &SseTx,
    shutdown: &CancellationToken,
    dec_out: &mut Utf8StreamDecoder,
    dec_err: &mut Utf8StreamDecoder,
) {
    let (text, raw) = dec_out.flush();
    if !text.is_empty() {
        let frame = StreamEvent::simple(StreamEventKind::Stdout, Some(text)).frame();
        let _ = send_sse(tx, shutdown, frame).await;
    }
    handle.release_credit(raw);
    let (text, raw) = dec_err.flush();
    if !text.is_empty() {
        let frame = StreamEvent::simple(StreamEventKind::Stderr, Some(text)).frame();
        let _ = send_sse(tx, shutdown, frame).await;
    }
    handle.release_credit(raw);
}

fn error_event(evalue: String) -> StreamEvent {
    StreamEvent {
        kind: StreamEventKind::Error,
        text: None,
        execution_time: None,
        error: Some(StreamError {
            ename: "CommandExecError".into(),
            evalue,
        }),
    }
}

/// Project a numeric process exit to its terminal SSE event: `0` is a success
/// (`execution_complete` + elapsed ms); any nonzero code is an `error`.
fn exit_terminal(code: i32, elapsed_ms: u64) -> StreamEvent {
    if code == 0 {
        StreamEvent {
            kind: StreamEventKind::ExecutionComplete,
            text: None,
            execution_time: Some(elapsed_ms),
            error: None,
        }
    } else {
        error_event(code.to_string())
    }
}

pub(crate) async fn delete_command<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
    crate::error::ValidatedQuery(params): crate::error::ValidatedQuery<CommandDeleteParams>,
) -> Result<Response, ApiError> {
    // Resolve the sandbox first (unknown → 404 before the command lookup).
    state.backend.status(&SandboxId(id.clone())).await?;
    match state.live.take_for_cleanup(&id, &params.id) {
        Some((canceller, won)) => {
            // A currently-running command: 200 whether or not we won the
            // escalation race; only the winner owns the kill.
            if won {
                spawn_escalation(canceller);
            }
            Ok(StatusCode::OK.into_response())
        }
        // Unknown / completed / already-cleaned command id → 404. Best-effort:
        // a DELETE racing natural completion may legitimately 404.
        None => Err(ApiError::Backend(
            playpencil_core::backend::BackendError::NotFound,
        )),
    }
}

/// Reserved 501 stub (sandbox resolved first → 404 before 501). The second path
/// segment (a command id) is accepted but unused.
pub(crate) async fn command_reserved_stub<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path((id, _cmd)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    state.backend.status(&SandboxId(id)).await?;
    Err(ApiError::NotImplemented(
        "this command surface is not supported".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Pure projection / framing (white-box) ----------------------------

    #[test]
    fn exit_terminal_projection() {
        // Success → execution_complete with elapsed ms, no error.
        let ev = exit_terminal(0, 42);
        assert!(matches!(ev.kind, StreamEventKind::ExecutionComplete));
        assert_eq!(ev.execution_time, Some(42));
        assert!(ev.error.is_none());

        // Nonzero → error carrying the numeric code as evalue.
        let ev = exit_terminal(7, 0);
        assert!(matches!(ev.kind, StreamEventKind::Error));
        let e = ev.error.unwrap();
        assert_eq!(e.evalue, "7");
        assert_eq!(e.ename, "CommandExecError");
    }

    #[test]
    fn start_error_projection() {
        let ev = error_event("no shell available".into());
        let e = ev.error.unwrap();
        assert_eq!(e.evalue, "no shell available");
        assert_eq!(e.ename, "CommandExecError");
    }

    #[test]
    fn sse_framing_is_raw_json_plus_blank_line() {
        let bytes = StreamEvent::simple(StreamEventKind::Init, Some("cmd-1".into())).frame();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        // Raw JSON object then a blank line — NOT axum's event:/data: framing.
        assert!(s.ends_with("\n\n"));
        assert!(!s.contains("event:"));
        assert!(!s.contains("data:"));
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["type"], "init");
        assert_eq!(v["text"], "cmd-1");
        // Absent optionals are omitted.
        assert!(v.get("error").is_none());
        assert!(v.get("execution_time").is_none());
    }

    // ---- Router-level error routing (MockBackend) -------------------------

    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use playpencil_core::backend::SandboxBackendSend;
    use playpencil_core::backend::mock::MockBackend;
    use playpencil_core::lifecycle::State as LifeState;
    use playpencil_core::types::{NetworkPolicy, ResourceLimits, SandboxConfig};

    use crate::router::build_router;

    fn cfg() -> SandboxConfig {
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
            entrypoint: None,
        }
    }

    async fn await_state(backend: &MockBackend, id: &SandboxId, want: Option<LifeState>) {
        for _ in 0..200 {
            if let Ok(v) = backend.status(id).await
                && v.status.state == want
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("sandbox did not reach {want:?}");
    }

    fn post_command(id: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/v1x/sandboxes/{id}/execd/command"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn running_router() -> (axum::Router, SandboxId, std::sync::Arc<MockBackend>) {
        let state = AppState::new(MockBackend::new());
        let backend = state.backend.clone();
        let id = backend.create_and_start(cfg()).await.unwrap();
        await_state(&backend, &id, Some(LifeState::Running)).await;
        (build_router(state), id, backend)
    }

    #[tokio::test]
    async fn unknown_sandbox_is_404_before_validation() {
        let state = AppState::new(MockBackend::new());
        let app = build_router(state);
        // Even with an empty (invalid) command, the unknown sandbox wins → 404.
        let resp = app
            .oneshot(post_command("nope", r#"{"command":""}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_json_is_422() {
        let (app, id, _b) = running_router().await;
        let resp = app.oneshot(post_command(&id.0, "{not json")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn empty_command_is_422() {
        let (app, id, _b) = running_router().await;
        let resp = app
            .oneshot(post_command(&id.0, r#"{"command":""}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn gid_without_uid_is_422() {
        let (app, id, _b) = running_router().await;
        let resp = app
            .oneshot(post_command(&id.0, r#"{"command":"echo hi","gid":5}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn background_true_is_501_not_422() {
        let (app, id, _b) = running_router().await;
        let resp = app
            .oneshot(post_command(
                &id.0,
                r#"{"command":"echo hi","background":true}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn not_running_sandbox_is_409() {
        let state = AppState::new(MockBackend::new());
        let backend = state.backend.clone();
        let id = backend.create(cfg()).await.unwrap();
        await_state(&backend, &id, Some(LifeState::Stopped)).await;
        let app = build_router(state);
        let resp = app
            .oneshot(post_command(&id.0, r#"{"command":"echo hi"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn valid_command_streams_init_event() {
        let (app, id, _b) = running_router().await;
        let resp = app
            .oneshot(post_command(&id.0, r#"{"command":"echo hi"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        let mut stream = resp.into_body().into_data_stream();
        let chunk = tokio::time::timeout(
            Duration::from_secs(2),
            futures_util::StreamExt::next(&mut stream),
        )
        .await
        .expect("init chunk before timeout")
        .expect("a chunk")
        .expect("body ok");
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("\"type\":\"init\""), "got: {text:?}");
    }

    #[tokio::test]
    async fn reserved_stub_unknown_is_404_known_is_501() {
        let (app, id, _b) = running_router().await;
        let unknown = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1x/sandboxes/nope/execd/command/status/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let known = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1x/sandboxes/{}/execd/command/x/logs", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(known.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn delete_unknown_command_is_404() {
        let (app, id, _b) = running_router().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1x/sandboxes/{}/execd/command?id=missing", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_missing_id_is_422_with_api_error_shape() {
        let (app, id, _b) = running_router().await;
        // No `id` query param: the validated extractor returns the API's standard
        // validation error (422 + ErrorResponse JSON), not Axum's plain rejection.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1x/sandboxes/{}/execd/command", id.0))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "validation_error");
    }
}
