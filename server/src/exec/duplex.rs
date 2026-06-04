//! The neutral duplex exec face over a WebSocket: one connection per exec.
//!
//! Framing (binary-safe, no base64):
//! - DATA: binary frames `[1-byte stream tag][raw bytes]` — server→client
//!   `stdout`/`stderr`, client→server `stdin`.
//! - CONTROL: text frames carrying a JSON object — server→client
//!   `exit`/`start_error`, client→server `signal`/`resize`/`stdin_eof`.
//!
//! The session opens with a single text frame carrying the exec request.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Bytes;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};

use playpencil_core::backend::{BackendError, SandboxBackendSend};
use playpencil_core::lifecycle::State as LifeState;
use playpencil_core::types::{
    ExecEvent, ExecIo, ExecMode, ExecRequest, STDIN_FRAME_RAW_MAX, SandboxId,
};

use crate::error::ApiError;
use crate::exec::spawn_escalation;
use crate::state::AppState;

// Stream tags for the binary data frames.
const TAG_STDOUT: u8 = 0;
const TAG_STDERR: u8 = 1;
const TAG_STDIN: u8 = 2;

/// Cap on a single inbound WebSocket message, so a client cannot push
/// tungstenite's ~64 MiB default into one connection. The largest legitimate
/// inbound message is the JSON open frame; bound it to the console frame cap
/// (1 MiB), matching the command-face exec-frame limit. Inbound stdin is bounded
/// more tightly to [`STDIN_FRAME_RAW_MAX`] per frame in `read_loop`.
const MAX_INBOUND_MESSAGE_BYTES: usize = 1024 * 1024;

/// The opening request, sent by the client as the first (text) frame.
#[derive(Deserialize)]
struct DuplexOpen {
    command: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    gid: Option<u32>,
}

/// Client→server text control messages.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientControl {
    Signal { signal: i32 },
    Resize { cols: u16, rows: u16 },
    StdinEof,
}

/// Server→client text control / terminal messages.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerControl {
    Exit { code: i32 },
    StartError { message: String },
}

/// Build a binary data frame: a 1-byte stream tag followed by the raw payload.
fn data_frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 1);
    v.push(tag);
    v.extend_from_slice(payload);
    v
}

fn control_text(c: &ServerControl) -> Message {
    let json = serde_json::to_string(c).expect("ServerControl serializes");
    Message::Text(Utf8Bytes::from(json))
}

pub(crate) async fn duplex<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Validate the sandbox BEFORE upgrading so an unknown id is 404 and a
    // non-running one is 409 — matching the command face — instead of a 101
    // followed by an in-band error. In-band `start_error` is reserved for
    // failures that can only surface post-open (a bad open payload, or the exec
    // failing to start).
    let view = state.backend.status(&SandboxId(id.clone())).await?;
    if view.status.state != Some(LifeState::Running) {
        return Err(ApiError::Backend(BackendError::InvalidState));
    }
    // Bound inbound buffering per connection (vs tungstenite's ~64 MiB default).
    let ws = ws
        .max_message_size(MAX_INBOUND_MESSAGE_BYTES)
        .max_frame_size(MAX_INBOUND_MESSAGE_BYTES);
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, id)))
}

async fn handle_socket<B: SandboxBackendSend + Sync + 'static>(
    socket: WebSocket,
    state: AppState<B>,
    id: String,
) {
    let (mut sender, mut receiver) = socket.split();

    // First frame must be the JSON open request.
    let open = match receiver.next().await {
        Some(Ok(Message::Text(s))) => match serde_json::from_str::<DuplexOpen>(&s) {
            Ok(o) if !o.command.is_empty() => o,
            _ => {
                let _ = sender
                    .send(control_text(&ServerControl::StartError {
                        message: "invalid open request".into(),
                    }))
                    .await;
                let _ = sender.close().await;
                return;
            }
        },
        _ => {
            let _ = sender.close().await;
            return;
        }
    };

    // Credential resolution is driven by uid, so a gid without a uid would be
    // silently ignored. Reject it (in-band, since open params arrive post-open),
    // matching the command face's gid-requires-uid rule.
    if open.gid.is_some() && open.uid.is_none() {
        let _ = sender
            .send(control_text(&ServerControl::StartError {
                message: "gid requires uid".into(),
            }))
            .await;
        let _ = sender.close().await;
        return;
    }

    let req = ExecRequest {
        command: open.command,
        working_dir: open.cwd,
        env: open.env.into_iter().collect(),
        uid: open.uid,
        gid: open.gid,
        mode: ExecMode::Argv,
    };
    let handle = match state.backend.exec(&SandboxId(id), req).await {
        Ok(h) => h,
        Err(e) => {
            let _ = sender
                .send(control_text(&ServerControl::StartError {
                    message: e.to_string(),
                }))
                .await;
            let _ = sender.close().await;
            return;
        }
    };

    let (events, io) = handle.split();
    // One escalation owner across the reader (client-close) and writer
    // (disconnect/shutdown) sides: whoever wins the latch owns the bounded
    // TERM→grace→KILL escalation, so the two disconnect races cannot double-fire.
    let cleanup = Arc::new(AtomicBool::new(false));
    let canceller = io.canceller();
    let reader = tokio::spawn(read_loop(receiver, io.clone(), cleanup.clone()));

    let terminal = write_loop(&mut sender, events, &io, &state.shutdown).await;

    // The client direction is no longer needed once the process terminated or
    // the writer ended; stop the reader.
    reader.abort();
    if !terminal && !cleanup.swap(true, Ordering::AcqRel) {
        // Client disconnect / server shutdown before the process ended: kill it
        // so a TERM-ignoring command does not orphan (TERM → grace → KILL).
        spawn_escalation(canceller);
    }
    let _ = sender.close().await;
}

/// Forward process output (binary) and the terminal (text control) to the client.
/// Returns true if a terminal was observed, false on disconnect / shutdown.
async fn write_loop(
    sender: &mut SplitSink<WebSocket, Message>,
    mut events: tokio::sync::mpsc::Receiver<ExecEvent>,
    io: &ExecIo,
    shutdown: &tokio_util::sync::CancellationToken,
) -> bool {
    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => return false,
            e = events.recv() => match e {
                Some(e) => e,
                None => return false,
            },
        };
        match event {
            ExecEvent::Stdout(b) => {
                let n = b.len();
                if sender
                    .send(Message::Binary(Bytes::from(data_frame(TAG_STDOUT, &b))))
                    .await
                    .is_err()
                {
                    return false;
                }
                io.release_credit(n);
            }
            ExecEvent::Stderr(b) => {
                let n = b.len();
                if sender
                    .send(Message::Binary(Bytes::from(data_frame(TAG_STDERR, &b))))
                    .await
                    .is_err()
                {
                    return false;
                }
                io.release_credit(n);
            }
            ExecEvent::StartError(message) => {
                let _ = sender
                    .send(control_text(&ServerControl::StartError { message }))
                    .await;
                return true;
            }
            ExecEvent::Exit { code } => {
                let _ = sender
                    .send(control_text(&ServerControl::Exit { code }))
                    .await;
                return true;
            }
        }
    }
}

/// Apply client→server frames to the exec I/O until the client closes.
async fn read_loop(mut receiver: SplitStream<WebSocket>, io: ExecIo, cleanup: Arc<AtomicBool>) {
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Binary(b) => {
                if let Some((&tag, rest)) = b.split_first()
                    && tag == TAG_STDIN
                {
                    // Bound inbound stdin per frame to the relay's chunk cap: a
                    // larger frame is a protocol violation — fail loud (tear the
                    // exec down via the cleanup below) rather than buffer/forward
                    // it, keeping stdin ingress within STDIN_FRAME_RAW_MAX.
                    if rest.len() > STDIN_FRAME_RAW_MAX || io.write_stdin(rest).await.is_err() {
                        break;
                    }
                }
            }
            Message::Text(s) => match serde_json::from_str::<ClientControl>(&s) {
                Ok(ClientControl::Signal { signal }) => {
                    let _ = io.signal(signal).await;
                }
                Ok(ClientControl::Resize { cols, rows }) => {
                    let _ = io.resize(cols, rows).await;
                }
                Ok(ClientControl::StdinEof) => {
                    let _ = io.close_stdin().await;
                }
                Err(_) => {}
            },
            Message::Close(_) => break,
            _ => {}
        }
    }
    // Client gone: close stdin and (if we win the latch) own the bounded
    // TERM→grace→KILL escalation so the process does not orphan.
    let _ = io.close_stdin().await;
    if !cleanup.swap(true, Ordering::AcqRel) {
        spawn_escalation(io.canceller());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_prepends_tag() {
        let f = data_frame(TAG_STDOUT, b"hi");
        assert_eq!(f, vec![0, b'h', b'i']);
        let f = data_frame(TAG_STDERR, b"");
        assert_eq!(f, vec![1]);
    }

    #[test]
    fn client_control_parses() {
        let s: ClientControl = serde_json::from_str(r#"{"type":"signal","signal":9}"#).unwrap();
        assert!(matches!(s, ClientControl::Signal { signal: 9 }));
        let r: ClientControl =
            serde_json::from_str(r#"{"type":"resize","cols":80,"rows":24}"#).unwrap();
        assert!(matches!(r, ClientControl::Resize { cols: 80, rows: 24 }));
        let e: ClientControl = serde_json::from_str(r#"{"type":"stdin_eof"}"#).unwrap();
        assert!(matches!(e, ClientControl::StdinEof));
    }

    #[test]
    fn server_control_serializes() {
        let m = control_text(&ServerControl::Exit { code: 7 });
        let Message::Text(t) = m else {
            panic!("expected text control");
        };
        assert!(t.as_str().contains("\"type\":\"exit\""));
        assert!(t.as_str().contains("\"code\":7"));

        let m = control_text(&ServerControl::StartError {
            message: "boom".into(),
        });
        let Message::Text(t) = m else {
            panic!("expected text control");
        };
        assert!(t.as_str().contains("\"type\":\"start_error\""));
        assert!(t.as_str().contains("boom"));
    }

    #[test]
    fn open_request_parses_with_defaults() {
        let o: DuplexOpen = serde_json::from_str(r#"{"command":["bash"]}"#).unwrap();
        assert_eq!(o.command, vec!["bash"]);
        assert!(o.cwd.is_none());
        assert!(o.env.is_empty());
        assert!(o.uid.is_none());
    }

    // Pre-upgrade sandbox validation (404 unknown / 409 not-running) cannot be
    // exercised with a synthetic `oneshot` request: axum's WebSocket upgrade
    // extractor requires a real upgradable connection and otherwise rejects with
    // 426 before the handler runs. It is covered end-to-end against the daemon in
    // tests/test_libkrun_backend.py.
}
