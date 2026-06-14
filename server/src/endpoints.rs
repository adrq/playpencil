//! Service-endpoint discovery: maps an in-sandbox port to the externally
//! reachable base URL plus an access-token header, in the execd-compatible shape.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use playpencil_core::backend::{BackendError, SandboxBackendSend};
use playpencil_core::types::SandboxId;

use crate::error::ApiError;
use crate::state::AppState;

/// The well-known in-sandbox port the command face is discovered under.
const EXECD_DISCOVERY_PORT: u16 = 44772;

#[derive(Serialize)]
struct EndpointResponse {
    endpoint: String,
    headers: HashMap<String, String>,
}

pub(crate) async fn discover_endpoint<B: SandboxBackendSend + Sync + 'static>(
    State(state): State<AppState<B>>,
    Path((id, port)): Path<(String, u16)>,
) -> Result<Response, ApiError> {
    // 404 if the sandbox never existed.
    state.backend.status(&SandboxId(id.clone())).await?;

    // N1 serves only the command base; any other port is unknown.
    if port != EXECD_DISCOVERY_PORT {
        return Err(ApiError::Backend(BackendError::NotFound));
    }

    let mut headers = HashMap::new();
    headers.insert("X-EXECD-ACCESS-TOKEN".to_string(), random_token());
    // The discovery contract returns a scheme-less authority+path; the client
    // supplies the scheme. This is intentional — do not prepend `http://`.
    let resp = EndpointResponse {
        endpoint: format!("{}/v1x/sandboxes/{}/execd", state.public_addr, id),
        headers,
    };
    Ok(Json(resp).into_response())
}

/// A fresh non-empty random token per response (auth is unenforced in N1; the
/// client echoes whatever it is handed). No registry/persistence.
fn random_token() -> String {
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if f.read_exact(&mut buf).is_err() {
            seed_from_time(&mut buf);
        }
    } else {
        seed_from_time(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn seed_from_time(buf: &mut [u8; 16]) {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    buf.copy_from_slice(&n.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use playpencil_core::backend::SandboxBackendSend;
    use playpencil_core::backend::mock::MockBackend;
    use playpencil_core::lifecycle::State as LifeState;
    use playpencil_core::types::{NetworkPolicy, ResourceLimits, SandboxConfig};

    use crate::router::build_router;
    use crate::state::AppState;

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

    async fn running() -> (axum::Router, String) {
        let state = AppState::new(MockBackend::new());
        let backend = state.backend.clone();
        let id = backend.create_and_start(cfg()).await.unwrap();
        for _ in 0..200 {
            if let Ok(v) = backend.status(&id).await
                && v.status.state == Some(LifeState::Running)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (build_router(state), id.0)
    }

    #[tokio::test]
    async fn unknown_sandbox_is_404() {
        let state = AppState::new(MockBackend::new());
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sandboxes/nope/endpoints/44772")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn command_port_returns_endpoint_and_token() {
        let (app, id) = running().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/sandboxes/{id}/endpoints/44772"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let endpoint = v["endpoint"].as_str().unwrap();
        assert!(
            endpoint.ends_with(&format!("/v1x/sandboxes/{id}/execd")),
            "{endpoint}"
        );
        let token = v["headers"]["X-EXECD-ACCESS-TOKEN"].as_str().unwrap();
        assert!(!token.is_empty());
    }

    #[tokio::test]
    async fn other_port_is_404() {
        let (app, id) = running().await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/sandboxes/{id}/endpoints/8080"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
