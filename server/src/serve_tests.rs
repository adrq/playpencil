//! Health route and drain behaviour of the assembled server.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use futures_util::StreamExt;
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tower::ServiceExt;

use playpencil_core::backend::SandboxBackendSend;
use playpencil_core::backend::health::Unhealthy;
use playpencil_core::backend::mock::MockBackend;
use playpencil_core::types::{NetworkPolicy, ResourceLimits, SandboxConfig, SandboxId};

use crate::drain::Admission;
use crate::health::HealthState;
use crate::router::{build_app, build_router, with_admission};
use crate::state::AppState;
use crate::test_support::{
    BlockingStore, TestBackend, dechunk, parse_response, read_to_end, read_until, request,
    send_request, wait_until,
};

fn config() -> SandboxConfig {
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

struct Server {
    addr: SocketAddr,
    admission: Arc<Admission>,
    backend: Arc<TestBackend>,
    signal: Option<oneshot::Sender<()>>,
    handle: JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start(backend: TestBackend) -> Self {
        Self::start_with(backend, build_app).await
    }

    async fn start_with(
        backend: TestBackend,
        app: impl FnOnce(AppState<TestBackend>) -> Router,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = AppState::new(backend).with_public_addr(addr);
        let admission = state.admission.clone();
        let shutdown = state.shutdown.clone();
        let backend = state.backend.clone();
        let app = app(state);
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(crate::serve_app(
            listener,
            app,
            admission.clone(),
            shutdown,
            async move {
                let _ = rx.await;
            },
        ));
        Self {
            addr,
            admission,
            backend,
            signal: Some(tx),
            handle,
        }
    }

    async fn signal(&mut self) {
        self.signal.take().unwrap().send(()).unwrap();
        let admission = self.admission.clone();
        wait_until("drain began", move || admission.is_draining()).await;
    }

    async fn stopped(self, within: Duration) {
        tokio::time::timeout(within, self.handle)
            .await
            .expect("server did not stop")
            .unwrap()
            .unwrap();
    }
}

async fn oneshot(app: Router, method: &str, uri: &str) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Bytes {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
}

fn assert_refused(resp: &axum::response::Response) {
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()[header::RETRY_AFTER], "1");
    assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
}

// --- Health ----------------------------------------------------------------

#[tokio::test]
async fn health_200_empty_body() {
    let app = build_app(AppState::new(TestBackend::default()));
    let resp = oneshot(app, "GET", "/v1/health").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
    assert!(body_bytes(resp).await.is_empty());
}

#[tokio::test]
async fn health_503_empty_body() {
    let backend = TestBackend::default();
    *backend.health_result.lock().unwrap() = Some(Unhealthy::StoreTimeout);
    let app = build_app(AppState::new(backend));
    let resp = oneshot(app, "GET", "/v1/health").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
    assert!(resp.headers().get(header::RETRY_AFTER).is_none());
    assert!(body_bytes(resp).await.is_empty());
}

// --- Admission gate ----------------------------------------------------------

#[tokio::test]
async fn drain_refuses_non_health_with_bare_503_retry_after() {
    let state = AppState::new(TestBackend::default());
    let admission = state.admission.clone();
    let app = build_app(state);
    assert_eq!(
        oneshot(app.clone(), "GET", "/v1/sandboxes").await.status(),
        StatusCode::OK
    );

    admission.begin_drain();
    let resp = oneshot(app, "GET", "/v1/sandboxes").await;
    assert_refused(&resp);
    assert!(body_bytes(resp).await.is_empty());
    assert_eq!(admission.admitted(), 0);
}

#[tokio::test]
async fn drain_with_nothing_admitted_completes() {
    let mut server = Server::start(TestBackend::default()).await;
    assert_eq!(request(server.addr, "GET", "/v1/health").await.status, 200);
    server.signal().await;
    let addr = server.addr;
    server.stopped(Duration::from_secs(2)).await;
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn drain_refuses_unknown_path_and_method_with_bare_503() {
    let state = AppState::new(TestBackend::default());
    let admission = state.admission.clone();
    let app = build_app(state);
    let cases = [
        ("GET", "/no/such/path", StatusCode::NOT_FOUND),
        ("DELETE", "/v1/sandboxes", StatusCode::METHOD_NOT_ALLOWED),
        ("POST", "/v1/health", StatusCode::METHOD_NOT_ALLOWED),
    ];
    for (method, uri, before) in cases {
        let resp = oneshot(app.clone(), method, uri).await;
        assert_eq!(resp.status(), before, "{method} {uri}");
    }

    admission.begin_drain();
    for (method, uri, _) in cases {
        let resp = oneshot(app.clone(), method, uri).await;
        assert_refused(&resp);
        assert!(body_bytes(resp).await.is_empty(), "{method} {uri}");
    }
}

#[tokio::test]
async fn drain_refuses_new_streams_with_bare_503() {
    let state = AppState::new(TestBackend::default());
    let admission = state.admission.clone();
    let id = state.backend.create(config()).await.unwrap();
    let app = build_app(state);
    admission.begin_drain();

    let events = oneshot(
        app.clone(),
        "GET",
        &format!("/v1x/sandboxes/{}/events", id.0),
    )
    .await;
    assert_refused(&events);

    let command = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1x/sandboxes/{}/execd/command", id.0))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"command":"true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_refused(&command);

    let upgrade = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1x/sandboxes/{}/exec", id.0))
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .header(header::SEC_WEBSOCKET_VERSION, "13")
                .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_refused(&upgrade);
    assert_eq!(admission.admitted(), 0);
}

// --- Drain over TCP ----------------------------------------------------------

#[tokio::test]
async fn drain_admitted_request_completes() {
    let gate = Arc::new(Semaphore::new(0));
    let mut server = Server::start(TestBackend {
        list_gate: Some(gate.clone()),
        ..TestBackend::default()
    })
    .await;

    let mut held = send_request(server.addr, "GET", "/v1/sandboxes").await;
    let backend = server.backend.clone();
    wait_until("list admitted", move || {
        backend.list_calls.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(server.admission.admitted(), 1);

    server.signal().await;
    assert_eq!(request(server.addr, "GET", "/v1/health").await.status, 503);
    let refused = request(server.addr, "GET", "/v1/sandboxes").await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.header("retry-after").as_deref(), Some("1"));
    assert!(!server.handle.is_finished());

    gate.add_permits(1);
    let resp = parse_response(&read_to_end(&mut held).await);
    assert_eq!(resp.status, 200);
    let addr = server.addr;
    server.stopped(Duration::from_secs(5)).await;
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn drain_waits_for_gated_response_body() {
    let gate = Arc::new(Semaphore::new(0));
    let body_gate = gate.clone();
    let mut server = Server::start_with(TestBackend::default(), move |state| {
        let admission = state.admission.clone();
        let health = HealthState::new(state.backend.clone(), admission.clone());
        let stream_route = Router::new().route(
            "/test/stream",
            get(move || {
                let gate = body_gate.clone();
                async move {
                    let first = futures_util::stream::once(async {
                        Ok::<_, Infallible>(Bytes::from_static(b"first\n"))
                    });
                    let second = futures_util::stream::once(async move {
                        gate.acquire().await.unwrap().forget();
                        Ok::<_, Infallible>(Bytes::from_static(b"second\n"))
                    });
                    Body::from_stream(first.chain(second))
                }
            }),
        );
        with_admission(
            build_router(state)
                .merge(crate::v1::routes::router(health))
                .merge(stream_route),
            admission,
        )
    })
    .await;

    let mut client = send_request(server.addr, "GET", "/test/stream").await;
    let mut raw = read_until(&mut client, b"first\n").await;

    server.signal().await;
    assert_eq!(request(server.addr, "GET", "/v1/health").await.status, 503);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!server.handle.is_finished());

    gate.add_permits(1);
    raw.extend(read_to_end(&mut client).await);
    let resp = parse_response(&raw);
    assert_eq!(resp.status, 200);
    assert_eq!(dechunk(&resp.body), b"first\nsecond\n");
    server.stopped(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn drain_existing_events_open_until_admitted_done() {
    let gate = Arc::new(Semaphore::new(0));
    let mut server = Server::start(TestBackend {
        list_gate: Some(gate.clone()),
        ..TestBackend::default()
    })
    .await;
    let id: SandboxId = server.backend.create(config()).await.unwrap();

    let mut events = send_request(
        server.addr,
        "GET",
        &format!("/v1x/sandboxes/{}/events", id.0),
    )
    .await;
    read_until(&mut events, b"state_change").await;

    let _held = send_request(server.addr, "GET", "/v1/sandboxes").await;
    let backend = server.backend.clone();
    wait_until("list admitted", move || {
        backend.list_calls.load(Ordering::SeqCst) == 1
    })
    .await;

    server.signal().await;
    let mut buf = [0u8; 1024];
    let still_open = tokio::time::timeout(Duration::from_millis(200), events.read(&mut buf)).await;
    assert!(
        still_open.is_err(),
        "events stream ended while a request was admitted"
    );
    assert!(!server.handle.is_finished());

    gate.add_permits(1);
    let tail = read_to_end(&mut events).await;
    assert!(
        tail.ends_with(b"0\r\n\r\n"),
        "{:?}",
        String::from_utf8_lossy(&tail)
    );
    server.stopped(Duration::from_secs(5)).await;
}

#[test]
fn blocked_store_probe_does_not_hold_the_drain_or_teardown() {
    let store = Arc::new(BlockingStore::default());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut server = Server::start(TestBackend {
            inner: MockBackend::with_store(store.clone()),
            ..TestBackend::default()
        })
        .await;

        let mut health = send_request(server.addr, "GET", "/v1/health").await;
        let probing = store.clone();
        wait_until("store probe in flight", move || {
            probing.probes_entered() == 1
        })
        .await;

        server.signal().await;
        let resp = tokio::time::timeout(Duration::from_secs(1), read_to_end(&mut health))
            .await
            .expect("health did not answer promptly");
        assert_eq!(parse_response(&resp).status, 503);
        server.stopped(Duration::from_secs(1)).await;
    });

    // Runtime teardown completes while the probe is still blocked.
    let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(rt);
        let _ = dropped_tx.send(());
    });
    let dropped = dropped_rx.recv_timeout(Duration::from_secs(1));
    assert_eq!(store.probes_entered(), 1);
    store.release();
    dropped.expect("runtime teardown waited for the blocked probe");
}
