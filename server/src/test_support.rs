//! Test backend and raw HTTP helpers for server tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use playpencil_core::backend::health::Unhealthy;
use playpencil_core::backend::mock::MockBackend;
use playpencil_core::backend::{BackendError, Capabilities, OutputSnapshot, SandboxBackendSend};
use playpencil_core::store::{InMemoryStore, PersistedRecord, Store};
use playpencil_core::types::{
    EntrypointExit, ExecHandle, ExecRequest, SandboxConfig, SandboxId, SandboxStatus, SandboxView,
};

/// A [`MockBackend`] whose `list` can be held on a gate and whose health can
/// be overridden with a failure.
#[derive(Default)]
pub(crate) struct TestBackend {
    pub(crate) inner: MockBackend,
    /// When set, `list` waits for a permit.
    pub(crate) list_gate: Option<Arc<Semaphore>>,
    /// When set, `health` returns this failure instead of the inner backend's
    /// result.
    pub(crate) health_result: std::sync::Mutex<Option<Unhealthy>>,
    pub(crate) list_calls: AtomicUsize,
}

/// An in-memory store whose `probe` blocks until released.
#[derive(Default)]
pub(crate) struct BlockingStore {
    inner: InMemoryStore,
    released: std::sync::Mutex<bool>,
    release_cv: std::sync::Condvar,
    probes_entered: AtomicUsize,
}

impl BlockingStore {
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release_cv.notify_all();
    }

    pub(crate) fn probes_entered(&self) -> usize {
        self.probes_entered.load(Ordering::SeqCst)
    }
}

impl Store for BlockingStore {
    fn upsert(&self, record: &PersistedRecord) -> std::io::Result<()> {
        self.inner.upsert(record)
    }
    fn delete(&self, id: &SandboxId) -> std::io::Result<()> {
        self.inner.delete(id)
    }
    fn load_all(&self) -> std::io::Result<Vec<PersistedRecord>> {
        self.inner.load_all()
    }
    fn replace_all(&self, records: &[PersistedRecord]) -> std::io::Result<()> {
        self.inner.replace_all(records)
    }
    fn probe(&self) -> std::io::Result<()> {
        self.probes_entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release_cv.wait(released).unwrap();
        }
        Ok(())
    }
}

impl SandboxBackendSend for TestBackend {
    async fn create(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        self.inner.create(config).await
    }
    async fn create_and_start(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        self.inner.create_and_start(config).await
    }
    async fn start(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.inner.start(id).await
    }
    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.inner.stop(id).await
    }
    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.inner.destroy(id).await
    }
    async fn status(&self, id: &SandboxId) -> Result<SandboxView, BackendError> {
        self.inner.status(id).await
    }
    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError> {
        self.inner.exec(id, req).await
    }
    async fn list(&self) -> Result<Vec<SandboxView>, BackendError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.list_gate {
            let _permit = gate.acquire().await.unwrap();
        }
        self.inner.list().await
    }
    async fn entrypoint_exit(
        &self,
        id: &SandboxId,
    ) -> Result<Option<EntrypointExit>, BackendError> {
        self.inner.entrypoint_exit(id).await
    }
    async fn entrypoint_output(
        &self,
        id: &SandboxId,
    ) -> Result<Option<OutputSnapshot>, BackendError> {
        self.inner.entrypoint_output(id).await
    }
    fn subscribe(
        &self,
        id: &SandboxId,
    ) -> Result<tokio::sync::broadcast::Receiver<SandboxStatus>, BackendError> {
        self.inner.subscribe(id)
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn health(&self) -> Result<(), Unhealthy> {
        let failure = self.health_result.lock().unwrap().clone();
        match failure {
            Some(e) => Err(e),
            None => self.inner.health().await,
        }
    }
}

/// Polls `cond` every 2 ms for up to 5 s.
pub(crate) async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// A raw HTTP/1.1 response.
#[derive(Debug)]
pub(crate) struct RawResponse {
    pub(crate) status: u16,
    pub(crate) head: String,
    pub(crate) body: Vec<u8>,
}

impl RawResponse {
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

/// Splits a raw response at the end of its head.
pub(crate) fn parse_response(raw: &[u8]) -> RawResponse {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    RawResponse {
        status,
        head,
        body: raw[split + 4..].to_vec(),
    }
}

/// Decodes a chunked transfer-encoded body.
pub(crate) fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line_end]).unwrap(), 16).unwrap();
        body = &body[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Opens a connection and sends `method path` with `Connection: close`.
pub(crate) async fn send_request(addr: SocketAddr, method: &str, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream
}

/// Reads until the peer closes, within 5 s.
pub(crate) async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("response did not complete")
        .unwrap();
    raw
}

/// Sends a request and reads the complete response.
pub(crate) async fn request(addr: SocketAddr, method: &str, path: &str) -> RawResponse {
    let mut stream = send_request(addr, method, path).await;
    parse_response(&read_to_end(&mut stream).await)
}

/// Reads until `needle` has been received, within 5 s.
pub(crate) async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !raw.windows(needle.len()).any(|w| w == needle) {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before {needle:?}");
            raw.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("expected bytes did not arrive");
    raw
}
