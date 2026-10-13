//! Request admission and the SIGTERM drain.
//!
//! Every request except `GET /v1/health` passes the admission gate. Once the
//! drain begins, the gate refuses with a bare 503 and `Retry-After`. Admitted
//! requests are counted until their response body ends; stream responses
//! (marked with [`StreamResponse`]) are released when their handler returns.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::{Frame, SizeHint};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// `Retry-After` value, in seconds, on requests refused during the drain.
pub(crate) const RETRY_AFTER_SECS: &str = "1";

/// Response extension set by handlers whose response is a long-lived stream.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamResponse;

#[derive(Default)]
struct AdmissionInner {
    draining: bool,
    admitted: usize,
}

/// Admission state shared by the gate, the drain and the health handler.
pub(crate) struct Admission {
    inner: Mutex<AdmissionInner>,
    drained: watch::Sender<bool>,
    drain_started: CancellationToken,
}

/// Counts one admitted request until dropped.
pub(crate) struct AdmitGuard {
    admission: Arc<Admission>,
}

impl Admission {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(AdmissionInner::default()),
            drained: watch::Sender::new(false),
            drain_started: CancellationToken::new(),
        })
    }

    /// Admits a request unless the drain has begun.
    pub(crate) fn try_admit(self: &Arc<Self>) -> Option<AdmitGuard> {
        let mut inner = self.lock();
        if inner.draining {
            return None;
        }
        inner.admitted += 1;
        Some(AdmitGuard {
            admission: self.clone(),
        })
    }

    /// Stops admitting. Drained once no admitted request remains.
    pub(crate) fn begin_drain(&self) {
        let mut inner = self.lock();
        inner.draining = true;
        if inner.admitted == 0 {
            self.drained.send_replace(true);
        }
        drop(inner);
        self.drain_started.cancel();
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.lock().draining
    }

    /// Cancelled when the drain begins.
    pub(crate) fn drain_started(&self) -> CancellationToken {
        self.drain_started.clone()
    }

    /// Completes once the drain has begun and no admitted request remains.
    pub(crate) async fn wait_drained(&self) {
        let mut drained = self.drained.subscribe();
        // The sender lives in `self`, so the channel cannot close here.
        let _ = drained.wait_for(|d| *d).await;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AdmissionInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn admitted(&self) -> usize {
        self.lock().admitted
    }
}

impl Drop for AdmitGuard {
    fn drop(&mut self) {
        let mut inner = self.admission.lock();
        inner.admitted -= 1;
        if inner.draining && inner.admitted == 0 {
            self.admission.drained.send_replace(true);
        }
    }
}

/// The response to a request refused during the drain: 503, no body.
pub(crate) fn refused() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, RETRY_AFTER_SECS)],
    )
        .into_response()
}

fn is_health(req: &Request) -> bool {
    req.method() == Method::GET && req.uri().path() == "/v1/health"
}

/// Admission middleware; apply it as the outermost layer.
pub(crate) async fn admit(
    State(admission): State<Arc<Admission>>,
    req: Request,
    next: Next,
) -> Response {
    if is_health(&req) {
        return next.run(req).await;
    }
    let Some(guard) = admission.try_admit() else {
        return refused();
    };
    let resp = next.run(req).await;
    if resp.extensions().get::<StreamResponse>().is_some() {
        return resp;
    }
    resp.map(|inner| {
        Body::new(GuardedBody {
            inner,
            guard: Some(guard),
        })
    })
}

/// A response body that holds an admission until it ends or is dropped.
struct GuardedBody {
    inner: Body,
    guard: Option<AdmitGuard>,
}

impl http_body::Body for GuardedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(poll, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.guard.take();
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn drained_soon(admission: &Admission) -> bool {
        tokio::time::timeout(Duration::from_millis(100), admission.wait_drained())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn admission_drained_only_when_admitted_request_releases() {
        let admission = Admission::new();
        let guard = admission.try_admit().unwrap();
        admission.begin_drain();
        assert!(admission.is_draining());
        assert!(!drained_soon(&admission).await);
        drop(guard);
        assert!(drained_soon(&admission).await);
    }

    #[tokio::test]
    async fn admission_refuses_after_drain_without_counting() {
        let admission = Admission::new();
        admission.begin_drain();
        assert!(admission.try_admit().is_none());
        assert_eq!(admission.admitted(), 0);
        assert!(drained_soon(&admission).await);
    }

    #[tokio::test]
    async fn admission_drain_at_zero_is_drained_at_once() {
        let admission = Admission::new();
        assert!(!admission.is_draining());
        admission.begin_drain();
        assert!(drained_soon(&admission).await);
    }

    #[tokio::test]
    async fn admission_drained_after_last_of_several_guards() {
        let admission = Admission::new();
        let guards: Vec<_> = (0..3).map(|_| admission.try_admit().unwrap()).collect();
        assert_eq!(admission.admitted(), 3);
        admission.begin_drain();
        let mut guards = guards.into_iter();
        drop(guards.next());
        drop(guards.next());
        assert!(!drained_soon(&admission).await);
        drop(guards.next());
        assert!(drained_soon(&admission).await);
        assert_eq!(admission.admitted(), 0);
    }

    #[tokio::test]
    async fn admission_waiter_subscribing_after_transition_sees_drained() {
        // No receiver exists when begin_drain() observes zero admitted.
        let at_zero = Admission::new();
        assert_eq!(at_zero.drained.receiver_count(), 0);
        at_zero.begin_drain();
        assert!(drained_soon(&at_zero).await);

        // No receiver exists when the last guard drops.
        let on_release = Admission::new();
        let guard = on_release.try_admit().unwrap();
        on_release.begin_drain();
        assert_eq!(on_release.drained.receiver_count(), 0);
        drop(guard);
        assert!(drained_soon(&on_release).await);
    }

    #[test]
    fn admission_never_admits_after_drained_is_observed() {
        for _ in 0..200 {
            let admission = Admission::new();
            let mut drained = admission.drained.subscribe();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let admitters: Vec<_> = (0..4)
                .map(|_| {
                    let admission = admission.clone();
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        let mut violations = 0;
                        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                            if let Some(guard) = admission.try_admit() {
                                if *admission.drained.borrow() {
                                    violations += 1;
                                }
                                drop(guard);
                            }
                        }
                        violations
                    })
                })
                .collect();
            std::thread::yield_now();
            admission.begin_drain();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !*drained.borrow_and_update() {
                assert!(std::time::Instant::now() < deadline, "never drained");
                std::thread::yield_now();
            }
            assert!(admission.try_admit().is_none());
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            for admitter in admitters {
                assert_eq!(admitter.join().unwrap(), 0);
            }
            assert_eq!(admission.admitted(), 0);
        }
    }

    #[test]
    fn refused_is_bare_503_with_retry_after() {
        let resp = refused();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "1");
        assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
        assert_eq!(http_body::Body::size_hint(resp.body()).exact(), Some(0));
    }
}
