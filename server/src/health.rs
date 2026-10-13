//! `GET /v1/health`: a readiness signal. 200 when the daemon can serve; 503
//! when the store is unreadable or unwritable, the sandbox runtime is down, or
//! the daemon is draining. Always an empty body.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use futures_util::future::BoxFuture;

use playpencil_core::backend::SandboxBackendSend;
use playpencil_core::backend::health::Unhealthy;

use crate::drain::Admission;

type HealthCheck = dyn Fn() -> BoxFuture<'static, Result<(), Unhealthy>> + Send + Sync;

/// State of the health handler.
#[derive(Clone)]
pub(crate) struct HealthState {
    check: Arc<HealthCheck>,
    admission: Arc<Admission>,
    healthy: Arc<AtomicBool>,
    #[cfg(test)]
    pause: Option<Arc<test_support::Pause>>,
}

impl HealthState {
    pub(crate) fn new<B: SandboxBackendSend + Sync + 'static>(
        backend: Arc<B>,
        admission: Arc<Admission>,
    ) -> Self {
        Self::from_check(
            Arc::new(move || {
                let backend = backend.clone();
                Box::pin(async move { backend.health().await })
            }),
            admission,
        )
    }

    fn from_check(check: Arc<HealthCheck>, admission: Arc<Admission>) -> Self {
        Self {
            check,
            admission,
            healthy: Arc::new(AtomicBool::new(true)),
            #[cfg(test)]
            pause: None,
        }
    }

    /// The health status: 503 while draining, otherwise from the backend.
    pub(crate) async fn status(&self) -> StatusCode {
        if self.admission.is_draining() {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        let drain_started = self.admission.drain_started();
        let result = tokio::select! {
            result = (self.check)() => result,
            _ = drain_started.cancelled() => return StatusCode::SERVICE_UNAVAILABLE,
        };
        #[cfg(test)]
        if let Some(pause) = &self.pause {
            pause.reached.add_permits(1);
            pause.release.acquire().await.unwrap().forget();
        }
        if self.admission.is_draining() {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        match result {
            Ok(()) => {
                if !self.healthy.swap(true, Ordering::SeqCst) {
                    tracing::info!("health: daemon can serve again");
                }
                StatusCode::OK
            }
            Err(e) => {
                if self.healthy.swap(false, Ordering::SeqCst) {
                    tracing::warn!("health: daemon cannot serve: {e}");
                }
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use tokio::sync::Semaphore;

    /// A pause point in the health handler, right before the final drain
    /// check.
    pub(crate) struct Pause {
        pub(crate) reached: Semaphore,
        pub(crate) release: Semaphore,
    }

    impl Default for Pause {
        fn default() -> Self {
            Self {
                reached: Semaphore::new(0),
                release: Semaphore::new(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::Semaphore;

    fn fixed(result: Result<(), Unhealthy>) -> Arc<HealthCheck> {
        Arc::new(move || {
            let result = result.clone();
            Box::pin(async move { result })
        })
    }

    /// A check that adds a permit to `started` when it runs, then blocks until
    /// `gate` has a permit and succeeds.
    fn gated(started: Arc<Semaphore>, gate: Arc<Semaphore>) -> Arc<HealthCheck> {
        Arc::new(move || {
            let (started, gate) = (started.clone(), gate.clone());
            Box::pin(async move {
                started.add_permits(1);
                let _permit = gate.acquire().await.unwrap();
                Ok(())
            })
        })
    }

    #[tokio::test]
    async fn healthy_backend_is_200() {
        let health = HealthState::from_check(fixed(Ok(())), Admission::new());
        assert_eq!(health.status().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn unhealthy_backend_is_503_and_recovers() {
        let admission = Admission::new();
        let health =
            HealthState::from_check(fixed(Err(Unhealthy::StoreTimeout)), admission.clone());
        assert_eq!(health.status().await, StatusCode::SERVICE_UNAVAILABLE);
        let health = HealthState {
            check: fixed(Ok(())),
            ..health
        };
        assert_eq!(health.status().await, StatusCode::OK);
    }

    #[tokio::test]
    async fn draining_is_503_without_a_backend_call() {
        let admission = Admission::new();
        admission.begin_drain();
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let check: Arc<HealthCheck> = Arc::new(move || {
            flag.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        });
        let health = HealthState::from_check(check, admission);
        assert_eq!(health.status().await, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn probe_crossing_drain_answers_503() {
        // (a) The drain begins while the check is still waiting.
        let admission = Admission::new();
        let started = Arc::new(Semaphore::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let health =
            HealthState::from_check(gated(started.clone(), gate.clone()), admission.clone());
        let call = tokio::spawn(async move { health.status().await });
        started.acquire().await.unwrap().forget();
        admission.begin_drain();
        let status = tokio::time::timeout(Duration::from_millis(200), call)
            .await
            .expect("health did not answer promptly")
            .unwrap();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(gate.available_permits(), 0);

        // (b) The check succeeds, then the drain begins before the final check.
        let admission = Admission::new();
        let pause = Arc::new(test_support::Pause::default());
        let health = HealthState {
            pause: Some(pause.clone()),
            ..HealthState::from_check(fixed(Ok(())), admission.clone())
        };
        let call = tokio::spawn(async move { health.status().await });
        pause.reached.acquire().await.unwrap().forget();
        admission.begin_drain();
        pause.release.add_permits(1);
        assert_eq!(call.await.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
