use std::sync::Arc;

use tokio_util::sync::CancellationToken;

pub(crate) struct AppState<B> {
    pub backend: Arc<B>,
    // Cancelled when the server begins shutting down. Long-lived handlers (SSE
    // streams) observe it so they end and let graceful shutdown drain.
    pub shutdown: CancellationToken,
}

impl<B> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<B> AppState<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
            shutdown: CancellationToken::new(),
        }
    }
}
