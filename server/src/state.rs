use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use playpencil_core::types::SandboxId;

use crate::api_types::NetworkPolicyWire;

#[derive(Clone)]
pub(crate) struct StoredConfig {
    pub image: String,
    pub name: Option<String>,
    pub network: NetworkPolicyWire,
}

#[derive(Clone)]
pub(crate) enum SandboxEvent {
    StateChange { state: String },
}

pub(crate) struct AppState<B> {
    pub backend: Arc<B>,
    pub configs: Arc<Mutex<HashMap<SandboxId, StoredConfig>>>,
    pub events: Arc<Mutex<HashMap<SandboxId, broadcast::Sender<SandboxEvent>>>>,
    // Cancelled when the server begins shutting down. Long-lived handlers (SSE
    // streams) observe it so they end and let graceful shutdown drain.
    pub shutdown: CancellationToken,
}

impl<B> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            configs: self.configs.clone(),
            events: self.events.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<B> AppState<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
            configs: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(HashMap::new())),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn publish_event(&self, id: &SandboxId, event: SandboxEvent) {
        let map = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = map.get(id) {
            // Ignore send errors (no subscribers).
            let _ = tx.send(event);
        }
    }
}
