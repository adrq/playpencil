use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use playpencil_core::types::ExecCanceller;
use tokio_util::sync::CancellationToken;

use crate::drain::Admission;

/// A live command's controller: a cancellation handle plus a first-cancel-wins
/// latch so DELETE, the disconnect guard, and the timeout produce a single
/// escalation owner.
pub(crate) struct LiveControl {
    pub canceller: ExecCanceller,
    pub cleanup_started: Arc<AtomicBool>,
}

/// Registry of running command-face execs keyed by `(sandbox_id, command_id)`.
/// An entry is present only while the command is RUNNING: it is inserted before
/// the stream emits its `init` and removed when the terminal is observed (or on
/// cleanup). Presence is the DELETE contract: present → 200, absent → 404.
#[derive(Default)]
pub(crate) struct LiveControlRegistry {
    map: Mutex<HashMap<(String, String), LiveControl>>,
}

impl LiveControlRegistry {
    pub fn insert(&self, sandbox: String, command: String, control: LiveControl) {
        self.map.lock().unwrap().insert((sandbox, command), control);
    }

    pub fn remove(&self, sandbox: &str, command: &str) {
        self.map
            .lock()
            .unwrap()
            .remove(&(sandbox.to_string(), command.to_string()));
    }

    /// Look up a running command and return its canceller plus whether THIS
    /// caller won the single-escalation race. `None` when no such running
    /// command exists (unknown / already completed / already cleaned).
    pub fn take_for_cleanup(&self, sandbox: &str, command: &str) -> Option<(ExecCanceller, bool)> {
        let map = self.map.lock().unwrap();
        let c = map.get(&(sandbox.to_string(), command.to_string()))?;
        let won = !c
            .cleanup_started
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        Some((c.canceller.clone(), won))
    }
}

pub(crate) struct AppState<B> {
    pub backend: Arc<B>,
    // Cancelled once the drain has no admitted requests left. Long-lived
    // handlers (SSE streams, exec faces) observe it and end.
    pub shutdown: CancellationToken,
    pub live: Arc<LiveControlRegistry>,
    pub admission: Arc<Admission>,
}

impl<B> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            shutdown: self.shutdown.clone(),
            live: self.live.clone(),
            admission: self.admission.clone(),
        }
    }
}

impl<B> AppState<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
            shutdown: CancellationToken::new(),
            live: Arc::new(LiveControlRegistry::default()),
            admission: Admission::new(),
        }
    }
}
