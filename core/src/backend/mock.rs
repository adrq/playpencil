use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::lifecycle::SandboxState;
use crate::types::{ExecId, ExecRequest, SandboxConfig, SandboxId, SandboxStatus};

use super::{BackendError, Capabilities, SandboxBackend};

struct SandboxEntry {
    state: SandboxState,
}

pub struct MockBackend {
    sandboxes: Mutex<HashMap<SandboxId, SandboxEntry>>,
    next_id: AtomicU64,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            sandboxes: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{n}")
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for MockBackend {
    async fn create(&self, _config: SandboxConfig) -> Result<SandboxId, BackendError> {
        let id = SandboxId(self.next_id("mock"));

        let state = SandboxState::Creating
            .transition_to(SandboxState::Ready)
            .map_err(|_| BackendError::InvalidState)?;

        let entry = SandboxEntry { state };
        self.sandboxes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), entry);
        Ok(id)
    }

    async fn start(&self, id: &SandboxId) -> Result<(), BackendError> {
        let mut map = self.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get_mut(id).ok_or(BackendError::NotFound)?;
        entry.state = entry
            .state
            .transition_to(SandboxState::Running)
            .map_err(|_| BackendError::InvalidState)?;
        Ok(())
    }

    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError> {
        let mut map = self.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get_mut(id).ok_or(BackendError::NotFound)?;
        entry.state = entry
            .state
            .transition_to(SandboxState::Stopped)
            .map_err(|_| BackendError::InvalidState)?;
        Ok(())
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError> {
        let mut map = self.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get_mut(id).ok_or(BackendError::NotFound)?;
        entry.state = entry
            .state
            .transition_to(SandboxState::Destroyed)
            .map_err(|_| BackendError::InvalidState)?;
        Ok(())
    }

    async fn status(&self, id: &SandboxId) -> Result<SandboxStatus, BackendError> {
        let map = self.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get(id).ok_or(BackendError::NotFound)?;
        Ok(SandboxStatus {
            sandbox_id: id.clone(),
            state: entry.state.to_string(),
            created_at: None,
        })
    }

    async fn exec(&self, id: &SandboxId, _req: ExecRequest) -> Result<ExecId, BackendError> {
        let map = self.sandboxes.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.get(id).ok_or(BackendError::NotFound)?;
        if entry.state != SandboxState::Running {
            return Err(BackendError::InvalidState);
        }
        Ok(ExecId(self.next_id("exec")))
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_isolation: false,
            network_policy: false,
            host_mounts: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "test:latest".into(),
            resource_limits: crate::types::ResourceLimits {
                cpus: None,
                memory_bytes: None,
                disk_bytes: None,
            },
            mounts: vec![],
            network: crate::types::NetworkPolicy::Isolated,
            env: vec![],
        }
    }

    #[tokio::test]
    async fn test_create_returns_unique_ids() {
        let backend = MockBackend::new();
        let id1 = backend.create(test_config()).await.unwrap();
        let id2 = backend.create(test_config()).await.unwrap();
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_create_status_is_ready() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "ready");
        assert!(status.created_at.is_none());
    }

    #[tokio::test]
    async fn test_start_transitions_to_running() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "running");
    }

    #[tokio::test]
    async fn test_stop_transitions_to_stopped() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        backend.stop(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "stopped");
    }

    #[tokio::test]
    async fn test_destroy_transitions_to_destroyed() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    #[tokio::test]
    async fn test_destroy_from_running() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    #[tokio::test]
    async fn test_destroy_from_stopped() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        backend.stop(&id).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    #[tokio::test]
    async fn test_start_not_found() {
        let backend = MockBackend::new();
        let result = backend.start(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_restart_from_stopped() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        backend.stop(&id).await.unwrap();
        backend.start(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "running");
    }

    #[tokio::test]
    async fn test_start_invalid_state_from_destroyed() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_stop_invalid_state_from_ready() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        let result = backend.stop(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_exec_in_running_state() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        let req = ExecRequest {
            command: vec!["echo".into(), "hello".into()],
            working_dir: None,
            env: vec![],
        };
        let exec_id = backend.exec(&id, req).await.unwrap();
        assert!(exec_id.0.starts_with("exec-"));
    }

    #[tokio::test]
    async fn test_exec_not_running() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&id, req).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_exec_returns_unique_ids() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        let req1 = ExecRequest {
            command: vec!["a".into()],
            working_dir: None,
            env: vec![],
        };
        let req2 = ExecRequest {
            command: vec!["b".into()],
            working_dir: None,
            env: vec![],
        };
        let eid1 = backend.exec(&id, req1).await.unwrap();
        let eid2 = backend.exec(&id, req2).await.unwrap();
        assert_ne!(eid1, eid2);
    }

    #[tokio::test]
    async fn test_capabilities_all_false() {
        let backend = MockBackend::new();
        assert_eq!(
            backend.capabilities(),
            Capabilities {
                hardware_isolation: false,
                network_policy: false,
                host_mounts: false,
            }
        );
    }

    #[tokio::test]
    async fn test_status_not_found() {
        let backend = MockBackend::new();
        let result = backend.status(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_destroy_not_found() {
        let backend = MockBackend::new();
        let result = backend.destroy(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_stop_not_found() {
        let backend = MockBackend::new();
        let result = backend.stop(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_exec_not_found() {
        let backend = MockBackend::new();
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&SandboxId("bogus".into()), req).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_status_sandbox_id_matches() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.sandbox_id, id);
    }

    #[tokio::test]
    async fn test_double_start() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_double_destroy() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let result = backend.destroy(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_stop_from_destroyed() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let result = backend.stop(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_exec_from_stopped() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.start(&id).await.unwrap();
        backend.stop(&id).await.unwrap();
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&id, req).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn test_exec_from_destroyed() {
        let backend = MockBackend::new();
        let id = backend.create(test_config()).await.unwrap();
        backend.destroy(&id).await.unwrap();
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&id, req).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }
}
