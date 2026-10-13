use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::lifecycle::{DesiredState, Verb};
use crate::store::{InMemoryStore, PersistedRecord};
use crate::types::{
    EntrypointExit, ExecHandle, ExecId, ExecRequest, SandboxConfig, SandboxId, SandboxStatus,
    SandboxView, validate_entrypoint,
};

use super::reconciler::{
    DriverFactory, EntrypointExitSink, ReconcileRuntime, RootfsHandleExt, RunningVmHandle,
    VmDriverSend,
};
use super::{BackendError, Capabilities, SandboxBackendSend};

/// In-memory driver: provisioning and VM lifecycle are instant no-ops, with a
/// flippable liveness flag for crash simulation.
pub struct MockRunningVm {
    pid: i32,
    pid_start_time: u64,
    alive: Arc<AtomicBool>,
}

impl RunningVmHandle for MockRunningVm {
    fn pid(&self) -> i32 {
        self.pid
    }
    fn pid_start_time(&self) -> u64 {
        self.pid_start_time
    }
}

pub struct MockRootfsHandle {
    root: PathBuf,
}

impl RootfsHandleExt for MockRootfsHandle {
    fn rootfs_path(&self) -> &std::path::Path {
        &self.root
    }
}

pub struct MockDriver {
    session_dir: PathBuf,
    pid_counter: Arc<AtomicI32>,
}

impl VmDriverSend for MockDriver {
    type RunningVm = MockRunningVm;
    type RootfsHandle = MockRootfsHandle;

    async fn provision(
        &mut self,
        _cfg: &SandboxConfig,
    ) -> Result<Self::RootfsHandle, BackendError> {
        Ok(MockRootfsHandle {
            root: self.session_dir.join("rootfs"),
        })
    }

    async fn start(
        &mut self,
        _cfg: &SandboxConfig,
        _rootfs: &Self::RootfsHandle,
        _entrypoint_exit: EntrypointExitSink,
    ) -> Result<Self::RunningVm, BackendError> {
        Ok(MockRunningVm {
            pid: self.pid_counter.fetch_add(1, Ordering::Relaxed),
            // A synthetic start time that never matches a real /proc entry.
            pid_start_time: 0,
            alive: Arc::new(AtomicBool::new(true)),
        })
    }

    async fn stop(&mut self, _vm: Self::RunningVm) {}

    async fn graceful_shutdown(&self, vm: &mut Self::RunningVm) {
        vm.alive.store(false, Ordering::Release);
    }

    async fn teardown(
        &mut self,
        _vm: Option<Self::RunningVm>,
        _rootfs: Option<Self::RootfsHandle>,
    ) -> Result<(), (BackendError, Option<Self::RootfsHandle>)> {
        Ok(())
    }

    fn recover_rootfs(
        &self,
        record: &PersistedRecord,
    ) -> Result<Option<Self::RootfsHandle>, BackendError> {
        Ok(record
            .rootfs_path
            .as_ref()
            .map(|root| MockRootfsHandle { root: root.clone() }))
    }

    fn is_alive(&self, vm: &mut Self::RunningVm) -> bool {
        vm.alive.load(Ordering::Acquire)
    }
}

pub struct MockFactory {
    base_dir: PathBuf,
    pid_counter: Arc<AtomicI32>,
}

impl DriverFactory for MockFactory {
    type Driver = MockDriver;
    fn build(&self, id: &SandboxId, _config: &SandboxConfig) -> MockDriver {
        MockDriver {
            session_dir: self.base_dir.join(&id.0),
            pid_counter: self.pid_counter.clone(),
        }
    }
}

pub struct MockBackend {
    runtime: ReconcileRuntime<MockFactory>,
    next_exec: AtomicU64,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::with_runtime_store(Arc::new(InMemoryStore::new()))
    }

    /// A mock backend whose runtime persists to `store`.
    #[cfg(feature = "test-util")]
    pub fn with_store(store: Arc<dyn crate::store::Store>) -> Self {
        Self::with_runtime_store(store)
    }

    fn with_runtime_store(store: Arc<dyn crate::store::Store>) -> Self {
        let base_dir = std::env::temp_dir().join(format!("pp-mock-{}", std::process::id()));
        let factory = MockFactory {
            base_dir,
            pid_counter: Arc::new(AtomicI32::new(1_000_000)),
        };
        Self {
            runtime: ReconcileRuntime::new(factory, store),
            next_exec: AtomicU64::new(1),
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        self.runtime.shutdown();
    }
}

impl SandboxBackendSend for MockBackend {
    async fn create_and_start(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        validate_entrypoint(config.entrypoint.as_deref()).map_err(BackendError::InvalidInput)?;
        self.runtime.create(config, DesiredState::Running).await
    }

    async fn start(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.runtime
            .set_desired(id, Verb::Start, DesiredState::Running)
            .await
    }

    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.runtime
            .set_desired(id, Verb::Stop, DesiredState::Stopped)
            .await
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError> {
        self.runtime
            .set_desired(id, Verb::Destroy, DesiredState::Destroyed)
            .await
    }

    async fn status(&self, id: &SandboxId) -> Result<SandboxView, BackendError> {
        self.runtime.status(id)
    }

    async fn exec(&self, id: &SandboxId, _req: ExecRequest) -> Result<ExecHandle, BackendError> {
        let view = self.runtime.status(id)?;
        if view.status.state != Some(crate::lifecycle::State::Running) {
            return Err(BackendError::InvalidState);
        }
        let n = self.next_exec.fetch_add(1, Ordering::Relaxed);
        // A handle with an already-closed event stream and stdin/control going
        // nowhere — the mock runs no real process.
        Ok(ExecHandle::for_mock(ExecId(format!("exec-{n}"))))
    }

    async fn entrypoint_exit(
        &self,
        id: &SandboxId,
    ) -> Result<Option<EntrypointExit>, BackendError> {
        self.runtime.entrypoint_exit(id)
    }

    async fn list(&self) -> Result<Vec<SandboxView>, BackendError> {
        Ok(self.runtime.list())
    }

    fn subscribe(
        &self,
        id: &SandboxId,
    ) -> Result<tokio::sync::broadcast::Receiver<SandboxStatus>, BackendError> {
        self.runtime.subscribe(id)
    }

    async fn health(&self) -> Result<(), super::health::Unhealthy> {
        self.runtime.health(|| true).await
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
    use crate::lifecycle::State;
    use std::time::Duration;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "test:latest".into(),
            mounts: vec![],
            network: crate::types::NetworkPolicy::Isolated,
            env: vec![],
            entrypoint: None,
        }
    }

    /// Poll `status` until the state matches (accepted-not-converged backends
    /// reconcile asynchronously).
    async fn await_state(backend: &MockBackend, id: &SandboxId, want: Option<State>) {
        for _ in 0..200 {
            if let Ok(view) = backend.status(id).await
                && view.status.state == want
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let got = backend.status(id).await.ok().and_then(|v| v.status.state);
        panic!("timed out waiting for {want:?}, last was {got:?}");
    }

    /// Create a running sandbox, then stop it and wait for `Stopped`.
    async fn create_stopped(backend: &MockBackend) -> SandboxId {
        let id = backend.create_and_start(test_config()).await.unwrap();
        await_state(backend, &id, Some(State::Running)).await;
        backend.stop(&id).await.unwrap();
        await_state(backend, &id, Some(State::Stopped)).await;
        id
    }

    #[tokio::test]
    async fn create_and_start_returns_unique_ids() {
        let backend = MockBackend::new();
        let id1 = backend.create_and_start(test_config()).await.unwrap();
        let id2 = backend.create_and_start(test_config()).await.unwrap();
        assert_ne!(id1, id2);
        await_state(&backend, &id1, Some(State::Running)).await;
    }

    #[tokio::test]
    async fn create_and_start_converges_to_running() {
        let backend = MockBackend::new();
        let id = backend.create_and_start(test_config()).await.unwrap();
        await_state(&backend, &id, Some(State::Running)).await;
    }

    #[tokio::test]
    async fn start_then_stop() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        backend.start(&id).await.unwrap();
        await_state(&backend, &id, Some(State::Running)).await;
        backend.stop(&id).await.unwrap();
        await_state(&backend, &id, Some(State::Stopped)).await;
    }

    #[tokio::test]
    async fn destroy_is_retained_as_destroyed() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        backend.destroy(&id).await.unwrap();
        await_state(&backend, &id, Some(State::Destroyed)).await;
        // Record retained, not NotFound.
        let view = backend.status(&id).await.unwrap();
        assert_eq!(view.status.state, Some(State::Destroyed));
    }

    #[tokio::test]
    async fn accepted_status_reflects_intent_before_convergence() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        backend.start(&id).await.unwrap();
        // Immediately after the accepted ack, desired is Running and durable.
        let view = backend.status(&id).await.unwrap();
        assert_eq!(view.status.desired, DesiredState::Running);
    }

    #[tokio::test]
    async fn start_rejected_when_being_destroyed() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        backend.destroy(&id).await.unwrap();
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    #[tokio::test]
    async fn start_not_found() {
        let backend = MockBackend::new();
        let result = backend.start(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn status_not_found() {
        let backend = MockBackend::new();
        let result = backend.status(&SandboxId("bogus".into())).await;
        assert!(matches!(result, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn exec_requires_running() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
            uid: None,
            gid: None,
            mode: Default::default(),
        };
        assert!(matches!(
            backend.exec(&id, req).await,
            Err(BackendError::InvalidState)
        ));
        backend.start(&id).await.unwrap();
        await_state(&backend, &id, Some(State::Running)).await;
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
            uid: None,
            gid: None,
            mode: Default::default(),
        };
        let handle = backend.exec(&id, req).await.unwrap();
        assert!(handle.exec_id.0.starts_with("exec-"));
    }

    #[tokio::test]
    async fn list_includes_created_sandbox() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        let list = backend.list().await.unwrap();
        assert!(list.iter().any(|v| v.status.sandbox_id == id));
    }

    #[tokio::test]
    async fn subscribe_receives_running_transition() {
        let backend = MockBackend::new();
        let id = create_stopped(&backend).await;
        let mut rx = backend.subscribe(&id).unwrap();
        backend.start(&id).await.unwrap();
        // The Running transition is broadcast by the actor after convergence.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    if let Ok(status) = msg
                        && status.state == Some(State::Running)
                    {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => panic!("no Running event"),
            }
        }
    }

    #[tokio::test]
    async fn capabilities_all_false() {
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
}
