//! Single-writer, generation-latched sandbox reconciler.
//!
//! Each sandbox is driven by exactly one per-sandbox task (the actor) that is
//! the sole writer of the durable record and the sole owner of live resources.
//! API methods enqueue commands and await an acceptance ack; readers observe a
//! published snapshot without ever locking the actor.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::BackendError;
use crate::lifecycle::{
    DesiredState, FailureReason, ReconcileAction, State, Verb, next_action, precondition_ok,
};
use crate::store::{PersistedRecord, Store, verify_pid};
use crate::types::{EntrypointExit, SandboxConfig, SandboxId, SandboxStatus, SandboxView};

/// How often an idle actor re-checks VM liveness.
const LIVENESS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long recovery waits for a SIGKILL'd leftover VM to actually disappear
/// before failing recovery rather than serving a still-live sandbox as stopped.
const RECOVER_KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll `still_alive` until it reports false, sleeping between checks. Returns
/// an error if the process is still alive after `timeout` (so a SIGKILL'd VM
/// that refuses to die fails recovery loudly instead of being served as dead).
async fn await_pid_death(
    id: &SandboxId,
    mut still_alive: impl FnMut() -> bool,
    timeout: Duration,
) -> Result<(), BackendError> {
    const STEP: Duration = Duration::from_millis(20);
    let mut waited = Duration::ZERO;
    while still_alive() {
        if waited >= timeout {
            return Err(BackendError::Internal(format!(
                "recovered VM for sandbox {} did not die after SIGKILL",
                id.0
            )));
        }
        tokio::time::sleep(STEP).await;
        waited += STEP;
    }
    Ok(())
}

pub(crate) fn rfc3339_now() -> String {
    crate::backend::libkrun::rfc3339_now()
}

// ---------------------------------------------------------------------------
// Driver seam
// ---------------------------------------------------------------------------

/// Accessors the reconciler reads off a running VM for persistence and
/// PID-reuse defense.
pub trait RunningVmHandle {
    fn pid(&self) -> i32;
    fn pid_start_time(&self) -> u64;
}

/// Accessors for a prepared rootfs. `rootfs_path` is the persisted mount/copy
/// root; `session_dir` is its parent (the cleanup target).
pub trait RootfsHandleExt {
    fn rootfs_path(&self) -> &std::path::Path;
    fn session_dir(&self) -> &std::path::Path;
}

/// The only backend-specific surface. One driver instance is constructed per
/// sandbox (carrying that sandbox's id + session context).
#[trait_variant::make(VmDriverSend: Send)]
pub trait VmDriver {
    type RunningVm: RunningVmHandle + Send + 'static;
    type RootfsHandle: RootfsHandleExt + Send + 'static;

    async fn provision(&mut self, cfg: &SandboxConfig) -> Result<Self::RootfsHandle, BackendError>;
    async fn start(
        &mut self,
        cfg: &SandboxConfig,
        rootfs: &Self::RootfsHandle,
        entrypoint_exit: EntrypointExitSink,
    ) -> Result<Self::RunningVm, BackendError>;
    /// Running -> Stopped: kill the VM and free run-scoped resources.
    /// Infallible / best-effort (the liveness observer and reaper backstop the
    /// kill), so it consumes the handle and returns nothing.
    async fn stop(&mut self, vm: Self::RunningVm);
    /// Bring a running VM down gracefully, BORROWING it so the caller can retain
    /// the handle until the liveness observer commits the terminal state. Closes
    /// the guest console so the guest flushes and self-exits, waits a bounded time
    /// for that, and only then kills as a backstop. Used by the main-process-exit
    /// coupling (borrow + retain) and by teardown (then consume).
    async fn graceful_shutdown(&self, vm: &mut Self::RunningVm);
    /// Teardown to Destroyed: kill the VM (if any) and delete the rootfs with
    /// bounded retry. On persistent rootfs-delete failure, returns the rootfs
    /// handle back so the destroy can be re-asserted.
    async fn teardown(
        &mut self,
        vm: Option<Self::RunningVm>,
        rootfs: Option<Self::RootfsHandle>,
    ) -> Result<(), (BackendError, Option<Self::RootfsHandle>)>;
    /// Side-effect-free reconstruction of the in-memory rootfs handle from the
    /// persisted record.
    fn recover_rootfs(
        &self,
        record: &PersistedRecord,
    ) -> Result<Option<Self::RootfsHandle>, BackendError>;
    /// Runtime liveness of the held VM. Reaps + defuses the handle on exit so a
    /// reaped (possibly reused) pid is never signalled again.
    fn is_alive(&self, vm: &mut Self::RunningVm) -> bool;
}

/// Builds a per-sandbox driver from its id + config.
pub trait DriverFactory: Send + Sync + 'static {
    type Driver: VmDriverSend + Send + 'static;
    fn build(&self, id: &SandboxId, config: &SandboxConfig) -> Self::Driver;
}

// ---------------------------------------------------------------------------
// Shared per-sandbox handles
// ---------------------------------------------------------------------------

pub(crate) enum ReconcileCommand {
    SetDesired {
        verb: Verb,
        desired: DesiredState,
        ack: oneshot::Sender<Result<(), BackendError>>,
    },
    /// The sandbox's main process terminated. Fire-and-forget (no ack); the actor
    /// stashes the outcome and couples the VM down on its next reconcile.
    EntrypointExited { outcome: EntrypointExit },
}

/// A narrow, cloneable channel the VM driver uses to report that the sandbox's
/// main process has terminated, routed onto the sandbox's own command queue so
/// the single-writer actor handles it serially with every other transition.
#[derive(Clone)]
pub struct EntrypointExitSink(mpsc::Sender<ReconcileCommand>);

impl EntrypointExitSink {
    /// Report the main process's outcome. Best-effort: a closed channel means the
    /// actor is already gone, so there is nothing to couple.
    pub async fn post(&self, outcome: EntrypointExit) {
        let _ = self
            .0
            .send(ReconcileCommand::EntrypointExited { outcome })
            .await;
    }
}

#[cfg(test)]
impl EntrypointExitSink {
    /// A sink plus its receiving end, so a test can assert what was posted.
    pub(crate) fn channel() -> (Self, mpsc::Receiver<ReconcileCommand>) {
        let (tx, rx) = mpsc::channel(8);
        (Self(tx), rx)
    }
}

/// Extract a posted main-process outcome from a reconcile command (test helper).
#[cfg(test)]
pub(crate) fn entrypoint_exited_outcome(cmd: ReconcileCommand) -> Option<EntrypointExit> {
    match cmd {
        ReconcileCommand::EntrypointExited { outcome } => Some(outcome),
        ReconcileCommand::SetDesired { .. } => None,
    }
}

/// The read-side handles published for one sandbox. Holds no live resources and
/// is never locked across an await.
struct SharedEntry {
    cmd_tx: mpsc::Sender<ReconcileCommand>,
    view_rx: watch::Receiver<SandboxView>,
    events_tx: broadcast::Sender<SandboxStatus>,
    /// The backend-only main-process exit carrier, seeded from the persisted
    /// record and updated on every carrier-affecting commit. Distinct from
    /// `view_rx` so the carrier never reaches the wire projection.
    entrypoint_exit_rx: watch::Receiver<Option<EntrypointExit>>,
    poisoned: Arc<AtomicBool>,
}

type SharedMap = Arc<RwLock<HashMap<SandboxId, SharedEntry>>>;

// ---------------------------------------------------------------------------
// Reconcile runtime (embedded by each backend)
// ---------------------------------------------------------------------------

/// Runtime readiness for the recover-before-use guard.
const STATE_NOT_RECOVERED: u8 = 0;
const STATE_RECOVERING: u8 = 1;
const STATE_READY: u8 = 2;

pub struct ReconcileRuntime<F: DriverFactory> {
    factory: Arc<F>,
    store: Arc<dyn Store>,
    map: SharedMap,
    shutdown: CancellationToken,
    next_sandbox: AtomicU64,
    state: AtomicU8,
}

impl<F: DriverFactory> ReconcileRuntime<F> {
    /// A runtime that is immediately ready to accept create/start (no recovery
    /// step) — for non-durable backends and tests.
    pub fn new(factory: F, store: Arc<dyn Store>) -> Self {
        Self::with_state(factory, store, STATE_READY)
    }

    /// A durable runtime that MUST `recover()` before it accepts create/start,
    /// so a fresh id allocation can't overwrite a persisted record and recovery
    /// can't race a live actor.
    pub fn new_recoverable(factory: F, store: Arc<dyn Store>) -> Self {
        Self::with_state(factory, store, STATE_NOT_RECOVERED)
    }

    fn with_state(factory: F, store: Arc<dyn Store>, state: u8) -> Self {
        Self {
            factory: Arc::new(factory),
            store,
            map: Arc::new(RwLock::new(HashMap::new())),
            shutdown: CancellationToken::new(),
            next_sandbox: AtomicU64::new(1),
            state: AtomicU8::new(state),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    fn alloc_id(&self) -> SandboxId {
        let n = self.next_sandbox.fetch_add(1, Ordering::Relaxed);
        SandboxId(format!("sb-{n}"))
    }

    /// Reject create/start until recovery has completed (durable runtime); a
    /// `new` runtime is Ready from construction so this is a no-op there.
    fn ensure_ready(&self) -> Result<(), BackendError> {
        if self.state.load(Ordering::Acquire) != STATE_READY {
            return Err(BackendError::Internal(
                "runtime not ready: recovery must complete before create/start".into(),
            ));
        }
        Ok(())
    }

    /// Spawn a new sandbox with the given initial intent and return its id once
    /// the genesis record is durably persisted.
    pub async fn create(
        &self,
        config: SandboxConfig,
        desired: DesiredState,
    ) -> Result<SandboxId, BackendError> {
        self.ensure_ready()?;
        let id = self.alloc_id();
        let driver = self.factory.build(&id, &config);
        let now = rfc3339_now();
        let record = PersistedRecord {
            id: id.clone(),
            config,
            desired,
            generation: 1,
            state: None,
            observed_generation: 0,
            pid: None,
            pid_start_time: None,
            rootfs_path: None,
            reason: None,
            message: None,
            entrypoint_exit: None,
            created_at: now.clone(),
            last_transition_at: now,
        };

        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (view_tx, view_rx) = watch::channel(view_of(&record));
        let (entrypoint_exit_tx, entrypoint_exit_rx) =
            watch::channel(record.entrypoint_exit.clone());
        let (events_tx, _) = broadcast::channel(64);
        let poisoned = Arc::new(AtomicBool::new(false));
        let entry = SharedEntry {
            cmd_tx: cmd_tx.clone(),
            view_rx,
            events_tx: events_tx.clone(),
            entrypoint_exit_rx,
            poisoned: poisoned.clone(),
        };

        let (ack_tx, ack_rx) = oneshot::channel();
        let actor = Actor {
            record,
            running_vm: None,
            rootfs: None,
            pending_rollback: None,
            pending_entrypoint_exit: None,
            entrypoint_coupling: false,
            driver,
            store: self.store.clone(),
            cmd_rx,
            self_cmd_tx: cmd_tx,
            view_tx,
            entrypoint_exit_tx,
            events_tx,
            poisoned,
            map: self.map.clone(),
            shutdown: self.shutdown.clone(),
            genesis: Some((entry, ack_tx)),
        };
        tokio::spawn(actor.run());

        match ack_rx.await {
            Ok(result) => result.map(|()| id),
            Err(_) => Err(BackendError::Internal("actor dropped".into())),
        }
    }

    pub async fn set_desired(
        &self,
        id: &SandboxId,
        verb: Verb,
        desired: DesiredState,
    ) -> Result<(), BackendError> {
        self.ensure_ready()?;
        let cmd_tx = {
            let map = self.map.read().unwrap();
            let entry = map.get(id).ok_or(BackendError::NotFound)?;
            if entry.poisoned.load(Ordering::Acquire) {
                return Err(BackendError::Internal("sandbox actor poisoned".into()));
            }
            entry.cmd_tx.clone()
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if cmd_tx
            .send(ReconcileCommand::SetDesired {
                verb,
                desired,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            return Err(BackendError::Internal("sandbox actor gone".into()));
        }
        match ack_rx.await {
            Ok(result) => result,
            Err(_) => Err(BackendError::Internal("actor dropped ack".into())),
        }
    }

    pub fn status(&self, id: &SandboxId) -> Result<SandboxView, BackendError> {
        let map = self.map.read().unwrap();
        let entry = map.get(id).ok_or(BackendError::NotFound)?;
        if entry.poisoned.load(Ordering::Acquire) {
            return Err(BackendError::Internal("sandbox actor poisoned".into()));
        }
        Ok(entry.view_rx.borrow().clone())
    }

    pub fn list(&self) -> Vec<SandboxView> {
        let map = self.map.read().unwrap();
        map.values()
            .filter(|e| !e.poisoned.load(Ordering::Acquire))
            .map(|e| e.view_rx.borrow().clone())
            .collect()
    }

    /// The backend-only main-process exit carrier for one sandbox, read off the
    /// per-sandbox watch channel (seeded from the persisted record). Backend
    /// implementations delegate here so the read path is backend-agnostic.
    pub fn entrypoint_exit(&self, id: &SandboxId) -> Result<Option<EntrypointExit>, BackendError> {
        let map = self.map.read().unwrap();
        let entry = map.get(id).ok_or(BackendError::NotFound)?;
        if entry.poisoned.load(Ordering::Acquire) {
            return Err(BackendError::Internal("sandbox actor poisoned".into()));
        }
        Ok(entry.entrypoint_exit_rx.borrow().clone())
    }

    pub fn subscribe(
        &self,
        id: &SandboxId,
    ) -> Result<broadcast::Receiver<SandboxStatus>, BackendError> {
        let map = self.map.read().unwrap();
        let entry = map.get(id).ok_or(BackendError::NotFound)?;
        if entry.poisoned.load(Ordering::Acquire) {
            return Err(BackendError::Internal("sandbox actor poisoned".into()));
        }
        Ok(entry.events_tx.subscribe())
    }

    /// Reconstruct sandbox actors from the durable store. Must run inside a
    /// Tokio runtime, before serving.
    pub async fn recover(&self) -> Result<(), BackendError> {
        // Recovery is INIT-ONLY and runs before any sandbox exists. Move
        // NotRecovered -> Recovering: this rejects a second recover() and a
        // recover() on a non-recoverable (already-Ready) runtime, and subsumes
        // the old init-only latch. Also refuse if any actor is already live so
        // recovery can never replace an existing sandbox's actor.
        if self
            .state
            .compare_exchange(
                STATE_NOT_RECOVERED,
                STATE_RECOVERING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return Err(BackendError::Internal(
                "recover() already ran or runtime is not recoverable".into(),
            ));
        }
        if !self.map.read().unwrap().is_empty() {
            return Err(BackendError::Internal(
                "recover() cannot run after sandboxes already exist".into(),
            ));
        }
        let store = self.store.clone();
        let records = tokio::task::spawn_blocking(move || store.load_all())
            .await
            .map_err(|e| BackendError::Internal(format!("recover join: {e}")))?
            .map_err(|e| BackendError::Internal(format!("load store: {e}")))?;

        // Never reuse a recovered id. If the highest recovered id is already
        // u64::MAX the id space is exhausted: fail recovery loudly rather than
        // wrap to 0 and reuse/overwrite an existing recovered id.
        let mut max_n = 0u64;
        for record in &records {
            if let Some(n) = record.id.0.strip_prefix("sb-").and_then(|s| s.parse().ok()) {
                max_n = max_n.max(n);
            }
        }
        let next = max_n
            .checked_add(1)
            .ok_or_else(|| BackendError::Internal("recovered sandbox id space exhausted".into()))?;
        self.next_sandbox.store(next, Ordering::Relaxed);

        // Recovery pass: kill/verify leftover VMs, recover rootfs and normalize
        // EVERY record IN MEMORY with NO durable writes. If any record's
        // kill-verify or rootfs recovery fails the whole pass aborts here, so
        // state.json is left byte-unchanged and no actor is spawned.
        let mut prepared = Vec::with_capacity(records.len());
        let mut normalized = Vec::with_capacity(records.len());
        let mut any_changed = false;
        for mut record in records {
            // Defense-in-depth reaper: kill a VM that somehow outlived the
            // daemon, then confirm it is actually gone before serving the
            // sandbox as not-running. Reporting Stopped/teardown-ready while the
            // old VM is still alive would let the workload double-run.
            if let (Some(pid), Some(start)) = (record.pid, record.pid_start_time)
                && verify_pid(pid, start)
            {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                await_pid_death(&record.id, || verify_pid(pid, start), RECOVER_KILL_TIMEOUT)
                    .await?;
            }

            let driver = self.factory.build(&record.id, &record.config);
            let rootfs = VmDriverSend::recover_rootfs(&driver, &record)?;

            // Normalize the record against reality before serving, persisting any
            // change. Two cases:
            //  - The recorded rootfs is gone from disk (crash/incomplete provision):
            //    reset to a reprovisionable genesis so a later start rebuilds it
            //    instead of failing forever against a missing rootfs.
            //  - A recovered Running record has no live VM (no re-attach), so it is
            //    dead by construction: settle it by intent.
            let changed = if record.rootfs_path.is_some() && rootfs.is_none() {
                record.state = None;
                record.rootfs_path = None;
                record.pid = None;
                record.pid_start_time = None;
                record.reason = None;
                record.message = None;
                record.entrypoint_exit = None;
                record.observed_generation = 0;
                record.last_transition_at = rfc3339_now();
                true
            } else {
                normalize_recovered(&mut record)
            };
            any_changed |= changed;
            normalized.push(record.clone());
            prepared.push((record, driver, rootfs));
        }

        // Atomic persistence pass: only after ALL records pass, commit the COMPLETE normalized
        // map in ONE atomic store write (not N interleaved upserts). Skipped
        // when nothing changed so a clean recovery leaves state.json untouched.
        if any_changed {
            persist_all(self.store.clone(), normalized)
                .await
                .map_err(|e| BackendError::Internal(format!("persist recovered: {e}")))?;
        }

        // Publish pass: durable state committed and every leftover VM confirmed dead
        // — now publish map entries and spawn one actor per sandbox.
        for (record, driver, rootfs) in prepared {
            let (cmd_tx, cmd_rx) = mpsc::channel(16);
            let (view_tx, view_rx) = watch::channel(view_of(&record));
            let (entrypoint_exit_tx, entrypoint_exit_rx) =
                watch::channel(record.entrypoint_exit.clone());
            let (events_tx, _) = broadcast::channel(64);
            let poisoned = Arc::new(AtomicBool::new(false));
            let entry = SharedEntry {
                cmd_tx: cmd_tx.clone(),
                view_rx,
                events_tx: events_tx.clone(),
                entrypoint_exit_rx,
                poisoned: poisoned.clone(),
            };
            self.map.write().unwrap().insert(record.id.clone(), entry);

            let actor = Actor {
                record,
                running_vm: None,
                rootfs,
                pending_rollback: None,
                pending_entrypoint_exit: None,
                entrypoint_coupling: false,
                driver,
                store: self.store.clone(),
                cmd_rx,
                self_cmd_tx: cmd_tx,
                view_tx,
                entrypoint_exit_tx,
                events_tx,
                poisoned,
                map: self.map.clone(),
                shutdown: self.shutdown.clone(),
                genesis: None,
            };
            tokio::spawn(actor.run());
        }
        // Recovery fully succeeded; accept create()/set_desired() now. A
        // mid-recovery abort returns Err above with state left at Recovering
        // (fail-stop), so create/set_desired stay rejected with a clear error.
        self.state.store(STATE_READY, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The per-sandbox actor
// ---------------------------------------------------------------------------

struct Actor<D: VmDriverSend> {
    record: PersistedRecord,
    running_vm: Option<D::RunningVm>,
    rootfs: Option<D::RootfsHandle>,
    /// A rootfs whose rollback cleanup keeps failing; retried each tick.
    pending_rollback: Option<D::RootfsHandle>,
    /// A main-process exit awaiting coupling. Held in memory only (never
    /// persisted) until the final terminal commit takes it; discarded if a
    /// stop/destroy supersedes.
    pending_entrypoint_exit: Option<EntrypointExit>,
    /// Set when the apply step has run the graceful-shutdown coupling for a
    /// stashed exit (the VM was still alive when the host applied it — the
    /// real-exit signature). Gates whether the following crash commit carries the
    /// outcome, so a spontaneous crash whose synthetic terminal raced ahead never
    /// manufactures a carrier.
    entrypoint_coupling: bool,
    driver: D,
    store: Arc<dyn Store>,
    cmd_rx: mpsc::Receiver<ReconcileCommand>,
    /// A clone of this sandbox's command sender, used to build the
    /// `EntrypointExitSink` handed to each `start`.
    self_cmd_tx: mpsc::Sender<ReconcileCommand>,
    view_tx: watch::Sender<SandboxView>,
    entrypoint_exit_tx: watch::Sender<Option<EntrypointExit>>,
    events_tx: broadcast::Sender<SandboxStatus>,
    poisoned: Arc<AtomicBool>,
    map: SharedMap,
    shutdown: CancellationToken,
    genesis: Option<(SharedEntry, oneshot::Sender<Result<(), BackendError>>)>,
}

impl<D: VmDriverSend + Send + 'static> Actor<D> {
    async fn run(mut self) {
        if let Some((entry, ack)) = self.genesis.take() {
            // Cancel-before-commit: caller's future dropped before any durable
            // effect -> no record, no map entry.
            if ack.is_closed() {
                return;
            }
            if let Err(e) = persist_record(self.store.clone(), self.record.clone()).await {
                let _ = ack.send(Err(BackendError::Internal(format!("persist genesis: {e}"))));
                return;
            }
            // Publish strictly after the genesis fsync, even if the ack receiver
            // was already dropped (cancel-after-commit completes).
            self.map
                .write()
                .unwrap()
                .insert(self.record.id.clone(), entry);
            self.publish_view();
            let _ = ack.send(Ok(()));
        }

        self.reconcile_until_settled().await;
        if self.stopped() {
            return;
        }

        let mut tick = tokio::time::interval(LIVENESS_POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => return,
                maybe = self.cmd_rx.recv() => match maybe {
                    Some(cmd) => {
                        self.accept_command(cmd).await;
                        self.reconcile_until_settled().await;
                        if self.stopped() { return; }
                    }
                    None => return,
                },
                _ = tick.tick() => {
                    if self.poisoned.load(Ordering::Acquire) {
                        self.retry_rollback().await;
                        if self.stopped() { return; }
                    } else {
                        self.reconcile_until_settled().await;
                        if self.stopped() { return; }
                    }
                }
            }
        }
    }

    /// A poisoned actor with no outstanding rollback has nothing left to do.
    fn stopped(&self) -> bool {
        self.poisoned.load(Ordering::Acquire) && self.pending_rollback.is_none()
    }

    fn view(&self) -> SandboxView {
        view_of(&self.record)
    }

    fn status(&self) -> SandboxStatus {
        view_of(&self.record).status
    }

    /// Publish the view (wire-facing) and the backend-only exit carrier together,
    /// keeping both watch channels in sync with the committed record.
    fn publish_view(&self) {
        let _ = self.view_tx.send(self.view());
        let _ = self
            .entrypoint_exit_tx
            .send(self.record.entrypoint_exit.clone());
    }

    /// Fsync the record then publish the view. Use for a committed transition.
    async fn commit(&mut self) -> io::Result<()> {
        persist_record(self.store.clone(), self.record.clone()).await?;
        self.publish_view();
        Ok(())
    }

    fn broadcast(&self) {
        let _ = self.events_tx.send(self.status());
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Validate, bump generation, fsync, then publish + ack — in that order, so
    /// a reader never observes non-durable intent.
    async fn accept_command(&mut self, cmd: ReconcileCommand) {
        accept_command_into(
            &mut self.record,
            &self.store,
            &self.view_tx,
            &mut self.pending_entrypoint_exit,
            cmd,
        )
        .await;
    }

    async fn drain_commands(&mut self) {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            self.accept_command(cmd).await;
        }
    }

    async fn reconcile_until_settled(&mut self) {
        loop {
            if self.poisoned.load(Ordering::Acquire) || self.shutdown.is_cancelled() {
                return;
            }
            self.observe_liveness().await;
            if self.poisoned.load(Ordering::Acquire) {
                return;
            }
            // A stashed main-process exit couples the VM down here; re-loop so the
            // following observe_liveness commits the terminal + carrier.
            if self.couple_pending_entrypoint_exit().await {
                continue;
            }
            let attempted_gen = self.record.generation;
            let action = next_action(
                self.record.state,
                self.record.desired,
                self.record.reason,
                self.rootfs.is_some(),
                self.record.generation,
                self.record.observed_generation,
            );
            match action {
                ReconcileAction::Settled => {
                    self.converge().await;
                    return;
                }
                ReconcileAction::Provision => self.do_provision(attempted_gen).await,
                ReconcileAction::Start => self.do_start(attempted_gen).await,
                ReconcileAction::Stop => self.do_stop(attempted_gen).await,
                ReconcileAction::Teardown => self.do_teardown(attempted_gen).await,
            }
            self.drain_commands().await;
        }
    }

    /// Mark convergence (observed = generation) with no driver work. A failure
    /// here has no side effect to undo, so it simply retries on the next tick.
    async fn converge(&mut self) {
        if self.record.observed_generation == self.record.generation {
            return;
        }
        let prev = self.record.observed_generation;
        self.record.observed_generation = self.record.generation;
        if self.commit().await.is_err() {
            self.record.observed_generation = prev;
        }
    }

    /// If a main-process exit is stashed and the VM is still running as intended,
    /// bring it down gracefully (command-live, so a concurrent stop/destroy is
    /// still accepted) and retain the handle. Returns true if it ran the coupling,
    /// so the caller re-loops and the following `observe_liveness` commits the
    /// terminal state and writes the carrier.
    async fn couple_pending_entrypoint_exit(&mut self) -> bool {
        if self.pending_entrypoint_exit.is_none()
            || self.record.state != Some(State::Running)
            || self.record.desired != DesiredState::Running
            || self.running_vm.is_none()
        {
            return false;
        }
        // Latch the coupling so the crash commit carries the outcome (the VM was
        // alive when we applied the exit — the real-exit signature).
        self.entrypoint_coupling = true;
        let vm = self.running_vm.as_mut().expect("running_vm checked above");
        let fut = self.driver.graceful_shutdown(vm);
        drive_action(
            &mut self.cmd_rx,
            &mut self.record,
            &self.store,
            &self.view_tx,
            &mut self.pending_entrypoint_exit,
            &self.shutdown,
            fut,
        )
        .await;
        true
    }

    /// A `Running` VM that died: release resources and transition by intent.
    async fn observe_liveness(&mut self) {
        if self.record.state != Some(State::Running) {
            return;
        }
        let dead = match self.running_vm.as_mut() {
            None => true,
            Some(vm) => !self.driver.is_alive(vm),
        };
        if !dead {
            return;
        }
        self.running_vm = None;
        self.record.pid = None;
        self.record.pid_start_time = None;
        self.record.last_transition_at = rfc3339_now();
        // A coupled main-process exit carries its outcome onto the crash commit;
        // an uncoupled death (a spontaneous crash, whose synthetic terminal may
        // have raced a stash in ahead of us) settles plain crashed with no
        // carrier. Either way the in-memory stash is discarded here.
        let coupled_outcome = if self.entrypoint_coupling {
            self.pending_entrypoint_exit.take()
        } else {
            None
        };
        self.pending_entrypoint_exit = None;
        self.entrypoint_coupling = false;
        match self.record.desired {
            DesiredState::Running => {
                self.record.state = Some(State::Failed);
                self.record.reason = Some(FailureReason::Crashed);
                self.record.message = Some("vm exited unexpectedly".into());
                self.record.entrypoint_exit = coupled_outcome;
                self.record.observed_generation = self.record.generation;
            }
            DesiredState::Stopped => {
                self.record.state = Some(State::Stopped);
                self.record.reason = None;
                self.record.message = None;
                self.record.entrypoint_exit = None;
                self.record.observed_generation = self.record.generation;
            }
            // Never persist a pid-less Running: commit Stopped first, keep the
            // generation gap open, then fall through to teardown.
            DesiredState::Destroyed => {
                self.record.state = Some(State::Stopped);
                self.record.reason = None;
                self.record.message = None;
                self.record.entrypoint_exit = None;
            }
        }
        if self.commit().await.is_err() {
            self.poison();
            return;
        }
        self.broadcast();
    }

    async fn do_provision(&mut self, attempted_gen: u64) {
        let cfg = self.record.config.clone();
        let outcome = {
            let fut = self.driver.provision(&cfg);
            drive_action(
                &mut self.cmd_rx,
                &mut self.record,
                &self.store,
                &self.view_tx,
                &mut self.pending_entrypoint_exit,
                &self.shutdown,
                fut,
            )
            .await
        };
        let Some(result) = outcome else {
            return;
        };
        match result {
            Ok(rootfs) => {
                let prior = self.record.clone();
                self.record.state = Some(State::Stopped);
                self.record.rootfs_path = Some(rootfs.rootfs_path().to_path_buf());
                self.record.reason = None;
                self.record.message = None;
                self.record.entrypoint_exit = None;
                self.record.last_transition_at = rfc3339_now();
                match persist_record(self.store.clone(), self.record.clone()).await {
                    Ok(()) => {
                        self.rootfs = Some(rootfs);
                        self.publish_view();
                        self.broadcast();
                    }
                    Err(_) => {
                        self.record = prior;
                        self.rollback_rootfs(rootfs).await;
                    }
                }
            }
            Err(e) => {
                self.fail_or_discard(attempted_gen, FailureReason::ProvisionFailed, e)
                    .await
            }
        }
    }

    async fn do_start(&mut self, attempted_gen: u64) {
        // A fresh run must never inherit a prior run's stashed exit. Any pending
        // outcome reaching here belongs to an abandoned run (a start that failed,
        // or a stop/destroy that superseded the coupling before it ran), so clear
        // it before launching — only an exit produced by THIS run (stashed during
        // the start below) can then couple it down.
        self.pending_entrypoint_exit = None;
        self.entrypoint_coupling = false;

        let cfg = self.record.config.clone();
        let Some(rootfs) = self.rootfs.as_ref() else {
            self.fail_or_discard(
                attempted_gen,
                FailureReason::StartFailed,
                BackendError::Internal("no rootfs to start".into()),
            )
            .await;
            return;
        };
        let outcome = {
            let sink = EntrypointExitSink(self.self_cmd_tx.clone());
            let fut = self.driver.start(&cfg, rootfs, sink);
            drive_action(
                &mut self.cmd_rx,
                &mut self.record,
                &self.store,
                &self.view_tx,
                &mut self.pending_entrypoint_exit,
                &self.shutdown,
                fut,
            )
            .await
        };
        let Some(result) = outcome else {
            return;
        };
        match result {
            Ok(vm) => {
                let prior = self.record.clone();
                self.record.state = Some(State::Running);
                self.record.pid = Some(vm.pid());
                self.record.pid_start_time = Some(vm.pid_start_time());
                self.record.reason = None;
                self.record.message = None;
                self.record.entrypoint_exit = None;
                self.record.last_transition_at = rfc3339_now();
                match persist_record(self.store.clone(), self.record.clone()).await {
                    Ok(()) => {
                        self.running_vm = Some(vm);
                        self.publish_view();
                        self.broadcast();
                    }
                    Err(_) => {
                        self.record = prior;
                        // The forked VM was never recorded: kill it, then poison.
                        self.driver.stop(vm).await;
                        self.poison();
                    }
                }
            }
            Err(e) => {
                self.fail_or_discard(attempted_gen, FailureReason::StartFailed, e)
                    .await
            }
        }
    }

    async fn do_stop(&mut self, _attempted_gen: u64) {
        if let Some(vm) = self.running_vm.take() {
            let fut = self.driver.stop(vm);
            if drive_action(
                &mut self.cmd_rx,
                &mut self.record,
                &self.store,
                &self.view_tx,
                &mut self.pending_entrypoint_exit,
                &self.shutdown,
                fut,
            )
            .await
            .is_none()
            {
                return;
            }
        }
        self.record.state = Some(State::Stopped);
        self.record.pid = None;
        self.record.pid_start_time = None;
        self.record.reason = None;
        self.record.message = None;
        self.record.entrypoint_exit = None;
        self.record.last_transition_at = rfc3339_now();
        if self.commit().await.is_err() {
            self.poison();
            return;
        }
        self.broadcast();
    }

    async fn do_teardown(&mut self, attempted_gen: u64) {
        let vm = self.running_vm.take();
        let rootfs = self.rootfs.take();
        let outcome = {
            let fut = self.driver.teardown(vm, rootfs);
            drive_action(
                &mut self.cmd_rx,
                &mut self.record,
                &self.store,
                &self.view_tx,
                &mut self.pending_entrypoint_exit,
                &self.shutdown,
                fut,
            )
            .await
        };
        let Some(result) = outcome else {
            return;
        };
        match result {
            Ok(()) => {
                self.record.state = Some(State::Destroyed);
                self.record.observed_generation = self.record.generation;
                self.record.pid = None;
                self.record.pid_start_time = None;
                self.record.rootfs_path = None;
                self.record.reason = None;
                self.record.message = None;
                self.record.entrypoint_exit = None;
                self.record.last_transition_at = rfc3339_now();
                if self.commit().await.is_err() {
                    self.poison();
                    return;
                }
                self.broadcast();
            }
            Err((e, returned)) => {
                self.rootfs = returned;
                // The VM was consumed/killed by teardown; clear its pid so the
                // persisted record stays valid (a pid implies Running).
                self.record.pid = None;
                self.record.pid_start_time = None;
                if attempted_gen == self.record.generation {
                    self.record.state = Some(State::Failed);
                    self.record.reason = Some(FailureReason::DestroyFailed);
                    self.record.message = Some(e.to_string());
                    self.record.entrypoint_exit = None;
                    self.record.observed_generation = attempted_gen;
                    self.record.last_transition_at = rfc3339_now();
                    if self.commit().await.is_err() {
                        self.poison();
                        return;
                    }
                    self.broadcast();
                } else {
                    // Superseded by another destroy mid-teardown: the VM is
                    // reaped, so settle a valid destroy-pending shape and let the
                    // loop retry. Choose the state by whether a rootfs remains so
                    // the record stays valid (Stopped requires a rootfs; a
                    // no-rootfs sandbox settles back to genesis). Clear any prior
                    // failure detail — a non-Failed state carries no reason.
                    self.record.state = if self.record.rootfs_path.is_some() {
                        Some(State::Stopped)
                    } else {
                        None
                    };
                    self.record.reason = None;
                    self.record.message = None;
                    self.record.entrypoint_exit = None;
                    self.record.observed_generation = attempted_gen;
                    self.record.last_transition_at = rfc3339_now();
                    let _ = self.commit().await;
                }
            }
        }
    }

    /// Latch a terminal failure iff the attempt still matches the current
    /// generation; otherwise the verb was superseded — discard, don't latch.
    async fn fail_or_discard(
        &mut self,
        attempted_gen: u64,
        reason: FailureReason,
        e: BackendError,
    ) {
        if attempted_gen == self.record.generation {
            self.record.state = Some(State::Failed);
            self.record.reason = Some(reason);
            self.record.message = Some(e.to_string());
            self.record.entrypoint_exit = None;
            self.record.observed_generation = attempted_gen;
            self.record.last_transition_at = rfc3339_now();
            if self.commit().await.is_err() {
                self.poison();
                return;
            }
            self.broadcast();
        } else {
            self.record.observed_generation = attempted_gen;
            let _ = self.commit().await;
        }
    }

    /// Clean up a rootfs that was built but never durably recorded, then poison.
    /// If cleanup keeps failing the actor stays alive holding the handle and
    /// retries each tick so the resource stays tracked.
    async fn rollback_rootfs(&mut self, rootfs: D::RootfsHandle) {
        self.poison();
        if let Err((_, returned)) = self.driver.teardown(None, Some(rootfs)).await {
            self.pending_rollback = returned;
        }
    }

    async fn retry_rollback(&mut self) {
        if let Some(rootfs) = self.pending_rollback.take()
            && let Err((_, returned)) = self.driver.teardown(None, Some(rootfs)).await
        {
            self.pending_rollback = returned;
        }
    }
}

fn view_of(record: &PersistedRecord) -> SandboxView {
    SandboxView {
        status: SandboxStatus {
            sandbox_id: record.id.clone(),
            state: record.state,
            desired: record.desired,
            generation: record.generation,
            observed_generation: record.observed_generation,
            reason: record.reason,
            message: record.message.clone(),
            created_at: Some(record.created_at.clone()),
            last_transition_at: Some(record.last_transition_at.clone()),
        },
        config: record.config.clone(),
    }
}

/// A store write whose atomic rename succeeded but whose directory fsync failed
/// is already COMMITTED on disk. Treating it as a failure would make the caller
/// roll back in memory while disk holds the new record — diverging the two and
/// letting a rejected intent resurrect on restart. So map that committed write
/// to success and surface only the degraded crash-durability as a warning.
fn settle_persist(label: &str, result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if crate::store::is_committed_unsynced_error(&e) => {
            tracing::warn!("{label}: {e}");
            Ok(())
        }
        other => other,
    }
}

/// Fsync a record off the actor's thread without borrowing the actor across
/// the await (keeping the actor future `Send`).
async fn persist_record(store: Arc<dyn Store>, record: PersistedRecord) -> io::Result<()> {
    let id = record.id.0.clone();
    let result = tokio::task::spawn_blocking(move || store.upsert(&record))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)));
    settle_persist(&id, result)
}

/// Commit the WHOLE normalized record set in one atomic store write (recovery's
/// single durable commit), off the async runtime's thread.
async fn persist_all(store: Arc<dyn Store>, records: Vec<PersistedRecord>) -> io::Result<()> {
    let result = tokio::task::spawn_blocking(move || store.replace_all(&records))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e)));
    settle_persist("recovery commit", result)
}

/// Apply the dead-VM transition to a recovered `Running` record (it has no live
/// handle, so it is dead by construction). Mirrors `observe_liveness`'s dead
/// branch. Returns true if the record changed.
fn normalize_recovered(record: &mut PersistedRecord) -> bool {
    if record.state != Some(State::Running) {
        return false;
    }
    record.pid = None;
    record.pid_start_time = None;
    record.last_transition_at = rfc3339_now();
    // A recovered Running record carries no observed exit (the VM was SIGKILLed
    // on restart), so it normalizes to plain crashed/stopped with no carrier. A
    // genuine Failed(Crashed)+Some record is not a Running record, so it is left
    // untouched (this function only acts on Running) and its carrier is preserved.
    record.entrypoint_exit = None;
    match record.desired {
        DesiredState::Running => {
            record.state = Some(State::Failed);
            record.reason = Some(FailureReason::Crashed);
            record.message = Some("vm exited unexpectedly".into());
            record.observed_generation = record.generation;
        }
        DesiredState::Stopped => {
            record.state = Some(State::Stopped);
            record.reason = None;
            record.message = None;
            record.observed_generation = record.generation;
        }
        DesiredState::Destroyed => {
            record.state = Some(State::Stopped);
            record.reason = None;
            record.message = None;
        }
    }
    true
}

/// Accept a command into the record: validate, bump generation, fsync, then
/// publish + ack. Borrows only record/store/view fields so it can run while a
/// driver action borrows the driver.
async fn accept_command_into(
    record: &mut PersistedRecord,
    store: &Arc<dyn Store>,
    view_tx: &watch::Sender<SandboxView>,
    pending_entrypoint_exit: &mut Option<EntrypointExit>,
    cmd: ReconcileCommand,
) {
    let (verb, desired, ack) = match cmd {
        ReconcileCommand::SetDesired { verb, desired, ack } => (verb, desired, ack),
        ReconcileCommand::EntrypointExited { outcome } => {
            // Only couple while the caller still wants the sandbox running; a
            // stop/destroy that already flipped the intent wins, and a late exit
            // is dropped (the box still reaches its terminal state).
            if record.desired == DesiredState::Running {
                *pending_entrypoint_exit = Some(outcome);
            }
            return;
        }
    };
    if ack.is_closed() {
        return;
    }
    if !precondition_ok(record.state, record.desired, record.reason, verb) {
        let _ = ack.send(Err(BackendError::InvalidState));
        return;
    }
    let prev_gen = record.generation;
    let prev_desired = record.desired;
    record.generation += 1;
    record.desired = desired;
    match persist_record(store.clone(), record.clone()).await {
        Ok(()) => {
            let _ = view_tx.send(view_of(record));
            let _ = ack.send(Ok(()));
        }
        Err(e) => {
            record.generation = prev_gen;
            record.desired = prev_desired;
            let _ = ack.send(Err(BackendError::Internal(format!("persist: {e}"))));
        }
    }
}

/// Drive an in-flight driver action to completion while keeping the command
/// path live, so a command arriving mid-action is accepted (persisted + acked)
/// immediately. Returns `None` on shutdown (the action future is dropped). The
/// future is polled to completion — never restarted — and borrows only the
/// driver, disjoint from the accept path, so the actor stays the sole
/// sequential writer of the record.
#[allow(clippy::too_many_arguments)]
async fn drive_action<T>(
    cmd_rx: &mut mpsc::Receiver<ReconcileCommand>,
    record: &mut PersistedRecord,
    store: &Arc<dyn Store>,
    view_tx: &watch::Sender<SandboxView>,
    pending_entrypoint_exit: &mut Option<EntrypointExit>,
    shutdown: &CancellationToken,
    fut: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::pin!(fut);
    let mut closed = false;
    loop {
        tokio::select! {
            out = &mut fut => return Some(out),
            _ = shutdown.cancelled() => return None,
            maybe = cmd_rx.recv(), if !closed => match maybe {
                Some(cmd) => {
                    accept_command_into(record, store, view_tx, pending_entrypoint_exit, cmd).await
                }
                None => closed = true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;
    use crate::types::{NetworkPolicy, ResourceLimits};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn cfg() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "img".into(),
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

    // --- Controllable test driver ----------------------------------------

    #[derive(Clone, Default)]
    struct Ctl {
        provision_fail: Arc<AtomicBool>,
        start_fail: Arc<AtomicBool>,
        teardown_fail: Arc<AtomicBool>,
        provision_hold: Arc<AtomicBool>,
        start_hold: Arc<AtomicBool>,
        teardown_hold: Arc<AtomicBool>,
        rootfs_missing: Arc<AtomicBool>,
        alive: Arc<AtomicBool>,
        graceful_hold: Arc<AtomicBool>,
        provisions: Arc<AtomicU64>,
        starts: Arc<AtomicU64>,
        teardowns: Arc<AtomicU64>,
        graceful_shutdowns: Arc<AtomicU64>,
        /// The most recent exit sink handed to `start`, so a test can post a
        /// main-process exit into the actor.
        entrypoint_sink: Arc<std::sync::Mutex<Option<EntrypointExitSink>>>,
        /// Sandbox ids whose `recover_rootfs` should fail (per-record recovery
        /// failure injection for the two-phase recovery test).
        recover_fail_ids: Arc<std::sync::Mutex<Vec<String>>>,
    }

    async fn spin_while(flag: &Arc<AtomicBool>) {
        while flag.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    struct TestVm {
        pid: i32,
        start: u64,
        alive: Arc<AtomicBool>,
    }
    impl RunningVmHandle for TestVm {
        fn pid(&self) -> i32 {
            self.pid
        }
        fn pid_start_time(&self) -> u64 {
            self.start
        }
    }

    struct TestRootfs {
        root: PathBuf,
        session: PathBuf,
    }
    impl RootfsHandleExt for TestRootfs {
        fn rootfs_path(&self) -> &Path {
            &self.root
        }
        fn session_dir(&self) -> &Path {
            &self.session
        }
    }

    struct TestDriver {
        ctl: Ctl,
        session: PathBuf,
    }

    impl VmDriverSend for TestDriver {
        type RunningVm = TestVm;
        type RootfsHandle = TestRootfs;

        async fn provision(&mut self, _cfg: &SandboxConfig) -> Result<TestRootfs, BackendError> {
            self.ctl.provisions.fetch_add(1, Ordering::Relaxed);
            spin_while(&self.ctl.provision_hold).await;
            if self.ctl.provision_fail.load(Ordering::Acquire) {
                return Err(BackendError::Internal("provision".into()));
            }
            Ok(TestRootfs {
                root: self.session.join("rootfs"),
                session: self.session.clone(),
            })
        }

        async fn start(
            &mut self,
            _cfg: &SandboxConfig,
            _rootfs: &TestRootfs,
            sink: EntrypointExitSink,
        ) -> Result<TestVm, BackendError> {
            self.ctl.starts.fetch_add(1, Ordering::Relaxed);
            *self.ctl.entrypoint_sink.lock().unwrap() = Some(sink);
            spin_while(&self.ctl.start_hold).await;
            if self.ctl.start_fail.load(Ordering::Acquire) {
                return Err(BackendError::Internal("start".into()));
            }
            self.ctl.alive.store(true, Ordering::Release);
            Ok(TestVm {
                pid: 1_000_000,
                start: 0,
                alive: self.ctl.alive.clone(),
            })
        }

        async fn stop(&mut self, _vm: TestVm) {}

        async fn graceful_shutdown(&self, vm: &mut TestVm) {
            self.ctl.graceful_shutdowns.fetch_add(1, Ordering::Relaxed);
            spin_while(&self.ctl.graceful_hold).await;
            // The controlled console-close makes the guest self-exit: the VM goes
            // dead, which the following liveness observation commits.
            vm.alive.store(false, Ordering::Release);
        }

        async fn teardown(
            &mut self,
            _vm: Option<TestVm>,
            rootfs: Option<TestRootfs>,
        ) -> Result<(), (BackendError, Option<TestRootfs>)> {
            self.ctl.teardowns.fetch_add(1, Ordering::Relaxed);
            spin_while(&self.ctl.teardown_hold).await;
            if self.ctl.teardown_fail.load(Ordering::Acquire) {
                return Err((BackendError::Internal("teardown".into()), rootfs));
            }
            Ok(())
        }

        fn recover_rootfs(
            &self,
            record: &PersistedRecord,
        ) -> Result<Option<TestRootfs>, BackendError> {
            if self
                .ctl
                .recover_fail_ids
                .lock()
                .unwrap()
                .iter()
                .any(|id| id == &record.id.0)
            {
                return Err(BackendError::Internal("recover_rootfs".into()));
            }
            // Simulate the canonical rootfs dir being gone from disk.
            if self.ctl.rootfs_missing.load(Ordering::Acquire) {
                return Ok(None);
            }
            Ok(record.rootfs_path.as_ref().map(|root| TestRootfs {
                root: root.clone(),
                session: self.session.clone(),
            }))
        }

        fn is_alive(&self, vm: &mut TestVm) -> bool {
            vm.alive.load(Ordering::Acquire)
        }
    }

    struct TestFactory {
        ctl: Ctl,
        base: PathBuf,
    }
    impl DriverFactory for TestFactory {
        type Driver = TestDriver;
        fn build(&self, id: &SandboxId, _config: &SandboxConfig) -> TestDriver {
            TestDriver {
                ctl: self.ctl.clone(),
                session: self.base.join(&id.0),
            }
        }
    }

    fn runtime(ctl: Ctl, store: Arc<dyn Store>) -> ReconcileRuntime<TestFactory> {
        let base = std::env::temp_dir().join(format!(
            "pp-recon-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        ReconcileRuntime::new(TestFactory { ctl, base }, store)
    }

    fn recoverable_runtime(ctl: Ctl, store: Arc<dyn Store>) -> ReconcileRuntime<TestFactory> {
        let base = std::env::temp_dir().join(format!(
            "pp-recon-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        ReconcileRuntime::new_recoverable(TestFactory { ctl, base }, store)
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    async fn await_view<F: DriverFactory>(
        rt: &ReconcileRuntime<F>,
        id: &SandboxId,
        pred: impl Fn(&SandboxView) -> bool,
    ) -> SandboxView {
        for _ in 0..400 {
            if let Ok(v) = rt.status(id)
                && pred(&v)
            {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "timed out: last = {:?}",
            rt.status(id).map(|v| v.status.state)
        );
    }

    // --- Fault-injecting store -------------------------------------------

    struct FaultStore {
        inner: InMemoryStore,
        fail_after: AtomicU64,
    }
    impl FaultStore {
        fn new(fail_after: u64) -> Self {
            Self {
                inner: InMemoryStore::new(),
                fail_after: AtomicU64::new(fail_after),
            }
        }
    }
    impl Store for FaultStore {
        fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
            if self.fail_after.load(Ordering::Acquire) == 0 {
                return Err(io::Error::other("injected"));
            }
            self.fail_after.fetch_sub(1, Ordering::AcqRel);
            self.inner.upsert(record)
        }
        fn delete(&self, id: &SandboxId) -> io::Result<()> {
            self.inner.delete(id)
        }
        fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
            self.inner.load_all()
        }
        fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
            self.inner.replace_all(records)
        }
    }

    /// Wraps an in-memory store and flags if any upsert ever persists a record
    /// that fails the store's load-time validation invariants.
    struct ValidatingStore {
        inner: InMemoryStore,
        saw_invalid: Arc<AtomicBool>,
    }
    impl Store for ValidatingStore {
        fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
            self.inner.upsert(record)?;
            if self.inner.load_all().is_err() {
                self.saw_invalid.store(true, Ordering::Release);
            }
            Ok(())
        }
        fn delete(&self, id: &SandboxId) -> io::Result<()> {
            self.inner.delete(id)
        }
        fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
            self.inner.load_all()
        }
        fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
            self.inner.replace_all(records)?;
            if self.inner.load_all().is_err() {
                self.saw_invalid.store(true, Ordering::Release);
            }
            Ok(())
        }
    }

    /// Commits every write to an inner in-memory store, then reports a
    /// committed-but-unsynced durability error — simulating a successful atomic
    /// rename whose follow-up directory fsync failed. The record IS durable, so
    /// the actor must treat the write as committed and never roll back.
    struct CommittedUnsyncedStore {
        inner: InMemoryStore,
    }
    impl Store for CommittedUnsyncedStore {
        fn upsert(&self, record: &PersistedRecord) -> io::Result<()> {
            self.inner.upsert(record)?;
            Err(crate::store::committed_unsynced_error(io::Error::other(
                "dir fsync failed",
            )))
        }
        fn delete(&self, id: &SandboxId) -> io::Result<()> {
            self.inner.delete(id)
        }
        fn load_all(&self) -> io::Result<Vec<PersistedRecord>> {
            self.inner.load_all()
        }
        fn replace_all(&self, records: &[PersistedRecord]) -> io::Result<()> {
            self.inner.replace_all(records)?;
            Err(crate::store::committed_unsynced_error(io::Error::other(
                "dir fsync failed",
            )))
        }
    }

    // --- Tests ------------------------------------------------------------

    #[tokio::test]
    async fn create_converges_to_stopped() {
        let rt = runtime(Ctl::default(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Stopped)).await;
        assert_eq!(v.status.observed_generation, v.status.generation);
        assert!(v.status.reason.is_none());
    }

    #[tokio::test]
    async fn create_and_start_converges_to_running() {
        let ctl = Ctl::default();
        let rt = runtime(ctl, Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
    }

    #[tokio::test]
    async fn accepted_intent_visible_before_convergence() {
        let rt = runtime(Ctl::default(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Stopped)).await;
        rt.set_desired(&id, Verb::Start, DesiredState::Running)
            .await
            .unwrap();
        // The accepted desired is durable + visible immediately after the ack.
        let v = rt.status(&id).unwrap();
        assert_eq!(v.status.desired, DesiredState::Running);
    }

    #[tokio::test]
    async fn start_failure_latches_and_one_retry() {
        let ctl = Ctl::default();
        ctl.start_fail.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::StartFailed));
        assert_eq!(v.status.observed_generation, v.status.generation);
        let starts_before = ctl.starts.load(Ordering::Acquire);

        // Latched: no autonomous retry.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(ctl.starts.load(Ordering::Acquire), starts_before);

        // A fresh verb reopens exactly one attempt; let it succeed now.
        ctl.start_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Start, DesiredState::Running)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
    }

    #[tokio::test]
    async fn destroy_retained_and_teardown_failure_latches() {
        let ctl = Ctl::default();
        ctl.teardown_fail.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Stopped)).await;
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::DestroyFailed));

        // Re-assert destroy; allow it to succeed.
        ctl.teardown_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
        // Retained, not pruned.
        assert_eq!(rt.status(&id).unwrap().status.state, Some(State::Destroyed));
        assert!(v.config.image == "img");
    }

    #[tokio::test]
    async fn crash_detected_transitions_to_failed() {
        let ctl = Ctl::default();
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        // Kill the VM out from under the actor.
        ctl.alive.store(false, Ordering::Release);
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
    }

    #[tokio::test]
    async fn boot_recovery_running_observed_dead() {
        let store = Arc::new(InMemoryStore::new());
        // Seed a Running record (its VM is gone after a restart).
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-7".into()),
                config: cfg(),
                desired: DesiredState::Running,
                generation: 1,
                state: Some(State::Running),
                observed_generation: 1,
                pid: Some(1_000_000),
                pid_start_time: Some(0),
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let rt = recoverable_runtime(Ctl::default(), store);
        rt.recover().await.unwrap();
        let v = await_view(&rt, &SandboxId("sb-7".into()), |v| {
            v.status.state == Some(State::Failed)
        })
        .await;
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
        // Id allocator advanced past recovered ids.
        let new_id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        assert_eq!(new_id.0, "sb-8");
    }

    #[tokio::test]
    async fn await_pid_death_times_out_when_still_alive() {
        // A process that never dies must fail recovery loudly, not be served.
        let id = SandboxId("sb-1".into());
        let res = await_pid_death(&id, || true, Duration::from_millis(40)).await;
        assert!(res.is_err(), "still-alive pid must error");
    }

    #[tokio::test]
    async fn await_pid_death_returns_when_pid_clears() {
        // Reports alive for the first few polls, then dead: recovery proceeds.
        let id = SandboxId("sb-1".into());
        let mut calls = 0u32;
        let res = await_pid_death(
            &id,
            || {
                calls += 1;
                calls < 3
            },
            Duration::from_secs(5),
        )
        .await;
        assert!(res.is_ok(), "cleared pid must succeed");
    }

    #[tokio::test]
    async fn second_recover_is_rejected_no_double_spawn() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-9".into()),
                config: cfg(),
                desired: DesiredState::Stopped,
                generation: 1,
                state: Some(State::Stopped),
                observed_generation: 1,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let ctl = Ctl::default();
        let rt = recoverable_runtime(ctl.clone(), store);
        rt.recover().await.unwrap();
        let provisions_after_first = ctl.provisions.load(Ordering::Acquire);
        // A second recovery must be rejected, not spawn a duplicate actor.
        assert!(rt.recover().await.is_err());
        // No new actor was spawned (the gone-rootfs case would reprovision; here
        // the rootfs is present so provisions stays put either way).
        assert_eq!(
            ctl.provisions.load(Ordering::Acquire),
            provisions_after_first
        );
    }

    #[tokio::test]
    async fn recovery_is_atomic_no_spawn_if_a_later_record_fails() {
        // On-disk store iterates in sorted key order, so sb-1 (which would
        // provision) is recovered before sb-2 (whose recovery we force to fail).
        let dir = std::env::temp_dir().join(format!(
            "pp-recon-atomic-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store: Arc<dyn Store> = Arc::new(crate::store::JsonStore::new(dir.join("state.json")));
        let now = rfc3339_now();
        // sb-1: genesis Running — its actor, once spawned, would provision.
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-1".into()),
                config: cfg(),
                desired: DesiredState::Running,
                generation: 1,
                state: None,
                observed_generation: 0,
                pid: None,
                pid_start_time: None,
                rootfs_path: None,
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now.clone(),
            })
            .unwrap();
        // sb-2: a valid record whose recovery is forced to fail.
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-2".into()),
                config: cfg(),
                desired: DesiredState::Stopped,
                generation: 1,
                state: Some(State::Stopped),
                observed_generation: 1,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();

        // Snapshot state.json before recovery to prove no partial rewrite.
        let before = std::fs::read(dir.join("state.json")).unwrap();

        let ctl = Ctl::default();
        ctl.recover_fail_ids.lock().unwrap().push("sb-2".into());
        let rt = recoverable_runtime(ctl.clone(), store);

        // A later record's recovery failure aborts the whole pass.
        assert!(rt.recover().await.is_err());
        // The durable store is byte-unchanged: recovery committed nothing.
        assert_eq!(
            std::fs::read(dir.join("state.json")).unwrap(),
            before,
            "state.json must be byte-unchanged on failed recovery"
        );
        // Give any erroneously-spawned actor a chance to run before asserting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // No earlier-actor side effects: sb-1 never provisioned and has no entry.
        assert_eq!(ctl.provisions.load(Ordering::Acquire), 0);
        assert!(matches!(
            rt.status(&SandboxId("sb-1".into())),
            Err(BackendError::NotFound)
        ));
        assert!(matches!(
            rt.status(&SandboxId("sb-2".into())),
            Err(BackendError::NotFound)
        ));
    }

    #[tokio::test]
    async fn new_runtime_creates_without_recover() {
        // The non-durable `new` path (mock/server) creates without recovery.
        let rt = runtime(Ctl::default(), Arc::new(InMemoryStore::new()));
        assert!(rt.create(cfg(), DesiredState::Stopped).await.is_ok());
    }

    #[tokio::test]
    async fn create_before_recover_is_rejected_on_recoverable_runtime() {
        // A durable runtime must recover before create(), else a fresh sb-1
        // could overwrite a persisted record.
        let rt = recoverable_runtime(Ctl::default(), Arc::new(InMemoryStore::new()));
        assert!(rt.create(cfg(), DesiredState::Stopped).await.is_err());
    }

    #[tokio::test]
    async fn recover_after_actor_exists_is_rejected() {
        // recover() (empty store) -> Ready; create() spawns an actor; a second
        // recover() must be rejected (no duplicate actor/entry).
        let rt = recoverable_runtime(Ctl::default(), Arc::new(InMemoryStore::new()));
        rt.recover().await.unwrap();
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        assert!(rt.recover().await.is_err());
        assert!(rt.status(&id).is_ok());
    }

    #[tokio::test]
    async fn recover_running_dead_pid_reports_failed_immediately() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-3".into()),
                config: cfg(),
                desired: DesiredState::Running,
                generation: 1,
                state: Some(State::Running),
                observed_generation: 1,
                pid: Some(1_000_000),
                pid_start_time: Some(0),
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let rt = recoverable_runtime(Ctl::default(), store);
        rt.recover().await.unwrap();
        // First status read, no polling: recovery normalized the dead Running.
        let v = rt.status(&SandboxId("sb-3".into())).unwrap();
        assert_eq!(v.status.state, Some(State::Failed));
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
    }

    #[tokio::test]
    async fn recover_missing_rootfs_reprovisions_on_start() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-5".into()),
                config: cfg(),
                desired: DesiredState::Stopped,
                generation: 3,
                state: Some(State::Stopped),
                observed_generation: 3,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let ctl = Ctl::default();
        // The recorded rootfs is gone from disk: recover_rootfs returns None.
        ctl.rootfs_missing.store(true, Ordering::Release);
        let rt = recoverable_runtime(ctl.clone(), store);
        rt.recover().await.unwrap();
        let id = SandboxId("sb-5".into());
        // The gone-rootfs Stopped record reset to a reprovisionable shape and
        // reconciled to Stopped by reprovisioning (not stuck/failed).
        await_view(&rt, &id, |v| v.status.state == Some(State::Stopped)).await;
        assert!(ctl.provisions.load(Ordering::Acquire) >= 1);
        // A subsequent start converges to Running rather than StartFailing forever.
        rt.set_desired(&id, Verb::Start, DesiredState::Running)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
    }

    #[tokio::test]
    async fn recover_rejects_overflowing_sandbox_id() {
        // A structurally-valid but corrupt record at sb-<u64::MAX> would make
        // the next id (max + 1) overflow; recovery must fail loudly, never wrap
        // to 0 (which would reuse/overwrite a recovered id).
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId(format!("sb-{}", u64::MAX)),
                config: cfg(),
                desired: DesiredState::Stopped,
                generation: 3,
                state: Some(State::Stopped),
                observed_generation: 3,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let rt = recoverable_runtime(Ctl::default(), store);
        assert!(matches!(rt.recover().await, Err(BackendError::Internal(_))));
    }

    #[tokio::test]
    async fn boot_recovery_clean_stopped_untouched() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-1".into()),
                config: cfg(),
                desired: DesiredState::Stopped,
                generation: 3,
                state: Some(State::Stopped),
                observed_generation: 3,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let ctl = Ctl::default();
        let rt = recoverable_runtime(ctl.clone(), store);
        rt.recover().await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let v = rt.status(&SandboxId("sb-1".into())).unwrap();
        assert_eq!(v.status.state, Some(State::Stopped));
        assert_eq!(v.status.generation, 3);
        // No reprovision of a healthy stopped sandbox.
        assert_eq!(ctl.provisions.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn persist_failure_poisons_actor() {
        // Genesis fsync succeeds (call 1); the next transition's fsync fails.
        let store = Arc::new(FaultStore::new(1));
        let ctl = Ctl::default();
        let rt = runtime(ctl, store);
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        // After genesis the provision->Stopped commit fails, poisoning the actor.
        for _ in 0..400 {
            if matches!(rt.status(&id), Err(BackendError::Internal(_))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("actor did not poison");
    }

    #[tokio::test]
    async fn committed_unsynced_persist_is_not_rolled_back() {
        // Every store write commits (to the inner store) but reports a
        // committed-but-unsynced durability error. The actor must treat each as
        // committed: genesis + provision converge to Stopped (no poison), and an
        // accepted command keeps its bumped generation rather than rolling back.
        let store = Arc::new(CommittedUnsyncedStore {
            inner: InMemoryStore::new(),
        });
        let rt = runtime(Ctl::default(), store.clone());
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        // Wait for full convergence (not just the first Stopped publish, which can
        // precede the converge commit that latches observed == generation).
        let v = await_view(&rt, &id, |v| {
            v.status.state == Some(State::Stopped)
                && v.status.observed_generation == v.status.generation
        })
        .await;
        assert_eq!(v.status.observed_generation, v.status.generation);

        // An accepted Start is acked Ok and its generation bump is NOT rolled
        // back, even though the persist reported committed-but-unsynced.
        let gen_before = rt.status(&id).unwrap().status.generation;
        rt.set_desired(&id, Verb::Start, DesiredState::Running)
            .await
            .unwrap();
        let after = rt.status(&id).unwrap().status;
        assert_eq!(after.desired, DesiredState::Running);
        assert_eq!(after.generation, gen_before + 1);

        // The committed writes are actually present in the durable store.
        let rec = store
            .load_all()
            .unwrap()
            .into_iter()
            .find(|r| r.id == id)
            .expect("record committed despite unsynced durability");
        assert_eq!(rec.desired, DesiredState::Running);
    }

    #[tokio::test]
    async fn teardown_failure_from_running_keeps_record_valid() {
        let ctl = Ctl::default();
        ctl.teardown_fail.store(true, Ordering::Release);
        let store = Arc::new(InMemoryStore::new());
        let rt = runtime(ctl.clone(), store.clone());
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::DestroyFailed));
        // A teardown failure from Running must not leave a pid on the Failed
        // record, or load_all would reject it as corrupt on the next boot.
        let records = store
            .load_all()
            .expect("destroy_failed record must remain valid");
        let rec = records.iter().find(|r| r.id == id).unwrap();
        assert!(rec.pid.is_none() && rec.pid_start_time.is_none());
        assert_eq!(rec.state, Some(State::Failed));
    }

    #[tokio::test]
    async fn destroy_accepted_during_slow_provision_no_orphan() {
        let ctl = Ctl::default();
        ctl.provision_hold.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        // Provision is in flight and blocked. The destroy must be accepted
        // (durably persisted + acked) promptly, not after provision completes.
        let acked = tokio::time::timeout(
            Duration::from_secs(2),
            rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed),
        )
        .await;
        assert!(
            matches!(acked, Ok(Ok(()))),
            "destroy must be accepted while provision is in flight: {acked:?}"
        );
        // Release provision; the built rootfs must then be torn down (no orphan).
        ctl.provision_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
        assert_eq!(ctl.provisions.load(Ordering::Acquire), 1);
        assert!(
            ctl.teardowns.load(Ordering::Acquire) >= 1,
            "the provisioned rootfs must be torn down"
        );
    }

    #[tokio::test]
    async fn start_success_superseded_by_destroy_tears_down() {
        let ctl = Ctl::default();
        ctl.start_hold.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        // Wait until start is in flight (provision done, start blocked).
        for _ in 0..400 {
            if ctl.starts.load(Ordering::Acquire) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(ctl.starts.load(Ordering::Acquire), 1);
        // Destroy is accepted while start is in flight.
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        // Let start complete: the VM is recorded, then torn down toward Destroyed.
        ctl.start_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
        assert!(ctl.teardowns.load(Ordering::Acquire) >= 1);
    }

    #[tokio::test]
    async fn superseded_start_failure_is_discarded_not_latched() {
        let ctl = Ctl::default();
        ctl.start_hold.store(true, Ordering::Release);
        ctl.start_fail.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        for _ in 0..400 {
            if ctl.starts.load(Ordering::Acquire) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Stop supersedes the in-flight start (bumps generation).
        rt.set_desired(&id, Verb::Stop, DesiredState::Stopped)
            .await
            .unwrap();
        // Release start; it fails, but the failure is stale (superseded) so it
        // is discarded, not latched: the sandbox settles Stopped, never Failed.
        ctl.start_fail.store(false, Ordering::Release);
        ctl.start_hold.store(false, Ordering::Release);
        let v = await_view(&rt, &id, |v| {
            v.status.state == Some(State::Stopped)
                && v.status.observed_generation == v.status.generation
        })
        .await;
        assert_eq!(v.status.state, Some(State::Stopped));
        assert!(v.status.reason.is_none());
    }

    #[tokio::test]
    async fn superseded_teardown_failure_from_failed_stays_valid() {
        let saw_invalid = Arc::new(AtomicBool::new(false));
        let store = Arc::new(ValidatingStore {
            inner: InMemoryStore::new(),
            saw_invalid: saw_invalid.clone(),
        });
        let ctl = Ctl::default();
        ctl.teardown_fail.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), store);
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Stopped)).await;
        // Destroy fails and latches DestroyFailed (state carries a reason).
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::DestroyFailed)
        })
        .await;
        // Reopen the destroy; the teardown retry blocks so we can supersede it.
        ctl.teardown_hold.store(true, Ordering::Release);
        let before = ctl.teardowns.load(Ordering::Acquire);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        for _ in 0..400 {
            if ctl.teardowns.load(Ordering::Acquire) > before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Supersede the in-flight retry (entry state is Failed/DestroyFailed).
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        // Release; the retry fails superseded -> must settle a VALID record
        // (Stopped with no stale reason), then converge once teardown succeeds.
        ctl.teardown_fail.store(false, Ordering::Release);
        ctl.teardown_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
        assert!(
            !saw_invalid.load(Ordering::Acquire),
            "superseded teardown must never persist an invalid record"
        );
    }

    // --- No-rootfs teardown-failure matrix (validate-on-write would poison the
    // actor on any invalid shape, so convergence proves every shape is valid) ---

    #[tokio::test]
    async fn teardown_failure_without_rootfs_latches_valid_destroy_failed() {
        let ctl = Ctl::default();
        ctl.provision_fail.store(true, Ordering::Release);
        let store = Arc::new(InMemoryStore::new());
        let rt = runtime(ctl.clone(), store.clone());
        let id = rt.create(cfg(), DesiredState::Stopped).await.unwrap();
        // Never provisioned: Failed(ProvisionFailed) with no rootfs.
        await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::ProvisionFailed)
        })
        .await;
        // Destroy a never-provisioned sandbox; teardown(None, None) fails.
        ctl.teardown_fail.store(true, Ordering::Release);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        let v = await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::DestroyFailed)
        })
        .await;
        // A no-rootfs DestroyFailed is a valid, intentional shape (not poisoned).
        assert_eq!(v.status.state, Some(State::Failed));
        assert!(rt.status(&id).is_ok());
        assert!(store.load_all().is_ok());
        // Re-assert destroy with cleanup succeeding -> Destroyed.
        ctl.teardown_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
    }

    #[tokio::test]
    async fn recover_genesis_destroy_teardown_failure_stays_valid() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-9".into()),
                config: cfg(),
                desired: DesiredState::Destroyed,
                generation: 2,
                state: None,
                observed_generation: 1,
                pid: None,
                pid_start_time: None,
                rootfs_path: None,
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let ctl = Ctl::default();
        ctl.teardown_fail.store(true, Ordering::Release);
        let rt = recoverable_runtime(ctl.clone(), store.clone());
        rt.recover().await.unwrap();
        let id = SandboxId("sb-9".into());
        // teardown(None, None) fails -> DestroyFailed with no rootfs (valid).
        let v = await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::DestroyFailed)
        })
        .await;
        assert_eq!(v.status.state, Some(State::Failed));
        assert!(store.load_all().is_ok());
        // Retry to Destroyed.
        ctl.teardown_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
    }

    #[tokio::test]
    async fn superseded_teardown_failure_without_rootfs_stays_valid() {
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-10".into()),
                config: cfg(),
                desired: DesiredState::Destroyed,
                generation: 2,
                state: None,
                observed_generation: 1,
                pid: None,
                pid_start_time: None,
                rootfs_path: None,
                reason: None,
                message: None,
                entrypoint_exit: None,
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let ctl = Ctl::default();
        ctl.teardown_fail.store(true, Ordering::Release);
        ctl.teardown_hold.store(true, Ordering::Release);
        let rt = recoverable_runtime(ctl.clone(), store.clone());
        rt.recover().await.unwrap();
        let id = SandboxId("sb-10".into());
        // teardown in flight + blocked; supersede with another destroy.
        for _ in 0..400 {
            if ctl.teardowns.load(Ordering::Acquire) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        // Release the failing teardown: superseded branch must settle a VALID
        // no-rootfs shape (genesis), then the retry latches DestroyFailed.
        ctl.teardown_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::DestroyFailed)
        })
        .await;
        assert!(store.load_all().is_ok());
        // Converge to Destroyed once cleanup succeeds.
        ctl.teardown_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
    }

    // --- Main-process exit coupling --------------------------------------

    /// Wait until `start` has handed the driver an exit sink, then return it.
    async fn await_sink(ctl: &Ctl) -> EntrypointExitSink {
        for _ in 0..400 {
            if let Some(sink) = ctl.entrypoint_sink.lock().unwrap().clone() {
                return sink;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("start never produced an exit sink");
    }

    #[tokio::test]
    async fn entrypoint_exit_couples_to_failed_crashed_with_carrier() {
        let ctl = Ctl::default();
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        // A real exit (the VM is still alive) couples the VM down and carries the
        // outcome onto the terminal record.
        await_sink(&ctl)
            .await
            .post(EntrypointExit::Exited { code: 5 })
            .await;
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
        assert_eq!(
            rt.entrypoint_exit(&id).unwrap(),
            Some(EntrypointExit::Exited { code: 5 })
        );
        // The coupling ran the graceful primitive exactly to bring the VM down.
        assert!(ctl.graceful_shutdowns.load(Ordering::Acquire) >= 1);
    }

    #[tokio::test]
    async fn entrypoint_start_error_couples_with_start_error_carrier() {
        let ctl = Ctl::default();
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        await_sink(&ctl)
            .await
            .post(EntrypointExit::StartError {
                message: "no such file".into(),
            })
            .await;
        await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(
            rt.entrypoint_exit(&id).unwrap(),
            Some(EntrypointExit::StartError {
                message: "no such file".into()
            })
        );
    }

    #[tokio::test]
    async fn spontaneous_crash_has_no_carrier() {
        let ctl = Ctl::default();
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        let sink = await_sink(&ctl).await;
        // A spontaneous crash: the VM is already dead AND a synthetic terminal
        // posts (as the relay would on a crash). The coupling guard sees the VM
        // was not coupled down, so the terminal carries no exit outcome.
        ctl.alive.store(false, Ordering::Release);
        sink.post(EntrypointExit::Exited { code: -1 }).await;
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
        assert_eq!(rt.entrypoint_exit(&id).unwrap(), None);
    }

    #[tokio::test]
    async fn entrypoint_exit_mid_start_is_stashed_and_applied() {
        let ctl = Ctl::default();
        ctl.start_hold.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        // The sink is published at the very top of start, before it blocks, so the
        // exit arrives while start is still in flight (before Running commits).
        let sink = await_sink(&ctl).await;
        sink.post(EntrypointExit::Exited { code: 9 }).await;
        ctl.start_hold.store(false, Ordering::Release);
        // The stash is applied once Running settles, deterministically carrying it.
        let v = await_view(&rt, &id, |v| v.status.state == Some(State::Failed)).await;
        assert_eq!(v.status.reason, Some(FailureReason::Crashed));
        assert_eq!(
            rt.entrypoint_exit(&id).unwrap(),
            Some(EntrypointExit::Exited { code: 9 })
        );
    }

    #[tokio::test]
    async fn destroy_during_graceful_converges_destroyed_without_carrier() {
        let ctl = Ctl::default();
        ctl.graceful_hold.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        // The exit starts the coupling, which blocks inside the graceful primitive.
        await_sink(&ctl)
            .await
            .post(EntrypointExit::Exited { code: 0 })
            .await;
        for _ in 0..400 {
            if ctl.graceful_shutdowns.load(Ordering::Acquire) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // A destroy arriving mid-graceful is accepted promptly (command-live), not
        // blocked behind the in-flight graceful future.
        let acked = tokio::time::timeout(
            Duration::from_secs(2),
            rt.set_desired(&id, Verb::Destroy, DesiredState::Destroyed),
        )
        .await;
        assert!(
            matches!(acked, Ok(Ok(()))),
            "destroy must be accepted while graceful is in flight: {acked:?}"
        );
        // Once graceful completes, the box converges to Destroyed with no carrier.
        ctl.graceful_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| v.status.state == Some(State::Destroyed)).await;
        assert_eq!(rt.entrypoint_exit(&id).unwrap(), None);
    }

    #[tokio::test]
    async fn recovered_crashed_carrier_is_visible_immediately() {
        // A persisted Failed(Crashed)+Some record's carrier is seeded onto the
        // seam at recovery, so it reads back without any further commit.
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-1".into()),
                config: cfg(),
                desired: DesiredState::Running,
                generation: 2,
                state: Some(State::Failed),
                observed_generation: 2,
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: Some(FailureReason::Crashed),
                message: Some("vm exited unexpectedly".into()),
                entrypoint_exit: Some(EntrypointExit::Exited { code: 3 }),
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let rt = recoverable_runtime(Ctl::default(), store);
        rt.recover().await.unwrap();
        assert_eq!(
            rt.entrypoint_exit(&SandboxId("sb-1".into())).unwrap(),
            Some(EntrypointExit::Exited { code: 3 })
        );
    }

    #[tokio::test]
    async fn stale_entrypoint_exit_does_not_couple_a_later_run() {
        // An exit stashed during a doomed start must not survive to couple a LATER
        // successful run down — a cross-run correctness hazard.
        let ctl = Ctl::default();
        ctl.start_fail.store(true, Ordering::Release);
        ctl.start_hold.store(true, Ordering::Release);
        let rt = runtime(ctl.clone(), Arc::new(InMemoryStore::new()));
        let id = rt.create(cfg(), DesiredState::Running).await.unwrap();
        // The sink is published at the top of start (before it blocks + fails), so
        // the exit is stashed during this doomed run.
        let sink = await_sink(&ctl).await;
        sink.post(EntrypointExit::Exited { code: 1 }).await;
        ctl.start_hold.store(false, Ordering::Release);
        await_view(&rt, &id, |v| {
            v.status.reason == Some(FailureReason::StartFailed)
        })
        .await;
        // Reopen with a now-succeeding start: the stale exit must be discarded, so
        // the fresh run reaches Running and STAYS there (never coupled down).
        ctl.start_fail.store(false, Ordering::Release);
        rt.set_desired(&id, Verb::Start, DesiredState::Running)
            .await
            .unwrap();
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            rt.status(&id).unwrap().status.state,
            Some(State::Running),
            "a stale pending exit must not couple a later run down"
        );
        assert_eq!(rt.entrypoint_exit(&id).unwrap(), None);
    }

    #[tokio::test]
    async fn recovery_self_heals_stale_carrier_when_accepted_start_runs() {
        // A daemon crash AFTER a start was accepted (generation bumped, observed <
        // generation) but BEFORE do_start ran leaves a valid
        // Failed(Crashed)+desired=Running+Some record. The accept un-latched the
        // box (observed != generation), so recovery boots it and the carrier is
        // cleared at the Running state-write — the stale carrier does not persist
        // indefinitely.
        let store = Arc::new(InMemoryStore::new());
        let now = rfc3339_now();
        store
            .upsert(&PersistedRecord {
                id: SandboxId("sb-1".into()),
                config: cfg(),
                desired: DesiredState::Running,
                generation: 3,
                state: Some(State::Failed),
                observed_generation: 2, // accepted start, not yet executed
                pid: None,
                pid_start_time: None,
                rootfs_path: Some(std::env::temp_dir().join("pp-rec/rootfs")),
                reason: Some(FailureReason::Crashed),
                message: Some("vm exited unexpectedly".into()),
                entrypoint_exit: Some(EntrypointExit::Exited { code: 9 }),
                created_at: now.clone(),
                last_transition_at: now,
            })
            .unwrap();
        let rt = recoverable_runtime(Ctl::default(), store);
        rt.recover().await.unwrap();
        let id = SandboxId("sb-1".into());
        await_view(&rt, &id, |v| v.status.state == Some(State::Running)).await;
        assert_eq!(rt.entrypoint_exit(&id).unwrap(), None);
    }
}
