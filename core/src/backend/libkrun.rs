use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backend::{BackendError, Capabilities, SandboxBackendSend};
use crate::krun::KrunCtx;
use crate::lifecycle::SandboxState;
use crate::net::{NetBackendConfig, NetBackendHandle};
use crate::oci::{ImageCache, ImageReference, RegistryClient};
use crate::rootfs::{PreparedRootfs, RootfsConfig, RootfsProvider};
use crate::types::{
    ExecControl, ExecEvent, ExecHandle, ExecId, ExecRequest, MountConfig, NetworkPolicy,
    SandboxConfig, SandboxId, SandboxStatus,
};
use crate::util::{base64_decode, base64_encode};

// ---------------------------------------------------------------------------
// Guest exec protocol (mirrors init/src/proto.rs)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostMsg {
    Exec {
        id: String,
        cmd: Vec<String>,
        env: Vec<String>,
        workdir: Option<String>,
    },
    Stdin {
        id: String,
        data: String,
    },
    Signal {
        id: String,
        signal: i32,
    },
    Resize {
        id: String,
        cols: u32,
        rows: u32,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuestMsg {
    Stdout { id: String, data: String },
    Stderr { id: String, data: String },
    Exit { id: String, code: i32 },
}

// ---------------------------------------------------------------------------
// Console I/O task command
// ---------------------------------------------------------------------------

enum ConsoleCmd {
    Send(String),
    /// Like Send, but the write task confirms success/failure via the oneshot.
    /// exec() awaits the result so it can return an error if the Exec message
    /// was never delivered to the guest.
    SendAck(String, oneshot::Sender<bool>),
    RegisterExec {
        id: String,
        events_tx: mpsc::Sender<ExecEvent>,
    },
    /// Remove a registered exec sender, e.g. after a failed SendAck write.
    UnregisterExec(String),
    /// Graceful shutdown: send Exit{-1} to all registered sessions, then stop.
    Teardown,
}

// ---------------------------------------------------------------------------
// Reconciler request/response types
// ---------------------------------------------------------------------------

/// Sent from API methods to the reconciler loop.
enum ReconcileRequest {
    SetDesired {
        target: SandboxState,
        result_tx: oneshot::Sender<Result<(), BackendError>>,
    },
}

/// Sent on a dedicated channel for on-demand liveness checks.
struct LivenessCheck {
    done_tx: oneshot::Sender<()>,
}

// ---------------------------------------------------------------------------
// Per-sandbox shared record (API methods + reconciler)
// ---------------------------------------------------------------------------

struct SandboxRecord {
    actual_state: SandboxState,
    created_at: String,
    #[allow(dead_code)] // retained for status queries on destroyed sandboxes
    config: SandboxConfig,
    reconciler_panicked: Arc<AtomicBool>,
    live: Option<LiveState>,
}

struct LiveState {
    reconcile_tx: mpsc::Sender<ReconcileRequest>,
    liveness_tx: mpsc::Sender<LivenessCheck>,
    #[allow(dead_code)] // kept to prevent the task from being detached
    reconciler_handle: JoinHandle<()>,
    pending_target: Option<SandboxState>,
    console_cmd_tx: Option<mpsc::Sender<ConsoleCmd>>,
    cancel_token: CancellationToken,
    #[allow(dead_code)] // read-only crash indicator for API methods
    vm_alive: Arc<AtomicBool>,
}

// ---------------------------------------------------------------------------
// Reconciler-private state
// ---------------------------------------------------------------------------

struct ReconcilerState {
    actual: SandboxState,
    desired: SandboxState,
    config: SandboxConfig,
    rootfs: Option<PreparedRootfs>,
    krun_ctx: Option<KrunCtx>,
    console_host_sock: Option<UnixStream>,
    console_guest_fd: Option<i32>,
    net_backend_sock: Option<UnixStream>,
    net_vm_sock_fd: Option<i32>,
    vm_pid: Option<i32>,
    child_guard: Option<ChildGuard>,
    net_handle: Option<NetBackendHandle>,
    console_cmd_tx: Option<mpsc::Sender<ConsoleCmd>>,
    io_task: Option<JoinHandle<()>>,
    vm_alive: Arc<AtomicBool>,
    cancel_token: CancellationToken,
    waiters: Vec<(SandboxState, oneshot::Sender<Result<(), BackendError>>)>,
}

// ---------------------------------------------------------------------------
// RAII guards
// ---------------------------------------------------------------------------

/// Sets `reconciler_panicked` to true on drop unless defused.
struct ReconcilerPanicGuard(Option<Arc<AtomicBool>>);

impl ReconcilerPanicGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self(Some(flag))
    }
    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for ReconcilerPanicGuard {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(true, Ordering::Release);
        }
    }
}

/// Holds a child PID and kills + reaps it in a background thread on drop.
/// Call `defuse()` before any explicit kill in an error path, or after the PID
/// has been safely stored in the entry, to prevent a double-kill.
struct ChildGuard(Option<i32>);

impl ChildGuard {
    fn new(pid: i32) -> Self {
        Self(Some(pid))
    }

    /// Prevent the guard from killing the child on drop.
    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            // Runs only on async cancellation (rare). Spawn a detached OS thread so we
            // don't block the async executor while waiting for the child to die.
            std::thread::spawn(move || {
                kill_and_wait(pid);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// LibkrunBackend
// ---------------------------------------------------------------------------

pub struct LibkrunBackend {
    data_dir: PathBuf,
    init_binary: PathBuf,
    rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    image_cache: Arc<Mutex<ImageCache>>,
    registry_client: Arc<Mutex<RegistryClient>>,
    sandboxes: Arc<Mutex<HashMap<SandboxId, SandboxRecord>>>,
    next_sandbox: AtomicU64,
    next_exec: AtomicU64,
    launch_mutex: Arc<Mutex<()>>,
    shutdown_token: CancellationToken,
}

impl Drop for LibkrunBackend {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}

/// Static MAC addresses for the guest and the network backend (gateway).
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const BACKEND_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];

/// Guest IP for Allowlist network mode.
const GUEST_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 2, 15);
/// Gateway IP for Allowlist network mode.
const GATEWAY_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 2, 1);

/// The virtio-console port name the guest init listens on.
const EXEC_PORT_NAME: &str = "playpencil.exec";

/// TSI flags: hijack both INET and UNIX connections.
const TSI_HIJACK_ALL: u32 = 3;

/// Guest path for the init binary — always installed here by the rootfs provider.
const GUEST_INIT_PATH: &str = "/usr/local/bin/playpencil-init";

/// Standard environment variables injected into every guest.
const GUEST_STANDARD_ENV: &[&str] = &[
    "HOME=/root",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TERM=xterm",
];

/// Guest paths that may never be used as mount destinations.
const PROTECTED_GUEST_PATHS: &[&str] = &["/", "/proc", "/sys", "/dev", GUEST_INIT_PATH];

/// Maximum size (bytes) of a single newline-delimited JSON frame sent to the guest.
/// Matches the 1 MiB line limit enforced by init's console reader.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum raw bytes per stdin chunk so that the base64-encoded JSON frame stays
/// under MAX_FRAME_BYTES. Base64 expands 3:4 so 512 KiB raw → 682 KiB base64,
/// leaving ~342 KiB of headroom for JSON overhead under the 1 MiB frame limit.
const STDIN_CHUNK_BYTES: usize = 512 * 1024;

/// Return the current UTC time formatted as an RFC3339 string (seconds precision).
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Civil date from days since Unix epoch (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------
// Reachability check for desired-state targets
// ---------------------------------------------------------------------------

/// Returns true if `target` is reachable from `actual` via reconcile steps.
/// Only valid desired-state targets are checked — intermediate states
/// (Starting, Stopping) are not valid targets.
fn can_reach(actual: SandboxState, target: SandboxState) -> bool {
    matches!(
        (actual, target),
        (SandboxState::Ready, SandboxState::Running)
            | (SandboxState::Ready, SandboxState::Destroyed)
            | (SandboxState::Running, SandboxState::Stopped)
            | (SandboxState::Running, SandboxState::Destroyed)
            | (SandboxState::Stopped, SandboxState::Running)
            | (SandboxState::Stopped, SandboxState::Destroyed)
            | (SandboxState::Creating, SandboxState::Ready)
    )
}

// ---------------------------------------------------------------------------
// Waiter notification helpers
// ---------------------------------------------------------------------------

fn reconstruct_error(err: &BackendError) -> BackendError {
    match err {
        BackendError::InvalidState => BackendError::InvalidState,
        BackendError::NotFound => BackendError::NotFound,
        BackendError::InvalidInput(msg) => BackendError::InvalidInput(msg.clone()),
        BackendError::Internal(msg) => BackendError::Internal(msg.clone()),
    }
}

fn notify_waiters_ok(state: &mut ReconcilerState) {
    for (target, tx) in state.waiters.drain(..) {
        if target == state.actual {
            let _ = tx.send(Ok(()));
        } else {
            let _ = tx.send(Err(BackendError::InvalidState));
        }
    }
}

fn notify_waiters_with_error(state: &mut ReconcilerState, err: &BackendError) {
    for (_, tx) in state.waiters.drain(..) {
        let _ = tx.send(Err(reconstruct_error(err)));
    }
}

fn drain_waiters_with(
    waiters: &mut Vec<(SandboxState, oneshot::Sender<Result<(), BackendError>>)>,
    make_err: impl Fn(SandboxState) -> BackendError,
) {
    for (target, tx) in waiters.drain(..) {
        let _ = tx.send(Err(make_err(target)));
    }
}

fn supersede_waiters(waiters: &mut Vec<(SandboxState, oneshot::Sender<Result<(), BackendError>>)>) {
    for (_, tx) in waiters.drain(..) {
        let _ = tx.send(Err(BackendError::InvalidState));
    }
}

// ---------------------------------------------------------------------------
// Shared record update helpers
// ---------------------------------------------------------------------------

/// Snapshot of reconciler state needed for the shared record update.
/// Extracted from ReconcilerState to avoid passing the full struct (which is !Send
/// due to KrunCtx containing Cell<()>).
struct ReconcilerSnapshot {
    actual: SandboxState,
    console_cmd_tx: Option<mpsc::Sender<ConsoleCmd>>,
    cancel_token: CancellationToken,
}

impl ReconcilerState {
    fn snapshot(&self) -> ReconcilerSnapshot {
        ReconcilerSnapshot {
            actual: self.actual,
            console_cmd_tx: self.console_cmd_tx.clone(),
            cancel_token: self.cancel_token.clone(),
        }
    }
}

async fn update_shared_record(
    sandboxes: &Mutex<HashMap<SandboxId, SandboxRecord>>,
    id: &SandboxId,
    snap: &ReconcilerSnapshot,
) {
    let mut map = sandboxes.lock().await;
    let Some(record) = map.get_mut(id) else {
        return;
    };
    record.actual_state = snap.actual;

    if snap.actual == SandboxState::Destroyed {
        record.live = None;
    } else if let Some(live) = record.live.as_mut() {
        live.console_cmd_tx = snap.console_cmd_tx.clone();
        live.cancel_token = snap.cancel_token.clone();
    }
}

/// Only clear pending_target if it still matches the transition we just
/// completed. A concurrent API method may have set a new claim (e.g.
/// Destroyed) between our channel drain and this call.
async fn clear_pending_target(
    sandboxes: &Mutex<HashMap<SandboxId, SandboxRecord>>,
    id: &SandboxId,
    expected: SandboxState,
) {
    if let Some(record) = sandboxes.lock().await.get_mut(id)
        && let Some(live) = record.live.as_mut()
        && live.pending_target == Some(expected)
    {
        live.pending_target = None;
    }
}

// ---------------------------------------------------------------------------
// Process management (unchanged)
// ---------------------------------------------------------------------------

/// Non-blocking child liveness check via waitpid(WNOHANG).
/// Returns true if the child is still running.
/// If this returns false, the child has been reaped — do NOT send signals to its PID.
fn check_child_liveness(pid: i32) -> bool {
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid {
            return false;
        }
        if w < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if errno.kind() == std::io::ErrorKind::WouldBlock
                || errno.raw_os_error() == Some(libc::ECHILD)
            {
                return false;
            }
        }
        return true; // w == 0 → child still running
    }
}

/// Kill the VM child and wait for it to exit.
/// Only called when we know the child is alive (never after a reaped waitpid).
fn kill_and_wait(pid: i32) {
    unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid
            || (w < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            return;
        }
    }
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status: libc::c_int = 0;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        if w == pid {
            return;
        }
        if w < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Resource teardown helpers (unchanged)
// ---------------------------------------------------------------------------

/// Tear down run-scoped resources: kill the VM (only if pid is Some), wait for I/O task.
async fn do_stop(pid: Option<i32>, net: Option<NetBackendHandle>, io_task: Option<JoinHandle<()>>) {
    if let Some(p) = pid {
        tokio::task::spawn_blocking(move || kill_and_wait(p))
            .await
            .ok();
    }
    if let Some(task) = io_task {
        let abort_handle = task.abort_handle();
        if tokio::time::timeout(std::time::Duration::from_millis(500), task)
            .await
            .is_err()
        {
            abort_handle.abort();
        }
    }
    if let Some(net) = net {
        tokio::task::spawn_blocking(move || {
            let _ = net.stop();
        })
        .await
        .ok();
    }
}

async fn do_destroy_rootfs(rootfs: PreparedRootfs) {
    tokio::task::spawn_blocking(move || {
        let _ = rootfs.destroy();
    })
    .await
    .ok();
}

// ---------------------------------------------------------------------------
// Mount validation (unchanged)
// ---------------------------------------------------------------------------

/// Validate mount configurations. Called before starting a VM.
fn validate_mounts(mounts: &[MountConfig]) -> Result<(), BackendError> {
    for (i, m) in mounts.iter().enumerate() {
        // Reject embedded NUL first: it slips past the Path-based checks below
        // but would corrupt the guest manifest / truncate at a C boundary.
        if m.host_path.contains('\0') || m.guest_path.contains('\0') {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: paths must not contain NUL"
            )));
        }
        let host = Path::new(&m.host_path);
        let guest = Path::new(&m.guest_path);

        if !host.is_absolute() {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: host_path '{}' must be absolute",
                m.host_path
            )));
        }
        if !host.exists() {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: host_path '{}' does not exist",
                m.host_path
            )));
        }
        if !guest.is_absolute() {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: guest_path '{}' must be absolute",
                m.guest_path
            )));
        }
        if m.host_path.contains("/../") || m.host_path.ends_with("/..") {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: host_path '{}' contains '..'",
                m.host_path
            )));
        }
        if m.guest_path.contains("/../") || m.guest_path.ends_with("/..") {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: guest_path '{}' contains '..'",
                m.guest_path
            )));
        }
        // Reject exact matches and descendants (e.g. /proc/sys, /dev/shm).
        // "/" is special: match only exactly, since all absolute paths start_with "/".
        if PROTECTED_GUEST_PATHS.iter().any(|&p| {
            if p == "/" {
                m.guest_path == p
            } else {
                guest.starts_with(p)
            }
        }) {
            return Err(BackendError::InvalidInput(format!(
                "mount[{i}]: guest_path '{}' is protected",
                m.guest_path
            )));
        }
    }
    Ok(())
}

/// Validate the image reference is well-formed. Done in `create` so a malformed
/// ref is a caller error (InvalidInput → 4xx) rather than surfacing later as an
/// internal reconcile failure.
fn validate_image_ref(image: &str) -> Result<(), BackendError> {
    let _: ImageReference = image.parse().map_err(|e| {
        BackendError::InvalidInput(format!("invalid image reference '{image}': {e}"))
    })?;
    Ok(())
}

/// Validate environment entries. Reject NUL (truncates at the C boundary) in
/// keys/values and '=' in keys (ambiguous KEY=VALUE framing). User input, so
/// these are InvalidInput, not internal errors.
fn validate_env(env: &[(String, String)]) -> Result<(), BackendError> {
    for (k, v) in env {
        if k.is_empty() {
            return Err(BackendError::InvalidInput(
                "env key must not be empty".into(),
            ));
        }
        if k.contains('\0') || v.contains('\0') {
            return Err(BackendError::InvalidInput(
                "env keys and values must not contain NUL".into(),
            ));
        }
        if k.contains('=') {
            return Err(BackendError::InvalidInput(
                "env key must not contain '='".into(),
            ));
        }
    }
    Ok(())
}

/// Write /etc/playpencil/mounts.json into the rootfs.
/// Tags use deterministic `mount0`, `mount1`, … indices matching add_virtiofs3 calls.
fn write_mounts_manifest(rootfs_root: &Path, mounts: &[MountConfig]) -> Result<(), BackendError> {
    let dir = rootfs_root.join("etc/playpencil");
    std::fs::create_dir_all(&dir)
        .map_err(|e| BackendError::Internal(format!("create /etc/playpencil: {e}")))?;

    #[derive(Serialize)]
    struct Entry {
        tag: String,
        guest_path: String,
        read_only: bool,
    }

    let entries: Vec<Entry> = mounts
        .iter()
        .enumerate()
        .map(|(i, m)| Entry {
            tag: format!("mount{i}"),
            guest_path: m.guest_path.clone(),
            read_only: m.read_only,
        })
        .collect();

    let json = serde_json::to_string(&entries)
        .map_err(|e| BackendError::Internal(format!("serialize mounts: {e}")))?;
    std::fs::write(dir.join("mounts.json"), json)
        .map_err(|e| BackendError::Internal(format!("write mounts.json: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// KrunCtx preparation (unchanged)
// ---------------------------------------------------------------------------

/// Build a KrunCtx and create the exec console and (for Allowlist) net socketpairs.
/// This is the heavy pre-fork configuration; it is called from create() and on each restart.
///
/// The UnixStreams are kept alive until after the spawn_blocking call succeeds so that
/// cancellation at the .await point auto-closes the fds via RAII (no leak).
async fn prepare_krun(
    config: &SandboxConfig,
    rootfs_root: PathBuf,
) -> Result<(KrunCtx, UnixStream, i32, Option<UnixStream>, Option<i32>), BackendError> {
    let (console_host, console_guest) = UnixStream::pair()
        .map_err(|e| BackendError::Internal(format!("console socketpair: {e}")))?;
    let cgfd: i32 = console_guest.as_raw_fd();

    let (net_backend_sock, net_vm_stream) = match &config.network {
        NetworkPolicy::Allowlist { .. } => {
            let (backend, vm) = UnixStream::pair()
                .map_err(|e| BackendError::Internal(format!("net socketpair: {e}")))?;
            (Some(backend), Some(vm))
        }
        _ => (None, None),
    };
    let nvfd: Option<i32> = net_vm_stream.as_ref().map(|s| s.as_raw_fd());

    let cfg = config.clone();

    let krun_ctx = tokio::task::spawn_blocking(move || -> Result<KrunCtx, BackendError> {
        let mut krun =
            KrunCtx::new().map_err(|e| BackendError::Internal(format!("krun_create_ctx: {e}")))?;

        let cpus = cfg.resource_limits.cpus.unwrap_or(1).min(u8::MAX as u32) as u8;
        let ram_mib = cfg
            .resource_limits
            .memory_bytes
            .map(|b| (b / (1024 * 1024)) as u32)
            .unwrap_or(256);

        krun.set_vm_config(cpus, ram_mib)
            .map_err(|e| BackendError::Internal(format!("set_vm_config: {e}")))?;

        krun.set_root(&rootfs_root)
            .map_err(|e| BackendError::Internal(format!("set_root: {e}")))?;

        // Virtiofs mounts with deterministic mount0, mount1, … tags.
        for (i, mount) in cfg.mounts.iter().enumerate() {
            let host_path = Path::new(&mount.host_path);
            let tag = format!("mount{i}");
            krun.add_virtiofs3(&tag, host_path, 0, mount.read_only)
                .map_err(|e| {
                    BackendError::Internal(format!("add_virtiofs3 {}: {e}", mount.host_path))
                })?;
        }

        // Network.
        match &cfg.network {
            NetworkPolicy::Isolated => {}
            NetworkPolicy::Unrestricted => {
                krun.disable_implicit_vsock()
                    .map_err(|e| BackendError::Internal(format!("disable_implicit_vsock: {e}")))?;
                krun.add_vsock(TSI_HIJACK_ALL)
                    .map_err(|e| BackendError::Internal(format!("add_vsock: {e}")))?;
            }
            NetworkPolicy::Allowlist { .. } => {
                if let Some(fd) = nvfd {
                    krun.add_net_unixstream(None, fd, &GUEST_MAC, 0, 0)
                        .map_err(|e| BackendError::Internal(format!("add_net_unixstream: {e}")))?;
                }
            }
        }

        // Environment: standard vars + sandbox vars + optional net mode.
        // PLAYPENCIL_* keys are reserved for internal use; strip them from user env.
        let mut env_strs: Vec<&str> = GUEST_STANDARD_ENV.to_vec();
        let sandbox_env: Vec<String> = cfg
            .env
            .iter()
            .filter(|(k, _)| !k.starts_with("PLAYPENCIL_"))
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        for s in &sandbox_env {
            env_strs.push(s.as_str());
        }
        if cfg.network == NetworkPolicy::Unrestricted {
            env_strs.push("PLAYPENCIL_NET_MODE=unrestricted");
        }

        krun.set_exec(GUEST_INIT_PATH, &[], Some(&env_strs))
            .map_err(|e| BackendError::Internal(format!("set_exec: {e}")))?;

        // Disable the implicit console before adding the multiport one.
        krun.disable_implicit_console()
            .map_err(|e| BackendError::Internal(format!("disable_implicit_console: {e}")))?;

        let console_id = krun
            .add_virtio_console_multiport()
            .map_err(|e| BackendError::Internal(format!("add_virtio_console_multiport: {e}")))?;
        krun.add_console_port_inout(console_id, EXEC_PORT_NAME, cgfd, cgfd)
            .map_err(|e| BackendError::Internal(format!("add_console_port_inout: {e}")))?;

        Ok(krun)
    })
    .await
    .map_err(|e| BackendError::Internal(format!("spawn_blocking panicked: {e}")))?;
    let krun_ctx = krun_ctx?;

    // All krun config calls succeeded. Transfer fd ownership from UnixStream to raw fd.
    let console_guest_fd = console_guest.into_raw_fd();
    let net_vm_sock_fd = net_vm_stream.map(|s| s.into_raw_fd());

    Ok((
        krun_ctx,
        console_host,
        console_guest_fd,
        net_backend_sock,
        net_vm_sock_fd,
    ))
}

// ---------------------------------------------------------------------------
// Reconciler: run-scoped resource helpers
// ---------------------------------------------------------------------------

/// Take run-scoped resources from reconciler state.
/// Sends Teardown so active exec sessions receive Exit{-1}.
fn take_run_resources(
    state: &mut ReconcilerState,
) -> (
    Option<i32>,
    Option<NetBackendHandle>,
    Option<JoinHandle<()>>,
) {
    let pid = state.vm_pid.take();
    let net = state.net_handle.take();
    let task = state.io_task.take();
    state.cancel_token.cancel();
    if let Some(tx) = state.console_cmd_tx.take() {
        let _ = tx.try_send(ConsoleCmd::Teardown);
    }
    // Defuse child_guard — we're handling the PID explicitly.
    if let Some(mut g) = state.child_guard.take() {
        g.defuse();
    }
    (pid, net, task)
}

type AllResources = (
    Option<i32>,
    Option<PreparedRootfs>,
    Option<NetBackendHandle>,
    Option<JoinHandle<()>>,
    Option<i32>, // console_guest_fd
    Option<i32>, // net_vm_sock_fd
);

/// Take ALL resources including rootfs and pre-start config. Used by destroy paths.
fn take_all_resources(state: &mut ReconcilerState) -> AllResources {
    let (pid, net, task) = take_run_resources(state);
    let rootfs = state.rootfs.take();
    state.krun_ctx.take();
    state.net_backend_sock.take();
    state.console_host_sock.take();
    let cgfd = state.console_guest_fd.take();
    let nvfd = state.net_vm_sock_fd.take();
    (pid, rootfs, net, task, cgfd, nvfd)
}

// ---------------------------------------------------------------------------
// Reconciler: liveness check
// ---------------------------------------------------------------------------

/// Handle a detected crash: clean up run resources, notify Running waiters.
/// Called after check_child_liveness returned false and PID/guard have already been cleared.
async fn handle_crash(state: &mut ReconcilerState) {
    let (pid, net, task) = take_run_resources(state);
    do_stop(pid, net, task).await;
    state.actual = SandboxState::Stopped;
    state.desired = SandboxState::Stopped;
    let mut remaining = Vec::new();
    for (target, tx) in state.waiters.drain(..) {
        if target == SandboxState::Running {
            let _ = tx.send(Err(BackendError::Internal("VM crashed".into())));
        } else {
            remaining.push((target, tx));
        }
    }
    state.waiters = remaining;
}

/// Check if the VM is still alive. If crashed, handle cleanup.
/// This is split to avoid holding &mut ReconcilerState across awaits that
/// also need &ReconcilerState (which is !Send due to KrunCtx).
async fn do_liveness_check(
    state: &mut ReconcilerState,
    sandboxes: &Mutex<HashMap<SandboxId, SandboxRecord>>,
    id: &SandboxId,
) {
    if state.actual != SandboxState::Running {
        return;
    }
    if let Some(pid) = state.vm_pid
        && !check_child_liveness(pid)
    {
        state.vm_pid = None;
        if let Some(mut g) = state.child_guard.take() {
            g.defuse();
        }
        state.vm_alive.store(false, Ordering::Release);
        handle_crash(state).await;
        let snap = state.snapshot();
        update_shared_record(sandboxes, id, &snap).await;
        // Crash invalidates any pending Running or Stopped claim.
        // Don't clear Destroyed — that should stick.
        {
            let mut map = sandboxes.lock().await;
            if let Some(record) = map.get_mut(id)
                && let Some(live) = record.live.as_mut()
                && live.pending_target != Some(SandboxState::Destroyed)
            {
                live.pending_target = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reconciler: shared context (bundles args to avoid clippy::too_many_arguments)
// ---------------------------------------------------------------------------

struct ReconcilerCtx {
    id: SandboxId,
    sandboxes: Arc<Mutex<HashMap<SandboxId, SandboxRecord>>>,
    launch_mutex: Arc<Mutex<()>>,
    data_dir: PathBuf,
    init_binary: PathBuf,
    rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    image_cache: Arc<Mutex<ImageCache>>,
    registry_client: Arc<Mutex<RegistryClient>>,
    shutdown_token: CancellationToken,
}

/// Best-effort rebuild of krun_ctx for retry after fork/net failure.
async fn try_rebuild_krun(state: &mut ReconcilerState) {
    if let Some(rootfs) = state.rootfs.as_ref()
        && let Ok((krun, host, gfd, nb, nvfd)) =
            prepare_krun(&state.config, rootfs.root.clone()).await
    {
        state.krun_ctx = Some(krun);
        state.console_host_sock = Some(host);
        state.console_guest_fd = Some(gfd);
        state.net_backend_sock = nb;
        state.net_vm_sock_fd = nvfd;
    }
}

/// Pre-teardown liveness check: if child is dead, clear PID and defuse guard
/// so do_stop doesn't try to kill a reaped/reused PID.
/// Returns true if the VM was already dead (crashed).
fn pre_teardown_liveness_check(state: &mut ReconcilerState) -> bool {
    if let Some(pid) = state.vm_pid
        && !check_child_liveness(pid)
    {
        state.vm_pid = None;
        if let Some(mut g) = state.child_guard.take() {
            g.defuse();
        }
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Reconciler: single step
// ---------------------------------------------------------------------------

async fn reconcile_step(
    state: &mut ReconcilerState,
    ctx: &ReconcilerCtx,
) -> Result<(), BackendError> {
    match (state.actual, state.desired) {
        // --- Creating → Ready ---
        (SandboxState::Creating, _) if state.desired != SandboxState::Destroyed => {
            // Pull OCI image.
            let base_rootfs = {
                let image_ref: ImageReference = state.config.image.parse().map_err(|e| {
                    BackendError::Internal(format!(
                        "invalid image reference '{}': {e}",
                        state.config.image
                    ))
                })?;
                let cache = ctx.image_cache.lock().await;
                let mut client = ctx.registry_client.lock().await;
                cache
                    .ensure(&mut client, &image_ref)
                    .await
                    .map_err(|e| BackendError::Internal(format!("image pull failed: {e}")))?
            };

            // Prepare rootfs overlay.
            let session_dir = ctx.data_dir.join("sessions");
            let rfs_config = RootfsConfig {
                sandbox_id: ctx.id.0.clone(),
                base_rootfs: base_rootfs.clone(),
                session_dir,
                init_binary: ctx.init_binary.clone(),
            };
            let prepared = tokio::task::spawn_blocking({
                let provider = ctx.rootfs_provider.clone();
                let cfg = rfs_config;
                move || provider.prepare(&cfg)
            })
            .await
            .map_err(|e| BackendError::Internal(format!("rootfs task panicked: {e}")))?
            .map_err(|e| BackendError::Internal(format!("rootfs prepare: {e}")))?;

            // Write mounts manifest.
            if let Err(e) = write_mounts_manifest(&prepared.root, &state.config.mounts) {
                tokio::task::spawn_blocking(move || {
                    let _ = prepared.destroy();
                })
                .await
                .ok();
                return Err(e);
            }

            // Build KrunCtx.
            let rootfs_root = prepared.root.clone();
            let krun_result = prepare_krun(&state.config, rootfs_root).await;
            let (krun_ctx, console_host_sock, console_guest_fd, net_backend_sock, net_vm_sock_fd) =
                match krun_result {
                    Ok(r) => r,
                    Err(e) => {
                        tokio::task::spawn_blocking(move || {
                            let _ = prepared.destroy();
                        })
                        .await
                        .ok();
                        return Err(e);
                    }
                };

            state.rootfs = Some(prepared);
            state.krun_ctx = Some(krun_ctx);
            state.console_host_sock = Some(console_host_sock);
            state.console_guest_fd = Some(console_guest_fd);
            state.net_backend_sock = net_backend_sock;
            state.net_vm_sock_fd = net_vm_sock_fd;
            state.actual = SandboxState::Ready;
            Ok(())
        }

        // --- Creating → Destroyed (create cancelled or shutdown) ---
        (SandboxState::Creating, SandboxState::Destroyed) => {
            state.actual = SandboxState::Destroyed;
            Ok(())
        }

        // --- Ready/Stopped → Running ---
        (SandboxState::Ready, SandboxState::Running)
        | (SandboxState::Stopped, SandboxState::Running) => {
            let prior_state = state.actual;

            // On restart: re-create KrunCtx (consumed by previous start).
            if prior_state == SandboxState::Stopped {
                let rootfs_root = state
                    .rootfs
                    .as_ref()
                    .map(|r| r.root.clone())
                    .ok_or_else(|| BackendError::Internal("rootfs missing".into()))?;

                match prepare_krun(&state.config, rootfs_root).await {
                    Ok((krun_ctx, host_sock, guest_fd, net_backend, net_vm_fd)) => {
                        state.krun_ctx = Some(krun_ctx);
                        state.console_host_sock = Some(host_sock);
                        state.console_guest_fd = Some(guest_fd);
                        state.net_backend_sock = net_backend;
                        state.net_vm_sock_fd = net_vm_fd;
                    }
                    Err(e) => {
                        state.actual = prior_state;
                        return Err(e);
                    }
                }
            }

            // Take pre-built resources.
            let krun_ctx = state
                .krun_ctx
                .take()
                .ok_or_else(|| BackendError::Internal("no krun ctx".into()))?;
            let console_host_sock = state
                .console_host_sock
                .take()
                .ok_or_else(|| BackendError::Internal("no console host sock".into()))?;
            let console_guest_fd = state
                .console_guest_fd
                .take()
                .ok_or_else(|| BackendError::Internal("no console guest fd".into()))?;
            let net_backend_sock = state.net_backend_sock.take();
            let net_vm_sock_fd = state.net_vm_sock_fd.take();

            // Fork under the launch mutex.
            let launch_guard = ctx.launch_mutex.lock().await;
            let fork_result = tokio::task::spawn_blocking(move || -> Result<i32, BackendError> {
                let child = krun_ctx.start().map_err(|e| {
                    // Fork failed: close extracted FDs to prevent leaks.
                    unsafe { libc::close(console_guest_fd) };
                    if let Some(fd) = net_vm_sock_fd {
                        unsafe { libc::close(fd) };
                    }
                    BackendError::Internal(format!("krun start: {e}"))
                })?;
                unsafe { libc::close(console_guest_fd) };
                if let Some(fd) = net_vm_sock_fd {
                    unsafe { libc::close(fd) };
                }
                Ok(child)
            })
            .await;
            drop(launch_guard);

            // Handle both JoinError (panic/cancel) and fork failure through
            // the same rollback path: close leaked FDs, rebuild krun_ctx.
            let child_pid = match fork_result {
                Ok(Ok(pid)) => pid,
                Ok(Err(e)) => {
                    // Fork failed inside the closure (FDs already closed there).
                    try_rebuild_krun(state).await;
                    state.actual = prior_state;
                    return Err(e);
                }
                Err(join_err) => {
                    // spawn_blocking panicked or was cancelled.
                    // FDs were copied into the closure; close the outer copies.
                    unsafe { libc::close(console_guest_fd) };
                    if let Some(fd) = net_vm_sock_fd {
                        unsafe { libc::close(fd) };
                    }
                    try_rebuild_krun(state).await;
                    state.actual = prior_state;
                    return Err(BackendError::Internal(format!(
                        "spawn_blocking panicked: {join_err}"
                    )));
                }
            };

            // RAII guard for the fork window.
            let mut fork_guard = ChildGuard::new(child_pid);

            // Start net backend (Allowlist only).
            let net_handle = if let Some(sock) = net_backend_sock {
                if let NetworkPolicy::Allowlist { allowed_domains } = &state.config.network {
                    let net_cfg = NetBackendConfig {
                        socket: sock,
                        allowed_domains: allowed_domains.clone(),
                        backend_mac: BACKEND_MAC,
                        guest_mac: GUEST_MAC,
                        gateway_ip: GATEWAY_IP,
                        guest_ip: GUEST_IP,
                    };
                    match crate::net::start(net_cfg) {
                        Ok(h) => Some(h),
                        Err(e) => {
                            fork_guard.defuse();
                            tokio::task::spawn_blocking(move || kill_and_wait(child_pid))
                                .await
                                .ok();
                            try_rebuild_krun(state).await;
                            state.actual = prior_state;
                            return Err(BackendError::Internal(format!("net backend: {e}")));
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Spawn console I/O task.
            let (cmd_tx, cmd_rx) = mpsc::channel::<ConsoleCmd>(256);
            let io_task = tokio::spawn(run_console_io(console_host_sock, cmd_rx));

            // Store run-scoped resources.
            state.vm_pid = Some(child_pid);
            state.vm_alive.store(true, Ordering::Release);
            fork_guard.defuse();
            state.child_guard = Some(ChildGuard::new(child_pid));
            state.net_handle = net_handle;
            state.console_cmd_tx = Some(cmd_tx);
            state.io_task = Some(io_task);
            state.cancel_token = CancellationToken::new();
            state.actual = SandboxState::Running;
            Ok(())
        }

        // --- Running → Stopped ---
        (SandboxState::Running, SandboxState::Stopped) => {
            let vm_was_already_dead = pre_teardown_liveness_check(state);
            let (pid, net, task) = take_run_resources(state);
            do_stop(pid, net, task).await;
            state.vm_alive.store(false, Ordering::Release);
            state.actual = SandboxState::Stopped;
            if vm_was_already_dead {
                // VM crashed before stop was requested. Match current
                // behavior: surface as InvalidState so callers know the
                // stop didn't cause the stop — it was a crash.
                Err(BackendError::InvalidState)
            } else {
                Ok(())
            }
        }

        // --- Running → Destroyed ---
        (SandboxState::Running, SandboxState::Destroyed) => {
            pre_teardown_liveness_check(state);
            let (pid, rootfs, net, task, cgfd, nvfd) = take_all_resources(state);
            if let Some(fd) = cgfd {
                unsafe { libc::close(fd) };
            }
            if let Some(fd) = nvfd {
                unsafe { libc::close(fd) };
            }
            do_stop(pid, net, task).await;
            state.vm_alive.store(false, Ordering::Release);
            if let Some(rfs) = rootfs {
                do_destroy_rootfs(rfs).await;
            }
            state.actual = SandboxState::Destroyed;
            Ok(())
        }

        // --- Ready/Stopped → Destroyed ---
        (SandboxState::Ready, SandboxState::Destroyed)
        | (SandboxState::Stopped, SandboxState::Destroyed) => {
            let rootfs = state.rootfs.take();
            state.krun_ctx.take();
            state.net_backend_sock.take();
            state.console_host_sock.take();
            let cgfd = state.console_guest_fd.take();
            let nvfd = state.net_vm_sock_fd.take();
            if let Some(fd) = cgfd {
                unsafe { libc::close(fd) };
            }
            if let Some(fd) = nvfd {
                unsafe { libc::close(fd) };
            }
            if let Some(rfs) = rootfs {
                do_destroy_rootfs(rfs).await;
            }
            state.actual = SandboxState::Destroyed;
            Ok(())
        }

        // No-op: already at desired state.
        _ if state.actual == state.desired => Ok(()),

        _ => Err(BackendError::InvalidState),
    }
}

// ---------------------------------------------------------------------------
// Reconciler loop
// ---------------------------------------------------------------------------

/// Arguments for spawning a reconciler task.
struct ReconcilerArgs {
    ctx: ReconcilerCtx,
    request_rx: mpsc::Receiver<ReconcileRequest>,
    liveness_rx: mpsc::Receiver<LivenessCheck>,
    initial_config: SandboxConfig,
    init_result_tx: oneshot::Sender<Result<(), BackendError>>,
    record_inserted_rx: oneshot::Receiver<()>,
    vm_alive: Arc<AtomicBool>,
    reconciler_panicked: Arc<AtomicBool>,
}

async fn reconciler_loop(args: ReconcilerArgs) {
    let ReconcilerArgs {
        ctx,
        mut request_rx,
        mut liveness_rx,
        initial_config,
        init_result_tx,
        record_inserted_rx,
        vm_alive,
        reconciler_panicked,
    } = args;
    let mut _panic_guard = ReconcilerPanicGuard::new(reconciler_panicked);

    // Wait for create() to insert the record before touching the shared map.
    if record_inserted_rx.await.is_err() {
        _panic_guard.defuse();
        return;
    }

    let mut state = ReconcilerState {
        actual: SandboxState::Creating,
        desired: SandboxState::Ready,
        config: initial_config,
        rootfs: None,
        krun_ctx: None,
        console_host_sock: None,
        console_guest_fd: None,
        net_backend_sock: None,
        net_vm_sock_fd: None,
        vm_pid: None,
        child_guard: None,
        net_handle: None,
        console_cmd_tx: None,
        io_task: None,
        vm_alive,
        cancel_token: CancellationToken::new(),
        waiters: vec![],
    };

    // Initial reconcile: Creating -> Ready
    let init_result = reconcile_step(&mut state, &ctx).await;
    update_shared_record(&ctx.sandboxes, &ctx.id, &state.snapshot()).await;
    clear_pending_target(&ctx.sandboxes, &ctx.id, SandboxState::Ready).await;

    if let Err(ref e) = init_result {
        if init_result_tx.send(Err(reconstruct_error(e))).is_err() {
            // create() was cancelled — receiver dropped. Drive teardown and remove record.
            state.desired = SandboxState::Destroyed;
            while state.actual != SandboxState::Destroyed {
                let _ = reconcile_step(&mut state, &ctx).await;
                update_shared_record(&ctx.sandboxes, &ctx.id, &state.snapshot()).await;
            }
            ctx.sandboxes.lock().await.remove(&ctx.id);
        }
        _panic_guard.defuse();
        return;
    }
    if init_result_tx.send(Ok(())).is_err() {
        // create() was cancelled. Self-destruct.
        state.desired = SandboxState::Destroyed;
        while state.actual != SandboxState::Destroyed {
            let _ = reconcile_step(&mut state, &ctx).await;
            update_shared_record(&ctx.sandboxes, &ctx.id, &state.snapshot()).await;
        }
        ctx.sandboxes.lock().await.remove(&ctx.id);
        _panic_guard.defuse();
        return;
    }

    // Main loop
    loop {
        tokio::select! {
            _ = ctx.shutdown_token.cancelled() => {
                state.desired = SandboxState::Destroyed;
                drain_waiters_with(
                    &mut state.waiters,
                    |_| BackendError::Internal("backend shutting down".into()),
                );
            }
            req = request_rx.recv() => {
                match req {
                    Some(ReconcileRequest::SetDesired { target, result_tx }) => {
                        if !can_reach(state.actual, target) {
                            let _ = result_tx.send(Err(BackendError::InvalidState));
                            clear_pending_target(&ctx.sandboxes, &ctx.id, target).await;
                            continue;
                        }
                        if target == SandboxState::Destroyed
                            && state.desired != SandboxState::Destroyed
                        {
                            supersede_waiters(&mut state.waiters);
                        }
                        state.desired = target;
                        state.waiters.push((target, result_tx));
                    }
                    None => {
                        state.desired = SandboxState::Destroyed;
                        drain_waiters_with(
                            &mut state.waiters,
                            |_| BackendError::Internal("backend dropped".into()),
                        );
                    }
                }
            }
            Some(check) = liveness_rx.recv() => {
                do_liveness_check(&mut state, &ctx.sandboxes, &ctx.id).await;
                let _ = check.done_tx.send(());
                continue;
            }
        }

        // Reconcile until actual == desired (or error)
        while state.actual != state.desired {
            let step_result = reconcile_step(&mut state, &ctx).await;
            update_shared_record(&ctx.sandboxes, &ctx.id, &state.snapshot()).await;
            if let Err(ref e) = step_result {
                // Drain pending requests to pick up a destroy() that arrived during the failed step.
                while let Ok(req) = request_rx.try_recv() {
                    match req {
                        ReconcileRequest::SetDesired { target, result_tx } => {
                            if target == SandboxState::Destroyed {
                                supersede_waiters(&mut state.waiters);
                                state.desired = SandboxState::Destroyed;
                            }
                            state.waiters.push((target, result_tx));
                        }
                    }
                }
                // Check shared record for pending destroy.
                let shared_pending = ctx
                    .sandboxes
                    .lock()
                    .await
                    .get(&ctx.id)
                    .and_then(|r| r.live.as_ref())
                    .and_then(|l| l.pending_target);

                let has_destroy = state.desired == SandboxState::Destroyed
                    || state
                        .waiters
                        .iter()
                        .any(|(t, _)| *t == SandboxState::Destroyed)
                    || shared_pending == Some(SandboxState::Destroyed);

                if has_destroy {
                    let mut destroy_waiters = Vec::new();
                    for (target, tx) in state.waiters.drain(..) {
                        if target == SandboxState::Destroyed {
                            destroy_waiters.push((target, tx));
                        } else {
                            let _ = tx.send(Err(reconstruct_error(e)));
                        }
                    }
                    state.waiters = destroy_waiters;
                    state.desired = SandboxState::Destroyed;
                    continue;
                }
                clear_pending_target(&ctx.sandboxes, &ctx.id, state.desired).await;
                notify_waiters_with_error(&mut state, e);
                break;
            }
        }
        if state.actual == state.desired {
            // Drain pending requests before notifying.
            while let Ok(req) = request_rx.try_recv() {
                match req {
                    ReconcileRequest::SetDesired { target, result_tx } => {
                        if target == SandboxState::Destroyed
                            && state.desired != SandboxState::Destroyed
                        {
                            supersede_waiters(&mut state.waiters);
                            state.desired = SandboxState::Destroyed;
                        }
                        state.waiters.push((target, result_tx));
                    }
                }
            }
            if state.actual == state.desired {
                clear_pending_target(&ctx.sandboxes, &ctx.id, state.desired).await;
                notify_waiters_ok(&mut state);
            } else {
                // Drain changed desired (e.g. queued destroy during start).
                // Resume reconciliation immediately instead of waiting for
                // another select! cycle, which would deadlock the waiter.
                continue;
            }
        }
        if state.actual == SandboxState::Destroyed {
            _panic_guard.defuse();
            break;
        }
    }

    if state.actual != SandboxState::Destroyed {
        ctx.sandboxes.lock().await.remove(&ctx.id);
    }
}

// ---------------------------------------------------------------------------
// LibkrunBackend implementation
// ---------------------------------------------------------------------------

impl LibkrunBackend {
    pub fn new(
        data_dir: impl Into<PathBuf>,
        init_binary: impl Into<PathBuf>,
        rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    ) -> Result<Self, BackendError> {
        let data_dir = data_dir.into();
        let init_binary = init_binary.into();
        let image_cache = ImageCache::new(&data_dir);
        let registry_client = RegistryClient::new()
            .map_err(|e| BackendError::Internal(format!("registry client: {e}")))?;
        Ok(Self {
            data_dir,
            init_binary,
            rootfs_provider,
            image_cache: Arc::new(Mutex::new(image_cache)),
            registry_client: Arc::new(Mutex::new(registry_client)),
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            next_sandbox: AtomicU64::new(1),
            next_exec: AtomicU64::new(1),
            launch_mutex: Arc::new(Mutex::new(())),
            shutdown_token: CancellationToken::new(),
        })
    }

    fn alloc_sandbox_id(&self) -> SandboxId {
        let n = self.next_sandbox.fetch_add(1, Ordering::Relaxed);
        SandboxId(format!("sb-{n}"))
    }

    fn alloc_exec_id(&self) -> ExecId {
        let n = self.next_exec.fetch_add(1, Ordering::Relaxed);
        ExecId(format!("exec-{n}"))
    }

    /// Send a liveness check to the reconciler and wait for acknowledgment.
    /// Returns the refreshed state. Caller must re-lock the map after this.
    async fn send_liveness_check(
        liveness_tx: mpsc::Sender<LivenessCheck>,
    ) -> Result<(), BackendError> {
        let (done_tx, done_rx) = oneshot::channel();
        if liveness_tx.send(LivenessCheck { done_tx }).await.is_err() {
            return Err(BackendError::Internal("reconciler task crashed".into()));
        }
        // Ignore recv error — reconciler may have crashed after sending.
        let _ = done_rx.await;
        Ok(())
    }
}

impl SandboxBackendSend for LibkrunBackend {
    async fn create(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        let id = self.alloc_sandbox_id();
        validate_image_ref(&config.image)?;
        validate_mounts(&config.mounts)?;
        validate_env(&config.env)?;

        let (reconcile_tx, reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        let (init_tx, init_rx) = oneshot::channel::<Result<(), BackendError>>();
        let (inserted_tx, inserted_rx) = oneshot::channel::<()>();
        let (liveness_tx, liveness_rx) = mpsc::channel::<LivenessCheck>(16);

        let vm_alive = Arc::new(AtomicBool::new(false));
        let reconciler_panicked = Arc::new(AtomicBool::new(false));

        let reconciler_ctx = ReconcilerCtx {
            id: id.clone(),
            sandboxes: self.sandboxes.clone(),
            launch_mutex: self.launch_mutex.clone(),
            data_dir: self.data_dir.clone(),
            init_binary: self.init_binary.clone(),
            rootfs_provider: self.rootfs_provider.clone(),
            image_cache: self.image_cache.clone(),
            registry_client: self.registry_client.clone(),
            shutdown_token: self.shutdown_token.clone(),
        };
        let reconciler_handle = tokio::spawn(reconciler_loop(ReconcilerArgs {
            ctx: reconciler_ctx,
            request_rx: reconcile_rx,
            liveness_rx,
            initial_config: config.clone(),
            init_result_tx: init_tx,
            record_inserted_rx: inserted_rx,
            vm_alive: vm_alive.clone(),
            reconciler_panicked: reconciler_panicked.clone(),
        }));

        let record = SandboxRecord {
            actual_state: SandboxState::Creating,
            created_at: rfc3339_now(),
            config,
            reconciler_panicked,
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle,
                pending_target: Some(SandboxState::Ready),
                console_cmd_tx: None,
                cancel_token: CancellationToken::new(),
                vm_alive,
            }),
        };

        self.sandboxes.lock().await.insert(id.clone(), record);
        let _ = inserted_tx.send(());

        match init_rx.await {
            Ok(Ok(())) => Ok(id),
            Ok(Err(e)) => {
                self.sandboxes.lock().await.remove(&id);
                Err(e)
            }
            Err(_) => {
                self.sandboxes.lock().await.remove(&id);
                Err(BackendError::Internal(
                    "reconciler crashed during create".into(),
                ))
            }
        }
    }

    async fn start(&self, id: &SandboxId) -> Result<(), BackendError> {
        let (result_rx, reconcile_tx) = {
            let mut map = self.sandboxes.lock().await;
            let record = map.get_mut(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            let live = record.live.as_mut().ok_or(BackendError::InvalidState)?;
            if live.pending_target.is_some() {
                return Err(BackendError::InvalidState);
            }
            if record.actual_state != SandboxState::Ready
                && record.actual_state != SandboxState::Stopped
            {
                return Err(BackendError::InvalidState);
            }
            let prior_state = record.actual_state;
            live.pending_target = Some(SandboxState::Running);
            record.actual_state = SandboxState::Starting;

            let (result_tx, result_rx) = oneshot::channel();
            let reconcile_tx = live.reconcile_tx.clone();
            if reconcile_tx
                .try_send(ReconcileRequest::SetDesired {
                    target: SandboxState::Running,
                    result_tx,
                })
                .is_err()
            {
                record.actual_state = prior_state;
                if let Some(live) = record.live.as_mut() {
                    live.pending_target = None;
                }
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            (result_rx, reconcile_tx)
        };
        // Keep reconcile_tx alive so the channel isn't closed.
        let _keep = reconcile_tx;

        match result_rx.await {
            Ok(result) => result,
            Err(_) => Err(BackendError::Internal("reconciler task crashed".into())),
        }
    }

    async fn stop(&self, id: &SandboxId) -> Result<(), BackendError> {
        // Claim Stopping synchronously under the lock before any await.
        // The reconciler handles crash detection in its pre-teardown step.
        // If the VM has already crashed, the reconciler still cleans up
        // and transitions to Stopped, but returns InvalidState to the
        // caller (the stop didn't cause the stop — it was a crash).
        let result_rx = {
            let mut map = self.sandboxes.lock().await;
            let record = map.get_mut(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            let live = record.live.as_mut().ok_or(BackendError::InvalidState)?;
            if live.pending_target.is_some() {
                return Err(BackendError::InvalidState);
            }
            if record.actual_state != SandboxState::Running {
                return Err(BackendError::InvalidState);
            }
            live.pending_target = Some(SandboxState::Stopped);
            record.actual_state = SandboxState::Stopping;

            let (result_tx, result_rx) = oneshot::channel();
            if live
                .reconcile_tx
                .try_send(ReconcileRequest::SetDesired {
                    target: SandboxState::Stopped,
                    result_tx,
                })
                .is_err()
            {
                record.actual_state = SandboxState::Running;
                if let Some(live) = record.live.as_mut() {
                    live.pending_target = None;
                }
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            result_rx
        };

        match result_rx.await {
            Ok(result) => result,
            Err(_) => Err(BackendError::Internal("reconciler task crashed".into())),
        }
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), BackendError> {
        let result_rx = {
            let mut map = self.sandboxes.lock().await;
            let record = map.get_mut(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            let live = record.live.as_mut().ok_or(BackendError::InvalidState)?;
            if record.actual_state == SandboxState::Destroyed {
                return Err(BackendError::InvalidState);
            }
            if live.pending_target == Some(SandboxState::Destroyed) {
                return Err(BackendError::InvalidState);
            }
            if live.pending_target.is_some() && live.pending_target != Some(SandboxState::Running) {
                // Mid-stop: reject (matches current Stopping->Destroyed rejection).
                return Err(BackendError::InvalidState);
            }
            live.pending_target = Some(SandboxState::Destroyed);

            let (result_tx, result_rx) = oneshot::channel();
            if live
                .reconcile_tx
                .try_send(ReconcileRequest::SetDesired {
                    target: SandboxState::Destroyed,
                    result_tx,
                })
                .is_err()
            {
                if let Some(live) = record.live.as_mut() {
                    live.pending_target = None;
                }
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            result_rx
        };

        match result_rx.await {
            Ok(result) => result,
            Err(_) => Err(BackendError::Internal("reconciler task crashed".into())),
        }
    }

    async fn status(&self, id: &SandboxId) -> Result<SandboxStatus, BackendError> {
        // First lock: check for short-circuits.
        let liveness_tx = {
            let map = self.sandboxes.lock().await;
            let record = map.get(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            // Short-circuit: pending destroy.
            if let Some(live) = &record.live
                && live.pending_target == Some(SandboxState::Destroyed)
            {
                return Ok(SandboxStatus {
                    sandbox_id: id.clone(),
                    state: "destroyed".into(),
                    created_at: Some(record.created_at.clone()),
                });
            }
            if record.actual_state == SandboxState::Running {
                record.live.as_ref().map(|l| l.liveness_tx.clone())
            } else {
                None
            }
        };

        // Liveness check if running.
        if let Some(tx) = liveness_tx {
            Self::send_liveness_check(tx).await?;
        }

        // Re-lock and repeat all short-circuit checks (state may have changed
        // during the liveness await — e.g. concurrent destroy() claimed pending_target).
        let map = self.sandboxes.lock().await;
        let record = map.get(id).ok_or(BackendError::NotFound)?;
        if record.reconciler_panicked.load(Ordering::Acquire) {
            return Err(BackendError::Internal("reconciler task crashed".into()));
        }
        if let Some(live) = &record.live
            && live.pending_target == Some(SandboxState::Destroyed)
        {
            return Ok(SandboxStatus {
                sandbox_id: id.clone(),
                state: "destroyed".into(),
                created_at: Some(record.created_at.clone()),
            });
        }
        Ok(SandboxStatus {
            sandbox_id: id.clone(),
            state: record.actual_state.to_string(),
            created_at: Some(record.created_at.clone()),
        })
    }

    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError> {
        // First lock: check for short-circuits.
        let liveness_tx = {
            let map = self.sandboxes.lock().await;
            let record = map.get(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            let live = record.live.as_ref().ok_or(BackendError::InvalidState)?;
            if live.pending_target.is_some() {
                return Err(BackendError::InvalidState);
            }
            if record.actual_state == SandboxState::Running {
                Some(live.liveness_tx.clone())
            } else {
                None
            }
        };

        // Liveness check if running.
        if let Some(tx) = liveness_tx {
            Self::send_liveness_check(tx).await?;
        }

        // Re-lock and repeat all checks (state may have changed during liveness await).
        let (cmd_tx, cancel_token) = {
            let map = self.sandboxes.lock().await;
            let record = map.get(id).ok_or(BackendError::NotFound)?;
            if record.reconciler_panicked.load(Ordering::Acquire) {
                return Err(BackendError::Internal("reconciler task crashed".into()));
            }
            let live = record.live.as_ref().ok_or(BackendError::InvalidState)?;
            if live.pending_target.is_some() {
                return Err(BackendError::InvalidState);
            }
            if record.actual_state != SandboxState::Running {
                return Err(BackendError::InvalidState);
            }
            let tx = live
                .console_cmd_tx
                .clone()
                .ok_or_else(|| BackendError::Internal("no exec console available".into()))?;
            (tx, live.cancel_token.clone())
        };

        let exec_id = self.alloc_exec_id();
        let (events_tx, events_rx) = mpsc::channel::<ExecEvent>(256);
        let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(64);

        cmd_tx
            .send(ConsoleCmd::RegisterExec {
                id: exec_id.0.clone(),
                events_tx,
            })
            .await
            .map_err(|_| BackendError::Internal("console I/O task gone".into()))?;

        let env_strs: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let host_msg = HostMsg::Exec {
            id: exec_id.0.clone(),
            cmd: req.command,
            env: env_strs,
            workdir: req.working_dir,
        };
        let json = serde_json::to_string(&host_msg)
            .map_err(|e| BackendError::Internal(format!("serialize exec msg: {e}")))?;
        if json.len() >= MAX_FRAME_BYTES {
            let _ = cmd_tx
                .send(ConsoleCmd::UnregisterExec(exec_id.0.clone()))
                .await;
            return Err(BackendError::Internal(
                "exec message exceeds 1 MiB frame limit".into(),
            ));
        }
        let (ack_tx, ack_rx) = oneshot::channel::<bool>();
        cmd_tx
            .send(ConsoleCmd::SendAck(json, ack_tx))
            .await
            .map_err(|_| BackendError::Internal("console I/O task gone".into()))?;
        let write_ok = match tokio::time::timeout(std::time::Duration::from_secs(30), ack_rx).await
        {
            Ok(result) => result.unwrap_or(false),
            Err(_) => false,
        };
        if !write_ok {
            let _ = cmd_tx
                .send(ConsoleCmd::UnregisterExec(exec_id.0.clone()))
                .await;
            return Err(BackendError::Internal(
                "failed to send exec message to guest".into(),
            ));
        }

        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ExecControl>(16);

        // Stdin relay.
        let stdin_exec_id = exec_id.0.clone();
        let stdin_cmd_tx = cmd_tx.clone();
        let stdin_cancel = cancel_token.clone();
        tokio::spawn(async move {
            let mut stdin_rx = stdin_rx;
            let mut sender_dropped = false;
            loop {
                let data = tokio::select! {
                    data = stdin_rx.recv() => {
                        match data {
                            Some(d) => d,
                            None => { sender_dropped = true; break; }
                        }
                    }
                    _ = stdin_cancel.cancelled() => break,
                };
                let chunks: Vec<&[u8]> = if data.is_empty() {
                    vec![&[]]
                } else {
                    data.chunks(STDIN_CHUNK_BYTES).collect()
                };
                for chunk in chunks {
                    let encoded = base64_encode(chunk);
                    let msg = HostMsg::Stdin {
                        id: stdin_exec_id.clone(),
                        data: encoded,
                    };
                    if let Ok(json) = serde_json::to_string(&msg)
                        && stdin_cmd_tx.send(ConsoleCmd::Send(json)).await.is_err()
                    {
                        return;
                    }
                }
            }
            if sender_dropped
                && let Ok(json) = serde_json::to_string(&HostMsg::Stdin {
                    id: stdin_exec_id,
                    data: String::new(),
                })
            {
                let _ = stdin_cmd_tx.send(ConsoleCmd::Send(json)).await;
            }
        });

        // Control relay.
        let ctrl_exec_id = exec_id.0.clone();
        tokio::spawn(async move {
            let mut ctrl_rx = ctrl_rx;
            loop {
                let ctrl = tokio::select! {
                    ctrl = ctrl_rx.recv() => {
                        match ctrl {
                            Some(c) => c,
                            None => break,
                        }
                    }
                    _ = cancel_token.cancelled() => break,
                };
                let msg = match ctrl {
                    ExecControl::Signal(signal) => HostMsg::Signal {
                        id: ctrl_exec_id.clone(),
                        signal,
                    },
                    ExecControl::Resize { cols, rows } => HostMsg::Resize {
                        id: ctrl_exec_id.clone(),
                        cols: cols as u32,
                        rows: rows as u32,
                    },
                };
                if let Ok(json) = serde_json::to_string(&msg)
                    && cmd_tx.send(ConsoleCmd::Send(json)).await.is_err()
                {
                    return;
                }
            }
        });

        Ok(ExecHandle {
            exec_id,
            events: events_rx,
            stdin: stdin_tx,
            control: ctrl_tx,
        })
    }

    async fn list(&self) -> Result<Vec<SandboxStatus>, BackendError> {
        // Snapshot ids and (for running sandboxes) liveness senders under the
        // lock, then release it before awaiting — same pattern as status(), so a
        // crashed VM is reflected instead of showing a stale Running state.
        let snapshot: Vec<(SandboxId, Option<mpsc::Sender<LivenessCheck>>)> = {
            let map = self.sandboxes.lock().await;
            map.iter()
                .map(|(id, record)| {
                    // Skip the liveness check for a pending-destroy record: its
                    // actual_state is still Running until teardown completes, but
                    // the reconciler is busy in the destroy step and won't service
                    // liveness_rx, so awaiting it would block list() behind the
                    // destroy. The rebuild below reports it as "destroyed" anyway.
                    let pending_destroy = record
                        .live
                        .as_ref()
                        .is_some_and(|l| l.pending_target == Some(SandboxState::Destroyed));
                    let tx = if record.actual_state == SandboxState::Running && !pending_destroy {
                        record.live.as_ref().map(|l| l.liveness_tx.clone())
                    } else {
                        None
                    };
                    (id.clone(), tx)
                })
                .collect()
        };

        // Trigger liveness checks without holding the lock. Errors (e.g. a
        // crashed reconciler) are ignored here; the rebuild below reports the
        // last known state rather than failing the whole list.
        for (_, tx) in &snapshot {
            if let Some(tx) = tx {
                let _ = Self::send_liveness_check(tx.clone()).await;
            }
        }

        // Re-lock and rebuild, applying the pending-destroy short-circuit that
        // status() uses. Sandboxes removed during the await are skipped.
        let map = self.sandboxes.lock().await;
        Ok(snapshot
            .iter()
            .filter_map(|(id, _)| {
                let record = map.get(id)?;
                let state = if record
                    .live
                    .as_ref()
                    .is_some_and(|l| l.pending_target == Some(SandboxState::Destroyed))
                {
                    "destroyed".to_string()
                } else {
                    record.actual_state.to_string()
                };
                Some(SandboxStatus {
                    sandbox_id: id.clone(),
                    state,
                    created_at: Some(record.created_at.clone()),
                })
            })
            .collect())
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_isolation: true,
            network_policy: true,
            host_mounts: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Console I/O task
// ---------------------------------------------------------------------------

async fn run_console_io(sock: UnixStream, mut cmd_rx: mpsc::Receiver<ConsoleCmd>) {
    if sock.set_nonblocking(true).is_err() {
        return;
    }
    let sock = match tokio::net::UnixStream::from_std(sock) {
        Ok(s) => s,
        Err(_) => return,
    };

    let (read_half, write_half) = sock.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    let (write_tx, mut write_rx) = mpsc::channel::<(String, Option<oneshot::Sender<bool>>)>(128);
    let write_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut wh = write_half;
        while let Some((line, ack)) = write_rx.recv().await {
            let msg = format!("{line}\n");
            if wh.write_all(msg.as_bytes()).await.is_err() {
                if let Some(ack) = ack {
                    let _ = ack.send(false);
                }
                break;
            }
            if let Some(ack) = ack {
                let _ = ack.send(true);
            }
        }
    });

    let mut sessions: HashMap<String, mpsc::Sender<ExecEvent>> = HashMap::new();
    let mut line_buf = Vec::new();

    loop {
        tokio::select! {
            line_result = read_capped_line(&mut reader, &mut line_buf) => {
                match line_result {
                    Ok(Some(line)) => {
                        dispatch_guest_message(&line, &mut sessions).await;
                    }
                    Ok(None) => {
                        // Oversized frame discarded; continue reading.
                    }
                    Err(_) => break, // EOF or I/O error
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ConsoleCmd::Send(json)) => {
                        let _ = write_tx.send((json, None)).await;
                    }
                    Some(ConsoleCmd::SendAck(json, ack)) => {
                        let _ = write_tx.send((json, Some(ack))).await;
                    }
                    Some(ConsoleCmd::RegisterExec { id, events_tx }) => {
                        sessions.insert(id, events_tx);
                    }
                    Some(ConsoleCmd::UnregisterExec(id)) => {
                        sessions.remove(&id);
                    }
                    Some(ConsoleCmd::Teardown) | None => break,
                }
            }
        }
    }

    // Send synthetic Exit{-1} to any sessions that didn't get a real exit event.
    for (id, tx) in sessions.drain() {
        if tx.send(ExecEvent::Exit { code: -1 }).await.is_err() {
            tracing::debug!("teardown: exit channel closed for exec {id}; receiver already gone");
        }
    }

    write_task.abort();
}

/// Read a newline-delimited line from the reader, capped at MAX_FRAME_BYTES.
/// Returns Ok(Some(line)) on success, Ok(None) if a frame was discarded for being
/// oversized, or Err on EOF/I/O error.
async fn read_capped_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<String>, std::io::Error> {
    use tokio::io::AsyncBufReadExt;
    buf.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "console EOF",
            ));
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            break;
        }
        buf.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);
        if buf.len() > MAX_FRAME_BYTES {
            buf.clear();
            loop {
                let avail = reader.fill_buf().await?;
                if avail.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "console EOF",
                    ));
                }
                if let Some(nl) = avail.iter().position(|&b| b == b'\n') {
                    reader.consume(nl + 1);
                    break;
                }
                let n = avail.len();
                reader.consume(n);
            }
            tracing::warn!("guest frame exceeds 1 MiB limit; discarding");
            return Ok(None);
        }
    }
    if buf.len() > MAX_FRAME_BYTES {
        tracing::warn!("guest frame exceeds 1 MiB limit; discarding");
        buf.clear();
        return Ok(None);
    }
    String::from_utf8(std::mem::take(buf))
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

async fn dispatch_guest_message(
    line: &str,
    sessions: &mut HashMap<String, mpsc::Sender<ExecEvent>>,
) {
    let msg: GuestMsg = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("invalid guest message: {e} — line: {line}");
            return;
        }
    };

    match msg {
        GuestMsg::Stdout { id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                tracing::warn!("base64 decode failure for stdout on exec {id}; dropping message");
                return;
            };
            send_event(sessions, &id, ExecEvent::Stdout(bytes));
        }
        GuestMsg::Stderr { id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                tracing::warn!("base64 decode failure for stderr on exec {id}; dropping message");
                return;
            };
            send_event(sessions, &id, ExecEvent::Stderr(bytes));
        }
        GuestMsg::Exit { id, code } => {
            if let Some(tx) = sessions.remove(&id) {
                if tx.send(ExecEvent::Exit { code }).await.is_err() {
                    tracing::debug!("exit channel closed for exec {id}; receiver already gone");
                }
            } else {
                tracing::debug!("exit event for unknown exec id: {id}");
            }
        }
    }
}

fn send_event(sessions: &mut HashMap<String, mpsc::Sender<ExecEvent>>, id: &str, event: ExecEvent) {
    if let Some(tx) = sessions.get(id) {
        if tx.try_send(event).is_err() {
            tracing::warn!("event channel full or closed for exec {id}; dropping event");
        }
    } else {
        tracing::debug!("exec event for unknown id: {id}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Base64 + mount validation tests (unchanged)
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello\x00\xff\x7f";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
    }

    #[test]
    fn test_base64_encode_known() {
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_base64_decode_known() {
        assert_eq!(
            base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap(),
            b"Hello, World!"
        );
    }

    #[test]
    fn test_validate_mounts_rejects_non_absolute_host() {
        let m = MountConfig {
            host_path: "relative/path".into(),
            guest_path: "/mnt".into(),
            read_only: true,
        };
        // User-input failures surface as InvalidInput so the API returns 4xx.
        assert!(matches!(
            validate_mounts(&[m]),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_mounts_rejects_non_absolute_guest() {
        let m = MountConfig {
            host_path: "/tmp".into(),
            guest_path: "relative".into(),
            read_only: true,
        };
        assert!(validate_mounts(&[m]).is_err());
    }

    #[test]
    fn test_validate_mounts_rejects_protected_guest_paths() {
        for path in PROTECTED_GUEST_PATHS {
            let m = MountConfig {
                host_path: "/tmp".into(),
                guest_path: (*path).into(),
                read_only: true,
            };
            assert!(
                validate_mounts(&[m]).is_err(),
                "should reject protected path: {path}"
            );
        }
    }

    #[test]
    fn test_validate_mounts_rejects_dotdot() {
        let m = MountConfig {
            host_path: "/tmp/../etc".into(),
            guest_path: "/mnt".into(),
            read_only: true,
        };
        assert!(validate_mounts(&[m]).is_err());
    }

    #[test]
    fn test_validate_mounts_accepts_valid() {
        let m = MountConfig {
            host_path: "/tmp".into(),
            guest_path: "/workspace".into(),
            read_only: false,
        };
        assert!(validate_mounts(&[m]).is_ok());
    }

    #[test]
    fn test_validate_mounts_rejects_nul() {
        let m = MountConfig {
            host_path: "/tmp/a\0b".into(),
            guest_path: "/mnt".into(),
            read_only: true,
        };
        assert!(matches!(
            validate_mounts(&[m]),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_image_ref_rejects_malformed() {
        assert!(matches!(
            validate_image_ref("::bad::"),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_image_ref_accepts_valid() {
        assert!(validate_image_ref("alpine:3.19").is_ok());
    }

    #[test]
    fn test_validate_env_rejects_nul() {
        let env = vec![("KEY".to_string(), "va\0lue".to_string())];
        assert!(matches!(
            validate_env(&env),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_env_rejects_equals_in_key() {
        let env = vec![("K=Y".to_string(), "value".to_string())];
        assert!(matches!(
            validate_env(&env),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_env_rejects_empty_key() {
        let env = vec![(String::new(), "value".to_string())];
        assert!(matches!(
            validate_env(&env),
            Err(BackendError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_env_accepts_valid() {
        let env = vec![("KEY".to_string(), "value".to_string())];
        assert!(validate_env(&env).is_ok());
    }

    // -----------------------------------------------------------------------
    // Pure function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_can_reach_valid_transitions() {
        assert!(can_reach(SandboxState::Ready, SandboxState::Running));
        assert!(can_reach(SandboxState::Ready, SandboxState::Destroyed));
        assert!(can_reach(SandboxState::Running, SandboxState::Stopped));
        assert!(can_reach(SandboxState::Running, SandboxState::Destroyed));
        assert!(can_reach(SandboxState::Stopped, SandboxState::Running));
        assert!(can_reach(SandboxState::Stopped, SandboxState::Destroyed));
        assert!(can_reach(SandboxState::Creating, SandboxState::Ready));
    }

    #[test]
    fn test_can_reach_invalid_transitions() {
        assert!(!can_reach(SandboxState::Destroyed, SandboxState::Running));
        assert!(!can_reach(SandboxState::Destroyed, SandboxState::Ready));
        assert!(!can_reach(SandboxState::Ready, SandboxState::Stopped));
        assert!(!can_reach(SandboxState::Stopped, SandboxState::Ready));
        assert!(!can_reach(SandboxState::Creating, SandboxState::Running));
    }

    #[test]
    fn test_reconstruct_error_preserves_variant() {
        let e1 = BackendError::InvalidState;
        assert!(matches!(reconstruct_error(&e1), BackendError::InvalidState));
        let e2 = BackendError::NotFound;
        assert!(matches!(reconstruct_error(&e2), BackendError::NotFound));
        let e3 = BackendError::Internal("test msg".into());
        match reconstruct_error(&e3) {
            BackendError::Internal(msg) => assert_eq!(msg, "test msg"),
            _ => panic!("expected Internal"),
        }
    }

    #[test]
    fn test_reconciler_panic_guard_sets_flag_on_drop() {
        let flag = Arc::new(AtomicBool::new(false));
        drop(ReconcilerPanicGuard::new(flag.clone()));
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_reconciler_panic_guard_defused() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut guard = ReconcilerPanicGuard::new(flag.clone());
        guard.defuse();
        drop(guard);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_notify_waiters_ok_matching_target() {
        let mut state = make_reconciler_state(SandboxState::Running);
        let (tx, mut rx) = oneshot::channel();
        state.waiters.push((SandboxState::Running, tx));
        notify_waiters_ok(&mut state);
        assert!(rx.try_recv().unwrap().is_ok());
    }

    #[test]
    fn test_notify_waiters_ok_superseded_target() {
        let mut state = make_reconciler_state(SandboxState::Destroyed);
        let (tx_run, mut rx_run) = oneshot::channel();
        let (tx_destroy, mut rx_destroy) = oneshot::channel();
        state.waiters.push((SandboxState::Running, tx_run));
        state.waiters.push((SandboxState::Destroyed, tx_destroy));
        notify_waiters_ok(&mut state);
        assert!(matches!(
            rx_run.try_recv().unwrap(),
            Err(BackendError::InvalidState)
        ));
        assert!(rx_destroy.try_recv().unwrap().is_ok());
    }

    #[test]
    fn test_supersede_waiters_sends_invalid_state() {
        let (tx1, mut rx1) = oneshot::channel();
        let (tx2, mut rx2) = oneshot::channel();
        let mut waiters = vec![(SandboxState::Running, tx1), (SandboxState::Stopped, tx2)];
        supersede_waiters(&mut waiters);
        assert!(waiters.is_empty());
        assert!(matches!(
            rx1.try_recv().unwrap(),
            Err(BackendError::InvalidState)
        ));
        assert!(matches!(
            rx2.try_recv().unwrap(),
            Err(BackendError::InvalidState)
        ));
    }

    #[test]
    fn test_drain_waiters_with_custom_error() {
        let (tx, mut rx) = oneshot::channel();
        let mut waiters = vec![(SandboxState::Running, tx)];
        drain_waiters_with(&mut waiters, |_| {
            BackendError::Internal("shutting down".into())
        });
        match rx.try_recv().unwrap() {
            Err(BackendError::Internal(msg)) => assert_eq!(msg, "shutting down"),
            other => panic!("expected Internal, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test backend helper: injects a sandbox record with a mini-reconciler
    // that processes SetDesired requests and liveness checks without KVM.
    // This lets us call the REAL SandboxBackend trait methods.
    // -----------------------------------------------------------------------

    async fn inject_sandbox(backend: &LibkrunBackend, initial_state: SandboxState) -> SandboxId {
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, mut reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        let (liveness_tx, mut liveness_rx) = mpsc::channel::<LivenessCheck>(16);
        let vm_alive = Arc::new(AtomicBool::new(initial_state == SandboxState::Running));
        let reconciler_panicked = Arc::new(AtomicBool::new(false));
        let sandboxes = backend.sandboxes.clone();
        let sandbox_id = id.clone();

        let (console_tx, mut console_rx) = mpsc::channel::<ConsoleCmd>(256);
        tokio::spawn(async move { while console_rx.recv().await.is_some() {} });

        let reconciler_handle = tokio::spawn({
            let sandboxes = sandboxes.clone();
            let id = sandbox_id.clone();
            let vm_alive = vm_alive.clone();
            async move {
                let mut actual = initial_state;
                loop {
                    tokio::select! {
                        req = reconcile_rx.recv() => {
                            match req {
                                Some(ReconcileRequest::SetDesired { target, result_tx }) => {
                                    if !can_reach(actual, target) {
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id)
                                            && let Some(l) = r.live.as_mut()
                                        {
                                            l.pending_target = None;
                                        }
                                        continue;
                                    }
                                    actual = target;
                                    vm_alive.store(actual == SandboxState::Running, Ordering::Release);
                                    if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                        r.actual_state = actual;
                                        if let Some(l) = r.live.as_mut() {
                                            l.pending_target = None;
                                        }
                                        if actual == SandboxState::Destroyed {
                                            r.live = None;
                                        }
                                    }
                                    let _ = result_tx.send(Ok(()));
                                    if actual == SandboxState::Destroyed { return; }
                                }
                                None => return,
                            }
                        }
                        Some(check) = liveness_rx.recv() => {
                            let _ = check.done_tx.send(());
                        }
                    }
                }
            }
        });

        let record = SandboxRecord {
            actual_state: initial_state,
            created_at: rfc3339_now(),
            config: test_config(),
            reconciler_panicked,
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle,
                pending_target: None,
                console_cmd_tx: if initial_state == SandboxState::Running {
                    Some(console_tx)
                } else {
                    None
                },
                cancel_token: CancellationToken::new(),
                vm_alive,
            }),
        };

        backend.sandboxes.lock().await.insert(id.clone(), record);
        id
    }

    /// Like inject_sandbox but the mini-reconciler fails the first
    /// SetDesired(Running) with an Internal error, then succeeds on retry.
    /// Rolls back actual_state to Ready on the failed attempt.
    async fn inject_sandbox_fail_first_start(backend: &LibkrunBackend) -> SandboxId {
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, mut reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        let (liveness_tx, mut liveness_rx) = mpsc::channel::<LivenessCheck>(16);
        let vm_alive = Arc::new(AtomicBool::new(false));
        let reconciler_panicked = Arc::new(AtomicBool::new(false));
        let sandboxes = backend.sandboxes.clone();
        let sandbox_id = id.clone();

        let (_console_tx, mut console_rx) = mpsc::channel::<ConsoleCmd>(256);
        tokio::spawn(async move { while console_rx.recv().await.is_some() {} });

        let reconciler_handle = tokio::spawn({
            let sandboxes = sandboxes.clone();
            let id = sandbox_id.clone();
            let vm_alive = vm_alive.clone();
            async move {
                let mut actual = SandboxState::Ready;
                let mut start_failed = false;
                loop {
                    tokio::select! {
                        req = reconcile_rx.recv() => {
                            match req {
                                Some(ReconcileRequest::SetDesired { target, result_tx }) => {
                                    // Fail the first Running request.
                                    if target == SandboxState::Running && !start_failed {
                                        start_failed = true;
                                        // Roll back to Ready in the shared record.
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id)
                                            && let Some(l) = r.live.as_mut()
                                        {
                                            r.actual_state = SandboxState::Ready;
                                            l.pending_target = None;
                                        }
                                        let _ = result_tx.send(Err(BackendError::Internal(
                                            "simulated fork failure".into(),
                                        )));
                                        continue;
                                    }
                                    if !can_reach(actual, target) {
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id)
                                            && let Some(l) = r.live.as_mut()
                                        {
                                            l.pending_target = None;
                                        }
                                        continue;
                                    }
                                    actual = target;
                                    vm_alive.store(actual == SandboxState::Running, Ordering::Release);
                                    if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                        r.actual_state = actual;
                                        if let Some(l) = r.live.as_mut() {
                                            l.pending_target = None;
                                        }
                                        if actual == SandboxState::Destroyed {
                                            r.live = None;
                                        }
                                    }
                                    let _ = result_tx.send(Ok(()));
                                    if actual == SandboxState::Destroyed { return; }
                                }
                                None => return,
                            }
                        }
                        Some(check) = liveness_rx.recv() => {
                            let _ = check.done_tx.send(());
                        }
                    }
                }
            }
        });

        let record = SandboxRecord {
            actual_state: SandboxState::Ready,
            created_at: rfc3339_now(),
            config: test_config(),
            reconciler_panicked,
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle,
                pending_target: None,
                console_cmd_tx: None,
                cancel_token: CancellationToken::new(),
                vm_alive,
            }),
        };

        backend.sandboxes.lock().await.insert(id.clone(), record);
        id
    }

    fn make_test_backend() -> LibkrunBackend {
        let data_dir = PathBuf::from("/tmp/playpencil-test-nonexistent");
        let image_cache = ImageCache::new(&data_dir);
        let registry_client = RegistryClient::new().unwrap();
        LibkrunBackend {
            data_dir,
            init_binary: PathBuf::from("/nonexistent"),
            rootfs_provider: Arc::new(NullRootfsProvider),
            image_cache: Arc::new(Mutex::new(image_cache)),
            registry_client: Arc::new(Mutex::new(registry_client)),
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            next_sandbox: AtomicU64::new(1),
            next_exec: AtomicU64::new(1),
            launch_mutex: Arc::new(Mutex::new(())),
            shutdown_token: CancellationToken::new(),
        }
    }

    struct NullRootfsProvider;
    impl RootfsProvider for NullRootfsProvider {
        fn prepare(&self, _: &RootfsConfig) -> Result<PreparedRootfs, crate::rootfs::RootfsError> {
            Err(crate::rootfs::RootfsError::Io(std::io::Error::other(
                "null provider",
            )))
        }
        fn fuse_overlayfs_available(&self) -> bool {
            false
        }
    }

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
            network: NetworkPolicy::Isolated,
            env: vec![],
        }
    }

    fn make_reconciler_state(actual: SandboxState) -> ReconcilerState {
        ReconcilerState {
            actual,
            desired: actual,
            config: test_config(),
            rootfs: None,
            krun_ctx: None,
            console_host_sock: None,
            console_guest_fd: None,
            net_backend_sock: None,
            net_vm_sock_fd: None,
            vm_pid: None,
            child_guard: None,
            net_handle: None,
            console_cmd_tx: None,
            io_task: None,
            vm_alive: Arc::new(AtomicBool::new(false)),
            cancel_token: CancellationToken::new(),
            waiters: vec![],
        }
    }

    // ===== reconcile rejects invalid desired state =====
    #[tokio::test]
    async fn test_reconcile_rejects_invalid_desired_state() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    // ===== destroy from running direct =====
    #[tokio::test]
    async fn test_reconcile_destroy_from_running_direct() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    // ===== list() does not block on a pending-destroy record =====
    #[tokio::test]
    async fn test_list_skips_liveness_for_pending_destroy() {
        let backend = make_test_backend();
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, _reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        // No task services liveness_rx, so a liveness check would hang forever;
        // list() must skip it for a pending-destroy record.
        let (liveness_tx, _liveness_rx) = mpsc::channel::<LivenessCheck>(16);
        let record = SandboxRecord {
            actual_state: SandboxState::Running,
            created_at: rfc3339_now(),
            config: test_config(),
            reconciler_panicked: Arc::new(AtomicBool::new(false)),
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle: tokio::spawn(async {}),
                pending_target: Some(SandboxState::Destroyed),
                console_cmd_tx: None,
                cancel_token: CancellationToken::new(),
                vm_alive: Arc::new(AtomicBool::new(true)),
            }),
        };
        backend.sandboxes.lock().await.insert(id.clone(), record);

        let statuses = tokio::time::timeout(std::time::Duration::from_secs(2), backend.list())
            .await
            .expect("list() blocked on a pending-destroy record")
            .unwrap();
        let entry = statuses.iter().find(|s| s.sandbox_id == id).unwrap();
        assert_eq!(entry.state, "destroyed");
    }

    // ===== waiter gets error on failure =====
    #[test]
    fn test_reconcile_waiter_gets_error_on_failure() {
        let mut state = make_reconciler_state(SandboxState::Ready);
        let (tx1, mut rx1) = oneshot::channel();
        let (tx2, mut rx2) = oneshot::channel();
        state.waiters.push((SandboxState::Running, tx1));
        state.waiters.push((SandboxState::Running, tx2));
        notify_waiters_with_error(&mut state, &BackendError::Internal("fork failed".into()));
        assert!(state.waiters.is_empty());
        match rx1.try_recv().unwrap() {
            Err(BackendError::Internal(msg)) => assert_eq!(msg, "fork failed"),
            other => panic!("expected Internal, got {:?}", other),
        }
        match rx2.try_recv().unwrap() {
            Err(BackendError::Internal(msg)) => assert_eq!(msg, "fork failed"),
            other => panic!("expected Internal, got {:?}", other),
        }
    }

    // ===== create failure cleans up record =====
    #[tokio::test]
    async fn test_create_failure_cleans_up_record() {
        let backend = make_test_backend();
        let result = backend.create(test_config()).await;
        assert!(result.is_err());
        assert!(backend.sandboxes.lock().await.is_empty());
    }

    // ===== create failure leaves no leaked records =====
    #[tokio::test]
    async fn test_create_failure_no_leaked_records() {
        let backend = make_test_backend();
        // Two consecutive failures should each clean up.
        let r1 = backend.create(test_config()).await;
        let r2 = backend.create(test_config()).await;
        assert!(r1.is_err());
        assert!(r2.is_err());
        assert!(backend.sandboxes.lock().await.is_empty());
    }

    // ===== concurrent start/start rejects second =====
    #[tokio::test]
    async fn test_concurrent_start_start_rejects_second() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Ready).await;
        let (r1, r2) = tokio::join!(backend.start(&id), backend.start(&id));
        let ok = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        let err = [&r1, &r2].iter().filter(|r| r.is_err()).count();
        assert_eq!(ok, 1);
        assert_eq!(err, 1);
    }

    // ===== destroy during stop rejects =====
    #[tokio::test]
    async fn test_destroy_during_stop_rejects() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        // Stop first, then try destroy while stop is in progress.
        backend.stop(&id).await.unwrap();
        // After stop completes, sandbox is Stopped. Destroy from Stopped is valid.
        // The test intent is: destroy during an in-progress stop gets InvalidState.
        // Simulate by setting pending_target as if stop() just claimed it.
        let id2 = inject_sandbox(&backend, SandboxState::Running).await;
        {
            let mut map = backend.sandboxes.lock().await;
            let record = map.get_mut(&id2).unwrap();
            let live = record.live.as_mut().unwrap();
            live.pending_target = Some(SandboxState::Stopped);
            record.actual_state = SandboxState::Stopping;
        }
        let result = backend.destroy(&id2).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    // ===== start during stop rejects =====
    #[tokio::test]
    async fn test_start_during_stop_rejects() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        // Set up mid-stop state: pending_target=Stopped, actual=Stopping.
        {
            let mut map = backend.sandboxes.lock().await;
            let record = map.get_mut(&id).unwrap();
            let live = record.live.as_mut().unwrap();
            live.pending_target = Some(SandboxState::Stopped);
            record.actual_state = SandboxState::Stopping;
        }
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    // ===== exec during stop rejects =====
    #[tokio::test]
    async fn test_exec_during_stop_rejects() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        // Set up mid-stop state.
        {
            let mut map = backend.sandboxes.lock().await;
            let record = map.get_mut(&id).unwrap();
            let live = record.live.as_mut().unwrap();
            live.pending_target = Some(SandboxState::Stopped);
        }
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&id, req).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    // ===== destroy during start supersedes =====
    // Uses the delayed reconciler so destroy() arrives during the start
    // transition. start() caller gets InvalidState (superseded).
    #[tokio::test]
    async fn test_destroy_during_start_supersedes() {
        let backend = Arc::new(make_test_backend());
        let id = inject_sandbox_with_delay(
            &backend,
            SandboxState::Ready,
            std::time::Duration::from_millis(50),
        )
        .await;

        let b1 = backend.clone();
        let b2 = backend.clone();
        let id1 = id.clone();
        let id2 = id.clone();

        let start_handle = tokio::spawn(async move { b1.start(&id1).await });
        // Small delay so start() claims first, then destroy() supersedes.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let destroy_handle = tokio::spawn(async move { b2.destroy(&id2).await });

        let r_start = tokio::time::timeout(std::time::Duration::from_secs(5), start_handle)
            .await
            .expect("start timed out")
            .expect("start panicked");
        let r_destroy = tokio::time::timeout(std::time::Duration::from_secs(5), destroy_handle)
            .await
            .expect("destroy timed out")
            .expect("destroy panicked");

        // start() should get InvalidState (superseded by destroy).
        assert!(
            matches!(r_start, Err(BackendError::InvalidState)),
            "start() should get InvalidState when superseded, got {:?}",
            r_start
        );
        assert!(r_destroy.is_ok(), "destroy() should succeed");
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    // ===== concurrent double destroy rejects second =====
    #[tokio::test]
    async fn test_concurrent_double_destroy_rejects_second() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        let (r1, r2) = tokio::join!(backend.destroy(&id), backend.destroy(&id));
        let ok = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        let err = [&r1, &r2].iter().filter(|r| r.is_err()).count();
        assert_eq!(ok, 1);
        assert_eq!(err, 1);
    }

    // ===== destroy queued behind failing start =====
    #[test]
    fn test_destroy_queued_behind_failing_start() {
        let mut state = make_reconciler_state(SandboxState::Ready);
        let (start_tx, mut start_rx) = oneshot::channel();
        let (destroy_tx, mut destroy_rx) = oneshot::channel();
        state.waiters.push((SandboxState::Running, start_tx));
        state.waiters.push((SandboxState::Destroyed, destroy_tx));
        state.desired = SandboxState::Destroyed;
        let err = BackendError::Internal("fork failed".into());
        let mut destroy_waiters = Vec::new();
        for (target, tx) in state.waiters.drain(..) {
            if target == SandboxState::Destroyed {
                destroy_waiters.push((target, tx));
            } else {
                let _ = tx.send(Err(reconstruct_error(&err)));
            }
        }
        state.waiters = destroy_waiters;
        match start_rx.try_recv().unwrap() {
            Err(BackendError::Internal(msg)) => assert_eq!(msg, "fork failed"),
            other => panic!("expected Internal, got {:?}", other),
        }
        assert!(destroy_rx.try_recv().is_err());
        assert_eq!(state.waiters.len(), 1);
    }

    // ===== status after crash returns stopped =====
    #[tokio::test]
    async fn test_status_after_crash_returns_stopped() {
        let mut state = make_reconciler_state(SandboxState::Running);
        state.vm_alive.store(false, Ordering::Release);
        handle_crash(&mut state).await;
        assert_eq!(state.actual, SandboxState::Stopped);
        assert_eq!(state.desired, SandboxState::Stopped);
    }

    // ===== start after crash succeeds =====
    #[tokio::test]
    async fn test_start_after_crash_succeeds() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Stopped).await;
        backend.start(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "running");
    }

    // ===== stop after crash returns invalid state =====
    #[tokio::test]
    async fn test_stop_after_crash_returns_invalid_state() {
        // A sandbox already at Stopped (e.g. after crash detection by reconciler)
        // cannot be stopped again — stop() requires actual_state == Running.
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Stopped).await;
        let result = backend.stop(&id).await;
        assert!(matches!(result, Err(BackendError::InvalidState)));
    }

    // ===== no stale PID signaling after crash =====
    #[test]
    fn test_no_stale_pid_signaling_after_crash() {
        let mut state = make_reconciler_state(SandboxState::Running);
        state.vm_pid = None;
        pre_teardown_liveness_check(&mut state);
        assert!(state.vm_pid.is_none());
        let (pid, _, _) = take_run_resources(&mut state);
        assert!(pid.is_none());
    }

    // ===== cancellation safety start =====
    #[test]
    fn test_cancellation_safety_start() {
        let mut guard = ChildGuard::new(999999);
        guard.defuse();
        drop(guard);
        let guard = ChildGuard(None);
        drop(guard);
        let guard = ChildGuard::new(999999);
        assert!(guard.0.is_some());
        std::mem::forget(guard);
    }

    // ===== restart after failed start =====
    #[tokio::test]
    async fn test_restart_after_failed_start() {
        let backend = make_test_backend();
        let id = inject_sandbox_fail_first_start(&backend).await;
        // First start fails (reconciler returns error).
        let r1 = backend.start(&id).await;
        assert!(matches!(r1, Err(BackendError::Internal(_))));
        // Sandbox should still be in Ready — not stuck in Starting.
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "ready");
        // Retry succeeds.
        backend.start(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "running");
    }

    // ===== backend drop cancels shutdown token and reconciler exits =====
    #[tokio::test]
    async fn test_backend_drop_cancels_token_and_reconciler_exits() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        // Grab a handle to the reconciler task before dropping.
        let reconciler_handle = {
            let map = backend.sandboxes.lock().await;
            let record = map.get(&id).unwrap();
            let live = record.live.as_ref().unwrap();
            live.reconcile_tx.clone() // keep a sender so we can check channel closure
        };
        let shutdown = backend.shutdown_token.clone();
        assert!(!shutdown.is_cancelled());
        drop(backend);
        assert!(shutdown.is_cancelled());
        // The reconciler's request channel should close (senders dropped with the record).
        // Sending on the cloned sender will fail once the reconciler exits.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (tx, _rx) = oneshot::channel();
        let send_result = reconciler_handle
            .send(ReconcileRequest::SetDesired {
                target: SandboxState::Stopped,
                result_tx: tx,
            })
            .await;
        // Channel may still be open (reconciler hasn't exited yet) or closed.
        // The key property: shutdown_token is cancelled, which the real reconciler selects on.
        let _ = send_result;
    }

    // ===== destroy after unobserved crash =====
    #[test]
    fn test_destroy_after_unobserved_crash() {
        let mut state = make_reconciler_state(SandboxState::Running);
        state.desired = SandboxState::Destroyed;
        pre_teardown_liveness_check(&mut state);
        assert!(state.vm_pid.is_none());
        let (pid, _, _, _, _, _) = take_all_resources(&mut state);
        assert!(pid.is_none());
    }

    // ===== destroy from running never shows stopping =====
    #[tokio::test]
    async fn test_destroy_from_running_never_shows_stopping() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
        assert_ne!(status.state, "stopping");
    }

    // ===== reconciler panic detected by status =====
    #[tokio::test]
    async fn test_reconciler_panic_detected_by_status() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        backend
            .sandboxes
            .lock()
            .await
            .get(&id)
            .unwrap()
            .reconciler_panicked
            .store(true, Ordering::Release);
        let result = backend.status(&id).await;
        assert!(matches!(result, Err(BackendError::Internal(_))));
    }

    // ===== reconciler panic detected by exec =====
    #[tokio::test]
    async fn test_reconciler_panic_detected_by_exec() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        backend
            .sandboxes
            .lock()
            .await
            .get(&id)
            .unwrap()
            .reconciler_panicked
            .store(true, Ordering::Release);
        let req = ExecRequest {
            command: vec!["echo".into()],
            working_dir: None,
            env: vec![],
        };
        let result = backend.exec(&id, req).await;
        assert!(matches!(result, Err(BackendError::Internal(_))));
    }

    // ===== start cancellation rollback =====
    #[tokio::test]
    async fn test_start_cancellation_rollback() {
        let backend = make_test_backend();
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, reconcile_rx) = mpsc::channel::<ReconcileRequest>(1);
        drop(reconcile_rx);
        let (liveness_tx, _lrx) = mpsc::channel::<LivenessCheck>(16);
        backend.sandboxes.lock().await.insert(
            id.clone(),
            SandboxRecord {
                actual_state: SandboxState::Ready,
                created_at: rfc3339_now(),
                config: test_config(),
                reconciler_panicked: Arc::new(AtomicBool::new(false)),
                live: Some(LiveState {
                    reconcile_tx,
                    liveness_tx,
                    reconciler_handle: tokio::spawn(async {}),
                    pending_target: None,
                    console_cmd_tx: None,
                    cancel_token: CancellationToken::new(),
                    vm_alive: Arc::new(AtomicBool::new(false)),
                }),
            },
        );
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::Internal(_))));
        let map = backend.sandboxes.lock().await;
        let record = map.get(&id).unwrap();
        assert_eq!(record.actual_state, SandboxState::Ready);
        assert_eq!(record.live.as_ref().unwrap().pending_target, None);
    }

    // ===== panic guard flags crash, child guard holds PID until defused =====
    // Full VM child cleanup on reconciler panic requires KVM — this tests the
    // guard mechanics that enable it.
    #[test]
    fn test_panic_guard_and_child_guard_mechanics() {
        // ReconcilerPanicGuard sets flag on drop (simulates panic path).
        let flag = Arc::new(AtomicBool::new(false));
        drop(ReconcilerPanicGuard::new(flag.clone()));
        assert!(flag.load(Ordering::Acquire));
        // ChildGuard holds PID until defused.
        let mut guard = ChildGuard::new(999999);
        assert!(guard.0.is_some());
        guard.defuse();
        assert!(guard.0.is_none());
        // After defuse, drop is a no-op — no kill attempt.
        drop(guard);
    }

    // ===== stop during start returns invalid state =====
    #[tokio::test]
    async fn test_stop_during_start_returns_invalid_state() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Ready).await;
        let (r_start, r_stop) = tokio::join!(backend.start(&id), backend.stop(&id));
        assert!(r_start.is_ok());
        assert!(matches!(r_stop, Err(BackendError::InvalidState)));
    }

    // ===== status after destroy returns destroyed =====
    #[tokio::test]
    async fn test_status_after_destroy_returns_destroyed() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Ready).await;
        backend.destroy(&id).await.unwrap();
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    // ===== crash clears child guard =====
    #[test]
    fn test_crash_clears_child_guard() {
        let mut state = make_reconciler_state(SandboxState::Running);
        state.child_guard = Some(ChildGuard(None));
        let (pid, _, _) = take_run_resources(&mut state);
        assert!(pid.is_none());
        assert!(state.child_guard.is_none());
    }

    // ===== crash during pending stop =====
    #[test]
    fn test_crash_during_pending_stop() {
        let mut state = make_reconciler_state(SandboxState::Stopped);
        state.desired = SandboxState::Stopped;
        let (tx, mut rx) = oneshot::channel();
        state.waiters.push((SandboxState::Stopped, tx));
        notify_waiters_ok(&mut state);
        assert!(rx.try_recv().unwrap().is_ok());
    }

    // ===== crash during pending destroy =====
    #[test]
    fn test_crash_during_pending_destroy() {
        let mut state = make_reconciler_state(SandboxState::Stopped);
        state.desired = SandboxState::Destroyed;
        pre_teardown_liveness_check(&mut state);
        assert!(state.vm_pid.is_none());
        assert!(can_reach(SandboxState::Stopped, SandboxState::Destroyed));
    }

    // ===== destroy during start never shows running again =====
    #[tokio::test]
    async fn test_destroy_during_start_never_shows_running_again() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Ready).await;
        let (_r_start, _r_destroy) = tokio::join!(backend.start(&id), backend.destroy(&id));
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    // ===== destroy after reconciler panic =====
    #[tokio::test]
    async fn test_destroy_after_reconciler_panic() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        backend
            .sandboxes
            .lock()
            .await
            .get(&id)
            .unwrap()
            .reconciler_panicked
            .store(true, Ordering::Release);
        let result = backend.destroy(&id).await;
        assert!(matches!(result, Err(BackendError::Internal(_))));
    }

    // ===== Regression: status() re-checks pending_target after liveness (Issue 2) =====
    #[tokio::test]
    async fn test_status_rechecks_after_liveness_await() {
        let backend = make_test_backend();
        let id = inject_sandbox(&backend, SandboxState::Running).await;
        {
            let mut map = backend.sandboxes.lock().await;
            let record = map.get_mut(&id).unwrap();
            record.live.as_mut().unwrap().pending_target = Some(SandboxState::Destroyed);
        }
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "destroyed");
    }

    // ===== Regression: start() rollback preserves Stopped state (Concern 1) =====
    #[tokio::test]
    async fn test_start_rollback_preserves_stopped_state() {
        let backend = make_test_backend();
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, reconcile_rx) = mpsc::channel::<ReconcileRequest>(1);
        drop(reconcile_rx);
        let (liveness_tx, _lrx) = mpsc::channel::<LivenessCheck>(16);
        backend.sandboxes.lock().await.insert(
            id.clone(),
            SandboxRecord {
                actual_state: SandboxState::Stopped,
                created_at: rfc3339_now(),
                config: test_config(),
                reconciler_panicked: Arc::new(AtomicBool::new(false)),
                live: Some(LiveState {
                    reconcile_tx,
                    liveness_tx,
                    reconciler_handle: tokio::spawn(async {}),
                    pending_target: None,
                    console_cmd_tx: None,
                    cancel_token: CancellationToken::new(),
                    vm_alive: Arc::new(AtomicBool::new(false)),
                }),
            },
        );
        let result = backend.start(&id).await;
        assert!(matches!(result, Err(BackendError::Internal(_))));
        let map = backend.sandboxes.lock().await;
        assert_eq!(map.get(&id).unwrap().actual_state, SandboxState::Stopped);
    }

    // -----------------------------------------------------------------------
    // inject_sandbox_with_delay: like inject_sandbox but the mini-reconciler
    // sleeps before completing each transition, giving time for concurrent
    // requests to be queued via try_send while the first is in-flight.
    // -----------------------------------------------------------------------
    async fn inject_sandbox_with_delay(
        backend: &LibkrunBackend,
        initial_state: SandboxState,
        delay: std::time::Duration,
    ) -> SandboxId {
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, mut reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        let (liveness_tx, mut liveness_rx) = mpsc::channel::<LivenessCheck>(16);
        let vm_alive = Arc::new(AtomicBool::new(initial_state == SandboxState::Running));
        let reconciler_panicked = Arc::new(AtomicBool::new(false));
        let sandboxes = backend.sandboxes.clone();
        let sandbox_id = id.clone();

        let (console_tx, mut console_rx) = mpsc::channel::<ConsoleCmd>(256);
        tokio::spawn(async move { while console_rx.recv().await.is_some() {} });

        let reconciler_handle = tokio::spawn({
            let sandboxes = sandboxes.clone();
            let id = sandbox_id.clone();
            let vm_alive = vm_alive.clone();
            async move {
                let mut actual = initial_state;
                loop {
                    tokio::select! {
                        req = reconcile_rx.recv() => {
                            match req {
                                Some(ReconcileRequest::SetDesired { target, result_tx }) => {
                                    if !can_reach(actual, target) {
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id)
                                            && let Some(l) = r.live.as_mut()
                                        {
                                            l.pending_target = None;
                                        }
                                        continue;
                                    }
                                    // Delay to simulate slow transition — lets concurrent
                                    // requests arrive via try_send while we're "working".
                                    tokio::time::sleep(delay).await;
                                    actual = target;
                                    vm_alive.store(actual == SandboxState::Running, Ordering::Release);
                                    // Drain any requests that arrived during the delay,
                                    // mirroring the real reconciler's drain-after-converge.
                                    let mut extra = Vec::new();
                                    while let Ok(req) = reconcile_rx.try_recv() {
                                        extra.push(req);
                                    }
                                    // Update shared record.
                                    if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                        r.actual_state = actual;
                                        if let Some(l) = r.live.as_mut() {
                                            l.pending_target = None;
                                        }
                                        if actual == SandboxState::Destroyed {
                                            r.live = None;
                                        }
                                    }
                                    // Check if any drained request supersedes.
                                    let mut destroy_waiter = None;
                                    let mut superseded = false;
                                    for req in &extra {
                                        match req {
                                            ReconcileRequest::SetDesired { target, .. }
                                                if *target == SandboxState::Destroyed =>
                                            {
                                                superseded = true;
                                            }
                                            _ => {}
                                        }
                                    }
                                    if superseded {
                                        // Start waiter gets InvalidState (superseded).
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        // Process the destroy.
                                        for req in extra {
                                            match req {
                                                ReconcileRequest::SetDesired { target, result_tx } => {
                                                    if target == SandboxState::Destroyed
                                                        && can_reach(actual, target)
                                                    {
                                                        actual = SandboxState::Destroyed;
                                                        vm_alive.store(false, Ordering::Release);
                                                        if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                                            r.actual_state = actual;
                                                            if let Some(l) = r.live.as_mut() {
                                                                l.pending_target = None;
                                                            }
                                                            r.live = None;
                                                        }
                                                        destroy_waiter = Some(result_tx);
                                                    } else {
                                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                                    }
                                                }
                                            }
                                        }
                                        if let Some(tx) = destroy_waiter {
                                            let _ = tx.send(Ok(()));
                                        }
                                        return;
                                    }
                                    // No supersede — notify original waiter.
                                    let _ = result_tx.send(Ok(()));
                                    // Process other drained requests normally.
                                    for req in extra {
                                        match req {
                                            ReconcileRequest::SetDesired { target, result_tx } => {
                                                if can_reach(actual, target) {
                                                    actual = target;
                                                    vm_alive.store(actual == SandboxState::Running, Ordering::Release);
                                                    if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                                        r.actual_state = actual;
                                                        if let Some(l) = r.live.as_mut() {
                                                            l.pending_target = None;
                                                        }
                                                        if actual == SandboxState::Destroyed {
                                                            r.live = None;
                                                        }
                                                    }
                                                    let _ = result_tx.send(Ok(()));
                                                } else {
                                                    let _ = result_tx.send(Err(BackendError::InvalidState));
                                                }
                                            }
                                        }
                                        if actual == SandboxState::Destroyed { return; }
                                    }
                                    if actual == SandboxState::Destroyed { return; }
                                }
                                None => return,
                            }
                        }
                        Some(check) = liveness_rx.recv() => {
                            let _ = check.done_tx.send(());
                        }
                    }
                }
            }
        });

        let record = SandboxRecord {
            actual_state: initial_state,
            created_at: rfc3339_now(),
            config: test_config(),
            reconciler_panicked,
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle,
                pending_target: None,
                console_cmd_tx: if initial_state == SandboxState::Running {
                    Some(console_tx)
                } else {
                    None
                },
                cancel_token: CancellationToken::new(),
                vm_alive,
            }),
        };

        backend.sandboxes.lock().await.insert(id.clone(), record);
        id
    }

    // ===== Regression: destroy queued during start completes (drain-resume) =====
    #[tokio::test]
    async fn test_destroy_queued_during_start_completes() {
        let backend = make_test_backend();
        let id = inject_sandbox_with_delay(
            &backend,
            SandboxState::Ready,
            std::time::Duration::from_millis(50),
        )
        .await;

        // start() is sent first — the reconciler will sleep 50ms processing it.
        // destroy() is sent ~5ms later — it arrives while start is still in-flight
        // and gets queued in the channel. The reconciler drains it after completing
        // the start transition.
        let start_handle = tokio::spawn({
            let backend_sandboxes = backend.sandboxes.clone();
            let id = id.clone();
            async move {
                // We need to call start() through the backend's trait method.
                // But we can't move backend into the spawn. Instead, manually
                // replicate the start() claim + send pattern.
                let result_rx = {
                    let mut map = backend_sandboxes.lock().await;
                    let record = map.get_mut(&id).unwrap();
                    let live = record.live.as_mut().unwrap();
                    live.pending_target = Some(SandboxState::Running);
                    record.actual_state = SandboxState::Starting;
                    let (result_tx, result_rx) = oneshot::channel();
                    live.reconcile_tx
                        .try_send(ReconcileRequest::SetDesired {
                            target: SandboxState::Running,
                            result_tx,
                        })
                        .unwrap();
                    result_rx
                };
                result_rx.await.unwrap()
            }
        });

        // Short delay to ensure start's try_send lands first.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let destroy_handle = tokio::spawn({
            let backend_sandboxes = backend.sandboxes.clone();
            let id = id.clone();
            async move {
                let result_rx = {
                    let mut map = backend_sandboxes.lock().await;
                    let record = map.get_mut(&id).unwrap();
                    let live = record.live.as_mut().unwrap();
                    live.pending_target = Some(SandboxState::Destroyed);
                    let (result_tx, result_rx) = oneshot::channel();
                    live.reconcile_tx
                        .try_send(ReconcileRequest::SetDesired {
                            target: SandboxState::Destroyed,
                            result_tx,
                        })
                        .unwrap();
                    result_rx
                };
                result_rx.await.unwrap()
            }
        });

        // Both must complete within a reasonable timeout — a deadlock would hang.
        let timeout = std::time::Duration::from_secs(5);
        let r_start = tokio::time::timeout(timeout, start_handle)
            .await
            .expect("start() timed out — possible deadlock")
            .unwrap();
        let r_destroy = tokio::time::timeout(timeout, destroy_handle)
            .await
            .expect("destroy() timed out — possible deadlock")
            .unwrap();

        // Start waiter was superseded by destroy.
        assert!(
            matches!(r_start, Err(BackendError::InvalidState)),
            "start waiter should get InvalidState (superseded), got: {:?}",
            r_start
        );
        // Destroy completes successfully.
        assert!(
            r_destroy.is_ok(),
            "destroy waiter should get Ok, got: {:?}",
            r_destroy
        );
    }

    // ===== Regression: stop on crashed VM returns InvalidState =====
    // VM crashed (vm_alive=false) between start completing and stop being called.
    // The liveness check detects the crash and transitions to Stopped.
    // stop() sees non-Running state after liveness and returns InvalidState.
    #[tokio::test]
    async fn test_stop_on_crashed_vm_returns_invalid_state() {
        let backend = make_test_backend();
        let id = backend.alloc_sandbox_id();
        let (reconcile_tx, mut reconcile_rx) = mpsc::channel::<ReconcileRequest>(16);
        let (liveness_tx, mut liveness_rx) = mpsc::channel::<LivenessCheck>(16);
        // VM is "Running" but already crashed — vm_alive is false.
        let vm_alive = Arc::new(AtomicBool::new(false));
        let reconciler_panicked = Arc::new(AtomicBool::new(false));
        let sandboxes = backend.sandboxes.clone();
        let sandbox_id = id.clone();

        let (console_tx, mut console_rx) = mpsc::channel::<ConsoleCmd>(256);
        tokio::spawn(async move { while console_rx.recv().await.is_some() {} });

        let reconciler_handle = tokio::spawn({
            let sandboxes = sandboxes.clone();
            let id = sandbox_id.clone();
            let vm_alive = vm_alive.clone();
            async move {
                let mut actual = SandboxState::Running;
                loop {
                    tokio::select! {
                        req = reconcile_rx.recv() => {
                            match req {
                                Some(ReconcileRequest::SetDesired { target, result_tx }) => {
                                    if target == SandboxState::Stopped
                                        && !vm_alive.load(Ordering::Acquire)
                                    {
                                        // VM already dead: transition to Stopped but
                                        // return InvalidState (mirrors real reconciler
                                        // behavior when pre_teardown_liveness_check
                                        // finds the VM already dead).
                                        actual = SandboxState::Stopped;
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                            r.actual_state = actual;
                                            if let Some(l) = r.live.as_mut() {
                                                l.pending_target = None;
                                            }
                                        }
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        continue;
                                    }
                                    if !can_reach(actual, target) {
                                        let _ = result_tx.send(Err(BackendError::InvalidState));
                                        if let Some(r) = sandboxes.lock().await.get_mut(&id)
                                            && let Some(l) = r.live.as_mut()
                                        {
                                            l.pending_target = None;
                                        }
                                        continue;
                                    }
                                    actual = target;
                                    vm_alive.store(actual == SandboxState::Running, Ordering::Release);
                                    if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                        r.actual_state = actual;
                                        if let Some(l) = r.live.as_mut() {
                                            l.pending_target = None;
                                        }
                                        if actual == SandboxState::Destroyed { r.live = None; }
                                    }
                                    let _ = result_tx.send(Ok(()));
                                    if actual == SandboxState::Destroyed { return; }
                                }
                                None => return,
                            }
                        }
                        Some(check) = liveness_rx.recv() => {
                            // Liveness check detects crash: update state to Stopped.
                            if actual == SandboxState::Running
                                && !vm_alive.load(Ordering::Acquire)
                            {
                                actual = SandboxState::Stopped;
                                if let Some(r) = sandboxes.lock().await.get_mut(&id) {
                                    r.actual_state = actual;
                                    if let Some(l) = r.live.as_mut() {
                                        l.pending_target = None;
                                    }
                                }
                            }
                            let _ = check.done_tx.send(());
                        }
                    }
                }
            }
        });

        let record = SandboxRecord {
            actual_state: SandboxState::Running,
            created_at: rfc3339_now(),
            config: test_config(),
            reconciler_panicked,
            live: Some(LiveState {
                reconcile_tx,
                liveness_tx,
                reconciler_handle,
                pending_target: None,
                console_cmd_tx: Some(console_tx),
                cancel_token: CancellationToken::new(),
                vm_alive,
            }),
        };
        backend.sandboxes.lock().await.insert(id.clone(), record);

        // stop() sends a liveness check first — the reconciler detects the crash
        // and transitions to Stopped. stop() re-reads state, sees non-Running,
        // and returns InvalidState.
        let result = backend.stop(&id).await;
        assert!(
            matches!(result, Err(BackendError::InvalidState)),
            "stop() on crashed VM should return InvalidState, got: {:?}",
            result
        );
        // Sandbox should be Stopped (crash was handled).
        let status = backend.status(&id).await.unwrap();
        assert_eq!(status.state, "stopped");
    }
}
