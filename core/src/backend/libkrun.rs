use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backend::reconciler::{
    DriverFactory, ReconcileRuntime, RootfsHandleExt, RunningVmHandle, VmDriverSend,
};
use crate::backend::{BackendError, Capabilities, SandboxBackendSend};
use crate::krun::KrunCtx;
use crate::lifecycle::{DesiredState, State, Verb};
use crate::net::{NetBackendConfig, NetBackendHandle};
use crate::oci::{ImageCache, ImageReference, RegistryClient};
use crate::rootfs::{RootfsConfig, RootfsProvider};
use crate::store::{JsonStore, PersistedRecord, Store, verify_pid};
use crate::types::{
    ExecControl, ExecEvent, ExecHandle, ExecId, ExecRequest, MountConfig, NetworkPolicy,
    SandboxConfig, SandboxId, SandboxStatus, SandboxView,
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

/// A running VM's exec relay registry: the live stdin/control relay
/// `JoinHandle`s plus a `closing` gate. `exec` registers relays and VM shutdown
/// drains them under the SAME lock, so once shutdown sets `closing` no further
/// relay can be registered — none can outlive teardown to keep a stdin/control
/// channel briefly open.
struct ExecRegistry {
    closing: bool,
    tasks: Vec<JoinHandle<()>>,
}

type ExecTasks = Arc<std::sync::Mutex<ExecRegistry>>;

/// Register a started exec's two relay tasks, refusing once the VM is closing or
/// its token is cancelled. Holds the registry lock while it checks the gate and,
/// only if the VM is still open, spawns the relays (via `spawn`) and stores
/// their handles — all without awaiting, so the gate check and registration are
/// atomic against shutdown's drain. Returns false (relays never spawned) when
/// the VM is shutting down.
fn register_exec_relays(
    registry: &ExecTasks,
    cancel: &CancellationToken,
    spawn: impl FnOnce() -> (JoinHandle<()>, JoinHandle<()>),
) -> bool {
    let mut reg = registry.lock().unwrap();
    if reg.closing || cancel.is_cancelled() {
        return false;
    }
    let (stdin_task, ctrl_task) = spawn();
    reg.tasks.retain(|t| !t.is_finished());
    reg.tasks.push(stdin_task);
    reg.tasks.push(ctrl_task);
    true
}

/// A running VM's console command channel, a cancellation token that fires when
/// the VM stops, crashes, or is destroyed, and the registry of its exec relay
/// tasks. `exec` clones the token into its stdin/control relay tasks so they
/// terminate the moment the VM goes away, and records their handles so shutdown
/// can synchronously close their receivers (making post-teardown writes fail).
#[derive(Clone)]
struct ConsoleHandle {
    cmd_tx: mpsc::Sender<ConsoleCmd>,
    cancel: CancellationToken,
    exec_tasks: ExecTasks,
}

/// Per-sandbox map from sandbox id to its running VM's console handle. Populated
/// by the driver's `start`, removed when the VM stops, recovered crashes, or is
/// destroyed. `exec` reads it to reach a running guest.
type ConsoleMap = Arc<RwLock<HashMap<SandboxId, ConsoleHandle>>>;

// ---------------------------------------------------------------------------
// RAII guards
// ---------------------------------------------------------------------------

/// Holds a child PID and its captured start time, killing + reaping it in a
/// background thread on drop unless defused. The start time defeats PID reuse:
/// a reaped or recycled PID is never signalled. Call `defuse()` before any
/// explicit kill, or once the PID is owned elsewhere, to prevent a double-kill.
struct ChildGuard {
    pid: Option<i32>,
    start_time: u64,
}

impl ChildGuard {
    fn new(pid: i32, start_time: u64) -> Self {
        Self {
            pid: Some(pid),
            start_time,
        }
    }

    /// Prevent the guard from killing the child on drop.
    fn defuse(&mut self) {
        self.pid = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let start = self.start_time;
            // Runs only on async cancellation / orphaned drop (rare). Spawn a
            // detached OS thread so we don't block the executor, and verify the
            // PID before signalling so a reaped/reused PID is never touched.
            std::thread::spawn(move || {
                if verify_pid(pid, start) {
                    kill_and_wait(pid);
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Fork supervisor
// ---------------------------------------------------------------------------

/// A request to fork a VM on the supervisor thread.
struct ForkRequest {
    krun_ctx: KrunCtx,
    console_guest_fd: i32,
    net_vm_sock_fd: Option<i32>,
    reply: oneshot::Sender<Result<i32, BackendError>>,
}

/// Owns the daemon-lifetime thread that performs every `fork()`.
///
/// `PR_SET_PDEATHSIG(SIGKILL)` fires when the *forking thread* dies. Forking from
/// a Tokio `spawn_blocking` worker is fatal: the pool reaps idle workers after a
/// short keep-alive, killing the VM while the daemon is still alive. This thread
/// lives for the whole backend lifetime, so the signal fires only on real daemon
/// exit.
struct ForkSupervisor {
    // `Option` so `Drop` can take + drop the sender before joining the thread.
    tx: Option<std::sync::mpsc::Sender<ForkRequest>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Deliver a fork result to the caller, reaping the child if the reply could not
/// be delivered (the caller's future was dropped after the fork succeeded).
fn deliver_fork_result(
    reply: oneshot::Sender<Result<i32, BackendError>>,
    result: Result<i32, BackendError>,
    reap: impl FnOnce(i32),
) {
    if let Err(Ok(pid)) = reply.send(result) {
        reap(pid);
    }
}

impl ForkSupervisor {
    fn new() -> Result<Self, BackendError> {
        let (tx, rx) = std::sync::mpsc::channel::<ForkRequest>();
        let handle = std::thread::Builder::new()
            .name("pp-fork-supervisor".into())
            .spawn(move || {
                while let Ok(req) = rx.recv() {
                    let ForkRequest {
                        krun_ctx,
                        console_guest_fd,
                        net_vm_sock_fd,
                        reply,
                    } = req;
                    let result = krun_ctx
                        .start()
                        .map_err(|e| BackendError::Internal(format!("krun start: {e}")));
                    // The extracted FDs belong to the parent and are now duplicated
                    // into the child; close the parent copies on every outcome.
                    unsafe { libc::close(console_guest_fd) };
                    if let Some(fd) = net_vm_sock_fd {
                        unsafe { libc::close(fd) };
                    }
                    deliver_fork_result(reply, result, kill_and_wait);
                }
            })
            .map_err(|e| BackendError::Internal(format!("spawn fork supervisor thread: {e}")))?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    /// Fork a VM on the supervisor thread and await the child PID.
    async fn fork_vm(
        &self,
        krun_ctx: KrunCtx,
        console_guest_fd: i32,
        net_vm_sock_fd: Option<i32>,
    ) -> Result<i32, BackendError> {
        let (reply, reply_rx) = oneshot::channel();
        let req = ForkRequest {
            krun_ctx,
            console_guest_fd,
            net_vm_sock_fd,
            reply,
        };
        let Some(tx) = self.tx.as_ref() else {
            unsafe { libc::close(req.console_guest_fd) };
            if let Some(fd) = req.net_vm_sock_fd {
                unsafe { libc::close(fd) };
            }
            return Err(BackendError::Internal("fork supervisor unavailable".into()));
        };
        if let Err(std::sync::mpsc::SendError(req)) = tx.send(req) {
            // Supervisor gone before enqueue: no fork happened, close the FDs.
            unsafe { libc::close(req.console_guest_fd) };
            if let Some(fd) = req.net_vm_sock_fd {
                unsafe { libc::close(fd) };
            }
            return Err(BackendError::Internal("fork supervisor unavailable".into()));
        }
        match reply_rx.await {
            Ok(result) => result,
            Err(_) => Err(BackendError::Internal(
                "fork supervisor dropped reply".into(),
            )),
        }
    }
}

impl Drop for ForkSupervisor {
    fn drop(&mut self) {
        // Drop the sender so the recv loop ends, then join.
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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
pub(crate) fn rfc3339_now() -> String {
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
// Process management
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
// Mount / image / env validation
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
// KrunCtx preparation
// ---------------------------------------------------------------------------

/// Build a KrunCtx and create the exec console and (for Allowlist) net socketpairs.
/// This is the heavy pre-fork configuration; it runs on each start.
///
/// The VM-side UnixStreams (console_guest, net_vm_stream) are moved INTO the
/// blocking task so they stay owned for the whole KrunCtx configuration: a
/// cancellation of this future cannot drop them mid-configure and leave the
/// task operating on closed/reused fd numbers. They are returned with the ctx
/// so the caller keeps ownership for the fork.
async fn prepare_krun(
    config: &SandboxConfig,
    rootfs_root: PathBuf,
) -> Result<
    (
        KrunCtx,
        UnixStream,
        OwnedFd,
        Option<UnixStream>,
        Option<OwnedFd>,
    ),
    BackendError,
> {
    let (console_host, console_guest) = UnixStream::pair()
        .map_err(|e| BackendError::Internal(format!("console socketpair: {e}")))?;

    let (net_backend_sock, net_vm_stream) = match &config.network {
        NetworkPolicy::Allowlist { .. } => {
            let (backend, vm) = UnixStream::pair()
                .map_err(|e| BackendError::Internal(format!("net socketpair: {e}")))?;
            (Some(backend), Some(vm))
        }
        _ => (None, None),
    };
    let cfg = config.clone();

    let (krun_ctx, console_guest, net_vm_stream) = tokio::task::spawn_blocking(
        move || -> Result<(KrunCtx, UnixStream, Option<UnixStream>), BackendError> {
            let cgfd: i32 = console_guest.as_raw_fd();
            let nvfd: Option<i32> = net_vm_stream.as_ref().map(|s| s.as_raw_fd());

            let mut krun = KrunCtx::new()
                .map_err(|e| BackendError::Internal(format!("krun_create_ctx: {e}")))?;

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
                    krun.disable_implicit_vsock().map_err(|e| {
                        BackendError::Internal(format!("disable_implicit_vsock: {e}"))
                    })?;
                    krun.add_vsock(TSI_HIJACK_ALL)
                        .map_err(|e| BackendError::Internal(format!("add_vsock: {e}")))?;
                }
                NetworkPolicy::Allowlist { .. } => {
                    if let Some(fd) = nvfd {
                        krun.add_net_unixstream(None, fd, &GUEST_MAC, 0, 0)
                            .map_err(|e| {
                                BackendError::Internal(format!("add_net_unixstream: {e}"))
                            })?;
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

            let console_id = krun.add_virtio_console_multiport().map_err(|e| {
                BackendError::Internal(format!("add_virtio_console_multiport: {e}"))
            })?;
            krun.add_console_port_inout(console_id, EXEC_PORT_NAME, cgfd, cgfd)
                .map_err(|e| BackendError::Internal(format!("add_console_port_inout: {e}")))?;

            Ok((krun, console_guest, net_vm_stream))
        },
    )
    .await
    .map_err(|e| BackendError::Internal(format!("spawn_blocking panicked: {e}")))??;

    // All krun config calls succeeded. Keep the VM-side fds under RAII
    // ownership (OwnedFd) so a cancellation before the fork is accepted still
    // closes them; the raw fd is extracted only once the fork is committed.
    let console_guest_fd = OwnedFd::from(console_guest);
    let net_vm_sock_fd = net_vm_stream.map(OwnedFd::from);

    Ok((
        krun_ctx,
        console_host,
        console_guest_fd,
        net_backend_sock,
        net_vm_sock_fd,
    ))
}

// ---------------------------------------------------------------------------
// Driver handle types
// ---------------------------------------------------------------------------

/// A live VM and its run-scoped resources. The PID + start time persist for
/// PID-reuse defense; the held `ChildGuard` kills the VM on an orphaned drop.
pub struct LibkrunRunningVm {
    pid: i32,
    pid_start_time: u64,
    child_guard: ChildGuard,
    net_handle: Option<NetBackendHandle>,
    io_task: Option<JoinHandle<()>>,
    console_cmd_tx: mpsc::Sender<ConsoleCmd>,
    console_map: ConsoleMap,
    exec_cancel: CancellationToken,
    exec_tasks: ExecTasks,
    id: SandboxId,
}

impl RunningVmHandle for LibkrunRunningVm {
    fn pid(&self) -> i32 {
        self.pid
    }
    fn pid_start_time(&self) -> u64 {
        self.pid_start_time
    }
}

impl LibkrunRunningVm {
    /// Kill the VM (verifying the PID first), drain run-scoped I/O and network
    /// resources, and drop the published console channel. Best-effort.
    async fn shutdown(mut self) {
        // Cancel exec relays, then synchronously abort and await each so its
        // receiver is dropped before this returns. Once a relay's receiver is
        // gone the matching ExecHandle stdin/control sender fails on its very
        // next send, so a write/signal/resize after destroy fails immediately
        // (no polling/race). Then drop the console handle so exec() can no
        // longer reach this VM.
        self.exec_cancel.cancel();
        // Set the closing gate and take the live relays under the SAME lock
        // exec() registers through, so no exec() racing teardown can register a
        // relay after this drain. Abort+await each so its receiver is dropped
        // before this returns.
        let tasks: Vec<JoinHandle<()>> = {
            let mut reg = self.exec_tasks.lock().unwrap();
            reg.closing = true;
            std::mem::take(&mut reg.tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        if let Ok(mut map) = self.console_map.write() {
            map.remove(&self.id);
        }
        // Ask the console task to deliver Exit{-1} to any live exec sessions.
        let _ = self.console_cmd_tx.try_send(ConsoleCmd::Teardown);

        let pid = self.pid;
        let start = self.pid_start_time;
        // We handle the kill explicitly; the guard must not also fire on drop.
        self.child_guard.defuse();
        tokio::task::spawn_blocking(move || {
            if verify_pid(pid, start) {
                kill_and_wait(pid);
            }
        })
        .await
        .ok();

        if let Some(task) = self.io_task.take() {
            let abort_handle = task.abort_handle();
            if tokio::time::timeout(std::time::Duration::from_millis(500), task)
                .await
                .is_err()
            {
                abort_handle.abort();
            }
        }
        if let Some(net) = self.net_handle.take() {
            tokio::task::spawn_blocking(move || {
                let _ = net.stop();
            })
            .await
            .ok();
        }
    }
}

impl Drop for LibkrunRunningVm {
    fn drop(&mut self) {
        // Backstop for the crash path, where the reconciler drops the VM after
        // observing it dead: cancel and abort exec relays (so a crashed VM's
        // relays also terminate and their receivers drop, rejecting writes) and
        // clear the stale console handle. Drop can't await, so the abort is
        // best-effort here. The kill is owned by `child_guard` (already defused
        // if the VM was reaped).
        self.exec_cancel.cancel();
        if let Ok(mut reg) = self.exec_tasks.lock() {
            reg.closing = true;
            for task in reg.tasks.drain(..) {
                task.abort();
            }
        }
        if let Ok(mut map) = self.console_map.write() {
            map.remove(&self.id);
        }
    }
}

/// A prepared (or recovered) rootfs. Cleanup operates purely on `root` via
/// `cleanup_session_dir`, so no provider handle is retained.
pub struct LibkrunRootfsHandle {
    root: PathBuf,
    session_dir: PathBuf,
}

impl RootfsHandleExt for LibkrunRootfsHandle {
    fn rootfs_path(&self) -> &Path {
        &self.root
    }
    fn session_dir(&self) -> &Path {
        &self.session_dir
    }
}

// ---------------------------------------------------------------------------
// Per-sandbox driver
// ---------------------------------------------------------------------------

/// Backend-specific VM lifecycle for one sandbox. Re-packages the libkrun
/// provisioning, fork, network, and console machinery behind the reconciler's
/// driver seam.
pub struct LibkrunDriver {
    id: SandboxId,
    data_dir: PathBuf,
    init_binary: PathBuf,
    rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    image_cache: Arc<Mutex<ImageCache>>,
    registry_client: Arc<Mutex<RegistryClient>>,
    fork_supervisor: Arc<ForkSupervisor>,
    launch_mutex: Arc<Mutex<()>>,
    console_map: ConsoleMap,
}

impl VmDriverSend for LibkrunDriver {
    type RunningVm = LibkrunRunningVm;
    type RootfsHandle = LibkrunRootfsHandle;

    async fn provision(&mut self, cfg: &SandboxConfig) -> Result<Self::RootfsHandle, BackendError> {
        // Pull the OCI image.
        let base_rootfs = {
            let image_ref: ImageReference = cfg.image.parse().map_err(|e| {
                BackendError::Internal(format!("invalid image reference '{}': {e}", cfg.image))
            })?;
            let cache = self.image_cache.lock().await;
            let mut client = self.registry_client.lock().await;
            cache
                .ensure(&mut client, &image_ref)
                .await
                .map_err(|e| BackendError::Internal(format!("image pull failed: {e}")))?
        };

        // Clear any partial rootfs from a crashed/cancelled prior provision
        // before prepare reuses the per-sandbox session directory.
        let sessions_root = self.data_dir.join("sessions");
        let clear_id = self.id.0.clone();
        let clear_provider = self.rootfs_provider.clone();
        tokio::task::spawn_blocking({
            let sessions_root = sessions_root.clone();
            move || clear_provider.clear_session_dir(&sessions_root, &clear_id)
        })
        .await
        .map_err(|e| BackendError::Internal(format!("clear session task panicked: {e}")))?
        .map_err(|e| BackendError::Internal(format!("clear stale rootfs: {e}")))?;

        // Prepare the rootfs overlay under data_dir/sessions/<id>.
        let rfs_config = RootfsConfig {
            sandbox_id: self.id.0.clone(),
            base_rootfs,
            session_dir: sessions_root,
            init_binary: self.init_binary.clone(),
        };
        let mounts = cfg.mounts.clone();
        let prepared = tokio::task::spawn_blocking({
            let provider = self.rootfs_provider.clone();
            move || provider.prepare(&rfs_config)
        })
        .await
        .map_err(|e| BackendError::Internal(format!("rootfs task panicked: {e}")))?
        .map_err(|e| BackendError::Internal(format!("rootfs prepare: {e}")))?;

        // Write the mounts manifest; on failure, destroy the prepared rootfs.
        if let Err(e) = write_mounts_manifest(&prepared.root, &mounts) {
            tokio::task::spawn_blocking(move || {
                let _ = prepared.destroy();
            })
            .await
            .ok();
            return Err(e);
        }

        // The provider handle is inert (no Drop, PathBuf-only cleanup state);
        // the mount/copy lives on disk and is torn down via cleanup_session_dir.
        let root = prepared.root.clone();
        let session_dir = root
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| root.clone());
        Ok(LibkrunRootfsHandle { root, session_dir })
    }

    async fn start(
        &mut self,
        cfg: &SandboxConfig,
        rootfs: &Self::RootfsHandle,
    ) -> Result<Self::RunningVm, BackendError> {
        // Fail loud if a fuse-overlay rootfs persists but its mount is gone
        // (e.g. a host reboot): booting it would expose an empty rootfs, and
        // reprovisioning would discard the upper layer.
        let sessions_root = self.data_dir.join("sessions");
        let check_id = self.id.0.clone();
        let check_provider = self.rootfs_provider.clone();
        let unmounted = tokio::task::spawn_blocking(move || {
            check_provider.fuse_rootfs_unmounted(&sessions_root, &check_id)
        })
        .await
        .map_err(|e| BackendError::Internal(format!("rootfs mount check panicked: {e}")))?
        .map_err(|e| BackendError::Internal(format!("rootfs mount check: {e}")))?;
        if unmounted {
            return Err(BackendError::Internal(
                "sandbox rootfs overlay is not mounted (host reboot?); recreate the sandbox".into(),
            ));
        }

        let (krun_ctx, console_host_sock, console_guest_fd, net_backend_sock, net_vm_sock_fd) =
            prepare_krun(cfg, rootfs.root.clone()).await?;

        // Fork under the launch mutex. The VM-side fds stay RAII-owned until the
        // mutex is acquired, so a shutdown-cancellation while parked on the lock
        // closes them rather than leaking; the raw fds are extracted only once
        // the fork is about to be committed, and the supervisor closes them on
        // every fork outcome.
        let child_pid = {
            let _launch_guard = self.launch_mutex.lock().await;
            let console_guest_fd = console_guest_fd.into_raw_fd();
            let net_vm_sock_fd = net_vm_sock_fd.map(|fd| fd.into_raw_fd());
            self.fork_supervisor
                .fork_vm(krun_ctx, console_guest_fd, net_vm_sock_fd)
                .await?
        };

        // A verifiable (pid, start) is required: every kill path guards on
        // verify_pid, so a Running VM with an unmatchable token could never be
        // killed. A missing or zero start time is a start failure.
        let start_time = match crate::store::require_pid_start_time(child_pid) {
            Ok(t) if t != 0 => t,
            other => {
                tokio::task::spawn_blocking(move || kill_and_wait(child_pid))
                    .await
                    .ok();
                // Zero is unverifiable; reuse the generic message. A platform
                // without /proc surfaces require_pid_start_time's unsupported error.
                return Err(BackendError::Internal(
                    other
                        .err()
                        .unwrap_or_else(|| "could not capture VM start time".into()),
                ));
            }
        };
        // Armed for the start window; moved into the VM on success so it guards
        // the whole VM lifetime, or defused + killed explicitly on rollback.
        let mut child_guard = ChildGuard::new(child_pid, start_time);

        // Start the network backend (Allowlist only).
        let net_handle = match (net_backend_sock, &cfg.network) {
            (Some(sock), NetworkPolicy::Allowlist { allowed_domains }) => {
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
                        child_guard.defuse();
                        tokio::task::spawn_blocking(move || kill_and_wait(child_pid))
                            .await
                            .ok();
                        return Err(BackendError::Internal(format!("net backend: {e}")));
                    }
                }
            }
            _ => None,
        };

        // Spawn the console I/O task and publish its command channel.
        let (cmd_tx, cmd_rx) = mpsc::channel::<ConsoleCmd>(256);
        let io_task = tokio::spawn(run_console_io(console_host_sock, cmd_rx));
        let exec_cancel = CancellationToken::new();
        let exec_tasks: ExecTasks = Arc::new(std::sync::Mutex::new(ExecRegistry {
            closing: false,
            tasks: Vec::new(),
        }));
        if let Ok(mut map) = self.console_map.write() {
            map.insert(
                self.id.clone(),
                ConsoleHandle {
                    cmd_tx: cmd_tx.clone(),
                    cancel: exec_cancel.clone(),
                    exec_tasks: exec_tasks.clone(),
                },
            );
        }

        Ok(LibkrunRunningVm {
            pid: child_pid,
            pid_start_time: start_time,
            child_guard,
            net_handle,
            io_task: Some(io_task),
            console_cmd_tx: cmd_tx,
            console_map: self.console_map.clone(),
            exec_cancel,
            exec_tasks,
            id: self.id.clone(),
        })
    }

    async fn stop(&mut self, vm: Self::RunningVm) {
        vm.shutdown().await;
    }

    async fn teardown(
        &mut self,
        vm: Option<Self::RunningVm>,
        rootfs: Option<Self::RootfsHandle>,
    ) -> Result<(), (BackendError, Option<Self::RootfsHandle>)> {
        if let Some(vm) = vm {
            vm.shutdown().await;
        }
        // Derive the deletion target from the validated id + data_dir, never
        // the (untrusted) stored rootfs path; covers the rootfs-None case too.
        let sessions_root = self.data_dir.join("sessions");
        let id = self.id.0.clone();
        let provider = self.rootfs_provider.clone();
        let result =
            tokio::task::spawn_blocking(move || provider.clear_session_dir(&sessions_root, &id))
                .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err((
                BackendError::Internal(format!("rootfs cleanup: {e}")),
                rootfs,
            )),
            Err(e) => Err((
                BackendError::Internal(format!("cleanup task panicked: {e}")),
                rootfs,
            )),
        }
    }

    fn recover_rootfs(
        &self,
        record: &PersistedRecord,
    ) -> Result<Option<Self::RootfsHandle>, BackendError> {
        // rootfs_path is only a presence signal; the path itself is derived
        // from the validated id + data_dir so a tampered record can never widen
        // the boot/deletion target.
        if record.rootfs_path.is_none() {
            return Ok(None);
        }
        let sessions_root = self.data_dir.join("sessions");
        let root = self
            .rootfs_provider
            .session_rootfs_path(&sessions_root, &self.id.0)
            .map_err(|e| BackendError::Internal(format!("recover rootfs path: {e}")))?;
        // The state file can outlive the rootfs after a crash; a missing
        // canonical dir means no usable rootfs, so the record reprovisions.
        if !root.exists() {
            return Ok(None);
        }
        let session_dir = sessions_root.join(&self.id.0);
        Ok(Some(LibkrunRootfsHandle { root, session_dir }))
    }

    fn is_alive(&self, vm: &mut Self::RunningVm) -> bool {
        if check_child_liveness(vm.pid) {
            true
        } else {
            // Reaped (possibly to be reused): never signal this PID again.
            vm.child_guard.defuse();
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Driver factory
// ---------------------------------------------------------------------------

/// Builds a `LibkrunDriver` per sandbox, sharing the backend-wide image cache,
/// registry client, fork supervisor, launch mutex, and console map.
pub struct LibkrunFactory {
    data_dir: PathBuf,
    init_binary: PathBuf,
    rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    image_cache: Arc<Mutex<ImageCache>>,
    registry_client: Arc<Mutex<RegistryClient>>,
    fork_supervisor: Arc<ForkSupervisor>,
    launch_mutex: Arc<Mutex<()>>,
    console_map: ConsoleMap,
}

impl DriverFactory for LibkrunFactory {
    type Driver = LibkrunDriver;
    fn build(&self, id: &SandboxId, _config: &SandboxConfig) -> LibkrunDriver {
        LibkrunDriver {
            id: id.clone(),
            data_dir: self.data_dir.clone(),
            init_binary: self.init_binary.clone(),
            rootfs_provider: self.rootfs_provider.clone(),
            image_cache: self.image_cache.clone(),
            registry_client: self.registry_client.clone(),
            fork_supervisor: self.fork_supervisor.clone(),
            launch_mutex: self.launch_mutex.clone(),
            console_map: self.console_map.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// LibkrunBackend
// ---------------------------------------------------------------------------

pub struct LibkrunBackend {
    runtime: ReconcileRuntime<LibkrunFactory>,
    console_map: ConsoleMap,
    next_exec: AtomicU64,
}

impl LibkrunBackend {
    pub fn new(
        data_dir: impl Into<PathBuf>,
        init_binary: impl Into<PathBuf>,
        rootfs_provider: Arc<dyn RootfsProvider + Send + Sync>,
    ) -> Result<Self, BackendError> {
        let data_dir = data_dir.into();
        let init_binary = init_binary.into();
        let image_cache = Arc::new(Mutex::new(ImageCache::new(&data_dir)));
        let registry_client =
            Arc::new(Mutex::new(RegistryClient::new().map_err(|e| {
                BackendError::Internal(format!("registry client: {e}"))
            })?));
        let console_map: ConsoleMap = Arc::new(RwLock::new(HashMap::new()));

        let factory = LibkrunFactory {
            data_dir: data_dir.clone(),
            init_binary,
            rootfs_provider,
            image_cache,
            registry_client,
            fork_supervisor: Arc::new(ForkSupervisor::new()?),
            launch_mutex: Arc::new(Mutex::new(())),
            console_map: console_map.clone(),
        };
        let store: Arc<dyn Store> = Arc::new(JsonStore::new(data_dir.join("state.json")));

        Ok(Self {
            runtime: ReconcileRuntime::new_recoverable(factory, store),
            console_map,
            next_exec: AtomicU64::new(1),
        })
    }

    /// Reconstruct sandbox actors from the durable store. Run inside a Tokio
    /// runtime before serving.
    pub async fn recover(&self) -> Result<(), BackendError> {
        self.runtime.recover().await
    }

    fn alloc_exec_id(&self) -> ExecId {
        let n = self.next_exec.fetch_add(1, Ordering::Relaxed);
        ExecId(format!("exec-{n}"))
    }
}

impl Drop for LibkrunBackend {
    fn drop(&mut self) {
        self.runtime.shutdown();
    }
}

impl SandboxBackendSend for LibkrunBackend {
    async fn create(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        validate_image_ref(&config.image)?;
        validate_mounts(&config.mounts)?;
        validate_env(&config.env)?;
        self.runtime.create(config, DesiredState::Stopped).await
    }

    async fn create_and_start(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        validate_image_ref(&config.image)?;
        validate_mounts(&config.mounts)?;
        validate_env(&config.env)?;
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

    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError> {
        let view = self.runtime.status(id)?;
        if view.status.state != Some(State::Running) {
            return Err(BackendError::InvalidState);
        }
        let ConsoleHandle {
            cmd_tx,
            cancel,
            exec_tasks,
        } = {
            let map = self.console_map.read().unwrap();
            map.get(id).cloned()
        }
        .ok_or(BackendError::InvalidState)?;
        // Cheap early-out for a VM already torn down between the status check
        // and here; the authoritative refusal is the closing gate below.
        if cancel.is_cancelled() {
            return Err(BackendError::InvalidState);
        }

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

        let stdin_exec_id = exec_id.0.clone();
        let stdin_cmd_tx = cmd_tx.clone();
        let stdin_cancel = cancel.clone();
        let ctrl_exec_id = exec_id.0.clone();
        let ctrl_cmd_tx = cmd_tx.clone();
        let ctrl_cancel = cancel.clone();

        // Spawn + register the stdin/control relays atomically against
        // shutdown's drain: if the VM is already closing or cancelled they are
        // never spawned and exec is refused, so no relay can keep a
        // stdin/control channel open past teardown. Both relays terminate when
        // the VM is cancelled (stop/destroy/crash), when the caller drops their
        // sender, or when the console closes.
        let registered = register_exec_relays(&exec_tasks, &cancel, move || {
            let stdin_task = tokio::spawn(async move {
                let mut stdin_rx = stdin_rx;
                loop {
                    let data = tokio::select! {
                        _ = stdin_cancel.cancelled() => return,
                        maybe = stdin_rx.recv() => match maybe {
                            Some(d) => d,
                            None => break,
                        },
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
                // Sender dropped: signal EOF to the guest with an empty frame.
                if let Ok(json) = serde_json::to_string(&HostMsg::Stdin {
                    id: stdin_exec_id,
                    data: String::new(),
                }) {
                    let _ = stdin_cmd_tx.send(ConsoleCmd::Send(json)).await;
                }
            });
            let ctrl_task = tokio::spawn(async move {
                let mut ctrl_rx = ctrl_rx;
                loop {
                    let ctrl = tokio::select! {
                        _ = ctrl_cancel.cancelled() => return,
                        maybe = ctrl_rx.recv() => match maybe {
                            Some(c) => c,
                            None => return,
                        },
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
                        && ctrl_cmd_tx.send(ConsoleCmd::Send(json)).await.is_err()
                    {
                        return;
                    }
                }
            });
            (stdin_task, ctrl_task)
        });
        if !registered {
            // The VM started shutting down after we registered with the guest;
            // unregister (best-effort) and refuse rather than hand back a
            // briefly-live stdin/control sender.
            let _ = cmd_tx
                .send(ConsoleCmd::UnregisterExec(exec_id.0.clone()))
                .await;
            return Err(BackendError::InvalidState);
        }

        Ok(ExecHandle {
            exec_id,
            events: events_rx,
            stdin: stdin_tx,
            control: ctrl_tx,
        })
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
    // Exec relay registration gate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_exec_relays_refuses_cancelled_or_closing() {
        let registry: ExecTasks = Arc::new(std::sync::Mutex::new(ExecRegistry {
            closing: false,
            tasks: Vec::new(),
        }));

        // A cancelled token is refused and the relays are never spawned.
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut spawned = false;
        let ok = register_exec_relays(&registry, &cancelled, || {
            spawned = true;
            (tokio::spawn(async {}), tokio::spawn(async {}))
        });
        assert!(!ok);
        assert!(!spawned, "cancelled VM must not spawn relays");
        assert!(registry.lock().unwrap().tasks.is_empty());

        // A live, non-closing VM registers exactly the two relays.
        let live = CancellationToken::new();
        let ok = register_exec_relays(&registry, &live, || {
            (tokio::spawn(async {}), tokio::spawn(async {}))
        });
        assert!(ok);
        assert_eq!(registry.lock().unwrap().tasks.len(), 2);

        // Once closing is set (as shutdown does, under this lock), a later
        // registration is refused even with a live token.
        registry.lock().unwrap().closing = true;
        let mut spawned_after = false;
        let ok = register_exec_relays(&registry, &live, || {
            spawned_after = true;
            (tokio::spawn(async {}), tokio::spawn(async {}))
        });
        assert!(!ok);
        assert!(!spawned_after, "closing VM must not spawn relays");
        assert_eq!(
            registry.lock().unwrap().tasks.len(),
            2,
            "no new relay added"
        );
    }

    // -----------------------------------------------------------------------
    // Fork supervisor tests
    // -----------------------------------------------------------------------

    #[test]
    fn deliver_fork_result_reaps_when_reply_undelivered() {
        // Receiver dropped before delivery: the child PID must be reaped.
        let (reply, reply_rx) = oneshot::channel::<Result<i32, BackendError>>();
        drop(reply_rx);
        let reaped = std::cell::Cell::new(None);
        deliver_fork_result(reply, Ok(4242), |pid| reaped.set(Some(pid)));
        assert_eq!(reaped.get(), Some(4242));
    }

    #[test]
    fn deliver_fork_result_delivers_to_live_receiver() {
        let (reply, reply_rx) = oneshot::channel::<Result<i32, BackendError>>();
        let reaped = std::cell::Cell::new(None);
        deliver_fork_result(reply, Ok(7), |pid| reaped.set(Some(pid)));
        assert_eq!(reaped.get(), None, "live receiver must not trigger a reap");
        assert!(matches!(reply_rx.blocking_recv(), Ok(Ok(7))));
    }

    #[test]
    fn fork_supervisor_drop_does_not_hang() {
        // Construct + drop with no requests in flight: must return promptly.
        let sup = ForkSupervisor::new().unwrap();
        drop(sup);
    }

    // -----------------------------------------------------------------------
    // Base64 + validation tests
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
    // Teardown cleanup is bounded to the canonical session dir
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn test_config() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "alpine".into(),
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

    #[cfg(target_os = "linux")]
    fn test_driver(data_dir: &Path, id: SandboxId) -> LibkrunDriver {
        LibkrunDriver {
            id,
            data_dir: data_dir.to_path_buf(),
            init_binary: PathBuf::from("/nonexistent"),
            rootfs_provider: Arc::new(crate::rootfs::linux::LinuxRootfsProvider),
            image_cache: Arc::new(Mutex::new(ImageCache::new(data_dir))),
            registry_client: Arc::new(Mutex::new(RegistryClient::new().unwrap())),
            fork_supervisor: Arc::new(ForkSupervisor::new().unwrap()),
            launch_mutex: Arc::new(Mutex::new(())),
            console_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(target_os = "linux")]
    fn test_record(id: &SandboxId, rootfs_path: Option<PathBuf>) -> PersistedRecord {
        PersistedRecord {
            id: id.clone(),
            config: test_config(),
            desired: DesiredState::Destroyed,
            generation: 2,
            state: Some(State::Stopped),
            observed_generation: 1,
            pid: None,
            pid_start_time: None,
            rootfs_path,
            reason: None,
            message: None,
            created_at: "t0".into(),
            last_transition_at: "t0".into(),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn teardown_without_rootfs_clears_stale_session_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let sandbox_dir = data_dir.join("sessions").join("sb-1");
        std::fs::create_dir_all(sandbox_dir.join("merged/etc")).unwrap();
        std::fs::write(sandbox_dir.join("merged/etc/junk"), b"stale").unwrap();

        let mut driver = test_driver(&data_dir, SandboxId("sb-1".into()));
        assert!(driver.teardown(None, None).await.is_ok());
        assert!(!sandbox_dir.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn teardown_never_deletes_foreign_rootfs_path() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        // A path a tampered record might point at, outside the session root.
        let foreign = tmp.path().join("evil");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("keep"), b"important").unwrap();

        let id = SandboxId("sb-1".into());
        let mut driver = test_driver(&data_dir, id.clone());
        // The canonical dir exists on disk so recover_rootfs returns a handle.
        std::fs::create_dir_all(data_dir.join("sessions").join("sb-1").join("merged")).unwrap();
        let record = test_record(&id, Some(foreign.join("merged")));

        // recover_rootfs ignores the stored path and derives the canonical one.
        let handle = VmDriverSend::recover_rootfs(&driver, &record)
            .unwrap()
            .unwrap();
        assert_eq!(
            handle.rootfs_path(),
            data_dir.join("sessions").join("sb-1").join("merged")
        );

        // Teardown touches only the canonical session dir; the foreign path survives.
        let _ = driver.teardown(None, Some(handle)).await;
        assert!(foreign.join("keep").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recover_rootfs_none_when_canonical_dir_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let id = SandboxId("sb-1".into());
        let driver = test_driver(&data_dir, id.clone());
        // rootfs_path present in the record but no dir on disk.
        let record = test_record(&id, Some(data_dir.join("sessions/sb-1/merged")));
        assert!(
            VmDriverSend::recover_rootfs(&driver, &record)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recover_rootfs_some_when_canonical_dir_present() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let id = SandboxId("sb-1".into());
        let merged = data_dir.join("sessions").join("sb-1").join("merged");
        std::fs::create_dir_all(&merged).unwrap();
        let driver = test_driver(&data_dir, id.clone());
        // Stored path is ignored; presence + on-disk canonical dir => Some.
        let record = test_record(&id, Some(data_dir.join("ignored")));
        let handle = VmDriverSend::recover_rootfs(&driver, &record)
            .unwrap()
            .unwrap();
        assert_eq!(handle.rootfs_path(), merged);
        // No rootfs recorded => None regardless of disk.
        let none_record = test_record(&id, None);
        assert!(
            VmDriverSend::recover_rootfs(&driver, &none_record)
                .unwrap()
                .is_none()
        );
    }
}
