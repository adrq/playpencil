use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

use crate::backend::reconciler::{
    DriverFactory, EntrypointExitSink, ReconcileRuntime, RootfsHandleExt, RunningVmHandle,
    VmDriverSend,
};
use crate::backend::{BackendError, Capabilities, SandboxBackendSend};
use crate::krun::KrunCtx;
use crate::lifecycle::{DesiredState, State, Verb};
use crate::net::{NetBackendConfig, NetBackendHandle};
use crate::oci::{ImageCache, ImageReference, RegistryClient};
use crate::rootfs::{RootfsConfig, RootfsProvider};
use crate::store::{JsonStore, PersistedRecord, Store, verify_pid};
use crate::types::{
    EntrypointExit, ExecEvent, ExecHandle, ExecId, ExecIo, ExecMode, ExecRequest, MountConfig,
    NetworkPolicy, SandboxConfig, SandboxId, SandboxStatus, SandboxView, validate_entrypoint,
};
use pipemux::protocol::{self, HostFrame};
use pipemux::relay::{ExecMuxHost, MuxError, spawn_mux};

/// Per-sandbox map from sandbox id to its running VM's exec engine handle.
/// Populated by the driver's `start`, removed when the VM stops, recovers a
/// crash, or is destroyed. `exec` reads it to reach a running guest.
type ConsoleMap = Arc<RwLock<HashMap<SandboxId, ExecMuxHost>>>;

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

impl ForkSupervisor {
    /// Whether the supervisor thread is still running.
    fn is_alive(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
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

/// Exec id for the sandbox's main process. Distinct from the `exec-N` ids minted
/// for caller exec requests, so the two never collide on one console.
const ENTRYPOINT_EXEC_ID: &str = "entrypoint";

/// How long a controlled shutdown waits for the guest to flush and self-exit
/// after the console is closed, before the SIGKILL backstop fires.
const GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the guest to self-exit.
const GRACEFUL_EXIT_STEP: Duration = Duration::from_millis(50);

/// How long a controlled teardown waits for the main-process consumer to reach
/// its terminal before aborting it.
const CONSUMER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// vCPU count for every guest.
const DEFAULT_VCPUS: u8 = 1;

/// Guest RAM in MiB for every guest.
const DEFAULT_RAM_MIB: u32 = 256;

/// Standard environment variables injected into every guest.
const GUEST_STANDARD_ENV: &[&str] = &[
    "HOME=/root",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TERM=xterm",
];

/// Guest paths that may never be used as mount destinations.
const PROTECTED_GUEST_PATHS: &[&str] = &["/", "/proc", "/sys", "/dev", GUEST_INIT_PATH];

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

/// Wait for a process to exit on its own, polling `still_alive` until it reports
/// false; if it is still alive at `timeout`, invoke `kill` once as the backstop.
/// Returns true iff `kill` was invoked. Pure over its closures so the
/// self-exit-vs-backstop decision is testable without a real VM. Blocking — run
/// it off the async runtime.
fn wait_for_exit_or_kill(
    mut still_alive: impl FnMut() -> bool,
    kill: impl FnOnce(),
    timeout: Duration,
    step: Duration,
) -> bool {
    let mut waited = Duration::ZERO;
    while still_alive() {
        if waited >= timeout {
            kill();
            return true;
        }
        std::thread::sleep(step);
        waited += step;
    }
    false
}

/// Drains the main process's exec events, releasing flow-control credit for each
/// output chunk. On the terminal, posts the outcome unless the suppression latch
/// is set.
async fn run_entrypoint_consumer(
    mut events: tokio::sync::mpsc::Receiver<ExecEvent>,
    io: ExecIo,
    sink: EntrypointExitSink,
    terminal_untrusted: Arc<AtomicBool>,
) {
    while let Some(event) = events.recv().await {
        match event {
            ExecEvent::Stdout(bytes) | ExecEvent::Stderr(bytes) => {
                io.release_credit(bytes.len());
            }
            ExecEvent::Exit { code } => {
                // Post only a trusted terminal; a suppressed one (teardown or
                // crash) posts nothing.
                if !terminal_untrusted.load(Ordering::Acquire) {
                    sink.post(EntrypointExit::Exited { code }).await;
                }
                return;
            }
            ExecEvent::StartError(message) => {
                if !terminal_untrusted.load(Ordering::Acquire) {
                    sink.post(EntrypointExit::StartError { message }).await;
                }
                return;
            }
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

/// Checks that the image reference parses; a malformed reference is
/// `InvalidInput`. Called by `create_and_start`.
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

/// Rejects a gid without a uid, and env entries with an empty key, NUL, or '='
/// in the key.
fn check_exec_request(req: &ExecRequest) -> Result<(), BackendError> {
    if req.gid.is_some() && req.uid.is_none() {
        return Err(BackendError::InvalidInput("gid requires uid".into()));
    }
    validate_env(&req.env)
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

            krun.set_vm_config(DEFAULT_VCPUS, DEFAULT_RAM_MIB)
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
    /// The exec engine handle for this VM (shared with the console map). Owns the
    /// relay teardown ordering; this struct just interleaves it with the VM kill.
    mux: ExecMuxHost,
    console_map: ConsoleMap,
    id: SandboxId,
    /// The run-scoped main-process consumer, which reports the main process's
    /// exit. Fenced before teardown injects a synthetic terminal, so a forced
    /// terminal is never reported as an exit.
    consumer_task: Option<JoinHandle<()>>,
    /// Set the instant the VM is observed dead, or any teardown/drop begins —
    /// before any synthetic terminal can be produced. The consumer suppresses its
    /// exit report when set. Shared with the consumer task.
    terminal_untrusted: Arc<AtomicBool>,
}

impl LibkrunRunningVm {
    /// Sets the suppression latch and aborts the main-process consumer. Used by
    /// the immediate-kill `stop` path; `graceful_shutdown` uses `drain_consumer`.
    async fn fence_consumer(&mut self) {
        self.terminal_untrusted.store(true, Ordering::Release);
        if let Some(task) = self.consumer_task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    /// Waits for the main-process consumer to reach its terminal (the latch is
    /// already set, so it posts nothing), aborting it after
    /// `CONSUMER_DRAIN_TIMEOUT`.
    async fn drain_consumer(&mut self) {
        if let Some(task) = self.consumer_task.take() {
            let abort = task.abort_handle();
            if tokio::time::timeout(CONSUMER_DRAIN_TIMEOUT, task)
                .await
                .is_err()
            {
                abort.abort();
            }
        }
    }
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
    /// Kills the VM (verifying the PID first), drains run-scoped I/O and network
    /// resources, and drops the published console channel. Best-effort, with no
    /// guest flush. Used by `stop`; teardown runs `graceful_shutdown` first.
    async fn shutdown(mut self) {
        // Fence the main-process consumer before any synthetic terminal so it
        // never reports a forced terminal as a real exit.
        self.fence_consumer().await;
        // Tear down the exec engine first: this cancels the VM gate, drains
        // (abort+await) the stdin/control relays so a retained handle's next
        // send fails immediately, and asks the reader to deliver a synthetic
        // terminal to every live session before socket I/O is aborted. The
        // ordering is owned by the engine (see `ExecMuxHost::shutdown`).
        self.mux.shutdown().await;
        // Drop the published handle so exec() can no longer reach this VM. The
        // cancel + closing gates already refuse any racing exec(), so this is
        // cleanup only.
        if let Ok(mut map) = self.console_map.write() {
            map.remove(&self.id);
        }

        let pid = self.pid;
        let start = self.pid_start_time;
        // Keep the kill-guard ARMED across the kill: if this future is dropped
        // (runtime cancellation) before the kill completes, the guard's Drop still
        // reaps the VM. Defuse only AFTER the explicit kill, so the two never both
        // fire (verify_pid also guards against a double-kill).
        tokio::task::spawn_blocking(move || {
            if verify_pid(pid, start) {
                kill_and_wait(pid);
            }
        })
        .await
        .ok();
        self.child_guard.defuse();

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
        // observing it dead: cancel + abort the exec relays (so a crashed VM's
        // relays also terminate and their receivers drop, rejecting writes) and
        // clear the stale console handle. Drop can't await, so the abort is
        // best-effort here. The kill is owned by `child_guard` (already defused
        // if the VM was reaped).
        //
        // Mark the terminal untrusted before tearing the relays down: the
        // detached consumer will receive the resulting synthetic terminal and
        // must suppress it rather than report a bogus exit carrier.
        self.terminal_untrusted.store(true, Ordering::Release);
        if let Some(task) = self.consumer_task.take() {
            task.abort();
        }
        self.mux.drop_relays_sync();
        if let Ok(mut map) = self.console_map.write() {
            map.remove(&self.id);
        }
    }
}

/// A prepared (or recovered) rootfs. Cleanup operates purely on `root` via
/// `cleanup_session_dir`, so no provider handle is retained.
pub struct LibkrunRootfsHandle {
    root: PathBuf,
}

impl RootfsHandleExt for LibkrunRootfsHandle {
    fn rootfs_path(&self) -> &Path {
        &self.root
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
        Ok(LibkrunRootfsHandle { root })
    }

    async fn start(
        &mut self,
        cfg: &SandboxConfig,
        rootfs: &Self::RootfsHandle,
        entrypoint_exit: EntrypointExitSink,
    ) -> Result<Self::RunningVm, BackendError> {
        // Defense-in-depth: the create + durable-record paths already validated
        // this, but a corrupt command must fail the boot loudly, not reach exec.
        validate_entrypoint(cfg.entrypoint.as_deref()).map_err(BackendError::Internal)?;

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

        // Convert the console socket to async halves and spawn the exec engine
        // over them, then publish its handle so exec() can reach the guest. The
        // (practically impossible) conversion failure for a fresh socketpair fd
        // is surfaced as a start error rather than a silently dead console.
        let (read_half, write_half) = match console_host_sock
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UnixStream::from_std(console_host_sock))
        {
            Ok(stream) => stream.into_split(),
            Err(e) => {
                child_guard.defuse();
                tokio::task::spawn_blocking(move || kill_and_wait(child_pid))
                    .await
                    .ok();
                return Err(BackendError::Internal(format!("console socket setup: {e}")));
            }
        };
        let (mux, io_task) = spawn_mux(read_half, write_half);
        if let Ok(mut map) = self.console_map.write() {
            map.insert(self.id.clone(), mux.clone());
        }

        // Construct the VM handle FIRST so any post-fork launch failure can unwind
        // the entire VM (kill + relays + console-map entry + net) through one
        // `shutdown()`, leaving no orphan process or stale console handle.
        let mut vm = LibkrunRunningVm {
            pid: child_pid,
            pid_start_time: start_time,
            child_guard,
            net_handle,
            io_task: Some(io_task),
            mux,
            console_map: self.console_map.clone(),
            id: self.id.clone(),
            consumer_task: None,
            terminal_untrusted: Arc::new(AtomicBool::new(false)),
        };

        // Launch the main process (if any) as a normal exec with its
        // exit-reporting consumer. An idle sandbox (no entrypoint) opens no exec.
        if let Some(entrypoint) = cfg.entrypoint.clone()
            && let Err(e) = self
                .launch_entrypoint(&mut vm, entrypoint, entrypoint_exit)
                .await
        {
            vm.shutdown().await;
            return Err(e);
        }

        Ok(vm)
    }

    async fn stop(&mut self, vm: Self::RunningVm) {
        vm.shutdown().await;
    }

    async fn graceful_shutdown(&self, vm: &mut Self::RunningVm) {
        // (a) Suppress any terminal report without aborting the consumer.
        vm.terminal_untrusted.store(true, Ordering::Release);
        // (b) cancel the relays and send the engine teardown. This injects a
        // synthetic terminal AFTER any queued output (relay FIFO), so the consumer
        // drains all staged output before it sees the terminal.
        vm.mux.shutdown().await;
        // Wait for the consumer to reach the terminal; it posts nothing because
        // the latch is set. Bounded.
        vm.drain_consumer().await;
        // (c) await the I/O task so the console transport actually drops and the
        // guest observes the hangup BEFORE we start waiting for it to self-exit.
        if let Some(io_task) = vm.io_task.take() {
            let abort = io_task.abort_handle();
            if tokio::time::timeout(Duration::from_millis(500), io_task)
                .await
                .is_err()
            {
                abort.abort();
            }
        }
        // (d)/(e) the guest now flushes (sync) and self-exits; wait a bounded time
        // for that, killing only as the backstop on timeout. Keep the kill-guard
        // ARMED across the wait+kill so a dropped (cancelled) graceful future still
        // reaps the retained VM; defuse only AFTER the kill completes.
        let pid = vm.pid;
        tokio::task::spawn_blocking(move || {
            wait_for_exit_or_kill(
                || check_child_liveness(pid),
                || kill_and_wait(pid),
                GRACEFUL_EXIT_TIMEOUT,
                GRACEFUL_EXIT_STEP,
            )
        })
        .await
        .ok();
        vm.child_guard.defuse();
        // Drop the published console handle and stop networking.
        if let Ok(mut map) = vm.console_map.write() {
            map.remove(&vm.id);
        }
        if let Some(net) = vm.net_handle.take() {
            tokio::task::spawn_blocking(move || {
                let _ = net.stop();
            })
            .await
            .ok();
        }
    }

    async fn teardown(
        &mut self,
        vm: Option<Self::RunningVm>,
        rootfs: Option<Self::RootfsHandle>,
    ) -> Result<(), (BackendError, Option<Self::RootfsHandle>)> {
        if let Some(mut vm) = vm {
            // Flush the guest via the graceful primitive, then drop the inert handle.
            self.graceful_shutdown(&mut vm).await;
            drop(vm);
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
        Ok(Some(LibkrunRootfsHandle { root }))
    }

    fn is_alive(&self, vm: &mut Self::RunningVm) -> bool {
        if check_child_liveness(vm.pid) {
            true
        } else {
            // The VM is dead. Mark the terminal untrusted BEFORE the handle is
            // dropped (which tears the relays down and injects a synthetic
            // terminal), so the consumer suppresses it instead of manufacturing a
            // bogus exit carrier. Reaped (possibly to be reused): never signal
            // this PID again.
            vm.terminal_untrusted.store(true, Ordering::Release);
            vm.child_guard.defuse();
            false
        }
    }
}

impl LibkrunDriver {
    /// Opens the sandbox's main process as a normal exec and spawns its
    /// exit-reporting consumer onto the VM handle. Every fallible step returns
    /// `Err` without wiring the VM, so the caller's `shutdown()` unwinds the whole
    /// VM.
    async fn launch_entrypoint(
        &self,
        vm: &mut LibkrunRunningVm,
        entrypoint: Vec<String>,
        sink: EntrypointExitSink,
    ) -> Result<(), BackendError> {
        // Argv-only frame with NO env: the child inherits init's environ, which
        // already carries the standard guest vars + the create env. cwd "/" and no
        // uid/gid (it runs as the main process).
        let host_msg = HostFrame::Exec {
            id: ENTRYPOINT_EXEC_ID.to_string(),
            cmd: entrypoint,
            env: vec![],
            workdir: None,
            uid: None,
            gid: None,
            mode: ExecMode::default(),
        };
        let json = serde_json::to_string(&host_msg)
            .map_err(|e| BackendError::Internal(format!("serialize entrypoint exec: {e}")))?;
        if protocol::outbound_json_frame_too_large(json.len()) {
            return Err(BackendError::Internal(
                "entrypoint command exceeds 1 MiB frame limit".into(),
            ));
        }

        let handle = vm
            .mux
            .open(ExecId(ENTRYPOINT_EXEC_ID.to_string()), json)
            .await
            .map_err(|e| match e {
                MuxError::Closing => BackendError::Internal("vm closing during launch".into()),
                MuxError::ReaderGone => BackendError::Internal("console reader gone".into()),
                MuxError::WriteChannelClosed => {
                    BackendError::Internal("console I/O task gone".into())
                }
                MuxError::WriteFailed => {
                    BackendError::Internal("failed to send entrypoint to guest".into())
                }
            })?;

        // Output produced before the consumer spawns is held in the relay's per-id
        // buffer, bounded by the output-credit window.
        let (events, io) = handle.split();
        // The main process is non-interactive: signal EOF at the start so a child
        // reading stdin sees a clean end rather than blocking forever.
        let _ = io.close_stdin().await;
        let consumer = tokio::spawn(run_entrypoint_consumer(
            events,
            io,
            sink,
            vm.terminal_untrusted.clone(),
        ));
        vm.consumer_task = Some(consumer);
        Ok(())
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
    fork_supervisor: Arc<ForkSupervisor>,
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
        let fork_supervisor = Arc::new(ForkSupervisor::new()?);

        let factory = LibkrunFactory {
            data_dir: data_dir.clone(),
            init_binary,
            rootfs_provider,
            image_cache,
            registry_client,
            fork_supervisor: fork_supervisor.clone(),
            launch_mutex: Arc::new(Mutex::new(())),
            console_map: console_map.clone(),
        };
        let store: Arc<dyn Store> = Arc::new(JsonStore::new(data_dir.join("state.json")));

        Ok(Self {
            runtime: ReconcileRuntime::new_recoverable(factory, store),
            fork_supervisor,
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
    async fn create_and_start(&self, config: SandboxConfig) -> Result<SandboxId, BackendError> {
        validate_image_ref(&config.image)?;
        validate_mounts(&config.mounts)?;
        validate_env(&config.env)?;
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

    async fn exec(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecHandle, BackendError> {
        let view = self.runtime.status(id)?;
        // Input checks run after the sandbox resolves and before the frame size
        // check, the running-state check, or any guest dispatch.
        check_exec_request(&req)?;

        // Build and size-check the exec frame as INPUT VALIDATION: its size is
        // driven by user input (command/cwd/env), so an oversized request is
        // malformed for the 1 MiB wire limit (422), not an internal error (500).
        // Done here — after the sandbox resolves, alongside the gid/env checks —
        // but BEFORE registering the session, so a rejected request never leaves a
        // session or forwarder behind.
        let exec_id = self.alloc_exec_id();
        let env_strs: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let host_msg = HostFrame::Exec {
            id: exec_id.0.clone(),
            cmd: req.command,
            env: env_strs,
            workdir: req.working_dir,
            uid: req.uid,
            gid: req.gid,
            mode: req.mode,
        };
        let json = serde_json::to_string(&host_msg)
            .map_err(|e| BackendError::Internal(format!("serialize exec msg: {e}")))?;
        if protocol::outbound_json_frame_too_large(json.len()) {
            return Err(BackendError::InvalidInput(
                "exec message exceeds 1 MiB frame limit".into(),
            ));
        }

        if view.status.state != Some(State::Running) {
            return Err(BackendError::InvalidState);
        }
        let mux = {
            let map = self.console_map.read().unwrap();
            map.get(id).cloned()
        }
        .ok_or(BackendError::InvalidState)?;

        // The engine owns the full open ordering (register-before-exec barrier →
        // exec-frame write+ack → atomic relay registration against the closing
        // gate) and refuses if the VM is shutting down. Map its failures back to
        // the backend error variants — the wire/status semantics are unchanged.
        mux.open(exec_id, json).await.map_err(|e| match e {
            MuxError::Closing => BackendError::InvalidState,
            MuxError::ReaderGone => BackendError::Internal("console reader gone".into()),
            MuxError::WriteChannelClosed => BackendError::Internal("console I/O task gone".into()),
            MuxError::WriteFailed => {
                BackendError::Internal("failed to send exec message to guest".into())
            }
        })
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
        let supervisor = self.fork_supervisor.clone();
        self.runtime.health(move || supervisor.is_alive()).await
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_isolation: true,
            network_policy: true,
            host_mounts: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_supervisor_reports_dead_after_thread_exit() {
        let mut supervisor = ForkSupervisor::new().unwrap();
        assert!(supervisor.is_alive());
        supervisor.tx.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while supervisor.is_alive() {
            assert!(std::time::Instant::now() < deadline, "thread did not exit");
            std::thread::sleep(Duration::from_millis(2));
        }
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
    // Validation tests
    // -----------------------------------------------------------------------
    // (base64 codec parity is owned by pipemux::protocol golden tests.)

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

    #[test]
    fn check_exec_request_rejects_gid_without_uid() {
        let req = |uid, gid| ExecRequest {
            command: vec!["id".into()],
            working_dir: None,
            env: vec![],
            uid,
            gid,
            mode: ExecMode::default(),
        };
        assert!(matches!(
            check_exec_request(&req(None, Some(5))),
            Err(BackendError::InvalidInput(m)) if m == "gid requires uid"
        ));
        assert!(check_exec_request(&req(Some(5), Some(5))).is_ok());
    }

    // -----------------------------------------------------------------------
    // Graceful-shutdown self-exit-vs-backstop ordering
    // -----------------------------------------------------------------------

    #[test]
    fn graceful_wait_skips_kill_when_process_self_exits() {
        // A process that self-exits promptly after console-close must NOT be
        // killed: the backstop counter stays zero.
        let mut polls = 0u32;
        let kills = std::cell::Cell::new(0u32);
        let killed = wait_for_exit_or_kill(
            || {
                polls += 1;
                polls < 3 // alive for two polls, then gone
            },
            || kills.set(kills.get() + 1),
            Duration::from_secs(5),
            Duration::from_millis(1),
        );
        assert!(!killed);
        assert_eq!(
            kills.get(),
            0,
            "self-exit must not trigger the kill backstop"
        );
    }

    #[test]
    fn graceful_wait_kills_after_timeout_when_never_exits() {
        // A process that never self-exits is killed exactly once, only after the
        // bounded wait elapses.
        let kills = std::cell::Cell::new(0u32);
        let killed = wait_for_exit_or_kill(
            || true,
            || kills.set(kills.get() + 1),
            Duration::from_millis(20),
            Duration::from_millis(2),
        );
        assert!(killed);
        assert_eq!(kills.get(), 1, "a stuck process is killed exactly once");
    }

    // -----------------------------------------------------------------------
    // Main-process consumer: exit report + suppression latch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn consumer_reports_real_exit() {
        use crate::backend::reconciler::{EntrypointExitSink, entrypoint_exited_outcome};
        let (events_tx, events_rx) = tokio::sync::mpsc::channel::<ExecEvent>(8);
        let (_dead, io) = ExecHandle::for_mock(ExecId("e".into())).split();
        let (sink, mut rx) = EntrypointExitSink::channel();
        let latch = Arc::new(AtomicBool::new(false));
        let consumer = tokio::spawn(run_entrypoint_consumer(events_rx, io, sink, latch));

        events_tx
            .send(ExecEvent::Stdout(b"hi".to_vec()))
            .await
            .unwrap();
        events_tx.send(ExecEvent::Exit { code: 7 }).await.unwrap();
        consumer.await.unwrap();

        // A trusted (real) terminal posts its outcome.
        assert_eq!(
            entrypoint_exited_outcome(rx.recv().await.unwrap()),
            Some(EntrypointExit::Exited { code: 7 })
        );
    }

    #[tokio::test]
    async fn consumer_suppresses_terminal_when_untrusted() {
        use crate::backend::reconciler::EntrypointExitSink;
        let (events_tx, events_rx) = tokio::sync::mpsc::channel::<ExecEvent>(8);
        let (_dead, io) = ExecHandle::for_mock(ExecId("e".into())).split();
        let (sink, mut rx) = EntrypointExitSink::channel();
        // Latch set BEFORE the terminal arrives (the teardown/crash signature): a
        // synthetic exit must NOT manufacture a carrier.
        let latch = Arc::new(AtomicBool::new(true));
        let consumer = tokio::spawn(run_entrypoint_consumer(events_rx, io, sink, latch));

        events_tx.send(ExecEvent::Exit { code: -1 }).await.unwrap();
        consumer.await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "an untrusted terminal must not post an exit"
        );
    }

    // -----------------------------------------------------------------------
    // Kill-guard reap-on-drop + post-fork unwind cleanup
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn child_guard_reaps_on_drop_when_armed() {
        // The shutdown/graceful kill paths keep the ChildGuard armed across the
        // kill so a cancelled (dropped) shutdown future still reaps the VM. This
        // pins that safety net: an armed guard, when dropped, kills + reaps its
        // child.
        let child = std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as i32;
        std::mem::forget(child); // the guard owns the reap (waitpid)
        let start = crate::store::pid_start_time(pid).expect("child start time");
        drop(ChildGuard::new(pid, start));
        // The guard reaps on a detached thread; poll briefly for the pid to clear.
        let mut gone = false;
        for _ in 0..300 {
            if !verify_pid(pid, start) {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(gone, "an armed guard must reap its child on drop");
    }

    #[tokio::test]
    async fn shutdown_clears_published_console_handle() {
        // The post-fork-failure unwind calls LibkrunRunningVm::shutdown(); it must
        // remove the published console handle (and finish the I/O task), so a
        // failed launch leaves no stale console entry. A non-existent pid makes the
        // kill path a verified no-op, so no real VM is needed.
        let (host, _guest) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (r, w) = host.into_split();
        let (mux, io_task) = spawn_mux(r, w);

        let console_map: ConsoleMap = Arc::new(RwLock::new(HashMap::new()));
        let id = SandboxId("sb-x".into());
        console_map.write().unwrap().insert(id.clone(), mux.clone());

        let fake_pid = 0x7fff_fffe; // never a live process -> verify_pid is false
        let vm = LibkrunRunningVm {
            pid: fake_pid,
            pid_start_time: 0,
            child_guard: ChildGuard::new(fake_pid, 0),
            net_handle: None,
            io_task: Some(io_task),
            mux,
            console_map: console_map.clone(),
            id: id.clone(),
            consumer_task: None,
            terminal_untrusted: Arc::new(AtomicBool::new(false)),
        };
        vm.shutdown().await;

        assert!(
            console_map.read().unwrap().get(&id).is_none(),
            "shutdown must drop the published console handle"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn graceful_shutdown_drains_consumer_without_posting() {
        // A controlled teardown runs the consumer through the (synthetic) terminal
        // rather than aborting it, and posts no carrier.
        use crate::backend::reconciler::EntrypointExitSink;
        use tokio::io::AsyncWriteExt;

        let (host, guest) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (hr, hw) = host.into_split();
        let (mux, io_task) = spawn_mux(hr, hw);

        let exec_json = serde_json::to_string(&HostFrame::Exec {
            id: ENTRYPOINT_EXEC_ID.to_string(),
            cmd: vec!["x".to_string()],
            env: vec![],
            workdir: None,
            uid: None,
            gid: None,
            mode: ExecMode::default(),
        })
        .unwrap();
        let handle = mux
            .open(ExecId(ENTRYPOINT_EXEC_ID.to_string()), exec_json)
            .await
            .unwrap();
        let (events, io) = handle.split();

        let (sink, mut rx) = EntrypointExitSink::channel();
        let latch = Arc::new(AtomicBool::new(false));
        let returned = Arc::new(AtomicBool::new(false));
        let consumer = {
            let latch = latch.clone();
            let returned = returned.clone();
            tokio::spawn(async move {
                run_entrypoint_consumer(events, io, sink, latch).await;
                returned.store(true, Ordering::Release);
            })
        };

        // The guest emits stdout (base64 of "hello") ahead of the teardown.
        guest.set_nonblocking(true).unwrap();
        let guest = tokio::net::UnixStream::from_std(guest).unwrap();
        let (_gr, mut gw) = guest.into_split();
        gw.write_all(b"{\"type\":\"stdout\",\"id\":\"entrypoint\",\"data\":\"aGVsbG8=\"}\n")
            .await
            .unwrap();

        let console_map: ConsoleMap = Arc::new(RwLock::new(HashMap::new()));
        let id = SandboxId("sb-x".into());
        console_map.write().unwrap().insert(id.clone(), mux.clone());
        let fake_pid = 0x7fff_fffe;
        let mut vm = LibkrunRunningVm {
            pid: fake_pid,
            pid_start_time: 0,
            child_guard: ChildGuard::new(fake_pid, 0),
            net_handle: None,
            io_task: Some(io_task),
            mux,
            console_map: console_map.clone(),
            id: id.clone(),
            consumer_task: Some(consumer),
            terminal_untrusted: latch,
        };

        let tmp = tempfile::tempdir().unwrap();
        let driver = test_driver(tmp.path(), id);
        driver.graceful_shutdown(&mut vm).await;

        assert!(
            returned.load(Ordering::Acquire),
            "controlled teardown must drain the consumer to its terminal, not abort it"
        );
        assert!(
            rx.try_recv().is_err(),
            "controlled teardown must not post a carrier"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn teardown_fails_first_stdin_write_on_live_exec() {
        let (host, _guest) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (hr, hw) = host.into_split();
        let (mux, io_task) = spawn_mux(hr, hw);

        let exec_json = serde_json::to_string(&HostFrame::Exec {
            id: "exec-1".to_string(),
            cmd: vec!["cat".to_string()],
            env: vec![],
            workdir: None,
            uid: None,
            gid: None,
            mode: ExecMode::default(),
        })
        .unwrap();
        let handle = mux
            .open(ExecId("exec-1".to_string()), exec_json)
            .await
            .unwrap();
        let (_events, io) = handle.split();
        assert_eq!(
            io.write_stdin(b"x").await,
            Ok(()),
            "live exec accepts stdin"
        );

        let console_map: ConsoleMap = Arc::new(RwLock::new(HashMap::new()));
        let id = SandboxId("sb-x".into());
        console_map.write().unwrap().insert(id.clone(), mux.clone());
        let fake_pid = 0x7fff_fffe;
        let vm = LibkrunRunningVm {
            pid: fake_pid,
            pid_start_time: 0,
            child_guard: ChildGuard::new(fake_pid, 0),
            net_handle: None,
            io_task: Some(io_task),
            mux,
            console_map,
            id: id.clone(),
            consumer_task: None,
            terminal_untrusted: Arc::new(AtomicBool::new(false)),
        };

        let tmp = tempfile::tempdir().unwrap();
        let mut driver = test_driver(tmp.path(), id);
        assert!(driver.teardown(Some(vm), None).await.is_ok());

        assert_eq!(
            io.write_stdin(b"x").await,
            Err(()),
            "the first stdin write after teardown must fail"
        );
    }

    // -----------------------------------------------------------------------
    // Teardown cleanup is bounded to the canonical session dir
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn test_config() -> SandboxConfig {
        SandboxConfig {
            name: None,
            image: "alpine".into(),
            mounts: vec![],
            network: NetworkPolicy::Isolated,
            env: vec![],
            entrypoint: None,
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
            entrypoint_exit: None,
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
