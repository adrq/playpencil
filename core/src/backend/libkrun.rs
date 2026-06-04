use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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
    ExecBackchannel, ExecControl, ExecEvent, ExecHandle, ExecId, ExecMode, ExecRequest,
    INPUT_WINDOW, MountConfig, NetworkPolicy, STDIN_FRAME_RAW_MAX, SandboxConfig, SandboxId,
    SandboxStatus, SandboxView, StdinMsg,
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
        uid: Option<u32>,
        gid: Option<u32>,
        mode: ExecMode,
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
    /// Output flow-control: the guest stops reading this child's stdout/stderr.
    Pause {
        id: String,
    },
    /// Output flow-control: the guest resumes reading this child's output.
    Resume {
        id: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GuestMsg {
    Stdout {
        id: String,
        data: String,
    },
    Stderr {
        id: String,
        data: String,
    },
    Exit {
        id: String,
        code: i32,
    },
    /// The command never started as intended (distinct from a numeric exit).
    StartError {
        id: String,
        message: String,
    },
    /// Input flow-control: grant the host `bytes` more stdin send-credit.
    StdinCredit {
        id: String,
        bytes: usize,
    },
    /// The guest closed/discarded the child's stdin while the process keeps
    /// running (e.g. the child closed fd0 early). The host terminates this exec's
    /// stdin relay so pending and future writes fail loudly instead of hanging on
    /// credit that will never be granted.
    StdinClosed {
        id: String,
    },
}

// ---------------------------------------------------------------------------
// Output flow-control accounting thresholds (raw process bytes per exec id).
// ---------------------------------------------------------------------------

/// Pause a child's output once this many raw bytes are outstanding (between the
/// guest and the point the consumer has yielded them downstream).
const OUTPUT_HIGH: usize = 256 * 1024;
/// Resume a paused child once outstanding falls below this.
const OUTPUT_LOW: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Console I/O channels
// ---------------------------------------------------------------------------

/// Bound on the per-console interactive-signal channel. Client-driven signals
/// take a SEPARATE bounded path (not the unbounded reader-priority channel) so a
/// signal flood backpressures the client instead of growing host memory.
const SIGNAL_CHANNEL: usize = 64;

/// Bulk write command: exec/stdin/resize frames. Drained by the writer task
/// AFTER the priority and signal channels, so a flood of stdin never starves a
/// pause/resume/cancel or an interactive signal. Resize stays here (no
/// preemption needed); interactive signals use the bounded signal channel.
enum ConsoleCmd {
    Send(String),
    /// Like Send, but the write task confirms success/failure via the oneshot.
    /// exec() awaits the result so it can return an error if the Exec message
    /// was never delivered to the guest.
    SendAck(String, oneshot::Sender<bool>),
}

/// Priority write: pause/resume + latched cancellation signals. The writer
/// drains this before the bulk queue at every frame boundary.
enum PriorityMsg {
    Pause { id: String },
    Resume { id: String },
    Signal { id: String, sig: i32 },
}

/// Reader control channel (UNBOUNDED, independent of the bulk write queue) so a
/// saturated bulk queue can never block registration, credit release, or
/// teardown.
enum CtlMsg {
    RegisterExec {
        id: String,
        events_tx: mpsc::Sender<ExecEvent>,
        stdin_credit_tx: mpsc::UnboundedSender<u32>,
        done: CancellationToken,
        /// Terminates ONLY the stdin relay (not the control relay, not a
        /// terminal) when the guest reports the child closed its stdin early.
        stdin_closed: CancellationToken,
        /// Fired once the session is inserted AND its forwarder spawned — the
        /// register-before-exec barrier.
        ack: oneshot::Sender<()>,
    },
    /// Remove a registered exec, e.g. after a failed exec-frame write.
    UnregisterExec(String),
    /// Consumer-requested output-credit release; the reader is the sole mutator
    /// of the accounting.
    ReleaseCredit { id: String, raw_n: usize },
    /// The event consumer was dropped: stop accounting/pausing this id.
    Abandoned(String),
    /// Graceful shutdown: push a terminal to every live session, then stop.
    Teardown,
}

/// One ordered output item destined for an exec's event consumer.
enum SessionItem {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Terminal(Terminal),
}

enum Terminal {
    Exit { code: i32 },
    StartError { message: String },
}

/// Reader-owned per-id record. `outstanding`/`paused`/`abandoned` are mutated
/// ONLY by the reader task, so they need no synchronization.
struct ExecSession {
    out_tx: mpsc::UnboundedSender<SessionItem>,
    stdin_credit_tx: mpsc::UnboundedSender<u32>,
    outstanding: usize,
    paused: bool,
    abandoned: bool,
    /// Fired on terminal/teardown; closes the stdin + control relays only.
    done: CancellationToken,
    /// Fired when the guest reports the child closed its stdin early; closes the
    /// stdin relay ONLY (the process keeps running, so output + signals stay).
    stdin_closed: CancellationToken,
}

/// The exec back-channel for a libkrun-backed handle: routes output-credit
/// releases to the reader and latched cancellation to the priority writer.
struct LibkrunBackchannel {
    id: String,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    /// 0 none / 1 TERM / 2 KILL — coalesces repeated cancellation.
    cancel_phase: Arc<AtomicU8>,
}

impl ExecBackchannel for LibkrunBackchannel {
    fn release_credit(&self, raw_n: usize) {
        let _ = self.ctl_tx.send(CtlMsg::ReleaseCredit {
            id: self.id.clone(),
            raw_n,
        });
    }

    fn cancel(&self, sig: i32) {
        let target: u8 = if sig == libc::SIGKILL { 2 } else { 1 };
        loop {
            let cur = self.cancel_phase.load(Ordering::Acquire);
            if cur >= target {
                return; // already at or past this escalation level
            }
            if self
                .cancel_phase
                .compare_exchange(cur, target, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Resume once on the first advance so a paused child can receive
                // the signal; then the signal itself.
                if cur == 0 {
                    let _ = self.prio_tx.send(PriorityMsg::Resume {
                        id: self.id.clone(),
                    });
                }
                let _ = self.prio_tx.send(PriorityMsg::Signal {
                    id: self.id.clone(),
                    sig,
                });
                return;
            }
        }
    }
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
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    /// Bounded per-console interactive-signal path (framed JSON), drained by the
    /// writer ahead of bulk stdin. Bounded so a client signal flood backpressures.
    signal_tx: mpsc::Sender<String>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
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
    console_ctl_tx: mpsc::UnboundedSender<CtlMsg>,
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
        // Ask the console reader (independent unbounded ctl channel) to deliver
        // a terminal to any live exec sessions before socket I/O is aborted.
        let _ = self.console_ctl_tx.send(CtlMsg::Teardown);

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

        // Spawn the console I/O task and publish its channels. The bulk command
        // queue carries exec/stdin/resize frames; the priority queue carries
        // pause/resume + latched cancellation + interactive signals; the reader
        // ctl channel (unbounded, independent of the bulk queue) carries
        // registration/credit/teardown.
        let (cmd_tx, cmd_rx) = mpsc::channel::<ConsoleCmd>(256);
        let (prio_tx, prio_rx) = mpsc::unbounded_channel::<PriorityMsg>();
        let (signal_tx, signal_rx) = mpsc::channel::<String>(SIGNAL_CHANNEL);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<CtlMsg>();
        let io_task = tokio::spawn(run_console_io(
            console_host_sock,
            cmd_rx,
            prio_rx,
            prio_tx.clone(),
            signal_rx,
            ctl_tx.clone(),
            ctl_rx,
        ));
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
                    prio_tx: prio_tx.clone(),
                    signal_tx: signal_tx.clone(),
                    ctl_tx: ctl_tx.clone(),
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
            console_ctl_tx: ctl_tx,
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
        // Shared backstop for ALL callers (FFI/direct core, not just the HTTP/WS
        // adapters): credential drop is driven by uid, so a gid without a uid
        // would be silently ignored. Reject it (after the sandbox resolves, so an
        // unknown id is still 404) before requiring the running state or
        // dispatching to the guest.
        if req.gid.is_some() && req.uid.is_none() {
            return Err(BackendError::InvalidInput("gid requires uid".into()));
        }
        // Validate env at the same boundary (NUL / empty key / '=' in key) so a
        // malformed entry is a clean InvalidInput here rather than a guest-side
        // start error after the command was already accepted, or a key silently
        // re-split by putenv.
        validate_env(&req.env)?;

        // Build and size-check the exec frame as INPUT VALIDATION: its size is
        // driven by user input (command/cwd/env), so an oversized request is
        // malformed for the 1 MiB wire limit (422), not an internal error (500).
        // Done here — after the sandbox resolves, alongside the gid/env checks —
        // but BEFORE registering the session, so a rejected request never leaves a
        // session or forwarder behind.
        let exec_id = self.alloc_exec_id();
        let env_strs: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let host_msg = HostMsg::Exec {
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
        if json.len() >= MAX_FRAME_BYTES {
            return Err(BackendError::InvalidInput(
                "exec message exceeds 1 MiB frame limit".into(),
            ));
        }

        if view.status.state != Some(State::Running) {
            return Err(BackendError::InvalidState);
        }
        let ConsoleHandle {
            cmd_tx,
            prio_tx,
            signal_tx,
            ctl_tx,
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

        let (events_tx, events_rx) = mpsc::channel::<ExecEvent>(256);
        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinMsg>(64);
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ExecControl>(16);
        let (credit_tx, credit_rx) = mpsc::unbounded_channel::<u32>();
        let done = CancellationToken::new();
        let stdin_closed = CancellationToken::new();
        let cancel_phase = Arc::new(AtomicU8::new(0));

        // Register-before-exec barrier: the reader must install the session and
        // spawn its forwarder BEFORE the guest can receive the exec frame, else
        // early output for this id would be dropped as "unknown id". The ctl
        // channel is unbounded and independent of the bulk writer, so this never
        // blocks behind a saturated bulk queue.
        let (ack_tx, ack_rx) = oneshot::channel::<()>();
        ctl_tx
            .send(CtlMsg::RegisterExec {
                id: exec_id.0.clone(),
                events_tx,
                stdin_credit_tx: credit_tx,
                done: done.clone(),
                stdin_closed: stdin_closed.clone(),
                ack: ack_tx,
            })
            .map_err(|_| BackendError::Internal("console reader gone".into()))?;
        ack_rx
            .await
            .map_err(|_| BackendError::Internal("console reader gone".into()))?;

        let (wack_tx, wack_rx) = oneshot::channel::<bool>();
        cmd_tx
            .send(ConsoleCmd::SendAck(json, wack_tx))
            .await
            .map_err(|_| BackendError::Internal("console I/O task gone".into()))?;
        let write_ok = match tokio::time::timeout(std::time::Duration::from_secs(30), wack_rx).await
        {
            Ok(result) => result.unwrap_or(false),
            Err(_) => false,
        };
        if !write_ok {
            let _ = ctl_tx.send(CtlMsg::UnregisterExec(exec_id.0.clone()));
            return Err(BackendError::Internal(
                "failed to send exec message to guest".into(),
            ));
        }

        let stdin_exec_id = exec_id.0.clone();
        let stdin_cmd_tx = cmd_tx.clone();
        let stdin_cancel = cancel.clone();
        let stdin_done = done.clone();
        let stdin_closed_relay = stdin_closed.clone();
        let ctrl_exec_id = exec_id.0.clone();
        let ctrl_cmd_tx = cmd_tx.clone();
        let ctrl_signal_tx = signal_tx.clone();
        let ctrl_cancel = cancel.clone();
        let ctrl_done = done.clone();

        // Spawn + register the stdin/control relays atomically against
        // shutdown's drain: if the VM is already closing or cancelled they are
        // never spawned and exec is refused, so no relay can keep a
        // stdin/control channel open past teardown. Both relays terminate when
        // the VM is cancelled (stop/destroy/crash), when the per-exec `done`
        // fires (terminal/start-error/teardown), when the caller drops their
        // sender, or when the console closes.
        let registered = register_exec_relays(&exec_tasks, &cancel, move || {
            let stdin_task = tokio::spawn(stdin_relay(
                stdin_exec_id,
                stdin_rx,
                credit_rx,
                stdin_cmd_tx,
                stdin_cancel,
                stdin_done,
                stdin_closed_relay,
            ));
            let ctrl_task = tokio::spawn(control_relay(
                ctrl_exec_id,
                ctrl_rx,
                ctrl_cmd_tx,
                ctrl_signal_tx,
                ctrl_cancel,
                ctrl_done,
            ));
            (stdin_task, ctrl_task)
        });
        if !registered {
            // The VM started shutting down after we registered with the guest;
            // unregister (best-effort) and refuse rather than hand back a
            // briefly-live stdin/control sender.
            let _ = ctl_tx.send(CtlMsg::UnregisterExec(exec_id.0.clone()));
            return Err(BackendError::InvalidState);
        }

        let backchannel = Arc::new(LibkrunBackchannel {
            id: exec_id.0.clone(),
            ctl_tx,
            prio_tx,
            cancel_phase,
        });

        Ok(ExecHandle {
            exec_id,
            events: events_rx,
            io: crate::types::ExecIo {
                stdin: stdin_tx,
                control: ctrl_tx,
                backchannel,
                stdin_closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                stdin_gate: Arc::new(tokio::sync::Mutex::new(())),
            },
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

async fn run_console_io(
    sock: UnixStream,
    cmd_rx: mpsc::Receiver<ConsoleCmd>,
    prio_rx: mpsc::UnboundedReceiver<PriorityMsg>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    signal_rx: mpsc::Receiver<String>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    ctl_rx: mpsc::UnboundedReceiver<CtlMsg>,
) {
    if sock.set_nonblocking(true).is_err() {
        return;
    }
    let sock = match tokio::net::UnixStream::from_std(sock) {
        Ok(s) => s,
        Err(_) => return,
    };

    let (read_half, write_half) = sock.into_split();
    // Writer task: priority frames first, then interactive signals, then the bulk
    // queue. Only this task ever awaits the socket write half, so the reader never
    // blocks on a write.
    let write_task = tokio::spawn(run_writer(write_half, cmd_rx, prio_rx, signal_rx));
    // Reader: owns the read half, the session map, and the (unbounded,
    // independent) control channel; it is the SOLE mutator of per-id accounting.
    run_reader(read_half, ctl_rx, ctl_tx, prio_tx).await;
    write_task.abort();
}

/// Drain the priority channel, then the bounded interactive-signal channel,
/// ahead of the bulk command queue at every frame boundary — so a flood of bulk
/// stdin can never starve a pause/resume/cancel or an interactive signal. The
/// signal channel is bounded (unlike the reader-priority channel, whose senders
/// are bounded-by-construction), so a client signal flood backpressures instead
/// of growing host memory.
async fn run_writer(
    write_half: tokio::net::unix::OwnedWriteHalf,
    mut cmd_rx: mpsc::Receiver<ConsoleCmd>,
    mut prio_rx: mpsc::UnboundedReceiver<PriorityMsg>,
    mut signal_rx: mpsc::Receiver<String>,
) {
    use tokio::io::AsyncWriteExt;
    let mut wh = write_half;
    loop {
        tokio::select! {
            biased;
            // Priority frames win at the frame boundary. When all priority
            // senders are gone recv() yields None, the pattern fails to match,
            // and this branch is skipped in favour of the next.
            Some(p) = prio_rx.recv() => {
                let msg = match p {
                    PriorityMsg::Pause { id } => HostMsg::Pause { id },
                    PriorityMsg::Resume { id } => HostMsg::Resume { id },
                    PriorityMsg::Signal { id, sig } => HostMsg::Signal { id, signal: sig },
                };
                if let Ok(json) = serde_json::to_string(&msg)
                    && wh.write_all(format!("{json}\n").as_bytes()).await.is_err()
                {
                    break;
                }
            }
            // Interactive signals (pre-framed JSON) preempt bulk stdin but sit on
            // a bounded channel so a flood cannot grow host memory.
            Some(json) = signal_rx.recv() => {
                if wh.write_all(format!("{json}\n").as_bytes()).await.is_err() {
                    break;
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    ConsoleCmd::Send(json) => {
                        if wh.write_all(format!("{json}\n").as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    ConsoleCmd::SendAck(json, ack) => {
                        let ok = wh.write_all(format!("{json}\n").as_bytes()).await.is_ok();
                        let _ = ack.send(ok);
                        if !ok {
                            break;
                        }
                    }
                }
            }
            // Both channels closed (VM gone): nothing more to write. The reader
            // ending aborts this task anyway; this guards against an all-disabled
            // select.
            else => break,
        }
    }
}

/// Reader: parse guest frames, drive output-credit accounting, route control
/// messages, and on teardown push a terminal to every live session.
async fn run_reader(
    read_half: tokio::net::unix::OwnedReadHalf,
    mut ctl_rx: mpsc::UnboundedReceiver<CtlMsg>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
) {
    let mut reader = tokio::io::BufReader::new(read_half);
    let mut sessions: HashMap<String, ExecSession> = HashMap::new();
    let mut line_buf = Vec::new();

    loop {
        tokio::select! {
            line_result = read_capped_line(&mut reader, &mut line_buf) => {
                match line_result {
                    Ok(Some(line)) => handle_guest_frame(&line, &mut sessions, &prio_tx),
                    Ok(None) => {} // oversized frame discarded; keep reading
                    Err(_) => break, // EOF or I/O error
                }
            }
            ctl = ctl_rx.recv() => {
                match ctl {
                    Some(CtlMsg::RegisterExec { id, events_tx, stdin_credit_tx, done, stdin_closed, ack }) => {
                        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionItem>();
                        // Spawn the forwarder BEFORE acking so the session is
                        // fully live (insert + forwarder) when exec() proceeds.
                        tokio::spawn(forward_output(id.clone(), out_rx, events_tx, ctl_tx.clone()));
                        sessions.insert(id, ExecSession {
                            out_tx,
                            stdin_credit_tx,
                            outstanding: 0,
                            paused: false,
                            abandoned: false,
                            done,
                            stdin_closed,
                        });
                        let _ = ack.send(());
                    }
                    Some(CtlMsg::UnregisterExec(id)) => {
                        if let Some(s) = sessions.remove(&id) {
                            s.done.cancel();
                        }
                    }
                    Some(CtlMsg::ReleaseCredit { id, raw_n }) => {
                        if let Some(s) = sessions.get_mut(&id)
                            && !s.abandoned
                        {
                            s.outstanding = s.outstanding.saturating_sub(raw_n);
                            if s.paused && s.outstanding < OUTPUT_LOW {
                                s.paused = false;
                                let _ = prio_tx.send(PriorityMsg::Resume { id });
                            }
                        }
                    }
                    Some(CtlMsg::Abandoned(id)) => {
                        if let Some(s) = sessions.get_mut(&id) {
                            s.abandoned = true;
                            if s.paused {
                                s.paused = false;
                                let _ = prio_tx.send(PriorityMsg::Resume { id });
                            }
                        }
                    }
                    Some(CtlMsg::Teardown) | None => break,
                }
            }
        }
    }

    // Teardown: push a synthetic terminal into each live session BEFORE the
    // socket I/O is torn down, so the forwarder always delivers a terminal.
    for (_id, s) in sessions.drain() {
        let _ = s
            .out_tx
            .send(SessionItem::Terminal(Terminal::Exit { code: -1 }));
        s.done.cancel();
    }
}

/// Per-id output forwarder: drains the ordered `out_rx` to the event consumer.
/// Lives on `out_rx` ONLY (it never observes the per-exec `done`), so the
/// FIFO-queued output and its terminal are always delivered before it exits. If
/// the consumer is dropped, it signals `Abandoned` once (so the reader unpauses
/// and stops accounting) and then drains/discards to the terminal.
async fn forward_output(
    id: String,
    mut out_rx: mpsc::UnboundedReceiver<SessionItem>,
    events_tx: mpsc::Sender<ExecEvent>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
) {
    let mut abandoned = false;
    loop {
        // While a consumer is still attached, watch for it dropping even when no
        // output is flowing (e.g. the guest is paused at the output-credit HIGH
        // mark). Parking on `out_rx.recv()` alone would never observe that drop,
        // so the reader would never get `Abandoned`, never resume, and the child
        // could block in write() until teardown. Once abandoned we stop watching
        // `closed()` (it would resolve immediately) and just drain to discard.
        let item = if abandoned {
            match out_rx.recv().await {
                Some(item) => item,
                None => break,
            }
        } else {
            tokio::select! {
                biased;
                _ = events_tx.closed() => {
                    abandoned = true;
                    let _ = ctl_tx.send(CtlMsg::Abandoned(id.clone()));
                    continue;
                }
                maybe = out_rx.recv() => match maybe {
                    Some(item) => item,
                    None => break,
                },
            }
        };
        match item {
            SessionItem::Stdout(b) => {
                if !abandoned && events_tx.send(ExecEvent::Stdout(b)).await.is_err() {
                    abandoned = true;
                    let _ = ctl_tx.send(CtlMsg::Abandoned(id.clone()));
                }
            }
            SessionItem::Stderr(b) => {
                if !abandoned && events_tx.send(ExecEvent::Stderr(b)).await.is_err() {
                    abandoned = true;
                    let _ = ctl_tx.send(CtlMsg::Abandoned(id.clone()));
                }
            }
            SessionItem::Terminal(t) => {
                if !abandoned {
                    let ev = match t {
                        Terminal::Exit { code } => ExecEvent::Exit { code },
                        Terminal::StartError { message } => ExecEvent::StartError(message),
                    };
                    let _ = events_tx.send(ev).await;
                }
                return;
            }
        }
    }
    // out_rx closed without a terminal (e.g. forced abort) → synthetic exit.
    if !abandoned {
        let _ = events_tx.send(ExecEvent::Exit { code: -1 }).await;
    }
}

/// Per-id stdin relay with a byte-exact credit window. Starts with a full
/// [`INPUT_WINDOW`] of send-credit and parks (no busy-spin) awaiting guest
/// `stdin_credit` grants once exhausted; each emitted frame is at most
/// [`STDIN_FRAME_RAW_MAX`] raw bytes. Exits on cancel/done/EOF or when the guest
/// reports the child closed its stdin early (`stdin_closed`), dropping its
/// receivers so a retained handle's stdin send fails promptly rather than
/// hanging on credit that will never be granted.
async fn stdin_relay(
    id: String,
    mut stdin_rx: mpsc::Receiver<StdinMsg>,
    mut credit_rx: mpsc::UnboundedReceiver<u32>,
    cmd_tx: mpsc::Sender<ConsoleCmd>,
    cancel: CancellationToken,
    done: CancellationToken,
    stdin_closed: CancellationToken,
) {
    let mut send_window: u64 = INPUT_WINDOW as u64;
    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => return,
            _ = done.cancelled() => return,
            _ = stdin_closed.cancelled() => return,
            m = stdin_rx.recv() => m,
        };
        let data = match msg {
            Some(StdinMsg::Data(d)) => d,
            // Explicit EOF or all senders dropped: emit one empty frame, stop.
            Some(StdinMsg::Eof) | None => {
                send_stdin_eof(&id, &cmd_tx).await;
                return;
            }
        };
        let mut off = 0;
        while off < data.len() {
            // Absorb any pending grants without blocking.
            while let Ok(n) = credit_rx.try_recv() {
                send_window = send_window.saturating_add(n as u64);
            }
            while send_window == 0 {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = done.cancelled() => return,
                    _ = stdin_closed.cancelled() => return,
                    g = credit_rx.recv() => match g {
                        Some(n) => send_window = send_window.saturating_add(n as u64),
                        None => return, // grants channel gone
                    },
                }
            }
            let take = (data.len() - off)
                .min(send_window as usize)
                .min(STDIN_FRAME_RAW_MAX);
            let frame = HostMsg::Stdin {
                id: id.clone(),
                data: base64_encode(&data[off..off + take]),
            };
            match serde_json::to_string(&frame) {
                Ok(json) => {
                    if cmd_tx.send(ConsoleCmd::Send(json)).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
            send_window -= take as u64;
            off += take;
        }
    }
}

async fn send_stdin_eof(id: &str, cmd_tx: &mpsc::Sender<ConsoleCmd>) {
    if let Ok(json) = serde_json::to_string(&HostMsg::Stdin {
        id: id.to_string(),
        data: String::new(),
    }) {
        let _ = cmd_tx.send(ConsoleCmd::Send(json)).await;
    }
}

/// Per-id control relay for interactive signal/resize (duplex face). Interactive
/// SIGNALS take the bounded signal channel so a SIGINT preempts streamed bulk
/// stdin (drained ahead of it by the writer) WITHOUT an unbounded queue: a signal
/// flood backpressures here (and thus the WS client) instead of growing host
/// memory. RESIZE stays on the bulk path. Exits on cancel/done/EOF so a retained
/// handle's control send fails promptly.
async fn control_relay(
    id: String,
    mut ctrl_rx: mpsc::Receiver<ExecControl>,
    cmd_tx: mpsc::Sender<ConsoleCmd>,
    signal_tx: mpsc::Sender<String>,
    cancel: CancellationToken,
    done: CancellationToken,
) {
    loop {
        let ctrl = tokio::select! {
            _ = cancel.cancelled() => return,
            _ = done.cancelled() => return,
            m = ctrl_rx.recv() => match m {
                Some(c) => c,
                None => return,
            },
        };
        match ctrl {
            ExecControl::Signal(signal) => {
                // Bounded priority path: preempts queued bulk stdin but awaiting
                // the send backpressures a signal flood (no unbounded growth).
                let Ok(json) = serde_json::to_string(&HostMsg::Signal {
                    id: id.clone(),
                    signal,
                }) else {
                    continue;
                };
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = done.cancelled() => return,
                    r = signal_tx.send(json) => {
                        if r.is_err() {
                            return;
                        }
                    }
                }
            }
            ExecControl::Resize { cols, rows } => {
                let msg = HostMsg::Resize {
                    id: id.clone(),
                    cols: cols as u32,
                    rows: rows as u32,
                };
                if let Ok(json) = serde_json::to_string(&msg)
                    && cmd_tx.send(ConsoleCmd::Send(json)).await.is_err()
                {
                    return;
                }
            }
        }
    }
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

/// Parse one guest frame and dispatch it. Never awaits: output is staged into
/// the per-id unbounded `out_tx`, credit accounting and pause emission are
/// synchronous, and terminals fire the session's `done`. This keeps the reader
/// free of any head-of-line blocking.
fn handle_guest_frame(
    line: &str,
    sessions: &mut HashMap<String, ExecSession>,
    prio_tx: &mpsc::UnboundedSender<PriorityMsg>,
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
            stage_output(sessions, prio_tx, &id, true, bytes);
        }
        GuestMsg::Stderr { id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                tracing::warn!("base64 decode failure for stderr on exec {id}; dropping message");
                return;
            };
            stage_output(sessions, prio_tx, &id, false, bytes);
        }
        GuestMsg::Exit { id, code } => {
            terminate_session(sessions, &id, Terminal::Exit { code });
        }
        GuestMsg::StartError { id, message } => {
            terminate_session(sessions, &id, Terminal::StartError { message });
        }
        GuestMsg::StdinCredit { id, bytes } => {
            if let Some(s) = sessions.get(&id) {
                let grant = bytes.min(u32::MAX as usize) as u32;
                let _ = s.stdin_credit_tx.send(grant);
            }
        }
        GuestMsg::StdinClosed { id } => {
            // The child closed its stdin while still running: terminate the stdin
            // relay so a write parked on exhausted credit (or any future write)
            // fails promptly instead of waiting on credit that will never come.
            if let Some(s) = sessions.get(&id) {
                s.stdin_closed.cancel();
            }
        }
    }
}

/// Stage one output chunk and apply the output-credit accounting. The reader is
/// the sole mutator of `outstanding`/`paused`, so this needs no locking.
fn stage_output(
    sessions: &mut HashMap<String, ExecSession>,
    prio_tx: &mpsc::UnboundedSender<PriorityMsg>,
    id: &str,
    is_stdout: bool,
    bytes: Vec<u8>,
) {
    let Some(s) = sessions.get_mut(id) else {
        tracing::debug!("output for unknown exec id: {id}");
        return;
    };
    // The consumer has dropped: drop the chunk immediately — do NOT queue it into
    // the unbounded out_tx and do NOT touch accounting — so an abandoned exec
    // cannot grow host memory while a TERM-ignoring child keeps writing during
    // the kill grace. Terminal delivery is separate (terminate_session), so the
    // forwarder still exits cleanly.
    if s.abandoned {
        return;
    }
    let raw_n = bytes.len();
    let item = if is_stdout {
        SessionItem::Stdout(bytes)
    } else {
        SessionItem::Stderr(bytes)
    };
    if s.out_tx.send(item).is_err() {
        return; // forwarder gone
    }
    s.outstanding += raw_n;
    if s.outstanding > OUTPUT_HIGH && !s.paused {
        s.paused = true;
        let _ = prio_tx.send(PriorityMsg::Pause { id: id.to_string() });
    }
}

/// Deliver a terminal to a session: push it FIFO-after-output, fire `done`
/// (closing the stdin + control relays), and remove the session.
fn terminate_session(sessions: &mut HashMap<String, ExecSession>, id: &str, t: Terminal) {
    if let Some(s) = sessions.remove(id) {
        let _ = s.out_tx.send(SessionItem::Terminal(t));
        s.done.cancel();
    } else {
        tracing::debug!("terminal for unknown exec id: {id}");
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

    // -----------------------------------------------------------------------
    // Flow-control: output credit, input credit window, latched cancellation
    // -----------------------------------------------------------------------

    /// Decode the raw stdin payload from a bulk `Send` frame, if it is one.
    fn stdin_frame_raw(cmd: &ConsoleCmd) -> Option<Vec<u8>> {
        let ConsoleCmd::Send(json) = cmd else {
            return None;
        };
        let v: serde_json::Value = serde_json::from_str(json).ok()?;
        if v["type"] != "stdin" {
            return None;
        }
        base64_decode(v["data"].as_str()?)
    }

    async fn next_frame(rx: &mut mpsc::Receiver<ConsoleCmd>, ms: u64) -> Option<ConsoleCmd> {
        tokio::time::timeout(std::time::Duration::from_millis(ms), rx.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn stdin_relay_respects_credit_window_and_frame_cap() {
        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinMsg>(64);
        let (credit_tx, credit_rx) = mpsc::unbounded_channel::<u32>();
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ConsoleCmd>(1000);
        let cancel = CancellationToken::new();
        let done = CancellationToken::new();
        let stdin_closed = CancellationToken::new();
        let relay = tokio::spawn(stdin_relay(
            "e1".into(),
            stdin_rx,
            credit_rx,
            cmd_tx,
            cancel.clone(),
            done.clone(),
            stdin_closed.clone(),
        ));

        // Feed 6 * 64 KiB = 384 KiB, more than one INPUT_WINDOW (256 KiB).
        let chunk = vec![b'a'; STDIN_FRAME_RAW_MAX];
        for _ in 0..6 {
            stdin_tx.send(StdinMsg::Data(chunk.clone())).await.unwrap();
        }

        // The relay starts with a full window of credit and parks once it is
        // exhausted: exactly INPUT_WINDOW raw bytes are emitted, no more.
        let mut first_phase = 0usize;
        while let Some(cmd) = next_frame(&mut cmd_rx, 200).await {
            let raw = stdin_frame_raw(&cmd).expect("a stdin frame");
            assert!(
                raw.len() <= STDIN_FRAME_RAW_MAX,
                "frame exceeds the per-frame cap"
            );
            first_phase += raw.len();
        }
        assert_eq!(
            first_phase, INPUT_WINDOW,
            "relay sent exactly one window before parking for credit"
        );

        // Grant enough credit for the remainder; the relay resumes and drains.
        credit_tx.send(INPUT_WINDOW as u32).unwrap();
        let mut second_phase = 0usize;
        while let Some(cmd) = next_frame(&mut cmd_rx, 200).await {
            second_phase += stdin_frame_raw(&cmd).expect("a stdin frame").len();
        }
        assert_eq!(
            first_phase + second_phase,
            6 * STDIN_FRAME_RAW_MAX,
            "all stdin bytes are eventually delivered, lossless"
        );

        // `done` force-closes the relay so a retained handle's send fails.
        done.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay exits on done")
            .unwrap();
        assert!(
            stdin_tx.send(StdinMsg::Data(vec![1])).await.is_err(),
            "stdin send fails after the relay closed"
        );
    }

    #[tokio::test]
    async fn stdin_relay_terminates_on_stdin_closed_while_credit_starved() {
        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinMsg>(64);
        let (_credit_tx, credit_rx) = mpsc::unbounded_channel::<u32>();
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ConsoleCmd>(1000);
        let cancel = CancellationToken::new();
        let done = CancellationToken::new();
        let stdin_closed = CancellationToken::new();
        let relay = tokio::spawn(stdin_relay(
            "e1".into(),
            stdin_rx,
            credit_rx,
            cmd_tx,
            cancel.clone(),
            done.clone(),
            stdin_closed.clone(),
        ));

        // Feed more than one window so the relay drains a full window and then
        // parks awaiting credit that — mirroring a child that closed its stdin —
        // will never come.
        let chunk = vec![b'a'; STDIN_FRAME_RAW_MAX];
        for _ in 0..6 {
            stdin_tx.send(StdinMsg::Data(chunk.clone())).await.unwrap();
        }
        let mut drained = 0usize;
        while let Some(cmd) = next_frame(&mut cmd_rx, 200).await {
            drained += stdin_frame_raw(&cmd).expect("a stdin frame").len();
        }
        assert_eq!(
            drained, INPUT_WINDOW,
            "parked once the window was exhausted"
        );

        // The guest reported the child closed its stdin: the relay must terminate
        // promptly instead of hanging on credit, so writes fail loudly.
        stdin_closed.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("relay exits promptly on stdin_closed")
            .unwrap();
        assert!(
            stdin_tx.send(StdinMsg::Data(vec![b'z'])).await.is_err(),
            "stdin send fails after the relay terminated"
        );
    }

    #[tokio::test]
    async fn backchannel_cancel_is_latched_and_bounded() {
        let (prio_tx, mut prio_rx) = mpsc::unbounded_channel::<PriorityMsg>();
        let (ctl_tx, _ctl_rx) = mpsc::unbounded_channel::<CtlMsg>();
        let bc = LibkrunBackchannel {
            id: "e1".into(),
            ctl_tx,
            prio_tx,
            cancel_phase: Arc::new(AtomicU8::new(0)),
        };

        // Many concurrent-style cancels (DELETE + timeout + disconnect + retained
        // handle) must coalesce to at most one resume + one TERM + one KILL.
        bc.cancel(libc::SIGTERM);
        bc.cancel(libc::SIGTERM);
        bc.cancel(libc::SIGTERM);
        bc.cancel(libc::SIGKILL);
        bc.cancel(libc::SIGKILL);

        let mut msgs = Vec::new();
        while let Ok(m) = prio_rx.try_recv() {
            msgs.push(m);
        }
        assert_eq!(msgs.len(), 3, "exactly resume + TERM + KILL");
        assert!(matches!(msgs[0], PriorityMsg::Resume { .. }));
        assert!(matches!(msgs[1], PriorityMsg::Signal { sig, .. } if sig == libc::SIGTERM));
        assert!(matches!(msgs[2], PriorityMsg::Signal { sig, .. } if sig == libc::SIGKILL));
    }

    // ---- Reader integration over a socketpair --------------------------------

    struct ReaderHarness {
        io: JoinHandle<()>,
        ctl_tx: mpsc::UnboundedSender<CtlMsg>,
        // Held to keep the bulk + signal channels open, mirroring the
        // ConsoleHandle/relays that hold them in production.
        _cmd_tx: mpsc::Sender<ConsoleCmd>,
        _signal_tx: mpsc::Sender<String>,
        guest_w: tokio::net::unix::OwnedWriteHalf,
        guest_r: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    }

    impl ReaderHarness {
        fn new() -> Self {
            let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
            let (cmd_tx, cmd_rx) = mpsc::channel::<ConsoleCmd>(256);
            let (prio_tx, prio_rx) = mpsc::unbounded_channel::<PriorityMsg>();
            let (signal_tx, signal_rx) = mpsc::channel::<String>(SIGNAL_CHANNEL);
            let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<CtlMsg>();
            let io = tokio::spawn(run_console_io(
                host,
                cmd_rx,
                prio_rx,
                prio_tx.clone(),
                signal_rx,
                ctl_tx.clone(),
                ctl_rx,
            ));
            guest.set_nonblocking(true).unwrap();
            let guest = tokio::net::UnixStream::from_std(guest).unwrap();
            let (gr, guest_w) = guest.into_split();
            Self {
                io,
                ctl_tx,
                _cmd_tx: cmd_tx,
                _signal_tx: signal_tx,
                guest_w,
                guest_r: tokio::io::BufReader::new(gr),
            }
        }

        async fn register(&self, id: &str) -> (mpsc::Receiver<ExecEvent>, CancellationToken) {
            let (events_tx, events_rx) = mpsc::channel::<ExecEvent>(256);
            let (credit_tx, _credit_rx) = mpsc::unbounded_channel::<u32>();
            let done = CancellationToken::new();
            let (ack_tx, ack_rx) = oneshot::channel();
            self.ctl_tx
                .send(CtlMsg::RegisterExec {
                    id: id.into(),
                    events_tx,
                    stdin_credit_tx: credit_tx,
                    done: done.clone(),
                    stdin_closed: CancellationToken::new(),
                    ack: ack_tx,
                })
                .unwrap();
            ack_rx.await.unwrap();
            (events_rx, done)
        }

        async fn guest_send(&mut self, json: &str) {
            use tokio::io::AsyncWriteExt;
            self.guest_w
                .write_all(format!("{json}\n").as_bytes())
                .await
                .unwrap();
        }

        /// Read host->guest frames until one of `want` type appears (or timeout).
        async fn await_host_frame(&mut self, want: &str, ms: u64) -> bool {
            use tokio::io::AsyncBufReadExt;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms);
            loop {
                let mut line = String::new();
                let read =
                    tokio::time::timeout_at(deadline, self.guest_r.read_line(&mut line)).await;
                match read {
                    Ok(Ok(n)) if n > 0 => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim())
                            && v["type"] == want
                        {
                            return true;
                        }
                    }
                    _ => return false,
                }
            }
        }
    }

    #[tokio::test]
    async fn output_credit_pauses_above_high_and_resumes_below_low() {
        let mut h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;

        // Five 64 KiB stdout frames = 320 KiB > OUTPUT_HIGH (256 KiB).
        let chunk = vec![b'x'; 64 * 1024];
        let frames = 5;
        for _ in 0..frames {
            let json = format!(
                "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
                base64_encode(&chunk)
            );
            h.guest_send(&json).await;
        }

        // Crossing HIGH (with no credit released) pauses the child's output.
        assert!(
            h.await_host_frame("pause", 1000).await,
            "expected a pause frame once outstanding crossed HIGH"
        );

        // Drain all output losslessly, then release the credit it represented.
        let mut got = 0usize;
        while got < frames * chunk.len() {
            match tokio::time::timeout(std::time::Duration::from_secs(1), events_rx.recv()).await {
                Ok(Some(ExecEvent::Stdout(b))) => {
                    assert!(b.iter().all(|&c| c == b'x'));
                    got += b.len();
                }
                other => panic!("expected stdout, got {other:?}"),
            }
        }
        assert_eq!(got, frames * chunk.len());

        // Releasing the outstanding credit drops below LOW and resumes.
        h.ctl_tx
            .send(CtlMsg::ReleaseCredit {
                id: "e1".into(),
                raw_n: got,
            })
            .unwrap();
        assert!(
            h.await_host_frame("resume", 1000).await,
            "expected a resume frame once outstanding fell below LOW"
        );

        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn exit_is_delivered_strictly_after_output() {
        let mut h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;

        h.guest_send(&format!(
            "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
            base64_encode(b"hello")
        ))
        .await;
        h.guest_send("{\"type\":\"exit\",\"id\":\"e1\",\"code\":7}")
            .await;

        let first = events_rx.recv().await.unwrap();
        assert_eq!(first, ExecEvent::Stdout(b"hello".to_vec()));
        let second = events_rx.recv().await.unwrap();
        assert_eq!(second, ExecEvent::Exit { code: 7 });

        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn start_error_surfaces_as_terminal_after_output() {
        let mut h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;

        h.guest_send(&format!(
            "{{\"type\":\"stderr\",\"id\":\"e1\",\"data\":\"{}\"}}",
            base64_encode(b"warn")
        ))
        .await;
        h.guest_send("{\"type\":\"start_error\",\"id\":\"e1\",\"message\":\"no shell available\"}")
            .await;

        assert_eq!(
            events_rx.recv().await.unwrap(),
            ExecEvent::Stderr(b"warn".to_vec())
        );
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ExecEvent::StartError("no shell available".into())
        );

        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn teardown_delivers_synthetic_terminal() {
        let h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;
        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        // A live session with no real exit gets a synthetic Exit{-1}.
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ExecEvent::Exit { code: -1 }
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn dropped_consumer_unpauses_and_never_repauses() {
        let mut h = ReaderHarness::new();
        // Register with a consumer we will drop, and a tiny events buffer so the
        // forwarder's send fails promptly once the receiver is gone.
        let (events_tx, events_rx) = mpsc::channel::<ExecEvent>(1);
        let (credit_tx, _credit_rx) = mpsc::unbounded_channel::<u32>();
        let done = CancellationToken::new();
        let (ack_tx, ack_rx) = oneshot::channel();
        h.ctl_tx
            .send(CtlMsg::RegisterExec {
                id: "e1".into(),
                events_tx,
                stdin_credit_tx: credit_tx,
                done,
                stdin_closed: CancellationToken::new(),
                ack: ack_tx,
            })
            .unwrap();
        ack_rx.await.unwrap();

        // Push past HIGH so the id pauses, then drop the consumer.
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..5 {
            h.guest_send(&format!(
                "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
                base64_encode(&chunk)
            ))
            .await;
        }
        assert!(h.await_host_frame("pause", 1000).await, "paused above HIGH");
        drop(events_rx);

        // The forwarder signals Abandoned → the reader resumes once.
        assert!(
            h.await_host_frame("resume", 1000).await,
            "abandoned consumer resumes the id"
        );

        // More stdout must NOT re-pause the abandoned id.
        for _ in 0..5 {
            h.guest_send(&format!(
                "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
                base64_encode(&chunk)
            ))
            .await;
        }
        assert!(
            !h.await_host_frame("pause", 400).await,
            "an abandoned id is never re-paused"
        );

        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn dropped_consumer_while_paused_and_parked_resumes() {
        let mut h = ReaderHarness::new();
        // A roomy events buffer so the forwarder can deliver every frame and
        // then PARK on out_rx with nothing in flight (no pending send to fail).
        let (mut events_rx, _done) = h.register("e1").await;

        // Push past HIGH so the id pauses.
        let chunk = vec![b'x'; 64 * 1024];
        let frames = 5;
        for _ in 0..frames {
            h.guest_send(&format!(
                "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
                base64_encode(&chunk)
            ))
            .await;
        }
        assert!(h.await_host_frame("pause", 1000).await, "paused above HIGH");

        // Drain ALL output but do NOT release credit: the id stays paused and
        // the forwarder ends up parked on out_rx with no in-flight send.
        let mut got = 0usize;
        while got < frames * chunk.len() {
            match tokio::time::timeout(std::time::Duration::from_secs(1), events_rx.recv()).await {
                Ok(Some(ExecEvent::Stdout(b))) => got += b.len(),
                other => panic!("expected stdout, got {other:?}"),
            }
        }

        // Drop the consumer while the forwarder is parked (not mid-send). It must
        // still observe the drop and signal Abandoned so the reader resumes;
        // otherwise the paused child would block in write() until teardown.
        drop(events_rx);
        assert!(
            h.await_host_frame("resume", 1000).await,
            "a consumer dropped while paused+parked still resumes the id"
        );

        h.ctl_tx.send(CtlMsg::Teardown).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h.io).await;
    }

    #[tokio::test]
    async fn stage_output_drops_chunks_for_abandoned_session() {
        // White-box: an abandoned session must drop output immediately — nothing
        // queued into the unbounded out_tx and no accounting/pause change — so an
        // abandoned exec cannot grow host memory.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SessionItem>();
        let (credit_tx, _credit_rx) = mpsc::unbounded_channel::<u32>();
        let (prio_tx, mut prio_rx) = mpsc::unbounded_channel::<PriorityMsg>();
        let mut sessions = std::collections::HashMap::new();
        sessions.insert(
            "e1".to_string(),
            ExecSession {
                out_tx,
                stdin_credit_tx: credit_tx,
                outstanding: 0,
                paused: false,
                abandoned: true,
                done: CancellationToken::new(),
                stdin_closed: CancellationToken::new(),
            },
        );

        let big = vec![b'x'; 1024 * 1024];
        stage_output(&mut sessions, &prio_tx, "e1", true, big.clone());
        stage_output(&mut sessions, &prio_tx, "e1", false, big);

        assert!(
            out_rx.try_recv().is_err(),
            "no items must be queued for an abandoned exec"
        );
        assert!(prio_rx.try_recv().is_err(), "no pause must be emitted");
        let s = sessions.get("e1").unwrap();
        assert_eq!(s.outstanding, 0, "accounting must not change");
        assert!(!s.paused);
    }

    #[tokio::test]
    async fn duplex_signal_takes_signal_path_and_preempts_bulk_stdin() {
        use tokio::io::AsyncBufReadExt;

        // Phase 1 — routing: control_relay sends an interactive SIGNAL (pre-framed
        // JSON) on the bounded signal channel, while RESIZE stays on the bulk
        // command queue.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ConsoleCmd>(16);
        let (signal_tx, mut signal_rx) = mpsc::channel::<String>(SIGNAL_CHANNEL);
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ExecControl>(4);
        let cancel = CancellationToken::new();
        let done = CancellationToken::new();
        let relay = tokio::spawn(control_relay(
            "e1".into(),
            ctrl_rx,
            cmd_tx.clone(),
            signal_tx.clone(),
            cancel.clone(),
            done.clone(),
        ));

        ctrl_tx
            .send(ExecControl::Signal(libc::SIGINT))
            .await
            .unwrap();
        let sig_json = signal_rx.recv().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&sig_json).unwrap();
        assert_eq!(v["type"], "signal");
        assert_eq!(v["signal"], libc::SIGINT);

        ctrl_tx
            .send(ExecControl::Resize { cols: 80, rows: 24 })
            .await
            .unwrap();
        match cmd_rx.recv().await.unwrap() {
            ConsoleCmd::Send(j) => assert!(j.contains("\"type\":\"resize\""), "{j}"),
            _ => panic!("resize must stay on the bulk path"),
        }
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), relay).await;

        // Phase 2 — preemption: with the bulk stdin queue saturated and a framed
        // signal queued on the bounded signal channel, the biased writer emits the
        // signal BEFORE any bulk stdin.
        let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
        guest.set_nonblocking(true).unwrap();
        host.set_nonblocking(true).unwrap();
        let guest = tokio::net::UnixStream::from_std(guest).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (gr, _gw) = guest.into_split();
        let mut reader = tokio::io::BufReader::new(gr);
        let (_hr, wh) = host.into_split();

        let (cmd_tx2, cmd_rx2) = mpsc::channel::<ConsoleCmd>(16);
        let (_prio_tx2, prio_rx2) = mpsc::unbounded_channel::<PriorityMsg>();
        let (signal_tx2, signal_rx2) = mpsc::channel::<String>(SIGNAL_CHANNEL);
        for _ in 0..8 {
            let json = serde_json::to_string(&HostMsg::Stdin {
                id: "e1".into(),
                data: base64_encode(b"x"),
            })
            .unwrap();
            cmd_tx2.send(ConsoleCmd::Send(json)).await.unwrap();
        }
        // Queued before the writer starts, so the biased select must drain it first.
        let sig_frame = serde_json::to_string(&HostMsg::Signal {
            id: "e1".into(),
            signal: libc::SIGINT,
        })
        .unwrap();
        signal_tx2.send(sig_frame).await.unwrap();
        let writer = tokio::spawn(run_writer(wh, cmd_rx2, prio_rx2, signal_rx2));

        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reader.read_line(&mut line),
        )
        .await
        .expect("a frame before timeout")
        .expect("read ok");
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(
            v["type"], "signal",
            "the interactive signal must preempt the queued bulk stdin"
        );
        writer.abort();
    }

    #[tokio::test]
    async fn signal_flood_backpressures_and_does_not_grow_unbounded() {
        // The signal channel is bounded and the writer is absent (never drained),
        // so control_relay blocks on a full signal channel, stops draining ctrl_rx,
        // and a client signal flood cannot be accepted without bound.
        let (cmd_tx, _cmd_rx) = mpsc::channel::<ConsoleCmd>(4);
        let (signal_tx, _signal_rx) = mpsc::channel::<String>(2);
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ExecControl>(2);
        let cancel = CancellationToken::new();
        let done = CancellationToken::new();
        let _relay = tokio::spawn(control_relay(
            "e1".into(),
            ctrl_rx,
            cmd_tx,
            signal_tx,
            cancel,
            done,
        ));

        let mut accepted = 0usize;
        for _ in 0..1000 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                ctrl_tx.send(ExecControl::Signal(libc::SIGINT)),
            )
            .await
            {
                Ok(Ok(())) => accepted += 1,
                _ => break, // send blocked → backpressure reached (bounded)
            }
        }
        assert!(
            accepted < 1000,
            "a signal flood must backpressure, not be accepted unboundedly (got {accepted})"
        );
    }
}
