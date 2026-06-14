//! The relay: demultiplex frames between one async transport and N per-id exec
//! sessions, with byte-exact credit flow control, priority/bulk write
//! scheduling, and teardown. tokio; NO libc (cancellation is classified with the
//! crate-owned [`crate::SIGKILL`] consts). Mac-portable — only tokio + the
//! injected transport halves, no `/proc`, no Linux-only flags.
//!
//! [`spawn_mux`] starts the engine over an already-split async transport and
//! returns an [`ExecMuxHost`]; [`ExecMuxHost::open`] starts one exec (owning the
//! full register→write-ack→relay-register ordering) and [`ExecMuxHost::shutdown`]
//! tears the engine down (owning the cancel→drain→teardown ordering). The
//! orderings are invariants of the engine, NOT the caller — see those methods.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::SIGKILL;
use crate::handle::{
    ExecBackchannel, ExecControl, ExecEvent, ExecHandle, ExecId, ExecIo, StdinMsg,
};
use crate::protocol::codec::{base64_decode, base64_encode};
use crate::protocol::limits::{INPUT_WINDOW, OUTPUT_HIGH, OUTPUT_LOW, STDIN_FRAME_RAW_MAX};
use crate::protocol::{self, GuestFrame, HostFrame};

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
    /// `open` awaits the result so it can return an error if the Exec message
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

/// The exec back-channel for a mux-backed handle: routes output-credit releases
/// to the reader and latched cancellation to the priority writer. Signal numbers
/// are crate-owned consts so the relay stays off libc.
struct MuxBackchannel {
    id: String,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    /// 0 none / 1 TERM / 2 KILL — coalesces repeated cancellation.
    cancel_phase: Arc<AtomicU8>,
}

impl ExecBackchannel for MuxBackchannel {
    fn release_credit(&self, raw_n: usize) {
        let _ = self.ctl_tx.send(CtlMsg::ReleaseCredit {
            id: self.id.clone(),
            raw_n,
        });
    }

    fn cancel(&self, sig: i32) {
        let target: u8 = if sig == SIGKILL { 2 } else { 1 };
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
/// `JoinHandle`s plus a `closing` gate. `open` registers relays and shutdown
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

/// Why an [`ExecMuxHost::open`] could not start an exec. The libkrun adapter maps
/// these to its backend error variants (the wire/status semantics are unchanged).
#[derive(Debug)]
pub enum MuxError {
    /// The VM is shutting down (cancelled or the registry is closing).
    Closing,
    /// The reader task is gone, so the session could not be registered.
    ReaderGone,
    /// The writer command channel is gone, so the exec frame could not be queued.
    WriteChannelClosed,
    /// The exec frame was queued but its write to the guest did not confirm.
    WriteFailed,
}

/// A handle to one running VM's exec engine: the bulk/priority/signal write
/// channels, the reader control channel, the VM-gone cancellation gate, and the
/// relay registry. Cloneable so the backend can both store it per running VM and
/// publish a clone for `exec` to reach. (Was `ConsoleHandle` + the channel wiring
/// in the libkrun backend.)
#[derive(Clone)]
pub struct ExecMuxHost {
    cmd_tx: mpsc::Sender<ConsoleCmd>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    /// Bounded per-console interactive-signal path (framed JSON), drained by the
    /// writer ahead of bulk stdin. Bounded so a client signal flood backpressures.
    signal_tx: mpsc::Sender<String>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    cancel: CancellationToken,
    exec_tasks: ExecTasks,
}

/// Spawn the console I/O engine over an already-split async transport (today a
/// virtio-console `UnixStream`; a network socket later). Returns the cloneable
/// [`ExecMuxHost`] plus the engine task's `JoinHandle` — the backend stores the
/// handle per running VM and keeps the task so it can interleave the engine
/// teardown with the VM kill (pid-kill-then-io-join).
pub fn spawn_mux<R, W>(read: R, write: W) -> (ExecMuxHost, JoinHandle<()>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, cmd_rx) = mpsc::channel::<ConsoleCmd>(256);
    let (prio_tx, prio_rx) = mpsc::unbounded_channel::<PriorityMsg>();
    let (signal_tx, signal_rx) = mpsc::channel::<String>(SIGNAL_CHANNEL);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<CtlMsg>();
    let io_task = tokio::spawn(run_mux(
        read,
        write,
        cmd_rx,
        prio_rx,
        prio_tx.clone(),
        signal_rx,
        ctl_tx.clone(),
        ctl_rx,
    ));
    let mux = ExecMuxHost {
        cmd_tx,
        prio_tx,
        signal_tx,
        ctl_tx,
        cancel: CancellationToken::new(),
        exec_tasks: Arc::new(std::sync::Mutex::new(ExecRegistry {
            closing: false,
            tasks: Vec::new(),
        })),
    };
    (mux, io_task)
}

impl ExecMuxHost {
    /// Open one exec. OWNS the full open ordering as one invariant: (1) refuse if
    /// the VM gate is already cancelled; (2) register the reader session + spawn
    /// its forwarder and AWAIT the register-before-exec ack; (3) write the Exec
    /// frame and await its confirmation; (4) register the stdin/control relays
    /// atomically against the `closing` gate. If the VM starts closing at any
    /// barrier, the session is unregistered and `open` refuses — it never returns
    /// a handle whose relays were never registered. `exec_id` is minted by the
    /// caller; `exec_json` is the pre-built, already-size-checked Exec frame
    /// (input validation stays in the adapter).
    pub async fn open(&self, exec_id: ExecId, exec_json: String) -> Result<ExecHandle, MuxError> {
        // Cheap early-out for a VM already torn down before we start; the
        // authoritative refusal is the closing gate at relay registration.
        if self.cancel.is_cancelled() {
            return Err(MuxError::Closing);
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
        self.ctl_tx
            .send(CtlMsg::RegisterExec {
                id: exec_id.0.clone(),
                events_tx,
                stdin_credit_tx: credit_tx,
                done: done.clone(),
                stdin_closed: stdin_closed.clone(),
                ack: ack_tx,
            })
            .map_err(|_| MuxError::ReaderGone)?;
        ack_rx.await.map_err(|_| MuxError::ReaderGone)?;

        let (wack_tx, wack_rx) = oneshot::channel::<bool>();
        self.cmd_tx
            .send(ConsoleCmd::SendAck(exec_json, wack_tx))
            .await
            .map_err(|_| MuxError::WriteChannelClosed)?;
        let write_ok = match tokio::time::timeout(std::time::Duration::from_secs(30), wack_rx).await
        {
            Ok(result) => result.unwrap_or(false),
            Err(_) => false,
        };
        if !write_ok {
            let _ = self.ctl_tx.send(CtlMsg::UnregisterExec(exec_id.0.clone()));
            return Err(MuxError::WriteFailed);
        }

        let stdin_exec_id = exec_id.0.clone();
        let stdin_cmd_tx = self.cmd_tx.clone();
        let stdin_cancel = self.cancel.clone();
        let stdin_done = done.clone();
        let stdin_closed_relay = stdin_closed.clone();
        let ctrl_exec_id = exec_id.0.clone();
        let ctrl_cmd_tx = self.cmd_tx.clone();
        let ctrl_signal_tx = self.signal_tx.clone();
        let ctrl_cancel = self.cancel.clone();
        let ctrl_done = done.clone();

        // Spawn + register the stdin/control relays atomically against shutdown's
        // drain: if the VM is already closing or cancelled they are never spawned
        // and the open is refused, so no relay can keep a stdin/control channel
        // open past teardown. Both relays terminate when the VM is cancelled
        // (stop/destroy/crash), when the per-exec `done` fires
        // (terminal/start-error/teardown), when the caller drops their sender, or
        // when the console closes.
        let registered = register_exec_relays(&self.exec_tasks, &self.cancel, move || {
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
            let _ = self.ctl_tx.send(CtlMsg::UnregisterExec(exec_id.0.clone()));
            return Err(MuxError::Closing);
        }

        let backchannel = Arc::new(MuxBackchannel {
            id: exec_id.0.clone(),
            ctl_tx: self.ctl_tx.clone(),
            prio_tx: self.prio_tx.clone(),
            cancel_phase,
        });
        let io = ExecIo::new(stdin_tx, ctrl_tx, backchannel);
        Ok(ExecHandle::from_parts(exec_id, events_rx, io))
    }

    /// Graceful teardown. OWNS the full shutdown ordering as one invariant: (1)
    /// cancel the VM gate; (2) under the registry lock set `closing` and take the
    /// relay handles, so no racing `open` can register a relay after the drain;
    /// (3) abort AND await each stdin/control relay so its receiver is dropped
    /// before this returns (a retained handle's next stdin/signal/resize send then
    /// fails immediately — no polling/race); (4) send `Teardown` so the reader
    /// delivers a synthetic terminal to every live session before socket I/O is
    /// aborted. The forwarder (on `out_rx` only) is never aborted, so queued
    /// output + the terminal always drain.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let tasks: Vec<JoinHandle<()>> = {
            let mut reg = self.exec_tasks.lock().unwrap();
            reg.closing = true;
            std::mem::take(&mut reg.tasks)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        let _ = self.ctl_tx.send(CtlMsg::Teardown);
    }

    /// Synchronous teardown backstop for the crash path (a `Drop` that cannot
    /// await): cancel the gate, set `closing`, and abort the relays best-effort.
    /// The synthetic terminal + socket teardown follow from the engine task
    /// ending; the kill is owned by the caller's process guard.
    pub fn drop_relays_sync(&self) {
        self.cancel.cancel();
        if let Ok(mut reg) = self.exec_tasks.lock() {
            reg.closing = true;
            for task in reg.tasks.drain(..) {
                task.abort();
            }
        }
    }
}

/// Run the console I/O engine over the split transport halves: a writer task
/// (priority → signal → bulk scheduling) plus the reader (session map, credit
/// accounting, teardown), which owns the read half and is the SOLE mutator of
/// per-id accounting. Generic over the transport so a second transport needs no
/// change here.
#[allow(clippy::too_many_arguments)]
async fn run_mux<R, W>(
    read: R,
    write: W,
    cmd_rx: mpsc::Receiver<ConsoleCmd>,
    prio_rx: mpsc::UnboundedReceiver<PriorityMsg>,
    prio_tx: mpsc::UnboundedSender<PriorityMsg>,
    signal_rx: mpsc::Receiver<String>,
    ctl_tx: mpsc::UnboundedSender<CtlMsg>,
    ctl_rx: mpsc::UnboundedReceiver<CtlMsg>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Writer task: priority frames first, then interactive signals, then the bulk
    // queue. Only this task ever awaits the socket write half, so the reader never
    // blocks on a write.
    let write_task = tokio::spawn(run_writer(write, cmd_rx, prio_rx, signal_rx));
    // Reader: owns the read half, the session map, and the (unbounded,
    // independent) control channel; it is the SOLE mutator of per-id accounting.
    run_reader(read, ctl_rx, ctl_tx, prio_tx).await;
    write_task.abort();
}

/// Drain the priority channel, then the bounded interactive-signal channel,
/// ahead of the bulk command queue at every frame boundary — so a flood of bulk
/// stdin can never starve a pause/resume/cancel or an interactive signal. The
/// signal channel is bounded (unlike the reader-priority channel, whose senders
/// are bounded-by-construction), so a client signal flood backpressures instead
/// of growing host memory.
async fn run_writer<W: AsyncWrite + Unpin>(
    write_half: W,
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
                    PriorityMsg::Pause { id } => HostFrame::Pause { id },
                    PriorityMsg::Resume { id } => HostFrame::Resume { id },
                    PriorityMsg::Signal { id, sig } => HostFrame::Signal { id, signal: sig },
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
async fn run_reader<R: AsyncRead + Unpin>(
    read_half: R,
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
                        // fully live (insert + forwarder) when open() proceeds.
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
            let frame = HostFrame::Stdin {
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
    if let Ok(json) = serde_json::to_string(&HostFrame::Stdin {
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
                let Ok(json) = serde_json::to_string(&HostFrame::Signal {
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
                let msg = HostFrame::Resize {
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

/// Read a newline-delimited line from the reader, capped at the inbound frame
/// limit. Returns Ok(Some(line)) on success, Ok(None) if a frame was discarded
/// for being oversized, or Err on EOF/I/O error.
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
        if protocol::inbound_frame_too_large(buf.len()) {
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
    if protocol::inbound_frame_too_large(buf.len()) {
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
    let msg: GuestFrame = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("invalid guest message: {e} — line: {line}");
            return;
        }
    };

    match msg {
        GuestFrame::Stdout { id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                tracing::warn!("base64 decode failure for stdout on exec {id}; dropping message");
                return;
            };
            stage_output(sessions, prio_tx, &id, true, bytes);
        }
        GuestFrame::Stderr { id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                tracing::warn!("base64 decode failure for stderr on exec {id}; dropping message");
                return;
            };
            stage_output(sessions, prio_tx, &id, false, bytes);
        }
        GuestFrame::Exit { id, code } => {
            terminate_session(sessions, &id, Terminal::Exit { code });
        }
        GuestFrame::StartError { id, message } => {
            terminate_session(sessions, &id, Terminal::StartError { message });
        }
        GuestFrame::StdinCredit { id, bytes } => {
            if let Some(s) = sessions.get(&id) {
                let grant = bytes.min(u32::MAX as usize) as u32;
                let _ = s.stdin_credit_tx.send(grant);
            }
        }
        GuestFrame::StdinClosed { id } => {
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
    use crate::{SIGINT, SIGKILL, SIGTERM};

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
        let bc = MuxBackchannel {
            id: "e1".into(),
            ctl_tx,
            prio_tx,
            cancel_phase: Arc::new(AtomicU8::new(0)),
        };

        // Many concurrent-style cancels (DELETE + timeout + disconnect + retained
        // handle) must coalesce to at most one resume + one TERM + one KILL.
        bc.cancel(SIGTERM);
        bc.cancel(SIGTERM);
        bc.cancel(SIGTERM);
        bc.cancel(SIGKILL);
        bc.cancel(SIGKILL);

        let mut msgs = Vec::new();
        while let Ok(m) = prio_rx.try_recv() {
            msgs.push(m);
        }
        assert_eq!(msgs.len(), 3, "exactly resume + TERM + KILL");
        assert!(matches!(msgs[0], PriorityMsg::Resume { .. }));
        assert!(matches!(msgs[1], PriorityMsg::Signal { sig, .. } if sig == SIGTERM));
        assert!(matches!(msgs[2], PriorityMsg::Signal { sig, .. } if sig == SIGKILL));
    }

    // ---- Exec relay registration gate ----------------------------------------

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

    // ---- Engine integration over a socketpair --------------------------------

    struct ReaderHarness {
        io: JoinHandle<()>,
        mux: ExecMuxHost,
        guest_w: tokio::net::unix::OwnedWriteHalf,
        guest_r: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    }

    impl ReaderHarness {
        fn new() -> Self {
            let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
            host.set_nonblocking(true).unwrap();
            let host = tokio::net::UnixStream::from_std(host).unwrap();
            let (hr, hw) = host.into_split();
            let (mux, io) = spawn_mux(hr, hw);
            guest.set_nonblocking(true).unwrap();
            let guest = tokio::net::UnixStream::from_std(guest).unwrap();
            let (gr, guest_w) = guest.into_split();
            Self {
                io,
                mux,
                guest_w,
                guest_r: tokio::io::BufReader::new(gr),
            }
        }

        /// Register a session directly (bypassing `open`), returning the event
        /// receiver + its `done` token.
        async fn register(&self, id: &str) -> (mpsc::Receiver<ExecEvent>, CancellationToken) {
            let (events_tx, events_rx) = mpsc::channel::<ExecEvent>(256);
            let (credit_tx, _credit_rx) = mpsc::unbounded_channel::<u32>();
            let done = CancellationToken::new();
            let (ack_tx, ack_rx) = oneshot::channel();
            self.mux
                .ctl_tx
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

        fn teardown_and_join(self) -> JoinHandle<()> {
            let _ = self.mux.ctl_tx.send(CtlMsg::Teardown);
            self.io
        }
    }

    /// A pre-built, size-valid exec frame for `id` (the adapter builds these).
    fn exec_json(id: &str) -> String {
        serde_json::to_string(&HostFrame::Exec {
            id: id.into(),
            cmd: vec!["true".into()],
            env: vec![],
            workdir: None,
            uid: None,
            gid: None,
            mode: Default::default(),
        })
        .unwrap()
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
        h.mux
            .ctl_tx
            .send(CtlMsg::ReleaseCredit {
                id: "e1".into(),
                raw_n: got,
            })
            .unwrap();
        assert!(
            h.await_host_frame("resume", 1000).await,
            "expected a resume frame once outstanding fell below LOW"
        );

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
    }

    #[tokio::test]
    async fn output_pause_fires_only_strictly_above_high() {
        // Boundary guard for `outstanding > OUTPUT_HIGH` (not >=): exactly
        // OUTPUT_HIGH outstanding must NOT pause; one more byte must.
        let mut h = ReaderHarness::new();
        let (_events_rx, _done) = h.register("e1").await;

        let at_high = vec![b'x'; OUTPUT_HIGH];
        h.guest_send(&format!(
            "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
            base64_encode(&at_high)
        ))
        .await;
        assert!(
            !h.await_host_frame("pause", 400).await,
            "exactly OUTPUT_HIGH outstanding must NOT pause"
        );

        h.guest_send(&format!(
            "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
            base64_encode(b"!")
        ))
        .await;
        assert!(
            h.await_host_frame("pause", 1000).await,
            "OUTPUT_HIGH + 1 must pause"
        );

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
    }

    #[tokio::test]
    async fn output_resume_fires_only_strictly_below_low() {
        // Boundary guard for `outstanding < OUTPUT_LOW` (not <=): releasing down
        // to exactly OUTPUT_LOW must NOT resume; one more byte must.
        let mut h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;

        // Cross HIGH to enter the paused state. One frame of OUTPUT_HIGH + 1.
        let chunk = vec![b'x'; OUTPUT_HIGH + 1];
        h.guest_send(&format!(
            "{{\"type\":\"stdout\",\"id\":\"e1\",\"data\":\"{}\"}}",
            base64_encode(&chunk)
        ))
        .await;
        assert!(h.await_host_frame("pause", 1000).await, "paused above HIGH");
        // Drain the single output frame so the forwarder is idle.
        match tokio::time::timeout(std::time::Duration::from_secs(1), events_rx.recv()).await {
            Ok(Some(ExecEvent::Stdout(b))) => assert_eq!(b.len(), OUTPUT_HIGH + 1),
            other => panic!("expected stdout, got {other:?}"),
        }

        // Release down to EXACTLY OUTPUT_LOW outstanding: not below, so no resume.
        h.mux
            .ctl_tx
            .send(CtlMsg::ReleaseCredit {
                id: "e1".into(),
                raw_n: (OUTPUT_HIGH + 1) - OUTPUT_LOW,
            })
            .unwrap();
        assert!(
            !h.await_host_frame("resume", 400).await,
            "exactly OUTPUT_LOW outstanding must NOT resume"
        );

        // One more byte of credit drops below LOW and resumes.
        h.mux
            .ctl_tx
            .send(CtlMsg::ReleaseCredit {
                id: "e1".into(),
                raw_n: 1,
            })
            .unwrap();
        assert!(
            h.await_host_frame("resume", 1000).await,
            "OUTPUT_LOW - 1 must resume"
        );

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
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

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
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

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
    }

    #[tokio::test]
    async fn teardown_delivers_synthetic_terminal() {
        let h = ReaderHarness::new();
        let (mut events_rx, _done) = h.register("e1").await;
        let io = h.teardown_and_join();
        // A live session with no real exit gets a synthetic Exit{-1}.
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ExecEvent::Exit { code: -1 }
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
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
        h.mux
            .ctl_tx
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

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
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

        let io = h.teardown_and_join();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
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

        ctrl_tx.send(ExecControl::Signal(SIGINT)).await.unwrap();
        let sig_json = signal_rx.recv().await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&sig_json).unwrap();
        assert_eq!(v["type"], "signal");
        assert_eq!(v["signal"], SIGINT);

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
            let json = serde_json::to_string(&HostFrame::Stdin {
                id: "e1".into(),
                data: base64_encode(b"x"),
            })
            .unwrap();
            cmd_tx2.send(ConsoleCmd::Send(json)).await.unwrap();
        }
        // Queued before the writer starts, so the biased select must drain it first.
        let sig_frame = serde_json::to_string(&HostFrame::Signal {
            id: "e1".into(),
            signal: SIGINT,
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
                ctrl_tx.send(ExecControl::Signal(SIGINT)),
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

    // ---- open() barrier / teardown ordering ----------------------------------

    #[tokio::test]
    async fn open_refused_before_register_when_cancelled() {
        // Barrier (a): the VM gate is already cancelled when open starts — it must
        // refuse immediately and register nothing (no reader session, no relays).
        let (host, _guest) = std::os::unix::net::UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (hr, hw) = host.into_split();
        let (mux, _io) = spawn_mux(hr, hw);

        mux.cancel.cancel();
        let r = mux.open(ExecId("e1".into()), exec_json("e1")).await;
        assert!(matches!(r, Err(MuxError::Closing)));
        assert!(
            mux.exec_tasks.lock().unwrap().tasks.is_empty(),
            "a refused open registers no relays"
        );
    }

    #[tokio::test]
    async fn open_refused_at_relay_barrier_when_closing_and_cleans_up() {
        // Barriers (b)/(c)/(d): the reader register + the exec-frame write both
        // succeed, but the registry is closing by the time relays would register.
        // open must refuse AND unregister the reader session, leaving no relays.
        let (host, _guest) = std::os::unix::net::UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (hr, hw) = host.into_split();
        let (mux, _io) = spawn_mux(hr, hw);
        // _guest stays open so the exec-frame write to the host side confirms.

        // Closing WITHOUT cancelling: the reader/writer stay alive so the first
        // two barriers pass; only the relay-registration gate refuses.
        mux.exec_tasks.lock().unwrap().closing = true;

        let r = mux.open(ExecId("e1".into()), exec_json("e1")).await;
        assert!(matches!(r, Err(MuxError::Closing)));
        assert!(
            mux.exec_tasks.lock().unwrap().tasks.is_empty(),
            "no relay tasks were spawned"
        );

        // The reader session was unregistered: a FRESH register + teardown still
        // delivers a single synthetic terminal, proving the reader is healthy and
        // not leaking the refused session.
        mux.exec_tasks.lock().unwrap().closing = false;
        let (events_tx, mut events_rx) = mpsc::channel::<ExecEvent>(4);
        let (credit_tx, _credit_rx) = mpsc::unbounded_channel::<u32>();
        let (ack_tx, ack_rx) = oneshot::channel();
        mux.ctl_tx
            .send(CtlMsg::RegisterExec {
                id: "e2".into(),
                events_tx,
                stdin_credit_tx: credit_tx,
                done: CancellationToken::new(),
                stdin_closed: CancellationToken::new(),
                ack: ack_tx,
            })
            .unwrap();
        ack_rx.await.unwrap();
        mux.shutdown().await;
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ExecEvent::Exit { code: -1 }
        );
    }

    #[tokio::test]
    async fn open_succeeds_then_shutdown_fails_retained_handle_sends() {
        // open builds a working handle; after shutdown drains the relays, a
        // retained handle's stdin send fails promptly (receivers dropped).
        let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let host = tokio::net::UnixStream::from_std(host).unwrap();
        let (hr, hw) = host.into_split();
        let (mux, io) = spawn_mux(hr, hw);
        // Keep the guest read end alive so the exec-frame write confirms.
        guest.set_nonblocking(true).unwrap();
        let _guest = tokio::net::UnixStream::from_std(guest).unwrap();

        let handle = mux
            .open(ExecId("e1".into()), exec_json("e1"))
            .await
            .expect("open succeeds on a live mux");
        assert_eq!(handle.exec_id.0, "e1");
        // Two relays registered.
        assert_eq!(mux.exec_tasks.lock().unwrap().tasks.len(), 2);

        mux.shutdown().await;
        // Relays drained → a retained handle's stdin write fails promptly.
        assert!(
            handle.write_stdin(b"x").await.is_err(),
            "stdin send fails after shutdown drained the relay"
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), io).await;
    }
}
