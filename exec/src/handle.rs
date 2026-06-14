//! The shared `ExecHandle` type family — the relay↔consumer seam.
//!
//! These types are needed by BOTH the `relay` capability (which builds a handle
//! in `ExecMuxHost::open`) and the `consumer` capability (which drives it), so
//! the module is compiled under `cfg(any(feature = "relay", feature =
//! "consumer"))`; tokio is enabled by either.
//!
//! The byte-bounded stdin gate (`write_stdin`/`close_stdin`) is the interesting
//! logic here and is unit-tested below. The relay internals (`ExecBackchannel`,
//! `NoopBackchannel`, `StdinMsg`, `ExecIo::new`, `ExecHandle::from_parts`) are
//! `pub(crate)` — the real handle is built inside this crate by the `relay`
//! module's `ExecMuxHost::open`, so no backchannel type appears in public API.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::protocol::ExecMode;
use crate::protocol::limits::STDIN_FRAME_RAW_MAX;

/// Opaque identifier for one exec session, minted host-side.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecId(pub String);

/// A request to run one command inside a sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub mode: ExecMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The command never started as intended (bad cwd, no shell, credential-drop
    /// failure, `execvp` failure). Distinct from a numeric process exit.
    StartError(String),
    Exit {
        code: i32,
    },
}

/// Control messages for a running exec session (signals, terminal resize).
pub enum ExecControl {
    Signal(i32),
    Resize { cols: u16, rows: u16 },
}

/// A stdin message to the per-id stdin relay. `Data` carries a raw chunk no
/// larger than [`STDIN_FRAME_RAW_MAX`] (the public `write_stdin` splits to this);
/// `Eof` requests the relay emit an end-of-input frame and stop. Relay-internal,
/// not public API.
// The `Data` payload is written by the consumer (`write_stdin`) but only READ by
// the relay's `stdin_relay`, so in a consumer-without-relay build it is
// legitimately unread — allow that one combo rather than a crate-wide allow.
#[cfg_attr(not(feature = "relay"), allow(dead_code))]
pub(crate) enum StdinMsg {
    Data(Vec<u8>),
    Eof,
}

/// The non-stream back-channel of an exec: output-credit release and latched
/// cancellation. The `relay` module supplies the concrete implementation; the
/// mock/test path uses [`NoopBackchannel`]. Relay-internal, not public API.
pub(crate) trait ExecBackchannel: Send + Sync {
    /// Request the host reader release `raw_n` bytes of output credit for this
    /// exec (called by the consumer after it has yielded the bytes downstream).
    fn release_credit(&self, raw_n: usize);
    /// Latched cancellation: deliver `sig` to the process group on the priority
    /// path, coalesced so repeated calls send at most one resume + one TERM +
    /// one KILL over the life of the exec.
    fn cancel(&self, sig: i32);
}

/// A back-channel that drops every request — used by the mock backend and unit
/// tests that hand-build an [`ExecHandle`].
pub(crate) struct NoopBackchannel;

impl ExecBackchannel for NoopBackchannel {
    fn release_credit(&self, _raw_n: usize) {}
    fn cancel(&self, _sig: i32) {}
}

/// A cloneable, send-safe cancellation handle for a running exec, decoupled
/// from the (non-clone) event stream so a controller (DELETE/timeout/disconnect)
/// can cancel while the consumer owns the [`ExecHandle`].
#[derive(Clone)]
pub struct ExecCanceller(Arc<dyn ExecBackchannel>);

impl ExecCanceller {
    /// Latched, priority cancellation with `sig` (see [`ExecHandle::cancel`]).
    pub fn cancel(&self, sig: i32) {
        self.0.cancel(sig);
    }
}

/// The non-stream I/O half of an exec: stdin, interactive control, output-credit
/// release, and cancellation. Cloneable and decoupled from the (non-clone) event
/// stream, so the duplex face can run a reader and a writer concurrently.
#[derive(Clone)]
pub struct ExecIo {
    /// Byte-bounded stdin relay channel; use [`ExecIo::write_stdin`].
    pub(crate) stdin: mpsc::Sender<StdinMsg>,
    /// Interactive control messages (signals, resize) for the duplex face.
    pub(crate) control: mpsc::Sender<ExecControl>,
    /// Output-credit release + latched cancellation.
    pub(crate) backchannel: Arc<dyn ExecBackchannel>,
    /// Shared EOF latch: set once [`ExecIo::close_stdin`] is requested. A
    /// best-effort fast path for an already-closed stdin; the authoritative
    /// check happens under [`ExecIo::stdin_gate`].
    pub(crate) stdin_closed: Arc<AtomicBool>,
    /// Serializes the (closed-check + channel enqueue) of stdin writes and the
    /// (set-closed + EOF enqueue) of `close_stdin`, so — across the cloneable
    /// senders — no `Data` can ever be enqueued behind the `Eof` (which the relay
    /// would silently drop). Held across the awaiting send; safe because stdin is
    /// logically sequential per exec and the relay drains independently.
    pub(crate) stdin_gate: Arc<tokio::sync::Mutex<()>>,
}

impl ExecIo {
    /// Build the I/O half from the relay's channel senders + back-channel,
    /// initialising the EOF latch and the stdin gate. Crate-internal: the `relay`
    /// module's `ExecMuxHost::open` builds the real handle through this.
    pub(crate) fn new(
        stdin: mpsc::Sender<StdinMsg>,
        control: mpsc::Sender<ExecControl>,
        backchannel: Arc<dyn ExecBackchannel>,
    ) -> Self {
        Self {
            stdin,
            control,
            backchannel,
            stdin_closed: Arc::new(AtomicBool::new(false)),
            stdin_gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// A no-op I/O half (dropped stdin/control receivers + a no-op back-channel),
    /// for the mock backend and tests that need a handle but no real process.
    pub(crate) fn noop() -> Self {
        let (stdin_tx, _stdin_rx) = mpsc::channel::<StdinMsg>(1);
        let (ctrl_tx, _ctrl_rx) = mpsc::channel::<ExecControl>(1);
        Self::new(stdin_tx, ctrl_tx, Arc::new(NoopBackchannel))
    }

    /// Send stdin bytes to the process, split into frames no larger than
    /// [`STDIN_FRAME_RAW_MAX`] so a single call never buffers an unbounded `Vec`
    /// in host memory; a large write back-pressures the caller on the bounded
    /// relay channel. `Err(())` means the relay is gone (terminal/teardown) or
    /// stdin has been closed.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), ()> {
        // Fast path: already closed, fail loud without taking the gate.
        if self.stdin_closed.load(Ordering::Acquire) {
            return Err(());
        }
        if data.is_empty() {
            return Ok(());
        }
        for chunk in data.chunks(STDIN_FRAME_RAW_MAX) {
            // The authoritative closed-check and the enqueue must be ONE critical
            // section under the gate, or a concurrent close could slip its Eof
            // between our check and our send — landing this Data behind the Eof.
            let _gate = self.stdin_gate.lock().await;
            if self.stdin_closed.load(Ordering::Acquire) {
                return Err(());
            }
            self.stdin
                .send(StdinMsg::Data(chunk.to_vec()))
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Signal end-of-input: under the gate, latch closed (so later writes fail
    /// rather than slip behind the EOF) then emit one empty stdin frame so the
    /// guest closes the child's stdin fd. Idempotent. `Err(())` if the relay is
    /// gone.
    pub async fn close_stdin(&self) -> Result<(), ()> {
        let _gate = self.stdin_gate.lock().await;
        if self.stdin_closed.swap(true, Ordering::AcqRel) {
            return Ok(()); // already closed
        }
        self.stdin.send(StdinMsg::Eof).await.map_err(|_| ())
    }

    /// Request release of `raw_n` bytes of output credit (see [`ExecBackchannel`]).
    pub fn release_credit(&self, raw_n: usize) {
        self.backchannel.release_credit(raw_n);
    }

    /// Latched, priority cancellation of the exec with `sig`.
    pub fn cancel(&self, sig: i32) {
        self.backchannel.cancel(sig);
    }

    /// A cloneable cancellation handle.
    pub fn canceller(&self) -> ExecCanceller {
        ExecCanceller(self.backchannel.clone())
    }

    /// Send a signal to the process's process group (interactive/duplex path).
    pub async fn signal(&self, sig: i32) -> Result<(), mpsc::error::SendError<ExecControl>> {
        self.control.send(ExecControl::Signal(sig)).await
    }

    /// Request a terminal resize for the process (interactive/duplex path).
    pub async fn resize(
        &self,
        cols: u16,
        rows: u16,
    ) -> Result<(), mpsc::error::SendError<ExecControl>> {
        self.control.send(ExecControl::Resize { cols, rows }).await
    }
}

pub struct ExecHandle {
    pub exec_id: ExecId,
    /// Receives stdout/stderr/start-error/exit events from the running process.
    pub events: mpsc::Receiver<ExecEvent>,
    pub(crate) io: ExecIo,
}

impl ExecHandle {
    /// Assemble a handle from its parts. Crate-internal: built only by the
    /// `relay` module's `ExecMuxHost::open` (a consumer-without-relay build never
    /// constructs a real handle, so this is relay-gated).
    #[cfg(feature = "relay")]
    pub(crate) fn from_parts(
        exec_id: ExecId,
        events: mpsc::Receiver<ExecEvent>,
        io: ExecIo,
    ) -> Self {
        Self {
            exec_id,
            events,
            io,
        }
    }

    /// A handle backed by no real process: the event stream is already closed and
    /// stdin/control go nowhere. For the mock backend and tests.
    pub fn for_mock(exec_id: ExecId) -> Self {
        let (_events_tx, events_rx) = mpsc::channel::<ExecEvent>(1);
        // _events_tx is dropped here, so the stream is closed immediately.
        Self {
            exec_id,
            events: events_rx,
            io: ExecIo::noop(),
        }
    }

    /// See [`ExecIo::write_stdin`].
    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), ()> {
        self.io.write_stdin(data).await
    }

    /// See [`ExecIo::close_stdin`].
    pub async fn close_stdin(&self) -> Result<(), ()> {
        self.io.close_stdin().await
    }

    /// See [`ExecIo::release_credit`].
    pub fn release_credit(&self, raw_n: usize) {
        self.io.release_credit(raw_n);
    }

    /// See [`ExecIo::cancel`].
    pub fn cancel(&self, sig: i32) {
        self.io.cancel(sig);
    }

    /// A cloneable cancellation handle, usable independently of the event stream.
    pub fn canceller(&self) -> ExecCanceller {
        self.io.canceller()
    }

    /// See [`ExecIo::signal`].
    pub async fn signal(&self, sig: i32) -> Result<(), mpsc::error::SendError<ExecControl>> {
        self.io.signal(sig).await
    }

    /// See [`ExecIo::resize`].
    pub async fn resize(
        &self,
        cols: u16,
        rows: u16,
    ) -> Result<(), mpsc::error::SendError<ExecControl>> {
        self.io.resize(cols, rows).await
    }

    /// Split into the event stream and the cloneable I/O half.
    pub fn split(self) -> (mpsc::Receiver<ExecEvent>, ExecIo) {
        (self.events, self.io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_io_with_cap(cap: usize) -> (ExecIo, mpsc::Receiver<StdinMsg>) {
        let (stdin_tx, stdin_rx) = mpsc::channel::<StdinMsg>(cap);
        let (ctrl_tx, _ctrl_rx) = mpsc::channel::<ExecControl>(8);
        let io = ExecIo::new(stdin_tx, ctrl_tx, Arc::new(NoopBackchannel));
        (io, stdin_rx)
    }

    fn test_io() -> (ExecIo, mpsc::Receiver<StdinMsg>) {
        test_io_with_cap(8)
    }

    #[tokio::test]
    async fn write_after_close_fails_and_prior_data_is_preserved() {
        let (io, mut stdin_rx) = test_io();

        // Data written before EOF is delivered, in order, then the EOF frame.
        io.write_stdin(b"hello").await.unwrap();
        io.close_stdin().await.unwrap();
        assert!(matches!(stdin_rx.recv().await, Some(StdinMsg::Data(d)) if d == b"hello"));
        assert!(matches!(stdin_rx.recv().await, Some(StdinMsg::Eof)));

        // After close, a further write fails loudly — never silently dropped
        // behind the EOF (even across cloned handles).
        let clone = io.clone();
        assert!(io.write_stdin(b"late").await.is_err());
        assert!(clone.write_stdin(b"late").await.is_err());

        // close_stdin is idempotent.
        assert!(io.close_stdin().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_and_close_race_never_enqueues_data_after_eof() {
        // Race write_stdin against close_stdin many times across threads: the gate
        // must make (closed-check + enqueue) atomic so the relay never sees Data
        // queued after the Eof, and a write that loses the race returns Err.
        for _ in 0..500 {
            let (io, mut stdin_rx) = test_io_with_cap(64);
            let writer = io.clone();
            let closer = io.clone();
            let w = tokio::spawn(async move { writer.write_stdin(b"data").await });
            let c = tokio::spawn(async move { closer.close_stdin().await });
            let wrote_ok = w.await.unwrap().is_ok();
            c.await.unwrap().unwrap();

            // Both tasks are done, so every send has happened; drain and inspect.
            let mut seen_eof = false;
            let mut data_count = 0usize;
            while let Ok(msg) = stdin_rx.try_recv() {
                match msg {
                    StdinMsg::Data(_) => {
                        assert!(!seen_eof, "Data must never be enqueued after Eof");
                        data_count += 1;
                    }
                    StdinMsg::Eof => seen_eof = true,
                }
            }
            // A successful write must have delivered its single Data frame (before
            // the Eof); a failed write must have enqueued nothing.
            assert_eq!(data_count, usize::from(wrote_ok));
        }
    }
}
