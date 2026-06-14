//! The producer: fork/exec children and multiplex N of them over one channel by
//! string id, with per-id input/output flow control, start-error semantics,
//! credential drop, and process-group signalling + reaping. `std` + `libc`,
//! sync, cross-platform (Linux + macOS).
//!
//! [`ExecMux`] owns the `id → ExecEntry` map and emits [`GuestFrame`]s through a
//! [`FrameSink`]. It is NOT an I/O driver: the caller (init) owns the blocking
//! `poll(2)` loop and feeds readiness in via [`ExecMux::poll_targets`] +
//! `on_*_ready`/[`ExecMux::tick`]. This keeps the producer free of any async
//! runtime (the producer firewall — see the crate docs).
//!
//! # Producer firewall
//!
//! This module is `std`+`libc`, sync. It MUST NOT reference tokio or any async
//! runtime. Under one crate + feature unification tokio is present on host
//! builds, so a stray `use tokio` would compile here and fail only at the `init`
//! musl-target build — hold the line by discipline, not by the compiler.

mod process;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::unix::io::RawFd;

use crate::protocol::codec::base64_decode;
use crate::protocol::limits::{CREDIT_GRANT_THRESHOLD, INPUT_WINDOW};
use crate::protocol::{GuestFrame, HostFrame};

use process::{ExecEntry, check_child_exit, read_pipe_chunk, read_start_err, start_exec};

/// Where emitted guest frames go (init writes them to the virtio-console).
///
/// CONTRACT (preserve today's behavior exactly): `send` is best-effort and
/// INFALLIBLE from the producer's view (no `Result`). The previous init code
/// swallowed console write errors and continued; a sink write failure MUST be
/// treated identically — log/drop THAT frame and continue local process
/// accounting. [`ExecMux`] never stops, drops entries, or alters loop control on
/// a sink failure. Console READ errors are a separate concern handled by the init
/// driver (they drive shutdown), not by this sink.
pub trait FrameSink {
    fn send(&mut self, frame: &GuestFrame);
}

/// Which child fd a poll slot refers to.
#[derive(Clone, Copy)]
pub enum FdKind {
    Stdout,
    Stderr,
    Stdin,
    StartErr,
}

/// What readiness the driver should poll a target for.
#[derive(Clone, Copy)]
pub enum Interest {
    /// Readable (`POLLIN`).
    Read,
    /// Writable (`POLLOUT`).
    Write,
}

/// One fd the driver's poll loop should watch, with the child/kind it belongs to
/// and the readiness to wait for. The driver maps these to its `pollfd` array and
/// feeds readiness back through the `on_*_ready` callbacks.
pub struct PollTarget {
    pub id: String,
    pub fd: RawFd,
    pub kind: FdKind,
    pub interest: Interest,
}

/// The reusable producer: the `id → ExecEntry` demux + per-id flow control +
/// reaping. No I/O driver — the caller owns the poll loop.
#[derive(Default)]
pub struct ExecMux {
    execs: HashMap<String, ExecEntry>,
}

impl ExecMux {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one decoded host frame (was `dispatch_line`). Emits guest frames
    /// (start_error, stdin_credit, stdin_closed) via `sink`. A `Stdin` frame
    /// appends bytes AND immediately performs the same nonblocking drain +
    /// synchronous credit emit at the grant threshold before returning — credit
    /// is NOT deferred to the next `on_stdin_writable`.
    pub fn handle_host_frame(&mut self, msg: HostFrame, sink: &mut dyn FrameSink) {
        match msg {
            HostFrame::Exec {
                id,
                cmd,
                env,
                workdir,
                uid,
                gid,
                mode,
            } => match self.execs.entry(id) {
                Entry::Occupied(occ) => {
                    // A duplicate exec frame for a LIVE id: ignore it, leaving the
                    // existing child and the host's session for that id intact. The
                    // host mints unique ids, so this only happens under a malformed
                    // or replayed frame — and a StartError here would terminalize
                    // the host's existing session (it maps StartError{id} to
                    // removal), closing the live ExecHandle while the original
                    // child keeps running and its output/exit are then dropped as
                    // "unknown id".
                    eprintln!("init: duplicate exec id {}, ignoring", occ.key());
                }
                Entry::Vacant(slot) => {
                    match start_exec(&cmd, &env, workdir.as_deref(), uid, gid, mode) {
                        Ok(entry) => {
                            slot.insert(entry);
                        }
                        Err(e) => {
                            let id = slot.into_key();
                            eprintln!("init: exec failed: {e}");
                            // A host-detected pre-fork failure (empty/NUL command,
                            // fork error) is a start-error, not a numeric exit.
                            sink.send(&GuestFrame::StartError { id, message: e });
                        }
                    }
                }
            },
            HostFrame::Stdin { id, data } => {
                if let Some(entry) = self.execs.get_mut(&id) {
                    match base64_decode(&data) {
                        // Malformed base64 is a fatal protocol error for this exec
                        // id (host/guest desync): fail loud rather than silently
                        // dropping input and risk the child hanging on stdin.
                        // SIGKILL the group and let the normal terminal path report
                        // the (signalled) exit.
                        None => {
                            eprintln!("init: invalid stdin base64 for exec {id}; killing child");
                            unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
                            entry.stdin_buf.clear();
                            if entry.stdin_fd >= 0 {
                                unsafe { libc::close(entry.stdin_fd) };
                                entry.stdin_fd = -1;
                            }
                        }
                        Some(bytes) if bytes.is_empty() => {
                            // Empty data = EOF: close once buffered stdin drains.
                            entry.stdin_eof_pending = true;
                            if entry.stdin_buf.is_empty() && entry.stdin_fd >= 0 {
                                unsafe { libc::close(entry.stdin_fd) };
                                entry.stdin_fd = -1;
                            }
                        }
                        Some(bytes) if entry.stdin_buf.len() + bytes.len() > INPUT_WINDOW => {
                            // Defense-in-depth: a compliant host never overshoots
                            // the credit window. An over-window frame is a fatal
                            // protocol error — do NOT buffer it (so the invariant
                            // always holds), SIGKILL the child group, and let the
                            // terminal path emit the (signalled) exit. Fail loud,
                            // never silently truncate.
                            eprintln!("init: stdin over-window for exec {id}; killing child");
                            unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
                        }
                        Some(bytes) => {
                            entry.stdin_buf.extend(bytes);
                            drain_child_stdin(&id, entry, sink);
                        }
                    }
                }
            }
            HostFrame::Signal { id, signal } => {
                if let Some(entry) = self.execs.get(&id) {
                    // Send to the child's process group.
                    unsafe { libc::kill(-(entry.pid), signal) };
                }
            }
            HostFrame::Pause { id } => {
                if let Some(entry) = self.execs.get_mut(&id) {
                    entry.paused = true;
                }
            }
            HostFrame::Resume { id } => {
                if let Some(entry) = self.execs.get_mut(&id) {
                    entry.paused = false;
                }
            }
            HostFrame::Resize { .. } => {
                // PTY resize not supported; ignore.
            }
        }
    }

    /// The fds the driver should poll, with their interest + which child/kind
    /// each is. Output fds are skipped while the child is output-paused (its
    /// `write()` blocks); the stdin fd is polled `POLLOUT` only when buffered data
    /// is pending; the start-error pipe is polled until it closes.
    pub fn poll_targets(&self) -> Vec<PollTarget> {
        let mut targets = Vec::new();
        for (id, entry) in &self.execs {
            if !entry.stdout_closed && !entry.paused {
                targets.push(PollTarget {
                    id: id.clone(),
                    fd: entry.stdout_fd,
                    kind: FdKind::Stdout,
                    interest: Interest::Read,
                });
            }
            if !entry.stderr_closed && !entry.paused {
                targets.push(PollTarget {
                    id: id.clone(),
                    fd: entry.stderr_fd,
                    kind: FdKind::Stderr,
                    interest: Interest::Read,
                });
            }
            if entry.stdin_fd >= 0 && !entry.stdin_buf.is_empty() {
                targets.push(PollTarget {
                    id: id.clone(),
                    fd: entry.stdin_fd,
                    kind: FdKind::Stdin,
                    interest: Interest::Write,
                });
            }
            if entry.start_err_fd >= 0 && !entry.start_err_closed {
                targets.push(PollTarget {
                    id: id.clone(),
                    fd: entry.start_err_fd,
                    kind: FdKind::StartErr,
                    interest: Interest::Read,
                });
            }
        }
        targets
    }

    /// A child stdout/stderr fd is readable: read one chunk, emit it, and record
    /// the fd as closed on EOF.
    pub fn on_output_ready(&mut self, id: &str, kind: FdKind, sink: &mut dyn FrameSink) {
        let is_stderr = matches!(kind, FdKind::Stderr);
        let Some(entry) = self.execs.get_mut(id) else {
            return;
        };
        let fd = if is_stderr {
            entry.stderr_fd
        } else {
            entry.stdout_fd
        };
        let (msg_opt, closed) = read_pipe_chunk(id, fd, is_stderr);
        if let Some(msg) = msg_opt {
            sink.send(&msg);
        }
        if closed {
            if is_stderr {
                entry.stderr_closed = true;
            } else {
                entry.stdout_closed = true;
            }
        }
    }

    /// A child stdin fd is writable: drain buffered stdin and grant credit.
    pub fn on_stdin_writable(&mut self, id: &str, sink: &mut dyn FrameSink) {
        if let Some(entry) = self.execs.get_mut(id) {
            drain_child_stdin(id, entry, sink);
        }
    }

    /// The pre-exec error pipe is readable: accumulate bytes, mark closed on EOF.
    pub fn on_start_err_ready(&mut self, id: &str) {
        if let Some(entry) = self.execs.get_mut(id) {
            let fd = entry.start_err_fd;
            if read_start_err(fd, &mut entry.start_err_buf) {
                entry.start_err_closed = true;
            }
        }
    }

    /// Periodic maintenance, preserving the exact per-iteration ordering: collect
    /// exits → kill stalled groups past their grace → finish done entries (emit
    /// terminals) → reap reparented descendants.
    pub fn tick(&mut self, sink: &mut dyn FrameSink) {
        collect_exits(&mut self.execs);
        kill_stalled_entries(&mut self.execs);
        finish_done_entries(&mut self.execs, sink);
        reap_reparented(&mut self.execs);
    }

    /// Shutdown: SIGKILL + blocking reap of every remaining child (was
    /// `kill_and_reap_all`). Called once when the driver loop exits.
    pub fn shutdown(&mut self) {
        kill_and_reap_all(&mut self.execs);
    }
}

/// Write as much buffered stdin to the child as the nonblocking pipe accepts,
/// then grant the host more credit for the freed bytes (batched). Never blocks:
/// a stuck child just leaves bytes buffered (≤ INPUT_WINDOW) and the host stops
/// sending once its window is exhausted.
fn drain_child_stdin(id: &str, entry: &mut ExecEntry, sink: &mut dyn FrameSink) {
    while !entry.stdin_buf.is_empty() && entry.stdin_fd >= 0 {
        let fd = entry.stdin_fd;
        let n = {
            let (front, _) = entry.stdin_buf.as_slices();
            if front.is_empty() {
                break;
            }
            unsafe { libc::write(fd, front.as_ptr() as *const libc::c_void, front.len()) }
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break; // pipe full; try again on the next POLLOUT
            }
            // Child closed its stdin (EPIPE) or another error: stop forwarding.
            // Discard the undelivered buffer WITHOUT crediting it (no silent
            // "looks successful" input loss) and tell the host the child's stdin
            // is gone so its relay terminates and pending/future writes fail
            // loudly instead of waiting on credit that will never be granted.
            unsafe { libc::close(entry.stdin_fd) };
            entry.stdin_fd = -1;
            entry.stdin_buf.clear();
            sink.send(&GuestFrame::StdinClosed { id: id.to_string() });
            break;
        }
        if n == 0 {
            break;
        }
        entry.stdin_buf.drain(..n as usize);
        entry.credit_pending += n as usize;
    }

    if entry.credit_pending >= CREDIT_GRANT_THRESHOLD {
        let grant = entry.credit_pending;
        entry.credit_pending = 0;
        sink.send(&GuestFrame::StdinCredit {
            id: id.to_string(),
            bytes: grant,
        });
    }

    // Honour a pending EOF once the buffer is fully drained.
    if entry.stdin_eof_pending && entry.stdin_buf.is_empty() && entry.stdin_fd >= 0 {
        unsafe { libc::close(entry.stdin_fd) };
        entry.stdin_fd = -1;
    }
}

/// Kill and synchronously reap every remaining child. Called once on shutdown.
fn kill_and_reap_all(execs: &mut HashMap<String, ExecEntry>) {
    // First pass: SIGKILL every tracked process group unconditionally.
    // Even if the leader exited, background descendants may still be alive.
    // ESRCH is harmless for already-exited groups.
    for entry in execs.values() {
        unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
    }
    // Second pass: blocking waitpid for each child.
    for entry in execs.values() {
        loop {
            let mut status: libc::c_int = 0;
            let w = unsafe { libc::waitpid(entry.pid, &mut status, 0) };
            if w == entry.pid {
                break;
            }
            if w < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break; // ECHILD or unexpected error — child already reaped
            }
        }
    }
}

fn collect_exits(execs: &mut HashMap<String, ExecEntry>) {
    for entry in execs.values_mut() {
        if entry.exit_code.is_none()
            && let Some(code) = check_child_exit(entry.pid)
        {
            entry.exit_code = Some(code);
            entry.grace_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_millis(200));
        }
    }
}

/// Kill process groups that have outlived their grace period, allowing pipe drain
/// to complete.
fn kill_stalled_entries(execs: &mut HashMap<String, ExecEntry>) {
    for entry in execs.values_mut() {
        if entry.exit_code.is_none() || entry.is_done() {
            continue;
        }
        if entry
            .grace_deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            // Kill all processes still holding our pipes open.
            unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
            entry.grace_deadline = None; // send only once
        }
    }
}

fn finish_done_entries(execs: &mut HashMap<String, ExecEntry>, sink: &mut dyn FrameSink) {
    let done_ids: Vec<String> = execs
        .iter()
        .filter(|(_, e)| e.is_done())
        .map(|(id, _)| id.clone())
        .collect();
    for id in done_ids {
        if let Some(entry) = execs.remove(&id) {
            // Kill any background processes in the group that outlived the leader.
            unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
            // A captured pre-exec failure is the terminal (it suppresses the
            // numeric exit); otherwise emit the numeric exit. Exactly one
            // terminal frame either way.
            match entry.start_error() {
                Some(message) => {
                    sink.send(&GuestFrame::StartError { id, message });
                }
                None => {
                    let code = entry.exit_code.unwrap_or(-1);
                    sink.send(&GuestFrame::Exit { id, code });
                }
            }
        }
    }
}

/// Reap any reparented children (descendants of tracked processes that outlived
/// their leader and were re-parented to PID 1). Called once per poll loop
/// iteration to prevent zombie accumulation.
///
/// If a reaped PID happens to be a tracked leader (race with collect_exits), its
/// exit code is recorded so finish_done_entries can clean it up normally.
fn reap_reparented(execs: &mut HashMap<String, ExecEntry>) {
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if w <= 0 {
            // 0 = no child ready; -1 (ECHILD) = no children left.
            break;
        }
        // Check whether this was a tracked leader reaped ahead of collect_exits.
        for entry in execs.values_mut() {
            if entry.pid == w && entry.exit_code.is_none() {
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    -1
                };
                entry.exit_code = Some(code);
                entry.grace_deadline =
                    Some(std::time::Instant::now() + std::time::Duration::from_millis(200));
                break;
            }
        }
        // Otherwise it was a reparented descendant — reaped silently.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::codec::base64_encode;
    use std::collections::VecDeque;
    use std::os::unix::io::RawFd;

    /// A sink that records every frame it receives.
    #[derive(Default)]
    struct RecordingSink {
        frames: Vec<GuestFrame>,
    }
    impl FrameSink for RecordingSink {
        fn send(&mut self, frame: &GuestFrame) {
            self.frames.push(frame.clone());
        }
    }

    /// A sink that drops everything — models a failing console write, which the
    /// producer must swallow (continue accounting, never drop entries).
    struct DropSink;
    impl FrameSink for DropSink {
        fn send(&mut self, _frame: &GuestFrame) {}
    }

    /// A pipe whose read end is drained by a background thread, so writes to the
    /// write end always complete. Returns the write-end fd; the reader thread
    /// stops at EOF when the write end is closed.
    fn draining_pipe() -> RawFd {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                let n = unsafe { libc::read(r, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
            }
            unsafe { libc::close(r) };
        });
        w
    }

    /// Build an ExecEntry wired to `stdin_fd`, with output/start-err already
    /// closed so only the stdin path is exercised and no real child is needed.
    fn stdin_only_entry(stdin_fd: RawFd) -> ExecEntry {
        ExecEntry {
            pid: 999_999, // never signalled on the happy path
            stdin_fd,
            stdout_fd: -1,
            stderr_fd: -1,
            start_err_fd: -1,
            stdout_closed: true,
            stderr_closed: true,
            start_err_closed: true,
            exit_code: None,
            grace_deadline: None,
            paused: false,
            stdin_buf: VecDeque::new(),
            stdin_eof_pending: false,
            credit_pending: 0,
            start_err_buf: Vec::new(),
        }
    }

    fn stdin_frame(id: &str, raw: &[u8]) -> HostFrame {
        HostFrame::Stdin {
            id: id.to_string(),
            data: base64_encode(raw),
        }
    }

    #[test]
    fn stdin_credit_is_batched_at_the_grant_threshold() {
        let mut mux = ExecMux::new();
        mux.execs
            .insert("e1".into(), stdin_only_entry(draining_pipe()));
        let mut sink = RecordingSink::default();

        // Just under the threshold: drained, but no grant yet.
        mux.handle_host_frame(
            stdin_frame("e1", &vec![b'x'; CREDIT_GRANT_THRESHOLD - 1]),
            &mut sink,
        );
        assert!(
            sink.frames.is_empty(),
            "no credit granted below CREDIT_GRANT_THRESHOLD"
        );

        // One more byte crosses the threshold: exactly one grant of the
        // accumulated count, proving the const is the batching knob (distinct
        // from STDIN_FRAME_RAW_MAX) and that credit is emitted synchronously.
        mux.handle_host_frame(stdin_frame("e1", b"x"), &mut sink);
        assert_eq!(sink.frames.len(), 1);
        assert!(
            matches!(&sink.frames[0], GuestFrame::StdinCredit { id, bytes }
                if id == "e1" && *bytes == CREDIT_GRANT_THRESHOLD)
        );
    }

    #[test]
    fn sink_failure_does_not_stop_accounting_or_drop_entries() {
        // A sink that drops every frame (a failing console write) must not stop
        // the mux: the entry stays, and credit accounting keeps advancing.
        let mut mux = ExecMux::new();
        mux.execs
            .insert("e1".into(), stdin_only_entry(draining_pipe()));

        // Cross the grant threshold; the StdinCredit is dropped by the sink.
        mux.handle_host_frame(
            stdin_frame("e1", &vec![b'x'; CREDIT_GRANT_THRESHOLD]),
            &mut DropSink,
        );

        // Entry was not dropped and accounting reset after the (dropped) grant.
        let entry = mux
            .execs
            .get("e1")
            .expect("entry must survive sink failure");
        assert_eq!(entry.credit_pending, 0);

        // A subsequent frame still flows — the loop control was not altered.
        mux.handle_host_frame(stdin_frame("e1", b"more"), &mut DropSink);
        assert_eq!(mux.execs.get("e1").unwrap().credit_pending, 4);
    }
}
