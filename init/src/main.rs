mod console;
mod dhcp;
mod exec;
mod mount;
mod net;
mod proto;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use console::{Console, find_and_open_exec_console, poll_and_read_line, write_line};
use exec::{
    CREDIT_GRANT_THRESHOLD, ExecEntry, INPUT_WINDOW, check_child_exit, read_pipe_chunk,
    read_start_err, start_exec,
};
use proto::{GuestMessage, HostMessage, base64_decode};

/// Which child fd a poll slot refers to.
#[derive(Clone, Copy)]
enum FdKind {
    Stdout,
    Stderr,
    Stdin,
    StartErr,
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

const EXEC_PORT_NAME: &str = "playpencil.exec";

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Dhcp(String),
    Console(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Dhcp(msg) => write!(f, "dhcp: {msg}"),
            Error::Console(msg) => write!(f, "console: {msg}"),
        }
    }
}

fn main() {
    install_signal_handlers();

    let mut console = match resolve_console() {
        Ok(c) => c,
        Err(()) => std::process::exit(1),
    };

    let mut execs: HashMap<String, ExecEntry> = HashMap::new();

    loop {
        if SHUTDOWN_REQUESTED.load(Relaxed) {
            break;
        }

        // Build pollfd array: console first (always polled so signals/pause are
        // never head-of-line blocked), then per-exec output pipes (skipped when
        // output-paused), the stdin pipe (POLLOUT when buffered data is pending),
        // and the pre-exec start-error pipe.
        let mut pollfds: Vec<libc::pollfd> = Vec::new();
        let console_fd = console.as_raw_fd();
        pollfds.push(libc::pollfd {
            fd: console_fd,
            events: libc::POLLIN,
            revents: 0,
        });

        // fd_map[i] pairs with pollfds[i+1]: (exec id, fd kind)
        let mut fd_map: Vec<(String, FdKind)> = Vec::new();
        for (id, entry) in &execs {
            // Output is suppressed while paused: the child's write() blocks.
            if !entry.stdout_closed && !entry.paused {
                pollfds.push(libc::pollfd {
                    fd: entry.stdout_fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                fd_map.push((id.clone(), FdKind::Stdout));
            }
            if !entry.stderr_closed && !entry.paused {
                pollfds.push(libc::pollfd {
                    fd: entry.stderr_fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                fd_map.push((id.clone(), FdKind::Stderr));
            }
            if entry.stdin_fd >= 0 && !entry.stdin_buf.is_empty() {
                pollfds.push(libc::pollfd {
                    fd: entry.stdin_fd,
                    events: libc::POLLOUT,
                    revents: 0,
                });
                fd_map.push((id.clone(), FdKind::Stdin));
            }
            if entry.start_err_fd >= 0 && !entry.start_err_closed {
                pollfds.push(libc::pollfd {
                    fd: entry.start_err_fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                fd_map.push((id.clone(), FdKind::StartErr));
            }
        }

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 100) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("init: poll error: {err}");
            break;
        }

        // Console is ready — drain all buffered lines before returning to poll().
        if pollfds[0].revents & libc::POLLIN != 0 {
            'drain: loop {
                match poll_and_read_line(&mut console, 0) {
                    Ok(Some(line)) => dispatch_line(&line, &mut execs, &console),
                    Ok(None) => break 'drain,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {
                        // Oversized line already handled inside poll_and_read_line; keep draining.
                        break 'drain;
                    }
                    Err(e) => {
                        eprintln!("init: console read error: {e}");
                        SHUTDOWN_REQUESTED.store(true, Relaxed);
                        break 'drain;
                    }
                }
            }
        }
        // Console hangup/error — host closed the connection, begin orderly shutdown.
        if pollfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            SHUTDOWN_REQUESTED.store(true, Relaxed);
        }

        // Per-exec fds.
        for (i, (id, kind)) in fd_map.iter().enumerate() {
            let pfd = &pollfds[i + 1];
            match kind {
                FdKind::Stdout | FdKind::Stderr => {
                    if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                        continue;
                    }
                    let is_stderr = matches!(kind, FdKind::Stderr);
                    let (msg_opt, closed) = read_pipe_chunk(id, pfd.fd, is_stderr);
                    if let Some(msg) = msg_opt {
                        send_guest_message(&console, &msg);
                    }
                    if closed && let Some(entry) = execs.get_mut(id) {
                        if is_stderr {
                            entry.stderr_closed = true;
                        } else {
                            entry.stdout_closed = true;
                        }
                    }
                }
                FdKind::Stdin => {
                    if pfd.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                        continue;
                    }
                    if let Some(entry) = execs.get_mut(id) {
                        drain_child_stdin(id, entry, &console);
                    }
                }
                FdKind::StartErr => {
                    if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                        continue;
                    }
                    if let Some(entry) = execs.get_mut(id) {
                        let fd = entry.start_err_fd;
                        if read_start_err(fd, &mut entry.start_err_buf) {
                            entry.start_err_closed = true;
                        }
                    }
                }
            }
        }

        // Non-blocking exit collection and cleanup.
        collect_exits(&mut execs);
        kill_stalled_entries(&mut execs);
        finish_done_entries(&mut execs, &console);
        // Reap any reparented descendants so they don't accumulate as zombies.
        reap_reparented(&mut execs);
    }

    // On shutdown, kill and reap any children that are still running so we do not
    // leak host processes (especially important in test mode via PLAYPENCIL_EXEC_FD).
    kill_and_reap_all(&mut execs);
}

fn dispatch_line(line: &str, execs: &mut HashMap<String, ExecEntry>, console: &Console) {
    let msg: HostMessage = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("init: invalid message: {e}");
            return;
        }
    };
    match msg {
        HostMessage::Exec {
            id,
            cmd,
            env,
            workdir,
            uid,
            gid,
            mode,
        } => match execs.entry(id) {
            Entry::Occupied(occ) => {
                // A duplicate exec frame for a LIVE id: ignore it, leaving the
                // existing child and the host's session for that id intact. The
                // host mints unique ids, so this only happens under a malformed or
                // replayed frame — and a StartError here would terminalize the
                // host's existing session (it maps StartError{id} to removal),
                // closing the live ExecHandle while the original child keeps
                // running and its output/exit are then dropped as "unknown id".
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
                        send_guest_message(console, &GuestMessage::StartError { id, message: e });
                    }
                }
            }
        },
        HostMessage::Stdin { id, data } => {
            if let Some(entry) = execs.get_mut(&id) {
                match base64_decode(&data) {
                    // Malformed base64 is a fatal protocol error for this exec id
                    // (host/guest desync): fail loud rather than silently dropping
                    // input and risk the child hanging on stdin. SIGKILL the group
                    // and let the normal terminal path report the (signalled) exit.
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
                        // Empty data = EOF: close once buffered stdin has drained.
                        entry.stdin_eof_pending = true;
                        if entry.stdin_buf.is_empty() && entry.stdin_fd >= 0 {
                            unsafe { libc::close(entry.stdin_fd) };
                            entry.stdin_fd = -1;
                        }
                    }
                    Some(bytes) if entry.stdin_buf.len() + bytes.len() > INPUT_WINDOW => {
                        // Defense-in-depth: a compliant host never overshoots the
                        // credit window. An over-window frame is a fatal protocol
                        // error — do NOT buffer it (so the invariant always holds),
                        // SIGKILL the child group, and let the terminal path emit
                        // the (signalled) exit. Fail loud, never silently truncate.
                        eprintln!("init: stdin over-window for exec {id}; killing child");
                        unsafe { libc::kill(-(entry.pid), libc::SIGKILL) };
                    }
                    Some(bytes) => {
                        entry.stdin_buf.extend(bytes);
                        drain_child_stdin(&id, entry, console);
                    }
                }
            }
        }
        HostMessage::Signal { id, signal } => {
            if let Some(entry) = execs.get(&id) {
                // Send to the child's process group.
                unsafe { libc::kill(-(entry.pid), signal) };
            }
        }
        HostMessage::Pause { id } => {
            if let Some(entry) = execs.get_mut(&id) {
                entry.paused = true;
            }
        }
        HostMessage::Resume { id } => {
            if let Some(entry) = execs.get_mut(&id) {
                entry.paused = false;
            }
        }
        HostMessage::Resize { .. } => {
            // PTY resize not supported; ignore.
        }
    }
}

/// Write as much buffered stdin to the child as the nonblocking pipe accepts,
/// then grant the host more credit for the freed bytes (batched). Never blocks:
/// a stuck child just leaves bytes buffered (≤ INPUT_WINDOW) and the host stops
/// sending once its window is exhausted.
fn drain_child_stdin(id: &str, entry: &mut ExecEntry, console: &Console) {
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock {
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
            send_guest_message(console, &GuestMessage::StdinClosed { id: id.to_string() });
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
        send_guest_message(
            console,
            &GuestMessage::StdinCredit {
                id: id.to_string(),
                bytes: grant,
            },
        );
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
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
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

/// Kill process groups that have outlived their grace period, allowing pipe drain to complete.
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

fn finish_done_entries(execs: &mut HashMap<String, ExecEntry>, console: &Console) {
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
                    send_guest_message(console, &GuestMessage::StartError { id, message });
                }
                None => {
                    let code = entry.exit_code.unwrap_or(-1);
                    send_guest_message(console, &GuestMessage::Exit { id, code });
                }
            }
        }
    }
}

fn send_guest_message(console: &Console, msg: &GuestMessage) {
    match serde_json::to_string(msg) {
        Ok(json) => {
            if let Err(e) = write_line(console, &json) {
                eprintln!("init: console write error: {e}");
            }
        }
        Err(e) => eprintln!("init: serialize error: {e}"),
    }
}

/// Determine the console source: test mode (env var) or normal bootstrap.
fn resolve_console() -> Result<Console, ()> {
    // Test mode: PLAYPENCIL_EXEC_FD provides a pre-opened fd.
    if let Ok(fd_str) = std::env::var("PLAYPENCIL_EXEC_FD") {
        let fd: RawFd = fd_str.parse().unwrap_or_else(|e| {
            eprintln!("init: invalid PLAYPENCIL_EXEC_FD '{fd_str}': {e}");
            std::process::exit(1);
        });
        return Console::from_raw_fd(fd).map_err(|e| {
            eprintln!("init: invalid PLAYPENCIL_EXEC_FD {fd}: {e}");
        });
    }

    let skip_bootstrap = std::env::var("PLAYPENCIL_SKIP_BOOTSTRAP").is_ok();

    if !skip_bootstrap {
        if let Err(e) = mount::bootstrap_mounts() {
            eprintln!("init: mount failed: {e}");
            return Err(());
        }

        let mounts = match mount::read_playpencil_mounts() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("init: failed to read mounts: {e}");
                return Err(());
            }
        };
        for entry in mounts {
            if let Err(e) = mount::mount_virtiofs(&entry.tag, &entry.guest_path, entry.read_only) {
                eprintln!(
                    "init: virtiofs mount {} -> {} failed: {e}",
                    entry.tag, entry.guest_path
                );
                return Err(());
            }
        }

        if let Err(e) = net::set_interface_up("lo") {
            eprintln!("init: failed to bring up lo: {e}");
        }

        setup_network();
    }

    match find_and_open_exec_console(EXEC_PORT_NAME) {
        Ok(c) => Ok(c),
        Err(e) => {
            eprintln!("init: exec console not available: {e}");
            Err(())
        }
    }
}

/// Configure the virtio-net interface. Non-fatal: logs a warning on failure.
/// In TSI (unrestricted) mode there is no virtio-net device; write a static
/// resolv.conf so DNS works through the TSI proxy.
fn setup_network() {
    if std::env::var("PLAYPENCIL_NET_MODE").as_deref() == Ok("unrestricted") {
        if let Err(e) = std::fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\n") {
            eprintln!("init: cannot write /etc/resolv.conf: {e}");
        }
        return;
    }

    let ifname = match net::find_virtio_net_interface() {
        Ok(name) => name,
        Err(e) => {
            eprintln!("init: no virtio-net interface found (non-fatal): {e}");
            return;
        }
    };

    if let Err(e) = net::set_interface_up(&ifname) {
        eprintln!("init: failed to bring up {ifname} (non-fatal): {e}");
        return;
    }

    let mac = match net::get_mac_address(&ifname) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("init: failed to get MAC for {ifname} (non-fatal): {e}");
            return;
        }
    };

    match dhcp::run_dhcp(&ifname, &mac) {
        Ok(lease) => {
            if let Err(e) = net::set_interface_addr(&ifname, lease.ip, lease.subnet_mask) {
                eprintln!("init: failed to configure {ifname} (non-fatal): {e}");
                return;
            }
            if let Err(e) = net::add_default_route(lease.gateway) {
                eprintln!("init: failed to add default route (non-fatal): {e}");
                return;
            }
            if let Err(e) = net::write_resolv_conf(&lease.dns_servers) {
                eprintln!("init: cannot write /etc/resolv.conf: {e}, DNS may not work");
            }
        }
        Err(e) => {
            eprintln!("init: DHCP failed (non-fatal): {e}");
        }
    }
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigterm_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());

        // Ignore SIGPIPE — write errors are handled explicitly.
        let mut sa_pipe: libc::sigaction = std::mem::zeroed();
        sa_pipe.sa_sigaction = libc::SIG_IGN;
        sa_pipe.sa_flags = 0;
        libc::sigemptyset(&mut sa_pipe.sa_mask);
        libc::sigaction(libc::SIGPIPE, &sa_pipe, std::ptr::null_mut());
    }
}

extern "C" fn sigterm_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Relaxed);
}

/// Reap any reparented children (descendants of tracked processes that outlived
/// their leader and were re-parented to PID 1). Called once per poll loop iteration
/// to prevent zombie accumulation.
///
/// If a reaped PID happens to be a tracked leader (race with collect_exits),
/// its exit code is recorded so finish_done_entries can clean it up normally.
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
