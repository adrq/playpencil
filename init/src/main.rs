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
use exec::{ExecEntry, check_child_exit, read_pipe_chunk, start_exec};
use proto::{GuestMessage, HostMessage, base64_decode, base64_encode};

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

        // Build pollfd array: console first, then all active child stdout/stderr pipes.
        let mut pollfds: Vec<libc::pollfd> = Vec::new();
        let console_fd = console.as_raw_fd();
        pollfds.push(libc::pollfd {
            fd: console_fd,
            events: libc::POLLIN,
            revents: 0,
        });

        // fd_map[i] pairs with pollfds[i+1]: (exec id, is_stderr)
        let mut fd_map: Vec<(String, bool)> = Vec::new();
        for (id, entry) in &execs {
            if !entry.stdout_closed {
                pollfds.push(libc::pollfd {
                    fd: entry.stdout_fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                fd_map.push((id.clone(), false));
            }
            if !entry.stderr_closed {
                pollfds.push(libc::pollfd {
                    fd: entry.stderr_fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
                fd_map.push((id.clone(), true));
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

        // Child output pipes.
        for (i, (id, is_stderr)) in fd_map.iter().enumerate() {
            let pfd = &pollfds[i + 1];
            if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                continue;
            }
            let (msg_opt, closed) = read_pipe_chunk(id, pfd.fd, *is_stderr);
            if let Some(msg) = msg_opt {
                send_guest_message(&console, &msg);
            }
            if closed && let Some(entry) = execs.get_mut(id) {
                if *is_stderr {
                    entry.stderr_closed = true;
                } else {
                    entry.stdout_closed = true;
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
        } => match execs.entry(id) {
            Entry::Occupied(occ) => {
                let id = occ.key().clone();
                eprintln!("init: duplicate exec id {id}, rejecting");
                send_guest_message(console, &GuestMessage::Exit { id, code: -1 });
            }
            Entry::Vacant(slot) => match start_exec(&cmd, &env, workdir.as_deref()) {
                Ok(entry) => {
                    slot.insert(entry);
                }
                Err(e) => {
                    let id = slot.into_key();
                    eprintln!("init: exec failed: {e}");
                    // Send the validation error as stderr so the caller can diagnose
                    // why the exec was rejected (empty command, bad workdir, etc.).
                    let err_bytes = format!("exec error: {e}\n").into_bytes();
                    send_guest_message(
                        console,
                        &GuestMessage::Stderr {
                            id: id.clone(),
                            data: base64_encode(&err_bytes),
                        },
                    );
                    send_guest_message(console, &GuestMessage::Exit { id, code: -1 });
                }
            },
        },
        HostMessage::Stdin { id, data } => {
            if let Some(entry) = execs.get_mut(&id)
                && let Some(bytes) = base64_decode(&data)
            {
                if bytes.is_empty() {
                    // Empty data = EOF: close stdin so the child sees EOF.
                    if entry.stdin_fd >= 0 {
                        unsafe { libc::close(entry.stdin_fd) };
                        entry.stdin_fd = -1;
                    }
                } else {
                    write_to_stdin(entry.stdin_fd, &bytes);
                }
            }
        }
        HostMessage::Signal { id, signal } => {
            if let Some(entry) = execs.get(&id) {
                // Send to the child's process group.
                unsafe { libc::kill(-(entry.pid), signal) };
            }
        }
        HostMessage::Resize { .. } => {
            // PTY resize not supported; ignore.
        }
    }
}

fn write_to_stdin(fd: RawFd, data: &[u8]) {
    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                data.len() - written,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        written += n as usize;
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
            let code = entry.exit_code.unwrap_or(-1);
            send_guest_message(console, &GuestMessage::Exit { id, code });
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
