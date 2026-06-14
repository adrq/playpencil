mod console;
mod dhcp;
mod mount;
mod net;

use std::fmt;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use console::{Console, find_and_open_exec_console, poll_and_read_line, write_line};
use pipemux::producer::{ExecMux, FdKind, FrameSink, Interest};
use pipemux::protocol::{GuestFrame, HostFrame};

/// Bridges emitted guest frames to the virtio-console. Serialization/write
/// failures are swallowed (best-effort) so a console hiccup never stalls process
/// accounting — matching the producer's infallible [`FrameSink`] contract.
struct ConsoleSink<'a>(&'a Console);

impl FrameSink for ConsoleSink<'_> {
    fn send(&mut self, frame: &GuestFrame) {
        match serde_json::to_string(frame) {
            Ok(json) => {
                if let Err(e) = write_line(self.0, &json) {
                    eprintln!("init: console write error: {e}");
                }
            }
            Err(e) => eprintln!("init: serialize error: {e}"),
        }
    }
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

    // Strip every reserved internal variable from our environment before any
    // child is launched, so neither the main process nor any exec inherits one.
    // resolve_console has already read the ones init itself consumes.
    scrub_reserved_env();

    let mut execs = ExecMux::new();

    loop {
        if SHUTDOWN_REQUESTED.load(Relaxed) {
            break;
        }

        // Build pollfd array: console first (always polled so signals/pause are
        // never head-of-line blocked), then the per-exec fds the producer wants
        // watched this iteration (output pipes skipped while output-paused, the
        // stdin pipe POLLOUT only when buffered data is pending, the start-error
        // pipe until it closes).
        let targets = execs.poll_targets();
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(targets.len() + 1);
        pollfds.push(libc::pollfd {
            fd: console.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        for t in &targets {
            let events = match t.interest {
                Interest::Read => libc::POLLIN,
                Interest::Write => libc::POLLOUT,
            };
            pollfds.push(libc::pollfd {
                fd: t.fd,
                events,
                revents: 0,
            });
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
                    Ok(Some(line)) => {
                        let mut sink = ConsoleSink(&console);
                        match serde_json::from_str::<HostFrame>(&line) {
                            Ok(frame) => execs.handle_host_frame(frame, &mut sink),
                            Err(e) => eprintln!("init: invalid message: {e}"),
                        }
                    }
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

        // Per-exec fds: feed readiness back to the producer, preserving the
        // established readiness-bit handling for each kind.
        let mut sink = ConsoleSink(&console);
        for (i, t) in targets.iter().enumerate() {
            let pfd = &pollfds[i + 1];
            match t.kind {
                FdKind::Stdout | FdKind::Stderr => {
                    if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                        continue;
                    }
                    execs.on_output_ready(&t.id, t.kind, &mut sink);
                }
                FdKind::Stdin => {
                    if pfd.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                        continue;
                    }
                    execs.on_stdin_writable(&t.id, &mut sink);
                }
                FdKind::StartErr => {
                    if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                        continue;
                    }
                    execs.on_start_err_ready(&t.id);
                }
            }
        }

        // Non-blocking exit collection and cleanup (collect → kill-stalled →
        // finish → reap), in that exact order.
        execs.tick(&mut sink);
    }

    // On shutdown, kill and reap any children that are still running so we do not
    // leak host processes (especially important in test mode via PLAYPENCIL_EXEC_FD).
    execs.shutdown();
    // Flush filesystem buffers so writes through host mounts reach disk before the
    // VM is torn down.
    unsafe { libc::sync() };
}

/// Remove every reserved `PLAYPENCIL_*` variable from the environment so no child
/// (the main process or any exec) inherits an internal control variable. Runs once
/// at startup before any child is launched, while init is still single-threaded.
fn scrub_reserved_env() {
    let reserved: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("PLAYPENCIL_"))
        .collect();
    for key in reserved {
        // SAFETY: init has not spawned any threads at this point, so there is no
        // concurrent environ access.
        unsafe { std::env::remove_var(&key) };
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
