mod console;
mod dhcp;
mod exec;
mod mount;
mod net;
mod proto;

use std::fmt;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use console::{Console, find_and_open_exec_console, poll_and_read_line, write_line};
use exec::handle_exec;
use proto::{ExecResponse, base64_encode};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGCHLD_RECEIVED: AtomicBool = AtomicBool::new(false);

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

    // Main exec loop
    loop {
        if SHUTDOWN_REQUESTED.load(Relaxed) {
            break;
        }
        if SIGCHLD_RECEIVED.swap(false, Relaxed) {
            reap_children();
        }

        let line = match poll_and_read_line(&mut console, 1000) {
            Ok(Some(l)) => l,
            Ok(None) => continue,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {
                let resp = ExecResponse {
                    exit_code: -1,
                    stdout: base64_encode(b""),
                    stderr: base64_encode(b"line exceeds 1MB limit"),
                };
                if let Err(e) =
                    write_line(&console, &serde_json::to_string(&resp).unwrap_or_default())
                {
                    eprintln!("init: console write error: {e}");
                    break;
                }
                continue;
            }
            Err(e) => {
                eprintln!("init: console read error: {e}");
                break;
            }
        };

        let req: proto::ExecRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_msg = format!("invalid request: {e}");
                let resp = ExecResponse {
                    exit_code: -1,
                    stdout: base64_encode(b""),
                    stderr: base64_encode(err_msg.as_bytes()),
                };
                if let Err(e) =
                    write_line(&console, &serde_json::to_string(&resp).unwrap_or_default())
                {
                    eprintln!("init: console write error: {e}");
                    break;
                }
                continue;
            }
        };

        let resp = handle_exec(&req);
        if let Err(e) = write_line(&console, &serde_json::to_string(&resp).unwrap_or_default()) {
            eprintln!("init: console write error: {e}");
            break;
        }
    }
}

/// Determine the console source: test mode (env var) or normal bootstrap.
fn resolve_console() -> Result<Console, ()> {
    // Test mode: PLAYPENCIL_EXEC_FD provides a pre-opened fd
    if let Ok(fd_str) = std::env::var("PLAYPENCIL_EXEC_FD") {
        let fd: RawFd = fd_str.parse().unwrap_or_else(|e| {
            eprintln!("init: invalid PLAYPENCIL_EXEC_FD '{fd_str}': {e}");
            std::process::exit(1);
        });
        return Console::from_raw_fd(fd).map_err(|e| {
            eprintln!("init: invalid PLAYPENCIL_EXEC_FD {fd}: {e}");
        });
    }

    // Test mode: skip bootstrap but still discover console
    let skip_bootstrap = std::env::var("PLAYPENCIL_SKIP_BOOTSTRAP").is_ok();

    if !skip_bootstrap {
        if let Err(e) = mount::bootstrap_mounts() {
            eprintln!("init: mount failed: {e}");
            return Err(());
        }

        if let Err(e) = net::set_interface_up("lo") {
            eprintln!("init: failed to bring up lo: {e}");
        }

        let ifname = match net::find_virtio_net_interface() {
            Ok(name) => name,
            Err(e) => {
                eprintln!("init: no network interface: {e}");
                return Err(());
            }
        };

        if let Err(e) = net::set_interface_up(&ifname) {
            eprintln!("init: failed to bring up {ifname}: {e}");
            return Err(());
        }

        let mac = match net::get_mac_address(&ifname) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("init: failed to get MAC for {ifname}: {e}");
                return Err(());
            }
        };

        match dhcp::run_dhcp(&ifname, &mac) {
            Ok(lease) => {
                if let Err(e) = net::set_interface_addr(&ifname, lease.ip, lease.subnet_mask) {
                    eprintln!("init: failed to configure {ifname}: {e}");
                    return Err(());
                }
                if let Err(e) = net::add_default_route(lease.gateway) {
                    eprintln!("init: failed to add default route: {e}");
                    return Err(());
                }
                if let Err(e) = net::write_resolv_conf(&lease.dns_servers) {
                    eprintln!("init: cannot write /etc/resolv.conf: {e}, DNS may not work");
                }
            }
            Err(e) => {
                eprintln!("init: DHCP failed: {e}");
                return Err(());
            }
        }
    }

    match find_and_open_exec_console(EXEC_PORT_NAME) {
        Ok(c) => Ok(c),
        Err(e) => {
            eprintln!("init: exec console not available: {e}");
            Err(())
        }
    }
}

fn install_signal_handlers() {
    unsafe {
        // SIGCHLD handler
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigchld_handler as *const () as usize;
        sa.sa_flags = libc::SA_NOCLDSTOP;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());

        // SIGTERM handler
        let mut sa_term: libc::sigaction = std::mem::zeroed();
        sa_term.sa_sigaction = sigterm_handler as *const () as usize;
        sa_term.sa_flags = 0;
        libc::sigemptyset(&mut sa_term.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa_term, std::ptr::null_mut());
    }
}

extern "C" fn sigchld_handler(_sig: libc::c_int) {
    SIGCHLD_RECEIVED.store(true, Relaxed);
}

extern "C" fn sigterm_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Relaxed);
}

pub fn reap_children() {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            continue;
        }
        if pid < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
}
