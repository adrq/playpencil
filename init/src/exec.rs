use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use crate::SHUTDOWN_REQUESTED;
use crate::proto::{ExecRequest, ExecResponse, base64_encode};

const MAX_CAPTURE: usize = 16 * 1024 * 1024; // 16MB
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

pub fn handle_exec(req: &ExecRequest) -> ExecResponse {
    if req.cmd.is_empty() {
        return error_response("empty command");
    }

    // Validate all strings for NUL bytes before fork
    for (i, s) in req.cmd.iter().enumerate() {
        if s.contains('\0') {
            return error_response(&format!("cmd[{i}] contains NUL byte"));
        }
    }
    for (i, s) in req.env.iter().enumerate() {
        if s.contains('\0') {
            return error_response(&format!("env[{i}] contains NUL byte"));
        }
    }
    if let Some(ref dir) = req.workdir {
        if dir.contains('\0') {
            return error_response("workdir contains NUL byte");
        }
        if !std::path::Path::new(dir.as_str()).is_dir() {
            return error_response(&format!("workdir does not exist: {dir}"));
        }
    }

    // Create pipes with O_CLOEXEC
    let (stdout_r, stdout_w) = match pipe_cloexec() {
        Ok(p) => p,
        Err(e) => return error_response(&format!("pipe: {e}")),
    };
    let (stderr_r, stderr_w) = match pipe_cloexec() {
        Ok(p) => p,
        Err(e) => {
            close_fd(stdout_r);
            close_fd(stdout_w);
            return error_response(&format!("pipe: {e}"));
        }
    };

    // Block SIGCHLD before fork to prevent reaping race
    let old_mask = block_sigchld();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        restore_sigmask(&old_mask);
        close_fd(stdout_r);
        close_fd(stdout_w);
        close_fd(stderr_r);
        close_fd(stderr_w);
        return error_response(&format!("fork: {}", io::Error::last_os_error()));
    }

    if pid == 0 {
        // Child
        child_exec(req, stdout_w, stderr_w, stdout_r, stderr_r, &old_mask);
    }

    // Parent
    // Set child's process group (race-free with child's setpgid(0,0))
    let _ = unsafe { libc::setpgid(pid, pid) };

    close_fd(stdout_w);
    close_fd(stderr_w);

    let (stdout_data, stderr_data, exit_code) = exec_and_drain(pid, stdout_r, stderr_r);

    close_fd(stdout_r);
    close_fd(stderr_r);

    // Kill any remaining descendants in the process group
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    reap_group();

    // Unblock SIGCHLD and reap any orphans
    restore_sigmask(&old_mask);
    crate::reap_children();

    ExecResponse {
        exit_code,
        stdout: base64_encode(&stdout_data),
        stderr: base64_encode(&stderr_data),
    }
}

fn child_exec(
    req: &ExecRequest,
    stdout_w: RawFd,
    stderr_w: RawFd,
    stdout_r: RawFd,
    stderr_r: RawFd,
    old_mask: &libc::sigset_t,
) -> ! {
    // Unblock SIGCHLD
    restore_sigmask(old_mask);

    // Reset signal dispositions to default before exec
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }

    // Own process group
    unsafe { libc::setpgid(0, 0) };

    // Close pipe read ends (not needed in child)
    close_fd(stdout_r);
    close_fd(stderr_r);

    // Move pipe write fds above 2 to avoid collisions with stdio.
    // F_DUPFD_CLOEXEC gives us a new fd >= 3 with CLOEXEC set.
    let out_w = move_fd_above_stdio(stdout_w);
    let err_w = move_fd_above_stdio(stderr_w);
    if out_w < 0 || err_w < 0 {
        unsafe { libc::_exit(126) };
    }

    // stdin -> /dev/null
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if devnull < 0 || unsafe { libc::dup2(devnull, 0) } < 0 {
        unsafe { libc::_exit(126) };
    }
    if devnull != 0 {
        close_fd(devnull);
    }

    // stdout/stderr redirection
    if unsafe { libc::dup2(out_w, 1) } < 0 || unsafe { libc::dup2(err_w, 2) } < 0 {
        unsafe { libc::_exit(126) };
    }
    // O_CLOEXEC on out_w/err_w means they auto-close on exec
    // But close them now since we have the dup'd copies on 1/2
    close_fd(out_w);
    close_fd(err_w);

    // Working directory (validated before fork, CString safe — no NUL bytes)
    if let Some(ref dir) = req.workdir {
        let c_dir = CString::new(dir.as_str()).unwrap();
        let ret = unsafe { libc::chdir(c_dir.as_ptr()) };
        if ret < 0 {
            unsafe { libc::_exit(126) };
        }
    }

    // Environment variables (validated before fork — no NUL bytes)
    for env_str in &req.env {
        let c_env = CString::new(env_str.as_str()).unwrap();
        unsafe { libc::putenv(c_env.into_raw()) };
    }

    // Build argv for execvp (validated before fork — no NUL bytes)
    let c_args: Vec<CString> = req
        .cmd
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    // If execvp returns, it failed
    unsafe { libc::_exit(127) };
}

/// Combined poll loop: drain pipes and check child exit concurrently.
fn exec_and_drain(child_pid: i32, stdout_fd: RawFd, stderr_fd: RawFd) -> (Vec<u8>, Vec<u8>, i32) {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut child_exited = false;
    let mut exit_code: i32 = -1;
    let mut drain_deadline: Option<Instant> = None;

    loop {
        // Check shutdown
        if SHUTDOWN_REQUESTED.load(Relaxed) && !child_exited {
            if let Some(code) = shutdown_child(child_pid) {
                exit_code = code;
            } else {
                exit_code = collect_exit(child_pid);
            }
            child_exited = true;
            drain_deadline = Some(Instant::now() + DRAIN_TIMEOUT);
        }

        // Build pollfd array for open pipes
        let mut pfds = Vec::new();
        if stdout_open {
            pfds.push(libc::pollfd {
                fd: stdout_fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if stderr_open {
            pfds.push(libc::pollfd {
                fd: stderr_fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        if pfds.is_empty() {
            // Both pipes closed
            if !child_exited {
                exit_code = collect_exit(child_pid);
            }
            break;
        }

        // Use short timeout if draining after child exit
        let timeout = if drain_deadline.is_some() { 50 } else { 100 };
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as u64, timeout) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Read from ready pipes
        for pfd in &pfds {
            if pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                let mut tmp = [0u8; 8192];
                let n =
                    unsafe { libc::read(pfd.fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue; // Retry on EINTR
                    }
                    if pfd.fd == stdout_fd {
                        stdout_open = false;
                    }
                    if pfd.fd == stderr_fd {
                        stderr_open = false;
                    }
                } else if n == 0 {
                    // EOF
                    if pfd.fd == stdout_fd {
                        stdout_open = false;
                    }
                    if pfd.fd == stderr_fd {
                        stderr_open = false;
                    }
                } else {
                    let data = &tmp[..n as usize];
                    let buf = if pfd.fd == stdout_fd {
                        &mut stdout_buf
                    } else {
                        &mut stderr_buf
                    };
                    // Bounded capture: store first 16MB, discard rest
                    if buf.len() < MAX_CAPTURE {
                        let remaining = MAX_CAPTURE - buf.len();
                        buf.extend_from_slice(&data[..data.len().min(remaining)]);
                    }
                    // Keep reading (drain-and-discard) to prevent child blocking
                }
            }
        }

        // Check child exit (non-blocking)
        if !child_exited {
            let mut status: libc::c_int = 0;
            let w = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            if w == child_pid {
                exit_code = decode_exit_status(status);
                child_exited = true;
                drain_deadline = Some(Instant::now() + DRAIN_TIMEOUT);
            }
        }

        // Drain timeout expired: stop
        if let Some(deadline) = drain_deadline
            && Instant::now() >= deadline
        {
            break;
        }
    }

    (stdout_buf, stderr_buf, exit_code)
}

/// Returns Some(exit_code) if the child was reaped, None if SIGKILL was sent
/// but reaping is left to the caller.
fn shutdown_child(pid: i32) -> Option<i32> {
    unsafe { libc::kill(-pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid {
            return Some(decode_exit_status(status));
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Non-blocking collect with SIGTERM awareness. Polls waitpid(WNOHANG)
/// so SIGTERM can interrupt the wait.
fn collect_exit(pid: i32) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid {
            return decode_exit_status(status);
        }
        if w < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return -1;
        }
        // Child still running — check if we need to shut down
        if SHUTDOWN_REQUESTED.load(Relaxed) {
            if let Some(code) = shutdown_child(pid) {
                return code;
            }
            // SIGKILL sent, blocking wait to collect (retry on EINTR)
            loop {
                let w2 = unsafe { libc::waitpid(pid, &mut status, 0) };
                if w2 == pid {
                    return decode_exit_status(status);
                }
                if w2 < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return -1;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn decode_exit_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

fn reap_group() {
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if w > 0 {
            continue;
        }
        if w < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
}

fn pipe_cloexec() -> Result<(RawFd, RawFd), io::Error> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Move an fd to >= 3 so it doesn't collide with stdin/stdout/stderr.
/// Returns the new fd (with CLOEXEC set), or -1 on error.
/// Closes the original fd if it was moved.
fn move_fd_above_stdio(fd: RawFd) -> RawFd {
    if fd > 2 {
        return fd;
    }
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new_fd >= 0 {
        close_fd(fd);
    }
    new_fd
}

fn close_fd(fd: RawFd) {
    unsafe { libc::close(fd) };
}

fn block_sigchld() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old);
        old
    }
}

fn restore_sigmask(mask: &libc::sigset_t) {
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut());
    }
}

fn error_response(msg: &str) -> ExecResponse {
    ExecResponse {
        exit_code: -1,
        stdout: base64_encode(b""),
        stderr: base64_encode(msg.as_bytes()),
    }
}
