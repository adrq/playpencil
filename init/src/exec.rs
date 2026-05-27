use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

use crate::proto::{GuestMessage, base64_encode};

/// State of a single running exec.
pub struct ExecEntry {
    pub pid: libc::pid_t,
    /// Write end of child's stdin pipe (host writes here to send stdin data).
    pub stdin_fd: RawFd,
    /// Read end of child's stdout pipe.
    pub stdout_fd: RawFd,
    /// Read end of child's stderr pipe.
    pub stderr_fd: RawFd,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    /// Exit code, set when waitpid confirms the child exited.
    pub exit_code: Option<i32>,
    /// Deadline after which lingering process group members are killed so pipes drain.
    /// Set when the leader exits; None until then and cleared after the kill.
    pub grace_deadline: Option<std::time::Instant>,
}

impl ExecEntry {
    /// True when we have collected the exit code and both output pipes are drained.
    pub fn is_done(&self) -> bool {
        self.exit_code.is_some() && self.stdout_closed && self.stderr_closed
    }
}

impl Drop for ExecEntry {
    fn drop(&mut self) {
        close_if_open(self.stdin_fd);
        close_if_open(self.stdout_fd);
        close_if_open(self.stderr_fd);
    }
}

/// Fork and start the child, returning an ExecEntry. Does not block.
pub fn start_exec(
    cmd: &[String],
    env: &[String],
    workdir: Option<&str>,
) -> Result<ExecEntry, String> {
    if cmd.is_empty() {
        return Err("empty command".into());
    }
    for (i, s) in cmd.iter().enumerate() {
        if s.contains('\0') {
            return Err(format!("cmd[{i}] contains NUL byte"));
        }
    }
    for (i, s) in env.iter().enumerate() {
        if s.contains('\0') {
            return Err(format!("env[{i}] contains NUL byte"));
        }
    }
    if let Some(dir) = workdir {
        if dir.contains('\0') {
            return Err("workdir contains NUL byte".into());
        }
        if !std::path::Path::new(dir).is_dir() {
            return Err(format!("workdir does not exist: {dir}"));
        }
    }

    let (stdin_r, stdin_w) = pipe_cloexec().map_err(|e| format!("pipe: {e}"))?;
    let (stdout_r, stdout_w) = pipe_cloexec().map_err(|e| {
        close_if_open(stdin_r);
        close_if_open(stdin_w);
        format!("pipe: {e}")
    })?;
    let (stderr_r, stderr_w) = pipe_cloexec().map_err(|e| {
        close_if_open(stdin_r);
        close_if_open(stdin_w);
        close_if_open(stdout_r);
        close_if_open(stdout_w);
        format!("pipe: {e}")
    })?;

    let old_mask = block_sigchld();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        restore_sigmask(&old_mask);
        close_if_open(stdin_r);
        close_if_open(stdin_w);
        close_if_open(stdout_r);
        close_if_open(stdout_w);
        close_if_open(stderr_r);
        close_if_open(stderr_w);
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }

    if pid == 0 {
        // Child: set up stdio and exec
        let fds = ChildFds {
            stdin_r,
            stdin_w,
            stdout_r,
            stdout_w,
            stderr_r,
            stderr_w,
        };
        child_exec(cmd, env, workdir, fds, &old_mask);
    }

    // Parent
    restore_sigmask(&old_mask);
    // Race-free: set child's process group
    let _ = unsafe { libc::setpgid(pid, pid) };

    // Close child-side fds in parent
    close_if_open(stdin_r);
    close_if_open(stdout_w);
    close_if_open(stderr_w);

    Ok(ExecEntry {
        pid,
        stdin_fd: stdin_w,
        stdout_fd: stdout_r,
        stderr_fd: stderr_r,
        stdout_closed: false,
        stderr_closed: false,
        exit_code: None,
        grace_deadline: None,
    })
}

/// Read available data from a pipe fd, encode it, and return a GuestMessage.
/// Returns None if the pipe is closed (EOF). Returns Some(msg) if data was read.
/// Returns Err on I/O error.
///
/// The returned bool indicates whether the fd is now closed.
pub fn read_pipe_chunk(exec_id: &str, fd: RawFd, is_stderr: bool) -> (Option<GuestMessage>, bool) {
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Error on read — treat as closed
            return (None, true);
        }
        if n == 0 {
            // EOF
            return (None, true);
        }
        let data = base64_encode(&buf[..n as usize]);
        let msg = if is_stderr {
            GuestMessage::Stderr {
                id: exec_id.to_string(),
                data,
            }
        } else {
            GuestMessage::Stdout {
                id: exec_id.to_string(),
                data,
            }
        };
        return (Some(msg), false);
    }
}

/// Non-blocking waitpid check. Returns Some(exit_code) if child has exited.
pub fn check_child_exit(pid: libc::pid_t) -> Option<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid {
            return Some(decode_exit_status(status));
        }
        if w < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return None;
    }
}

struct ChildFds {
    stdin_r: RawFd,
    stdin_w: RawFd,
    stdout_r: RawFd,
    stdout_w: RawFd,
    stderr_r: RawFd,
    stderr_w: RawFd,
}

fn child_exec(
    cmd: &[String],
    env: &[String],
    workdir: Option<&str>,
    fds: ChildFds,
    old_mask: &libc::sigset_t,
) -> ! {
    let ChildFds {
        stdin_r,
        stdin_w,
        stdout_r,
        stdout_w,
        stderr_r,
        stderr_w,
    } = fds;
    restore_sigmask(old_mask);

    // Reset signal dispositions
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }

    // Own process group
    unsafe { libc::setpgid(0, 0) };

    // Close parent-side fds not needed in child
    close_if_open(stdin_w);
    close_if_open(stdout_r);
    close_if_open(stderr_r);

    // Move pipe fds above 2 before dup2 to avoid collisions
    let in_r = move_fd_above_stdio(stdin_r);
    let out_w = move_fd_above_stdio(stdout_w);
    let err_w = move_fd_above_stdio(stderr_w);
    if in_r < 0 || out_w < 0 || err_w < 0 {
        unsafe { libc::_exit(126) };
    }

    // Redirect stdin/stdout/stderr
    if unsafe { libc::dup2(in_r, 0) } < 0
        || unsafe { libc::dup2(out_w, 1) } < 0
        || unsafe { libc::dup2(err_w, 2) } < 0
    {
        unsafe { libc::_exit(126) };
    }
    // O_CLOEXEC on in_r/out_w/err_w auto-closes them on exec
    close_if_open(in_r);
    close_if_open(out_w);
    close_if_open(err_w);

    // Working directory
    if let Some(dir) = workdir {
        let c_dir = CString::new(dir).unwrap();
        if unsafe { libc::chdir(c_dir.as_ptr()) } < 0 {
            unsafe { libc::_exit(126) };
        }
    }

    // Environment variables
    for env_str in env {
        let c_env = CString::new(env_str.as_str()).unwrap();
        unsafe { libc::putenv(c_env.into_raw()) };
    }

    // Build argv
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    unsafe { libc::_exit(127) };
}

fn pipe_cloexec() -> Result<(RawFd, RawFd), io::Error> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn move_fd_above_stdio(fd: RawFd) -> RawFd {
    if fd > 2 {
        return fd;
    }
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new_fd >= 0 {
        close_if_open(fd);
    }
    new_fd
}

fn close_if_open(fd: RawFd) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
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
