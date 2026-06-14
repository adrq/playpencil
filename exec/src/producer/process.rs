//! The process state machine: fork/exec a child, own its pipes + pre-exec error
//! pipe, resolve and drop credentials, and reap. `std` + `libc`, sync, no tokio.
//! Cross-platform (Linux + macOS); the only non-portable spot is pipe creation
//! (`pipe2` vs `pipe`+`fcntl`) and the `setgroups` `ngroups` arg type — both
//! handled below. In playpencil this runs only as the Linux guest; the macOS
//! arms are for a downstream native worker (credential-by-uid is best-effort
//! there).

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

use crate::protocol::codec::base64_encode;
use crate::protocol::{ExecMode, GuestFrame};

/// State of a single running exec.
pub(crate) struct ExecEntry {
    pub(crate) pid: libc::pid_t,
    /// Write end of child's stdin pipe (nonblocking). -1 once closed.
    pub(crate) stdin_fd: RawFd,
    /// Read end of child's stdout pipe.
    pub(crate) stdout_fd: RawFd,
    /// Read end of child's stderr pipe.
    pub(crate) stderr_fd: RawFd,
    /// Read end of the pre-exec error pipe. EOF-empty = the command started;
    /// any bytes = a pre-exec failure reason. -1 once closed.
    pub(crate) start_err_fd: RawFd,
    pub(crate) stdout_closed: bool,
    pub(crate) stderr_closed: bool,
    pub(crate) start_err_closed: bool,
    /// Exit code, set when waitpid confirms the child exited.
    pub(crate) exit_code: Option<i32>,
    /// Deadline after which lingering process group members are killed so pipes
    /// drain. Set when the leader exits; None until then and cleared after kill.
    pub(crate) grace_deadline: Option<std::time::Instant>,
    /// Output flow-control: when set, this child's stdout/stderr fds are dropped
    /// from the poll set so the child's `write()` blocks (only this command).
    pub(crate) paused: bool,
    /// Buffered incoming stdin awaiting nonblocking write to the child. Never
    /// exceeds [`INPUT_WINDOW`](crate::protocol::limits::INPUT_WINDOW).
    pub(crate) stdin_buf: VecDeque<u8>,
    /// Host signalled EOF; close the child's stdin fd once `stdin_buf` drains.
    pub(crate) stdin_eof_pending: bool,
    /// Bytes written to the child since the last credit grant.
    pub(crate) credit_pending: usize,
    /// Accumulated pre-exec error bytes (emitted as the terminal at completion).
    pub(crate) start_err_buf: Vec<u8>,
}

impl ExecEntry {
    /// True once the exit code is collected and stdout, stderr, and the
    /// start-error pipe are all drained — so a start-error reason is captured
    /// before the terminal frame is emitted.
    pub(crate) fn is_done(&self) -> bool {
        self.exit_code.is_some()
            && self.stdout_closed
            && self.stderr_closed
            && self.start_err_closed
    }

    /// The captured start-error reason, if the command failed to start.
    pub(crate) fn start_error(&self) -> Option<String> {
        if self.start_err_buf.is_empty() {
            None
        } else {
            Some(
                String::from_utf8_lossy(&self.start_err_buf)
                    .trim()
                    .to_string(),
            )
        }
    }
}

impl Drop for ExecEntry {
    fn drop(&mut self) {
        close_if_open(self.stdin_fd);
        close_if_open(self.stdout_fd);
        close_if_open(self.stderr_fd);
        close_if_open(self.start_err_fd);
    }
}

/// Resolved credential drop computed from `/etc/passwd` + `/etc/group`.
pub(crate) struct CredentialPlan {
    /// Supplemental groups to install via `setgroups` before `setgid`/`setuid`.
    /// `Some(_)` (including an empty vec) means call `setgroups`; an empty vec
    /// clears all supplemental groups. `resolve_credentials` always returns
    /// `Some` for a requested uid so the child never inherits init's groups.
    pub(crate) supplemental: Option<Vec<u32>>,
    /// Effective gid target (`setgid`).
    pub(crate) gid: u32,
    pub(crate) uid: u32,
}

/// Compute the credential drop for `uid` from passwd/group file contents. Pure
/// and host-independent so it can be unit-tested. `gid_override` forces the
/// setgid target; supplemental groups are still derived from the resolved login.
pub(crate) fn resolve_credentials(
    passwd: &str,
    group: &str,
    uid: u32,
    gid_override: Option<u32>,
) -> CredentialPlan {
    // Find the passwd entry: name:passwd:uid:gid:...
    let mut login: Option<String> = None;
    let mut primary_gid: Option<u32> = None;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            continue;
        }
        if f[2].parse::<u32>() == Ok(uid) {
            login = Some(f[0].to_string());
            primary_gid = f[3].parse::<u32>().ok();
            break;
        }
    }

    let (Some(login), Some(primary)) = (login, primary_gid) else {
        // Unresolvable uid: fall back. Either way the supplemental set is cleared
        // (Some(empty) → setgroups([]) runs) so the child never inherits init's
        // groups (which include root); the gid mirrors the uid unless overridden.
        return CredentialPlan {
            supplemental: Some(Vec::new()),
            gid: gid_override.unwrap_or(uid),
            uid,
        };
    };

    // Supplemental = primary gid + every group listing this login as a member.
    let mut supp: Vec<u32> = vec![primary];
    for line in group.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(g) = f[2].parse::<u32>() else {
            continue;
        };
        let is_member = f[3].split(',').any(|m| m == login);
        if is_member && !supp.contains(&g) {
            supp.push(g);
        }
    }
    supp.sort_unstable();
    supp.dedup();

    CredentialPlan {
        supplemental: Some(supp),
        gid: gid_override.unwrap_or(primary),
        uid,
    }
}

/// Fork and start the child, returning an ExecEntry. Does not block. Validation
/// failures (empty/NUL command, bad NUL in env/workdir) return `Err`, which the
/// caller surfaces as a start-error. Once the fork succeeds, any pre-exec
/// failure in the child is reported via the start-error pipe (not the exit code).
pub(crate) fn start_exec(
    cmd: &[String],
    env: &[String],
    workdir: Option<&str>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: ExecMode,
) -> Result<ExecEntry, String> {
    if cmd.is_empty() {
        return Err("empty command".into());
    }
    // Defense-in-depth: credentials are resolved from uid (gid only refines the
    // primary group), so a gid without a uid would silently run with the default
    // (typically root) creds. Fail loud rather than drop the credential intent.
    if gid.is_some() && uid.is_none() {
        return Err("gid requires uid".into());
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
    if let Some(dir) = workdir
        && dir.contains('\0')
    {
        return Err("workdir contains NUL byte".into());
    }

    // Credentials are resolved in the parent (where allocation/file I/O is safe)
    // and only applied (setgroups/setgid/setuid) in the child.
    let cred = uid.map(|u| {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
        resolve_credentials(&passwd, &group, u, gid)
    });

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
    let (start_err_r, start_err_w) = pipe_cloexec().map_err(|e| {
        close_if_open(stdin_r);
        close_if_open(stdin_w);
        close_if_open(stdout_r);
        close_if_open(stdout_w);
        close_if_open(stderr_r);
        close_if_open(stderr_w);
        format!("pipe: {e}")
    })?;

    let old_mask = block_sigchld();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        restore_sigmask(&old_mask);
        for fd in [
            stdin_r,
            stdin_w,
            stdout_r,
            stdout_w,
            stderr_r,
            stderr_w,
            start_err_r,
            start_err_w,
        ] {
            close_if_open(fd);
        }
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }

    if pid == 0 {
        let fds = ChildFds {
            stdin_r,
            stdin_w,
            stdout_r,
            stdout_w,
            stderr_r,
            stderr_w,
            start_err_r,
            start_err_w,
        };
        child_exec(cmd, env, workdir, mode, cred.as_ref(), fds, &old_mask);
    }

    // Parent
    restore_sigmask(&old_mask);
    let _ = unsafe { libc::setpgid(pid, pid) };

    // Close child-side fds in the parent.
    close_if_open(stdin_r);
    close_if_open(stdout_w);
    close_if_open(stderr_w);
    // The parent owns the read end of the start-error pipe; it must close the
    // write end so the read end sees EOF once the child execs (CLOEXEC) or exits.
    close_if_open(start_err_w);

    // Stdin write end is nonblocking so a stuck child never blocks init.
    set_nonblocking(stdin_w);
    set_nonblocking(start_err_r);

    Ok(ExecEntry {
        pid,
        stdin_fd: stdin_w,
        stdout_fd: stdout_r,
        stderr_fd: stderr_r,
        start_err_fd: start_err_r,
        stdout_closed: false,
        stderr_closed: false,
        start_err_closed: false,
        exit_code: None,
        grace_deadline: None,
        paused: false,
        stdin_buf: VecDeque::new(),
        stdin_eof_pending: false,
        credit_pending: 0,
        start_err_buf: Vec::new(),
    })
}

/// Read available data from a pipe fd, encode it, and return a GuestFrame.
/// Returns None if the pipe is closed (EOF). Returns Some(msg) if data was read.
/// The returned bool indicates whether the fd is now closed.
pub(crate) fn read_pipe_chunk(
    exec_id: &str,
    fd: RawFd,
    is_stderr: bool,
) -> (Option<GuestFrame>, bool) {
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return (None, true);
        }
        if n == 0 {
            return (None, true);
        }
        let data = base64_encode(&buf[..n as usize]);
        let msg = if is_stderr {
            GuestFrame::Stderr {
                id: exec_id.to_string(),
                data,
            }
        } else {
            GuestFrame::Stdout {
                id: exec_id.to_string(),
                data,
            }
        };
        return (Some(msg), false);
    }
}

/// Read available bytes from the pre-exec error pipe into `buf`. Returns true
/// when the pipe reached EOF (the read end can then be closed).
pub(crate) fn read_start_err(fd: RawFd, buf: &mut Vec<u8>) -> bool {
    let mut tmp = [0u8; 256];
    loop {
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // EAGAIN (no more data yet, not closed) or a real error.
            return err.kind() != io::ErrorKind::WouldBlock;
        }
        if n == 0 {
            return true; // EOF
        }
        buf.extend_from_slice(&tmp[..n as usize]);
    }
}

/// Non-blocking waitpid check. Returns Some(exit_code) if child has exited.
pub(crate) fn check_child_exit(pid: libc::pid_t) -> Option<i32> {
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
    start_err_r: RawFd,
    start_err_w: RawFd,
}

fn child_exec(
    cmd: &[String],
    env: &[String],
    workdir: Option<&str>,
    mode: ExecMode,
    cred: Option<&CredentialPlan>,
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
        start_err_r,
        start_err_w,
    } = fds;
    restore_sigmask(old_mask);

    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }

    unsafe { libc::setpgid(0, 0) };

    // Close the parent-side and unused ends not needed in the child.
    close_if_open(stdin_w);
    close_if_open(stdout_r);
    close_if_open(stderr_r);
    close_if_open(start_err_r);

    // Move fds above 2 before dup2 to avoid collisions. The start-error write
    // end is kept open (O_CLOEXEC) so a successful execvp auto-closes it (EOF)
    // and any pre-exec failure can be reported on it first.
    let in_r = move_fd_above_stdio(stdin_r);
    let out_w = move_fd_above_stdio(stdout_w);
    let err_w = move_fd_above_stdio(stderr_w);
    let serr = move_fd_above_stdio(start_err_w);
    if in_r < 0 || out_w < 0 || err_w < 0 || serr < 0 {
        // Cannot reliably report; exit non-zero.
        unsafe { libc::_exit(126) };
    }

    if unsafe { libc::dup2(in_r, 0) } < 0
        || unsafe { libc::dup2(out_w, 1) } < 0
        || unsafe { libc::dup2(err_w, 2) } < 0
    {
        write_start_err(serr, "failed to set up child stdio");
        unsafe { libc::_exit(126) };
    }
    close_if_open(in_r);
    close_if_open(out_w);
    close_if_open(err_w);

    // Working directory.
    if let Some(dir) = workdir {
        let c_dir = CString::new(dir).unwrap();
        if unsafe { libc::chdir(c_dir.as_ptr()) } < 0 {
            write_start_err(
                serr,
                &format!("chdir {dir}: {}", io::Error::last_os_error()),
            );
            unsafe { libc::_exit(1) };
        }
    }

    // Credential drop (while still privileged): setgroups, setgid, setuid.
    if let Some(c) = cred {
        if let Some(supp) = &c.supplemental {
            // `ngroups` is `size_t` on Linux and `c_int` on macOS — `as _` casts
            // to whichever the platform's `setgroups` expects.
            let ret = unsafe { libc::setgroups(supp.len() as _, supp.as_ptr()) };
            if ret < 0 {
                write_start_err(serr, &format!("setgroups: {}", io::Error::last_os_error()));
                unsafe { libc::_exit(1) };
            }
        }
        if unsafe { libc::setgid(c.gid as libc::gid_t) } < 0 {
            write_start_err(
                serr,
                &format!("setgid {}: {}", c.gid, io::Error::last_os_error()),
            );
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::setuid(c.uid as libc::uid_t) } < 0 {
            write_start_err(
                serr,
                &format!("setuid {}: {}", c.uid, io::Error::last_os_error()),
            );
            unsafe { libc::_exit(1) };
        }
    }

    // Environment variables.
    for env_str in env {
        let c_env = CString::new(env_str.as_str()).unwrap();
        unsafe { libc::putenv(c_env.into_raw()) };
    }

    match mode {
        ExecMode::Argv => exec_argv(cmd, serr),
        ExecMode::Shell => exec_shell(&cmd[0], serr),
    }
}

/// Direct argv exec. Reports failure on the start-error pipe and exits.
fn exec_argv(cmd: &[String], serr: RawFd) -> ! {
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    write_start_err(
        serr,
        &format!("exec {}: {}", cmd[0], io::Error::last_os_error()),
    );
    unsafe { libc::_exit(127) };
}

/// Run a shell line via `bash -c`, falling back to `sh -c` ONLY when bash is
/// not found (ENOENT). Any other bash failure is reported (a present-but-broken
/// bash is not silently masked by sh).
fn exec_shell(line: &str, serr: RawFd) -> ! {
    let c_line = CString::new(line).unwrap();
    let dash_c = CString::new("-c").unwrap();

    for shell in ["bash", "sh"] {
        let c_shell = CString::new(shell).unwrap();
        let argv: [*const libc::c_char; 4] = [
            c_shell.as_ptr(),
            dash_c.as_ptr(),
            c_line.as_ptr(),
            std::ptr::null(),
        ];
        unsafe { libc::execvp(c_shell.as_ptr(), argv.as_ptr()) };
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            write_start_err(serr, &format!("exec {shell}: {err}"));
            unsafe { libc::_exit(126) };
        }
        // bash not found → try sh next.
    }
    write_start_err(serr, "no shell available");
    unsafe { libc::_exit(127) };
}

/// Best-effort write of a start-error reason to the error pipe.
fn write_start_err(fd: RawFd, msg: &str) {
    let bytes = msg.as_bytes();
    let mut off = 0;
    while off < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

/// Create a close-on-exec pipe. Uses `pipe2(O_CLOEXEC)` on Linux; on other unix
/// (macOS) `pipe2` is unavailable, so fall back to `pipe` + `fcntl(FD_CLOEXEC)`.
/// The non-atomic fallback is fine for the single-threaded guest; a downstream
/// multi-threaded mac worker would lock around fork/accept.
fn pipe_cloexec() -> Result<(RawFd, RawFd), io::Error> {
    let mut fds = [0i32; 2];
    #[cfg(target_os = "linux")]
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    for fd in fds {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let err = io::Error::last_os_error();
            close_if_open(fds[0]);
            close_if_open(fds[1]);
            return Err(err);
        }
    }
    Ok((fds[0], fds[1]))
}

fn set_nonblocking(fd: RawFd) {
    if fd < 0 {
        return;
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:2000:Bob:/home/bob:/bin/sh\n";
    const GROUP: &str =
        "root:x:0:\nalice:x:1000:\nwheel:x:10:alice,bob\ndev:x:50:alice\nempty:x:99:\n";

    #[test]
    fn resolve_known_user_primary_and_supplemental() {
        let p = resolve_credentials(PASSWD, GROUP, 1000, None);
        assert_eq!(p.uid, 1000);
        assert_eq!(p.gid, 1000);
        // primary 1000 + wheel(10) + dev(50), sorted.
        assert_eq!(p.supplemental.unwrap(), vec![10, 50, 1000]);
    }

    #[test]
    fn resolve_gid_override_keeps_supplemental() {
        let p = resolve_credentials(PASSWD, GROUP, 1000, Some(4242));
        assert_eq!(p.gid, 4242);
        assert_eq!(p.supplemental.unwrap(), vec![10, 50, 1000]);
    }

    #[test]
    fn resolve_user_no_extra_groups() {
        let p = resolve_credentials(PASSWD, GROUP, 1001, None);
        assert_eq!(p.gid, 2000);
        // bob is a member of wheel(10); primary 2000.
        assert_eq!(p.supplemental.unwrap(), vec![10, 2000]);
    }

    #[test]
    fn resolve_unknown_uid_with_gid_uses_empty_supplemental() {
        let p = resolve_credentials(PASSWD, GROUP, 5000, Some(7));
        assert_eq!(p.gid, 7);
        assert_eq!(p.uid, 5000);
        assert_eq!(p.supplemental.unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn resolve_unknown_uid_no_gid_clears_supplemental() {
        // An unresolvable uid with no gid override must STILL clear supplemental
        // groups (Some(empty) → setgroups([]) runs) so the child never retains
        // init's groups (which include root); the gid mirrors the uid.
        let p = resolve_credentials(PASSWD, GROUP, 5000, None);
        assert_eq!(p.gid, 5000);
        assert_eq!(p.uid, 5000);
        assert_eq!(p.supplemental.unwrap(), Vec::<u32>::new());
    }
}
