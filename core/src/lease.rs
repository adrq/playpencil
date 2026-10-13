//! Exclusive data-directory lease: one daemon per data directory.
//!
//! The lease is an `flock(LOCK_EX)` on `<data-dir>/daemon.lock`, held through
//! an open file description. The lock file is never removed. While held, it
//! contains the holder's pid.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

/// Name of the lock file inside the data directory.
pub const LOCK_FILE_NAME: &str = "daemon.lock";

/// Descriptor of the most recently acquired live lease, or -1.
static LEASE_FD: AtomicI32 = AtomicI32::new(-1);

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error(
        "data directory {} is in use by another playpencil daemon{}; lock file {}",
        data_dir.display(),
        holder_pid.map(|p| format!(" (last recorded pid {p})")).unwrap_or_default(),
        lock_path.display()
    )]
    Held {
        data_dir: PathBuf,
        lock_path: PathBuf,
        /// The pid last recorded in the lock file, if readable. It may be stale.
        holder_pid: Option<u32>,
    },
    #[error("cannot lock data directory: lock file {}: {source}", lock_path.display())]
    Io {
        lock_path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// An exclusive lock on a data directory.
///
/// Dropping it closes its descriptor without an explicit unlock: the kernel
/// releases the lock once no descriptor on the open file description remains.
#[derive(Debug)]
pub struct DataDirLease {
    file: File,
    lock_path: PathBuf,
}

impl DataDirLease {
    /// Locks `data_dir`, which must exist, without waiting. Fails with
    /// [`LeaseError::Held`] if the lock is already held through another open
    /// file description. On success the lock file holds this process's pid.
    ///
    /// The descriptor is close-on-exec and is registered for
    /// [`close_in_forked_child`].
    pub fn acquire(data_dir: &Path) -> Result<Self, LeaseError> {
        let lock_path = data_dir.join(LOCK_FILE_NAME);
        let io_err = |source| LeaseError::Io {
            lock_path: lock_path.clone(),
            source,
        };

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(io_err)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LeaseError::Held {
                    data_dir: data_dir.to_path_buf(),
                    lock_path: lock_path.clone(),
                    holder_pid: read_pid(&mut file),
                });
            }
            Err(TryLockError::Error(e)) => return Err(io_err(e)),
        }

        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(format!("{}\n", std::process::id()).as_bytes()))
            .map_err(io_err)?;

        LEASE_FD.store(file.as_raw_fd(), Ordering::SeqCst);
        Ok(Self { file, lock_path })
    }

    /// Keeps the lease held and registered until the process exits.
    pub fn hold_until_exit(self) -> &'static DataDirLease {
        Box::leak(Box::new(self))
    }

    /// Path of the lock file.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for DataDirLease {
    fn drop(&mut self) {
        let _ = LEASE_FD.compare_exchange(
            self.file.as_raw_fd(),
            -1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

/// Reads the pid recorded in a lock file.
fn read_pid(file: &mut File) -> Option<u32> {
    let mut buf = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.take(32).read_to_string(&mut buf).ok()?;
    buf.trim().parse().ok()
}

/// Closes the registered lease descriptor in a forked child, so that a child
/// outliving its parent does not keep the lease held. The parent's lease is
/// unaffected.
///
/// Returns `false` if `close` failed, in which case the child may still hold
/// the lease. Async-signal-safe: call it in the child right after `fork()`.
pub fn close_in_forked_child() -> bool {
    let fd = LEASE_FD.load(Ordering::SeqCst);
    fd < 0 || unsafe { libc::close(fd) } == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    /// Serializes tests that register a lease, since the registration is
    /// process-wide.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    const HELPER_DIR_ENV: &str = "PLAYPENCIL_TEST_LEASE_DIR";
    const HELPER_SKIP_CLOSE_ENV: &str = "PLAYPENCIL_TEST_LEASE_SKIP_CLOSE";

    /// Runs one test of this binary in a fresh process with `dir` passed to it.
    fn run_helper(test: &str, dir: &Path, envs: &[(&str, &str)]) -> std::process::ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1"])
            .env(HELPER_DIR_ENV, dir)
            .envs(envs.iter().copied())
            .stdout(Stdio::null())
            .status()
            .unwrap()
    }

    fn helper_dir() -> Option<PathBuf> {
        std::env::var_os(HELPER_DIR_ENV).map(PathBuf::from)
    }

    #[test]
    fn second_acquire_is_held_with_holder_pid() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let _lease = DataDirLease::acquire(dir.path()).unwrap();

        let err = DataDirLease::acquire(dir.path()).unwrap_err();
        let LeaseError::Held {
            data_dir,
            lock_path,
            holder_pid,
        } = &err
        else {
            panic!("expected Held, got {err:?}");
        };
        assert_eq!(data_dir, dir.path());
        assert_eq!(lock_path, &dir.path().join("daemon.lock"));
        assert_eq!(*holder_pid, Some(std::process::id()));
        assert_eq!(
            err.to_string(),
            format!(
                "data directory {} is in use by another playpencil daemon \
                 (last recorded pid {}); lock file {}",
                dir.path().display(),
                std::process::id(),
                dir.path().join("daemon.lock").display()
            )
        );
    }

    #[test]
    fn held_message_omits_unreadable_pid() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let _lease = DataDirLease::acquire(dir.path()).unwrap();
        std::fs::write(dir.path().join("daemon.lock"), "").unwrap();

        let err = DataDirLease::acquire(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                LeaseError::Held {
                    holder_pid: None,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "data directory {} is in use by another playpencil daemon; lock file {}",
                dir.path().display(),
                dir.path().join("daemon.lock").display()
            )
        );
    }

    #[test]
    fn acquire_records_pid_over_stale_contents() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.lock"), "4194304999\nextra\n").unwrap();
        let _lease = DataDirLease::acquire(dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("daemon.lock")).unwrap(),
            format!("{}\n", std::process::id())
        );
    }

    #[test]
    fn lock_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let lease = DataDirLease::acquire(dir.path()).unwrap();
        let mode = std::fs::metadata(lease.lock_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn lock_file_symlink_is_refused() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("daemon.lock")).unwrap();

        let err = DataDirLease::acquire(dir.path()).unwrap_err();
        let LeaseError::Io { source, lock_path } = &err else {
            panic!("expected Io, got {err:?}");
        };
        assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
        assert_eq!(lock_path, &dir.path().join("daemon.lock"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
    }

    #[test]
    fn missing_data_dir_is_io_error() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let err = DataDirLease::acquire(&dir.path().join("absent")).unwrap_err();
        let LeaseError::Io { source, lock_path } = &err else {
            panic!("expected Io, got {err:?}");
        };
        assert_eq!(source.kind(), io::ErrorKind::NotFound);
        assert_eq!(lock_path, &dir.path().join("absent").join("daemon.lock"));
    }

    #[test]
    fn lease_fd_is_cloexec() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let lease = DataDirLease::acquire(dir.path()).unwrap();
        let flags = unsafe { libc::fcntl(lease.file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn lease_released_on_drop() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let lease = DataDirLease::acquire(dir.path()).unwrap();
        let fd = lease.file.as_raw_fd();
        assert_eq!(LEASE_FD.load(Ordering::SeqCst), fd);
        drop(lease);
        assert_eq!(LEASE_FD.load(Ordering::SeqCst), -1);
        DataDirLease::acquire(dir.path()).unwrap();
    }

    #[test]
    fn close_in_forked_child_reports_close_failure() {
        let _s = serial();
        assert_eq!(LEASE_FD.load(Ordering::SeqCst), -1);
        assert!(close_in_forked_child());

        // Above any descriptor limit, so never open: close fails with EBADF.
        LEASE_FD.store(i32::MAX, Ordering::SeqCst);
        let closed = close_in_forked_child();
        let errno = io::Error::last_os_error().raw_os_error();
        LEASE_FD.store(-1, Ordering::SeqCst);
        assert!(!closed);
        assert_eq!(errno, Some(libc::EBADF));
    }

    #[test]
    fn hold_until_exit_keeps_lease_after_scope() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let status = run_helper("lease::tests::helper_hold_until_exit", dir.path(), &[]);
        assert!(status.success(), "helper failed: {status:?}");
    }

    /// Subprocess body for `hold_until_exit_keeps_lease_after_scope`.
    #[test]
    fn helper_hold_until_exit() {
        let Some(dir) = helper_dir() else { return };
        let fd = {
            let lease = DataDirLease::acquire(&dir).unwrap().hold_until_exit();
            lease.file.as_raw_fd()
        };
        let err = DataDirLease::acquire(&dir).unwrap_err();
        assert!(matches!(err, LeaseError::Held { .. }), "{err:?}");
        assert_eq!(LEASE_FD.load(Ordering::SeqCst), fd);
    }

    /// Forks a child that stays alive until killed, returning once the child
    /// has run its post-fork step. The child has no parent-death signal, so
    /// only the descriptor decides whether it holds the lease.
    #[cfg(target_os = "linux")]
    fn fork_survivor(close_lease: bool) -> libc::pid_t {
        let mut ready = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            if close_lease && !close_in_forked_child() {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::write(ready[1], [1u8].as_ptr().cast(), 1) };
            loop {
                unsafe { libc::pause() };
            }
        }
        unsafe { libc::close(ready[1]) };
        let mut byte = 0u8;
        let n = unsafe { libc::read(ready[0], (&raw mut byte).cast(), 1) };
        unsafe { libc::close(ready[0]) };
        assert_eq!(n, 1, "child did not report readiness");
        pid
    }

    #[cfg(target_os = "linux")]
    fn kill_and_reap(pid: libc::pid_t) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    fn reacquire_after_parent_release(close_lease: bool) -> Result<DataDirLease, LeaseError> {
        let dir = tempfile::tempdir().unwrap();
        let lease = DataDirLease::acquire(dir.path()).unwrap();
        let child = fork_survivor(close_lease);
        drop(lease);
        let alive = unsafe { libc::kill(child, 0) } == 0;
        let result = DataDirLease::acquire(dir.path());
        kill_and_reap(child);
        assert!(alive, "child exited before the lease was re-acquired");
        result
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_child_does_not_hold_lease() {
        let _s = serial();
        reacquire_after_parent_release(true).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_child_without_close_holds_lease() {
        let _s = serial();
        let err = reacquire_after_parent_release(false).unwrap_err();
        assert!(matches!(err, LeaseError::Held { .. }), "{err:?}");
    }

    /// Process state letter from `/proc/<pid>/stat`.
    #[cfg(target_os = "linux")]
    fn proc_state(pid: libc::pid_t) -> char {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after_comm = &stat[stat.rfind(')').unwrap() + 2..];
        after_comm.chars().next().unwrap()
    }

    /// Runs the holder helper in a separate process, which exits leaving a
    /// forked child alive, then tries to acquire the lease in this process.
    #[cfg(target_os = "linux")]
    fn reacquire_after_holder_exit(close_lease: bool) -> Result<DataDirLease, LeaseError> {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let dir = tempfile::tempdir().unwrap();
        let envs: &[(&str, &str)] = if close_lease {
            &[]
        } else {
            &[(HELPER_SKIP_CLOSE_ENV, "1")]
        };
        let status = run_helper(
            "lease::tests::helper_holder_forks_survivor",
            dir.path(),
            envs,
        );
        assert!(status.success(), "holder failed: {status:?}");

        let child: libc::pid_t = std::fs::read_to_string(dir.path().join("child.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let state = proc_state(child);
        let result = DataDirLease::acquire(dir.path());
        kill_and_reap(child);
        assert!(
            state != 'Z',
            "child was not running when the lease was re-acquired"
        );
        result
    }

    /// Subprocess body for the holder-exit tests: acquires the lease, forks a
    /// survivor, records its pid, and exits.
    #[cfg(target_os = "linux")]
    #[test]
    fn helper_holder_forks_survivor() {
        let Some(dir) = helper_dir() else { return };
        let close_lease = std::env::var_os(HELPER_SKIP_CLOSE_ENV).is_none();
        let _lease = DataDirLease::acquire(&dir).unwrap();
        let child = fork_survivor(close_lease);
        std::fs::write(dir.join("child.pid"), format!("{child}\n")).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_outliving_holder_process_does_not_hold_lease() {
        let _s = serial();
        reacquire_after_holder_exit(true).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_outliving_holder_without_close_holds_lease() {
        let _s = serial();
        let err = reacquire_after_holder_exit(false).unwrap_err();
        assert!(matches!(err, LeaseError::Held { .. }), "{err:?}");
    }
}
