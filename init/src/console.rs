use std::fs;
use std::io;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use pipemux::protocol::limits::MAX_FRAME_BYTES;

use crate::Error;

const RETRY_ATTEMPTS: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_millis(200);

/// Buffered wrapper around the virtio-console fd.
/// Persists partial reads across calls so multi-message and
/// partial-message reads are handled correctly.
pub struct Console {
    file: fs::File,
    buf: Vec<u8>,
    /// When true, discard bytes until a newline to re-sync after an oversized line.
    discarding: bool,
}

impl Console {
    /// Wrap an existing fd. Validates the fd is open and sets FD_CLOEXEC.
    pub fn from_raw_fd(fd: RawFd) -> Result<Self, io::Error> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "negative file descriptor",
            ));
        }
        // Validate fd is open
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { fs::File::from_raw_fd(fd) };
        Ok(Self {
            file,
            buf: Vec::with_capacity(4096),
            discarding: false,
        })
    }

    fn raw_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        self.file.as_raw_fd()
    }

    /// Expose the underlying fd for use in external poll() calls.
    pub fn as_raw_fd(&self) -> RawFd {
        self.raw_fd()
    }
}

/// Discover the exec port and open it, retrying both steps together.
/// The sysfs entry may appear before the /dev/vportNpM node is ready.
pub fn find_and_open_exec_console(expected_name: &str) -> Result<Console, Error> {
    for attempt in 0..RETRY_ATTEMPTS {
        if let Some(path) = find_exec_port(expected_name) {
            match open_console(&path) {
                Ok(c) => return Ok(c),
                Err(_) if attempt < RETRY_ATTEMPTS - 1 => {
                    thread::sleep(RETRY_DELAY);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        if attempt < RETRY_ATTEMPTS - 1 {
            thread::sleep(RETRY_DELAY);
        }
    }
    Err(Error::Console(format!(
        "port '{expected_name}' not found after {RETRY_ATTEMPTS} attempts"
    )))
}

fn find_exec_port(expected_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir("/sys/class/virtio-ports/").ok()?;
    for entry in entries.flatten() {
        let port_name = entry.file_name().to_string_lossy().to_string();
        let name_path = entry.path().join("name");
        if let Ok(name) = fs::read_to_string(&name_path)
            && name.trim() == expected_name
        {
            return Some(PathBuf::from(format!("/dev/{port_name}")));
        }
    }
    None
}

fn open_console(path: &Path) -> Result<Console, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Error::Console(format!("{}: {e}", path.display())))?;
    Ok(Console {
        file,
        buf: Vec::with_capacity(4096),
        discarding: false,
    })
}

/// Poll the console fd and read a complete newline-delimited line.
/// Returns None on timeout, Err on I/O error or EINTR.
/// Lines are capped at 1MB.
pub fn poll_and_read_line(
    console: &mut Console,
    timeout_ms: i32,
) -> Result<Option<String>, io::Error> {
    // If discarding, drain until we consume a newline from the stream
    if console.discarding {
        return discard_until_newline(console, timeout_ms);
    }

    // Check buffer first for a complete line
    if let Some(line) = extract_line(&mut console.buf)? {
        return Ok(Some(line));
    }

    let fd = console.raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Ok(None); // Timeout
        }

        // Read available data
        let mut tmp = [0u8; 4096];
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "console EOF"));
        }
        console.buf.extend_from_slice(&tmp[..n as usize]);

        // Check if we have a complete line
        if let Some(line) = extract_line(&mut console.buf)? {
            return Ok(Some(line));
        }

        // Buffer exceeded max without a newline — return error immediately,
        // set discard flag so subsequent reads drain until the newline arrives
        if console.buf.len() > MAX_FRAME_BYTES {
            console.buf.clear();
            console.discarding = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "line exceeds 1MB limit",
            ));
        }
    }
}

/// Discard bytes from the stream until a newline is consumed, then return
/// Ok(None) to signal the stream is re-synchronized. The error was already
/// reported when the cap was first exceeded — no second error.
fn discard_until_newline(
    console: &mut Console,
    timeout_ms: i32,
) -> Result<Option<String>, io::Error> {
    // Check if the buffer already has a newline (from previous reads)
    if let Some(pos) = console.buf.iter().position(|&b| b == b'\n') {
        console.buf.drain(..=pos);
        console.discarding = false;
        return Ok(None);
    }
    console.buf.clear();

    let fd = console.raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if ret == 0 {
            return Ok(None); // Timeout, still discarding — caller will retry
        }

        let mut tmp = [0u8; 4096];
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "console EOF"));
        }

        let data = &tmp[..n as usize];
        if let Some(pos) = data.iter().position(|&b| b == b'\n') {
            // Keep bytes after the newline for the next request
            console.buf.extend_from_slice(&data[pos + 1..]);
            console.discarding = false;
            return Ok(None);
        }
        // No newline yet, keep discarding
    }
}

/// Write a line (with trailing newline) to the console.
/// Retries on EINTR since signal handlers don't use SA_RESTART.
pub fn write_line(console: &Console, data: &str) -> Result<(), io::Error> {
    use std::os::unix::io::AsRawFd;
    let fd = console.file.as_raw_fd();
    let mut out = data.as_bytes().to_vec();
    out.push(b'\n');
    let mut written = 0;
    while written < out.len() {
        let n = unsafe {
            libc::write(
                fd,
                out[written..].as_ptr() as *const libc::c_void,
                out.len() - written,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        written += n as usize;
    }
    Ok(())
}

/// Extract a complete newline-terminated line from the buffer.
/// Rejects lines that exceed MAX_FRAME_BYTES.
fn extract_line(buf: &mut Vec<u8>) -> Result<Option<String>, io::Error> {
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let line_len = pos; // excluding newline
        if line_len > MAX_FRAME_BYTES {
            // Oversized line arrived in one read — drain it and reject
            buf.drain(..=pos);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "line exceeds 1MB limit",
            ));
        }
        let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
        let line = &line_bytes[..line_bytes.len() - 1];
        let s = String::from_utf8(line.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(s))
    } else {
        Ok(None)
    }
}
